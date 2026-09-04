//! Stage 5 of the tool surface (tools 16–19): query & search — exercised
//! through the registry, the way both transports dispatch.
//!
//! The `search` tests here carry the fixture rows `tests/records/search_semantics.rs`
//! marks as owed at this level: the BOUND (the thin-results threshold gating
//! the near-miss pass, and the per-mechanism row cap) and Layer 1's other two
//! mechanisms (prefix neighbours, tree siblings) in the payload they ride in.

use native_ce::events::{FacetSetPayload, LinkAddedPayload};

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    alias_value, create_vocabulary, promote_value, propose_value, write_user_schema_config,
    SchemaConfigOptions,
};
use native_ce::query::fts::{NEAR_MISS_CAP, THIN_RESULTS_THRESHOLD};
use native_ce::store::{add_link, archive_record, create_record, create_record_as, set_facet};
use native_ce::{create_database, open_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic. The
// `aggregate-cancel-*` and `authored-*` counters keep their original relative
// ordering in case any aggregate or sample ever falls back to id order.
/// `aggregate-cancel-01`
const AGGREGATE_CANCEL_01: &str = "700c5000-0000-4000-8000-000000000001";
/// `aggregate-cancel-02`
const AGGREGATE_CANCEL_02: &str = "700c5000-0000-4000-8000-000000000002";
/// `aggregate-cancel-03`
const AGGREGATE_CANCEL_03: &str = "700c5000-0000-4000-8000-000000000003";
/// `authored-1`
const AUTHORED_1: &str = "700c5000-0000-4000-8000-000000000011";
/// `authored-2`
const AUTHORED_2: &str = "700c5000-0000-4000-8000-000000000012";
/// `authored-3`
const AUTHORED_3: &str = "700c5000-0000-4000-8000-000000000013";
/// `authored-4`
const AUTHORED_4: &str = "700c5000-0000-4000-8000-000000000014";
/// `legacy-authored`
const LEGACY_AUTHORED: &str = "700c5000-0000-4000-8000-000000000021";
/// `other-authored`
const OTHER_AUTHORED: &str = "700c5000-0000-4000-8000-000000000022";
/// `agent-work`
const AGENT_WORK: &str = "700c5000-0000-4000-8000-000000000031";
/// `unbound-work`
const UNBOUND_WORK: &str = "700c5000-0000-4000-8000-000000000032";
/// `hidden-parent`
const HIDDEN_PARENT: &str = "700c5000-0000-4000-8000-000000000041";
/// `strict-child`
const STRICT_CHILD: &str = "700c5000-0000-4000-8000-000000000042";
/// `prefix-child`
const PREFIX_CHILD: &str = "700c5000-0000-4000-8000-000000000043";
/// `infix-child`
const INFIX_CHILD: &str = "700c5000-0000-4000-8000-000000000044";
/// `sibling-child`
const SIBLING_CHILD: &str = "700c5000-0000-4000-8000-000000000045";

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

fn without_observed_at(mut output: Value) -> Value {
    assert!(output["observed_at"].is_string());
    output
        .as_object_mut()
        .expect("query_record output is an object")
        .remove("observed_at");
    output
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

async fn bind_account(db: &Db, person_id: &str, token: &str, canonical: bool) {
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, ?)",
    )
    .bind(person_id)
    .bind(token)
    .bind(i64::from(canonical))
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

fn link(source: &str, target: &str, relationship: &str) -> LinkAddedPayload {
    LinkAddedPayload {
        id: None,
        source_id: source.into(),
        target_id: target.into(),
        relationship: relationship.into(),
        note: None,
    }
}

async fn task(db: &Db, name: &str) -> String {
    create_record(
        db,
        json!({ "type": "WorkItem", "kind": "task", "name": name }),
    )
    .await
    .unwrap()
}

async fn task_with_facets(db: &Db, name: &str, facets: &[(&str, &str)]) -> String {
    let id = task(db, name).await;
    for (key, value) in facets {
        set_facet(
            db,
            &id,
            FacetSetPayload {
                key: (*key).into(),
                value: Some((*value).into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }
    id
}

fn names_of(hits: &Value) -> Vec<String> {
    hits.as_array()
        .unwrap()
        .iter()
        .map(|h| h["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn lifecycle_filters_resolve_aliases_per_effective_vocabulary_and_rows_expose_the_envelope() {
    let db = db().await;
    let registry = registry();

    let completed_id: String = sqlx::query_scalar(
        "SELECT id FROM vocabulary_values WHERE vocabulary_id = 'voc:lifecycle' AND value = 'completed'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let task_alias = propose_value(&db, "lifecycle", "done", None).await.unwrap();
    promote_value(&db, &task_alias).await.unwrap();

    create_vocabulary(&db, "document-lifecycle", None)
        .await
        .unwrap();
    let closed = propose_value(&db, "document-lifecycle", "closed", None)
        .await
        .unwrap();
    promote_value(&db, &closed).await.unwrap();
    let document_alias = propose_value(&db, "document-lifecycle", "done", None)
        .await
        .unwrap();
    promote_value(&db, &document_alias).await.unwrap();
    alias_value(&db, &document_alias, &closed).await.unwrap();
    create_vocabulary(&db, "resolution-lifecycle", None)
        .await
        .unwrap();
    let resolution_completed = propose_value(&db, "resolution-lifecycle", "completed", None)
        .await
        .unwrap();
    promote_value(&db, &resolution_completed).await.unwrap();
    write_user_schema_config(
        &db,
        json!({"shapes":{
            "Document":{"facets":{"lifecycle":{
                "vocab_ref":"document-lifecycle",
                "axis":{"key":"document_state","label":"Document state"}
            }}},
            "Resolution":{"facets":{"lifecycle":{
                "vocab_ref":"resolution-lifecycle",
                "axis":{"key":"resolution_state","label":"Resolution state"}
            }}}
        }}),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let task_id = task(&db, "completed task").await;
    call(
        &registry,
        &db,
        "update_record",
        json!({"id":task_id,"lifecycle":"done"}),
    )
    .await;
    let epic_id = create_record(
        &db,
        json!({"type":"WorkItem","kind":"epic","name":"completed epic","lifecycle":"done"}),
    )
    .await
    .unwrap();
    alias_value(&db, &task_alias, &completed_id).await.unwrap();
    let document_id = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"closed document","lifecycle":"closed"}),
    )
    .await
    .unwrap();
    let unrelated_id = create_record(
        &db,
        json!({"type":"Resolution","kind":"decision","name":"unrelated completed resolution","lifecycle":"completed"}),
    )
    .await
    .unwrap();

    let output = call(
        &registry,
        &db,
        "query_record",
        json!({"steps":[{"step":"filter","lifecycle":["done"]}]}),
    )
    .await;
    let records = output["records"].as_array().unwrap();
    let ids = records
        .iter()
        .map(|record| record["id"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        ids,
        std::collections::HashSet::from([task_id.as_str(), epic_id.as_str(), document_id.as_str()])
    );
    assert!(!ids.contains(unrelated_id.as_str()));
    for record in records {
        assert!(record.get("lifecycle").is_none());
        assert_eq!(record["lifecycle_interpretation"]["status"], "governed");
    }
    let task = records
        .iter()
        .find(|record| record["id"] == task_id)
        .unwrap();
    assert_eq!(
        task["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
    assert_eq!(task["lifecycle_interpretation"]["value"]["raw"], "done");
    assert_eq!(
        task["lifecycle_interpretation"]["value"]["id"],
        completed_id
    );
    assert_eq!(
        task["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );
    let epic = records
        .iter()
        .find(|record| record["id"] == epic_id)
        .unwrap();
    assert_eq!(
        epic["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
    assert_eq!(epic["lifecycle_interpretation"]["value"]["raw"], "done");
    assert_eq!(
        epic["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );
    let document = records
        .iter()
        .find(|record| record["id"] == document_id)
        .unwrap();
    assert_eq!(
        document["lifecycle_interpretation"]["axis"]["key"],
        "document_state"
    );
    assert_eq!(
        document["lifecycle_interpretation"]["value"]["raw"],
        "closed"
    );
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stage5_tools_register_in_surface_order() {
    let registry = registry();
    let names: Vec<&str> = registry.specs().map(|t| t.name.as_str()).collect();
    for tool in [
        "query_record",
        "resolve_rollup",
        "search",
        "query_sql",
        "scan",
    ] {
        assert!(names.contains(&tool), "missing {tool}");
    }
    let position = |tool: &str| names.iter().position(|n| *n == tool).unwrap();
    assert!(position("suggest_facet_values") < position("query_record"));
    assert!(position("query_record") < position("search"));
    assert!(position("query_record") < position("resolve_rollup"));
    assert!(position("resolve_rollup") < position("search"));
    assert!(position("search") < position("query_sql"));
    assert!(position("query_sql") < position("scan"));
    assert!(position("scan") < position("manage_vocabularies"));

    let description = &registry.get("scan").unwrap().description;
    for contract in [
        "lexical has score + snippet",
        "recent has last_activity_at",
        "high_degree has degree",
        "containers has child_count",
        "array of {id, type, name, axes, axis_count}",
        "sample heads, not the full axis pools",
        "ordered by axis_count DESC, name, id",
    ] {
        assert!(
            description.contains(contract),
            "missing {contract:?}: {description}"
        );
    }

    for tool in ["search", "scan"] {
        let spec = registry.get(tool).unwrap();
        let query_description = spec.input_schema["properties"]["query"]["description"]
            .as_str()
            .unwrap();
        let scope_description = spec.input_schema["properties"]["scope"]["description"]
            .as_str()
            .unwrap();

        for published_text in [spec.description.as_str(), query_description] {
            let normalized = published_text.to_ascii_lowercase();
            assert!(
                normalized.contains("lexical") && normalized.contains("not a record address"),
                "{tool} must keep query typed as lexical text: {published_text}"
            );
            assert!(
                published_text.contains("get_record")
                    && published_text.contains("short record reference"),
                "{tool} must route known references to get_record: {published_text}"
            );
        }
        assert!(
            scope_description.contains("Record address")
                && scope_description.contains("short record references"),
            "{tool}.scope must advertise address resolution: {scope_description}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tool 16 — query_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_record_filters_orders_and_pages() {
    let db = db().await;
    let registry = registry();
    for name in ["alpha", "beta", "gamma"] {
        task(&db, name).await;
    }
    create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "not a task" }),
    )
    .await
    .unwrap();

    let out = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "order": "name_asc",
            "limit": 2
        }),
    )
    .await;
    assert_eq!(out["shape"], "records");
    assert_eq!(out["total"], 3);
    assert_eq!(out["returned"], 2);
    assert_eq!(out["has_more"], true);
    assert_eq!(out["offset"], 0);
    assert_eq!(names_of(&out["records"]), vec!["alpha", "beta"]);

    let page2 = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "order": "name_asc",
            "limit": 2,
            "offset": 2
        }),
    )
    .await;
    assert_eq!(names_of(&page2["records"]), vec!["gamma"]);
    assert_eq!(page2["has_more"], false);

    for legacy_order in [
        "updated_desc",
        "created_desc",
        "last_activity_desc",
        "name_asc",
    ] {
        let legacy = call(
            &registry,
            &db,
            "query_record",
            json!({
                "steps": [{ "step": "filter", "types": ["WorkItem"] }],
                "order": legacy_order
            }),
        )
        .await;
        assert_eq!(legacy["total"], 3, "legacy order {legacy_order}");
        assert_eq!(legacy.get("messages"), None);
    }
}

#[tokio::test]
async fn query_record_orders_facets_by_explicit_lane_and_keeps_missing_last() {
    let db = db().await;
    let registry = registry();
    task_with_facets(&db, "two", &[("rank", "2")]).await;
    task_with_facets(&db, "ten", &[("rank", "10")]).await;
    task_with_facets(&db, "lane-miss", &[("rank", "not-a-number")]).await;
    task(&db, "missing").await;

    let query = |lane: &str, direction: &str| {
        json!({
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "facet_order": {
                "key": "rank",
                "lane": lane,
                "direction": direction
            },
            "order": "name_asc"
        })
    };

    let numeric_asc = call(&registry, &db, "query_record", query("number", "asc")).await;
    assert_eq!(
        names_of(&numeric_asc["records"]),
        vec!["two", "ten", "lane-miss", "missing"]
    );
    assert_eq!(
        numeric_asc["messages"],
        json!(["1 records have `rank` set but no numeric projection; they sort with missing values — use lane 'text' or store JSON numbers"])
    );

    let numeric_desc = call(&registry, &db, "query_record", query("number", "desc")).await;
    assert_eq!(
        names_of(&numeric_desc["records"]),
        vec!["ten", "two", "lane-miss", "missing"],
        "numeric direction reverses only populated values; both missing buckets stay last"
    );

    let text_asc = call(&registry, &db, "query_record", query("text", "asc")).await;
    assert_eq!(
        names_of(&text_asc["records"]),
        vec!["ten", "two", "lane-miss", "missing"],
        "the stored text lane deliberately diverges from numeric order"
    );
    assert_eq!(text_asc.get("messages"), None);

    let text_desc = call(&registry, &db, "query_record", query("text", "desc")).await;
    assert_eq!(
        names_of(&text_desc["records"]),
        vec!["lane-miss", "two", "ten", "missing"],
        "a genuinely absent facet remains last in descending text order"
    );
}

#[tokio::test]
async fn query_record_facet_ties_use_existing_order_then_id() {
    let db = db().await;
    let registry = registry();
    let newest = task_with_facets(&db, "newest", &[("rank", "1")]).await;
    let tied_a = task_with_facets(&db, "tie a", &[("rank", "1")]).await;
    let tied_b = task_with_facets(&db, "tie b", &[("rank", "1")]).await;
    sqlx::query("UPDATE records SET updated_at = '2026-08-01T03:00:00Z' WHERE id = ?")
        .bind(&newest)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    for id in [&tied_a, &tied_b] {
        sqlx::query("UPDATE records SET updated_at = '2026-08-01T02:00:00Z' WHERE id = ?")
            .bind(id)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
    }

    let out = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "facet_order": { "key": "rank", "lane": "number", "direction": "asc" },
            "order": "updated_desc"
        }),
    )
    .await;
    let ids: Vec<&str> = out["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["id"].as_str().unwrap())
        .collect();
    let mut tied = [tied_a.as_str(), tied_b.as_str()];
    tied.sort_unstable();
    assert_eq!(ids, vec![newest.as_str(), tied[0], tied[1]]);
}

#[tokio::test]
async fn query_record_facet_order_is_global_across_chunks_and_pages_stably() {
    let db = db().await;
    let registry = registry();
    let mut transaction = crate::common::fixture_write_pool(&db)
        .await
        .begin()
        .await
        .unwrap();
    for index in 0..405 {
        let id = format!("bulk-{index:03}");
        let name = format!("item-{:03}", 404 - index);
        sqlx::query("INSERT INTO records (id, type, name) VALUES (?, 'WorkItem', ?)")
            .bind(&id)
            .bind(&name)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO facet_values (id, record_id, key, value) VALUES (?, ?, 'rank', '1')",
        )
        .bind(format!("facet-{index:03}"))
        .bind(&id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    }
    transaction.commit().await.unwrap();

    let args = json!({
        "steps": [{ "step": "filter", "types": ["WorkItem"] }],
        "facet_order": { "key": "rank", "lane": "number", "direction": "asc" },
        "order": "name_asc",
        "limit": 15,
        "offset": 395
    });
    let first = call(&registry, &db, "query_record", args.clone()).await;
    let second = call(&registry, &db, "query_record", args).await;
    assert_eq!(
        without_observed_at(first.clone()),
        without_observed_at(second),
        "unchanged data must produce stable offset pages"
    );
    assert_eq!(first["total"], 405);
    assert_eq!(
        names_of(&first["records"]),
        (395..405)
            .map(|index| format!("item-{index:03}"))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn query_record_traverses_links_and_counts() {
    let db = db().await;
    let registry = registry();
    let a = task(&db, "task a").await;
    let b = task(&db, "task b").await;
    let goal = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "the goal" }),
    )
    .await
    .unwrap();
    add_link(&db, link(&a, &goal, "mentions")).await.unwrap();
    add_link(&db, link(&b, &goal, "mentions")).await.unwrap();

    // From the goal, an inbound content-owned link reaches both tasks.
    let out = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "types": ["Outcome"] },
                { "step": "traverse", "target": "links",
                  "relationship": "mentions", "direction": "in" }
            ],
            "order": "name_asc"
        }),
    )
    .await;
    assert_eq!(names_of(&out["records"]), vec!["task a", "task b"]);

    let exact = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "ids": [&a] }]
        }),
    )
    .await;
    assert_eq!(names_of(&exact["records"]), vec!["task a"]);

    // Count terminal, bucketed by type.
    let counts = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "count_by": "type"
        }),
    )
    .await;
    assert_eq!(counts["shape"], "counts");
    assert_eq!(counts["total"], 5);
    let buckets = counts["buckets"].as_array().unwrap();
    assert!(buckets.contains(&json!({ "key": "WorkItem", "count": 2 })));
    assert!(buckets.contains(&json!({ "key": "Outcome", "count": 1 })));
    assert!(buckets.contains(&json!({ "key": "Collection", "count": 2 })));
}

#[tokio::test]
async fn query_record_rejects_malformed_specs_before_executing() {
    let db = db().await;
    let registry = registry();

    let err = call_err(&registry, &db, "query_record", json!({ "steps": [] })).await;
    assert!(err.contains("at least one step"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "explode" }] }),
    )
    .await;
    assert!(err.contains("unknown step kind 'explode'"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "traverse", "target": "children", "direction": "out" }] }),
    )
    .await;
    assert!(err.contains("apply to target 'links' only"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter" }], "count_by": "colour" }),
    )
    .await;
    assert!(err.contains("unknown count_by 'colour'"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter" }], "count_by": "facet" }),
    )
    .await;
    assert!(err.contains("requires 'facet_key'"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter" }], "facet_key": "confidence" }),
    )
    .await;
    assert!(
        err.contains("'facet_key' requires count_by 'facet'"),
        "{err}"
    );

    // Unknown filter fields are caller bugs, surfaced with the step index.
    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "tyeps": ["WorkItem"] }] }),
    )
    .await;
    assert!(err.contains("step 0 (filter)"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "facets": [{
            "key": "target", "eq": "50", "ne": "51"
        }] }] }),
    )
    .await;
    assert!(err.contains("only one lower bound"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "facets": [{
            "key": "target", "gte": 50, "lte": "50"
        }] }] }),
    )
    .await;
    assert!(err.contains("must both be JSON numbers"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "facet_order": { "key": "rank", "lane": "quantity", "direction": "asc" }
        }),
    )
    .await;
    assert!(err.contains("expected 'number' or 'text'"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "facet_order": { "key": "rank", "direction": "asc" }
        }),
    )
    .await;
    assert!(err.contains("missing field `lane`"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "facet_order": { "key": " ", "lane": "number", "direction": "asc" }
        }),
    )
    .await;
    assert!(err.contains("key' must be a non-empty string"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "facet_order": { "key": "rank", "lane": "number", "direction": "sideways" }
        }),
    )
    .await;
    assert!(err.contains("expected 'asc' or 'desc'"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "count_by": "type",
            "facet_order": { "key": "rank", "lane": "number", "direction": "asc" }
        }),
    )
    .await;
    assert!(err.contains("cannot be used with 'count_by'"), "{err}");

    let schema = &registry.get("query_record").unwrap().input_schema;
    assert_eq!(
        schema["properties"]["facet_order"]["required"],
        json!(["direction", "key", "lane"])
    );
}

#[tokio::test]
async fn query_record_numeric_and_ordered_facet_filters_choose_the_correct_lane() {
    let db = db().await;
    let registry = registry();
    for (name, target) in [
        ("minus-three", "-3"),
        ("nine", "9"),
        ("twelve-point-five", "12.5"),
        ("spaced-forty-two", " 42 "),
        ("hundred", "100"),
        ("exponent", "1e3"),
        ("letters", "abc"),
        ("percent", "50%"),
        ("empty", ""),
        ("hex", "0x10"),
    ] {
        task_with_facets(&db, name, &[("target", target)]).await;
    }

    let lt = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{ "key": "target", "lt": 50 }] }],
            "order": "name_asc"
        }),
    )
    .await;
    assert_eq!(
        names_of(&lt["records"]),
        vec![
            "minus-three",
            "nine",
            "spaced-forty-two",
            "twelve-point-five"
        ]
    );

    let gt = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{ "key": "target", "gt": 50 }] }],
            "order": "name_asc"
        }),
    )
    .await;
    assert_eq!(names_of(&gt["records"]), vec!["exponent", "hundred"]);
    assert!(
        !names_of(&gt["records"]).contains(&"letters".to_string()),
        "non-numeric text must be absent from both directions of the numeric lane"
    );

    for (name, as_of) in [
        ("before", "2026-06-30"),
        ("on-floor", "2026-07-01"),
        ("after", "2026-07-31"),
    ] {
        task_with_facets(&db, name, &[("as_of", as_of)]).await;
    }
    let dates = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{
                "key": "as_of", "gte": "2026-07-01"
            }] }],
            "order": "name_asc"
        }),
    )
    .await;
    assert_eq!(names_of(&dates["records"]), vec!["after", "on-floor"]);
}

#[tokio::test]
async fn query_record_compares_numeric_facets_and_explains_lane_misses() {
    let db = db().await;
    let registry = registry();
    for (name, facets) in [
        ("behind", &[("current", "40"), ("target", "50")][..]),
        ("ahead", &[("current", "60"), ("target", "50")][..]),
        ("bad-current", &[("current", "abc"), ("target", "50")][..]),
        ("bad-target", &[("current", "40"), ("target", "abc")][..]),
        ("missing-target", &[("current", "40")][..]),
    ] {
        task_with_facets(&db, name, facets).await;
    }
    let compared = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{
                "key": "current", "lt_facet": "target"
            }] }]
        }),
    )
    .await;
    assert_eq!(names_of(&compared["records"]), vec!["behind"]);

    // The numeric filter matched `behind`; only the later traversal emptied
    // the pipeline. That is not a numeric lane miss.
    let emptied_later = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "facets": [{
                    "key": "current", "lt_facet": "target"
                }] },
                { "step": "traverse", "target": "links",
                  "relationship": "no-such", "direction": "out" }
            ]
        }),
    )
    .await;
    assert_eq!(emptied_later["total"], 0);
    assert_eq!(emptied_later.get("messages"), None);

    for name in ["red", "blue"] {
        task_with_facets(&db, name, &[("score_label", name)]).await;
    }
    let misses = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{
                "key": "score_label", "gt": 50
            }] }]
        }),
    )
    .await;
    assert_eq!(misses["total"], 0);
    assert_eq!(
        misses["messages"],
        json!(["2 records have `score_label` set but no numeric projection"])
    );

    // Diagnostics reuse the real working set entering the numeric filter.
    let scoped_miss = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "name_contains": "red" },
                { "step": "filter", "facets": [{
                    "key": "score_label", "gt": 50
                }] },
                { "step": "filter", "types": ["Outcome"] }
            ]
        }),
    )
    .await;
    assert_eq!(
        scoped_miss["messages"],
        json!(["1 records have `score_label` set but no numeric projection"])
    );
}

#[tokio::test]
async fn query_record_preserves_legacy_facet_forms_and_refuses_numeric_equality() {
    let db = db().await;
    let registry = registry();
    task_with_facets(&db, "fifty", &[("target", "50")]).await;
    for (name, value) in [
        ("fifty-decimal", "50.0"),
        ("fifty-exponent", "5e1"),
        ("fifty-spaced", " 50 "),
        ("forty-nine", "49"),
        ("not-a-number", "abc"),
    ] {
        task_with_facets(&db, name, &[("target", value)]).await;
    }

    let query = |facet: Value| {
        json!({
            "steps": [{ "step": "filter", "facets": [facet] }],
            "order": "name_asc"
        })
    };
    let legacy = call(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target", "value": "50" })),
    )
    .await;
    let explicit = call(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target", "eq": "50" })),
    )
    .await;
    assert_eq!(without_observed_at(legacy), without_observed_at(explicit));

    let exists = call(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target" })),
    )
    .await;
    let legacy_null = call(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target", "value": null })),
    )
    .await;
    assert_eq!(
        without_observed_at(exists),
        without_observed_at(legacy_null)
    );

    let quantity = call(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target", "gte": 50, "lte": 50 })),
    )
    .await;
    assert_eq!(
        names_of(&quantity["records"]),
        vec!["fifty", "fifty-decimal", "fifty-exponent", "fifty-spaced"]
    );

    let err = call_err(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target", "eq": 50 })),
    )
    .await;
    assert!(err.contains(r#"{eq: "50"}"#), "{err}");
    assert!(err.contains("{gte: 50, lte: 50}"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_record",
        query(json!({ "key": "target", "ne": 50 })),
    )
    .await;
    assert!(err.contains(r#"{ne: "50"}"#), "{err}");
    assert!(err.contains("{lt: 50}"), "{err}");
    assert!(err.contains("{gt: 50}"), "{err}");
    assert!(err.contains("separate queries"), "{err}");
    assert!(err.contains("not expressible as one ANDed"), "{err}");
    assert!(!err.contains("{gte: 50, lte: 50}"), "{err}");

    let schema = &registry.get("query_record").unwrap().input_schema;
    let facet_schema =
        &schema["properties"]["steps"]["items"]["oneOf"][0]["properties"]["facets"]["items"];
    assert_eq!(facet_schema["oneOf"].as_array().unwrap().len(), 3);
    for operator in [
        "value",
        "eq",
        "ne",
        "lt",
        "lte",
        "gt",
        "gte",
        "in",
        "lt_facet",
        "lte_facet",
        "gt_facet",
        "gte_facet",
    ] {
        assert!(
            facet_schema["properties"].get(operator).is_some(),
            "published schema is missing {operator}"
        );
    }
}

#[tokio::test]
async fn query_record_ne_is_exact_and_in_supports_numeric_and_string_members() {
    let db = db().await;
    let registry = registry();
    task_with_facets(&db, "token-alpha", &[("token", "alpha")]).await;
    task_with_facets(&db, "token-beta", &[("token", "beta")]).await;

    let ne = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{
                "key": "token", "ne": "alpha"
            }] }],
            "order": "name_asc"
        }),
    )
    .await;
    assert_eq!(names_of(&ne["records"]), vec!["token-beta"]);

    for (name, value) in [
        ("mixed-number", "50.0"),
        ("mixed-string", "blue"),
        ("mixed-other-number", "51"),
        ("mixed-nonnumeric", "abc"),
    ] {
        task_with_facets(&db, name, &[("selector", value)]).await;
    }
    let mixed = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "facets": [{
                "key": "selector", "in": [50, "blue"]
            }] }],
            "order": "name_asc"
        }),
    )
    .await;
    assert_eq!(
        names_of(&mixed["records"]),
        vec!["mixed-number", "mixed-string"]
    );
}

fn rollup_envelope(home_id: &str, op: &str, facet_key: Option<&str>) -> String {
    let mut fold = serde_json::Map::new();
    fold.insert("op".into(), json!(op));
    if let Some(key) = facet_key {
        fold.insert("facet_key".into(), json!(key));
    }
    json!({
        "v": "0.1",
        "outputs": {
            "total_spend": {
                "query": { "steps": [{ "step": "filter", "home_id": home_id }] },
                "fold": fold
            }
        }
    })
    .to_string()
}

async fn create_child_with_amount(
    registry: &ToolRegistry,
    db: &Db,
    home_id: &str,
    name: &str,
    amount: Option<Value>,
) -> String {
    let mut args = json!({ "type": "WorkItem", "name": name, "home_id": home_id });
    if let Some(amount) = amount {
        args["facets"] = json!({ "amount": amount });
    }
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// query_record scalar aggregates + stored named rollups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_record_scalar_folds_report_exclusions_and_empty_inputs() {
    let db = db().await;
    let registry = registry();
    let ledger = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "ledger" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    create_child_with_amount(&registry, &db, &ledger, "ten", Some(json!(10))).await;
    create_child_with_amount(&registry, &db, &ledger, "twenty", Some(json!(20))).await;
    create_child_with_amount(&registry, &db, &ledger, "text", Some(json!("unknown"))).await;
    create_child_with_amount(&registry, &db, &ledger, "missing", None).await;

    let query = |op: &str, facet_key: Option<&str>| {
        let mut aggregate = json!({ "op": op });
        if let Some(key) = facet_key {
            aggregate["facet_key"] = json!(key);
        }
        json!({
            "steps": [{ "step": "filter", "home_id": ledger }],
            "aggregate": aggregate
        })
    };

    let count = call(&registry, &db, "query_record", query("count", None)).await;
    assert_eq!(count["value"], 4);
    assert_eq!(count["matched_records"], 4);
    assert_eq!(count["contributing_values"], 4);
    assert_eq!(count["missing_values"], 0);
    assert_eq!(count["non_numeric_values"], 0);

    for (op, expected) in [
        ("sum", json!(30.0)),
        ("avg", json!(15.0)),
        ("min", json!(10.0)),
        ("max", json!(20.0)),
    ] {
        let out = call(&registry, &db, "query_record", query(op, Some("amount"))).await;
        assert_eq!(out["shape"], "aggregate");
        assert_eq!(out["value"], expected, "fold {op}");
        assert_eq!(out["matched_records"], 4);
        assert_eq!(out["contributing_values"], 2);
        assert_eq!(out["missing_values"], 1);
        assert_eq!(out["non_numeric_values"], 1);
    }

    let empty = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "name_contains": "no such expense" }],
            "aggregate": { "op": "sum", "facet_key": "amount" }
        }),
    )
    .await;
    assert_eq!(empty["value"], Value::Null);
    assert_eq!(empty["matched_records"], 0);
    assert_eq!(empty["contributing_values"], 0);
}

#[tokio::test]
async fn aggregates_reject_non_finite_values_and_overflow_but_average_safely() {
    let db = db().await;
    let registry = registry();

    let non_finite_ledger = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "non-finite ledger" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    create_child_with_amount(
        &registry,
        &db,
        &non_finite_ledger,
        "infinite",
        Some(json!("1e999")),
    )
    .await;
    let non_finite_query = json!({
        "steps": [{ "step": "filter", "home_id": non_finite_ledger }],
        "aggregate": { "op": "sum", "facet_key": "amount" }
    });
    let error = call_err(&registry, &db, "query_record", non_finite_query).await;
    assert_eq!(
        error,
        "aggregate 'sum' over facet 'amount' encountered a non-finite numeric value"
    );

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": non_finite_ledger,
            "facets": {
                "rollup": rollup_envelope(&non_finite_ledger, "sum", Some("amount"))
            }
        }),
    )
    .await;
    let address = json!({
        "record_id": non_finite_ledger,
        "rollup_name": "total_spend"
    });
    let first = call_err(&registry, &db, "resolve_rollup", address.clone()).await;
    let second = call_err(&registry, &db, "resolve_rollup", address).await;
    assert_eq!(
        first, second,
        "non-finite evaluation errors are never cached"
    );

    let large_ledger = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "large finite ledger" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    create_child_with_amount(
        &registry,
        &db,
        &large_ledger,
        "large one",
        Some(json!(1e308)),
    )
    .await;
    create_child_with_amount(
        &registry,
        &db,
        &large_ledger,
        "large two",
        Some(json!(1e308)),
    )
    .await;
    let aggregate = |op: &str| {
        json!({
            "steps": [{ "step": "filter", "home_id": large_ledger }],
            "aggregate": { "op": op, "facet_key": "amount" }
        })
    };
    let sum_error = call_err(&registry, &db, "query_record", aggregate("sum")).await;
    assert_eq!(
        sum_error,
        "aggregate 'sum' over facet 'amount' produced a non-finite result"
    );
    let average = call(&registry, &db, "query_record", aggregate("avg")).await;
    assert_eq!(average["value"], json!(1e308));
    assert_eq!(average["contributing_values"], 2);

    let cancellation_ledger = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "cancellation ledger" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (id, amount) in [
        (AGGREGATE_CANCEL_01, 1e308),
        (AGGREGATE_CANCEL_02, 1e308),
        (AGGREGATE_CANCEL_03, -1e308),
    ] {
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id,
                "type": "WorkItem",
                "name": id,
                "home_id": cancellation_ledger,
                "facets": { "amount": amount }
            }),
        )
        .await;
    }
    let cancellation_sum = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "home_id": cancellation_ledger }],
            "aggregate": { "op": "sum", "facet_key": "amount" }
        }),
    )
    .await;
    assert_eq!(cancellation_sum["value"], json!(1e308));
}

#[tokio::test]
async fn aggregate_specs_reject_wrong_fold_arity_paging_and_ordering() {
    let db = db().await;
    let registry = registry();
    for (args, needle) in [
        (
            json!({ "steps": [{ "step": "filter" }], "aggregate": { "op": "sum" } }),
            "requires 'facet_key'",
        ),
        (
            json!({ "steps": [{ "step": "filter" }], "aggregate": { "op": "count", "facet_key": "amount" } }),
            "does not take 'facet_key'",
        ),
        (
            json!({ "steps": [{ "step": "filter" }], "aggregate": { "op": "sum", "facet_key": "amount" }, "limit": 1 }),
            "reject ordering and paging",
        ),
        (
            json!({ "steps": [{ "step": "filter" }], "aggregate": { "op": "sum", "facet_key": "amount" }, "order": "name_asc" }),
            "reject ordering and paging",
        ),
        (
            json!({ "steps": [{ "step": "filter" }], "aggregate": { "op": "median", "facet_key": "amount" } }),
            "unknown variant",
        ),
    ] {
        let error = call_err(&registry, &db, "query_record", args).await;
        assert!(error.contains(needle), "{error}");
    }

    let schema = &registry.get("query_record").unwrap().input_schema;
    assert_eq!(
        schema["properties"]["aggregate"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["aggregate"]["properties"]["op"]["enum"],
        json!(["count", "sum", "avg", "min", "max"])
    );
}

#[tokio::test]
async fn stored_rollups_are_type_agnostic_and_prove_finance_total_without_sql() {
    let db = db().await;
    let registry = registry();
    for record_type in ["Outcome", "Collection"] {
        let bearer = call(
            &registry,
            &db,
            "create_record",
            json!({ "type": record_type, "name": format!("{record_type} ledger") }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let ledger_home = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "Collection",
                "kind": "folder",
                "name": format!("{record_type} ledger entries")
            }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        create_child_with_amount(&registry, &db, &ledger_home, "rent", Some(json!(1250))).await;
        create_child_with_amount(&registry, &db, &ledger_home, "food", Some(json!(87.5))).await;
        call(
            &registry,
            &db,
            "update_record",
            json!({
                "id": bearer,
                "facets": { "rollup": rollup_envelope(&ledger_home, "sum", Some("amount")) }
            }),
        )
        .await;
        let out = call(
            &registry,
            &db,
            "resolve_rollup",
            json!({ "record_id": bearer, "rollup_name": "total_spend" }),
        )
        .await;
        assert_eq!(out["value"], json!(1337.5));
        assert_eq!(out["record_id"], bearer);
        assert_eq!(out["rollup_name"], "total_spend");
        assert_eq!(out["cache_hit"], false);
        let materialised: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_values WHERE record_id = ? AND key = 'total_spend'",
        )
        .bind(&bearer)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(materialised, 0, "derived answers are never written back");
    }
}

#[tokio::test]
async fn reopening_the_database_starts_the_rollup_cache_cold() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rollup.db");
    let url = path.to_string_lossy().into_owned();
    let db = create_database(&url).await.unwrap();
    let registry = registry();
    let bearer = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "restart ledger" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    create_child_with_amount(&registry, &db, &bearer, "expense", Some(json!(7))).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": bearer,
            "facets": { "rollup": rollup_envelope(&bearer, "sum", Some("amount")) }
        }),
    )
    .await;
    let address = json!({ "record_id": bearer, "rollup_name": "total_spend" });
    assert_eq!(
        call(&registry, &db, "resolve_rollup", address.clone()).await["cache_hit"],
        false
    );
    assert_eq!(
        call(&registry, &db, "resolve_rollup", address.clone()).await["cache_hit"],
        true
    );
    db.close().await;

    let reopened = open_database(&url).await.unwrap();
    let after_restart = call(&registry, &reopened, "resolve_rollup", address).await;
    assert_eq!(after_restart["cache_hit"], false);
    assert_eq!(after_restart["value"], json!(7.0));
}

#[tokio::test]
async fn rollup_cache_hits_and_invalidates_on_content_meta_and_spec_digest() {
    let db = db().await;
    let registry = registry();
    let bearer = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "cached ledger" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    create_child_with_amount(&registry, &db, &bearer, "first", Some(json!(10))).await;
    let sum_spec = rollup_envelope(&bearer, "sum", Some("amount"));
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": bearer, "facets": { "rollup": sum_spec } }),
    )
    .await;
    let address = json!({ "record_id": bearer, "rollup_name": "total_spend" });

    let first = call(&registry, &db, "resolve_rollup", address.clone()).await;
    let second = call(&registry, &db, "resolve_rollup", address.clone()).await;
    assert_eq!(first["cache_hit"], false);
    assert_eq!(second["cache_hit"], true);
    assert_eq!(first["revision"], second["revision"]);

    create_child_with_amount(&registry, &db, &bearer, "second", Some(json!(5))).await;
    let content_miss = call(&registry, &db, "resolve_rollup", address.clone()).await;
    assert_eq!(content_miss["cache_hit"], false);
    assert_eq!(content_miss["value"], json!(15.0));
    assert!(
        content_miss["revision"]["content_event_seq"].as_i64()
            > first["revision"]["content_event_seq"].as_i64()
    );

    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "cache-revision-probe" }),
    )
    .await;
    let meta_miss = call(&registry, &db, "resolve_rollup", address.clone()).await;
    assert_eq!(meta_miss["cache_hit"], false);
    assert_eq!(meta_miss["value"], json!(15.0));
    assert!(
        meta_miss["revision"]["meta_event_seq"].as_i64()
            > content_miss["revision"]["meta_event_seq"].as_i64()
    );

    // Bypass the supported write path only to isolate the digest limb: the
    // content/meta revision stays fixed, yet changing the recipe must miss.
    let max_spec = rollup_envelope(&bearer, "max", Some("amount"));
    sqlx::query("UPDATE facet_values SET value = ? WHERE record_id = ? AND key = 'rollup'")
        .bind(max_spec)
        .bind(&bearer)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let digest_miss = call(&registry, &db, "resolve_rollup", address).await;
    assert_eq!(digest_miss["cache_hit"], false);
    assert_eq!(digest_miss["value"], json!(10.0));
    assert_eq!(digest_miss["revision"], meta_miss["revision"]);
    assert_ne!(digest_miss["spec_digest"], meta_miss["spec_digest"]);
}

#[tokio::test]
async fn rollup_cache_misses_when_authorization_narrows_without_content_events() {
    let db = db().await;
    let registry = registry();
    let alice = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Alice cache" }),
    )
    .await
    .unwrap();
    let bea = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Bea cache" }),
    )
    .await
    .unwrap();
    bind_account(&db, &alice, "acct:alice-cache", true).await;
    bind_account(&db, &bea, "acct:bea-cache", true).await;
    let bearer = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Collection", "kind": "folder", "name": "policy cache" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let child = create_child_with_amount(&registry, &db, &bearer, "visible", Some(json!(1))).await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &bearer,
        vec![AllowEntry::account("acct:bea-cache", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &child,
        vec![AllowEntry::account("acct:bea-cache", Capability::View)],
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": bearer,
            "facets": { "rollup": rollup_envelope(&bearer, "count", None) }
        }),
    )
    .await;
    let caller = Caller::authenticated("acct:bea-cache")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let address = json!({ "record_id": bearer, "rollup_name": "total_spend" });
    let first = call_as(
        &registry,
        &db,
        caller.clone(),
        "resolve_rollup",
        address.clone(),
    )
    .await;
    let cached = call_as(
        &registry,
        &db,
        caller.clone(),
        "resolve_rollup",
        address.clone(),
    )
    .await;
    assert_eq!(first["value"], 1);
    assert_eq!(first["cache_hit"], false);
    assert_eq!(cached["cache_hit"], true);
    let content_before = native_ce::query::events::content_high_water(&db)
        .await
        .unwrap();
    let epoch_before: i64 =
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &child,
        vec![AllowEntry::account("acct:alice-cache", Capability::Manage)],
    )
    .await
    .unwrap();
    assert_eq!(
        native_ce::query::events::content_high_water(&db)
            .await
            .unwrap(),
        content_before
    );
    let epoch_after: i64 =
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(epoch_after > epoch_before);
    let narrowed = call_as(&registry, &db, caller, "resolve_rollup", address).await;
    assert_eq!(narrowed["cache_hit"], false);
    assert_eq!(narrowed["value"], 0);
}

#[tokio::test]
async fn rollup_cache_separates_trusted_local_from_authenticated_local_in_both_orders() {
    let db = db().await;
    let registry = registry();
    let person = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Local credential account" }),
    )
    .await
    .unwrap();
    bind_account(&db, &person, "local", true).await;
    let authenticated_local = Caller::authenticated("local");

    for trusted_first in [true, false] {
        let bearer = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "Collection",
                "kind": "folder",
                "name": format!("trusted-local cache boundary {trusted_first}")
            }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let visible =
            create_child_with_amount(&registry, &db, &bearer, "visible", Some(json!(1))).await;
        let hidden =
            create_child_with_amount(&registry, &db, &bearer, "hidden", Some(json!(1))).await;
        replace_explicit_policy(
            &db,
            "test:policy",
            &bearer,
            vec![AllowEntry::account("local", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &visible,
            vec![AllowEntry::account("local", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &hidden,
            vec![AllowEntry::account("acct:other", Capability::Manage)],
        )
        .await
        .unwrap();
        call(
            &registry,
            &db,
            "update_record",
            json!({
                "id": bearer,
                "facets": { "rollup": rollup_envelope(&bearer, "count", None) }
            }),
        )
        .await;
        let address = json!({ "record_id": bearer, "rollup_name": "total_spend" });

        let (first, second) = if trusted_first {
            (
                call(&registry, &db, "resolve_rollup", address.clone()).await,
                call_as(
                    &registry,
                    &db,
                    authenticated_local.clone(),
                    "resolve_rollup",
                    address.clone(),
                )
                .await,
            )
        } else {
            (
                call_as(
                    &registry,
                    &db,
                    authenticated_local.clone(),
                    "resolve_rollup",
                    address.clone(),
                )
                .await,
                call(&registry, &db, "resolve_rollup", address.clone()).await,
            )
        };
        assert_eq!(first["cache_hit"], false);
        assert_eq!(
            second["cache_hit"], false,
            "authorization contexts must miss"
        );
        if trusted_first {
            assert_eq!(first["value"], 2);
            assert_eq!(second["value"], 1);
        } else {
            assert_eq!(first["value"], 1);
            assert_eq!(second["value"], 2);
        }

        let repeated = if trusted_first {
            call_as(
                &registry,
                &db,
                authenticated_local.clone(),
                "resolve_rollup",
                address,
            )
            .await
        } else {
            call(&registry, &db, "resolve_rollup", address).await
        };
        assert_eq!(repeated["cache_hit"], true);
        assert_eq!(repeated["value"], second["value"]);
    }
}

#[tokio::test]
async fn invalid_stored_rollup_errors_are_repeatable_and_never_become_results() {
    let db = db().await;
    let registry = registry();
    let bearer = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "name": "bad recipe bearer",
            "facets": {
                "rollup": json!({
                    "v": "0.1",
                    "outputs": {
                        "total_spend": {
                            "query": { "steps": [{ "step": "filter" }], "limit": 1 },
                            "fold": { "op": "sum", "facet_key": "amount" }
                        }
                    }
                }).to_string()
            }
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let address = json!({ "record_id": bearer, "rollup_name": "total_spend" });
    let first = call_err(&registry, &db, "resolve_rollup", address.clone()).await;
    let second = call_err(&registry, &db, "resolve_rollup", address).await;
    assert!(first.contains("unknown field `limit`"), "{first}");
    assert_eq!(
        first, second,
        "errors remain errors and are not cached as values"
    );

    for (raw, needle) in [
        (
            json!({ "v": "0.2", "outputs": {} }).to_string(),
            "unsupported rollup envelope version",
        ),
        (
            json!({ "v": "0.1", "outputs": {} }).to_string(),
            "must not be empty",
        ),
        ("7".to_string(), "invalid rollup envelope"),
    ] {
        call(
            &registry,
            &db,
            "update_record",
            json!({ "id": bearer, "facets": { "rollup": raw } }),
        )
        .await;
        let error = call_err(
            &registry,
            &db,
            "resolve_rollup",
            json!({ "record_id": bearer, "rollup_name": "total_spend" }),
        )
        .await;
        assert!(error.contains(needle), "{error}");
    }
}

// ---------------------------------------------------------------------------
// Tool 17 — search. The bound and the other two Layer-1 mechanisms live here
// (see tests/records/search_semantics.rs, module docs).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_with_enough_hits_stays_strict() {
    let db = db().await;
    let registry = registry();
    for i in 0..THIN_RESULTS_THRESHOLD {
        task(&db, &format!("meeting notes {i}")).await;
    }
    let out = call(&registry, &db, "search", json!({ "query": "meeting" })).await;
    assert_eq!(out["total"], THIN_RESULTS_THRESHOLD);
    assert_eq!(out["thin"], false);
    assert!(
        out.get("near_misses").is_none() && out.get("guidance").is_none(),
        "at or above the threshold the strict results stand alone: {out}"
    );
}

#[tokio::test]
async fn thin_search_surfaces_infix_near_misses_and_prompts_reformulation() {
    let db = db().await;
    let registry = registry();
    // ea7e5bd's worked example: one unicode61 token, unreachable by FTS.
    task(&db, "DetailRecordLayout").await;

    let out = call(
        &registry,
        &db,
        "search",
        json!({ "query": "detail record layout" }),
    )
    .await;
    assert_eq!(out["total"], 0);
    assert_eq!(out["thin"], true);
    assert_eq!(
        names_of(&out["near_misses"]["name_infix"]),
        vec!["DetailRecordLayout"],
        "the LIKE pass must reach the camelCase identifier"
    );
    let guidance = out["guidance"].as_str().unwrap();
    assert!(guidance.contains("No full-text matches"), "{guidance}");
    assert!(guidance.contains("reformulat"), "{guidance}");
    assert!(guidance.contains("near_misses"), "{guidance}");
}

#[tokio::test]
async fn thin_search_surfaces_prefix_neighbours_from_the_unstemmed_sibling() {
    let db = db().await;
    let registry = registry();
    task(&db, "Running totals").await;

    // Porter stems the index ("running" → "run"), so the stem-truncated typed
    // prefix "runni" matches nothing in records_fts — the unstemmed sibling is
    // what repairs it (3c40677).
    let out = call(&registry, &db, "search", json!({ "query": "runni" })).await;
    assert_eq!(out["total"], 0);
    assert_eq!(
        names_of(&out["near_misses"]["name_prefix"]),
        vec!["Running totals"]
    );
}

#[tokio::test]
async fn thin_search_surfaces_tree_siblings_of_partial_hits() {
    let db = db().await;
    let registry = registry();
    let parent = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Sprint 12" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Fix the flux capacitor", "home_id": parent }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Recalibrate the deflector", "home_id": parent }),
    )
    .await
    .unwrap();

    let out = call(&registry, &db, "search", json!({ "query": "capacitor" })).await;
    assert_eq!(out["total"], 1);
    assert_eq!(out["thin"], true);
    assert_eq!(
        names_of(&out["near_misses"]["tree_siblings"]),
        vec!["Recalibrate the deflector"],
        "siblings of the hit, excluding the hit itself"
    );
}

#[tokio::test]
async fn search_redacts_an_unreadable_parent_but_keeps_private_structure_for_near_misses() {
    let db = db().await;
    let registry = registry();
    let parent = create_record(
        &db,
        json!({ "id": HIDDEN_PARENT, "type": "Collection", "kind": "folder", "name": "Hidden parent" }),
    )
    .await
    .unwrap();
    let children = [
        (STRICT_CHILD, "Needle child"),
        (PREFIX_CHILD, "PrefixSecretChild"),
        (INFIX_CHILD, "InfixSecretChild"),
        (SIBLING_CHILD, "Visible structural sibling"),
    ];
    for (id, name) in children {
        create_record(
            &db,
            json!({ "id": id, "type": "WorkItem", "kind": "task", "name": name, "home_id": parent }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        "test:policy",
        &parent,
        vec![AllowEntry::account("alice", Capability::View)],
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("bea");

    let strict = call_as(
        &registry,
        &db,
        bea.clone(),
        "search",
        json!({ "query": "needle" }),
    )
    .await;
    assert_eq!(strict["hits"][0]["home_id"], Value::Null);
    let siblings = strict["near_misses"]["tree_siblings"].as_array().unwrap();
    assert!(siblings.iter().any(|row| row["id"] == SIBLING_CHILD));
    assert!(siblings.iter().all(|row| row["home_id"].is_null()));

    let prefix = call_as(
        &registry,
        &db,
        bea.clone(),
        "search",
        json!({ "query": "prefixsecr" }),
    )
    .await;
    assert_eq!(
        prefix["near_misses"]["name_prefix"][0]["home_id"],
        Value::Null
    );

    let infix = call_as(
        &registry,
        &db,
        bea,
        "search",
        json!({ "query": "secret child" }),
    )
    .await;
    assert!(infix["near_misses"]["name_infix"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["home_id"].is_null()));
}

#[tokio::test]
async fn near_misses_deduplicate_against_hits_and_each_other() {
    let db = db().await;
    let registry = registry();
    // Matches strict FTS ("layout" is a token), AND the prefix pass, AND the
    // infix pass — it must appear exactly once, as a strict hit.
    task(&db, "Layout survey").await;

    let out = call(&registry, &db, "search", json!({ "query": "layout" })).await;
    assert_eq!(names_of(&out["hits"]), vec!["Layout survey"]);
    assert_eq!(out["thin"], true);
    let near = &out["near_misses"];
    for mechanism in ["name_prefix", "name_infix", "tree_siblings"] {
        assert_eq!(
            near[mechanism].as_array().unwrap().len(),
            0,
            "{mechanism} must not repeat the strict hit"
        );
    }
}

#[tokio::test]
async fn near_miss_mechanisms_cap_their_rows() {
    let db = db().await;
    let registry = registry();
    // 15 camelCase names, every one infix-only: the pass must stop at the cap.
    for i in 0..15 {
        task(&db, &format!("GadgetWidget{i:02}Frame")).await;
    }
    let out = call(
        &registry,
        &db,
        "search",
        json!({ "query": "gadget widget" }),
    )
    .await;
    assert_eq!(out["total"], 0);
    let infix = out["near_misses"]["name_infix"].as_array().unwrap();
    assert_eq!(
        infix.len() as i64,
        NEAR_MISS_CAP,
        "near-misses are a prompt, not a page: cap at {NEAR_MISS_CAP}"
    );
}

#[tokio::test]
async fn tree_sibling_near_misses_stay_sql_bounded_with_a_large_visible_family() {
    let db = db().await;
    let registry = registry();
    let parent = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Large family" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Unique capacitor target", "home_id": parent }),
    )
    .await
    .unwrap();
    for index in 0..250 {
        create_record(
            &db,
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": format!("Sibling {index:03}"),
                "home_id": parent
            }),
        )
        .await
        .unwrap();
    }

    let out = call(&registry, &db, "search", json!({ "query": "capacitor" })).await;
    let siblings = out["near_misses"]["tree_siblings"].as_array().unwrap();
    assert_eq!(siblings.len() as i64, NEAR_MISS_CAP);
    assert_eq!(siblings[0]["name"], "Sibling 000");
    assert_eq!(siblings[9]["name"], "Sibling 009");
}

#[tokio::test]
async fn search_scopes_strict_hits_and_near_misses_to_the_subtree() {
    let db = db().await;
    let registry = registry();
    let here = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Here" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "DetailRecordLayout", "home_id": here }),
    )
    .await
    .unwrap();
    // Same names outside the scope — neither may leak in.
    task(&db, "DetailRecordLayout").await;
    task(&db, "detail record layout notes").await;

    let out = call(
        &registry,
        &db,
        "search",
        json!({ "query": "detail record layout", "scope": here }),
    )
    .await;
    assert_eq!(out["total"], 0, "the FTS-reachable copy is out of scope");
    let infix = out["near_misses"]["name_infix"].as_array().unwrap();
    assert_eq!(infix.len(), 1);
    assert_eq!(infix[0]["home_id"], json!(here));
}

#[tokio::test]
async fn tree_siblings_of_the_scope_root_stay_inside_the_scope() {
    let db = db().await;
    let registry = registry();
    // The scope root is itself the (thin) strict hit. Its tree siblings sit
    // OUTSIDE the requested subtree and must not leak into the payload.
    let parent = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Programme" }),
    )
    .await
    .unwrap();
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Scoped capacitor", "home_id": parent }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Unrelated sibling", "home_id": parent }),
    )
    .await
    .unwrap();

    let out = call(
        &registry,
        &db,
        "search",
        json!({ "query": "capacitor", "scope": root }),
    )
    .await;
    assert_eq!(out["total"], 1, "the scope root itself matches");
    assert_eq!(
        out["near_misses"]["tree_siblings"].as_array().unwrap(),
        &Vec::<Value>::new(),
        "the root's siblings are outside the scope and must not surface"
    );
}

#[tokio::test]
async fn search_rejects_empty_queries() {
    let db = db().await;
    let registry = registry();
    let err = call_err(&registry, &db, "search", json!({ "query": "   " })).await;
    assert!(err.contains("'query' must be non-empty"), "{err}");
}

// ---------------------------------------------------------------------------
// Tool 18 — query_sql
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_sql_runs_validated_selects() {
    let db = db().await;
    let registry = registry();
    task(&db, "only record").await;
    let out = call(
        &registry,
        &db,
        "query_sql",
        json!({ "sql": "SELECT name, type FROM records ORDER BY name" }),
    )
    .await;
    assert_eq!(out["columns"], json!(["name", "type"]));
    assert_eq!(out["row_count"], 3);
    assert_eq!(out["truncated"], false);
    assert_eq!(
        out["rows"][2],
        json!({ "name": "only record", "type": "WorkItem" })
    );
}

#[tokio::test]
async fn query_sql_accepts_lossless_typed_positional_parameters() {
    let db = db().await;
    let registry = registry();
    let out = call(
        &registry,
        &db,
        "query_sql",
        json!({
            "sql": "SELECT ?1 AS integer_value, ?2 AS bytes_value, ?3 AS json_value, ?4 AS timestamp_value",
            "parameters": [
                {"type":"integer", "value":"9223372036854775807"},
                {"type":"bytes", "value":"AP8="},
                {"type":"json", "value":"{\"stable\":true}"},
                {"type":"timestamp", "value":"2026-08-10T12:00:00Z"}
            ]
        }),
    )
    .await;
    assert_eq!(out["row_count"], 1);
    assert_eq!(
        out["rows"][0]["integer_value"],
        json!(9223372036854775807_i64)
    );
    assert_eq!(out["rows"][0]["bytes_value"], "AP8=");
    assert_eq!(out["rows"][0]["json_value"], r#"{"stable":true}"#);
    assert_eq!(out["rows"][0]["timestamp_value"], "2026-08-10T12:00:00Z");
}

#[tokio::test]
async fn query_sql_requires_value_for_every_parameter_tag() {
    let db = db().await;
    let registry = registry();
    for tag in [
        "boolean",
        "integer",
        "real",
        "text",
        "bytes",
        "json",
        "timestamp",
    ] {
        let err = call_err(
            &registry,
            &db,
            "query_sql",
            json!({ "sql": "SELECT ?1", "parameters": [{ "type": tag }] }),
        )
        .await;
        assert!(
            err.starts_with(
                "query_sql [invalid_arguments]: invalid arguments for query_sql: missing field `value`"
            ),
            "{tag}: {err}"
        );
    }
}

#[tokio::test]
async fn query_sql_rejects_duplicate_output_labels() {
    let db = db().await;
    let registry = registry();
    let err = call_err(
        &registry,
        &db,
        "query_sql",
        json!({"sql":"SELECT 1 AS duplicate, 2 AS duplicate"}),
    )
    .await;
    assert!(err.contains("duplicate_columns"), "{err}");
}

#[tokio::test]
async fn query_sql_rejections_surface_the_validator_messages() {
    let db = db().await;
    let registry = registry();
    let err = call_err(
        &registry,
        &db,
        "query_sql",
        json!({ "sql": "DELETE FROM records" }),
    )
    .await;
    assert!(err.contains("read-only"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "query_sql",
        json!({ "sql": "SELECT * FROM sqlite_master" }),
    )
    .await;
    assert!(
        err.contains("prohibited") || err.contains("not authorized"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Tool 19 — scan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_reports_census_axes_and_convergence() {
    let db = db().await;
    let registry = registry();
    let hub = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Everything hub" }),
    )
    .await
    .unwrap();
    for i in 0..3 {
        let id = create_record(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": format!("hub task {i}"), "home_id": hub }),
        )
        .await
        .unwrap();
        add_link(&db, link(&id, &hub, "mentions")).await.unwrap();
    }
    let archived = task(&db, "archived noise").await;
    archive_record(&db, &archived).await.unwrap();

    let out = call(
        &registry,
        &db,
        "scan",
        json!({ "query": "hub", "high_degree_min": 3 }),
    )
    .await;

    // Corpus: the two engine filing folders, the authored folder and 3 tasks;
    // the archived record is out.
    assert_eq!(out["corpus_size"], 6);
    let by_type = out["census"]["by_type"]["buckets"].as_array().unwrap();
    assert!(by_type.contains(&json!({ "key": "WorkItem", "count": 3 })));
    assert!(by_type.contains(&json!({ "key": "Collection", "count": 3 })));

    // Every axis carries the full pool count plus a bounded sample.
    let lexical = &out["axes"]["lexical"];
    assert_eq!(lexical["count"], 4, "all four names carry 'hub'");
    assert_eq!(lexical["samples"].as_array().unwrap().len(), 3);
    assert_eq!(lexical["quality"], "saturated");
    assert!(lexical["samples"][0]["score"].is_number());
    assert!(lexical["samples"][0]["snippet"].is_string());

    let recent = &out["axes"]["recent"];
    assert_eq!(recent["count"], 6, "all just created");
    assert!(recent["samples"][0]["last_activity_at"].is_string());

    let degree = &out["axes"]["high_degree"];
    assert_eq!(degree["count"], 1, "only the hub has >= 3 links");
    assert_eq!(degree["samples"][0]["name"], "Everything hub");
    assert_eq!(degree["samples"][0]["degree"], 3);

    let containers = &out["axes"]["containers"];
    assert_eq!(containers["count"], 3);
    assert_eq!(containers["samples"][0]["name"], "Everything hub");
    assert_eq!(containers["samples"][0]["child_count"], 3);

    // The hub surfaces on several axes' samples — convergence describes it.
    let convergence = out["convergence"].as_array().unwrap();
    let converged_hub = convergence
        .iter()
        .find(|record| record["id"] == hub)
        .expect("hub converges");
    assert_eq!(converged_hub["type"], "Collection");
    assert_eq!(converged_hub["name"], "Everything hub");
    assert_eq!(
        converged_hub["axis_count"].as_u64().unwrap(),
        converged_hub["axes"].as_array().unwrap().len() as u64
    );
    assert!(converged_hub["axis_count"].as_u64().unwrap() >= 2);
}

#[tokio::test]
async fn scan_orders_convergence_by_axis_count_then_name_then_id() {
    let db = db().await;
    let registry = registry();

    let alpha = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Alpha" }),
    )
    .await
    .unwrap();
    let beta = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Beta" }),
    )
    .await
    .unwrap();
    let gamma = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Gamma" }),
    )
    .await
    .unwrap();

    for (parent, child_name) in [
        (&alpha, "alpha child"),
        (&beta, "beta child"),
        (&gamma, "gamma child"),
    ] {
        create_record(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": child_name, "home_id": parent }),
        )
        .await
        .unwrap();
    }
    add_link(&db, link(&alpha, &beta, "mentions"))
        .await
        .unwrap();
    add_link(&db, link(&alpha, &gamma, "mentions"))
        .await
        .unwrap();

    // Put the collections at the recent sample head without changing any
    // axis's production query count.
    for (id, timestamp) in [
        (&alpha, "2099-01-03T00:00:00.000Z"),
        (&beta, "2099-01-02T00:00:00.000Z"),
        (&gamma, "2099-01-01T00:00:00.000Z"),
    ] {
        sqlx::query("UPDATE records SET last_activity_at = ? WHERE id = ?")
            .bind(timestamp)
            .bind(id)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
    }

    let out = call(
        &registry,
        &db,
        "scan",
        json!({ "query": "Alpha", "high_degree_min": 1 }),
    )
    .await;
    let convergence = out["convergence"].as_array().unwrap();
    assert_eq!(
        convergence
            .iter()
            .map(|record| (
                record["name"].as_str().unwrap(),
                record["axis_count"].as_u64().unwrap()
            ))
            .collect::<Vec<_>>(),
        vec![("Alpha", 4), ("Beta", 3), ("Gamma", 2)]
    );

    // Tie-breaking by id is observable when names match.
    sqlx::query("UPDATE records SET name = 'Same' WHERE id IN (?, ?)")
        .bind(&beta)
        .bind(&gamma)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let out = call(
        &registry,
        &db,
        "scan",
        json!({ "query": "Alpha", "high_degree_min": 1 }),
    )
    .await;
    let tied_ids = out["convergence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["name"] == "Same")
        .map(|record| record["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(tied_ids, {
        let mut ids = vec![beta.as_str(), gamma.as_str()];
        ids.sort_unstable();
        ids
    });
}

#[tokio::test]
async fn scan_lexical_pool_count_is_not_capped_by_the_sample_fetch() {
    let db = db().await;
    let registry = registry();
    // More matches than any fetch limit: the axis promises the FULL pool
    // count beside the bounded sample.
    for i in 0..205 {
        task(&db, &format!("widget {i}")).await;
    }
    let out = call(&registry, &db, "scan", json!({ "query": "widget" })).await;
    let lexical = &out["axes"]["lexical"];
    assert_eq!(lexical["count"], 205, "pool count must be uncapped");
    assert_eq!(lexical["samples"].as_array().unwrap().len(), 3);
    let sample = &lexical["samples"][0];
    assert!(sample.get("lifecycle").is_none());
    assert_eq!(
        sample["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
}

#[tokio::test]
async fn scan_gates_lexical_on_query_and_validates_scope() {
    let db = db().await;
    let registry = registry();
    task(&db, "solo").await;

    let out = call(&registry, &db, "scan", json!({})).await;
    assert!(
        out["axes"].get("lexical").is_none(),
        "no query, no lexical axis"
    );
    assert_eq!(out["axes"]["recent"]["quality"], "saturated");

    let err = call_err(&registry, &db, "scan", json!({ "scope": "nope" })).await;
    assert!(err.contains("scope record nope does not exist"), "{err}");

    let err = call_err(&registry, &db, "scan", json!({ "recent_window_days": 0 })).await;
    assert!(err.contains("recent_window_days"), "{err}");
}

#[tokio::test]
async fn scan_provenance_distinguishes_every_origin_class() {
    const YOU: &str = "acct_11111111111111111111111111111111";
    const OTHER: &str = "acct_22222222222222222222222222222222";
    const UNBOUND: &str = "acct_33333333333333333333333333333333";

    let db = db().await;
    let registry = registry();

    let you_person = create_record_as(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "You" }),
        Some(YOU),
    )
    .await
    .unwrap();
    bind_account(&db, &you_person, YOU, true).await;
    bind_account(&db, &you_person, "catalog-you", false).await;
    let other_person = create_record_as(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Other" }),
        Some(OTHER),
    )
    .await
    .unwrap();
    bind_account(&db, &other_person, OTHER, true).await;

    create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Yours" }),
        Some(YOU),
    )
    .await
    .unwrap();
    create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Your legacy alias" }),
        Some("catalog-you"),
    )
    .await
    .unwrap();
    create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Theirs" }),
        Some(OTHER),
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::authenticated(YOU),
        "create_record",
        json!({
            "id": AGENT_WORK,
            "type": "WorkItem",
            "kind": "task",
            "name": "Agent work",
            "run_key": "scout-chair-a748b2",
        }),
    )
    .await;
    let ingested = create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Imported" }),
        None,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier)
         VALUES (?, 'github', 'issue:42')",
    )
    .bind(&ingested)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "No actor" }),
    )
    .await
    .unwrap();
    create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Legacy local" }),
        Some("local"),
    )
    .await
    .unwrap();
    create_record_as(
        &db,
        json!({ "id": UNBOUND_WORK, "type": "WorkItem", "kind": "task", "name": "Unbound token" }),
        Some(UNBOUND),
    )
    .await
    .unwrap();

    let out = call_as(
        &registry,
        &db,
        Caller::authenticated(YOU),
        "scan",
        json!({}),
    )
    .await;
    let buckets = out["census"]["provenance"]["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|bucket| {
            (
                bucket["key"].as_str().unwrap(),
                bucket["count"].as_i64().unwrap(),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(out["census"]["provenance"]["total"], 12);
    assert_eq!(buckets.get("you"), Some(&3));
    assert_eq!(buckets.get("other_account"), Some(&2));
    assert_eq!(buckets.get("agent"), Some(&1));
    assert_eq!(buckets.get("ingested"), Some(&1));
    assert_eq!(buckets.get("unknown"), Some(&5));

    let unbound_caller = call_as(
        &registry,
        &db,
        Caller::authenticated(UNBOUND),
        "scan",
        json!({ "scope": UNBOUND_WORK }),
    )
    .await;
    assert_eq!(
        unbound_caller["census"]["provenance"]["buckets"],
        json!([{ "key": "unknown", "count": 1 }]),
        "raw equality with the caller is not identity without an account binding"
    );
}

#[tokio::test]
async fn scan_authored_by_defaults_selects_orders_and_affects_convergence() {
    const YOU: &str = "acct_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ALIAS: &str = "legacy-catalog-user";
    const OTHER: &str = "acct_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let db = db().await;
    let registry = registry();
    let you_person = create_record_as(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "You" }),
        Some(YOU),
    )
    .await
    .unwrap();
    bind_account(&db, &you_person, YOU, true).await;
    bind_account(&db, &you_person, ALIAS, false).await;
    let other_person = create_record_as(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Other" }),
        Some(OTHER),
    )
    .await
    .unwrap();
    bind_account(&db, &other_person, OTHER, true).await;

    let caller = Caller::authenticated(YOU);
    for (id, name) in [
        (AUTHORED_1, "Authored one"),
        (AUTHORED_2, "Authored two"),
        (AUTHORED_3, "Authored three"),
        (AUTHORED_4, "Authored four"),
    ] {
        call_as(
            &registry,
            &db,
            caller.clone(),
            "create_record",
            json!({ "id": id, "type": "WorkItem", "kind": "task", "name": name }),
        )
        .await;
    }
    create_record_as(
        &db,
        json!({ "id": LEGACY_AUTHORED, "type": "WorkItem", "kind": "task", "name": "Legacy authored" }),
        Some(ALIAS),
    )
    .await
    .unwrap();
    create_record_as(
        &db,
        json!({ "id": OTHER_AUTHORED, "type": "WorkItem", "kind": "task", "name": "Other authored" }),
        Some(OTHER),
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        caller.clone(),
        "update_record",
        json!({ "id": AUTHORED_1, "summary": "Newest attributed event" }),
    )
    .await;

    let out = call_as(
        &registry,
        &db,
        caller.clone(),
        "scan",
        json!({ "query": "Authored" }),
    )
    .await;
    let authored = &out["axes"]["authored_by"];
    assert_eq!(authored["count"], 6, "person + four current + legacy alias");
    assert_eq!(authored["samples"].as_array().unwrap().len(), 3);
    assert_eq!(authored["samples"][0]["id"], AUTHORED_1);
    assert!(authored["samples"][0]["authored_at"].is_string());
    let convergence = out["convergence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == AUTHORED_1)
        .expect("newest authored record converges");
    assert!(convergence["axes"]
        .as_array()
        .unwrap()
        .contains(&json!("authored_by")));

    let other = call_as(
        &registry,
        &db,
        caller,
        "scan",
        json!({ "authored_by": OTHER }),
    )
    .await;
    assert_eq!(other["axes"]["authored_by"]["count"], 2);

    let other_tasks = call_as(
        &registry,
        &db,
        Caller::authenticated(YOU),
        "scan",
        json!({ "authored_by": OTHER, "types": ["WorkItem"] }),
    )
    .await;
    assert_eq!(other_tasks["axes"]["authored_by"]["count"], 1);

    let err = registry
        .call(
            db.clone(),
            Caller::authenticated(YOU),
            "scan",
            json!({ "authored_by": "acct_cccccccccccccccccccccccccccccccc" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("must be an account token present in this file"));
}
