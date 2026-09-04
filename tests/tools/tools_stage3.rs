//! Stage 3 of the tool surface (tools 1–10): orientation & record lifecycle —
//! exercised through the registry, the way both transports dispatch.

use native_ce::conformance::rebuild_and_diff;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::create_vocabulary;
use native_ce::schema::{DDL_STATEMENTS, FROZEN_DDL_SHA256};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic.
/// `public-recent`
const PUBLIC_RECENT: &str = "700c3000-0000-4000-8000-000000000001";
/// `private-recent`
const PRIVATE_RECENT: &str = "700c3000-0000-4000-8000-000000000002";
/// `person:richard`
const PERSON_RICHARD: &str = "700c3000-0000-4000-8000-000000000003";
/// `atomic-1`
const ATOMIC_1: &str = "700c3000-0000-4000-8000-000000000004";

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

/// Create a record through the TOOL (not `store`) and return its id.
async fn create(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    let out = call(registry, db, "create_record", args).await;
    out["id"].as_str().unwrap().to_string()
}

fn body_digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stage3_tools_register_in_surface_order() {
    let registry = registry();
    let names: Vec<&str> = registry.specs().map(|t| t.name.as_str()).collect();
    let expected = [
        "bootstrap",
        "get_structure",
        "get_dashboard",
        "describe_schema",
        "quickstart",
        "read_guide",
        "create_record",
        "get_record",
        "update_record",
        "claim_unowned_record",
        "correct_record_type",
        "delete_record",
        "archive_record",
        "render_record",
    ];
    assert_eq!(
        &names[..14],
        &expected,
        "orientation, QuickStart, recovery, and record lifecycle tools lead the surface"
    );
}

/// Every window argument a handler accepts must be in the advertised schema.
/// The schemas set `additionalProperties: false`, so an argument missing from
/// one is an argument no contract-driven caller can send — the bound would ship
/// with no way to page past it. Asserting the schema alone would not prove
/// much, so each is also exercised end to end through the registry.
#[tokio::test]
async fn window_arguments_are_advertised_and_accepted() {
    let db = db().await;
    let registry = registry();

    let schema_of = |name: &str| {
        registry
            .specs()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("{name} not registered"))
            .input_schema
            .clone()
    };

    for (tool, args) in [
        (
            "get_record",
            vec![
                "children_limit",
                "children_offset",
                "links_limit",
                "links_offset",
                "include_suggestions",
                "suggestions_limit",
                "suggestions_offset",
            ],
        ),
        ("get_structure", vec!["max_children_per_node"]),
    ] {
        let schema = schema_of(tool);
        assert_eq!(
            schema["additionalProperties"], false,
            "{tool}: the closed schema is the reason this test exists"
        );
        for arg in args {
            assert!(
                schema["properties"][arg].is_object(),
                "{tool} accepts `{arg}` but does not advertise it"
            );
        }
    }

    // End to end: the arguments reach the handler and change the answer.
    let wide = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Wide" }),
    )
    .await;
    for i in 0..5 {
        create(
            &registry,
            &db,
            json!({ "type": "WorkItem", "name": format!("Child {i}"), "home_id": wide }),
        )
        .await;
    }

    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [wide], "children_limit": 2, "children_offset": 1, "links_limit": 0 }),
    )
    .await;
    let record = &out["records"][0];
    assert_eq!(record["children"].as_array().unwrap().len(), 2);
    assert_eq!(record["child_count"], 5);
    assert_eq!(record["children"][0]["name"], "Child 1", "offset applied");
    assert_eq!(out["children_limit"], 2, "the window is echoed back");

    let out = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": wide, "max_depth": 1, "max_children_per_node": 2 }),
    )
    .await;
    assert_eq!(
        out["nodes"].as_array().unwrap().len(),
        3,
        "root + 2 children"
    );
    assert_eq!(
        out["nodes"][0]["child_count"], 5,
        "the total still tells the truth"
    );
    assert_eq!(out["max_children_per_node"], 2, "the cap is echoed back");

    // And the ceiling rejects rather than clamps, through the tool.
    let err = call_err(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [wide], "children_limit": 100_000 }),
    )
    .await;
    assert!(err.contains("children limit must be <="), "{err}");
}

// ---------------------------------------------------------------------------
// Tool 1 — bootstrap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_returns_only_bounded_first_call_context() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Work" }),
    )
    .await;
    create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "child", "home_id": root }),
    )
    .await;
    let archived = create(&registry, &db, json!({ "type": "WorkItem", "name": "old" })).await;
    call(&registry, &db, "archive_record", json!({ "id": archived })).await;
    create_vocabulary(&db, "moods", Some("vocab-1"))
        .await
        .unwrap();

    let out = call(&registry, &db, "bootstrap", json!({})).await;
    let mut keys = out.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        [
            "contract",
            "current_world",
            "diagnostics",
            "engine",
            "instructions",
            "intentful_sessions",
            "next_steps",
            "orientation",
            "pending_obligations",
            "principal",
            "roots",
            "run",
            "session",
            "standing_context",
            "tool_exposure",
            "workspace"
        ]
    );
    assert_eq!(out["contract"]["version"], "native.bootstrap.v3");
    assert_eq!(out["contract"]["intent_agnostic"], true);
    assert_eq!(
        out["intentful_sessions"]["boundaries"][0]["statement"],
        "Bootstrap does not accept or resolve intent."
    );
    assert_eq!(
        out["intentful_sessions"]["boundaries"][1]["statement"],
        "set_intent is a separate call that declares intent and returns the purpose-relative briefing."
    );
    assert!(out["intentful_sessions"]["boundaries"][2]["statement"]
        .as_str()
        .unwrap()
        .contains("new declaration window while preserving earlier run history"));
    assert_eq!(out["session"]["run_key"], out["run"]["run_key"]);
    assert_eq!(out["session"]["whole_run_rollback"], false);
    assert!(out["orientation"]["content"]
        .as_str()
        .unwrap()
        .starts_with("# Working in Native"));
    assert_eq!(out["engine"]["name"], "native-ce");
    assert_eq!(
        out["engine"]["schema_version"],
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION
    );
    assert_eq!(
        out["engine"]["user_version"],
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION
    );
    let mut engine_keys = out["engine"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    engine_keys.sort();
    assert_eq!(
        engine_keys,
        ["name", "schema_version", "user_version", "version"]
    );
    for removed in [
        "counts",
        "spine",
        "schema_config",
        "vocabularies",
        "kind_registry",
    ] {
        assert!(
            out.get(removed).is_none(),
            "removed block {removed} returned"
        );
    }
    // The only root window is canonical and directly expandable.
    let roots = out["roots"]["items"].as_array().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["id"], json!(native_ce::schema::ROOT_RECORD_ID));
    assert_eq!(roots[0]["child_count"], 1);
    assert_eq!(out["roots"]["total"], 1);
    assert_eq!(out["roots"]["continuation"]["tool"], "get_structure");
    assert_eq!(
        out["roots"]["continuation"]["arguments"]["root_id"],
        native_ce::schema::ROOT_RECORD_ID
    );
    let fixed = &out["instructions"]["entries"][0];
    assert_eq!(fixed["scope"], "engine");
    assert_eq!(fixed["kind"], "fixed");
    assert_eq!(fixed["source"]["type"], "engine");
    assert_eq!(fixed["source"]["template_version"], 8);
    assert!(fixed["source"].get("record_id").is_none());
    assert!(fixed["content"]
        .as_str()
        .unwrap()
        .contains("Other principals and agents"));
    assert!(fixed["content"]
        .as_str()
        .unwrap()
        .contains("live, shared world"));
    assert!(fixed["content"]
        .as_str()
        .unwrap()
        .contains("make material execution"));
    assert!(fixed["content"]
        .as_str()
        .unwrap()
        .contains("A record makes the work resumable"));
    assert!(fixed["content"]
        .as_str()
        .unwrap()
        .contains("and periodically otherwise"));
    assert!(fixed["content"]
        .as_str()
        .unwrap()
        .contains("current boundary, material result or decision"));
    assert_eq!(out["workspace"]["primary_workspace"]["id"], "native:root");
    assert!(out["workspace"]["records_visible"].as_u64().is_some());
    assert!(
        out["current_world"]["recent_activity"]["items"]
            .as_array()
            .unwrap()
            .len()
            <= 3
    );
    for item in out["current_world"]["recent_activity"]["items"]
        .as_array()
        .unwrap()
    {
        assert!(item.get("lifecycle").is_none(), "{item:#}");
        assert!(item.get("lifecycle_interpretation").is_some(), "{item:#}");
    }
    let continuation_tools = out["next_steps"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["tool"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(continuation_tools.contains(&"set_intent"));
    assert!(continuation_tools.contains(&"get_dashboard"));
    assert!(continuation_tools.contains(&"get_structure"));
    let recent_step = out["next_steps"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["tool"] == "get_record")
        .expect("recent caller-visible activity should be inspectable");
    assert_eq!(recent_step["label"], "Inspect recent activity");
    assert!(recent_step["why"]
        .as_str()
        .unwrap()
        .contains("decide whether it is relevant"));
    for step in out["next_steps"]["items"].as_array().unwrap() {
        let tool = step["tool"].as_str().unwrap();
        let spec = registry
            .specs()
            .find(|spec| spec.name == tool)
            .unwrap_or_else(|| panic!("bootstrap suggested unregistered tool {tool}"));
        let arguments = step["arguments"].as_object().unwrap();
        for required in spec.input_schema["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{tool} schema has no required array"))
        {
            let required = required.as_str().unwrap();
            assert!(
                arguments.contains_key(required),
                "bootstrap omitted required argument {required} for {tool}"
            );
        }
        assert_eq!(
            arguments.get("run_key").and_then(Value::as_str),
            out["session"]["run_key"].as_str(),
            "{tool} continuation detached from first-class session"
        );
        assert_eq!(
            arguments.get("run_key").and_then(Value::as_str),
            out["run"]["run_key"].as_str(),
            "{tool} continuation detached from compatibility run"
        );
        for argument in arguments.keys() {
            assert!(
                spec.input_schema["properties"][argument].is_object(),
                "bootstrap suggested unknown argument {argument} for {tool}"
            );
        }
    }
    let err = call_err(&registry, &db, "bootstrap", json!({ "nope": 1 })).await;
    assert!(err.contains("invalid arguments for bootstrap"));
    let err = call_err(
        &registry,
        &db,
        "bootstrap",
        json!({ "intent": "must remain separate" }),
    )
    .await;
    assert!(err.contains("invalid arguments for bootstrap"));
}

#[tokio::test]
async fn bootstrap_omits_an_exact_lifecycle_envelope_that_cannot_fit_its_item_bound() {
    let db = db().await;
    let registry = registry();
    native_ce::meta::create_vocabulary(&db, "oversized-preview-lifecycle", None)
        .await
        .unwrap();
    let value_id = native_ce::meta::propose_value_with_metadata_as(
        &db,
        "oversized-preview-lifecycle",
        "current",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &value_id)
        .await
        .unwrap();
    native_ce::meta::write_user_schema_config(
        &db,
        json!({
            "shapes": { "Document": { "facets": { "lifecycle": {
                "vocab_ref": "oversized-preview-lifecycle",
                "axis": { "key": "document_state", "label": "x".repeat(2048) }
            }}}}
        }),
        native_ce::meta::SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let record_id = create(
        &registry,
        &db,
        json!({
            "type": "Document", "kind": "note", "name": "Oversized preview",
            "lifecycle": "current"
        }),
    )
    .await;

    let out = call(&registry, &db, "bootstrap", json!({})).await;
    let current_world = &out["current_world"];
    assert_eq!(current_world["omitted_unrepresentable_count"], 1);
    assert!(!current_world.to_string().contains(&record_id));
    assert!(
        serde_json::to_vec(current_world).unwrap().len()
            <= native_ce::mcp::tools::orientation::MAX_BOOTSTRAP_CURRENT_WORLD_BYTES
    );
}

#[tokio::test]
async fn bootstrap_rejects_a_noncanonical_parentless_forest() {
    let db = db().await;
    let registry = registry();
    sqlx::query(
        "INSERT INTO records(id,type,kind,name,policy_anchor_id) \
         VALUES('rogue-root','Collection','folder','Rogue','native:root')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let error = call_err(&registry, &db, "bootstrap", json!({})).await;
    assert!(
        error.contains("canonical-root invariant violated"),
        "{error}"
    );
}

#[tokio::test]
async fn large_corpus_changes_only_bounded_bootstrap_facts_and_previews() {
    let db = db().await;
    let registry = registry();
    let longest_handle = native_ce::wordlist::HANDLES
        .iter()
        .max_by_key(|word| word.len())
        .unwrap();
    let longest_disambiguator = native_ce::wordlist::DISAMBIGUATORS
        .iter()
        .max_by_key(|word| word.len())
        .unwrap();
    let maximal_run_key = format!("{longest_handle}-{longest_disambiguator}-zzzzzz");
    let args = json!({ "run_key": maximal_run_key });
    let before = call(&registry, &db, "bootstrap", args.clone()).await;

    sqlx::query(
        "WITH RECURSIVE sequence(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM sequence WHERE n<1000) \
         INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) \
         SELECT printf('unrelated-%04d',n),'Document','note','Unrelated','native:unfiled','native:root' FROM sequence",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let after = call(&registry, &db, "bootstrap", args).await;
    assert_eq!(before["run"], after["run"]);
    assert_eq!(before["orientation"], after["orientation"]);
    assert_eq!(before["instructions"], after["instructions"]);
    assert_eq!(after["workspace"]["records_visible"], 1002);
    assert_eq!(after["current_world"]["scan_limit"], 64);
    assert_eq!(after["current_world"]["scan_truncated"], true);
    assert_eq!(after["current_world"]["recent_activity"]["total_count"], 64);
    assert_eq!(
        after["current_world"]["recent_activity"]["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(after["current_world"]["recent_activity"]["truncated"], true);
    let bytes = serde_json::to_vec(&after).unwrap().len();
    let engine_bytes = serde_json::to_vec(&after["engine"]).unwrap().len();
    let run_bytes = serde_json::to_vec(&after["run"]).unwrap().len();
    let root_bytes = serde_json::to_vec(&after["roots"]).unwrap().len();
    let instruction_bytes = serde_json::to_vec(&after["instructions"]).unwrap().len();
    assert!(
        bytes <= native_ce::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES,
        "bounded bootstrap is {bytes} bytes (engine={engine_bytes}, run={run_bytes}, roots={root_bytes}, instructions={instruction_bytes}); limit={} bytes",
        native_ce::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES,
    );
}

#[tokio::test]
async fn bootstrap_uses_verified_portable_principal_identity_and_qualifies_time_and_counts() {
    let db = db().await;
    let registry = registry();
    let person = create(
        &registry,
        &db,
        json!({
            "id": PERSON_RICHARD,
            "type": "Entity",
            "kind": "person",
            "name": "Richard Ng",
            "home_id": native_ce::schema::UNFILED_RECORD_ID,
        }),
    )
    .await;
    for (system, identifier, canonical) in [
        ("account", "acct:richard", 1),
        ("email", "obsolete@example.com", 0),
        ("email", "richard@example.com", 1),
    ] {
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,?)",
        )
        .bind(&person)
        .bind(system)
        .bind(identifier)
        .bind(canonical)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:richard"),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(out["principal"]["person_record_id"], person);
    assert_eq!(out["principal"]["display_name"], "Richard Ng");
    assert_eq!(out["principal"]["email"], "richard@example.com");
    assert!(out["principal"]["local_timezone"].is_null());
    assert_eq!(
        out["principal"]["local_time_status"],
        "unknown: no verified principal timezone is available in native-ce"
    );
    assert!(out["principal"]["utc_datetime"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    assert_eq!(out["workspace"]["registered_humans_visible"], 1);
    assert!(out["workspace"]["human_count_qualification"]
        .as_str()
        .unwrap()
        .contains("not proof of an exhaustive roster"));
}

#[tokio::test]
async fn bootstrap_reuses_the_run_but_keeps_intent_declaration_and_briefing_separate() {
    let db = db().await;
    let registry = registry();
    let held = "scout-chair-a748b2";

    let before = call(&registry, &db, "bootstrap", json!({ "run_key": held })).await;
    assert_eq!(before["run"]["run_key"], held);
    assert_eq!(
        before["intentful_sessions"]["intent_declared_for_run"],
        false
    );
    assert!(before["next_steps"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step["tool"] == "set_intent"));

    let declaration = call(
        &registry,
        &db,
        "set_intent",
        json!({
            "run_key": held,
            "intent": "Evaluate the representative Native bootstrap"
        }),
    )
    .await;
    assert_eq!(
        declaration["accepted_intent"],
        "Evaluate the representative Native bootstrap"
    );
    assert!(declaration["briefing"].is_object());

    let after = call(&registry, &db, "bootstrap", json!({ "run_key": held })).await;
    assert_eq!(after["run"]["run_key"], held);
    assert_eq!(after["intentful_sessions"]["intent_declared_for_run"], true);
    assert!(after["next_steps"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["tool"] != "set_intent"));
    assert!(after.get("briefing").is_none());
}

#[tokio::test]
async fn bootstrap_current_world_is_caller_visible_and_does_not_leak_private_activity() {
    let db = db().await;
    let registry = registry();
    let public = create(
        &registry,
        &db,
        json!({ "id": PUBLIC_RECENT, "type": "Document", "name": "Public recent" }),
    )
    .await;
    let private = create(
        &registry,
        &db,
        json!({ "id": PRIVATE_RECENT, "type": "Document", "name": "Private recent" }),
    )
    .await;
    sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
        .bind(&private)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET policy_anchor_id=? WHERE id=?")
        .bind(&private)
        .bind(&private)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES(?,'account','local','allow','manage')",
    )
    .bind(&private)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:outsider"),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    let ids = out["current_world"]["recent_activity"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(ids.contains(&public.as_str()));
    assert!(!ids.contains(&private.as_str()));
    assert_eq!(
        out["current_world"]["scope"],
        "bounded preview, not a complete dashboard or claim of omniscience"
    );
}

// ---------------------------------------------------------------------------
// Tool 2 — get_structure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_structure_walks_depth_limited_with_counts() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "r" }),
    )
    .await;
    let mid = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "mid", "home_id": root }),
    )
    .await;
    let leaf = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "leaf", "home_id": mid }),
    )
    .await;
    let hidden = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "hidden", "home_id": root }),
    )
    .await;
    call(&registry, &db, "archive_record", json!({ "id": hidden })).await;

    // Depth 1: root + mid only, but mid still reports its truncated child.
    let out = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 1 }),
    )
    .await;
    let nodes = out["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2, "archived child skipped, leaf beyond depth");
    assert_eq!(nodes[1]["id"], json!(mid));
    assert_eq!(
        nodes[1]["child_count"], 1,
        "count visible at the depth limit"
    );

    // include_archived brings the archived child back.
    let out = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 1, "include_archived": true }),
    )
    .await;
    assert_eq!(out["nodes"].as_array().unwrap().len(), 3);

    let err = call_err(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": "missing" }),
    )
    .await;
    assert!(err.contains("does not exist"));
    let err = call_err(&registry, &db, "delete_record", json!({ "id": mid })).await;
    assert!(err.contains("still has live homed members"));
    call(&registry, &db, "delete_record", json!({ "id": leaf })).await;
    call(&registry, &db, "delete_record", json!({ "id": mid })).await;
    let err = call_err(&registry, &db, "get_structure", json!({ "root_id": mid })).await;
    assert!(err.contains("tombstoned"));
}

#[tokio::test]
async fn get_structure_exclude_types_prunes_before_counts_and_cap() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "r" }),
    )
    .await;
    let doc = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "a-doc", "home_id": root }),
    )
    .await;
    let task = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "c-task", "home_id": root }),
    )
    .await;
    let sub = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "sub", "home_id": root }),
    )
    .await;
    let buried = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "buried", "home_id": sub }),
    )
    .await;

    // Unfiltered behavior is preserved: everything appears.
    let out = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 3 }),
    )
    .await;
    let ids: Vec<String> = out["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["id"].as_str().unwrap().to_string())
        .collect();
    for expected in [&root, &doc, &task, &sub, &buried] {
        assert!(ids.contains(expected), "missing {expected} in {ids:?}");
    }

    // Excluding Document removes matching children at every visited level:
    // `sub` stays (it is a Collection) but reports zero children.
    let out = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 3, "exclude_types": ["Document"] }),
    )
    .await;
    let nodes = out["nodes"].as_array().unwrap().clone();
    let ids: Vec<&str> = nodes
        .iter()
        .map(|node| node["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&root.as_str()));
    assert!(ids.contains(&task.as_str()));
    assert!(ids.contains(&sub.as_str()));
    assert!(!ids.contains(&doc.as_str()), "excluded type still present");
    assert!(
        !ids.contains(&buried.as_str()),
        "excluded subtree not pruned"
    );
    let root_node = nodes.iter().find(|node| node["id"] == root).unwrap();
    assert_eq!(
        root_node["child_count"], 2,
        "count must describe the filtered walk"
    );
    let sub_node = nodes.iter().find(|node| node["id"] == sub).unwrap();
    assert_eq!(sub_node["child_count"], 0);

    // An excluded parent is pruned as a whole subtree. The non-excluded
    // Document beneath `sub` must not be re-parented or leaked into the walk.
    let pruned = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 3, "exclude_types": ["Collection"] }),
    )
    .await;
    let pruned_ids: Vec<&str> = pruned["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["id"].as_str().unwrap())
        .collect();
    assert!(!pruned_ids.contains(&sub.as_str()));
    assert!(!pruned_ids.contains(&buried.as_str()));
    assert_eq!(pruned["nodes"][0]["child_count"], 2);

    // Filtering runs before the sibling cap: the Document sorts first by
    // (name, id), so an unfiltered cap of 2 keeps the Document, while the
    // filtered cap of 2 still returns both non-excluded children. Filtering
    // after the cap would leave only one.
    let capped = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 1, "max_children_per_node": 2 }),
    )
    .await;
    let capped_ids: Vec<&str> = capped["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|node| node["id"] != root)
        .map(|node| node["id"].as_str().unwrap())
        .collect();
    assert_eq!(capped_ids.len(), 2);
    let filtered = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "max_depth": 1, "max_children_per_node": 2, "exclude_types": ["Document"] }),
    )
    .await;
    let filtered_ids: Vec<&str> = filtered["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|node| node["id"] != root)
        .map(|node| node["id"].as_str().unwrap())
        .collect();
    assert_eq!(filtered_ids.len(), 2, "exclusion must run before the cap");
    assert!(filtered_ids.contains(&task.as_str()));
    assert!(filtered_ids.contains(&sub.as_str()));
    assert_eq!(
        filtered["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["id"] == root)
            .unwrap()["child_count"],
        2
    );

    // The root is emitted even when its own type is excluded — pointing at a
    // record is asking for it, the same rule archived records follow.
    let out = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": doc, "exclude_types": ["Document"] }),
    )
    .await;
    assert_eq!(out["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(out["nodes"][0]["id"], json!(doc));

    // Unknown types are caller bugs, not silent empty filters.
    let err = call_err(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": root, "exclude_types": ["NotAType"] }),
    )
    .await;
    assert!(err.contains("not a spine type"), "{err}");
}

// ---------------------------------------------------------------------------
// Tool 3 — get_dashboard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_dashboard_buckets_active_stale_and_blocked() {
    let db = db().await;
    let registry = registry();
    let active = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "fresh", "lifecycle": "in_progress" }),
    )
    .await;
    // A stale record: projected directly with an old timestamp (projection-only
    // fixture — dashboard reads projections, not the log).
    crate::common::project_one(
        &db,
        &crate::common::ev(
            "stale-1",
            "record.created",
            "2020-01-01T00:00:00.000Z",
            json!({ "type": "WorkItem", "kind": "task", "name": "dusty", "lifecycle": "in_progress", "home_id": native_ce::schema::UNFILED_RECORD_ID }),
        ),
    )
    .await
    .unwrap();
    // No lifecycle → in neither active nor stale.
    create(&registry, &db, json!({ "type": "Document", "name": "doc" })).await;

    let blocker = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "blocker" }),
    )
    .await;
    let blocked = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "waiting", "links": [
            { "target_id": blocker, "relationship": "depends_on" }
        ]}),
    )
    .await;

    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    let ids = |bucket: &str| -> Vec<String> {
        out[bucket]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(ids("active").contains(&active));
    assert_eq!(ids("stale"), vec!["stale-1".to_string()]);
    assert_eq!(ids("blocked"), vec![blocked.clone()]);
    let entry = &out["blocked"][0];
    assert!(entry.get("lifecycle").is_none());
    assert_eq!(
        entry["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
    assert_eq!(entry["waiting_on"][0]["id"], json!(blocker));
    assert_eq!(out["lifecycle_census"]["shape"], "counts");

    // Archiving the blocker releases the block.
    call(&registry, &db, "archive_record", json!({ "id": blocker })).await;
    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    assert!(out["blocked"].as_array().unwrap().is_empty());

    // An incoming `blocks` edge blocks too.
    let gate = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "gate" }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": gate, "name": "gate" }),
    )
    .await; // touch only
    call(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "add",
            "source_id": gate,
            "target_id": active,
            "relationship": "blocks"
        }),
    )
    .await;
    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    let entry = &out["blocked"][0];
    assert_eq!(entry["id"], json!(active));
    assert_eq!(entry["blocked_by"][0]["id"], json!(gate));

    // Scope restricts every bucket.
    let scoped = call(&registry, &db, "get_dashboard", json!({ "scope": blocked })).await;
    assert!(scoped["blocked"].as_array().unwrap().is_empty());
    assert_eq!(scoped["active"][0]["id"], json!(blocked));

    let err = call_err(
        &registry,
        &db,
        "get_dashboard",
        json!({ "scope": "missing" }),
    )
    .await;
    assert!(err.contains("does not exist"));
    let err = call_err(&registry, &db, "get_dashboard", json!({ "limit": 0 })).await;
    assert!(err.contains("'limit'"));
    let err = call_err(
        &registry,
        &db,
        "get_dashboard",
        json!({ "stale_after_days": 0 }),
    )
    .await;
    assert!(err.contains("stale_after_days"));
}

#[tokio::test]
async fn get_dashboard_stale_keeps_the_oldest_when_limited() {
    let db = db().await;
    let registry = registry();
    // Three stale fixtures, distinct ages; a limited stale bucket must keep
    // the OLDEST (most neglected), not the newest of the stale.
    for (id, ts) in [
        ("stale-new", "2022-01-01T00:00:00.000Z"),
        ("stale-mid", "2021-01-01T00:00:00.000Z"),
        ("stale-old", "2020-01-01T00:00:00.000Z"),
    ] {
        crate::common::project_one(
            &db,
            &crate::common::ev(
                id,
                "record.created",
                ts,
                json!({ "type": "WorkItem", "kind": "task", "name": id, "lifecycle": "open", "home_id": native_ce::schema::UNFILED_RECORD_ID }),
            ),
        )
        .await
        .unwrap();
    }
    let out = call(&registry, &db, "get_dashboard", json!({ "limit": 2 })).await;
    let stale: Vec<&str> = out["stale"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(stale, vec!["stale-old", "stale-mid"]);

    // Unbounded staleness floors are an argument error, not a panic.
    let err = call_err(
        &registry,
        &db,
        "get_dashboard",
        json!({ "stale_after_days": i64::MAX }),
    )
    .await;
    assert!(err.contains("stale_after_days"));
}

/// Lifecycle must GOVERN the attention split, not merely gate entry to it.
/// Finished work leaves `active` and `stale` entirely; what "finished" means
/// is the record's effective vocabulary's answer, never a token list here.
#[tokio::test]
async fn get_dashboard_excludes_governed_terminal_lifecycles_from_attention() {
    let db = db().await;
    let registry = registry();
    let mut recent = std::collections::HashMap::new();
    for (name, lifecycle) in [
        ("recent open", "open"),
        ("recent in progress", "in_progress"),
        ("recent completed", "completed"),
        ("recent closed", "closed"),
    ] {
        recent.insert(
            name,
            create(
                &registry,
                &db,
                json!({ "type": "WorkItem", "kind": "task", "name": name, "lifecycle": lifecycle }),
            )
            .await,
        );
    }
    // Long-untouched fixtures, projected directly: `closed` is the OLDEST, so
    // if terminality were ignored it would lead the oldest-first stale bucket.
    for (id, ts, lifecycle) in [
        ("dusty-closed", "2019-01-01T00:00:00.000Z", "closed"),
        ("dusty-completed", "2019-06-01T00:00:00.000Z", "completed"),
        ("dusty-open", "2020-01-01T00:00:00.000Z", "open"),
    ] {
        crate::common::project_one(
            &db,
            &crate::common::ev(
                id,
                "record.created",
                ts,
                json!({ "type": "WorkItem", "kind": "task", "name": id, "lifecycle": lifecycle, "home_id": native_ce::schema::UNFILED_RECORD_ID }),
            ),
        )
        .await
        .unwrap();
    }

    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    let ids = |bucket: &str| -> Vec<String> {
        out[bucket]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap().to_string())
            .collect()
    };
    let active = ids("active");
    assert!(active.contains(&recent["recent open"]), "{active:?}");
    assert!(active.contains(&recent["recent in progress"]), "{active:?}");
    assert!(!active.contains(&recent["recent completed"]), "{active:?}");
    assert!(!active.contains(&recent["recent closed"]), "{active:?}");
    assert_eq!(out["active_total"], 2);

    // Only the still-open dusty record is neglect. The closed one is not
    // merely demoted — it is absent, so it cannot lead the list.
    assert_eq!(ids("stale"), vec!["dusty-open".to_string()]);
    assert_eq!(out["stale_total"], 1);
    for bucket in ["active", "stale"] {
        assert!(
            !ids(bucket).iter().any(|id| id.starts_with("dusty-c")),
            "{bucket}: {:?}",
            ids(bucket)
        );
    }
    // Every record here is governed, so the gap census stays empty — the
    // exclusion above came from terminality, not from a classification miss.
    assert_eq!(out["unclassified_lifecycle"]["total_count"], 0);
}

/// A terminal token introduced by a KIND's own vocabulary must take effect
/// with no edit to the dashboard. Two kinds give the same raw token opposite
/// meanings; the buckets have to follow the effective schema, not the string.
#[tokio::test]
async fn get_dashboard_honours_kind_specific_terminality_without_token_literals() {
    use native_ce::meta::{
        promote_value, propose_value_with_metadata_as, write_user_schema_config,
        SchemaConfigOptions, VocabularyValueTerminality,
    };
    let db = db().await;
    let registry = registry();
    crate::common::govern_kind(&db, "WorkItem", "kind-open").await;
    crate::common::govern_kind(&db, "WorkItem", "kind-terminal").await;
    for vocabulary in ["kind-open-lifecycle", "kind-terminal-lifecycle"] {
        create_vocabulary(&db, vocabulary, Some(&format!("voc:{vocabulary}")))
            .await
            .unwrap();
    }
    for (vocabulary, terminality) in [
        ("kind-open-lifecycle", VocabularyValueTerminality::Open),
        (
            "kind-terminal-lifecycle",
            VocabularyValueTerminality::TerminalPositive,
        ),
    ] {
        let value =
            propose_value_with_metadata_as(&db, vocabulary, "ready", None, 1.0, terminality, None)
                .await
                .unwrap();
        promote_value(&db, &value).await.unwrap();
    }
    write_user_schema_config(
        &db,
        json!({
            "shapes": {
                "WorkItem:kind-open": {
                    "facets": { "lifecycle": {
                        "axis": { "key": "kind_status", "label": "Kind status" },
                        "vocab_ref": "rec:voc:kind-open-lifecycle"
                    } }
                },
                "WorkItem:kind-terminal": {
                    "facets": { "lifecycle": {
                        "axis": { "key": "kind_status", "label": "Kind status" },
                        "vocab_ref": "rec:voc:kind-terminal-lifecycle"
                    } }
                }
            }
        }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let still_open = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "kind-open", "name": "same token, open", "lifecycle": "ready" }),
    )
    .await;
    let finished = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "kind-terminal", "name": "same token, done", "lifecycle": "ready" }),
    )
    .await;

    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    let active: Vec<&str> = out["active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    assert!(active.contains(&still_open.as_str()), "{active:?}");
    assert!(!active.contains(&finished.as_str()), "{active:?}");
}

/// Epics use the same declared work-status axis as tasks. Existing valid raw
/// values therefore enter the ordinary attention split, while terminal epics
/// leave it, without appearing in the governance-gap census.
#[tokio::test]
async fn get_dashboard_treats_epics_as_governed_work_and_honours_terminality() {
    let db = db().await;
    let registry = registry();
    let in_progress_epic = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "epic", "name": "active epic", "lifecycle": "in_progress" }),
    )
    .await;
    let completed_epic = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "epic", "name": "completed epic", "lifecycle": "completed" }),
    )
    .await;
    let open_task = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "open task", "lifecycle": "open" }),
    )
    .await;
    // Existing rows are interpreted through today's pack without a rewrite.
    for (id, timestamp, lifecycle) in [
        ("dusty-epic", "2020-01-01T00:00:00.000Z", "in_progress"),
        ("dusty-closed-epic", "2019-01-01T00:00:00.000Z", "closed"),
    ] {
        crate::common::project_one(
            &db,
            &crate::common::ev(
                id,
                "record.created",
                timestamp,
                json!({
                    "type": "WorkItem",
                    "kind": "epic",
                    "name": id,
                    "lifecycle": lifecycle,
                    "home_id": native_ce::schema::UNFILED_RECORD_ID
                }),
            ),
        )
        .await
        .unwrap();
    }

    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    let ids = |bucket: &str| -> Vec<String> {
        out[bucket]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap().to_string())
            .collect()
    };
    let active = ids("active");
    assert!(active.contains(&in_progress_epic), "{active:?}");
    assert!(active.contains(&open_task), "{active:?}");
    assert!(!active.contains(&completed_epic), "{active:?}");
    assert_eq!(ids("stale"), vec!["dusty-epic".to_string()]);
    assert!(!ids("stale").contains(&"dusty-closed-epic".to_string()));
    let epic_entry = out["active"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == in_progress_epic)
        .unwrap();
    assert_eq!(
        epic_entry["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
    assert_eq!(
        epic_entry["lifecycle_interpretation"]["terminality"],
        "open"
    );
    assert_eq!(out["unclassified_lifecycle"]["total_count"], 0);
}

/// A lifecycle the engine cannot interpret is reported with its reason, and a
/// single uninterpretable record neither empties nor fails the dashboard.
#[tokio::test]
async fn get_dashboard_reports_uninterpretable_lifecycles_without_emptying_itself() {
    let db = db().await;
    let registry = registry();
    let governed = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "governed", "lifecycle": "open" }),
    )
    .await;
    // Ordinary authoring now rejects this shape. Model retained imported
    // evidence through the explicit historical projection seam instead.
    let ungoverned = "historical-ungoverned-lifecycle".to_string();
    crate::common::project_one(
        &db,
        &crate::common::ev(
            &ungoverned,
            "record.created",
            "2099-01-01T00:00:00.000Z",
            json!({
                "type": "Collection",
                "kind": "folder",
                "name": "ungoverned lifecycle",
                "lifecycle": "ready",
                "persistence": "enduring",
                "home_id": native_ce::schema::UNFILED_RECORD_ID
            }),
        ),
    )
    .await
    .unwrap();
    // Governed, but carrying a token the vocabulary does not admit — the
    // shape a historical or corrupt projection leaves behind.
    let unknown_value = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "unknown token", "lifecycle": "open" }),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = 'ready' WHERE id = ?")
        .bind(&unknown_value)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    let active: Vec<&str> = out["active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    // All three are attention: the two uninterpretable ones are not punished
    // for the gap, and the governed open one is unaffected by their presence.
    for id in [&governed, &ungoverned, &unknown_value] {
        assert!(active.contains(&id.as_str()), "{id}: {active:?}");
    }
    let census = &out["unclassified_lifecycle"];
    assert_eq!(census["total_count"], 2);
    let items = census["items"].as_array().unwrap();
    for (id, reason) in [
        (&ungoverned, "no_governing_vocabulary"),
        (&unknown_value, "unknown_or_inactive_value"),
    ] {
        let entry = items
            .iter()
            .find(|entry| entry["id"] == json!(id))
            .unwrap_or_else(|| panic!("{id} missing: {items:?}"));
        assert_eq!(entry["reason"], json!(reason));
        assert!(entry.get("lifecycle").is_none());
        assert_eq!(entry["lifecycle_interpretation"]["status"], "unclassified");
        assert_eq!(entry["lifecycle_interpretation"]["raw"], "ready");
    }

    // A reader of the rendered output can tell it happened — and cannot read
    // the census as a place the records went instead.
    let text = native_ce::mcp::render::render("get_dashboard", &out).unwrap();
    assert!(
        text.contains("Unclassified lifecycle (2 of 2 shown)"),
        "{text}"
    );
    assert!(text.contains("these records are listed above"), "{text}");
    assert!(text.contains("no_governing_vocabulary"), "{text}");
    assert!(text.contains("unknown_or_inactive_value"), "{text}");
}

/// The invariants the attention rework must not disturb: the census obeys the
/// same per-call bound and the same subtree scope as the buckets it annotates.
#[tokio::test]
async fn get_dashboard_unclassified_census_respects_scope_and_bounds() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "scope root", "persistence": "enduring" }),
    )
    .await;
    let mut inside = Vec::new();
    for index in 0..3 {
        let id = format!("historical-unclassified-inside-{index}");
        crate::common::project_one(
            &db,
            &crate::common::ev(
                &id,
                "record.created",
                "2020-01-01T00:00:00.000Z",
                json!({
                    "type": "Collection",
                    "kind": "folder",
                    "name": format!("inside {index}"),
                    "lifecycle": "ready",
                    "persistence": "enduring",
                    "home_id": root,
                }),
            ),
        )
        .await
        .unwrap();
        inside.push(id);
    }
    let outside = "historical-unclassified-outside".to_string();
    crate::common::project_one(
        &db,
        &crate::common::ev(
            &outside,
            "record.created",
            "2020-01-01T00:00:00.000Z",
            json!({
                "type": "Collection",
                "kind": "folder",
                "name": "outside",
                "lifecycle": "ready",
                "persistence": "enduring",
                "home_id": native_ce::schema::UNFILED_RECORD_ID
            }),
        ),
    )
    .await
    .unwrap();

    let out = call(&registry, &db, "get_dashboard", json!({})).await;
    assert_eq!(out["unclassified_lifecycle"]["total_count"], 4);
    assert_eq!(out["unclassified_lifecycle"]["truncated"], false);

    // Bounded like every other window: the total still reports the truth.
    let bounded = call(&registry, &db, "get_dashboard", json!({ "limit": 2 })).await;
    assert_eq!(
        bounded["unclassified_lifecycle"]["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(bounded["unclassified_lifecycle"]["total_count"], 4);
    assert_eq!(bounded["unclassified_lifecycle"]["truncated"], true);

    let scoped = call(&registry, &db, "get_dashboard", json!({ "scope": root })).await;
    let scoped_ids: Vec<&str> = scoped["unclassified_lifecycle"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    assert_eq!(scoped["unclassified_lifecycle"]["total_count"], 3);
    assert!(!scoped_ids.contains(&outside.as_str()), "{scoped_ids:?}");
    for id in &inside {
        assert!(scoped_ids.contains(&id.as_str()), "{scoped_ids:?}");
    }
}

// ---------------------------------------------------------------------------
// Tool 4 — describe_schema
// ---------------------------------------------------------------------------

#[tokio::test]
async fn describe_schema_classifies_tables_by_authority() {
    let db = db().await;
    let registry = registry();
    let out = call(&registry, &db, "describe_schema", json!({})).await;
    assert_eq!(out["engine"]["ddl_fingerprint"], FROZEN_DDL_SHA256);
    assert_eq!(
        out["engine"]["user_version"],
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION
    );
    assert_eq!(
        out["model"],
        "event-authoritative: `content_events` plus its identity-preserving \
         `content_event_sources` provenance are authoritative for the content projections \
         (`records`, `links`, `facet_values`, `facet_observations`, `annotation_targets`, \
         `message_audience_state`, `message_audiences`, `message_conversations`, \
         `module_releases`, `module_release_imports`, `recipe_releases`, \
         `recipe_release_input_classes`, `artifact_source_attestations`, \
         `artifact_inputs`, `artifact_module_grants`); \
         `meta_events` is \
         authoritative for the meta projections (`vocabularies`, `vocabulary_values`, \
         `schema_config`); `policy_events` is authoritative for portable policy; \
         `control_events` is authoritative for portable member, instruction, and onboarding \
         control state; `derivation_events` is authoritative for stable derivation series, \
         immutable revisions, exact input manifests and failed attempts; projections are \
         rebuilt by replay and must never be written directly"
    );
    let tables = out["tables"].as_array().unwrap();
    assert_eq!(tables.len(), native_ce::schema::REQUIRED_TABLES.len());
    let role_of = |name: &str| -> String {
        tables
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("table {name} missing"))["role"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let facet_values = tables
        .iter()
        .find(|table| table["name"] == "facet_values")
        .expect("facet_values table");
    assert!(
        facet_values["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|column| column["name"] == "value_num" && column["type"] == "REAL"),
        "describe_schema must expose the generated numeric projection"
    );
    for (table_name, column_name, semantic_role, portability) in [
        (
            "content_events",
            "seq",
            "database_local_replay_position",
            "non_portable",
        ),
        (
            "content_events",
            "id",
            "portable_event_identity",
            "portable",
        ),
        (
            "content_event_sources",
            "source_seq",
            "origin_replay_position",
            "portable_with_origin_database_id",
        ),
    ] {
        let column = tables
            .iter()
            .find(|table| table["name"] == table_name)
            .unwrap()["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|column| column["name"] == column_name)
            .unwrap();
        assert_eq!(column["semantic_role"], semantic_role);
        assert_eq!(column["portability"], portability);
    }
    // Three authoritative logs, and each tier's tables classified as projections of
    // its own log (ba9f97e). `vocabularies` moving from meta/system to projection
    // is the whole decision in one assertion: the meta tier is no longer
    // direct-write state sitting outside any log.
    assert_eq!(role_of("content_events"), "authoritative");
    assert_eq!(
        role_of("content_event_sources"),
        "authoritative source provenance (immutable companion to content_events)"
    );
    assert_eq!(role_of("meta_events"), "authoritative");
    assert_eq!(role_of("policy_events"), "authoritative");
    assert_eq!(role_of("control_events"), "authoritative");
    assert_eq!(role_of("derivation_events"), "authoritative");
    // The read log announces its own disposability in the orientation surface —
    // a caller tempted to build on these rows should learn from the schema
    // description that they may simply not be there.
    for table in ["read_log_calls", "read_log_touches"] {
        assert!(
            role_of(table).contains("disposable"),
            "{table} must describe itself as disposable"
        );
    }
    assert!(role_of("records").starts_with("projection"));
    assert!(role_of("facet_observations").starts_with("projection"));
    assert!(role_of("annotation_targets").starts_with("projection"));
    for table in [
        "message_audience_state",
        "message_audiences",
        "message_conversations",
        "module_releases",
        "module_release_imports",
        "artifact_source_attestations",
        "artifact_inputs",
        "artifact_module_grants",
    ] {
        assert_eq!(
            role_of(table),
            "projection (rebuildable from content_events; never write directly)",
            "{table} must be classified as content-event-derived engine state"
        );
    }
    assert_eq!(
        role_of("derivation_requests"),
        "substrate (durable operational derivation coordination, direct-write with fenced leases)"
    );
    for table in [
        "derivation_series",
        "derivation_revisions",
        "derivation_revision_inputs",
        "derivation_attempts",
        "derivation_target_bindings",
        "derivation_target_publications",
        "derivation_selected_publications",
        "derivation_target_heads",
        "derivation_event_applications",
    ] {
        assert_eq!(
            role_of(table),
            "projection (rebuildable from derivation_events; never write directly)"
        );
    }
    assert!(role_of("vocabularies").starts_with("projection"));
    assert!(role_of("schema_config").starts_with("projection"));
    assert!(role_of("blobs").starts_with("substrate"));
    assert_eq!(
        role_of("bindings"),
        "substrate (durable external-identity mappings, direct-write by design)"
    );
    assert!(role_of("binding_audit").contains("append-only"));
    assert!(role_of("external_observations").contains("qualified"));
    assert!(role_of("database_identity").contains("portable database identity"));
    for table in ["record_policies", "policy_entries"] {
        assert_eq!(
            role_of(table),
            "projection (rebuildable from policy_events; never write directly)"
        );
    }
    for table in [
        "member_contexts",
        "instruction_bindings",
        "onboarding_programmes",
        "onboarding_programme_sources",
        "member_obligations",
        "seeded_instruction_sources",
        "control_event_applications",
    ] {
        assert_eq!(
            role_of(table),
            "projection (rebuildable from control_events; never write directly)"
        );
    }
    assert!(role_of("authorization_revision").contains("cache-invalidation"));
    assert_eq!(
        role_of("jobs"),
        "substrate (transient operational state, direct-write by design)"
    );
    assert!(role_of("records_fts").starts_with("derived index"));
    let events_table = tables
        .iter()
        .find(|t| t["name"] == "content_events")
        .unwrap();
    let seq = events_table["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "seq")
        .unwrap();
    assert_eq!(seq["pk"], true);
    assert_eq!(out.get("ddl_statements"), None);
    let with_ddl = call(
        &registry,
        &db,
        "describe_schema",
        json!({ "include_ddl": true }),
    )
    .await;
    assert_eq!(
        with_ddl["ddl_statements"].as_array().unwrap().len(),
        DDL_STATEMENTS.len(),
        "describe_schema must return the complete frozen DDL"
    );
}

// ---------------------------------------------------------------------------
// Tool 5 — create_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_record_composes_fields_facets_and_links() {
    let db = db().await;
    let registry = registry();
    let parent = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "p" }),
    )
    .await;
    let target = create(&registry, &db, json!({ "type": "Outcome", "name": "g" })).await;
    let out = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "chore",
            "name": "wash up",
            "body": "the sink",
            "home_id": parent,
            "maturity": "draft",
            "persistence": "occurrent",
            "facets": { "priority": "high" },
            "links": [
                { "target_id": target, "relationship": "implements", "note": "why" },
                { "target_id": parent, "relationship": "part_of", "note": "content carve" }
            ]
        }),
    )
    .await;
    assert_eq!(out["type"], "WorkItem");
    assert_eq!(out["kind"], "chore");
    assert_eq!(out["lifecycle_interpretation"]["status"], "absent");
    assert!(out.get("lifecycle").is_none());
    assert_eq!(out["persistence"], "occurrent");
    assert_eq!(out["facets"][0]["key"], "priority");
    let links = out["links_out"].as_array().unwrap();
    assert_eq!(links.len(), 2);
    let implements = links
        .iter()
        .find(|link| link["relationship"] == "implements")
        .unwrap();
    assert_eq!(implements["note"], "why");
    assert!(links.iter().any(|link| link["relationship"] == "part_of"));
    let record_id = out["id"].as_str().unwrap();
    let action_attestation_id: String = sqlx::query_scalar(
        "SELECT o.action_attestation_id
           FROM provenance_action_outputs o JOIN content_events e
             ON o.output_domain='content' AND o.output_event_id=e.id
          WHERE e.record_id=? AND e.type='record.created'",
    )
    .bind(record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let domains: Vec<(String, i64)> = sqlx::query_as(
        "SELECT output_domain,COUNT(*) FROM provenance_action_outputs
          WHERE action_attestation_id=? GROUP BY output_domain ORDER BY output_domain",
    )
    .bind(&action_attestation_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        domains,
        vec![("content".into(), 3), ("relationship".into(), 2)]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM provenance_action_attestations WHERE id=? AND operation='create_record'",
        )
        .bind(&action_attestation_id)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1,
        "mixed inline links must share exactly one request attestation",
    );
    assert_eq!(
        out["ancestors"].as_array().unwrap().last().unwrap()["id"],
        json!(parent)
    );

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "future-chore",
            "name": "cannot guess future lifecycle semantics",
            "lifecycle": "ready"
        }),
    )
    .await;
    assert!(
        err.contains("ordinary non-null lifecycle writes require"),
        "{err}"
    );

    // Argument validation.
    let err = call_err(&registry, &db, "create_record", json!({ "type": "Sprint" })).await;
    assert!(err.contains("not a spine type"));
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "facets": { "archived": "true" } }),
    )
    .await;
    assert!(err.contains("engine-reserved"));
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "facets": { "lifecycle": "ready" } }),
    )
    .await;
    assert!(err.contains("spine facet"));
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "home_id": "missing" }),
    )
    .await;
    assert!(err.contains("home missing does not exist"));
}

#[tokio::test]
async fn kind_schema_and_supported_writes_require_non_empty_values() {
    let db = db().await;
    let registry = registry();

    for tool in ["create_record", "update_record"] {
        let schema = &registry
            .specs()
            .find(|spec| spec.name == tool)
            .unwrap_or_else(|| panic!("{tool} not registered"))
            .input_schema;
        let branch = if tool == "update_record" {
            &schema["oneOf"][0]
        } else {
            schema
        };
        assert_eq!(
            branch["properties"]["kind"]["minLength"], 1,
            "{tool} must advertise kind as a non-empty string"
        );
    }
    let create_schema = &registry.get("create_record").unwrap().input_schema;
    assert!(create_schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|field| field == "kind"));
    assert_eq!(
        registry.get("update_record").unwrap().input_schema["oneOf"][0]["properties"]["kind"]
            ["type"],
        "string"
    );

    for (args, expected) in [
        (
            json!({ "type": "WorkItem", "reason": "missing kind probe" }),
            "kind",
        ),
        (
            json!({ "type": "WorkItem", "kind": null, "reason": "null kind probe" }),
            "expected a string",
        ),
        (
            json!({ "type": "WorkItem", "kind": "", "reason": "empty kind probe" }),
            "kind",
        ),
    ] {
        let error = registry
            .call(db.clone(), Caller::local(), "create_record", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }

    let characterised = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    for kind in [Value::Null, json!("")] {
        let update_err = call_err(
            &registry,
            &db,
            "update_record",
            json!({ "id": characterised, "kind": kind }),
        )
        .await;
        assert!(update_err.contains("cannot be cleared"), "{update_err}");
    }
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": characterised, "kind": "x-novel-replacement" }),
    )
    .await;
    assert_eq!(updated["kind"], "x-novel-replacement");
    assert_eq!(updated["kind_governance"]["quarantined"], true);
}

#[tokio::test]
async fn generic_record_tools_cannot_mint_semantic_unit_lookalikes() {
    let db = db().await;
    let registry = registry();

    let before = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let create_error = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "semantic-unit" }),
    )
    .await;
    assert!(create_error.contains("reserved for freshness-kernel promotion"));
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before,
        "a rejected lookalike create must append nothing"
    );

    let entity = create(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "ordinary" }),
    )
    .await;
    let before_update = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let update_error = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": entity, "kind": "semantic-unit" }),
    )
    .await;
    assert!(update_error.contains("reserved for freshness-kernel promotion"));
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before_update,
        "a rejected lookalike update must append nothing"
    );
}

#[tokio::test]
async fn create_record_is_atomic_across_its_event_batch() {
    let db = db().await;
    let registry = registry();
    // A dangling vocab_ref fails the facet.set guard INSIDE the batch — the
    // record.created that preceded it must roll back with it (finding 5,
    // resolved by a54f708 option A).
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "id": ATOMIC_1,
            "name": "doomed",
            "facets": { "mood": { "value": "blue", "vocab_ref": "rec:nope" } }
        }),
    )
    .await;
    assert!(err.contains("does not resolve to a vocabulary"));
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        2,
        "no partial write: the whole batch rolled back"
    );
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM records").await,
        2
    );

    // Same shape for a dead link target: nothing lands.
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "name": "doomed too",
            "links": [ { "target_id": "missing", "relationship": "blocks" } ]
        }),
    )
    .await;
    assert!(err.contains("record missing does not exist"));
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM records").await,
        2
    );
}

// ---------------------------------------------------------------------------
// Tool 6 — get_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_record_batches_with_partial_success() {
    let db = db().await;
    let registry = registry();
    let id = create(&registry, &db, json!({ "type": "WorkItem", "name": "t" })).await;
    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id, "missing"] }),
    )
    .await;
    let records = out["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["status"], "found");
    assert_eq!(records[0]["name"], "t");
    assert_eq!(records[1]["status"], "not_found");
    assert_eq!(records[1]["id"], "missing");

    let err = call_err(&registry, &db, "get_record", json!({ "ids": [] })).await;
    assert!(err.contains("must not be empty"));
}

// ---------------------------------------------------------------------------
// Tool 7 — update_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_record_appends_one_event_carrying_changed_fields() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "before", "kind": "task" }),
    )
    .await;
    let rejected_resulting_kind = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "prospective future kind", "kind": "task" }),
    )
    .await;
    let before = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let out = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "name": "after",
            "body": "text",
            "kind": "epic",
            "lifecycle": "completed",
            "facets": { "priority": "low" }
        }),
    )
    .await;
    assert_eq!(out["name"], "after");
    assert_eq!(out["kind"], "epic");
    assert_eq!(out["lifecycle_interpretation"]["status"], "governed");
    assert_eq!(
        out["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );
    assert!(out.get("lifecycle").is_none());
    assert_eq!(out["facets"][0]["value"], "low");
    // ONE record.updated + ONE facet.set — never per-field.
    let after = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    assert_eq!(after - before, 2);
    let updated_payload = crate::common::text_of(
        &db,
        "SELECT payload FROM content_events WHERE type = 'record.updated' ORDER BY seq DESC LIMIT 1",
        "payload",
    )
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&updated_payload).unwrap();
    let keys: Vec<&str> = payload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    // The changed fields, plus `reason` — which is PAYLOAD, not a column, and so
    // rides in the event rather than needing DDL of its own. Named explicitly
    // rather than counted, so that a fifth key arriving for some other reason
    // still fails here.
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec!["body", "kind", "lifecycle", "name", "reason"],
        "only the changed fields travel, plus the reason: {keys:?}"
    );

    let before_rejected =
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": rejected_resulting_kind, "kind": "x-novel-updated" }),
    )
    .await;
    assert!(
        err.contains("ordinary non-null lifecycle writes require"),
        "{err}"
    );
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before_rejected,
        "rejected resulting-kind change must be atomic"
    );

    // Facet unset via null.
    let out = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "facets": { "priority": null } }),
    )
    .await;
    assert!(out["facets"].as_array().unwrap().is_empty());

    // Guards.
    let err = call_err(&registry, &db, "update_record", json!({ "id": id })).await;
    assert!(err.contains("no changes"));
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "persistence": null }),
    )
    .await;
    assert!(err.contains("cannot clear persistence"));
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "name": null }),
    )
    .await;
    assert!(err.contains("'name' cannot be null"));
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "name": 7 }),
    )
    .await;
    assert!(err.contains("must be a string or null"));
}

#[tokio::test]
async fn update_record_targeted_body_replace_handles_unique_and_unicode_matches() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "name": "protocol",
            "body": "Before: all three children. Café 🐕 says 你好. After stays."
        }),
    )
    .await;
    let before = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let out = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "name": "protocol corrected",
            "body_replace": [
                { "old": "all three children", "new": "all direct children" },
                { "old": "Café 🐕 says 你好", "new": "Café 🦮 says 您好" }
            ]
        }),
    )
    .await;

    assert_eq!(out["name"], "protocol corrected");
    assert_eq!(
        out["body"],
        "Before: all direct children. Café 🦮 says 您好. After stays."
    );
    let after = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    assert_eq!(after - before, 1, "one authoritative update event");

    let payload = crate::common::text_of(
        &db,
        "SELECT payload FROM content_events WHERE type = 'record.updated' ORDER BY seq DESC LIMIT 1",
        "payload",
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap(),
        json!({
            "name": "protocol corrected",
            "reason": "Test fixture write — this call's subject is not the reason field.",
            "body": "Before: all direct children. Café 🦮 says 您好. After stays."
        }),
        "the ordinary record.updated path carries the resolved body, and the reason \
         alongside it — payload, not a column"
    );
}

#[tokio::test]
async fn update_record_targeted_body_replace_rejections_write_nothing() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({
            "type": "Document",
            "name": "stable",
            "body": "dog / dog / tail"
        }),
    )
    .await;

    for (args, error_fragment) in [
        (
            json!({
                "id": id,
                "name": "must not land",
                "body_replace": [{ "old": "cat", "new": "fox" }]
            }),
            "matched 0 occurrences",
        ),
        (
            json!({
                "id": id,
                "body_replace": [{ "old": "dog", "new": "cat" }]
            }),
            "matched 2 occurrences",
        ),
        (
            json!({
                "id": id,
                "body_replace": [{ "old": "dog", "new": "cat", "expected_count": 3 }]
            }),
            "expected 3 occurrences but matched 2",
        ),
        (
            json!({
                "id": id,
                "body": "whole rewrite",
                "body_replace": [{ "old": "dog", "new": "cat", "replace_all": true }]
            }),
            "mutually exclusive",
        ),
    ] {
        let before = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
        let err = call_err(&registry, &db, "update_record", args).await;
        assert!(err.contains(error_fragment), "{err}");
        let after = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
        assert_eq!(after, before, "rejected call appended an event: {err}");
        let record = call(&registry, &db, "get_record", json!({ "ids": [id.clone()] })).await;
        assert_eq!(record["records"][0]["body"], "dog / dog / tail");
        assert_eq!(record["records"][0]["name"], "stable");
    }
}

#[tokio::test]
async fn update_record_targeted_body_replace_supports_explicit_multi_match_modes() {
    let db = db().await;
    let registry = registry();
    let replace_all = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "all", "body": "🐕 dog 🐕 dog" }),
    )
    .await;
    let asserted = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "counted", "body": "one—one—two" }),
    )
    .await;

    let out = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": replace_all,
            "body_replace": [{ "old": "🐕", "new": "🦮", "replace_all": true }]
        }),
    )
    .await;
    assert_eq!(out["body"], "🦮 dog 🦮 dog");

    let out = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": asserted,
            "body_replace": [{ "old": "one", "new": "three", "expected_count": 2 }]
        }),
    )
    .await;
    assert_eq!(out["body"], "three—three—two");
}

#[tokio::test]
async fn update_record_body_digest_rejects_a_stale_whole_or_targeted_body_write() {
    let db = db().await;
    let registry = registry();
    let initial = "all three children";
    let id = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "protocol", "body": initial }),
    )
    .await;
    let stale_digest = body_digest(initial);

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "body": "newer preface; all three children; newer suffix",
            "if_body_digest": stale_digest.clone()
        }),
    )
    .await;
    let after_newer_write =
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    for args in [
        json!({
            "id": id,
            "body": "stale whole-body overwrite",
            "if_body_digest": stale_digest
        }),
        json!({
            "id": id,
            "body_replace": [{ "old": "all three children", "new": "all direct children" }],
            "if_body_digest": stale_digest
        }),
    ] {
        let err = call_err(&registry, &db, "update_record", args).await;
        assert!(err.contains("body digest conflict"), "{err}");
        assert_eq!(
            crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
            after_newer_write,
            "a stale caller appended an event"
        );
    }

    let record = call(&registry, &db, "get_record", json!({ "ids": [id.clone()] })).await;
    assert_eq!(
        record["records"][0]["body"],
        "newer preface; all three children; newer suffix"
    );

    // A fresh digest succeeds, proving the guard is usable rather than merely
    // rejecting every guarded call.
    let current = record["records"][0]["body"].as_str().unwrap();
    let out = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "body_replace": [{ "old": "all three children", "new": "all direct children" }],
            "if_body_digest": body_digest(current)
        }),
    )
    .await;
    assert_eq!(
        out["body"],
        "newer preface; all direct children; newer suffix"
    );
}

#[tokio::test]
async fn update_record_timestamp_precondition_matches_and_rejects_stale_or_malformed_writes_atomically(
) {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "before", "body": "alpha" }),
    )
    .await;
    let known_updated_at = "2026-01-02T03:04:05.006Z";
    sqlx::query("UPDATE records SET updated_at = ? WHERE id = ?")
        .bind(known_updated_at)
        .bind(&id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let matching = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "name": "matching",
            "if_unmodified_since": "2026-01-02T04:04:05.006+01:00"
        }),
    )
    .await;
    assert_eq!(matching["name"], "matching");

    let after_matching = call(&registry, &db, "get_record", json!({ "ids": [id.clone()] })).await;
    let current_updated_at = after_matching["records"][0]["updated_at"]
        .as_str()
        .unwrap()
        .to_owned();
    let event_count = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let stale = registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            crate::common::with_test_reason(
                "update_record",
                json!({
                    "id": id,
                    "name": "must not land",
                    "facets": { "priority": "urgent" },
                    "if_unmodified_since": known_updated_at
                }),
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(stale, native_ce::Error::Conflict(_)), "{stale:?}");
    assert!(stale.to_string().contains("stale write conflict"));
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        event_count,
        "stale fields and facets must not append any event"
    );

    let malformed = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "name": "also must not land",
            "if_unmodified_since": "not-a-timestamp"
        }),
    )
    .await;
    assert!(
        malformed.contains("must be an RFC3339 timestamp"),
        "{malformed}"
    );
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        event_count
    );

    let composed = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "body": "beta",
            "facets": { "priority": "low" },
            "if_unmodified_since": current_updated_at,
            "if_body_digest": body_digest("alpha")
        }),
    )
    .await;
    assert_eq!(composed["body"], "beta");
    assert_eq!(composed["facets"][0]["value"], "low");

    let before_facet = composed["updated_at"].as_str().unwrap().to_owned();
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "facets": { "priority": "medium" } }),
    )
    .await;
    let after_facet = call(&registry, &db, "get_record", json!({ "ids": [id.clone()] })).await;
    assert_ne!(after_facet["records"][0]["updated_at"], before_facet);
    let stale_after_facet = registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            crate::common::with_test_reason(
                "update_record",
                json!({
                    "id": id,
                    "name": "facet-blind stale write",
                    "if_unmodified_since": before_facet
                }),
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(stale_after_facet, native_ce::Error::Conflict(_)));
}

#[tokio::test]
async fn update_record_rehomes_with_cycle_and_liveness_guards() {
    let db = db().await;
    let registry = registry();
    let a = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "a" }),
    )
    .await;
    let b = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "b", "home_id": a }),
    )
    .await;
    let c = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "c", "home_id": b }),
    )
    .await;

    // Legal rehome: c moves into a.
    let out = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": c, "home_id": a }),
    )
    .await;
    assert_eq!(out["home_id"], json!(a));
    // Null is reserved to the engine root.
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": c, "home_id": null }),
    )
    .await;
    assert!(err.contains("cannot clear home_id"));

    // Cycle guards.
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": a, "home_id": a }),
    )
    .await;
    assert!(err.contains("own home"));
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": a, "home_id": b }),
    )
    .await;
    assert!(err.contains("containment cycle"));

    // Tombstoned records are frozen — the projector's guard surfaces.
    call(&registry, &db, "delete_record", json!({ "id": c })).await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": c, "name": "zombie" }),
    )
    .await;
    assert!(err.contains("tombstoned"));
}

#[tokio::test]
async fn update_record_multi_contract_is_bounded_exact_and_singular_compatible() {
    let db = db().await;
    let registry = registry();
    let schema = &registry
        .specs()
        .find(|spec| spec.name == "update_record")
        .unwrap()
        .input_schema;
    assert_eq!(schema["oneOf"].as_array().unwrap().len(), 2);
    let multi = &schema["oneOf"][1]["allOf"][0];
    assert_eq!(multi["properties"]["ids"]["maxItems"], 100);
    assert_eq!(multi["properties"]["ids"]["uniqueItems"], true);

    let id = create(
        &registry,
        &db,
        json!({"type":"WorkItem","kind":"task","name":"singular remains singular"}),
    )
    .await;
    let singular = call(
        &registry,
        &db,
        "update_record",
        json!({"id":id,"name":"still enriched"}),
    )
    .await;
    assert_eq!(singular["name"], "still enriched");
    assert!(singular.get("results").is_none());

    for (args, needle) in [
        (json!({"ids":[],"maturity":"active"}), "at least one"),
        (
            json!({"ids":[id.clone(),id.clone()],"maturity":"active"}),
            "duplicates",
        ),
        (
            json!({"ids":[&id[..7]],"maturity":"active"}),
            "exact canonical",
        ),
        (
            json!({"ids":[id.clone()],"name":"same name"}),
            "unknown field",
        ),
        (
            json!({"id":id.clone(),"ids":[id.clone()],"maturity":"active"}),
            "unknown field",
        ),
    ] {
        let error = call_err(&registry, &db, "update_record", args).await;
        assert!(error.contains(needle), "{error}");
    }

    let over_limit = (0..101)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    let error = call_err(
        &registry,
        &db,
        "update_record",
        json!({"ids":over_limit,"maturity":"active"}),
    )
    .await;
    assert!(error.contains("at most 100"), "{error}");
}

#[tokio::test]
async fn update_record_multi_is_atomic_idempotent_and_preconditioned() {
    let db = db().await;
    let registry = registry();
    let mut ids = Vec::new();
    for name in ["first", "second", "third"] {
        ids.push(
            create(
                &registry,
                &db,
                json!({
                    "type":"WorkItem",
                    "kind":"task",
                    "name":name,
                    "maturity":"exploratory",
                    "facets":{"triage":"untriaged"}
                }),
            )
            .await,
        );
    }
    let before = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let receipt = call(
        &registry,
        &db,
        "update_record",
        json!({
            "ids":ids,
            "facets":{"triage":"completed","owner_note":null},
            "maturity":"active",
            "if_facets":{"triage":"untriaged","owner_note":null},
            "if_maturity":"exploratory"
        }),
    )
    .await;
    assert_eq!(receipt["requested"], 3);
    assert_eq!(receipt["changed"], 3);
    assert_eq!(receipt["unchanged"], 0);
    assert_eq!(receipt["results"][0]["index"], 0);
    assert_eq!(receipt["results"][2]["status"], "changed");
    let after = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    assert_eq!(
        after - before,
        6,
        "one field and one facet event per target"
    );

    let retry = call(
        &registry,
        &db,
        "update_record",
        json!({
            "ids":ids,
            "facets":{"triage":"completed","owner_note":null},
            "maturity":"active"
        }),
    )
    .await;
    assert_eq!(retry["changed"], 0);
    assert_eq!(retry["unchanged"], 3);
    let after_retry = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    assert_eq!(after_retry, after, "an identical retry emits no events");

    let stale = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "ids":ids,
            "facets":{"triage":"reviewed"},
            "if_facets":{"triage":"untriaged"}
        }),
    )
    .await;
    assert!(stale.contains("nothing was written"), "{stale}");
    assert!(stale.contains("conflicted=3"), "{stale}");
    let after_stale = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    assert_eq!(after_stale, after);
}

#[tokio::test]
async fn update_record_multi_relocation_supports_related_targets_and_rejects_cycles_atomically() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({"type":"Collection","kind":"folder","name":"source"}),
    )
    .await;
    let parent = create(
        &registry,
        &db,
        json!({"type":"Collection","kind":"folder","name":"parent","home_id":source}),
    )
    .await;
    let child = create(
        &registry,
        &db,
        json!({"type":"Collection","kind":"folder","name":"child","home_id":parent}),
    )
    .await;
    let destination = create(
        &registry,
        &db,
        json!({"type":"Collection","kind":"folder","name":"destination"}),
    )
    .await;

    let cycle = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "ids":[source.clone(),parent.clone()],
            "home_id":child
        }),
    )
    .await;
    assert!(cycle.contains("containment cycle"), "{cycle}");
    let unchanged = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[source.clone(),parent.clone()]}),
    )
    .await;
    assert_eq!(unchanged["records"][0]["home_id"], "native:unfiled");
    assert_eq!(unchanged["records"][1]["home_id"], source);

    let moved = call(
        &registry,
        &db,
        "update_record",
        json!({
            "ids":[child.clone(),parent.clone()],
            "home_id":destination
        }),
    )
    .await;
    assert_eq!(moved["changed"], 2);
    assert_eq!(moved["results"][0]["id"], child);
    let records = call(&registry, &db, "get_record", json!({"ids":[child,parent]})).await;
    assert!(records["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| record["home_id"] == destination));
}

#[tokio::test]
async fn update_record_cycle_guard_is_not_depth_capped() {
    let db = db().await;
    let registry = registry();
    // A containment chain deeper than the read layer's 100-level walk cap:
    // the in-transaction cycle check must still see the top of the chain
    // from the bottom.
    let top = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "top" }),
    )
    .await;
    let mut parent = top.clone();
    for depth in 0..105 {
        parent = create(
            &registry,
            &db,
            json!({ "type": "Collection", "kind": "folder", "name": format!("d{depth}"), "home_id": parent }),
        )
        .await;
    }
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": top, "home_id": parent }),
    )
    .await;
    assert!(err.contains("containment cycle"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Tool 8 — delete_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_record_tombstones_and_freezes() {
    let db = db().await;
    let registry = registry();
    let id = create(&registry, &db, json!({ "type": "WorkItem", "name": "t" })).await;
    let out = call(&registry, &db, "delete_record", json!({ "id": id })).await;
    assert_eq!(out["deleted"], true);
    assert!(out["deleted_at"].is_string());

    // Frozen: no further mutation events land — not even a second delete.
    let err = call_err(&registry, &db, "delete_record", json!({ "id": id })).await;
    assert!(err.contains("tombstoned"));
    let err = call_err(&registry, &db, "archive_record", json!({ "id": id })).await;
    assert!(err.contains("tombstoned"));
    let err = call_err(&registry, &db, "delete_record", json!({ "id": "no" })).await;
    assert!(err.contains("does not exist"));

    // Direct fetch still returns the tombstone (pointing at it is asking).
    let out = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
    assert_eq!(out["records"][0]["status"], "found");
    assert!(out["records"][0]["deleted_at"].is_string());
}

// ---------------------------------------------------------------------------
// Tool 9 — archive_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn archive_record_round_trips_preserving_lifecycle() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "epic", "name": "t", "lifecycle": "in_progress" }),
    )
    .await;
    let out = call(&registry, &db, "archive_record", json!({ "id": id })).await;
    assert_eq!(out["changed"], true);

    // Archived: out of default walks, still directly fetchable and mutable.
    let fetched = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
    assert_eq!(fetched["records"][0]["archived"], true);
    assert!(fetched["records"][0].get("lifecycle").is_none());
    assert_eq!(
        fetched["records"][0]["lifecycle_interpretation"]["value"]["raw"],
        "in_progress"
    );
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "body": "still mutable" }),
    )
    .await;

    // Idempotent no-op appends NO event.
    let before = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let out = call(&registry, &db, "archive_record", json!({ "id": id })).await;
    assert_eq!(out["changed"], false);
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before
    );

    // Restore = unset; lifecycle survived the round trip.
    let out = call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": id, "archived": false }),
    )
    .await;
    assert_eq!(out["changed"], true);
    let fetched = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
    assert_eq!(fetched["records"][0]["archived"], false);
    assert_eq!(
        fetched["records"][0]["lifecycle_interpretation"]["value"]["raw"],
        "in_progress"
    );

    let err = call_err(&registry, &db, "archive_record", json!({ "id": "no" })).await;
    assert!(err.contains("does not exist"));
}

// ---------------------------------------------------------------------------
// Tool 10 — render_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn render_record_is_deterministic_markdown() {
    let db = db().await;
    let registry = registry();
    let parent = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Projects" }),
    )
    .await;
    let target = create(
        &registry,
        &db,
        json!({ "type": "Outcome", "name": "Ship it" }),
    )
    .await;
    let id = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem",
            "kind": "epic",
            "name": "The task",
            "body": "Body text.",
            "summary": "One line.",
            "home_id": parent,
            "lifecycle": "in_progress",
            "facets": { "priority": "high" },
            "links": [ { "target_id": target, "relationship": "implements" } ]
        }),
    )
    .await;
    create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Notes", "home_id": parent,
                "links": [{ "target_id": id, "relationship": "part_of" }] }),
    )
    .await;

    let out = call(&registry, &db, "render_record", json!({ "id": id })).await;
    let markdown = out["markdown"].as_str().unwrap();
    assert!(markdown.starts_with("# The task\n"));
    assert!(markdown.contains("**WorkItem** / epic"));
    assert!(markdown.contains("Path: Workspace → Unfiled → Projects"));
    assert!(markdown.contains("lifecycle: in_progress · persistence: enduring"));
    assert!(markdown.contains("> One line."));
    assert!(markdown.contains("Body text."));
    assert!(markdown.contains("- priority: high"));
    assert!(markdown.contains("→ implements — Ship it"));
    assert!(markdown.contains("← part_of — Notes"));

    // Deterministic: same input, byte-identical output.
    let again = call(&registry, &db, "render_record", json!({ "id": id })).await;
    assert_eq!(out, again);

    // Incoming links render from the far side.
    let goal = call(&registry, &db, "render_record", json!({ "id": target })).await;
    assert!(goal["markdown"]
        .as_str()
        .unwrap()
        .contains("← implements — The task"));

    let err = call_err(&registry, &db, "render_record", json!({ "id": "no" })).await;
    assert!(err.contains("does not exist"));
}

/// `render_record` inherits `get_record`'s window (decision 5055a9c), so it can
/// only render part of a wide container — and a deterministic render that drops
/// the rest silently is a render of a different, smaller record. The heading
/// has to say so.
#[tokio::test]
async fn render_record_declares_what_it_truncated() {
    let db = db().await;
    let registry = registry();
    let wide = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Wide" }),
    )
    .await;
    for i in 0..205 {
        create(
            &registry,
            &db,
            json!({ "type": "WorkItem", "name": format!("Child {i:04}"), "home_id": wide }),
        )
        .await;
    }

    let out = call(&registry, &db, "render_record", json!({ "id": wide })).await;
    let markdown = out["markdown"].as_str().unwrap();
    assert!(
        markdown.contains("## Children — showing 200 of 205"),
        "a truncated section must declare the truncation, got:\n{markdown}"
    );
    assert!(
        markdown.contains("children_offset"),
        "and must name the way to see the rest"
    );

    // A section that fits carries no marker — the notice is a signal, not
    // furniture on every render.
    let small = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Small" }),
    )
    .await;
    create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Only child", "home_id": small }),
    )
    .await;
    let out = call(&registry, &db, "render_record", json!({ "id": small })).await;
    let markdown = out["markdown"].as_str().unwrap();
    assert!(markdown.contains("## Children\n"));
    assert!(!markdown.contains("showing"));
    assert!(!markdown.contains("children_offset"));
}

/// Anything a caller might act on must name a tool that is registered. Three
/// quarters of the v1 surface is built, so it is easy to write a helpful string
/// pointing at a tool from a stage that has not landed — and a recovery path
/// that 404s is worse than none, because it is offered exactly when someone is
/// stuck. Covers descriptions, schema text, and the errors the bounds raise.
#[tokio::test]
async fn caller_facing_text_never_names_an_unregistered_tool() {
    let db = db().await;
    let registry = registry();
    let registered: std::collections::HashSet<String> =
        registry.specs().map(|t| t.name.clone()).collect();

    // Every v1 tool name, so the scan can tell "names a tool" from "names a
    // column". Kept literal: deriving it from the registry would only ever find
    // tools that exist, which is the opposite of the point.
    let all_v1_tools = [
        "bootstrap",
        "get_structure",
        "get_dashboard",
        "describe_schema",
        "read_guide",
        "create_record",
        "get_record",
        "update_record",
        "delete_record",
        "archive_record",
        "render_record",
        "get_history",
        "manage_links",
        "manage_facet_observations",
        "resolve_facets",
        "suggest_facet_values",
        "query_record",
        "search",
        "query_sql",
        "scan",
        "manage_vocabularies",
        "manage_schema_config",
        "attach_text",
        "attach_from_url",
        "read_attachment",
        "manage_attachments",
        "start_work",
    ];

    let mut haystacks: Vec<(String, String)> = Vec::new();
    for spec in registry.specs() {
        haystacks.push((
            format!("{} description", spec.name),
            spec.description.clone(),
        ));
        haystacks.push((
            format!("{} schema", spec.name),
            spec.input_schema.to_string(),
        ));
    }

    // The bound errors, which are the strings a stuck caller actually reads.
    let wide = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Wide" }),
    )
    .await;
    for (label, args) in [
        (
            "get_record over-limit error",
            json!({ "ids": [&wide], "children_limit": 100_000 }),
        ),
        (
            "get_record over-limit error (links)",
            json!({ "ids": [&wide], "links_limit": 100_000 }),
        ),
    ] {
        haystacks.push((
            label.into(),
            call_err(&registry, &db, "get_record", args).await,
        ));
    }
    haystacks.push((
        "get_structure over-cap error".into(),
        call_err(
            &registry,
            &db,
            "get_structure",
            json!({ "root_id": &wide, "max_children_per_node": 100_000 }),
        )
        .await,
    ));

    // And the rendered truncation notice.
    for i in 0..205 {
        create(
            &registry,
            &db,
            json!({ "type": "WorkItem", "name": format!("C{i:04}"), "home_id": wide }),
        )
        .await;
    }
    let out = call(&registry, &db, "render_record", json!({ "id": &wide })).await;
    haystacks.push((
        "render_record truncation notice".into(),
        out["markdown"].as_str().unwrap().to_string(),
    ));

    for (where_, text) in &haystacks {
        for tool in all_v1_tools {
            if text.contains(tool) && !registered.contains(tool) {
                panic!(
                    "{where_} names `{tool}`, which is not registered — \
                     a caller following it gets an unknown-tool error.\n{text}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Acceptance: rebuild-and-diff after a full tool-driven session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rebuild_and_diff_passes_after_a_full_tool_session() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Everything" }),
    )
    .await;
    let goal = create(
        &registry,
        &db,
        json!({ "type": "Outcome", "name": "goal", "home_id": root }),
    )
    .await;
    let task = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "task", "home_id": root,
            "facets": { "priority": "high" },
            "links": [ { "target_id": goal, "relationship": "implements" } ]
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": task, "name": "renamed", "lifecycle": "in_progress",
                "facets": { "priority": null, "effort": "small" } }),
    )
    .await;
    call(&registry, &db, "archive_record", json!({ "id": goal })).await;
    call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": goal, "archived": false }),
    )
    .await;
    let doomed = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "scrap", "home_id": root,
                "links": [{ "target_id": task, "relationship": "part_of" }] }),
    )
    .await;
    call(&registry, &db, "delete_record", json!({ "id": doomed })).await;
    // Reads along the way exercise the read layer against the same state.
    call(&registry, &db, "get_structure", json!({ "root_id": root })).await;
    call(&registry, &db, "get_dashboard", json!({ "scope": root })).await;
    call(&registry, &db, "render_record", json!({ "id": task })).await;

    let diff = rebuild_and_diff(&db).await.unwrap();
    assert!(
        diff.equal,
        "projections diverge from replay: {:?}",
        diff.tables
    );
}
