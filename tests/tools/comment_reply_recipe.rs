//! Deterministic comment-reply recipe regression for b895e09.
//!
//! Fixed inputs, disposable DB, no LLM. Dispatches through the real
//! `ExecutorPrototypeStdioServer` envelope (bootstrap → run_key →
//! records_read/records_write), validates the reply arguments with
//! `jsonschema` against `describe_operation` contracts, and asserts
//! behavior/sequencing without a fixed call count. Aliases are prospective
//! until review/tests pass. Desktop prompt lives with 845c121.

use native_ce::mcp::{
    register_surface_tools, register_workspace_tool_with, Caller, ExecutorPrototypeStdioServer,
    ToolRegistry,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use std::sync::Arc;

const PAGE_ID: &str = "c0aa0000-0000-4000-8000-000000000001";
const ROOT_ID: &str = "c0aa0000-0000-4000-8000-000000000002";
// Distinct triggering comment: the idempotency key names the trigger, while
// the reply links part_of to the root. Desktop requires the two to stay distinct.
const TRIGGER_ID: &str = "c0aa0000-0000-4000-8000-000000000003";
const PAGE_BODY: &str = "fixed page body for comment-reply recipe";
const ROOT_BODY: &str = "fixed root concern";
const REPLY_BODY: &str = "fixed reply body";
const REASON: &str = "fixed test reason for comment reply";

async fn server() -> (ExecutorPrototypeStdioServer, Db) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    // Concrete workspace directory delegate (not the schema-only rejecting
    // one): mirrors the hosted shape. Live workspace dispatch stays
    // hosted-gated, so workspace alias routing is covered at catalogue level
    // in executor_prototype unit tests; this delegate keeps the ToolSpec real.
    register_workspace_tool_with(&mut registry, |_db, _caller, _arguments| async {
        Ok(json!({"workspaces": []}))
    })
    .unwrap();
    let server =
        ExecutorPrototypeStdioServer::new(Arc::new(registry), db.clone(), Caller::local(), None)
            .await
            .unwrap();
    (server, db)
}

async fn bootstrap_run_key(server: &ExecutorPrototypeStdioServer) -> String {
    let res = server
        .handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"bootstrap","arguments":{"format":"json"}}}))
        .await
        .unwrap();
    assert_eq!(res["result"]["isError"], false, "{res}");
    res["result"]["structuredContent"]["session"]["run_key"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn exec(
    server: &ExecutorPrototypeStdioServer,
    id: i64,
    name: &str,
    operation: &str,
    args: Value,
    run_key: &str,
) -> Value {
    server
        .handle_message(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":name,"arguments":{
                "operation":operation,"arguments":args,
                "run_key":run_key,"format":"json"}}}))
        .await
        .unwrap()
}

// describe_operation is a special top-level envelope: {executor, operation,
// run_key, format} — not nested under operation/arguments like executors.
async fn describe(
    server: &ExecutorPrototypeStdioServer,
    id: i64,
    executor: &str,
    operation: &str,
    run_key: &str,
) -> Value {
    server
        .handle_message(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"describe_operation","arguments":{
                "executor":executor,"operation":operation,
                "run_key":run_key,"format":"json"}}}))
        .await
        .unwrap()
}

fn reply_args(root: &str, page: &str, triggering: &str) -> Value {
    json!({
        "type": "Annotation", "kind": "comment", "body": REPLY_BODY,
        "links": [{"target_id": root, "relationship": "part_of"}],
        "sources": [{"record_id": page, "reason": "read page before reply"}],
        "reason": REASON,
        "idempotency_key": format!("native.ask.reply:{triggering}"),
    })
}

#[tokio::test]
async fn comment_reply_recipe_executes_through_executor_envelope() {
    let (server, db) = server().await;
    // Bootstrap first; dependent calls reuse its run_key.
    let run_key = bootstrap_run_key(&server).await;

    // Fixed page + targetless root via the executor (explicit reason, no helper).
    let mut id = 10;
    for (args, kind) in [
        (
            json!({"id": PAGE_ID, "type": "Document", "kind": "note",
            "name": "recipe page", "body": PAGE_BODY, "reason": REASON}),
            "page",
        ),
        (
            json!({"id": ROOT_ID, "type": "Annotation", "kind": "comment",
            "body": ROOT_BODY, "lifecycle": "open",
            "links": [{"target_id": PAGE_ID, "relationship": "part_of"}],
            "reason": REASON}),
            "root",
        ),
    ] {
        let res = exec(
            &server,
            id,
            "records_write",
            "create_record",
            args,
            &run_key,
        )
        .await;
        id += 1;
        assert_eq!(res["result"]["isError"], false, "{kind}: {res}");
    }

    // Authoritative contract: describe_operation input_schema validates recipe.
    let desc = describe(&server, id, "records_write", "create_record", &run_key).await;
    id += 1;
    assert_eq!(desc["result"]["isError"], false, "{desc}");
    let schema = desc["result"]["structuredContent"]["input_schema"].clone();
    let recipe = reply_args(ROOT_ID, PAGE_ID, TRIGGER_ID);
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&recipe),
        "{schema}"
    );
    // Missing reason must fail validation (no helper may mask it).
    let mut no_reason = recipe.clone();
    no_reason.as_object_mut().unwrap().remove("reason");
    assert!(!jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&no_reason));

    // Page baseline, then one reply.
    let before = exec(
        &server,
        id,
        "records_read",
        "get_record",
        json!({"ids": [PAGE_ID]}),
        &run_key,
    )
    .await;
    id += 1;
    assert_eq!(
        before["result"]["structuredContent"]["records"][0]["body"],
        json!(PAGE_BODY)
    );
    let first = exec(
        &server,
        id,
        "records_write",
        "create_record",
        recipe.clone(),
        &run_key,
    )
    .await;
    id += 1;
    assert_eq!(first["result"]["isError"], false, "{first}");
    let reply_id = first["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Alias routes (prospective, ordinary surface): executor-prefixed bare
    // strips to canonical, and describe resolves the alias to the canonical
    // contract. Workspace live dispatch stays hosted-gated; its alias is
    // covered at catalogue level in executor_prototype unit tests.
    let alias_get = exec(
        &server,
        id,
        "records_read",
        "records_read.get_record",
        json!({"ids": [PAGE_ID]}),
        &run_key,
    )
    .await;
    id += 1;
    assert_eq!(alias_get["result"]["isError"], false, "{alias_get}");
    let alias_desc = describe(
        &server,
        id,
        "records_write",
        "records_write.create_record",
        &run_key,
    )
    .await;
    id += 1;
    assert_eq!(alias_desc["result"]["isError"], false, "{alias_desc}");
    assert_eq!(
        alias_desc["result"]["structuredContent"]["operation"],
        json!("create_record")
    );

    // Reply linkage, body, declared source; page unchanged.
    let reply = exec(
        &server,
        id,
        "records_read",
        "get_record",
        json!({"ids": [reply_id.clone()]}),
        &run_key,
    )
    .await;
    id += 1;
    let rec = &reply["result"]["structuredContent"]["records"][0];
    assert_eq!(rec["type"], json!("Annotation"));
    assert_eq!(rec["body"], json!(REPLY_BODY));
    assert!(rec.get("summary").and_then(Value::as_str).is_none());
    let part_of: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&reply_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(part_of, vec![ROOT_ID.to_string()]);
    // Structured source-declaration evidence from the stored create event
    // (independent of compact/verbose response mode).
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id = ? AND type = 'record.created'",
    )
    .bind(&reply_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let event: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(event["basis"]["format"], json!("native.source-basis.v1"));
    assert_eq!(event["basis"]["sources"][0]["record_id"], json!(PAGE_ID));
    // Key identity is the trigger, linkage is the root: distinct by design.
    assert_eq!(
        recipe["idempotency_key"],
        json!(format!("native.ask.reply:{TRIGGER_ID}"))
    );
    assert_ne!(TRIGGER_ID, ROOT_ID);
    let after = exec(
        &server,
        id,
        "records_read",
        "get_record",
        json!({"ids": [PAGE_ID]}),
        &run_key,
    )
    .await;
    id += 1;
    assert_eq!(
        after["result"]["structuredContent"]["records"][0]["body"],
        json!(PAGE_BODY)
    );

    // Identical retry: no duplicate.
    let second = exec(
        &server,
        id,
        "records_write",
        "create_record",
        recipe,
        &run_key,
    )
    .await;
    assert_eq!(second["result"]["structuredContent"]["id"], json!(reply_id));
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE relationship = 'part_of' AND target_id = ?",
    )
    .bind(ROOT_ID)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
}
