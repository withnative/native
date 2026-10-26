//! Lean surface: catalogue projection, `call_executor` parity with direct
//! dispatch, the direct-call refusal, discovery, bootstrap and routing.
//!
//! Parity cases compare a full executor server and a lean server over the
//! same database and caller. Each pair differs only in route, so equal
//! results show `call_executor` entered the one governed path rather than a
//! copy of it.

use std::sync::Arc;

use serde_json::{json, Value};

use super::tests::{hosted_registry, registry};
use super::*;
use crate::db::create_database;

const RUN_KEY: &str = "lean-surface-parity";

const LEAN_ADVERTISED: [&str; 10] = [
    "bootstrap",
    "describe_operation",
    "system_read",
    "guidance_read",
    "records_read",
    "records_write",
    "records_lifecycle",
    "coordination_write",
    "sql_read",
    "call_executor",
];

/// Ceiling for the lean descriptor catalogue on the hosted registration
/// set. The proxy emulation measured 23.4 KB; this leaves headroom for the
/// call_executor card without letting the surface drift back toward the
/// ~80 KB full catalogue unnoticed.
const LEAN_DESCRIPTOR_MAX_BYTES: usize = 32 * 1024;

fn full_catalogue(registry: &ToolRegistry, hosted: bool) -> PinnedExecutorCatalogue {
    build_ordinary_catalogue(
        registry,
        crate::mcp::registry::EngineKind::Sqlite,
        hosted,
        &ExperimentalExecutors::empty(),
    )
    .unwrap()
}

fn lean_catalogue(registry: &ToolRegistry, hosted: bool) -> PinnedExecutorCatalogue {
    build_ordinary_catalogue_projection(
        registry,
        crate::mcp::registry::EngineKind::Sqlite,
        hosted,
        &ExperimentalExecutors::empty(),
        true,
    )
    .unwrap()
}

fn names(descriptors: &[Value]) -> Vec<&str> {
    descriptors
        .iter()
        .filter_map(|descriptor| descriptor["name"].as_str())
        .collect()
}

fn descriptor<'a>(descriptors: &'a [Value], name: &str) -> &'a Value {
    descriptors
        .iter()
        .find(|descriptor| descriptor["name"] == name)
        .unwrap_or_else(|| panic!("{name} is advertised"))
}

fn call_message(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"tools/call",
        "params":{"name":name,"arguments":arguments}
    })
}

async fn send(
    server: &ExecutorPrototypeStdioServer,
    id: u64,
    name: &str,
    arguments: Value,
) -> Value {
    server
        .handle_message(call_message(id, name, arguments))
        .await
        .expect("tools/call with an id is answered")
}

/// `call_executor` envelope for the same direct call.
fn routed(executor: &str, mut envelope: Value) -> Value {
    envelope["executor"] = json!(executor);
    envelope
}

/// Everything a caller observes except the per-server manifest metadata.
fn observed(response: &Value) -> Value {
    let mut result = response["result"].clone();
    if let Some(result) = result.as_object_mut() {
        result.remove("_meta");
    }
    result
}

async fn servers() -> (
    crate::Db,
    ExecutorPrototypeStdioServer,
    ExecutorPrototypeStdioServer,
) {
    let db = create_database(":memory:").await.unwrap();
    let full = ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
        .await
        .unwrap();
    let lean = ExecutorPrototypeStdioServer::new_for_surface(
        registry(),
        db.clone(),
        Caller::local(),
        None,
        None,
        ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Lean,
    )
    .await
    .unwrap();
    (db, full, lean)
}

async fn create_note(server: &ExecutorPrototypeStdioServer, id: u64, name: &str) -> String {
    let created = send(
        server,
        id,
        "records_write",
        json!({
            "operation":"create_record",
            "format":"json",
            "run_key":RUN_KEY,
            "arguments":{
                "type":"Document",
                "kind":"note",
                "name":name,
                "body":"Lean surface fixture.",
                "reason":"Lean surface fixture record."
            }
        }),
    )
    .await;
    assert_eq!(created["result"]["isError"], false, "{created}");
    created["result"]["structuredContent"]["id"]
        .as_str()
        .or_else(|| created["result"]["structuredContent"]["record"]["id"].as_str())
        .unwrap_or_else(|| panic!("created record id: {created}"))
        .to_string()
}

#[tokio::test]
async fn advertised_lean_tools_list_routes_app_requests_to_installed_apps() {
    let (_, _, lean) = servers().await;
    let listed = lean
        .handle_message(json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}))
        .await
        .unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    let guidance = descriptor(tools, "guidance_read");
    let cue = guidance["description"].as_str().unwrap();
    assert!(cue.contains("Build an app:"), "{cue}");
    assert!(cue.contains("read_guide topic app-builder-1.0.0"), "{cue}");
    assert!(cue.contains("installed apps"), "{cue}");
    assert!(!names(tools).contains(&"read_guide"));
    assert!(!names(tools).contains(&"artifacts_write"));
}

#[tokio::test]
async fn prepare_install_call_executor_is_read_only_and_returns_pin() {
    let (_, full, lean) = servers().await;
    let body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Prepared</title></head><body><main><h1>Prepared</h1></main></body></html>";
    let id = "ab000000-0000-4000-8000-000000000001";
    let created = send(
        &full,
        1,
        "records_write",
        json!({
            "operation": "create_record", "format": "json", "run_key": RUN_KEY,
            "arguments": {"id": id, "type": "Document", "kind": "artifact", "name": "Prepared",
                "body": body, "facets": {"runtime": "native.html.v1"}, "reason": "Prepare fixture."}
        }),
    )
    .await;
    assert_eq!(created["result"]["isError"], false, "{created}");
    let envelope = json!({"operation": "manage_alpha_tabs.prepare_install", "format": "json", "run_key": RUN_KEY,
        "arguments": {"artifact_id": id, "expected_body_digest": crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(body),
            "package": "agent.prepared", "version": "1.0.0", "declaration": {"needs": [], "effects": []},
            "reason": "Install source through MCP."}});
    assert_eq!(
        lean.contracts
            .get(&(
                "artifacts_read".into(),
                "manage_alpha_tabs.prepare_install".into()
            ))
            .unwrap()
            .access,
        OperationAccess::Read
    );
    let direct = send(&full, 2, "artifacts_read", envelope.clone()).await;
    let through = send(
        &lean,
        2,
        "call_executor",
        routed("artifacts_read", envelope),
    )
    .await;
    assert_eq!(through["result"]["isError"], false, "{through}");
    assert_eq!(observed(&direct), observed(&through));
    assert_eq!(through["result"]["structuredContent"]["ready"], true);
    assert_eq!(
        through["result"]["structuredContent"]["next_call"]["operation"],
        "manage_alpha_tabs.install"
    );
}

#[test]
fn lean_catalogue_advertises_the_direct_set_and_keeps_every_callable_index() {
    let registry = registry();
    let full = full_catalogue(&registry, false);
    let lean = lean_catalogue(&registry, false);

    assert_eq!(names(&lean.descriptors), LEAN_ADVERTISED);
    assert!(full.direct_operations.is_none());
    assert!(!names(&full.descriptors).contains(&"call_executor"));

    // Advertisement is per operation and separate from the callable
    // indexes: contracts, aliases and classification stay whole.
    assert_eq!(
        lean.contracts.keys().collect::<Vec<_>>(),
        full.contracts.keys().collect::<Vec<_>>()
    );
    assert_eq!(lean.operations_by_executor, full.operations_by_executor);
    let direct = lean.direct_operations.as_ref().unwrap();
    assert_eq!(direct["records_read"], ["get_record", "search"]);
    assert_eq!(
        direct["records_write"],
        full.operations_by_executor["records_write"]
    );
    assert!(!direct.contains_key("records_delete"));

    // records_read is narrowed everywhere a discriminator appears, with
    // search-and-get_record prose and field listing.
    let records_read = descriptor(&lean.descriptors, "records_read");
    assert_eq!(
        records_read["inputSchema"]["properties"]["operation"]["enum"],
        json!(["get_record", "search"])
    );
    let schema = records_read["inputSchema"].to_string();
    for hidden in ["\"query_record\"", "get_dashboard:"] {
        assert!(!schema.contains(hidden), "{hidden} leaked into {schema}");
    }
    assert!(schema.contains("\"get_record\""), "{schema}");
    // The per-operation field listing names get_record's real fields and no
    // field that only another operation uses.
    let arguments = records_read["inputSchema"]["properties"]["arguments"]["description"]
        .as_str()
        .unwrap();
    assert!(arguments.contains("get_record:"), "{arguments}");
    for field in ["ids", "as_of"] {
        assert!(
            arguments.contains(field),
            "{field} missing from {arguments}"
        );
    }
    for other in ["query_record:", "steps"] {
        assert!(
            !arguments.contains(other),
            "{other} leaked into {arguments}"
        );
    }
    assert!(records_read["description"]
        .as_str()
        .unwrap()
        .contains("call_executor"));

    // Unchanged executors are byte-identical to the full catalogue's.
    for unchanged in [
        "bootstrap",
        "describe_operation",
        "system_read",
        "guidance_read",
        "records_write",
        "records_lifecycle",
        "coordination_write",
        "sql_read",
    ] {
        assert_eq!(
            descriptor(&lean.descriptors, unchanged),
            descriptor(&full.descriptors, unchanged),
            "{unchanged}"
        );
    }
    // describe_operation keeps its unnarrowed executor enum.
    assert_eq!(
        descriptor(&lean.descriptors, "describe_operation")["inputSchema"]["properties"]
            ["executor"]["enum"],
        descriptor(&full.descriptors, "describe_operation")["inputSchema"]["properties"]
            ["executor"]["enum"]
    );

    // call_executor reaches every contracted executor but bootstrap, and its
    // card carries the exact enumeration query and a worked example.
    let call = descriptor(&lean.descriptors, "call_executor");
    let targets = call["inputSchema"]["properties"]["executor"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let expected_targets = full
        .operations_by_executor
        .keys()
        .map(String::as_str)
        .filter(|executor| *executor != "bootstrap")
        .collect::<Vec<_>>();
    assert_eq!(targets, expected_targets);
    assert_eq!(
        call["inputSchema"]["required"],
        json!(["executor", "operation"])
    );
    let description = call["description"].as_str().unwrap();
    assert!(description.contains(lean::LEAN_CATALOG_QUERY));
    assert!(description.contains("operation:'get_history'"));
    for executor in full.operations_by_executor.keys() {
        if !direct.contains_key(executor) {
            assert!(description.contains(executor.as_str()), "{executor}");
        }
    }
    assert!(description.contains("records_read (all but get_record, search)"));

    // Bytes and digest are recomputed over the served projection.
    assert_eq!(
        lean.descriptor_bytes,
        serde_json::to_vec(&lean.descriptors).unwrap().len()
    );
    assert_eq!(
        lean.manifest_digest,
        jcs_sha256(&Value::Array(lean.descriptors.clone())).unwrap()
    );
    assert_ne!(lean.manifest_digest, full.manifest_digest);
}

#[test]
fn lean_hosted_descriptor_budget_is_measured_on_hosted_registrations() {
    let registry = hosted_registry();
    let full = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
        &registry,
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Executor,
    )
    .unwrap();
    let lean = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
        &registry,
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Lean,
    )
    .unwrap();
    let call_bytes = serde_json::to_vec(descriptor(&lean.descriptors, "call_executor"))
        .unwrap()
        .len();
    println!(
        "lean hosted executor descriptors: lean={} full={} call_executor={} limit={}",
        lean.descriptor_bytes(),
        full.descriptor_bytes(),
        call_bytes,
        LEAN_DESCRIPTOR_MAX_BYTES
    );
    assert_eq!(names(&lean.descriptors), LEAN_ADVERTISED);
    assert!(
        lean.descriptor_bytes() <= LEAN_DESCRIPTOR_MAX_BYTES,
        "lean descriptors {} exceed {}",
        lean.descriptor_bytes(),
        LEAN_DESCRIPTOR_MAX_BYTES
    );
    assert!(lean.descriptor_bytes() * 2 < full.descriptor_bytes());
    // Hosted-only executors stay callable through call_executor.
    let targets = descriptor(&lean.descriptors, "call_executor")["inputSchema"]["properties"]
        ["executor"]["enum"]
        .clone();
    for hosted_only in ["membership_admin", "workspace_read"] {
        assert!(
            targets.as_array().unwrap().contains(&json!(hosted_only)),
            "{hosted_only}"
        );
    }

    // An allowlisted experimental executor joins the callable set only.
    let allowlisted = ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
    let experimental = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
        &registry,
        &allowlisted,
        crate::mcp::McpSurfaceMode::Lean,
    )
    .unwrap();
    assert_eq!(names(&experimental.descriptors), LEAN_ADVERTISED);
    assert!(
        descriptor(&experimental.descriptors, "call_executor")["inputSchema"]["properties"]
            ["executor"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("sql_write"))
    );
    assert!(!targets.as_array().unwrap().contains(&json!("sql_write")));
}

#[test]
fn lean_classification_unwraps_call_executor_and_full_classification_is_unchanged() {
    let registry = registry();
    let full = full_catalogue(&registry, false);
    let lean = lean_catalogue(&registry, false);
    let access = |catalogue: &PinnedExecutorCatalogue, name: &str, arguments: Value| {
        catalogue
            .classify_tools_call(name, Some(&arguments))
            .map(|(operation, access)| (format!("{operation:?}"), access))
    };

    let delete = access(
        &lean,
        "call_executor",
        json!({"executor":"records_delete","operation":"delete_record"}),
    )
    .unwrap();
    assert_eq!(delete.1, OperationAccess::Mutation);
    assert_eq!(
        Some(delete),
        access(
            &full,
            "records_delete",
            json!({"operation":"delete_record"})
        )
    );
    assert_eq!(
        access(
            &lean,
            "call_executor",
            json!({"executor":"records_read","operation":"records_read.get_record"})
        ),
        access(&full, "records_read", json!({"operation":"get_record"}))
    );
    // A direct call to a hidden operation still classifies truthfully; the
    // lean dispatch refuses it before admission or plan access.
    assert_eq!(
        access(&lean, "records_read", json!({"operation":"get_record"})),
        access(&full, "records_read", json!({"operation":"get_record"}))
    );
    for unusable in [
        json!({"operation":"get_record"}),
        json!({"executor":"bootstrap","operation":"bootstrap"}),
        json!({"executor":"call_executor","operation":"get_record"}),
        json!({"executor":5,"operation":"get_record"}),
        json!({"executor":"no_such_executor","operation":"get_record"}),
    ] {
        assert_eq!(
            access(&lean, "call_executor", unusable.clone()),
            None,
            "{unusable}"
        );
    }
    // Off lean, call_executor is not a contract.
    assert_eq!(
        access(
            &full,
            "call_executor",
            json!({"executor":"records_read","operation":"get_record"})
        ),
        None
    );
}

#[tokio::test]
async fn call_executor_matches_direct_dispatch_for_reads_writes_and_refusals() {
    let (db, full, lean) = servers().await;
    let id = create_note(&full, 1, "Lean parity read").await;

    // Read.
    let read = json!({
        "operation":"get_record",
        "format":"json",
        "run_key":RUN_KEY,
        "arguments":{"ids":[id]}
    });
    let direct = send(&full, 2, "records_read", read.clone()).await;
    let through = send(
        &lean,
        2,
        "call_executor",
        routed("records_read", read.clone()),
    )
    .await;
    assert_eq!(direct["result"]["isError"], false, "{direct}");
    assert_eq!(observed(&through), observed(&direct));

    // Alias resolution is the direct path's.
    let aliased = send(
        &lean,
        3,
        "call_executor",
        routed(
            "records_read",
            json!({"operation":"records_read.get_record","format":"json","run_key":RUN_KEY,"arguments":{"ids":[id]}}),
        ),
    )
    .await;
    assert_eq!(observed(&aliased), observed(&direct));

    // Validation failure and its repair are the direct path's.
    let invalid = json!({"operation":"get_record","run_key":RUN_KEY,"arguments":{"ids":5}});
    let direct_invalid = send(&full, 4, "records_read", invalid.clone()).await;
    let through_invalid = send(
        &lean,
        4,
        "call_executor",
        routed("records_read", invalid.clone()),
    )
    .await;
    assert_eq!(direct_invalid["result"]["isError"], true);
    assert_eq!(observed(&through_invalid), observed(&direct_invalid));

    // Unknown pairs: operation and executor.
    for (executor, envelope) in [
        (
            "records_read",
            json!({"operation":"no_such_operation","run_key":RUN_KEY}),
        ),
        (
            "no_such_executor",
            json!({"operation":"get_record","run_key":RUN_KEY}),
        ),
    ] {
        let direct = send(&full, 5, executor, envelope.clone()).await;
        let through = send(&lean, 5, "call_executor", routed(executor, envelope)).await;
        assert_eq!(direct["result"]["isError"], true, "{direct}");
        assert_eq!(observed(&through), observed(&direct), "{executor}");
    }

    // Experimental-off target: not allowlisted, so not a contract on either.
    let experimental = json!({"operation":"preview","run_key":RUN_KEY,"arguments":{}});
    let direct = send(&full, 6, "sql_write", experimental.clone()).await;
    let through = send(&lean, 6, "call_executor", routed("sql_write", experimental)).await;
    assert_eq!(direct["result"]["isError"], true);
    assert_eq!(observed(&through), observed(&direct));

    // Write: the same governed create, attributed and captured the same way.
    let create = |name: &str| {
        json!({
            "operation":"create_record",
            "format":"json",
            "run_key":RUN_KEY,
            "arguments":{"type":"Document","kind":"note","name":name,"body":"x","reason":"Lean parity write."}
        })
    };
    let direct = send(&full, 7, "records_write", create("Direct write")).await;
    let through = send(
        &lean,
        7,
        "call_executor",
        routed("records_write", create("Routed write")),
    )
    .await;
    assert_eq!(direct["result"]["isError"], false, "{direct}");
    assert_eq!(through["result"]["isError"], false, "{through}");
    let keys = |response: &Value| {
        response["result"]["structuredContent"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&through), keys(&direct));
    db.drain_captures_for_tests().await;
    // The fixture run key is not issuance-shaped, so it is not a validated
    // column value; match the captured envelopes by tool and name instead.
    let captured: Vec<(String, String)> = sqlx::query_as(
        "SELECT tool, arguments FROM read_log_calls WHERE tool = 'create_record' ORDER BY seq",
    )
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    let routed_capture = captured
        .iter()
        .find(|(_, arguments)| arguments.contains("Routed write"))
        .expect("the routed write is captured like a direct one");
    let direct_capture = captured
        .iter()
        .find(|(_, arguments)| arguments.contains("Direct write"))
        .expect("the direct write is captured");
    assert_eq!(
        routed_capture.1.replace("Routed write", "<name>"),
        direct_capture.1.replace("Direct write", "<name>")
    );
    db.close().await;
}

#[tokio::test]
async fn call_executor_prepares_and_executes_plans_through_the_governed_path() {
    let (db, full, lean) = servers().await;
    let first = create_note(&full, 1, "Delete directly").await;
    let second = create_note(&full, 2, "Delete through call_executor").await;
    let prepare = |id: &str| {
        json!({
            "operation":"delete_record",
            "run_key":RUN_KEY,
            "arguments":{"id":id,"reason":"Lean parity plan."}
        })
    };

    let direct = send(&full, 3, "records_delete", prepare(&first)).await;
    assert_eq!(direct["result"]["isError"], false, "{direct}");
    assert_eq!(
        direct["result"]["structuredContent"]["next_call"]["tool"],
        "records_delete"
    );

    let prepared = send(
        &lean,
        4,
        "call_executor",
        routed("records_delete", prepare(&second)),
    )
    .await;
    assert_eq!(prepared["result"]["isError"], false, "{prepared}");
    let plan = &prepared["result"]["structuredContent"];
    assert_eq!(plan["preparation_mutated"], false);
    // The hidden target's continuation names call_executor, as written.
    assert_eq!(
        plan["next_call"],
        json!({
            "tool":"call_executor",
            "arguments":{
                "executor":"records_delete",
                "operation":"delete_record",
                "plan_id":plan["plan_id"],
                "target":plan["target"],
                "effect_summary":plan["effect_summary"],
            }
        })
    );
    // Preparation and execution stay separate: execution refuses raw arguments.
    let mut mixed = plan["next_call"]["arguments"].clone();
    mixed["arguments"] = json!({"id":second});
    let mut direct_mixed = mixed.clone();
    direct_mixed.as_object_mut().unwrap().remove("executor");
    let refused_mixed = send(&lean, 5, "call_executor", mixed).await;
    let direct_refused_mixed = send(&full, 5, "records_delete", direct_mixed).await;
    assert_eq!(refused_mixed["result"]["isError"], true, "{refused_mixed}");
    assert_eq!(
        refused_mixed["result"]["structuredContent"]["plan_error"]["code"],
        direct_refused_mixed["result"]["structuredContent"]["plan_error"]["code"]
    );

    let mut execute = plan["next_call"]["arguments"].clone();
    execute["run_key"] = json!(RUN_KEY);
    let executed = send(&lean, 6, "call_executor", execute).await;
    assert_eq!(executed["result"]["isError"], false, "{executed}");
    let deleted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'record.deleted'",
    )
    .bind(&second)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(deleted, 1);

    // A surface switch invalidates prepared plans: they bind the served
    // manifest digest, which differs between the full and lean catalogues.
    let mut stale = direct["result"]["structuredContent"]["next_call"]["arguments"].clone();
    stale["executor"] = json!("records_delete");
    stale["run_key"] = json!(RUN_KEY);
    let switched = send(&lean, 7, "call_executor", stale).await;
    assert_eq!(switched["result"]["isError"], true, "{switched}");
    assert_eq!(
        switched["result"]["structuredContent"]["plan_error"]["code"],
        "plan_contract_mismatch"
    );
    let not_deleted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'record.deleted'",
    )
    .bind(&first)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(not_deleted, 0);
    db.close().await;
}

#[tokio::test]
async fn lean_refuses_direct_calls_to_operations_it_does_not_advertise() {
    let (db, full, lean) = servers().await;
    let id = create_note(&full, 1, "Hidden read target").await;

    let read = json!({"operation":"get_record","format":"json","run_key":RUN_KEY,"arguments":{"ids":[id]}});
    // get_record is advertised directly: the lean read matches the full one.
    let direct_read = send(&lean, 2, "records_read", read.clone()).await;
    assert_eq!(direct_read["result"]["isError"], false, "{direct_read}");
    let full_read = send(&full, 2, "records_read", read.clone()).await;
    assert_eq!(observed(&direct_read), observed(&full_read));

    // Another records_read operation stays routed: get_history is refused
    // with the call_executor repair.
    let history = json!({"operation":"get_history","format":"json","run_key":RUN_KEY,"arguments":{"record_id":id}});
    let refused = send(&lean, 2, "records_read", history.clone()).await;
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    let repair = &refused["result"]["structuredContent"]["repair"];
    assert_eq!(repair["code"], "call_executor_required");
    assert_eq!(repair["tool"], "call_executor");
    assert_eq!(
        repair["corrections"],
        json!([{"op":"add","path":"/executor","value":"records_read"}])
    );
    assert_eq!(repair["next_call"]["tool"], "call_executor");
    assert_eq!(
        repair["next_call"]["arguments"],
        routed("records_read", history.clone())
    );
    let text = refused["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not advertised directly"), "{text}");
    assert!(text.contains("call_executor"), "{text}");
    // The repair is callable as written and matches the direct full read.
    let repaired = send(
        &lean,
        3,
        "call_executor",
        repair["next_call"]["arguments"].clone(),
    )
    .await;
    let direct = send(&full, 3, "records_read", history).await;
    assert_eq!(observed(&repaired), observed(&direct));

    // A hidden mutation is refused before admission, preparation or dispatch.
    let delete = json!({"operation":"delete_record","run_key":RUN_KEY,"arguments":{"id":id,"reason":"must not run"}});
    let refused_delete = send(&lean, 4, "records_delete", delete).await;
    assert_eq!(refused_delete["result"]["isError"], true);
    assert!(refused_delete["result"]["structuredContent"]
        .get("plan_id")
        .is_none());
    assert_eq!(
        refused_delete["result"]["structuredContent"]["repair"]["next_call"]["arguments"]
            ["executor"],
        "records_delete"
    );

    // Unknown operations on a directly advertised executor list its direct
    // operations and point at call_executor for the rest.
    let unknown = send(
        &lean,
        5,
        "records_read",
        json!({"operation":"nope","run_key":RUN_KEY}),
    )
    .await;
    let text = unknown["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("select one of: get_record, search"), "{text}");
    assert!(text.contains("call_executor"), "{text}");
    // A direct call to a hidden executor's unknown operation says the same.
    let hidden = send(
        &lean,
        6,
        "records_delete",
        json!({"operation":"nope","run_key":RUN_KEY}),
    )
    .await;
    let text = hidden["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not advertised directly"), "{text}");

    // Advertised operations stay direct.
    let search = send(
        &lean,
        7,
        "records_read",
        json!({"operation":"search","format":"json","run_key":RUN_KEY,"arguments":{"query":"Hidden"}}),
    )
    .await;
    assert_eq!(search["result"]["isError"], false, "{search}");

    // The envelope itself is validated before any dispatch.
    for (envelope, needle) in [
        (
            json!({"operation":"get_record"}),
            "missing required string field 'executor'",
        ),
        (
            json!({"executor":"bootstrap","operation":"bootstrap"}),
            "call bootstrap directly",
        ),
        (
            json!({"executor":"describe_operation","operation":"x"}),
            "call describe_operation directly",
        ),
    ] {
        let refused = send(&lean, 8, "call_executor", envelope).await;
        assert_eq!(refused["result"]["isError"], true);
        let text = refused["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(needle), "{text}");
    }
    // Off lean there is no call_executor.
    let absent = send(
        &full,
        9,
        "call_executor",
        json!({"executor":"records_read","operation":"get_record"}),
    )
    .await;
    assert!(absent["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("unknown executor 'call_executor'"));
    db.close().await;
}

#[tokio::test]
async fn lean_discovery_keeps_every_contract_and_marks_direct_advertisement() {
    let (db, full, lean) = servers().await;

    let described = send(
        &lean,
        1,
        "describe_operation",
        json!({"executor":"records_delete","operation":"delete_record"}),
    )
    .await;
    let direct_described = send(
        &full,
        1,
        "describe_operation",
        json!({"executor":"records_delete","operation":"delete_record"}),
    )
    .await;
    assert_eq!(described["result"]["isError"], false, "{described}");
    assert_eq!(observed(&described), observed(&direct_described));

    let catalog = |sql: &str| json!({"operation":"query_sql","format":"json","run_key":RUN_KEY,"arguments":{"sql":sql}});
    let rows = send(
        &lean,
        2,
        "sql_read",
        catalog("SELECT executor, operation, contract_digest, advertised_directly FROM catalog_operations ORDER BY executor, operation"),
    )
    .await;
    assert_eq!(rows["result"]["isError"], false, "{rows}");
    let rows = rows["result"]["structuredContent"]["rows"]
        .as_array()
        .unwrap()
        .clone();
    let direct = lean.direct_operations.as_ref().unwrap();
    let contracts = &lean.contracts;
    let expected = lean
        .operations_by_executor
        .iter()
        .flat_map(|(executor, operations)| {
            operations.iter().map(move |operation| {
                json!({
                    "executor":executor,
                    "operation":operation,
                    "contract_digest":contracts[&(executor.clone(), operation.clone())].digest,
                    "advertised_directly": i64::from(lean::is_directly_advertised(direct, executor, operation)),
                })
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(rows, expected);

    // The advertised enumeration query returns exactly the hidden pairs.
    let hidden = send(&lean, 3, "sql_read", catalog(lean::LEAN_CATALOG_QUERY)).await;
    let hidden_pairs = hidden["result"]["structuredContent"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["executor"].as_str().unwrap().to_string(),
                row["operation"].as_str().unwrap().to_string(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let all_pairs = lean
        .operations_by_executor
        .iter()
        .flat_map(|(executor, operations)| {
            operations
                .iter()
                .map(move |operation| (executor.clone(), operation.clone()))
        })
        .collect::<std::collections::BTreeSet<_>>();
    let expected_hidden = all_pairs
        .difference(&lean::direct_pairs(direct))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(hidden_pairs, expected_hidden);
    assert!(!hidden_pairs.contains(&("records_read".into(), "get_record".into())));
    assert!(hidden_pairs.contains(&("records_read".into(), "get_history".into())));

    // A full server marks every row as advertised directly.
    let full_rows = send(
        &full,
        4,
        "sql_read",
        catalog("SELECT COUNT(*) AS hidden FROM catalog_operations WHERE advertised_directly = 0"),
    )
    .await;
    assert_eq!(
        full_rows["result"]["structuredContent"]["rows"][0]["hidden"],
        0
    );
    db.close().await;
}

#[tokio::test]
async fn lean_bootstrap_reports_the_projection_in_json_and_text() {
    let (db, full, lean) = servers().await;

    let json_bootstrap = send(&lean, 1, "bootstrap", json!({"format":"json"})).await;
    assert_eq!(
        json_bootstrap["result"]["isError"], false,
        "{json_bootstrap}"
    );
    // The rebased posture capsule must coexist with the record-reading
    // examples below, on both the structured and rendered lean bootstrap.
    let posture = json_bootstrap["result"]["structuredContent"]["orientation"]["content"]
        .as_str()
        .unwrap();
    for cue in ["app-builder-1.0.0", "Preview/Adopt", "`compositions`"] {
        assert!(posture.contains(cue), "{posture}");
    }
    let exposure = &json_bootstrap["result"]["structuredContent"]["tool_exposure"];
    assert_eq!(exposure["surface"], "executor");
    assert_eq!(exposure["scope"], "ordinary");
    assert_eq!(exposure["projection"], "lean");
    assert_eq!(exposure["advertised_count"], LEAN_ADVERTISED.len());
    assert_eq!(exposure["advertised_bytes"], lean.descriptor_bytes);
    assert_eq!(exposure["advertised_tools"], json!(LEAN_ADVERTISED));
    let call = &exposure["call_executor"];
    assert_eq!(call["catalog_query"], lean::LEAN_CATALOG_QUERY);
    assert!(call["hidden_executors"]
        .as_array()
        .unwrap()
        .contains(&json!("records_delete")));
    assert_eq!(
        call["narrowed_executors"]["records_read"],
        json!(["get_record", "search"])
    );
    assert_eq!(
        call["examples"][0],
        json!({"executor":"records_read","operation":"get_history","arguments":{"record_id":"<id or short reference>"}})
    );
    let examples = call["examples"].as_array().unwrap();
    assert!(examples
        .iter()
        .any(|example| example["executor"] == "sql_read"
            && example["operation"] == "query_sql"
            && example["arguments"]["sql"]
                .as_str()
                .unwrap()
                .contains("WHERE")));
    assert!(examples
        .iter()
        .any(|example| example["operation"] == "search"));
    let guidance = call["guidance"].as_str().unwrap();
    for phrase in [
        "known reference",
        "filter, count or follow links",
        "free text",
    ] {
        assert!(guidance.contains(phrase), "{guidance}");
    }
    let expected_hidden = lean
        .operations_by_executor
        .iter()
        .filter(|(executor, _)| executor.as_str() != "bootstrap")
        .flat_map(|(executor, operations)| {
            operations
                .iter()
                .map(move |operation| (executor, operation))
        })
        .filter(|(executor, operation)| {
            !lean::is_directly_advertised(
                lean.direct_operations.as_ref().unwrap(),
                executor,
                operation,
            )
        })
        .count();
    assert_eq!(call["hidden_operation_count"], expected_hidden);

    let text_bootstrap = send(&lean, 2, "bootstrap", json!({"format":"text"})).await;
    let text = text_bootstrap["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("## Lean tool surface"), "{text}");
    for cue in ["app-builder-1.0.0", "Preview/Adopt", "`compositions`"] {
        assert!(text.contains(cue), "{text}");
    }
    assert!(text.contains(lean::LEAN_CATALOG_QUERY), "{text}");
    assert!(
        text.contains("Reachable only through `call_executor`:"),
        "{text}"
    );
    assert!(text.contains("records_delete"), "{text}");
    assert!(
        text.contains("`records_read` is advertised for get_record and search only"),
        "{text}"
    );
    assert!(text.contains("Example `call_executor`:"), "{text}");
    assert!(
        text.contains("choose, filter, count or follow links with sql_read query_sql"),
        "{text}"
    );

    // The full executor bootstrap is unchanged.
    let full_text = send(&full, 3, "bootstrap", json!({"format":"text"})).await;
    let full_text = full_text["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!full_text.contains("Lean tool surface"));
    let full_json = send(&full, 4, "bootstrap", json!({"format":"json"})).await;
    assert!(full_json["result"]["structuredContent"]["tool_exposure"]
        .get("projection")
        .is_none());
    db.close().await;
}

#[tokio::test]
async fn call_executor_routing_is_marked_in_telemetry_and_trace() {
    let db = create_database(":memory:").await.unwrap();
    let sink = Arc::new(telemetry::TestTelemetrySink::default());
    let context = ExecutorTelemetryContext::new(sink.clone(), DEFAULT_RETENTION_DAYS).unwrap();
    let lean = ExecutorPrototypeStdioServer::new_for_surface(
        registry(),
        db.clone(),
        Caller::local(),
        None,
        Some(context.clone()),
        ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Lean,
    )
    .await
    .unwrap();
    let id = create_note(&lean, 1, "Routing fixture").await;
    let baseline = sink.events().len();
    let trace_baseline = lean.trace_events().len();

    let routed_read = send(
        &lean,
        2,
        "call_executor",
        json!({"executor":"records_read","operation":"get_record","run_key":RUN_KEY,"arguments":{"ids":[id]}}),
    )
    .await;
    assert_eq!(routed_read["result"]["isError"], false, "{routed_read}");
    let routed_invalid = send(
        &lean,
        3,
        "call_executor",
        json!({"executor":"records_read","operation":"get_record","run_key":RUN_KEY,"arguments":{"ids":5}}),
    )
    .await;
    assert_eq!(routed_invalid["result"]["isError"], true);
    let routed_unresolved = send(
        &lean,
        4,
        "call_executor",
        json!({"operation":"get_record","run_key":RUN_KEY}),
    )
    .await;
    assert_eq!(routed_unresolved["result"]["isError"], true);
    let direct_search = send(
        &lean,
        5,
        "records_read",
        json!({"operation":"search","run_key":RUN_KEY,"arguments":{"query":"Routing"}}),
    )
    .await;
    assert_eq!(direct_search["result"]["isError"], false, "{direct_search}");
    context.flush().unwrap();

    let events = sink.events()[baseline..]
        .iter()
        .map(|event| serde_json::from_slice::<Value>(event).unwrap())
        .filter(|event| !event["request"].is_null())
        .collect::<Vec<_>>();
    let routed_events = |operation: &str| {
        events
            .iter()
            .filter(|event| event["request"]["operation"] == operation)
            .collect::<Vec<_>>()
    };
    // Target, route and outcome are distinguishable per request.
    let get_record = routed_events("get_record");
    assert!(!get_record.is_empty());
    for event in &get_record {
        assert_eq!(event["request"]["route"], "call_executor", "{event}");
        assert_eq!(event["request"]["executor"], "records_read", "{event}");
    }
    assert!(get_record.iter().any(|event| {
        event["phase"] == "dispatch_completed" && event["outcome"] == "succeeded"
    }));
    assert!(get_record.iter().any(|event| {
        event["phase"] == "validation_completed"
            && event["outcome"] == "rejected"
            && event["error_class"] == "schema_validation"
    }));
    // An envelope that names no target is still marked as routed.
    assert!(events.iter().any(|event| {
        event["request"]["route"] == "call_executor"
            && event["request"]["executor"] == "unknown"
            && event["error_class"] == "selection_error"
    }));
    // A local lean server binds its session to the lean surface.
    assert!(events
        .iter()
        .all(|event| event["session"]["surface"] == "lean"));
    // Direct calls keep the historical event shape: no route key.
    let search = routed_events("search");
    assert!(!search.is_empty());
    for event in search {
        assert!(event["request"].get("route").is_none(), "{event}");
    }

    let trace = lean.trace_events()[trace_baseline..].to_vec();
    assert!(trace.iter().any(|event| {
        event["route"] == "call_executor"
            && event["executor"] == "records_read"
            && event["operation"] == "get_record"
            && event["completed"] == true
    }));
    assert!(trace.iter().any(|event| {
        event["route"] == "call_executor" && event["kind"] == "validation_failure"
    }));
    assert!(trace
        .iter()
        .filter(|event| event["operation"] == "search")
        .all(|event| event.get("route").is_none()));
    db.close().await;
}

#[tokio::test]
async fn early_lean_refusal_renders_the_dispatch_refusal_without_run_context() {
    let (db, full, lean) = servers().await;
    let registry = registry();
    let catalogue = lean_catalogue(&registry, false);
    let full_catalogue = full_catalogue(&registry, false);
    let envelope = json!({"operation":"get_history","arguments":{"record_id":"x"}});
    let dispatched = send(&lean, 1, "records_read", envelope.clone()).await;
    let early = catalogue
        .lean_direct_refusal(json!(1), false, "records_read", Some(&envelope))
        .expect("a hidden direct call is refused early");
    assert_eq!(early["id"], 1);
    assert_eq!(early["result"]["isError"], true);
    assert_eq!(
        early["result"]["structuredContent"]["repair"],
        dispatched["result"]["structuredContent"]["repair"]
    );
    assert_eq!(
        early["result"]["structuredContent"]["repair"]["next_call"]["arguments"]["operation"],
        "get_history"
    );
    assert_eq!(early["result"]["_meta"], dispatched["result"]["_meta"]);
    let early_text = early["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        early_text.contains("not advertised directly"),
        "{early_text}"
    );
    assert!(early_text.contains("Repair contract:"), "{early_text}");
    // A nested-only operation is read where dispatch hoists it.
    assert!(catalogue
        .lean_direct_refusal(
            json!(2),
            true,
            "records_delete",
            Some(&json!({"arguments":{"operation":"delete_record","id":"x"}}))
        )
        .is_some());
    for (name, arguments) in [
        (
            "records_read",
            json!({"operation":"search","arguments":{"query":"x"}}),
        ),
        (
            "records_read",
            json!({"operation":"get_record","arguments":{"ids":["x"]}}),
        ),
        ("records_read", json!({"operation":"no_such_operation"})),
        (
            "call_executor",
            json!({"executor":"records_read","operation":"get_record"}),
        ),
        ("bootstrap", json!({})),
        (
            "describe_operation",
            json!({"executor":"records_delete","operation":"delete_record"}),
        ),
        ("no_such_executor", json!({"operation":"get_record"})),
    ] {
        assert!(
            catalogue
                .lean_direct_refusal(json!(3), false, name, Some(&arguments))
                .is_none(),
            "{name} {arguments}"
        );
    }
    assert!(full_catalogue
        .lean_direct_refusal(json!(4), false, "records_read", Some(&envelope))
        .is_none());
    drop(full);
    db.close().await;
}

#[test]
fn lean_ordinary_sessions_are_marked_lean_and_every_other_catalogue_executor() {
    let sink = Arc::new(telemetry::TestTelemetrySink::default());
    let context = ExecutorTelemetryContext::new(sink.clone(), DEFAULT_RETENTION_DAYS).unwrap();
    let registry = hosted_registry();
    let lean = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
        &registry,
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Lean,
    )
    .unwrap();
    let full = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
        &registry,
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Executor,
    )
    .unwrap();
    let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
        &registry,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    for (catalogue_lean, digest, bytes) in [
        (
            lean.is_lean(),
            lean.manifest_digest(),
            lean.descriptor_bytes(),
        ),
        (
            full.is_lean(),
            full.manifest_digest(),
            full.descriptor_bytes(),
        ),
    ] {
        context
            .bind_hosted_manifest_for_surface(
                telemetry::TelemetrySurface::for_ordinary_catalogue(catalogue_lean),
                digest,
                bytes,
            )
            .authorization_accepted();
    }
    // Lens catalogues keep the historical binding, whatever the surface.
    context
        .bind_hosted_manifest(lens.manifest_digest(), lens.descriptor_bytes())
        .authorization_accepted();
    context.flush().unwrap();
    let surfaces = sink
        .events()
        .iter()
        .map(|event| serde_json::from_slice::<Value>(event).unwrap())
        .filter(|event| event["phase"] == "authorization_checked")
        .map(|event| {
            (
                event["session"]["manifest_sha256"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                event["session"]["surface"].as_str().unwrap().to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        surfaces,
        [
            (lean.manifest_digest().to_string(), "lean".to_string()),
            (full.manifest_digest().to_string(), "executor".to_string()),
            (lens.manifest_digest().to_string(), "executor".to_string()),
        ]
    );
}
