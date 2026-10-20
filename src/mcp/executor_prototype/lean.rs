//! Lean projection of the ordinary executor catalogue.
//!
//! `NATIVE_CE_MCP_SURFACE=lean` advertises a small direct set plus one
//! generic entry point, `call_executor`. The projection changes discovery
//! only. Every callable index — contracts, aliases, classification,
//! `describe_operation` and `catalog_operations` — stays the full ordinary
//! catalogue, and a `call_executor` request is unwrapped into the exact
//! envelope a direct executor call would carry before it enters the one
//! governed dispatch path in [`ExecutorPrototypeStdioServer`]. There is no
//! second lookup, authorization, plan or capture path here.
//!
//! What lean tracks separately is *direct advertisement*, per operation: a
//! lean server refuses a direct call to an operation it does not advertise
//! directly (for example a cached `records_read.get_record` schema) and the
//! repair names the equivalent `call_executor` call.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{OperationContracts, OperationsByExecutor};

/// The one generic entry point the lean surface adds.
pub(super) const CALL_EXECUTOR: &str = "call_executor";

/// Executors advertised directly on the lean surface. Each keeps every
/// operation it routes except where [`LEAN_NARROWED_OPERATIONS`] narrows it.
const LEAN_DIRECT_EXECUTORS: &[&str] = &[
    "bootstrap",
    "describe_operation",
    "system_read",
    "coordination_write",
    "sql_read",
    "guidance_read",
    "records_read",
    "records_write",
    "records_lifecycle",
];

/// Directly advertised executors narrowed to a subset of their operations.
const LEAN_NARROWED_OPERATIONS: &[(&str, &[&str])] = &[("records_read", &["search"])];

/// `call_executor` never wraps these: they are advertised directly and are
/// not ordinary operation contracts on the generic path.
const CALL_EXECUTOR_EXCLUDED_TARGETS: &[&str] = &["bootstrap", "describe_operation", CALL_EXECUTOR];

/// Exact enumeration of everything reachable only through `call_executor`.
pub(super) const LEAN_CATALOG_QUERY: &str = "SELECT executor, operation, access, plan_required FROM catalog_operations WHERE advertised_directly = 0 ORDER BY executor, operation";

/// Search-only prose for the narrowed `records_read` descriptor. The audited
/// prose names `get_record` and `query_record`, which are not advertised
/// directly here.
const LEAN_RECORDS_READ_DESCRIPTION: &str = "Search authorized records by lexical text: {operation:'search', arguments:{query:'...'}}. Prefer sql_read query_sql for structured reads. Every other records_read operation (get_record, query_record, get_structure, get_history, whats_changed and more) stays callable through call_executor, e.g. {executor:'records_read', operation:'get_record', arguments:{ids:[reference]}}.";

/// How a `tools/call` reached the governed dispatch path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CallRoute {
    /// Addressed by executor tool name.
    Direct,
    /// Unwrapped from a `call_executor` envelope.
    CallExecutor,
}

/// The per-operation index of what a lean catalogue advertises directly.
/// `bootstrap` keeps its single contract; `describe_operation` is not a
/// contract and is advertised unconditionally.
pub(super) fn direct_operations(callable: &OperationsByExecutor) -> OperationsByExecutor {
    let mut direct = OperationsByExecutor::new();
    for executor in LEAN_DIRECT_EXECUTORS {
        let Some(operations) = callable.get(*executor) else {
            continue;
        };
        let narrowed = LEAN_NARROWED_OPERATIONS
            .iter()
            .find(|(name, _)| name == executor)
            .map(|(_, retained)| *retained);
        let operations = operations
            .iter()
            .filter(|operation| {
                narrowed.is_none_or(|retained| retained.contains(&operation.as_str()))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !operations.is_empty() {
            direct.insert((*executor).to_string(), operations);
        }
    }
    direct
}

pub(super) fn is_directly_advertised(
    direct: &OperationsByExecutor,
    executor: &str,
    operation: &str,
) -> bool {
    direct
        .get(executor)
        .is_some_and(|operations| operations.iter().any(|listed| listed == operation))
}

/// Restrict a contract map to the directly advertised pairs, so lean
/// descriptor post-processing (format conditions, field listings) describes
/// exactly the advertised enum and nothing hidden.
pub(super) fn direct_contracts(
    contracts: &OperationContracts,
    direct: &OperationsByExecutor,
) -> OperationContracts {
    contracts
        .iter()
        .filter(|((executor, operation), _)| is_directly_advertised(direct, executor, operation))
        .map(|(key, contract)| (key.clone(), contract.clone()))
        .collect()
}

/// Project executable (enum-narrowed, pre-post-processing) descriptors onto
/// the lean direct set. `describe_operation` keeps its unnarrowed executor
/// enum: it answers every contracted pair.
pub(super) fn project_descriptors(
    descriptors: Vec<Value>,
    direct: &OperationsByExecutor,
) -> Vec<Value> {
    let mut projected = Vec::new();
    for mut descriptor in descriptors {
        let Some(name) = descriptor
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        if name == "describe_operation" {
            projected.push(descriptor);
            continue;
        }
        let Some(operations) = direct.get(&name) else {
            continue;
        };
        if name != "bootstrap" {
            descriptor["inputSchema"]["properties"]["operation"]["enum"] = json!(operations);
            let retained = operations
                .iter()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>();
            super::filter_operation_constraints(&mut descriptor["inputSchema"], &retained);
        }
        if name == "records_read" {
            descriptor["description"] = json!(LEAN_RECORDS_READ_DESCRIPTION);
        }
        projected.push(descriptor);
    }
    projected
}

/// Executors with no directly advertised operation, and executors that are
/// advertised but narrowed (with their direct operations).
fn hidden_executors(
    callable: &OperationsByExecutor,
    direct: &OperationsByExecutor,
) -> (Vec<String>, BTreeMap<String, Vec<String>>) {
    let mut hidden = Vec::new();
    let mut narrowed = BTreeMap::new();
    for (executor, operations) in callable {
        if CALL_EXECUTOR_EXCLUDED_TARGETS.contains(&executor.as_str()) {
            continue;
        }
        match direct.get(executor) {
            None => hidden.push(executor.clone()),
            Some(direct_operations) if direct_operations.len() < operations.len() => {
                narrowed.insert(executor.clone(), direct_operations.clone());
            }
            Some(_) => {}
        }
    }
    (hidden, narrowed)
}

fn hidden_operation_count(callable: &OperationsByExecutor, direct: &OperationsByExecutor) -> usize {
    callable
        .iter()
        .filter(|(executor, _)| !CALL_EXECUTOR_EXCLUDED_TARGETS.contains(&executor.as_str()))
        .flat_map(|(executor, operations)| {
            operations
                .iter()
                .map(move |operation| (executor.as_str(), operation.as_str()))
        })
        .filter(|(executor, operation)| !is_directly_advertised(direct, executor, operation))
        .count()
}

fn narrowed_clause(narrowed: &BTreeMap<String, Vec<String>>) -> String {
    narrowed
        .iter()
        .map(|(executor, operations)| format!("{executor} (all but {})", operations.join(", ")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The advertised `call_executor` descriptor. Its envelope is the ordinary
/// executor envelope plus `executor`; preparation and execution stay
/// mutually exclusive exactly as on plan-carrying executors.
pub(super) fn call_executor_descriptor(
    callable: &OperationsByExecutor,
    direct: &OperationsByExecutor,
) -> Value {
    let targets = callable
        .keys()
        .filter(|executor| !CALL_EXECUTOR_EXCLUDED_TARGETS.contains(&executor.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let (hidden, narrowed) = hidden_executors(callable, direct);
    let mut reach = format!("Executors reachable only here: {}.", hidden.join(", "));
    if !narrowed.is_empty() {
        reach.push_str(&format!(
            " Partly advertised: {}.",
            narrowed_clause(&narrowed)
        ));
    }
    let description = format!(
        "Call any contracted operation that is not advertised directly, through the same contract, authorization, validation and plan gating as a direct executor call. {reach} List them with sql_read query_sql: {LEAN_CATALOG_QUERY}; describe_operation {{executor, operation}} returns any contract. Example: {{executor:'records_read', operation:'get_record', arguments:{{ids:[reference]}}}}. Plan-required operations: prepare with {{executor, operation, arguments}}, then execute only with the returned {{executor, operation, plan_id, target, effect_summary}}."
    );
    json!({
        "name": CALL_EXECUTOR,
        "title": "Call executor",
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "executor": {
                    "type": "string",
                    "enum": targets,
                    "description": "Target executor."
                },
                "operation": {
                    "type": "string",
                    "description": "Target operation, as listed by catalog_operations or describe_operation."
                },
                "arguments": {
                    "type": "object",
                    "description": "Nested operation arguments only. Keep executor, operation, run_key, parent_key and format in the call_executor envelope."
                },
                "run_key": {"type": "string"},
                "parent_key": {"type": "string"},
                "format": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "description": "Response representation. Availability follows the target operation; plan-backed operations are json only. Keep this field outside nested arguments."
                },
                "plan_id": {"type": "string", "description": "Opaque id returned by preparation."},
                "target": {"type": "string", "description": "Exact visible target returned by preparation."},
                "effect_summary": {"type": "string", "description": "Exact visible effect returned by preparation."}
            },
            "required": ["executor", "operation"],
            "additionalProperties": false,
            "oneOf": [
                {
                    "title": "Direct or prepare",
                    "not": {"anyOf": [
                        {"required": ["plan_id"]},
                        {"required": ["target"]},
                        {"required": ["effect_summary"]}
                    ]}
                },
                {
                    "title": "Execute prepared plan",
                    "required": ["plan_id", "target", "effect_summary"],
                    "not": {"required": ["arguments"]}
                }
            ]
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false,
            "openWorldHint": false
        }
    })
}

/// Lean fields merged into bootstrap's `tool_exposure` summary. The text
/// bootstrap renders the same object.
pub(super) fn exposure_summary(
    callable: &OperationsByExecutor,
    direct: &OperationsByExecutor,
    advertised_tools: &[Value],
) -> Value {
    let (hidden, narrowed) = hidden_executors(callable, direct);
    let advertised = advertised_tools
        .iter()
        .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    json!({
        "advertised_tools": advertised,
        "call_executor": {
            "hidden_executors": hidden,
            "narrowed_executors": narrowed,
            "hidden_operation_count": hidden_operation_count(callable, direct),
            "catalog_query": LEAN_CATALOG_QUERY,
            "examples": [
                {"executor": "records_read", "operation": "get_record", "arguments": {"ids": ["<id or short reference>"]}},
                {"executor": "sql_read", "operation": "query_sql", "arguments": {"sql": "SELECT id, name FROM records WHERE type = 'WorkItem' ORDER BY id LIMIT 20"}},
                {"executor": "records_read", "operation": "search", "arguments": {"query": "<words>"}},
                {"executor": "coordination_read", "operation": "get_run_activity", "arguments": {}}
            ],
            "guidance": "Open a known reference with get_record; choose, filter, count or follow links with sql_read query_sql; use records_read search for free text, and reach any other operation through call_executor with {executor, operation, arguments}. It runs the same contract, authorization, validation and plan gating as a direct call."
        }
    })
}

/// Split one `call_executor` envelope into its target executor and the exact
/// envelope a direct call to that executor carries. Only the top-level
/// `executor` field is removed, so every JSON pointer in a later repair is
/// still relative to the caller's own envelope.
pub(crate) fn unwrap_envelope(arguments: &Value) -> Result<(String, Value), String> {
    let executor = target_executor(arguments)?.to_string();
    let mut inner = arguments
        .as_object()
        .cloned()
        .expect("target_executor accepted an object envelope");
    inner.remove("executor");
    Ok((executor, Value::Object(inner)))
}

/// The target executor named by one `call_executor` envelope, validated the
/// same way for pre-auth classification and dispatch.
pub(super) fn target_executor(arguments: &Value) -> Result<&str, String> {
    let Some(envelope) = arguments.as_object() else {
        return Err("call_executor arguments must be an object".into());
    };
    let executor = match envelope.get("executor") {
        Some(Value::String(executor)) if !executor.is_empty() => executor.as_str(),
        Some(_) => return Err("call_executor field 'executor' must be a non-empty string naming the target executor".into()),
        None => return Err(format!(
            "missing required string field 'executor'. call_executor routes {{executor, operation, arguments}}; list targets with sql_read query_sql: {LEAN_CATALOG_QUERY}"
        )),
    };
    if CALL_EXECUTOR_EXCLUDED_TARGETS.contains(&executor) {
        return Err(format!(
            "{executor} is advertised directly on this surface and is not a call_executor target; call {executor} directly"
        ));
    }
    Ok(executor)
}

/// Selection diagnostic for a direct call on a lean server whose operation
/// is not a known direct operation of that executor.
pub(super) fn unknown_direct_operation_diagnostic(
    executor: &str,
    operation: &str,
    callable: &OperationsByExecutor,
    direct: &OperationsByExecutor,
) -> Option<String> {
    let callable_operations = callable.get(executor)?;
    let direct_operations = direct.get(executor).cloned().unwrap_or_default();
    let hidden_known = callable_operations.iter().any(|listed| listed == operation);
    if hidden_known {
        return None;
    }
    if direct_operations.is_empty() {
        return Some(format!(
            "{executor} is not advertised directly on this lean surface; call its operations through call_executor with {{executor:'{executor}', operation, arguments}}. Its operations: {}",
            callable_operations.join(", ")
        ));
    }
    Some(format!(
        "unknown operation '{operation}' for {executor}; select one of: {}. Other {executor} operations ({}) are callable through call_executor with {{executor:'{executor}', operation, arguments}}. Keep operation as routing metadata and nest operation-specific fields under arguments",
        direct_operations.join(", "),
        callable_operations
            .iter()
            .filter(|listed| !direct_operations.contains(listed))
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Largest equivalent envelope the direct-call refusal will echo as a
/// literal `next_call`. Larger envelopes are described by their correction.
const REFUSAL_NEXT_CALL_MAX_BYTES: usize = 2048;

/// Structured repair for a direct call to an operation this lean server
/// does not advertise directly. The governed path was not entered: nothing
/// was validated, admitted, prepared or dispatched.
pub(super) fn direct_refusal(executor: &str, operation: &str, envelope: &Value) -> (String, Value) {
    let mut equivalent = serde_json::Map::new();
    equivalent.insert("executor".into(), json!(executor));
    if let Some(fields) = envelope.as_object() {
        for (key, value) in fields {
            equivalent.insert(key.clone(), value.clone());
        }
    }
    equivalent.insert("operation".into(), json!(operation));
    let equivalent = Value::Object(equivalent);
    let routing = json!({"executor": executor, "operation": operation});
    let diagnostic = format!(
        "{executor}.{operation} is not advertised directly on this lean surface. Send the same envelope to call_executor with executor '{executor}': {routing} plus your arguments, run_key, parent_key and format unchanged."
    );
    let mut repair = json!({
        "code": "call_executor_required",
        "reason_code": "not_advertised_directly",
        "error_class": "selection_error",
        "executor": executor,
        "operation": operation,
        "tool": CALL_EXECUTOR,
        "corrections": [{"op": "add", "path": "/executor", "value": executor}],
        "retry_ready": true,
    });
    if serde_json::to_vec(&equivalent).is_ok_and(|bytes| bytes.len() <= REFUSAL_NEXT_CALL_MAX_BYTES)
    {
        repair["next_call"] = json!({"tool": CALL_EXECUTOR, "arguments": equivalent});
    }
    (diagnostic, repair)
}

/// Attach the structured direct-call repair to one rendered refusal, in
/// the same shape whether the refusal is rendered at hosted pre-auth, by the
/// maintenance proxy, or at dispatch.
pub(super) fn attach_direct_refusal_repair(body: &mut Value, repair: Value) {
    let repair_text = repair.to_string();
    body["result"]["structuredContent"]["repair"] = repair;
    if let Some(Value::String(text)) = body.pointer_mut("/result/content/0/text") {
        text.push_str(&format!("\nRepair contract: {repair_text}"));
    }
}

/// Rewrite a tool-addressed continuation (`next_call: {tool, arguments}`)
/// whose target is not advertised directly so that it names
/// `call_executor`. Continuations already addressed to an advertised
/// operation, or without a `tool`, are left untouched.
pub(super) fn rewrite_next_call(value: &mut Value, direct: &OperationsByExecutor) {
    let Some(next_call) = value.get_mut("next_call").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(tool) = next_call
        .get("tool")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    if tool == CALL_EXECUTOR {
        return;
    }
    let Some(operation) = next_call
        .get("arguments")
        .and_then(|arguments| arguments.get("operation"))
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    if is_directly_advertised(direct, &tool, &operation) {
        return;
    }
    let mut arguments = serde_json::Map::new();
    arguments.insert("executor".into(), json!(tool));
    if let Some(Value::Object(fields)) = next_call.get("arguments") {
        for (key, value) in fields {
            arguments.insert(key.clone(), value.clone());
        }
    }
    next_call.insert("tool".into(), json!(CALL_EXECUTOR));
    next_call.insert("arguments".into(), Value::Object(arguments));
}

/// Directly advertised pairs, as a set, for assertions and projection.
#[cfg(test)]
pub(super) fn direct_pairs(
    direct: &OperationsByExecutor,
) -> std::collections::BTreeSet<(String, String)> {
    direct
        .iter()
        .flat_map(|(executor, operations)| {
            operations
                .iter()
                .map(move |operation| (executor.clone(), operation.clone()))
        })
        .collect()
}
