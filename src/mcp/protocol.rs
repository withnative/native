//! Transport-neutral MCP JSON-RPC dispatch.
//!
//! The 2026-07-28 protocol is stateless: every request carries its protocol
//! revision and client capabilities in `params._meta`. Both stdio and hosted
//! Streamable HTTP dispatch modern requests here, so method behavior and MCP
//! result framing cannot drift between transports. The initialize-era
//! dispatcher is shared here too, allowing stdio and authenticated HTTP to
//! expose the same legacy list/call/error behavior without protocol sessions.
//! HTTP-only concerns (authentication, Origin, Accept, and header validation)
//! remain in the held hosting gateway; newline framing remains in `mcp::stdio`.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::Error;

use super::evidence::ToolResult;
use super::lens_dispatch::LensDispatch;
use super::registry::{attach_run_context, Caller, EngineHandle, ToolRegistry};
use super::DeploymentPersistenceLease;
use super::ResolvedToolExposure;
use super::{apps, render};

/// The current, stateless MCP revision implemented by both transports.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Legacy MCP protocol revision preferred for initialize-era clients.
pub(crate) const LEGACY_PROTOCOL_VERSION: &str = "2025-06-18";

/// The only revisions negotiable through the legacy `initialize` lifecycle.
pub(crate) const LEGACY_SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] =
    ["2025-06-18", "2025-03-26", "2024-11-05"];

pub(crate) const PARSE_ERROR: i64 = -32700;
pub(crate) const INVALID_REQUEST: i64 = -32600;
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
pub(crate) const INVALID_PARAMS: i64 = -32602;
pub(crate) const INTERNAL_ERROR: i64 = -32603;
pub(crate) const HEADER_MISMATCH: i64 = -32020;
pub(crate) const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_INFO_META: &str = "io.modelcontextprotocol/clientInfo";
const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO_META: &str = "io.modelcontextprotocol/serverInfo";

/// Dispatch result before a transport renders it.
pub(crate) enum RpcOutcome {
    /// A notification never receives a JSON-RPC body.
    Notification,
    /// A request response, including the error code when it is an error.
    Response {
        body: Value,
        error_code: Option<i64>,
    },
}

impl RpcOutcome {
    pub(crate) fn response(body: Value) -> Self {
        RpcOutcome::Response {
            body,
            error_code: None,
        }
    }

    pub(crate) fn error(id: Value, code: i64, message: &str) -> Self {
        RpcOutcome::Response {
            body: error_response(id, code, message),
            error_code: Some(code),
        }
    }
}

/// Does this message opt into the stateless 2026-era protocol?
///
/// Presence, not validity, of modern reserved metadata selects the modern
/// path. `server/discover` is itself modern-only and selects it even when its
/// metadata is malformed. That keeps bad modern requests on the schema/error
/// path they attempted instead of misclassifying them as legacy traffic.
pub(crate) fn is_modern_request(message: &Value) -> bool {
    if message.get("method").and_then(Value::as_str) == Some("server/discover") {
        return true;
    }
    let Some(meta) = message
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    [
        PROTOCOL_VERSION_META,
        CLIENT_INFO_META,
        CLIENT_CAPABILITIES_META,
    ]
    .iter()
    .any(|key| meta.contains_key(*key))
}

/// Extract the request id for a transport-level error.
///
/// Invalid ids are deliberately not echoed.
pub(crate) fn request_id(message: &Value) -> Value {
    match message.get("id") {
        Some(id @ Value::String(_)) => id.clone(),
        Some(id @ Value::Number(n)) if n.is_i64() || n.is_u64() => id.clone(),
        _ => Value::Null,
    }
}

/// Extract the method and, where defined, the standard routable name.
pub(crate) fn method_and_name(message: &Value) -> (Option<&str>, Option<&str>) {
    let method = message.get("method").and_then(Value::as_str);
    let name = match method {
        Some("tools/call") => message
            .get("params")
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str),
        _ => None,
    };
    (method, name)
}

/// Protocol version declared in the request body.
pub(crate) fn requested_protocol_version(message: &Value) -> Option<&str> {
    message
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
        .and_then(Value::as_str)
}

/// Handle one stateless 2026-era MCP message.
pub(crate) async fn handle_modern_message(
    registry: Arc<ToolRegistry>,
    db: Db,
    caller: Caller,
    message: Value,
) -> RpcOutcome {
    handle_modern_engine_message(registry, EngineHandle::Sqlite(db), caller, message).await
}

pub(crate) async fn handle_modern_engine_message(
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    message: Value,
) -> RpcOutcome {
    handle_modern_message_with_dispatch(
        registry,
        ProtocolToolDispatch::Single { engine, caller },
        message,
        None,
    )
    .await
}

pub(crate) async fn handle_modern_engine_message_with_persistence(
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> RpcOutcome {
    handle_modern_message_with_dispatch(
        registry,
        ProtocolToolDispatch::Single { engine, caller },
        message,
        persistence_lease,
    )
    .await
}

pub(crate) async fn handle_modern_lens_message(
    registry: Arc<ToolRegistry>,
    dispatcher: Arc<dyn LensDispatch>,
    message: Value,
) -> RpcOutcome {
    handle_modern_message_with_dispatch(
        registry,
        ProtocolToolDispatch::Lens(dispatcher),
        message,
        None,
    )
    .await
}

#[allow(clippy::large_enum_variant)]
enum ProtocolToolDispatch {
    Single {
        engine: EngineHandle,
        caller: Caller,
    },
    Lens(Arc<dyn LensDispatch>),
}

impl ProtocolToolDispatch {
    fn exposure_policy(&self, registry: &ToolRegistry) -> ResolvedToolExposure {
        match self {
            Self::Single { caller, .. } => caller
                .exposure_policy()
                .cloned()
                .unwrap_or_else(|| ResolvedToolExposure::new(registry.exposure_profile())),
            Self::Lens(dispatcher) => dispatcher.exposure_policy(registry),
        }
    }

    async fn run_context(&self, registry: &ToolRegistry, arguments: &Value) -> Value {
        if registry.is_standby_read_only() {
            return Value::Null;
        }
        match self {
            Self::Single { engine, caller } => {
                registry
                    .run_context_for_engine(engine, caller.clone(), arguments)
                    .await
            }
            Self::Lens(dispatcher) => dispatcher.run_context(registry, arguments).await,
        }
    }
}

async fn handle_modern_message_with_dispatch(
    registry: Arc<ToolRegistry>,
    dispatch: ProtocolToolDispatch,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> RpcOutcome {
    let Some(object) = message.as_object() else {
        return RpcOutcome::error(
            Value::Null,
            INVALID_REQUEST,
            "invalid request: not a JSON object",
        );
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return RpcOutcome::error(
            Value::Null,
            INVALID_REQUEST,
            "invalid request: missing or invalid 'jsonrpc' version (expected \"2.0\")",
        );
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        if object.get("result").is_some() || object.get("error").is_some() {
            return RpcOutcome::Notification;
        }
        return RpcOutcome::error(
            request_id(&message),
            INVALID_REQUEST,
            "invalid request: no method",
        );
    };

    let id = match object.get("id") {
        None => return RpcOutcome::Notification,
        Some(id @ Value::String(_)) => id.clone(),
        Some(id @ Value::Number(n)) if n.is_i64() || n.is_u64() => id.clone(),
        Some(_) => {
            return RpcOutcome::error(
                Value::Null,
                INVALID_REQUEST,
                "invalid request: 'id' must be a string or an integer",
            )
        }
    };

    let Some(params) = object.get("params").and_then(Value::as_object) else {
        return RpcOutcome::error(
            id,
            INVALID_PARAMS,
            "invalid params: modern MCP requests require object params",
        );
    };
    let Some(meta) = params.get("_meta").and_then(Value::as_object) else {
        return RpcOutcome::error(
            id,
            INVALID_PARAMS,
            "invalid params: modern MCP requests require object params._meta",
        );
    };
    let Some(version) = meta.get(PROTOCOL_VERSION_META).and_then(Value::as_str) else {
        return RpcOutcome::error(
            id,
            INVALID_PARAMS,
            "invalid params: params._meta requires a string protocol version",
        );
    };
    if version != PROTOCOL_VERSION {
        return RpcOutcome::Response {
            body: unsupported_protocol_response(id, version),
            error_code: Some(UNSUPPORTED_PROTOCOL_VERSION),
        };
    }
    let Some(client_capabilities) = meta.get(CLIENT_CAPABILITIES_META) else {
        return RpcOutcome::error(
            id,
            INVALID_PARAMS,
            "invalid params: params._meta requires object client capabilities",
        );
    };
    if let Err(message) = validate_client_capabilities(client_capabilities) {
        return RpcOutcome::error(id, INVALID_PARAMS, &message);
    }
    if let Some(client_info) = meta.get(CLIENT_INFO_META) {
        if let Err(message) = validate_implementation(client_info) {
            return RpcOutcome::error(id, INVALID_PARAMS, &message);
        }
    }
    if let Some(progress_token) = meta.get("progressToken") {
        if !progress_token.is_string() && !progress_token.is_number() {
            return RpcOutcome::error(
                id,
                INVALID_PARAMS,
                "invalid params: params._meta.progressToken must be a string or number",
            );
        }
    }
    if meta
        .get("io.modelcontextprotocol/logLevel")
        .is_some_and(|value| {
            !matches!(
                value.as_str(),
                Some(
                    "alert"
                        | "critical"
                        | "debug"
                        | "emergency"
                        | "error"
                        | "info"
                        | "notice"
                        | "warning"
                )
            )
        })
    {
        return RpcOutcome::error(
            id,
            INVALID_PARAMS,
            "invalid params: params._meta logLevel is not a LoggingLevel",
        );
    }
    if method == "tools/call" {
        if let Some(name) = params
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| registry.get(name).is_some())
        {
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if let Err(error) =
                preflight_read_only_call(&registry, name, &arguments, persistence_lease.as_ref())
            {
                let resource_uri = registry
                    .get(name)
                    .and_then(|tool| tool.ui.as_ref().map(|ui| ui.resource_uri));
                let mut result = call_error_content(&error, Value::Null, resource_uri);
                add_modern_result_fields(&mut result);
                return RpcOutcome::response(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                }));
            }
        }
    }
    if let Err(message) = validate_method_params(method, params) {
        if method == "tools/call" {
            // A malformed CallToolRequest remains a JSON-RPC protocol error.
            // Error.data is the schema-defined extension point for preserving
            // the call's universal correlation echo without misclassifying it
            // as a tool-execution result.
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let run_context = dispatch.run_context(&registry, &arguments).await;
            return RpcOutcome::Response {
                body: error_response_with_data(
                    id,
                    INVALID_PARAMS,
                    &message,
                    json!({ "run_context": run_context }),
                ),
                error_code: Some(INVALID_PARAMS),
            };
        }
        return RpcOutcome::error(id, INVALID_PARAMS, &message);
    }

    let outcome = match method {
        "server/discover" => Ok(discover_result()),
        "tools/list" => match &dispatch {
            ProtocolToolDispatch::Single { .. } => {
                tools_list_result(&registry, &dispatch.exposure_policy(&registry))
                    .map_err(|error| (INTERNAL_ERROR, error.to_string()))
            }
            ProtocolToolDispatch::Lens(dispatcher) => dispatcher
                .tools_list(&registry, true)
                .map_err(|error| (INTERNAL_ERROR, error.to_string())),
        },
        "resources/list" => Ok(modern_resource_result(apps::list())),
        "resources/read" => resource_read_result(params, true),
        "tools/call" => match &dispatch {
            ProtocolToolDispatch::Single { engine, caller } => {
                tools_call_result(
                    &registry,
                    engine.clone(),
                    caller.clone(),
                    params,
                    persistence_lease.clone(),
                )
                .await
            }
            ProtocolToolDispatch::Lens(dispatcher) => {
                dispatcher.tools_call(&registry, params, true).await
            }
        },
        "initialize" => Err((
            METHOD_NOT_FOUND,
            format!(
                "method not found: initialize; this server uses stateless MCP {PROTOCOL_VERSION}"
            ),
        )),
        _ => Err((METHOD_NOT_FOUND, format!("method not found: {method}"))),
    };

    match outcome {
        Ok(result) => RpcOutcome::response(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })),
        Err((code, message)) => RpcOutcome::error(id, code, &message),
    }
}

/// Handle one initialize-era MCP message.
///
/// This function deliberately owns no lifecycle or session state. Each
/// transport supplies the database selected for this request, so hosted HTTP
/// can authenticate every request independently and survive process restarts.
pub(crate) async fn handle_legacy_message(
    registry: Arc<ToolRegistry>,
    db: Db,
    caller: Caller,
    message: Value,
) -> RpcOutcome {
    handle_legacy_engine_message(registry, EngineHandle::Sqlite(db), caller, message).await
}

pub(crate) async fn handle_legacy_engine_message(
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    message: Value,
) -> RpcOutcome {
    handle_legacy_message_with_dispatch(
        registry,
        ProtocolToolDispatch::Single { engine, caller },
        message,
        None,
    )
    .await
}

pub(crate) async fn handle_legacy_engine_message_with_persistence(
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> RpcOutcome {
    handle_legacy_message_with_dispatch(
        registry,
        ProtocolToolDispatch::Single { engine, caller },
        message,
        persistence_lease,
    )
    .await
}

pub(crate) async fn handle_legacy_lens_message(
    registry: Arc<ToolRegistry>,
    dispatcher: Arc<dyn LensDispatch>,
    message: Value,
) -> RpcOutcome {
    handle_legacy_message_with_dispatch(
        registry,
        ProtocolToolDispatch::Lens(dispatcher),
        message,
        None,
    )
    .await
}

async fn handle_legacy_message_with_dispatch(
    registry: Arc<ToolRegistry>,
    dispatch: ProtocolToolDispatch,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> RpcOutcome {
    // Envelope first (JSON-RPC 2.0): an object carrying `jsonrpc: "2.0"`.
    // Anything else is answered -32600 with a null id — silently dropping
    // valid-JSON-invalid-request input would leave a compliant caller waiting
    // forever for a response that never comes.
    let Some(object) = message.as_object() else {
        return RpcOutcome::error(
            Value::Null,
            INVALID_REQUEST,
            "invalid request: not a JSON object",
        );
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return RpcOutcome::error(
            Value::Null,
            INVALID_REQUEST,
            "invalid request: missing or invalid 'jsonrpc' version (expected \"2.0\")",
        );
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        // A response to a server-initiated request would arrive method-less
        // and is ignored per JSON-RPC (we initiate none); everything else
        // method-less is invalid.
        if object.get("result").is_some() || object.get("error").is_some() {
            return RpcOutcome::Notification;
        }
        return RpcOutcome::error(
            object.get("id").cloned().unwrap_or(Value::Null),
            INVALID_REQUEST,
            "invalid request: no method",
        );
    };
    let params = object.get("params").cloned().unwrap_or(Value::Null);

    // No id → notification: never answered, whatever the method. An id that
    // IS present must be a string or an integer — MCP (unlike bare JSON-RPC)
    // forbids null ids, and fractional/structured ids are invalid in both.
    let id = match object.get("id") {
        None => return RpcOutcome::Notification,
        Some(id @ Value::String(_)) => id.clone(),
        Some(id @ Value::Number(n)) if n.is_i64() || n.is_u64() => id.clone(),
        Some(_) => {
            return RpcOutcome::error(
                Value::Null,
                INVALID_REQUEST,
                "invalid request: 'id' must be a string or an integer",
            )
        }
    };

    let outcome = match method {
        "initialize" => Ok(legacy_initialize_result(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => match &dispatch {
            ProtocolToolDispatch::Single { .. } => {
                legacy_tools_list_result(&registry, &dispatch.exposure_policy(&registry))
                    .map_err(|error| (INTERNAL_ERROR, error.to_string()))
            }
            ProtocolToolDispatch::Lens(dispatcher) => dispatcher
                .tools_list(&registry, false)
                .map_err(|error| (INTERNAL_ERROR, error.to_string())),
        },
        "resources/list" => Ok(apps::list()),
        "resources/read" => match params.as_object() {
            Some(params) => resource_read_result(params, false),
            None => Err((
                INVALID_PARAMS,
                "invalid params: resources/read params must be an object".into(),
            )),
        },
        "tools/call" => match &dispatch {
            ProtocolToolDispatch::Single { engine, caller } => {
                legacy_tools_call_result(
                    &registry,
                    engine.clone(),
                    caller.clone(),
                    &params,
                    persistence_lease.clone(),
                )
                .await
            }
            ProtocolToolDispatch::Lens(dispatcher) => match params.as_object() {
                Some(params) => dispatcher.tools_call(&registry, params, false).await,
                None => Err((
                    INVALID_PARAMS,
                    "invalid params: tools/call params must be an object".into(),
                )),
            },
        },
        _ => Err((METHOD_NOT_FOUND, format!("method not found: {method}"))),
    };
    match outcome {
        Ok(result) => RpcOutcome::response(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })),
        Err((code, message)) => RpcOutcome::error(id, code, &message),
    }
}

fn legacy_initialize_result(params: &Value) -> Value {
    // Echo the requested revision only when it is one we support; otherwise
    // answer with our preferred legacy version. The final revision is never
    // negotiated through initialize.
    let protocol_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|version| LEGACY_SUPPORTED_PROTOCOL_VERSIONS.contains(version))
        .unwrap_or(LEGACY_PROTOCOL_VERSION);
    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {}, "resources": {} },
        "serverInfo": {
            "name": crate::ENGINE_NAME,
            "version": crate::engine_version_string(),
        },
    })
}

fn legacy_tools_list_result(
    registry: &ToolRegistry,
    policy: &ResolvedToolExposure,
) -> crate::Result<Value> {
    registry.validate_policy_budget(policy)?;
    let tools: Vec<Value> = registry
        .descriptor_projection_for_policy(policy)
        .into_iter()
        .map(|tool| tool.descriptor)
        .collect();
    Ok(json!({ "tools": tools }))
}

pub(crate) fn tool_descriptor(tool: &super::registry::ToolSpec) -> Value {
    tool.descriptor()
}

fn modern_resource_result(mut result: Value) -> Value {
    let object = result
        .as_object_mut()
        .expect("resource result is an object");
    object.insert("resultType".into(), json!("complete"));
    object.insert("ttlMs".into(), json!(0));
    object.insert("cacheScope".into(), json!("private"));
    object.insert("_meta".into(), result_meta());
    result
}

fn resource_read_result(
    params: &serde_json::Map<String, Value>,
    modern: bool,
) -> std::result::Result<Value, (i64, String)> {
    let Some(uri) = params.get("uri").and_then(Value::as_str) else {
        return Err((
            INVALID_PARAMS,
            "invalid params: resources/read uri must be a string".into(),
        ));
    };
    let Some(result) = apps::read(uri) else {
        return Err((INVALID_PARAMS, format!("unknown resource: {uri}")));
    };
    Ok(if modern {
        modern_resource_result(result)
    } else {
        result
    })
}

/// Frame a handler payload with readable model content.
///
/// An audited standalone text rendering omits duplicate `structuredContent`.
/// Explicit JSON, Apps, tools without a renderer, conservative mutation/mixed
/// families, and defensive recovery preserve the compatibility shape. Errors
/// are framed separately by [`call_error_content`].
pub(crate) fn call_result_content(
    name: &str,
    format: render::Format,
    result: ToolResult,
    resource_uri: Option<&str>,
) -> Value {
    let ToolResult {
        structured: value,
        evidence,
        ..
    } = result;
    let rendered = match format {
        render::Format::Text | render::Format::App => render::render_outcome(name, &value),
        // A tool with no renderer resolves to Json before reaching here, so
        // this arm is the caller having asked for JSON explicitly.
        render::Format::Json => None,
    };
    if format == render::Format::App {
        let mut result = json!({
            "content": [{
                "type": "text",
                "text": rendered.map(|outcome| outcome.text).unwrap_or_else(|| value.to_string()),
            }],
            "structuredContent": value,
            "isError": false,
            "_meta": {
                "ui": {
                    "resourceUri": resource_uri.expect("App tool has resource URI"),
                }
            },
        });
        attach_mcp_evidence(&mut result, &evidence);
        return result;
    }
    let mut result = match rendered {
        Some(outcome) if !outcome.requires_structured_fallback => json!({
            "content": [{ "type": "text", "text": outcome.text }],
            "isError": false,
        }),
        Some(outcome) => json!({
            "content": [{ "type": "text", "text": outcome.text }],
            "structuredContent": value,
            "isError": false,
        }),
        None => json!({
            "content": [{ "type": "text", "text": value.to_string() }],
            "structuredContent": value,
            "isError": false,
        }),
    };
    attach_mcp_evidence(&mut result, &evidence);
    result
}

fn attach_mcp_evidence(result: &mut Value, evidence: &[super::evidence::TransientEvidence]) {
    if evidence.is_empty() {
        return;
    }
    let object = result.as_object_mut().expect("tool result object");
    let content = object
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .expect("tool result content array");
    content.extend(evidence.iter().map(|item| item.mcp_content_block()));
    let meta = object.entry("_meta").or_insert_with(|| json!({}));
    meta.as_object_mut()
        .expect("tool result _meta object")
        .insert(
            "transientEvidence".into(),
            Value::Array(evidence.iter().map(|item| item.metadata()).collect()),
        );
}

pub(crate) fn call_error_content(
    error: &Error,
    run_context: Value,
    resource_uri: Option<&str>,
) -> Value {
    let standby_read_only = error.to_string() == super::registry::STANDBY_READ_ONLY_ERROR;
    let deployment_operation = error.deployment_read_only_operation();
    let message = if standby_read_only {
        "this Native server is a read-only standby".to_string()
    } else if deployment_operation.is_some() {
        "this Native deployment is temporarily read-only".to_string()
    } else {
        error.to_string()
    };
    let mut text = message.clone();
    text.push_str(&render::render_run_context(&run_context));
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "error": message,
            "run_context": run_context,
        },
        "isError": true,
    });
    if standby_read_only {
        result["structuredContent"]["error_code"] = json!(super::registry::STANDBY_READ_ONLY_ERROR);
    } else if let Some(operation) = deployment_operation {
        result["structuredContent"]["error_code"] = json!(super::DEPLOYMENT_READ_ONLY_ERROR);
        result["structuredContent"]["retryable"] = json!(true);
        result["structuredContent"]["applied"] = json!(false);
        result["structuredContent"]["operation"] = json!(operation);
    }
    if let Some(resource_uri) = resource_uri {
        result
            .as_object_mut()
            .expect("tool error result object")
            .insert(
                "_meta".into(),
                json!({ "ui": { "resourceUri": resource_uri } }),
            );
    }
    result
}

fn preflight_read_only_call(
    registry: &ToolRegistry,
    name: &str,
    arguments: &Value,
    persistence_lease: Option<&DeploymentPersistenceLease>,
) -> crate::Result<()> {
    registry.admit_standby_call(name, arguments)?;
    if let Some(lease) = persistence_lease {
        registry.reuse_deployment_admission(lease)?;
        return Ok(());
    }
    registry.preflight_deployment_call(name, arguments)
}

/// Legacy `tools/call`: Ok is a full MCP call-tool result (success or
/// `isError: true`); Err is a JSON-RPC-level failure.
async fn legacy_tools_call_result(
    registry: &ToolRegistry,
    engine: EngineHandle,
    caller: Caller,
    params: &Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> std::result::Result<Value, (i64, String)> {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Err((INVALID_PARAMS, "invalid params: missing tool name".into()));
    };
    let Some(tool) = registry.get(name) else {
        return Err((INVALID_PARAMS, format!("unknown tool: {name}")));
    };
    let mut arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Err(error) =
        preflight_read_only_call(registry, name, &arguments, persistence_lease.as_ref())
    {
        return Ok(call_error_content(
            &error,
            Value::Null,
            tool.ui.as_ref().map(|ui| ui.resource_uri),
        ));
    }
    // `format` is stripped before dispatch: handlers parse with
    // `deny_unknown_fields`, so one that reached a handler would be rejected
    // as a caller bug. A bad value is a tool-execution error, not a
    // JSON-RPC-level one — same shape as any other invalid argument.
    let format = if tool.ui.is_some() {
        if let Err(message) = render::reject_format(&arguments, "MCP App tool") {
            let run_context = registry
                .run_context_for_engine(&engine, caller, &arguments)
                .await;
            return Ok(call_error_content(
                &Error::engine(message),
                run_context,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            ));
        }
        render::Format::App
    } else {
        match render::take_format(name, &mut arguments) {
            Ok(format) => format,
            Err(message) => {
                let run_context = registry
                    .run_context_for_engine(&engine, caller, &arguments)
                    .await;
                return Ok(call_error_content(
                    &Error::engine(message),
                    run_context,
                    None,
                ));
            }
        }
    };
    let dispatched = match persistence_lease {
        Some(lease) => {
            registry
                .call_engine_detailed_with_persistence(engine, caller, name, arguments, lease)
                .await
        }
        None => {
            registry
                .call_engine_detailed(engine, caller, name, arguments)
                .await
        }
    };
    let call = match dispatched {
        Ok(call) => call,
        Err(error @ Error::DeploymentReadOnly(_)) => {
            return Ok(call_error_content(
                &error,
                Value::Null,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            ));
        }
        Err(error) => return Err((INTERNAL_ERROR, error.to_string())),
    };
    match call.outcome {
        Ok(mut value) => {
            value.structured = attach_run_context(value.structured, call.run_context);
            Ok(call_result_content(
                name,
                format,
                value,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            ))
        }
        Err(err @ (Error::Engine(_) | Error::Conflict(_) | Error::Auth(_))) => {
            Ok(call_error_content(
                &err,
                call.run_context,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            ))
        }
        Err(err) => Err((INTERNAL_ERROR, err.to_string())),
    }
}

pub(crate) fn validate_implementation(value: &Value) -> std::result::Result<(), String> {
    let Some(info) = value.as_object() else {
        return Err("invalid params: clientInfo must be an object".into());
    };
    if !info.get("name").is_some_and(Value::is_string) {
        return Err("invalid params: clientInfo.name must be a string".into());
    }
    if !info.get("version").is_some_and(Value::is_string) {
        return Err("invalid params: clientInfo.version must be a string".into());
    }
    for field in ["title", "description", "websiteUrl"] {
        if info.get(field).is_some_and(|value| !value.is_string()) {
            return Err(format!(
                "invalid params: clientInfo.{field} must be a string"
            ));
        }
    }
    if let Some(website_url) = info.get("websiteUrl").and_then(Value::as_str) {
        if url::Url::parse(website_url).is_err() {
            return Err("invalid params: clientInfo.websiteUrl must be a URI".into());
        }
    }
    if let Some(icons) = info.get("icons") {
        let Some(icons) = icons.as_array() else {
            return Err("invalid params: clientInfo.icons must be an array".into());
        };
        for (index, icon) in icons.iter().enumerate() {
            let Some(icon) = icon.as_object() else {
                return Err(format!(
                    "invalid params: clientInfo.icons[{index}] must be an object"
                ));
            };
            if !icon.get("src").is_some_and(Value::is_string) {
                return Err(format!(
                    "invalid params: clientInfo.icons[{index}].src must be a string"
                ));
            }
            if icon
                .get("src")
                .and_then(Value::as_str)
                .is_some_and(|src| url::Url::parse(src).is_err())
            {
                return Err(format!(
                    "invalid params: clientInfo.icons[{index}].src must be a URI"
                ));
            }
            if icon.get("mimeType").is_some_and(|value| !value.is_string()) {
                return Err(format!(
                    "invalid params: clientInfo.icons[{index}].mimeType must be a string"
                ));
            }
            if let Some(sizes) = icon.get("sizes") {
                if !sizes
                    .as_array()
                    .is_some_and(|sizes| sizes.iter().all(Value::is_string))
                {
                    return Err(format!(
                        "invalid params: clientInfo.icons[{index}].sizes must be an array of strings"
                    ));
                }
            }
            if icon
                .get("theme")
                .is_some_and(|value| !matches!(value.as_str(), Some("light" | "dark")))
            {
                return Err(format!(
                    "invalid params: clientInfo.icons[{index}].theme must be 'light' or 'dark'"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_client_capabilities(value: &Value) -> std::result::Result<(), String> {
    let Some(capabilities) = value.as_object() else {
        return Err("invalid params: params._meta requires object client capabilities".into());
    };
    for field in [
        "roots",
        "sampling",
        "elicitation",
        "experimental",
        "extensions",
    ] {
        if capabilities
            .get(field)
            .is_some_and(|value| !value.is_object())
        {
            return Err(format!(
                "invalid params: clientCapabilities.{field} must be an object"
            ));
        }
    }
    for field in ["experimental", "extensions"] {
        if let Some(entries) = capabilities.get(field).and_then(Value::as_object) {
            if entries.values().any(|value| !value.is_object()) {
                return Err(format!(
                    "invalid params: clientCapabilities.{field} values must be objects"
                ));
            }
            if field == "extensions"
                && entries
                    .keys()
                    .any(|identifier| !is_prefixed_meta_key(identifier))
            {
                return Err(
                    "invalid params: clientCapabilities.extensions identifiers require a valid prefix"
                        .into(),
                );
            }
        }
    }
    if let Some(sampling) = capabilities.get("sampling").and_then(Value::as_object) {
        for field in ["context", "tools"] {
            if sampling.get(field).is_some_and(|value| !value.is_object()) {
                return Err(format!(
                    "invalid params: clientCapabilities.sampling.{field} must be an object"
                ));
            }
        }
    }
    if let Some(elicitation) = capabilities.get("elicitation").and_then(Value::as_object) {
        for field in ["form", "url"] {
            if elicitation
                .get(field)
                .is_some_and(|value| !value.is_object())
            {
                return Err(format!(
                    "invalid params: clientCapabilities.elicitation.{field} must be an object"
                ));
            }
        }
    }
    Ok(())
}

fn is_prefixed_meta_key(key: &str) -> bool {
    let Some((prefix, name)) = key.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || name.contains('/') {
        return false;
    }
    let valid_label = |label: &str| {
        let mut chars = label.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !first.is_ascii_alphabetic() {
            return false;
        }
        let mut last = first;
        for character in chars {
            if !character.is_ascii_alphanumeric() && character != '-' {
                return false;
            }
            last = character;
        }
        last.is_ascii_alphanumeric()
    };
    if !prefix.split('.').all(valid_label) {
        return false;
    }
    if name.is_empty() {
        return true;
    }
    let bytes = name.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn validate_method_params(
    method: &str,
    params: &serde_json::Map<String, Value>,
) -> std::result::Result<(), String> {
    match method {
        "server/discover" => Ok(()),
        "tools/list" | "resources/list" => {
            if params.contains_key("cursor") {
                return Err(
                    format!("invalid params: {method} does not accept a cursor because the complete list is returned in one page"),
                );
            }
            Ok(())
        }
        "resources/read" => {
            if !params.get("uri").is_some_and(Value::is_string) {
                return Err("invalid params: resources/read uri must be a string".into());
            }
            Ok(())
        }
        "tools/call" => {
            if !params.get("name").is_some_and(Value::is_string) {
                return Err("invalid params: tools/call name must be a string".into());
            }
            if params
                .get("arguments")
                .is_some_and(|value| !value.is_object())
            {
                return Err("invalid params: tools/call arguments must be an object".into());
            }
            if params
                .get("inputResponses")
                .is_some_and(|value| !value.is_object())
            {
                return Err("invalid params: tools/call inputResponses must be an object".into());
            }
            if params
                .get("requestState")
                .is_some_and(|value| !value.is_string())
            {
                return Err("invalid params: tools/call requestState must be a string".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn result_meta() -> Value {
    json!({
        SERVER_INFO_META: {
            "name": crate::ENGINE_NAME,
            "version": crate::engine_version_string(),
        }
    })
}

fn discover_result() -> Value {
    json!({
        "resultType": "complete",
        "supportedVersions": [PROTOCOL_VERSION],
        "capabilities": { "tools": {}, "resources": {} },
        "instructions": "Native's event-authoritative knowledge store. Use tools/list to discover the available tool surface.",
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": result_meta(),
    })
}

fn tools_list_result(
    registry: &ToolRegistry,
    policy: &ResolvedToolExposure,
) -> crate::Result<Value> {
    registry.validate_policy_budget(policy)?;
    let tools: Vec<Value> = registry
        .descriptor_projection_for_policy(policy)
        .into_iter()
        .map(|tool| tool.descriptor)
        .collect();
    Ok(json!({
        "resultType": "complete",
        "tools": tools,
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": result_meta(),
    }))
}

async fn tools_call_result(
    registry: &ToolRegistry,
    engine: EngineHandle,
    caller: Caller,
    params: &serde_json::Map<String, Value>,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> std::result::Result<Value, (i64, String)> {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Err((INVALID_PARAMS, "invalid params: missing tool name".into()));
    };
    let Some(tool) = registry.get(name) else {
        return Err((INVALID_PARAMS, format!("unknown tool: {name}")));
    };
    let mut arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Err(error) =
        preflight_read_only_call(registry, name, &arguments, persistence_lease.as_ref())
    {
        let mut result = call_error_content(
            &error,
            Value::Null,
            tool.ui.as_ref().map(|ui| ui.resource_uri),
        );
        add_modern_result_fields(&mut result);
        return Ok(result);
    }
    let format = if tool.ui.is_some() {
        if let Err(message) = render::reject_format(&arguments, "MCP App tool") {
            let run_context = registry
                .run_context_for_engine(&engine, caller, &arguments)
                .await;
            let mut result = call_error_content(
                &Error::engine(message),
                run_context,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            );
            add_modern_result_fields(&mut result);
            return Ok(result);
        }
        render::Format::App
    } else {
        match render::take_format(name, &mut arguments) {
            Ok(format) => format,
            Err(message) => {
                let run_context = registry
                    .run_context_for_engine(&engine, caller, &arguments)
                    .await;
                let mut result = call_error_content(&Error::engine(message), run_context, None);
                add_modern_result_fields(&mut result);
                return Ok(result);
            }
        }
    };
    let dispatched = match persistence_lease {
        Some(lease) => {
            registry
                .call_engine_detailed_with_persistence(engine, caller, name, arguments, lease)
                .await
        }
        None => {
            registry
                .call_engine_detailed(engine, caller, name, arguments)
                .await
        }
    };
    let call = match dispatched {
        Ok(call) => call,
        Err(error @ Error::DeploymentReadOnly(_)) => {
            let mut result = call_error_content(
                &error,
                Value::Null,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            );
            add_modern_result_fields(&mut result);
            return Ok(result);
        }
        Err(error) => return Err((INTERNAL_ERROR, error.to_string())),
    };
    match call.outcome {
        Ok(mut value) => {
            // The era's own envelope fields wrap the shared framing, so the
            // text/JSON decision lives in exactly one place.
            value.structured = attach_run_context(value.structured, call.run_context);
            let mut result = call_result_content(
                name,
                format,
                value,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            );
            add_modern_result_fields(&mut result);
            Ok(result)
        }
        Err(err @ (Error::Engine(_) | Error::Conflict(_) | Error::Auth(_))) => {
            let mut result = call_error_content(
                &err,
                call.run_context,
                tool.ui.as_ref().map(|ui| ui.resource_uri),
            );
            add_modern_result_fields(&mut result);
            Ok(result)
        }
        Err(err) => Err((INTERNAL_ERROR, err.to_string())),
    }
}

pub(crate) fn add_modern_result_fields(result: &mut Value) {
    let object = result.as_object_mut().expect("tool result object");
    object.insert("resultType".into(), json!("complete"));
    let meta = object.entry("_meta").or_insert_with(|| json!({}));
    let meta = meta.as_object_mut().expect("tool result _meta object");
    meta.insert(
        SERVER_INFO_META.into(),
        result_meta()[SERVER_INFO_META].clone(),
    );
}

pub(crate) fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

fn error_response_with_data(id: Value, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data },
    })
}

pub(crate) fn header_mismatch_response(id: Value, message: &str) -> Value {
    error_response(id, HEADER_MISMATCH, message)
}

pub(crate) fn unsupported_protocol_response(id: Value, requested: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": UNSUPPORTED_PROTOCOL_VERSION,
            "message": "Unsupported protocol version",
            "data": {
                "supported": [PROTOCOL_VERSION],
                "requested": requested,
            }
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{register_surface_tools, TransientEvidence};

    fn complete_record_payload() -> Value {
        json!({
            "records": [{
                "id": "rec-1",
                "type": "Note",
                "name": "Rendered record",
                "body": "Complete body mentioning structuredContent as ordinary payload text"
            }]
        })
    }

    #[test]
    fn call_result_framing_omits_only_safe_default_text_duplicates() {
        let value = complete_record_payload();
        let text = call_result_content(
            "get_record",
            render::Format::Text,
            value.clone().into(),
            None,
        );
        assert!(text.get("structuredContent").is_none());
        assert!(text["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Rendered record"));

        let explicit_json = call_result_content(
            "get_record",
            render::Format::Json,
            value.clone().into(),
            None,
        );
        assert_eq!(explicit_json["structuredContent"], value);

        let app = call_result_content(
            "get_record",
            render::Format::App,
            complete_record_payload().into(),
            Some("ui://record"),
        );
        assert_eq!(app["structuredContent"], complete_record_payload());
        assert_eq!(app["_meta"]["ui"]["resourceUri"], "ui://record");

        let unrendered_value = json!({ "future": "exact" });
        let unrendered = call_result_content(
            "tool_without_renderer",
            render::Format::Text,
            unrendered_value.clone().into(),
            None,
        );
        assert_eq!(unrendered["structuredContent"], unrendered_value);

        let malformed_write = json!({});
        let fallback = call_result_content(
            "correct_record_type",
            render::Format::Text,
            malformed_write.clone().into(),
            None,
        );
        assert_eq!(fallback["structuredContent"], malformed_write);
        assert!(fallback["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("do not repeat the write"));

        let future_mutation_receipt = json!({
            "id": "rec-1",
            "changed": true,
            "previous_seq": 41,
            "future_receipt": { "delivery": "deferred" }
        });
        let mutation = call_result_content(
            "delete_record",
            render::Format::Text,
            future_mutation_receipt.clone().into(),
            None,
        );
        assert_eq!(mutation["structuredContent"], future_mutation_receipt);

        let error = call_error_content(
            &Error::engine("failed safely"),
            json!({ "run_id": "run-1" }),
            None,
        );
        assert_eq!(error["isError"], true);
        assert_eq!(error["structuredContent"]["error"], "failed safely");
    }

    #[test]
    fn text_only_results_keep_transient_evidence_blocks_and_metadata() {
        let framed = call_result_content(
            "get_record",
            render::Format::Text,
            ToolResult::rich(
                complete_record_payload(),
                vec![
                    TransientEvidence::image("desktop", "image/png", b"pixels").unwrap(),
                    TransientEvidence::pdf("print", b"%PDF-1.7").unwrap(),
                ],
            ),
            None,
        );
        assert!(framed.get("structuredContent").is_none());
        assert_eq!(framed["content"][1]["type"], "image");
        assert_eq!(framed["content"][1]["data"], "cGl4ZWxz");
        assert_eq!(framed["content"][2]["type"], "resource");
        assert_eq!(framed["content"][2]["resource"]["blob"], "JVBERi0xLjc=");
        assert_eq!(framed["_meta"]["transientEvidence"][0]["handle"], "desktop");
        assert_eq!(framed["_meta"]["transientEvidence"][1]["handle"], "print");
    }

    #[test]
    fn rich_results_append_typed_image_and_pdf_content_without_polluting_structured_data() {
        let framed = call_result_content(
            "test_rich_result",
            render::Format::Json,
            ToolResult::rich(
                json!({ "status": "verified" }),
                vec![
                    TransientEvidence::image("desktop", "image/png", b"pixels").unwrap(),
                    TransientEvidence::pdf("print", b"%PDF-1.7").unwrap(),
                ],
            ),
            None,
        );
        assert_eq!(framed["structuredContent"], json!({ "status": "verified" }));
        assert_eq!(framed["content"][1]["type"], "image");
        assert_eq!(framed["content"][1]["mimeType"], "image/png");
        assert_eq!(framed["content"][1]["data"], "cGl4ZWxz");
        assert_eq!(framed["content"][2]["type"], "resource");
        assert_eq!(
            framed["content"][2]["resource"]["uri"],
            "native-evidence://transient/print"
        );
        assert_eq!(
            framed["content"][2]["resource"]["mimeType"],
            "application/pdf"
        );
        assert_eq!(framed["content"][2]["resource"]["blob"], "JVBERi0xLjc=");
        assert_eq!(framed["_meta"]["transientEvidence"][0]["handle"], "desktop");
        assert_eq!(framed["_meta"]["transientEvidence"][1]["handle"], "print");
        assert!(framed["_meta"]["transientEvidence"][0].get("url").is_none());
    }

    fn registry() -> Arc<ToolRegistry> {
        let mut registry = ToolRegistry::new();
        registry.set_exposure_profile(crate::mcp::ExposureProfile::Complete);
        register_surface_tools(&mut registry).unwrap();
        Arc::new(registry)
    }

    fn modern(id: i64, method: &str, params: Value) -> Value {
        let mut params = params.as_object().cloned().unwrap();
        params.insert(
            "_meta".into(),
            json!({
                PROTOCOL_VERSION_META: PROTOCOL_VERSION,
                CLIENT_CAPABILITIES_META: {},
                CLIENT_INFO_META: { "name": "test", "version": "1" },
            }),
        );
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    fn response(outcome: RpcOutcome) -> Value {
        match outcome {
            RpcOutcome::Response { body, .. } => body,
            RpcOutcome::Notification => panic!("expected response"),
        }
    }

    #[tokio::test]
    async fn app_tools_reject_caller_selected_format_in_both_protocol_eras() {
        let db = crate::create_database(":memory:").await.unwrap();
        let registry = registry();
        let app = registry
            .specs()
            .find(|tool| tool.ui.is_some())
            .expect("surface registry contains an MCP App")
            .name
            .clone();
        for modern_era in [false, true] {
            let params = json!({"name":app,"arguments":{"format":"json"}});
            let request = if modern_era {
                modern(39, "tools/call", params)
            } else {
                json!({"jsonrpc":"2.0","id":39,"method":"tools/call","params":params})
            };
            let called = if modern_era {
                response(
                    handle_modern_message(registry.clone(), db.clone(), Caller::local(), request)
                        .await,
                )
            } else {
                response(
                    handle_legacy_message(registry.clone(), db.clone(), Caller::local(), request)
                        .await,
                )
            };
            assert_eq!(called["result"]["isError"], true, "{called}");
            assert!(called["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("selects its response representation"));
        }
        db.close().await;
    }

    #[tokio::test]
    async fn emitted_direct_descriptors_drive_executable_response_format_matrix() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut complete_registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut complete_registry).unwrap();
        register_surface_tools(&mut complete_registry).unwrap();
        let registry = Arc::new(complete_registry);
        let projection = registry.descriptor_projection(crate::mcp::ExposureProfile::Complete);
        let fixtures = [
            ("bootstrap", json!({})),
            (
                "get_record",
                json!({"ids":["native:root"], "run_key":"format-matrix-3f81aa"}),
            ),
            ("ping", json!({"run_key":"format-matrix-3f81aa"})),
        ];

        for (tool, base_arguments) in fixtures {
            let descriptor = projection
                .iter()
                .find(|advertised| advertised.name == tool)
                .unwrap();
            let validator =
                jsonschema::validator_for(&descriptor.descriptor["inputSchema"]).unwrap();
            let advertised_formats = descriptor.descriptor["inputSchema"]["properties"]["format"]
                ["enum"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>();
            let expected_formats = if tool == "ping" {
                vec!["json"]
            } else {
                vec!["text", "json"]
            };
            assert_eq!(advertised_formats, expected_formats, "{tool}");
            for &format in &advertised_formats {
                let mut arguments = base_arguments.clone();
                arguments["format"] = json!(format);
                assert!(validator.is_valid(&arguments), "{tool}.{format}");
                let called = response(
                    handle_legacy_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        json!({
                            "jsonrpc":"2.0",
                            "id":40,
                            "method":"tools/call",
                            "params":{"name":tool,"arguments":arguments}
                        }),
                    )
                    .await,
                );
                assert_eq!(
                    called["result"]["isError"], false,
                    "{tool}.{format}: {called}"
                );
                let text = called["result"]["content"][0]["text"].as_str().unwrap();
                if format == "json" {
                    assert_eq!(
                        serde_json::from_str::<Value>(text).unwrap(),
                        called["result"]["structuredContent"],
                        "{tool}.{format} did not use exact JSON framing"
                    );
                } else {
                    assert!(
                        serde_json::from_str::<Value>(text).is_err(),
                        "{tool}: {text}"
                    );
                }
            }
            if !advertised_formats.contains(&"text") {
                let mut arguments = base_arguments.clone();
                arguments["format"] = json!("text");
                assert!(!validator.is_valid(&arguments), "{tool}.text");
                let called = response(
                    handle_legacy_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        json!({
                            "jsonrpc":"2.0",
                            "id":41,
                            "method":"tools/call",
                            "params":{"name":tool,"arguments":arguments}
                        }),
                    )
                    .await,
                );
                assert_eq!(called["result"]["isError"], true, "{tool}.text: {called}");
                assert!(called["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("no registered text renderer"));
            }
        }
        db.close().await;
    }

    #[tokio::test]
    async fn standby_discovery_and_capability_errors_match_across_protocol_eras() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut standby = ToolRegistry::new();
        standby.set_exposure_profile(crate::mcp::ExposureProfile::Complete);
        register_surface_tools(&mut standby).unwrap();
        standby.set_standby_read_only(true);
        let standby = Arc::new(standby);

        for modern_era in [false, true] {
            let list_request = if modern_era {
                modern(40, "tools/list", json!({}))
            } else {
                json!({"jsonrpc":"2.0","id":40,"method":"tools/list","params":{}})
            };
            let listed = if modern_era {
                response(
                    handle_modern_message(
                        standby.clone(),
                        db.clone(),
                        Caller::local(),
                        list_request,
                    )
                    .await,
                )
            } else {
                response(
                    handle_legacy_message(
                        standby.clone(),
                        db.clone(),
                        Caller::local(),
                        list_request,
                    )
                    .await,
                )
            };
            let tools = listed["result"]["tools"].as_array().unwrap();
            assert!(!tools.iter().any(|tool| tool["name"] == "create_record"));
            let links = tools
                .iter()
                .find(|tool| tool["name"] == "manage_links")
                .unwrap();
            assert_eq!(
                links["inputSchema"]["properties"]["action"]["enum"],
                json!(["list"])
            );

            // The capability boundary wins over renderer and handler argument
            // parsing, so deliberately malformed write arguments still return
            // the same stable standby error.
            let params = json!({
                "name":"create_record",
                "arguments":{"format":7,"not":"a create_record shape"}
            });
            let call_request = if modern_era {
                modern(41, "tools/call", params)
            } else {
                json!({"jsonrpc":"2.0","id":41,"method":"tools/call","params":params})
            };
            let called = if modern_era {
                response(
                    handle_modern_message(
                        standby.clone(),
                        db.clone(),
                        Caller::local(),
                        call_request,
                    )
                    .await,
                )
            } else {
                response(
                    handle_legacy_message(
                        standby.clone(),
                        db.clone(),
                        Caller::local(),
                        call_request,
                    )
                    .await,
                )
            };
            assert_eq!(
                called["result"]["structuredContent"]["error_code"],
                crate::mcp::registry::STANDBY_READ_ONLY_ERROR
            );
            assert_eq!(
                called["result"]["structuredContent"]["run_context"],
                Value::Null
            );
        }

        // Modern envelope validation must not enter ordinary run-context
        // persistence before a known mutation is classified. The malformed
        // universal field would otherwise take the INVALID_PARAMS path and
        // try to mint this run key.
        let malformed = response(
            handle_modern_message(
                standby.clone(),
                db.clone(),
                Caller::local(),
                modern(
                    42,
                    "tools/call",
                    json!({
                        "name":"create_record",
                        "arguments":{"run_key":"new"},
                        "requestState":7
                    }),
                ),
            )
            .await,
        );
        assert_eq!(
            malformed["result"]["structuredContent"]["error_code"],
            crate::mcp::registry::STANDBY_READ_ONLY_ERROR
        );
        assert_eq!(
            malformed["result"]["structuredContent"]["run_context"],
            Value::Null
        );

        let unknown = response(
            handle_modern_message(
                standby.clone(),
                db.clone(),
                Caller::local(),
                modern(
                    43,
                    "tools/call",
                    json!({"name":"future_unregistered_tool","arguments":{}}),
                ),
            )
            .await,
        );
        assert_eq!(unknown["error"]["code"], INVALID_PARAMS);
        assert!(unknown["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));

        let captured: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(captured, 0);
        db.close().await;
    }

    #[tokio::test]
    async fn deployment_read_only_rejection_is_typed_and_identical_across_protocol_eras() {
        let db = crate::create_database(":memory:").await.unwrap();
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let mut frozen = ToolRegistry::new();
        frozen.set_exposure_profile(crate::mcp::ExposureProfile::Complete);
        crate::mcp::register_builtin_tools(&mut frozen).unwrap();
        register_surface_tools(&mut frozen).unwrap();
        frozen.set_deployment_mutation_barrier(barrier.clone());
        let frozen = Arc::new(frozen);
        let _freeze = barrier.freeze().await;

        for modern_era in [false, true] {
            let params = json!({
                "name":"create_record",
                "arguments":{"format":7,"action":"caller-value","not":"parsed"},
                "requestState":7
            });
            let request = if modern_era {
                modern(51, "tools/call", params)
            } else {
                json!({"jsonrpc":"2.0","id":51,"method":"tools/call","params":params})
            };
            let called = if modern_era {
                response(
                    handle_modern_message(frozen.clone(), db.clone(), Caller::local(), request)
                        .await,
                )
            } else {
                response(
                    handle_legacy_message(frozen.clone(), db.clone(), Caller::local(), request)
                        .await,
                )
            };
            let error = &called["result"]["structuredContent"];
            assert_eq!(error["error_code"], crate::mcp::DEPLOYMENT_READ_ONLY_ERROR);
            assert_eq!(error["retryable"], true);
            assert_eq!(error["applied"], false);
            assert_eq!(error["operation"], "create_record");
            assert_eq!(error["run_context"], Value::Null);
            if modern_era {
                assert_eq!(called["result"]["resultType"], "complete");
            }
        }

        let ping = response(
            handle_modern_message(
                frozen.clone(),
                db.clone(),
                Caller::local(),
                modern(52, "tools/call", json!({"name":"ping","arguments":{}})),
            )
            .await,
        );
        assert_eq!(ping["result"]["isError"], false);
        let captured: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(captured, 0);
        db.close().await;
    }

    #[tokio::test]
    async fn both_protocol_eras_list_and_read_concrete_app_resources() {
        let db = crate::create_database(":memory:").await.unwrap();
        let registry = registry();
        let legacy_list = response(
            handle_legacy_message(
                registry.clone(),
                db.clone(),
                Caller::local(),
                json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {} }),
            )
            .await,
        );
        let modern_list = response(
            handle_modern_message(
                registry.clone(),
                db.clone(),
                Caller::local(),
                modern(2, "resources/list", json!({})),
            )
            .await,
        );
        for list in [&legacy_list["result"], &modern_list["result"]] {
            assert_eq!(list["resources"].as_array().unwrap().len(), 2);
            assert_eq!(list["resources"][0]["mimeType"], apps::MIME_TYPE);
        }
        let read = response(
            handle_modern_message(
                registry.clone(),
                db.clone(),
                Caller::local(),
                modern(
                    3,
                    "resources/read",
                    json!({ "uri": apps::RECORD_VERSION_DIFF_URI }),
                ),
            )
            .await,
        );
        assert_eq!(
            read["result"]["contents"][0]["_meta"]["ui"]["csp"]["connectDomains"],
            json!([])
        );
        let listed_resource = modern_list["result"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["uri"] == apps::RECORD_VERSION_DIFF_URI)
            .unwrap();
        assert_eq!(
            listed_resource["_meta"],
            read["result"]["contents"][0]["_meta"]
        );
        assert!(read["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("ui/notifications/tool-result"));
        let unknown = response(
            handle_modern_message(
                registry,
                db.clone(),
                Caller::local(),
                modern(
                    4,
                    "resources/read",
                    json!({ "uri": "ui://native-ce/unknown.html" }),
                ),
            )
            .await,
        );
        assert_eq!(unknown["error"]["code"], INVALID_PARAMS);
        db.close().await;
    }

    #[tokio::test]
    async fn app_descriptor_and_result_framing_are_shared_across_eras() {
        let db = crate::create_database(":memory:").await.unwrap();
        let registry = registry();
        let created = registry.call(db.clone(), Caller::local(), "create_record", json!({
            "type": "Document", "kind": "note", "name": "Review target", "body": "before", "reason": "fixture"
        })).await.unwrap();
        let record_id = created["id"].as_str().unwrap();
        for modern_era in [false, true] {
            let list_request = if modern_era {
                modern(10, "tools/list", json!({}))
            } else {
                json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {} })
            };
            let list = if modern_era {
                response(
                    handle_modern_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        list_request,
                    )
                    .await,
                )
            } else {
                response(
                    handle_legacy_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        list_request,
                    )
                    .await,
                )
            };
            let descriptor = list["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == "render_suggestion_review")
                .unwrap();
            assert_eq!(
                descriptor["_meta"]["ui"]["resourceUri"],
                apps::SUGGESTION_REVIEW_URI
            );
            assert_eq!(
                descriptor["_meta"]["ui/resourceUri"],
                apps::SUGGESTION_REVIEW_URI
            );
            assert!(descriptor["inputSchema"]["properties"]
                .get("format")
                .is_none());

            let params = json!({ "name": "render_suggestion_review", "arguments": { "record_id": record_id } });
            let call_request = if modern_era {
                modern(11, "tools/call", params)
            } else {
                json!({ "jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": params })
            };
            let call = if modern_era {
                response(
                    handle_modern_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        call_request,
                    )
                    .await,
                )
            } else {
                response(
                    handle_legacy_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        call_request,
                    )
                    .await,
                )
            };
            let result = &call["result"];
            assert_eq!(result["structuredContent"]["view"], "suggestion_review");
            assert!(result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Review target"));
            assert_eq!(
                result["_meta"]["ui"]["resourceUri"],
                apps::SUGGESTION_REVIEW_URI
            );

            let error_params = json!({ "name": "render_suggestion_review", "arguments": { "record_id": "missing" } });
            let error_request = if modern_era {
                modern(12, "tools/call", error_params)
            } else {
                json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": error_params })
            };
            let error = if modern_era {
                response(
                    handle_modern_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        error_request,
                    )
                    .await,
                )
            } else {
                response(
                    handle_legacy_message(
                        registry.clone(),
                        db.clone(),
                        Caller::local(),
                        error_request,
                    )
                    .await,
                )
            };
            assert_eq!(error["result"]["isError"], true);
            assert_eq!(
                error["result"]["_meta"]["ui"]["resourceUri"],
                apps::SUGGESTION_REVIEW_URI
            );
        }
        db.close().await;
    }
}
