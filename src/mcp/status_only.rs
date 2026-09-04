//! Database-less MCP transport for a standby with no usable generation.
//!
//! This is deliberately separate from [`super::stdio::StdioServer`]. That
//! server's construction and dispatch contracts require a selected engine;
//! manufacturing an empty SQLite database here would make snapshot-backed
//! answers look authoritative and would violate standby startup's fail-closed
//! boundary.

use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::{Error, Result};

use super::protocol::{self, RpcOutcome};

/// Stable tool-result code returned when no verified generation can be served.
pub const STANDBY_STATUS_ONLY_ERROR: &str = "STANDBY_STATUS_ONLY";

const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO_META: &str = "io.modelcontextprotocol/serverInfo";

const BOOTSTRAP: &str = "bootstrap";
const STANDBY_STATUS: &str = "standby_status";

/// A newline-delimited MCP server which owns diagnostics but no database.
#[derive(Clone, Debug)]
pub struct StatusOnlyStdioServer {
    status: StatusSource,
}

#[derive(Clone, Debug)]
enum StatusSource {
    Static(Value),
    Dynamic(Box<crate::standby::StandbyStatusProvider>),
}

impl StatusOnlyStdioServer {
    /// Construct a status-only server from the activation layer's structured
    /// diagnostics. The payload is returned without reinterpretation by both
    /// static tools.
    pub fn new(status: Value) -> Self {
        Self {
            status: StatusSource::Static(status),
        }
    }

    /// Construct a status-only server whose diagnostics are recomputed for
    /// every call while a background refresh may still be running.
    pub fn with_provider(provider: crate::standby::StandbyStatusProvider) -> Self {
        Self {
            status: StatusSource::Dynamic(Box::new(provider)),
        }
    }

    async fn status(&self) -> Value {
        match &self.status {
            StatusSource::Static(status) => status.clone(),
            StatusSource::Dynamic(provider) => serde_json::to_value(provider.status().await)
                .expect("standby status is serializable"),
        }
    }

    /// Serve process stdin/stdout until EOF.
    pub async fn serve_stdio(&self) -> Result<()> {
        self.serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await
    }

    /// Serve newline-delimited JSON-RPC over the supplied streams.
    pub async fn serve<R, W>(&self, mut reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle_message(message).await,
                Err(error) => Some(protocol::error_response(
                    Value::Null,
                    protocol::PARSE_ERROR,
                    &format!("parse error: {error}"),
                )),
            };
            if let Some(response) = response {
                let mut bytes = serde_json::to_vec(&response)?;
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }

    async fn handle_message(&self, message: Value) -> Option<Value> {
        if message.as_object().is_some_and(|object| {
            object.get("method").is_none()
                && (object.get("result").is_some() || object.get("error").is_some())
        }) {
            return None;
        }
        let outcome = if protocol::is_modern_request(&message) {
            self.handle_modern(message).await
        } else {
            self.handle_legacy(message).await
        };
        match outcome {
            RpcOutcome::Notification => None,
            RpcOutcome::Response { body, .. } => Some(body),
        }
    }

    async fn handle_legacy(&self, message: Value) -> RpcOutcome {
        let Some((id, method, params)) = validated_envelope(&message) else {
            return invalid_envelope(&message);
        };
        let Some(id) = id else {
            return RpcOutcome::Notification;
        };

        let result = match method {
            "initialize" => Ok(legacy_initialize_result(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tool_descriptors() })),
            "tools/call" => self.call_tool(&params, false).await,
            _ => Err((
                protocol::METHOD_NOT_FOUND,
                format!("method not found: {method}"),
            )),
        };
        framed(id, result)
    }

    async fn handle_modern(&self, message: Value) -> RpcOutcome {
        let Some((id, method, params)) = validated_envelope(&message) else {
            return invalid_envelope(&message);
        };
        let Some(id) = id else {
            return RpcOutcome::Notification;
        };
        let Some(params) = params.as_object() else {
            return RpcOutcome::error(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: modern MCP requests require object params",
            );
        };
        let Some(meta) = params.get("_meta").and_then(Value::as_object) else {
            return RpcOutcome::error(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: modern MCP requests require object params._meta",
            );
        };
        let Some(version) = meta.get(PROTOCOL_VERSION_META).and_then(Value::as_str) else {
            return RpcOutcome::error(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: params._meta requires a string protocol version",
            );
        };
        if version != protocol::PROTOCOL_VERSION {
            return RpcOutcome::Response {
                body: protocol::unsupported_protocol_response(id, version),
                error_code: Some(protocol::UNSUPPORTED_PROTOCOL_VERSION),
            };
        }
        let Some(client_capabilities) = meta.get(CLIENT_CAPABILITIES_META) else {
            return RpcOutcome::error(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: params._meta requires object client capabilities",
            );
        };
        if let Err(message) = protocol::validate_client_capabilities(client_capabilities) {
            return RpcOutcome::error(id, protocol::INVALID_PARAMS, &message);
        }
        if let Some(client_info) = meta.get("io.modelcontextprotocol/clientInfo") {
            if let Err(message) = protocol::validate_implementation(client_info) {
                return RpcOutcome::error(id, protocol::INVALID_PARAMS, &message);
            }
        }
        if meta
            .get("progressToken")
            .is_some_and(|value| !value.is_string() && !value.is_number())
        {
            return RpcOutcome::error(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: params._meta.progressToken must be a string or number",
            );
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
                protocol::INVALID_PARAMS,
                "invalid params: params._meta logLevel is not a LoggingLevel",
            );
        }
        if let Err(message) = protocol::validate_method_params(method, params) {
            return RpcOutcome::error(id, protocol::INVALID_PARAMS, &message);
        }

        let result = match method {
            "server/discover" => Ok(discover_result()),
            "tools/list" => Ok(modern_tools_list_result()),
            "tools/call" => self.call_tool(&Value::Object(params.clone()), true).await,
            _ => Err((
                protocol::METHOD_NOT_FOUND,
                format!("method not found: {method}"),
            )),
        };
        framed(id, result)
    }

    async fn call_tool(
        &self,
        params: &Value,
        modern: bool,
    ) -> std::result::Result<Value, (i64, String)> {
        let Some(params) = params.as_object() else {
            return Err((
                protocol::INVALID_PARAMS,
                "invalid params: tools/call params must be an object".into(),
            ));
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Err((
                protocol::INVALID_PARAMS,
                "invalid params: missing tool name".into(),
            ));
        };
        if params
            .get("arguments")
            .is_some_and(|arguments| !arguments.is_object())
        {
            return Err((
                protocol::INVALID_PARAMS,
                "invalid params: tools/call arguments must be an object".into(),
            ));
        }

        let mut result = if matches!(name, BOOTSTRAP | STANDBY_STATUS) {
            match validate_static_arguments(params.get("arguments")) {
                Ok(format) => static_tool_result(self.status().await, format, name),
                Err(message) => {
                    protocol::call_error_content(&Error::engine(message), Value::Null, None)
                }
            }
        } else {
            unavailable_tool_result()
        };
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        Ok(result)
    }
}

fn validate_static_arguments(
    arguments: Option<&Value>,
) -> std::result::Result<StatusFormat, String> {
    let Some(arguments) = arguments else {
        return Ok(StatusFormat::Text);
    };
    let object = arguments
        .as_object()
        .expect("caller validated object arguments");
    if object.keys().any(|key| key != "format") {
        return Err("bootstrap and standby_status accept only the format argument".into());
    }
    match object.get("format") {
        None => Ok(StatusFormat::Text),
        Some(Value::String(format)) if format == "text" => Ok(StatusFormat::Text),
        Some(Value::String(format)) if format == "json" => Ok(StatusFormat::Json),
        Some(_) => Err("format must be 'text' or 'json'".into()),
    }
}

#[derive(Clone, Copy)]
enum StatusFormat {
    Text,
    Json,
}

fn validated_envelope(message: &Value) -> Option<(Option<Value>, &str, Value)> {
    let object = message.as_object()?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let method = object.get("method")?.as_str()?;
    let id = match object.get("id") {
        None => None,
        Some(id @ Value::String(_)) => Some(id.clone()),
        Some(id @ Value::Number(number)) if number.is_i64() || number.is_u64() => Some(id.clone()),
        Some(_) => return None,
    };
    Some((
        id,
        method,
        object.get("params").cloned().unwrap_or(Value::Null),
    ))
}

fn invalid_envelope(message: &Value) -> RpcOutcome {
    let (id, detail) = match message.as_object() {
        None => (Value::Null, "invalid request: not a JSON object"),
        Some(object) if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") => (
            Value::Null,
            "invalid request: missing or invalid 'jsonrpc' version (expected \"2.0\")",
        ),
        Some(object) if object.get("method").and_then(Value::as_str).is_none() => (
            object.get("id").cloned().unwrap_or(Value::Null),
            "invalid request: no method",
        ),
        Some(_) => (
            Value::Null,
            "invalid request: 'id' must be a string or an integer",
        ),
    };
    RpcOutcome::error(id, protocol::INVALID_REQUEST, detail)
}

fn framed(id: Value, result: std::result::Result<Value, (i64, String)>) -> RpcOutcome {
    match result {
        Ok(result) => RpcOutcome::response(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })),
        Err((code, message)) => RpcOutcome::error(id, code, &message),
    }
}

fn server_info() -> Value {
    json!({
        "name": crate::ENGINE_NAME,
        "version": crate::engine_version_string(),
    })
}

fn result_meta() -> Value {
    let mut meta = Map::new();
    meta.insert(SERVER_INFO_META.into(), server_info());
    Value::Object(meta)
}

fn legacy_initialize_result(params: &Value) -> Value {
    let protocol_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|version| protocol::LEGACY_SUPPORTED_PROTOCOL_VERSIONS.contains(version))
        .unwrap_or(protocol::LEGACY_PROTOCOL_VERSION);
    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": server_info(),
    })
}

fn discover_result() -> Value {
    json!({
        "resultType": "complete",
        "supportedVersions": [protocol::PROTOCOL_VERSION],
        "capabilities": { "tools": {} },
        "instructions": "This Native standby has no usable verified generation. Only bootstrap and standby_status are available.",
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": result_meta(),
    })
}

fn modern_tools_list_result() -> Value {
    json!({
        "resultType": "complete",
        "tools": tool_descriptors(),
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": result_meta(),
    })
}

fn tool_descriptors() -> Vec<Value> {
    [
        (
            BOOTSTRAP,
            "Return status-only local standby orientation and diagnostics.",
        ),
        (
            STANDBY_STATUS,
            "Return the current local standby activation diagnostics.",
        ),
    ]
    .into_iter()
    .map(|(name, description)| {
        json!({
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "format": { "type": "string", "enum": ["text", "json"] }
                },
                "additionalProperties": false
            }
        })
    })
    .collect()
}

fn static_tool_result(status: Value, format: StatusFormat, _tool: &str) -> Value {
    let text = match format {
        StatusFormat::Text => super::render::render(STANDBY_STATUS, &status)
            .expect("standby status has a human renderer"),
        StatusFormat::Json => status.to_string(),
    };
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": status,
        "isError": false,
    })
}

fn unavailable_tool_result() -> Value {
    let message = "standby snapshot unavailable; only bootstrap and standby_status are available";
    json!({
        "content": [{ "type": "text", "text": message }],
        "structuredContent": {
            "error": message,
            "error_code": STANDBY_STATUS_ONLY_ERROR,
            "run_context": Value::Null,
        },
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> StatusOnlyStdioServer {
        StatusOnlyStdioServer::new(json!({
            "mode": "status_only",
            "reason": "no_usable_generation",
        }))
    }

    async fn response(server: &StatusOnlyStdioServer, message: Value) -> Value {
        server
            .handle_message(message)
            .await
            .expect("request response")
    }

    fn modern(id: i64, method: &str, fields: Value) -> Value {
        let mut params = fields.as_object().cloned().unwrap_or_default();
        params.insert(
            "_meta".into(),
            json!({
                PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION,
                CLIENT_CAPABILITIES_META: {},
            }),
        );
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    #[tokio::test]
    async fn legacy_surface_is_static_and_snapshot_calls_fail_as_tool_results() {
        let server = server();
        let initialized = response(
            &server,
            json!({
                "jsonrpc":"2.0", "id":1, "method":"initialize",
                "params":{"protocolVersion":"2024-11-05"}
            }),
        )
        .await;
        assert_eq!(initialized["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(
            response(
                &server,
                json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}})
            )
            .await["result"],
            json!({})
        );

        let listed = response(
            &server,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        )
        .await;
        let names = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![BOOTSTRAP, STANDBY_STATUS]);

        let bootstrap = response(
            &server,
            json!({
                "jsonrpc":"2.0", "id":4, "method":"tools/call",
                "params":{"name":BOOTSTRAP,"arguments":{}}
            }),
        )
        .await;
        assert_eq!(
            bootstrap["result"]["structuredContent"]["mode"],
            "status_only"
        );
        assert_eq!(bootstrap["result"]["isError"], false);

        let unavailable = response(
            &server,
            json!({
                "jsonrpc":"2.0", "id":5, "method":"tools/call",
                "params":{"name":"get_record","arguments":{"ids":["record"]}}
            }),
        )
        .await;
        assert_eq!(unavailable["result"]["isError"], true);
        assert_eq!(
            unavailable["result"]["structuredContent"]["error_code"],
            STANDBY_STATUS_ONLY_ERROR
        );

        let malformed = response(
            &server,
            modern(
                5,
                "tools/call",
                json!({"name":BOOTSTRAP,"arguments":{"unknown":true}}),
            ),
        )
        .await;
        assert_eq!(malformed["result"]["isError"], true);
        assert!(malformed["result"]["structuredContent"]["error"]
            .as_str()
            .unwrap()
            .contains("only the format argument"));

        let invalid_format = response(
            &server,
            modern(
                6,
                "tools/call",
                json!({"name":BOOTSTRAP,"arguments":{"format":null}}),
            ),
        )
        .await;
        assert_eq!(invalid_format["result"]["isError"], true);

        let invalid_capabilities = response(
            &server,
            json!({
                "jsonrpc":"2.0", "id":7, "method":"tools/list",
                "params":{"_meta":{
                    PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION,
                    CLIENT_CAPABILITIES_META: {"extensions":{"bad":true}}
                }}
            }),
        )
        .await;
        assert_eq!(
            invalid_capabilities["error"]["code"],
            protocol::INVALID_PARAMS
        );
    }

    #[tokio::test]
    async fn modern_surface_has_complete_metadata_and_static_calls() {
        let server = server();
        let discovered = response(&server, modern(1, "server/discover", json!({}))).await;
        assert_eq!(discovered["result"]["resultType"], "complete");
        assert_eq!(
            discovered["result"]["supportedVersions"][0],
            protocol::PROTOCOL_VERSION
        );

        let listed = response(&server, modern(2, "tools/list", json!({}))).await;
        assert_eq!(listed["result"]["resultType"], "complete");
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);
        assert!(listed["result"]["_meta"][SERVER_INFO_META].is_object());

        let status = response(
            &server,
            modern(
                3,
                "tools/call",
                json!({"name":STANDBY_STATUS,"arguments":{}}),
            ),
        )
        .await;
        assert_eq!(status["result"]["resultType"], "complete");
        assert_eq!(
            status["result"]["structuredContent"]["reason"],
            "no_usable_generation"
        );

        let unavailable = response(
            &server,
            modern(
                4,
                "tools/call",
                json!({"name":"search","arguments":{"query":"anything"}}),
            ),
        )
        .await;
        assert_eq!(unavailable["result"]["resultType"], "complete");
        assert_eq!(
            unavailable["result"]["structuredContent"]["error_code"],
            STANDBY_STATUS_ONLY_ERROR
        );
    }

    #[tokio::test]
    async fn newline_transport_needs_no_engine_handle() {
        let input = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
"#;
        let mut output = Vec::new();
        server().serve(input.as_slice(), &mut output).await.unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["result"]["tools"].as_array().unwrap().len(), 2);
    }
}
