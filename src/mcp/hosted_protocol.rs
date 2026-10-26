//! Narrow package boundary for hosted MCP transports.
//!
//! The protocol implementation remains crate-private. Hosted adapters use
//! this facade so they can move to a held package without turning every
//! parser, error code, and dispatch helper into unrelated top-level API.

use std::sync::Arc;

use serde_json::Value;

use crate::{Db, Error};

use super::evidence::ToolResult;
use super::lens_dispatch::LensDispatch;
use super::protocol;
use super::registry::{Caller, EngineHandle, ToolRegistry};
use super::render::Format;
use super::DeploymentPersistenceLease;

pub const PROTOCOL_VERSION: &str = protocol::PROTOCOL_VERSION;
pub const PARSE_ERROR: i64 = protocol::PARSE_ERROR;
pub const INVALID_REQUEST: i64 = protocol::INVALID_REQUEST;
pub const METHOD_NOT_FOUND: i64 = protocol::METHOD_NOT_FOUND;
pub const INVALID_PARAMS: i64 = protocol::INVALID_PARAMS;
pub const INTERNAL_ERROR: i64 = protocol::INTERNAL_ERROR;
pub const HEADER_MISMATCH: i64 = protocol::HEADER_MISMATCH;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = protocol::UNSUPPORTED_PROTOCOL_VERSION;

/// Opaque protocol dispatch result exposed only at the hosted transport
/// boundary.
pub struct HostedRpcOutcome(protocol::RpcOutcome);

impl From<protocol::RpcOutcome> for HostedRpcOutcome {
    fn from(outcome: protocol::RpcOutcome) -> Self {
        Self(outcome)
    }
}

impl HostedRpcOutcome {
    /// Consume the outcome into its HTTP-relevant parts. Notifications have
    /// no response body; every request response retains its protocol error
    /// code so the hosted transport can apply the exact HTTP status mapping.
    pub fn into_response(self) -> Option<(Value, Option<i64>)> {
        match self.0 {
            protocol::RpcOutcome::Notification => None,
            protocol::RpcOutcome::Response { body, error_code } => Some((body, error_code)),
        }
    }
}

pub fn is_modern_request(message: &Value) -> bool {
    protocol::is_modern_request(message)
}

pub fn supports_legacy_protocol_version(version: &str) -> bool {
    protocol::LEGACY_SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

pub fn request_id(message: &Value) -> Value {
    protocol::request_id(message)
}

pub fn method_and_name(message: &Value) -> (Option<&str>, Option<&str>) {
    protocol::method_and_name(message)
}

/// Shared pre-dispatch validation for a direct-dispatch `tools/call`: the
/// envelope both eras require plus the modern metadata when `modern`. The
/// caller must already have matched `tools/call` with a well-formed id (as
/// [`method_and_name`] plus an id check do); notifications can therefore
/// never reach this function. Returns the validated request id, or the exact
/// response body and error code the generic path renders.
pub fn validate_direct_call_envelope(
    message: &Value,
    modern: bool,
) -> std::result::Result<Value, (Value, Option<i64>)> {
    let outcome = if modern {
        match protocol::validate_modern_envelope(message) {
            Ok(envelope) => return Ok(envelope.id),
            Err(outcome) => outcome,
        }
    } else {
        match protocol::validate_legacy_envelope(message) {
            Ok(_) => return Ok(protocol::request_id(message)),
            Err(outcome) => outcome,
        }
    };
    match HostedRpcOutcome::from(outcome).into_response() {
        Some(response) => Err(response),
        // Unreachable: the caller matched `tools/call` with a well-formed
        // id, so neither envelope reports a notification.
        None => Err((
            protocol::error_response(
                Value::Null,
                protocol::INVALID_REQUEST,
                "invalid request: notification without id",
            ),
            Some(protocol::INVALID_REQUEST),
        )),
    }
}

/// Thin wrapper over the shared client-capabilities check.
pub fn validate_direct_client_capabilities(value: &Value) -> std::result::Result<(), String> {
    protocol::validate_client_capabilities(value)
}

/// Thin wrapper over the shared client-info check.
pub fn validate_direct_implementation(value: &Value) -> std::result::Result<(), String> {
    protocol::validate_implementation(value)
}

/// Thin wrapper over the shared method-params check.
pub fn validate_direct_method_params(
    method: &str,
    params: &serde_json::Map<String, Value>,
) -> std::result::Result<(), String> {
    protocol::validate_method_params(method, params)
}

/// Thin wrapper over the shared standby app-caller check: `native/app`
/// metadata is only valid on the read-only owner standby.
pub fn check_direct_standby_caller(
    registry: &ToolRegistry,
    caller: Caller,
    meta: Option<&Value>,
) -> std::result::Result<Caller, (i64, String)> {
    protocol::standby_app_caller(registry, caller, meta)
}

pub fn requested_protocol_version(message: &Value) -> Option<&str> {
    protocol::requested_protocol_version(message)
}

pub async fn handle_modern_message(
    registry: Arc<ToolRegistry>,
    db: Db,
    caller: Caller,
    message: Value,
) -> HostedRpcOutcome {
    protocol::handle_modern_message(registry, db, caller, message)
        .await
        .into()
}

pub async fn handle_legacy_message(
    registry: Arc<ToolRegistry>,
    db: Db,
    caller: Caller,
    message: Value,
) -> HostedRpcOutcome {
    protocol::handle_legacy_message(registry, db, caller, message)
        .await
        .into()
}

/// Dispatch one 2026-era MCP message reusing a deployment admission the
/// transport admitted before authentication. A freeze registered after that
/// admission drains instead of re-refusing; without a lease the call
/// re-admits exactly as [`handle_modern_message`] does.
pub async fn handle_modern_message_with_persistence(
    registry: Arc<ToolRegistry>,
    db: Db,
    caller: Caller,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> HostedRpcOutcome {
    handle_modern_engine_message_with_persistence(
        registry,
        EngineHandle::Sqlite(db),
        caller,
        message,
        persistence_lease,
    )
    .await
}

/// Engine-aware dispatch for hosted surfaces that select a workspace engine.
pub async fn handle_modern_engine_message_with_persistence(
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> HostedRpcOutcome {
    protocol::handle_modern_engine_message_with_persistence(
        registry,
        engine,
        caller,
        message,
        persistence_lease,
    )
    .await
    .into()
}

/// Initialize-era counterpart to [`handle_modern_message_with_persistence`].
pub async fn handle_legacy_message_with_persistence(
    registry: Arc<ToolRegistry>,
    db: Db,
    caller: Caller,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> HostedRpcOutcome {
    handle_legacy_engine_message_with_persistence(
        registry,
        EngineHandle::Sqlite(db),
        caller,
        message,
        persistence_lease,
    )
    .await
}

/// Initialize-era engine-aware dispatch.
pub async fn handle_legacy_engine_message_with_persistence(
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    message: Value,
    persistence_lease: Option<DeploymentPersistenceLease>,
) -> HostedRpcOutcome {
    protocol::handle_legacy_engine_message_with_persistence(
        registry,
        engine,
        caller,
        message,
        persistence_lease,
    )
    .await
    .into()
}

pub async fn handle_modern_lens_message(
    registry: Arc<ToolRegistry>,
    dispatcher: Arc<dyn LensDispatch>,
    message: Value,
) -> HostedRpcOutcome {
    protocol::handle_modern_lens_message(registry, dispatcher, message)
        .await
        .into()
}

pub async fn handle_legacy_lens_message(
    registry: Arc<ToolRegistry>,
    dispatcher: Arc<dyn LensDispatch>,
    message: Value,
) -> HostedRpcOutcome {
    protocol::handle_legacy_lens_message(registry, dispatcher, message)
        .await
        .into()
}

pub fn error_response(id: Value, code: i64, message: &str) -> Value {
    protocol::error_response(id, code, message)
}

pub fn header_mismatch_response(id: Value, message: &str) -> Value {
    protocol::header_mismatch_response(id, message)
}

pub fn unsupported_protocol_response(id: Value, requested: &str) -> Value {
    protocol::unsupported_protocol_response(id, requested)
}

pub fn call_result_content(
    name: &str,
    format: Format,
    result: ToolResult,
    resource_uri: Option<&str>,
) -> Value {
    protocol::call_result_content(name, format, result, resource_uri)
}

pub fn call_error_content(error: &Error, run_context: Value, resource_uri: Option<&str>) -> Value {
    protocol::call_error_content(error, run_context, resource_uri)
}

pub fn add_modern_result_fields(result: &mut Value) {
    protocol::add_modern_result_fields(result);
}

/// Validate a hosted outbox tools/call before any speculative write. Invalid
/// messages fall through to the ordinary protocol error path. The outbox's
/// custody contract treats an explicit null id as a request.
pub fn valid_outbox_tool_call(message: &Value) -> bool {
    if message["jsonrpc"] != "2.0" || message["method"] != "tools/call" {
        return false;
    }
    match message.get("id") {
        Some(Value::Null | Value::String(_)) => {}
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => {}
        _ => return false,
    }
    let Some(params) = message.get("params").and_then(Value::as_object) else {
        return false;
    };
    if protocol::validate_method_params("tools/call", params).is_err()
        || params.contains_key("inputResponses")
    {
        return false;
    }
    if !protocol::is_modern_request(message) {
        return true;
    }
    let Some(meta) = params.get("_meta").and_then(Value::as_object) else {
        return false;
    };
    if meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
        != Some(PROTOCOL_VERSION)
    {
        return false;
    }
    let Some(caps) = meta.get("io.modelcontextprotocol/clientCapabilities") else {
        return false;
    };
    if protocol::validate_client_capabilities(caps).is_err() {
        return false;
    }
    if meta
        .get("io.modelcontextprotocol/clientInfo")
        .is_some_and(|v| protocol::validate_implementation(v).is_err())
    {
        return false;
    }
    if meta
        .get("progressToken")
        .is_some_and(|v| !v.is_string() && !v.is_number())
    {
        return false;
    }
    !meta
        .get("io.modelcontextprotocol/logLevel")
        .is_some_and(|v| {
            !matches!(
                v.as_str(),
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
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    #[test]
    fn hosted_outcome_preserves_notification_and_protocol_error_code() {
        assert!(HostedRpcOutcome::from(protocol::RpcOutcome::Notification)
            .into_response()
            .is_none());

        let outcome = HostedRpcOutcome::from(protocol::RpcOutcome::error(
            json!(7),
            INVALID_PARAMS,
            "invalid hosted request",
        ));
        let (body, error_code) = outcome
            .into_response()
            .expect("request error remains a response");
        assert_eq!(error_code, Some(INVALID_PARAMS));
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], INVALID_PARAMS);
        assert_eq!(body["error"]["message"], "invalid hosted request");
    }

    /// A lease admitted before a freeze still dispatches through the
    /// persistence facades once freeze intent is registered, while a fresh
    /// dispatch re-admits and takes the frozen refusal. This is the exact
    /// contract the hosted MCP transports rely on for mid-flight calls.
    #[tokio::test]
    async fn message_with_persistence_reuses_held_lease_under_freeze_intent() {
        use super::super::{
            register_builtin_tools, register_surface_tools, Caller, DeploymentAdmission,
            DeploymentMutationBarrier, OperationAccess, ToolRegistry, DEPLOYMENT_READ_ONLY_ERROR,
        };

        let db = crate::db::create_database(":memory:").await.unwrap();
        let barrier = DeploymentMutationBarrier::default();
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        registry.set_deployment_mutation_barrier(barrier.clone());
        let registry = Arc::new(registry);

        let arguments = json!({"not": "parsed"});
        let (operation, access) = registry
            .registered_operation("create_record", &arguments)
            .unwrap();
        assert_eq!(access, OperationAccess::Mutation);
        let lease = match barrier.admit(&operation, access).unwrap() {
            DeploymentAdmission::Writable(lease) => lease,
            DeploymentAdmission::FrozenRead => panic!("open barrier refused a mutation"),
        };
        let freeze = {
            let barrier = barrier.clone();
            tokio::spawn(async move { barrier.freeze().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !barrier.is_read_only() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("freeze intent was not registered");

        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "create_record", "arguments": {"not": "parsed"}},
        });
        // Fresh dispatch re-admits and refuses with the frozen shape.
        let refused = handle_legacy_message(
            registry.clone(),
            db.clone(),
            Caller::local(),
            message.clone(),
        )
        .await;
        let (body, _) = refused.into_response().expect("refusal is a response");
        assert_eq!(
            body["result"]["structuredContent"]["error_code"],
            DEPLOYMENT_READ_ONLY_ERROR
        );

        // The held lease reuses through the same barrier: past the freeze
        // into argument validation, never the frozen refusal.
        let through = handle_legacy_message_with_persistence(
            registry.clone(),
            db.clone(),
            Caller::local(),
            message,
            Some(lease.clone()),
        )
        .await;
        let (body, _) = through.into_response().expect("dispatch is a response");
        assert_ne!(
            body["result"]["structuredContent"].get("error_code"),
            Some(&json!(DEPLOYMENT_READ_ONLY_ERROR))
        );

        drop(lease);
        tokio::time::timeout(std::time::Duration::from_secs(2), freeze)
            .await
            .expect("freeze did not acquire after lease drain")
            .unwrap();
    }
}
