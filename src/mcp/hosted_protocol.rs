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
use super::registry::{Caller, ToolRegistry};
use super::render::Format;

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
}
