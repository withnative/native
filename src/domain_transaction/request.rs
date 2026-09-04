//! Canonical MCP request admission and result lifecycle.
//!
//! This is intentionally a wrapper around the existing concrete MCP types,
//! not a second tool abstraction. Backend selection stays in the registry;
//! SQLite supplies the admitted handler future while this module owns the
//! cross-cutting order shared by every implemented path.

use std::future::Future;

use futures::future::BoxFuture;
use serde_json::Value;

use crate::mcp::evidence::ToolResult;
use crate::mcp::interactions::{Extractor, ToolKind};
use crate::mcp::registry::Caller;
use crate::store::EventAnnotations;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernedRequestOperation {
    Authorization,
    InteractionCapture,
    RealtimeWakeup,
    RunContext,
    StableErrors,
    StrictPortability,
    TransientEvidence,
}

impl GovernedRequestOperation {
    pub const ALL: [Self; 7] = [
        Self::Authorization,
        Self::InteractionCapture,
        Self::RealtimeWakeup,
        Self::RunContext,
        Self::StableErrors,
        Self::StrictPortability,
        Self::TransientEvidence,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Authorization => "request.authorization",
            Self::InteractionCapture => "request.interaction-capture",
            Self::RealtimeWakeup => "request.realtime-wakeup",
            Self::RunContext => "request.run-context",
            Self::StableErrors => "request.stable-errors",
            Self::StrictPortability => "request.strict-portability",
            Self::TransientEvidence => "request.transient-evidence",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Authorization => 1 << 0,
            Self::InteractionCapture => 1 << 1,
            Self::RealtimeWakeup => 1 << 2,
            Self::RunContext => 1 << 3,
            Self::StableErrors => 1 << 4,
            Self::StrictPortability => 1 << 5,
            Self::TransientEvidence => 1 << 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernedRequestStage {
    pub operation: GovernedRequestOperation,
    pub dispatch_responsibility: &'static str,
}

pub const GOVERNED_REQUEST_PIPELINE: [GovernedRequestStage; 7] = [
    GovernedRequestStage {
        operation: GovernedRequestOperation::RunContext,
        dispatch_responsibility: "pre-handler run-context resolution",
    },
    GovernedRequestStage {
        operation: GovernedRequestOperation::StrictPortability,
        dispatch_responsibility: "storage-profile operation admission wrapper",
    },
    GovernedRequestStage {
        operation: GovernedRequestOperation::Authorization,
        dispatch_responsibility: "registered handler authorization boundary",
    },
    GovernedRequestStage {
        operation: GovernedRequestOperation::RealtimeWakeup,
        dispatch_responsibility: "post-handler committed-event notification boundary",
    },
    GovernedRequestStage {
        operation: GovernedRequestOperation::TransientEvidence,
        dispatch_responsibility: "tool-result evidence envelope boundary",
    },
    GovernedRequestStage {
        operation: GovernedRequestOperation::InteractionCapture,
        dispatch_responsibility: "post-handler best-effort interaction tap",
    },
    GovernedRequestStage {
        operation: GovernedRequestOperation::StableErrors,
        dispatch_responsibility: "stable tool-call outcome boundary",
    },
];

pub const fn governed_request_pipeline_is_exhaustive() -> bool {
    if GOVERNED_REQUEST_PIPELINE.len() != GovernedRequestOperation::ALL.len() {
        return false;
    }
    let mut governed = 0_u8;
    let mut index = 0;
    while index < GovernedRequestOperation::ALL.len() {
        governed |= GovernedRequestOperation::ALL[index].bit();
        index += 1;
    }
    let mut pipeline = 0_u8;
    index = 0;
    while index < GOVERNED_REQUEST_PIPELINE.len() {
        pipeline |= GOVERNED_REQUEST_PIPELINE[index].operation.bit();
        index += 1;
    }
    governed == pipeline
}

const _: () = assert!(governed_request_pipeline_is_exhaustive());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GovernedRequestStageDisposition {
    Applied,
    Suppressed,
}

/// A backend must declare every physical request capability. `Suppressed` is
/// an explicit compatibility decision for an already-routed backend, never an
/// inference from a missing handle. New implemented conformance paths require
/// `Applied`; `Unsupported` fails before the handler can mutate state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestStageCapability {
    Applied,
    Suppressed,
    #[allow(dead_code)] // Constructed by backend adapters as conformance expands.
    Unsupported,
}

pub(crate) struct InteractionCapture<'a> {
    pub extractor: Extractor,
    pub tool_name: &'a str,
    pub caller: &'a Caller,
    pub original_arguments: &'a Value,
    pub run_context: &'a Value,
    pub outcome: std::result::Result<&'a Value, &'a Error>,
    pub started_at: &'a str,
    pub ended_at: &'a str,
}

/// Narrow physical operations needed by the canonical request fold. This is
/// not a tool interface: handlers remain concrete registry closures and the
/// port cannot parse arguments, authorize records, shape results, or execute
/// arbitrary statements.
pub(crate) trait RequestLifecyclePort: Sync {
    fn backend_label(&self) -> &'static str;

    fn capability(&self, operation: GovernedRequestOperation) -> RequestStageCapability;

    fn mint_run_key<'a>(&'a self, agent_key: Option<&'a str>) -> BoxFuture<'a, Result<String>>;

    fn intent_at<'a>(&'a self, run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>>;

    /// Persist a successful intent declaration for one already-validated full
    /// run key. This is separate from the optional interaction tap: adapters
    /// may qualify run context without claiming interaction capture.
    fn persist_intent<'a>(
        &'a self,
        run_key: &'a str,
        intent: &'a str,
        authenticated_account: &'a str,
    ) -> BoxFuture<'a, Result<()>>;

    fn displaced_key_note<'a>(&'a self, caller: &'a Caller) -> BoxFuture<'a, Option<String>>;

    fn with_operation_admission<'a>(
        &'a self,
        operation: &'a str,
        capability: Option<&'a str>,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>>;

    fn with_realtime_completion<'a>(
        &'a self,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>>;

    fn capture_interaction<'a>(&'a self, capture: InteractionCapture<'a>) -> BoxFuture<'a, ()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GovernedRequestStageEvent {
    pub operation: GovernedRequestOperation,
    pub disposition: GovernedRequestStageDisposition,
}

struct GovernedRequestTrace {
    next: usize,
    events: [GovernedRequestStageEvent; GOVERNED_REQUEST_PIPELINE.len()],
}

/// One canonical tool-call result before transport framing. This is the same
/// concrete type historically exposed from the registry; that path re-exports
/// it so extraction does not create a parallel public result model.
pub struct ToolCallOutcome {
    pub original_arguments: Value,
    pub run_context: Value,
    pub outcome: Result<ToolResult>,
    #[cfg(test)]
    pub(crate) governed_request_trace: [GovernedRequestStageEvent; GOVERNED_REQUEST_PIPELINE.len()],
}

impl ToolCallOutcome {
    pub(crate) fn into_result(self) -> Result<Value> {
        self.outcome
            .map(|value| attach_run_context(value.structured, self.run_context))
    }
}

impl GovernedRequestTrace {
    fn new() -> Self {
        Self {
            next: 0,
            events: [GovernedRequestStageEvent {
                operation: GovernedRequestOperation::RunContext,
                disposition: GovernedRequestStageDisposition::Suppressed,
            }; GOVERNED_REQUEST_PIPELINE.len()],
        }
    }

    fn record(
        &mut self,
        operation: GovernedRequestOperation,
        disposition: GovernedRequestStageDisposition,
    ) {
        assert_eq!(
            GOVERNED_REQUEST_PIPELINE[self.next].operation, operation,
            "governed request wrapper order drifted from the executable pipeline"
        );
        self.events[self.next] = GovernedRequestStageEvent {
            operation,
            disposition,
        };
        self.next += 1;
    }

    fn finish(self) -> [GovernedRequestStageEvent; GOVERNED_REQUEST_PIPELINE.len()] {
        assert_eq!(
            self.next,
            GOVERNED_REQUEST_PIPELINE.len(),
            "governed request dispatch omitted a wrapper stage"
        );
        self.events
    }
}

const RUN_KEY_ARG: &str = "run_key";
const PARENT_KEY_ARG: &str = "parent_key";

pub(crate) fn add_run_context_arguments(schema: &mut Value, kind: Option<ToolKind>) {
    if kind.is_some_and(ToolKind::ignores_run_context_arguments) {
        return;
    }
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(branches) = object.get_mut("oneOf").and_then(Value::as_array_mut) {
        for branch in branches.iter_mut() {
            add_run_context_arguments(branch, kind);
        }
        object
            .entry("properties")
            .or_insert_with(|| serde_json::json!({}));
    }
    if let Some(branches) = object.get_mut("allOf").and_then(Value::as_array_mut) {
        for branch in branches.iter_mut() {
            add_run_context_arguments(branch, kind);
        }
    }
    let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    properties.insert(
        RUN_KEY_ARG.into(),
        serde_json::json!({
            "type": "string",
            "description": "Run correlation handle from bootstrap. Reuse the same key on every call, reads included. Mint with \"new\" or \"new:<agent_key>\". See coordination guide."
        }),
    );
    properties.insert(
        PARENT_KEY_ARG.into(),
        serde_json::json!({
            "type": "string",
            "description": "Optional spawning run_key; an unverified lineage hint. Minting sentinels are invalid. See coordination guide."
        }),
    );
    if !kind.is_some_and(ToolKind::callable_without_run_key) {
        let required = object
            .entry("required")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(list) = required.as_array_mut() {
            if !list.iter().any(|value| value == RUN_KEY_ARG) {
                list.push(Value::String(RUN_KEY_ARG.into()));
            }
        }
    }
}

fn run_context_values(arguments: &Value) -> (Option<&Value>, Option<&Value>) {
    let Some(object) = arguments.as_object() else {
        return (None, None);
    };
    (object.get(RUN_KEY_ARG), object.get(PARENT_KEY_ARG))
}

fn strip_run_context(arguments: &mut Value) {
    if let Some(object) = arguments.as_object_mut() {
        object.remove(RUN_KEY_ARG);
        object.remove(PARENT_KEY_ARG);
    }
}

pub(crate) struct ResolvedRunContext {
    pub caller: Caller,
    pub echo: Value,
    pub intent: Option<String>,
}

pub(crate) async fn resolve_run_context<P: RequestLifecyclePort + ?Sized>(
    port: &P,
    caller: Caller,
    arguments: &Value,
    public_origin: Option<&str>,
) -> ResolvedRunContext {
    let (raw_run_key, raw_parent_key) = run_context_values(arguments);
    let capability = port.capability(GovernedRequestOperation::RunContext);
    let mut run_key = crate::runkey::validate_run_key_value(raw_run_key);
    if let crate::runkey::KeyOutcome::Requested { agent_key } = &run_key {
        let minted = match capability {
            RequestStageCapability::Applied => port.mint_run_key(agent_key.as_deref()).await,
            RequestStageCapability::Suppressed | RequestStageCapability::Unsupported => {
                Err(Error::engine("run-key persistence is unavailable"))
            }
        };
        run_key = match minted {
            Ok(minted) => crate::runkey::KeyOutcome::Minted(minted),
            Err(_) => crate::runkey::KeyOutcome::Absent,
        };
    }
    let parent_key = crate::runkey::validate_parent_key_value(raw_parent_key);
    let caller = caller.with_run_context(
        run_key.stored().map(String::from),
        parent_key.stored().map(String::from),
    );
    let intent = match capability {
        RequestStageCapability::Applied => port.intent_at(caller.run_key()).await,
        RequestStageCapability::Suppressed | RequestStageCapability::Unsupported => None,
    };
    let caller = caller.with_intent(intent.clone());
    let displaced_note = if raw_run_key.and_then(Value::as_str).is_some_and(|raw| {
        raw != crate::runkey::SENTINEL && !raw.starts_with(crate::runkey::AGENT_KEY_SENTINEL_PREFIX)
    }) {
        match capability {
            RequestStageCapability::Applied => port.displaced_key_note(&caller).await,
            RequestStageCapability::Suppressed | RequestStageCapability::Unsupported => None,
        }
    } else {
        None
    };
    let echo = run_context_echo(
        &caller,
        &run_key,
        &parent_key,
        intent.as_deref(),
        displaced_note,
        public_origin,
    );
    ResolvedRunContext {
        caller,
        echo,
        intent,
    }
}

pub(crate) async fn run_context_for<P: RequestLifecyclePort + ?Sized>(
    port: &P,
    caller: Caller,
    arguments: &Value,
    public_origin: Option<&str>,
) -> Value {
    resolve_run_context(port, caller, arguments, public_origin)
        .await
        .echo
}

fn run_context_echo(
    caller: &Caller,
    run_key: &crate::runkey::KeyOutcome,
    parent_key: &crate::runkey::KeyOutcome,
    intent: Option<&str>,
    displaced_note: Option<String>,
    public_origin: Option<&str>,
) -> Value {
    let mut context = serde_json::Map::new();
    context.insert(
        RUN_KEY_ARG.into(),
        match caller.run_key() {
            Some(key) => Value::String(key.into()),
            None => Value::Null,
        },
    );
    context.insert(
        "intent".into(),
        intent.map_or(Value::Null, |value| Value::String(value.into())),
    );
    if let Some(parent) = caller.parent_key() {
        context.insert(PARENT_KEY_ARG.into(), Value::String(parent.into()));
    }
    let mut notes: Vec<String> = Vec::new();
    if let Some(key) = caller.run_key() {
        let path = format!("/workbench/runs/{key}");
        let follow_url = public_origin
            .map(|origin| format!("{origin}{path}"))
            .unwrap_or_else(|| path.clone());
        context.insert("follow_path".into(), Value::String(path));
        context.insert("follow_url".into(), Value::String(follow_url));
        if public_origin.is_none() {
            notes.push(
                "No public origin is configured; the follow link is relative to this Native CE deployment."
                    .into(),
            );
        }
    }
    if caller.run_key().is_none() {
        notes.push(
            "This call is not attached to a run. Pass run_key on every call to correlate \
             them — use the required key issued by bootstrap."
                .into(),
        );
    }
    notes.extend(run_key.note());
    notes.extend(parent_key.parent_note());
    notes.extend(displaced_note);
    if !notes.is_empty() {
        context.insert(
            "notes".into(),
            Value::Array(notes.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(context)
}

pub(crate) fn attach_run_context(result: Value, run_context: Value) -> Value {
    if run_context.is_null() {
        return result;
    }
    match result {
        Value::Object(mut object) => {
            object.insert("run_context".into(), run_context);
            Value::Object(object)
        }
        value => serde_json::json!({
            "value": value,
            "run_context": run_context,
        }),
    }
}

pub(crate) fn unsupported_backend_tool(tool: &str, backend: &str) -> Error {
    Error::engine(format!(
        "tool {tool} is not implemented for the {backend} backend"
    ))
}

pub(crate) fn unsupported_request_capability(
    backend: &str,
    operation: GovernedRequestOperation,
) -> Error {
    Error::engine(format!(
        "{backend} request capability '{}' is unsupported",
        operation.id()
    ))
}

fn admitted_stage<P: RequestLifecyclePort + ?Sized>(
    port: &P,
    operation: GovernedRequestOperation,
) -> Result<GovernedRequestStageDisposition> {
    match port.capability(operation) {
        RequestStageCapability::Applied => Ok(GovernedRequestStageDisposition::Applied),
        RequestStageCapability::Suppressed => Ok(GovernedRequestStageDisposition::Suppressed),
        RequestStageCapability::Unsupported => Err(unsupported_request_capability(
            port.backend_label(),
            operation,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_request<P, F, Fut>(
    port: &P,
    caller: Caller,
    name: &str,
    kind: Option<ToolKind>,
    extractor: Extractor,
    original_arguments: Value,
    capture: bool,
    public_origin: Option<&str>,
    bootstrap_exposure: Option<Value>,
    handler: F,
) -> Result<ToolCallOutcome>
where
    P: RequestLifecyclePort + ?Sized,
    F: FnOnce(Caller, Value) -> Fut,
    Fut: Future<Output = Result<ToolResult>> + Send,
{
    let run_context_stage = admitted_stage(port, GovernedRequestOperation::RunContext)?;
    let portability_stage = admitted_stage(port, GovernedRequestOperation::StrictPortability)?;
    let realtime_stage = admitted_stage(port, GovernedRequestOperation::RealtimeWakeup)?;
    let transient_stage = admitted_stage(port, GovernedRequestOperation::TransientEvidence)?;
    let interaction_stage = if capture {
        admitted_stage(port, GovernedRequestOperation::InteractionCapture)?
    } else {
        GovernedRequestStageDisposition::Suppressed
    };
    let mut trace = GovernedRequestTrace::new();
    let started_at = crate::mcp::interactions::timestamp();
    let mut resolved = if kind.is_some_and(ToolKind::ignores_run_context_arguments) {
        ResolvedRunContext {
            caller: caller.with_run_context(None, None).with_intent(None),
            echo: Value::Null,
            intent: None,
        }
    } else {
        resolve_run_context(port, caller, &original_arguments, public_origin).await
    };
    trace.record(GovernedRequestOperation::RunContext, run_context_stage);
    let capture_caller = resolved.caller.clone();
    let declaration_run_key = resolved.caller.run_key().map(String::from);
    let mut handler_arguments = original_arguments.clone();
    if !kind.is_some_and(ToolKind::ignores_run_context_arguments) {
        strip_run_context(&mut handler_arguments);
    }
    let annotations = EventAnnotations {
        run_key: resolved.caller.run_key().map(String::from),
        parent_key: resolved.caller.parent_key().map(String::from),
        intent: resolved.intent.clone(),
    };
    let provenance = crate::provenance::ProvenanceDispatch::from_caller(
        &resolved.caller,
        name,
        &handler_arguments,
        resolved.intent.as_deref(),
    );
    let portability_capability = crate::storage_profile::capability_for_tool(
        kind,
        &handler_arguments,
        resolved.caller.is_trusted_local(),
    );
    let handler_future = provenance.scope(crate::store::with_event_annotations(
        annotations,
        handler(resolved.caller, handler_arguments),
    ));
    trace.record(
        GovernedRequestOperation::StrictPortability,
        portability_stage,
    );
    let mut execution: BoxFuture<'_, Result<ToolResult>> = Box::pin(handler_future);
    if portability_stage == GovernedRequestStageDisposition::Applied {
        execution = port.with_operation_admission(name, portability_capability, execution);
    }
    if realtime_stage == GovernedRequestStageDisposition::Applied {
        execution = port.with_realtime_completion(execution);
    }
    let mut outcome = execution.await;
    if let Ok(result) = &mut outcome {
        let attestation_ids = provenance.receipt_ids();
        if !attestation_ids.is_empty() {
            if let Some(object) = result.structured.as_object_mut() {
                object.insert(
                    "action_attestation_ids".into(),
                    serde_json::to_value(attestation_ids)?,
                );
            }
        }
    }
    if kind == Some(ToolKind::PreviewRecordShape) {
        outcome = outcome.and_then(|mut result| {
            result.structured =
                super::record_shape_preflight::bound_preview_response_for_run_context(
                    result.structured,
                    &resolved.echo,
                )?;
            Ok(result)
        });
    }
    trace.record(
        GovernedRequestOperation::Authorization,
        GovernedRequestStageDisposition::Applied,
    );
    trace.record(GovernedRequestOperation::RealtimeWakeup, realtime_stage);

    if kind.is_some_and(ToolKind::issues_run_key) {
        let mut bootstrap_size_error = None;
        if let (Ok(result), Some(exposure)) = (&mut outcome, bootstrap_exposure) {
            if let Some(payload) = result.structured.as_object_mut() {
                let exposure_bytes = serde_json::to_vec(&exposure)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX);
                if exposure_bytes
                    > crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES
                {
                    bootstrap_size_error = Some(format!(
                        "bootstrap tool-exposure component is {exposure_bytes} bytes; limit is {} bytes",
                        crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES
                    ));
                } else {
                    payload.insert("tool_exposure".into(), exposure);
                    let total_bytes = serde_json::to_vec(payload)
                        .map(|bytes| bytes.len())
                        .unwrap_or(usize::MAX);
                    if total_bytes > crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES {
                        bootstrap_size_error = Some(format!(
                            "bootstrap payload is {total_bytes} bytes after tool exposure; compositional transport limit is {} bytes",
                            crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES
                        ));
                    }
                }
            }
        }
        if let Some(message) = bootstrap_size_error {
            outcome = Err(Error::engine(message));
        }
    }
    if kind == Some(ToolKind::SetIntent) && outcome.is_ok() {
        if let Some(intent) = original_arguments.get("intent").and_then(Value::as_str) {
            if let Some(run_key) = declaration_run_key.as_deref() {
                if let Err(error) = port
                    .persist_intent(run_key, intent, capture_caller.credential())
                    .await
                {
                    outcome = Err(error);
                }
            }
            if outcome.is_ok() {
                if let Some(echo) = resolved.echo.as_object_mut() {
                    echo.insert("intent".into(), Value::String(intent.to_string()));
                }
            }
        }
    }
    trace.record(GovernedRequestOperation::TransientEvidence, transient_stage);
    let ended_at = crate::mcp::interactions::timestamp();
    if capture && interaction_stage == GovernedRequestStageDisposition::Applied {
        port.capture_interaction(InteractionCapture {
            extractor,
            tool_name: name,
            caller: &capture_caller,
            original_arguments: &original_arguments,
            run_context: &resolved.echo,
            outcome: outcome.as_ref().map(|result| {
                result
                    .interaction_context
                    .as_ref()
                    .unwrap_or(&result.structured)
            }),
            started_at: &started_at,
            ended_at: &ended_at,
        })
        .await;
    }
    trace.record(
        GovernedRequestOperation::InteractionCapture,
        interaction_stage,
    );
    trace.record(
        GovernedRequestOperation::StableErrors,
        GovernedRequestStageDisposition::Applied,
    );
    #[cfg(test)]
    let governed_request_trace = trace.finish();
    #[cfg(not(test))]
    let _ = trace.finish();
    Ok(ToolCallOutcome {
        original_arguments,
        run_context: if kind.is_some_and(ToolKind::omits_run_context_echo) {
            Value::Null
        } else {
            resolved.echo
        },
        outcome,
        #[cfg(test)]
        governed_request_trace,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::mcp::{CustomInteractionPolicy, ToolExposure, ToolRegistry, TransientEvidence};
    use crate::store::AppendSpec;

    #[test]
    fn unsupported_backend_error_is_exact_and_backend_neutral() {
        assert_eq!(
            unsupported_backend_tool("get_record", "turso").to_string(),
            "tool get_record is not implemented for the turso backend"
        );
    }

    #[test]
    fn run_context_descends_into_all_of_object_branches() {
        let mut schema = json!({
            "allOf": [
                {"type":"object","properties":{"ids":{"type":"array"}},"required":["ids"]},
                {"anyOf":[{"required":["facets"]},{"required":["maturity"]}]}
            ]
        });

        add_run_context_arguments(&mut schema, Some(ToolKind::UpdateRecord));

        assert!(schema["allOf"][0]["properties"]["run_key"].is_object());
        assert!(schema["allOf"][0]["properties"]["parent_key"].is_object());
        assert!(schema["allOf"][0]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("run_key")));
    }

    #[tokio::test]
    async fn wrapper_preserves_run_echo_transient_evidence_and_interaction_policy() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        registry
            .register_custom(
                "wrapper_rich",
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                "wrapper test",
                json!({"type":"object","properties":{}}),
                |_db, caller, arguments| async move {
                    assert!(arguments.as_object().unwrap().is_empty());
                    assert_eq!(caller.run_key(), Some("scout-chair-a748b2"));
                    Ok(ToolResult::rich(
                        json!({"ok":true}),
                        vec![TransientEvidence::image("proof", "image/png", b"pixels")?],
                    ))
                },
            )
            .unwrap();

        let outcome = registry
            .call_detailed(
                db.clone(),
                Caller::local(),
                "wrapper_rich",
                json!({"run_key":"scout-chair-a748b2"}),
            )
            .await
            .unwrap();
        assert_eq!(outcome.original_arguments["run_key"], "scout-chair-a748b2");
        assert_eq!(outcome.run_context["run_key"], "scout-chair-a748b2");
        let result = outcome.outcome.unwrap();
        assert_eq!(result.structured, json!({"ok":true}));
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].handle, "proof");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM read_log_calls WHERE tool = 'wrapper_rich'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM read_log_touches")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
        db.close().await;
    }

    #[tokio::test]
    async fn realtime_wakes_after_committed_handler_completion_and_rollback_is_silent() {
        let db = crate::create_database(":memory:").await.unwrap();
        let (db, hub) = crate::realtime::RealtimeHub::install(db).await.unwrap();
        let mut receiver = hub.subscribe();
        let committed = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut registry = ToolRegistry::new();
        registry
            .register_custom(
                "deferred_realtime_commit",
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                "wrapper realtime test",
                json!({"type":"object","properties":{}}),
                {
                    let committed = Arc::clone(&committed);
                    let release = Arc::clone(&release);
                    move |db, _caller, _arguments| {
                        let committed = Arc::clone(&committed);
                        let release = Arc::clone(&release);
                        async move {
                            let mut transaction = crate::db::begin_write(db.write_pool()).await?;
                            crate::store::append_in(
                                &db,
                                &mut transaction,
                                AppendSpec {
                                    record_id: "c0119117-0000-4000-8000-000000000001".into(),
                                    event_type: "record.created".into(),
                                    payload: json!({
                                        "type":"Document",
                                        "kind":"note",
                                        "name":"committed"
                                    }),
                                    actor: Some("test".into()),
                                },
                            )
                            .await?;
                            db.commit_content(transaction).await?;
                            committed.notify_one();
                            release.notified().await;
                            Ok(json!({"ok":true}))
                        }
                    }
                },
            )
            .unwrap();
        registry
            .register_custom(
                "silent_realtime_rollback",
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                "wrapper rollback test",
                json!({"type":"object","properties":{}}),
                |db, _caller, _arguments| async move {
                    let mut transaction = crate::db::begin_write(db.write_pool()).await?;
                    crate::store::append_in(
                        &db,
                        &mut transaction,
                        AppendSpec {
                            record_id: "0110bac6-0000-4000-8000-000000000002".into(),
                            event_type: "record.created".into(),
                            payload: json!({
                                "type":"Document",
                                "kind":"note",
                                "name":"rolled back"
                            }),
                            actor: Some("test".into()),
                        },
                    )
                    .await?;
                    transaction.rollback().await?;
                    Ok(json!({"ok":true}))
                },
            )
            .unwrap();
        let registry = Arc::new(registry);
        let call = tokio::spawn({
            let registry = Arc::clone(&registry);
            let db = db.clone();
            async move {
                registry
                    .call(
                        db,
                        Caller::local(),
                        "deferred_realtime_commit",
                        json!({"run_key":"scout-chair-a748b2"}),
                    )
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), committed.notified())
            .await
            .expect("handler committed");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.recv())
                .await
                .is_err(),
            "realtime escaped before the handler completed"
        );
        release.notify_one();
        call.await.unwrap().unwrap();
        let published = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(published.record_id, "c0119117-0000-4000-8000-000000000001");

        registry
            .call(
                db.clone(),
                Caller::local(),
                "silent_realtime_rollback",
                json!({"run_key":"scout-chair-a748b2"}),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.recv())
                .await
                .is_err(),
            "rollback produced a realtime event"
        );
        db.close().await;
    }
}
