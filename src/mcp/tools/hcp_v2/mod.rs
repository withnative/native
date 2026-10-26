//! Hosted HCP v2 entry tools (Human Context Protocol v2, Draft 1, MCP binding,
//! §10): `hcp_searchPreferences`, `hcp_getPreference`, `hcp_addPreference`,
//! `hcp_updatePreference` and `hcp_deletePreference`.
//!
//! This is the entry model and the five context operations over Native's
//! sealed events. V1 uses control events; v2 uses its existing content log and
//! private feature projections (`kernel`). It does not route a host or authenticate OAuth clients
//! (the hosting layer does). Audit and conflict transitions are sealed events;
//! confirmations bind locally verified human suggestion resolutions to a version.
//!
//! **Trusted state is a fold of events.** A person's entries are the ordered
//! fold ([`fold`]) of admitted HCP events, scoped to the authenticated account
//! (the resolved kernel account principal on v2). Each operation is one write
//! transaction that validates against that state and appends its events
//! ([`store`]). Both `hcp.*` and `kernel.hcp_*` events are reserved to sealed
//! handlers. V2 never creates or reads a `control_events` table.
//!
//! **The record is a view.** Each entry also has a private Native record the
//! person can read and edit ([`view`]). It is projected from the events after
//! the transaction, best effort, and is never read as evidence.
//!
//! **Personal context only.** Every entry is about the connected person
//! (HCP v2 §3.2.1).
//!
//! **Opt-in per workspace.** `Resolution/hcp_entry` is a workspace-defined
//! kind, not a built-in one. Every tool first checks that it is active in the
//! caller's v1 workspace. V2 requires explicit installation and adoption of
//! the exported `hcp.entry` and `hcp.suggestion` definitions. Otherwise tools
//! refuse with `native:not-configured` ([`setup`]); handlers never enable HCP.
//!
//! **No per-client grants.** Every connected client acts with the person's
//! ordinary Native access, so every category is treated as granted. The OAuth
//! client id is recorded on writes as `submittedByClient` for attribution only
//! and also binds disclosure from read events and client add/update versions.
//! Direct get requires earlier disclosure to that client (§5.2.2); calls
//! without a client id are refused (§3.11, invariant 5).
//!
//! **Envelope.** Results are returned in `structuredContent` and as JSON in a
//! text block (§10.3). A Core error is a tool execution error: `isError: true`
//! with `structuredContent: { type, detail }` (§10.4). `not authorized` is one
//! indistinguishable answer for "outside the grant", "does not exist", "hidden"
//! and "not yours to change".

mod audit;
mod client;
mod confirm;
mod conflicts;
mod fold;
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) mod kernel;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod kernel_human;
#[cfg(feature = "v2-kernel-probe")]
mod kernel_view;
mod limits;
mod model;
mod ops;
mod reconcile;
mod schemas;
mod setup;
mod store;
mod view;

#[cfg(test)]
mod tests;

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::interactions::{CustomInteractionPolicy, ToolExposure};
use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
use crate::mcp::DeploymentPersistenceLease;

use client::ClientIdentity;
use schemas::{description, input_schema};
use store::Store;

pub(super) fn register_audit_tool(registry: &mut ToolRegistry) -> Result<()> {
    audit::register(registry)
}
pub use audit::AUDIT_TOOL;
pub use client::{PseudonymKey, MIN_PSEUDONYM_SECRET_BYTES};
pub use schemas::{
    hcp_v2_tool_descriptors, ADD_PREFERENCE, DELETE_PREFERENCE, GET_PREFERENCE, SEARCH_PREFERENCES,
    TOOL_NAMES, UPDATE_PREFERENCE,
};
pub use setup::{
    KERNEL_ENTRY_DEFINITION, KERNEL_ENTRY_FAMILY, KERNEL_SUGGESTION_DEFINITION,
    KERNEL_SUGGESTION_FAMILY,
};

/// Proof that the caller is the HCP v2 handler. `hcp.*` control events are
/// reserved (see [`crate::control::NewControlEvent::hcp_state`]): their only
/// constructor needs one of these, and the private field and private `mint`
/// mean only this module and the modules beneath it can make one. No tool
/// takes an event type, and no other module can write into a person's trusted
/// state.
pub(crate) struct HcpWriteSeal {
    _private: (),
}

impl HcpWriteSeal {
    fn mint() -> Self {
        Self { _private: () }
    }
}

/// Core error codes (HCP v2 §5.5), as carried in `structuredContent.type`.
const MALFORMED_REQUEST: &str = "malformed-request";
const SCOPE_DENIED: &str = "scope-denied";
/// Error types this provider adds. They live in the `native:` namespace so
/// they are never mistaken for a Core code (HCP v2 §5.5).
const INTERNAL_ERROR: &str = "native:internal-error";
const DEPLOYMENT_READ_ONLY: &str = "native:deployment-read-only";
const DEPLOYMENT_DRAINING: &str = "native:deployment-draining";

/// Said for every not-authorized answer, so that the text cannot tell "outside
/// the grant" from "no such entry" (HCP v2 §5.2.2, §10.4).
const SCOPE_DENIED_DETAIL: &str =
    "The request is outside the authorized scope, or the entry does not exist.";

/// Why an operation did not produce a result.
pub(super) enum Failure {
    /// A Core error, or the provider's not-configured refusal: reported to the
    /// client as a tool execution error.
    Core { code: &'static str, detail: String },
    /// A Native-level failure. Deployment fences go to the transport as they
    /// are; anything else is reported as an internal error.
    Native(Error),
}

impl Failure {
    pub(super) fn invalid(detail: impl Into<String>) -> Self {
        Failure::Core {
            code: MALFORMED_REQUEST,
            detail: detail.into(),
        }
    }

    pub(super) fn not_authorized() -> Self {
        Failure::Core {
            code: SCOPE_DENIED,
            detail: SCOPE_DENIED_DETAIL.into(),
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Failure::Native(error)
    }
}

pub(super) type Outcome = std::result::Result<Value, Failure>;

// ---- registration ---------------------------------------------------------

/// Register the five HCP v2 tools in their own registry, as extension tools:
/// not shipped-tool kinds, no record-interaction logging.
///
/// None is declared read-only. Search and get append a `preference.read` audit
/// event (HCP v2 §8.1) once the audit log lands, and that is a write; a frozen
/// deployment must refuse them rather than serve unaudited reads (see
/// the durable read ledger).
pub fn register_hcp_v2_tools(registry: &mut ToolRegistry, key: PseudonymKey) -> Result<()> {
    macro_rules! register {
        ($name:expr, $operation:path) => {
            registry.register_custom(
                $name,
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                description($name),
                input_schema($name),
                {
                    let key = key.clone();
                    move |db: Db, caller: Caller, arguments: Value| {
                        let key = key.clone();
                        async move { run(db, caller, key, $operation, arguments).await }
                    }
                },
            )?
        };
    }
    register!(SEARCH_PREFERENCES, ops::search);
    register!(GET_PREFERENCE, ops::get);
    register!(ADD_PREFERENCE, ops::add);
    register!(UPDATE_PREFERENCE, ops::update);
    register!(DELETE_PREFERENCE, ops::delete);
    #[cfg(feature = "v2-kernel-probe")]
    {
        macro_rules! kernel_handler {
            ($name:expr, $operation:path) => {{
                let key = key.clone();
                registry.register_engine_handler(
                    $name,
                    crate::mcp::registry::EngineKind::KernelV2,
                    move |engine, caller, arguments| {
                        let key = key.clone();
                        async move {
                            let crate::mcp::registry::EngineHandle::KernelV2(db) = engine else {
                                unreachable!()
                            };
                            run_kernel(db, caller, key, $operation, arguments).await
                        }
                    },
                )?;
            }};
        }
        kernel_handler!(SEARCH_PREFERENCES, ops::search);
        kernel_handler!(GET_PREFERENCE, ops::get);
        kernel_handler!(ADD_PREFERENCE, ops::add);
        kernel_handler!(UPDATE_PREFERENCE, ops::update);
        kernel_handler!(DELETE_PREFERENCE, ops::delete);
    }
    Ok(())
}

/// Run one operation for a caller and frame its outcome as the MCP tool
/// result. Only deployment fences escape as `Err`.
async fn run<F>(
    db: Db,
    caller: Caller,
    key: PseudonymKey,
    operation: F,
    arguments: Value,
) -> Result<Value>
where
    F: for<'a> AsyncOperation<'a>,
{
    // A call no client can be held accountable for is not authorized,
    // whatever it asks (HCP v2 §3.11, invariant 5).
    let Some(client) = ClientIdentity::of(&caller) else {
        return Ok(error_frame(SCOPE_DENIED, SCOPE_DENIED_DETAIL));
    };
    match setup::not_configured(&db).await {
        Ok(None) => {}
        Ok(Some(message)) => return Ok(error_frame(setup::NOT_CONFIGURED, &message)),
        Err(error) => return fail(error),
    }
    let store = Store::new(&db, &caller, client, key);
    match operation.call(&store, &arguments).await {
        Ok(result) => Ok(success_frame(result)),
        Err(Failure::Core { code, detail }) => Ok(error_frame(code, &detail)),
        Err(Failure::Native(error)) => fail(error),
    }
}

#[cfg(feature = "v2-kernel-probe")]
async fn run_kernel<F>(
    db: Db,
    caller: Caller,
    key: PseudonymKey,
    operation: F,
    arguments: Value,
) -> Result<Value>
where
    F: for<'a> AsyncOperation<'a>,
{
    let Some(client) = ClientIdentity::of(&caller) else {
        return Ok(error_frame(SCOPE_DENIED, SCOPE_DENIED_DETAIL));
    };
    match setup::not_configured_kernel(&db).await {
        Ok(None) => {}
        Ok(Some(message)) => return Ok(error_frame(setup::NOT_CONFIGURED, &message)),
        Err(error) => return fail(error),
    }
    let store = match Store::new_kernel(&db, &caller, client, key).await {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    match operation.call(&store, &arguments).await {
        Ok(result) => Ok(success_frame(result)),
        Err(Failure::Core { code, detail }) => Ok(error_frame(code, &detail)),
        Err(Failure::Native(error)) => fail(error),
    }
}

/// An operation: an async function of the store and the raw arguments.
trait AsyncOperation<'a>: Copy {
    fn call(
        self,
        store: &'a Store<'a>,
        arguments: &'a Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>>;
}

impl<'a, F, Fut> AsyncOperation<'a> for F
where
    F: Fn(&'a Store<'a>, &'a Value) -> Fut + Copy,
    Fut: std::future::Future<Output = Outcome> + Send + 'a,
{
    fn call(
        self,
        store: &'a Store<'a>,
        arguments: &'a Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>> {
        Box::pin(self(store, arguments))
    }
}

/// Native refused the caller access to a record, or the record is not there
/// for them. Native answers "not visible" and "not permitted" identically on
/// purpose; so must this module, or a refusal would tell a client that an
/// entry exists.
fn is_authorization_refusal(error: &Error) -> bool {
    matches!(error, Error::Engine(message)
        if message.contains("; caller has ")
            || message.contains("does not exist")
            || message.contains("not visible")
            || message.contains("portable account binding"))
}

/// A Native-level failure: fences go to the transport, a refusal of access is
/// the same not-authorized answer as for an absent entry, the rest is
/// internal.
fn fail(error: Error) -> Result<Value> {
    match error {
        Error::DeploymentReadOnly(_)
        | Error::DeploymentDraining(_)
        | Error::Sqlx(sqlx::Error::PoolTimedOut) => Err(error),
        refusal if is_authorization_refusal(&refusal) => {
            Ok(error_frame(SCOPE_DENIED, SCOPE_DENIED_DETAIL))
        }
        other => {
            eprintln!("[native-ce] hcp_v2: internal error: {other}");
            Ok(error_frame(INTERNAL_ERROR, "Internal error"))
        }
    }
}

// ---- dispatch and MCP framing ---------------------------------------------

fn success_frame(body: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": body.to_string() }],
        "structuredContent": body,
        "isError": false,
    })
}

/// A Core error as a tool execution error (HCP v2 §10.4).
fn error_frame(code: &str, detail: &str) -> Value {
    json!({
        "isError": true,
        "structuredContent": { "type": code, "detail": detail },
        "content": [{ "type": "text", "text": format!("{code}: {detail}") }],
    })
}

/// The `tools/call` result for a Native-level failure before or around a
/// handler (for example a deployment freeze refused ahead of authentication).
pub fn failure_frame(error: &Error) -> Value {
    match error {
        Error::DeploymentReadOnly(_) => error_frame(
            DEPLOYMENT_READ_ONLY,
            "This Native deployment is temporarily read-only; retry shortly",
        ),
        Error::DeploymentDraining(_) => error_frame(
            DEPLOYMENT_DRAINING,
            "This Native deployment is draining; the outcome of a write is unknown, so read the entry before retrying",
        ),
        other => {
            eprintln!("[native-ce] hcp_v2: dispatch error: {other}");
            error_frame(INTERNAL_ERROR, "Internal error")
        }
    }
}

/// Call one HCP v2 tool and return the complete MCP `tools/call` result, or
/// `None` for a name that is not one of the five (the transport then answers
/// with a protocol error, HCP v2 §10.4).
///
/// `lease` is the deployment admission the transport took before
/// authentication, reused so a freeze registered afterwards drains this call
/// instead of refusing it; without one the registry admits the call itself.
pub async fn call_tool(
    registry: &ToolRegistry,
    db: Db,
    caller: Caller,
    name: &str,
    arguments: Value,
    lease: Option<DeploymentPersistenceLease>,
) -> Option<Value> {
    call_tool_engine(
        registry,
        EngineHandle::Sqlite(db),
        caller,
        name,
        arguments,
        lease,
    )
    .await
}

/// Engine-aware counterpart of [`call_tool`]. The hosting route supplies the
/// engine selected by the admitted workspace; framing and deployment admission
/// remain identical across workspace generations.
pub async fn call_tool_engine(
    registry: &ToolRegistry,
    engine: EngineHandle,
    caller: Caller,
    name: &str,
    arguments: Value,
    lease: Option<DeploymentPersistenceLease>,
) -> Option<Value> {
    if !TOOL_NAMES.contains(&name) {
        return None;
    }
    let dispatched = match lease {
        Some(lease) => {
            Box::pin(
                registry
                    .call_engine_detailed_with_persistence(engine, caller, name, arguments, lease),
            )
            .await
        }
        None => Box::pin(registry.call_engine_detailed(engine, caller, name, arguments)).await,
    };
    let result = match dispatched {
        Ok(call) => call.outcome.map(|result| result.structured),
        Err(error) => Err(error),
    };
    Some(match result {
        Ok(mut frame) => {
            // The registry names the attestations of the writes a call made.
            // Whether a read wrote anything (folding in an edit made in
            // Native, say) is not for a client to see: it would tell an
            // absent entry from one that exists but is hidden.
            if let Some(map) = frame.as_object_mut() {
                map.remove("action_attestation_ids");
            }
            frame
        }
        Err(error) => failure_frame(&error),
    })
}
