//! Hosted HCP preference tools (slices 1-2, Layer 1 + inference) plus the
//! slice-4a Layer 3 read tools `searchContext` and `traceContextItem`.
//!
//! These seven tools reproduce ContextRouter's MCP contract at 0439d8f
//! (conformance spec e5ae9ef) over Native records: `listPreferenceSlugs`,
//! `searchPreferences`, `listPermissionGrants` and `mutatePreferences`
//! (GLOBAL scope only), plus `smartSearchPreferences` over a Claude Haiku
//! client (see [`claude`]). `consolidateSchema` is deliberately not
//! registered or advertised yet.
//!
//! **Opt-in per workspace.** `Resolution/preference` is a workspace-defined
//! kind, not a built-in one. Every tool first checks that it is active in the
//! caller's workspace and otherwise refuses with `HCP_NOT_CONFIGURED` (see
//! [`setup`]); `/hcp` never defines or promotes the kind itself.
//!
//! **No per-client grants.** Every connected client acts with the person's
//! ordinary Native access (decision 87ce011 #4). The OAuth client id is
//! recorded on writes for attribution only and is never read by an
//! authorization decision. `listPermissionGrants` says so plainly instead of
//! inventing rules.
//!
//! **Provenance (slice 3).** Every preference carries an optional `native`
//! block (see [`native_block`]) and `mutatePreferences` accepts an optional
//! `expectedRevision`. Both are additive: a ContextRouter client sends and reads
//! neither.
//!
//! **Envelope.** Each handler returns the ContextRouter body `{ success, ... }`
//! as an ordinary `Ok(Value)`; `success: false` bodies carry `code` and
//! `error`. The `/hcp` transport frames `success: false` as an MCP tool error
//! (`isError: true`). See `storage` notes in [`store`] for the record model.

mod claude;
mod context_item;
mod context_search;
mod context_trace;
mod context_write;
mod extensions;
mod limits;
pub(crate) mod locks;
mod model;
mod native_block;
mod setup;
mod store;

use serde_json::{json, Map, Value};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::interactions::{CustomInteractionPolicy, ToolExposure};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::DeploymentPersistenceLease;

use model::{
    category_of, valid_slug, validate_value, Catalog, Definition, Scope, ValueType, ALLOW_SENSITIVE,
};
use store::{
    CatalogRecord, Described, PrefRecord, Provenance, Store, SuggestionRecord, MAX_EVIDENCE_BYTES,
};

pub const LIST_PREFERENCE_SLUGS: &str = "listPreferenceSlugs";
pub const SEARCH_PREFERENCES: &str = "searchPreferences";
pub const LIST_PERMISSION_GRANTS: &str = "listPermissionGrants";
pub const MUTATE_PREFERENCES: &str = "mutatePreferences";
pub const SMART_SEARCH_PREFERENCES: &str = "smartSearchPreferences";
pub const SEARCH_CONTEXT: &str = "searchContext";
pub const TRACE_CONTEXT_ITEM: &str = "traceContextItem";
pub const PROPOSE_CONTEXT_ITEM: &str = "proposeContextItem";
pub const RESOLVE_CONTEXT_ITEM: &str = "resolveContextItem";

/// The tools `/hcp` advertises, in `tools/list` order.
pub const TOOL_NAMES: [&str; 9] = [
    LIST_PREFERENCE_SLUGS,
    SEARCH_PREFERENCES,
    LIST_PERMISSION_GRANTS,
    MUTATE_PREFERENCES,
    SMART_SEARCH_PREFERENCES,
    SEARCH_CONTEXT,
    TRACE_CONTEXT_ITEM,
    PROPOSE_CONTEXT_ITEM,
    RESOLVE_CONTEXT_ITEM,
];

pub use extensions::{
    hcp_v2_extension_descriptors, register_hcp_v2_extensions, EXTENSION_TOOL_NAMES,
    NATIVE_PROPOSE_CONTEXT_ITEM, NATIVE_RESOLVE_CONTEXT_ITEM, NATIVE_SEARCH_CONTEXT,
    NATIVE_TRACE_CONTEXT_ITEM,
};

const CATALOG_RETRIES: usize = 3;

// Test-only pause points. A test arms one named point with a future (a
// concurrent Native edit); the code under test awaits it at that point, so a
// race between a check and the write it guards is reproduced deterministically.
#[cfg(test)]
type PauseFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
#[cfg(test)]
thread_local! {
    static PAUSE: std::cell::RefCell<Option<(&'static str, PauseFuture)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn arm_pause(
    point: &'static str,
    edit: impl std::future::Future<Output = ()> + Send + 'static,
) {
    PAUSE.with(|slot| *slot.borrow_mut() = Some((point, Box::pin(edit))));
}

#[cfg(test)]
async fn pause(point: &str) {
    let armed = PAUSE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(armed, _)| *armed == point) {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, edit)) = armed {
        edit.await;
    }
}

#[cfg(not(test))]
async fn pause(_point: &str) {}

// Test-only fault points: a test arms a named point and the next pass through it
// fails, so an error at an exact step (before or after a write) is reproduced.
#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn arm_fault(point: &'static str) {
    FAULT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn fault(point: &str) -> Result<()> {
    if FAULT.with(|slot| slot.get()) == Some(point) {
        FAULT.with(|slot| slot.set(None));
        return Err(Error::Io(std::io::Error::other("injected fault")));
    }
    Ok(())
}

#[cfg(not(test))]
fn fault(_point: &str) -> Result<()> {
    Ok(())
}

const OPERATIONS: [&str; 6] = [
    "SUGGEST_PREFERENCE",
    "SET_PREFERENCE",
    "CREATE_DEFINITION",
    "UPDATE_DEFINITION",
    "ARCHIVE_DEFINITION",
    "DELETE_PREFERENCE",
];

// ---- descriptors --------------------------------------------------------

fn string_schema() -> Value {
    json!({ "type": "string" })
}

fn input_schema(name: &str) -> Value {
    match name {
        LIST_PREFERENCE_SLUGS => json!({
            "type": "object",
            "properties": {
                "category": { "type": "string", "description": "Only definitions whose slug starts with this category (the part before the first dot)." }
            }
        }),
        SEARCH_PREFERENCES => json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Literal match: slug prefix, category substring or description substring, case-insensitive. Omit for every active preference." },
                "locationId": { "type": "string", "description": "Not supported: this endpoint serves GLOBAL preferences only." },
                "includeSuggestions": { "type": "boolean", "description": "Also return open suggestions under `suggested`." }
            }
        }),
        LIST_PERMISSION_GRANTS => json!({ "type": "object", "properties": {} }),
        SMART_SEARCH_PREFERENCES => json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "What to match preferences against; interpreted by the model." },
                "locationId": { "type": "string", "description": "Not supported: this endpoint serves GLOBAL preferences only." },
                "includeSuggestions": { "type": "boolean", "description": "Also return open suggestions under `matchedSuggestedPreferences`." }
            },
            "required": ["query"]
        }),
        SEARCH_CONTEXT => json!({
            "type": "object",
            "properties": {
                "task": { "type": "string", "description": "Natural-language task to find context for; candidates come from lexical search over these words." },
                "scope": {
                    "type": "object",
                    "properties": {
                        "project": { "type": "string", "description": "Only records under this folder or record." },
                        "subject": { "type": "string", "description": "Only records linked to this entity." }
                    }
                },
                "kinds": { "type": "array", "items": { "type": "string" }, "description": "Only records of these Native `Type/kind` values (for example `Resolution/decision`)." },
                "include": {
                    "type": "object",
                    "properties": {
                        "proposed": { "type": "boolean", "description": "Also return proposed items. Default false." },
                        "superseded": { "type": "boolean", "description": "Also return superseded records. Default false." },
                        "sources": { "type": "boolean", "description": "Also return status-less source records. Default true; false keeps only status-bearing items." }
                    }
                },
                "limit": { "type": "number", "description": "How many items to return. Default 10, max 50." }
            },
            "required": ["task"]
        }),
        PROPOSE_CONTEXT_ITEM => json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "description": "Native Type/kind of a new item, for example `Resolution/decision`, `Resolution/rule` or `Document/note` (the bare words decision, rule, note and fact are accepted). Required without `target`. A preference is proposed with mutatePreferences." },
                "statement": { "type": "string", "description": "The proposed text. For a new item, its content (the first line becomes its title). With `target`, the full replacement text for the target's body." },
                "value": { "description": "Not supported: a preference value is proposed with mutatePreferences." },
                "subject": { "type": "string", "description": "New item only. Reference of the person it is about; linked in the same call." },
                "appliesTo": { "type": "array", "items": { "type": "string" }, "description": "New item only. References of the projects, folders or records it applies to; linked in the same call." },
                "evidence": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ref": { "type": "string", "description": "A record this rests on; linked as evidence in the same call." },
                            "text": { "type": "string", "description": "A quotation or note, recorded on the proposal." }
                        }
                    }
                },
                "target": {
                    "type": "object",
                    "description": "Present = propose a change to an existing record instead of a new item.",
                    "properties": {
                        "ref": { "type": "string" },
                        "expectedRevision": { "type": "string", "description": "The target's `revision` you read. The proposal is anchored to it and Native refuses to apply it if the target has changed by the time it is accepted." }
                    },
                    "required": ["ref", "expectedRevision"]
                }
            },
            "required": ["statement"]
        }),
        RESOLVE_CONTEXT_ITEM => json!({
            "type": "object",
            "properties": {
                "ref": { "type": "string", "description": "A new proposed item to accept, or an accepted item to supersede. (A change proposal is resolved in Native: accept and reject on one answer RESOLVE_IN_NATIVE.)" },
                "action": { "type": "string", "enum": ["accept", "reject", "supersede"], "description": "reject is only ever answered RESOLVE_IN_NATIVE (a change proposal) or UNSUPPORTED_ACTION (a new item has no rejected state)." },
                "expectedRevision": { "type": "string", "description": "Required for accept and supersede: the item's `revision` as you read it. A stale one gives STALE_REVISION and changes nothing." },
                "replacement": {
                    "type": "object",
                    "description": "Supersede only. `{ ref }` of an existing item (propose it first; it may still be proposed). An inline statement is refused, and so is a revision on the replacement.",
                    "properties": {
                        "ref": { "type": "string" }
                    }
                },
                "reason": { "type": "string", "description": "Why; recorded with the resolution." }
            },
            "required": ["ref", "action", "reason"]
        }),
        TRACE_CONTEXT_ITEM => json!({
            "type": "object",
            "properties": {
                "ref": { "type": "string", "description": "Short reference or id of the record to trace." },
                "include": { "type": "array", "items": { "type": "string", "enum": ["evidence", "history", "supersession"] }, "description": "Sections to return. Default all three." },
                "historyLimit": { "type": "number", "description": "How many history entries to return. Default 20, max 100." }
            },
            "required": ["ref"]
        }),
        _ => json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": OPERATIONS },
                "preference": {
                    "type": "object",
                    "properties": {
                        "id": string_schema(),
                        "slug": string_schema(),
                        "value": { "type": "string", "description": "The value, JSON-encoded as a string (for example \"\\\"concise\\\"\", \"true\" or \"[\\\"a\\\"]\")." },
                        "locationId": string_schema(),
                        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
                        "evidence": { "type": "object", "description": "Structured provenance object; never JSON-encoded. Set \"speaker\": \"user\" when it is the person's own words, so Native reports the value as the person's view (basis `reported`)." },
                        "expectedRevision": { "type": "string", "description": "Optional, SET_PREFERENCE (of an existing record: the first SET refuses it) and DELETE_PREFERENCE of an active value only. The `native.revision` you last read; a stale one (or any, on an archived preference) is refused with STALE_REVISION and nothing changes. SUGGEST_PREFERENCE and DELETE_PREFERENCE of a suggestion refuse it up front (UNSUPPORTED_EXPECTED_REVISION)." }
                    }
                },
                "definition": {
                    "type": "object",
                    "properties": {
                        "id": string_schema(),
                        "slug": string_schema(),
                        "displayName": string_schema(),
                        "description": string_schema(),
                        "valueType": { "type": "string", "enum": ["STRING", "BOOLEAN", "ENUM", "ARRAY"] },
                        "scope": { "type": "string", "enum": ["GLOBAL", "LOCATION"] },
                        "options": { "type": "array", "items": string_schema() },
                        "isSensitive": { "type": "boolean" },
                        "expectedRevision": { "type": "string", "description": "Optional, UPDATE_DEFINITION and ARCHIVE_DEFINITION only. The `native.revision` you last read for this definition; a stale one is refused with STALE_REVISION." }
                    }
                }
            },
            "required": ["operation"]
        }),
    }
}

fn description(name: &str) -> &'static str {
    match name {
        LIST_PREFERENCE_SLUGS => "List the preference definitions visible to you (slug, category, description, value type, options, scope), without stored values.",
        SEARCH_PREFERENCES => "Retrieve stored preferences by literal slug prefix, category or description. Suggestions are returned only when includeSuggestions is true. Each preference may carry an optional `native` block: recordRef, url, revision (pass it back as expectedRevision), assertedBy with a basis (direct, endorsed, reported, or null when it is only an agent's inference), recordedBy and evidence.",
        LIST_PERMISSION_GRANTS => "List this client's permission grants. Native has no per-client grants: the list is empty and every client acts with the person's ordinary Native access.",
        SMART_SEARCH_PREFERENCES => "Match stored preferences against a natural-language query with model-assisted relevance. Returns matched definitions in relevance order with their active values (and suggestions only when includeSuggestions is true). Needs server-side model configuration. Preferences carry the same optional `native` block as searchPreferences.",
        SEARCH_CONTEXT => "Find records relevant to a natural-language task: decisions, preferences and other readable records in one list, model-ranked with a lexical fallback. Candidates come only from authorised reads and never reach the model unread. Status-bearing items rank first; `include.sources: false` keeps only them.",
        PROPOSE_CONTEXT_ITEM => "Propose a context item without making it current. With `target` ({ ref, expectedRevision }) it creates one Native suggestion on that record, anchored to the revision you read; Native refuses to apply it if the target has since changed. Without `target` it creates one new record of the given Type/kind at Native's `proposed` maturity, with its subject, appliesTo and evidence links written in the same call; searchContext reports it as `proposed`, never `accepted`, until it is resolved. Returns the proposal's ref. A preference is proposed with mutatePreferences.",
        RESOLVE_CONTEXT_ITEM => "Accept a proposed new item, or supersede an accepted one, each as one atomic Native write; anything that could not be made atomic is refused and nothing is attempted. accept makes a proposed new item accepted (checked against expectedRevision); supersede marks an accepted item superseded by an existing replacement `{ ref }` and links the two in one write (the replacement may itself still be proposed, and is reported as it is; an inline replacement is refused). A change proposal (a suggestion on an existing record) is NOT resolved here: accept and reject answer RESOLVE_IN_NATIVE with the target record's url and change nothing, because the person resolves it in Native. Permission is Native's own: you can resolve what your access lets you edit, and the item records who accepted it (an agent's acceptance is recorded as the agent's, with no claim that the person said it). Outcomes: accepted, superseded, conflict (nothing changed; code STALE_REVISION carries the current revision), refused (nothing changed), unconfirmed (the write may have landed: re-read before retrying).",
        TRACE_CONTEXT_ITEM => "Follow one context item through authorised reads: the item itself plus its evidence links, revision history and supersession. Unreadable records are refused without revealing that they exist.",
        _ => "Change one preference or definition per call. Values are JSON-encoded strings. SUGGEST_PREFERENCE records an inference for the person to review; SET_PREFERENCE revises the stored value in place. GLOBAL scope only. Optional expectedRevision (the `native.revision` last read) refuses a stale SET, DELETE of a value, UPDATE_DEFINITION or ARCHIVE_DEFINITION with STALE_REVISION and changes nothing; SUGGEST_PREFERENCE and DELETE of a suggestion refuse it (UNSUPPORTED_EXPECTED_REVISION). After an error that may follow a write, changed is null (OUTCOME_UNCERTAIN): re-read.",
    }
}

/// The tools that write; every other `/hcp` tool is read-only.
fn is_mutator(name: &str) -> bool {
    matches!(
        name,
        MUTATE_PREFERENCES | PROPOSE_CONTEXT_ITEM | RESOLVE_CONTEXT_ITEM
    )
}

/// MCP descriptors for the advertised tools, with ContextRouter's annotations
/// (read tools `readOnlyHint`, the mutator not read-only and not idempotent).
pub fn hcp_tool_descriptors() -> Vec<Value> {
    TOOL_NAMES
        .iter()
        .map(|name| {
            let mutator = is_mutator(name);
            let mut annotations = json!({ "readOnlyHint": !mutator, "openWorldHint": false });
            if mutator {
                annotations["idempotentHint"] = json!(false);
            }
            json!({
                "name": name,
                "description": description(name),
                "inputSchema": input_schema(name),
                "annotations": annotations,
            })
        })
        .collect()
}

/// Register the HCP tools in their own registry. They are registered as
/// extension tools: not shipped-tool kinds, no record-interaction logging. The
/// read tools are declared read-only; `mutatePreferences`, `proposeContextItem`
/// and `resolveContextItem` are mutations.
pub fn register_hcp_tools(registry: &mut ToolRegistry) -> Result<()> {
    macro_rules! register {
        ($name:expr, $handler:expr) => {
            registry.register_custom(
                $name,
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                description($name),
                input_schema($name),
                $handler,
            )?
        };
    }
    register!(LIST_PREFERENCE_SLUGS, list_preference_slugs);
    register!(SEARCH_PREFERENCES, search_preferences);
    register!(LIST_PERMISSION_GRANTS, list_permission_grants);
    register!(MUTATE_PREFERENCES, mutate_preferences);
    register!(SMART_SEARCH_PREFERENCES, smart_search_preferences);
    register!(SEARCH_CONTEXT, context_search::search_context);
    register!(TRACE_CONTEXT_ITEM, context_trace::trace_context_item);
    register!(PROPOSE_CONTEXT_ITEM, context_write::propose_context_item);
    register!(RESOLVE_CONTEXT_ITEM, context_write::resolve_context_item);
    // The six read tools never write, so a frozen deployment keeps serving
    // them. Admission classifies by tool name (server-owned, not by arguments).
    for name in [
        LIST_PREFERENCE_SLUGS,
        SEARCH_PREFERENCES,
        LIST_PERMISSION_GRANTS,
        SMART_SEARCH_PREFERENCES,
        SEARCH_CONTEXT,
        TRACE_CONTEXT_ITEM,
    ] {
        registry.declare_read_only(name)?;
    }
    Ok(())
}

// ---- dispatch and MCP framing -------------------------------------------

/// Frame a ContextRouter body as an MCP tool result: `content[0].text` is the
/// JSON of `structuredContent`, and `isError` is true exactly when the body
/// reports `success: false` (or, for dispatch-level failures, carries only
/// `error`).
fn frame(body: Value) -> Value {
    let is_error = body.get("success") == Some(&Value::Bool(false))
        || (body.get("success").is_none() && body.get("error").is_some());
    json!({
        "content": [{ "type": "text", "text": body.to_string() }],
        "structuredContent": body,
        "isError": is_error,
    })
}

/// Call one HCP tool and return the complete MCP `tools/call` result.
///
/// An unknown tool answers `{ error }` with no `success` field. A Native-level
/// failure the handler did not describe (a deployment fence, a lost database)
/// is reported in the same `success: false` envelope with a stable code rather
/// than as a protocol error, so a client always receives one shape.
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
) -> Value {
    if !TOOL_NAMES.contains(&name) {
        return frame(json!({ "error": format!("Unknown tool: {name}") }));
    }
    let dispatched = match lease {
        Some(lease) => {
            Box::pin(registry.call_detailed_with_persistence(db, caller, name, arguments, lease))
                .await
        }
        None => Box::pin(registry.call_detailed(db, caller, name, arguments)).await,
    };
    let result = match dispatched {
        Ok(call) => call.outcome.map(|result| result.structured),
        Err(error) => Err(error),
    };
    match result {
        Ok(mut body) => {
            absolutize_record_urls(&|path| registry.absolute_record_url(path), &mut body);
            frame(body)
        }
        Err(error) => failure_frame(name, &error),
    }
}

/// Turns a record's relative path into its absolute address, when the
/// deployment has an origin to give it.
type Absolute<'a> = &'a dyn Fn(&str) -> Option<String>;

/// `native.url` is built from the record's relative path; give it the
/// deployment's origin, exactly as `/mcp` does for `record_url`. Without a
/// configured origin it stays the relative path, as on stdio.
///
/// Only the known provenance paths are rewritten, and nothing under a `value`
/// is ever visited: a stored value that happens to look like a `native` block
/// is the person's data and stays byte for byte as stored.
fn absolutize_record_urls(absolute: Absolute, body: &mut Value) {
    fn link(absolute: Absolute, holder: &mut Value) {
        let Some(native) = holder.get_mut("native").and_then(Value::as_object_mut) else {
            return;
        };
        let resolved = native
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| url.starts_with('/'))
            .and_then(absolute);
        if let Some(url) = resolved {
            native.insert("url".into(), Value::String(url));
        }
    }
    // searchPreferences: `active` and `suggested`, each `{ preferences: [..] }`.
    for list in ["active", "suggested"] {
        if let Some(items) = body
            .get_mut(list)
            .and_then(|list| list.get_mut("preferences"))
            .and_then(Value::as_array_mut)
        {
            items.iter_mut().for_each(|item| link(absolute, item));
        }
    }
    // smartSearchPreferences.
    for list in ["matchedActivePreferences", "matchedSuggestedPreferences"] {
        if let Some(items) = body.get_mut(list).and_then(Value::as_array_mut) {
            items.iter_mut().for_each(|item| link(absolute, item));
        }
    }
    // mutatePreferences.
    for holder in ["preference", "definition"] {
        if let Some(holder) = body.get_mut(holder) {
            link(absolute, holder);
        }
    }
    // resolveContextItem RESOLVE_IN_NATIVE: the target record's url, and the
    // same path where the message names it.
    if let Some(target) = body.get_mut("target").filter(|target| target.is_object()) {
        let before = target
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string);
        absolutize_url(absolute, target);
        let after = target
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let (Some(before), Some(after)) = (before, after) {
            if before != after {
                if let Some(message) = body.get("error").and_then(Value::as_str) {
                    let message = message.replace(&format!("`{before}`"), &format!("`{after}`"));
                    body["error"] = Value::String(message);
                }
            }
        }
    }
    // searchContext: `items` are ContextItems with relative `url`s.
    if let Some(items) = body.get_mut("items").and_then(Value::as_array_mut) {
        for item in items.iter_mut() {
            absolutize_url(absolute, item);
        }
    }
    // traceContextItem: `item` plus full items under `supersession`.
    if let Some(item) = body.get_mut("item") {
        absolutize_url(absolute, item);
    }
    if let Some(supersession) = body.get_mut("supersession") {
        if let Some(items) = supersession
            .get_mut("supersedes")
            .and_then(Value::as_array_mut)
        {
            for item in items.iter_mut() {
                absolutize_url(absolute, item);
            }
        }
        if let Some(item) = supersession.get_mut("supersededBy") {
            absolutize_url(absolute, item);
        }
    }
}

/// Give one ContextItem's relative `url` the deployment's origin.
fn absolutize_url(absolute: Absolute, item: &mut Value) {
    let resolved = item
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with('/'))
        .and_then(absolute);
    if let Some(url) = resolved {
        item["url"] = Value::String(url);
    }
}

/// The `tools/call` result for a Native-level failure before or around a
/// handler (for example a deployment freeze refused ahead of authentication).
pub fn failure_frame(name: &str, error: &Error) -> Value {
    let (code, message) = transport_failure(error);
    let mut body = json!({ "success": false, "code": code, "error": message });
    if is_mutator(name) {
        // A read-only fence refuses the call before it changes anything. A
        // draining fence says itself that the outcome of a write is unknown, and
        // any other failure that escapes a mutation may have followed a write:
        // `changed` is then unknown (`null`), never `false`.
        let refused_first = matches!(error, Error::DeploymentReadOnly(_));
        body["changed"] = if refused_first {
            json!(false)
        } else {
            Value::Null
        };
        if name == RESOLVE_CONTEXT_ITEM {
            body["outcome"] = json!(if refused_first {
                "refused"
            } else {
                "unconfirmed"
            });
        }
    }
    frame(body)
}

fn transport_failure(error: &Error) -> (&'static str, String) {
    match error {
        Error::DeploymentReadOnly(_) => (
            "DEPLOYMENT_READ_ONLY",
            "This Native deployment is temporarily read-only; retry shortly".to_string(),
        ),
        Error::DeploymentDraining(_) => (
            "DEPLOYMENT_DRAINING",
            "This Native deployment is draining; the outcome of a write is unknown, so re-read before retrying"
                .to_string(),
        ),
        other => {
            eprintln!("[native-ce] hcp: dispatch error: {other}");
            ("INTERNAL_ERROR", "Internal error".to_string())
        }
    }
}

// ---- envelopes ----------------------------------------------------------

fn ok(mut body: Map<String, Value>) -> Value {
    let mut out = Map::new();
    out.insert("success".into(), Value::Bool(true));
    out.append(&mut body);
    Value::Object(out)
}

fn failure(code: &str, error: impl Into<String>) -> Value {
    json!({ "success": false, "code": code, "error": error.into() })
}

/// A Native error the tool can describe. Deployment fences and pool timeouts
/// are not the tool's to describe: they bubble to the transport unchanged.
fn describe(error: Error) -> Result<(&'static str, String)> {
    match &error {
        Error::DeploymentReadOnly(_)
        | Error::DeploymentDraining(_)
        | Error::Sqlx(sqlx::Error::PoolTimedOut) => Err(error),
        Error::Engine(message)
            if message.contains(" capability; caller has ")
                || message.contains("does not exist")
                || message.contains("portable account binding") =>
        {
            // Native answers "not visible" and "not permitted" identically on
            // purpose; so does this endpoint.
            Ok(("MCP_PERMISSION_DENIED", "Permission denied".to_string()))
        }
        Error::Conflict(_) => Ok((
            "STALE_REVISION",
            "The preference changed while this request ran; re-read it and retry".to_string(),
        )),
        other => {
            eprintln!("[native-ce] hcp: internal error: {other}");
            Ok(("INTERNAL_ERROR", "Internal error".to_string()))
        }
    }
}

fn arguments_object(arguments: &Value) -> std::result::Result<&Map<String, Value>, String> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    match arguments {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(EMPTY.get_or_init(Map::new)),
        _ => Err("arguments must be an object".into()),
    }
}

fn optional_str<'v>(
    map: &'v Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'v str>, String> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

// ---- wire shapes --------------------------------------------------------

fn preference_wire(
    id: &str,
    slug: &str,
    value: Value,
    status: &str,
    confidence: Option<f64>,
    updated_at: &str,
    description: &str,
) -> Value {
    json!({
        "id": id,
        "slug": slug,
        "value": value,
        "status": status,
        "sourceType": "INFERRED",
        "confidence": confidence,
        "locationId": null,
        "updatedAt": updated_at,
        "category": category_of(slug),
        "description": description,
    })
}

/// Attach the `native` block and the `sourceType` derived with it.
fn with_native(mut wire: Value, described: &Described) -> Value {
    wire["sourceType"] = json!(described.source_type);
    wire["native"] = described.native.clone();
    wire
}

fn active_wire(record: &PrefRecord, definition: &Definition) -> Option<Value> {
    let value = record.value()?;
    validate_value(definition, &value).ok()?;
    Some(preference_wire(
        &record.id,
        &record.slug,
        value,
        "ACTIVE",
        record.confidence,
        &record.updated_at,
        &definition.description,
    ))
}

fn suggested_wire(record: &SuggestionRecord, definition: &Definition) -> Option<Value> {
    let value = record.value()?;
    validate_value(definition, &value).ok()?;
    Some(preference_wire(
        &record.id,
        &record.slug,
        value,
        "SUGGESTED",
        record.confidence,
        &record.updated_at,
        &definition.description,
    ))
}

/// Definitions this interface may show: active, and never sensitive.
fn visible_definitions(catalog: &Catalog) -> Vec<&Definition> {
    let mut definitions: Vec<&Definition> = catalog
        .definitions
        .iter()
        .filter(|definition| {
            definition.is_active() && (ALLOW_SENSITIVE || !definition.is_sensitive)
        })
        .collect();
    definitions.sort_by(|a, b| a.slug.cmp(&b.slug));
    definitions
}

/// The wire entries for active records, each with its `native` block and the
/// confidence and `sourceType` its producer implies.
async fn active_wires(
    store: &Store<'_>,
    candidates: Vec<(PrefRecord, &Definition)>,
) -> Result<Vec<Value>> {
    let records: Vec<PrefRecord> = candidates
        .iter()
        .map(|(record, _)| record.clone())
        .collect();
    let described = store.describe_active(&records).await?;
    let mut wires = Vec::with_capacity(candidates.len());
    for ((record, definition), described) in candidates.into_iter().zip(&described) {
        let record = PrefRecord {
            confidence: described.confidence,
            ..described.refreshed.clone().unwrap_or(record)
        };
        wires.extend(active_wire(&record, definition).map(|wire| with_native(wire, described)));
    }
    Ok(wires)
}

/// The wire entries for open suggestions, each with its `native` block.
async fn suggested_wires(
    store: &Store<'_>,
    pairs: Vec<(&SuggestionRecord, &Definition)>,
) -> Result<Vec<Value>> {
    let records: Vec<&SuggestionRecord> = pairs.iter().map(|(record, _)| *record).collect();
    let described = store.describe_suggestions(&records).await?;
    let mut wires = Vec::with_capacity(pairs.len());
    for ((record, definition), described) in pairs.into_iter().zip(&described) {
        wires.extend(suggested_wire(record, definition).map(|wire| with_native(wire, described)));
    }
    Ok(wires)
}

// ---- read tools ---------------------------------------------------------

/// The body every tool returns while the workspace has not enabled HCP.
async fn refused_if_not_configured(db: &Db) -> Result<Option<Value>> {
    if extensions::on_hcp_v2_host() {
        return extensions::not_configured(db).await;
    }
    Ok(setup::not_configured(db)
        .await?
        .map(|message| failure(setup::NOT_CONFIGURED, message)))
}

async fn list_preference_slugs(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if let Some(refusal) = refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match arguments_object(&arguments) {
        Ok(args) => args,
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    };
    let category = match optional_str(args, "category") {
        Ok(category) => category,
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    };
    let store = Store::new(&db, &caller);
    let catalog = store
        .load_catalog()
        .await?
        .map(|record| record.catalog)
        .unwrap_or_else(Catalog::empty);
    let definitions: Vec<&Definition> = visible_definitions(&catalog)
        .into_iter()
        .filter(|definition| category.is_none_or(|category| definition.category() == category))
        .collect();
    let mut categories: Vec<&str> = definitions.iter().map(|d| d.category()).collect();
    categories.sort_unstable();
    categories.dedup();
    let mut body = Map::new();
    body.insert("categories".into(), json!(categories));
    body.insert("count".into(), json!(definitions.len()));
    body.insert(
        "preferences".into(),
        Value::Array(definitions.iter().map(|d| d.catalog_entry()).collect()),
    );
    Ok(ok(body))
}

async fn search_preferences(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if let Some(refusal) = refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match arguments_object(&arguments) {
        Ok(args) => args,
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    };
    let query = match optional_str(args, "query") {
        Ok(query) => query.map(str::to_lowercase),
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    };
    match optional_str(args, "locationId") {
        Ok(None) => {}
        Ok(Some(_)) => return Ok(unsupported_location()),
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    }
    let include_suggestions = match args.get("includeSuggestions") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Ok(failure(
                "INVALID_MUTATION_INPUT",
                "includeSuggestions must be a boolean",
            ))
        }
    };

    let store = Store::new(&db, &caller);
    let Some(catalog) = store.load_catalog().await?.map(|record| record.catalog) else {
        return Ok(search_body(Vec::new(), include_suggestions.then(Vec::new)));
    };
    let matching: Vec<&Definition> = visible_definitions(&catalog)
        .into_iter()
        .filter(|definition| match &query {
            None => true,
            Some(query) => {
                definition.slug.starts_with(query.as_str())
                    || definition.category().contains(query.as_str())
                    || definition
                        .description
                        .to_lowercase()
                        .contains(query.as_str())
            }
        })
        .collect();
    // A record counts only under the exact definition it was written for.
    let definition_for = |slug: &str, definition_id: &str| {
        matching
            .iter()
            .find(|d| d.slug == slug && d.id == definition_id)
            .copied()
    };

    let mut candidates: Vec<(PrefRecord, &Definition)> = store
        .load_preferences()
        .await?
        .into_iter()
        .filter_map(|record| {
            let definition = definition_for(&record.slug, &record.definition_id)?;
            active_wire(&record, definition)?;
            Some((record, definition))
        })
        .collect();
    candidates.truncate(limits::search_results());
    // Provenance (which confidence and `native` block a value carries) is
    // resolved only for the records actually returned.
    let active = active_wires(&store, candidates).await?;
    let suggested = if include_suggestions {
        let open = store.load_suggestions().await?;
        let mut pairs: Vec<(&SuggestionRecord, &Definition)> = open
            .iter()
            .filter_map(|record| {
                let definition = definition_for(&record.slug, &record.definition_id)?;
                suggested_wire(record, definition)?;
                Some((record, definition))
            })
            .collect();
        pairs.truncate(limits::search_results());
        Some(suggested_wires(&store, pairs).await?)
    } else {
        None
    };
    Ok(search_body(active, suggested))
}

fn search_body(active: Vec<Value>, suggested: Option<Vec<Value>>) -> Value {
    let mut body = Map::new();
    body.insert(
        "active".into(),
        json!({ "count": active.len(), "preferences": active }),
    );
    if let Some(suggested) = suggested {
        body.insert(
            "suggested".into(),
            json!({ "count": suggested.len(), "preferences": suggested }),
        );
    }
    ok(body)
}

fn unsupported_location() -> Value {
    failure(
        "UNSUPPORTED_SCOPE",
        "Location preferences are not supported; this endpoint serves GLOBAL preferences only",
    )
}

// ---- smartSearchPreferences (slice 2) -----------------------------------

/// The model client is missing: configuration, not a model failure.
const SMART_NOT_CONFIGURED: &str = "SMART_SEARCH_NOT_CONFIGURED";
/// The model call failed: refusal, truncation, HTTP, timeout or bad JSON.
const SMART_FAILED: &str = "SMART_SEARCH_FAILED";

// Test-only hook: arm a one-shot failure of the visibility re-read, so a
// test can prove a failed reload returns nothing from the pre-call set.
// Consumed (reset) on read.
#[cfg(test)]
thread_local! {
    static FAIL_VISIBILITY_RELOAD: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn fail_next_visibility_reload() {
    FAIL_VISIBILITY_RELOAD.with(|flag| flag.set(true));
}
/// The model's reading is a short string, not a body: cap it.
const INTERPRETATION_MAX_CHARS: usize = 300;

fn truncate_interpretation_to(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        text.chars().take(max).collect()
    } else {
        text.to_string()
    }
}

async fn smart_search_preferences(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if let Some(refusal) = refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match arguments_object(&arguments) {
        Ok(args) => args,
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    };
    let query = match args.get("query") {
        Some(Value::String(query)) if !query.trim().is_empty() => query.clone(),
        _ => return Ok(failure("INVALID_MUTATION_INPUT", "query is required")),
    };
    if query.len() > claude::QUERY_MAX_BYTES {
        return Ok(failure(
            "INVALID_MUTATION_INPUT",
            format!("query is too long (max {} bytes)", claude::QUERY_MAX_BYTES),
        ));
    }
    match optional_str(args, "locationId") {
        Ok(None) => {}
        Ok(Some(_)) => return Ok(unsupported_location()),
        Err(message) => return Ok(failure("INVALID_MUTATION_INPUT", message)),
    }
    let include_suggestions = match args.get("includeSuggestions") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Ok(failure(
                "INVALID_MUTATION_INPUT",
                "includeSuggestions must be a boolean",
            ))
        }
    };

    let store = Store::new(&db, &caller);
    let catalog = store
        .load_catalog()
        .await?
        .map(|record| record.catalog)
        .unwrap_or_else(Catalog::empty);
    let visible = visible_definitions(&catalog);
    if visible.is_empty() {
        // No catalog, no model call.
        return Ok(smart_body(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            String::new(),
        ));
    }
    // The catalog the caller may read: slugs with descriptions, no values.
    // Sensitive definitions are already withheld by `visible_definitions`.
    // Over the cap, send the first entries by stable slug order and say so
    // in the result (refusing would brick smart search for large catalogs;
    // silently dropping would lie about coverage).
    let truncated = visible.len().saturating_sub(claude::CATALOG_MAX_ENTRIES);
    let sent = &visible[..visible.len() - truncated];
    let catalog_json = Value::Array(
        sent.iter()
            .map(|definition| {
                json!({
                    "slug": definition.slug,
                    "description": claude::truncate_description(&definition.description),
                    "category": definition.category(),
                })
            })
            .collect(),
    );
    let relevance = match claude::identify_for_tool(&catalog_json, &query).await {
        Ok(relevance) => relevance,
        Err(claude::Error::NotConfigured(message)) => {
            return Ok(failure(SMART_NOT_CONFIGURED, message));
        }
        Err(error) => {
            return Ok(failure(
                SMART_FAILED,
                format!("smart-search model call failed: {error}"),
            ));
        }
    };
    // The note says what was skipped, and the 300-character cap covers
    // the whole field, note included: the model's text is cut to whatever
    // budget the note leaves, so the note itself always survives intact.
    let note = if truncated > 0 {
        format!(
            "[Native note: catalog truncated — the remaining {truncated} of {} definitions were not searched.]",
            visible.len()
        )
    } else {
        String::new()
    };
    let budget = INTERPRETATION_MAX_CHARS.saturating_sub(note.chars().count());
    let mut query_interpretation =
        truncate_interpretation_to(&relevance.query_interpretation, budget);
    if !note.is_empty() {
        if !query_interpretation.is_empty() {
            query_interpretation.push(' ');
        }
        query_interpretation.push_str(&note);
    }
    // Drop slugs not in the catalog and de-duplicate, keeping model order.
    // Validation is against what the model actually saw (`sent`), so a
    // truncated-away slug counts as a hallucination even though it exists.
    let mut ordered: Vec<&Definition> = Vec::new();
    for slug in &relevance.relevant_slugs {
        if ordered.iter().any(|definition| definition.slug == *slug) {
            continue;
        }
        if let Some(definition) = sent.iter().copied().find(|d| d.slug == *slug) {
            ordered.push(definition);
        }
    }
    let rank_of = |slug: &str| ordered.iter().position(|d| d.slug == slug);
    // A record counts only under the exact definition it was written for.
    let definition_for = |slug: &str, definition_id: &str| {
        ordered
            .iter()
            .find(|d| d.slug == slug && d.id == definition_id)
            .copied()
    };
    let mut matched_definitions: Vec<Value> = ordered
        .iter()
        .map(|definition| {
            json!({
                "slug": definition.slug,
                "description": definition.description,
                "category": definition.category(),
            })
        })
        .collect();

    let mut active: Vec<(usize, PrefRecord, &Definition)> = store
        .load_preferences()
        .await?
        .into_iter()
        .filter_map(|record| {
            let definition = definition_for(&record.slug, &record.definition_id)?;
            active_wire(&record, definition)?;
            Some((rank_of(&record.slug)?, record, definition))
        })
        .collect();
    active.sort_by_key(|(rank, _, _)| *rank);
    active.truncate(limits::search_results());
    // Provenance (which confidence and `native` block a value carries) is
    // resolved only for the records actually returned.
    let mut matched_active = active_wires(
        &store,
        active
            .into_iter()
            .map(|(_, record, definition)| (record, definition))
            .collect(),
    )
    .await?;
    let open = if include_suggestions {
        store.load_suggestions().await?
    } else {
        Vec::new()
    };
    let mut suggested: Vec<(usize, &SuggestionRecord, &Definition)> = open
        .iter()
        .filter_map(|record| {
            let definition = definition_for(&record.slug, &record.definition_id)?;
            suggested_wire(record, definition)?;
            Some((rank_of(&record.slug)?, record, definition))
        })
        .collect();
    suggested.sort_by_key(|(rank, _, _)| *rank);
    suggested.truncate(limits::search_results());
    let mut matched_suggested = suggested_wires(
        &store,
        suggested
            .into_iter()
            .map(|(_, record, definition)| (record, definition))
            .collect(),
    )
    .await?;
    // Re-apply the sensitivity filter to all three lists against a fresh
    // catalog read: a definition marked sensitive (or removed) while the
    // model call ran must not leak into the output. Fail closed: a failed
    // re-read errors the call like any other store read, never serving the
    // possibly-revoked pre-call set.
    #[cfg(test)]
    if FAIL_VISIBILITY_RELOAD.with(|flag| flag.replace(false)) {
        return Err(crate::error::Error::engine(
            "test-forced visibility reload failure",
        ));
    }
    let fresh: std::collections::HashSet<String> = visible_definitions(
        &store
            .load_catalog()
            .await?
            .map(|record| record.catalog)
            .unwrap_or_else(Catalog::empty),
    )
    .iter()
    .map(|definition| definition.slug.clone())
    .collect();
    apply_visibility(
        &mut matched_definitions,
        &mut matched_active,
        &mut matched_suggested,
        &fresh,
    );
    Ok(smart_body(
        matched_definitions,
        matched_active,
        matched_suggested,
        query_interpretation,
    ))
}

/// Drop every output entry whose slug the caller may not read, across all
/// three lists. Pure so tests can drive it directly.
fn apply_visibility(
    definitions: &mut Vec<Value>,
    active: &mut Vec<Value>,
    suggested: &mut Vec<Value>,
    allowed: &std::collections::HashSet<String>,
) {
    for list in [definitions, active, suggested] {
        list.retain(|item| {
            item.get("slug")
                .and_then(Value::as_str)
                .is_some_and(|slug| allowed.contains(slug))
        });
    }
}

fn smart_body(
    definitions: Vec<Value>,
    active: Vec<Value>,
    suggested: Vec<Value>,
    interpretation: String,
) -> Value {
    let mut body = Map::new();
    body.insert("matchedDefinitions".into(), Value::Array(definitions));
    body.insert("matchedActivePreferences".into(), Value::Array(active));
    body.insert(
        "matchedSuggestedPreferences".into(),
        Value::Array(suggested),
    );
    body.insert("queryInterpretation".into(), Value::String(interpretation));
    ok(body)
}

async fn list_permission_grants(db: Db, _caller: Caller, _arguments: Value) -> Result<Value> {
    if let Some(refusal) = refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let mut body = Map::new();
    body.insert("grants".into(), json!([]));
    body.insert(
        "native".into(),
        json!({ "perClientGrants": "not_implemented", "access": "principal" }),
    );
    Ok(ok(body))
}

// ---- mutatePreferences --------------------------------------------------

/// A refusal of one mutation, rendered into the audited envelope.
struct Refusal {
    code: &'static str,
    error: String,
    target: Option<String>,
    /// The revision the thing is at now, on a `STALE_REVISION` refusal.
    current_revision: Option<String>,
    /// The change may or may not have been applied, so `changed` is unknown.
    uncertain: bool,
}

impl Refusal {
    fn new(code: &'static str, error: impl Into<String>) -> Self {
        Self {
            code,
            error: error.into(),
            target: None,
            current_revision: None,
            uncertain: false,
        }
    }

    /// An error after a write was issued: it may have landed, and the answer
    /// must not claim it did not.
    fn uncertain(target: Option<&str>) -> Self {
        let mut refusal = Self::new(
            "OUTCOME_UNCERTAIN",
            "The change may or may not have been applied; re-read the preference before retrying",
        );
        refusal.target = target.map(str::to_string);
        refusal.uncertain = true;
        refusal
    }

    /// `expectedRevision` on an archived preference: an archived value never
    /// matches, and is not restored on behalf of a request that expects a
    /// revision. It has no current revision to offer.
    fn stale_archived(target: &str) -> Self {
        Self::new(
            "STALE_REVISION",
            "The preference is archived, so no expectedRevision matches it and it was not restored; re-read it, or SET without expectedRevision to restore it",
        )
        .at(target)
    }

    /// `expectedRevision` where no atomic guard exists to enforce it.
    fn unsupported_expected_revision(target: &str, operation: &str) -> Self {
        Self::new(
            "UNSUPPORTED_EXPECTED_REVISION",
            format!(
                "expectedRevision is not supported on {operation}: Native has no atomic guard for it there, so nothing was attempted. Omit expectedRevision"
            ),
        )
        .at(target)
    }

    /// The caller's `expectedRevision` is not the current one.
    fn stale(target: &str, current: String) -> Self {
        let mut refusal = Self::new(
            "STALE_REVISION",
            "expectedRevision is stale: the value changed since it was read; re-read it and retry",
        )
        .at(target);
        refusal.current_revision = Some(current);
        refusal
    }

    fn at(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    fn input(error: impl Into<String>) -> Self {
        Self::new("INVALID_MUTATION_INPUT", error)
    }

    fn denied_sensitive(target: &str) -> Self {
        Self::new(
            "MCP_PERMISSION_DENIED",
            "Sensitive preference access denied",
        )
        .at(target)
    }
}

/// What a successful mutation reports.
struct Applied {
    changed: bool,
    code: Option<&'static str>,
    target: String,
    preference: Option<Value>,
    definition: Option<Value>,
    /// For a definition result: the exact definition the catalog write
    /// stored, and the catalog record holding it, so its `native` block is
    /// built from what was written and not from a later read.
    defined: Option<Defined>,
}

struct Defined {
    catalog_id: String,
    definition: Definition,
}

type Outcome = Result<std::result::Result<Applied, Refusal>>;
/// An outcome that is already decided (no I/O left).
type Decided = std::result::Result<Applied, Refusal>;

/// The revision a value is at: the SHA-256 of its body, which is exactly the
/// `if_body_digest` Native checks atomically on `update_record`. An empty body
/// (nothing set yet, or cleared) has the digest of the empty string.
fn body_revision(body: &str) -> String {
    store::sha256_hex(body)
}

/// A definition lives inside the catalog record, whose body digest would move
/// on any definition's change. A definition's revision is therefore the digest
/// of the definition itself, which moves only when it does.
fn definition_revision(definition: &Definition) -> String {
    store::sha256_hex(&serde_json::to_string(definition).expect("a definition serializes"))
}

/// `Some(current)` when `expected` is present and is not `current`.
fn stale(expected: Option<&str>, current: impl FnOnce() -> String) -> Option<String> {
    let expected = expected?;
    let current = current();
    (expected != current).then_some(current)
}

/// `expectedRevision` of a `preference` or `definition` object.
fn expected_revision(
    map: &Map<String, Value>,
    prefix: &str,
) -> std::result::Result<Option<String>, Refusal> {
    match map.get("expectedRevision") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(revision)) if !revision.trim().is_empty() => Ok(Some(revision.clone())),
        Some(_) => Err(Refusal::input(format!(
            "{prefix}.expectedRevision must be a non-empty string"
        ))),
    }
}

fn required_permission(operation: &str) -> Option<&'static str> {
    match operation {
        "SUGGEST_PREFERENCE" => Some("SUGGEST"),
        "SET_PREFERENCE" | "DELETE_PREFERENCE" => Some("WRITE"),
        "CREATE_DEFINITION" | "UPDATE_DEFINITION" | "ARCHIVE_DEFINITION" => Some("DEFINE"),
        _ => None,
    }
}

async fn mutate_preferences(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let store = Store::new(&db, &caller);
    let audit = json!({
        "origin": "MCP",
        "actorClientKey": store.client,
        "correlationId": store.correlation_id,
    });
    let operation = arguments
        .get("operation")
        .and_then(Value::as_str)
        .map(str::to_string);
    let permission = operation.as_deref().and_then(required_permission);

    let outcome: Outcome = if let Some(message) = setup::not_configured(&db).await? {
        Ok(Err(Refusal::new(setup::NOT_CONFIGURED, message)))
    } else if !arguments.is_object() {
        Ok(Err(Refusal::input("arguments must be an object")))
    } else if let (Some(operation), Some(_)) = (operation.as_deref(), permission) {
        // One mutation at a time per person and workspace: lookup-or-create,
        // definition changes and preference writes must not interleave.
        let _serialised = locks::acquire(&format!(
            "{}|{}",
            caller.hosting_database().unwrap_or_default(),
            store.person
        ))
        .await;
        apply(&store, operation, &arguments).await
    } else {
        Ok(Err(Refusal::new(
            "INVALID_MUTATION_OPERATION",
            match &operation {
                None => "operation is required".to_string(),
                Some(operation) => format!("Unknown operation: {operation}"),
            },
        )))
    };

    let mut envelope = Map::new();
    match outcome? {
        Ok(applied) => {
            envelope.insert("success".into(), json!(true));
            envelope.insert("changed".into(), json!(applied.changed));
            envelope.insert("operation".into(), json!(operation));
            envelope.insert("requiredPermission".into(), json!(permission));
            envelope.insert("target".into(), json!(applied.target));
            if let Some(code) = applied.code {
                envelope.insert("code".into(), json!(code));
            }
            if let Some(preference) = applied.preference {
                envelope.insert("preference".into(), preference);
            }
            if let Some(definition) = applied.definition {
                envelope.insert("definition".into(), definition);
            }
        }
        Err(refusal) => {
            envelope.insert("success".into(), json!(false));
            // `null` when the change may have landed: never claim it did not.
            envelope.insert(
                "changed".into(),
                if refusal.uncertain {
                    Value::Null
                } else {
                    json!(false)
                },
            );
            envelope.insert("operation".into(), json!(operation));
            envelope.insert("requiredPermission".into(), json!(permission));
            envelope.insert("target".into(), json!(refusal.target));
            envelope.insert("code".into(), json!(refusal.code));
            envelope.insert("error".into(), json!(refusal.error));
            if let Some(revision) = refusal.current_revision {
                envelope.insert("current".into(), json!({ "revision": revision }));
            }
        }
    }
    envelope.insert("audit".into(), audit);
    Ok(Value::Object(envelope))
}

async fn apply(store: &Store<'_>, operation: &str, arguments: &Value) -> Outcome {
    let result = match operation {
        "CREATE_DEFINITION" => {
            describe_definition(store, create_definition(store, arguments).await).await
        }
        "UPDATE_DEFINITION" => {
            describe_definition(store, update_definition(store, arguments).await).await
        }
        "ARCHIVE_DEFINITION" => {
            describe_definition(store, archive_definition(store, arguments).await).await
        }
        "SET_PREFERENCE" => write_preference(store, arguments, false).await,
        "SUGGEST_PREFERENCE" => write_preference(store, arguments, true).await,
        "DELETE_PREFERENCE" => delete_preference(store, arguments).await,
        _ => unreachable!("operation was matched against the table"),
    };
    match result {
        Ok(outcome) => Ok(outcome),
        // A write was issued (or has landed) and then something failed: whatever
        // the error, whether the change landed is not known.
        Err(error) if store.outcome_uncertain() => {
            eprintln!("[native-ce] hcp: error after a write was issued: {error}");
            Ok(Err(Refusal::uncertain(None)))
        }
        Err(error) => describe(error).map(|(code, message)| Err(Refusal::new(code, message))),
    }
}

/// Give a definition result its `native` block.
async fn describe_definition(store: &Store<'_>, outcome: Outcome) -> Outcome {
    pause("definition_written").await;
    let mut applied = match outcome? {
        Ok(applied) => applied,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(defined) = applied.defined.take() {
        let native = store
            .describe_definition(
                &defined.catalog_id,
                &defined.definition,
                &definition_revision(&defined.definition),
            )
            .await?;
        if let Some(wire) = applied.definition.as_mut() {
            wire["native"] = native;
        }
    }
    Ok(Ok(applied))
}

fn object_field<'v>(
    arguments: &'v Value,
    key: &str,
) -> std::result::Result<&'v Map<String, Value>, Refusal> {
    match arguments.get(key) {
        Some(Value::Object(map)) => Ok(map),
        Some(_) => Err(Refusal::input(format!("{key} must be an object"))),
        None => Err(Refusal::input(format!("{key} is required"))),
    }
}

fn required_str<'v>(
    map: &'v Map<String, Value>,
    key: &str,
    prefix: &str,
) -> std::result::Result<&'v str, Refusal> {
    match map.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s),
        _ => Err(Refusal::input(format!("{prefix}.{key} is required"))),
    }
}

fn optional_field_str<'v>(
    map: &'v Map<String, Value>,
    key: &str,
    prefix: &str,
) -> std::result::Result<Option<&'v str>, Refusal> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(Refusal::input(format!("{prefix}.{key} must be a string"))),
    }
}

fn parse_value_type(raw: &str) -> Option<ValueType> {
    match raw {
        "STRING" => Some(ValueType::String),
        "BOOLEAN" => Some(ValueType::Boolean),
        "ENUM" => Some(ValueType::Enum),
        "ARRAY" => Some(ValueType::Array),
        _ => None,
    }
}

fn parse_options(map: &Map<String, Value>) -> std::result::Result<Option<Vec<String>>, Refusal> {
    match map.get("options") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .map(Some)
            .ok_or_else(|| Refusal::input("definition.options must be an array of strings")),
        Some(_) => Err(Refusal::input(
            "definition.options must be an array of strings",
        )),
    }
}

fn parse_scope(raw: &str) -> Option<Scope> {
    match raw {
        "GLOBAL" => Some(Scope::Global),
        "LOCATION" => Some(Scope::Location),
        _ => None,
    }
}

fn check_enum_options(
    value_type: ValueType,
    options: &Option<Vec<String>>,
) -> std::result::Result<(), Refusal> {
    match (value_type, options) {
        (ValueType::Enum, Some(options))
            if !options.is_empty() && options.iter().all(|o| !o.is_empty()) =>
        {
            Ok(())
        }
        (ValueType::Enum, _) => Err(Refusal::new(
            "INVALID_PREFERENCE_DEFINITION",
            "ENUM definitions require a nonempty options array",
        )),
        (_, Some(_)) => Err(Refusal::new(
            "INVALID_PREFERENCE_DEFINITION",
            "options are allowed only for ENUM definitions",
        )),
        (_, None) => Ok(()),
    }
}

fn now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Read-modify-write of the catalog, retried when another writer revised it
/// between our read and our guarded write.
async fn edit_catalog<F>(
    store: &Store<'_>,
    what: &str,
    mut edit: F,
) -> Result<std::result::Result<Applied, Refusal>>
where
    F: FnMut(&mut Catalog) -> std::result::Result<Applied, Refusal>,
{
    for attempt in 0..CATALOG_RETRIES {
        let existing: Option<CatalogRecord> = store.load_catalog().await?;
        let mut catalog = existing
            .as_ref()
            .map(|record| record.catalog.clone())
            .unwrap_or_else(Catalog::empty);
        let applied = match edit(&mut catalog) {
            Ok(applied) => applied,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match store.save_catalog(existing.as_ref(), &catalog, what).await {
            Ok(catalog_id) => {
                let mut applied = applied;
                if let Some(defined) = applied.defined.as_mut() {
                    defined.catalog_id = catalog_id;
                }
                return Ok(Ok(applied));
            }
            Err(Error::Conflict(_)) if attempt + 1 < CATALOG_RETRIES => continue,
            Err(error) => return Err(error),
        }
    }
    Err(Error::engine("catalog changed concurrently"))
}

async fn create_definition(store: &Store<'_>, arguments: &Value) -> Outcome {
    let input = match object_field(arguments, "definition") {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let parsed = (|| {
        let slug = required_str(input, "slug", "definition")?;
        let description = required_str(input, "description", "definition")?;
        let value_type = required_str(input, "valueType", "definition")?;
        let scope = required_str(input, "scope", "definition")?;
        let display_name = optional_field_str(input, "displayName", "definition")?;
        let options = parse_options(input)?;
        let sensitive = match input.get("isSensitive") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(Refusal::input("definition.isSensitive must be a boolean")),
        };
        Ok((
            slug,
            description,
            value_type,
            scope,
            display_name,
            options,
            sensitive,
        ))
    })();
    let (slug, description, value_type, scope, display_name, options, sensitive) = match parsed {
        Ok(parsed) => parsed,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if input.get("expectedRevision").is_some_and(|v| !v.is_null()) {
        return Ok(Err(Refusal::input(
            "definition.expectedRevision does not apply to CREATE_DEFINITION: there is nothing to revise",
        )
        .at(slug)));
    }
    if sensitive && !ALLOW_SENSITIVE {
        return Ok(Err(Refusal::denied_sensitive(slug)));
    }
    if !valid_slug(slug) {
        return Ok(Err(Refusal::new(
            "INVALID_PREFERENCE_DEFINITION",
            "Invalid slug format: use lowercase dotted words such as writing.length",
        )
        .at(slug)));
    }
    let Some(value_type) = parse_value_type(value_type) else {
        return Ok(Err(Refusal::new(
            "INVALID_PREFERENCE_DEFINITION",
            "valueType must be STRING, BOOLEAN, ENUM or ARRAY",
        )
        .at(slug)));
    };
    let Some(scope) = parse_scope(scope) else {
        return Ok(Err(Refusal::new(
            "INVALID_PREFERENCE_DEFINITION",
            "scope must be GLOBAL or LOCATION",
        )
        .at(slug)));
    };
    if scope == Scope::Location {
        return Ok(Err(unsupported_scope_refusal(slug)));
    }
    if let Err(refusal) = check_enum_options(value_type, &options) {
        return Ok(Err(refusal.at(slug)));
    }
    let (slug, description, display_name) = (
        slug.to_string(),
        description.to_string(),
        display_name.map(str::to_string),
    );
    let client = store.client.clone();
    edit_catalog(store, &format!("create definition {slug}"), |catalog| {
        if catalog.active(&slug).is_some() {
            return Err(Refusal::new(
                "PREFERENCE_DEFINITION_CONFLICT",
                format!("A definition for {slug} already exists"),
            )
            .at(&slug));
        }
        let stamp = now();
        let definition = Definition {
            id: uuid::Uuid::new_v4().to_string(),
            slug: slug.clone(),
            display_name: display_name.clone(),
            description: description.clone(),
            value_type,
            scope,
            options: options.clone(),
            is_sensitive: sensitive,
            created_at: stamp.clone(),
            updated_at: stamp,
            archived_at: None,
            client: Some(client.clone()),
        };
        let wire = definition.wire();
        catalog.definitions.push(definition.clone());
        Ok(Applied {
            changed: true,
            code: None,
            target: slug.clone(),
            preference: None,
            definition: Some(wire),
            defined: Some(Defined {
                catalog_id: String::new(),
                definition,
            }),
        })
    })
    .await
}

fn unsupported_scope_refusal(target: &str) -> Refusal {
    Refusal::new(
        "UNSUPPORTED_SCOPE",
        "LOCATION scope is not supported; this endpoint serves GLOBAL preferences only",
    )
    .at(target)
}

/// Resolve the definition an UPDATE/ARCHIVE names: by id (any state) or by
/// slug (active first). Returns the index into the catalog.
fn find_definition(
    catalog: &Catalog,
    input: &Map<String, Value>,
) -> std::result::Result<usize, Refusal> {
    let id = optional_field_str(input, "id", "definition")?;
    let slug = optional_field_str(input, "slug", "definition")?;
    let index = match (id, slug) {
        (Some(id), _) => catalog.definitions.iter().position(|d| d.id == id),
        (None, Some(slug)) => catalog
            .definitions
            .iter()
            .position(|d| d.slug == slug && d.is_active())
            .or_else(|| catalog.definitions.iter().position(|d| d.slug == slug)),
        (None, None) => {
            return Err(Refusal::input(
                "definition.id or definition.slug is required",
            ))
        }
    };
    let Some(index) = index else {
        return Err(Refusal::new(
            "PREFERENCE_DEFINITION_NOT_FOUND",
            "Definition not found",
        ));
    };
    let definition = &catalog.definitions[index];
    if !definition.is_active() {
        return Err(
            Refusal::new("PREFERENCE_DEFINITION_ARCHIVED", "Definition is archived")
                .at(&definition.slug),
        );
    }
    Ok(index)
}

async fn update_definition(store: &Store<'_>, arguments: &Value) -> Outcome {
    let input = match object_field(arguments, "definition") {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // Everything stored under the definition, the pending suggestions
    // included, must still satisfy the revised definition. A suggestion that
    // stopped fitting would be accepted later into a value HCP cannot show, so
    // the change is refused rather than silently rejecting someone's proposals;
    // the message tells the caller how to clear them.
    let current = store
        .load_catalog()
        .await?
        .map(|record| record.catalog)
        .unwrap_or_else(Catalog::empty);
    let mut stored: Vec<(&'static str, Value)> = Vec::new();
    if let Ok(index) = find_definition(&current, input) {
        let definition_id = current.definitions[index].id.clone();
        if let Some(value) = store
            .find_preference(&definition_id)
            .await?
            .and_then(|record| record.value())
        {
            stored.push(("The stored value", value));
        }
        for suggestion in store
            .open_suggestions_for_definition(&definition_id)
            .await?
        {
            if let Some(value) = suggestion.value() {
                stored.push(("A pending suggestion", value));
            }
        }
    }
    let expected = match expected_revision(input, "definition") {
        Ok(expected) => expected,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let client = store.client.clone();
    edit_catalog(store, "update definition", |catalog| {
        let index = find_definition(catalog, input)?;
        let existing = catalog.definitions[index].clone();
        let target = existing.slug.clone();
        // A sensitive definition is refused before anything about it, its
        // revision included, can be learned.
        if existing.is_sensitive && !ALLOW_SENSITIVE {
            return Err(Refusal::denied_sensitive(&target));
        }
        if let Some(current) = stale(expected.as_deref(), || definition_revision(&existing)) {
            return Err(Refusal::stale(&target, current));
        }
        if let Some(slug) = optional_field_str(input, "slug", "definition")? {
            if slug != existing.slug {
                return Err(Refusal::input("Renaming a slug is not supported").at(&target));
            }
        }
        let mut updated = existing;
        if let Some(name) = optional_field_str(input, "displayName", "definition")? {
            updated.display_name = Some(name.to_string());
        }
        if let Some(text) = optional_field_str(input, "description", "definition")? {
            if text.trim().is_empty() {
                return Err(Refusal::input("definition.description must not be blank").at(&target));
            }
            updated.description = text.to_string();
        }
        if let Some(raw) = optional_field_str(input, "valueType", "definition")? {
            updated.value_type = parse_value_type(raw).ok_or_else(|| {
                Refusal::new(
                    "INVALID_PREFERENCE_DEFINITION",
                    "valueType must be STRING, BOOLEAN, ENUM or ARRAY",
                )
                .at(&target)
            })?;
        }
        if let Some(raw) = optional_field_str(input, "scope", "definition")? {
            match parse_scope(raw) {
                Some(Scope::Global) => {}
                Some(Scope::Location) => return Err(unsupported_scope_refusal(&target)),
                None => {
                    return Err(Refusal::new(
                        "INVALID_PREFERENCE_DEFINITION",
                        "scope must be GLOBAL or LOCATION",
                    )
                    .at(&target))
                }
            }
        }
        if input.contains_key("options") {
            updated.options = parse_options(input)?;
        }
        match input.get("isSensitive") {
            None | Some(Value::Null) => {}
            Some(Value::Bool(true)) if !ALLOW_SENSITIVE => {
                return Err(Refusal::denied_sensitive(&target))
            }
            Some(Value::Bool(flag)) => updated.is_sensitive = *flag,
            Some(_) => {
                return Err(Refusal::input("definition.isSensitive must be a boolean").at(&target))
            }
        }
        check_enum_options(updated.value_type, &updated.options).map_err(|r| r.at(&target))?;
        for (what, value) in &stored {
            if validate_value(&updated, value).is_err() {
                let remedy = if *what == "A pending suggestion" {
                    "; withdraw it first with DELETE_PREFERENCE and its id"
                } else {
                    ""
                };
                return Err(Refusal::new(
                    "INVALID_PREFERENCE_DEFINITION",
                    format!("{what} no longer matches the revised definition{remedy}"),
                )
                .at(&target));
            }
        }
        updated.updated_at = now();
        updated.client = Some(client.clone());
        let wire = updated.wire();
        catalog.definitions[index] = updated.clone();
        Ok(Applied {
            changed: true,
            code: None,
            target,
            preference: None,
            definition: Some(wire),
            defined: Some(Defined {
                catalog_id: String::new(),
                definition: updated,
            }),
        })
    })
    .await
}

async fn archive_definition(store: &Store<'_>, arguments: &Value) -> Outcome {
    let input = match object_field(arguments, "definition") {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let expected = match expected_revision(input, "definition") {
        Ok(expected) => expected,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let client = store.client.clone();
    edit_catalog(store, "archive definition", |catalog| {
        let index = find_definition(catalog, input)?;
        let target = catalog.definitions[index].slug.clone();
        if catalog.definitions[index].is_sensitive && !ALLOW_SENSITIVE {
            return Err(Refusal::denied_sensitive(&target));
        }
        if let Some(current) = stale(expected.as_deref(), || {
            definition_revision(&catalog.definitions[index])
        }) {
            return Err(Refusal::stale(&target, current));
        }
        let stamp = now();
        catalog.definitions[index].archived_at = Some(stamp.clone());
        catalog.definitions[index].updated_at = stamp;
        catalog.definitions[index].client = Some(client.clone());
        Ok(Applied {
            changed: true,
            code: None,
            target,
            preference: None,
            definition: Some(catalog.definitions[index].wire()),
            defined: Some(Defined {
                catalog_id: String::new(),
                definition: catalog.definitions[index].clone(),
            }),
        })
    })
    .await
}

/// Decode and check the `preference` object shared by SET and SUGGEST.
struct PreferenceInput {
    slug: String,
    value: Value,
    value_json: String,
    provenance: Provenance,
    /// The revision the client last read; checked when present.
    expected_revision: Option<String>,
}

fn parse_preference(
    arguments: &Value,
    confidence_required: bool,
) -> std::result::Result<PreferenceInput, Refusal> {
    let input = object_field(arguments, "preference")?;
    let slug = required_str(input, "slug", "preference")?.to_string();
    let raw = required_str(input, "value", "preference")?;
    let value: Value = serde_json::from_str(raw)
        .map_err(|_| Refusal::input("preference.value must be a JSON-encoded string").at(&slug))?;
    let confidence = match input.get("confidence") {
        None | Some(Value::Null) if confidence_required => {
            return Err(Refusal::input("preference.confidence is required").at(&slug))
        }
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => match n.as_f64() {
            Some(c) if (0.0..=1.0).contains(&c) => Some(c),
            _ => {
                return Err(
                    Refusal::input("preference.confidence must be between 0 and 1").at(&slug),
                )
            }
        },
        Some(_) => return Err(Refusal::input("preference.confidence must be a number").at(&slug)),
    };
    let evidence = match input.get("evidence") {
        None => None,
        Some(evidence @ Value::Object(_)) => {
            if evidence.to_string().len() > MAX_EVIDENCE_BYTES {
                return Err(Refusal::input("preference.evidence is too large").at(&slug));
            }
            Some(evidence.clone())
        }
        Some(_) => {
            return Err(Refusal::input(
                "preference.evidence must be a structured object, not an array, null or JSON-encoded string",
            )
            .at(&slug))
        }
    };
    if input.contains_key("locationId") && !input["locationId"].is_null() {
        return Err(unsupported_scope_refusal(&slug));
    }
    let expected_revision = expected_revision(input, "preference").map_err(|r| r.at(&slug))?;
    let value_json = serde_json::to_string(&value).expect("a parsed value serializes");
    Ok(PreferenceInput {
        slug,
        value,
        value_json,
        provenance: Provenance {
            confidence,
            evidence,
        },
        expected_revision,
    })
}

/// Run `attempt`, repeating it from a fresh read when it reports a conflict
/// (the record changed between our read and our guarded write).
async fn retried<T, F, Fut>(mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    for tries in 1..=CATALOG_RETRIES {
        match attempt().await {
            Err(Error::Conflict(_)) if tries < CATALOG_RETRIES => continue,
            other => return other,
        }
    }
    unreachable!("the last attempt always returns")
}

/// The one preference record for this definition: found by key (never by
/// scanning), revived if the person archived it in Native, or created empty.
async fn ensure_record(
    store: &Store<'_>,
    definition: &Definition,
    what: &str,
) -> Result<PrefRecord> {
    if let Some(record) = store.find_preference(&definition.id).await? {
        if record.archived {
            store.archive(&record.id, false, what).await?;
        }
        return Ok(PrefRecord {
            archived: false,
            ..record
        });
    }
    let id = store
        .create_preference(definition, "", &Provenance::default(), what)
        .await?;
    store
        .find_preference_by_id(&id)
        .await?
        .ok_or_else(|| Error::engine("the new preference record is not readable"))
}

async fn write_preference(store: &Store<'_>, arguments: &Value, suggest: bool) -> Outcome {
    let input = match parse_preference(arguments, suggest) {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let slug = input.slug.as_str();
    let catalog = store
        .load_catalog()
        .await?
        .map(|record| record.catalog)
        .unwrap_or_else(Catalog::empty);
    let Some(definition) = catalog.active(slug) else {
        return Ok(Err(Refusal::new(
            "UNKNOWN_PREFERENCE_SLUG",
            format!("No active definition for {slug}"),
        )
        .at(slug)));
    };
    if definition.is_sensitive && !ALLOW_SENSITIVE {
        return Ok(Err(Refusal::denied_sensitive(slug)));
    }
    if let Err(message) = validate_value(definition, &input.value) {
        return Ok(Err(
            Refusal::new("INVALID_PREFERENCE_VALUE", message).at(slug)
        ));
    }
    if suggest {
        suggest_value(store, definition, &input).await
    } else {
        set_value(store, definition, &input).await
    }
}

/// Why a SET carrying an `expectedRevision` was not attempted.
enum Unmet {
    /// The record is at another revision.
    Stale(String),
    /// The record is archived: nothing matches it, and it is not restored.
    Archived,
    /// There is no record yet, so there is no guarded write to create it with.
    NoRecord,
}

async fn set_value(store: &Store<'_>, definition: &Definition, input: &PreferenceInput) -> Outcome {
    let what = format!("set {}", definition.slug);
    let expected = input.expected_revision.as_deref();
    // With an expectedRevision the revision is checked against the same read the
    // write is guarded by (`if_body_digest`), so a Native edit that lands in
    // between makes the write conflict, and the retry sees it as stale. An
    // archived record never matches: it is not restored for a request that
    // expects a particular revision. A record that does not exist yet cannot be
    // created under a revision either: creation has no digest guard.
    let written = retried(|| async {
        match store.find_preference(&definition.id).await? {
            Some(record) => {
                if expected.is_some() && record.archived {
                    return Ok(Err(Unmet::Archived));
                }
                if let Some(current) = stale(expected, || body_revision(&record.body)) {
                    return Ok(Err(Unmet::Stale(current)));
                }
                pause("set_checked").await;
                fault("set_before_write")?;
                if record.archived {
                    store.archive(&record.id, false, &what).await?;
                }
                store
                    .revise_preference(
                        &record,
                        definition,
                        &input.value_json,
                        &input.provenance,
                        &what,
                    )
                    .await?;
                Ok(Ok(record.id))
            }
            None => {
                // Creating the record has no digest guard to ride on.
                if expected.is_some() {
                    return Ok(Err(Unmet::NoRecord));
                }
                Ok(Ok(store
                    .create_preference(definition, &input.value_json, &input.provenance, &what)
                    .await?))
            }
        }
    })
    .await?;
    fault("set_written")?;
    let id = match written {
        Ok(id) => id,
        Err(Unmet::Stale(current)) => {
            return Ok(Err(Refusal::stale(&definition.slug, current)));
        }
        Err(Unmet::Archived) => return Ok(Err(Refusal::stale_archived(&definition.slug))),
        Err(Unmet::NoRecord) => {
            return Ok(Err(Refusal::unsupported_expected_revision(
                &definition.slug,
                "the first SET_PREFERENCE of a value (no record exists yet)",
            )));
        }
    };
    let preference = match store.find_preference_by_id(&id).await? {
        Some(record) => active_wires(store, vec![(record, definition)]).await?.pop(),
        None => None,
    };
    Ok(Ok(Applied {
        changed: true,
        code: None,
        target: definition.slug.clone(),
        preference,
        definition: None,
        defined: None,
    }))
}

async fn suggest_value(
    store: &Store<'_>,
    definition: &Definition,
    input: &PreferenceInput,
) -> Outcome {
    let slug = definition.slug.as_str();
    // `create_record` has no digest guard, so a suggestion cannot be made
    // atomically against a revision. Refuse before anything is attempted.
    if input.expected_revision.is_some() {
        return Ok(Err(Refusal::unsupported_expected_revision(
            slug,
            "SUGGEST_PREFERENCE",
        )));
    }
    // ContextRouter's rule (suggestPreference, at 0439d8f): a REJECTED row for
    // this person and definition suppresses every later suggestion, whatever
    // its value. A suggestion Native rejected is that row here.
    if store.has_rejected_suggestion(&definition.id).await? {
        return Ok(suppressed(store, slug));
    }
    // Decide whether there is anything to suggest from a read, before anything
    // is restored or created: a value that is already stored, or already
    // proposed, suppresses the suggestion, and a suppressed suggestion changes
    // nothing (it must not un-archive the record on its way to finding that out).
    if let Some(record) = store.find_preference(&definition.id).await? {
        if record.value().as_ref() == Some(&input.value) {
            return Ok(suppressed(store, slug));
        }
        if store
            .open_suggestions_for_target_any(&record.id)
            .await?
            .iter()
            .any(|suggestion| suggestion.value().as_ref() == Some(&input.value))
        {
            return Ok(suppressed(store, slug));
        }
    }
    pause("suggest_prechecked").await;
    let what = format!("suggest {slug}");
    let suggestion_id = retried(|| async {
        let record = ensure_record(store, definition, &what).await?;
        // Nothing to propose when the value is already active or already
        // pending.
        if record.value().as_ref() == Some(&input.value) {
            return Ok(None);
        }
        let pending = store.open_suggestions_for_target(&record.id).await?;
        if pending
            .iter()
            .any(|suggestion| suggestion.value().as_ref() == Some(&input.value))
        {
            return Ok(None);
        }
        // Only a proposal HCP authored is replaced; a suggestion made in
        // Native keeps its own text and preconditions.
        match pending
            .into_iter()
            .find(|suggestion| suggestion.hcp_authored)
        {
            Some(existing) => Ok(Some(
                store
                    .revise_suggestion(
                        &existing,
                        &record,
                        &input.value_json,
                        &input.provenance,
                        &what,
                    )
                    .await?,
            )),
            None => Ok(Some(
                store
                    .create_suggestion(&record, &input.value_json, &input.provenance, &what)
                    .await?,
            )),
        }
    })
    .await?;
    let Some(suggestion_id) = suggestion_id else {
        return Ok(suppressed(store, slug));
    };
    let preference = match store.find_suggestion_by_id(&suggestion_id).await? {
        Some(suggestion) => suggested_wires(store, vec![(&suggestion, definition)])
            .await?
            .pop(),
        None => None,
    };
    Ok(Ok(Applied {
        changed: true,
        code: None,
        target: slug.to_string(),
        preference,
        definition: None,
        defined: None,
    }))
}

/// A suggestion that is suppressed because there is nothing to propose.
///
/// `changed` is what this request actually did, read from the write tracker, not
/// assumed: a request that restored an archived record on its way to finding
/// nothing to propose has changed that record, so it must not say `false`.
/// Before any write it is `false`. After a write that is known to have
/// committed it is `true` (with the suppression code, which is still the
/// reason no suggestion was made). If a write was issued and its outcome is
/// not known, the answer is the uncertain refusal.
fn suppressed(store: &Store<'_>, slug: &str) -> Decided {
    if store.write_in_flight() {
        return Err(Refusal::uncertain(Some(slug)));
    }
    Ok(Applied {
        changed: store.writes_committed(),
        code: Some("SUGGESTION_SUPPRESSED"),
        target: slug.to_string(),
        preference: None,
        definition: None,
        defined: None,
    })
}

async fn delete_preference(store: &Store<'_>, arguments: &Value) -> Outcome {
    let input = match object_field(arguments, "preference") {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let id = match required_str(input, "id", "preference") {
        Ok(id) => id.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let expected = match expected_revision(input, "preference") {
        Ok(expected) => expected,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // Resolve the slug from the id server-side before authorizing anything:
    // the caller never names the target. Both lookups are by id.
    let active = store
        .find_preference_by_id(&id)
        .await?
        .filter(PrefRecord::has_value);
    let suggestion = match &active {
        Some(_) => None,
        None => store.find_suggestion_by_id(&id).await?,
    };
    let (slug, definition_id) = match (&active, &suggestion) {
        (Some(record), _) => (record.slug.clone(), record.definition_id.clone()),
        (None, Some(suggestion)) => (suggestion.slug.clone(), suggestion.definition_id.clone()),
        (None, None) => {
            return Ok(Err(Refusal::new(
                "PREFERENCE_NOT_FOUND",
                "Preference not found",
            )))
        }
    };
    let catalog = store
        .load_catalog()
        .await?
        .map(|record| record.catalog)
        .unwrap_or_else(Catalog::empty);
    let definition = catalog
        .definitions
        .iter()
        .find(|d| d.slug == slug && d.id == definition_id && d.is_active());
    if definition.is_some_and(|d| d.is_sensitive) && !ALLOW_SENSITIVE {
        return Ok(Err(Refusal::denied_sensitive(&slug)));
    }
    let Some(definition) = definition else {
        return Ok(Err(Refusal::new(
            "PREFERENCE_NOT_FOUND",
            "Preference not found",
        )
        .at(&slug)));
    };

    let what = format!("delete {slug}");
    let removed = match (&active, &suggestion) {
        (Some(record), _) => {
            let described = active_wires(store, vec![(record.clone(), definition)])
                .await?
                .pop();
            // Clear the value but keep the record, so suggestions waiting on
            // it stay attached (and re-anchored to the now-empty body). The
            // revision is checked against the read the clear is guarded by.
            let cleared = retried(|| async {
                let fresh = store.find_preference_by_id(&record.id).await?;
                let body = fresh.as_ref().map_or("", |fresh| fresh.body.as_str());
                if let Some(current) = stale(expected.as_deref(), || body_revision(body)) {
                    return Ok(Err(current));
                }
                pause("delete_checked").await;
                let Some(fresh) = fresh.filter(PrefRecord::has_value) else {
                    return Ok(Ok(()));
                };
                store
                    .revise_preference(&fresh, definition, "", &Provenance::default(), &what)
                    .await?;
                for pending in store.open_suggestions_for_target(&fresh.id).await? {
                    store.reanchor_suggestion(&pending, "", &what).await?;
                }
                Ok(Ok(()))
            })
            .await?;
            if let Err(current) = cleared {
                return Ok(Err(Refusal::stale(&slug, current)));
            }
            described
        }
        (None, Some(suggestion)) => {
            // Withdrawing is an archive, which has no digest guard: an
            // expected revision cannot be enforced, so nothing is attempted.
            if expected.is_some() {
                return Ok(Err(Refusal::unsupported_expected_revision(
                    &slug,
                    "DELETE_PREFERENCE on a suggestion",
                )));
            }
            let described = suggested_wires(store, vec![(suggestion, definition)])
                .await?
                .pop();
            store.withdraw_suggestion(suggestion, &what).await?;
            described
        }
        (None, None) => unreachable!("resolved above"),
    };
    Ok(Ok(Applied {
        changed: true,
        code: None,
        target: slug,
        preference: removed,
        definition: None,
        defined: None,
    }))
}

#[cfg(test)]
mod acceptance_tests;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod extension_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod provenance_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod smart_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_tests;
