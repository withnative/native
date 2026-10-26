//! Tool descriptors: input schemas (HCP v2 §10.3.1-§10.3.5), output schemas
//! for each Core result (§5.2) with the error object as an alternative
//! (§10.4), and descriptions.
//!
//! The input schemas carry the structure §10.3 gives, with descriptions in this
//! module's own words.

use serde_json::{json, Value};

pub const SEARCH_PREFERENCES: &str = "hcp_searchPreferences";
pub const GET_PREFERENCE: &str = "hcp_getPreference";
pub const ADD_PREFERENCE: &str = "hcp_addPreference";
pub const UPDATE_PREFERENCE: &str = "hcp_updatePreference";
pub const DELETE_PREFERENCE: &str = "hcp_deletePreference";

/// The tools, in `tools/list` order (HCP v2 §10.3).
pub const TOOL_NAMES: [&str; 5] = [
    SEARCH_PREFERENCES,
    GET_PREFERENCE,
    ADD_PREFERENCE,
    UPDATE_PREFERENCE,
    DELETE_PREFERENCE,
];

pub(super) fn description(name: &str) -> &'static str {
    match name {
        SEARCH_PREFERENCES => "Search the connected person's context for the few entries relevant to a task, within the categories you name and for a stated purpose. Results are ordered by lexical overlap with the query, capped at maxEntries (default 5, at most 20), never padded, and not paginated. Fields that identify the person's other systems are omitted, and the result reports which.",
        GET_PREFERENCE => "Read one entry of the connected person's context by its identifier, for a stated purpose, optionally at an earlier version. Requires earlier disclosure to this client through search/get or an add/update response. An entry that is absent, hidden or not yours to read all answer the same way.",
        ADD_PREFERENCE => "Record a new preference about the connected person. Say whether the person stated it (user-declared) or you inferred it (model-inferred); an inference needs a confidence and the model that made it. The provider records who submitted it and when; those fields cannot be supplied.",
        UPDATE_PREFERENCE => "Revise an entry. The revision becomes a new version with its own provenance and no confirmations; earlier versions are kept. An entry the person has rejected cannot be revised.",
        DELETE_PREFERENCE => "Mark an entry deleted. It is hidden from clients at once and stays held for the person, who alone can remove it permanently.",
        _ => "",
    }
}

/// Which tools only read.
pub(super) fn is_read_only(name: &str) -> bool {
    matches!(name, SEARCH_PREFERENCES | GET_PREFERENCE)
}

pub(super) fn input_schema(name: &str) -> Value {
    match name {
        SEARCH_PREFERENCES => json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "What the context is needed for, in natural language." },
                "categories": { "type": "array", "items": { "type": "string" }, "description": "Category slugs to search." },
                "purpose": { "type": "string", "description": "Why the context is needed, in plain language. Recorded for the person." },
                "maxEntries": { "type": "integer", "default": 5, "description": "Most entries to return. Default 5; values above 20 are treated as 20." },
                "responseDetail": { "type": "string", "enum": ["full", "minimal"], "default": "full", "description": "minimal returns only id, category, dimension and value for each entry." }
            },
            "required": ["query", "categories", "purpose"]
        }),
        GET_PREFERENCE => json!({
            "type": "object",
            "properties": {
                "entryId": { "type": "string", "description": "The entry's urn:uuid identifier." },
                "purpose": { "type": "string", "description": "Why the entry is needed, in plain language. Recorded for the person." },
                "version": { "type": "integer", "description": "Optional. An earlier version to return instead of the current one." }
            },
            "required": ["entryId", "purpose"]
        }),
        ADD_PREFERENCE => json!({
            "type": "object",
            "properties": {
                "category": { "type": "string", "description": "Category slug." },
                "dimension": { "type": ["string", "null"], "description": "Optional. What the entry is about within its category." },
                "preference": { "type": "string", "description": "The preference, as a natural language statement." },
                "declarationType": { "type": "string", "enum": ["user-declared", "model-inferred"] },
                "confidence": { "type": ["string", "null"], "enum": ["high", "medium", "low", null], "description": "Required for model-inferred; omit or null otherwise." },
                "assertedBy": { "type": "string", "description": "Required for model-inferred: the model that made the inference, with its version." },
                "sourceContext": { "type": "string", "description": "The conversation or document the entry came from." }
            },
            "required": ["category", "preference", "declarationType", "sourceContext"],
            "allOf": [{
                "if": { "properties": { "declarationType": { "const": "model-inferred" } }, "required": ["declarationType"] },
                "then": {
                    "required": ["confidence", "assertedBy"],
                    "properties": { "confidence": { "type": "string", "enum": ["high", "medium", "low"] } }
                },
                "else": { "properties": { "confidence": { "type": "null" } } }
            }]
        }),
        UPDATE_PREFERENCE => json!({
            "type": "object",
            "properties": {
                "entryId": { "type": "string", "description": "The entry's urn:uuid identifier." },
                "updatedPreference": { "type": "string", "description": "The revised preference statement." },
                "reason": { "type": "string", "description": "Why it is being revised. Recorded for the person." },
                "declarationType": { "type": "string", "enum": ["user-declared", "model-inferred"], "description": "Optional. Omitted means unchanged." },
                "confidence": { "type": ["string", "null"], "enum": ["high", "medium", "low", null] },
                "assertedBy": { "type": "string", "description": "Optional. Who asserted the revised statement." },
                "sourceContext": { "type": "string" }
            },
            "required": ["entryId", "updatedPreference", "reason"]
        }),
        DELETE_PREFERENCE => json!({
            "type": "object",
            "properties": {
                "entryId": { "type": "string", "description": "The entry's urn:uuid identifier." },
                "reason": { "type": "string", "description": "Why it is being deleted. Recorded for the person." }
            },
            "required": ["entryId", "reason"]
        }),
        _ => json!({ "type": "object" }),
    }
}

/// A full Tier 1 entry as a Context Client receives it.
fn entry_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "@context": { "type": "array", "items": { "type": "string" } },
            "id": { "type": "string" },
            "type": { "type": "array", "items": { "type": "string" } },
            "credentialType": { "type": "string" },
            "claim": {
                "type": "object",
                "properties": {
                    "issuanceDate": { "type": "string" },
                    "expirationDate": { "type": ["string", "null"] },
                    "subject": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "relationship": { "type": ["string", "null"] },
                            "preference": {}
                        },
                        "required": ["id", "preference"]
                    }
                },
                "required": ["issuanceDate", "subject"]
            },
            "record": {
                "type": "object",
                "properties": {
                    "category": { "type": "string" },
                    "dimension": { "type": ["string", "null"] },
                    "declarationType": { "type": "string" },
                    "confidence": { "type": ["string", "null"] },
                    "status": { "type": "string" },
                    "version": { "type": "integer" },
                    "previousVersion": { "type": ["integer", "null"] },
                    "provenance": { "type": "object" }
                },
                "required": ["category", "declarationType", "status", "version", "provenance"]
            }
        },
        "required": ["id", "type", "credentialType", "claim", "record"]
    })
}

fn minimal_entry_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "record": {
                "type": "object",
                "properties": {
                    "category": { "type": "string" },
                    "dimension": { "type": ["string", "null"] }
                },
                "required": ["category"]
            },
            "value": {}
        },
        "required": ["id", "record", "value"]
    })
}

fn minimization_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "method": { "type": "string" },
            "redactedFields": { "type": "array", "items": { "type": "string" } }
        },
        "required": ["method", "redactedFields"]
    })
}

/// The error object a tool execution error carries (HCP v2 §10.4): a Core
/// error code as `type`, plus the codes this provider adds for conditions Core
/// has no error for.
fn error_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": {
                "type": "string",
                "enum": [
                    "malformed-request", "invalid-token", "scope-denied",
                    "idempotency-conflict", "rate-limited", "unsupported-version",
                    "native:not-configured", "native:deployment-read-only",
                    "native:deployment-draining", "native:internal-error"
                ]
            },
            "detail": { "type": "string" }
        },
        "required": ["type", "detail"]
    })
}

pub(super) fn output_schema(name: &str) -> Value {
    let result = match name {
        SEARCH_PREFERENCES => json!({
            "type": "object",
            "properties": {
                "entries": { "type": "array", "items": { "anyOf": [entry_schema(), minimal_entry_schema()] } },
                "retrievalId": { "type": "string" },
                "minimization": minimization_schema(),
                "categoriesSearched": { "type": "array", "items": { "type": "string" } },
                "timestamp": { "type": "string" }
            },
            "required": ["entries", "retrievalId", "minimization", "categoriesSearched", "timestamp"]
        }),
        GET_PREFERENCE => json!({
            "type": "object",
            "properties": {
                "entry": entry_schema(),
                "retrievalId": { "type": "string" },
                "minimization": minimization_schema(),
                "timestamp": { "type": "string" }
            },
            "required": ["entry", "retrievalId", "minimization", "timestamp"]
        }),
        ADD_PREFERENCE | UPDATE_PREFERENCE => entry_schema(),
        DELETE_PREFERENCE => json!({
            "type": "object",
            "properties": {
                "entryId": { "type": "string" },
                "status": { "type": "string", "enum": ["deleted"] },
                "timestamp": { "type": "string" }
            },
            "required": ["entryId", "status", "timestamp"]
        }),
        _ => json!({ "type": "object" }),
    };
    json!({ "anyOf": [result, error_schema()] })
}

/// MCP descriptors for the five tools: what `tools/list` returns for HCP v2.
pub fn hcp_v2_tool_descriptors() -> Vec<Value> {
    TOOL_NAMES
        .iter()
        .map(|name| {
            let read_only = is_read_only(name);
            let mut annotations = json!({ "readOnlyHint": read_only, "openWorldHint": false });
            if !read_only {
                annotations["destructiveHint"] = json!(*name == DELETE_PREFERENCE);
                annotations["idempotentHint"] = json!(*name == DELETE_PREFERENCE);
            }
            json!({
                "name": name,
                "description": description(name),
                "inputSchema": input_schema(name),
                "outputSchema": output_schema(name),
                "annotations": annotations,
            })
        })
        .collect()
}
