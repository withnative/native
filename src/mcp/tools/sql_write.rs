//! Experimental source contract for preview-only `sql_write` (E4 M1).
//!
//! Live runtimes register this source ToolSpec only when the deployment
//! allowlisted its executor (`NATIVE_CE_EXPERIMENTAL_EXECUTORS=sql_write`);
//! the direct handler unconditionally refuses, so every direct call fails
//! closed without touching the database. Preview is plan-required. The schema
//! mirrors `SqlWritePreviewArgs` (`executor_prototype/write_operations.rs`):
//! one portable read SELECT yielding typed `set_field` operation rows over at
//! most 25 caller-visible records (at most one `name` and one `summary` per
//! record), tagged positional parameters, a caller-visible reason, and an
//! optional expected content sequence.

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::{Error, Result};

use super::super::{Caller, CustomInteractionPolicy, ToolExposure, ToolRegistry};
use super::REASON_DESCRIPTION;

/// Registered source tool name; the executor/operation pair reuses it.
pub const TOOL: &str = "sql_write";

/// Stable direct-call refusal. There is no direct execution route: preview is
/// plan-required, so the only truthful direct answer is an explicit error
/// that appends nothing.
pub const DIRECT_REFUSAL: &str = "sql_write has no direct execution path: preview is plan-required and commit is withheld; this refusal appended nothing";

/// One tagged positional parameter, mirroring the `query_sql` value model so
/// the preview envelope binds exactly what the governed read path
/// accepts. `value: null` is a typed SQL NULL.
fn parameter_schema(tag: &str, value_schema: Value) -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": { "const": tag },
            "value": value_schema
        },
        "required": ["type", "value"],
        "additionalProperties": false
    })
}

/// Source schema mirroring `SqlWritePreviewArgs`. `additionalProperties:
/// false` throughout is the schema form of `deny_unknown_fields`.
fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "statement": {
                "type": "string",
                "minLength": 1,
                "maxLength": 65536,
                "description": "One portable read SELECT yielding visible set_field rows (record_id, op, key, value), one per (record, name|summary). At most 25 distinct records and at most one row per (record_id, key); duplicates, overflow, and unknown ops/keys/columns refuse. Never authority for physical writes."
            },
            "parameters": {
                "type": "array",
                "maxItems": 256,
                "description": "Ordered tagged positional parameters (?N) for the selection statement.",
                "items": {
                    "oneOf": [
                        parameter_schema("boolean", json!({ "type": ["boolean", "null"] })),
                        parameter_schema("integer", json!({ "type": ["string", "null"], "pattern": "^-?[0-9]+$" })),
                        parameter_schema("real", json!({ "type": ["number", "null"] })),
                        parameter_schema("text", json!({ "type": ["string", "null"] })),
                        parameter_schema("bytes", json!({ "type": ["string", "null"], "contentEncoding": "base64" })),
                        parameter_schema("json", json!({ "type": ["string", "null"], "description": "Valid JSON text; use the string 'null' for JSON null and an explicit null value for SQL NULL." })),
                        parameter_schema("timestamp", json!({ "type": ["string", "null"], "format": "date-time" }))
                    ]
                }
            },
            "reason": { "type": "string", "minLength": 1, "maxLength": 1024, "description": REASON_DESCRIPTION },
            "expected_version": { "type": ["integer", "null"], "minimum": 1, "description": "Optional expected content sequence pin, valid only when the selection targets exactly one record. A multi-record selection refuses it; multi-record version integrity comes from the signed per-target versions instead." }
        },
        "required": ["statement", "reason"],
        "additionalProperties": false
    })
}

/// Direct handler: unconditional explicit refusal with no mutation. The
/// database handle is never touched; preview flows through the plan path.
async fn execute(_db: Db, _caller: Caller, _arguments: Value) -> Result<Value> {
    Err(Error::engine(DIRECT_REFUSAL))
}

pub fn register_sql_write_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_custom(
        TOOL,
        // No semantic write occurs, so there is nothing to attribute through
        // events or run context.
        CustomInteractionPolicy::NoRecordInteractions,
        // Same discovery posture as the other build-enabled experimental
        // probe: out of the near-full Focused descriptor, visible under
        // Complete only once a deployment allowlists the executor.
        ToolExposure::extension(false),
        "EXPERIMENTAL, preview-only SQL-selected record edit. Direct calls always refuse without mutation; preview is plan-required and the sql_write executor is admitted only under the experimental allowlist. Schema mirrors the preview envelope: one portable read SELECT yielding set_field rows for name or summary over at most 25 visible records, tagged positional parameters, reason, and an optional single-target expected version.",
        input_schema(),
        execute,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::create_database;
    use crate::mcp::register_surface_tools;
    use crate::mcp::{register_allowlisted_experimental_tools, register_builtin_tools};
    use crate::mcp::{ExperimentalExecutors, ExposureProfile, EXPERIMENTAL_SQL_WRITE_EXECUTOR};

    fn runtime_registry(experimental: &ExperimentalExecutors) -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        register_allowlisted_experimental_tools(&mut registry, experimental).unwrap();
        registry
    }

    #[test]
    fn source_schema_mirrors_preview_args() {
        let schema = input_schema();
        let properties = schema["properties"].as_object().expect("schema properties");
        for field in ["statement", "parameters", "reason", "expected_version"] {
            assert!(properties.contains_key(field), "schema is missing {field}");
        }
        assert_eq!(
            schema["required"],
            json!(["statement", "reason"]),
            "required fields must match SqlWritePreviewArgs"
        );
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(
            schema["properties"]["parameters"]["items"]["oneOf"]
                .as_array()
                .expect("parameter variants")
                .len(),
            7,
            "parameter model must mirror the seven query_sql tags"
        );
    }

    #[test]
    fn default_runtime_registry_omits_source_while_opt_in_includes_it() {
        let default = runtime_registry(&ExperimentalExecutors::empty());
        assert!(default.get(TOOL).is_none());
        assert!(
            !default
                .specs_for_profile(ExposureProfile::Complete)
                .any(|candidate| candidate.name == TOOL),
            "default Complete tools/list must omit sql_write"
        );
        let allowlisted = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_SQL_WRITE_EXECUTOR.to_string(),
        ))
        .unwrap();
        let opted = runtime_registry(&allowlisted);
        let spec = opted
            .get(TOOL)
            .expect("allowlisted registry must hold the sql_write source");
        assert!(!spec.description.trim().is_empty());
        assert!(!spec.exposure.shown_in(ExposureProfile::Focused));
        assert!(spec.exposure.shown_in(ExposureProfile::Complete));
        assert!(opted
            .specs_for_profile(ExposureProfile::Complete)
            .any(|candidate| candidate.name == TOOL));
    }

    #[tokio::test]
    async fn direct_handler_always_refuses_without_mutation() {
        let db = create_database(":memory:").await.unwrap();
        let record = crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Refusal probe","body":"hello"}),
        )
        .await
        .unwrap();
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let error = execute(
            db.clone(),
            Caller::local(),
            json!({
                "statement": "SELECT id AS record_id FROM records",
                "reason": "refusal probe",
            }),
        )
        .await
        .expect_err("direct sql_write must refuse");
        assert!(
            error.to_string().contains("no direct execution path"),
            "unexpected refusal: {error}"
        );
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_before, events_after, "refusal must append no event");
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(&record)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(name, "Refusal probe");
    }
}
