//! Experimental source contract for preview-only `sql_write` (E4 M1).
//!
//! Live runtimes register this source ToolSpec only when the deployment
//! allowlisted its executor (`NATIVE_CE_EXPERIMENTAL_EXECUTORS=sql_write`);
//! the direct handler unconditionally refuses, so every direct call fails
//! closed without touching the database. Preview is plan-required. The schema
//! mirrors `SqlWritePreviewArgs` (`executor_prototype/write_operations.rs`):
//! one portable read SELECT yielding typed operation rows over at most 25
//! caller-visible records (at most one `set_field` per `name`/`summary`, at
//! most one string-valued `set_facet` or SQL NULL `unset_facet` per open facet
//! key, a single whole-record `archive` with SQL NULL `key`/`value`, or a
//! directed `add_link` or `remove_link` over `relates_to`), tagged positional
//! parameters, a caller-visible reason, and an optional expected content
//! sequence. `set_facet` is a current assertion matching `update_record.facets`,
//! never an observation-only write; `unset_facet` matches an explicit null
//! there (absent facet has `changed:false` projected state); `archive` matches
//! `archive_record` and requires Manage.
//!
//! `add_link` previews the directed `legacy_link.v1` compatibility proposition
//! that `manage_links.add` builds for a relationship-owned `relates_to`: Edit
//! source plus View target, no content/Message `link.added` fallback, and a
//! re-add that appends support rather than a no-op. Its optional top-level
//! `link_note` is effective only when the preview would create the proposition
//! and is ignored when it would append support. `remove_link` contests that
//! same directed proposition as `manage_links.remove` does — Edit source plus
//! View target, no content-owned `link.removed` fallback, no note — and
//! refuses absent or inactive propositions rather than previewing a no-op.
//! Like every op here it is preview only: execution revalidates and never
//! commits.

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::{Error, Result};

use super::super::{Caller, CustomInteractionPolicy, ToolExposure, ToolRegistry};

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
        "properties": {
            "type": { "const": tag },
            "value": value_schema
        }
    })
}

/// Source schema mirroring `SqlWritePreviewArgs`. `additionalProperties:
/// false` throughout is the schema form of `deny_unknown_fields`.
fn input_schema() -> Value {
    let mut schema = json!({
       "type": "object",
       "properties": {
           "statement": {
               "type": "string",
               "minLength": 1,
               "maxLength": 65536,
               "description": "Portable SELECT of visible (record_id,op,key,value): set_field name|summary; open-key set_facet/unset_facet (NULL); archive (NULL key/value, Manage); directed add/remove_link relates_to (target id, no note on remove). Max 25 records/50 rows. Invalid shapes, duplicates, reserved facets, and archive/link mixing refuse. Preview only."
           },
           "parameters": {
               "type": "array",
               "maxItems": 256,

               "items": {
                   "type":"object","required":["type","value"],"additionalProperties":false,
                   "properties":{"type":{},"value":{}},
                   "oneOf": [
                       parameter_schema("boolean", json!({ "type": ["boolean", "null"] })),
                       parameter_schema("integer", json!({ "type": ["string", "null"], "pattern": "^-?[0-9]+$" })),
                       parameter_schema("real", json!({ "type": ["number", "null"] })),
                       parameter_schema("text", json!({ "type": ["string", "null"] })),
                       parameter_schema("bytes", json!({ "type": ["string", "null"], "contentEncoding": "base64" })),
                       parameter_schema("json", json!({ "type": ["string", "null"] })),
                       parameter_schema("timestamp", json!({ "type": ["string", "null"], "format": "date-time" }))
                   ]
               }
           },
           "reason": { "type": "string", "minLength": 1, "maxLength": 1024 },
           "expected_version": { "type": ["integer", "null"], "minimum": 1 },
           "link_note": { "type": ["string", "null"] }
       },
       "required": ["statement", "reason"],
       "additionalProperties": false
    });
    schema["properties"]["selection_contract"] = json!({"const":"native.sql-write-selection.v1"});
    schema["properties"]["folder_id"] = json!({"type":"string","minLength":1});
    schema["properties"]["write"] = json!({"oneOf":[
        {"type":"object","properties":{"op":{"const":"set_facet"},"key":{"type":"string","minLength":1,"maxLength":120},"value":{"type":"string","maxLength":1024}},"required":["op","key","value"],"additionalProperties":false},
        {"type":"object","properties":{"op":{"const":"add_link"},"target_id":{"type":"string","minLength":1}},"required":["op","target_id"],"additionalProperties":false},
        {"type":"object","properties":{"op":{"const":"archive"}},"required":["op"],"additionalProperties":false}
    ]});
    schema["properties"]["write"]["type"] = json!("object");
    for branch in schema["properties"]["write"]["oneOf"]
        .as_array_mut()
        .unwrap()
    {
        branch.as_object_mut().unwrap().remove("type");
    }
    // Root constraints remain conjunctive with each arm. Do not repeat the
    // inherited minimum or object type; false schemas forbid wire presence.
    schema["oneOf"] = json!([
        {"not":{"required":["selection_contract"]},"properties":{"folder_id":false,"write":false}},
        {"required":["selection_contract","folder_id","write"],"properties":{"link_note":false,"expected_version":{"type":"integer"},"parameters":{"items":{"properties":{"type":{"enum":["text","boolean"]},"value":{"maxLength":1024}}}}}}
    ]);
    schema["properties"]["statement"]
        .as_object_mut()
        .unwrap()
        .remove("description");
    schema
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
        "Preview only; never commits. selection_contract=native.sql-write-selection.v1, folder_id, write. SELECT id FROM children WHERE current_facet('k')='v'. Legacy rows retained.",
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
        for field in [
            "statement",
            "parameters",
            "reason",
            "expected_version",
            "link_note",
        ] {
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
        // The optional directed note is a nullable string, mirroring the serde
        // `Option<String>` that treats an explicit null as absent. The
        // authoritative non-blank/1024 bound lives in the preparer rather than
        // the disclosed schema, which keeps the Complete descriptor inside its
        // byte budget.
        assert_eq!(
            schema["properties"]["link_note"]["type"],
            json!(["string", "null"])
        );
    }

    #[test]
    fn compact_descriptor_keeps_legacy_and_closed_selected_wire_validation() {
        let validator = jsonschema::validator_for(&input_schema()).unwrap();
        let base =
            json!({"statement":"SELECT id FROM children","reason":"Review scoped selection."});
        assert!(validator.is_valid(&base));
        let mut selected = base.clone();
        selected["selection_contract"] = json!("native.sql-write-selection.v1");
        selected["folder_id"] = json!("native:scope");
        selected["write"] = json!({"op":"archive"});
        for tag in ["text", "boolean"] {
            selected["parameters"] = json!([{"type":tag,"value":null}]);
            assert!(validator.is_valid(&selected));
        }
        for tag in ["integer", "real", "bytes", "json", "timestamp"] {
            selected["parameters"] = json!([{"type":tag,"value":null}]);
            assert!(!validator.is_valid(&selected));
            let mut legacy = base.clone();
            legacy["parameters"] = selected["parameters"].clone();
            assert!(validator.is_valid(&legacy));
        }
        selected.as_object_mut().unwrap().remove("parameters");
        for (key, value) in [
            ("write", json!({"op":"archive","key":"extra"})),
            ("expected_version", Value::Null),
            ("selection_contract", json!("unknown")),
            ("unknown", json!(true)),
        ] {
            let mut invalid = selected.clone();
            invalid[key] = value;
            assert!(!validator.is_valid(&invalid), "{invalid}");
        }
        let mut legacy = base.clone();
        legacy["expected_version"] = Value::Null;
        assert!(validator.is_valid(&legacy));
        let mut undiscriminated = selected;
        undiscriminated
            .as_object_mut()
            .unwrap()
            .remove("selection_contract");
        assert!(!validator.is_valid(&undiscriminated));
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
    #[test]
    fn opt_in_source_ordinary_and_lens_complete_boot_budgets() {
        use crate::mcp::{
            descriptor_projection_bytes, lens_descriptor_projection, validate_lens_profile_budgets,
        };
        let experimental = ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
        let r = runtime_registry(&experimental);
        for profile in ExposureProfile::ALL {
            let ordinary = r.descriptor_projection(profile);
            let lens = lens_descriptor_projection(&r, profile).unwrap();
            println!(
                "sql_write opt-in {}: ordinary={} lens={} limit={}",
                profile.as_str(),
                descriptor_projection_bytes(&ordinary),
                descriptor_projection_bytes(&lens),
                profile.max_descriptor_bytes()
            );
        }
        r.validate_profile_budgets().unwrap();
        validate_lens_profile_budgets(&r).unwrap();
    }
}
