//! Built-in tools — registered once, reachable over every transport.
//!
//! These are the seam's own tools, not part of the 31-tool v1 surface: `ping`
//! (liveness), `engine_info` (engine, schema, and storage-profile runtime
//! information for the connected db), and the explicitly registered
//! `standby_status` for an active local standby.
//! They exist so the seam is testable end-to-end before any surface tool
//! lands, and they follow the same rule as everything else: structured data
//! out, no formatting.

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::db::{DatabaseOpenMode, Db};
use crate::error::{Error, Result};
use crate::{ENGINE_NAME, ENGINE_VERSION, GIT_SHA};

use super::registry::{Caller, ToolRegistry};
use super::ToolKind;

/// A JSON Schema accepting an empty argument object.
fn no_arguments_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArguments {}

fn require_no_arguments(arguments: Value) -> Result<()> {
    serde_json::from_value::<NoArguments>(arguments)
        .map(|_| ())
        .map_err(|err| Error::engine(format!("invalid arguments: {err}")))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineInfoArguments {
    #[serde(default)]
    target_profiles: Vec<crate::storage_profile::StorageTarget>,
    #[serde(default)]
    required_capabilities: Option<Vec<String>>,
}

fn engine_info_arguments_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "target_profiles": {
                "type": "array",
                "maxItems": 8,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "revision", "mode"],
                    "properties": {
                        "id": { "type": "string", "pattern": "^[a-z][a-z0-9-]*$" },
                        "revision": { "type": "integer", "minimum": 1 },
                        "mode": { "enum": ["embedded", "network", "sync"] }
                    }
                }
            },
            "required_capabilities": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": true,
                "items": { "type": "string", "minLength": 1 }
            }
        },
        "additionalProperties": false
    })
}

async fn engine_info(db: Db, _caller: Caller, arguments: Value) -> Result<Value> {
    if arguments
        .get("required_capabilities")
        .is_some_and(Value::is_null)
    {
        return Err(Error::engine(
            "invalid arguments: required_capabilities must be an array when present",
        ));
    }
    let arguments = serde_json::from_value::<EngineInfoArguments>(arguments)
        .map_err(|err| Error::engine(format!("invalid arguments: {err}")))?;
    if arguments.required_capabilities.is_some() && arguments.target_profiles.is_empty() {
        return Err(Error::engine(
            "required_capabilities requires at least one target profile",
        ));
    }
    // `PRAGMA user_version` marks the file's engine schema version (decision
    // 7d61dd1); a pre-schema file reads 0.
    let row = sqlx::query("PRAGMA user_version")
        .fetch_one(db.write_pool())
        .await?;
    let schema_version: i64 = row.get(0);
    let standby = db.open_mode() == DatabaseOpenMode::StandbyReadOnly;
    let mut result = json!({
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        // The source revision (task 142e0d2). `engine_version` is `0.0.0` and
        // says nothing; this is the field that answers "what is running?"
        // without access to the deploying platform's console.
        "git_sha": GIT_SHA,
        "schema_version": schema_version,
        "storage_profile": crate::storage_profile::active_profile_report_for_db(&db).await?,
        "query_sql": crate::query::sql_contract::capability(
            crate::query::sql_contract::QuerySqlProfile::SqliteLocal
        ),
    });
    if standby {
        result["runtime"] = json!({
            "mode": "standby",
            "read_only": true,
            "writes_supported": false,
            "canonical_authority": "hosted",
            "mutation_error": super::registry::STANDBY_READ_ONLY_ERROR,
        });
    }
    if !arguments.target_profiles.is_empty() {
        result["portability_audit"] = crate::storage_profile::portability_audit(
            &arguments.target_profiles,
            arguments.required_capabilities.as_deref(),
        )?;
    }
    Ok(result)
}

/// Register the built-in tools. Called once per registry by both transports'
/// entry points (bin / server construction), never per transport.
pub fn register_builtin_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::Ping,
        "Liveness check — returns { ok: true }.",
        no_arguments_schema(),
        |_db, _caller, arguments| async move {
            require_no_arguments(arguments)?;
            Ok(json!({ "ok": true }))
        },
    )?;
    registry.register(
        ToolKind::EngineInfo,
        "Engine, schema, and active storage-profile information; optionally performs a read-only portability audit against exact target profile revisions.",
        engine_info_arguments_schema(),
        engine_info,
    )?;
    Ok(())
}

/// Register the active-serving local standby's machine-readable status read.
///
/// This remains separate from [`register_builtin_tools`]: ordinary writable
/// and hosted registries must not advertise a standby capability they do not
/// possess. The provider owns the runtime and generation evidence used to
/// build a fresh report for every call.
pub fn register_standby_status_tool(
    registry: &mut ToolRegistry,
    provider: crate::standby::StandbyStatusProvider,
) -> Result<()> {
    registry.register(
        ToolKind::StandbyStatus,
        "Current local standby mode, generation provenance, freshness, compatibility, and refresh diagnostics.",
        no_arguments_schema(),
        move |_db, _caller, arguments| {
            let provider = provider.clone();
            async move {
                require_no_arguments(arguments)?;
                Ok(serde_json::to_value(provider.status().await)?)
            }
        },
    )
}
