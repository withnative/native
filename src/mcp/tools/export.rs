//! `export_snapshot` — a tool-native door to the verified SQLite eject
//! artifact served by `GET /export`.
//!
//! ## Binary payload decision
//!
//! A database-sized binary does not belong in one JSON tool result. This tool
//! therefore keeps the verified snapshot as an ephemeral, principal-bound
//! export handle and returns bounded base64 pages. Repeating a page read is
//! deterministic because every page comes from the same immutable snapshot;
//! the final page is cached briefly so a lost response can be retried after
//! the snapshot itself and its single-flight lease have been released.
//!
//! The alternatives are deliberately rejected here, next to the contract:
//!
//! - a server path or HTTP URL would make the agent leave the tool surface and
//!   would expose a deployment-local path or require another credentialed
//!   transport step;
//! - storing the snapshot as an attachment would put a database export inside
//!   the live database it exports, causing later snapshots to recursively carry
//!   prior snapshots and permanently grow the blob tier;
//! - one base64 result, with or without a ceiling, either materializes the
//!   whole database several times in server/client memory or stops being an
//!   export capability when a real database crosses the ceiling.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::{
    SnapshotRequest, SnapshotSourceRef, ToolKind, SNAPSHOT_DEFAULT_PAGE_BYTES,
    SNAPSHOT_MAX_PAGE_BYTES,
};

use super::parse_args;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportSnapshotArgs {
    export_id: Option<String>,
    offset: Option<u64>,
    length: Option<usize>,
    standby_consumer: Option<crate::standby_snapshot::StandbyConsumerIdentity>,
}

async fn export_snapshot(
    db: crate::db::Db,
    caller: Caller,
    arguments: Value,
    source: SnapshotSourceRef,
) -> Result<Value> {
    const TOOL: &str = "export_snapshot";
    let args: ExportSnapshotArgs = parse_args(TOOL, arguments)?;
    let length = args.length.unwrap_or(SNAPSHOT_DEFAULT_PAGE_BYTES);
    if length == 0 || length > SNAPSHOT_MAX_PAGE_BYTES {
        return Err(Error::engine(format!(
            "{TOOL}: 'length' must be between 1 and {SNAPSHOT_MAX_PAGE_BYTES}"
        )));
    }
    let offset = match (&args.export_id, args.offset) {
        (None, None | Some(0)) => 0,
        (None, Some(offset)) => {
            return Err(Error::engine(format!(
                "{TOOL}: a new snapshot must start at offset 0, not {offset}"
            )))
        }
        (Some(_), Some(offset)) => offset,
        (Some(_), None) => {
            return Err(Error::engine(
                "export_snapshot: continuing an export_id requires an explicit 'offset'",
            ))
        }
    };
    if args.export_id.is_some() && args.standby_consumer.is_some() {
        return Err(Error::engine(
            "export_snapshot: standby_consumer is valid only when starting a new snapshot",
        ));
    }
    if let Some(consumer) = &args.standby_consumer {
        consumer.validate_declaration().map_err(|error| {
            Error::engine(format!(
                "export_snapshot: invalid standby_consumer: {error}"
            ))
        })?;
    }
    let page = source
        .page(
            db,
            caller,
            SnapshotRequest {
                export_id: args.export_id,
                offset,
                length,
                standby_consumer: args.standby_consumer,
            },
        )
        .await?;
    serde_json::to_value(page).map_err(Into::into)
}

pub fn register_export_tool(registry: &mut ToolRegistry, source: SnapshotSourceRef) -> Result<()> {
    registry.register(
        ToolKind::ExportSnapshot,
        "Owner-only verified SQLite snapshot. Omit export_id to start; continue with its handle and offset until eof. A hosted first call may bind standby_consumer for per-page provenance; other exports omit it.",
        json!({
            "type": "object",
            "properties": {
                "export_id": {
                    "type": "string",
                    "description": "Opaque handle returned by the first page. Omit to create a new consistent snapshot."
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Byte offset in the immutable snapshot. Omit (or use 0) on the first call; required with export_id."
                },
                "length": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": SNAPSHOT_MAX_PAGE_BYTES,
                    "default": SNAPSHOT_DEFAULT_PAGE_BYTES,
                    "description": "Maximum decoded bytes in this page."
                },
                "standby_consumer": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["contract", "version", "platform", "source_sha", "artifact_sha256", "engine_schema_version", "ddl_sha256"],
                    "properties": {
                        "contract": { "const": "native.standby-consumer.v1" },
                        "version": { "const": 1 },
                        "platform": { "enum": ["linux-x86_64"] },
                        "source_sha": { "type": "string" },
                        "artifact_sha256": { "type": "string" },
                        "engine_schema_version": { "type": "integer", "minimum": 1 },
                        "ddl_sha256": { "type": "string" }
                    }
                }
            },
            "additionalProperties": false
        }),
        move |db, caller, arguments| {
            let source = source.clone();
            async move { export_snapshot(db, caller, arguments, source).await }
        },
    )?;
    Ok(())
}
