//! Supported Receipt-backed authoring tools.

use serde_json::{json, Value};

use crate::authoring::{self, SaveAccountInput, MAX_SAVE_ACCOUNT_SOURCES};
use crate::db::Db;
use crate::error::Result;

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, principal, REASON_DESCRIPTION};

const TOOL: &str = "save_account";

async fn save_account(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let input: SaveAccountInput = parse_args(TOOL, arguments)?;
    let saved = authoring::save_account(&db, principal(&caller), caller.actor(), input).await?;
    Ok(serde_json::to_value(saved)?)
}

/// Register the bounded authoring write surface.
pub fn register_authoring_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::SaveAccount,
        "Save the body of an existing ordinary Document kind:note together with its exact declared record-body source basis through one Receipt aggregate. Create the note first with create_record. Every source revision must still be that source's body head at assembly; stale selections fail instead of being replaced. Identical idempotent retries recover the original receipt after later output or source changes, with authorization rechecked. Source declarations record use, not semantic correctness; changed prior sources are carried as unresolved and surfaced, never silently assessed as valid. Executable artifacts, runtime-bound records and semantic Units are unsupported.",
        json!({
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Existing ordinary Document kind:note to save. Returned top-level as record_id."
                },
                "expected_revision_event_id": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Exact current body revision event of record_id. A stale base fails without writing."
                },
                "body": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Complete replacement body for the authored note."
                },
                "sources": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_SAVE_ACCOUNT_SOURCES,
                    "description": "Distinct declared source records with exact current body revisions. This declares use, not correctness.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "record_id": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Source record whose body was used."
                            },
                            "revision_event_id": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Exact source body revision selected by the caller; it must equal the head selected at assembly."
                            },
                            "role": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Task-relative role this source played in the authored text."
                            },
                            "reason": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Why this exact source was used for this authored text."
                            }
                        },
                        "required": ["record_id", "revision_event_id", "role", "reason"],
                        "additionalProperties": false
                    }
                },
                "idempotency_key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                    "description": "Caller-stable key scoped to record_id. Same key and request replays; changed request conflicts."
                },
                "reason": {
                    "type": "string",
                    "minLength": 1,
                    "description": REASON_DESCRIPTION
                }
            },
            "required": [
                "record_id", "expected_revision_event_id", "body", "sources",
                "idempotency_key", "reason"
            ],
            "additionalProperties": false
        }),
        save_account,
    )?;
    Ok(())
}
