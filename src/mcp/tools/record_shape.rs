//! Advisory record-shape preview over one live schema snapshot.

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::Result;
use crate::schema::SPINE_TYPES;

use super::super::{Caller, ToolKind, ToolRegistry};

async fn preview_record_shape(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let mut snapshot = db.write_pool().begin().await?;
    let result = {
        let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut snapshot);
        crate::domain_transaction::execute_preview_record_shape(&mut executor, &caller, arguments)
            .await
    };

    match result {
        Ok(preview) => {
            snapshot.rollback().await?;
            Ok(preview)
        }
        Err(primary) => {
            let _ = snapshot.rollback().await;
            Err(primary)
        }
    }
}

pub fn register_record_shape_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::PreviewRecordShape,
        "Preview the live effective record shape for an optional spine type and kind, and \
         deterministically assess supplied open-facet values. Facet acceptance covers only the \
         facet-specific predicates create_record applies under this snapshot. This remains \
         advisory schema guidance: create_record independently revalidates current state, and no \
         preview token or field is accepted by create_record.",
        json!({
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": SPINE_TYPES,
                    "description": "Optional spine type to preview."
                },
                "kind": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Optional nonblank open subtype. Requires type when supplied."
                },
                "facets": {
                    "type": "object",
                    "maxProperties": 100,
                    "description": "Optional proposed open facets using create_record's scalar, atomic-object, or {value,vocab_ref} grammar. Requires type. Spine requirements are reported informationally through their top-level create_record paths.",
                    "additionalProperties": true
                }
            },
            "dependentRequired": { "facets": ["type"] },
            "additionalProperties": false
        }),
        preview_record_shape,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_shape_focused_and_advisory() {
        let mut registry = ToolRegistry::new();
        register_record_shape_tool(&mut registry).unwrap();
        let tool = registry.get("preview_record_shape").unwrap();
        let schema = &tool.input_schema;

        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["run_key"]));
        assert!(!schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "type" || field == "kind"));
        assert_eq!(schema["properties"]["type"]["enum"], json!(SPINE_TYPES));
        assert_eq!(schema["properties"]["kind"]["minLength"], 1);
        assert_eq!(schema["properties"]["facets"]["maxProperties"], 100);
        assert_eq!(schema["dependentRequired"]["facets"], json!(["type"]));
        assert!(schema["properties"]["kind"]["description"]
            .as_str()
            .unwrap()
            .contains("Requires type"));
        assert!(tool.description.contains("advisory"));
        assert!(tool.description.contains("facet-specific"));
        assert!(tool.description.contains("no preview token"));
    }
}
