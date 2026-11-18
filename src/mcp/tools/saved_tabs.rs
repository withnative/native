//! Source contract for caller-scoped saved working slots. Legacy engines refuse.
use crate::mcp::{registry::ToolRegistry, ToolKind};
use crate::{Error, Result};
use serde_json::json;

pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    let mut schema = json!({"type":"object","properties":{
        "action":{"enum":["create","get","list","rename","retire"]},
        "creation_key":{"type":"string","minLength":1,"maxLength":256},
        "app":{"type":"string","minLength":1,"maxLength":256},
        "initial_record_id":{"type":["string","null"]},
        "record_id":{"type":"string","minLength":1},
        "expected_revision":{"type":"string","minLength":1},
        "operation_id":{"type":"string","minLength":1,"maxLength":256},
        "custom_title":{"type":["string","null"],"maxLength":2048},
        "reason":{"type":"string","minLength":1},
        "limit":{"type":"integer","minimum":1,"maximum":100},
        "after":{"type":"string"},"include_retired":{"type":"boolean"}
    },"required":["action"],"additionalProperties":false,"oneOf":[
        {"properties":{"action":{"const":"create"}},"required":["creation_key","app","initial_record_id","reason"]},
        {"properties":{"action":{"const":"get"}},"required":["record_id"]},
        {"properties":{"action":{"const":"list"}}},
        {"properties":{"action":{"const":"rename"}},"required":["record_id","expected_revision","operation_id","custom_title","reason"]},
        {"properties":{"action":{"const":"retire"}},"required":["record_id","expected_revision","operation_id","reason"]}
    ]});
    let all: Vec<String> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    for (branch, allowed) in schema["oneOf"].as_array_mut().unwrap().iter_mut().zip([
        vec![
            "action",
            "creation_key",
            "app",
            "initial_record_id",
            "reason",
        ],
        vec!["action", "record_id"],
        vec!["action", "limit", "after", "include_retired"],
        vec![
            "action",
            "record_id",
            "expected_revision",
            "operation_id",
            "custom_title",
            "reason",
        ],
        vec![
            "action",
            "record_id",
            "expected_revision",
            "operation_id",
            "reason",
        ],
    ]) {
        let forbidden: Vec<_> = all
            .iter()
            .filter(|key| !allowed.contains(&key.as_str()))
            .map(|key| json!({"required":[key]}))
            .collect();
        branch["not"] = json!({"anyOf":forbidden});
    }
    registry.register(ToolKind::ManageSavedTabs,
        "Account-private saved working slots. Create is idempotent per caller creation key; rename/reset and retirement use canonical revisions and operation ids. Retirement is terminal. Requires kernel v2 and the installed/adopted native.saved_tabs/saved_tabs@1 package.",
        schema,
        |_db,_caller,_args| async { Err::<serde_json::Value,_>(Error::engine("manage_saved_tabs: unsupported engine; kernel_v2 required")) }
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::interactions::AuthoritativeDisposition;

    #[test]
    fn saved_tabs_classifies_live_reads_and_refuses_all_offline_authority() {
        assert_eq!(
            ToolKind::ManageSavedTabs.authoritative_disposition(),
            AuthoritativeDisposition::Actions(&["get", "list"])
        );
        assert_eq!(
            ToolKind::ManageSavedTabs.standby_disposition(),
            AuthoritativeDisposition::Mutation
        );
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        registry.set_standby_read_only(true);
        for action in ["create", "get", "list", "rename", "retire"] {
            assert!(registry
                .admit_standby_call("manage_saved_tabs", &json!({"action":action}))
                .unwrap_err()
                .to_string()
                .contains("unavailable_offline"));
        }
    }
}
