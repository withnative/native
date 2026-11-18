//! Shared publication management source. Hosting activation is separate.
use super::*;

pub(crate) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let mut branches = Vec::new();
    for action in ["inspect", "preview", "publish", "unpublish"] {
        let mut properties = serde_json::json!({
            "action":{"const":action},
            "id":{"type":"string","minLength":1,"maxLength":256}
        });
        let mut required = vec!["action", "id"];
        if action != "inspect" && action != "preview" {
            properties["expected_revision"] = serde_json::json!({"type":"integer","minimum":0});
            properties["expected_publication_version"] =
                serde_json::json!({"type":["integer","null"],"minimum":1});
            properties["operation_key"] =
                serde_json::json!({"type":"string","minLength":1,"maxLength":256});
            properties["reason"] =
                serde_json::json!({"type":"string","minLength":1,"maxLength":512});
            required.extend([
                "expected_revision",
                "expected_publication_version",
                "operation_key",
                "reason",
            ]);
            if action == "unpublish" {
                properties["public_id"] =
                    serde_json::json!({"type":"string","pattern":"^[0-9a-f]{32}$"});
                required.push("public_id");
            }
        }
        branches.push(serde_json::json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}));
    }
    registry.register(super::super::ToolKind::ManagePublication,
        "Publication management; default off (NATIVE_PUBLICATION_MANAGEMENT=1), v2 only; mutations require canonical writer. Copy inspection reports recorded state, not current authority. Current record Manage required, including retries; no owner bypass. App-attributed callers are unsupported, including inspection. The required reason is management-plan and action evidence, not a field in the v1 publication event. Inspect recorded state without eligibility checks; preview returns exact saved content without writing. Publish/unpublish require executor plans. Publishes LIVE saved title/body; images use alt text only. Explicit grant persists rehome and private policy tightening until revoked or lifecycle invalidation. Kernel success does not configure public routing or a usable URL.",
        serde_json::json!({"type":"object","oneOf":branches}),
        |_db,_caller,_args|async {Err::<serde_json::Value,_>(crate::Error::engine("publication_profile_unsupported: publication management requires canonical v2"))})?;
    registry.restrict_engine_operations(
        "manage_publication",
        super::super::registry::EngineKind::Sqlite,
        "action",
        &["inspect", "preview", "publish", "unpublish"],
    )
}
