//! One fixed operation source; definitions and revision metadata are on demand.
use super::*;
pub(crate) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let fields = serde_json::json!({
        "id":{"type":"string"},"view_id":{"type":"string"},"revision_id":{"type":"string"},
        "definition":{"type":"object"},"pin":{"type":"object"},"name":{"type":"string"},
        "expected_binding_event_id":{"type":["string","null"]},
        "idempotency_key":{"type":"string","minLength":1,"maxLength":200},"reason":{"type":"string"},
        "limit":{"type":"integer","minimum":1,"maximum":16,"default":8},"cursor":{"type":"string","maxLength":4096}
    });
    let mut branches = Vec::new();
    for (action, required, optional) in [
        (
            "get_view_revision",
            &["view_id", "revision_id"][..],
            &[][..],
        ),
        (
            "list_view_revisions",
            &["view_id"][..],
            &["limit", "cursor"][..],
        ),
        (
            "record_view_revision",
            &["id", "definition", "idempotency_key"][..],
            &["reason"][..],
        ),
        (
            "activate_view",
            &[
                "id",
                "pin",
                "name",
                "expected_binding_event_id",
                "idempotency_key",
            ][..],
            &["reason"][..],
        ),
        (
            "unpublish_view",
            &["id", "expected_binding_event_id", "idempotency_key"][..],
            &["reason"][..],
        ),
        ("prepare_named_views", &[][..], &[][..]),
    ] {
        let mut properties = serde_json::Map::new();
        properties.insert("action".into(), serde_json::json!({"const":action}));
        for field in required.iter().chain(optional) {
            properties.insert((*field).into(), fields[*field].clone());
        }
        let required: Vec<_> = std::iter::once("action")
            .chain(required.iter().copied())
            .collect();
        branches.push(serde_json::json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}));
    }
    registry.register(super::super::ToolKind::ManageNamedViews,
        "Named views; hosted v2; gated off by default. Draft: member + bearer Edit. Publish/unpublish: workspace owner + bearer Edit + executor plan. Activate: closure View. Unpublish broken views. See catalog_view_definitions",
        serde_json::json!({"type":"object","oneOf":branches}),
        |_db,_caller,_args|async {Err::<serde_json::Value,_>(crate::Error::engine("view_profile_unsupported: named view operations require hosted v2"))})
}
