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
        "Named views; hosted v2; default off except proposals. Draft: member + bearer Edit. Publish/unpublish: workspace owner + bearer Edit + executor plan. Activate: closure View. Unpublish broken views. See catalog_view_definitions",
        serde_json::json!({"type":"object","oneOf":branches}),
        |_db,_caller,_args|async {Err::<serde_json::Value,_>(crate::Error::engine("view_profile_unsupported: named view operations require hosted v2"))})?;
    registry.register_operation_schema("manage_named_views", "propose_view", serde_json::json!({
        "type":"object", "description":"No-effect hosted-v2 writer facet proposal. View only. Reuse bootstrap run_key; allocation sentinels refuse. Supply returned definition to record_view_revision, which recomputes it. Producers remain gated; unsupported contexts refuse.",
        "properties":{
            "action":{"const":"propose_view"},
            "id":{"type":"string","minLength":1,"maxLength":128,"description":"Existing bearer; current View required."},
            "record_type":{"type":"string","minLength":1,"maxLength":128},
            "kind":{"type":["string","null"],"minLength":1,"maxLength":128},
            "home":{"type":"string","minLength":1,"maxLength":128,"description":"Logical governing collection, or native:root; anchored-H profile only."},
            "selection":{"oneOf":[
                {"type":"object","properties":{"kind":{"const":"keys"},"keys":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":18,"uniqueItems":true}},"required":["kind","keys"],"additionalProperties":false},
                {"type":"object","properties":{"kind":{"const":"all"}},"required":["kind"],"additionalProperties":false}
            ]},
            "profile":{"enum":["facet-1","facet-global-1"],"description":"Optional closed profile. Omitted keeps facet-1; explicit only, never auto-switched."}
        },"required":["action","id","record_type","home","selection"],"additionalProperties":false
    }))?;
    registry.restrict_engine_operations(
        "manage_named_views",
        super::super::registry::EngineKind::Sqlite,
        "action",
        &[
            "get_view_revision",
            "list_view_revisions",
            "record_view_revision",
            "activate_view",
            "unpublish_view",
            "prepare_named_views",
        ],
    )
}
