// Frozen from origin/main 9169f3ec8, before the minted-ID pilot.
//! Engine-specific contracts for the implemented v2 argument surface.
use crate::mcp::kernel_v2::*;

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    for (name, allowed, description) in [
        ("attach_text", &["id", "ids", "record_id", "text", "filename", "mime", "name", "lifecycle", "facets", "idempotency_key"][..],
            "Store UTF-8 text as an attachment on v2. Owner, persistence and maturity overrides are unavailable."),
        ("attach_from_url", &["record_id", "url", "filename", "name", "lifecycle", "facets", "max_bytes", "idempotency_key"][..],
            "Fetch a URL under the production SSRF guard (http/https only, public addresses only, pinned DNS, per-hop redirect revalidation, streamed size cap) and store the bytes as an attachment on v2. Owner, persistence and maturity overrides are unavailable. A keyed retry replays without fetching; keyed receipts omit final_url and redirects."),
        ("update_record", &["id", "record_id", "home_id", "name", "summary", "lifecycle", "persistence", "maturity", "body", "body_set", "body_append", "body_replace", "if_body_digest", "if_unmodified_since", "if_policy_revision", "facets", "links", "sources", "reason", "response_mode", "idempotency_key"][..],
            "Update one v2 record with guarded body, field, metadata, facet and link changes. Whole-body replacement requires a revision guard. Declared sources are validated with current View and body revision on the write transaction and retained on the first authoring event; updates without such an event report not_recorded. Owner/type changes and bulk updates are unavailable. response_mode is full."),
    ] {
        let source = &registry.get(name).expect("registered source").input_schema;
        // update_record's source contract has a singular and a bulk branch.
        // V2 implements only the singular branch; its properties live in allOf.
        let mut schema = if name == "update_record" { source["oneOf"][0].clone() } else { source.clone() };
        let properties = if name == "update_record" { &mut schema["allOf"][0]["properties"] } else { &mut schema["properties"] };
        properties.as_object_mut().expect("source properties").retain(|key, _| allowed.contains(&key.as_str()));
        if name == "update_record" {
            properties["response_mode"] = json!({"type":"string","enum":["full"]});
        }
        schema["description"] = json!(description);
        registry.set_kernel_v2_schema(name, schema)?;
    }
    let mut schema = registry
        .get("batch_write")
        .expect("registered source")
        .input_schema
        .clone();
    schema["properties"]
        .as_object_mut()
        .unwrap()
        .remove("sources");
    schema["properties"]["items"]["items"] = json!({"oneOf":[
        {"type":"object","properties":{"op":{"const":"update"},"id":{"type":"string"},"if_unmodified_since":{"type":"string"},"if_policy_revision":{"type":"string","minLength":1}},"required":["op","id"],"anyOf":[{"required":["if_unmodified_since"]},{"required":["if_policy_revision"]}],"additionalProperties":false},
        {"type":"object","properties":{"op":{"const":"archive"},"id":{"type":"string"},"archived":{"type":"boolean"}},"required":["op","id"],"additionalProperties":false}
    ]});
    schema["description"] = json!("Atomic v2 batch of up to 25 guard-only updates and archive/reopen transitions. Field/facet updates and link additions are unavailable. Each target authorizes before any mutation; a failing item refuses the entire batch. An adjacent guard then archive may share an id. Reuse the same idempotency key and identical arguments after an ambiguous failure.");
    registry.set_kernel_v2_schema("batch_write", schema)?;
    let mut schema = registry
        .get("create_many")
        .expect("registered source")
        .input_schema
        .clone();
    schema["properties"]["records"]["items"]["properties"]
        .as_object_mut()
        .expect("create_many item properties")
        .retain(|key, _| {
            [
                "ref",
                "parent_ref",
                "type",
                "kind",
                "name",
                "body",
                "home_id",
                "summary",
                "lifecycle",
                "persistence",
                "maturity",
                "sources",
                "facets",
                "confirm",
                "links",
                "target",
            ]
            .contains(&key.as_str())
        });
    schema["description"] = json!("Create up to 25 records as one v2 dependency graph. Local refs support parent_ref, links[].target_ref and [[ref]] body mentions; the graph is cycle-checked before writes and items are created in stable topological order. V2 mints every record id: omit id and owner_id. Failures block only dependants; receipts keep input positions with null ids for failures. response_mode=verbose returns created shapes. With idempotency_key, retry with identical arguments: created items replay, failed ones resume; changed arguments are refused before new writes.");
    registry.set_kernel_v2_schema("create_many", schema)
}
