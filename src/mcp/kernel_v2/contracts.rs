//! Engine-specific contracts for the implemented v2 argument surface.
use super::*;

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
    if writes::minted_ids_enabled() {
        register_minted_id_contracts(
            registry,
            &["create_record", "attach_text", "attach_from_url"],
        )?;
    }
    let mut schema = registry
        .get("batch_write")
        .expect("registered source")
        .input_schema
        .clone();
    // Reuse ordinary body operation shapes without broadening the legacy batch.
    let update = registry
        .get("update_record")
        .unwrap()
        .input_schema_for_engine(EngineKind::KernelV2);
    for key in ["body_set", "body_append", "body_replace"] {
        schema["properties"]["items"]["items"]["oneOf"][0]["properties"][key] =
            update["allOf"][0]["properties"][key].clone();
    }
    schema["properties"]["items"]["items"]["oneOf"][0]["anyOf"] = json!([
        {"required":["body_set"]}, {"required":["body_append"]}, {"required":["body_replace"]},
        {"required":["name"]}, {"required":["summary"]}, {"required":["maturity"]},
        {"required":["home_id"]}, {"required":["facets"]}, {"required":["if_facets"]},
        {"required":["if_maturity"]}, {"required":["if_home_id"]}, {"required":["if_body_digest"]},
        {"required":["if_unmodified_since"]}, {"required":["if_policy_revision"]}
    ]);
    schema["properties"]["items"]["items"]["oneOf"][0]["allOf"] = json!([
        {"not":{"required":["body_set","body_append"]}},
        {"not":{"required":["body_set","body_replace"]}},
        {"not":{"required":["body_append","body_replace"]}}
    ]);
    schema["description"] = json!("Atomic v2 batch of up to 25 body/field/facet updates (body_set, body_append, body_replace, name, summary, maturity, home_id, facets), link additions and archive/reopen transitions under one reason and idempotency key. Items use flat {op, ...} shapes, with op update, add_link or archive. Update guards may stand alone. Each leaf checks current permissions and guards in the shared transaction; a failing item rolls back the entire batch. An adjacent guard-only update then archive may share an id. Identical keyed retries return the original receipt after current View checks. Shared sources resolve once before item mutations and are retained on each update's first field, metadata, body or facet event. Guard-only, unchanged, link and archive items report not_recorded; relationship-provider provenance is unchanged. Omitted sources mean undeclared; [] declares none. Body replacements retain ordinary per-record guards. Body targets with active or grace coedit sessions refuse the entire batch without flushing; use update_record for routed live edits. Per-item receipts include version and body_digest for changed or unchanged body/field/facet updates. App source publication remains on update_record.");
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

/// One compiled capture profile, independent of today's runtime enablement.
/// Normal registration still selects it only under the existing minted-ID gate.
pub(super) fn register_minted_id_contracts(
    registry: &mut ToolRegistry,
    names: &[&str],
) -> Result<()> {
    for &name in names {
        let source = registry.get(name).expect("registered source");
        let mut schema = source.input_schema_for_engine(EngineKind::KernelV2).clone();
        schema["properties"][if name != "create_record" {
            "attachment_id"
        } else {
            "id"
        }] = json!({"type":"string","description":"Optional locally minted UUIDv8; requires server opt-in and id_nonce."});
        schema["properties"]["id_nonce"] = json!({"type":"string","description":"256-bit mint nonce, unpadded base64url. Context is authenticated by the server."});
        registry.set_kernel_v2_schema(name, schema)?;
    }
    Ok(())
}
