//! Advisory record-shape preview through the registered SQLite tool surface.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    create_vocabulary, deprecate_value, promote_value, propose_value,
    propose_value_with_kind_metadata_as, write_user_schema_config, KindMetadataV1,
    SchemaConfigOptions, VocabularyValueTerminality,
};
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, args: Value) -> native_ce::Result<Value> {
    call_as(registry, db, Caller::local(), args).await
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(db.clone(), caller, "preview_record_shape", args)
        .await
}

async fn govern_kind(db: &Db, record_type: &str, token: &str) {
    let vocabulary = format!("kind:{record_type}");
    let vocabulary_id = format!("voc:kind:{record_type}");
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vocabularies WHERE id = ?)")
        .bind(&vocabulary_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    if !exists {
        create_vocabulary(db, &vocabulary, Some(&vocabulary_id))
            .await
            .unwrap();
    }
    let resolution = native_ce::meta::kind::resolve(db, record_type, token)
        .await
        .unwrap();
    if !resolution.quarantined {
        return;
    }
    let id = propose_value_with_kind_metadata_as(
        db,
        &vocabulary,
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
}

async fn propose_kind(db: &Db, record_type: &str, token: &str) -> String {
    let vocabulary = format!("kind:{record_type}");
    let vocabulary_id = format!("voc:kind:{record_type}");
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vocabularies WHERE id = ?)")
        .bind(&vocabulary_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    if !exists {
        create_vocabulary(db, &vocabulary, Some(&vocabulary_id))
            .await
            .unwrap();
    }
    propose_value_with_kind_metadata_as(
        db,
        &vocabulary,
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap()
}

async fn authoritative_heads(db: &Db) -> Vec<i64> {
    let mut heads = Vec::new();
    for table in [
        "content_events",
        "meta_events",
        "policy_events",
        "control_events",
        "relationship_events",
        "derivation_events",
    ] {
        let sql = format!("SELECT COALESCE(MAX(seq), 0) FROM {table}");
        heads.push(sqlx::query_scalar(&sql).fetch_one(db.pool()).await.unwrap());
    }
    heads.push(
        sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
    );
    heads
}

async fn govern_value(db: &Db, vocabulary: &str, vocabulary_id: &str, value: &str) {
    create_vocabulary(db, vocabulary, Some(vocabulary_id))
        .await
        .unwrap();
    let value_id = propose_value(db, vocabulary, value, None).await.unwrap();
    promote_value(db, &value_id).await.unwrap();
}

#[tokio::test]
async fn cold_start_preview_is_bounded_catalogue_only_and_write_free() {
    let db = db().await;
    let registry = registry();
    let before = authoritative_heads(&db).await;

    let preview = call(&registry, &db, json!({})).await.unwrap();

    assert_eq!(preview["schema"], "native.record_shape_preview.v1");
    assert_eq!(preview["catalogs"]["types"].as_array().unwrap().len(), 10);
    assert_eq!(
        preview["catalogs"]["relationships"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert!(preview["selection"].is_null());
    assert!(preview.get("proposed_facets").is_none());
    assert_eq!(preview["advisory_only"], true);
    assert_eq!(preview["accepted_by_create_record"], false);
    assert_eq!(preview["zero_authoritative_writes"], true);
    assert!(preview["advisory_basis"]["schema_state_revision"]
        .as_str()
        .unwrap()
        .starts_with("schema-state-v1:meta:"));
    assert_eq!(
        preview["advisory_basis"]["semantic_contract"]["revision"],
        "record-shape-preview-v2-facet-values"
    );
    assert!(preview["not_checked"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry == "proposed_spine_values"));
    assert!(!preview["not_checked"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry == "proposed_record_values"));
    assert!(serde_json::to_vec(&preview).unwrap().len() <= 65_536);
    assert_eq!(authoritative_heads(&db).await, before);
}

#[tokio::test]
async fn selected_kind_reports_live_resolution_and_global_shape() {
    let db = db().await;
    let registry = registry();
    govern_kind(&db, "Resolution", "decision").await;
    write_user_schema_config(
        &db,
        json!({ "shapes": {
            "Resolution:decision": { "facets": {
                "confidence": { "required": true, "values": ["low", "high"] }
            } }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let governed = call(
        &registry,
        &db,
        json!({ "type": "Resolution", "kind": "decision" }),
    )
    .await
    .unwrap();
    assert_eq!(
        governed["selection"]["kind_resolution"]["quarantined"],
        false
    );
    assert_eq!(governed["selection"]["cross_type_matches"], json!([]));
    assert_eq!(governed["selection"]["effective_kind"], "decision");
    assert_eq!(
        governed["selection"]["spine_facets"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        governed["selection"]["effective_facet_shape"]["confidence"]["required"],
        true
    );
    let other_caller = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:unrelated"),
        json!({ "type": "Resolution", "kind": "decision" }),
    )
    .await
    .unwrap();
    assert_eq!(other_caller, governed);

    let mismatch = call(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "decision" }),
    )
    .await
    .unwrap();
    assert_eq!(
        mismatch["selection"]["kind_resolution"]["quarantined"],
        true
    );
    let warning = mismatch["selection"]["kind_resolution"]["warning"]
        .as_str()
        .unwrap();
    assert!(warning.contains("Resolution"), "{warning}");
    assert_eq!(
        mismatch["selection"]["cross_type_matches"][0]["type"],
        "Resolution"
    );
}

#[tokio::test]
async fn cross_type_matches_are_structured_for_proposed_and_deprecated_selected_rows() {
    let db = db().await;
    let registry = registry();

    let proposed_token = "cross-type-proposed-preview";
    propose_kind(&db, "Document", proposed_token).await;
    govern_kind(&db, "WorkItem", proposed_token).await;
    govern_kind(&db, "Resolution", proposed_token).await;

    let proposed = call(
        &registry,
        &db,
        json!({ "type": "Document", "kind": proposed_token }),
    )
    .await
    .unwrap();
    assert_eq!(
        proposed["selection"]["kind_resolution"]["classification"],
        "proposed"
    );
    assert_eq!(
        proposed["selection"]["cross_type_matches"],
        json!([
            {
                "type": "Resolution",
                "matched_token": proposed_token,
                "classification": "active_canonical",
                "canonical_kind": proposed_token,
                "canonical_value_id": format!("vv:voc:kind:Resolution:{proposed_token}"),
                "lifecycle_status": "active",
            },
            {
                "type": "WorkItem",
                "matched_token": proposed_token,
                "classification": "active_canonical",
                "canonical_kind": proposed_token,
                "canonical_value_id": format!("vv:voc:kind:WorkItem:{proposed_token}"),
                "lifecycle_status": "active",
            },
        ])
    );

    let deprecated_token = "cross-type-deprecated-preview";
    let deprecated_id = propose_kind(&db, "Document", deprecated_token).await;
    promote_value(&db, &deprecated_id).await.unwrap();
    deprecate_value(&db, &deprecated_id).await.unwrap();
    govern_kind(&db, "Outcome", deprecated_token).await;

    let deprecated = call(
        &registry,
        &db,
        json!({ "type": "Document", "kind": deprecated_token }),
    )
    .await
    .unwrap();
    assert_eq!(
        deprecated["selection"]["kind_resolution"]["classification"],
        "deprecated_non_alias"
    );
    assert_eq!(
        deprecated["selection"]["cross_type_matches"],
        json!([{
            "type": "Outcome",
            "matched_token": deprecated_token,
            "classification": "active_canonical",
            "canonical_kind": deprecated_token,
            "canonical_value_id": format!("vv:voc:kind:Outcome:{deprecated_token}"),
            "lifecycle_status": "active",
        }])
    );
}

#[tokio::test]
async fn preview_rejects_kind_without_type_and_unknown_arguments() {
    let db = db().await;
    let registry = registry();

    let error = call(&registry, &db, json!({ "kind": "decision" }))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("'kind' requires 'type'"), "{error}");

    let error = call(
        &registry,
        &db,
        json!({ "type": "Document", "name": "not checked" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown field"), "{error}");
}

#[tokio::test]
async fn proposed_facets_require_type_enforce_the_bound_and_reject_malformed_values() {
    let db = db().await;
    let registry = registry();
    let before = authoritative_heads(&db).await;

    let error = call(&registry, &db, json!({ "facets": {} }))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("'facets' requires 'type'"), "{error}");

    let error = call(
        &registry,
        &db,
        json!({ "type": "Document", "facets": null }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("'facets' must be an object"), "{error}");

    let oversized = (0..101)
        .map(|index| (format!("facet-{index:03}"), json!("value")))
        .collect::<serde_json::Map<_, _>>();
    let error = call(
        &registry,
        &db,
        json!({ "type": "Document", "facets": oversized }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("at most 100 entries"), "{error}");

    for malformed in [Value::Null, json!(true), json!(["value"])] {
        let error = call(
            &registry,
            &db,
            json!({ "type": "Document", "facets": { "area": malformed } }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("must be a string, number, object"),
            "{error}"
        );
    }
    assert_eq!(authoritative_heads(&db).await, before);
}

#[tokio::test]
async fn proposed_facets_report_vocabulary_open_carrier_and_required_facts_without_writes() {
    let db = db().await;
    let registry = registry();
    govern_value(&db, "area", "voc:area", "schema").await;
    write_user_schema_config(
        &db,
        json!({ "shapes": { "WorkItem:task": { "facets": {
            "area": { "vocab_ref": "area" },
            "lifecycle": { "required": true }
        } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let before = authoritative_heads(&db).await;

    let preview = call(
        &registry,
        &db,
        json!({
            "type": "WorkItem",
            "kind": "task",
            "facets": {
                "area": "schema",
                "novel": "honest",
                "lifecycle": "open",
                "archived": "true"
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(preview["proposed_facets"]["status"], "rejected");
    let assessments = preview["proposed_facets"]["assessments"]
        .as_array()
        .unwrap();
    let by_key = |key: &str| {
        assessments
            .iter()
            .find(|assessment| assessment["key"] == key)
            .unwrap()
    };
    assert_eq!(by_key("area")["status"], "accepted");
    assert_eq!(by_key("area")["governing_vocabulary"]["id"], "voc:area");
    assert_eq!(
        by_key("area")["value_resolution"]["classification"],
        "active_member"
    );
    assert_eq!(by_key("novel")["status"], "accepted");
    assert_eq!(by_key("novel")["declaration"], "open");
    assert_eq!(
        by_key("lifecycle")["issues"],
        json!(["spine_facet_wrong_carrier"])
    );
    assert_eq!(
        by_key("lifecycle")["create_record_input"]["field"],
        "lifecycle"
    );
    assert_eq!(
        by_key("archived")["issues"],
        json!(["engine_reserved_facet"])
    );
    let lifecycle = preview["proposed_facets"]["required_declarations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|declaration| declaration["key"] == "lifecycle")
        .unwrap();
    assert_eq!(lifecycle["create_record_input"]["field"], "lifecycle");
    assert_eq!(
        lifecycle["candidate_presence"],
        "outside_facet_only_preview_input"
    );
    assert_eq!(authoritative_heads(&db).await, before);

    let rejected = call(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "facets": { "area": "unknown" } }),
    )
    .await
    .unwrap();
    assert_eq!(rejected["proposed_facets"]["status"], "rejected");
    assert_eq!(
        rejected["proposed_facets"]["assessments"][0]["issues"],
        json!(["not_active_vocabulary_member"])
    );
}

#[tokio::test]
async fn proposed_facets_mirror_declared_type_values_object_and_vocab_ref_predicates() {
    let db = db().await;
    let registry = registry();
    govern_value(&db, "area", "voc:area", "schema").await;
    govern_value(&db, "other-area", "voc:other-area", "schema").await;
    write_user_schema_config(
        &db,
        json!({ "shapes": { "Document:note": { "facets": {
            "area": { "vocab_ref": "area" },
            "effort": { "type": "number" },
            "priority": { "values": ["low", "high"] },
            "payload": {
                "type": "object",
                "json_schema": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } },
                    "required": ["name"],
                    "additionalProperties": false
                }
            },
            "declared_empty": {}
        } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let preview = call(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "facets": {
                "area": { "value": "schema", "vocab_ref": "other-area" },
                "effort": "large",
                "priority": "urgent",
                "payload": { "unexpected": true },
                "declared_empty": { "object": true },
                "open_object": { "object": true },
                "dangling": { "value": "x", "vocab_ref": "missing-vocabulary" },
                "named_ref": { "value": "x", "vocab_ref": "area" }
            }
        }),
    )
    .await
    .unwrap();
    let assessments = preview["proposed_facets"]["assessments"]
        .as_array()
        .unwrap();
    let issues = |key: &str| {
        assessments
            .iter()
            .find(|assessment| assessment["key"] == key)
            .unwrap()["issues"]
            .clone()
    };
    assert_eq!(issues("area"), json!(["conflicting_vocabulary_reference"]));
    assert_eq!(issues("effort"), json!(["declared_type_mismatch"]));
    assert_eq!(issues("priority"), json!(["not_in_declared_values"]));
    assert_eq!(issues("payload"), json!(["object_value_invalid"]));
    assert_eq!(issues("declared_empty"), json!(["undeclared_object_value"]));
    assert_eq!(issues("open_object"), json!([]));
    assert_eq!(issues("dangling"), json!(["dangling_vocabulary_reference"]));
    assert_eq!(
        issues("named_ref"),
        json!(["dangling_vocabulary_reference"])
    );

    let before = authoritative_heads(&db).await;
    let create_error = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": "9855d3b0-0000-4000-8000-000000000001",
                "type": "Document",
                "kind": "note",
                "name": "Named open vocabulary reference",
                "facets": { "named_ref": { "value": "x", "vocab_ref": "area" } },
                "reason": "Prove preview and create reject the same open vocabulary reference."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(create_error.contains("does not resolve to a vocabulary"));
    assert_eq!(authoritative_heads(&db).await, before);
}

#[tokio::test]
async fn one_hundred_large_open_facets_keep_every_assessment_inside_the_response_ceiling() {
    let db = db().await;
    let registry = registry();
    let before = authoritative_heads(&db).await;
    let facets = (0..100)
        .map(|index| {
            (
                format!("facet-{index:03}-{}", "k".repeat(512)),
                json!("v".repeat(4096)),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let preview = call(
        &registry,
        &db,
        json!({ "type": "Document", "facets": facets }),
    )
    .await
    .unwrap();
    assert_eq!(
        preview["proposed_facets"]["assessments"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    assert!(serde_json::to_vec(&preview).unwrap().len() <= 65_536);
    assert_eq!(authoritative_heads(&db).await, before);
}

#[tokio::test]
async fn proposed_facets_bound_large_context_and_required_declarations_without_writes() {
    let db = db().await;
    let registry = registry();
    let required = (0..500)
        .map(|index| {
            (
                format!("required-{index:03}-{}", "k".repeat(512)),
                json!({ "required": true }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let facets = required
        .keys()
        .take(100)
        .map(|key| (key.clone(), json!("supplied")))
        .collect::<serde_json::Map<_, _>>();
    write_user_schema_config(
        &db,
        json!({ "shapes": { "Document": { "facets": required } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let before = authoritative_heads(&db).await;

    let preview = call(
        &registry,
        &db,
        json!({
            "type": "Document",
            "kind": "k".repeat(100_000),
            "facets": facets,
        }),
    )
    .await
    .unwrap();
    assert_eq!(preview["proposed_facets"]["status"], "rejected");
    assert_eq!(
        preview["proposed_facets"]["assessments"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    assert!(preview["run_context"].is_object());
    assert_eq!(
        preview["proposed_facets"]["required_declarations_omitted_count"],
        500
    );
    assert!(
        preview["proposed_facets"]["required_declarations_omission"]["sha256"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        preview["proposed_facets"]["context"]["kind"]
            .as_str()
            .unwrap()
            .len(),
        71
    );
    assert!(serde_json::to_vec(&preview).unwrap().len() <= 65_536);
    assert_eq!(authoritative_heads(&db).await, before);
}
