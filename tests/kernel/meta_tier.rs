//! Stage 6 of the tool surface (tools 20–21): the meta tier — vocabularies and
//! the schema_config cascade — exercised through the registry, the way both
//! transports dispatch.
//!
//! The interesting half is `manage_schema_config`'s rejection (a): the
//! spine-facet interop floor (3057bba §4). Its comparison predicate is defined
//! in `src/mcp/tools/meta.rs`'s module header; the tests below cover each of
//! its four limbs and each of its documented exclusions. One of those
//! exclusions — cardinality — is excluded because it is inert rather than
//! because it is permitted, so it has its own symmetric rejection (c) rather
//! than a limb, and its own tests alongside them.

use native_ce::events::FacetSetPayload;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{seed_pack_schema_config, seed_vocabularies, vocab_ref, SchemaConfigOptions};
use native_ce::query::cascade::{self, SchemaConfigRow};
use native_ce::store::{create_record, set_facet};
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

async fn db() -> Db {
    // Meta-tier fixtures define their own pack rows; retain the normal seeded
    // vocabularies while leaving the pack projection explicit per test.
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    seed_vocabularies(&db).await.unwrap();
    db
}

async fn govern_kind(db: &Db, record_type: &str, token: &str) {
    if !native_ce::meta::kind::resolve(db, record_type, token)
        .await
        .unwrap()
        .quarantined
    {
        return;
    }
    let id = native_ce::meta::propose_value_with_kind_metadata_as(
        db,
        &format!("kind:{record_type}"),
        token,
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(db, &id).await.unwrap();
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap_err()
        .to_string()
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stage6_tools_register_alongside_the_rest_of_the_surface() {
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    let names: Vec<&str> = registry.specs().map(|t| t.name.as_str()).collect();
    for tool in ["manage_vocabularies", "manage_schema_config"] {
        assert!(names.contains(&tool), "{tool} missing from {names:?}");
    }
    // Registration is unique-by-name; a second pass must fail, not shadow.
    assert!(register_surface_tools(&mut registry).is_err());
}

// ---------------------------------------------------------------------------
// Tool 20 — manage_vocabularies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn runs_the_sanctioned_lifecycle_through_the_tool() {
    let db = db().await;
    let registry = registry();

    for vocabulary in ["lifecycle", "comment-lifecycle", "suggestion-lifecycle"] {
        let listed = call(
            &registry,
            &db,
            "manage_vocabularies",
            json!({ "action": "list_values", "vocabulary": vocabulary, "status": "active" }),
        )
        .await;
        assert_eq!(listed["vocabulary"]["name"], vocabulary, "{listed:#}");
        let values = listed["values"].as_array().unwrap();
        assert!(!values.is_empty(), "{vocabulary}");
        assert!(
            values.iter().all(|value| value["gloss"]
                .as_str()
                .is_some_and(|gloss| !gloss.trim().is_empty())),
            "{vocabulary}: {listed:#}"
        );
    }

    let created = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "theme" }),
    )
    .await;
    assert_eq!(created["vocabulary_id"], "voc:theme");
    // The form a facet shape / facet assignment references it by.
    assert_eq!(created["vocab_ref"], "rec:voc:theme");

    let offsite = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": "theme", "value": "offsite",
                "gloss": "a day away from the desk", "ordinal": 200,
                "terminality": "terminal_positive" }),
    )
    .await;
    assert_eq!(offsite["status"], "proposed");
    assert_eq!(offsite["ordinal"], 200.0);
    assert_eq!(offsite["terminality"], "terminal_positive");
    let offsite_id = offsite["value_id"].as_str().unwrap().to_string();

    let away_day = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": "theme", "value": "away day",
                "ordinal": 100 }),
    )
    .await;
    let away_day_id = away_day["value_id"].as_str().unwrap().to_string();

    for id in [&offsite_id, &away_day_id] {
        let promoted = call(
            &registry,
            &db,
            "manage_vocabularies",
            json!({ "action": "promote_value", "value_id": id }),
        )
        .await;
        assert_eq!(promoted["status"], "active");
    }

    // Reordering is a standalone metadata operation. It accepts fractional
    // positions and cannot mutate the value's active lifecycle status.
    let reordered = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "reorder_value", "value_id": offsite_id, "ordinal": 50.5 }),
    )
    .await;
    assert_eq!(reordered["reordered"], true);
    assert_eq!(reordered["ordinal"], 50.5);
    let row =
        sqlx::query("SELECT status, ordinal, terminality FROM vocabulary_values WHERE id = ?")
            .bind(&offsite_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(row.get::<String, _>("status"), "active");
    assert_eq!(row.get::<f64, _>("ordinal"), 50.5);
    assert_eq!(row.get::<String, _>("terminality"), "terminal_positive");

    // Rename/merge goes through alias, never delete-and-recreate.
    let aliased = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "alias_value", "value_id": away_day_id, "canonical_id": offsite_id }),
    )
    .await;
    assert_eq!(aliased["alias_of"], json!(offsite_id));
    assert_eq!(aliased["status"], "deprecated");

    // The read half: unfiltered lists both, alias-resolved by default.
    let all = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "list_values", "vocabulary": "theme" }),
    )
    .await;
    assert_eq!(all["vocabulary"]["name"], "theme");
    assert_eq!(all["vocab_ref"], "rec:voc:theme");
    let values = all["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["value"], "offsite");
    assert_eq!(values[0]["ordinal"], 50.5);
    assert_eq!(values[0]["terminality"], "terminal_positive");
    let alias = values.iter().find(|v| v["value"] == "away day").unwrap();
    assert_eq!(alias["canonical"]["value"], "offsite");

    // Status-filtered, alias resolution opted out of.
    let active = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "list_values", "vocabulary": "theme", "status": "active",
                "resolve_aliases": false }),
    )
    .await;
    assert_eq!(active["values"].as_array().unwrap().len(), 1);
    assert_eq!(active["values"][0]["value"], "offsite");
    assert!(active["values"][0].get("canonical").is_none());

    // Deprecation is how a value leaves service.
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "deprecate_value", "value_id": offsite_id }),
    )
    .await;
    let active = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "list_values", "vocabulary": "theme", "status": "active" }),
    )
    .await;
    assert!(active["values"].as_array().unwrap().is_empty());
}

/// The tool must NOT re-implement the delete guards — it dispatches, and
/// `meta::vocabulary`'s rejections surface verbatim (e3e14cd: the enforcement
/// stays app-layer, in that module, permanently).
#[tokio::test]
async fn surfaces_the_meta_layer_delete_rejections_without_reimplementing_them() {
    let db = db().await;
    let registry = registry();
    seed_vocabularies(&db).await.unwrap();

    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_value", "value_id": "vv:voc:maturity:decided" }),
    )
    .await;
    assert!(err.contains("seeded"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_vocabulary", "vocabulary": "maturity" }),
    )
    .await;
    assert!(err.contains("seeded"), "{err}");

    // A referenced value: the facet assignment would be stranded.
    let vid = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "mood" }),
    )
    .await["vocabulary_id"]
        .as_str()
        .unwrap()
        .to_string();
    let happy = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": "mood", "value": "happy" }),
    )
    .await["value_id"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "promote_value", "value_id": happy }),
    )
    .await;
    let rec = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "diary" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        &rec,
        FacetSetPayload {
            key: "mood".into(),
            value: Some("happy".into()),
            vocab_ref: Some(vocab_ref(&vid)),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();

    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_value", "value_id": happy }),
    )
    .await;
    assert!(err.contains("facet assignment"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_vocabulary", "vocabulary": "mood" }),
    )
    .await;
    assert!(err.contains("strand"), "{err}");

    // The guard protects integrity; it is not blanket immutability.
    let typo = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": "mood", "value": "hapy" }),
    )
    .await["value_id"]
        .as_str()
        .unwrap()
        .to_string();
    let deleted = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_value", "value_id": typo }),
    )
    .await;
    assert_eq!(deleted["deleted"], true);
}

#[tokio::test]
async fn rejects_malformed_vocabulary_arguments() {
    let db = db().await;
    let registry = registry();

    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "list_values", "vocabulary": "nope" }),
    )
    .await;
    assert!(err.contains("does not exist"), "{err}");

    // An unknown action, an unknown field and an invalid status are all
    // caller bugs worth surfacing (deny_unknown_fields, typed status).
    for args in [
        json!({ "action": "merge_vocabularies" }),
        json!({ "action": "create_vocabulary", "name": "x", "colour": "red" }),
        json!({ "action": "list_values", "vocabulary": "x", "status": "retired" }),
        json!({ "action": "propose_value", "vocabulary": "x" }),
    ] {
        let err = call_err(&registry, &db, "manage_vocabularies", args.clone()).await;
        assert!(
            err.contains("invalid arguments for manage_vocabularies"),
            "{args} -> {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tool 21 — manage_schema_config: read + write
// ---------------------------------------------------------------------------

/// A pack floor exercising every constraint the loosening predicate knows
/// about: a required spine facet, a vocab-governed spine facet, an
/// enum-constrained spine facet, and a non-spine pack facet.
async fn seed_pack(db: &Db) {
    govern_kind(db, "WorkItem", "chore").await;
    seed_pack_schema_config(
        db,
        "@native/recommended",
        json!({ "shapes": {
            "WorkItem": {
                "facets": {
                    "lifecycle": { "required": true, "vocab": "voc:lifecycle", "axis": { "key": "work_status", "label": "Work status" } },
                    "persistence": { "values": ["enduring", "occurrent"] },
                    "maturity": { "required": true },
                    "confidence": { "required": true, "vocab": "voc:confidence" }
                }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
}

/// Write a user-layer config through the tool, returning the error string.
async fn write_err(registry: &ToolRegistry, db: &Db, data: Value) -> String {
    call_err(
        registry,
        db,
        "manage_schema_config",
        json!({ "action": "write", "data": data }),
    )
    .await
}

/// Write a user-layer config through the tool, asserting it is accepted.
async fn write_ok(registry: &ToolRegistry, db: &Db, data: Value) -> Value {
    call(
        registry,
        db,
        "manage_schema_config",
        json!({ "action": "write", "data": data }),
    )
    .await
}

#[tokio::test]
async fn reads_both_cascade_views_and_writes_the_user_layer() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    let written = write_ok(
        &registry,
        &db,
        json!({ "shapes": {
            "WorkItem": { "facets": { "confidence": { "values": ["likely"] } } },
            "Outcome": { "facets": { "horizon": {} } }
        } }),
    )
    .await;
    assert_eq!(written["layer"], "user");
    let user_row_id = written["id"].as_str().unwrap().to_string();

    let read = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read" }),
    )
    .await;
    // Pack view stays pristine; resolved carries the user layer over it.
    assert_eq!(
        read["pack"]["shapes"]["WorkItem"]["facets"]["confidence"]["vocab"],
        "voc:confidence"
    );
    assert!(read["pack"]["shapes"].get("Outcome").is_none());
    assert_eq!(
        read["resolved"]["shapes"]["WorkItem"]["facets"]["confidence"]["values"],
        json!(["likely"])
    );
    // Untouched pack keys survive the overlay.
    assert_eq!(
        read["resolved"]["shapes"]["WorkItem"]["facets"]["lifecycle"]["required"],
        true
    );
    assert!(read["resolved"]["shapes"]["Outcome"]["facets"]
        .get("horizon")
        .is_some());
    // The floor constants ride along so a caller can see what is judged.
    assert_eq!(
        read["spine_facets"],
        json!(["lifecycle", "owner", "persistence", "maturity"])
    );
    assert_eq!(
        read["reserved_facets"],
        json!(["archived", "blob_ref", "canvas.promoted_from"])
    );
    assert_eq!(read["rows"].as_array().unwrap().len(), 2);

    // Layer-filtered rows; the two views are unconditional.
    let user_only = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read", "layer": "user" }),
    )
    .await;
    let rows = user_only["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], json!(user_row_id));
    assert!(user_only["pack"]["shapes"].get("WorkItem").is_some());

    // Re-writing the same row id updates it in place (one editable layer).
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "id": user_row_id,
                "data": { "shapes": { "Outcome": { "facets": { "horizon": { "values": ["q"] } } } } },
                "version_lineage": "2" }),
    )
    .await;
    let after = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read", "layer": "user" }),
    )
    .await;
    assert_eq!(after["rows"].as_array().unwrap().len(), 1);
    assert_eq!(after["rows"][0]["version_lineage"], "2");
}

/// A read derives `pack`, `resolved` and `rows` from ONE fetch (task a3fb2e2):
/// the cascade is folded from the same row set the `rows` field is filtered
/// from, so a direct write landing between two reads cannot pair rows from one
/// state with views from another. What the in-memory filter must not change is
/// the answer: for every layer argument it still matches, row for row and in
/// order, what `schema_config_rows(db, Some(layer))` returns from SQL.
#[tokio::test]
async fn a_read_derives_the_cascade_and_the_rows_from_one_fetch() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    seed_pack_schema_config(
        &db,
        "@native/extra",
        json!({ "shapes": { "Outcome": { "facets": { "horizon": { "required": true } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "confidence": { "values": ["likely"] } } } } }),
    )
    .await;
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "Outcome": { "facets": { "horizon": { "values": ["q", "y"] } } } } }),
    )
    .await;

    // The in-memory layer filter answers exactly what SQL does, including the
    // unfiltered case and the application order within a layer.
    for layer in [None, Some("pack"), Some("user")] {
        let mut args = json!({ "action": "read" });
        if let Some(layer) = layer {
            args["layer"] = json!(layer);
        }
        let read = call(&registry, &db, "manage_schema_config", args).await;
        let from_sql = cascade::schema_config_rows(&db, layer).await.unwrap();
        assert_eq!(
            read["rows"],
            serde_json::to_value(&from_sql).unwrap(),
            "rows disagree with schema_config_rows(db, {layer:?})"
        );
        // The two cascade views are unconditional — the layer filter narrows the
        // rows listing only.
        let whole = cascade::resolve(&db).await.unwrap();
        assert_eq!(read["pack"], whole.pack);
        assert_eq!(read["resolved"], whole.resolved);
    }
}

/// `resolve_from_rows` carries the fold `resolve` used to inline: same answer
/// over the same rows, including the `applies_to_collection_id` skip for
/// v1-deferred subtree overlays (3057bba), which no write path can produce yet.
#[tokio::test]
async fn resolve_from_rows_reproduces_the_folds_of_resolve() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    write_ok(
        &registry,
        &db,
        json!({ "shapes": {
            "WorkItem": { "facets": { "confidence": { "values": ["likely"] } } },
            "Outcome": { "facets": { "horizon": {} } }
        } }),
    )
    .await;

    let rows = cascade::schema_config_rows(&db, None).await.unwrap();
    let folded = cascade::resolve_from_rows(&rows);
    let fetched = cascade::resolve(&db).await.unwrap();
    assert_eq!(folded.pack, fetched.pack);
    let mut fetched_shapes = fetched.resolved.clone();
    let fetched_shape_rows = fetched_shapes["shapes"].as_object_mut().unwrap();
    for shape in fetched_shape_rows.values_mut() {
        shape.as_object_mut().unwrap().remove("kinds");
    }
    fetched_shape_rows.retain(|_, shape| !shape.as_object().unwrap().is_empty());
    assert_eq!(folded.resolved, fetched_shapes);

    // A subtree overlay is inert on both views, whichever layer carries it.
    let mut with_overlay = rows;
    with_overlay.push(SchemaConfigRow {
        id: "sub:pack".into(),
        layer: "pack".into(),
        name: None,
        data: json!({ "shapes": { "WorkItem": { "facets": { "lifecycle": { "required": false } } } } }),
        applies_to_collection_id: Some("rec-collection".into()),
        version_lineage: None,
        created_at: "2026-07-29T00:00:00Z".into(),
    });
    with_overlay.push(SchemaConfigRow {
        id: "sub:user".into(),
        layer: "user".into(),
        name: None,
        data: json!({ "shapes": { "Subtree": { "facets": { "only_here": {} } } } }),
        applies_to_collection_id: Some("rec-collection".into()),
        version_lineage: None,
        created_at: "2026-07-29T00:00:01Z".into(),
    });
    let skipped = cascade::resolve_from_rows(&with_overlay);
    assert_eq!(skipped.pack, fetched.pack);
    assert_eq!(skipped.resolved, fetched_shapes);
    assert_eq!(
        skipped.resolved["shapes"]["WorkItem"]["facets"]["lifecycle"]["required"],
        json!(true),
        "a subtree overlay must not reach the resolved view"
    );
    assert!(skipped.resolved["shapes"].get("Subtree").is_none());
}

#[tokio::test]
async fn rejects_a_user_write_aimed_at_a_pack_row_and_a_non_object_payload() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    let pack_id = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read", "layer": "pack" }),
    )
    .await["rows"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let err = call_err(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "id": pack_id,
                "data": { "shapes": { "Outcome": { "facets": { "horizon": {} } } } } }),
    )
    .await;
    assert!(err.contains("seed-only"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": "shapes" }),
    )
    .await;
    assert!(err.contains("must be a JSON object"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": {}, "layer": "user" }),
    )
    .await;
    assert!(
        err.contains("invalid arguments for manage_schema_config"),
        "{err}"
    );
}

// ---- Rejection (b) — engine-reserved keys, wired not rebuilt ---------------

#[tokio::test]
async fn rejection_b_fires_on_any_configuration_of_reserved_facets_in_either_direction() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    for key in ["archived", "blob_ref", "canvas.promoted_from"] {
        for shape in [
            json!({ "values": ["true", "false"] }), // loosening direction
            json!({ "required": true }),            // tightening direction
            json!({}),                              // no direction at all
        ] {
            let err = write_err(
                &registry,
                &db,
                json!({ "shapes": { "WorkItem": { "facets": { (key): shape } } } }),
            )
            .await;
            assert!(err.contains("engine-reserved"), "{err}");
        }
    }

    // A payload that trips both rejections reports (b) — the stronger claim.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "archived": {},
            "lifecycle": { "vocab": "voc:mine" }
        } } } }),
    )
    .await;
    assert!(err.contains("engine-reserved"), "{err}");
}

// ---- Rejection (c) — cardinality on any facet key, inert either way --------

/// `multi` is honoured nowhere in the engine, and for the four spine facets it
/// never could be: they project to scalar COLUMNS on `records`. So a `multi`
/// claim over one is neither a loosening nor a tightening — it is empty, and
/// the resolved view would advertise it faithfully anyway. The write is refused
/// on the key's PRESENCE, in either direction, like rejection (b).
#[tokio::test]
async fn rejection_c_fires_on_multi_over_any_spine_key_in_either_direction() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    // On `Outcome`, which the pack does not shape at all: there is no floor here,
    // so nothing rejection (a) could possibly be firing on. Rejection (c) does
    // not consult the cascade — an inert claim is inert with or without a pack.
    for key in ["lifecycle", "owner", "persistence", "maturity"] {
        for multi in [json!(true), json!(false)] {
            let err = write_err(
                &registry,
                &db,
                json!({ "shapes": { "Outcome": { "facets": { key: { "multi": multi } } } } }),
            )
            .await;
            assert!(
                err.contains(&format!("cannot configure `multi` on facet '{key}'")),
                "{err}"
            );
            assert!(err.contains("inert in either direction"), "{err}");
            assert!(!err.contains("cannot loosen"), "{err}");
        }
    }

    // And on a pack-shaped key whose shape is otherwise a faithful restatement
    // of the pack's — so the ONLY thing wrong with the payload is the `multi`.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "lifecycle": { "required": true, "vocab": "voc:lifecycle", "multi": false } } } } }),
    )
    .await;
    assert!(
        err.contains("cannot configure `multi` on facet 'lifecycle'"),
        "{err}"
    );

    // A payload tripping both (c) and (a) reports (c) — the symmetric claim
    // (the key means nothing here) over the bounded, directional one.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "lifecycle": { "multi": true } } } } }),
    )
    .await;
    assert!(err.contains("cannot configure `multi`"), "{err}");
    assert!(!err.contains("cannot loosen"), "{err}");
}

/// Open facets live in `facet_values` under `UNIQUE (record_id, key)`, so they
/// are just as single-valued as spine facets. Both boolean directions are
/// rejected, and the message points callers to naturally multi-valued links.
#[tokio::test]
async fn rejection_c_fires_on_multi_over_any_open_facet_in_either_direction() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    for (key, multi) in [("confidence", true), ("horizon", false)] {
        let err = write_err(
            &registry,
            &db,
            json!({ "shapes": {
                "Outcome": { "facets": { key: { "multi": multi } } }
            } }),
        )
        .await;
        assert!(
            err.contains(&format!("cannot configure `multi` on facet '{key}'")),
            "{err}"
        );
        assert!(
            err.contains("Cardinality decides facet versus link"),
            "{err}"
        );
        assert!(err.contains("contributors"), "{err}");
        assert!(err.contains("`links`"), "{err}");
    }
}

/// Kind-discriminated shapes use the same absolute scan. Rejection happens
/// before pack lookup or kind enumeration can affect the result.
#[tokio::test]
async fn rejection_c_fires_on_multi_in_a_kind_discriminated_shape() {
    let db = db().await;
    let registry = registry();

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": {
            "WorkItem:chore": { "facets": { "assignee": { "multi": true } } }
        } }),
    )
    .await;
    assert!(
        err.contains("cannot configure `multi` on facet 'assignee'"),
        "{err}"
    );
    assert!(err.contains("shape 'WorkItem:chore'"), "{err}");
}

// ---- Rejection (a) — the spine-facet interop floor, limb by limb -----------

#[tokio::test]
async fn rejection_a_blocks_kind_shape_bypass_of_a_base_spine_floor() {
    let db = db().await;
    let registry = registry();
    govern_kind(&db, "Outcome", "key_result").await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": {
            "Outcome": {
                "facets": { "owner": { "required": true } }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": {
            "Outcome:key_result": { "facets": { "owner": {} } }
        } }),
    )
    .await;
    assert!(err.contains("cannot loosen spine facet 'owner'"), "{err}");
    assert!(err.contains("Outcome:key_result"), "{err}");
    assert!(err.contains("required"), "{err}");
}

#[tokio::test]
async fn kind_shapes_must_use_the_post_write_resolved_kinds_list() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    seed_pack_schema_config(
        &db,
        "@native/kind-shape",
        json!({ "shapes": {
            "WorkItem:chore": { "facets": { "confidence": { "required": true } } }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": {
            "WorkItem:choer": { "facets": { "confidence": {} } }
        } }),
    )
    .await;
    assert!(err.contains("ungoverned kind 'choer'"), "{err}");
    assert!(err.contains("WorkItem:choer"), "{err}");

    let chore_id = native_ce::meta::kind::resolve(&db, "WorkItem", "chore")
        .await
        .unwrap()
        .canonical_value_id
        .unwrap();
    let alias_id = native_ce::meta::propose_value_with_kind_metadata_as(
        &db,
        "kind:WorkItem",
        "housework",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(
            "WorkItem",
            "housework",
        )),
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &alias_id)
        .await
        .unwrap();
    native_ce::meta::alias_value(&db, &alias_id, &chore_id)
        .await
        .unwrap();
    let proposed_id = native_ce::meta::propose_value_with_kind_metadata_as(
        &db,
        "kind:WorkItem",
        "proposed_task",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(
            "WorkItem",
            "proposed_task",
        )),
        None,
    )
    .await
    .unwrap();
    let deprecated_id = native_ce::meta::propose_value_with_kind_metadata_as(
        &db,
        "kind:WorkItem",
        "retired_task",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(
            "WorkItem",
            "retired_task",
        )),
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &deprecated_id)
        .await
        .unwrap();
    native_ce::meta::deprecate_value(&db, &deprecated_id)
        .await
        .unwrap();

    for token in ["housework", "proposed_task", "retired_task", "foreign_task"] {
        let err = write_err(
            &registry,
            &db,
            json!({ "shapes": {
                format!("WorkItem:{token}"): { "facets": { "confidence": {} } }
            } }),
        )
        .await;
        assert!(err.contains("active canonical"), "{token}: {err}");
    }

    let bearer = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Scoped bearer" }),
    )
    .await
    .unwrap();
    for token in ["housework", "proposed_task", "retired_task", "foreign_task"] {
        let err = call_err(
            &registry,
            &db,
            "manage_schema_config",
            json!({
                "action": "write",
                "applies_to_collection_id": &bearer,
                "data": { "shapes": {
                    format!("WorkItem:{token}"): { "facets": { "confidence": {} } }
                } }
            }),
        )
        .await;
        assert!(err.contains("active canonical"), "scoped {token}: {err}");
    }
    let _ = proposed_id;

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": {
            "WorkItem": { "kinds": ["errand"] }
        } }),
    )
    .await;
    assert!(
        err.contains("kind:<Type> vocabularies are authoritative"),
        "{err}"
    );

    // Kind identity is installed through its vocabulary; shape config owns
    // only the kind-specific facets.
    govern_kind(&db, "Outcome", "key_result").await;
    write_ok(
        &registry,
        &db,
        json!({ "shapes": {
            "Outcome:key_result": { "facets": { "target": { "required": true } } }
        } }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({
            "action": "write",
            "applies_to_collection_id": bearer,
            "data": { "shapes": {
                "WorkItem:chore": { "facets": { "confidence": {} } }
            } }
        }),
    )
    .await;
}

#[tokio::test]
async fn rejection_a_limb_1_removal() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    // `null` is the only expressible un-shaping: an omitted key inherits.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "lifecycle": Value::Null } } } }),
    )
    .await;
    assert!(
        err.contains("cannot loosen spine facet 'lifecycle'"),
        "{err}"
    );
    assert!(err.contains("clears the shape"), "{err}");
    assert!(err.contains("interop floor"), "{err}");
}

#[tokio::test]
async fn rejection_a_limb_2_de_requiring_explicitly_or_by_omission() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "maturity": { "required": false } } } } }),
    )
    .await;
    assert!(
        err.contains("cannot loosen spine facet 'maturity'"),
        "{err}"
    );
    assert!(err.contains("required"), "{err}");

    // Omitting `required` is not "unchanged" — facet shapes replace wholesale.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "maturity": { "description": "how settled" } } } } }),
    )
    .await;
    assert!(
        err.contains("cannot loosen spine facet 'maturity'"),
        "{err}"
    );
}

#[tokio::test]
async fn rejection_a_limb_3_enum_widening_or_dropping() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "persistence": { "values": ["enduring", "occurrent", "eternal"] } } } } }),
    )
    .await;
    assert!(
        err.contains("cannot loosen spine facet 'persistence'"),
        "{err}"
    );
    assert!(err.contains("adds value \"eternal\""), "{err}");

    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "persistence": { "description": "kind of thing" } } } } }),
    )
    .await;
    assert!(err.contains("lists none"), "{err}");
}

#[tokio::test]
async fn rejection_a_limb_4_vocabulary_dropped_or_swapped() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    // Dropped: the pack governs lifecycle, the user layer governs nothing.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "lifecycle": { "required": true } } } } }),
    )
    .await;
    assert!(err.contains("names none"), "{err}");

    // Swapped: re-pointing a spine facet at a vocabulary the user controls is
    // the fork this limb catches — regardless of that vocabulary's contents.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "lifecycle": { "required": true, "vocab": "voc:my-lifecycle", "axis": { "key": "work_status", "label": "Work status" } } } } } }),
    )
    .await;
    assert!(err.contains("re-points it"), "{err}");
    assert!(err.contains("voc:my-lifecycle"), "{err}");

    // `rec:`-prefixed and bare refs name the same vocabulary — not a swap.
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "lifecycle": { "required": true, "vocab_ref": "rec:voc:lifecycle", "axis": { "key": "work_status", "label": "Work status" } } } } } }),
    )
    .await;
}

#[tokio::test]
async fn rejection_a_limb_5_requires_the_exact_pack_lifecycle_axis() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    for axis in [
        json!({ "key": "workflow_state", "label": "Work status" }),
        json!({ "key": "work_status", "label": "Workflow status" }),
    ] {
        let err = write_err(
            &registry,
            &db,
            json!({ "shapes": { "WorkItem": { "facets": {
                "lifecycle": { "required": true, "vocab": "lifecycle", "axis": axis }
            } } } }),
        )
        .await;
        assert!(err.contains("exact axis object"), "{err}");
    }
}

/// Limb 4 judges vocabulary IDENTITY, not spelling. `get_vocabulary` matches
/// id OR name, so one row has several legal designators — bare name, bare id,
/// and either behind `rec:`. A user layer that faithfully restates the pack's
/// own vocabulary in a different form is the honest case the floor exists to
/// permit; comparing the designator strings rejected it as a swap.
#[tokio::test]
async fn rejection_a_limb_4_resolves_designators_before_comparing_them() {
    let db = db().await;
    let registry = registry();
    // `maturity` is a seeded vocabulary: row id `voc:maturity`, name `maturity`.
    seed_vocabularies(&db).await.unwrap();
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        // The pack names it by NAME; the canonical ref form is `rec:voc:maturity`.
        json!({ "shapes": { "WorkItem": { "facets": {
            "maturity": { "required": true, "vocab": "maturity" } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    // Same row, canonical ref spelling — a restatement, not a swap.
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "maturity": { "required": true, "vocab_ref": vocab_ref("voc:maturity") } } } } }),
    )
    .await;

    // Same row, bare id spelling.
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "maturity": { "required": true, "vocab": "voc:maturity" } } } } }),
    )
    .await;

    // A different row is still a swap — resolution does not collapse two
    // vocabularies into one, only two names for one.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "maturity": { "required": true, "vocab": "confidence" } } } } }),
    )
    .await;
    assert!(err.contains("re-points it"), "{err}");

    // A designator naming no row falls back to itself, so the limb keeps
    // working on a config written ahead of the vocabulary it names.
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "maturity": { "required": true, "vocab": "voc:not-yet-created" } } } } }),
    )
    .await;
    assert!(err.contains("re-points it"), "{err}");
}

/// Judging an identity is only worth something if the identity is what gets
/// STORED. A name-form reference is re-resolved on every later read, and a
/// vocabulary can be deleted and recreated under the same name with a
/// different id — `delete_vocabulary` guards only `facet_values`, which spine
/// facets never populate. Without canonicalisation the stored user shape
/// rebinds to the new vocabulary while the pack's id-form reference still
/// pins the old one: the floor moves with no schema_config write at all.
#[tokio::test]
async fn accepted_spine_vocab_refs_are_stored_as_identities_not_names() {
    let db = db().await;
    let registry = registry();
    // A user-created (non-seeded, therefore deletable) governing vocabulary.
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "document-lifecycle" }),
    )
    .await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "Document": { "facets": {
            "lifecycle": { "required": true, "vocab": "voc:document-lifecycle", "axis": { "key": "document_state", "label": "Document state" } } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    // Accepted by name — the same row the pack names by id.
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "Document": { "facets": {
            "lifecycle": { "required": true, "vocab": "document-lifecycle", "axis": { "key": "document_state", "label": "Document state" } } } } } }),
    )
    .await;

    // Stored as the identity, not the name.
    let read = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read", "layer": "user" }),
    )
    .await;
    assert_eq!(
        read["rows"][0]["data"]["shapes"]["Document"]["facets"]["lifecycle"]["vocab"],
        "rec:voc:document-lifecycle"
    );

    // And the rebind route is closed at its root: the vocabulary a floor names
    // can no longer be deleted out from under it. Both layers reference it, so
    // both are named.
    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_vocabulary", "vocabulary": "document-lifecycle" }),
    )
    .await;
    assert!(err.contains("schema_config layer(s) govern"), "{err}");
    assert!(err.contains("pack and user"), "{err}");

    // Naming a DIFFERENT vocabulary is still the swap limb 4 exists for.
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "mine" }),
    )
    .await;
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "Document": { "facets": {
            "lifecycle": { "required": true, "vocab": "voc:mine", "axis": { "key": "document_state", "label": "Document state" } } } } } }),
    )
    .await;
    assert!(err.contains("re-points it"), "{err}");
}

/// The `facet_values` reference count is structurally incapable of protecting a
/// vocabulary that governs a SPINE facet: spine facets project to columns on
/// `records`, so no `facet_values` row is ever written for one. Only the
/// `schema_config` count stands between a spine floor and a dangling reference.
#[tokio::test]
async fn a_vocabulary_governing_a_spine_facet_cannot_be_deleted() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "document-lifecycle" }),
    )
    .await;
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "Document": { "facets": {
            "lifecycle": { "required": true, "vocab": "document-lifecycle", "axis": { "key": "document_state", "label": "Document state" } } } } } }),
    )
    .await;

    // A record actually carrying the governed spine facet. This is the
    // assignment the `facet_values` guard would catch for any other facet —
    // and cannot catch here, because it lands in a column.
    let rec = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "ship it" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        &rec,
        FacetSetPayload {
            key: "lifecycle".into(),
            value: Some("active".into()),
            vocab_ref: Some(vocab_ref("voc:document-lifecycle")),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();

    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_vocabulary", "vocabulary": "document-lifecycle" }),
    )
    .await;
    assert!(err.contains("schema_config layer(s) govern"), "{err}");
    assert!(err.contains("user"), "{err}");
}

/// The guard must not over-block: a vocabulary no shape names is still
/// deletable, which is the whole point of hard delete existing at all.
#[tokio::test]
async fn an_unreferenced_vocabulary_is_still_deletable() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "mood" }),
    )
    .await;
    let deleted = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_vocabulary", "vocabulary": "mood" }),
    )
    .await;
    assert_eq!(deleted["deleted"], true);
}

/// Non-spine facets carry no floor, so their references are stored exactly as
/// the user wrote them — canonicalisation is a floor mechanism, not a house
/// style imposed on a hackable seed file.
#[tokio::test]
async fn non_spine_vocab_refs_are_stored_verbatim() {
    let db = db().await;
    let registry = registry();
    seed_vocabularies(&db).await.unwrap();
    seed_pack(&db).await;

    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "confidence": { "required": true, "vocab": "confidence" } } } } }),
    )
    .await;
    let read = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read", "layer": "user" }),
    )
    .await;
    assert_eq!(
        read["rows"][0]["data"]["shapes"]["WorkItem"]["facets"]["confidence"]["vocab"],
        "confidence"
    );
}

#[tokio::test]
async fn rejection_a_permits_everything_it_documents_as_not_loosening() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;

    // Non-spine pack facets are freely loosenable — the whole point of the
    // spine-floor rule as against a blanket ban (3057bba §4).
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "confidence": {} } } } }),
    )
    .await;

    // A spine key the pack does not shape has no floor to be under.
    write_ok(
        &registry,
        &db,
        json!({ "shapes": {
            "WorkItem": { "facets": { "owner": {} } },
            "Outcome": { "facets": { "lifecycle": {} } }
        } }),
    )
    .await;

    // Tightening, on every limb at once: required stays, the enum narrows to a
    // subset, the vocabulary is restated, and a `values` list is ADDED
    // alongside it.
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": {
            "facets": {
                "lifecycle": { "required": true, "vocab": "voc:lifecycle", "values": ["open"], "axis": { "key": "work_status", "label": "Work status" } },
                "persistence": { "values": ["enduring"] },
                "maturity": { "required": true, "default": "exploratory" }
            } } } }),
    )
    .await;

    let read = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read" }),
    )
    .await;
    assert_eq!(
        read["resolved"]["shapes"]["WorkItem"]["facets"]["persistence"]["values"],
        json!(["enduring"])
    );
    assert_eq!(
        read["resolved"]["shapes"]["WorkItem"]["kinds"],
        json!(["chore", "epic", "task"])
    );
}

/// A second user row cannot slip a loosening past by writing after a compliant
/// one: every user write is judged against the PACK view, not against whatever
/// the resolved view currently happens to say.
#[tokio::test]
async fn rejection_a_judges_each_user_row_against_the_pack_not_the_resolved_view() {
    let db = db().await;
    let registry = registry();
    seed_pack(&db).await;
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {
            "lifecycle": { "required": true, "vocab": "voc:lifecycle", "axis": { "key": "work_status", "label": "Work status" } } } } } }),
    )
    .await;
    let err = write_err(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "lifecycle": { "vocab": "voc:lifecycle", "axis": { "key": "work_status", "label": "Work status" } } } } } }),
    )
    .await;
    assert!(
        err.contains("cannot loosen spine facet 'lifecycle'"),
        "{err}"
    );
}

/// With no pack layer at all there is no floor — a user layer alone cannot be
/// "looser than" anything.
#[tokio::test]
async fn rejection_a_is_inert_without_a_pack_layer() {
    let db = db().await;
    let registry = registry();
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "lifecycle": {}, "maturity": Value::Null } } } }),
    )
    .await;
}

// ---------------------------------------------------------------------------
// The meta tier stays outside the event log (Fork C)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meta_writes_append_no_events() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "theme" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": "theme", "value": "offsite" }),
    )
    .await;
    write_ok(
        &registry,
        &db,
        json!({ "shapes": { "Outcome": { "facets": { "horizon": {} } } } }),
    )
    .await;

    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE actor <> 'engine:seed'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        events, 0,
        "the meta tier is direct-write by design (Fork C) — no events"
    );
}
