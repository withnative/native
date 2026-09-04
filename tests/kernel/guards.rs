//! The contract guards the v1 tool surface promises (Native task e035091) —
//! enforcement tests for what docs/tool-surface.md asserts:
//!   1. vocabulary lifecycle: propose/promote/deprecate/alias, no hard delete of
//!      seeded or referenced values/vocabularies (tool 20)
//!   2. schema_config rejects engine-reserved keys (`archived`) in either
//!      direction (tool 21)
//!   3. archive_record set/unset semantics: archived='true' | unset, lifecycle
//!      preserved across the round trip (tool 9)
//!   4. facet_values.vocab_ref referential integrity, app-layer (no FK in the
//!      frozen DDL)

use crate::common::count;
use native_ce::conformance::rebuild_and_diff;
use native_ce::events::FacetSetPayload;
use native_ce::meta::{
    alias_value, create_vocabulary, delete_value, delete_vocabulary, deprecate_value,
    promote_value, propose_value, seed_pack_schema_config, seed_vocabularies, vocab_ref,
    write_user_schema_config, SchemaConfigOptions,
};
use native_ce::store::{
    append, archive_record, create_record, restore_record, set_facet, AppendSpec,
};
use native_ce::{create_database, Db};
use serde_json::json;
use sqlx::Row;

async fn status_of(db: &Db, value_id: &str) -> String {
    sqlx::query("SELECT status FROM vocabulary_values WHERE id = ?")
        .bind(value_id)
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get("status")
}

// ---- guard 1 — vocabulary lifecycle, no hard delete (tool 20) ----

#[tokio::test]
async fn runs_the_sanctioned_lifecycle_propose_promote_deprecate() {
    let db = create_database(":memory:").await.unwrap();
    let vid = create_vocabulary(&db, "mood", None).await.unwrap();
    let value_id = propose_value(&db, "mood", "jubilant", Some("unreservedly happy"))
        .await
        .unwrap();

    assert_eq!(status_of(&db, &value_id).await, "proposed");

    promote_value(&db, &value_id).await.unwrap();
    assert_eq!(status_of(&db, &value_id).await, "active");

    deprecate_value(&db, &value_id).await.unwrap();
    let row = sqlx::query("SELECT status, vocabulary_id FROM vocabulary_values WHERE id = ?")
        .bind(&value_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "deprecated");
    assert_eq!(row.get::<String, _>("vocabulary_id"), vid);
    db.close().await;
}

#[tokio::test]
async fn aliases_within_a_vocabulary_and_rejects_cross_vocabulary_and_chained_aliases() {
    let db = create_database(":memory:").await.unwrap();
    create_vocabulary(&db, "mood", None).await.unwrap();
    create_vocabulary(&db, "weather", None).await.unwrap();
    let happy = propose_value(&db, "mood", "happy", None).await.unwrap();
    let jubilant = propose_value(&db, "mood", "jubilant", None).await.unwrap();
    let sunny = propose_value(&db, "weather", "sunny", None).await.unwrap();
    promote_value(&db, &happy).await.unwrap();

    alias_value(&db, &jubilant, &happy).await.unwrap();
    let row = sqlx::query("SELECT alias_of, status FROM vocabulary_values WHERE id = ?")
        .bind(&jubilant)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        row.get::<Option<String>, _>("alias_of").as_deref(),
        Some(happy.as_str())
    );
    // an alias is a redirect, not a live value
    assert_eq!(row.get::<String, _>("status"), "deprecated");

    let err = alias_value(&db, &sunny, &happy)
        .await
        .expect_err("cross-vocab")
        .to_string();
    assert!(err.contains("across vocabularies"), "{err}");
    // Chains rejected: the canonical must not itself be an alias.
    let glad = propose_value(&db, "mood", "glad", None).await.unwrap();
    let err = alias_value(&db, &glad, &jubilant)
        .await
        .expect_err("chain")
        .to_string();
    assert!(err.contains("itself an alias"), "{err}");
    let err = alias_value(&db, &glad, &glad)
        .await
        .expect_err("self")
        .to_string();
    assert!(err.contains("itself"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn rejects_deletion_of_seeded_values_and_vocabularies() {
    let db = create_database(":memory:").await.unwrap();
    seed_vocabularies(&db).await.unwrap();
    let err = delete_value(&db, "vv:voc:maturity:decided")
        .await
        .expect_err("seeded value")
        .to_string();
    assert!(err.contains("seeded"), "{err}");
    let err = delete_vocabulary(&db, "maturity")
        .await
        .expect_err("seeded vocab")
        .to_string();
    assert!(err.contains("seeded"), "{err}");
    // Seeding is idempotent.
    seed_vocabularies(&db).await.unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM vocabularies WHERE name = 'maturity'"
        )
        .await,
        1
    );
    db.close().await;
}

#[tokio::test]
async fn rejects_deletion_of_a_referenced_value_and_a_referenced_vocabulary() {
    let db = create_database(":memory:").await.unwrap();
    let vid = create_vocabulary(&db, "mood", None).await.unwrap();
    let happy = propose_value(&db, "mood", "happy", None).await.unwrap();
    promote_value(&db, &happy).await.unwrap();
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

    let err = delete_value(&db, &happy)
        .await
        .expect_err("referenced value")
        .to_string();
    assert!(err.contains("facet assignment"), "{err}");
    let err = delete_vocabulary(&db, "mood")
        .await
        .expect_err("referenced vocab")
        .to_string();
    assert!(err.contains("strand"), "{err}");
    // The sanctioned exit still works while referenced.
    deprecate_value(&db, &happy).await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn rejects_deletion_of_an_alias_target_but_allows_deleting_an_unreferenced_unseeded_value() {
    let db = create_database(":memory:").await.unwrap();
    create_vocabulary(&db, "mood", None).await.unwrap();
    let happy = propose_value(&db, "mood", "happy", None).await.unwrap();
    let jubilant = propose_value(&db, "mood", "jubilant", None).await.unwrap();
    promote_value(&db, &happy).await.unwrap();
    alias_value(&db, &jubilant, &happy).await.unwrap();

    let err = delete_value(&db, &happy)
        .await
        .expect_err("alias target")
        .to_string();
    assert!(err.contains("alias"), "{err}");

    // A just-proposed typo, never referenced: deletable.
    let typo = propose_value(&db, "mood", "hapy", None).await.unwrap();
    delete_value(&db, &typo).await.unwrap();
    // An unreferenced, unseeded vocabulary: deletable (values cascade).
    create_vocabulary(&db, "scratch", None).await.unwrap();
    propose_value(&db, "scratch", "x", None).await.unwrap();
    delete_vocabulary(&db, "scratch").await.unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM vocabulary_values WHERE vocabulary_id = 'voc:scratch'"
        )
        .await,
        0
    );
    db.close().await;
}

// ---- guard 2 — schema_config rejects engine-reserved keys (tool 21) ----

#[tokio::test]
async fn rejects_any_user_configuration_of_archived_in_either_direction() {
    let db = create_database(":memory:").await.unwrap();
    let before = count(&db, "SELECT COUNT(*) AS n FROM schema_config").await;
    // "Loosening" direction — making it freely writable.
    let err = write_user_schema_config(
        &db,
        json!({ "shapes": { "Document": { "facets": { "archived": { "values": ["true", "false"] } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .expect_err("loosening")
    .to_string();
    assert!(err.contains("engine-reserved"), "{err}");
    // "Tightening" direction — e.g. making it required — is just as breaking.
    let err = write_user_schema_config(
        &db,
        json!({ "shapes": { "WorkItem": { "facets": { "archived": { "required": true } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .expect_err("tightening")
    .to_string();
    assert!(err.contains("engine-reserved"), "{err}");
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM schema_config").await,
        before
    ); // nothing landed
    db.close().await;
}

#[tokio::test]
async fn accepts_a_user_layer_over_non_reserved_keys_including_spine_facets() {
    let db = create_database(":memory:").await.unwrap();
    let id = write_user_schema_config(
        &db,
        json!({
            "shapes": {
                "Document": { "facets": { "confidence": { "vocabulary": "confidence" } } },
                // Spine facets stay configurable (only LOOSENING is barred — 3057bba;
                // that check lands with the cascade resolver).
                "WorkItem": { "facets": { "lifecycle": { "vocabulary": "lifecycle" } } },
            }
        }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let layer: String = sqlx::query("SELECT layer FROM schema_config WHERE id = ?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get("layer");
    assert_eq!(layer, "user");
    db.close().await;
}

#[tokio::test]
async fn holds_the_guard_on_the_pack_layer_and_on_string_payloads_too() {
    let db = create_database(":memory:").await.unwrap();
    let err = seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "Document": { "facets": { "archived": {} } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .expect_err("pack layer")
    .to_string();
    assert!(err.contains("engine-reserved"), "{err}");
    let err = write_user_schema_config(
        &db,
        r#"{"shapes":{"Outcome":{"facets":{"archived":{}}}}}"#,
        SchemaConfigOptions::default(),
    )
    .await
    .expect_err("string payload")
    .to_string();
    assert!(err.contains("engine-reserved"), "{err}");
    let err = write_user_schema_config(&db, "not json", SchemaConfigOptions::default())
        .await
        .expect_err("invalid json")
        .to_string();
    assert!(err.contains("valid JSON"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn rejects_a_user_write_aimed_at_a_pack_row_id() {
    // The pack layer is seed-only.
    let db = create_database(":memory:").await.unwrap();
    let pack_id = seed_pack_schema_config(
        &db,
        "@test/guarded",
        json!({ "shapes": { "Document": { "facets": { "confidence": {} } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let err = write_user_schema_config(
        &db,
        json!({ "shapes": { "Document": { "facets": { "mood": {} } } } }),
        SchemaConfigOptions {
            id: Some(pack_id.clone()),
            version_lineage: None,
            ..Default::default()
        },
    )
    .await
    .expect_err("pack row write")
    .to_string();
    assert!(err.contains("seed-only"), "{err}");
    let row = sqlx::query("SELECT layer, data FROM schema_config WHERE id = ?")
        .bind(&pack_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("layer"), "pack");
    assert!(row.get::<String, _>("data").contains("confidence")); // untouched
    db.close().await;
}

// ---- guard 3 — archive_record set/unset semantics (tool 9) ----

#[tokio::test]
async fn archives_with_archived_true_restores_by_unsetting_preserving_lifecycle() {
    let db = create_database(":memory:").await.unwrap();
    let rec = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "ship it", "lifecycle": "in_progress" }),
    )
    .await
    .unwrap();
    archive_record(&db, &rec).await.unwrap();

    let value: String =
        sqlx::query("SELECT value FROM facet_values WHERE record_id = ? AND key = 'archived'")
            .bind(&rec)
            .fetch_one(db.pool())
            .await
            .unwrap()
            .get("value");
    assert_eq!(value, "true");

    restore_record(&db, &rec).await.unwrap();
    assert_eq!(
        count(&db, &format!("SELECT COUNT(*) AS n FROM facet_values WHERE record_id = '{rec}' AND key = 'archived'")).await,
        0
    ); // absence IS the restored state

    let lifecycle = crate::common::text_of(
        &db,
        &format!("SELECT lifecycle FROM records WHERE id = '{rec}'"),
        "lifecycle",
    )
    .await;
    assert_eq!(lifecycle.as_deref(), Some("in_progress")); // round trip preserved it
    db.close().await;
}

#[tokio::test]
async fn makes_archived_false_unrepresentable() {
    // The projector rejects it, rolling back the event.
    let db = create_database(":memory:").await.unwrap();
    let rec = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "ship it" }),
    )
    .await
    .unwrap();
    let err = append(
        &db,
        AppendSpec {
            record_id: rec,
            event_type: "facet.set".into(),
            payload: json!({ "key": "archived", "value": "false" }),
            actor: None,
        },
    )
    .await
    .expect_err("must reject")
    .to_string();
    assert!(err.contains("only takes the value 'true'"), "{err}");
    // The rejection rolled back the append — no phantom event in the log.
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM content_events WHERE type = 'facet.set'"
        )
        .await,
        0
    );
    db.close().await;
}

#[tokio::test]
async fn replays_archive_restore_logs_cleanly() {
    let db = create_database(":memory:").await.unwrap();
    let rec = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "ship it", "lifecycle": "done" }),
    )
    .await
    .unwrap();
    archive_record(&db, &rec).await.unwrap();
    restore_record(&db, &rec).await.unwrap();
    archive_record(&db, &rec).await.unwrap();
    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(result.equal);
    db.close().await;
}

// ---- guard 4 — vocab_ref referential integrity, app-layer ----

#[tokio::test]
async fn rejects_a_facet_write_whose_vocab_ref_resolves_to_no_vocabulary() {
    let db = create_database(":memory:").await.unwrap();
    let rec = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "note" }),
    )
    .await
    .unwrap();
    let err = set_facet(
        &db,
        &rec,
        FacetSetPayload {
            key: "mood".into(),
            value: Some("happy".into()),
            vocab_ref: Some("rec:voc:nope".into()),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .expect_err("must reject")
    .to_string();
    assert!(err.contains("does not resolve"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn holds_the_guard_on_the_raw_append_path_too() {
    // Validated inside the write tx.
    let db = create_database(":memory:").await.unwrap();
    let rec = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "note" }),
    )
    .await
    .unwrap();
    let err = append(
        &db,
        AppendSpec {
            record_id: rec,
            event_type: "facet.set".into(),
            payload: json!({ "key": "mood", "value": "happy", "vocab_ref": "rec:voc:nope" }),
            actor: None,
        },
    )
    .await
    .expect_err("must reject")
    .to_string();
    assert!(err.contains("does not resolve"), "{err}");
    // The rejection rolled back the append — no phantom event, no dangling row.
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM content_events WHERE type = 'facet.set'"
        )
        .await,
        0
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM facet_values").await,
        0
    );
    db.close().await;
}

#[tokio::test]
async fn accepts_a_valid_vocab_ref_in_both_bare_and_rec_prefixed_forms() {
    let db = create_database(":memory:").await.unwrap();
    let vid = create_vocabulary(&db, "mood", None).await.unwrap();
    let rec = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "note" }),
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
    set_facet(
        &db,
        &rec,
        FacetSetPayload {
            key: "mood2".into(),
            value: Some("glad".into()),
            vocab_ref: Some(vid.clone()),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let refs: Vec<String> =
        sqlx::query("SELECT vocab_ref FROM facet_values WHERE record_id = ? ORDER BY key")
            .bind(&rec)
            .fetch_all(db.pool())
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get("vocab_ref"))
            .collect();
    assert_eq!(refs, vec![format!("rec:{vid}"), vid]);
    db.close().await;
}
