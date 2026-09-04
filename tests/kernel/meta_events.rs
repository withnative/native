//! The meta tier's authoritative log (decision ba9f97e) — `meta_events`, its
//! fold, and its rebuild-and-diff.
//!
//! The point of these tests is not that the meta log EXISTS but that it is
//! AUTHORITATIVE, which is a claim with teeth in exactly three places:
//!   1. every meta mutation appends (a verb that silently skips the log is the
//!      drift the decision exists to prevent);
//!   2. replaying the log into a fresh database reproduces the tables exactly;
//!   3. the rebuild-and-diff can FAIL — a check that only ever passes is not a
//!      forcing function, and an empty meta log passes trivially.
//!
//! (3) is why the drift tests below write to the projections directly. That is
//! precisely the thing the write API forbids, and simulating it is the only way
//! to prove the conformance check would catch it.

use native_ce::conformance::{rebuild_and_diff_meta, run_conformance};
use native_ce::meta::{
    alias_value, create_vocabulary, delete_value, delete_vocabulary, deprecate_value,
    promote_value, propose_value, read_all_meta_events, reorder_value, seed_pack_schema_config,
    seed_recommended_pack_schema_config, seed_vocabularies, set_gloss, write_user_schema_config,
    SchemaConfigOptions,
};
use native_ce::{apply_schema, open_database, Db};
use serde_json::json;
use sqlx::Row;

async fn db() -> Db {
    // These tests assert exact append sequences and deliberately exercise the
    // first seed, so use the DDL-only constructor rather than startup defaults.
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    db
}

async fn meta_event_count(db: &Db) -> i64 {
    sqlx::query("SELECT COUNT(*) AS n FROM meta_events")
        .fetch_one(db.pool())
        .await
        .expect("count")
        .get("n")
}

async fn types_in_order(db: &Db) -> Vec<String> {
    let mut conn = crate::common::fixture_write_pool(db)
        .await
        .acquire()
        .await
        .unwrap();
    read_all_meta_events(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.event_type)
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Every mutation site appends
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_vocabulary_verb_appends_its_event() {
    let db = db().await;
    let vid = create_vocabulary(&db, "moods", None).await.unwrap();
    let calm = propose_value(&db, &vid, "calm", Some("settled"))
        .await
        .unwrap();
    let serene = propose_value(&db, &vid, "serene", None).await.unwrap();
    promote_value(&db, &calm).await.unwrap();
    promote_value(&db, &serene).await.unwrap();
    reorder_value(&db, &calm, 150.5).await.unwrap();
    deprecate_value(&db, &serene).await.unwrap();
    alias_value(&db, &serene, &calm).await.unwrap();

    assert_eq!(
        types_in_order(&db).await,
        vec![
            "vocabulary.created",
            "vocab_value.proposed",
            "vocab_value.proposed",
            "vocab_value.promoted",
            "vocab_value.promoted",
            "vocab_value.reordered",
            "vocab_value.deprecated",
            "vocab_value.aliased",
        ]
    );
    db.close().await;
}

#[tokio::test]
async fn the_guarded_deletes_append_too() {
    let db = db().await;
    let vid = create_vocabulary(&db, "moods", None).await.unwrap();
    let typo = propose_value(&db, &vid, "clam", None).await.unwrap();
    // Neither seeded nor referenced, so the guard permits the hard delete.
    delete_value(&db, &typo).await.unwrap();
    delete_vocabulary(&db, &vid).await.unwrap();

    let types = types_in_order(&db).await;
    assert_eq!(types.last().unwrap(), "vocabulary.deleted");
    assert!(types.contains(&"vocab_value.deleted".to_string()));
    db.close().await;
}

#[tokio::test]
async fn both_schema_config_layers_append_one_type() {
    let db = db().await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "WorkItem": { "facets": {} } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_user_schema_config(
        &db,
        json!({ "shapes": { "Outcome": { "facets": {} } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        types_in_order(&db).await,
        vec!["schema_config.set", "schema_config.set"]
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// 1b. `set_gloss` — the only writer of `gloss` after proposal
// ---------------------------------------------------------------------------

/// The `(type, payload)` of every meta event, in log order.
async fn typed_payloads(db: &Db) -> Vec<(String, Option<serde_json::Value>)> {
    let mut conn = crate::common::fixture_write_pool(db)
        .await
        .acquire()
        .await
        .unwrap();
    read_all_meta_events(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .map(|e| {
            (
                e.event_type,
                e.payload
                    .as_deref()
                    .map(|p| serde_json::from_str(p).unwrap()),
            )
        })
        .collect()
}

async fn stored_gloss(db: &Db, value_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT gloss FROM vocabulary_values WHERE id = ?")
        .bind(value_id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn set_gloss_appends_exactly_one_gloss_set_event() {
    let db = db().await;
    let vid = create_vocabulary(&db, "moods", None).await.unwrap();
    let calm = propose_value(&db, &vid, "calm", None).await.unwrap();
    let before = meta_event_count(&db).await;

    set_gloss(&db, &calm, Some("settled, without agitation"))
        .await
        .unwrap();

    assert_eq!(meta_event_count(&db).await, before + 1);
    let (event_type, payload) = typed_payloads(&db).await.pop().unwrap();
    assert_eq!(event_type, "vocab_value.gloss_set");
    assert_eq!(
        payload,
        Some(json!({ "gloss": "settled, without agitation" }))
    );
    assert_eq!(
        stored_gloss(&db, &calm).await.as_deref(),
        Some("settled, without agitation")
    );
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn an_unglossed_seeded_value_can_be_glossed_after_the_fact() {
    // Lifecycle values ship with definitions; other seeded rows may still be
    // bare, and must not be a distinct class the amendment path refuses.
    let db = db().await;
    seed_vocabularies(&db).await.unwrap();
    let open = "vv:voc:maturity:exploratory";
    assert_eq!(
        stored_gloss(&db, open).await,
        None,
        "seeded rows start bare"
    );
    let before = meta_event_count(&db).await;

    set_gloss(&db, open, Some("Not yet started."))
        .await
        .unwrap();

    assert_eq!(meta_event_count(&db).await, before + 1);
    assert_eq!(
        stored_gloss(&db, open).await.as_deref(),
        Some("Not yet started.")
    );
    let result = rebuild_and_diff_meta(&db).await.unwrap();
    assert!(result.equal, "meta drift: {:?}", result.tables);
    db.close().await;
}

#[tokio::test]
async fn lifecycle_seed_glosses_backfill_blanks_once_and_preserve_amendments() {
    let db = db().await;
    seed_vocabularies(&db).await.unwrap();
    let open = "vv:voc:lifecycle:open";
    let blocked = "vv:voc:lifecycle:blocked";

    assert_eq!(
        stored_gloss(&db, open).await.as_deref(),
        Some("Work is available but has not started.")
    );

    // Model an old projection whose seeded rows predate built-in glosses.
    sqlx::query("UPDATE vocabulary_values SET gloss = NULL WHERE id = ?")
        .bind(open)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query("UPDATE vocabulary_values SET gloss = '   ' WHERE id = ?")
        .bind(blocked)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let before_backfill = meta_event_count(&db).await;
    seed_vocabularies(&db).await.unwrap();
    assert_eq!(meta_event_count(&db).await, before_backfill + 2);
    assert_eq!(
        stored_gloss(&db, open).await.as_deref(),
        Some("Work is available but has not started.")
    );
    assert_eq!(
        stored_gloss(&db, blocked).await.as_deref(),
        Some("Work cannot currently proceed because of an impediment.")
    );

    // Reopening/reseeding is a no-op after the backfill, and a nonblank local
    // amendment remains authoritative rather than being reset by the pack.
    let after_backfill = meta_event_count(&db).await;
    seed_vocabularies(&db).await.unwrap();
    assert_eq!(meta_event_count(&db).await, after_backfill);
    set_gloss(&db, open, Some("Locally clarified wording."))
        .await
        .unwrap();
    let after_amendment = meta_event_count(&db).await;
    seed_vocabularies(&db).await.unwrap();
    assert_eq!(meta_event_count(&db).await, after_amendment);
    assert_eq!(
        stored_gloss(&db, open).await.as_deref(),
        Some("Locally clarified wording.")
    );
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn the_last_gloss_wins_and_none_clears_it() {
    let db = db().await;
    let vid = create_vocabulary(&db, "moods", None).await.unwrap();
    let calm = propose_value(&db, &vid, "calm", Some("first"))
        .await
        .unwrap();

    set_gloss(&db, &calm, Some("second")).await.unwrap();
    set_gloss(&db, &calm, Some("third")).await.unwrap();
    assert_eq!(stored_gloss(&db, &calm).await.as_deref(), Some("third"));

    set_gloss(&db, &calm, None).await.unwrap();
    assert_eq!(stored_gloss(&db, &calm).await, None);

    let types = types_in_order(&db).await;
    assert_eq!(
        types
            .iter()
            .filter(|t| *t == "vocab_value.gloss_set")
            .count(),
        3
    );
    let (_, last) = typed_payloads(&db).await.pop().unwrap();
    assert_eq!(last, Some(json!({ "gloss": serde_json::Value::Null })));
    // Clearing must replay as a clear, not as "leave whatever is there".
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn set_gloss_on_an_unknown_value_appends_nothing() {
    let db = db().await;
    create_vocabulary(&db, "moods", None).await.unwrap();
    let before = meta_event_count(&db).await;

    let error = set_gloss(&db, "vv:voc:moods:absent", Some("nothing to define"))
        .await
        .unwrap_err();

    assert_eq!(meta_event_count(&db).await, before, "{error}");
    db.close().await;
}

// ---------------------------------------------------------------------------
// 2. Seeding is idempotent IN THE LOG, not just in the tables
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reseeding_appends_nothing() {
    let db = db().await;
    seed_vocabularies(&db).await.unwrap();
    let after_first = meta_event_count(&db).await;
    assert!(after_first > 0, "the first seed must record itself");

    // `seed_vocabularies` is designed to run on every open. If it appended
    // unconditionally, the log would grow forever while nothing changed — and
    // rebuild-and-diff would keep passing, so nothing would ever surface it.
    seed_vocabularies(&db).await.unwrap();
    seed_vocabularies(&db).await.unwrap();
    assert_eq!(meta_event_count(&db).await, after_first);

    db.close().await;
}

#[tokio::test]
async fn reseeding_a_pack_schema_config_appends_nothing() {
    let db = db().await;
    let opts = || SchemaConfigOptions::default();
    let data = || json!({ "shapes": { "WorkItem": { "facets": {} } } });
    seed_pack_schema_config(&db, "@native/recommended", data(), opts())
        .await
        .unwrap();
    let after_first = meta_event_count(&db).await;
    seed_pack_schema_config(&db, "@native/recommended", data(), opts())
        .await
        .unwrap();
    assert_eq!(meta_event_count(&db).await, after_first);
    db.close().await;
}

#[tokio::test]
async fn a_changed_engine_pack_appends_one_upgrade_then_becomes_idempotent() {
    let db = db().await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "Document:definition": { "facets": {} } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let before = meta_event_count(&db).await;
    seed_recommended_pack_schema_config(&db).await.unwrap();
    assert_eq!(meta_event_count(&db).await, before + 1);
    seed_recommended_pack_schema_config(&db).await.unwrap();
    assert_eq!(meta_event_count(&db).await, before + 1);
    let data: String =
        sqlx::query_scalar("SELECT data FROM schema_config WHERE id = 'pack:@native/recommended'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let data: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(
        data["shapes"]["Message"]["facets"]["expectation"],
        json!({ "vocab_ref": "message-expectation", "required": true })
    );
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
}

// ---------------------------------------------------------------------------
// 3. Replay reproduces the tier
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_full_lifecycle_rebuilds_exactly() {
    let db = db().await;
    seed_vocabularies(&db).await.unwrap();
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "WorkItem": { "facets": {} } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let vid = create_vocabulary(&db, "moods", None).await.unwrap();
    let calm = propose_value(&db, &vid, "calm", Some("settled"))
        .await
        .unwrap();
    let serene = propose_value(&db, &vid, "serene", None).await.unwrap();
    promote_value(&db, &calm).await.unwrap();
    alias_value(&db, &serene, &calm).await.unwrap();
    // A gloss written after the fact — on an active value and on a seeded one —
    // must be reproduced by the fold, not just by the live write.
    set_gloss(&db, &calm, Some("settled, without agitation"))
        .await
        .unwrap();
    set_gloss(&db, "vv:voc:lifecycle:open", Some("Not yet started."))
        .await
        .unwrap();
    write_user_schema_config(
        &db,
        json!({ "shapes": { "Outcome": { "facets": {} } } }),
        SchemaConfigOptions {
            version_lineage: Some("v1".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let result = rebuild_and_diff_meta(&db).await.unwrap();
    assert!(result.equal, "meta drift: {:?}", result.tables);
    // Guard against the check passing because it compared nothing.
    assert!(result.event_count >= 6);
    for table in ["vocabularies", "vocabulary_values", "schema_config"] {
        let t = result.tables.iter().find(|t| t.table == table).unwrap();
        assert!(t.live > 0, "{table} was empty — the check proved nothing");
    }
    db.close().await;
}

#[tokio::test]
async fn deleting_a_vocabulary_rebuilds_its_cascade() {
    // The fold deletes the parent and lets the FK cascade take the values, the
    // same way the live path does. If the two ever disagreed, this diff is where
    // it would show.
    let db = db().await;
    let vid = create_vocabulary(&db, "moods", None).await.unwrap();
    propose_value(&db, &vid, "calm", None).await.unwrap();
    propose_value(&db, &vid, "serene", None).await.unwrap();
    delete_vocabulary(&db, &vid).await.unwrap();

    let values: i64 = sqlx::query("SELECT COUNT(*) AS n FROM vocabulary_values")
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get("n");
    assert_eq!(values, 0, "the live delete should cascade");

    let result = rebuild_and_diff_meta(&db).await.unwrap();
    assert!(result.equal, "meta drift: {:?}", result.tables);
    db.close().await;
}

// ---------------------------------------------------------------------------
// 4. The check can FAIL — otherwise it is decoration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meta_rebuild_catches_a_row_written_behind_the_log() {
    let db = db().await;
    create_vocabulary(&db, "moods", None).await.unwrap();

    // Exactly what the write API forbids: a direct write to a projection. This
    // is the corruption an advisory log could never surface, and the reason the
    // meta log had to be authoritative rather than a side-channel changelog.
    sqlx::query("INSERT INTO vocabularies (id, name, created_at) VALUES ('voc:ghost', 'ghost', '2026-01-01T00:00:00.000Z')")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let result = rebuild_and_diff_meta(&db).await.unwrap();
    assert!(!result.equal, "drift went undetected");
    let vocabs = result
        .tables
        .iter()
        .find(|t| t.table == "vocabularies")
        .unwrap();
    assert_eq!(vocabs.live, 2);
    assert_eq!(vocabs.rebuilt, 1);

    // And it must surface through the suite, not only the harness.
    let report = run_conformance(&db).await;
    assert!(!report.ok);
    let check = report
        .checks
        .iter()
        .find(|c| c.check == "rebuild-and-diff-meta")
        .unwrap();
    assert!(!check.ok);
    assert!(check.violations.join("\n").contains("vocabularies"));

    db.close().await;
}

#[tokio::test]
async fn meta_drift_does_not_fail_the_content_check_and_vice_versa() {
    // The tiers are checked independently on purpose: a shared pass/fail signal
    // would let one tier's drift hide behind the other being green.
    let db = db().await;
    create_vocabulary(&db, "moods", None).await.unwrap();
    sqlx::query("INSERT INTO vocabularies (id, name, created_at) VALUES ('voc:ghost', 'ghost', '2026-01-01T00:00:00.000Z')")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let report = run_conformance(&db).await;
    let content = report
        .checks
        .iter()
        .find(|c| c.check == "rebuild-and-diff")
        .unwrap();
    let meta = report
        .checks
        .iter()
        .find(|c| c.check == "rebuild-and-diff-meta")
        .unwrap();
    assert!(
        content.ok,
        "content tier should be unaffected by meta drift"
    );
    assert!(!meta.ok);
    db.close().await;
}

#[tokio::test]
async fn an_unknown_meta_event_type_is_refused_by_the_fold() {
    // The meta fold is closed the same way the content fold is: an unrecognised
    // type must break replay loudly rather than be skipped, or the log would
    // stop being the law for anything it happened not to understand.
    let db = db().await;
    sqlx::query(
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at)
          VALUES ('m1', 'voc:moods', 'vocabulary.renamed', '{}', NULL, '2026-01-01T00:00:00.000Z')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let err = rebuild_and_diff_meta(&db).await.unwrap_err().to_string();
    assert!(
        err.contains("unknown meta event type"),
        "unexpected error: {err}"
    );

    let report = run_conformance(&db).await;
    let meta = report
        .checks
        .iter()
        .find(|c| c.check == "rebuild-and-diff-meta")
        .unwrap();
    assert!(!meta.ok);
    assert!(meta.violations.join("\n").contains("could not be replayed"));
    db.close().await;
}

#[tokio::test]
async fn a_meta_event_against_a_missing_subject_is_refused() {
    let db = db().await;
    sqlx::query(
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at)
          VALUES ('m1', 'vv:nope', 'vocab_value.promoted', '{}', NULL, '2026-01-01T00:00:00.000Z')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let err = rebuild_and_diff_meta(&db).await.unwrap_err().to_string();
    assert!(err.contains("matched no row"), "unexpected error: {err}");
    db.close().await;
}

#[tokio::test]
async fn a_phantom_vocabulary_delete_fails_rebuild_and_conformance() {
    let db = db().await;
    sqlx::query(
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at)
          VALUES ('m1', 'voc:nope', 'vocabulary.deleted', '{}', NULL, '2026-01-01T00:00:00.000Z')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let err = rebuild_and_diff_meta(&db).await.unwrap_err().to_string();
    assert!(err.contains("matched no row"), "unexpected error: {err}");

    let report = run_conformance(&db).await;
    let meta = report
        .checks
        .iter()
        .find(|c| c.check == "rebuild-and-diff-meta")
        .unwrap();
    assert!(!meta.ok);
    assert!(meta.violations.join("\n").contains("could not be replayed"));
    db.close().await;
}

// ---------------------------------------------------------------------------
// 5. The guards still hold — and still leave no event behind when they reject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_mutation_appends_no_event() {
    let db = db().await;
    seed_vocabularies(&db).await.unwrap();
    let before = meta_event_count(&db).await;

    // Seeded values are contract — the guard rejects the hard delete.
    let err = delete_value(&db, "vv:voc:maturity:decided")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("seeded"), "{err}");

    // The rejection must roll back cleanly. An authoritative log that recorded
    // writes which never happened would be worse than no log at all.
    assert_eq!(meta_event_count(&db).await, before);
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn the_pack_layer_guard_survives_the_move_to_append_then_fold() {
    // This guard used to ride on the upsert's `ON CONFLICT ... WHERE layer =
    // 'user'`. Moving the write into the fold meant re-expressing it as an
    // explicit pre-append check, so it is worth proving it still bites.
    let db = db().await;
    let pack_id = seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "WorkItem": { "facets": {} } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let before = meta_event_count(&db).await;

    let err = write_user_schema_config(
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {} } } }),
        SchemaConfigOptions {
            id: Some(pack_id.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("pack layer"), "{err}");
    assert_eq!(meta_event_count(&db).await, before);

    // And the pack row is untouched.
    let layer: String = sqlx::query_scalar("SELECT layer FROM schema_config WHERE id = ?")
        .bind(&pack_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(layer, "pack");
    db.close().await;
}

#[tokio::test]
async fn a_user_schema_config_row_can_still_be_rewritten_in_place() {
    let db = db().await;
    let id = write_user_schema_config(
        &db,
        json!({ "shapes": { "Outcome": { "facets": {} } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_user_schema_config(
        &db,
        json!({ "shapes": { "WorkItem": { "facets": {} } } }),
        SchemaConfigOptions {
            id: Some(id.clone()),
            version_lineage: Some("v2".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let rows: i64 = sqlx::query("SELECT COUNT(*) AS n FROM schema_config")
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get("n");
    assert_eq!(rows, 1, "the second write should update, not insert");
    let lineage: Option<String> =
        sqlx::query_scalar("SELECT version_lineage FROM schema_config WHERE id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(lineage.as_deref(), Some("v2"));
    // Two events, one row — the log carries the history the table cannot.
    assert_eq!(meta_event_count(&db).await, 2);
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
    db.close().await;
}
