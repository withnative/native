//! The schema stands up on a real SQLite file (WAL, FK), enforces the frozen
//! constraints, and keeps the export-fidelity seam.

use native_ce::{apply_schema, create_database, open_database, open_existing_database};
use sqlx::Row;

#[tokio::test]
async fn applies_cleanly_in_wal_mode_and_creates_every_table() {
    let dir = tempfile::Builder::new()
        .prefix("native-ce-")
        .tempdir()
        .unwrap();
    let path = dir.path().join("native.db");
    let client = open_database(&path.to_string_lossy()).await.unwrap();

    let jm: String = sqlx::query("PRAGMA journal_mode")
        .fetch_one(client.pool())
        .await
        .unwrap()
        .get("journal_mode");
    assert_eq!(jm.to_lowercase(), "wal");

    apply_schema(&client).await.unwrap();

    let rows = sqlx::query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .fetch_all(client.pool())
        .await
        .unwrap();
    let names: Vec<String> = rows.into_iter().map(|r| r.get("name")).collect();
    for t in [
        "content_events",
        "content_event_causal_frontier",
        "content_event_causal_cutover",
        "content_event_sources",
        "policy_events",
        "control_events",
        "derivation_events",
        "derivation_series",
        "derivation_revisions",
        "derivation_revision_inputs",
        "derivation_attempts",
        "derivation_target_bindings",
        "derivation_target_publications",
        "derivation_selected_publications",
        "derivation_target_heads",
        "derivation_event_applications",
        "derivation_requests",
        "derivation_artifact_role_assignments",
        "derivation_artifact_role_retirements",
        "derivation_artifact_role_heads",
        "derivation_revision_confirmations",
        "derivation_confirmation_retractions",
        "derivation_confirmation_heads",
        "recipe_releases",
        "recipe_release_input_classes",
        "meta_events",
        "records",
        "links",
        "facet_values",
        "facet_observations",
        "bindings",
        "binding_systems",
        "binding_audit",
        "external_observations",
        "database_identity",
        "database_identity_audit",
        "blobs",
        "embeddings",
        "vocabularies",
        "vocabulary_values",
        "schema_config",
        "jobs",
        "member_contexts",
        "instruction_bindings",
        "onboarding_programmes",
        "onboarding_programme_sources",
        "member_obligations",
        "seeded_instruction_sources",
        "control_event_applications",
    ] {
        assert!(names.iter().any(|n| n == t), "missing table {t}");
    }

    // The on-disk file physically exists (this is the representative artifact the
    // export-fidelity check consumes).
    assert!(std::fs::metadata(&path).unwrap().is_file());
    client.close().await;
}

#[tokio::test]
async fn active_derivation_role_lookup_has_a_pinned_partial_index() {
    let client = create_database(":memory:").await.unwrap();
    let index_sql: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_schema
          WHERE type='index' AND name='idx_derivation_artifact_role_heads_active_role'",
    )
    .fetch_one(client.pool())
    .await
    .unwrap();
    assert!(index_sql.contains("role,target_record_id,target_slot,active_assignment_id"));
    assert!(index_sql.contains("WHERE active_assignment_id IS NOT NULL"));

    let plan = sqlx::query(
        "EXPLAIN QUERY PLAN
         SELECT active_assignment_id
           FROM derivation_artifact_role_heads
                INDEXED BY idx_derivation_artifact_role_heads_active_role
          WHERE role='change_summary' AND active_assignment_id IS NOT NULL",
    )
    .fetch_all(client.pool())
    .await
    .unwrap();
    assert!(plan.iter().any(|row| {
        row.get::<String, _>("detail")
            .contains("idx_derivation_artifact_role_heads_active_role")
    }));
}

#[tokio::test]
async fn fresh_and_reopened_databases_install_defaults_without_duplicate_meta_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("native.db");
    let url = path.to_string_lossy();

    let db = create_database(&url).await.unwrap();
    let core_kind_vocabularies: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vocabularies WHERE name LIKE 'kind:%'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        core_kind_vocabularies,
        native_ce::schema::SPINE_TYPES.len() as i64
    );

    let governed_core_kinds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vocabulary_values
          WHERE vocabulary_id LIKE 'voc:kind:%' AND status = 'active'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(governed_core_kinds > 0);

    let recommended_pack: (String, String) = sqlx::query_as(
        "SELECT layer, name FROM schema_config WHERE id = 'pack:@native/recommended'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        recommended_pack,
        ("pack".into(), "@native/recommended".into())
    );

    let after_create: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(after_create > 0);
    db.close().await;

    for _ in 0..2 {
        let reopened = open_existing_database(&url).await.unwrap();
        let after_reopen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(after_reopen, after_create);
        reopened.close().await;
    }
}

#[tokio::test]
async fn enforces_the_closed_spine_type_check() {
    let client = create_database(":memory:").await.unwrap();
    // A new top-level type is unrepresentable.
    assert!(
        sqlx::query("INSERT INTO records (id, type) VALUES ('x', 'Recipe')")
            .execute(&crate::common::fixture_write_pool(&client).await)
            .await
            .is_err()
    );
    // ...and the ninth spine type is accepted.
    sqlx::query("INSERT INTO records (id, type) VALUES ('ok', 'Annotation')")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    client.close().await;
}

#[tokio::test]
async fn vocabulary_value_progression_metadata_has_safe_defaults_and_closed_terminality() {
    let client = create_database(":memory:").await.unwrap();
    sqlx::query("INSERT INTO vocabularies (id, name) VALUES ('voc:test', 'test')")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO vocabulary_values (id, vocabulary_id, value) \
         VALUES ('vv:test', 'voc:test', 'backlog')",
    )
    .execute(&crate::common::fixture_write_pool(&client).await)
    .await
    .unwrap();
    let row =
        sqlx::query("SELECT ordinal, terminality FROM vocabulary_values WHERE id = 'vv:test'")
            .fetch_one(client.pool())
            .await
            .unwrap();
    assert_eq!(row.get::<f64, _>("ordinal"), 0.0);
    assert_eq!(row.get::<String, _>("terminality"), "open");
    assert!(sqlx::query(
        "UPDATE vocabulary_values SET terminality = 'maybe_done' WHERE id = 'vv:test'",
    )
    .execute(&crate::common::fixture_write_pool(&client).await)
    .await
    .is_err());
    client.close().await;
}

#[tokio::test]
async fn bindings_enforce_external_identity_and_one_canonical_per_system() {
    let client = create_database(":memory:").await.unwrap();
    for id in ["a", "b"] {
        sqlx::query("INSERT INTO records (id, type) VALUES (?, 'Document')")
            .bind(id)
            .execute(&crate::common::fixture_write_pool(&client).await)
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES ('a', 'github', 'node:1', 1)",
    )
    .execute(&crate::common::fixture_write_pool(&client).await)
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier)
             VALUES ('b', 'github', 'node:1')"
        )
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .is_err(),
        "one external identity cannot bind to two records"
    );
    assert!(
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES ('a', 'github', 'node:2', 1)"
        )
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .is_err(),
        "one record cannot have two canonical ids for the same system"
    );
    client.close().await;
}

#[tokio::test]
async fn enforces_the_persistence_enum_defaults_and_rejects_null() {
    let client = create_database(":memory:").await.unwrap();
    // Invalid enum value rejected.
    assert!(sqlx::query(
        "INSERT INTO records (id, type, persistence) VALUES ('p', 'Entity', 'sometimes')"
    )
    .execute(&crate::common::fixture_write_pool(&client).await)
    .await
    .is_err());
    // Explicit NULL rejected (non-null).
    assert!(sqlx::query(
        "INSERT INTO records (id, type, persistence) VALUES ('n', 'Entity', NULL)"
    )
    .execute(&crate::common::fixture_write_pool(&client).await)
    .await
    .is_err());
    // Omitted -> defaults to 'enduring'.
    sqlx::query("INSERT INTO records (id, type) VALUES ('d', 'Document')")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    let persistence = crate::common::text_of(
        &client,
        "SELECT persistence FROM records WHERE id = 'd'",
        "persistence",
    )
    .await;
    assert_eq!(persistence.as_deref(), Some("enduring"));
    client.close().await;
}

#[tokio::test]
async fn keeps_embeddings_vector_a_plain_blob() {
    let client = create_database(":memory:").await.unwrap();
    let cols = sqlx::query("PRAGMA table_info(embeddings)")
        .fetch_all(client.pool())
        .await
        .unwrap();
    let vector = cols
        .iter()
        .find(|r| r.get::<String, _>("name") == "vector")
        .expect("embeddings.vector column exists");
    assert_eq!(vector.get::<String, _>("type").to_uppercase(), "BLOB");
    client.close().await;
}
