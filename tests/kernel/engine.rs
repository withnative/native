//! Event-authoritative engine over representative data on a real file:
//! projections, unicode/blob round-trips, FTS5, and rebuild-and-diff.

use native_ce::conformance::rebuild_and_diff;
use native_ce::events::{FacetSetPayload, LinkAddedPayload, LinkRemovedPayload};
use native_ce::store::{
    add_link, create_record, delete_record, remove_link, set_facet, unset_facet, update_record,
};
use native_ce::{create_database, open_database, Db};
use serde_json::json;
use sqlx::Row;

fn facet(key: &str, value: &str) -> FacetSetPayload {
    FacetSetPayload {
        key: key.into(),
        value: Some(value.into()),
        vocab_ref: None,
        as_of: None,
        observation_only: false,
    }
}

fn link(source: &str, target: &str, relationship: &str, note: Option<&str>) -> LinkAddedPayload {
    LinkAddedPayload {
        id: None,
        source_id: source.into(),
        target_id: target.into(),
        relationship: relationship.into(),
        note: note.map(String::from),
    }
}

fn blob_payload() -> Vec<u8> {
    let mut payload = "日本語 ✍️".as_bytes().to_vec();
    payload.extend([0, 1, 2, 255, 254]);
    payload
}

/// Seed a representative portable workspace: records + events + links, with
/// unicode content and an inline blob. Exercises every event type and both facet
/// paths (spine facet -> column, open facet -> facet_values row).
async fn seed_representative(db: &Db) -> String {
    // Entity (owner) — unicode name. Must exist before anything references it (FK).
    let ada = create_record(
        db,
        json!({ "type": "Entity", "kind": "person", "name": "Ada Lovelace 💻" }),
    )
    .await
    .unwrap();

    // Folder acting as the task's canonical browse home.
    let project = create_record(
        db,
        json!({ "type": "Collection", "kind": "folder", "name": "Analytical Engine — programme" }),
    )
    .await
    .unwrap();

    let goal = create_record(
        db,
        json!({ "type": "Outcome", "kind": "target", "name": "Compute Bernoulli numbers" }),
    )
    .await
    .unwrap();

    let task = create_record(
        db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Punch the cards", "home_id": project }),
    )
    .await
    .unwrap();

    let doc = create_record(
        db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Note G — 日本語 test ✍️",
            "body": "The analytical engine weaves algebraic patterns — Bernoulli, loops, ✅.",
        }),
    )
    .await
    .unwrap();

    // Spine facets -> columns on records.
    set_facet(db, &task, facet("lifecycle", "in_progress"))
        .await
        .unwrap();
    set_facet(db, &task, facet("owner", &ada)).await.unwrap(); // owner -> owner_id column (FK)
    set_facet(db, &doc, facet("persistence", "enduring"))
        .await
        .unwrap();
    set_facet(db, &doc, facet("maturity", "candidate"))
        .await
        .unwrap();

    // Open / pack facets -> facet_values rows (anti-preamble fields). A
    // vocab-governed facet needs its vocabulary to exist first — set_facet
    // validates vocab_ref app-layer (no FK in the frozen DDL).
    set_facet(db, &doc, facet("provenance", "drafted with Ada, 1843"))
        .await
        .unwrap();
    set_facet(
        db,
        &doc,
        FacetSetPayload {
            key: "confidence".into(),
            value: Some("confident".into()),
            vocab_ref: Some("rec:voc:confidence".into()),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    // Set-then-change a facet (exercises the upsert path).
    set_facet(db, &task, facet("confidence", "tentative"))
        .await
        .unwrap();
    set_facet(db, &task, facet("confidence", "likely"))
        .await
        .unwrap();

    // Links (spine relationships).
    add_link(db, link(&task, &goal, "part_of", None))
        .await
        .unwrap();
    add_link(db, link(&task, &doc, "mentions", Some("need Note G first")))
        .await
        .unwrap();
    add_link(db, link(&goal, &ada, "renders", None))
        .await
        .unwrap();

    // Mutations: update, unset, remove-link, and a create+soft-delete.
    update_record(
        db,
        &doc,
        json!({ "summary": "The first published algorithm." }),
    )
    .await
    .unwrap();
    unset_facet(db, &task, "confidence").await.unwrap();
    remove_link(
        db,
        LinkRemovedPayload {
            source_id: goal.clone(),
            target_id: ada.clone(),
            relationship: "renders".into(),
        },
    )
    .await
    .unwrap();

    let throwaway = create_record(
        db,
        json!({ "type": "WorkItem", "kind": "task", "name": "obsolete" }),
    )
    .await
    .unwrap();
    delete_record(db, &throwaway).await.unwrap();

    // A blob (5th substrate primitive) — bytes-in-file, binary + unicode payload.
    let payload = blob_payload();
    sqlx::query(
        "INSERT INTO blobs (id, bytes, mime, size_bytes, original_filename, storage_tier)
          VALUES (?, ?, ?, ?, ?, 'inline')",
    )
    .bind("blob-1")
    .bind(&payload)
    .bind("application/octet-stream")
    .bind(payload.len() as i64)
    .bind("note-g.bin")
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();

    doc
}

async fn file_backed_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::Builder::new()
        .prefix("native-ce-")
        .tempdir()
        .unwrap();
    let db = create_database(&dir.path().join("native.db").to_string_lossy())
        .await
        .unwrap();
    (dir, db)
}

#[tokio::test]
async fn projects_records_links_and_facets_from_the_event_log() {
    let (_dir, db) = file_backed_db().await;
    seed_representative(&db).await;

    // ada, project, goal, task, doc (throwaway soft-deleted)
    assert_eq!(
        crate::common::count(
            &db,
            "SELECT COUNT(*) n FROM records WHERE deleted_at IS NULL"
        )
        .await,
        7
    );

    // Spine facet landed on the column, not in facet_values.
    let task =
        sqlx::query("SELECT lifecycle, owner_id FROM records WHERE name = 'Punch the cards'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        task.get::<Option<String>, _>("lifecycle").as_deref(),
        Some("in_progress")
    );
    assert!(task.get::<Option<String>, _>("owner_id").is_some());

    // Open facet landed in facet_values; spine facet did NOT.
    let keys: Vec<String> = sqlx::query("SELECT DISTINCT key FROM facet_values ORDER BY key")
        .fetch_all(db.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.get("key"))
        .collect();
    assert!(keys.contains(&"provenance".to_string()));
    assert!(keys.contains(&"confidence".to_string()));
    assert!(!keys.contains(&"lifecycle".to_string()));
    assert!(!keys.contains(&"owner".to_string()));

    // unset removed the task's confidence facet; the doc's remains.
    assert_eq!(
        crate::common::count(
            &db,
            "SELECT COUNT(*) n FROM facet_values WHERE key = 'confidence'"
        )
        .await,
        1
    );

    // Links: part_of + mentions remain; renders was removed.
    let relationships: Vec<String> =
        sqlx::query("SELECT relationship FROM links ORDER BY relationship")
            .fetch_all(db.pool())
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get("relationship"))
            .collect();
    assert_eq!(
        relationships,
        vec!["mentions".to_string(), "part_of".to_string()]
    );

    // Soft-deleted record still present but stamped.
    let gone = crate::common::text_of(
        &db,
        "SELECT deleted_at FROM records WHERE name = 'obsolete'",
        "deleted_at",
    )
    .await;
    assert!(gone.is_some());
    db.close().await;
}

#[tokio::test]
async fn round_trips_unicode_bodies_and_binary_blobs() {
    let (_dir, db) = file_backed_db().await;
    seed_representative(&db).await;

    let doc = sqlx::query("SELECT name, body FROM records WHERE type = 'Document'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(doc.get::<String, _>("name").contains("日本語"));
    assert!(doc.get::<Option<String>, _>("body").unwrap().contains("✅"));

    let blob = sqlx::query("SELECT bytes, size_bytes FROM blobs WHERE id = 'blob-1'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let expected = blob_payload();
    assert_eq!(blob.get::<Vec<u8>, _>("bytes"), expected);
    assert_eq!(blob.get::<i64, _>("size_bytes"), expected.len() as i64);
    db.close().await;
}

#[tokio::test]
async fn indexes_records_in_fts5() {
    let (_dir, db) = file_backed_db().await;
    seed_representative(&db).await;
    let hits = sqlx::query("SELECT rowid FROM records_fts WHERE records_fts MATCH ?")
        .bind("analytical")
        .fetch_all(db.pool())
        .await
        .unwrap();
    assert!(!hits.is_empty());
    db.close().await;
}

/// STEMMING (06c105b) — `records_fts` is built with `tokenize='porter unicode61'`,
/// so the stemmer is applied to index and query alike: the query `meetings` finds
/// a record named `meeting`. FAILS on the pre-re-freeze DDL, where the default
/// `unicode61` tokenizer stores tokens as written and the two are unrelated
/// strings.
#[tokio::test]
async fn stems_the_index_so_meetings_matches_meeting() {
    let (_dir, db) = file_backed_db().await;
    create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "meeting", "body": "quarterly planning" }),
    )
    .await
    .unwrap();

    for query in ["meetings", "meeting", "planned"] {
        let hits = sqlx::query("SELECT rowid FROM records_fts WHERE records_fts MATCH ?")
            .bind(query)
            .fetch_all(db.pool())
            .await
            .unwrap();
        assert_eq!(
            hits.len(),
            1,
            "porter should collapse '{query}' onto the stored stem"
        );
    }
    db.close().await;
}

/// THE PREFIX REPAIR (3c40677) — porter stores `running` as the stem `run`, so
/// `runni*` cannot match it. The unstemmed `unicode61` sibling over `name`
/// exists precisely to close that regression. FAILS without the sibling table
/// (no such table), and the first assertion pins WHY it is needed: the stemmed
/// index really does return 0 for the same query.
#[tokio::test]
async fn the_unstemmed_sibling_matches_a_stem_truncated_prefix() {
    let (_dir, db) = file_backed_db().await;
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "running" }),
    )
    .await
    .unwrap();

    // The regression, asserted rather than assumed.
    let stemmed = sqlx::query("SELECT rowid FROM records_fts WHERE records_fts MATCH ?")
        .bind("runni*")
        .fetch_all(db.pool())
        .await
        .unwrap();
    assert!(
        stemmed.is_empty(),
        "porter stores the stem 'run', so 'runni*' must not match — if this passes, \
         the tokenizer is not porter and the re-freeze did not land"
    );

    // The repair.
    let unstemmed =
        sqlx::query("SELECT rowid FROM records_name_idx WHERE records_name_idx MATCH ?")
            .bind("runni*")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        unstemmed.len(),
        1,
        "the unstemmed unicode61 sibling must recover the stem-truncated prefix"
    );
    db.close().await;
}

/// THE VERSION MARKER (7d61dd1) — a freshly created database reports
/// `PRAGMA user_version` = the current engine schema, and the value survives
/// `VACUUM INTO`, so an
/// exported file stays self-describing rather than becoming anonymous.
#[tokio::test]
async fn stamps_current_user_version_and_survives_vacuum_into() {
    let (dir, db) = file_backed_db().await;
    seed_representative(&db).await;

    let version: i64 = sqlx::query("PRAGMA user_version")
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        version,
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
        "a fresh database must be stamped with the current user_version"
    );

    // The export path: VACUUM INTO a new file, then reopen it standalone.
    let exported = dir.path().join("exported.db");
    sqlx::query(&format!(
        "VACUUM INTO '{}'",
        exported.to_string_lossy().replace('\'', "''")
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    db.close().await;

    let copy = open_database(&exported.to_string_lossy()).await.unwrap();
    let exported_version: i64 = sqlx::query("PRAGMA user_version")
        .fetch_one(copy.pool())
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        exported_version,
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
        "user_version must survive VACUUM INTO — an exported brain stays self-describing"
    );
    copy.close().await;
}

#[tokio::test]
async fn rebuild_and_diff_passes_replayed_projections_equal_live() {
    let (_dir, db) = file_backed_db().await;
    seed_representative(&db).await;
    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(
        result.equal,
        "rebuild drift: {}",
        serde_json::to_string_pretty(&result.tables).unwrap()
    );
    assert!(result.event_count > 0);
    // Sanity: two engine filing records + five live + one soft-deleted.
    let records = result.tables.iter().find(|t| t.table == "records").unwrap();
    assert_eq!(records.live, 8);
    db.close().await;
}

#[tokio::test]
async fn rebuild_and_diff_detects_drift_from_an_ad_hoc_update() {
    let (_dir, db) = file_backed_db().await;
    seed_representative(&db).await;
    // Corrupt a projection directly — exactly what the event-authoritative model forbids.
    sqlx::query("UPDATE records SET name = 'TAMPERED' WHERE type = 'Outcome'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(!result.equal);
    let records = result.tables.iter().find(|t| t.table == "records").unwrap();
    assert!(!records.mismatches.is_empty());
    db.close().await;
}

#[tokio::test]
async fn rebuild_and_diff_is_equal_on_a_fresh_seeded_database() {
    let db = create_database(":memory:").await.unwrap();
    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(result.equal);
    assert_eq!(result.event_count, 2);
    db.close().await;
}
