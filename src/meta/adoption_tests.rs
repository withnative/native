//! Gated adoption tests (E1 test-only prototype), re-fixtured on
//! synthetic families. Nothing here touches `resolution_*`, `ontology_*`, or
//! the canonical interchange (deferred per D-c). Equality-with-log assertions
//! use the kernel-local rebuild helper: production `rebuild_and_diff_meta`
//! is untouched and its fresh database has no registry tables.

use crate::db::{begin_write, create_database, Db};
use crate::definition_registry::{
    ensure_registry_tables, install_definition_artifact, install_definition_artifact_in,
    read_definition_artifact, rebuild_and_diff_kernel_tables,
};
use crate::error::Result;
use crate::meta::adoption::{append_definition_adoption_in, read_definition_adoption_on};
use crate::meta::definition_artifact::RevisionIdentity;
use crate::meta::log::{append_meta_in, MetaAppendSpec};

async fn test_db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    ensure_registry_tables(&db).await.unwrap();
    crate::meta::package::ensure_package_tables(&db)
        .await
        .unwrap();
    db
}

fn widget_bytes(version: u32) -> Vec<u8> {
    serde_json::json!({"family": "example.widget", "version": version, "kinds": []})
        .to_string()
        .into_bytes()
}

async fn set_adoption(
    db: &Db,
    family: &str,
    selected: Option<&RevisionIdentity>,
    subject: Option<&str>,
) -> Result<i64> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut allocation = crate::act::ActAllocation::new();
    let event = append_meta_in(
        &mut tx,
        MetaAppendSpec::with_payload(
            subject
                .map(str::to_owned)
                .unwrap_or_else(|| format!("definition-adoption:{family}")),
            "definition_adoption.set.v1",
            serde_json::json!({"family": family, "selected": selected}),
        ),
        &mut allocation,
    )
    .await?;
    tx.commit().await?;
    Ok(event.seq)
}

async fn choice(db: &Db, family: &str) -> (Option<i64>, Option<String>, i64) {
    sqlx::query_as(
        "SELECT selected_version, selected_digest, event_seq FROM definition_adoptions WHERE family = ?",
    )
    .bind(family)
    .fetch_one(db.write_pool())
    .await
    .unwrap()
}

async fn event_count(db: &Db, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM meta_events WHERE type = ?")
        .bind(event_type)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn keyed_adoption_fold_rejects_invalid_request_key_without_event() {
    let db = test_db().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let error = append_meta_in(
        &mut tx,
        MetaAppendSpec::with_payload(
            "definition-adoption:example.widget".to_string(),
            "definition_adoption.set.v1",
            serde_json::json!({"family": "example.widget", "selected": null, "request_key": " "}),
        ),
        &mut allocation,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("request_key"), "{error}");
    tx.rollback().await.unwrap();
    assert_eq!(event_count(&db, "definition_adoption.set.v1").await, 0);
    db.close().await;
}

#[tokio::test]
async fn synthetic_install_and_adoption_share_one_write_transaction() {
    // Re-fixtured from the shipped-Resolution shared-transaction test: same
    // cross-module scenario on the synthetic `example.widget` family.
    let db = test_db().await;
    let bytes = widget_bytes(1);
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let installed =
        install_definition_artifact_in(&mut tx, "example.widget", 1, &bytes, &mut allocation)
            .await
            .unwrap();
    assert!(installed.installed);
    let choice = append_definition_adoption_in(
        &mut tx,
        "example.widget",
        Some(&installed.identity),
        &mut allocation,
    )
    .await
    .unwrap();
    assert_eq!(choice.selected, Some(installed.identity.clone()));
    assert_eq!(
        read_definition_adoption_on(&mut tx, "example.widget")
            .await
            .unwrap(),
        Some(choice.clone())
    );
    tx.commit().await.unwrap();

    let stored = read_definition_artifact(&db, "example.widget", 1, &installed.identity.digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.bytes.as_bytes(), bytes.as_slice());
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert_eq!(
        read_definition_adoption_on(&mut conn, "example.widget")
            .await
            .unwrap(),
        Some(choice)
    );
    drop(conn);
    assert_eq!(event_count(&db, "definition_artifact.installed").await, 1);
    assert_eq!(event_count(&db, "definition_adoption.set.v1").await, 1);
    assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());

    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let repeat =
        install_definition_artifact_in(&mut tx, "example.widget", 1, &bytes, &mut allocation)
            .await
            .unwrap();
    assert!(!repeat.installed);
    assert_eq!(repeat.identity, installed.identity);
    tx.commit().await.unwrap();
    assert_eq!(event_count(&db, "definition_artifact.installed").await, 1);
    assert_eq!(event_count(&db, "definition_adoption.set.v1").await, 1);
}

#[tokio::test]
async fn failed_adoption_rolls_back_install_and_its_event() {
    // Re-fixtured from the shipped-Resolution rollback test.
    let db = test_db().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let installed = install_definition_artifact_in(
        &mut tx,
        "example.widget",
        1,
        &widget_bytes(1),
        &mut allocation,
    )
    .await
    .unwrap();
    let wrong = RevisionIdentity {
        digest: "0".repeat(64),
        ..installed.identity.clone()
    };
    let err =
        append_definition_adoption_in(&mut tx, "example.widget", Some(&wrong), &mut allocation)
            .await
            .unwrap_err();
    assert!(err.to_string().contains("has not been installed"), "{err}");
    tx.rollback().await.unwrap();

    assert_eq!(event_count(&db, "definition_artifact.installed").await, 0);
    assert_eq!(event_count(&db, "definition_adoption.set.v1").await, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM definition_artifacts")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM definition_adoptions")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        0
    );
    assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
    // The rolled-back log is empty, so the production meta rebuild (ordinary
    // tables only, per D-c) still replays equal, as the reference branch
    // asserted. Event-bearing tests keep the kernel diff only: production
    // replay of kernel events fails with `no such table` until K10 (SF-4).
    assert!(
        crate::conformance::rebuild_and_diff_meta(&db)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn failure_after_both_appends_rolls_back_both_projections_and_events() {
    let db = test_db().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let installed = install_definition_artifact_in(
        &mut tx,
        "example.widget",
        1,
        &widget_bytes(1),
        &mut allocation,
    )
    .await
    .unwrap();
    append_definition_adoption_in(
        &mut tx,
        "example.widget",
        Some(&installed.identity),
        &mut allocation,
    )
    .await
    .unwrap();
    let failure = sqlx::query("INSERT INTO nonexistent_table VALUES (1)")
        .execute(&mut *tx)
        .await;
    assert!(failure.is_err());
    tx.rollback().await.unwrap();

    assert_eq!(event_count(&db, "definition_artifact.installed").await, 0);
    assert_eq!(event_count(&db, "definition_adoption.set.v1").await, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM definition_artifacts")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM definition_adoptions")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn verified_adoption_read_rejects_projection_drift() {
    let db = test_db().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let installed = install_definition_artifact_in(
        &mut tx,
        "example.widget",
        1,
        &widget_bytes(1),
        &mut allocation,
    )
    .await
    .unwrap();
    append_definition_adoption_in(
        &mut tx,
        "example.widget",
        Some(&installed.identity),
        &mut allocation,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE definition_adoptions SET selected_digest = ? WHERE family = ?")
        .bind("0".repeat(64))
        .bind("example.widget")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = read_definition_adoption_on(&mut conn, "example.widget")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("disagrees with referenced event"),
        "{err}"
    );
}

#[tokio::test]
async fn verified_adoption_read_rejects_stale_but_once_valid_choice() {
    let db = test_db().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let first = install_definition_artifact_in(
        &mut tx,
        "example.widget",
        1,
        &widget_bytes(1),
        &mut allocation,
    )
    .await
    .unwrap();
    let second = install_definition_artifact_in(
        &mut tx,
        "example.widget",
        2,
        &widget_bytes(2),
        &mut allocation,
    )
    .await
    .unwrap();
    let old = append_definition_adoption_in(
        &mut tx,
        "example.widget",
        Some(&first.identity),
        &mut allocation,
    )
    .await
    .unwrap();
    let current = append_definition_adoption_in(
        &mut tx,
        "example.widget",
        Some(&second.identity),
        &mut allocation,
    )
    .await
    .unwrap();
    assert!(current.event_seq > old.event_seq);
    tx.commit().await.unwrap();

    sqlx::query(
        "UPDATE definition_adoptions SET selected_version = ?, selected_digest = ?, event_seq = ? WHERE family = ?",
    )
    .bind(first.identity.version as i64)
    .bind(&first.identity.digest)
    .bind(old.event_seq)
    .bind("example.widget")
    .execute(db.write_pool()).await.unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = read_definition_adoption_on(&mut conn, "example.widget")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("latest family event"), "{err}");
}

#[tokio::test]
async fn internal_disable_appends_explicit_null_choice() {
    let db = test_db().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let choice = append_definition_adoption_in(&mut tx, "example.widget", None, &mut allocation)
        .await
        .unwrap();
    assert_eq!(choice.selected, None);
    tx.commit().await.unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert_eq!(
        read_definition_adoption_on(&mut conn, "example.widget")
            .await
            .unwrap(),
        Some(choice)
    );
    drop(conn);
    assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn adopt_after_install_replays_from_meta_log() {
    let db = test_db().await;
    let bytes = br#"{"family":"example","version":1,"kinds":[]}"#;
    let revision = install_definition_artifact(&db, "example", 1, bytes)
        .await
        .unwrap();
    let seq = set_adoption(&db, "example", Some(&revision), None)
        .await
        .unwrap();
    assert_eq!(
        choice(&db, "example").await,
        (Some(1), Some(revision.digest), seq)
    );
    assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn missing_revision_and_wrong_subject_refuse_without_event() {
    let db = test_db().await;
    let missing = RevisionIdentity {
        family: "example".into(),
        version: 1,
        digest: "a".repeat(64),
    };
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let err = set_adoption(&db, "example", Some(&missing), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("has not been installed"));
    let err = set_adoption(&db, "example", None, Some("vv:voc:example:active"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("reserved family identity"));
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let err = append_meta_in(
        &mut tx,
        MetaAppendSpec::with_payload(
            "definition-adoption:example",
            "definition_adoption.set.v1",
            serde_json::json!({"family": "example"}),
        ),
        &mut allocation,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("explicitly carry selected"));
    tx.rollback().await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(after, before);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM definition_adoptions")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn malformed_selected_payloads_refuse_without_event() {
    let db = test_db().await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let cases = [
        (
            serde_json::json!({"family":"example","selected":{"family":"other","version":1,"digest":"a".repeat(64)}}),
            "identity is invalid",
        ),
        (
            serde_json::json!({"family":"example","selected":{"family":"example","version":1,"digest":"bad"}}),
            "identity is invalid",
        ),
        (
            serde_json::json!({"family":"example","selected":null,"extra":true}),
            "unknown field",
        ),
        (
            serde_json::json!({"family":"example","selected":{"family":"example","version":1,"digest":"a".repeat(64),"extra":true}}),
            "unknown field",
        ),
    ];
    for (payload, expected) in cases {
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let mut allocation = crate::act::ActAllocation::new();
        let err = append_meta_in(
            &mut tx,
            MetaAppendSpec::with_payload(
                "definition-adoption:example",
                "definition_adoption.set.v1",
                payload,
            ),
            &mut allocation,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains(expected), "{err}");
        tx.rollback().await.unwrap();
    }
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn tampered_projection_cannot_be_adopted() {
    let db = test_db().await;
    let revision = install_definition_artifact(
        &db,
        "example",
        1,
        br#"{"family":"example","version":1,"kinds":[]}"#,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE definition_artifacts SET artifact_bytes = 'broken' WHERE id = ?")
        .bind(revision.value_id())
        .execute(db.write_pool())
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let err = set_adoption(&db, "example", Some(&revision), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("digest mismatch"));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn disable_keeps_bytes_and_tombstone_through_replay() {
    let db = test_db().await;
    let bytes = br#"{"family":"example","version":1,"kinds":[]}"#;
    let revision = install_definition_artifact(&db, "example", 1, bytes)
        .await
        .unwrap();
    set_adoption(&db, "example", Some(&revision), None)
        .await
        .unwrap();
    let seq = set_adoption(&db, "example", None, None).await.unwrap();
    assert_eq!(choice(&db, "example").await, (None, None, seq));
    let stored = read_definition_artifact(&db, "example", 1, &revision.digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.bytes.as_bytes(), bytes);
    assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
    sqlx::query(
        "UPDATE definition_adoptions SET event_seq = event_seq + 1 WHERE family = 'example'",
    )
    .execute(db.write_pool())
    .await
    .unwrap();
    assert!(!rebuild_and_diff_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn latest_event_wins_per_family_independently() {
    let db = test_db().await;
    let a1 = install_definition_artifact(
        &db,
        "alpha",
        1,
        br#"{"family":"alpha","version":1,"kinds":[]}"#,
    )
    .await
    .unwrap();
    let a2 = install_definition_artifact(
        &db,
        "alpha",
        2,
        br#"{"family":"alpha","version":2,"kinds":[]}"#,
    )
    .await
    .unwrap();
    let b1 = install_definition_artifact(
        &db,
        "beta",
        1,
        br#"{"family":"beta","version":1,"kinds":[]}"#,
    )
    .await
    .unwrap();
    set_adoption(&db, "alpha", Some(&a1), None).await.unwrap();
    let bseq = set_adoption(&db, "beta", Some(&b1), None).await.unwrap();
    set_adoption(&db, "alpha", None, None).await.unwrap();
    let aseq = set_adoption(&db, "alpha", Some(&a2), None).await.unwrap();
    assert_eq!(choice(&db, "alpha").await, (Some(2), Some(a2.digest), aseq));
    assert_eq!(choice(&db, "beta").await, (Some(1), Some(b1.digest), bseq));
    assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
}
