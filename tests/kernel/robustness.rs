//! Robustness regressions from the engine build's review findings: in-memory
//! isolation, missing-record rollbacks, activity bumps, required persistence,
//! and phantom link.removed events.

use crate::common::{count, ev, project_one};
use native_ce::create_database;
use native_ce::events::{FacetSetPayload, LinkAddedPayload, LinkRemovedPayload};
use native_ce::store::{
    add_link, create_record, delete_record, remove_link, set_facet, unset_facet, update_record,
};
use serde_json::json;

// ---- In-memory database survives many mutations (finding 1) ----

#[tokio::test]
async fn handles_more_than_one_write_transaction_on_a_memory_default() {
    let db = create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "first" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "second" }),
    )
    .await
    .unwrap();
    assert_eq!(count(&db, "SELECT COUNT(*) n FROM records").await, 4);
    db.close().await;
}

#[tokio::test]
async fn keeps_separate_memory_databases_isolated() {
    // rebuild-and-diff depends on this.
    let a = create_database(":memory:").await.unwrap();
    let b = create_database(":memory:").await.unwrap();
    create_record(
        &a,
        json!({ "type": "Document", "kind": "note", "name": "only-in-a" }),
    )
    .await
    .unwrap();
    assert_eq!(count(&b, "SELECT COUNT(*) n FROM records").await, 2);
    a.close().await;
    b.close().await;
}

// ---- Mutations against missing records fail and roll back (finding 2) ----

#[tokio::test]
async fn rejects_update_based_events_and_leaves_no_orphan_events() {
    let db = create_database(":memory:").await.unwrap();
    let expect_missing = |result: native_ce::Result<()>, label: &str| {
        let err = result
            .expect_err(&format!("{label} must be rejected"))
            .to_string();
        assert!(err.contains("does not exist"), "{label}: {err}");
    };
    expect_missing(
        update_record(&db, "missing", json!({ "name": "ghost" })).await,
        "update",
    );
    expect_missing(delete_record(&db, "missing").await, "delete");
    expect_missing(
        set_facet(
            &db,
            "missing",
            FacetSetPayload {
                key: "lifecycle".into(),
                value: Some("open".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await,
        "set spine facet",
    );
    expect_missing(
        unset_facet(&db, "missing", "lifecycle").await,
        "unset facet",
    );
    // Open-facet set on a missing record is rejected by the liveness guard / FK.
    assert!(set_facet(
        &db,
        "missing",
        FacetSetPayload {
            key: "provenance".into(),
            value: Some("x".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        }
    )
    .await
    .is_err());

    // Every failed mutation rolled its event back — the log is empty.
    assert_eq!(count(&db, "SELECT COUNT(*) n FROM content_events").await, 2);
    db.close().await;
}

// ---- Every mutation event advances last_activity_at (finding 4) ----

#[tokio::test]
async fn bumps_on_links_and_on_open_facet_unset_not_just_facet_set() {
    let db = create_database(":memory:").await.unwrap();
    project_one(
        &db,
        &ev(
            "r1",
            "record.created",
            "2026-01-01T00:00:00.000Z",
            json!({ "type": "WorkItem", "kind": "task", "name": "src", "home_id": "native:unfiled" }),
        ),
    )
    .await
    .unwrap();
    project_one(
        &db,
        &ev(
            "r2",
            "record.created",
            "2026-01-01T00:00:01.000Z",
            json!({ "type": "Outcome", "kind": "target", "name": "tgt", "home_id": "native:unfiled" }),
        ),
    )
    .await
    .unwrap();

    async fn last_activity(db: &native_ce::Db) -> Option<String> {
        crate::common::text_of(
            db,
            "SELECT last_activity_at FROM records WHERE id = 'r1'",
            "last_activity_at",
        )
        .await
    }

    // link.added bumps the source's activity timestamp.
    project_one(
        &db,
        &ev(
            "r1",
            "link.added",
            "2026-02-02T00:00:00.000Z",
            json!({ "source_id": "r1", "target_id": "r2", "relationship": "part_of" }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        last_activity(&db).await.as_deref(),
        Some("2026-02-02T00:00:00.000Z")
    );

    // open-facet set then unset — the unset must also bump.
    project_one(
        &db,
        &ev(
            "r1",
            "facet.set",
            "2026-03-03T00:00:00.000Z",
            json!({ "key": "provenance", "value": "x" }),
        ),
    )
    .await
    .unwrap();
    project_one(
        &db,
        &ev(
            "r1",
            "facet.unset",
            "2026-04-04T00:00:00.000Z",
            json!({ "key": "provenance" }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        last_activity(&db).await.as_deref(),
        Some("2026-04-04T00:00:00.000Z")
    );

    // link.removed bumps too.
    project_one(
        &db,
        &ev(
            "r1",
            "link.removed",
            "2026-05-05T00:00:00.000Z",
            json!({ "source_id": "r1", "target_id": "r2", "relationship": "part_of" }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        last_activity(&db).await.as_deref(),
        Some("2026-05-05T00:00:00.000Z")
    );
    db.close().await;
}

// ---- persistence is a required spine facet (2e5ed3e Am.2 §3 / option a) ----

#[tokio::test]
async fn defaults_created_records_to_enduring_and_forbids_unsetting_persistence() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "no persistence given" }),
    )
    .await
    .unwrap();
    let persistence = crate::common::text_of(
        &db,
        &format!("SELECT persistence FROM records WHERE id = '{id}'"),
        "persistence",
    )
    .await;
    assert_eq!(persistence.as_deref(), Some("enduring"));

    // Can be changed between the two enum values...
    set_facet(
        &db,
        &id,
        FacetSetPayload {
            key: "persistence".into(),
            value: Some("occurrent".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let changed = crate::common::text_of(
        &db,
        &format!("SELECT persistence FROM records WHERE id = '{id}'"),
        "persistence",
    )
    .await;
    assert_eq!(changed.as_deref(), Some("occurrent"));

    // ...but NOT unset (it is non-null).
    let err = unset_facet(&db, &id, "persistence")
        .await
        .expect_err("must reject")
        .to_string();
    assert!(err.contains("cannot unset persistence"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn rejects_an_explicit_null_persistence_on_create() {
    let db = create_database(":memory:").await.unwrap();
    // A runtime caller (JSON payload) that bypasses the types must still be
    // rejected by the NOT NULL constraint, not silently defaulted to enduring.
    assert!(create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "x", "persistence": null })
    )
    .await
    .is_err());
    assert_eq!(count(&db, "SELECT COUNT(*) n FROM records").await, 2);
    db.close().await;
}

// ---- link.removed requires the link to exist (finding — phantom events) ----

#[tokio::test]
async fn throws_and_leaves_no_event_when_removing_a_nonexistent_link() {
    let db = create_database(":memory:").await.unwrap();
    // Both endpoints exist (so the liveness guard passes) but no link joins them.
    let a = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "a" }),
    )
    .await
    .unwrap();
    let b = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "b" }),
    )
    .await
    .unwrap();
    let err = remove_link(
        &db,
        LinkRemovedPayload {
            source_id: a,
            target_id: b,
            relationship: "mentions".into(),
        },
    )
    .await
    .expect_err("must reject")
    .to_string();
    assert!(err.contains("cannot remove link"), "{err}");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) n FROM content_events WHERE type = 'link.removed'"
        )
        .await,
        0
    );
    db.close().await;
}

#[tokio::test]
async fn removes_an_existing_link_and_records_the_event() {
    let db = create_database(":memory:").await.unwrap();
    let a = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "a" }),
    )
    .await
    .unwrap();
    let b = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "b" }),
    )
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: a.clone(),
            target_id: b.clone(),
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: a,
            target_id: b,
            relationship: "part_of".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(count(&db, "SELECT COUNT(*) n FROM links").await, 0);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) n FROM content_events WHERE type = 'link.removed'"
        )
        .await,
        1
    );
    db.close().await;
}
