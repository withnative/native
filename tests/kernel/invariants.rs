//! Systematic invariant matrix for the projector, enumerating each event against
//! missing / live / soft-deleted state, with the expected precondition, activity
//! bump, rollback, and re-application behaviour. This is the belt-and-suspenders
//! layer that guards against the whack-a-mole class of bug found in review.

use crate::common::{count, ev, project_one};
use native_ce::events::{FacetSetPayload, LinkAddedPayload, LinkRemovedPayload};
use native_ce::store::{
    add_link, append, delete_record, remove_link, set_facet, unset_facet, update_record, AppendSpec,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use uuid::Uuid;

const EARLY: &str = "2020-01-01T00:00:00.000Z";
const T: &str = "2027-07-07T07:07:07.000Z";

async fn mk(db: &Db, record_type: &str) -> String {
    let id = Uuid::new_v4().to_string();
    project_one(
        db,
        &ev(
            &id,
            "record.created",
            EARLY,
            json!({ "type": record_type, "kind": "x-test-fixture", "name": record_type, "home_id": "native:unfiled" }),
        ),
    )
    .await
    .unwrap();
    id
}

async fn last_activity(db: &Db, id: &str) -> String {
    crate::common::text_of(
        db,
        &format!("SELECT last_activity_at FROM records WHERE id = '{id}'"),
        "last_activity_at",
    )
    .await
    .expect("last_activity_at set")
}

#[tokio::test]
async fn updated_at_advances_when_sequential_events_share_a_millisecond() {
    let db = create_database(":memory:").await.unwrap();
    let id = mk(&db, "WorkItem").await;
    let before = crate::common::text_of(
        &db,
        &format!("SELECT updated_at FROM records WHERE id = '{id}'"),
        "updated_at",
    )
    .await
    .unwrap();
    project_one(
        &db,
        &ev(&id, "record.updated", &before, json!({ "name": "changed" })),
    )
    .await
    .unwrap();
    let after = crate::common::text_of(
        &db,
        &format!("SELECT updated_at FROM records WHERE id = '{id}'"),
        "updated_at",
    )
    .await
    .unwrap();
    let expected = (chrono::DateTime::parse_from_rfc3339(&before).unwrap()
        + chrono::Duration::milliseconds(1))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(after, expected);

    project_one(
        &db,
        &ev(
            &id,
            "facet.set",
            &after,
            json!({ "key": "priority", "value": "high" }),
        ),
    )
    .await
    .unwrap();
    let after_touch = crate::common::text_of(
        &db,
        &format!("SELECT updated_at FROM records WHERE id = '{id}'"),
        "updated_at",
    )
    .await
    .unwrap();
    let expected_touch = (chrono::DateTime::parse_from_rfc3339(&after).unwrap()
        + chrono::Duration::milliseconds(1))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(
        after_touch, expected_touch,
        "touch-routed mutations share the record-wide monotonic token"
    );
}

#[tokio::test]
async fn projector_requires_non_empty_kind_on_create_and_update() {
    let db = create_database(":memory:").await.unwrap();

    for (label, payload) in [
        (
            "missing",
            json!({ "type": "WorkItem", "home_id": "native:unfiled" }),
        ),
        (
            "null",
            json!({ "type": "WorkItem", "kind": null, "home_id": "native:unfiled" }),
        ),
        (
            "empty",
            json!({ "type": "WorkItem", "kind": "", "home_id": "native:unfiled" }),
        ),
    ] {
        let error = project_one(
            &db,
            &ev(
                &format!("{label}-kind-create"),
                "record.created",
                EARLY,
                payload,
            ),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("kind"), "{label}: {error}");
    }

    let id = mk(&db, "WorkItem").await;
    for (label, kind) in [("null", Value::Null), ("empty", json!(""))] {
        let error = project_one(&db, &ev(&id, "record.updated", T, json!({ "kind": kind })))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("kind"), "{label}: {error}");
    }
    project_one(
        &db,
        &ev(
            &id,
            "record.updated",
            T,
            json!({ "kind": "x-novel-replacement" }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT kind FROM records WHERE id = '{id}'"),
            "kind",
        )
        .await,
        Some("x-novel-replacement".into())
    );

    db.close().await;
}

// ---- Precondition: mutation events against a MISSING record roll back ----

#[tokio::test]
async fn mutations_against_missing_state_throw_and_append_no_event() {
    let cases: [&str; 8] = [
        "record.updated",
        "record.deleted",
        "facet.set (spine)",
        "facet.set (open)",
        "facet.unset (spine)",
        "facet.unset (open)",
        "link.added",
        "link.removed",
    ];
    for name in cases {
        let db = create_database(":memory:").await.unwrap();
        let outcome = match name {
            "record.updated" => update_record(&db, "missing", json!({ "name": "x" })).await,
            "record.deleted" => delete_record(&db, "missing").await,
            "facet.set (spine)" => {
                set_facet(
                    &db,
                    "missing",
                    FacetSetPayload {
                        key: "lifecycle".into(),
                        value: Some("x".into()),
                        vocab_ref: None,
                        as_of: None,
                        observation_only: false,
                    },
                )
                .await
            }
            "facet.set (open)" => {
                set_facet(
                    &db,
                    "missing",
                    FacetSetPayload {
                        key: "provenance".into(),
                        value: Some("x".into()),
                        vocab_ref: None,
                        as_of: None,
                        observation_only: false,
                    },
                )
                .await
            }
            "facet.unset (spine)" => unset_facet(&db, "missing", "lifecycle").await,
            "facet.unset (open)" => unset_facet(&db, "missing", "provenance").await,
            "link.added" => {
                add_link(
                    &db,
                    LinkAddedPayload {
                        id: None,
                        source_id: "missing".into(),
                        target_id: "x".into(),
                        relationship: "mentions".into(),
                        note: None,
                    },
                )
                .await
            }
            "link.removed" => {
                remove_link(
                    &db,
                    LinkRemovedPayload {
                        source_id: "missing".into(),
                        target_id: "x".into(),
                        relationship: "mentions".into(),
                    },
                )
                .await
            }
            other => unreachable!("{other}"),
        };
        assert!(outcome.is_err(), "{name} should roll back");
        assert_eq!(
            count(&db, "SELECT COUNT(*) n FROM content_events").await,
            2,
            "{name} left an orphan event"
        );
        db.close().await;
    }
}

// ---- Activity: every mutation event advances last_activity_at ----

#[tokio::test]
async fn every_mutation_event_advances_last_activity_at() {
    let cases: [&str; 8] = [
        "record.updated",
        "record.deleted",
        "facet.set (spine)",
        "facet.set (open)",
        "facet.unset (spine)",
        "facet.unset (open)",
        "link.added",
        "link.removed",
    ];
    for name in cases {
        let db = create_database(":memory:").await.unwrap();
        let (rid, event) = match name {
            "record.updated" => {
                let id = mk(&db, "WorkItem").await;
                (
                    id.clone(),
                    ev(&id, "record.updated", T, json!({ "name": "z" })),
                )
            }
            "record.deleted" => {
                let id = mk(&db, "WorkItem").await;
                (id.clone(), ev(&id, "record.deleted", T, json!({})))
            }
            "facet.set (spine)" => {
                let id = mk(&db, "WorkItem").await;
                (
                    id.clone(),
                    ev(
                        &id,
                        "facet.set",
                        T,
                        json!({ "key": "lifecycle", "value": "open" }),
                    ),
                )
            }
            "facet.set (open)" => {
                let id = mk(&db, "WorkItem").await;
                (
                    id.clone(),
                    ev(
                        &id,
                        "facet.set",
                        T,
                        json!({ "key": "provenance", "value": "p" }),
                    ),
                )
            }
            "facet.unset (spine)" => {
                let id = mk(&db, "WorkItem").await;
                project_one(
                    &db,
                    &ev(
                        &id,
                        "facet.set",
                        EARLY,
                        json!({ "key": "lifecycle", "value": "open" }),
                    ),
                )
                .await
                .unwrap();
                (
                    id.clone(),
                    ev(&id, "facet.unset", T, json!({ "key": "lifecycle" })),
                )
            }
            "facet.unset (open)" => {
                let id = mk(&db, "WorkItem").await;
                project_one(
                    &db,
                    &ev(
                        &id,
                        "facet.set",
                        EARLY,
                        json!({ "key": "provenance", "value": "p" }),
                    ),
                )
                .await
                .unwrap();
                (
                    id.clone(),
                    ev(&id, "facet.unset", T, json!({ "key": "provenance" })),
                )
            }
            "link.added" => {
                let a = mk(&db, "WorkItem").await;
                let b = mk(&db, "Outcome").await;
                (
                    a.clone(),
                    ev(
                        &a,
                        "link.added",
                        T,
                        json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
                    ),
                )
            }
            "link.removed" => {
                let a = mk(&db, "WorkItem").await;
                let b = mk(&db, "Outcome").await;
                project_one(
                    &db,
                    &ev(
                        &a,
                        "link.added",
                        EARLY,
                        json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
                    ),
                )
                .await
                .unwrap();
                (
                    a.clone(),
                    ev(
                        &a,
                        "link.removed",
                        T,
                        json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
                    ),
                )
            }
            other => unreachable!("{other}"),
        };
        project_one(&db, &event).await.unwrap();
        assert_eq!(
            last_activity(&db, &rid).await,
            T,
            "{name} must bump last_activity_at"
        );
        db.close().await;
    }
}

// ---- Soft-deleted state: tombstoned records are frozen (decision ef32e44) ----

#[tokio::test]
async fn rejects_every_mutation_event_that_touches_a_tombstoned_record() {
    let db = create_database(":memory:").await.unwrap();
    let id = mk(&db, "WorkItem").await;
    let other = mk(&db, "Outcome").await;
    project_one(
        &db,
        &ev(&id, "record.deleted", "2026-01-01T00:00:00.000Z", json!({})),
    )
    .await
    .unwrap();

    let expect_tombstoned = |result: native_ce::Result<()>, label: &str| {
        let err = result
            .expect_err(&format!("{label} must be rejected"))
            .to_string();
        assert!(err.contains("tombstoned"), "{label}: {err}");
    };

    expect_tombstoned(
        project_one(
            &db,
            &ev(&id, "record.updated", T, json!({ "summary": "x" })),
        )
        .await,
        "record.updated",
    );
    expect_tombstoned(
        project_one(&db, &ev(&id, "record.deleted", T, json!({}))).await,
        "record.deleted",
    );
    expect_tombstoned(
        project_one(
            &db,
            &ev(
                &id,
                "facet.set",
                T,
                json!({ "key": "lifecycle", "value": "x" }),
            ),
        )
        .await,
        "facet.set (spine)",
    );
    expect_tombstoned(
        project_one(
            &db,
            &ev(
                &id,
                "facet.set",
                T,
                json!({ "key": "provenance", "value": "x" }),
            ),
        )
        .await,
        "facet.set (open)",
    );
    expect_tombstoned(
        project_one(
            &db,
            &ev(&id, "facet.unset", T, json!({ "key": "provenance" })),
        )
        .await,
        "facet.unset",
    );
    // ...including a link naming it as either endpoint.
    expect_tombstoned(
        project_one(
            &db,
            &ev(
                &other,
                "link.added",
                T,
                json!({ "source_id": other, "target_id": id, "relationship": "renders" }),
            ),
        )
        .await,
        "link.added (target tombstoned)",
    );
    expect_tombstoned(
        project_one(
            &db,
            &ev(
                &id,
                "link.added",
                T,
                json!({ "source_id": id, "target_id": other, "relationship": "renders" }),
            ),
        )
        .await,
        "link.added (source tombstoned)",
    );

    // The tombstone is untouched (no summary written; still deleted).
    let row = sqlx::query("SELECT summary, deleted_at FROM records WHERE id = ?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    use sqlx::Row;
    assert!(row.get::<Option<String>, _>("summary").is_none());
    assert!(row.get::<Option<String>, _>("deleted_at").is_some());
    db.close().await;
}

// ---- Re-application: the contract is exactly-once, not idempotent ----

#[tokio::test]
async fn record_created_is_not_idempotent_reapply_raises() {
    let db = create_database(":memory:").await.unwrap();
    let e = ev(
        &Uuid::new_v4().to_string(),
        "record.created",
        T,
        json!({ "type": "Document", "kind": "note", "name": "once", "home_id": "native:unfiled" }),
    );
    project_one(&db, &e).await.unwrap();
    assert!(project_one(&db, &e).await.is_err());
    db.close().await;
}

#[tokio::test]
async fn link_removed_is_not_idempotent_reapply_raises() {
    let db = create_database(":memory:").await.unwrap();
    let a = mk(&db, "WorkItem").await;
    let b = mk(&db, "Outcome").await;
    project_one(
        &db,
        &ev(
            &a,
            "link.added",
            EARLY,
            json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
        ),
    )
    .await
    .unwrap();
    let rm = ev(
        &a,
        "link.removed",
        T,
        json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
    );
    project_one(&db, &rm).await.unwrap();
    let err = project_one(&db, &rm)
        .await
        .expect_err("link already gone")
        .to_string();
    assert!(err.contains("cannot remove link"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn facet_set_and_link_added_happen_to_be_upserts() {
    let db = create_database(":memory:").await.unwrap();
    let a = mk(&db, "WorkItem").await;
    let b = mk(&db, "Outcome").await;
    let fs = ev(
        &a,
        "facet.set",
        T,
        json!({ "key": "provenance", "value": "p" }),
    );
    project_one(&db, &fs).await.unwrap();
    project_one(&db, &fs).await.unwrap(); // documented as incidental
    let la = ev(
        &a,
        "link.added",
        T,
        json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
    );
    project_one(&db, &la).await.unwrap();
    project_one(&db, &la).await.unwrap();
    // Exactly one facet row and one link despite the double apply.
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) n FROM facet_values WHERE record_id = '{a}'")
        )
        .await,
        1
    );
    assert_eq!(count(&db, "SELECT COUNT(*) n FROM links").await, 1);
    db.close().await;
}

// ---- Envelope/payload consistency: link events are indexed under source_id ----

#[tokio::test]
async fn project_rejects_a_link_added_whose_record_id_differs_from_source_id() {
    let db = create_database(":memory:").await.unwrap();
    let a = mk(&db, "WorkItem").await;
    let b = mk(&db, "Outcome").await;
    let err = project_one(
        &db,
        &ev(
            "wrong-index-key",
            "link.added",
            T,
            json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
        ),
    )
    .await
    .expect_err("must reject")
    .to_string();
    assert!(err.contains("envelope mismatch"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn public_append_rejects_a_misindexed_link_event_and_stores_nothing() {
    let db = create_database(":memory:").await.unwrap();
    let a = mk(&db, "WorkItem").await;
    let b = mk(&db, "Outcome").await;
    let err = append(
        &db,
        AppendSpec {
            record_id: "wrong-index-key".into(),
            event_type: "link.added".into(),
            payload: json!({ "source_id": a, "target_id": b, "relationship": "part_of" }),
            actor: None,
        },
    )
    .await
    .expect_err("must reject")
    .to_string();
    assert!(err.contains("envelope mismatch"), "{err}");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) n FROM content_events WHERE type = 'link.added'"
        )
        .await,
        0
    );
    assert_eq!(count(&db, "SELECT COUNT(*) n FROM links").await, 0);
    db.close().await;
}
