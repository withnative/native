use serde_json::json;
use sqlx::Row;

use crate::db::{begin_write, Db};
use crate::store::{create_record, update_record};

use super::bindings::{publish_record_body_revision_with_failure, PublicationFailurePoint};
use super::*;

/// Pinned fixture record ids.
///
/// `ALPHA_NOTE_ID` must sort before `BETA_NOTE_ID`: the two-carrier test reads
/// its bindings back `ORDER BY target_record_id` and asserts alpha then beta.
const DERIVED_NOTE_ID: &str = "b17d0000-0000-4000-8000-000000000001";
const FIXTURE_RECIPE_ID: &str = "b17d0000-0000-4000-8000-000000000002";
const ALPHA_NOTE_ID: &str = "b17d0000-0000-4000-8000-000000000011";
const BETA_NOTE_ID: &str = "b17d0000-0000-4000-8000-000000000012";

async fn append(db: &Db, input: NewDerivationEvent) -> DerivationEventRow {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let event = append_derivation_event_in(&mut tx, input).await.unwrap();
    tx.commit().await.unwrap();
    event
}

async fn fixture() -> (Db, String, String, String) {
    let db = crate::db::create_database(":memory:").await.unwrap();
    let target = create_record(
        &db,
        json!({
            "id":DERIVED_NOTE_ID,
            "type":"Document",
            "kind":"note",
            "name":"Derived note",
            "body":null
        }),
    )
    .await
    .unwrap();
    let row = sqlx::query(
        "SELECT id,payload FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(&target)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event: String = row.try_get("id").unwrap();
    let source_payload: String = row.try_get("payload").unwrap();
    let source_sha = digest_json(&serde_json::from_str(&source_payload).unwrap());
    create_record(
        &db,
        json!({
            "id":FIXTURE_RECIPE_ID,
            "type":"Program",
            "kind":"recipe",
            "name":"Fixture recipe",
            "body":"{}"
        }),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO recipe_releases
         (publication_event_id,program_id,source_event_id,source_sha256,descriptor_sha256,
          descriptor,status,local_event_seq,status_event_seq,published_at)
         VALUES(?,?,?,?,?,?,'published',1,1,'2026-01-01T00:00:00Z')",
    )
    .bind(&source_event)
    .bind(FIXTURE_RECIPE_ID)
    .bind(&source_event)
    .bind(&source_sha)
    .bind(&source_sha)
    .bind(&source_payload)
    .execute(db.write_pool())
    .await
    .unwrap();
    append(
        &db,
        NewDerivationEvent::authored(
            "series:test",
            "agent:test",
            None,
            "create generic series",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: "series:test".into(),
                series_key: "test:record-body".into(),
                definition: json!({"fixture":"generic"}),
            }),
        )
        .unwrap(),
    )
    .await;
    (db, target, source_event, source_sha)
}

fn revision(
    id: &str,
    predecessor: Option<&str>,
    source_event: &str,
    source_sha: &str,
) -> DerivationRevisionCompleted {
    DerivationRevisionCompleted {
        id: id.into(),
        series_id: "series:test".into(),
        predecessor_revision_id: predecessor.map(str::to_owned),
        canonical_request: CanonicalDerivationRequest {
            query_contract: "native.test.v1".into(),
            query_contract_version: 1,
            selection: json!({"all":true}),
            scope: json!({"fixture":"generic"}),
        },
        recipe_revision: RecipeRevisionRef {
            definition_id: FIXTURE_RECIPE_ID.into(),
            publication_id: source_event.into(),
            sha256: source_sha.into(),
        },
        effective_source_boundary: EffectiveSourceBoundary {
            after_seq: Some(0),
            through_seq: 1,
            resolved_scope_membership_sha256: "a".repeat(64),
            metadata: json!({}),
        },
        inputs: vec![DerivationInput {
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: source_event.into(),
            sha256: source_sha.into(),
            metadata: json!({}),
        }],
        output_ref: DerivationOutputRef {
            output_kind: "content_event".into(),
            event_id: source_event.into(),
            sha256: source_sha.into(),
        },
        completion_metadata: json!({"fixture":true}),
    }
}

fn publication_input(
    target: DerivationTarget,
    source_event: &str,
    source_sha: &str,
) -> PublishRecordBodyRevision {
    PublishRecordBodyRevision {
        publication_idempotency_key: "publish:one".into(),
        revision_idempotency_key: "revision:one".into(),
        actor: "agent:test".into(),
        run_key: None,
        reason: "publish exact output".into(),
        publication_id: "publication:one".into(),
        binding_id: "binding:one".into(),
        target,
        expected_generation: 1,
        expected_target_version: 1,
        body: "generated output".into(),
        revision: revision("revision:one", None, source_event, source_sha),
    }
}

#[tokio::test]
async fn binding_is_one_writer_versioned_and_history_survives_detach() {
    let (db, target, source_event, source_sha) = fixture().await;
    let descriptor = DerivationTarget::record_body(&target);
    bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:one",
        "agent:test",
        None,
        "bind target",
        DerivationTargetBound {
            binding_id: "binding:one".into(),
            series_id: "series:test".into(),
            target: descriptor.clone(),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(source_event.clone()),
            expected_body_sha256: Some(source_sha.clone()),
        },
    )
    .await
    .unwrap();

    let retried = bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:one",
        "agent:test",
        Some("later-run".into()),
        "bind target",
        DerivationTargetBound {
            binding_id: "binding:one".into(),
            series_id: "series:test".into(),
            target: DerivationTarget::record_body(&target),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(source_event.clone()),
            expected_body_sha256: Some(source_sha.clone()),
        },
    )
    .await
    .unwrap();
    assert_eq!(retried.idempotency_key, "bind:one");

    let conflict = bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:two",
        "agent:test",
        None,
        "competing writer",
        DerivationTargetBound {
            binding_id: "binding:two".into(),
            series_id: "series:test".into(),
            target: descriptor.clone(),
            expected_target_version: 1,
            generation: 2,
            expected_body_event_id: Some(source_event.clone()),
            expected_body_sha256: Some(source_sha.clone()),
        },
    )
    .await
    .unwrap_err();
    assert!(conflict.to_string().contains("generation/version race"));

    let stale_detach = detach_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "detach:stale",
        "agent:test",
        None,
        "stale detach",
        DerivationTargetDetached {
            binding_id: "binding:one".into(),
            target: descriptor.clone(),
            expected_generation: 1,
            expected_target_version: 0,
        },
    )
    .await
    .unwrap_err();
    assert!(stale_detach.to_string().contains("generation/version race"));

    detach_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "detach:one",
        "agent:test",
        None,
        "detach target",
        DerivationTargetDetached {
            binding_id: "binding:one".into(),
            target: descriptor.clone(),
            expected_generation: 1,
            expected_target_version: 1,
        },
    )
    .await
    .unwrap();
    bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:two",
        "agent:test",
        None,
        "bind successor",
        DerivationTargetBound {
            binding_id: "binding:two".into(),
            series_id: "series:test".into(),
            target: descriptor,
            expected_target_version: 2,
            generation: 2,
            expected_body_event_id: Some(source_event),
            expected_body_sha256: Some(source_sha),
        },
    )
    .await
    .unwrap();

    let history: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM derivation_target_bindings")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(history, 2);
    let old_detached: Option<String> = sqlx::query_scalar(
        "SELECT detached_event_id FROM derivation_target_bindings WHERE binding_id='binding:one'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(old_detached.is_some());
}

#[tokio::test]
async fn atomic_publication_selects_revision_and_fences_authored_or_stale_body_writes() {
    let (db, target, source_event, source_sha) = fixture().await;
    let descriptor = DerivationTarget::record_body(&target);
    bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:one",
        "agent:test",
        None,
        "bind target",
        DerivationTargetBound {
            binding_id: "binding:one".into(),
            series_id: "series:test".into(),
            target: descriptor.clone(),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(source_event.clone()),
            expected_body_sha256: Some(source_sha.clone()),
        },
    )
    .await
    .unwrap();

    let authored = update_record(&db, &target, json!({"body":"authored overwrite"}))
        .await
        .unwrap_err();
    assert!(authored.to_string().contains("derived record body"));
    update_record(&db, &target, json!({"name":"metadata remains editable"}))
        .await
        .unwrap();

    let published = publish_record_body_revision(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        publication_input(descriptor.clone(), &source_event, &source_sha),
    )
    .await
    .unwrap();
    assert_eq!(published.content_event.record_id, target);
    let event_count_before_retry: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM derivation_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let retried = publish_record_body_revision(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        PublishRecordBodyRevision {
            publication_idempotency_key: "publish:one".into(),
            revision_idempotency_key: "revision:one".into(),
            actor: "agent:test".into(),
            run_key: Some("retry-from-another-run".into()),
            reason: "publish exact output".into(),
            publication_id: "publication:one".into(),
            binding_id: "binding:one".into(),
            target: descriptor.clone(),
            expected_generation: 1,
            expected_target_version: 1,
            body: "generated output".into(),
            revision: revision("revision:one", None, &source_event, &source_sha),
        },
    )
    .await
    .unwrap();
    assert_eq!(retried.content_event.id, published.content_event.id);
    assert_eq!(retried.revision_event.id, published.revision_event.id);
    assert_eq!(retried.publication_event.id, published.publication_event.id);
    let event_count_after_retry: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM derivation_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(event_count_after_retry, event_count_before_retry);

    let inspection = inspect_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        descriptor.clone(),
    )
    .await
    .unwrap();
    assert_eq!(inspection.bindings.len(), 1);
    assert_eq!(inspection.publications.len(), 1);
    assert_eq!(
        inspection.head.unwrap().selected_publication_id.as_deref(),
        Some("publication:one")
    );
    let deletion = crate::store::delete_record(&db, &target).await.unwrap_err();
    assert!(deletion.to_string().contains("detach it first"));
    let row = sqlx::query(
        "SELECT r.body,s.revision_id,s.output_event_id
           FROM records r JOIN derivation_selected_publications s
             ON s.target_record_id=r.id AND s.target_kind='record' AND s.target_slot='body'
          WHERE r.id=?",
    )
    .bind(&target)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        row.try_get::<String, _>("body").unwrap(),
        "generated output"
    );
    assert_eq!(
        row.try_get::<String, _>("revision_id").unwrap(),
        "revision:one"
    );
    assert_eq!(
        row.try_get::<String, _>("output_event_id").unwrap(),
        published.content_event.id
    );

    detach_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "detach:one",
        "agent:test",
        None,
        "detach first writer",
        DerivationTargetDetached {
            binding_id: "binding:one".into(),
            target: descriptor.clone(),
            expected_generation: 1,
            expected_target_version: 2,
        },
    )
    .await
    .unwrap();
    update_record(&db, &target, json!({"body":null}))
        .await
        .unwrap();
    let cleared = sqlx::query(
        "SELECT id,payload FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(&target)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let cleared_event: String = cleared.try_get("id").unwrap();
    let cleared_payload: String = cleared.try_get("payload").unwrap();
    let cleared_sha = digest_json(&serde_json::from_str(&cleared_payload).unwrap());
    bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:two",
        "agent:test",
        None,
        "bind replacement writer",
        DerivationTargetBound {
            binding_id: "binding:two".into(),
            series_id: "series:test".into(),
            target: descriptor.clone(),
            expected_target_version: 3,
            generation: 2,
            expected_body_event_id: Some(cleared_event),
            expected_body_sha256: Some(cleared_sha),
        },
    )
    .await
    .unwrap();
    let stale = publish_record_body_revision(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        PublishRecordBodyRevision {
            publication_idempotency_key: "publish:stale".into(),
            revision_idempotency_key: "revision:stale".into(),
            actor: "agent:test".into(),
            run_key: None,
            reason: "stale worker must lose".into(),
            publication_id: "publication:stale".into(),
            binding_id: "binding:one".into(),
            target: descriptor,
            expected_generation: 1,
            expected_target_version: 2,
            body: "stale output".into(),
            revision: revision(
                "revision:stale",
                Some("revision:one"),
                &source_event,
                &source_sha,
            ),
        },
    )
    .await
    .unwrap_err();
    assert!(stale.to_string().contains("binding generation"));
    let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&target)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(body, None);
    let stale_revision_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM derivation_revisions WHERE id='revision:stale')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let stale_publication_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM derivation_target_publications WHERE publication_id='publication:stale')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!stale_revision_exists && !stale_publication_exists);
}

#[tokio::test]
async fn publication_rolls_back_at_every_atomic_boundary_and_replays_exactly() {
    for failure_point in [
        PublicationFailurePoint::AfterContentEvent,
        PublicationFailurePoint::AfterRevisionEvent,
        PublicationFailurePoint::AfterPublicationEvent,
    ] {
        let (db, target, source_event, source_sha) = fixture().await;
        let descriptor = DerivationTarget::record_body(&target);
        bind_target(
            &db,
            crate::authorization::Principal::bound("agent:test", true),
            "bind:one",
            "agent:test",
            None,
            "bind target",
            DerivationTargetBound {
                binding_id: "binding:one".into(),
                series_id: "series:test".into(),
                target: descriptor.clone(),
                expected_target_version: 0,
                generation: 1,
                expected_body_event_id: Some(source_event.clone()),
                expected_body_sha256: Some(source_sha.clone()),
            },
        )
        .await
        .unwrap();
        let content_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        publish_record_body_revision_with_failure(
            &db,
            crate::authorization::Principal::bound("agent:test", true),
            publication_input(descriptor, &source_event, &source_sha),
            failure_point,
        )
        .await
        .unwrap_err();
        let content_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
        let revision_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM derivation_revisions WHERE id='revision:one')",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let publication_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM derivation_target_publications WHERE publication_id='publication:one')",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(content_after, content_before);
        assert_eq!(body, None);
        assert!(!revision_exists && !publication_exists);
    }

    let (db, target, source_event, source_sha) = fixture().await;
    let descriptor = DerivationTarget::record_body(&target);
    bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:one",
        "agent:test",
        None,
        "bind target",
        DerivationTargetBound {
            binding_id: "binding:one".into(),
            series_id: "series:test".into(),
            target: descriptor.clone(),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(source_event.clone()),
            expected_body_sha256: Some(source_sha.clone()),
        },
    )
    .await
    .unwrap();
    publish_record_body_revision(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        publication_input(descriptor, &source_event, &source_sha),
    )
    .await
    .unwrap();
    let diff = crate::conformance::rebuild_and_diff_derivation(&db)
        .await
        .unwrap();
    assert!(diff
        .tables
        .iter()
        .all(|table| { table.live == table.rebuilt && table.mismatches.is_empty() }));
}

#[tokio::test]
async fn binding_rejects_stale_body_preflight_and_actor_mismatch() {
    let (db, target, source_event, source_sha) = fixture().await;
    let descriptor = DerivationTarget::record_body(&target);
    update_record(&db, &target, json!({"body":null}))
        .await
        .unwrap();
    let stale = bind_target(
        &db,
        crate::authorization::Principal::bound("agent:test", true),
        "bind:stale-cas",
        "agent:test",
        None,
        "stale preflight",
        DerivationTargetBound {
            binding_id: "binding:stale-cas".into(),
            series_id: "series:test".into(),
            target: descriptor.clone(),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(source_event),
            expected_body_sha256: Some(source_sha),
        },
    )
    .await
    .unwrap_err();
    assert!(stale
        .to_string()
        .contains("changed since binding preflight"));

    let actor = bind_target(
        &db,
        crate::authorization::Principal::bound("someone:else", true),
        "bind:wrong-actor",
        "agent:test",
        None,
        "forged actor",
        DerivationTargetBound {
            binding_id: "binding:wrong-actor".into(),
            series_id: "series:test".into(),
            target: descriptor,
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: None,
            expected_body_sha256: None,
        },
    )
    .await
    .unwrap_err();
    assert!(actor.to_string().contains("must match"));
}

#[tokio::test]
async fn the_same_binding_primitive_serves_two_note_carriers_and_recipes() {
    let db = crate::db::create_database(":memory:").await.unwrap();
    for (ordinal, recipe, record_id) in [
        ("alpha", "native.alpha.v1", ALPHA_NOTE_ID),
        ("beta", "native.beta.v1", BETA_NOTE_ID),
    ] {
        let record_id = record_id.to_string();
        create_record(
            &db,
            json!({
                "id": record_id,
                "type": "Document",
                "kind": "note",
                "name": format!("Derived {ordinal}"),
                "body": null
            }),
        )
        .await
        .unwrap();
        let row = sqlx::query(
            "SELECT id,payload FROM content_events WHERE record_id=? AND type='record.created'",
        )
        .bind(&record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let source_event: String = row.try_get("id").unwrap();
        let source_payload: String = row.try_get("payload").unwrap();
        let source_sha = digest_json(&serde_json::from_str(&source_payload).unwrap());
        let series_id = format!("series:{ordinal}");
        append(
            &db,
            NewDerivationEvent::authored(
                format!("series:{ordinal}"),
                "agent:test",
                None,
                "create generic series",
                DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                    id: series_id.clone(),
                    series_key: format!("test:{ordinal}:record-body"),
                    definition: json!({"recipe_contract": recipe}),
                }),
            )
            .unwrap(),
        )
        .await;
        bind_target(
            &db,
            crate::authorization::Principal::bound("agent:test", true),
            format!("bind:{ordinal}"),
            "agent:test",
            None,
            "bind generic recipe output",
            DerivationTargetBound {
                binding_id: format!("binding:{ordinal}"),
                series_id,
                target: DerivationTarget::record_body(record_id),
                expected_target_version: 0,
                generation: 1,
                expected_body_event_id: Some(source_event),
                expected_body_sha256: Some(source_sha),
            },
        )
        .await
        .unwrap();
    }
    let bindings: Vec<(String, String)> = sqlx::query_as(
        "SELECT target_record_id,series_id FROM derivation_target_bindings ORDER BY target_record_id",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        bindings,
        vec![
            (ALPHA_NOTE_ID.into(), "series:alpha".into()),
            (BETA_NOTE_ID.into(), "series:beta".into()),
        ]
    );
}
