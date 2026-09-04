use serde_json::json;
use sqlx::Row;

use crate::db::{begin_write, Db};

use super::*;

async fn append(db: &Db, input: NewDerivationEvent) -> DerivationEventRow {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let event = append_derivation_event_in(&mut tx, input).await.unwrap();
    tx.commit().await.unwrap();
    event
}

#[tokio::test]
async fn successful_revision_has_canonical_exact_manifest_and_replays() {
    let db = crate::db::create_database(":memory:").await.unwrap();
    let source = sqlx::query(
        "SELECT id,record_id,payload FROM content_events WHERE payload IS NOT NULL ORDER BY seq LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event_id: String = source.try_get("id").unwrap();
    let source_record_id: String = source.try_get("record_id").unwrap();
    let source_payload: String = source.try_get("payload").unwrap();
    let source_digest = digest_json(&serde_json::from_str(&source_payload).unwrap());
    sqlx::query(
        "INSERT INTO recipe_releases
         (publication_event_id,program_id,source_event_id,source_sha256,descriptor_sha256,
          descriptor,status,local_event_seq,status_event_seq,published_at)
         VALUES(?,?,?,?,?,?,'published',1,1,'2026-01-01T00:00:00Z')",
    )
    .bind(&source_event_id)
    .bind(&source_record_id)
    .bind(&source_event_id)
    .bind(&source_digest)
    .bind(&source_digest)
    .bind(&source_payload)
    .execute(db.write_pool())
    .await
    .unwrap();
    append(
        &db,
        NewDerivationEvent::authored(
            "series-1",
            "person:alice",
            Some("run-1".into()),
            "define a reusable summary series",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: "series-1".into(),
                series_key: "change-summary:record-1".into(),
                definition: json!({"output":"note","recipe":"engine:change-summary/v1"}),
            }),
        )
        .unwrap(),
    )
    .await;
    let revision = append(
        &db,
        NewDerivationEvent::authored(
            "revision-1",
            "agent:codex",
            Some("run-2".into()),
            "materialize the exact inputs",
            DerivationEventPayload::RevisionCompleted(DerivationRevisionCompleted {
                id: "revision-1".into(),
                series_id: "series-1".into(),
                predecessor_revision_id: None,
                canonical_request: CanonicalDerivationRequest {
                    query_contract: "native.test".into(),
                    query_contract_version: 1,
                    selection: json!({"b":2,"a":1}),
                    scope: json!({"record_ids":[source_record_id.clone()]}),
                },
                recipe_revision: RecipeRevisionRef {
                    definition_id: source_record_id,
                    publication_id: source_event_id.clone(),
                    sha256: source_digest.clone(),
                },
                effective_source_boundary: EffectiveSourceBoundary {
                    after_seq: Some(0),
                    through_seq: 42,
                    resolved_scope_membership_sha256: "d".repeat(64),
                    metadata: json!({}),
                },
                inputs: vec![DerivationInput {
                    input_role: "source".into(),
                    input_kind: "content_event".into(),
                    portable_id: source_event_id.clone(),
                    sha256: source_digest.clone(),
                    metadata: json!({}),
                }],
                output_ref: DerivationOutputRef {
                    output_kind: "content_event".into(),
                    event_id: source_event_id,
                    sha256: source_digest,
                },
                completion_metadata: json!({"executor":"test"}),
            }),
        )
        .unwrap(),
    )
    .await;
    let mut live = db.pool().acquire().await.unwrap();
    let manifest: String =
        sqlx::query_scalar("SELECT input_manifest FROM derivation_revisions WHERE id='revision-1'")
            .fetch_one(&mut *live)
            .await
            .unwrap();
    assert!(manifest.contains("native.test"));
    assert!(manifest.contains("resolved_scope_membership_sha256"));
    let completed_at: String =
        sqlx::query_scalar("SELECT completed_at FROM derivation_revisions WHERE id='revision-1'")
            .fetch_one(&mut *live)
            .await
            .unwrap();
    assert_eq!(completed_at, revision.created_at);

    let events = read_all_derivation_events(&mut live).await.unwrap();
    let rebuilt = crate::db::create_database(":memory:").await.unwrap();
    let mut rebuilt_conn = rebuilt.write_pool().acquire().await.unwrap();
    replay_derivations(&mut rebuilt_conn, &events)
        .await
        .unwrap();
    let row = sqlx::query("SELECT id,input_manifest_sha256 FROM derivation_revisions")
        .fetch_one(&mut *rebuilt_conn)
        .await
        .unwrap();
    assert_eq!(row.try_get::<String, _>("id").unwrap(), "revision-1");
    assert_eq!(
        row.try_get::<String, _>("input_manifest_sha256").unwrap(),
        digest_json(&serde_json::from_str::<serde_json::Value>(&manifest).unwrap())
    );
}

#[tokio::test]
async fn idempotency_rejects_different_intent() {
    let db = crate::db::create_database(":memory:").await.unwrap();
    let first = NewDerivationEvent::authored(
        "same-key",
        "person:alice",
        None,
        "create",
        DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
            id: "series-1".into(),
            series_key: "one".into(),
            definition: json!({}),
        }),
    )
    .unwrap();
    append(&db, first).await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let error = append_derivation_event_in(
        &mut tx,
        NewDerivationEvent::authored(
            "same-key",
            "person:alice",
            None,
            "create",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: "series-2".into(),
                series_key: "two".into(),
                definition: json!({}),
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("different intent"));
}

#[tokio::test]
async fn controlled_success_identity_uses_full_coordination_key_variants() {
    let db = crate::db::create_database(":memory:").await.unwrap();
    let source = sqlx::query(
        "SELECT id,record_id,payload FROM content_events
          WHERE payload IS NOT NULL ORDER BY seq LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event: String = source.try_get("id").unwrap();
    let source_record: String = source.try_get("record_id").unwrap();
    let source_payload: String = source.try_get("payload").unwrap();
    let source_sha =
        digest_json(&serde_json::from_str::<serde_json::Value>(&source_payload).unwrap());
    sqlx::query(
        "INSERT INTO recipe_releases
         (publication_event_id,program_id,source_event_id,source_sha256,descriptor_sha256,
          descriptor,status,local_event_seq,status_event_seq,published_at)
         VALUES(?,?,?,?,?,?,'published',1,1,'2026-01-01T00:00:00Z')",
    )
    .bind(&source_event)
    .bind(&source_record)
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
            "series:controlled-identities",
            "agent:test",
            None,
            "define series",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: "series:controlled-identities".into(),
                series_key: "series:controlled-identities".into(),
                definition: json!({"controlled":true}),
            }),
        )
        .unwrap(),
    )
    .await;
    let mut predecessor = None;
    let keys = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
    for (ordinal, key) in keys.iter().enumerate() {
        let id = format!("revision:controlled:{ordinal}");
        append(
            &db,
            NewDerivationEvent::authored(
                format!("event:controlled:{ordinal}"),
                "agent:test",
                None,
                "persist controlled variant",
                DerivationEventPayload::RevisionCompleted(DerivationRevisionCompleted {
                    id: id.clone(),
                    series_id: "series:controlled-identities".into(),
                    predecessor_revision_id: predecessor.clone(),
                    canonical_request: CanonicalDerivationRequest {
                        query_contract: "native.test.v1".into(),
                        query_contract_version: 1,
                        selection: json!({}),
                        scope: json!({}),
                    },
                    recipe_revision: RecipeRevisionRef {
                        definition_id: source_record.clone(),
                        publication_id: source_event.clone(),
                        sha256: source_sha.clone(),
                    },
                    effective_source_boundary: EffectiveSourceBoundary {
                        after_seq: Some(0),
                        through_seq: 1,
                        resolved_scope_membership_sha256: "d".repeat(64),
                        metadata: json!({}),
                    },
                    inputs: vec![DerivationInput {
                        input_role: "source".into(),
                        input_kind: "content_event".into(),
                        portable_id: source_event.clone(),
                        sha256: source_sha.clone(),
                        metadata: json!({}),
                    }],
                    output_ref: DerivationOutputRef {
                        output_kind: "content_event".into(),
                        event_id: source_event.clone(),
                        sha256: source_sha.clone(),
                    },
                    completion_metadata: json!({
                        "schema":"native.derivation-completion.v1",
                        "request_key_sha256":key,
                        "target_basis":{"variant":ordinal},
                        "budget":{"variant":ordinal},
                        "audience":{"sha256":format!("audience:{ordinal}")},
                    }),
                }),
            )
            .unwrap(),
        )
        .await;
        predecessor = Some(id);
    }
    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT request_identity_sha256 FROM derivation_revisions
          WHERE series_id='series:controlled-identities' ORDER BY completed_event_seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(stored, keys);
}
