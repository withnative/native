use serde_json::json;
use sqlx::Row;

use crate::db::{begin_write, Db};

use super::*;

async fn append(db: &Db, input: NewDerivationEvent) -> DerivationEventRow {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut act_alloc = crate::act::ActAllocation::new();
    let event = append_derivation_event_in(&mut tx, input, &mut act_alloc)
        .await
        .unwrap();
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
    let mut act_alloc = crate::act::ActAllocation::new();
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
        &mut act_alloc,
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

#[tokio::test]
async fn derivation_events_in_act_range_is_bounded_ordered_and_excludes_null_acts() {
    use std::collections::BTreeMap;

    const LEGACY: &str = "derivation-event-legacy-null-act";

    let db = crate::db::create_database(":memory:").await.unwrap();
    // Three real authored series, each committed by its own seam call so each
    // carries its own act stamp.
    for ordinal in 0..3 {
        append(
            &db,
            NewDerivationEvent::authored(
                format!("series:act-range-{ordinal}"),
                "person:alice",
                Some(format!("run-{ordinal}")),
                "define a range witness series",
                DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                    id: format!("series:act-range-{ordinal}"),
                    series_key: format!("act-range:{ordinal}"),
                    definition: json!({"output":"note","recipe":"native/range"}),
                }),
            )
            .unwrap(),
        )
        .await;
    }
    // A legacy grouping-unknown row: `NULL` act, schema-valid, narrow.
    sqlx::query(
        "INSERT INTO derivation_events
             (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
              actor,run_key,reason,payload,created_at,act)
         VALUES(?,'legacy-key','derivation.series.created',1,'derivation_series',
                'series:legacy','engine:seed',NULL,'legacy act witness','{}',
                '2026-01-01T00:00:00.000Z',NULL)",
    )
    .bind(LEGACY)
    .execute(db.write_pool())
    .await
    .unwrap();

    let mut conn = db.pool().acquire().await.unwrap();
    let full = read_all_derivation_events(&mut conn).await.unwrap();

    let act_of: BTreeMap<i64, Option<i64>> = sqlx::query("SELECT seq, act FROM derivation_events")
        .fetch_all(&mut *conn)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get("seq"), row.get("act")))
        .collect();
    let mut acts: Vec<i64> = act_of.values().flatten().copied().collect();
    acts.sort_unstable();
    acts.dedup();
    assert!(
        acts.len() >= 3,
        "the test expects at least three stamped acts"
    );

    for (from_exclusive, to_inclusive) in
        [(acts[0], acts[2]), (acts[1], acts[2]), (acts[0], acts[1])]
    {
        let bounded = derivation_events_in_act_range(&mut conn, from_exclusive, to_inclusive)
            .await
            .unwrap();
        assert!(bounded.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        let expected: Vec<DerivationEventRow> = full
            .iter()
            .filter(|event| {
                act_of[&event.seq].is_some_and(|act| act > from_exclusive && act <= to_inclusive)
            })
            .cloned()
            .collect();
        assert_eq!(
            bounded, expected,
            "range ({from_exclusive}, {to_inclusive}]"
        );
        assert!(
            !bounded.iter().any(|event| event.id == LEGACY),
            "a NULL-act row never matches the range predicate"
        );
    }

    // Equal bounds are the empty half-open interval, not a widening.
    assert!(derivation_events_in_act_range(&mut conn, acts[2], acts[2])
        .await
        .unwrap()
        .is_empty());
    // The NULL row is still part of the full log, proving it was excluded by
    // the predicate and not dropped by the decoder.
    assert!(full.iter().any(|event| event.id == LEGACY));
}
