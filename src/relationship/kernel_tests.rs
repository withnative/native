use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map};
use tokio::sync::Barrier;
use uuid::Uuid;

use super::*;

const NOW: &str = "2026-08-12T12:34:56.123Z";

/// Pinned fixture record ids. Both are also interpolated into the legacy-link
/// INSERT below, which is built from these same constants.
const RECORD_A_ID: &str = "4e1a0000-0000-4000-8000-000000000001";
const RECORD_B_ID: &str = "4e1a0000-0000-4000-8000-000000000002";

async fn command(db: &crate::Db) -> CreateRelationshipWithAssertion {
    let origin = crate::identity::database_id(db).await.unwrap();
    let a_ref = crate::identity::encode_native_record(&origin, RECORD_A_ID).unwrap();
    let b_ref = crate::identity::encode_native_record(&origin, RECORD_B_ID).unwrap();
    let endpoints = vec![
        RelationshipEndpoint {
            role: "participant".into(),
            portable_ref: a_ref.clone(),
            record_type: Some("Document".into()),
            record_kind: Some("note".into()),
            record_id: None,
        },
        RelationshipEndpoint {
            role: "participant".into(),
            portable_ref: b_ref,
            record_type: Some("Document".into()),
            record_kind: Some("note".into()),
            record_id: None,
        },
    ];
    let definition = core_relationship_type_manifest()
        .unwrap()
        .relationship_types
        .into_iter()
        .find(|definition| definition.id == "relates_to.v1")
        .unwrap();
    let key = definition
        .canonical_proposition_key(
            &endpoints
                .iter()
                .map(RelationshipEndpoint::proposition_endpoint)
                .collect::<Vec<_>>(),
            &BTreeMap::new(),
        )
        .unwrap();
    let relationship_created = RelationshipCreatedV1 {
        schema_version: 1,
        relationship_revision: 1,
        relationship_type: "relates_to".into(),
        type_definition_id: "relates_to.v1".into(),
        endpoint_semantics: EndpointSemantics::Symmetric,
        endpoints,
        identity_qualifiers: Map::new(),
        canonical_proposition_key: key,
        reducer_id: "default".into(),
        reducer_version: 1,
        legacy_link: None,
    };
    let assertion_created = AssertionCreatedV1 {
        schema_version: 1,
        relationship: RelationshipCoordinate {
            relationship_origin_db_id: origin.clone(),
            relationship_id: Uuid::new_v4().to_string(),
            relationship_revision: 1,
        },
        relationship_created_event: RelationshipEventCoordinate {
            issuer_origin_db_id: origin.clone(),
            event_id: Uuid::new_v4().to_string(),
        },
        stance: "support".into(),
        semantic_claimant: "native-principal:local".into(),
        on_behalf_of: Some("semantic-subject:test".into()),
        rationale: Some("test support".into()),
        valid_from: None,
        valid_until: None,
        causal_parents: Vec::new(),
        origin_admission: OriginAdmissionV1::test_fixture(
            "relates_to.v1",
            "anchor_authorised_support",
            "participant",
            &a_ref,
            "edit_either_anchor_view_both.v1",
            &"a".repeat(64),
            "action-attestation-test",
        ),
        authoring_action_attestation_id: "action-attestation-test".into(),
    };
    prepare_relationship_with_assertion(
        &origin,
        "native-principal:local",
        NOW,
        NOW,
        relationship_created,
        assertion_created,
    )
    .unwrap()
}

fn assertion_event(
    command: &CreateRelationshipWithAssertion,
    expected_stream_version: i64,
    payload: RelationshipEventPayload,
) -> RelationshipEventSpec {
    RelationshipEventSpec {
        event_id: Uuid::new_v4().to_string(),
        stream_id: command.assertion_event.stream_id.clone(),
        expected_stream_version,
        relationship: command.assertion_event.relationship.clone(),
        payload,
        actor: "native-principal:local".into(),
        issuer_origin_db_id: command.assertion_event.issuer_origin_db_id.clone(),
        occurred_at: NOW.into(),
        ingested_at: NOW.into(),
    }
}

#[tokio::test]
async fn atomic_genesis_exact_retry_and_collision_are_deterministic() {
    let db = crate::create_database(":memory:").await.unwrap();
    let command = command(&db).await;
    let created = create_relationship_with_assertion(&db, &command)
        .await
        .unwrap();
    assert!(!created.relationship.exact_retry);
    assert!(!created.assertion.exact_retry);
    let retried = create_relationship_with_assertion(&db, &command)
        .await
        .unwrap();
    assert!(retried.relationship.exact_retry && retried.assertion.exact_retry);
    assert_eq!(retried.relationship.seq, created.relationship.seq);
    assert_eq!(retried.assertion.seq, created.assertion.seq);

    let mut collision = command.clone();
    collision.relationship_event.actor = "native-principal:different".into();
    let error = create_relationship_with_assertion(&db, &collision)
        .await
        .unwrap_err();
    assert!(matches!(error, crate::Error::Conflict(_)));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn stream_cas_and_forced_second_write_failure_leave_no_partial_state() {
    let db = crate::create_database(":memory:").await.unwrap();
    let first = command(&db).await;
    super::persistence::with_forced_atomic_assertion_write_failure(
        create_relationship_with_assertion(&db, &first),
    )
    .await
    .unwrap_err();
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM relationship_events),
                (SELECT COUNT(*) FROM relationships),
                (SELECT COUNT(*) FROM relationship_assertion_heads)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0));

    create_relationship_with_assertion(&db, &first)
        .await
        .unwrap();
    let stale = assertion_event(
        &first,
        0,
        RelationshipEventPayload::AssertionEvidenceAdded(AssertionEvidenceAddedV1 {
            schema_version: 1,
            evidence_ref: "native-evidence:test".into(),
            reason: "test".into(),
        }),
    );
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let error = append_relationship_event_in(&mut tx, &stale)
        .await
        .unwrap_err();
    assert!(matches!(error, crate::Error::Conflict(_)));
    tx.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 2, "failed append savepoint leaked an event");
}

#[tokio::test]
async fn assertion_state_machine_never_mutates_another_assertion() {
    let db = crate::create_database(":memory:").await.unwrap();
    let command = command(&db).await;
    create_relationship_with_assertion(&db, &command)
        .await
        .unwrap();
    let retracted = assertion_event(
        &command,
        1,
        RelationshipEventPayload::AssertionRetracted(AssertionStateChangedV1 {
            schema_version: 1,
            reason: "withdrawn".into(),
        }),
    );
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    append_relationship_event_in(&mut tx, &retracted)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let illegal_restore = assertion_event(
        &command,
        2,
        RelationshipEventPayload::AssertionRestored(AssertionStateChangedV1 {
            schema_version: 1,
            reason: "cannot restore a retraction".into(),
        }),
    );
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let error = append_relationship_event_in(&mut tx, &illegal_restore)
        .await
        .unwrap_err();
    assert!(matches!(error, crate::Error::Conflict(_)));
    tx.rollback().await.unwrap();
    let head: (String, i64, String) = sqlx::query_as(
        "SELECT assertion_id,stream_version,state FROM relationship_assertion_heads",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        head,
        (command.assertion_event.stream_id, 2, "retracted".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_writers_to_one_assertion_have_one_cas_winner() {
    let db = crate::create_database(":memory:").await.unwrap();
    let command = command(&db).await;
    create_relationship_with_assertion(&db, &command)
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = Vec::new();
    for suffix in ["a", "b"] {
        let db = db.clone();
        let barrier = barrier.clone();
        let spec = assertion_event(
            &command,
            1,
            RelationshipEventPayload::AssertionEvidenceAdded(AssertionEvidenceAddedV1 {
                schema_version: 1,
                evidence_ref: format!("native-evidence:{suffix}"),
                reason: "concurrent evidence".into(),
            }),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let result = append_relationship_event_in(&mut tx, &spec).await;
            match &result {
                Ok(_) => tx.commit().await.unwrap(),
                Err(_) => tx.rollback().await.unwrap(),
            }
            result
        }));
    }
    let results = futures::future::join_all(tasks).await;
    assert_eq!(
        results
            .into_iter()
            .filter(|result| result.as_ref().unwrap().is_ok())
            .count(),
        1
    );
    let versions: Vec<i64> = sqlx::query_scalar(
        "SELECT stream_version FROM relationship_events WHERE stream_kind='assertion' ORDER BY stream_version",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(versions, vec![1, 2]);
}

#[tokio::test]
async fn live_proposition_uniqueness_and_append_only_triggers_hold() {
    let db = crate::create_database(":memory:").await.unwrap();
    let first = command(&db).await;
    create_relationship_with_assertion(&db, &first)
        .await
        .unwrap();
    let second = command(&db).await;
    let error = create_relationship_with_assertion(&db, &second)
        .await
        .unwrap_err();
    assert!(matches!(error, crate::Error::Conflict(_)));
    for statement in [
        "UPDATE relationship_events SET actor='tampered'",
        "DELETE FROM relationship_events",
    ] {
        let error = sqlx::query(statement)
            .execute(db.write_pool())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("append-only"));
    }
}

#[tokio::test]
async fn integrity_scan_accepts_kernel_state_and_rejects_projection_drift() {
    let db = crate::create_database(":memory:").await.unwrap();
    let command = command(&db).await;
    create_relationship_with_assertion(&db, &command)
        .await
        .unwrap();
    assert!(relationship_state_violations(&db).await.unwrap().is_empty());
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE relationship_assertion_heads SET stream_version=7")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(!relationship_state_violations(&db).await.unwrap().is_empty());
}

#[tokio::test]
async fn synchronous_projection_records_endpoint_activity_and_defers_legacy_link_ownership() {
    let db = crate::create_database(":memory:").await.unwrap();
    for id in [RECORD_A_ID, RECORD_B_ID] {
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: id.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Document","kind":"note","name":id}),
                actor: Some("local".into()),
            },
        )
        .await
        .unwrap();
    }
    let mut command = command(&db).await;
    let RelationshipEventPayload::RelationshipCreated(created) =
        &mut command.relationship_event.payload
    else {
        unreachable!()
    };
    for endpoint in &mut created.endpoints {
        endpoint.record_id = Some(
            crate::identity::decode_native_record(&endpoint.portable_ref)
                .unwrap()
                .1,
        );
    }
    create_relationship_with_assertion(&db, &command)
        .await
        .unwrap();
    let activity: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_endpoint_activity")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(activity, 4, "both ledger events affect both endpoints");
    let deterministic: (String, String, String) = sqlx::query_as(
        "SELECT assertion_set_digest,knowledge_watermark,recomputed_at
           FROM effective_relationships",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(deterministic.0.len(), 64);
    assert!(!deterministic.1.contains("seq"));
    assert!(deterministic.1.contains("assertion_issuer_origin_db_id"));
    assert_eq!(deterministic.2, NOW);

    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    sqlx::query(
        "UPDATE relationship_local_admissions
            SET local_admission_state='admitted',
                local_admission_class='anchor_authorised_support'
          WHERE assertion_id=?1",
    )
    .bind(&command.assertion_event.stream_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    super::projector::recompute_relationship_in(
        &mut tx,
        &command
            .relationship_event
            .relationship
            .relationship_origin_db_id,
        &command.relationship_event.relationship.relationship_id,
    )
    .await
    .unwrap();
    let link_id = format!(
        "rel:{}:{}",
        command
            .relationship_event
            .relationship
            .relationship_origin_db_id,
        command.relationship_event.stream_id
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM links WHERE id=?1")
            .bind(&link_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DELETE FROM links WHERE id=?1")
        .bind(&link_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(&format!(
        "INSERT INTO links(id,source_id,target_id,relationship,created_at)
         VALUES('legacy-link','{RECORD_B_ID}','{RECORD_A_ID}','relates_to',?1)"
    ))
    .bind(NOW)
    .execute(&mut *tx)
    .await
    .unwrap();
    super::projector::recompute_relationship_in(
        &mut tx,
        &command
            .relationship_event
            .relationship
            .relationship_origin_db_id,
        &command.relationship_event.relationship.relationship_id,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM links WHERE id=?1")
            .bind(&link_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        0,
        "the legacy content row owns the coordinate until cutover"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM links WHERE id='legacy-link'")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        1
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

async fn append_one(db: &crate::Db, spec: &RelationshipEventSpec) {
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    append_relationship_event_in(&mut tx, spec).await.unwrap();
    tx.commit().await.unwrap();
}

async fn admit_for_convergence(
    db: &crate::Db,
    relationship: &RelationshipCoordinate,
    support_id: &str,
    contest_id: &str,
) {
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    for (assertion_id, class) in [
        (support_id, "anchor_authorised_support"),
        (contest_id, "endpoint_bound_contest"),
    ] {
        sqlx::query(
            "UPDATE relationship_local_admissions
                SET local_admission_state='admitted', local_admission_class=?1
              WHERE issuer_origin_db_id=?2 AND assertion_id=?3",
        )
        .bind(class)
        .bind(&relationship.relationship_origin_db_id)
        .bind(assertion_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    super::projector::recompute_relationship_in(
        &mut tx,
        &relationship.relationship_origin_db_id,
        &relationship.relationship_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn deterministic_projection_snapshot(db: &crate::Db) -> serde_json::Value {
    async fn one(db: &crate::Db, sql: &str) -> serde_json::Value {
        let value: String = sqlx::query_scalar(sql).fetch_one(db.pool()).await.unwrap();
        serde_json::from_str(&value).unwrap()
    }
    async fn many(db: &crate::Db, sql: &str) -> Vec<serde_json::Value> {
        let values: Vec<String> = sqlx::query_scalar(sql).fetch_all(db.pool()).await.unwrap();
        values
            .into_iter()
            .map(|value| serde_json::from_str(&value).unwrap())
            .collect()
    }
    json!({
        "relationship": one(db, "SELECT json_object(
            'relationship_origin_db_id',relationship_origin_db_id,'relationship_id',relationship_id,
            'relationship_revision',relationship_revision,'relationship_type',relationship_type,
            'type_definition_id',type_definition_id,'canonical_proposition_key',canonical_proposition_key,
            'endpoint_semantics',endpoint_semantics,'identity_qualifiers',json(identity_qualifiers),
            'reducer_id',reducer_id,'reducer_version',reducer_version,'stream_version',stream_version,
            'status',status,'successor_origin_db_id',successor_origin_db_id,
            'successor_relationship_id',successor_relationship_id,
            'created_event_issuer_origin_db_id',created_event_issuer_origin_db_id,
            'created_event_id',created_event_id,'last_event_issuer_origin_db_id',last_event_issuer_origin_db_id,
            'last_event_id',last_event_id,'occurred_at',occurred_at) FROM relationships").await,
        "endpoints": many(db, "SELECT json_object(
            'ordinal',ordinal,'role',role,'portable_ref',portable_ref,'record_type',record_type,
            'record_kind',record_kind,'record_id',record_id)
            FROM relationship_endpoints ORDER BY ordinal").await,
        "heads": many(db, "SELECT json_object(
            'issuer_origin_db_id',issuer_origin_db_id,'assertion_id',assertion_id,
            'stream_version',stream_version,'stance',stance,'state',state,
            'causal_parents',json(causal_parents),'origin_admission',json(origin_admission),
            'last_event_issuer_origin_db_id',last_event_issuer_origin_db_id,
            'last_event_id',last_event_id,'occurred_at',occurred_at)
            FROM relationship_assertion_heads ORDER BY issuer_origin_db_id,assertion_id").await,
        "local_admissions": many(db, "SELECT json_object(
            'issuer_origin_db_id',issuer_origin_db_id,'assertion_id',assertion_id,
            'local_admission_state',local_admission_state,'local_admission_class',local_admission_class,
            'type_definition_id',type_definition_id,'local_policy_version',local_policy_version,
            'local_reason',local_reason,'local_evidence_digest',local_evidence_digest,
            'recomputed_at',recomputed_at)
            FROM relationship_local_admissions ORDER BY issuer_origin_db_id,assertion_id").await,
        "effective": one(db, "SELECT json_object(
            'effective_state',effective_state,'epistemic_state',epistemic_state,
            'support_count',support_count,'contest_count',contest_count,
            'admission_counts',json(admission_counts),'reducer_id',reducer_id,
            'reducer_version',reducer_version,'assertion_set_digest',assertion_set_digest,
            'knowledge_watermark',json(knowledge_watermark),'recomputed_at',recomputed_at)
            FROM effective_relationships").await,
        "link": one(db, "SELECT json_object('id',id,'source_id',source_id,'target_id',target_id,
            'relationship',relationship,'note',note,'created_at',created_at)
            FROM links WHERE id LIKE 'rel:%'").await,
    })
}

#[tokio::test]
async fn fixed_assertion_arrival_permutations_converge_full_effective_projection() {
    let left = crate::create_database(":memory:").await.unwrap();
    let right = crate::create_database(":memory:").await.unwrap();
    for db in [&left, &right] {
        for id in [RECORD_A_ID, RECORD_B_ID] {
            crate::store::append(
                db,
                crate::store::AppendSpec {
                    record_id: id.into(),
                    event_type: "record.created".into(),
                    payload: json!({"type":"Document","kind":"note","name":id}),
                    actor: Some("local".into()),
                },
            )
            .await
            .unwrap();
        }
    }

    let mut fixed = command(&left).await;
    let relationship_id = "11111111-1111-4111-8111-111111111111";
    let relationship_event_id = "22222222-2222-4222-8222-222222222222";
    let support_id = "33333333-3333-4333-8333-333333333333";
    let support_event_id = "44444444-4444-4444-8444-444444444444";
    fixed.relationship_event.stream_id = relationship_id.into();
    fixed.relationship_event.event_id = relationship_event_id.into();
    fixed.relationship_event.relationship.relationship_id = relationship_id.into();
    let RelationshipEventPayload::RelationshipCreated(created) =
        &mut fixed.relationship_event.payload
    else {
        unreachable!()
    };
    for endpoint in &mut created.endpoints {
        endpoint.record_id = Some(
            crate::identity::decode_native_record(&endpoint.portable_ref)
                .unwrap()
                .1,
        );
    }
    fixed.assertion_event.stream_id = support_id.into();
    fixed.assertion_event.event_id = support_event_id.into();
    fixed.assertion_event.relationship.relationship_id = relationship_id.into();
    let RelationshipEventPayload::AssertionCreated(support) = &mut fixed.assertion_event.payload
    else {
        unreachable!()
    };
    support.relationship.relationship_id = relationship_id.into();
    support.relationship_created_event.event_id = relationship_event_id.into();

    let relationship = fixed.relationship_event.relationship.clone();
    let endpoint_ref = match &fixed.relationship_event.payload {
        RelationshipEventPayload::RelationshipCreated(created) => {
            created.endpoints[0].portable_ref.clone()
        }
        _ => unreachable!(),
    };
    let contest_id = "55555555-5555-4555-8555-555555555555";
    let contest = RelationshipEventSpec {
        event_id: "66666666-6666-4666-8666-666666666666".into(),
        stream_id: contest_id.into(),
        expected_stream_version: 0,
        relationship: relationship.clone(),
        payload: RelationshipEventPayload::AssertionCreated(AssertionCreatedV1 {
            schema_version: 1,
            relationship: relationship.clone(),
            relationship_created_event: RelationshipEventCoordinate {
                issuer_origin_db_id: relationship.relationship_origin_db_id.clone(),
                event_id: relationship_event_id.into(),
            },
            stance: "contest".into(),
            semantic_claimant: "native-principal:bound-endpoint".into(),
            on_behalf_of: None,
            rationale: Some("fixed convergence contest".into()),
            valid_from: None,
            valid_until: None,
            causal_parents: Vec::new(),
            origin_admission: OriginAdmissionV1::test_fixture(
                "relates_to.v1",
                "endpoint_bound_contest",
                "participant",
                &endpoint_ref,
                "verified_endpoint_binding.v1",
                &"b".repeat(64),
                "action-attestation-contest",
            ),
            authoring_action_attestation_id: "action-attestation-contest".into(),
        }),
        actor: "native-principal:bound-endpoint".into(),
        issuer_origin_db_id: relationship.relationship_origin_db_id.clone(),
        occurred_at: "2026-08-12T12:34:57.123Z".into(),
        ingested_at: "2026-08-12T12:34:58.123Z".into(),
    };

    append_one(&left, &fixed.relationship_event).await;
    append_one(&right, &fixed.relationship_event).await;
    append_one(&left, &fixed.assertion_event).await;
    append_one(&left, &contest).await;
    append_one(&right, &contest).await;
    append_one(&right, &fixed.assertion_event).await;
    for db in [&left, &right] {
        admit_for_convergence(db, &relationship, support_id, contest_id).await;
    }

    let left_order: Vec<String> =
        sqlx::query_scalar("SELECT id FROM relationship_events ORDER BY seq")
            .fetch_all(left.pool())
            .await
            .unwrap();
    let right_order: Vec<String> =
        sqlx::query_scalar("SELECT id FROM relationship_events ORDER BY seq")
            .fetch_all(right.pool())
            .await
            .unwrap();
    assert_ne!(
        left_order, right_order,
        "fixture must genuinely permute arrival"
    );
    let left_snapshot = deterministic_projection_snapshot(&left).await;
    let right_snapshot = deterministic_projection_snapshot(&right).await;
    assert_eq!(left_snapshot, right_snapshot);
    assert_eq!(left_snapshot["effective"]["effective_state"], "active");
    assert_eq!(left_snapshot["effective"]["epistemic_state"], "contested");
    assert_eq!(
        left_snapshot["effective"]["assertion_set_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(left_snapshot["effective"]["knowledge_watermark"].is_array());
}

#[tokio::test]
async fn integrity_scan_rejects_direct_sql_event_envelope_corruption() {
    let db = crate::create_database(":memory:").await.unwrap();
    let command = command(&db).await;
    let event = &command.relationship_event;
    let payload = String::from_utf8(crate::derivation::canonical_json(
        &event.payload.value().unwrap(),
    ))
    .unwrap();
    sqlx::query(
        "INSERT INTO relationship_events
         (id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
          relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at)
         VALUES(?1,'relationship',?2,1,?3,?4,?5,?6,?7,?8,?9,?10)",
    )
    .bind(event.event_id.to_uppercase())
    .bind(&event.stream_id)
    .bind(&event.relationship.relationship_origin_db_id)
    .bind(&event.relationship.relationship_id)
    .bind(event.payload.event_type())
    .bind(payload)
    .bind(&event.actor)
    .bind("ndb_ffffffffffffffffffffffffffffffff")
    .bind("2026-08-12T13:34:56.123+01:00")
    .bind(&event.ingested_at)
    .execute(db.write_pool())
    .await
    .unwrap();

    let violations = relationship_state_violations(&db).await.unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("invalid relationship event envelope")),
        "{violations:#?}"
    );
}

#[test]
fn closed_payloads_uuid_timestamps_admission_and_causality_fail_closed() {
    let origin = "ndb_0123456789abcdef0123456789abcdef";
    let endpoint_ref = crate::identity::encode_native_record(origin, "a").unwrap();
    let base = json!({
        "schema_version":1,
        "relationship":{"relationship_origin_db_id":origin,"relationship_id":Uuid::new_v4().to_string(),"relationship_revision":1},
        "relationship_created_event":{"issuer_origin_db_id":origin,"event_id":Uuid::new_v4().to_string()},
        "stance":"support",
        "semantic_claimant":"principal",
        "on_behalf_of":null,
        "rationale":null,
        "valid_from":null,
        "valid_until":null,
        "causal_parents":[],
        "origin_admission":{
            "schema_version":1,
            "relationship_type_definition":"relates_to.v1",
            "admission_class":"anchor_authorised_support",
            "authority_anchor":{"endpoint_role":"participant","endpoint_ref":endpoint_ref},
            "admission_rule":"edit_either_anchor_view_both.v1",
            "authorization_decision_digest":"a".repeat(64),
            "authoring_action_attestation_id":"attestation"
        },
        "authoring_action_attestation_id":"attestation"
    });
    parse_event_payload("assertion.created.v1", base.clone()).unwrap();
    for (path, value) in [("unknown", json!(true)), ("stance", json!("contest"))] {
        let mut invalid = base.clone();
        invalid[path] = value;
        assert!(parse_event_payload("assertion.created.v1", invalid).is_err());
    }
    let mut invalid_class = base.clone();
    invalid_class["origin_admission"]["admission_class"] = json!("not_governed");
    assert!(parse_event_payload("assertion.created.v1", invalid_class).is_err());
    let mut invalid_parent = base.clone();
    invalid_parent["causal_parents"] = json!([{
        "assertion_issuer_origin_db_id":origin,
        "assertion_id":Uuid::new_v4().to_string(),
        "head_event_issuer_origin_db_id":"ndb_ffffffffffffffffffffffffffffffff",
        "head_event_id":Uuid::new_v4().to_string(),
        "head_stream_version":1
    }]);
    assert!(parse_event_payload("assertion.created.v1", invalid_parent).is_err());
    let mut blank_on_behalf_of = base.clone();
    blank_on_behalf_of["on_behalf_of"] = json!("  ");
    assert!(parse_event_payload("assertion.created.v1", blank_on_behalf_of).is_err());

    let payload = parse_event_payload("assertion.created.v1", base).unwrap();
    let spec = RelationshipEventSpec {
        event_id: Uuid::new_v4().to_string().to_uppercase(),
        stream_id: Uuid::new_v4().to_string(),
        expected_stream_version: 0,
        relationship: match &payload {
            RelationshipEventPayload::AssertionCreated(created) => created.relationship.clone(),
            _ => unreachable!(),
        },
        payload,
        actor: "principal".into(),
        issuer_origin_db_id: origin.into(),
        occurred_at: "not-a-timestamp".into(),
        ingested_at: NOW.into(),
    };
    assert!(spec.validate().is_err());

    let mut noncanonical_valid_time = match spec.payload.clone() {
        RelationshipEventPayload::AssertionCreated(payload) => payload,
        _ => unreachable!(),
    };
    noncanonical_valid_time.valid_from = Some("2026-08-12T13:34:56.123+01:00".into());
    assert!(
        RelationshipEventPayload::AssertionCreated(noncanonical_valid_time)
            .validate()
            .is_err()
    );
}

#[tokio::test]
async fn wildcard_roles_accept_kindless_endpoints_but_constrained_roles_do_not() {
    let db = crate::create_database(":memory:").await.unwrap();
    let mut wildcard = command(&db).await;
    let RelationshipEventPayload::RelationshipCreated(created) =
        &mut wildcard.relationship_event.payload
    else {
        unreachable!()
    };
    for endpoint in &mut created.endpoints {
        endpoint.record_type = None;
        endpoint.record_kind = None;
    }
    assert!(wildcard.relationship_event.payload.validate().is_ok());

    let definition = core_relationship_type_manifest()
        .unwrap()
        .relationship_types
        .into_iter()
        .find(|definition| definition.id == "assigned_to.v1")
        .unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let endpoints = vec![
        RelationshipEndpoint {
            role: "subject".into(),
            portable_ref: crate::identity::encode_native_record(&origin, "task").unwrap(),
            record_type: Some("WorkItem".into()),
            record_kind: None,
            record_id: None,
        },
        RelationshipEndpoint {
            role: "object".into(),
            portable_ref: crate::identity::encode_native_record(&origin, "person").unwrap(),
            record_type: Some("Entity".into()),
            record_kind: Some("person".into()),
            record_id: None,
        },
    ];
    let key = definition
        .canonical_proposition_key(
            &endpoints
                .iter()
                .map(RelationshipEndpoint::proposition_endpoint)
                .collect::<Vec<_>>(),
            &BTreeMap::new(),
        )
        .unwrap();
    let constrained = RelationshipEventPayload::RelationshipCreated(RelationshipCreatedV1 {
        schema_version: 1,
        relationship_revision: 1,
        relationship_type: "assigned_to".into(),
        type_definition_id: "assigned_to.v1".into(),
        endpoint_semantics: EndpointSemantics::Directed,
        endpoints,
        identity_qualifiers: Map::new(),
        canonical_proposition_key: key,
        reducer_id: "assigned_to".into(),
        reducer_version: 1,
        legacy_link: None,
    });
    assert!(constrained.validate().is_err());
    db.close().await;
}

#[test]
fn equivalent_noncanonical_event_timestamps_are_rejected_before_fingerprinting() {
    let origin = "ndb_0123456789abcdef0123456789abcdef";
    let coordinate = RelationshipCoordinate {
        relationship_origin_db_id: origin.into(),
        relationship_id: Uuid::new_v4().to_string(),
        relationship_revision: 1,
    };
    let mut spec = RelationshipEventSpec {
        event_id: Uuid::new_v4().to_string(),
        stream_id: coordinate.relationship_id.clone(),
        expected_stream_version: 0,
        relationship: coordinate,
        payload: RelationshipEventPayload::RelationshipRetired(RelationshipRetiredV1 {
            schema_version: 1,
            reason: "canonical".into(),
        }),
        actor: "principal".into(),
        issuer_origin_db_id: origin.into(),
        occurred_at: NOW.into(),
        ingested_at: NOW.into(),
    };
    assert!(spec.fingerprint().is_ok());
    spec.occurred_at = "2026-08-12T13:34:56.123+01:00".into();
    assert!(spec.fingerprint().is_err());
    spec.occurred_at = "2026-08-12T12:34:56.123Z".into();
    spec.ingested_at = "2026-08-12T12:34:56Z".into();
    assert!(spec.fingerprint().is_err());
}

#[test]
fn fingerprint_is_jcs_stable_and_excludes_receiver_ingest_time() {
    let origin = "ndb_0123456789abcdef0123456789abcdef";
    let coordinate = RelationshipCoordinate {
        relationship_origin_db_id: origin.into(),
        relationship_id: Uuid::new_v4().to_string(),
        relationship_revision: 1,
    };
    let mut a = RelationshipEventSpec {
        event_id: Uuid::new_v4().to_string(),
        stream_id: coordinate.relationship_id.clone(),
        expected_stream_version: 0,
        relationship: coordinate,
        payload: RelationshipEventPayload::RelationshipRetired(RelationshipRetiredV1 {
            schema_version: 1,
            reason: "canonical".into(),
        }),
        actor: "principal".into(),
        issuer_origin_db_id: origin.into(),
        occurred_at: NOW.into(),
        ingested_at: NOW.into(),
    };
    let fingerprint = a.fingerprint().unwrap();
    a.ingested_at = "2026-08-12T12:35:00.000Z".into();
    assert_eq!(a.fingerprint().unwrap(), fingerprint);
    a.actor = "other".into();
    assert_ne!(a.fingerprint().unwrap(), fingerprint);
}
