use serde_json::json;
use sqlx::Row;

use crate::authorization::{AllowEntry, Capability, Principal};
use crate::db::{begin_write, Db};
use crate::store::{create_record, EventAnnotations};

use super::*;

/// Pinned fixture record ids. Nothing here reads an id's text back and no
/// assertion orders by id, so only their identity and distinctness matter.
const RECIPE_ID: &str = "c0f14000-0000-4000-8000-000000000001";
const SOURCE_ONE_ID: &str = "c0f14000-0000-4000-8000-000000000002";
const SOURCE_TWO_ID: &str = "c0f14000-0000-4000-8000-000000000003";
const SOURCE_THREE_ID: &str = "c0f14000-0000-4000-8000-000000000004";
const SOURCE_TOMBSTONED_ID: &str = "c0f14000-0000-4000-8000-000000000005";
const WEEKLY_CHANGE_SUMMARY_ID: &str = "c0f14000-0000-4000-8000-000000000006";
const UNBOUND_ROLE_NOTE_ID: &str = "c0f14000-0000-4000-8000-000000000007";
const RECIPE_PUBLICATION_ID: &str = "11111111-1111-4111-8111-111111111111";
const OUTPUT_CONTRACT_ID: &str = "native.change-summary.test.v1";

struct CurrentApplicability;

impl RevisionApplicabilityGate for CurrentApplicability {
    fn is_current_and_audience_available<'a>(
        &'a self,
        _snapshot: &'a mut sqlx::Transaction<'static, sqlx::Sqlite>,
        _basis: &'a RevisionRecognitionBasis,
    ) -> futures::future::BoxFuture<'a, crate::Result<bool>> {
        Box::pin(async { Ok(true) })
    }
}

struct UnavailableApplicability;

impl RevisionApplicabilityGate for UnavailableApplicability {
    fn is_current_and_audience_available<'a>(
        &'a self,
        _snapshot: &'a mut sqlx::Transaction<'static, sqlx::Sqlite>,
        _basis: &'a RevisionRecognitionBasis,
    ) -> futures::future::BoxFuture<'a, crate::Result<bool>> {
        Box::pin(async { Ok(false) })
    }
}

struct OnlyRevisionApplicability(&'static str);

impl RevisionApplicabilityGate for OnlyRevisionApplicability {
    fn is_current_and_audience_available<'a>(
        &'a self,
        _snapshot: &'a mut sqlx::Transaction<'static, sqlx::Sqlite>,
        basis: &'a RevisionRecognitionBasis,
    ) -> futures::future::BoxFuture<'a, crate::Result<bool>> {
        Box::pin(async move { Ok(basis.revision_id == self.0) })
    }
}

fn output_contract() -> OutputContractSelector {
    OutputContractSelector {
        id: OUTPUT_CONTRACT_ID.into(),
        version: 1,
    }
}

fn recipe_publication_payload() -> serde_json::Value {
    json!({"summary":"fixture recipe publication identity"})
}

fn recipe_publication_sha256() -> String {
    digest_json(&recipe_publication_payload())
}

#[derive(Clone)]
struct PublishedFixture {
    target: DerivationTarget,
    assignment: ArtifactRoleAssigned,
    assignment_event: DerivationEventRow,
    source_events: Vec<(String, String)>,
}

async fn append(db: &Db, input: NewDerivationEvent) -> DerivationEventRow {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let event = append_derivation_event_in(&mut tx, input).await.unwrap();
    tx.commit().await.unwrap();
    event
}

async fn source(db: &Db, id: &str, run_key: &str, visible: bool) -> (String, String) {
    let record_id = crate::store::with_event_annotations(
        EventAnnotations {
            run_key: Some(run_key.into()),
            parent_key: None,
            intent: Some("source run".into()),
        },
        create_record(
            db,
            json!({"id":id,"type":"Document","kind":"note","name":id,"body":"source"}),
        ),
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        db,
        "fixture",
        &record_id,
        vec![AllowEntry::account(
            if visible { "agent:test" } else { "agent:other" },
            Capability::Manage,
        )],
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
    let event_id: String = row.try_get("id").unwrap();
    let payload: String = row.try_get("payload").unwrap();
    let digest = digest_json(&serde_json::from_str(&payload).unwrap());
    (event_id, digest)
}

fn revision(
    id: &str,
    predecessor: Option<&str>,
    sources: &[(String, String)],
) -> DerivationRevisionCompleted {
    DerivationRevisionCompleted {
        id: id.into(),
        series_id: "series:change-summary".into(),
        predecessor_revision_id: predecessor.map(str::to_owned),
        canonical_request: CanonicalDerivationRequest {
            query_contract: "native.change-summary.test.v1".into(),
            query_contract_version: 1,
            selection: json!({"runs":3,"revision":id}),
            scope: json!({"fixture":true}),
        },
        recipe_revision: RecipeRevisionRef {
            definition_id: RECIPE_ID.into(),
            publication_id: RECIPE_PUBLICATION_ID.into(),
            sha256: recipe_publication_sha256(),
        },
        effective_source_boundary: EffectiveSourceBoundary {
            after_seq: Some(0),
            through_seq: 3,
            resolved_scope_membership_sha256: "a".repeat(64),
            metadata: json!({}),
        },
        inputs: sources
            .iter()
            .map(|(event_id, sha256)| DerivationInput {
                input_role: "source".into(),
                input_kind: "content_event".into(),
                portable_id: event_id.clone(),
                sha256: sha256.clone(),
                metadata: json!({}),
            })
            .collect(),
        output_ref: DerivationOutputRef {
            output_kind: "content_event".into(),
            event_id: sources[0].0.clone(),
            sha256: sources[0].1.clone(),
        },
        completion_metadata: json!({"fixture":true}),
    }
}

async fn fixture() -> (Db, PublishedFixture) {
    let db = crate::db::create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({"id":RECIPE_ID,"type":"Program","kind":"recipe","name":"Fixture recipe"}),
    )
    .await
    .unwrap();
    let mut recipe_tx = begin_write(db.write_pool()).await.unwrap();
    crate::store::append_with_event_id_in(
        &db,
        &mut recipe_tx,
        RECIPE_PUBLICATION_ID.into(),
        crate::store::AppendSpec {
            record_id: RECIPE_ID.into(),
            event_type: "record.updated".into(),
            payload: recipe_publication_payload(),
            actor: Some("fixture".into()),
        },
    )
    .await
    .unwrap();
    db.commit_content(recipe_tx).await.unwrap();
    sqlx::query(
        "INSERT INTO recipe_releases
         (publication_event_id,program_id,source_event_id,source_sha256,descriptor_sha256,
          descriptor,status,local_event_seq,status_event_seq,published_at)
         VALUES(?,?,?,?,?,?,'withdrawn',?,?,?)",
    )
    .bind(RECIPE_PUBLICATION_ID)
    .bind(RECIPE_ID)
    .bind("recipe-source:event")
    .bind("c".repeat(64))
    .bind(recipe_publication_sha256())
    .bind(
        json!({
            "definition": {
                "output_contract": {
                    "id": OUTPUT_CONTRACT_ID,
                    "version": 1
                }
            }
        })
        .to_string(),
    )
    .bind(1_i64)
    .bind(1_i64)
    .bind("2026-08-04T00:00:00.000Z")
    .execute(db.write_pool())
    .await
    .unwrap();
    let sources = vec![
        source(&db, SOURCE_ONE_ID, "run:one", true).await,
        source(&db, SOURCE_TWO_ID, "run:two", true).await,
        source(&db, SOURCE_THREE_ID, "run:three", false).await,
    ];
    let carrier = create_record(
        &db,
        json!({
            "id":WEEKLY_CHANGE_SUMMARY_ID,
            "type":"Document",
            "kind":"note",
            "name":"A title that carries no recognition semantics",
            "body":null
        }),
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "fixture",
        &carrier,
        vec![AllowEntry::account("agent:test", Capability::Manage)],
    )
    .await
    .unwrap();
    let carrier_event = sqlx::query(
        "SELECT id,payload FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(&carrier)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let carrier_event_id: String = carrier_event.try_get("id").unwrap();
    let carrier_payload: String = carrier_event.try_get("payload").unwrap();
    let carrier_sha = digest_json(&serde_json::from_str(&carrier_payload).unwrap());
    append(
        &db,
        NewDerivationEvent::authored(
            "series:change-summary",
            "agent:test",
            None,
            "create change-summary series",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: "series:change-summary".into(),
                series_key: "change-summary:test".into(),
                definition: json!({"product_neutral":true}),
            }),
        )
        .unwrap(),
    )
    .await;
    let target = DerivationTarget::record_body(&carrier);
    bind_target(
        &db,
        Principal::bound("agent:test", true),
        "bind:change-summary",
        "agent:test",
        None,
        "bind summary carrier",
        DerivationTargetBound {
            binding_id: "binding:change-summary".into(),
            series_id: "series:change-summary".into(),
            target: target.clone(),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(carrier_event_id),
            expected_body_sha256: Some(carrier_sha),
        },
    )
    .await
    .unwrap();
    publish_record_body_revision(
        &db,
        Principal::bound("agent:test", true),
        PublishRecordBodyRevision {
            publication_idempotency_key: "publish:summary:one".into(),
            revision_idempotency_key: "revision:summary:one".into(),
            actor: "agent:test".into(),
            run_key: Some("run:summary:one".into()),
            reason: "publish summary draft".into(),
            publication_id: "publication:summary:one".into(),
            binding_id: "binding:change-summary".into(),
            target: target.clone(),
            expected_generation: 1,
            expected_target_version: 1,
            body: "three changes".into(),
            revision: revision("revision:summary:one", None, &sources),
        },
    )
    .await
    .unwrap();
    let assignment = ArtifactRoleAssigned {
        assignment_id: "role:summary:one".into(),
        target: target.clone(),
        role: CHANGE_SUMMARY_ROLE.into(),
        expected_role_head_event_id: None,
    };
    let assignment_event = assign_artifact_role(
        &db,
        Principal::bound("agent:test", true),
        "role:assign:one",
        "agent:test",
        None,
        "recognize as change summary",
        assignment.clone(),
    )
    .await
    .unwrap();
    (
        db,
        PublishedFixture {
            target,
            assignment,
            assignment_event,
            source_events: sources,
        },
    )
}

async fn confirmation(
    db: &Db,
    fixture: &PublishedFixture,
    confirmation_id: &str,
    revision_id: &str,
    publication_id: &str,
    target_version: i64,
    expected_head: Option<String>,
) -> RevisionConfirmed {
    let row = sqlx::query(
        "SELECT r.input_manifest_sha256,p.output_sha256
           FROM derivation_revisions r
           JOIN derivation_target_publications p ON p.revision_id=r.id
          WHERE r.id=? AND p.publication_id=?",
    )
    .bind(revision_id)
    .bind(publication_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    RevisionConfirmed {
        confirmation_id: confirmation_id.into(),
        assignment_id: fixture.assignment.assignment_id.clone(),
        target: fixture.target.clone(),
        role: CHANGE_SUMMARY_ROLE.into(),
        series_id: "series:change-summary".into(),
        revision_id: revision_id.into(),
        publication_id: publication_id.into(),
        binding_id: "binding:change-summary".into(),
        expected_generation: 1,
        expected_target_version: target_version,
        expected_input_manifest_sha256: row.try_get("input_manifest_sha256").unwrap(),
        expected_output_sha256: row.try_get("output_sha256").unwrap(),
        expected_confirmation_head_event_id: expected_head,
    }
}

#[tokio::test]
async fn role_not_heuristics_recognizes_one_confirmed_artifact_and_peers_into_three_runs() {
    let (db, fixture) = fixture().await;
    let principal = Principal::bound("agent:test", true);
    // A note title/kind alone is never recognition. A different role is also
    // not silently treated as a change summary.
    assert!(query_confirmed_artifacts(
        &db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        10,
        10,
        &CurrentApplicability,
    )
    .await
    .unwrap()
    .items
    .is_empty());
    let confirmation = confirmation(
        &db,
        &fixture,
        "confirmation:one",
        "revision:summary:one",
        "publication:summary:one",
        2,
        None,
    )
    .await;
    confirm_revision(
        &db,
        principal,
        "confirm:one",
        "agent:test",
        None,
        "ship the weekly summary",
        confirmation,
    )
    .await
    .unwrap();
    assert!(query_confirmed_artifacts(
        &db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &OutputContractSelector {
            id: "native.some-other-result.v1".into(),
            version: 1,
        },
        None,
        10,
        10,
        &CurrentApplicability,
    )
    .await
    .unwrap()
    .items
    .is_empty());
    assert!(query_confirmed_artifacts(
        &db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        10,
        10,
        &UnavailableApplicability,
    )
    .await
    .unwrap()
    .items
    .is_empty());
    let results = query_confirmed_artifacts(
        &db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        10,
        10,
        &CurrentApplicability,
    )
    .await
    .unwrap();
    assert_eq!(results.items.len(), 1);
    assert_eq!(results.items[0].confirmed_body, "three changes");
    assert_eq!(results.items[0].source_runs.len(), 3);
    assert_eq!(
        results.items[0]
            .source_runs
            .iter()
            .filter(|run| run.redacted)
            .count(),
        1
    );
    let mut visible_runs = results.items[0]
        .source_runs
        .iter()
        .filter_map(|run| run.run_key.as_deref())
        .collect::<Vec<_>>();
    visible_runs.sort_unstable();
    assert_eq!(visible_runs, vec!["run:one", "run:two"]);
}

#[tokio::test]
async fn capped_inapplicable_scan_returns_a_cursor_that_reaches_the_later_current_artifact() {
    let (db, fixture) = fixture().await;
    let principal = Principal::bound("agent:test", true);
    confirm_revision(
        &db,
        principal,
        "confirm:scan:valid",
        "agent:test",
        None,
        "ship the artifact behind the inapplicable scan window",
        confirmation(
            &db,
            &fixture,
            "confirmation:scan:valid",
            "revision:summary:one",
            "publication:summary:one",
            2,
            None,
        )
        .await,
    )
    .await
    .unwrap();

    let recipe_revision = json!({
        "definition_id":RECIPE_ID,
        "publication_id":RECIPE_PUBLICATION_ID,
        "sha256":recipe_publication_sha256()
    })
    .to_string();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    for ordinal in 0..1_000_i64 {
        let suffix = format!("{ordinal:04}");
        let carrier = format!("scan:carrier:{suffix}");
        let binding = format!("scan:binding:{suffix}");
        let revision = format!("scan:revision:{suffix}");
        let publication = format!("scan:publication:{suffix}");
        let assignment = format!("scan:assignment:{suffix}");
        let confirmation = format!("scan:confirmation:{suffix}");
        let digest = digest_json(&json!({"scan":ordinal}));
        let sequence = 10_000 + ordinal;
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id)
             VALUES(?,'Document','note',?,?,?)",
        )
        .bind(&carrier)
        .bind(&carrier)
        .bind(&fixture.target.record_id)
        .bind(&fixture.target.record_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_target_bindings
             (binding_id,series_id,target_kind,target_record_id,target_slot,generation,
              bound_event_id,bound_event_seq,bound_at)
             VALUES(?,'series:change-summary','record',?,'body',1,?,?,?)",
        )
        .bind(&binding)
        .bind(&carrier)
        .bind(format!("scan:bound:event:{suffix}"))
        .bind(sequence)
        .bind("2026-08-04T00:00:00.000Z")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_revisions
             (id,series_id,predecessor_revision_id,definition_sha256,canonical_request,
              canonical_request_sha256,request_identity_sha256,recipe_revision,
              recipe_revision_ref_sha256,effective_source_boundary,
              effective_source_boundary_sha256,input_manifest,input_manifest_sha256,
              output_ref,output_ref_sha256,completion_metadata,completion_metadata_sha256,
              completed_event_id,completed_event_seq,completed_at)
             VALUES(?,'series:change-summary',NULL,?,
                    '{\"query_contract\":\"native.scan.v1\",\"query_contract_version\":1,\"selection\":{},\"scope\":{}}',
                    ?,?,?,?,
                    '{\"after_seq\":null,\"through_seq\":1,\"resolved_scope_membership_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"metadata\":{}}',
                    ?,'{}',?,
                    '{\"output_kind\":\"content_event\",\"event_id\":\"fixture\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}',
                    ?,'{}',?,?,?,?)",
        )
        .bind(&revision)
        .bind("d".repeat(64))
        .bind(&digest)
        .bind(&digest)
        .bind(&recipe_revision)
        .bind(recipe_publication_sha256())
        .bind(&digest)
        .bind(&digest)
        .bind(&digest)
        .bind(&digest)
        .bind(format!("scan:revision:event:{suffix}"))
        .bind(sequence)
        .bind("2026-08-04T00:00:00.000Z")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_target_publications
             (publication_id,binding_id,generation,target_version,revision_id,output_event_id,
              output_sha256,published_event_id,published_event_seq,published_at)
             VALUES(?,?,1,1,?,?,?, ?,?,?)",
        )
        .bind(&publication)
        .bind(&binding)
        .bind(&revision)
        .bind(format!("scan:output:event:{suffix}"))
        .bind(&digest)
        .bind(format!("scan:published:event:{suffix}"))
        .bind(sequence)
        .bind("2026-08-04T00:00:00.000Z")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_target_heads
             (target_kind,target_record_id,target_slot,generation,target_version,
              active_binding_id,selected_publication_id)
             VALUES('record',?,'body',1,1,?,NULL)",
        )
        .bind(&carrier)
        .bind(&binding)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_artifact_role_assignments
             (assignment_id,target_kind,target_record_id,target_slot,role,
              assigned_event_id,assigned_event_seq,assigned_at)
             VALUES(?,'record',?,'body',?,?,?,?)",
        )
        .bind(&assignment)
        .bind(&carrier)
        .bind(CHANGE_SUMMARY_ROLE)
        .bind(format!("scan:assigned:event:{suffix}"))
        .bind(sequence)
        .bind("2026-08-04T00:00:00.000Z")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_artifact_role_heads
             (target_kind,target_record_id,target_slot,role,active_assignment_id,
              head_event_id,head_event_seq)
             VALUES('record',?,'body',?,?,?,?)",
        )
        .bind(&carrier)
        .bind(CHANGE_SUMMARY_ROLE)
        .bind(&assignment)
        .bind(format!("scan:role-head:event:{suffix}"))
        .bind(sequence)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_revision_confirmations
             (confirmation_id,assignment_id,series_id,revision_id,publication_id,binding_id,
              generation,target_version,input_manifest_sha256,output_sha256,
              predecessor_head_event_id,confirmed_event_id,confirmed_event_seq,
              confirmed_at,confirmed_by)
             VALUES(?,?,'series:change-summary',?,?,?,1,1,?,?,NULL,?,?,?,'agent:test')",
        )
        .bind(&confirmation)
        .bind(&assignment)
        .bind(&revision)
        .bind(&publication)
        .bind(&binding)
        .bind(&digest)
        .bind(&digest)
        .bind(format!("scan:confirmed:event:{suffix}"))
        .bind(sequence)
        .bind("2026-08-04T00:00:00.000Z")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO derivation_confirmation_heads
             (assignment_id,confirmation_id,head_event_id,head_event_seq)
             VALUES(?,?,?,?)",
        )
        .bind(&assignment)
        .bind(&confirmation)
        .bind(format!("scan:confirmation-head:event:{suffix}"))
        .bind(sequence)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let gate = OnlyRevisionApplicability("revision:summary:one");
    let capped = query_confirmed_artifacts(
        &db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        1,
        10,
        &gate,
    )
    .await
    .unwrap();
    assert!(capped.items.is_empty());
    let continuation = capped
        .next_cursor
        .expect("the capped empty page must retain its last scanned position");
    let serialized_cursor = serde_json::to_value(&continuation).unwrap();
    assert_eq!(
        serialized_cursor
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["token"]
    );
    let cursor_bytes = serialized_cursor.to_string();
    assert!(!cursor_bytes.contains("scan:assignment"));
    assert!(!cursor_bytes.contains("scan:confirmation"));
    let resumed = query_confirmed_artifacts(
        &db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        Some(&continuation),
        1,
        10,
        &gate,
    )
    .await
    .unwrap();
    assert_eq!(resumed.items.len(), 1);
    assert_eq!(resumed.items[0].revision_id, "revision:summary:one");
}

#[tokio::test]
async fn confirmation_reauthenticates_actor_and_serializes_competing_heads() {
    let (db, fixture) = fixture().await;
    let principal = Principal::bound("agent:test", true);
    let base = confirmation(
        &db,
        &fixture,
        "confirmation:race:a",
        "revision:summary:one",
        "publication:summary:one",
        2,
        None,
    )
    .await;
    let wrong_actor = confirm_revision(
        &db,
        principal,
        "confirm:wrong-actor",
        "agent:other",
        None,
        "must fail",
        base.clone(),
    )
    .await
    .unwrap_err();
    assert!(wrong_actor.to_string().contains("actor must match"));
    let denied = confirm_revision(
        &db,
        Principal::bound("agent:other", true),
        "confirm:denied",
        "agent:other",
        None,
        "must fail",
        base.clone(),
    )
    .await
    .unwrap_err();
    assert!(denied.to_string().contains("requires Edit"));
    let mut competing = base.clone();
    competing.confirmation_id = "confirmation:race:b".into();
    let left = confirm_revision(
        &db,
        principal,
        "confirm:race:a",
        "agent:test",
        None,
        "race confirmation",
        base.clone(),
    );
    let right = confirm_revision(
        &db,
        principal,
        "confirm:race:b",
        "agent:test",
        None,
        "race confirmation",
        competing,
    );
    let (left, right) = tokio::join!(left, right);
    assert_ne!(left.is_ok(), right.is_ok());
    let winner = left.or(right).unwrap();
    let retry_payload = if winner.aggregate_id == base.confirmation_id {
        base
    } else {
        let mut value = base;
        value.confirmation_id = "confirmation:race:b".into();
        value
    };
    let retry_key = if winner.aggregate_id == retry_payload.confirmation_id {
        if retry_payload.confirmation_id.ends_with(":a") {
            "confirm:race:a"
        } else {
            "confirm:race:b"
        }
    } else {
        unreachable!()
    };
    let retry = confirm_revision(
        &db,
        principal,
        retry_key,
        "agent:test",
        Some("later-run".into()),
        "race confirmation",
        retry_payload,
    )
    .await
    .unwrap();
    assert_eq!(retry.id, winner.id);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM derivation_revision_confirmations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn editor_agents_and_humans_can_confirm_and_retract_but_viewers_cannot() {
    let (db, fixture) = fixture().await;
    crate::authorization::replace_explicit_policy(
        &db,
        "fixture",
        &fixture.target.record_id,
        vec![
            AllowEntry::account("agent:editor", Capability::Edit),
            AllowEntry::account("person:editor", Capability::Edit),
            AllowEntry::account("agent:viewer", Capability::View),
        ],
    )
    .await
    .unwrap();
    let candidate = confirmation(
        &db,
        &fixture,
        "confirmation:editor",
        "revision:summary:one",
        "publication:summary:one",
        2,
        None,
    )
    .await;
    let denied = confirm_revision(
        &db,
        Principal::bound("agent:viewer", true),
        "confirm:viewer",
        "agent:viewer",
        None,
        "viewer cannot confirm",
        candidate.clone(),
    )
    .await
    .unwrap_err();
    assert!(denied.to_string().contains("requires Edit"));
    let confirmed = confirm_revision(
        &db,
        Principal::bound("agent:editor", true),
        "confirm:editor",
        "agent:editor",
        None,
        "authorized agent judgement",
        candidate,
    )
    .await
    .unwrap();
    let retracted = retract_confirmation(
        &db,
        Principal::bound("person:editor", true),
        "retract:editor",
        "person:editor",
        None,
        "authorized human correction",
        ConfirmationRetracted {
            retraction_id: "retraction:editor".into(),
            confirmation_id: "confirmation:editor".into(),
            assignment_id: fixture.assignment.assignment_id,
            target: fixture.target,
            expected_confirmation_head_event_id: confirmed.id,
        },
    )
    .await
    .unwrap();
    assert_eq!(retracted.actor, "person:editor");
}

#[tokio::test]
async fn stale_cas_rolls_back_without_turning_publication_into_confirmation() {
    let (db, fixture) = fixture().await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM derivation_revision_confirmations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
    let mut stale = confirmation(
        &db,
        &fixture,
        "confirmation:stale",
        "revision:summary:one",
        "publication:summary:one",
        2,
        None,
    )
    .await;
    stale.expected_input_manifest_sha256 = "f".repeat(64);
    let error = confirm_revision(
        &db,
        Principal::bound("agent:test", true),
        "confirm:stale",
        "agent:test",
        None,
        "stale confirmation",
        stale,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("CAS"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM derivation_events WHERE type='derivation.revision.confirmed'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn newer_publish_is_a_draft_and_retraction_restores_prior_confirmation_history() {
    let (db, fixture) = fixture().await;
    let principal = Principal::bound("agent:test", true);
    let first = confirmation(
        &db,
        &fixture,
        "confirmation:one",
        "revision:summary:one",
        "publication:summary:one",
        2,
        None,
    )
    .await;
    let first_event = confirm_revision(
        &db,
        principal,
        "confirm:one",
        "agent:test",
        None,
        "ship first",
        first,
    )
    .await
    .unwrap();
    publish_record_body_revision(
        &db,
        principal,
        PublishRecordBodyRevision {
            publication_idempotency_key: "publish:summary:two".into(),
            revision_idempotency_key: "revision:summary:two".into(),
            actor: "agent:test".into(),
            run_key: Some("run:summary:two".into()),
            reason: "publish successor draft".into(),
            publication_id: "publication:summary:two".into(),
            binding_id: "binding:change-summary".into(),
            target: fixture.target.clone(),
            expected_generation: 1,
            expected_target_version: 2,
            body: "four changes".into(),
            revision: revision(
                "revision:summary:two",
                Some("revision:summary:one"),
                &fixture.source_events,
            ),
        },
    )
    .await
    .unwrap();
    let shipped = inspect_confirmed_artifact(
        &db,
        principal,
        &fixture.assignment.assignment_id,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        10,
        &CurrentApplicability,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(shipped.revision_id, "revision:summary:one");
    assert!(shipped.draft_available);
    let detach = detach_target(
        &db,
        principal,
        "detach:blocked",
        "agent:test",
        None,
        "cannot detach shipped artifact",
        DerivationTargetDetached {
            binding_id: "binding:change-summary".into(),
            target: fixture.target.clone(),
            expected_generation: 1,
            expected_target_version: 3,
        },
    )
    .await
    .unwrap_err();
    assert!(detach.to_string().contains("active artifact role"));
    let retirement = retire_artifact_role(
        &db,
        principal,
        "role:retire:blocked",
        "agent:test",
        None,
        "cannot retire shipped role",
        ArtifactRoleRetired {
            retirement_id: "retirement:blocked".into(),
            assignment_id: fixture.assignment.assignment_id.clone(),
            target: fixture.target.clone(),
            role: CHANGE_SUMMARY_ROLE.into(),
            expected_assignment_event_id: fixture.assignment_event.id.clone(),
            expected_confirmation_head_event_id: Some(first_event.id.clone()),
        },
    )
    .await
    .unwrap_err();
    assert!(retirement.to_string().contains("active confirmation"));
    let second = confirmation(
        &db,
        &fixture,
        "confirmation:two",
        "revision:summary:two",
        "publication:summary:two",
        3,
        Some(first_event.id.clone()),
    )
    .await;
    let second_event = confirm_revision(
        &db,
        principal,
        "confirm:two",
        "agent:test",
        None,
        "ship second",
        second,
    )
    .await
    .unwrap();
    let retraction = retract_confirmation(
        &db,
        principal,
        "retract:two",
        "agent:test",
        None,
        "correct second confirmation",
        ConfirmationRetracted {
            retraction_id: "retraction:two".into(),
            confirmation_id: "confirmation:two".into(),
            assignment_id: fixture.assignment.assignment_id.clone(),
            target: fixture.target.clone(),
            expected_confirmation_head_event_id: second_event.id,
        },
    )
    .await
    .unwrap();
    let restored = inspect_confirmed_artifact(
        &db,
        principal,
        &fixture.assignment.assignment_id,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        10,
        &CurrentApplicability,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(restored.confirmation_id, "confirmation:one");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM derivation_revision_confirmations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        2
    );
    // Retraction is itself the current head fence even when it restores the
    // previous confirmation.
    let head_event: String = sqlx::query_scalar(
        "SELECT head_event_id FROM derivation_confirmation_heads WHERE assignment_id=?",
    )
    .bind(&fixture.assignment.assignment_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(head_event, retraction.id);
}

#[tokio::test]
async fn retract_still_requires_role_retirement_before_detach_and_delete() {
    let (db, fixture) = fixture().await;
    let principal = Principal::bound("agent:test", true);
    let confirmed = confirm_revision(
        &db,
        principal,
        "confirm:lifecycle",
        "agent:test",
        None,
        "confirm lifecycle fixture",
        confirmation(
            &db,
            &fixture,
            "confirmation:lifecycle",
            "revision:summary:one",
            "publication:summary:one",
            2,
            None,
        )
        .await,
    )
    .await
    .unwrap();
    let retracted = retract_confirmation(
        &db,
        principal,
        "retract:lifecycle",
        "agent:test",
        None,
        "retract lifecycle fixture",
        ConfirmationRetracted {
            retraction_id: "retraction:lifecycle".into(),
            confirmation_id: "confirmation:lifecycle".into(),
            assignment_id: fixture.assignment.assignment_id.clone(),
            target: fixture.target.clone(),
            expected_confirmation_head_event_id: confirmed.id,
        },
    )
    .await
    .unwrap();
    let blocked = detach_target(
        &db,
        principal,
        "detach:role-still-active",
        "agent:test",
        None,
        "retraction does not retire role",
        DerivationTargetDetached {
            binding_id: "binding:change-summary".into(),
            target: fixture.target.clone(),
            expected_generation: 1,
            expected_target_version: 2,
        },
    )
    .await
    .unwrap_err();
    assert!(blocked.to_string().contains("active artifact role"));
    let retired = retire_artifact_role(
        &db,
        principal,
        "retire:lifecycle:first",
        "agent:test",
        None,
        "retire before detach",
        ArtifactRoleRetired {
            retirement_id: "retirement:lifecycle:first".into(),
            assignment_id: fixture.assignment.assignment_id.clone(),
            target: fixture.target.clone(),
            role: CHANGE_SUMMARY_ROLE.into(),
            expected_assignment_event_id: fixture.assignment_event.id.clone(),
            expected_confirmation_head_event_id: Some(retracted.id),
        },
    )
    .await
    .unwrap();
    let stale_reassignment = assign_artifact_role(
        &db,
        principal,
        "assign:lifecycle:stale",
        "agent:test",
        None,
        "stale genesis fence must fail",
        ArtifactRoleAssigned {
            assignment_id: "role:lifecycle:stale".into(),
            target: fixture.target.clone(),
            role: CHANGE_SUMMARY_ROLE.into(),
            expected_role_head_event_id: None,
        },
    )
    .await
    .unwrap_err();
    assert!(stale_reassignment.to_string().contains("role-head CAS"));
    let reassigned = assign_artifact_role(
        &db,
        principal,
        "assign:lifecycle:second",
        "agent:test",
        None,
        "reassign from exact retirement fence",
        ArtifactRoleAssigned {
            assignment_id: "role:lifecycle:second".into(),
            target: fixture.target.clone(),
            role: CHANGE_SUMMARY_ROLE.into(),
            expected_role_head_event_id: Some(retired.id),
        },
    )
    .await
    .unwrap();
    let delete_blocked = crate::store::delete_record(&db, &fixture.target.record_id)
        .await
        .unwrap_err();
    assert!(delete_blocked.to_string().contains("detach it first"));
    retire_artifact_role(
        &db,
        principal,
        "retire:lifecycle:second",
        "agent:test",
        None,
        "retire reassigned role",
        ArtifactRoleRetired {
            retirement_id: "retirement:lifecycle:second".into(),
            assignment_id: "role:lifecycle:second".into(),
            target: fixture.target.clone(),
            role: CHANGE_SUMMARY_ROLE.into(),
            expected_assignment_event_id: reassigned.id,
            expected_confirmation_head_event_id: None,
        },
    )
    .await
    .unwrap();
    detach_target(
        &db,
        principal,
        "detach:lifecycle",
        "agent:test",
        None,
        "detach after roles retired",
        DerivationTargetDetached {
            binding_id: "binding:change-summary".into(),
            target: fixture.target.clone(),
            expected_generation: 1,
            expected_target_version: 2,
        },
    )
    .await
    .unwrap();
    crate::store::delete_record(&db, &fixture.target.record_id)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM derivation_revision_confirmations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM derivation_artifact_role_assignments")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn active_unbound_role_blocks_carrier_deletion_as_defense_in_depth() {
    let db = crate::db::create_database(":memory:").await.unwrap();
    let carrier = create_record(
        &db,
        json!({"id":UNBOUND_ROLE_NOTE_ID,"type":"Document","kind":"note","name":"Unbound"}),
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "fixture",
        &carrier,
        vec![AllowEntry::account("agent:test", Capability::Manage)],
    )
    .await
    .unwrap();
    assign_artifact_role(
        &db,
        Principal::bound("agent:test", true),
        "assign:unbound",
        "agent:test",
        None,
        "exercise delete guard",
        ArtifactRoleAssigned {
            assignment_id: "role:unbound".into(),
            target: DerivationTarget::record_body(&carrier),
            role: "review_summary".into(),
            expected_role_head_event_id: None,
        },
    )
    .await
    .unwrap();
    let error = crate::store::delete_record(&db, &carrier)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("artifact role is active"));
}

#[tokio::test]
async fn source_pages_are_bounded_and_authority_never_comes_from_input_metadata() {
    let (db, fixture) = fixture().await;
    let tombstoned = source(&db, SOURCE_TOMBSTONED_ID, "run:tombstoned", true).await;
    crate::store::delete_record(&db, SOURCE_TOMBSTONED_ID)
        .await
        .unwrap();
    let next_revision = revision(
        "revision:summary:sources",
        Some("revision:summary:one"),
        &fixture.source_events,
    );
    let inspection_inputs = vec![
        DerivationInput {
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: fixture.source_events[0].0.clone(),
            sha256: fixture.source_events[0].1.clone(),
            metadata: json!({}),
        },
        DerivationInput {
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: fixture.source_events[2].0.clone(),
            sha256: fixture.source_events[2].1.clone(),
            metadata: json!({}),
        },
        DerivationInput {
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: tombstoned.0,
            sha256: tombstoned.1,
            metadata: json!({}),
        },
        DerivationInput {
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: "missing-content-event".into(),
            sha256: "e".repeat(64),
            metadata: json!({}),
        },
        DerivationInput {
            input_role: "source".into(),
            input_kind: "versioned".into(),
            portable_id: "forged-version".into(),
            sha256: "f".repeat(64),
            metadata: json!({"record_id":SOURCE_ONE_ID}),
        },
        DerivationInput {
            input_role: "source".into(),
            input_kind: "blob".into(),
            portable_id: "forged-blob".into(),
            sha256: "b".repeat(64),
            metadata: json!({"record_id":SOURCE_ONE_ID}),
        },
    ];
    publish_record_body_revision(
        &db,
        Principal::bound("agent:test", true),
        PublishRecordBodyRevision {
            publication_idempotency_key: "publish:summary:sources".into(),
            revision_idempotency_key: "revision:summary:sources".into(),
            actor: "agent:test".into(),
            run_key: Some("run:summary:sources".into()),
            reason: "publish source authorization fixture".into(),
            publication_id: "publication:summary:sources".into(),
            binding_id: "binding:change-summary".into(),
            target: fixture.target.clone(),
            expected_generation: 1,
            expected_target_version: 2,
            body: "source boundary fixture".into(),
            revision: next_revision,
        },
    )
    .await
    .unwrap();
    confirm_revision(
        &db,
        Principal::bound("agent:test", true),
        "confirm:sources",
        "agent:test",
        None,
        "confirm source boundary fixture",
        confirmation(
            &db,
            &fixture,
            "confirmation:sources",
            "revision:summary:sources",
            "publication:summary:sources",
            3,
            None,
        )
        .await,
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM derivation_revision_inputs WHERE revision_id=?")
        .bind("revision:summary:sources")
        .execute(db.write_pool())
        .await
        .unwrap();
    for (ordinal, input) in inspection_inputs.into_iter().enumerate() {
        sqlx::query(
            "INSERT INTO derivation_revision_inputs
             (revision_id,ordinal,input_role,input_kind,portable_id,sha256,metadata)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind("revision:summary:sources")
        .bind(ordinal as i64)
        .bind(input.input_role)
        .bind(input.input_kind)
        .bind(input.portable_id)
        .bind(input.sha256)
        .bind(input.metadata.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    let mut cursor = None;
    let mut sources = Vec::new();
    loop {
        let inspection = inspect_confirmed_artifact(
            &db,
            Principal::bound("agent:test", true),
            &fixture.assignment.assignment_id,
            CHANGE_SUMMARY_ROLE,
            &output_contract(),
            cursor.as_ref(),
            2,
            &CurrentApplicability,
        )
        .await
        .unwrap()
        .unwrap();
        sources.extend(inspection.source_runs);
        cursor = inspection.next_source_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(sources.len(), 6);
    assert_eq!(sources.iter().filter(|source| !source.redacted).count(), 1);
    assert!(sources
        .iter()
        .filter(|source| matches!(source.input_kind.as_str(), "blob" | "versioned"))
        .all(|source| source.redacted && source.portable_id.is_none() && source.sha256.is_none()));
    assert!(inspect_confirmed_artifact(
        &db,
        Principal::bound("agent:test", true),
        &fixture.assignment.assignment_id,
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        0,
        &CurrentApplicability,
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("source page limit"));
    assert!(query_confirmed_artifacts(
        &db,
        Principal::bound("agent:test", true),
        CHANGE_SUMMARY_ROLE,
        &output_contract(),
        None,
        MAX_CONFIRMED_ARTIFACT_PAGE_LIMIT + 1,
        2,
        &CurrentApplicability,
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("artifact page limit"));
}

#[tokio::test]
async fn confirmation_replays_exactly_and_projection_corruption_fails_integrity() {
    let (db, fixture) = fixture().await;
    let principal = Principal::bound("agent:test", true);
    let value = confirmation(
        &db,
        &fixture,
        "confirmation:replay",
        "revision:summary:one",
        "publication:summary:one",
        2,
        None,
    )
    .await;
    confirm_revision(
        &db,
        principal,
        "confirm:replay",
        "agent:test",
        None,
        "ship replay fixture",
        value,
    )
    .await
    .unwrap();
    let mut live = db.pool().acquire().await.unwrap();
    let events = read_all_derivation_events(&mut live).await.unwrap();
    drop(live);
    let raw_replay = crate::db::create_database(":memory:").await.unwrap();
    let mut raw = raw_replay.write_pool().acquire().await.unwrap();
    replay_derivations(&mut raw, &events).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM derivation_artifact_role_assignments")
            .fetch_one(&mut *raw)
            .await
            .unwrap(),
        1
    );
    drop(raw);
    raw_replay.close().await;
    let replay = crate::conformance::rebuild_and_diff_derivation(&db)
        .await
        .unwrap();
    assert!(replay
        .tables
        .iter()
        .all(|table| table.live == table.rebuilt && table.mismatches.is_empty()));
    sqlx::query(
        "UPDATE derivation_confirmation_heads SET confirmation_id=NULL WHERE assignment_id=?",
    )
    .bind(&fixture.assignment.assignment_id)
    .execute(db.write_pool())
    .await
    .unwrap();
    let violations = state_violations(&db).await.unwrap();
    assert!(violations
        .iter()
        .any(|violation| violation.contains("derivation_confirmation_heads")));
}
