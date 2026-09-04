use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::authorization::{AllowEntry, Capability, Principal};
use crate::db::{begin_write, Db};
use crate::events::FacetSetPayload;
use crate::recipe::{
    canonical_recipe_definition, publish_recipe_release, PublishRecipeRelease, RecipeBudgetField,
    RecipeBudgetLimits, RecipeBudgetPolicy, RecipeContract, RecipeDefinition,
    RecipeExecutionProfile, RecipeInstructions, RecipeModelCapability, RecipeRenderer,
    RecipeRepairPolicy, RECIPE_RUNTIME,
};

use super::requests::{
    acquire_or_steal_request_in, acquire_or_steal_request_with_clock,
    complete_request_with_publication_at, fail_request_with_clock, renew_request_with_clock,
    CompletionFailurePoint, DerivationCoordinatorClock, RequestFailurePoint,
};
use super::*;

#[derive(Clone)]
struct TestClock(Arc<Mutex<chrono::DateTime<Utc>>>);

impl TestClock {
    fn at(value: chrono::DateTime<Utc>) -> Self {
        Self(Arc::new(Mutex::new(value)))
    }

    fn set(&self, value: chrono::DateTime<Utc>) {
        *self.0.lock().unwrap() = value;
    }
}

impl DerivationCoordinatorClock for TestClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

async fn create_series(db: &Db, id: &str) {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    append_derivation_event_in(
        &mut tx,
        NewDerivationEvent::authored(
            format!("request-test:{id}"),
            "person:request-test",
            None,
            "define request test series",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: id.into(),
                series_key: format!("request-test:{id}"),
                definition: json!({"recipe":"test"}),
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

fn spec(series_id: &str) -> DerivationRequestSpec {
    DerivationRequestSpec {
        series_id: series_id.into(),
        definition_sha256: digest_json(&json!({"recipe":"test"})),
        canonical_request: CanonicalDerivationRequest {
            query_contract: "native.test.v1".into(),
            query_contract_version: 1,
            selection: json!({"b":2,"a":1}),
            scope: json!({"records":["record-b","record-a"]}),
        },
        recipe_revision: RecipeRevisionRef {
            definition_id: "recipe:test".into(),
            publication_id: "publication:test:1".into(),
            sha256: "2".repeat(64),
        },
        effective_source_boundary: EffectiveSourceBoundary {
            after_seq: Some(0),
            through_seq: 10,
            resolved_scope_membership_sha256: "3".repeat(64),
            metadata: json!({"source":"test"}),
        },
        target_basis: json!({"target_version":4,"binding_generation":2}),
        budget: json!({"tokens":2048}),
        audience_policy: None,
        audience_sha256: "4".repeat(64),
    }
}

fn requester(actor: &str) -> CreateOrJoinRequest {
    CreateOrJoinRequest {
        requested_by: actor.into(),
        requested_run_key: Some(format!("run:{actor}")),
    }
}

fn fixed_time(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn contract(id: &str, schema: serde_json::Value) -> RecipeContract {
    RecipeContract {
        id: id.into(),
        version: 1,
        schema_sha256: digest_json(&schema),
        schema,
    }
}

fn controlled_recipe_definition() -> RecipeDefinition {
    let instructions = "Return one validated summary object.";
    RecipeDefinition {
        instructions: RecipeInstructions {
            revision: "test:1".into(),
            text: instructions.into(),
            sha256: sha256_bytes(instructions.as_bytes()),
        },
        query_contract: contract(
            "native.test.v1",
            json!({"type":"object","additionalProperties":true}),
        ),
        allowed_input_classes: vec![
            crate::recipe::RecipeInputClass::ContentEvent,
            crate::recipe::RecipeInputClass::RecordBody,
        ],
        result_contract: contract(
            "native.test.result.v1",
            json!({
                "type":"object",
                "required":["summary"],
                "properties":{"summary":{"type":"string"}},
                "additionalProperties":false
            }),
        ),
        output_contract: contract(
            "native.document-body.v1",
            json!({
                "type":"object",
                "required":["body"],
                "properties":{"body":{"type":"string"}},
                "additionalProperties":false
            }),
        ),
        renderer: RecipeRenderer {
            id: "native.test.renderer".into(),
            revision: "1".into(),
            sha256: "a".repeat(64),
        },
        budgets: RecipeBudgetPolicy {
            supported_fields: vec![RecipeBudgetField::MaxOutputBytes],
            defaults: RecipeBudgetLimits {
                max_input_bytes: 10_000,
                max_input_items: 10,
                max_input_tokens: 2_000,
                max_output_bytes: 1_000,
                max_output_tokens: 200,
            },
            maxima: RecipeBudgetLimits {
                max_input_bytes: 100_000,
                max_input_items: 100,
                max_input_tokens: 20_000,
                max_output_bytes: 10_000,
                max_output_tokens: 2_000,
            },
        },
        contextual_inputs: vec![],
        execution_profile: RecipeExecutionProfile {
            profile_id: "native.test.structured".into(),
            required_capabilities: vec![RecipeModelCapability::JsonSchemaOutput],
            temperature_milli: 0,
            max_output_tokens: 200,
        },
        repair_policy: RecipeRepairPolicy {
            max_repairs: 0,
            max_validation_errors: 4,
            repair_profile_id: None,
        },
    }
}

fn acquired(result: AcquireRequestResult) -> DerivationRequestLease {
    match result {
        AcquireRequestResult::Acquired(lease) => lease,
        other => panic!("expected acquired lease, got {other:?}"),
    }
}

async fn acquire_at(
    db: &Db,
    request_id: &str,
    owner: &str,
    run_key: Option<&str>,
    now: chrono::DateTime<Utc>,
    duration: Duration,
) -> crate::Result<AcquireRequestResult> {
    acquire_or_steal_request_with_clock(
        db,
        request_id,
        owner,
        run_key,
        duration,
        &TestClock::at(now),
    )
    .await
}

async fn renew_at(
    db: &Db,
    lease: &DerivationRequestLease,
    now: chrono::DateTime<Utc>,
    duration: Duration,
) -> crate::Result<Option<DerivationRequestLease>> {
    renew_request_with_clock(db, lease, duration, &TestClock::at(now)).await
}

async fn fail_at(
    db: &Db,
    lease: &DerivationRequestLease,
    now: chrono::DateTime<Utc>,
    failure_code: &str,
    failure_metadata: serde_json::Value,
    retryable: bool,
    next_attempt_at: Option<chrono::DateTime<Utc>>,
) -> crate::Result<bool> {
    let request = inspect_request(db, &lease.request_id)
        .await?
        .expect("request exists");
    let retry_after =
        next_attempt_at.map(|at| (at - now).to_std().expect("test retry is not before now"));
    let failure = failure_for(
        &request,
        lease.clone(),
        failure_code,
        failure_metadata,
        retryable,
        retry_after,
    );
    Ok(
        fail_request_with_clock(db, failure, &TestClock::at(now), RequestFailurePoint::None)
            .await?
            .is_some(),
    )
}

fn failure_for(
    request: &DerivationRequestSnapshot,
    lease: DerivationRequestLease,
    failure_code: &str,
    failure_metadata: serde_json::Value,
    retryable: bool,
    retry_after: Option<Duration>,
) -> DerivationRequestFailure {
    let id = Uuid::new_v4().to_string();
    DerivationRequestFailure {
        lease,
        event_idempotency_key: format!("failure:{id}"),
        actor: "agent:test-worker".into(),
        run_key: Some("run:test-worker".into()),
        reason: "record the exact failed derivation attempt".into(),
        evidence: DerivationAttemptFailed {
            id,
            series_id: request.spec.series_id.clone(),
            coordination_request_key_sha256: Some(request.request_key_sha256.clone()),
            canonical_request: request.spec.canonical_request.clone(),
            recipe_revision: request.spec.recipe_revision.clone(),
            effective_source_boundary: request.spec.effective_source_boundary.clone(),
            attempt_ordinal: request.attempt_count,
            retryable,
            executor_descriptor: json!({"executor":"test"}),
            failure_code: failure_code.into(),
            failure_metadata,
        },
        retry_after,
    }
}

#[tokio::test]
async fn create_or_join_is_canonical_and_preserves_first_requester() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:stable-join").await;
    let first = create_or_join_request(&db, spec("series:stable-join"), requester("person:first"))
        .await
        .unwrap();
    assert!(first.created);

    let mut reordered = spec("series:stable-join");
    // RFC 8785 renders 1.0 as 1. Joining must compare canonical identity,
    // not serde_json's in-memory integer/float representation.
    reordered.canonical_request.selection = json!({"a":1.0,"b":2});
    reordered.target_basis = json!({"binding_generation":2,"target_version":4});
    let joined = create_or_join_request(&db, reordered, requester("person:second"))
        .await
        .unwrap();
    assert!(!joined.created);
    assert_eq!(joined.request.id, first.request.id);
    assert_eq!(
        joined.request.request_key_sha256,
        first.request.request_key_sha256
    );
    assert_eq!(joined.request.requested_by, "person:first");
    assert_eq!(joined.request.state, DerivationRequestState::Pending);

    let mut changed_basis = spec("series:stable-join");
    changed_basis.target_basis = json!({"binding_generation":2,"target_version":5});
    let distinct = create_or_join_request(&db, changed_basis, requester("person:first"))
        .await
        .unwrap();
    assert!(distinct.created);
    assert_ne!(distinct.request.id, first.request.id);
    assert_ne!(
        distinct.request.request_key_sha256,
        first.request.request_key_sha256
    );
}

#[tokio::test]
async fn coordination_identity_allows_ordinal_one_for_each_operational_request() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:coordination-identity").await;
    let base = spec("series:coordination-identity");
    let mut changed_basis = base.clone();
    changed_basis.target_basis = json!({"target_version":5,"binding_generation":2});
    let mut changed_budget = base.clone();
    changed_budget.budget = json!({"tokens":4096});
    let mut changed_audience = base.clone();
    changed_audience.audience_sha256 = "5".repeat(64);

    let specs = [base, changed_basis, changed_budget, changed_audience];
    let mut request_keys = Vec::new();
    for (ordinal, request_spec) in specs.into_iter().enumerate() {
        let request = create_or_join_request(
            &db,
            request_spec,
            requester(&format!("person:variant-{ordinal}")),
        )
        .await
        .unwrap()
        .request;
        request_keys.push(request.request_key_sha256.clone());
        let lease = acquired(
            acquire_at(
                &db,
                &request.id,
                &format!("worker:variant-{ordinal}"),
                None,
                fixed_time(ordinal as i64),
                Duration::from_secs(30),
            )
            .await
            .unwrap(),
        );
        assert_eq!(lease.generation, 1);
        assert!(fail_at(
            &db,
            &lease,
            fixed_time(ordinal as i64 + 1),
            "variant_failure",
            json!({"variant":ordinal}),
            false,
            None,
        )
        .await
        .unwrap());
    }

    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),count(DISTINCT request_identity_sha256),
                count(DISTINCT coordination_request_key_sha256),min(attempt_ordinal)
           FROM derivation_attempts",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(counts, (4, 1, 4, 1));
    let projected_keys: Vec<String> = sqlx::query_scalar(
        "SELECT coordination_request_key_sha256 FROM derivation_attempts ORDER BY coordination_request_key_sha256",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    request_keys.sort();
    assert_eq!(projected_keys, request_keys);
    assert!(state_violations(&db).await.unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_create_and_acquire_have_one_winner() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:concurrent").await;
    let left_db = db.clone();
    let right_db = db.clone();
    let left = tokio::spawn(async move {
        create_or_join_request(
            &left_db,
            spec("series:concurrent"),
            requester("person:left"),
        )
        .await
        .unwrap()
    });
    let right = tokio::spawn(async move {
        create_or_join_request(
            &right_db,
            spec("series:concurrent"),
            requester("person:right"),
        )
        .await
        .unwrap()
    });
    let left = left.await.unwrap();
    let right = right.await.unwrap();
    assert_ne!(left.created, right.created);
    assert_eq!(left.request.id, right.request.id);

    let request_id = left.request.id;
    let left_db = db.clone();
    let left_id = request_id.clone();
    let right_db = db.clone();
    let right_id = request_id.clone();
    let now = fixed_time(0);
    let left = tokio::spawn(async move {
        acquire_at(
            &left_db,
            &left_id,
            "worker:left",
            None,
            now,
            Duration::from_secs(10),
        )
        .await
        .unwrap()
    });
    let right = tokio::spawn(async move {
        acquire_at(
            &right_db,
            &right_id,
            "worker:right",
            None,
            now,
            Duration::from_secs(10),
        )
        .await
        .unwrap()
    });
    let results = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, AcquireRequestResult::Acquired(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, AcquireRequestResult::Busy))
            .count(),
        1
    );
}

#[tokio::test]
async fn transaction_owned_acquire_can_be_composed_and_rolled_back() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:transaction-owned-acquire").await;
    let request = create_or_join_request(
        &db,
        spec("series:transaction-owned-acquire"),
        requester("person:transaction-owned-acquire"),
    )
    .await
    .unwrap()
    .request;

    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let lease = acquired(
        acquire_or_steal_request_in(
            &mut tx,
            &request.id,
            "worker:composed",
            Some("run:composed"),
            Duration::from_secs(30),
        )
        .await
        .unwrap(),
    );
    assert_eq!(lease.generation, 1);
    let state: String = sqlx::query_scalar("SELECT state FROM derivation_requests WHERE id=?")
        .bind(&request.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(state, "running");
    tx.rollback().await.unwrap();

    let after = inspect_request(&db, &request.id).await.unwrap().unwrap();
    assert_eq!(after.state, DerivationRequestState::Pending);
    assert_eq!(after.lease_generation, 0);
}

#[tokio::test]
async fn renewal_extends_a_live_lease_and_expiry_enables_fenced_steal() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:steal").await;
    let request = create_or_join_request(&db, spec("series:steal"), requester("person:a"))
        .await
        .unwrap()
        .request;
    let first = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:first",
            Some("run:first"),
            fixed_time(0),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
    );
    assert_eq!(first.generation, 1);
    assert_eq!(
        acquire_at(
            &db,
            &request.id,
            "worker:second",
            None,
            fixed_time(5),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
        AcquireRequestResult::Busy
    );
    let renewed = renew_at(&db, &first, fixed_time(5), Duration::from_secs(10))
        .await
        .unwrap()
        .expect("live lease extends");
    assert_eq!(renewed.generation, 1);
    assert_eq!(
        acquire_at(
            &db,
            &request.id,
            "worker:second",
            None,
            fixed_time(11),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
        AcquireRequestResult::Busy
    );
    let second = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:second",
            Some("run:second"),
            fixed_time(16),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
    );
    assert_eq!(second.generation, 2);
    assert!(
        renew_at(&db, &first, fixed_time(17), Duration::from_secs(10))
            .await
            .unwrap()
            .is_none()
    );
    assert!(!fail_at(
        &db,
        &first,
        fixed_time(17),
        "stale_worker",
        json!({}),
        false,
        None,
    )
    .await
    .unwrap());
    assert!(fail_at(
        &db,
        &second,
        fixed_time(17),
        "retryable_provider_failure",
        json!({"class":"provider"}),
        true,
        Some(fixed_time(18)),
    )
    .await
    .unwrap());
    assert_eq!(
        acquire_at(
            &db,
            &request.id,
            "worker:third",
            None,
            fixed_time(17),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
        AcquireRequestResult::Busy
    );
    let third = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:third",
            None,
            fixed_time(18),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
    );
    assert_eq!(third.generation, 3);
    assert!(fail_at(
        &db,
        &third,
        fixed_time(19),
        "attempts_exhausted",
        json!({}),
        false,
        None,
    )
    .await
    .unwrap());
    let terminal = inspect_request(&db, &request.id).await.unwrap().unwrap();
    assert!(terminal.is_terminal());
    assert!(!terminal.retryable);
    assert_eq!(terminal.attempt_count, 3);
    assert_eq!(
        acquire_at(
            &db,
            &request.id,
            "worker:fourth",
            None,
            fixed_time(30),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
        AcquireRequestResult::Terminal
    );
}

#[tokio::test]
async fn expired_owner_cannot_renew_or_fail_before_any_steal() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:expired").await;
    let request = create_or_join_request(&db, spec("series:expired"), requester("person:expired"))
        .await
        .unwrap()
        .request;
    let lease = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:expired",
            None,
            fixed_time(0),
            Duration::from_secs(1),
        )
        .await
        .unwrap(),
    );
    assert!(
        renew_at(&db, &lease, fixed_time(2), Duration::from_secs(10))
            .await
            .unwrap()
            .is_none()
    );
    assert!(!fail_at(
        &db,
        &lease,
        fixed_time(2),
        "too_late",
        json!({}),
        false,
        None,
    )
    .await
    .unwrap());
}

#[tokio::test]
async fn coordinator_samples_time_after_waiting_for_the_write_lock() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:lock-wait").await;
    let request =
        create_or_join_request(&db, spec("series:lock-wait"), requester("person:lock-wait"))
            .await
            .unwrap()
            .request;
    let first = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:first",
            None,
            fixed_time(0),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
    );
    let held_write = begin_write(db.write_pool()).await.unwrap();
    let clock = TestClock::at(fixed_time(5));
    let waiting_clock = clock.clone();
    let waiting_db = db.clone();
    let request_id = request.id.clone();
    let waiting = tokio::spawn(async move {
        acquire_or_steal_request_with_clock(
            &waiting_db,
            &request_id,
            "worker:second",
            None,
            Duration::from_secs(10),
            &waiting_clock,
        )
        .await
        .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiting.is_finished());
    clock.set(fixed_time(11));
    held_write.rollback().await.unwrap();
    let stolen = acquired(waiting.await.unwrap());
    assert_eq!(stolen.generation, first.generation + 1);
}

#[tokio::test]
async fn failure_evidence_and_request_transition_roll_back_together() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:failure-atomicity").await;
    let request = create_or_join_request(
        &db,
        spec("series:failure-atomicity"),
        requester("person:failure-atomicity"),
    )
    .await
    .unwrap()
    .request;
    let lease = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:failure",
            Some("run:failure"),
            fixed_time(0),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
    );
    let running = inspect_request(&db, &request.id).await.unwrap().unwrap();
    let failure = failure_for(
        &running,
        lease,
        "provider_unavailable",
        json!({"provider":"test"}),
        false,
        None,
    );
    let mut mismatched = failure.clone();
    mismatched.evidence.coordination_request_key_sha256 = Some("f".repeat(64));
    let error = fail_request_with_clock(
        &db,
        mismatched,
        &TestClock::at(fixed_time(1)),
        RequestFailurePoint::None,
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match its fenced request attempt"));
    for point in [
        RequestFailurePoint::AfterEvidence,
        RequestFailurePoint::AfterTransition,
    ] {
        let error =
            fail_request_with_clock(&db, failure.clone(), &TestClock::at(fixed_time(1)), point)
                .await
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("injected derivation request crash"));
        let after = inspect_request(&db, &request.id).await.unwrap().unwrap();
        assert_eq!(after.state, DerivationRequestState::Running);
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM derivation_events WHERE type='derivation.attempt.failed'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM derivation_attempts")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!((events, attempts), (0, 0));
    }
    let event = fail_request_with_clock(
        &db,
        failure.clone(),
        &TestClock::at(fixed_time(1)),
        RequestFailurePoint::None,
    )
    .await
    .unwrap()
    .expect("live lease records evidence");
    assert_eq!(event.aggregate_id, failure.evidence.id);
    let after = inspect_request(&db, &request.id).await.unwrap().unwrap();
    assert_eq!(after.state, DerivationRequestState::Failed);
    assert!(after.is_terminal());
    assert_eq!(after.failure_code.as_deref(), Some("provider_unavailable"));
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM derivation_attempts")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(attempts, 1);
    assert!(fail_request_with_clock(
        &db,
        failure,
        &TestClock::at(fixed_time(2)),
        RequestFailurePoint::None,
    )
    .await
    .unwrap()
    .is_none());
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM derivation_attempts")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(attempts, 1);
}

#[tokio::test]
async fn inspect_and_bounded_wait_are_pure_reads() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:wait").await;
    let request = create_or_join_request(&db, spec("series:wait"), requester("person:wait"))
        .await
        .unwrap()
        .request;
    let before: String = sqlx::query_scalar(
        "SELECT json_object('state',state,'generation',lease_generation,'updated_at',updated_at)
           FROM derivation_requests WHERE id=?",
    )
    .bind(&request.id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let inspected = inspect_request(&db, &request.id).await.unwrap().unwrap();
    assert_eq!(inspected.state, DerivationRequestState::Pending);
    let waited = wait_for_request(
        &db,
        &request.id,
        Duration::from_millis(15),
        Some(Duration::from_millis(5)),
    )
    .await
    .unwrap();
    assert!(matches!(waited, RequestWaitOutcome::TimedOut(_)));
    let after: String = sqlx::query_scalar(
        "SELECT json_object('state',state,'generation',lease_generation,'updated_at',updated_at)
           FROM derivation_requests WHERE id=?",
    )
    .bind(&request.id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(before, after);

    let lease = acquired(
        acquire_at(
            &db,
            &request.id,
            "worker:terminal",
            None,
            fixed_time(0),
            Duration::from_secs(10),
        )
        .await
        .unwrap(),
    );
    assert!(fail_at(
        &db,
        &lease,
        fixed_time(1),
        "terminal",
        json!({"inspectable":true}),
        false,
        None,
    )
    .await
    .unwrap());
    let terminal = wait_for_request(&db, &request.id, Duration::ZERO, None)
        .await
        .unwrap();
    match terminal {
        RequestWaitOutcome::Terminal(snapshot) => {
            assert_eq!(snapshot.failure_code.as_deref(), Some("terminal"));
            assert_eq!(snapshot.failure_metadata, Some(json!({"inspectable":true})));
        }
        other => panic!("expected terminal request, got {other:?}"),
    }
}

#[tokio::test]
async fn governed_request_acquire_validates_and_atomically_publishes_success() {
    let db = crate::create_database(":memory:").await.unwrap();
    let principal = Principal::bound("acct:publisher", false);
    let definition = controlled_recipe_definition();
    let recipe_body = canonical_recipe_definition(&definition).unwrap();
    let recipe_id = crate::store::create_record_as(
        &db,
        json!({
            "id":"4e9e5700-0000-4000-8000-000000000001",
            "type":"Program",
            "kind":"recipe",
            "name":"Controlled success recipe",
            "body":recipe_body
        }),
        Some("acct:publisher"),
    )
    .await
    .unwrap();
    crate::store::set_facet(
        &db,
        &recipe_id,
        FacetSetPayload {
            key: "runtime".into(),
            value: Some(RECIPE_RUNTIME.into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "acct:publisher",
        &recipe_id,
        vec![AllowEntry::account("acct:publisher", Capability::Manage)],
    )
    .await
    .unwrap();
    let recipe_source = sqlx::query(
        "SELECT id,json_extract(payload,'$.body') AS body FROM content_events
          WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(&recipe_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let recipe_source_event: String = recipe_source.try_get("id").unwrap();
    let recipe_source_body: String = recipe_source.try_get("body").unwrap();
    let release = publish_recipe_release(
        &db,
        principal,
        PublishRecipeRelease {
            publication_event_id: Uuid::new_v4().to_string(),
            program_id: recipe_id.clone(),
            source_event_id: recipe_source_event,
            source_sha256: sha256_bytes(recipe_source_body.as_bytes()),
            definition,
        },
    )
    .await
    .unwrap();

    let target_id = crate::store::create_record_as(
        &db,
        json!({
            "id":"4e9e5700-0000-4000-8000-000000000002",
            "type":"Document",
            "kind":"note",
            "name":"Controlled result",
            "body":null
        }),
        Some("acct:publisher"),
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "acct:publisher",
        &target_id,
        vec![
            AllowEntry::account("acct:publisher", Capability::Edit),
            AllowEntry::members(Capability::View),
        ],
    )
    .await
    .unwrap();
    let source = sqlx::query(
        "SELECT id,seq,payload FROM content_events
          WHERE record_id=? AND type='record.created' ORDER BY seq LIMIT 1",
    )
    .bind(&target_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event: String = source.try_get("id").unwrap();
    let source_seq: i64 = source.try_get("seq").unwrap();
    let source_payload: String = source.try_get("payload").unwrap();
    let source_sha =
        digest_json(&serde_json::from_str::<serde_json::Value>(&source_payload).unwrap());
    let policy_anchor_id: String =
        sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(&target_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let audience_policy = DerivationAudiencePolicy {
        schema: DERIVATION_AUDIENCE_SCHEMA.into(),
        policy_anchor_id,
        principals: vec![
            DerivationAudiencePrincipal {
                account_id: "acct:audience".into(),
                is_member: true,
            },
            DerivationAudiencePrincipal {
                account_id: "acct:publisher".into(),
                is_member: false,
            },
        ],
    };
    let audience_sha256 = audience_policy_sha256(&audience_policy).unwrap();
    let pinned_recipe = RecipeRevisionRef {
        definition_id: recipe_id.clone(),
        publication_id: release.descriptor.publication_event_id.clone(),
        sha256: release.descriptor_sha256.clone(),
    };
    let controlled_budget = json!({"max_output_bytes":1000});
    let series_definition = json!({
        "recipe_revision": pinned_recipe,
        "budget": controlled_budget,
        "audience_sha256": audience_sha256,
    });
    let mut series_tx = begin_write(db.write_pool()).await.unwrap();
    append_derivation_event_in(
        &mut series_tx,
        NewDerivationEvent::authored(
            "series:controlled-success",
            "acct:publisher",
            None,
            "define controlled series",
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: "series:controlled-success".into(),
                series_key: "series:controlled-success".into(),
                definition: series_definition.clone(),
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    series_tx.commit().await.unwrap();
    let target = DerivationTarget::record_body(&target_id);
    bind_target(
        &db,
        principal,
        "bind:controlled-success",
        "acct:publisher",
        None,
        "bind controlled output",
        DerivationTargetBound {
            binding_id: "binding:controlled-success".into(),
            series_id: "series:controlled-success".into(),
            target: target.clone(),
            expected_target_version: 0,
            generation: 1,
            expected_body_event_id: Some(source_event.clone()),
            expected_body_sha256: Some(source_sha.clone()),
        },
    )
    .await
    .unwrap();
    let request_spec = DerivationRequestSpec {
        series_id: "series:controlled-success".into(),
        definition_sha256: digest_json(&series_definition),
        canonical_request: CanonicalDerivationRequest {
            query_contract: "native.test.v1".into(),
            query_contract_version: 1,
            selection: json!({"all":true}),
            scope: json!({"record_ids":[target_id.clone()]}),
        },
        recipe_revision: pinned_recipe,
        effective_source_boundary: EffectiveSourceBoundary {
            after_seq: Some(0),
            through_seq: source_seq,
            resolved_scope_membership_sha256: "7".repeat(64),
            metadata: json!({}),
        },
        target_basis: json!({
            "target":target,
            "binding_id":"binding:controlled-success",
            "binding_generation":1,
            "target_version":1
        }),
        budget: controlled_budget,
        audience_policy: Some(audience_policy),
        audience_sha256,
    };
    let request = create_or_join_request(
        &db,
        request_spec.clone(),
        CreateOrJoinRequest {
            requested_by: "acct:publisher".into(),
            requested_run_key: Some("run:controlled".into()),
        },
    )
    .await
    .unwrap()
    .request;
    crate::store::update_record(
        &db,
        &request_spec.recipe_revision.definition_id,
        json!({"body":"a later draft that is not the published recipe"}),
    )
    .await
    .unwrap();
    let bypass = acquire_or_steal_request(
        &db,
        &request.id,
        "worker:bypass",
        Some("run:bypass"),
        Duration::from_secs(30),
    )
    .await
    .unwrap_err();
    assert!(bypass
        .to_string()
        .contains("controlled execution acquisition"));
    let lease = match acquire_request_for_controlled_execution(
        &db,
        principal,
        &request.id,
        "worker:one",
        Some("run:controlled"),
        release.status_event_seq,
        Duration::from_secs(30),
    )
    .await
    .unwrap()
    {
        AcquireRequestResult::Acquired(lease) => lease,
        other => panic!("expected controlled lease, got {other:?}"),
    };
    let publication = PublishRecordBodyRevision {
        publication_idempotency_key: "publish:controlled-success".into(),
        revision_idempotency_key: "revision:controlled-success".into(),
        actor: "acct:publisher".into(),
        run_key: Some("run:controlled".into()),
        reason: "publish validated controlled result".into(),
        publication_id: "publication:controlled-success".into(),
        binding_id: "binding:controlled-success".into(),
        target: DerivationTarget::record_body(&target_id),
        expected_generation: 1,
        expected_target_version: 1,
        body: "validated summary".into(),
        revision: DerivationRevisionCompleted {
            id: "revision:controlled-success".into(),
            series_id: request_spec.series_id.clone(),
            predecessor_revision_id: None,
            canonical_request: request_spec.canonical_request.clone(),
            recipe_revision: request_spec.recipe_revision.clone(),
            effective_source_boundary: request_spec.effective_source_boundary.clone(),
            inputs: vec![DerivationInput {
                input_role: "source".into(),
                input_kind: "content_event".into(),
                portable_id: source_event,
                sha256: source_sha,
                metadata: json!({"record_id":target_id}),
            }],
            output_ref: DerivationOutputRef {
                output_kind: "content_event".into(),
                event_id: "replaced-at-publication".into(),
                sha256: "0".repeat(64),
            },
            completion_metadata: json!({}),
        },
    };
    let mut completion = CompleteDerivationRequest {
        lease: lease.clone(),
        expected_recipe_status_event_seq: release.status_event_seq,
        structured_result: json!({"summary":"validated summary"}),
        rendered_output: json!({"body":"validated summary"}),
        executor: DerivationExecutorDescriptor {
            provider: "test-provider".into(),
            model: "test-model".into(),
            executor_revision: "executor:1".into(),
            execution_profile_id: "native.test.structured".into(),
            capabilities: vec![RecipeModelCapability::JsonSchemaOutput],
            parameters: json!({"temperature_milli":0,"max_output_tokens":200}),
            usage: DerivationExecutionUsage {
                input_bytes: canonical_json(
                    &serde_json::from_str::<serde_json::Value>(&source_payload).unwrap(),
                )
                .len() as u64,
                input_items: 1,
                input_tokens: 10,
                output_bytes: "validated summary".len() as u64,
                output_tokens: 3,
            },
        },
        publication,
    };
    let bypass = publish_record_body_revision(&db, principal, completion.publication.clone())
        .await
        .unwrap_err();
    assert!(bypass.to_string().contains("durable request completion"));
    sqlx::query(
        "UPDATE derivation_requests SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE id=?",
    )
    .bind(&request.id)
    .execute(db.write_pool())
    .await
    .unwrap();
    let winning_lease = match acquire_request_for_controlled_execution(
        &db,
        principal,
        &request.id,
        "worker:two",
        Some("run:controlled"),
        release.status_event_seq,
        Duration::from_secs(30),
    )
    .await
    .unwrap()
    {
        AcquireRequestResult::Acquired(lease) => lease,
        other => panic!("expected stolen controlled lease, got {other:?}"),
    };
    assert_eq!(winning_lease.generation, lease.generation + 1);
    assert!(
        complete_request_with_publication(&db, principal, completion.clone())
            .await
            .unwrap()
            .is_none()
    );
    completion.lease = winning_lease;
    let mut wrong_owner = completion.clone();
    wrong_owner.lease.owner = "worker:stale".into();
    assert!(
        complete_request_with_publication(&db, principal, wrong_owner)
            .await
            .unwrap()
            .is_none()
    );
    let mut wrong_run = completion.clone();
    wrong_run.publication.run_key = Some("run:other".into());
    let wrong_run_error = complete_request_with_publication(&db, principal, wrong_run)
        .await
        .unwrap_err();
    assert!(wrong_run_error.to_string().contains("winning lease"));
    let mut wrong_usage = completion.clone();
    wrong_usage.executor.usage.input_bytes += 1;
    let wrong_usage_error = complete_request_with_publication(&db, principal, wrong_usage)
        .await
        .unwrap_err();
    assert!(wrong_usage_error.to_string().contains("execution usage"));
    let mut exceeded_tokens = completion.clone();
    exceeded_tokens.executor.usage.output_tokens = 201;
    let exceeded_tokens_error = complete_request_with_publication(&db, principal, exceeded_tokens)
        .await
        .unwrap_err();
    assert!(exceeded_tokens_error
        .to_string()
        .contains("execution usage"));
    let mut wrong_profile = completion.clone();
    wrong_profile.executor.parameters["temperature_milli"] = json!(1);
    let wrong_profile_error = complete_request_with_publication(&db, principal, wrong_profile)
        .await
        .unwrap_err();
    assert!(wrong_profile_error
        .to_string()
        .contains("execution profile"));
    let mut wrong_target = completion.clone();
    wrong_target.publication.target = DerivationTarget::record_body("derived:other-target");
    let wrong_target_error = complete_request_with_publication(&db, principal, wrong_target)
        .await
        .unwrap_err();
    assert!(wrong_target_error.to_string().contains("target basis"));
    let mut hidden_input = completion.clone();
    hidden_input.publication.revision.inputs[0].metadata =
        json!({"record_id":"secret:hidden-input"});
    let hidden_error = complete_request_with_publication(&db, principal, hidden_input)
        .await
        .unwrap_err();
    assert_eq!(hidden_error.to_string(), "derivation audience proof failed");
    assert!(!hidden_error.to_string().contains("secret:hidden-input"));

    let context_id = crate::store::create_record_as(
        &db,
        json!({
            "id":"4e9e5700-0000-4000-8000-000000000003",
            "type":"Outcome",
            "kind":"impact",
            "name":"Completion race context",
            "body":"original context"
        }),
        Some("acct:publisher"),
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "acct:publisher",
        &context_id,
        vec![
            AllowEntry::account("acct:publisher", Capability::Manage),
            AllowEntry::account("acct:audience", Capability::View),
        ],
    )
    .await
    .unwrap();
    let context_event: (String, String) = sqlx::query_as(
        "SELECT id,json_extract(payload,'$.body') FROM content_events
          WHERE record_id=? AND json_type(payload,'$.body')='text'
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&context_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let mut stale_context = completion.clone();
    stale_context
        .publication
        .revision
        .inputs
        .push(DerivationInput {
            input_role: "context".into(),
            input_kind: "record_body".into(),
            portable_id: context_event.0,
            sha256: sha256_bytes(context_event.1.as_bytes()),
            metadata: json!({
                "record_id":context_id,
                "record_state":{
                    "type":"Outcome",
                    "kind":"impact",
                    "is_live":true,
                    "is_realised":true
                }
            }),
        });
    stale_context.executor.usage.input_items += 1;
    stale_context.executor.usage.input_bytes += context_event.1.len() as u64;
    crate::store::update_record(&db, &context_id, json!({"kind":"milestone"}))
        .await
        .unwrap();
    let stale_context_error = complete_request_with_publication(&db, principal, stale_context)
        .await
        .unwrap_err();
    assert_eq!(
        stale_context_error.to_string(),
        "derivation audience proof failed"
    );
    assert_eq!(
        inspect_request(&db, &request.id)
            .await
            .unwrap()
            .unwrap()
            .state,
        DerivationRequestState::Running
    );
    let stale_partial: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM derivation_revisions WHERE id='revision:controlled-success'),
           (SELECT count(*) FROM derivation_target_publications WHERE publication_id='publication:controlled-success')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(stale_partial, (0, 0));
    let injected = complete_request_with_publication_at(
        &db,
        principal,
        completion.clone(),
        &TestClock::at(Utc::now()),
        CompletionFailurePoint::AfterPublication,
    )
    .await
    .unwrap_err();
    assert!(injected.to_string().contains("after publication"));
    assert_eq!(
        inspect_request(&db, &request.id)
            .await
            .unwrap()
            .unwrap()
            .state,
        DerivationRequestState::Running
    );
    let partial: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM derivation_revisions WHERE id='revision:controlled-success'),
           (SELECT count(*) FROM derivation_target_publications WHERE publication_id='publication:controlled-success')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(partial, (0, 0));

    let published = complete_request_with_publication(&db, principal, completion)
        .await
        .unwrap()
        .expect("live generation publishes once");
    let terminal = inspect_request(&db, &request.id).await.unwrap().unwrap();
    assert_eq!(terminal.state, DerivationRequestState::Succeeded);
    assert_eq!(
        terminal.result_revision_id.as_deref(),
        Some("revision:controlled-success")
    );
    assert_eq!(
        published.revision_event.aggregate_id,
        "revision:controlled-success"
    );
    assert!(matches!(
        wait_for_request(&db, &request.id, Duration::ZERO, None)
            .await
            .unwrap(),
        RequestWaitOutcome::Terminal(_)
    ));
    let metadata: String = sqlx::query_scalar(
        "SELECT completion_metadata FROM derivation_revisions WHERE id='revision:controlled-success'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
    assert_eq!(metadata["executor"]["provider"], "test-provider");
    assert_eq!(metadata["request_key_sha256"], request.request_key_sha256);
    assert_eq!(metadata["attempt"]["lease_owner"], "worker:two");
    assert_eq!(metadata["attempt"]["lease_run_key"], "run:controlled");
    assert_eq!(metadata["attempt"]["lease_generation"], 2);
    assert_eq!(metadata["attempt"]["publication_actor"], "acct:publisher");
    assert_eq!(
        published.content_event.run_key.as_deref(),
        Some("run:controlled")
    );
    assert_eq!(
        published.revision_event.run_key.as_deref(),
        Some("run:controlled")
    );
    assert_eq!(
        published.publication_event.run_key.as_deref(),
        Some("run:controlled")
    );
    let recognition_basis = RevisionRecognitionBasis {
        series_id: request_spec.series_id.clone(),
        revision_id: "revision:controlled-success".into(),
        definition_sha256: request_spec.definition_sha256.clone(),
        canonical_request: request_spec.canonical_request.clone(),
        recipe_revision: request_spec.recipe_revision.clone(),
        effective_source_boundary: request_spec.effective_source_boundary.clone(),
        completion_metadata: metadata.clone(),
    };
    struct CurrentBasis(DerivationApplicabilityBasis);
    impl CurrentRevisionBasisResolver for CurrentBasis {
        fn current_basis<'a>(
            &'a self,
            _snapshot: &'a mut sqlx::Transaction<'static, sqlx::Sqlite>,
            _revision: &'a RevisionRecognitionBasis,
        ) -> futures::future::BoxFuture<'a, crate::Result<Option<DerivationApplicabilityBasis>>>
        {
            Box::pin(async { Ok(Some(self.0.clone())) })
        }
    }
    let current_basis = DerivationApplicabilityBasis::from(&request_spec);
    let live_gate = RequestRevisionApplicabilityGate::new(
        |account_id: &str| Some(matches!(account_id, "acct:audience" | "acct:publisher")),
        CurrentBasis(current_basis.clone()),
    );
    let mut applicability_snapshot = db.pool().begin().await.unwrap();
    assert!(live_gate
        .is_current_and_audience_available(&mut applicability_snapshot, &recognition_basis)
        .await
        .unwrap());
    applicability_snapshot.rollback().await.unwrap();
    assert!(revision_audience_is_available(
        &db,
        &request.id,
        "revision:controlled-success",
        &|account_id| Some(matches!(account_id, "acct:audience" | "acct:publisher")),
    )
    .await
    .unwrap());
    assert!(!revision_audience_is_available(
        &db,
        &request.id,
        "revision:controlled-success",
        &|account_id| Some(account_id == "acct:publisher"),
    )
    .await
    .unwrap());
    let offboarded_gate = RequestRevisionApplicabilityGate::new(
        |account_id: &str| Some(account_id == "acct:publisher"),
        CurrentBasis(current_basis.clone()),
    );
    let mut applicability_snapshot = db.pool().begin().await.unwrap();
    assert!(!offboarded_gate
        .is_current_and_audience_available(&mut applicability_snapshot, &recognition_basis)
        .await
        .unwrap());
    applicability_snapshot.rollback().await.unwrap();
    let mut behind = current_basis.clone();
    behind.effective_source_boundary.through_seq += 1;
    let behind_gate = RequestRevisionApplicabilityGate::new(
        |account_id: &str| Some(matches!(account_id, "acct:audience" | "acct:publisher")),
        CurrentBasis(behind),
    );
    let mut applicability_snapshot = db.pool().begin().await.unwrap();
    assert!(!behind_gate
        .is_current_and_audience_available(&mut applicability_snapshot, &recognition_basis)
        .await
        .unwrap());
    applicability_snapshot.rollback().await.unwrap();
    let mut scope_changed = current_basis.clone();
    scope_changed
        .effective_source_boundary
        .resolved_scope_membership_sha256 = "9".repeat(64);
    let scope_gate = RequestRevisionApplicabilityGate::new(
        |account_id: &str| Some(matches!(account_id, "acct:audience" | "acct:publisher")),
        CurrentBasis(scope_changed),
    );
    let mut applicability_snapshot = db.pool().begin().await.unwrap();
    assert!(!scope_gate
        .is_current_and_audience_available(&mut applicability_snapshot, &recognition_basis)
        .await
        .unwrap());
    applicability_snapshot.rollback().await.unwrap();
    let mut definition_changed = current_basis;
    definition_changed.definition_sha256 = "8".repeat(64);
    let definition_gate = RequestRevisionApplicabilityGate::new(
        |account_id: &str| Some(matches!(account_id, "acct:audience" | "acct:publisher")),
        CurrentBasis(definition_changed),
    );
    let mut applicability_snapshot = db.pool().begin().await.unwrap();
    assert!(!definition_gate
        .is_current_and_audience_available(&mut applicability_snapshot, &recognition_basis)
        .await
        .unwrap());
    applicability_snapshot.rollback().await.unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "acct:publisher",
        &target_id,
        vec![AllowEntry::account("acct:other", Capability::View)],
    )
    .await
    .unwrap();
    assert!(!revision_audience_is_available(
        &db,
        &request.id,
        "revision:controlled-success",
        &|_| Some(true),
    )
    .await
    .unwrap());
}

#[tokio::test]
async fn request_and_controlled_acquire_fence_the_stable_series_definition() {
    let db = crate::create_database(":memory:").await.unwrap();
    create_series(&db, "series:definition-fence").await;
    let mut mismatched = spec("series:definition-fence");
    mismatched.definition_sha256 = "f".repeat(64);
    let error = create_or_join_request(&db, mismatched, requester("person:mismatch"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("stable series"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM derivation_requests")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);

    let request = create_or_join_request(
        &db,
        spec("series:definition-fence"),
        requester("person:valid"),
    )
    .await
    .unwrap()
    .request;
    sqlx::query(
        "UPDATE derivation_series SET definition_sha256=? WHERE id='series:definition-fence'",
    )
    .bind("e".repeat(64))
    .execute(db.write_pool())
    .await
    .unwrap();
    let error = acquire_request_for_controlled_execution(
        &db,
        Principal::bound("person:valid", true),
        &request.id,
        "worker:definition-fence",
        None,
        1,
        Duration::from_secs(30),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("stable series"));
    let state = inspect_request(&db, &request.id).await.unwrap().unwrap();
    assert_eq!(state.state, DerivationRequestState::Pending);
    assert_eq!(state.lease_generation, 0);
}
