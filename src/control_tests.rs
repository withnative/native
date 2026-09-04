use crate::conformance::rebuild_and_diff_control;
use crate::control::{
    append_control_event, append_control_event_in, close_agent_run, ensure_agent_run,
    member_obligation_aggregate_id, programme_source_aggregate_id, ControlEventPayload,
    EmptyPayload, InstructionBindingReorderedPayload, InstructionBindingStatePayload,
    InstructionBindingTogglePayload, MemberContextProvisionedPayload,
    MemberObligationProgressedPayload, MemberObligationRebasedPayload,
    MemberObligationResolvedPayload, MemberObligationStatePayload, NewControlEvent,
    OnboardingProgrammeSourcePayload, OnboardingProgrammeSourceRemovedPayload,
    OnboardingProgrammeStatePayload, ProgrammeGenerationPublishedPayload,
    SeededInstructionSourceAppliedPayload,
};
use crate::store::create_record;
use crate::{create_database, open_existing_database_at};
use serde_json::json;
use sqlx::Row;

const NOW: &str = "2026-08-03T12:00:00Z";
const AGENT_RUN: &str = "scout-chair-a748b2";

// Pinned fixture record ids. Only ids that reach `record()` (and therefore the
// record-id authority) are UUIDs here; programme ids, binding ids, template
// keys and account tokens are separate namespaces and stay readable.
const PERSON_ID: &str = "c07f0000-0000-4000-8000-000000000001";
const PRIVATE_ROOT_ID: &str = "c07f0000-0000-4000-8000-000000000002";
const INSTRUCTIONS_ID: &str = "c07f0000-0000-4000-8000-000000000003";
const CRITERIA_ID: &str = "c07f0000-0000-4000-8000-000000000004";
const FAILURE_SOURCE_ID: &str = "c07f0000-0000-4000-8000-000000000005";
const ROLLED_PERSON_ID: &str = "c07f0000-0000-4000-8000-000000000006";
const ROLLED_ROOT_ID: &str = "c07f0000-0000-4000-8000-000000000007";
const STARTING_CONTEXT_ID: &str = "c07f0000-0000-4000-8000-000000000008";

async fn record(db: &crate::Db, id: &str) {
    create_record(
        db,
        json!({"id":id,"type":"Entity","kind":"person","name":id}),
    )
    .await
    .unwrap();
}

fn command(key: &str, aggregate_id: &str, payload: ControlEventPayload) -> NewControlEvent {
    NewControlEvent::authored(
        key,
        aggregate_id,
        "acct_alice",
        Some("gentle-calm-forest".into()),
        "control event test",
        payload,
    )
    .unwrap()
}

fn programme() -> OnboardingProgrammeStatePayload {
    OnboardingProgrammeStatePayload {
        id: "joined-orientation".into(),
        trigger_key: "on_member_joined".into(),
        generation: 1,
        position: 100,
        enabled: true,
        created_by: "acct_alice".into(),
        legacy_baseline_before: None,
        created_at: NOW.into(),
        updated_at: NOW.into(),
    }
}

async fn append_minimal_graph(db: &crate::Db) {
    for id in [PERSON_ID, PRIVATE_ROOT_ID, INSTRUCTIONS_ID, CRITERIA_ID] {
        record(db, id).await;
    }
    append_control_event(
        db,
        command(
            "context",
            "acct_alice",
            ControlEventPayload::MemberContextProvisioned(MemberContextProvisionedPayload {
                account_id: "acct_alice".into(),
                person_record_id: PERSON_ID.into(),
                root_record_id: PRIVATE_ROOT_ID.into(),
                created_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        db,
        command(
            "binding",
            "binding-1",
            ControlEventPayload::InstructionBindingCreated(InstructionBindingStatePayload {
                id: "binding-1".into(),
                scope_kind: "account".into(),
                scope_id: "acct_alice".into(),
                source_record_id: INSTRUCTIONS_ID.into(),
                position: 100,
                enabled: true,
                created_by: "acct_alice".into(),
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        db,
        command(
            "programme",
            "joined-orientation",
            ControlEventPayload::OnboardingProgrammeCreated(programme()),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        db,
        command(
            "source",
            &programme_source_aggregate_id("joined-orientation", CRITERIA_ID),
            ControlEventPayload::OnboardingProgrammeSourceAdded(OnboardingProgrammeSourcePayload {
                programme_id: "joined-orientation".into(),
                source_record_id: CRITERIA_ID.into(),
                source_role: "completion_criteria".into(),
                position: 100,
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        db,
        command(
            "obligation",
            &member_obligation_aggregate_id("acct_alice", "joined-orientation", 1),
            ControlEventPayload::MemberObligationActivated(MemberObligationStatePayload {
                account_id: "acct_alice".into(),
                programme_id: "joined-orientation".into(),
                generation: 1,
                state: "pending".into(),
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        db,
        command(
            "seed",
            INSTRUCTIONS_ID,
            ControlEventPayload::SeededInstructionSourceApplied(
                SeededInstructionSourceAppliedPayload {
                    source_record_id: INSTRUCTIONS_ID.into(),
                    template_key: "member-instructions".into(),
                    template_version: 1,
                    last_applied_digest: "sha256:test".into(),
                    last_applied_at: NOW.into(),
                    operation: None,
                    expected_body_digest: None,
                },
            ),
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn durable_agent_run_lifecycle_is_stable_and_replayable() {
    let db = create_database(":memory:").await.unwrap();
    let admitted = ensure_agent_run(&db, AGENT_RUN, "acct_alice")
        .await
        .unwrap();
    assert!(admitted.changed);
    let retried = ensure_agent_run(&db, AGENT_RUN, "acct_alice")
        .await
        .unwrap();
    assert!(!retried.changed);
    assert_eq!(retried.activity_id, admitted.activity_id);
    assert!(ensure_agent_run(&db, AGENT_RUN, "acct_bob")
        .await
        .unwrap_err()
        .to_string()
        .contains("another authenticated account"));

    let closed = close_agent_run(&db, AGENT_RUN, "acct_alice").await.unwrap();
    assert!(closed.changed);
    let reclosed = close_agent_run(&db, AGENT_RUN, "acct_alice").await.unwrap();
    assert!(!reclosed.changed);
    assert_eq!(reclosed.ended_at, closed.ended_at);
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
}

#[tokio::test]
async fn append_project_is_atomic_append_only_and_idempotent() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, PERSON_ID).await;
    record(&db, PRIVATE_ROOT_ID).await;
    let input = command(
        "arrival:alice",
        "acct_alice",
        ControlEventPayload::MemberContextProvisioned(MemberContextProvisionedPayload {
            account_id: "acct_alice".into(),
            person_record_id: PERSON_ID.into(),
            root_record_id: PRIVATE_ROOT_ID.into(),
            created_at: NOW.into(),
        }),
    );
    let first = append_control_event(&db, input.clone()).await.unwrap();
    let second = append_control_event(&db, input.clone()).await.unwrap();
    assert_eq!(first.id, second.id);
    let mut later_run = input;
    later_run.run_key = Some("brisk-new-river".into());
    let cross_run = append_control_event(&db, later_run).await.unwrap();
    assert_eq!(first.id, cross_run.id);
    assert_eq!(cross_run.run_key.as_deref(), Some("gentle-calm-forest"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM member_contexts")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        1
    );

    let collision = command(
        "arrival:alice",
        "acct_other",
        ControlEventPayload::MemberContextProvisioned(MemberContextProvisionedPayload {
            account_id: "acct_other".into(),
            person_record_id: PERSON_ID.into(),
            root_record_id: PRIVATE_ROOT_ID.into(),
            created_at: NOW.into(),
        }),
    );
    assert!(append_control_event(&db, collision)
        .await
        .unwrap_err()
        .to_string()
        .contains("different intent"));

    for statement in [
        "UPDATE control_events SET actor='tampered' WHERE seq=1",
        "DELETE FROM control_events WHERE seq=1",
    ] {
        assert!(sqlx::query(statement)
            .execute(db.write_pool())
            .await
            .is_err());
    }

    record(&db, FAILURE_SOURCE_ID).await;
    sqlx::query(
        "CREATE TRIGGER fail_control_projection BEFORE INSERT ON instruction_bindings
         BEGIN SELECT RAISE(ABORT,'injected control projection failure'); END",
    )
    .execute(db.write_pool())
    .await
    .unwrap();
    let failed = command(
        "atomic-failure",
        "failure-binding",
        ControlEventPayload::InstructionBindingCreated(InstructionBindingStatePayload {
            id: "failure-binding".into(),
            scope_kind: "database".into(),
            scope_id: "native:database".into(),
            source_record_id: FAILURE_SOURCE_ID.into(),
            position: 100,
            enabled: true,
            created_by: "acct_alice".into(),
            created_at: NOW.into(),
            updated_at: NOW.into(),
        }),
    );
    assert!(append_control_event(&db, failed).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM control_events WHERE idempotency_key='atomic-failure'"
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        0
    );

    record(&db, ROLLED_PERSON_ID).await;
    record(&db, ROLLED_ROOT_ID).await;
    let mut outer = db.write_pool().begin().await.unwrap();
    append_control_event_in(
        &mut outer,
        command(
            "outer-rollback",
            "acct_rolled",
            ControlEventPayload::MemberContextProvisioned(MemberContextProvisionedPayload {
                account_id: "acct_rolled".into(),
                person_record_id: ROLLED_PERSON_ID.into(),
                root_record_id: ROLLED_ROOT_ID.into(),
                created_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    outer.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM control_events WHERE idempotency_key='outer-rollback'"
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM control_event_applications WHERE event_id IN
             (SELECT id FROM control_events WHERE idempotency_key='atomic-failure')"
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn concurrent_first_arrival_key_converges() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, PERSON_ID).await;
    record(&db, PRIVATE_ROOT_ID).await;
    let input = command(
        "arrival:concurrent",
        "acct_alice",
        ControlEventPayload::MemberContextProvisioned(MemberContextProvisionedPayload {
            account_id: "acct_alice".into(),
            person_record_id: PERSON_ID.into(),
            root_record_id: PRIVATE_ROOT_ID.into(),
            created_at: NOW.into(),
        }),
    );
    let (left, right) = tokio::join!(
        append_control_event(&db, input.clone()),
        append_control_event(&db, input)
    );
    assert_eq!(left.unwrap().id, right.unwrap().id);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM member_contexts")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn replay_rebuilds_every_projection_and_reports_drift() {
    let db = create_database(":memory:").await.unwrap();
    append_minimal_graph(&db).await;
    let result = rebuild_and_diff_control(&db).await.unwrap();
    assert!(result.equal, "{result:#?}");
    assert_eq!(result.tables.len(), 9);

    sqlx::query("UPDATE instruction_bindings SET position=999 WHERE id='binding-1'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let drift = rebuild_and_diff_control(&db).await.unwrap();
    assert!(!drift.equal);
    assert!(drift
        .tables
        .iter()
        .any(|table| table.table == "instruction_bindings" && !table.mismatches.is_empty()));
}

#[tokio::test]
async fn unknown_type_version_and_payload_fields_fail_visibly() {
    let db = create_database(":memory:").await.unwrap();
    for (key, event_type, version, payload) in [
        ("unknown-type", "control.unknown", 1_i64, "{}"),
        ("unknown-version", "instruction_binding.removed", 2, "{}"),
        (
            "unknown-field",
            "instruction_binding.removed",
            1,
            r#"{"surprise":true}"#,
        ),
    ] {
        sqlx::query(
            "INSERT INTO control_events
             (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,reason,payload,created_at)
             VALUES(?,?,?,?,?,'aggregate','actor','reason',?,?)",
        )
        .bind(key)
        .bind(key)
        .bind(event_type)
        .bind(version)
        .bind(if event_type == "control.unknown" {
            "unknown"
        } else {
            "instruction_binding"
        })
        .bind(payload)
        .bind(NOW)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO control_events
         (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,reason,payload,created_at)
         VALUES('generation-overflow','generation-overflow',
                'onboarding_programme.generation_published',1,
                'onboarding_programme','programme','actor','reason',?,?)",
    )
    .bind(
        json!({
            "previous_generation": i64::MAX,
            "generation": i64::MAX,
            "updated_at": NOW,
            "audience_account_ids": []
        })
        .to_string(),
    )
    .bind(NOW)
    .execute(db.write_pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO control_events
         (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at)
         VALUES('agent-run-invalid-key','agent-run-invalid-key','agent_run.started.v1',1,
                'agent_run','activity','acct','not-a-full-key','reason',?,?)",
    )
    .bind(
        json!({
            "activity_id": "activity",
            "account_id": "acct",
            "started_at": NOW
        })
        .to_string(),
    )
    .bind(NOW)
    .execute(db.write_pool())
    .await
    .unwrap();
    for (key, event_type, payload) in [
        (
            "resolved-missing-evidence",
            "member_obligation.resolved",
            json!({
                "account_id":"acct", "programme_id":"programme", "generation":1,
                "state":"completed", "updated_at":NOW
            }),
        ),
        (
            "reopened-null-evidence",
            "member_obligation.reopened",
            json!({
                "account_id":"acct", "programme_id":"programme", "generation":1,
                "previous_state":"completed", "updated_at":NOW, "evidence":null
            }),
        ),
    ] {
        sqlx::query(
            "INSERT INTO control_events
             (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,reason,payload,created_at)
             VALUES(?,?,?,1,'member_obligation',?,'actor','reason',?,?)",
        )
        .bind(key)
        .bind(key)
        .bind(event_type)
        .bind(member_obligation_aggregate_id("acct", "programme", 1))
        .bind(payload.to_string())
        .bind(NOW)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
    let violations = crate::control::state_violations(&db).await.unwrap();
    let joined = violations.join("\n");
    assert!(joined.contains("unknown control event type"), "{joined}");
    assert!(
        joined.contains("unsupported control event schema version"),
        "{joined}"
    );
    assert!(
        joined.contains("unknown field") || joined.contains("surprise"),
        "{joined}"
    );
    assert!(
        joined.contains("cannot advance beyond i64::MAX"),
        "{joined}"
    );
    assert!(joined.contains("missing field `evidence`"), "{joined}");
    assert!(
        joined.contains("agent run start requires a valid full run key"),
        "{joined}"
    );
    assert!(
        joined.contains("reopened obligation evidence is required"),
        "{joined}"
    );
    assert!(rebuild_and_diff_control(&db).await.is_err());
}

#[tokio::test]
async fn transitions_and_generation_rebase_are_replayable() {
    let db = create_database(":memory:").await.unwrap();
    for id in [CRITERIA_ID] {
        record(&db, id).await;
    }
    append_control_event(
        &db,
        command(
            "programme",
            "joined-orientation",
            ControlEventPayload::OnboardingProgrammeCreated(programme()),
        ),
    )
    .await
    .unwrap();
    let wrong_aggregate = command(
        "activate-wrong-aggregate",
        "ambiguous:aggregate",
        ControlEventPayload::MemberObligationActivated(MemberObligationStatePayload {
            account_id: "wrong-aggregate".into(),
            programme_id: "joined-orientation".into(),
            generation: 1,
            state: "pending".into(),
            created_at: NOW.into(),
            updated_at: NOW.into(),
        }),
    );
    assert!(append_control_event(&db, wrong_aggregate)
        .await
        .unwrap_err()
        .to_string()
        .contains("canonical payload identity"));
    let stale_activation = command(
        "activate-wrong-generation",
        &member_obligation_aggregate_id("wrong-generation", "joined-orientation", 2),
        ControlEventPayload::MemberObligationActivated(MemberObligationStatePayload {
            account_id: "wrong-generation".into(),
            programme_id: "joined-orientation".into(),
            generation: 2,
            state: "pending".into(),
            created_at: NOW.into(),
            updated_at: NOW.into(),
        }),
    );
    assert!(append_control_event(&db, stale_activation).await.is_err());
    append_control_event(
        &db,
        command(
            "baseline",
            &member_obligation_aggregate_id("legacy", "joined-orientation", 1),
            ControlEventPayload::MemberObligationRolloutBaselined(MemberObligationStatePayload {
                account_id: "legacy".into(),
                programme_id: "joined-orientation".into(),
                generation: 1,
                state: "completed".into(),
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "activate",
            &member_obligation_aggregate_id("acct_alice", "joined-orientation", 1),
            ControlEventPayload::MemberObligationActivated(MemberObligationStatePayload {
                account_id: "acct_alice".into(),
                programme_id: "joined-orientation".into(),
                generation: 1,
                state: "pending".into(),
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "resolve",
            &member_obligation_aggregate_id("acct_alice", "joined-orientation", 1),
            ControlEventPayload::MemberObligationResolved(MemberObligationResolvedPayload {
                account_id: "acct_alice".into(),
                programme_id: "joined-orientation".into(),
                generation: 1,
                state: "completed".into(),
                updated_at: NOW.into(),
                evidence: json!({"record_id":CRITERIA_ID}),
            }),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "reopen",
            &member_obligation_aggregate_id("acct_alice", "joined-orientation", 1),
            ControlEventPayload::MemberObligationReopened(
                crate::control::MemberObligationReopenedPayload {
                    account_id: "acct_alice".into(),
                    programme_id: "joined-orientation".into(),
                    generation: 1,
                    previous_state: "completed".into(),
                    updated_at: NOW.into(),
                    evidence: json!({"member_intent":"reopen"}),
                },
            ),
        ),
    )
    .await
    .unwrap();
    let reopen_payload: String =
        sqlx::query_scalar("SELECT payload FROM control_events WHERE idempotency_key='reopen'")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reopen_payload).unwrap()["evidence"],
        json!({"member_intent":"reopen"})
    );
    let publish = command(
        "publish",
        "joined-orientation",
        ControlEventPayload::ProgrammeGenerationPublished(ProgrammeGenerationPublishedPayload {
            previous_generation: 1,
            generation: 2,
            updated_at: NOW.into(),
            audience_account_ids: vec!["acct_alice".into(), "acct_alice".into()],
            audience_digest: None,
            audience_kind: None,
            requested_account_ids: vec![],
        }),
    );
    let published = append_control_event(&db, publish).await.unwrap();
    let mut canonical_retry = command(
        "publish",
        "joined-orientation",
        ControlEventPayload::ProgrammeGenerationPublished(ProgrammeGenerationPublishedPayload {
            previous_generation: 1,
            generation: 2,
            updated_at: NOW.into(),
            audience_account_ids: vec!["acct_alice".into()],
            audience_digest: None,
            audience_kind: None,
            requested_account_ids: vec![],
        }),
    );
    canonical_retry.run_key = Some("later-retry-run".into());
    assert_eq!(
        append_control_event(&db, canonical_retry).await.unwrap().id,
        published.id
    );
    let skipped_generation = command(
        "publish-skipped-generation",
        "joined-orientation",
        ControlEventPayload::ProgrammeGenerationPublished(ProgrammeGenerationPublishedPayload {
            previous_generation: 2,
            generation: 4,
            updated_at: NOW.into(),
            audience_account_ids: vec![],
            audience_digest: None,
            audience_kind: None,
            requested_account_ids: vec![],
        }),
    );
    assert!(append_control_event(&db, skipped_generation).await.is_err());
    let wrong_rebase_generation = command(
        "rebase-not-current",
        &member_obligation_aggregate_id("acct_alice", "joined-orientation", 3),
        ControlEventPayload::MemberObligationRebased(MemberObligationRebasedPayload {
            account_id: "acct_alice".into(),
            programme_id: "joined-orientation".into(),
            previous_generation: 1,
            generation: 3,
            created_at: NOW.into(),
            updated_at: NOW.into(),
        }),
    );
    assert!(append_control_event(&db, wrong_rebase_generation)
        .await
        .is_err());
    append_control_event(
        &db,
        command(
            "rebase",
            &member_obligation_aggregate_id("acct_alice", "joined-orientation", 2),
            ControlEventPayload::MemberObligationRebased(MemberObligationRebasedPayload {
                account_id: "acct_alice".into(),
                programme_id: "joined-orientation".into(),
                previous_generation: 1,
                generation: 2,
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    let row = sqlx::query(
        "SELECT generation,state FROM member_obligations
          WHERE account_id='acct_alice' AND programme_id='joined-orientation'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("generation"), 2);
    assert_eq!(row.get::<String, _>("state"), "pending");
}

#[tokio::test]
async fn obligation_progress_is_exact_transition_checked_and_replayable() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, STARTING_CONTEXT_ID).await;
    append_control_event(
        &db,
        command(
            "progress-programme",
            "joined-orientation",
            ControlEventPayload::OnboardingProgrammeCreated(programme()),
        ),
    )
    .await
    .unwrap();
    let aggregate = member_obligation_aggregate_id("acct_alice", "joined-orientation", 1);
    append_control_event(
        &db,
        command(
            "progress-activate",
            &aggregate,
            ControlEventPayload::MemberObligationActivated(MemberObligationStatePayload {
                account_id: "acct_alice".into(),
                programme_id: "joined-orientation".into(),
                generation: 1,
                state: "pending".into(),
                created_at: NOW.into(),
                updated_at: NOW.into(),
            }),
        ),
    )
    .await
    .unwrap();

    let progress = |phase: &str, evidence, artifact_id: Option<&str>| {
        ControlEventPayload::MemberObligationProgressed(MemberObligationProgressedPayload {
            account_id: "acct_alice".into(),
            programme_id: "joined-orientation".into(),
            generation: 1,
            phase: phase.into(),
            updated_at: NOW.into(),
            evidence,
            resume_after: None,
            artifact_id: artifact_id.map(str::to_owned),
        })
    };
    append_control_event(
        &db,
        command(
            "progress-anchor",
            &aggregate,
            progress("anchor_established", json!({"basis":"user_stated"}), None),
        ),
    )
    .await
    .unwrap();

    let value_without_route = command(
        "progress-value-without-route",
        &aggregate,
        progress("value_delivered", json!({"basis":"user_confirmed"}), None),
    );
    assert!(append_control_event(&db, value_without_route)
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid progress transition"));

    let leaked_preview = command(
        "progress-preview-leak",
        &aggregate,
        progress(
            "artifact_previewed",
            json!({
                "content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "explicit_member_consent":true,
                "content_event_floor_seq":1,
                "existing_artifact_id":null,
                "draft":"private content must not enter control events"
            }),
            None,
        ),
    );
    assert!(append_control_event(&db, leaked_preview)
        .await
        .unwrap_err()
        .to_string()
        .contains("phase-specific audit schema"));

    let skipped_preview = command(
        "progress-skip-preview",
        &aggregate,
        progress("artifact_written", json!({}), Some(STARTING_CONTEXT_ID)),
    );
    assert!(append_control_event(&db, skipped_preview)
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid progress transition"));

    append_control_event(
        &db,
        command(
            "progress-preview",
            &aggregate,
            progress(
                "artifact_previewed",
                json!({
                    "content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "explicit_member_consent":true,
                    "content_event_floor_seq":1,
                    "existing_artifact_id":null
                }),
                None,
            ),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "progress-written",
            &aggregate,
            progress("artifact_written", json!({}), Some(STARTING_CONTEXT_ID)),
        ),
    )
    .await
    .unwrap();
    let legacy_value_without_route = command(
        "progress-legacy-value-without-route",
        &aggregate,
        progress("value_delivered", json!({"basis":"user_confirmed"}), None),
    );
    assert!(append_control_event(&db, legacy_value_without_route)
        .await
        .unwrap_err()
        .to_string()
        .contains("requires a selected QuickStart route"));
    append_control_event(
        &db,
        command(
            "progress-route-after-legacy-write",
            &aggregate,
            progress(
                "route_selected",
                json!({"route_id":"practical_workflow"}),
                None,
            ),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "progress-value-after-route",
            &aggregate,
            progress("value_delivered", json!({"basis":"user_confirmed"}), None),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "progress-deferred-after-write",
            &aggregate,
            progress("deferred", json!({"basis":"explicit_member_request"}), None),
        ),
    )
    .await
    .unwrap();
    append_control_event(
        &db,
        command(
            "progress-resume-written-checkpoint",
            &aggregate,
            progress(
                "anchor_established",
                json!({"basis":"user_confirmed","checkpoint":"artifact_written"}),
                None,
            ),
        ),
    )
    .await
    .unwrap();

    let row = sqlx::query(
        "SELECT phase,evidence,artifact_id,selected_route_id FROM member_obligation_progress
          WHERE account_id='acct_alice' AND programme_id='joined-orientation' AND generation=1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("phase"), "artifact_written");
    assert_eq!(row.get::<String, _>("evidence"), "{}");
    assert_eq!(row.get::<String, _>("artifact_id"), STARTING_CONTEXT_ID);
    assert_eq!(
        row.get::<String, _>("selected_route_id"),
        "practical_workflow"
    );
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
}

#[tokio::test]
async fn binding_programme_source_and_seed_lifecycles_replay_exactly() {
    let db = create_database(":memory:").await.unwrap();
    for id in [INSTRUCTIONS_ID, CRITERIA_ID] {
        record(&db, id).await;
    }
    let binding = |position, enabled| InstructionBindingStatePayload {
        id: "binding-1".into(),
        scope_kind: "database".into(),
        scope_id: "native:database".into(),
        source_record_id: INSTRUCTIONS_ID.into(),
        position,
        enabled,
        created_by: "acct_alice".into(),
        created_at: NOW.into(),
        updated_at: NOW.into(),
    };
    for (key, payload) in [
        (
            "binding-create",
            ControlEventPayload::InstructionBindingCreated(binding(100, true)),
        ),
        (
            "binding-change",
            ControlEventPayload::InstructionBindingChanged(binding(110, true)),
        ),
        (
            "binding-disable",
            ControlEventPayload::InstructionBindingDisabled(InstructionBindingTogglePayload {
                updated_at: NOW.into(),
            }),
        ),
        (
            "binding-enable",
            ControlEventPayload::InstructionBindingEnabled(InstructionBindingTogglePayload {
                updated_at: NOW.into(),
            }),
        ),
        (
            "binding-reorder",
            ControlEventPayload::InstructionBindingReordered(InstructionBindingReorderedPayload {
                position: 120,
                updated_at: NOW.into(),
            }),
        ),
        (
            "binding-remove",
            ControlEventPayload::InstructionBindingRemoved(EmptyPayload::default()),
        ),
    ] {
        append_control_event(&db, command(key, "binding-1", payload))
            .await
            .unwrap();
    }

    append_control_event(
        &db,
        command(
            "programme-create",
            "joined-orientation",
            ControlEventPayload::OnboardingProgrammeCreated(programme()),
        ),
    )
    .await
    .unwrap();

    let mut engine_owned = programme();
    engine_owned.id = "legacy-programme".into();
    engine_owned.legacy_baseline_before = Some("2026-08-02T00:00:00Z".into());
    assert!(NewControlEvent::authored(
        "authored-legacy-cutoff",
        "legacy-programme",
        "acct_alice",
        None,
        "forged cutoff",
        ControlEventPayload::OnboardingProgrammeCreated(engine_owned.clone()),
    )
    .unwrap_err()
    .to_string()
    .contains("engine programme creation path"));
    let mut changed = programme();
    changed.position = 200;
    changed.enabled = false;
    append_control_event(
        &db,
        command(
            "programme-change",
            "joined-orientation",
            ControlEventPayload::OnboardingProgrammeChanged(changed),
        ),
    )
    .await
    .unwrap();

    for (key, mut invalid) in [
        ("programme-change-generation", programme()),
        ("programme-change-baseline", programme()),
    ] {
        if key.ends_with("generation") {
            invalid.generation = 2;
        } else {
            invalid.legacy_baseline_before = Some("2026-08-02T00:00:00Z".into());
        }
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(append_control_event(
            &db,
            command(
                key,
                "joined-orientation",
                ControlEventPayload::OnboardingProgrammeChanged(invalid),
            ),
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            before,
            "a rejected ordinary programme change must roll back its event"
        );
    }
    let programme_row = sqlx::query(
        "SELECT generation, position, legacy_baseline_before
           FROM onboarding_programmes WHERE id='joined-orientation'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(programme_row.get::<i64, _>("generation"), 1);
    assert_eq!(programme_row.get::<i64, _>("position"), 200);
    assert_eq!(
        programme_row.get::<Option<String>, _>("legacy_baseline_before"),
        None
    );
    let source = |role: &str, position| OnboardingProgrammeSourcePayload {
        programme_id: "joined-orientation".into(),
        source_record_id: CRITERIA_ID.into(),
        source_role: role.into(),
        position,
    };
    assert!(append_control_event(
        &db,
        command(
            "source-wrong-aggregate",
            "joined-orientation:criteria",
            ControlEventPayload::OnboardingProgrammeSourceAdded(source("guidance", 100)),
        ),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("canonical payload identity"));
    for (key, payload) in [
        (
            "source-add",
            ControlEventPayload::OnboardingProgrammeSourceAdded(source("guidance", 100)),
        ),
        (
            "source-change",
            ControlEventPayload::OnboardingProgrammeSourceChanged(source(
                "completion_criteria",
                110,
            )),
        ),
        (
            "source-reorder",
            ControlEventPayload::OnboardingProgrammeSourceReordered(source(
                "completion_criteria",
                120,
            )),
        ),
        (
            "source-remove",
            ControlEventPayload::OnboardingProgrammeSourceRemoved(
                OnboardingProgrammeSourceRemovedPayload {
                    programme_id: "joined-orientation".into(),
                    source_record_id: CRITERIA_ID.into(),
                },
            ),
        ),
    ] {
        append_control_event(
            &db,
            command(
                key,
                &programme_source_aggregate_id("joined-orientation", CRITERIA_ID),
                payload,
            ),
        )
        .await
        .unwrap();
    }
    for version in [1_i64, 2] {
        append_control_event(
            &db,
            command(
                &format!("seed-{version}"),
                INSTRUCTIONS_ID,
                ControlEventPayload::SeededInstructionSourceApplied(
                    SeededInstructionSourceAppliedPayload {
                        source_record_id: INSTRUCTIONS_ID.into(),
                        template_key: "workspace-instructions".into(),
                        template_version: version,
                        last_applied_digest: format!("sha256:{version}"),
                        last_applied_at: NOW.into(),
                        operation: None,
                        expected_body_digest: None,
                    },
                ),
            ),
        )
        .await
        .unwrap();
    }
    append_control_event(
        &db,
        command(
            "seed-same-version",
            INSTRUCTIONS_ID,
            ControlEventPayload::SeededInstructionSourceApplied(
                SeededInstructionSourceAppliedPayload {
                    source_record_id: INSTRUCTIONS_ID.into(),
                    template_key: "workspace-instructions".into(),
                    template_version: 2,
                    last_applied_digest: "sha256:2".into(),
                    last_applied_at: NOW.into(),
                    operation: Some("reset_seeded_default".into()),
                    expected_body_digest: Some("sha256:customized".into()),
                },
            ),
        ),
    )
    .await
    .unwrap();
    for (key, template_key, version) in [
        ("seed-regression", "workspace-instructions", 1_i64),
        ("seed-key-change", "different-template", 3),
    ] {
        let error = append_control_event(
            &db,
            command(
                key,
                INSTRUCTIONS_ID,
                ControlEventPayload::SeededInstructionSourceApplied(
                    SeededInstructionSourceAppliedPayload {
                        source_record_id: INSTRUCTIONS_ID.into(),
                        template_key: template_key.into(),
                        template_version: version,
                        last_applied_digest: format!("sha256:{key}"),
                        last_applied_at: NOW.into(),
                        operation: None,
                        expected_body_digest: None,
                    },
                ),
            ),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("did not match exactly one"));
    }
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM instruction_bindings")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM onboarding_programme_sources")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(&format!(
            "SELECT template_version FROM seeded_instruction_sources \
                 WHERE source_record_id='{INSTRUCTIONS_ID}'"
        ))
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        2
    );
}

#[tokio::test]
async fn reopen_fails_closed_on_control_projection_drift() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control-drift.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    append_minimal_graph(&db).await;
    sqlx::query("UPDATE instruction_bindings SET position=999 WHERE id='binding-1'")
        .execute(db.write_pool())
        .await
        .unwrap();
    db.close().await;

    let error = open_existing_database_at(&path)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("control projection drift"), "{error}");
}
