use crate::conformance::rebuild_and_diff_control;
use crate::control::{
    alpha_tab_aggregate_id, append_control_event, append_control_event_in, close_agent_run,
    control_events_in_act_range, ensure_agent_run, member_obligation_aggregate_id,
    programme_source_aggregate_id, read_agent_run_reported_identity, read_all_control_events,
    replay_control, AlphaTabAdoptPayload, AlphaTabStatePayload, ControlEventPayload,
    ControlEventRow, EmptyPayload, InstructionBindingReorderedPayload,
    InstructionBindingStatePayload, InstructionBindingTogglePayload,
    MemberContextProvisionedPayload, MemberObligationProgressedPayload,
    MemberObligationRebasedPayload, MemberObligationResolvedPayload, MemberObligationStatePayload,
    NewControlEvent, OnboardingProgrammeSourcePayload, OnboardingProgrammeSourceRemovedPayload,
    OnboardingProgrammeStatePayload, ProgrammeGenerationPublishedPayload, ReportedRunIdentity,
    SeededInstructionSourceAppliedPayload, ALPHA_TAB_ADOPTION_VERIFIED,
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
const ALPHA_FIXTURE_ARTIFACT_ID: &str = "c07f0000-0000-4000-8000-000000000010";

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
    let admitted = ensure_agent_run(&db, AGENT_RUN, "acct_alice", ReportedRunIdentity::default())
        .await
        .unwrap();
    assert!(admitted.changed);
    let retried = ensure_agent_run(&db, AGENT_RUN, "acct_alice", ReportedRunIdentity::default())
        .await
        .unwrap();
    assert!(!retried.changed);
    assert_eq!(retried.activity_id, admitted.activity_id);
    assert!(
        ensure_agent_run(&db, AGENT_RUN, "acct_bob", ReportedRunIdentity::default(),)
            .await
            .unwrap_err()
            .to_string()
            .contains("another authenticated account")
    );

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
    let mut act_alloc = crate::act::ActAllocation::new();
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
        &mut act_alloc,
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
    assert_eq!(result.tables.len(), 10);

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

#[tokio::test]
async fn control_events_in_act_range_is_bounded_ordered_and_excludes_null_acts() {
    const LEGACY: &str = "control-event-legacy-null-act";

    let db = create_database(":memory:").await.unwrap();
    // Three real authored programmes, each committed by its own seam call so
    // each carries its own act stamp.
    for ordinal in 0..3 {
        append_control_event(
            &db,
            command(
                &format!("range-programme-{ordinal}"),
                &format!("range-programme-{ordinal}"),
                ControlEventPayload::OnboardingProgrammeCreated(OnboardingProgrammeStatePayload {
                    id: format!("range-programme-{ordinal}"),
                    trigger_key: format!("on_range_{ordinal}"),
                    generation: 1,
                    position: 100 + ordinal,
                    enabled: true,
                    created_by: "acct_alice".into(),
                    legacy_baseline_before: None,
                    created_at: NOW.into(),
                    updated_at: NOW.into(),
                }),
            ),
        )
        .await
        .unwrap();
    }
    // A legacy grouping-unknown row: `NULL` act, schema-valid, narrow.
    sqlx::query(
        "INSERT INTO control_events
             (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
              actor,run_key,reason,payload,created_at,act)
         VALUES('control-event-legacy-null-act','legacy-control-key',
                'onboarding_programme.created',1,'onboarding_programme','legacy-programme',
                'engine:seed',NULL,'legacy act witness','{}','2026-01-01T00:00:00.000Z',NULL)",
    )
    .execute(db.write_pool())
    .await
    .unwrap();

    let mut conn = db.pool().acquire().await.unwrap();
    let full = read_all_control_events(&mut conn).await.unwrap();
    let mut distinct: Vec<i64> = full.iter().filter_map(|event| event.act).collect();
    distinct.sort_unstable();
    distinct.dedup();
    assert!(
        distinct.len() >= 3,
        "the test expects at least three stamped acts"
    );

    for (from_exclusive, to_inclusive) in [
        (distinct[0], distinct[2]),
        (distinct[1], distinct[2]),
        (distinct[0], distinct[1]),
    ] {
        let bounded = control_events_in_act_range(&mut conn, from_exclusive, to_inclusive)
            .await
            .unwrap();
        assert!(bounded.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        let expected: Vec<_> = full
            .iter()
            .filter(|event| {
                event
                    .act
                    .is_some_and(|act| act > from_exclusive && act <= to_inclusive)
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
    assert!(
        control_events_in_act_range(&mut conn, distinct[2], distinct[2])
            .await
            .unwrap()
            .is_empty()
    );
    // The NULL row is still part of the full log, proving it was excluded by
    // the predicate and not dropped by the decoder.
    assert!(full.iter().any(|event| event.id == LEGACY));
}

fn reported(client_name: &str, client_version: &str) -> ReportedRunIdentity {
    ReportedRunIdentity {
        client_name: Some(client_name.into()),
        client_version: Some(client_version.into()),
        model: None,
    }
}

#[tokio::test]
async fn admitted_client_identity_is_stamped_on_start_event_and_run_row() {
    let db = create_database(":memory:").await.unwrap();
    let admitted = ensure_agent_run(&db, AGENT_RUN, "acct_alice", reported("hazel", "2.1.0"))
        .await
        .unwrap();
    assert!(admitted.changed);

    // The canonical start event carries the values under the v2 type.
    let (event_type, payload): (String, String) = sqlx::query_as(
        "SELECT type,payload FROM control_events WHERE aggregate_id=? ORDER BY seq LIMIT 1",
    )
    .bind(&admitted.activity_id)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(event_type, "agent_run.started.v2");
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["reported_mcp_client_name"], "hazel");
    assert_eq!(payload["reported_mcp_client_version"], "2.1.0");
    assert!(payload.get("reported_model").is_none());

    // The projection agrees, and the model slot stays empty: no writer exists.
    let identity = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_eq!(identity.client_name.as_deref(), Some("hazel"));
    assert_eq!(identity.client_version.as_deref(), Some("2.1.0"));
    assert_eq!(identity.model, None);

    // Mid-run divergence never overwrites the admitted values.
    let retried = ensure_agent_run(&db, AGENT_RUN, "acct_alice", reported("other", "9.9"))
        .await
        .unwrap();
    assert!(!retried.changed);
    let kept = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_eq!(kept.client_name.as_deref(), Some("hazel"));
    assert_eq!(kept.client_version.as_deref(), Some("2.1.0"));

    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn absent_client_info_records_absence_not_an_empty_string() {
    let db = create_database(":memory:").await.unwrap();
    ensure_agent_run(&db, AGENT_RUN, "acct_alice", ReportedRunIdentity::default())
        .await
        .unwrap();
    let absent = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_eq!(absent, ReportedRunIdentity::default());

    // A client that sent an empty string stays distinguishable from absence.
    let empty_run = "scout-chair-b748b2";
    ensure_agent_run(
        &db,
        empty_run,
        "acct_alice",
        ReportedRunIdentity {
            client_name: Some(String::new()),
            client_version: Some(String::new()),
            model: None,
        },
    )
    .await
    .unwrap();
    let empty = read_agent_run_reported_identity(&db, empty_run)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_ne!(empty, ReportedRunIdentity::default());
    assert_eq!(empty.client_name.as_deref(), Some(""));
    assert_eq!(empty.client_version.as_deref(), Some(""));

    // No writer populates the model slot on either run.
    assert_eq!(absent.model, None);
    assert_eq!(empty.model, None);
    db.close().await;
}

#[tokio::test]
async fn declared_model_is_stamped_at_admission_and_first_wins() {
    let db = create_database(":memory:").await.unwrap();
    let admitted = ensure_agent_run(
        &db,
        AGENT_RUN,
        "acct_alice",
        ReportedRunIdentity {
            model: Some("ledger-model-a".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(admitted.changed);

    // The canonical start event carries the claim under the v2 type, exactly
    // as given: an unrecognised string is still the claim that was made.
    let (event_type, payload): (String, String) = sqlx::query_as(
        "SELECT type,payload FROM control_events WHERE aggregate_id=? ORDER BY seq LIMIT 1",
    )
    .bind(&admitted.activity_id)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(event_type, "agent_run.started.v2");
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["reported_model"], "ledger-model-a");

    let identity = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_eq!(identity.model.as_deref(), Some("ledger-model-a"));

    // An identical repeat declaration is benign: success, no new event.
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let retried = ensure_agent_run(
        &db,
        AGENT_RUN,
        "acct_alice",
        ReportedRunIdentity {
            model: Some("ledger-model-a".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!retried.changed);
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(events_before, events_after);

    // A differing second declaration never overwrites the stored value at
    // this layer: admission still succeeds (the refusal is response-level,
    // in the `set_intent` handler, so an unverified value can never decide
    // whether the declaration itself lands).
    let diverged = ensure_agent_run(
        &db,
        AGENT_RUN,
        "acct_alice",
        ReportedRunIdentity {
            model: Some("ledger-model-b".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!diverged.changed);
    let kept = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_eq!(kept.model.as_deref(), Some("ledger-model-a"));

    // A run admitted without a model keeps recording none no matter what a
    // later call carries: with no event version that could record it, the
    // only honest answer is refusal, and that refusal lives in the response.
    let unstamped_run = "scout-chair-b748b2";
    ensure_agent_run(
        &db,
        unstamped_run,
        "acct_alice",
        ReportedRunIdentity::default(),
    )
    .await
    .unwrap();
    ensure_agent_run(
        &db,
        unstamped_run,
        "acct_alice",
        ReportedRunIdentity {
            model: Some("ledger-model-a".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let still_none = read_agent_run_reported_identity(&db, unstamped_run)
        .await
        .unwrap()
        .expect("admitted run reads back");
    assert_eq!(still_none.model, None);

    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn declared_model_is_clamped_before_it_is_compared() {
    let db = create_database(":memory:").await.unwrap();
    // 255 ASCII bytes plus one 2-byte `é`: 257 bytes total, so the 256-byte
    // cap falls inside the final character and must stop at the boundary.
    let overlong = format!("{}é", "m".repeat(255));
    assert_eq!(overlong.len(), 257);
    ensure_agent_run(
        &db,
        AGENT_RUN,
        "acct_alice",
        ReportedRunIdentity {
            model: Some(overlong.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let identity = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("admitted run reads back");
    let stored = identity.model.expect("clamped model stored");
    assert_eq!(stored, "m".repeat(255));
    assert!(stored.is_char_boundary(stored.len()));

    // The comparison runs on the clamped value: repeating the same overlong
    // declaration matches what admission stored instead of reading as new.
    ensure_agent_run(
        &db,
        AGENT_RUN,
        "acct_alice",
        ReportedRunIdentity {
            model: Some(overlong),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    db.close().await;
}

/// The stored model string is never read to decide anything. This pins the
/// complete set of `reported_model` literal references in `src/`: the event
/// payload, the SQLite/Turso projections and their conformance/compat lists,
/// the admission write path, the migration that added the column, and tests.
///
/// What this pin is and is not: it is a literal-reference pin, not a proof
/// against all readers. The sanctioned accessor
/// (`read_agent_run_reported_identity`) returns `ReportedRunIdentity`, so a
/// reader spelled `... .model` off that result never names the literal and
/// passes the literal half of the test — the `set_intent` response
/// confirmation is exactly such a reader today. Likewise
/// `Caller::reported_run_identity()` builds the identity without naming
/// either. The second and third halves below therefore pin the accessor and
/// identity-type names, and the caller-context builder name, the same way,
/// with the legitimate files listed. A new decision reader — routing,
/// permission, gating, rendering priority, or anything else — fails one of
/// the halves until its file is listed with a justification, which is the
/// point: reading a self-declared claim to decide behaviour must be a
/// conscious, reviewed choice, never an accident.
#[tokio::test]
async fn reported_model_has_no_decision_reader() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    // `contribution.rs` names the literal only in a comment-only forward
    // reference ("when a writer lands, `reported_model` joins ..."): no read.
    // `mcp/registry.rs` names it only in the display slice's absence
    // assertion (`reported_model` must NOT appear in the contribution run
    // block) and its doc comment: a negative check, not a read.
    // The two standby modules name it only while constructing complete
    // `AgentRunStartedPayload` fixtures for act-cut/materialisation coverage;
    // neither reads the reported value or uses it to decide behaviour.
    let literal_allowed = [
        "act.rs",
        "conformance/rebuild.rs",
        "control.rs",
        "control_tests.rs",
        "contribution.rs",
        "mcp/registry.rs",
        "migrations.rs",
        "schema/ddl.rs",
        "standby/act_materialise.rs",
        "standby/authority_probe.rs",
        "turso_local.rs",
    ];
    // Every file allowed to name the accessor or the identity type. The
    // production read lives in `mcp/tools/intent.rs` (the response
    // confirmation); `contribution.rs` projects the client fields through the
    // in-transaction variant and `mcp/tools/event_context.rs` does the same
    // for the run page's run block — both surface the client only, never the
    // model, and never to decide anything; `mcp/registry.rs` constructs the
    // admitted identity and reads it back in tests; the rest construct the
    // default identity for admission calls or read it back in migration tests.
    let accessor_allowed = [
        "control.rs",
        "control_tests.rs",
        "contribution.rs",
        "domain_transaction/request.rs",
        "mcp/registry.rs",
        "mcp/tools/event_context.rs",
        "mcp/tools/intent.rs",
        "mcp/tools/querying.rs",
        "mcp/tools/work.rs",
        "migrations.rs",
        "query/sql.rs",
        "turso_local.rs",
    ];
    // Every file allowed to name the caller-context builder that carries the
    // admitting call's client identity into persistence. A reader spelled
    // `caller.reported_run_identity().model` inside an already-allowlisted
    // file would otherwise evade both halves above. (`control_tests.rs`
    // itself is listed because this test names what it pins.)
    let builder_allowed = [
        "control_tests.rs",
        "domain_transaction/request.rs",
        "mcp/registry.rs",
    ];
    let mut literal_files = Vec::new();
    let mut reader_files = Vec::new();
    let mut identity_files = Vec::new();
    let mut builder_files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let content = std::fs::read_to_string(&path).unwrap();
                let relative = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if content.contains("reported_model") {
                    literal_files.push(relative.clone());
                }
                if content.contains("read_agent_run_reported_identity") {
                    reader_files.push(relative.clone());
                }
                if content.contains("ReportedRunIdentity") {
                    identity_files.push(relative.clone());
                }
                if content.contains("reported_run_identity") {
                    builder_files.push(relative);
                }
            }
        }
    }
    // A rename must fail loudly instead of passing vacuously: each name is
    // asserted independently so renaming either accessor alone still fails.
    assert!(
        !literal_files.is_empty(),
        "the reported_model literal vanished from src/: the pin below would pass without enforcing anything"
    );
    assert!(
        !reader_files.is_empty(),
        "read_agent_run_reported_identity vanished from src/: the pin below would pass without enforcing anything"
    );
    assert!(
        !identity_files.is_empty(),
        "ReportedRunIdentity vanished from src/: the pin below would pass without enforcing anything"
    );
    assert!(
        !builder_files.is_empty(),
        "reported_run_identity vanished from src/: the pin below would pass without enforcing anything"
    );
    let mut literal_offenders: Vec<_> = literal_files
        .iter()
        .filter(|relative| !literal_allowed.contains(&relative.as_str()))
        .collect();
    literal_offenders.sort();
    assert!(
        literal_offenders.is_empty(),
        "new reported_model reader(s) outside the allowlist — see this test's docs: {literal_offenders:?}"
    );
    let mut reader_offenders: Vec<_> = reader_files
        .iter()
        .filter(|relative| !accessor_allowed.contains(&relative.as_str()))
        .collect();
    reader_offenders.sort();
    assert!(
        reader_offenders.is_empty(),
        "new identity-reader user(s) outside the allowlist — see this test's docs: {reader_offenders:?}"
    );
    let mut identity_offenders: Vec<_> = identity_files
        .iter()
        .filter(|relative| !accessor_allowed.contains(&relative.as_str()))
        .collect();
    identity_offenders.sort();
    assert!(
        identity_offenders.is_empty(),
        "new ReportedRunIdentity user(s) outside the allowlist — see this test's docs: {identity_offenders:?}"
    );
    let mut builder_offenders: Vec<_> = builder_files
        .iter()
        .filter(|relative| !builder_allowed.contains(&relative.as_str()))
        .collect();
    builder_offenders.sort();
    assert!(
        builder_offenders.is_empty(),
        "new reported_run_identity builder user(s) outside the allowlist — see this test's docs: {builder_offenders:?}"
    );
}

#[tokio::test]
async fn pre_change_started_v1_event_replays_with_null_reported_identity() {
    // Byte-shape of a start event as the pre-change binary wrote it: no
    // reported_* keys at all. The new binary must project it with NULL
    // identity columns rather than rejecting the replay.
    let db = create_database(":memory:").await.unwrap();
    let activity_id = uuid::Uuid::new_v4().to_string();
    let event = ControlEventRow {
        seq: 1,
        id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: format!("agent-run-start:{AGENT_RUN}"),
        event_type: "agent_run.started.v1".into(),
        schema_version: 1,
        aggregate_kind: "agent_run".into(),
        aggregate_id: activity_id.clone(),
        actor: "acct_alice".into(),
        run_key: Some(AGENT_RUN.into()),
        reason: "pre-change admission".into(),
        payload: serde_json::json!({
            "activity_id": activity_id,
            "account_id": "acct_alice",
            "started_at": NOW,
        })
        .to_string(),
        created_at: NOW.into(),
        act: None,
    };
    let mut conn = db.write_pool().acquire().await.unwrap();
    replay_control(&mut conn, std::slice::from_ref(&event))
        .await
        .unwrap();
    drop(conn);
    let identity = read_agent_run_reported_identity(&db, AGENT_RUN)
        .await
        .unwrap()
        .expect("replayed run reads back");
    assert_eq!(identity, ReportedRunIdentity::default());
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn overlong_client_identity_is_clamped_on_utf8_boundaries() {
    let db = create_database(":memory:").await.unwrap();
    let long_run = "scout-chair-b748b2";
    ensure_agent_run(
        &db,
        long_run,
        "acct_alice",
        ReportedRunIdentity {
            client_name: Some("a".repeat(300)),
            // 255 ASCII bytes plus one 2-byte `é`: 257 bytes total, so the
            // 256-byte cap falls inside the final character.
            client_version: Some(format!("{}é", "a".repeat(255))),
            model: None,
        },
    )
    .await
    .unwrap();
    let identity = read_agent_run_reported_identity(&db, long_run)
        .await
        .unwrap()
        .expect("admitted run reads back");
    let name = identity.client_name.expect("clamped name stored");
    assert_eq!(name.len(), 256);
    let version = identity.client_version.expect("clamped version stored");
    assert_eq!(version, "a".repeat(255));
    assert!(identity.model.is_none());
    db.close().await;
}

fn alpha_tab_payload(previous_event_id: Option<&str>) -> AlphaTabStatePayload {
    AlphaTabStatePayload {
        account_id: "acct_alice".into(),
        package: "agent.attention-cockpit".into(),
        version: "0.1.0".into(),
        digest: format!("sha256:{}", "a".repeat(64)),
        artifact_id: ALPHA_FIXTURE_ARTIFACT_ID.into(),
        consented_source_revision: "rev-1".into(),
        declaration_digest: "b".repeat(64),
        consented_declaration: json!({"needs": ["attention.query.v1"], "effects": []}),
        adoption: crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into(),
        previous_event_id: previous_event_id.map(str::to_owned),
    }
}

#[tokio::test]
async fn alpha_tab_install_folds_and_reapplied_event_is_a_no_op() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, ALPHA_FIXTURE_ARTIFACT_ID).await;
    let event = append_control_event(
        &db,
        command(
            "alpha-install-1",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabInstalled(alpha_tab_payload(None)),
        ),
    )
    .await
    .unwrap();
    assert_eq!(event.event_type, "alpha_tab.installed");
    // Retry with the identical command converges on the first event.
    let retry = append_control_event(
        &db,
        command(
            "alpha-install-1",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabInstalled(alpha_tab_payload(None)),
        ),
    )
    .await
    .unwrap();
    assert_eq!(retry.id, event.id);
    let row: (String, String) = sqlx::query_as(
        "SELECT status, event_id FROM alpha_tab_installs WHERE account_id='acct_alice' AND package='agent.attention-cockpit'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(row, ("installed".to_string(), event.id));
    // Reusing the key for different intent fails visibly.
    let mut other = alpha_tab_payload(None);
    other.version = "0.2.0".into();
    let collision = append_control_event(
        &db,
        command(
            "alpha-install-1",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabInstalled(other),
        ),
    )
    .await;
    assert!(collision.is_err());
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_transitions_require_matching_cas_token() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, ALPHA_FIXTURE_ARTIFACT_ID).await;
    let installed = append_control_event(
        &db,
        command(
            "alpha-install-1",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabInstalled(alpha_tab_payload(None)),
        ),
    )
    .await
    .unwrap();
    // Wrong token: the projector's require_one guard errors rather than
    // drifting the row.
    let mut wrong = alpha_tab_payload(Some("not-the-token"));
    wrong.previous_event_id = Some("not-the-token".into());
    let failed = append_control_event(
        &db,
        command(
            "alpha-disable-1",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabDisabled(wrong),
        ),
    )
    .await;
    assert!(failed.is_err());
    let disabled = append_control_event(
        &db,
        command(
            "alpha-disable-1",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabDisabled(alpha_tab_payload(Some(&installed.id))),
        ),
    )
    .await
    .unwrap();
    let status: String = sqlx::query_scalar(
        "SELECT status FROM alpha_tab_installs WHERE account_id='acct_alice' AND package='agent.attention-cockpit'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(status, "disabled");
    // Double disable over the spent token fails.
    let again = append_control_event(
        &db,
        command(
            "alpha-disable-2",
            &alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
            ControlEventPayload::AlphaTabDisabled(alpha_tab_payload(Some(&installed.id))),
        ),
    )
    .await;
    assert!(again.is_err());
    let _ = disabled;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_validation_rejects_malformed_pins() {
    let db = create_database(":memory:").await.unwrap();
    let aggregate = alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit");
    // Bad digest scheme.
    let mut bad_digest = alpha_tab_payload(None);
    bad_digest.digest = "md5:abc".into();
    assert!(append_control_event(
        &db,
        command(
            "alpha-bad-1",
            &aggregate,
            ControlEventPayload::AlphaTabInstalled(bad_digest)
        ),
    )
    .await
    .is_err());
    // Non-object declaration.
    let mut bad_declaration = alpha_tab_payload(None);
    bad_declaration.consented_declaration = json!(["needs"]);
    assert!(append_control_event(
        &db,
        command(
            "alpha-bad-2",
            &aggregate,
            ControlEventPayload::AlphaTabInstalled(bad_declaration)
        ),
    )
    .await
    .is_err());
    // Adoption vocabulary is closed: anything but caller_asserted is
    // refused rather than stored under a stronger claim.
    let mut bad_adoption = alpha_tab_payload(None);
    bad_adoption.adoption = "verified_gesture".into();
    assert!(append_control_event(
        &db,
        command(
            "alpha-bad-3",
            &aggregate,
            ControlEventPayload::AlphaTabInstalled(bad_adoption)
        ),
    )
    .await
    .is_err());
    // Aggregate id must match the payload identity (punctuation cannot alias).
    assert!(append_control_event(
        &db,
        command(
            "alpha-bad-4",
            "v1:11:acct_alice:25:agent.attention-cockpit ",
            ControlEventPayload::AlphaTabInstalled(alpha_tab_payload(None)),
        ),
    )
    .await
    .is_err());
    db.close().await;
}

fn alpha_tab_adopt_payload(previous_event_id: &str) -> AlphaTabAdoptPayload {
    let installed = alpha_tab_payload(None);
    AlphaTabAdoptPayload {
        account_id: installed.account_id,
        package: installed.package,
        version: installed.version,
        digest: installed.digest,
        artifact_id: installed.artifact_id,
        consented_source_revision: installed.consented_source_revision,
        declaration_digest: installed.declaration_digest,
        consented_declaration: installed.consented_declaration,
        adoption: ALPHA_TAB_ADOPTION_VERIFIED.into(),
        previous_event_id: previous_event_id.into(),
        receipt_id: "preview_testreceipt01".into(),
        preview_session: "sess_test01".into(),
    }
}

#[tokio::test]
async fn alpha_tab_adopt_folds_verified_and_replay_is_a_no_op() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, ALPHA_FIXTURE_ARTIFACT_ID).await;
    let aggregate = alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit");
    let installed = append_control_event(
        &db,
        command(
            "alpha-install-1",
            &aggregate,
            ControlEventPayload::AlphaTabInstalled(alpha_tab_payload(None)),
        ),
    )
    .await
    .unwrap();
    let adopted = append_control_event(
        &db,
        command(
            "alpha-adopt-1",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(alpha_tab_adopt_payload(&installed.id)),
        ),
    )
    .await
    .unwrap();
    assert_eq!(adopted.event_type, "alpha_tab.adopted");
    let row: (String, String, String) = sqlx::query_as(
        "SELECT status, adoption, event_id FROM alpha_tab_installs WHERE account_id='acct_alice' AND package='agent.attention-cockpit'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "installed".to_string(),
            ALPHA_TAB_ADOPTION_VERIFIED.to_string(),
            adopted.id.clone()
        )
    );
    // Replaying the adopted event is a no-op: the application marker makes
    // the second projection converge without touching the row.
    let mut conn = db.write_pool().acquire().await.unwrap();
    let events = crate::control::read_all_control_events(&mut conn)
        .await
        .unwrap();
    let adopted_row = events
        .iter()
        .find(|event| event.id == adopted.id)
        .expect("adopted event reads back")
        .clone();
    drop(conn);
    let mut conn = db.write_pool().acquire().await.unwrap();
    replay_control(&mut conn, std::slice::from_ref(&adopted_row))
        .await
        .unwrap();
    drop(conn);
    let replayed: (String, String) = sqlx::query_as(
        "SELECT adoption, event_id FROM alpha_tab_installs WHERE account_id='acct_alice' AND package='agent.attention-cockpit'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        replayed,
        (ALPHA_TAB_ADOPTION_VERIFIED.to_string(), adopted.id.clone())
    );
    // Same-key retry with the identical command converges on the first
    // event, and the rebuilt projection still matches the live one.
    let retry = append_control_event(
        &db,
        command(
            "alpha-adopt-1",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(alpha_tab_adopt_payload(&installed.id)),
        ),
    )
    .await
    .unwrap();
    assert_eq!(retry.id, adopted.id);
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_adopt_projector_is_fail_closed() {
    let db = create_database(":memory:").await.unwrap();
    record(&db, ALPHA_FIXTURE_ARTIFACT_ID).await;
    let aggregate = alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit");
    // No install to bind: the projector's require_one guard errors rather
    // than creating a row.
    assert!(append_control_event(
        &db,
        command(
            "alpha-adopt-orphan",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(alpha_tab_adopt_payload("evt_genesis")),
        ),
    )
    .await
    .is_err());
    let installed = append_control_event(
        &db,
        command(
            "alpha-install-1",
            &aggregate,
            ControlEventPayload::AlphaTabInstalled(alpha_tab_payload(None)),
        ),
    )
    .await
    .unwrap();
    // Stale CAS token: errors rather than drifting the row.
    assert!(append_control_event(
        &db,
        command(
            "alpha-adopt-stale",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(alpha_tab_adopt_payload("not-the-token")),
        ),
    )
    .await
    .is_err());
    // Pin drift between the event and the stored row: the projector only
    // flips when every pin column still matches.
    let mut drifted = alpha_tab_adopt_payload(&installed.id);
    drifted.version = "9.9.9".into();
    assert!(append_control_event(
        &db,
        command(
            "alpha-adopt-drift",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(drifted)
        ),
    )
    .await
    .is_err());
    // A disabled install cannot adopt: restore first.
    let disabled = append_control_event(
        &db,
        command(
            "alpha-disable-1",
            &aggregate,
            ControlEventPayload::AlphaTabDisabled(alpha_tab_payload(Some(&installed.id))),
        ),
    )
    .await
    .unwrap();
    assert!(append_control_event(
        &db,
        command(
            "alpha-adopt-disabled",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(alpha_tab_adopt_payload(&disabled.id)),
        ),
    )
    .await
    .is_err());
    // Closed vocabulary both ways: an adopted event carrying
    // caller_asserted is a contradiction, and a direct install carrying the
    // verified value is a forgery — both rejected on write.
    let mut asserted_adopt = alpha_tab_adopt_payload(&disabled.id);
    asserted_adopt.adoption = crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
    assert!(append_control_event(
        &db,
        command(
            "alpha-adopt-asserted",
            &aggregate,
            ControlEventPayload::AlphaTabAdopted(asserted_adopt)
        ),
    )
    .await
    .is_err());
    let mut forged_install = alpha_tab_payload(None);
    forged_install.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    assert!(append_control_event(
        &db,
        command(
            "alpha-install-forged",
            &aggregate,
            ControlEventPayload::AlphaTabInstalled(forged_install)
        ),
    )
    .await
    .is_err());
    // Nothing above moved the row: still the disabled caller-asserted
    // install over the disable event.
    let row: (String, String, String) = sqlx::query_as(
        "SELECT status, adoption, event_id FROM alpha_tab_installs WHERE account_id='acct_alice' AND package='agent.attention-cockpit'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "disabled".to_string(),
            crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.to_string(),
            disabled.id
        )
    );
    db.close().await;
}
