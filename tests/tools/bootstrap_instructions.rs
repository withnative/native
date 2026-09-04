use crate::common;
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};

use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::Digest;

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> Value {
    registry
        .call(db.clone(), caller, tool, arguments)
        .await
        .unwrap()
}

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic. Programme,
// binding and idempotency keys are not record ids and stay readable. Sources
// inserted straight into `records` by raw SQL bypass admission and are left
// alone.
/// `quickstart-criteria`
const QUICKSTART_CRITERIA: &str = "b0075000-0000-4000-8000-000000000001";
/// `workspace-source`
const WORKSPACE_SOURCE: &str = "b0075000-0000-4000-8000-000000000002";
/// `onboarding-source`
const ONBOARDING_SOURCE: &str = "b0075000-0000-4000-8000-000000000003";
/// `criteria-source`
const CRITERIA_SOURCE: &str = "b0075000-0000-4000-8000-000000000004";
/// `member-source`
const MEMBER_SOURCE: &str = "b0075000-0000-4000-8000-000000000005";
/// `valid-source`
const VALID_SOURCE: &str = "b0075000-0000-4000-8000-000000000006";
/// `broken-source`
const BROKEN_SOURCE: &str = "b0075000-0000-4000-8000-000000000007";
/// `stale-criteria`
const STALE_CRITERIA: &str = "b0075000-0000-4000-8000-000000000008";

async fn document(registry: &ToolRegistry, db: &Db, id: &str, body: &str) {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({
            "id":id, "type":"Document", "kind":"note", "name":id,
            "body":body, "reason":"bootstrap instruction fixture"
        }),
    )
    .await;
}

#[tokio::test]
async fn quickstart_route_value_completion_and_subsequent_bootstrap_do_not_replay() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    document(
        &registry,
        &db,
        QUICKSTART_CRITERIA,
        "The member confirms that the selected route delivered useful value.",
    )
    .await;
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_onboarding",
        json!({
            "action":"create_programme", "programme_id":"native:onboarding-member-joined",
            "trigger_key":"on_member_joined", "position":100,
            "idempotency_key":"quickstart:programme", "reason":"create QuickStart journey fixture"
        }),
    )
    .await;
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_onboarding",
        json!({
            "action":"add_source", "programme_id":"native:onboarding-member-joined",
            "source_record_id":QUICKSTART_CRITERIA, "source_role":"completion_criteria",
            "position":100, "idempotency_key":"quickstart:criteria",
            "reason":"declare QuickStart completion criteria"
        }),
    )
    .await;
    sqlx::query("INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) VALUES('acct:quickstart','native:onboarding-member-joined',1,'pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        .execute(&common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let member = Caller::authenticated("acct:quickstart");
    let launcher = call(&registry, &db, member.clone(), "quickstart", json!({})).await;
    assert_eq!(launcher["contract"]["id"], "native.quickstart.v1");
    let initial = call(&registry, &db, member.clone(), "bootstrap", json!({})).await;
    assert_eq!(initial["pending_obligations"][0]["progress_state"], "new");
    let initial_text = render::render("bootstrap", &initial).unwrap();
    assert!(initial_text.contains("Offer three useful ways to begin"));
    let run_key = initial["run"]["run_key"].as_str().unwrap();

    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
            "phase":"route_selected", "evidence":{"route_id":"practical_workflow"},
            "run_key":run_key, "idempotency_key":"quickstart:route",
            "reason":"member selected the practical workflow"
        }),
    )
    .await;
    let routed = call(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":run_key}),
    )
    .await;
    assert_eq!(
        routed["pending_obligations"][0]["progress_phase"],
        "route_selected"
    );
    assert_eq!(
        routed["pending_obligations"][0]["selected_route_id"],
        "practical_workflow"
    );
    let routed_text = render::render("bootstrap", &routed).unwrap();
    assert!(routed_text.contains("Continue from the recorded progress"));
    assert!(!routed_text.contains("Offer three useful ways to begin"));

    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
            "phase":"value_delivered", "evidence":{"basis":"user_confirmed"},
            "run_key":run_key, "idempotency_key":"quickstart:value",
            "reason":"member confirmed the workflow delivered value"
        }),
    )
    .await;
    let delivered = call(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":run_key}),
    )
    .await;
    assert_eq!(
        delivered["pending_obligations"][0]["progress_phase"],
        "value_delivered"
    );

    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"resolve_obligation", "programme_id":"native:onboarding-member-joined", "generation":1,
            "resolution":"completed", "evidence":{"basis":"member_confirmed_complete"},
            "run_key":run_key, "idempotency_key":"quickstart:complete",
            "reason":"member confirmed the QuickStart journey was complete"
        }),
    )
    .await;

    let second_launcher = call(&registry, &db, member.clone(), "quickstart", json!({})).await;
    assert_eq!(
        second_launcher, launcher,
        "QuickStart remains build-owned and state-free"
    );
    let terminal = call(&registry, &db, member, "bootstrap", json!({})).await;
    assert!(terminal["pending_obligations"]
        .as_array()
        .unwrap()
        .is_empty());
    let terminal_text = render::render("bootstrap", &terminal).unwrap();
    assert!(!terminal_text.contains("Offer three useful ways to begin"));
    assert!(!terminal_text.contains("Continue from the recorded progress"));

    let phases: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.phase') FROM control_events WHERE type='member_obligation.progressed' AND json_extract(payload, '$.account_id')='acct:quickstart' AND json_extract(payload, '$.programme_id')='native:onboarding-member-joined' ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(phases, vec!["route_selected", "value_delivered"]);
    let state: String = sqlx::query_scalar(
        "SELECT state FROM member_obligations WHERE account_id='acct:quickstart' AND programme_id='native:onboarding-member-joined'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(state, "completed");
}

#[tokio::test]
async fn bootstrap_resolves_ordered_caller_context_without_consuming_obligations() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    document(&registry, &db, WORKSPACE_SOURCE, "Workspace says red.").await;
    document(&registry, &db, ONBOARDING_SOURCE, "Onboarding says blue.").await;
    document(
        &registry,
        &db,
        CRITERIA_SOURCE,
        "Confirm the member understands.",
    )
    .await;
    document(
        &registry,
        &db,
        MEMBER_SOURCE,
        "Member prefers concise replies — café.",
    )
    .await;

    call(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        json!({
            "action":"create_binding", "scope":"workspace", "binding_id":"workspace-binding",
            "source_record_id":WORKSPACE_SOURCE, "position":100,
            "idempotency_key":"bootstrap:workspace", "reason":"bind workspace guidance"
        }),
    )
    .await;
    let member = Caller::authenticated("acct:member");
    call(
        &registry,
        &db,
        member.clone(),
        "manage_instructions",
        json!({
            "action":"create_binding", "scope":"member", "binding_id":"member-binding",
            "source_record_id":MEMBER_SOURCE, "position":300,
            "idempotency_key":"bootstrap:member", "reason":"bind member guidance"
        }),
    )
    .await;
    call(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"create_programme", "programme_id":"joined", "trigger_key":"on_member_joined",
        "position":200, "idempotency_key":"bootstrap:programme", "reason":"create onboarding fixture"
    })).await;
    for (source, role, position) in [
        (ONBOARDING_SOURCE, "guidance", 100),
        (CRITERIA_SOURCE, "completion_criteria", 200),
    ] {
        call(&registry, &db, Caller::local(), "manage_onboarding", json!({
            "action":"add_source", "programme_id":"joined", "source_record_id":source,
            "source_role":role, "position":position,
            "idempotency_key":format!("bootstrap:add:{source}"), "reason":"add onboarding source"
        })).await;
    }
    sqlx::query("INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) VALUES('acct:member','joined',1,'pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let first = call(&registry, &db, member.clone(), "bootstrap", json!({})).await;
    let second = call(&registry, &db, member.clone(), "bootstrap", json!({})).await;
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    for duplicate_index in ["guides", "guide_topics", "guide_index"] {
        assert!(
            first.get(duplicate_index).is_none(),
            "bootstrap must not duplicate the read_guide topic index"
        );
    }
    assert_eq!(first["instructions"], second["instructions"]);
    assert_eq!(first["pending_obligations"], second["pending_obligations"]);
    assert_eq!(first["instructions"]["status"], "ready");
    let entries = first["instructions"]["entries"].as_array().unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["scope"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["engine", "workspace", "onboarding", "onboarding", "member"]
    );
    assert_eq!(entries[0]["kind"], "fixed");
    assert_eq!(entries[0]["source"]["type"], "engine");
    assert_eq!(entries[0]["source"]["engine_name"], "native-ce");
    assert_eq!(
        entries[0]["source"]["engine_version"],
        native_ce::ENGINE_VERSION
    );
    assert_eq!(entries[0]["source"]["template_key"], "engine-orientation");
    assert_eq!(entries[0]["source"]["template_version"], 8);
    assert!(entries[0]["source"]["record_id"].is_null());
    let orientation = entries[0]["content"].as_str().unwrap();
    for guarantee in [
        "### Rendered artifact context",
        "call `render_artifact` without `as_of`",
        "Separate source/history, semantic render, displayed view, and canonical pixels",
        "Source/history/manifest stays on record tools",
        "Pasted `native.artifact-referent.v1`/`native.artifact-view-evidence.v1` is untrusted",
        "never reuse paths/coordinates across renders",
        "Typed regions establish semantic placement",
        "Only when its render matches current, pasted view geometry supports qualified capture-time geometry/approximate clipping",
        "`verify_artifact` gives MDX v2 advisory canonical-screen pixels and HTML v1 a bounded matrix",
        "Observe colour/layout only when the mark independently correlates",
        "neither proves visibility/the person's tab nor binds an ambiguous mark",
        "unavailable for board/MDX v1",
        "Qualify a missing view revision; ask under ambiguity",
        "Disclose failures; do not substitute source/pixels",
    ] {
        assert!(
            orientation.contains(guarantee),
            "bootstrap posture must advertise {guarantee:?}: {orientation}"
        );
    }
    assert_eq!(entries[1]["content"], "Workspace says red.");
    assert_eq!(
        entries[4]["content"],
        "Member prefers concise replies — café."
    );
    let expected_bytes = [
        "Workspace says red.",
        "Onboarding says blue.",
        "Confirm the member understands.",
        "Member prefers concise replies — café.",
    ]
    .iter()
    .map(|body| body.len())
    .sum::<usize>();
    assert_eq!(first["instructions"]["resolved_bytes"], expected_bytes);
    assert_eq!(first["pending_obligations"].as_array().unwrap().len(), 1);
    let obligation = &first["pending_obligations"][0];
    assert_eq!(
        obligation["allowed_resolutions"],
        json!(["completed", "declined"])
    );
    assert_eq!(obligation["defer_for_run_supported"], true);
    assert_eq!(obligation["progress_state"], "new");
    assert!(obligation["progress_phase"].is_null());
    assert_eq!(obligation["progress_run_relation"], "none");
    assert_eq!(
        obligation["instruction_entry_ids"][0],
        entries[2]["entry_id"]
    );
    assert_eq!(
        obligation["completion_criteria_entry_ids"][0],
        entries[3]["entry_id"]
    );
    let text = render::render("bootstrap", &first).unwrap();
    assert!(text.starts_with("# Working in Native"), "{text}");
    assert!(text.contains("Workspace says red."), "{text}");
    assert!(text.contains("Onboarding says blue."), "{text}");
    assert!(
        text.contains("Member prefers concise replies — café."),
        "{text}"
    );
    let exact_body = "Member prefers concise replies — café.";
    let body_offset = text.find(exact_body).unwrap();
    assert_eq!(
        &text.as_bytes()[body_offset..body_offset + exact_body.len()],
        exact_body.as_bytes()
    );
    assert!(text[body_offset + exact_body.len()..].starts_with("\n--- end instruction body ---"));
    assert_eq!(
        entries[4]["source"]["body_digest"],
        hex::encode(sha2::Sha256::digest(exact_body.as_bytes()))
    );
    assert!(text.contains("not an automatic priority"), "{text}");
    assert!(!text.contains("## First-use onboarding"), "{text}");

    let held = first["run"]["run_key"].as_str().unwrap();
    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"joined", "generation":1,
            "phase":"anchor_established", "evidence":{"basis":"user_stated"},
            "idempotency_key":"bootstrap:progress:anchor", "reason":"member stated an aim",
            "run_key":held
        }),
    )
    .await;
    let in_progress = call(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":held}),
    )
    .await;
    assert_eq!(
        in_progress["pending_obligations"][0]["progress_state"],
        "in_progress"
    );
    assert_eq!(
        in_progress["pending_obligations"][0]["progress_phase"],
        "anchor_established"
    );
    assert_eq!(
        in_progress["pending_obligations"][0]["progress_run_relation"],
        "current_run"
    );
    let in_progress_text = render::render("bootstrap", &in_progress).unwrap();
    assert!(!in_progress_text.contains("## First-use onboarding"));
    let returning = call(&registry, &db, member.clone(), "bootstrap", json!({})).await;
    assert_eq!(
        returning["pending_obligations"][0]["progress_run_relation"],
        "returning"
    );
    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"joined", "generation":1,
            "phase":"deferred", "evidence":{"basis":"explicit_member_request"},
            "explicit_member_intent":true, "resume_after":"2026-09-01T00:00:00Z",
            "idempotency_key":"bootstrap:progress:defer", "reason":"member explicitly deferred",
            "run_key":held
        }),
    )
    .await;
    let deferred = call(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":held}),
    )
    .await;
    assert_eq!(
        deferred["pending_obligations"][0]["progress_state"],
        "deferred"
    );
    assert_eq!(
        deferred["pending_obligations"][0]["resume_after"],
        "2026-09-01T00:00:00Z"
    );
    let deferred_text = render::render("bootstrap", &deferred).unwrap();
    assert!(!deferred_text.contains("## First-use onboarding"));
    let resumed_run = "scout-chair-c748b2";
    let denied_resume = registry
        .call(
            db.clone(),
            member.clone(),
            "manage_onboarding",
            json!({
                "action":"record_progress", "programme_id":"joined", "generation":1,
                "phase":"anchor_established", "evidence":{"basis":"user_stated"},
                "run_key":resumed_run,
                "idempotency_key":"bootstrap:progress:resume-denied", "reason":"resume requires explicit confirmation"
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        denied_resume.contains("explicit member intent"),
        "{denied_resume}"
    );
    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"joined", "generation":1,
            "phase":"anchor_established", "evidence":{"basis":"user_confirmed"},
            "explicit_member_intent":true, "run_key":resumed_run,
            "idempotency_key":"bootstrap:progress:resume", "reason":"member explicitly resumed"
        }),
    )
    .await;
    let resumed = call(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":resumed_run}),
    )
    .await;
    assert_eq!(
        resumed["pending_obligations"][0]["progress_state"],
        "in_progress"
    );
    assert_eq!(
        resumed["pending_obligations"][0]["progress_run_relation"],
        "current_run"
    );
    assert!(resumed["pending_obligations"][0]["resume_after"].is_null());

    let other = call(
        &registry,
        &db,
        Caller::authenticated("acct:other"),
        "bootstrap",
        json!({}),
    )
    .await;
    assert_eq!(
        other["instructions"]["entries"].as_array().unwrap().len(),
        2
    );
    assert!(other["pending_obligations"].as_array().unwrap().is_empty());

    let listed = call(
        &registry,
        &db,
        Caller::local(),
        "manage_onboarding",
        json!({"action":"list_programmes"}),
    )
    .await;
    assert_eq!(
        listed["programmes"][0]["sources"][0]["source_record_id"],
        ONBOARDING_SOURCE
    );
    assert_eq!(
        listed["programmes"][0]["sources"][1]["source_role"],
        "completion_criteria"
    );

    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"resolve_obligation", "programme_id":"joined", "generation":1,
            "resolution":"completed", "evidence":{"criteria":"confirmed"},
            "idempotency_key":"bootstrap:complete", "reason":"member completed orientation"
        }),
    )
    .await;
    let completed = call(&registry, &db, member.clone(), "bootstrap", json!({})).await;
    assert!(completed["pending_obligations"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        completed["instructions"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let completed_text = render::render("bootstrap", &completed).unwrap();
    assert!(!completed_text.contains("Record that consented preview"));
    assert!(!completed_text.contains("Offer three useful ways to begin"));
    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"reopen_obligation", "programme_id":"joined", "generation":1,
            "evidence":{"intent":"reopen"}, "explicit_member_intent":true,
            "idempotency_key":"bootstrap:reopen-complete", "reason":"member reopened orientation"
        }),
    )
    .await;
    let reopened = call(&registry, &db, member.clone(), "bootstrap", json!({})).await;
    assert_eq!(reopened["pending_obligations"].as_array().unwrap().len(), 1);
    call(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"resolve_obligation", "programme_id":"joined", "generation":1,
            "resolution":"declined", "evidence":{"intent":"decline"}, "explicit_member_intent":true,
            "idempotency_key":"bootstrap:decline", "reason":"member declined orientation"
        }),
    )
    .await;
    let declined = call(&registry, &db, member, "bootstrap", json!({})).await;
    assert!(declined["pending_obligations"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        declined["instructions"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let declined_text = render::render("bootstrap", &declined).unwrap();
    assert!(!declined_text.contains("Record that consented preview"));
    assert!(!declined_text.contains("Offer three useful ways to begin"));
}

#[tokio::test]
async fn bootstrap_returns_no_partial_authoritative_stack_when_active_state_is_invalid() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    document(&registry, &db, VALID_SOURCE, "valid").await;
    document(&registry, &db, BROKEN_SOURCE, "broken").await;
    for (id, source, position) in [
        ("valid-binding", VALID_SOURCE, 100),
        ("broken-binding", BROKEN_SOURCE, 200),
    ] {
        call(&registry, &db, Caller::local(), "manage_instructions", json!({
            "action":"create_binding", "scope":"workspace", "binding_id":id,
            "source_record_id":source, "position":position,
            "idempotency_key":format!("bootstrap:{id}"), "reason":"create invalid bootstrap fixture"
        })).await;
    }
    sqlx::query(&format!(
        "UPDATE records SET deleted_at='2026-01-01T00:00:00Z' WHERE id='{BROKEN_SOURCE}'"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let payload = call(&registry, &db, Caller::local(), "bootstrap", json!({})).await;
    assert_eq!(payload["instructions"]["status"], "invalid");
    assert_eq!(payload["contract"]["version"], "native.bootstrap.v3");
    assert!(payload["orientation"]["content"]
        .as_str()
        .unwrap()
        .starts_with("# Working in Native"));
    assert!(payload["instructions"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        payload["instructions"]["diagnostics"][0]["source_record_id"],
        Value::Null
    );
    assert!(payload["instructions"]["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("Repair or remove"));

    sqlx::query(&format!(
        "UPDATE records SET deleted_at=NULL,body=x'FF' WHERE id='{BROKEN_SOURCE}'"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let corrupt = call(&registry, &db, Caller::local(), "bootstrap", json!({})).await;
    assert_eq!(corrupt["instructions"]["status"], "invalid");
    assert_eq!(
        corrupt["instructions"]["diagnostics"][0]["code"],
        "instruction_source_corrupt"
    );

    let maximum_valid_body = "a".repeat(32 * 1024 - "valid".len());
    sqlx::query(&format!(
        "UPDATE records SET body=? WHERE id='{BROKEN_SOURCE}'"
    ))
    .bind(maximum_valid_body)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let maximum_valid = call(&registry, &db, Caller::local(), "bootstrap", json!({})).await;
    assert_eq!(maximum_valid["instructions"]["status"], "ready");
    assert_eq!(maximum_valid["instructions"]["resolved_bytes"], 32 * 1024);
    assert_eq!(
        maximum_valid["contract"]["bounds_bytes"]["total"],
        native_ce::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES
    );
    let bounds = &maximum_valid["contract"]["bounds_bytes"];
    for component in [
        "contract",
        "orientation",
        "footing",
        "current_world",
        "intentful_sessions",
        "next_steps",
        "session",
        "compatibility",
        "diagnostics",
        "tool_exposure",
        "json_envelope",
        "instruction_context",
    ] {
        assert!(
            bounds[component].as_u64().is_some(),
            "missing declared {component} bound"
        );
    }
    let components = &maximum_valid["diagnostics"]["component_bytes"];
    for component in [
        "contract",
        "orientation",
        "footing",
        "current_world",
        "intentful_sessions",
        "next_steps",
        "session",
        "compatibility",
        "json_envelope",
        "instruction_context",
    ] {
        assert!(
            components[component].as_u64().unwrap() <= bounds[component].as_u64().unwrap(),
            "measured {component} exceeds its declared bound"
        );
    }
    use native_ce::mcp::tools::orientation as bootstrap_bounds;
    assert_eq!(
        bootstrap_bounds::MAX_BOOTSTRAP_TOTAL_BYTES,
        bootstrap_bounds::MAX_BOOTSTRAP_ORIENTATION_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_FOOTING_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_CURRENT_WORLD_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_INTENTFUL_SESSIONS_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_NEXT_STEPS_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_SESSION_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_COMPATIBILITY_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_CONTRACT_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_DIAGNOSTICS_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES
            + bootstrap_bounds::MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_BYTES
    );
    assert!(
        serde_json::to_vec(&maximum_valid).unwrap().len()
            <= native_ce::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES
    );
    assert!(
        !maximum_valid["instructions"]["entries"][0]["content"]
            .as_str()
            .unwrap()
            .is_empty(),
        "the fixed engine body is present but excluded from resolved_bytes"
    );

    sqlx::query(&format!(
        "UPDATE records SET body=? WHERE id='{BROKEN_SOURCE}'"
    ))
    .bind("é".repeat(16_385))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let oversize = call(&registry, &db, Caller::local(), "bootstrap", json!({})).await;
    assert_eq!(oversize["instructions"]["status"], "invalid");
    assert_eq!(
        oversize["instructions"]["diagnostics"][0]["code"],
        "instruction_budget_exceeded"
    );
    assert!(oversize["instructions"]["resolved_bytes"].as_u64().unwrap() > 32 * 1024);

    sqlx::query(&format!("UPDATE records SET body='private',policy_anchor_id='{BROKEN_SOURCE}' WHERE id='{BROKEN_SOURCE}'"))
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO record_policies(record_id) VALUES('{BROKEN_SOURCE}')"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(&format!("INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES('{BROKEN_SOURCE}','account','local','allow','manage')"))
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    let unauthorized = call(
        &registry,
        &db,
        Caller::authenticated("acct:outsider"),
        "bootstrap",
        json!({}),
    )
    .await;
    assert_eq!(unauthorized["instructions"]["status"], "invalid");
    assert_eq!(
        unauthorized["instructions"]["diagnostics"][0]["code"],
        "instruction_source_unreadable"
    );
    assert_eq!(
        unauthorized["instructions"]["diagnostics"][0]["source_record_id"],
        Value::Null
    );
    let rendered = render::render("bootstrap", &unauthorized).unwrap();
    assert!(rendered.starts_with("# Working in Native"), "{rendered}");
    assert!(rendered.contains("withheld partial guidance"));
    assert!(rendered.contains("manage_instructions"));
    assert!(!rendered.contains(BROKEN_SOURCE), "{rendered}");
}

#[tokio::test]
async fn bootstrap_fails_closed_when_tiny_sources_exceed_the_metadata_count_bound() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    for index in 0..=native_ce::MAX_BOOTSTRAP_INSTRUCTION_ENTRIES {
        let source_id = format!("bounded-source-{index}");
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,body,home_id,policy_anchor_id) \
             VALUES(?, 'Document', 'note', ?, 'x', 'native:unfiled', 'native:root')",
        )
        .bind(&source_id)
        .bind(&source_id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO instruction_bindings(id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at) \
             VALUES(?, 'database', 'native:database', ?, ?, 1, 'local', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(format!("bounded-binding-{index}"))
        .bind(source_id)
        .bind(index as i64)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }

    let payload = call(&registry, &db, Caller::local(), "bootstrap", json!({})).await;
    assert_eq!(payload["instructions"]["status"], "invalid");
    assert_eq!(
        payload["instructions"]["diagnostics"][0]["code"],
        "instruction_entry_count_exceeded"
    );
    assert!(payload["instructions"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(payload["pending_obligations"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        serde_json::to_vec(&payload).unwrap().len()
            < native_ce::MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES
    );
}

#[tokio::test]
async fn bootstrap_fails_closed_when_one_source_exceeds_the_serialized_metadata_bound() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    sqlx::query(
        "INSERT INTO records(id,type,kind,name,body,home_id,policy_anchor_id) \
         VALUES('metadata-heavy-source','Document','note',?,'x','native:unfiled','native:root')",
    )
    .bind("m".repeat(native_ce::MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO instruction_bindings(id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at) \
         VALUES('metadata-heavy-binding','database','native:database','metadata-heavy-source',1,1,'local','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let payload = call(&registry, &db, Caller::local(), "bootstrap", json!({})).await;
    assert_eq!(payload["instructions"]["status"], "invalid");
    assert_eq!(
        payload["instructions"]["diagnostics"][0]["code"],
        "instruction_metadata_budget_exceeded"
    );
    assert!(payload["instructions"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(serde_json::to_vec(&payload).unwrap().len() < 16 * 1024);
}

#[tokio::test]
async fn bootstrap_bounds_many_minimal_pending_programmes_without_partial_metadata() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    for index in 0..=native_ce::MAX_BOOTSTRAP_PENDING_OBLIGATIONS {
        let programme_id = format!("bounded-programme-{index}");
        sqlx::query(
            "INSERT INTO onboarding_programmes(id,trigger_key,generation,position,enabled,created_by,created_at,updated_at) \
             VALUES(?, 'on_member_joined', 1, ?, 1, 'local', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(&programme_id)
        .bind(index as i64)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) \
             VALUES('acct:bounded', ?, 1, 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(programme_id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }

    let payload = call(
        &registry,
        &db,
        Caller::authenticated("acct:bounded"),
        "bootstrap",
        json!({}),
    )
    .await;
    assert_eq!(payload["instructions"]["status"], "invalid");
    assert_eq!(
        payload["instructions"]["diagnostics"][0]["code"],
        "pending_obligation_count_exceeded"
    );
    assert!(payload["instructions"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(payload["pending_obligations"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn bootstrap_rejects_stale_pending_generation_without_partial_entries() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"create_programme", "programme_id":"stale-generation",
        "trigger_key":"on_member_joined", "position":100,
        "idempotency_key":"bootstrap:stale-programme", "reason":"create stale generation fixture"
    })).await;
    document(&registry, &db, STALE_CRITERIA, "Explicit criteria").await;
    call(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"add_source", "programme_id":"stale-generation", "source_record_id":STALE_CRITERIA,
        "source_role":"completion_criteria", "position":100,
        "idempotency_key":"bootstrap:stale-criteria", "reason":"add criteria fixture"
    })).await;
    sqlx::query("INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) VALUES('acct:member','stale-generation',1,'pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    sqlx::query("UPDATE onboarding_programmes SET generation=2 WHERE id='stale-generation'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let payload = call(
        &registry,
        &db,
        Caller::authenticated("acct:member"),
        "bootstrap",
        json!({}),
    )
    .await;
    assert_eq!(payload["instructions"]["status"], "invalid");
    assert_eq!(
        payload["instructions"]["diagnostics"][0]["code"],
        "pending_obligation_generation_mismatch"
    );
    assert!(payload["instructions"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());

    sqlx::query("UPDATE onboarding_programmes SET generation=1 WHERE id='stale-generation'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query(&format!(
        "UPDATE records SET body=NULL WHERE id='{STALE_CRITERIA}'"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let empty_criteria = call(
        &registry,
        &db,
        Caller::authenticated("acct:member"),
        "bootstrap",
        json!({}),
    )
    .await;
    assert_eq!(empty_criteria["instructions"]["status"], "invalid");
    assert_eq!(
        empty_criteria["instructions"]["diagnostics"][0]["code"],
        "completion_criteria_empty"
    );
    assert!(empty_criteria["instructions"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
}
