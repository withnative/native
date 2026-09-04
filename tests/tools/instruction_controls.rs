use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they are named
// after. Hardcoded, never generated, so assertions stay deterministic.
// Programme, binding and idempotency keys are not record ids and keep their
// readable forms.
/// `too-large`
const TOO_LARGE: &str = "1c700000-0000-4000-8000-000000000001";
/// `bound-source`
const BOUND_SOURCE: &str = "1c700000-0000-4000-8000-000000000002";
/// `member-source`
const MEMBER_SOURCE: &str = "1c700000-0000-4000-8000-000000000003";
/// `dangling-source`
const DANGLING_SOURCE: &str = "1c700000-0000-4000-8000-000000000004";
/// `safe-source`
const SAFE_SOURCE: &str = "1c700000-0000-4000-8000-000000000005";
/// `future-oversize`
const FUTURE_OVERSIZE: &str = "1c700000-0000-4000-8000-000000000006";
/// `retry-source`
const RETRY_SOURCE: &str = "1c700000-0000-4000-8000-000000000007";
/// `criteria-source`
const CRITERIA_SOURCE: &str = "1c700000-0000-4000-8000-000000000008";
/// `starting-context-completion-criteria`
const STARTING_CONTEXT_COMPLETION_CRITERIA: &str = "1c700000-0000-4000-8000-000000000009";
/// `person-member`
const PERSON_MEMBER: &str = "1c700000-0000-4000-8000-00000000000a";
/// `private-root`
const PRIVATE_ROOT: &str = "1c700000-0000-4000-8000-00000000000b";
/// `starting-context-exact`
const STARTING_CONTEXT_EXACT: &str = "1c700000-0000-4000-8000-00000000000c";
/// `starting-context-duplicate`
const STARTING_CONTEXT_DUPLICATE: &str = "1c700000-0000-4000-8000-00000000000d";
/// `starting-context`
const STARTING_CONTEXT: &str = "1c700000-0000-4000-8000-00000000000e";
/// `apply-seed`
const APPLY_SEED: &str = "1c700000-0000-4000-8000-00000000000f";
/// `reset-seed`
const RESET_SEED: &str = "1c700000-0000-4000-8000-000000000010";
/// `empty-criteria`
const EMPTY_CRITERIA: &str = "1c700000-0000-4000-8000-000000000011";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), caller, tool, args).await
}

async fn create_document(registry: &ToolRegistry, db: &Db, id: &str, body: &str) {
    call_as(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({
            "id": id,
            "type": "Document",
            "kind": "note",
            "name": id,
            "body": body,
            "reason": "instruction control fixture"
        }),
    )
    .await
    .unwrap();
}

fn body_digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

async fn seed_workspace_fixture(
    registry: &ToolRegistry,
    db: &Db,
    source_id: &str,
    body: &str,
    position: i64,
) {
    create_document(registry, db, source_id, body).await;
    call_as(
        registry,
        db,
        Caller::local(),
        "manage_instructions",
        json!({
            "action":"create_binding", "scope":"workspace",
            "binding_id":format!("binding:{source_id}"), "source_record_id":source_id,
            "position":position, "idempotency_key":format!("test:seed-binding:{source_id}"),
            "reason":"create seeded command fixture"
        }),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO seeded_instruction_sources
         (source_record_id,template_key,template_version,last_applied_digest,last_applied_at)
         VALUES(?,'workspace-agent-instructions',1,?,'2026-01-01T00:00:00Z')",
    )
    .bind(source_id)
    .bind(body_digest(body))
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

#[tokio::test]
async fn instruction_tools_register_with_closed_action_schemas() {
    let registry = registry();
    for name in ["manage_instructions", "manage_onboarding"] {
        let spec = registry.specs().find(|spec| spec.name == name).unwrap();
        assert_eq!(spec.input_schema["additionalProperties"], false);
        assert!(spec.input_schema["properties"]["action"]["enum"]
            .as_array()
            .is_some_and(|actions| !actions.is_empty()));
    }
}

#[tokio::test]
async fn workspace_binding_is_atomic_with_the_exact_utf8_budget() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, TOO_LARGE, &"é".repeat(16_385)).await;

    let error = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        json!({
            "action": "create_binding",
            "scope": "workspace",
            "binding_id": "oversize-binding",
            "source_record_id": TOO_LARGE,
            "position": 100,
            "idempotency_key": "test:oversize-binding",
            "reason": "exercise the hard authored-content allowance"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("instruction_budget_exceeded"), "{error}");
    let binding_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM instruction_bindings WHERE id='oversize-binding')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let event_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM control_events WHERE idempotency_key='test:oversize-binding')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!binding_exists);
    assert!(!event_exists);
}

#[tokio::test]
async fn active_sources_must_be_unbound_before_delete() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, BOUND_SOURCE, "short guidance").await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        json!({
            "action": "create_binding",
            "scope": "workspace",
            "binding_id": "live-binding",
            "source_record_id": BOUND_SOURCE,
            "position": 100,
            "idempotency_key": "test:live-binding",
            "reason": "bind the source for deletion protection"
        }),
    )
    .await
    .unwrap();

    let error = call_as(
        &registry,
        &db,
        Caller::local(),
        "delete_record",
        json!({ "id": BOUND_SOURCE, "reason": "exercise active source protection" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("live-binding"), "{error}");
    assert!(error.contains("disable or remove"), "{error}");
}

#[tokio::test]
async fn member_binding_authority_is_implicit_and_account_scoped() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, MEMBER_SOURCE, "member guidance").await;
    let alice = Caller::authenticated("acct:alice")
        .with_hosting_context("host-alice", "database")
        .with_hosting_owner(false);
    call_as(
        &registry,
        &db,
        alice,
        "manage_instructions",
        json!({
            "action": "create_binding",
            "scope": "member",
            "binding_id": "alice-binding",
            "source_record_id": MEMBER_SOURCE,
            "position": 100,
            "idempotency_key": "test:alice-binding",
            "reason": "create Alice's private binding"
        }),
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host-bea", "database")
        .with_hosting_owner(false);
    let error = call_as(
        &registry,
        &db,
        bea,
        "manage_instructions",
        json!({
            "action": "disable_binding",
            "binding_id": "alice-binding",
            "idempotency_key": "test:bea-disable",
            "reason": "must not cross the member boundary"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("matching member account"), "{error}");
}

#[tokio::test]
async fn programme_configuration_is_owner_only() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let member = Caller::authenticated("acct:member")
        .with_hosting_context("host-member", "database")
        .with_hosting_owner(false);
    let error = call_as(
        &registry,
        &db,
        member,
        "manage_onboarding",
        json!({
            "action": "create_programme",
            "programme_id": "member-created",
            "trigger_key": "on_member_joined",
            "position": 100,
            "idempotency_key": "test:member-created-programme",
            "reason": "exercise programme authority"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("database owner"), "{error}");
}

#[tokio::test]
async fn active_dangling_sources_fail_closed_and_block_control_mutations() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, DANGLING_SOURCE, "guidance").await;
    create_document(&registry, &db, SAFE_SOURCE, "other guidance").await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        json!({
            "action":"create_binding", "scope":"workspace", "binding_id":"dangling-binding",
            "source_record_id":DANGLING_SOURCE, "position":8100,
            "idempotency_key":"test:dangling:create", "reason":"create corruption fixture"
        }),
    )
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE records SET deleted_at='2026-01-01T00:00:00Z' WHERE id='{DANGLING_SOURCE}'"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let list_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        json!({"action":"list"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(list_error.contains("not readable"), "{list_error}");
    assert!(!list_error.contains(DANGLING_SOURCE), "{list_error}");

    let mutation_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        json!({
            "action":"create_binding", "scope":"workspace", "binding_id":"must-roll-back",
            "source_record_id":SAFE_SOURCE, "position":8200,
            "idempotency_key":"test:dangling:mutation", "reason":"validate every active source"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        mutation_error.contains("deleted active source"),
        "{mutation_error}"
    );
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM instruction_bindings WHERE id='must-roll-back')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!exists);
}

#[tokio::test]
async fn future_member_programme_budget_is_enforced_without_pending_members() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, FUTURE_OVERSIZE, &"é".repeat(16_385)).await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_onboarding",
        json!({
            "action":"create_programme", "programme_id":"future-members",
            "trigger_key":"on_member_joined", "position":9100, "enabled":false,
            "idempotency_key":"test:future:create", "reason":"create dormant programme"
        }),
    )
    .await
    .unwrap();
    let error = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_onboarding",
        json!({
            "action":"add_source", "programme_id":"future-members",
            "source_record_id":FUTURE_OVERSIZE, "source_role":"guidance", "position":100,
            "idempotency_key":"test:future:add", "reason":"validate future member stack"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("instruction_budget_exceeded"), "{error}");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM onboarding_programme_sources WHERE programme_id='future-members'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn destructive_control_commands_are_exactly_retryable_after_projection_changes() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, RETRY_SOURCE, "guidance").await;
    let owner = Caller::local();
    call_as(
        &registry,
        &db,
        owner.clone(),
        "manage_instructions",
        json!({
            "action":"create_binding", "scope":"workspace", "binding_id":"retry-binding",
            "source_record_id":RETRY_SOURCE, "position":9300,
            "idempotency_key":"test:retry:binding:create", "reason":"create retry fixture"
        }),
    )
    .await
    .unwrap();
    let remove_binding = json!({
        "action":"remove_binding", "binding_id":"retry-binding",
        "idempotency_key":"test:retry:binding:remove", "reason":"remove exactly once"
    });
    call_as(
        &registry,
        &db,
        owner.clone(),
        "manage_instructions",
        remove_binding.clone(),
    )
    .await
    .unwrap();
    let retry = call_as(
        &registry,
        &db,
        owner.clone(),
        "manage_instructions",
        remove_binding,
    )
    .await
    .unwrap();
    assert_eq!(retry["changed"], false);

    call_as(&registry, &db, owner.clone(), "manage_onboarding", json!({
        "action":"create_programme", "programme_id":"retry-programme", "trigger_key":"on_member_joined",
        "position":9300, "idempotency_key":"test:retry:programme:create", "reason":"create retry fixture"
    })).await.unwrap();
    call_as(&registry, &db, owner.clone(), "manage_onboarding", json!({
        "action":"add_source", "programme_id":"retry-programme", "source_record_id":RETRY_SOURCE,
        "source_role":"guidance", "position":100, "idempotency_key":"test:retry:source:add", "reason":"add retry fixture"
    })).await.unwrap();
    let remove_source = json!({
        "action":"remove_source", "programme_id":"retry-programme", "source_record_id":RETRY_SOURCE,
        "idempotency_key":"test:retry:source:remove", "reason":"remove exactly once"
    });
    call_as(
        &registry,
        &db,
        owner.clone(),
        "manage_onboarding",
        remove_source.clone(),
    )
    .await
    .unwrap();
    let retry = call_as(&registry, &db, owner, "manage_onboarding", remove_source)
        .await
        .unwrap();
    assert_eq!(retry["changed"], false);
}

#[tokio::test]
async fn obligation_resolution_and_reopen_retries_preserve_reopen_evidence() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, CRITERIA_SOURCE, "completion criteria").await;
    call_as(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"create_programme", "programme_id":"obligation-programme", "trigger_key":"on_member_joined",
        "position":9400, "idempotency_key":"test:obligation:create", "reason":"create obligation fixture"
    })).await.unwrap();
    call_as(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"add_source", "programme_id":"obligation-programme", "source_record_id":CRITERIA_SOURCE,
        "source_role":"completion_criteria", "position":100, "idempotency_key":"test:obligation:criteria", "reason":"declare criteria"
    })).await.unwrap();
    sqlx::query("INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) VALUES('acct:member','obligation-programme',1,'pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    let member = Caller::authenticated("acct:member");
    let anchor = json!({
        "action":"record_progress", "programme_id":"obligation-programme", "generation":1,
        "phase":"anchor_established", "evidence":{"basis":"user_stated"},
        "run_key":"scout-chair-a748b2",
        "idempotency_key":"test:obligation:anchor", "reason":"member stated their current aim"
    });
    assert_eq!(
        call_as(
            &registry,
            &db,
            member.clone(),
            "manage_onboarding",
            anchor.clone()
        )
        .await
        .unwrap()["changed"],
        true
    );
    assert_eq!(
        call_as(&registry, &db, member.clone(), "manage_onboarding", anchor)
            .await
            .unwrap()["changed"],
        false
    );
    let collision = call_as(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"obligation-programme", "generation":1,
            "phase":"anchor_established", "evidence":{"basis":"user_confirmed"},
            "run_key":"scout-chair-a748b2",
            "idempotency_key":"test:obligation:anchor", "reason":"member stated their current aim"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(collision.contains("different intent"), "{collision}");
    let skipped_preview = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"obligation-programme", "generation":1,
        "phase":"artifact_written", "evidence":{}, "artifact_id":CRITERIA_SOURCE,
        "explicit_member_intent":true, "run_key":"scout-chair-a748b2",
        "idempotency_key":"test:obligation:skip-preview", "reason":"must not skip consent preview"
    })).await.unwrap_err().to_string();
    assert!(
        skipped_preview.contains("invalid progress transition"),
        "{skipped_preview}"
    );
    call_as(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"obligation-programme", "generation":1,
            "phase":"deferred", "evidence":{"basis":"explicit_member_request"},
            "explicit_member_intent":true, "resume_after":"2026-09-01T00:00:00Z",
            "run_key":"scout-chair-a748b2",
            "idempotency_key":"test:obligation:defer", "reason":"member explicitly deferred"
        }),
    )
    .await
    .unwrap();
    let resolve = json!({
        "action":"resolve_obligation", "programme_id":"obligation-programme", "generation":1,
        "resolution":"completed", "evidence":{"record_id":CRITERIA_SOURCE},
        "idempotency_key":"test:obligation:resolve", "reason":"criteria completed"
    });
    call_as(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        resolve.clone(),
    )
    .await
    .unwrap();
    let progress_after_terminal = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"obligation-programme", "generation":1,
        "phase":"deferred", "evidence":{"basis":"explicit_member_request"},
        "explicit_member_intent":true,
        "run_key":"scout-chair-a748b2",
        "idempotency_key":"test:obligation:late-progress", "reason":"terminal obligations reject progress"
    })).await.unwrap_err().to_string();
    assert!(
        progress_after_terminal.contains("pending member obligation required"),
        "{progress_after_terminal}"
    );
    assert_eq!(
        call_as(&registry, &db, member.clone(), "manage_onboarding", resolve)
            .await
            .unwrap()["changed"],
        false
    );
    let reopen = json!({
        "action":"reopen_obligation", "programme_id":"obligation-programme", "generation":1,
        "evidence":{"member_intent":"continue onboarding"}, "explicit_member_intent":true,
        "idempotency_key":"test:obligation:reopen", "reason":"member explicitly asked to reopen"
    });
    call_as(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        reopen.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM member_obligation_progress
              WHERE account_id='acct:member' AND programme_id='obligation-programme' AND generation=1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0,
        "reopen must reset nonterminal progress for a fresh continuation"
    );
    assert_eq!(
        call_as(&registry, &db, member, "manage_onboarding", reopen)
            .await
            .unwrap()["changed"],
        false
    );
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM control_events WHERE idempotency_key='test:obligation:reopen'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap()["evidence"]["member_intent"],
        "continue onboarding"
    );
}

#[tokio::test]
async fn starting_context_requires_consented_same_run_private_write_and_projects_truthfully() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let member = Caller::authenticated("acct:member");
    let run_key = "scout-chair-a748b2";
    create_document(
        &registry,
        &db,
        STARTING_CONTEXT_COMPLETION_CRITERIA,
        "The member explicitly confirms that their Starting context is complete.",
    )
    .await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "id":PERSON_MEMBER, "type":"Entity", "kind":"person", "name":"Member",
            "reason":"create member fixture"
        }),
    )
    .await
    .unwrap();
    call_as(&registry, &db, Caller::local(), "create_record", json!({
        "id":PRIVATE_ROOT, "type":"Collection", "kind":"folder", "name":"My agent context",
        "home_id":"native:root", "owner_id":PERSON_MEMBER, "reason":"create private root fixture"
    })).await.unwrap();
    sqlx::query(&format!("INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('{PERSON_MEMBER}','account','acct:member',1)"))
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    sqlx::query(&format!("INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at) VALUES('acct:member','{PERSON_MEMBER}','{PRIVATE_ROOT}','2026-08-01T00:00:00Z')"))
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    replace_explicit_policy(
        &db,
        "acct:member",
        PRIVATE_ROOT,
        vec![AllowEntry::account("acct:member", Capability::Manage)],
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO onboarding_programmes(id,trigger_key,generation,position,enabled,created_by,created_at,updated_at) VALUES('native:onboarding-member-joined','on_member_joined',1,100,1,'fixture','2026-08-01T00:00:00Z','2026-08-01T00:00:00Z')")
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    sqlx::query(&format!("INSERT INTO onboarding_programme_sources(programme_id,source_record_id,source_role,position) VALUES('native:onboarding-member-joined','{STARTING_CONTEXT_COMPLETION_CRITERIA}','completion_criteria',100)"))
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    sqlx::query("INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) VALUES('acct:member','native:onboarding-member-joined',1,'pending','2026-08-01T00:00:00Z','2026-08-01T00:00:00Z')")
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();

    let control_events_before_denial: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let unauthorized = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:outsider"),
        "manage_onboarding",
        json!({
            "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
            "phase":"anchor_established", "evidence":{"basis":"user_stated"},
            "run_key":run_key, "idempotency_key":"test:context:unauthorized-anchor",
            "reason":"an unrelated account must not cross the exact-member boundary"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        unauthorized.contains("pending member obligation required"),
        "{unauthorized}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        control_events_before_denial,
        "authorization denial must not append a control event"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM member_obligation_progress")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0,
        "authorization denial must not create a progress projection"
    );

    let body = "# Starting context\n\n## Current aim\nShip the onboarding runtime.\n\n## Useful learned context\nThe member asked for concise progress.\n\n## Work or decision made\nUse a private ordinary note.\n\n## Next step\nVerify staging after merge.\n\n## Material uncertainty and source attribution\nNo external facts; all context was stated in this run.";
    let digest = body_digest(body);
    call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"anchor_established", "evidence":{"basis":"user_stated"}, "run_key":run_key,
        "idempotency_key":"test:context:anchor", "reason":"member stated the working aim"
    })).await.unwrap();
    let missing_run = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_previewed", "evidence":{"content_digest":digest},
        "explicit_member_intent":true,
        "idempotency_key":"test:context:preview:no-run", "reason":"missing run must fail closed"
    })).await.unwrap_err().to_string();
    assert!(
        missing_run.contains("Bootstrap's exact run_key"),
        "{missing_run}"
    );

    call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_previewed", "evidence":{"content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "explicit_member_intent":true, "run_key":run_key,
        "idempotency_key":"test:context:preview:wrong", "reason":"member consented to the first preview"
    })).await.unwrap();
    call_as(
        &registry,
        &db,
        member.clone(),
        "create_record",
        json!({
            "id":STARTING_CONTEXT, "type":"Document", "kind":"note", "name":"Starting context",
            "body":body, "home_id":PRIVATE_ROOT, "owner_id":PERSON_MEMBER, "run_key":run_key,
            "reason":"write the consented private context"
        }),
    )
    .await
    .unwrap();
    let wrong_digest = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_written", "evidence":{}, "artifact_id":STARTING_CONTEXT,
        "explicit_member_intent":true, "run_key":run_key,
        "idempotency_key":"test:context:written:wrong", "reason":"digest mismatch must fail"
    })).await.unwrap_err().to_string();
    assert!(
        wrong_digest.contains("differs from the preview"),
        "{wrong_digest}"
    );

    let prewritten_retry = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_previewed", "evidence":{"content_digest":digest},
        "explicit_member_intent":true, "run_key":run_key,
        "idempotency_key":"test:context:preview:exact", "reason":"member consented to the exact draft"
    })).await.unwrap_err().to_string();
    assert!(
        prewritten_retry.contains("cannot be retroactively consented"),
        "{prewritten_retry}"
    );
    call_as(
        &registry,
        &db,
        member.clone(),
        "delete_record",
        json!({
            "id":STARTING_CONTEXT, "run_key":run_key,
            "reason":"discard content written for the wrong preview"
        }),
    )
    .await
    .unwrap();
    call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_previewed", "evidence":{"content_digest":digest},
        "explicit_member_intent":true, "run_key":run_key,
        "idempotency_key":"test:context:preview:exact-after-cleanup", "reason":"member consented to the exact draft"
    })).await.unwrap();
    call_as(&registry, &db, member.clone(), "create_record", json!({
        "id":STARTING_CONTEXT_EXACT, "type":"Document", "kind":"note", "name":"Starting context",
        "body":body, "home_id":PRIVATE_ROOT, "owner_id":PERSON_MEMBER, "run_key":run_key,
        "reason":"create only after the exact consented preview"
    })).await.unwrap();
    let cross_run = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_written", "evidence":{}, "artifact_id":STARTING_CONTEXT_EXACT,
        "explicit_member_intent":true, "run_key":"scout-chair-b748b2",
        "idempotency_key":"test:context:written:cross-run", "reason":"cross-run write must fail"
    })).await.unwrap_err().to_string();
    assert!(cross_run.contains("same run"), "{cross_run}");
    let written = call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_written", "evidence":{}, "artifact_id":STARTING_CONTEXT_EXACT,
        "explicit_member_intent":true, "run_key":run_key,
        "idempotency_key":"test:context:written", "reason":"record the exact private write"
    })).await.unwrap();
    assert_eq!(written["phase"], "artifact_written");
    let current = call_as(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":run_key}),
    )
    .await
    .unwrap();
    assert_eq!(
        current["pending_obligations"][0]["progress_artifact_status"],
        "available_private"
    );
    let current_contract = &current["principal"]["private_context"]["starting_context_contract"];
    assert_eq!(current_contract["mode"], "already_written");
    assert_eq!(current_contract["onboarding_action"], "none");
    assert!(current_contract.get("body_template").is_none());
    assert!(current_contract.get("write_path").is_none());

    call_as(&registry, &db, member.clone(), "create_record", json!({
        "id":STARTING_CONTEXT_DUPLICATE, "type":"Document", "kind":"note", "name":"Starting context",
        "body":body, "home_id":PRIVATE_ROOT, "owner_id":PERSON_MEMBER, "run_key":run_key,
        "reason":"exercise duplicate fail-closed projection"
    })).await.unwrap();
    let duplicate = call_as(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":run_key}),
    )
    .await
    .unwrap();
    assert_eq!(
        duplicate["pending_obligations"][0]["progress_artifact_status"],
        "moved_or_policy_changed"
    );
    call_as(
        &registry,
        &db,
        member.clone(),
        "delete_record",
        json!({
            "id":STARTING_CONTEXT_DUPLICATE, "run_key":run_key, "reason":"remove duplicate fixture"
        }),
    )
    .await
    .unwrap();
    call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"deferred", "evidence":{"basis":"explicit_member_request"},
        "explicit_member_intent":true, "run_key":"scout-chair-c748b2",
        "idempotency_key":"test:context:defer-written", "reason":"member explicitly deferred after the write"
    })).await.unwrap();
    let deferred = call_as(
        &registry,
        &db,
        member.clone(),
        "bootstrap",
        json!({"run_key":"scout-chair-c748b2"}),
    )
    .await
    .unwrap();
    let deferred_contract = &deferred["principal"]["private_context"]["starting_context_contract"];
    assert_eq!(deferred_contract["mode"], "deferred_wait");
    assert_eq!(
        deferred_contract["onboarding_action"],
        "wait_for_explicit_resume"
    );
    assert!(deferred_contract.get("body_template").is_none());
    assert!(deferred_contract.get("write_path").is_none());
    let resume = json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"anchor_established", "evidence":{"basis":"user_confirmed"},
        "explicit_member_intent":true, "run_key":"scout-chair-d748b2",
        "idempotency_key":"test:context:resume-written", "reason":"member explicitly resumed the written checkpoint"
    });
    let resumed = call_as(
        &registry,
        &db,
        member.clone(),
        "manage_onboarding",
        resume.clone(),
    )
    .await
    .unwrap();
    assert_eq!(resumed["phase"], "artifact_written");
    assert_eq!(resumed["artifact_id"], STARTING_CONTEXT_EXACT);
    assert_eq!(
        call_as(&registry, &db, member.clone(), "manage_onboarding", resume)
            .await
            .unwrap()["changed"],
        false
    );
    let projected_evidence: String = sqlx::query_scalar(
        "SELECT evidence FROM member_obligation_progress
          WHERE account_id='acct:member' AND programme_id='native:onboarding-member-joined' AND generation=1",
    )
    .fetch_one(db.pool()).await.unwrap();
    assert_eq!(projected_evidence, "{}");
    call_as(&registry, &db, member.clone(), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"deferred", "evidence":{"basis":"explicit_member_request"},
        "explicit_member_intent":true, "run_key":"scout-chair-d748b2",
        "idempotency_key":"test:context:defer-invalidated", "reason":"defer before invalidating the checkpoint"
    })).await.unwrap();
    call_as(&registry, &db, member.clone(), "delete_record", json!({
        "id":STARTING_CONTEXT_EXACT, "run_key":run_key, "reason":"exercise deleted linked note status"
    })).await.unwrap();
    let deleted = call_as(
        &registry,
        &db,
        member,
        "bootstrap",
        json!({"run_key":run_key}),
    )
    .await
    .unwrap();
    assert_eq!(
        deleted["pending_obligations"][0]["progress_artifact_status"],
        "deleted"
    );
    let invalid_resume = call_as(&registry, &db, Caller::authenticated("acct:member"), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"anchor_established", "evidence":{"basis":"user_confirmed"},
        "explicit_member_intent":true, "run_key":"scout-chair-e748b2",
        "idempotency_key":"test:context:resume-invalid", "reason":"invalid checkpoint must fail closed"
    })).await.unwrap_err().to_string();
    assert!(
        invalid_resume.contains("reset_invalid_artifact"),
        "{invalid_resume}"
    );
    let reset = call_as(&registry, &db, Caller::authenticated("acct:member"), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"anchor_established", "evidence":{"basis":"user_confirmed","checkpoint":"reset_invalid_artifact"},
        "explicit_member_intent":true, "run_key":"scout-chair-e748b2",
        "idempotency_key":"test:context:reset-invalid", "reason":"member explicitly chose a fresh artifact flow"
    })).await.unwrap();
    assert_eq!(reset["phase"], "anchor_established");
    assert!(reset["artifact_id"].is_null());
    let fresh_preview = call_as(&registry, &db, Caller::authenticated("acct:member"), "manage_onboarding", json!({
        "action":"record_progress", "programme_id":"native:onboarding-member-joined", "generation":1,
        "phase":"artifact_previewed", "evidence":{"content_digest":digest},
        "explicit_member_intent":true, "run_key":"scout-chair-e748b2",
        "idempotency_key":"test:context:fresh-preview", "reason":"fresh flow after explicit checkpoint reset"
    })).await.unwrap();
    assert_eq!(fresh_preview["phase"], "artifact_previewed");
    call_as(&registry, &db, Caller::authenticated("acct:member"), "manage_onboarding", json!({
        "action":"resolve_obligation", "programme_id":"native:onboarding-member-joined", "generation":1,
        "resolution":"completed", "evidence":{"member_confirmation":"completed"},
        "run_key":"scout-chair-e748b2",
        "idempotency_key":"test:context:complete", "reason":"member explicitly confirmed completion"
    })).await.unwrap();
    let terminal = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:member"),
        "bootstrap",
        json!({
            "run_key":"scout-chair-e748b2"
        }),
    )
    .await
    .unwrap();
    let contract = &terminal["principal"]["private_context"]["starting_context_contract"];
    assert_eq!(contract["mode"], "ordinary_private_context");
    assert_eq!(contract["onboarding_action"], "none");
    assert_eq!(contract["available"], false);
    assert!(contract.get("body_template").is_none());
    assert!(contract.get("write_path").is_none());
}

#[tokio::test]
async fn seeded_apply_retry_uses_canonical_intent_before_the_changed_body_digest() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    seed_workspace_fixture(&registry, &db, APPLY_SEED, "old shipped body", 9600).await;
    let expected = body_digest("old shipped body");
    let command = json!({
        "action":"apply_seeded_default", "source_record_id":APPLY_SEED,
        "expected_body_digest":expected, "idempotency_key":"test:seed:apply",
        "reason":"apply the shipped default"
    });
    let first = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        command.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["body_changed"], true);
    let retry = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        command,
    )
    .await
    .unwrap();
    assert_eq!(retry["idempotent_retry"], true);
    assert_eq!(retry["changed"], false);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_events WHERE idempotency_key='test:seed:apply'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn customized_same_version_reset_is_durable_and_exactly_retryable() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    seed_workspace_fixture(&registry, &db, RESET_SEED, "customized body", 9700).await;
    let expected = body_digest("customized body");
    let command = json!({
        "action":"reset_seeded_default", "source_record_id":RESET_SEED,
        "expected_body_digest":expected, "confirm":true,
        "idempotency_key":"test:seed:reset", "reason":"explicitly restore the shipped default"
    });
    let first = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        command.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["body_changed"], true);
    assert_eq!(first["provenance_changed"], false);
    let retry = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_instructions",
        command,
    )
    .await
    .unwrap();
    assert_eq!(retry["idempotent_retry"], true);
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM control_events WHERE idempotency_key='test:seed:reset'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["operation"], "reset_seeded_default");
    assert_eq!(payload["expected_body_digest"], expected);
}

#[tokio::test]
async fn empty_completion_criteria_are_rejected_on_admission_and_completion() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_document(&registry, &db, EMPTY_CRITERIA, "").await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_onboarding",
        json!({
            "action":"create_programme", "programme_id":"criteria-programme",
            "trigger_key":"on_member_joined", "position":9800,
            "idempotency_key":"test:criteria:programme", "reason":"create criteria fixture"
        }),
    )
    .await
    .unwrap();
    let error = call_as(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"add_source", "programme_id":"criteria-programme", "source_record_id":EMPTY_CRITERIA,
        "source_role":"completion_criteria", "position":100,
        "idempotency_key":"test:criteria:empty-add", "reason":"must reject empty criteria"
    })).await.unwrap_err().to_string();
    assert!(error.contains("empty completion-criteria"), "{error}");

    call_as(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "id":EMPTY_CRITERIA, "body":"Explicit criteria", "reason":"make criteria admissible"
        }),
    )
    .await
    .unwrap();
    call_as(&registry, &db, Caller::local(), "manage_onboarding", json!({
        "action":"add_source", "programme_id":"criteria-programme", "source_record_id":EMPTY_CRITERIA,
        "source_role":"completion_criteria", "position":100,
        "idempotency_key":"test:criteria:add", "reason":"add explicit criteria"
    })).await.unwrap();
    sqlx::query("INSERT INTO member_obligations(account_id,programme_id,generation,state,created_at,updated_at) VALUES('acct:member','criteria-programme',1,'pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        .execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    sqlx::query(&format!(
        "UPDATE records SET body=NULL WHERE id='{EMPTY_CRITERIA}'"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let error = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:member"),
        "manage_onboarding",
        json!({
            "action":"resolve_obligation", "programme_id":"criteria-programme", "generation":1,
            "resolution":"completed", "evidence":{"attempted":true},
            "idempotency_key":"test:criteria:complete", "reason":"must reject corrupt criteria"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("empty active completion-criteria"),
        "{error}"
    );
    let state: String = sqlx::query_scalar("SELECT state FROM member_obligations WHERE account_id='acct:member' AND programme_id='criteria-programme' AND generation=1")
        .fetch_one(db.pool()).await.unwrap();
    assert_eq!(state, "pending");
}
