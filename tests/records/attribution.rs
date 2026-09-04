// Record ids must be canonical v4/v7 UUIDs, so every fixture id here is a
// pinned `a7718000-0000-4000-8000-<counter>` literal; the overflow evidence
// families use `a7718e01`/`a7718e02` with the ordinal as the counter.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::interchange::{export_canonical_interchange, import_canonical_interchange};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{append, AppendSpec};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

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
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    call_as(registry, db, Caller::local(), tool, args)
        .await
        .unwrap()
}

/// Read the current write token the way a caller must: through `get_record`.
/// Whole-body replacement is guarded, so the rewrites below carry the digest
/// they actually read rather than asserting an unguarded overwrite.
async fn current_body_digest(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["body_digest"]
        .as_str()
        .expect("get_record exposes body_digest")
        .to_owned()
}

async fn create(registry: &ToolRegistry, db: &Db, id: &str, body: Option<&str>) -> String {
    let mut args = json!({
        "id":id,"type":"Document","kind":"note","name":id,
    });
    if let Some(body) = body {
        args["body"] = json!(body);
    }
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .into()
}

async fn create_evidence_attestations(
    registry: &ToolRegistry,
    db: &Db,
    // Record ids must be canonical v4/v7 UUIDs, so callers pass the first eight
    // hex digits of a pinned id family and the ordinal becomes the counter.
    // Ordinal order therefore still equals id sort order.
    prefix: &str,
    count: usize,
) -> Vec<String> {
    let mut attestations = Vec::with_capacity(count);
    for ordinal in 0..count {
        let result = call(
            registry,
            db,
            "create_record",
            json!({
                "id":format!("{prefix}-0000-4000-8000-{ordinal:012}"),"type":"Document","kind":"note",
                "name":format!("Evidence {ordinal}"),"body":"bounded evidence sentinel"
            }),
        )
        .await;
        attestations.push(
            result["action_attestation_ids"][0]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    attestations
}

async fn body_target(db: &Db, id: &str, scope: &str, selectors: Value) -> Value {
    let row = sqlx::query(
        "SELECT e.id,r.body FROM records r JOIN content_events e ON e.record_id=r.id
          WHERE r.id=? AND (e.type='record.created' OR (e.type='record.updated' AND json_type(e.payload,'$.body') IS NOT NULL))
          ORDER BY e.seq DESC LIMIT 1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let body = row
        .try_get::<Option<String>, _>("body")
        .unwrap()
        .unwrap_or_default();
    json!({
        "source_event_id":row.try_get::<String, _>("id").unwrap(),
        "source_body_sha256":hex::encode(Sha256::digest(body.as_bytes())),
        "scope":scope,
        "selectors":selectors,
    })
}

fn assessment_args(bearer: &str, target: Value) -> Value {
    json!({
        "idempotency_key":format!("attribution-test-{}",uuid::Uuid::new_v4()),
        "bearer_id":bearer,
        "target":target,
        "subject":{"kind":"self_agent_execution"},
        "relation":"expresses_view",
        "polarity":"affirmed",
        "confidence":"likely",
        "transformation":"summary",
        "rationale":"The agent assesses that the exact revision represents its own synthesized view.",
    })
}

fn agent_caller(
    issuer: &native_ce::awareness::HumanInteractionTokenIssuer,
    bearer: &str,
) -> Caller {
    let ids = vec![bearer.to_string()];
    let token = issuer
        .issue(
            "local",
            "agent-executor:test-agent:test-delegation",
            &ids,
            60,
        )
        .unwrap();
    Caller::local()
        .with_agent_executor_token(issuer, &token, "test-agent", "test-delegation", &ids)
        .unwrap()
}

#[tokio::test]
async fn assessment_keeps_subject_executor_claim_and_exact_target_distinct() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000002",
        Some("A considered view."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let created = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target.clone()),
    )
    .await
    .unwrap();
    assert_eq!(created["claim_mode"], "assessment");
    let id = created["annotation_id"].as_str().unwrap();

    let read = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(read["attribution_count"], 1);
    let claim = &read["attributions"][0];
    assert_eq!(claim["annotation_id"], id);
    assert_eq!(claim["assertion"]["claim_mode"], "assessment");
    assert_eq!(claim["assertion"]["claimant_principal"], "test-agent");
    assert_eq!(claim["assertion"]["confidence"], "likely");
    assert_eq!(claim["assertion"]["transformation"], "summary");
    assert_eq!(
        claim["assertion"]["attributed_subject"]["kind"],
        "agent_execution"
    );
    assert_ne!(
        claim["assertion"]["claimant_principal"],
        claim["assertion"]["attributed_subject"]["ref"]
    );
    assert_eq!(
        claim["target"]["source_event_id"],
        target["source_event_id"]
    );
    assert_eq!(claim["target"]["validation"]["status"], "current");
    assert_eq!(
        claim["assertion"]["action_attestation_id"],
        created["action_attestation_id"]
    );
    assert_eq!(read["interpretation"]["status"], "current");
    assert_eq!(
        read["interpretation"]["groups"][0]["claims"][0]["claim_class"],
        "agent_opinion"
    );
    assert_eq!(
        read["interpretation"]["groups"][0]["exact_review_state"],
        "not_confirmed"
    );
    assert!(read["interpretation"]["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!("delegation_does_not_establish_endorsement")));
    assert!(read["interpretation"]["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!("confidence_does_not_establish_truth")));
    assert!(read["interpretation"]["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!("claim_counts_do_not_establish_consensus")));
    let executor = sqlx::query(
        "SELECT executor_ref,delegation_ref FROM provenance_action_attestations WHERE id=?",
    )
    .bind(created["action_attestation_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        executor.try_get::<String, _>("executor_ref").unwrap(),
        "test-agent"
    );
    assert_eq!(
        executor.try_get::<String, _>("delegation_ref").unwrap(),
        "test-delegation"
    );
    rebuild_and_diff(&db).await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn generic_record_surfaces_are_explicit_bounded_views_of_the_typed_projection() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000007",
        Some("A generic read target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("generic-agent");
    call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target),
    )
    .await
    .unwrap();
    let dedicated = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;

    let default_get = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[bearer],"resolve":false}),
    )
    .await;
    assert!(default_get.get("include_interpretation").is_none());
    assert!(default_get["records"][0].get("interpretation").is_none());
    let explicit_false = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":false}),
    )
    .await;
    assert_eq!(default_get, explicit_false);

    let default_query = call(
        &registry,
        &db,
        "query_record",
        json!({"steps":[{"step":"filter","ids":[bearer]}],"limit":50}),
    )
    .await;
    let explicit_false_query = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps":[{"step":"filter","ids":[bearer]}],
            "limit":50,
            "include_interpretation":false
        }),
    )
    .await;
    let mut default_query_stable = default_query;
    let mut explicit_false_query_stable = explicit_false_query;
    default_query_stable
        .as_object_mut()
        .unwrap()
        .remove("observed_at");
    explicit_false_query_stable
        .as_object_mut()
        .unwrap()
        .remove("observed_at");
    assert_eq!(default_query_stable, explicit_false_query_stable);
    let default_render = call(&registry, &db, "render_record", json!({"id":bearer})).await;
    let explicit_false_render = call(
        &registry,
        &db,
        "render_record",
        json!({"id":bearer,"include_interpretation":false}),
    )
    .await;
    assert_eq!(default_render, explicit_false_render);

    let get = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
    )
    .await;
    assert_eq!(get["include_interpretation"], true);
    assert_eq!(
        get["records"][0]["interpretation"],
        dedicated["interpretation"]
    );

    let query = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps":[{"step":"filter","kinds":["note"]}],
            "limit":50,
            "include_interpretation":true
        }),
    )
    .await;
    let queried = query["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == bearer)
        .unwrap();
    assert_eq!(queried["interpretation"], dedicated["interpretation"]);

    let rendered = call(
        &registry,
        &db,
        "render_record",
        json!({"id":bearer,"include_interpretation":true}),
    )
    .await;
    assert_eq!(rendered["interpretation"], dedicated["interpretation"]);
    let markdown = rendered["markdown"].as_str().unwrap();
    assert!(markdown.contains("## Interpretation"));
    assert!(markdown.contains("do not establish endorsement, truth, or consensus"));

    for arguments in [
        json!({"steps":[{"step":"filter"}],"count_by":"type","include_interpretation":true}),
        json!({"steps":[{"step":"filter"}],"aggregate":{"op":"count"},"include_interpretation":true}),
    ] {
        let error = call_as(&registry, &db, Caller::local(), "query_record", arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("supported only for record-producing queries"));
    }
    let historical_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({"ids":[bearer],"include_interpretation":true,"as_of":{"content_seq":1}}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(historical_error.contains("not supported with as_of in v1"));
    let query_limit_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "query_record",
        json!({
            "steps":[{"step":"filter"}],
            "limit":51,
            "include_interpretation":true
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(query_limit_error.contains("requires limit <= 50"));
    let too_many_ids = (0..51)
        .map(|index| format!("missing-{index}"))
        .collect::<Vec<_>>();
    let get_limit_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({"ids":too_many_ids,"include_interpretation":true}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(get_limit_error.contains("supports at most 50 ids"));

    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DROP TRIGGER provenance_action_attestations_no_update")
        .execute(&write_pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE provenance_action_attestations SET action_digest=printf('%064d',0) \
          WHERE id=(SELECT id FROM provenance_action_attestations ORDER BY id LIMIT 1)",
    )
    .execute(&write_pool)
    .await
    .unwrap();
    let default_after_corruption = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[bearer],"resolve":false}),
    )
    .await;
    assert_eq!(default_after_corruption["records"][0]["status"], "found");
    let missing = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":["a7718000-0000-4000-8000-000000000012"],"resolve":false,"include_interpretation":true}),
    )
    .await;
    assert_eq!(missing["records"][0]["status"], "not_found");
    assert!(missing["records"][0].get("interpretation").is_none());
    let opted_in_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(opted_in_error, "provenance attestation state is invalid");
    db.close().await;
}

#[tokio::test]
async fn canonical_interchange_preserves_claim_and_provenance_without_manufacturing_evidence() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000018",
        Some("Portable exact interpretation."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("portable-agent");
    call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target),
    )
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let bytes = export_canonical_interchange(&db).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let imported = import_canonical_interchange(&bytes, &temp.path().join("imported.db"))
        .await
        .unwrap();
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
        .fetch_one(imported.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        export_canonical_interchange(&imported).await.unwrap(),
        bytes
    );
    let read = call(
        &registry,
        &imported,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(read["attribution_count"], 1);
    imported.close().await;
    db.close().await;
}

#[tokio::test]
async fn imported_declaration_keeps_source_claim_but_loses_trusted_presentation() {
    const ACCOUNT_ID: &str = "acct_a7718000000040008000000000000028";
    const PERSON_ID: &str = "a7718000-0000-4000-8000-000000000028";
    const USER_ID: &str = "a7718000-0000-4000-8000-000000000029";
    const DATABASE_ID: &str = "a7718000-0000-4000-8000-000000000030";
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({
                    "id":PERSON_ID,
                    "type":"Entity",
                    "kind":"person",
                    "name":"Portable declarer"
                }),
            ),
        )
        .await
        .unwrap();
    native_ce::identity::add_binding(
        &db,
        &native_ce::identity::MutationContext {
            actor: "portable declaration fixture",
            reason: "bind the declaration caller to its person",
            run_key: None,
            parent_key: None,
            intent: None,
            internal: true,
            source_read_authorized: false,
        },
        PERSON_ID,
        &native_ce::identity::BindingClaim {
            system: "account".into(),
            identifier: ACCOUNT_ID.into(),
        },
        true,
    )
    .await
    .unwrap();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000019",
        Some("I directly affirm this exact revision."),
    )
    .await;
    let arguments = json!({
        "idempotency_key":"portable-declaration",
        "bearer_id":bearer,
        "target":body_target(&db,&bearer,"whole_revision",json!([])).await,
        "subject":{"kind":"self_person"},
        "relation":"expresses_view",
        "polarity":"affirmed",
        "transformation":"none",
        "rationale":"The source database accepted an exact structured human declaration."
    });
    let issuer =
        native_ce::provenance::ProvenanceInteractionTokenIssuer::random("portable-human-ui");
    let scope = native_ce::provenance::verified_action_scope("create_attribution", &arguments);
    let token = issuer.issue(ACCOUNT_ID, &scope, 60).unwrap();
    let caller = Caller::authenticated(ACCOUNT_ID)
        .with_hosting_context(USER_ID, DATABASE_ID)
        .with_hosting_owner(true)
        .with_attribution_declaration_token(&issuer, &token, &arguments)
        .unwrap();
    call_as(&registry, &db, caller, "create_attribution", arguments)
        .await
        .unwrap();
    let local = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(
        local["attributions"][0]["assertion"]["claim_mode"],
        "declaration"
    );
    assert_eq!(
        local["attributions"][0]["evidence"][0]["role"],
        "exact_target_confirmation"
    );
    assert_eq!(
        local["interpretation"]["groups"][0]["exact_review_state"],
        "receiver_local_confirmed"
    );

    let bytes = export_canonical_interchange(&db).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let imported = import_canonical_interchange(&bytes, &temp.path().join("declaration.db"))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM provenance_local_attestation_authority")
            .fetch_one(imported.pool())
            .await
            .unwrap(),
        0
    );
    let foreign = call(
        &registry,
        &imported,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(
        foreign["attributions"][0]["assertion"]["claim_mode"],
        "unverified_declaration"
    );
    assert!(foreign["attributions"][0]["evidence"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        foreign["interpretation"]["groups"][0]["claims"][0]["claim_class"],
        "unverified_declaration"
    );
    assert_eq!(
        foreign["interpretation"]["groups"][0]["exact_review_state"],
        "not_confirmed"
    );
    assert!(foreign["interpretation"]["groups"][0]["evidence_classes"]
        .as_array()
        .unwrap()
        .contains(&json!("foreign_unverified")));
    assert_eq!(
        foreign["attributions"][0]["assertion"]["claimant"],
        local["attributions"][0]["assertion"]["claimant"]
    );
    assert_eq!(
        foreign["attributions"][0]["target"]["source_event_id"],
        local["attributions"][0]["target"]["source_event_id"]
    );
    let reexport = export_canonical_interchange(&imported).await.unwrap();
    let source_bundle: Value = serde_json::from_slice(&bytes).unwrap();
    let receiver_bundle: Value = serde_json::from_slice(&reexport).unwrap();
    for section_name in [
        "provenance_action_attestations",
        "attribution_targets",
        "attribution_assertions",
        "attribution_evidence",
    ] {
        let section = |bundle: &Value| {
            bundle["sections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|section| section["name"] == section_name)
                .unwrap()
                .clone()
        };
        assert_eq!(section(&source_bundle), section(&receiver_bundle));
    }
    imported.close().await;
    db.close().await;
}

#[tokio::test]
async fn only_an_exact_trusted_same_person_gesture_becomes_a_declaration() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id":"a7718000-0000-4000-8000-000000000004","type":"Entity","kind":"person","name":"Declaring person"
        }),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('a7718000-0000-4000-8000-000000000004','account','local',1)",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000003",
        Some("I support this proposal."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let arguments = json!({
        "idempotency_key":"trusted-declaration-one",
        "bearer_id":bearer,"target":target,"subject":{"kind":"self_person"},
        "relation":"endorses","polarity":"affirmed","transformation":"none",
        "rationale":"The authenticated person used the exact structured Endorse gesture."
    });
    let issuer = native_ce::provenance::ProvenanceInteractionTokenIssuer::random("structured-ui");
    let scope = native_ce::provenance::verified_action_scope("create_attribution", &arguments);
    let token = issuer.issue("local", &scope, 60).unwrap();
    let mut tampered = arguments.clone();
    tampered["rationale"] = json!("A different accepted action.");
    assert!(Caller::local()
        .with_attribution_declaration_token(&issuer, &token, &tampered)
        .is_err());
    let caller = Caller::local()
        .with_attribution_declaration_token(&issuer, &token, &arguments)
        .unwrap();
    let mut altered_after_verification = arguments.clone();
    altered_after_verification["rationale"] = json!("A changed action after verification.");
    altered_after_verification["confidence"] = json!("plausible");
    let altered = registry
        .call(
            db.clone(),
            caller.clone(),
            "create_attribution",
            altered_after_verification,
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(altered.contains("verified interaction scope does not allow this accepted action"));
    let created = registry
        .call(
            db.clone(),
            caller.clone(),
            "create_attribution",
            arguments.clone(),
        )
        .await
        .unwrap();
    let declaration_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let events_after_create: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let reused = registry
        .call(
            db.clone(),
            caller.clone(),
            "create_attribution",
            arguments.clone(),
        )
        .await
        .unwrap();
    assert_eq!(created["claim_mode"], "declaration");
    assert_eq!(reused["claim_mode"], "declaration");
    assert_eq!(created["annotation_id"], reused["annotation_id"]);
    assert_eq!(
        created["action_attestation_id"],
        reused["action_attestation_id"]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM provenance_interaction_receipts")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        1,
        "an exact retry reuses the original verified interaction receipt"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        events_after_create,
        "an exact retry appends no duplicate aggregate events"
    );
    let mut conflicting_retry = arguments.clone();
    conflicting_retry["rationale"] = json!("The same command key now names different intent.");
    let conflict = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_attribution",
            conflicting_retry,
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(conflict.contains("idempotency command identity was reused"));
    let read = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    let claim = read["attributions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["annotation_id"] == created["annotation_id"])
        .unwrap();
    assert!(claim["assertion"]["confidence"].is_null());
    assert_eq!(claim["assertion"]["claimant_principal"], "structured-ui");
    let human_executor = sqlx::query(
        "SELECT executor_kind,executor_ref,delegation_ref
           FROM provenance_action_attestations WHERE id=?",
    )
    .bind(created["action_attestation_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        human_executor
            .try_get::<String, _>("executor_kind")
            .unwrap(),
        "human"
    );
    assert_eq!(
        human_executor.try_get::<String, _>("executor_ref").unwrap(),
        claim["assertion"]["claimant_principal"].as_str().unwrap()
    );
    assert!(human_executor
        .try_get::<Option<String>, _>("delegation_ref")
        .unwrap()
        .is_none());
    assert_eq!(claim["evidence"][0]["role"], "exact_target_confirmation");
    assert_eq!(
        claim["evidence"][0]["action_attestation_id"],
        created["action_attestation_id"]
    );
    let confirmation_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribution_evidence WHERE annotation_id=? AND role='exact_target_confirmation'",
    )
    .bind(created["annotation_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(confirmation_count, 1);

    let mut forged_creation = assessment_args(
        &bearer,
        body_target(&db, &bearer, "whole_revision", json!([])).await,
    );
    forged_creation["evidence"] = json!([{
        "role":"exact_target_confirmation",
        "action_attestation_id":created["action_attestation_id"]
    }]);
    let forged = call_as(
        &registry,
        &db,
        Caller::local(),
        "create_attribution",
        forged_creation,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(forged.contains("exact_target_confirmation"));
    let appended = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_attributions",
        json!({"action":"add_evidence","annotation_id":created["annotation_id"],"evidence":{
            "role":"exact_target_confirmation",
            "action_attestation_id":created["action_attestation_id"]
        }}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(appended.contains("exact_target_confirmation is internal"));

    let ordinary = call_as(
        &registry,
        &db,
        Caller::local(),
        "create_attribution",
        json!({
            "idempotency_key":"ordinary-cannot-declare",
            "bearer_id":bearer,"target":body_target(&db,&bearer,"whole_revision",json!([])).await,
            "subject":{"kind":"self_person"},"relation":"endorses","polarity":"affirmed",
            "transformation":"none","rationale":"An ordinary call cannot manufacture a declaration."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(ordinary.contains("assessment requires ordinal confidence"));

    let receipt_id: String = sqlx::query_scalar(
        "SELECT interaction_receipt_id FROM provenance_action_attestations WHERE id=?",
    )
    .bind(created["action_attestation_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DROP TRIGGER provenance_interaction_receipts_no_update")
        .execute(&write_pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE provenance_interaction_receipts SET sealed_evidence_ref='sealed://must-not-leak' WHERE id=?",
    )
    .bind(&receipt_id)
    .execute(&write_pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER provenance_interaction_receipts_no_update
         BEFORE UPDATE ON provenance_interaction_receipts
         BEGIN SELECT RAISE(ABORT, 'provenance_interaction_receipts is append-only'); END",
    )
    .execute(&write_pool)
    .await
    .unwrap();
    let explained = call_as(
        &registry,
        &db,
        caller.clone(),
        "read_attributions",
        json!({"bearer_id":bearer,"explain_annotation_id":created["annotation_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        explained["explanation"]["claim"]["exact_review_state"],
        "receiver_local_confirmed"
    );
    assert_eq!(
        explained["explanation"]["authoring_attestation"]["interaction"]
            ["sealed_reference_recorded"],
        true
    );
    assert!(!serde_json::to_string(&explained)
        .unwrap()
        .contains("sealed://must-not-leak"));

    replace_explicit_policy(
        &db,
        "declaration-observer-policy",
        &bearer,
        vec![AllowEntry::account("observer", Capability::View)],
    )
    .await
    .unwrap();
    let observer = call_as(
        &registry,
        &db,
        Caller::authenticated("observer"),
        "read_attributions",
        json!({"bearer_id":bearer,"explain_annotation_id":created["annotation_id"]}),
    )
    .await
    .unwrap();
    assert!(observer["explanation"]["authoring_attestation"]["why"].is_null());
    assert!(observer["explanation"]["authoring_attestation"]["interaction"].is_null());

    sqlx::query(
        "INSERT INTO provenance_attestation_validity_events
         (id,attestation_id,ordinal,status,reason,issuer,issued_at)
         VALUES(?,?,0,'invalidated','test compromise','test operator',?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(created["action_attestation_id"].as_str().unwrap())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&write_pool)
    .await
    .unwrap();
    let historical_after_invalidation = call_as(
        &registry,
        &db,
        caller,
        "read_attributions",
        json!({"bearer_id":bearer,"as_of_event_seq":declaration_seq}),
    )
    .await
    .unwrap();
    assert_eq!(
        historical_after_invalidation["interpretation"]["groups"][0]["claims"][0]["claim_class"],
        "unverified_declaration"
    );
    assert!(
        historical_after_invalidation["interpretation"]["groups"][0]["evidence_classes"]
            .as_array()
            .unwrap()
            .contains(&json!("invalidated"))
    );
    assert_eq!(
        historical_after_invalidation["interpretation"]["groups"][0]["exact_review_state"],
        "not_confirmed"
    );
    db.close().await;
}

#[tokio::test]
async fn multiple_conflicting_and_changed_stances_remain_independent() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000017",
        Some("One exact proposition."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    for person in [
        "a7718002-0000-4000-8000-000000000001",
        "a7718002-0000-4000-8000-000000000002",
    ] {
        call(
            &registry,
            &db,
            "create_record",
            json!({"id":person,"type":"Entity","kind":"person","name":person}),
        )
        .await;
    }
    for (person, polarity, stance) in [
        (
            "a7718002-0000-4000-8000-000000000001",
            "affirmed",
            "2026-08-01T00:00:00Z",
        ),
        (
            "a7718002-0000-4000-8000-000000000002",
            "denied",
            "2026-08-02T00:00:00Z",
        ),
        (
            "a7718002-0000-4000-8000-000000000001",
            "affirmed",
            "2026-08-03T00:00:00Z",
        ),
    ] {
        let mut args = assessment_args(&bearer, target.clone());
        args["subject"] = json!({"kind":"person_record","record_id":person});
        args["polarity"] = json!(polarity);
        args["relation"] = json!("endorses");
        args["stance_as_of"] = json!(stance);
        call(&registry, &db, "create_attribution", args).await;
    }
    let read = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer,"limit":2,"offset":0}),
    )
    .await;
    assert_eq!(read["attribution_count"], 3);
    assert_eq!(read["attributions"].as_array().unwrap().len(), 2);
    let second = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer,"limit":2,"offset":2}),
    )
    .await;
    assert_eq!(second["attribution_count"], 3);
    assert_eq!(second["attributions"].as_array().unwrap().len(), 1);
    let all = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    let subjects: Vec<_> = all["attributions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|claim| claim["assertion"]["attributed_subject"]["ref"].clone())
        .collect();
    assert!(subjects.contains(&json!("a7718002-0000-4000-8000-000000000001")));
    assert!(subjects.contains(&json!("a7718002-0000-4000-8000-000000000002")));
    db.close().await;
}

#[tokio::test]
async fn passage_validation_relocates_then_conflicts_without_reanchoring() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000015",
        Some("before unique phrase after"),
    )
    .await;
    let target = body_target(
        &db,
        &bearer,
        "passage",
        json!([{"type":"text_quote","exact":"unique phrase","prefix":"before ","suffix":" after"}]),
    )
    .await;
    let source_event = target["source_event_id"].clone();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
    call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": bearer, "body": "moved before unique phrase after",
            "if_body_digest": current_body_digest(&registry, &db, &bearer).await
        }),
    )
    .await;
    let relocated = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(
        relocated["attributions"][0]["target"]["validation"]["status"],
        "relocated"
    );
    assert_eq!(
        relocated["attributions"][0]["target"]["source_event_id"],
        source_event
    );
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": bearer,
            "body": "before unique phrase after / before unique phrase after",
            "if_body_digest": current_body_digest(&registry, &db, &bearer).await
        }),
    )
    .await;
    let conflict = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(
        conflict["attributions"][0]["target"]["validation"]["status"],
        "conflict"
    );
    db.close().await;
}

#[tokio::test]
async fn retraction_successor_and_later_evidence_are_append_only() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000011",
        Some("A claim target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
    let first = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target.clone()),
    )
    .await
    .unwrap();
    let first_id = first["annotation_id"].as_str().unwrap();
    let first_boundary: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    call(
        &registry,
        &db,
        "manage_attributions",
        json!({"action":"add_evidence","annotation_id":first_id,"evidence":{
            "role":"basis","action_attestation_id":first["action_attestation_id"]
        }}),
    )
    .await;
    let mut successor_args = assessment_args(&bearer, target);
    successor_args["successor_of"] = json!(first_id);
    let successor = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        successor_args,
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "manage_attributions",
        json!({"action":"retract","annotation_id":first_id,"reason":"The original assessment resolved the subject incorrectly."}),
    )
    .await;
    let read = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    let original = read["attributions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["annotation_id"] == first_id)
        .unwrap();
    assert_eq!(
        original["retraction"]["reason"],
        "The original assessment resolved the subject incorrectly."
    );
    assert_eq!(original["successor_ids"][0], successor["annotation_id"]);
    assert_eq!(original["evidence"][0]["role"], "basis");
    let explanation = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer,"limit":0,"explain_annotation_id":first_id}),
    )
    .await;
    assert!(explanation["attributions"].as_array().unwrap().is_empty());
    assert_eq!(explanation["explanation"]["complete"], true);
    assert_eq!(
        explanation["explanation"]["claim"]["lifecycle_state"],
        "retracted"
    );
    assert_eq!(
        explanation["explanation"]["claim"]["supersession_state"],
        "has_successors"
    );
    assert_eq!(
        explanation["explanation"]["claim"]["successor_ids"][0],
        successor["annotation_id"]
    );
    assert_eq!(
        explanation["explanation"]["claim"]["subject"]["kind"],
        "agent_execution"
    );
    assert_eq!(
        explanation["explanation"]["claim"]["relation"],
        "expresses_view"
    );
    assert_eq!(
        explanation["explanation"]["claim"]["rationale"],
        "The agent assesses that the exact revision represents its own synthesized view."
    );
    assert_eq!(
        explanation["explanation"]["authoring_evidence_visibility"],
        "complete"
    );
    let historical = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer,"as_of_event_seq":first_boundary}),
    )
    .await;
    assert_eq!(historical["attribution_count"], 1);
    assert!(historical["attributions"][0]["retraction"].is_null());
    assert!(historical["attributions"][0]["successor_ids"]
        .as_array()
        .unwrap()
        .is_empty());
    db.close().await;
}

#[tokio::test]
async fn attribution_is_hidden_from_ordinary_children_search_and_query() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000008",
        Some("Hidden interpretation target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
    let created = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target),
    )
    .await
    .unwrap();
    let root = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[native_ce::schema::ROOT_RECORD_ID]}),
    )
    .await;
    assert!(!root["records"][0]["children"]
        .as_array()
        .unwrap()
        .iter()
        .any(|child| child["id"] == created["annotation_id"]));
    let query = call(
        &registry,
        &db,
        "query_record",
        json!({"steps":[{"step":"filter","kinds":["attribution"]}]}),
    )
    .await;
    assert_eq!(query["total"], 0);
    let direct = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[created["annotation_id"]]}),
    )
    .await;
    assert_eq!(direct["records"][0]["status"], "not_found");
    let search = call(
        &registry,
        &db,
        "search",
        json!({"query":"Attribution claim"}),
    )
    .await;
    assert!(!search.to_string().contains(
        created["annotation_id"]
            .as_str()
            .expect("created attribution id")
    ));
    let annotation_id = created["annotation_id"].as_str().unwrap();
    for (tool, arguments) in [
        ("render_record", json!({"id":annotation_id})),
        ("get_history", json!({"record_id":annotation_id})),
        (
            "whats_changed",
            json!({"scope_record_id":annotation_id,"limit":1000}),
        ),
        (
            "render_record_version_diff",
            json!({"record_id":annotation_id,"before_seq":1}),
        ),
    ] {
        let error = call_as(&registry, &db, Caller::local(), tool, arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exist"), "{tool}: {error}");
        assert!(!error.contains("Attribution claim"), "{tool}: {error}");
    }
    for (tool, arguments) in [
        ("get_history", json!({"limit":1000})),
        ("whats_changed", json!({"after_local_seq":0,"limit":1000})),
    ] {
        let output = call(&registry, &db, tool, arguments).await;
        let serialized = output.to_string();
        assert!(!serialized.contains(annotation_id), "{tool} leaked the id");
        assert!(
            !serialized.contains("attribution.target.bound.v1")
                && !serialized.contains("attribution.asserted.v1")
                && !serialized.contains("attribution.evidence.added.v1"),
            "{tool} leaked attribution event types"
        );
    }
    let visible_bearer = native_ce::query::sql::query_sql(
        &db,
        &Caller::local(),
        &format!("SELECT id FROM records WHERE id='{bearer}'"),
    )
    .await
    .unwrap();
    assert_eq!(visible_bearer.rows.len(), 1);
    for (relation, statement) in [
        (
            "records",
            format!(
                "SELECT id,type,kind,name FROM records WHERE id='{annotation_id}' OR kind='attribution'"
            ),
        ),
        (
            "content_events",
            format!(
                "SELECT record_id,type FROM content_events WHERE record_id='{annotation_id}' OR type LIKE 'attribution.%'"
            ),
        ),
        (
            "links",
            format!(
                "SELECT source_id,target_id,relationship FROM links WHERE source_id='{annotation_id}' OR target_id='{annotation_id}'"
            ),
        ),
        (
            "facet_values",
            format!("SELECT record_id,key FROM facet_values WHERE record_id='{annotation_id}'"),
        ),
        (
            "facet_observations",
            format!(
                "SELECT record_id,key FROM facet_observations WHERE record_id='{annotation_id}'"
            ),
        ),
    ] {
        let result = native_ce::query::sql::query_sql(&db, &Caller::local(), &statement)
            .await
            .unwrap();
        assert!(result.rows.is_empty(), "query_sql leaked through {relation}");
    }
    let dedicated = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    assert_eq!(dedicated["attribution_count"], 1);
    db.close().await;
}

#[tokio::test]
async fn authorization_is_non_disclosing_and_denied_mutations_are_atomic() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000020",
        Some("Private interpretation target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("private-agent");
    let created = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target.clone()),
    )
    .await
    .unwrap();
    let annotation_id = created["annotation_id"].as_str().unwrap();
    replace_explicit_policy(
        &db,
        "private-attribution-policy",
        &bearer,
        vec![AllowEntry::account("acct:alice", Capability::Edit)],
    )
    .await
    .unwrap();
    let denied = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let content_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let attestations_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
            .fetch_one(db.pool())
            .await
            .unwrap();

    let read_error = call_as(
        &registry,
        &db,
        denied.clone(),
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(read_error, "read_attributions: bearer does not exist");

    let create_error = call_as(
        &registry,
        &db,
        denied.clone(),
        "create_attribution",
        assessment_args(&bearer, target),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!create_error.contains("Private interpretation target"));

    for arguments in [
        json!({"action":"add_evidence","annotation_id":annotation_id,"evidence":{
            "role":"basis","action_attestation_id":created["action_attestation_id"]
        }}),
        json!({"action":"retract","annotation_id":annotation_id,"reason":"unauthorized"}),
    ] {
        let error = call_as(
            &registry,
            &db,
            denied.clone(),
            "manage_attributions",
            arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not exist"));
        assert!(!error.contains("a7718000-0000-4000-8000-000000000020"));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        content_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM provenance_action_attestations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        attestations_before
    );
    db.close().await;
}

#[tokio::test]
async fn hidden_evidence_is_unknown_or_withheld_without_leaking_its_reference() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let evidence_record = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id":"a7718000-0000-4000-8000-000000000009","type":"Document","kind":"note",
            "name":"Hidden evidence output","body":"private evidence body"
        }),
    )
    .await;
    let evidence_attestation = evidence_record["action_attestation_ids"][0]
        .as_str()
        .unwrap()
        .to_string();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000025",
        Some("Visible target."),
    )
    .await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("hidden-evidence-agent");
    let mut args = assessment_args(
        &bearer,
        body_target(&db, &bearer, "whole_revision", json!([])).await,
    );
    args["evidence"] = json!([{
        "role":"basis","action_attestation_id":evidence_attestation
    }]);
    let created = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        args,
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "hidden-evidence-policy",
        "a7718000-0000-4000-8000-000000000009",
        vec![AllowEntry::account("evidence-owner", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "visible-bearer-policy",
        &bearer,
        vec![AllowEntry::account("observer", Capability::View)],
    )
    .await
    .unwrap();
    let read = call_as(
        &registry,
        &db,
        Caller::authenticated("observer"),
        "read_attributions",
        json!({
            "bearer_id":bearer,
            "explain_annotation_id":created["annotation_id"]
        }),
    )
    .await
    .unwrap();
    assert!(read["attributions"][0]["evidence"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(read["attributions"][0]["evidence_count"], 0);
    assert_eq!(read["attributions"][0]["evidence_complete"], false);
    assert_eq!(
        read["interpretation"]["groups"][0]["exact_review_state"],
        "unknown_or_withheld"
    );
    assert!(read["interpretation"]["groups"][0]["evidence_classes"]
        .as_array()
        .unwrap()
        .contains(&json!("unknown_or_withheld")));
    assert_eq!(
        read["explanation"]["evidence_visibility"],
        "unknown_or_withheld"
    );
    assert!(read["explanation"]["evidence"]
        .as_array()
        .unwrap()
        .is_empty());
    let serialized = serde_json::to_string(&read).unwrap();
    assert!(!serialized.contains(&evidence_attestation));
    assert!(!serialized.contains("private evidence body"));
    let generic = call_as(
        &registry,
        &db,
        Caller::authenticated("observer"),
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
    )
    .await
    .unwrap();
    assert_eq!(
        generic["records"][0]["interpretation"]["groups"][0]["exact_review_state"],
        "unknown_or_withheld"
    );
    let generic_serialized = serde_json::to_string(&generic).unwrap();
    assert!(!generic_serialized.contains(&evidence_attestation));
    assert!(!generic_serialized.contains("private evidence body"));
    db.close().await;
}

#[tokio::test]
async fn generic_request_claim_cap_is_global_and_non_disclosing() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let first = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000005",
        Some("First bounded target."),
    )
    .await;
    let second = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000006",
        Some("Second bounded target."),
    )
    .await;
    let first_target = body_target(&db, &first, "whole_revision", json!([])).await;
    let second_target = body_target(&db, &second, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("generic-cap-agent");
    let mut annotation_ids = Vec::new();
    for (bearer, target) in [(&first, &first_target), (&second, &second_target)] {
        for _ in 0..51 {
            let created = call_as(
                &registry,
                &db,
                agent_caller(&issuer, bearer),
                "create_attribution",
                assessment_args(bearer, target.clone()),
            )
            .await
            .unwrap();
            annotation_ids.push(created["annotation_id"].as_str().unwrap().to_string());
        }
    }

    let generic = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids":[first,second],
            "resolve":false,
            "include_interpretation":true
        }),
    )
    .await;
    for record in generic["records"].as_array().unwrap() {
        let projection = &record["interpretation"];
        assert!(projection["attribution_count"].is_null());
        assert_eq!(projection["complete"], false);
        assert!(projection["groups"].as_array().unwrap().is_empty());
        assert!(projection["limitations"]
            .as_array()
            .unwrap()
            .contains(&json!("request_claim_set_exceeds_bounded_projection_limit")));
    }
    let serialized = generic.to_string();
    assert!(annotation_ids
        .iter()
        .all(|annotation_id| !serialized.contains(annotation_id)));
    db.close().await;
}

#[tokio::test]
async fn per_claim_evidence_overflow_bounds_raw_projection_and_explanation_work() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let evidence_attestations = create_evidence_attestations(
        &registry,
        &db,
        "a7718e01",
        (native_ce::attribution::MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM + 1) as usize,
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000016",
        Some("Bounded interpretation target."),
    )
    .await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("overflow-agent");
    let mut args = assessment_args(
        &bearer,
        body_target(&db, &bearer, "whole_revision", json!([])).await,
    );
    args["evidence"] = Value::Array(
        evidence_attestations
            .iter()
            .map(|attestation| json!({"role":"basis","action_attestation_id":attestation}))
            .collect(),
    );
    let created = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        args,
    )
    .await
    .unwrap();

    let raw = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer,"limit":1}),
    )
    .await;
    assert_eq!(
        raw["attributions"][0]["evidence_count"],
        native_ce::attribution::MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM
    );
    assert_eq!(raw["attributions"][0]["evidence_complete"], false);
    assert_eq!(
        raw["attributions"][0]["evidence"].as_array().unwrap().len() as i64,
        native_ce::attribution::MAX_ATTRIBUTION_EVIDENCE_PER_CLAIM
    );
    assert_eq!(raw["interpretation"]["complete"], false);
    assert!(raw["interpretation"]["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!("claim_evidence_exceeds_bounded_projection_limit")));

    let explained = call(
        &registry,
        &db,
        "read_attributions",
        json!({
            "bearer_id":bearer,
            "limit":0,
            "explain_annotation_id":created["annotation_id"]
        }),
    )
    .await;
    assert!(explained["attributions"].as_array().unwrap().is_empty());
    assert_eq!(explained["explanation"]["complete"], false);
    assert_eq!(
        explained["explanation"]["evidence_visibility"],
        "unknown_or_withheld"
    );
    assert_eq!(
        explained["explanation"]["authoring_evidence_visibility"],
        "unknown_or_withheld"
    );
    assert!(explained["explanation"]["authoring_attestation"].is_null());
    assert!(explained["explanation"]["evidence"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(explained["explanation"]["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!("claim_evidence_exceeds_bounded_explanation_limit")));
    assert!(explained["explanation"]["claim"]["evidence_classes"]
        .as_array()
        .unwrap()
        .contains(&json!("unknown_or_withheld")));
    let serialized = serde_json::to_string(&explained).unwrap();
    assert!(evidence_attestations
        .iter()
        .all(|attestation| !serialized.contains(attestation)));
    let generic = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
    )
    .await;
    assert!(generic["records"][0]["interpretation"]["attribution_count"].is_null());
    assert_eq!(generic["records"][0]["interpretation"]["complete"], false);
    assert!(generic["records"][0]["interpretation"]["groups"]
        .as_array()
        .unwrap()
        .is_empty());
    let generic_serialized = generic.to_string();
    assert!(evidence_attestations
        .iter()
        .all(|attestation| !generic_serialized.contains(attestation)));
    db.close().await;
}

#[tokio::test]
async fn total_evidence_overflow_stops_projection_before_any_inspection() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let evidence_attestations = create_evidence_attestations(&registry, &db, "a7718e02", 29).await;
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000024",
        Some("Bounded aggregate target."),
    )
    .await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("total-overflow-agent");
    for _ in 0..9 {
        let mut args = assessment_args(
            &bearer,
            body_target(&db, &bearer, "whole_revision", json!([])).await,
        );
        args["evidence"] = Value::Array(
            evidence_attestations
                .iter()
                .map(|attestation| json!({"role":"basis","action_attestation_id":attestation}))
                .collect(),
        );
        call_as(
            &registry,
            &db,
            agent_caller(&issuer, &bearer),
            "create_attribution",
            args,
        )
        .await
        .unwrap();
    }

    let read = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":bearer,"limit":0}),
    )
    .await;
    assert!(read["attributions"].as_array().unwrap().is_empty());
    assert_eq!(read["interpretation"]["complete"], false);
    assert!(read["interpretation"]["groups"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(read["interpretation"]["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!("evidence_set_exceeds_bounded_projection_limit")));
    // No evidence rows were loaded into the response and the inspection phase
    // was never entered for the over-limit projection.
    let serialized = serde_json::to_string(&read).unwrap();
    assert!(evidence_attestations
        .iter()
        .all(|attestation| !serialized.contains(attestation)));
    let generic = call(
        &registry,
        &db,
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
    )
    .await;
    let projection = &generic["records"][0]["interpretation"];
    assert!(projection["attribution_count"].is_null());
    assert_eq!(projection["complete"], false);
    assert!(projection["groups"].as_array().unwrap().is_empty());
    assert!(projection["limitations"]
        .as_array()
        .unwrap()
        .contains(&json!(
            "request_evidence_set_exceeds_bounded_projection_limit"
        )));
    let generic_serialized = generic.to_string();
    assert!(evidence_attestations
        .iter()
        .all(|attestation| !generic_serialized.contains(attestation)));
    db.close().await;
}

#[tokio::test]
async fn generic_lifecycle_cannot_retarget_rekind_or_delete_attribution() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000010",
        Some("Immutable target."),
    )
    .await;
    let other = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000014",
        Some("Other target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
    let created = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        assessment_args(&bearer, target),
    )
    .await
    .unwrap();
    let id = created["annotation_id"].as_str().unwrap();
    assert!(append(
        &db,
        AppendSpec {
            record_id: "raw-attribution".into(),
            event_type: "record.created".into(),
            payload: json!({
                "type":"Annotation","kind":"attribution","name":"Raw bypass",
                "home_id":native_ce::schema::ROOT_RECORD_ID
            }),
            actor: Some("raw-test".into()),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("atomic attribution aggregate"));
    assert!(append(
        &db,
        AppendSpec {
            record_id: id.into(),
            event_type: "attribution.retracted.v1".into(),
            payload: json!({"retraction_id":"a7718000-0000-4000-8000-000000000021","reason":"bypass"}),
            actor: Some("raw-test".into()),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("aggregate-owned"));
    for (tool, args) in [
        ("update_record", json!({"id":id,"kind":"note"})),
        (
            "manage_links",
            json!({"action":"remove","source_id":id,"target_id":bearer,"relationship":"part_of"}),
        ),
        (
            "manage_links",
            json!({"action":"add","source_id":id,"target_id":other,"relationship":"part_of"}),
        ),
        (
            "delete_record",
            json!({"id":id,"reason":"try to erase history"}),
        ),
    ] {
        assert!(
            call_as(&registry, &db, Caller::local(), tool, args)
                .await
                .is_err(),
            "{tool} bypassed attribution lifecycle"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn projection_failure_rolls_back_the_whole_aggregate_and_attestation() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id":"a7718000-0000-4000-8000-000000000023","type":"Entity","kind":"person","name":"Rollback person"
        }),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('a7718000-0000-4000-8000-000000000023','account','local',1)",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000022",
        Some("Rollback target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    sqlx::query(
        "CREATE TRIGGER fail_attribution_evidence BEFORE INSERT ON attribution_evidence
         BEGIN SELECT RAISE(ABORT,'injected attribution evidence failure'); END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let arguments = json!({
        "id":"a7718000-0000-4000-8000-000000000013","idempotency_key":"rollback-declaration","bearer_id":bearer,"target":target,
        "subject":{"kind":"self_person"},"relation":"endorses",
        "polarity":"affirmed","transformation":"none",
        "rationale":"This aggregate is expected to fail during evidence projection."
    });
    let issuer = native_ce::provenance::ProvenanceInteractionTokenIssuer::random("structured-ui");
    let scope = native_ce::provenance::verified_action_scope("create_attribution", &arguments);
    let token = issuer.issue("local", &scope, 60).unwrap();
    let caller = Caller::local()
        .with_attribution_declaration_token(&issuer, &token, &arguments)
        .unwrap();
    let error = registry
        .call(db.clone(), caller, "create_attribution", arguments)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("injected attribution evidence failure"));
    for table in [
        "records",
        "attribution_targets",
        "attribution_assertions",
        "attribution_evidence",
    ] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {}='a7718000-0000-4000-8000-000000000013'",
            if table == "records" {
                "id"
            } else {
                "annotation_id"
            }
        ))
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let attestations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_outputs m JOIN content_events e ON e.id=m.output_event_id WHERE m.output_domain='content' AND e.record_id='a7718000-0000-4000-8000-000000000013'",
    )
    .fetch_one(db.pool()).await.unwrap();
    assert_eq!(attestations, 0);
    db.close().await;
}

#[tokio::test]
async fn attestation_failure_rolls_back_all_attribution_content() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        "a7718000-0000-4000-8000-000000000001",
        Some("Attestation rollback target."),
    )
    .await;
    let target = body_target(&db, &bearer, "whole_revision", json!([])).await;
    sqlx::query(
        "CREATE TRIGGER fail_attribution_attestation BEFORE INSERT ON provenance_action_attestations
         WHEN NEW.operation='create_attribution'
         BEGIN SELECT RAISE(ABORT,'injected action attestation failure'); END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("rollback-agent");
    let error = call_as(
        &registry,
        &db,
        agent_caller(&issuer, &bearer),
        "create_attribution",
        {
            let mut args = assessment_args(&bearer, target);
            args["id"] = json!("a7718001-0000-4000-8000-000000000001");
            args
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("injected action attestation failure"));
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id='a7718001-0000-4000-8000-000000000001'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(events, 0);
    let projections: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribution_assertions WHERE annotation_id='a7718001-0000-4000-8000-000000000001'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(projections, 0);
    db.close().await;
}
