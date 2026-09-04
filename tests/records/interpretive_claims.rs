// Record ids must be canonical v4/v7 UUIDs, so every `stress-*` fixture id here
// is a pinned `c1a10000-0000-4000-8000-<counter>` literal.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::interchange::{export_canonical_interchange, import_canonical_interchange};
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
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

async fn create(registry: &ToolRegistry, db: &Db, mut args: Value) -> Value {
    args.as_object_mut()
        .unwrap()
        .entry("reason")
        .or_insert_with(|| json!("Interpretive-claims conformance fixture"));
    call(registry, db, "create_record", args).await
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
        "source_event_id": row.try_get::<String, _>("id").unwrap(),
        "source_body_sha256": hex::encode(Sha256::digest(body.as_bytes())),
        "scope": scope,
        "selectors": selectors,
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
            "agent-executor:stress-agent:bounded-delegation",
            &ids,
            60,
        )
        .unwrap();
    Caller::local()
        .with_agent_executor_token(issuer, &token, "stress-agent", "bounded-delegation", &ids)
        .unwrap()
}

struct AssessmentDetails<'a> {
    relation: &'a str,
    polarity: &'a str,
    confidence: &'a str,
    transformation: &'a str,
    rationale: &'a str,
    stance_as_of: &'a str,
}

fn assessment(
    bearer: &str,
    target: Value,
    subject: Value,
    details: AssessmentDetails<'_>,
) -> Value {
    json!({
        "idempotency_key": format!("interpretive-stress-{}", uuid::Uuid::new_v4()),
        "bearer_id": bearer,
        "target": target,
        "subject": subject,
        "relation": details.relation,
        "polarity": details.polarity,
        "confidence": details.confidence,
        "transformation": details.transformation,
        "rationale": details.rationale,
        "stance_as_of": details.stance_as_of,
    })
}

async fn create_assessment(
    registry: &ToolRegistry,
    db: &Db,
    issuer: &native_ce::awareness::HumanInteractionTokenIssuer,
    args: Value,
) -> Value {
    let bearer = args["bearer_id"].as_str().unwrap().to_string();
    call_as(
        registry,
        db,
        agent_caller(issuer, &bearer),
        "create_attribution",
        args,
    )
    .await
    .unwrap()
}

fn query_filter(id: &str, hidden_kind: Option<&str>) -> Value {
    let mut filter = json!({"step":"filter","ids":[id]});
    if let Some(kind) = hidden_kind {
        filter["kinds"] = json!([kind]);
    }
    filter
}

async fn assert_surface_agreement(
    registry: &ToolRegistry,
    db: &Db,
    bearer: &str,
    hidden_kind: Option<&str>,
) -> Value {
    let dedicated = call(
        registry,
        db,
        "read_attributions",
        json!({"bearer_id":bearer}),
    )
    .await;
    let get = call(
        registry,
        db,
        "get_record",
        json!({"ids":[bearer],"resolve":false,"include_interpretation":true}),
    )
    .await;
    let query = call(
        registry,
        db,
        "query_record",
        json!({
            "steps":[query_filter(bearer, hidden_kind)],
            "limit":50,
            "include_interpretation":true
        }),
    )
    .await;
    let rendered = call(
        registry,
        db,
        "render_record",
        json!({"id":bearer,"include_interpretation":true}),
    )
    .await;
    let projection = &dedicated["interpretation"];
    assert_eq!(
        get["records"][0]["interpretation"], *projection,
        "get {bearer}"
    );
    assert_eq!(rendered["interpretation"], *projection, "render {bearer}");
    let queried = query["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == bearer)
        .unwrap_or_else(|| panic!("query omitted scenario bearer {bearer}"));
    assert_eq!(queried["interpretation"], *projection, "query {bearer}");

    let get_text = render::render("get_record", &get).unwrap();
    let query_text = render::render("query_record", &query).unwrap();
    let record_markdown = rendered["markdown"].as_str().unwrap();
    let status = projection["status"].as_str().unwrap();
    for text in [&get_text, &query_text] {
        assert!(
            text.contains(&format!("Interpretation: {status}")),
            "{bearer}: {text}"
        );
        assert!(text.contains("do not establish endorsement, truth, or consensus"));
        for group in projection["groups"].as_array().unwrap() {
            assert!(text.contains(group["headline"].as_str().unwrap()));
        }
    }
    assert!(record_markdown.contains("## Interpretation"));
    assert!(record_markdown.contains(&format!("Status: {status}")));
    assert!(record_markdown.contains("do not establish endorsement, truth, or consensus"));
    for group in projection["groups"].as_array().unwrap() {
        assert!(record_markdown.contains(group["headline"].as_str().unwrap()));
    }
    dedicated
}

fn assert_interpretation_only(projection: &Value) {
    let object = projection.as_object().unwrap();
    for forbidden in [
        "authorized",
        "behavioural_authority",
        "may_act",
        "may_publish",
        "permission",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "projection exposed {forbidden}"
        );
    }
    for limitation in [
        "delegation_does_not_establish_endorsement",
        "confidence_does_not_establish_truth",
        "claim_counts_do_not_establish_consensus",
    ] {
        assert!(projection["limitations"]
            .as_array()
            .unwrap()
            .contains(&json!(limitation)));
    }
}

#[tokio::test]
async fn domain_matrix_and_zero_claim_state_are_honest_across_every_read_surface() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("stress-domain-agent");

    create(
        &registry,
        &db,
        json!({"id":"c1a10000-0000-4000-8000-000000000011","type":"Entity","kind":"person","name":"Stress person"}),
    )
    .await;
    create(
        &registry,
        &db,
        json!({"id":"c1a10000-0000-4000-8000-000000000009","type":"WorkItem","kind":"task","name":"Legacy task","body":"Existing content with no attribution claim."}),
    )
    .await;
    let none =
        assert_surface_agreement(&registry, &db, "c1a10000-0000-4000-8000-000000000009", None)
            .await;
    assert_eq!(none["attribution_count"], 0);
    assert_eq!(none["interpretation"]["status"], "none");
    assert_eq!(none["interpretation"]["complete"], true);
    assert!(none["interpretation"]["groups"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_interpretation_only(&none["interpretation"]);

    for (id, record_type, kind, name, body) in [
        (
            "c1a10000-0000-4000-8000-000000000003",
            "Resolution",
            "decision",
            "Choose the durable protocol",
            "We will use the durable protocol.",
        ),
        (
            "c1a10000-0000-4000-8000-000000000013",
            "Resolution",
            "decision",
            "Recommendation: stage the rollout",
            "The recommendation is to stage the rollout.",
        ),
        (
            "c1a10000-0000-4000-8000-000000000007",
            "Document",
            "note",
            "Mixed-authorship analysis",
            "Human premise. Agent synthesis. Shared conclusion.",
        ),
        (
            "c1a10000-0000-4000-8000-000000000006",
            "Resolution",
            "rule",
            "Standing review guidance",
            "Ask for review before external publication.",
        ),
        (
            "c1a10000-0000-4000-8000-000000000005",
            "Document",
            "note",
            "External announcement draft",
            "Draft announcement for external readers; not yet authorized to publish.",
        ),
    ] {
        create(
            &registry,
            &db,
            json!({"id":id,"type":record_type,"kind":kind,"name":name,"body":body}),
        )
        .await;
    }
    create(
        &registry,
        &db,
        json!({
            "id":"c1a10000-0000-4000-8000-000000000001","type":"Annotation","kind":"comment","name":"",
            "body":"This passage needs a clearer qualifier.","lifecycle":"open",
            "links":[{"target_id":"c1a10000-0000-4000-8000-000000000007","relationship":"part_of"}]
        }),
    )
    .await;
    create(
        &registry,
        &db,
        json!({
            "id":"c1a10000-0000-4000-8000-000000000015","type":"Annotation","kind":"suggestion",
            "name":"Clarify the recommendation","body":"Stage the rollout after review.",
            "lifecycle":"open","facets":{"proposal.precondition":"none"},
            "links":[{"target_id":"c1a10000-0000-4000-8000-000000000013","relationship":"part_of"}]
        }),
    )
    .await;

    let person =
        || json!({"kind":"person_record","record_id":"c1a10000-0000-4000-8000-000000000011"});
    let agent = || json!({"kind":"self_agent_execution"});
    let scenarios = [
        (
            "c1a10000-0000-4000-8000-000000000003",
            agent(),
            "expresses_view",
            "synthesis",
            "agent_opinion",
            None,
        ),
        (
            "c1a10000-0000-4000-8000-000000000013",
            person(),
            "endorses",
            "summary",
            "assessed_human_stance",
            None,
        ),
        (
            "c1a10000-0000-4000-8000-000000000007",
            agent(),
            "expresses_view",
            "synthesis",
            "agent_opinion",
            None,
        ),
        (
            "c1a10000-0000-4000-8000-000000000001",
            agent(),
            "expresses_view",
            "selection",
            "agent_opinion",
            Some("comment"),
        ),
        (
            "c1a10000-0000-4000-8000-000000000015",
            agent(),
            "expresses_view",
            "paraphrase",
            "agent_opinion",
            Some("suggestion"),
        ),
        (
            "c1a10000-0000-4000-8000-000000000006",
            person(),
            "expresses_view",
            "selection",
            "assessed_human_stance",
            None,
        ),
        (
            "c1a10000-0000-4000-8000-000000000005",
            person(),
            "endorses",
            "summary",
            "assessed_human_stance",
            None,
        ),
    ];
    for (ordinal, (bearer, subject, relation, transformation, class, hidden_kind)) in
        scenarios.iter().enumerate()
    {
        let target = body_target(&db, bearer, "whole_revision", json!([])).await;
        create_assessment(
            &registry,
            &db,
            &issuer,
            assessment(
                bearer,
                target,
                subject.clone(),
                AssessmentDetails {
                    relation,
                    polarity: "affirmed",
                    confidence: "likely",
                    transformation,
                    rationale: "A bounded assessment for the adoption stress matrix.",
                    stance_as_of: &format!("2026-08-01T00:00:{ordinal:02}Z"),
                },
            ),
        )
        .await;
        let read = assert_surface_agreement(&registry, &db, bearer, *hidden_kind).await;
        assert_eq!(read["interpretation"]["status"], "current");
        assert_eq!(
            read["interpretation"]["groups"][0]["claims"][0]["claim_class"],
            *class
        );
        assert_interpretation_only(&read["interpretation"]);
    }

    let mixed_target = body_target(
        &db,
        "c1a10000-0000-4000-8000-000000000007",
        "passage",
        json!([{"type":"text_quote","exact":"Human premise","prefix":"","suffix":". Agent synthesis"}]),
    )
    .await;
    create_assessment(
        &registry,
        &db,
        &issuer,
        assessment(
            "c1a10000-0000-4000-8000-000000000007",
            mixed_target,
            person(),
            AssessmentDetails {
                relation: "expresses_view",
                polarity: "affirmed",
                confidence: "plausible",
                transformation: "paraphrase",
                rationale: "Only the exact human-premise passage is attributed to the person.",
                stance_as_of: "2026-08-02T00:00:00Z",
            },
        ),
    )
    .await;
    let mixed =
        assert_surface_agreement(&registry, &db, "c1a10000-0000-4000-8000-000000000007", None)
            .await;
    let subjects = mixed["interpretation"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["subject"]["kind"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(subjects.contains(&"person_record"));
    assert!(subjects.contains(&"agent_execution"));
    assert_eq!(mixed["attribution_count"], 2);
    assert_interpretation_only(&mixed["interpretation"]);

    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    assert!(native_ce::provenance::state_violations(&db)
        .await
        .unwrap()
        .is_empty());
    db.close().await;
}

#[tokio::test]
async fn direct_capture_later_confirmation_conflict_and_history_never_upgrade_assessments() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create(
        &registry,
        &db,
        json!({"id":"c1a10000-0000-4000-8000-000000000004","type":"Entity","kind":"person","name":"Stress declarer"}),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('c1a10000-0000-4000-8000-000000000004','account','local',1)",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    create(
        &registry,
        &db,
        json!({
            "id":"c1a10000-0000-4000-8000-000000000002","type":"Resolution","kind":"decision",
            "name":"Adopt the review rule","body":"Adopt the review rule for this exact revision."
        }),
    )
    .await;
    let target = body_target(
        &db,
        "c1a10000-0000-4000-8000-000000000002",
        "whole_revision",
        json!([]),
    )
    .await;
    let agent_issuer =
        native_ce::awareness::HumanInteractionTokenIssuer::random("stress-confirmation-agent");
    let first = create_assessment(
        &registry,
        &db,
        &agent_issuer,
        assessment(
            "c1a10000-0000-4000-8000-000000000002",
            target.clone(),
            json!({"kind":"person_record","record_id":"c1a10000-0000-4000-8000-000000000004"}),
            AssessmentDetails {
                relation: "endorses",
                polarity: "affirmed",
                confidence: "likely",
                transformation: "summary",
                rationale:
                    "An agent interprets a verified interaction; this remains an assessment.",
                stance_as_of: "2026-08-03T00:00:00Z",
            },
        ),
    )
    .await;
    let assessment_boundary: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let declaration_args = json!({
        "idempotency_key":"stress-later-exact-confirmation",
        "bearer_id":"c1a10000-0000-4000-8000-000000000002","target":target.clone(),
        "subject":{"kind":"self_person"},"relation":"endorses","polarity":"affirmed",
        "transformation":"none","stance_as_of":"2026-08-03T00:00:00Z",
        "rationale":"The authenticated person later used the exact structured gesture."
    });
    let human_issuer =
        native_ce::provenance::ProvenanceInteractionTokenIssuer::random("stress-structured-ui");
    let scope =
        native_ce::provenance::verified_action_scope("create_attribution", &declaration_args);
    let token = human_issuer.issue("local", &scope, 60).unwrap();
    let human_caller = Caller::local()
        .with_attribution_declaration_token(&human_issuer, &token, &declaration_args)
        .unwrap();
    let declaration = call_as(
        &registry,
        &db,
        human_caller.clone(),
        "create_attribution",
        declaration_args,
    )
    .await
    .unwrap();
    assert_eq!(declaration["claim_mode"], "declaration");

    let ordinary_declaration = call_as(
        &registry,
        &db,
        Caller::local(),
        "create_attribution",
        json!({
            "idempotency_key":"stress-forged-declaration",
            "bearer_id":"c1a10000-0000-4000-8000-000000000002","target":target.clone(),
            "subject":{"kind":"self_person"},"relation":"endorses","polarity":"affirmed",
            "transformation":"none","rationale":"Credential ownership alone must not declare."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(ordinary_declaration.contains("assessment requires ordinal confidence"));

    for polarity in ["affirmed", "denied"] {
        create_assessment(
            &registry,
            &db,
            &agent_issuer,
            assessment(
                "c1a10000-0000-4000-8000-000000000002",
                target.clone(),
                json!({"kind":"person_record","record_id":"c1a10000-0000-4000-8000-000000000004"}),
                AssessmentDetails {
                    relation: "endorses",
                    polarity,
                    confidence: "confident",
                    transformation: "selection",
                    rationale: "Conflicting agent assessments remain authored assessments.",
                    stance_as_of: "2026-08-04T00:00:00Z",
                },
            ),
        )
        .await;
    }
    let conflicted =
        assert_surface_agreement(&registry, &db, "c1a10000-0000-4000-8000-000000000002", None)
            .await;
    assert_eq!(conflicted["interpretation"]["status"], "conflicted");
    let claims = conflicted["interpretation"]["groups"][0]["claims"]
        .as_array()
        .unwrap();
    let declaration_claim = claims
        .iter()
        .find(|claim| claim["claim_class"] == "direct_declaration")
        .unwrap();
    assert_eq!(
        declaration_claim["exact_review_state"],
        "receiver_local_confirmed"
    );
    let declaration_evidence = declaration_claim["evidence_classes"].as_array().unwrap();
    assert!(declaration_evidence.contains(&json!("exact_target_confirmation")));
    assert!(
        claims
            .iter()
            .filter(|claim| claim["claim_class"] == "assessed_human_stance")
            .count()
            >= 2
    );
    assert_eq!(
        conflicted["interpretation"]["groups"][0]["exact_review_state"], "not_confirmed",
        "a prior exact declaration must not upgrade the later assessment frontier"
    );
    assert_interpretation_only(&conflicted["interpretation"]);

    let receipt_id: String = sqlx::query_scalar(
        "SELECT interaction_receipt_id FROM provenance_action_attestations WHERE id=?",
    )
    .bind(declaration["action_attestation_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DROP TRIGGER provenance_interaction_receipts_no_update")
        .execute(&write_pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE provenance_interaction_receipts
         SET sealed_evidence_ref='sealed://interpretive-stress-must-not-leak'
         WHERE id=?",
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
    let sealed = call_as(
        &registry,
        &db,
        human_caller.clone(),
        "read_attributions",
        json!({
            "bearer_id":"c1a10000-0000-4000-8000-000000000002",
            "explain_annotation_id":declaration["annotation_id"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        sealed["explanation"]["authoring_attestation"]["interaction"]["sealed_reference_recorded"],
        true
    );
    assert!(!sealed
        .to_string()
        .contains("sealed://interpretive-stress-must-not-leak"));

    let historical = call(
        &registry,
        &db,
        "read_attributions",
        json!({
            "bearer_id":"c1a10000-0000-4000-8000-000000000002",
            "as_of_event_seq":assessment_boundary
        }),
    )
    .await;
    assert_eq!(historical["attribution_count"], 1);
    assert_eq!(
        historical["interpretation"]["groups"][0]["claims"][0]["claim_class"],
        "assessed_human_stance"
    );
    assert_eq!(
        historical["interpretation"]["groups"][0]["exact_review_state"],
        "not_confirmed"
    );

    let mut successor_args = assessment(
        "c1a10000-0000-4000-8000-000000000002",
        target,
        json!({"kind":"person_record","record_id":"c1a10000-0000-4000-8000-000000000004"}),
        AssessmentDetails {
            relation: "endorses",
            polarity: "affirmed",
            confidence: "confident",
            transformation: "selection",
            rationale: "The corrected assessment succeeds the earlier bounded assessment.",
            stance_as_of: "2026-08-05T00:00:00Z",
        },
    );
    successor_args["successor_of"] = first["annotation_id"].clone();
    let successor = create_assessment(&registry, &db, &agent_issuer, successor_args).await;
    call(
        &registry,
        &db,
        "manage_attributions",
        json!({
            "action":"retract","annotation_id":first["annotation_id"],
            "reason":"The initial interpretation was too broad."
        }),
    )
    .await;
    let explanation = call_as(
        &registry,
        &db,
        human_caller,
        "read_attributions",
        json!({
            "bearer_id":"c1a10000-0000-4000-8000-000000000002",
            "limit":0,
            "explain_annotation_id":first["annotation_id"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        explanation["explanation"]["claim"]["lifecycle_state"],
        "retracted"
    );
    assert_eq!(
        explanation["explanation"]["claim"]["successor_ids"][0],
        successor["annotation_id"]
    );
    assert_interpretation_only(&explanation["interpretation"]);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    assert!(native_ce::provenance::state_violations(&db)
        .await
        .unwrap()
        .is_empty());
    db.close().await;
}

#[tokio::test]
async fn targets_hidden_evidence_import_and_current_invalidation_fail_closed() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let evidence = create(
        &registry,
        &db,
        json!({
            "id":"c1a10000-0000-4000-8000-000000000012","type":"Document","kind":"note",
            "name":"Private evidence","body":"Evidence body that must not be disclosed."
        }),
    )
    .await;
    let evidence_attestation = evidence["action_attestation_ids"][0]
        .as_str()
        .unwrap()
        .to_string();
    create(
        &registry,
        &db,
        json!({
            "id":"c1a10000-0000-4000-8000-000000000010","type":"Document","kind":"note",
            "name":"Passage target","body":"before unique governed phrase after"
        }),
    )
    .await;
    let target = body_target(
        &db,
        "c1a10000-0000-4000-8000-000000000010",
        "passage",
        json!([{
            "type":"text_quote","exact":"unique governed phrase",
            "prefix":"before ","suffix":" after"
        }]),
    )
    .await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("stress-private-agent");
    let mut args = assessment(
        "c1a10000-0000-4000-8000-000000000010",
        target,
        json!({"kind":"self_agent_execution"}),
        AssessmentDetails {
            relation: "expresses_view",
            polarity: "affirmed",
            confidence: "likely",
            transformation: "selection",
            rationale: "The assessment is bounded to one exact passage.",
            stance_as_of: "2026-08-06T00:00:00Z",
        },
    );
    args["evidence"] = json!([{
        "role":"basis","action_attestation_id":evidence_attestation
    }]);
    let created = create_assessment(&registry, &db, &issuer, args).await;

    replace_explicit_policy(
        &db,
        "stress-private-evidence-policy",
        "c1a10000-0000-4000-8000-000000000012",
        vec![AllowEntry::account("evidence-owner", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "stress-visible-passage-policy",
        "c1a10000-0000-4000-8000-000000000010",
        vec![AllowEntry::account("observer", Capability::View)],
    )
    .await
    .unwrap();
    let observer = call_as(
        &registry,
        &db,
        Caller::authenticated("observer"),
        "read_attributions",
        json!({
            "bearer_id":"c1a10000-0000-4000-8000-000000000010",
            "explain_annotation_id":created["annotation_id"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(observer["attributions"][0]["evidence_count"], 0);
    assert_eq!(observer["attributions"][0]["evidence_complete"], false);
    assert_eq!(
        observer["interpretation"]["groups"][0]["exact_review_state"],
        "unknown_or_withheld"
    );
    let observer_json = observer.to_string();
    assert!(!observer_json.contains(&evidence_attestation));
    assert!(!observer_json.contains("Evidence body that must not be disclosed"));

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "c1a10000-0000-4000-8000-000000000010",
            "body": "moved before unique governed phrase after",
            "if_body_digest": current_body_digest(&registry, &db, "c1a10000-0000-4000-8000-000000000010").await
        }),
    )
    .await;
    let relocated = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":"c1a10000-0000-4000-8000-000000000010"}),
    )
    .await;
    assert_eq!(
        relocated["interpretation"]["groups"][0]["target"]["state"],
        "relocated"
    );
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id":"c1a10000-0000-4000-8000-000000000010",
            "body":"before unique governed phrase after / before unique governed phrase after",
            "if_body_digest": current_body_digest(&registry, &db, "c1a10000-0000-4000-8000-000000000010").await
        }),
    )
    .await;
    let conflicted = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":"c1a10000-0000-4000-8000-000000000010"}),
    )
    .await;
    assert_eq!(
        conflicted["interpretation"]["groups"][0]["target"]["state"],
        "conflict"
    );

    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    assert!(native_ce::provenance::state_violations(&db)
        .await
        .unwrap()
        .is_empty());
    let bytes = export_canonical_interchange(&db).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let imported = import_canonical_interchange(&bytes, &temp.path().join("stress-import.db"))
        .await
        .unwrap();
    let foreign = call(
        &registry,
        &imported,
        "read_attributions",
        json!({"bearer_id":"c1a10000-0000-4000-8000-000000000010"}),
    )
    .await;
    assert!(foreign["interpretation"]["groups"][0]["evidence_classes"]
        .as_array()
        .unwrap()
        .contains(&json!("foreign_unverified")));
    assert_ne!(
        foreign["interpretation"]["groups"][0]["exact_review_state"],
        "receiver_local_confirmed"
    );
    imported.close().await;

    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO provenance_attestation_validity_events
         (id,attestation_id,ordinal,status,reason,issuer,issued_at)
         VALUES(?,?,0,'invalidated','stress compromise','stress operator',?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&evidence_attestation)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&write_pool)
    .await
    .unwrap();
    let invalidated = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":"c1a10000-0000-4000-8000-000000000010"}),
    )
    .await;
    assert!(
        invalidated["interpretation"]["groups"][0]["evidence_classes"]
            .as_array()
            .unwrap()
            .contains(&json!("invalidated"))
    );
    assert_ne!(
        invalidated["interpretation"]["groups"][0]["exact_review_state"],
        "receiver_local_confirmed"
    );
    db.close().await;
}

#[tokio::test]
async fn failed_aggregate_preserves_prior_claim_and_replay_has_no_partial_attestation() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create(
        &registry,
        &db,
        json!({
            "id":"c1a10000-0000-4000-8000-000000000014","type":"Document","kind":"note",
            "name":"Rollback bearer","body":"One committed claim must survive a later failed aggregate."
        }),
    )
    .await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("stress-rollback-agent");
    let committed = create_assessment(
        &registry,
        &db,
        &issuer,
        assessment(
            "c1a10000-0000-4000-8000-000000000014",
            body_target(
                &db,
                "c1a10000-0000-4000-8000-000000000014",
                "whole_revision",
                json!([]),
            )
            .await,
            json!({"kind":"self_agent_execution"}),
            AssessmentDetails {
                relation: "expresses_view",
                polarity: "affirmed",
                confidence: "likely",
                transformation: "summary",
                rationale: "This aggregate commits before the injected failure.",
                stance_as_of: "2026-08-07T00:00:00Z",
            },
        ),
    )
    .await;
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "CREATE TRIGGER fail_stress_attribution_attestation
         BEFORE INSERT ON provenance_action_attestations
         WHEN NEW.operation='create_attribution'
         BEGIN SELECT RAISE(ABORT,'injected stress attestation failure'); END",
    )
    .execute(&write_pool)
    .await
    .unwrap();
    let mut failed_args = assessment(
        "c1a10000-0000-4000-8000-000000000014",
        body_target(
            &db,
            "c1a10000-0000-4000-8000-000000000014",
            "whole_revision",
            json!([]),
        )
        .await,
        json!({"kind":"self_agent_execution"}),
        AssessmentDetails {
            relation: "expresses_view",
            polarity: "denied",
            confidence: "plausible",
            transformation: "selection",
            rationale: "This aggregate must roll back with its attestation.",
            stance_as_of: "2026-08-08T00:00:00Z",
        },
    );
    failed_args["id"] = json!("c1a10000-0000-4000-8000-000000000008");
    let error = call_as(
        &registry,
        &db,
        agent_caller(&issuer, "c1a10000-0000-4000-8000-000000000014"),
        "create_attribution",
        failed_args,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("injected stress attestation failure"));
    for (table, id_column) in [
        ("records", "id"),
        ("attribution_targets", "annotation_id"),
        ("attribution_assertions", "annotation_id"),
        ("attribution_evidence", "annotation_id"),
    ] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {id_column}='c1a10000-0000-4000-8000-000000000008'"
        ))
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(count, 0, "partial row survived in {table}");
    }
    let membership_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_outputs membership
         JOIN content_events event ON event.id=membership.output_event_id
         WHERE membership.output_domain='content' AND event.record_id='c1a10000-0000-4000-8000-000000000008'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        membership_count, 0,
        "partial provenance membership survived"
    );
    let read = call(
        &registry,
        &db,
        "read_attributions",
        json!({"bearer_id":"c1a10000-0000-4000-8000-000000000014"}),
    )
    .await;
    assert_eq!(read["attribution_count"], 1);
    assert_eq!(
        read["attributions"][0]["annotation_id"],
        committed["annotation_id"]
    );
    assert_eq!(read["interpretation"]["status"], "current");
    sqlx::query("DROP TRIGGER fail_stress_attribution_attestation")
        .execute(&write_pool)
        .await
        .unwrap();
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    assert!(native_ce::provenance::state_violations(&db)
        .await
        .unwrap()
        .is_empty());
    db.close().await;
}
