use native_ce::authorization::{
    effective_capability, replace_explicit_policy, AllowEntry, Capability, Principal,
};
use native_ce::conformance::rebuild_and_diff;
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const SENDER_ACCOUNT: &str = "acct_sender";
const RECIPIENT_ACCOUNT: &str = "acct_recipient";
const THIRD_ACCOUNT: &str = "acct_third";
// Record ids must be canonical v4/v7 UUIDs, so the person records are pinned
// literals whose counters keep the readable slugs' relative sort order
// (principal-only < recipient < sender < third). The account, principal,
// statement and mention identifiers in this file are not record ids and stay
// readable.
const PRINCIPAL_ONLY_PERSON: &str = "17e70000-0000-4000-8000-000000000001";
const RECIPIENT_PERSON: &str = "17e70000-0000-4000-8000-000000000002";
const SENDER_PERSON: &str = "17e70000-0000-4000-8000-000000000003";
const THIRD_PERSON: &str = "17e70000-0000-4000-8000-000000000004";
const SENDER_PRINCIPAL: &str = "native/sender";
const RECIPIENT_PRINCIPAL: &str = "native/recipient";
const THIRD_PRINCIPAL: &str = "native/third";
const DISCLOSURE_PREVIEW: &str =
    "Launch confirmation for Monday, addressed to the intended recipient.";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn install_people(db: &Db) {
    for (record_id, principal, account) in [
        (SENDER_PERSON, SENDER_PRINCIPAL, SENDER_ACCOUNT),
        (RECIPIENT_PERSON, RECIPIENT_PRINCIPAL, RECIPIENT_ACCOUNT),
        (THIRD_PERSON, THIRD_PRINCIPAL, THIRD_ACCOUNT),
    ] {
        create_raw_record(
            db,
            json!({"id":record_id,"type":"Entity","kind":"person","name":record_id}),
        )
        .await
        .unwrap();
        for (system, identifier) in [("native-principal", principal), ("account", account)] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,1)",
            )
            .bind(record_id)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(db).await)
            .await
            .unwrap();
        }
    }
}

async fn bind_policy(registry: &ToolRegistry, db: &Db, disposition: &str) -> String {
    let source = call(
        registry,
        db,
        SENDER_ACCOUNT,
        "create_record",
        json!({
            "type":"Document",
            "kind":"escalation-policy",
            "name":"Agent escalation policy",
            "body":serde_json::to_string(&json!({
                "format":"native.escalation-policy.v1",
                "issuer_principal_id":SENDER_PRINCIPAL,
                "statements":[{
                    "statement_id":"release-agent-send",
                    "kind":"hard_rule",
                    "scope":{"action.destination_kind":["same_workspace"]},
                    "when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},
                    "effect":{"disposition":disposition}
                }]
            })).unwrap()
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        registry,
        db,
        SENDER_ACCOUNT,
        "manage_instructions",
        json!({
            "action":"create_binding",
            "scope":"member",
            "source_record_id":source,
            "position":0,
            "idempotency_key":"bind-agent-policy",
            "reason":"Bind the principal's explicit policy source for this test."
        }),
    )
    .await
    .unwrap();
    source
}

async fn bind_policy_statements(
    registry: &ToolRegistry,
    db: &Db,
    key: &str,
    statements: Value,
) -> String {
    let source = call(
        registry,
        db,
        SENDER_ACCOUNT,
        "create_record",
        json!({
            "type":"Document",
            "kind":"escalation-policy",
            "name":format!("Policy {key}"),
            "body":serde_json::to_string(&json!({
                "format":"native.escalation-policy.v1",
                "issuer_principal_id":SENDER_PRINCIPAL,
                "statements":statements,
            })).unwrap()
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        registry,
        db,
        SENDER_ACCOUNT,
        "manage_instructions",
        json!({
            "action":"create_binding",
            "scope":"member",
            "source_record_id":source,
            "position":0,
            "idempotency_key":format!("bind-{key}"),
            "reason":"Bind the explicit policy validation fixture."
        }),
    )
    .await
    .unwrap();
    source
}

fn send_args(key: &str) -> Value {
    json!({
        "action":"send",
        "body":"We confirm the public launch will happen on Monday.",
        "preview":DISCLOSURE_PREVIEW,
        "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]},
        "addressed_to":[RECIPIENT_PERSON],
        "expectation":"reply",
        "idempotency_key":key,
        "reason":"Send the exact release update to its addressed reviewer."
    })
}

async fn inbox_principal_mention(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    message_id: &str,
) -> bool {
    let inbox = call(
        registry,
        db,
        account,
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":50}),
    )
    .await
    .unwrap();
    inbox["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["message_id"] == message_id)
        .expect("message is present in the recipient browse inbox")["mention"]["principal"]
        .as_bool()
        .unwrap()
}

#[tokio::test]
async fn generic_create_can_only_make_a_private_sender_draft() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let error = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "create_record",
        json!({
            "type":"Message",
            "kind":"text",
            "body":"bypass",
            "addressed_to":[RECIPIENT_PERSON],
            "facets":{"expectation":"none"}
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("sender-only Message draft"), "{error}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Message'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    let original = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"Recipient",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]},
            "addressed_to":[RECIPIENT_PERSON],
            "expectation":"none",
            "mentions":[{
                "mention_id":"draft-test-original-mention",
                "target_kind":"principal",
                "target_id":RECIPIENT_PERSON,
                "span_start":0,
                "span_end":9,
                "authored_label":"Recipient"
            }],
            "idempotency_key":"draft-test-original",
            "reason":"Create delivered mention awareness before a private correction draft."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let draft = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "create_record",
        json!({
            "type":"Message",
            "kind":"text",
            "body":"private draft",
            "addressed_to":[],
            "facets":{"expectation":"none"},
            "links":[{"target_id":&original,"relationship":"supersedes"}]
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        effective_capability(
            &db,
            Principal::bound(RECIPIENT_ACCOUNT, true),
            draft["id"].as_str().unwrap(),
        )
        .await
        .unwrap(),
        Capability::None
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT effective FROM message_mentions
              WHERE message_id=? AND mention_id='draft-test-original-mention'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1,
        "a sender-only superseding draft must not invalidate delivered mentions"
    );
    assert!(
        inbox_principal_mention(&registry, &db, RECIPIENT_ACCOUNT, &original).await,
        "the recipient inbox must retain mention awareness while the correction is private"
    );
    let share = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"share_history",
            "recipient_id":RECIPIENT_PERSON,
            "message_ids":[draft["id"]],
            "reason":"A private draft must not become deliverable through sharing."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(share.contains("undelivered draft"), "{share}");
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn blocking_send_requires_a_disclosure_safe_preview_before_any_append() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy(&registry, &db, "block_and_request_authority").await;
    let mut args = send_args("missing-preview");
    args.as_object_mut().unwrap().remove("preview");
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("disclosure-safe preview"), "{error}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Message'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn same_workspace_send_requires_a_canonical_local_recipient_account_for_every_disposition() {
    for disposition in [
        "silent_autonomy",
        "log_only",
        "notify_and_proceed",
        "block_and_request_authority",
    ] {
        let db = create_database(":memory:").await.unwrap();
        install_people(&db).await;
        create_raw_record(
            &db,
            json!({"id":PRINCIPAL_ONLY_PERSON,"type":"Entity","kind":"person","name":"Principal only"}),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,1)",
        )
        .bind(PRINCIPAL_ONLY_PERSON)
        .bind("native-principal")
        .bind("native/principal-only")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
        let registry = registry();
        bind_policy(&registry, &db, disposition).await;
        let mut args = send_args(&format!("local-account-{disposition}"));
        args["addressed_to"] = json!([PRINCIPAL_ONLY_PERSON]);
        let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("no canonical local account"), "{error}");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Message'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "{disposition}");
    }
}

#[tokio::test]
async fn blocked_draft_is_private_and_exact_authority_resumes_delivery_atomically() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let destination = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Launch channel"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let original = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"Recipient",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]},
            "addressed_to":[RECIPIENT_PERSON],
            "expectation":"none",
            "mentions":[{
                "mention_id":"original-recipient-mention",
                "target_kind":"principal",
                "target_id":RECIPIENT_PERSON,
                "span_start":0,
                "span_end":9,
                "authored_label":"Recipient"
            }],
            "idempotency_key":"original-before-blocked-correction",
            "reason":"Create delivered awareness that a blocked correction must not withdraw."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_candidates
              WHERE message_id=? AND reason='principal_mention' AND status='effective'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    let policy_source = bind_policy(&registry, &db, "block_and_request_authority").await;

    let mut correction_args = send_args("release-send-1");
    correction_args["body"] = json!("Recipient: We confirm the launch timing.");
    correction_args["home_id"] = json!(&destination);
    correction_args["mentions"] = json!([{
        "mention_id":"blocked-correction-recipient-mention",
        "target_kind":"principal",
        "target_id":RECIPIENT_PERSON,
        "span_start":0,
        "span_end":9,
        "authored_label":"Recipient"
    }]);
    correction_args["links"] = json!([{"target_id":&original,"relationship":"supersedes"}]);
    let correction_retry_args = correction_args.clone();
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        correction_args,
    )
    .await
    .unwrap();
    assert_eq!(blocked["delivery"]["status"], "blocked");
    assert_eq!(blocked["delivery"]["delivered"], false);
    assert!(call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({"action":"list_destinations"}),
    )
    .await
    .unwrap()["destinations"]
        .as_array()
        .unwrap()
        .is_empty());
    let message_id = blocked["id"].as_str().unwrap();
    let intervention_id = blocked["delivery"]["intervention_id"].as_str().unwrap();
    assert_eq!(
        effective_capability(&db, Principal::bound(RECIPIENT_ACCOUNT, true), message_id,)
            .await
            .unwrap(),
        Capability::None
    );
    let recipient_audience: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_audiences WHERE message_id=? AND principal_id=?",
    )
    .bind(message_id)
    .bind(RECIPIENT_PRINCIPAL)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(recipient_audience, 0);
    let blocked_candidates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidates
          WHERE message_id=? AND recipient_account_id=? AND status='effective'",
    )
    .bind(message_id)
    .bind(RECIPIENT_ACCOUNT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(blocked_candidates, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_candidates
              WHERE message_id=? AND reason='principal_mention' AND status='effective'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1,
        "a blocked correction must not withdraw delivered awareness"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT effective FROM message_mentions
              WHERE message_id=? AND mention_id='original-recipient-mention'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1,
        "a blocked superseding Message must not invalidate delivered mentions"
    );
    assert!(
        inbox_principal_mention(&registry, &db, RECIPIENT_ACCOUNT, &original).await,
        "blocked correction must not change recipient mention state"
    );
    let share_error = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"share_history",
            "recipient_id":RECIPIENT_PERSON,
            "message_ids":[message_id],
            "reason":"Attempt to share a blocked draft through the history path."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(share_error.contains("undelivered draft"), "{share_error}");
    let sender_view = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        sender_view.contains("intervention unavailable"),
        "{sender_view}"
    );

    let view = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    assert_eq!(view["action"], "get");
    assert_eq!(view["state"]["execution"]["state"], "blocked");
    assert_eq!(view["state"]["obligation"]["state"], "open");
    assert_eq!(view["trigger"]["summary"], DISCLOSURE_PREVIEW);
    assert!(view["policy_explanation"].get("trace").is_none());
    assert!(!view["policy_explanation"]
        .to_string()
        .contains(&policy_source));
    assert!(view["identity"]["canonical_url"]
        .as_str()
        .unwrap()
        .contains("/interventions/"));
    assert_eq!(
        view["guard_tokens"]["expected_intervention_seq"],
        view["projection_seq"]
    );
    assert_eq!(
        view["guard_tokens"]["expected_evaluation_digest"],
        blocked["delivery"]["evaluation_digest"]
    );
    assert_eq!(view["action_snapshot"]["requested_outcome"], "authority");
    assert_eq!(
        view["action_snapshot"]["action_digest"],
        blocked["delivery"]["action_digest"]
    );
    assert_eq!(
        view["request"]["action_digest"],
        view["action_snapshot"]["action_digest"]
    );
    let rendered_view = render::render("manage_interventions", &view).unwrap();
    assert!(
        rendered_view.starts_with(&format!("Intervention \"{intervention_id}\": \"blocked\".")),
        "{rendered_view}"
    );
    for expected in [
        "Cancel guard arguments:",
        "Resume-delivery guard arguments:",
        "Action controls:",
        "Frozen action:",
        "Identity:",
        "Trigger:",
        "Obligation state (independently live at read time):",
        "Policy explanation:",
        intervention_id,
        message_id,
        DISCLOSURE_PREVIEW,
        blocked["delivery"]["evaluation_digest"].as_str().unwrap(),
        blocked["delivery"]["action_digest"].as_str().unwrap(),
    ] {
        assert!(
            rendered_view.contains(expected),
            "missing {expected}: {rendered_view}"
        );
    }
    let blocked_for_paging = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("blocked-intervention-paging"),
    )
    .await
    .unwrap();
    let paging_intervention_id = blocked_for_paging["delivery"]["intervention_id"]
        .as_str()
        .unwrap();
    let target_query = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"query","execution":"blocked","limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(target_query["action"], "query");
    assert_eq!(target_query["execution"], "blocked");
    assert_eq!(target_query["limit"], 1);
    assert_eq!(target_query["count"], 1);
    assert_eq!(
        target_query["items"][0]["identity"]["intervention_id"],
        paging_intervention_id
    );
    assert_eq!(target_query["has_more"], true);
    assert!(target_query["next_cursor"].as_str().is_some());
    assert_eq!(target_query["candidate_scan_limit"], 200);
    assert_eq!(target_query["candidate_window_returned"], 3);
    assert_eq!(target_query["candidates_evaluated"], 2);
    assert_eq!(target_query["scan_limit_reached"], false);
    assert_eq!(target_query["query_basis"], "live_at_each_page_read");
    let rendered_target_query = render::render("manage_interventions", &target_query).unwrap();
    for expected in [
        "Intervention query returned 1 live viewer-relative item(s).",
        "Page controls:",
        "Next query arguments:",
        "Compact query row:",
        "Get full current view with arguments:",
        "Pages are evaluated live; this is not a frozen cross-page snapshot.",
        paging_intervention_id,
        target_query["next_cursor"].as_str().unwrap(),
    ] {
        assert!(
            rendered_target_query.contains(expected),
            "missing {expected}: {rendered_target_query}"
        );
    }
    let target_query_next = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"query",
            "execution":"blocked",
            "limit":1,
            "cursor":target_query["next_cursor"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(target_query_next["action"], "query");
    assert_eq!(target_query_next["execution"], "blocked");
    assert_eq!(target_query_next["limit"], 1);
    assert_eq!(target_query_next["count"], 1);
    assert_eq!(
        target_query_next["items"][0]["identity"]["intervention_id"],
        intervention_id
    );
    assert_eq!(target_query_next["has_more"], false);
    assert!(target_query_next["next_cursor"].is_null());
    assert_eq!(target_query_next["candidate_window_returned"], 2);
    assert_eq!(target_query_next["candidates_evaluated"], 2);
    assert_eq!(target_query_next["scan_limit_reached"], false);
    assert_eq!(target_query_next["query_basis"], "live_at_each_page_read");
    let rendered_target_query_next =
        render::render("manage_interventions", &target_query_next).unwrap();
    assert!(
        rendered_target_query_next.contains(intervention_id),
        "{rendered_target_query_next}"
    );
    assert!(
        rendered_target_query_next.contains(
            "No continuation cursor was issued; raised candidates below this page boundary were exhausted at this live read."
        ),
        "{rendered_target_query_next}"
    );
    let sender_query = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_interventions",
        json!({"action":"query","execution":"blocked"}),
    )
    .await
    .unwrap();
    assert_eq!(sender_query["action"], "query");
    assert_eq!(sender_query["execution"], "blocked");
    assert_eq!(sender_query["limit"], 25);
    assert_eq!(sender_query["count"], 0);
    assert_eq!(sender_query["has_more"], false);
    assert!(sender_query["next_cursor"].is_null());
    assert_eq!(sender_query["candidate_scan_limit"], 200);
    assert_eq!(sender_query["candidate_window_returned"], 0);
    assert_eq!(sender_query["candidates_evaluated"], 0);
    assert_eq!(sender_query["scan_limit_reached"], false);
    assert_eq!(sender_query["query_basis"], "live_at_each_page_read");
    let wrong_decision = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "create_record",
        json!({
            "type":"Resolution",
            "kind":"decision",
            "name":"Sender cannot approve for recipient",
            "body":"This is not recipient authority."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let wrong = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"resume_delivery",
            "intervention_id":intervention_id,
            "expected_intervention_seq":view["projection_seq"],
            "expected_evaluation_digest":blocked["delivery"]["evaluation_digest"],
            "authority_evidence_record_id":wrong_decision,
            "idempotency_key":"wrong-release-authority",
            "reason":"Attempt with authority authored by the wrong principal."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(wrong.contains("target-authored"), "{wrong}");
    let decision = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "create_record",
        json!({
            "type":"Resolution",
            "kind":"decision",
            "name":"Approve exact launch Message",
            "body":"Approved for this exact send only."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resumed = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"resume_delivery",
            "intervention_id":intervention_id,
            "expected_intervention_seq":view["projection_seq"],
            "expected_evaluation_digest":blocked["delivery"]["evaluation_digest"],
            "authority_evidence_record_id":decision,
            "idempotency_key":"resume-release-send-1",
            "reason":"The principal approved this exact draft and recipient set."
        }),
    )
    .await
    .unwrap();
    assert_eq!(resumed["action"], "resume_delivery");
    assert_eq!(resumed["state"]["execution"]["state"], "resumed");
    assert_eq!(resumed["write_receipt"]["status"], "resumed");
    assert_eq!(resumed["write_receipt"]["replayed"], false);
    assert_eq!(
        resumed["write_receipt"]["terminal_event"]["record_id"],
        message_id
    );
    assert_eq!(
        resumed["write_receipt"]["terminal_event"]["type"],
        "intervention.execution_resumed.v1"
    );
    assert_eq!(
        resumed["write_receipt"]["terminal_event"]["seq"],
        resumed["projection_seq"]
    );
    assert!(resumed["write_receipt"]["terminal_event"]["event_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(resumed["write_receipt"]["delivery_event_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert_eq!(
        resumed["write_receipt"]["transition"]["basis_kind"],
        "authority_evidence"
    );
    assert_eq!(
        resumed["write_receipt"]["transition"]["basis_record_id"],
        decision
    );
    assert_eq!(
        resumed["write_receipt"]["transition"]["action_digest"],
        blocked["delivery"]["action_digest"]
    );
    assert_eq!(
        resumed["write_receipt"]["transition"]["delivery_event_id"],
        resumed["write_receipt"]["delivery_event_id"]
    );
    assert_eq!(
        resumed["write_receipt"]["terminal_event"]["record_id"],
        resumed["trigger"]["message_id"]
    );
    assert_eq!(
        resumed["write_receipt"]["terminal_event"]["seq"],
        resumed["projection_seq"]
    );
    assert_eq!(
        resumed["write_receipt"]["transition"]["idempotency_key"],
        "resume-release-send-1"
    );
    assert_eq!(
        resumed["write_receipt"]["transition"]["summary"],
        "The principal approved this exact draft and recipient set."
    );
    assert!(
        resumed["write_receipt"]["transition"]["fresh_evaluation_digest"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty())
    );
    let rendered_resumed = render::render("manage_interventions", &resumed).unwrap();
    for expected in [
        "Intervention resume_delivery write receipt: applied.",
        "Terminal event:",
        "Transition:",
        "intervention.execution_resumed.v1",
        resumed["write_receipt"]["terminal_event"]["event_id"]
            .as_str()
            .unwrap(),
        resumed["write_receipt"]["delivery_event_id"]
            .as_str()
            .unwrap(),
        decision.as_str(),
        "resume-release-send-1",
    ] {
        assert!(
            rendered_resumed.contains(expected),
            "missing {expected}: {rendered_resumed}"
        );
    }
    let mut saturated_resumed = resumed.clone();
    saturated_resumed["write_receipt"]["transition"]["summary"] = json!("w".repeat(40_000));
    saturated_resumed["trigger"]["summary"] = json!("t".repeat(40_000));
    saturated_resumed["reason"]["summary"] = json!("r".repeat(40_000));
    saturated_resumed["action_snapshot"]["action"]["disclosure_preview"] =
        json!("a".repeat(40_000));
    let saturated_text = render::render("manage_interventions", &saturated_resumed).unwrap();
    assert!(saturated_text.len() < 30_000, "{}", saturated_text.len());
    assert!(saturated_text.contains("Exact response remains in structuredContent"));
    let destinations = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({"action":"list_destinations"}),
    )
    .await
    .unwrap();
    assert!(
        destinations["destinations"].as_array().unwrap().is_empty(),
        "resuming a direct-context Message must not turn its filing home into a destination"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT effective FROM message_mentions
              WHERE message_id=? AND mention_id='original-recipient-mention'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0,
        "authorized delivery applies the superseding mention invalidation"
    );
    let authorized_awareness_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidate_events
          WHERE source_event_type='message.delivery.authorized.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(authorized_awareness_events, 3);
    let resumed_retry = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"resume_delivery",
            "intervention_id":intervention_id,
            "expected_intervention_seq":view["projection_seq"],
            "expected_evaluation_digest":blocked["delivery"]["evaluation_digest"],
            "authority_evidence_record_id":decision,
            "idempotency_key":"resume-release-send-1",
            "reason":"The principal approved this exact draft and recipient set."
        }),
    )
    .await
    .unwrap();
    assert_eq!(resumed_retry["action"], "resume_delivery");
    assert_eq!(resumed_retry["projection_seq"], resumed["projection_seq"]);
    assert_eq!(resumed_retry["write_receipt"]["status"], "resumed");
    assert_eq!(resumed_retry["write_receipt"]["replayed"], true);
    assert_eq!(
        resumed_retry["write_receipt"]["terminal_event"],
        resumed["write_receipt"]["terminal_event"]
    );
    assert_eq!(
        resumed_retry["write_receipt"]["delivery_event_id"],
        resumed["write_receipt"]["delivery_event_id"]
    );
    assert_eq!(
        resumed_retry["write_receipt"]["transition"],
        resumed["write_receipt"]["transition"]
    );
    let rendered_resumed_retry = render::render("manage_interventions", &resumed_retry).unwrap();
    assert!(
        rendered_resumed_retry.starts_with(
            "Intervention resume_delivery write receipt: idempotent replay; no new write was performed by this call."
        ),
        "{rendered_resumed_retry}"
    );
    assert!(
        rendered_resumed_retry.contains(
            resumed["write_receipt"]["terminal_event"]["event_id"]
                .as_str()
                .unwrap()
        ),
        "{rendered_resumed_retry}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM awareness_events
              WHERE subject_account_id=? AND destination_id=? AND lane='destination'",
        )
        .bind(SENDER_ACCOUNT)
        .bind(&destination)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0,
        "a direct-context resume and its retry must never mutate the Collection destination rail"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT effective FROM message_mentions
              WHERE message_id=? AND mention_id='original-recipient-mention'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0,
        "resume retry must leave the one-time invalidation stable"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_candidate_events
              WHERE source_event_type='message.delivery.authorized.v1'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        authorized_awareness_events,
        "resume retry must not duplicate delivery awareness effects"
    );
    assert_eq!(resumed["state"]["obligation"]["state"], "open");
    let resumed_obligations: Vec<(String, String)> = sqlx::query_as(
        "SELECT source_event_type,status FROM notification_candidates
          WHERE message_id=? AND recipient_account_id=? AND reason='human_obligation'",
    )
    .bind(message_id)
    .bind(RECIPIENT_ACCOUNT)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        resumed_obligations,
        vec![(
            "message.delivery.authorized.v1".to_string(),
            "effective".to_string()
        )]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_candidates
              WHERE message_id=? AND reason='principal_mention' AND status='effective'",
        )
        .bind(message_id)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_candidates
              WHERE message_id=? AND status='effective'",
        )
        .bind(&original)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0,
        "authorized correction must withdraw prior delivered awareness"
    );
    assert!(
        !inbox_principal_mention(&registry, &db, RECIPIENT_ACCOUNT, &original).await,
        "authorized superseding delivery must clear recipient mention state"
    );
    assert!(
        effective_capability(&db, Principal::bound(RECIPIENT_ACCOUNT, true), message_id,)
            .await
            .unwrap()
            .allows(Capability::View)
    );
    let delivery_and_resume: Vec<String> = sqlx::query_scalar(
        "SELECT type FROM content_events WHERE record_id=?
          AND type IN ('message.delivery.authorized.v1','intervention.execution_resumed.v1')
          ORDER BY seq",
    )
    .bind(message_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        delivery_and_resume,
        vec![
            "message.delivery.authorized.v1".to_string(),
            "intervention.execution_resumed.v1".to_string()
        ]
    );
    let send_retry = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        correction_retry_args,
    )
    .await
    .unwrap();
    assert_eq!(send_retry["delivery"]["status"], "delivered");
    assert_eq!(send_retry["delivery"]["execution"], "resumed");
    assert_eq!(send_retry["delivery"]["delivered"], true);
    call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"Acknowledged; I will review it.",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]},
            "addressed_to":[SENDER_PERSON],
            "expectation":"none",
            "links":[{"target_id":message_id,"relationship":"reply_to"}],
            "idempotency_key":"reply-release-send-1",
            "reason":"Reply to the now-delivered Message."
        }),
    )
    .await
    .unwrap();
    let satisfied = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    assert_eq!(satisfied["action"], "get");
    assert_eq!(satisfied["state"]["execution"]["state"], "resumed");
    assert_eq!(satisfied["state"]["obligation"]["state"], "satisfied");
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.delivery_event_id','orphaned-delivery')
          WHERE record_id=? AND type='intervention.execution_resumed.v1'",
    )
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let malformed = rebuild_and_diff(&db).await.unwrap_err().to_string();
    assert!(
        malformed.contains("references no earlier delivery event"),
        "{malformed}"
    );
    let delivery_event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events
          WHERE record_id=? AND type='message.delivery.authorized.v1'",
    )
    .bind(message_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.delivery_event_id',?)
          WHERE record_id=? AND type='intervention.execution_resumed.v1'",
    )
    .bind(delivery_event_id)
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.fresh_evaluation_digest',?)
          WHERE record_id=? AND type='intervention.execution_resumed.v1'",
    )
    .bind("0".repeat(64))
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let mismatched_fresh_digest = rebuild_and_diff(&db).await.unwrap_err().to_string();
    assert!(
        mismatched_fresh_digest.contains("contradicts its authorized delivery event"),
        "{mismatched_fresh_digest}"
    );
    let fresh_digest: String = sqlx::query_scalar(
        "SELECT json_extract(payload,'$.fresh_evaluation_digest') FROM content_events
          WHERE record_id=? AND type='message.delivery.authorized.v1'",
    )
    .bind(message_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.fresh_evaluation_digest',?)
          WHERE record_id=? AND type='intervention.execution_resumed.v1'",
    )
    .bind(fresh_digest)
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.intended_recipients[0].principal','native/forged')
          WHERE record_id=? AND type='intervention.raised.v1'",
    )
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let contradictory = rebuild_and_diff(&db).await.unwrap_err().to_string();
    assert!(
        contradictory.contains("contradicts its earlier send evaluation"),
        "{contradictory}"
    );
}

#[tokio::test]
async fn replay_rejects_tampered_policy_traces_and_disclosure_action_facts() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy(&registry, &db, "silent_autonomy").await;
    let sent = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("tamper-send"),
    )
    .await
    .unwrap();
    let message_id = sent["id"].as_str().unwrap();
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.policy_trace.final_disposition','log_only')
          WHERE record_id=? AND type='message.send_evaluated.v1'",
    )
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let trace_error = rebuild_and_diff(&db).await.unwrap_err().to_string();
    assert!(
        trace_error.contains("evaluation digest mismatch"),
        "{trace_error}"
    );
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,
                '$.policy_trace.final_disposition','silent_autonomy',
                '$.action.disclosure_preview','forged preview')
          WHERE record_id=? AND type='message.send_evaluated.v1'",
    )
    .bind(message_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let action_error = rebuild_and_diff(&db).await.unwrap_err().to_string();
    assert!(
        action_error.contains("action facts or digest are inconsistent"),
        "{action_error}"
    );
}

#[tokio::test]
async fn unclassified_free_form_uses_notify_default_and_send_is_idempotent() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("notify-default-1"),
    )
    .await
    .unwrap();
    assert_eq!(first["delivery"]["status"], "delivered");
    assert_eq!(first["delivery"]["disposition"], "notify_and_proceed");
    assert_eq!(
        first["delivery"]["policy_trace"]["semantic_boundary"],
        "free-form prose is unclassified; only registry-derived structure and the typed send operation are deterministic"
    );
    let intervention_id = first["delivery"]["intervention_id"].as_str().unwrap();
    let open = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    assert_eq!(open["state"]["execution"]["state"], "proceeded");
    assert_eq!(open["state"]["obligation"]["state"], "open");
    call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "create_record",
        json!({
            "type":"Message",
            "kind":"text",
            "body":"A private reply draft is not delivery evidence.",
            "addressed_to":[],
            "facets":{"expectation":"none"},
            "links":[{"target_id":first["id"],"relationship":"reply_to"}]
        }),
    )
    .await
    .unwrap();
    let still_open = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    assert_eq!(still_open["state"]["obligation"]["state"], "open");
    call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"Reply evidence without any execution transition.",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]},
            "addressed_to":[SENDER_PERSON],
            "expectation":"none",
            "links":[{"target_id":first["id"],"relationship":"reply_to"}],
            "idempotency_key":"notify-default-reply",
            "reason":"Satisfy the recipient-relative reply expectation."
        }),
    )
    .await
    .unwrap();
    let satisfied = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    assert_eq!(satisfied["state"]["execution"]["state"], "proceeded");
    assert_eq!(satisfied["state"]["obligation"]["state"], "satisfied");
    let retry = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("notify-default-1"),
    )
    .await
    .unwrap();
    assert_eq!(retry["id"], first["id"]);
    assert_eq!(retry["delivery"]["idempotent_retry"], true);
    assert_eq!(
        retry["delivery"]["intervention_id"],
        first["delivery"]["intervention_id"]
    );
}

#[tokio::test]
async fn unverifiable_agent_selectors_fail_closed_and_cannot_be_spoofed() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy_statements(
        &registry,
        &db,
        "unverifiable-agent",
        json!([{
            "statement_id":"agent-only",
            "kind":"hard_rule",
            "scope":{"agent.id":["release-agent"]},
            "when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},
            "effect":{"disposition":"silent_autonomy"}
        }]),
    )
    .await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("unverifiable-agent-send"),
    )
    .await
    .unwrap();
    assert_eq!(blocked["delivery"]["status"], "blocked");
    assert!(blocked["delivery"]["policy_trace"]
        .to_string()
        .contains("unverifiable policy selector"));

    let mut spoofed = send_args("spoofed-agent-send");
    spoofed["agent_id"] = json!("release-agent");
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", spoofed)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field `agent_id`"), "{error}");
}

#[tokio::test]
async fn every_active_policy_statement_is_validated_before_matching() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy_statements(
        &registry,
        &db,
        "invalid-closed-schema",
        json!([
            {"statement_id":"unknown-scope","kind":"default","scope":{"unknown.field":["x"]},"effect":{"disposition":"log_only"}},
            {"statement_id":"nonmatching-invalid-predicate","kind":"hard_rule","scope":{"message.sender_principal_id":["never"]},"when":{"all":[{"field":"action.operation","op":"contains","value":"send"}]},"effect":{"disposition":"log_only"}},
            {"statement_id":"nonmatching-wrong-boolean","kind":"hard_rule","scope":{"message.sender_principal_id":["never"],"action.reversible":["false"]},"when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},"effect":{"disposition":"log_only"}},
            {"statement_id":"wrong-closed-value","kind":"hard_rule","scope":{},"when":{"all":[{"field":"action.operation","op":"eq","value":"email"}]},"effect":{"disposition":"log_only"}},
            {"statement_id":"list-equality","kind":"hard_rule","scope":{},"when":{"all":[{"field":"action.correspondent_principal_ids","op":"eq","value":"native/recipient"}]},"effect":{"disposition":"log_only"}},
            {"statement_id":"blank-identifier","kind":"default","scope":{"message.sender_principal_id":["  "]},"effect":{"disposition":"log_only"}},
            {"statement_id":"empty-set","kind":"default","scope":{"action.class":[]},"effect":{"disposition":"log_only"}},
            {"statement_id":"bad-effect","kind":"default","scope":{},"effect":{"disposition":"ship_it"}},
            {"statement_id":"duplicate","kind":"default","scope":{},"effect":{"disposition":"log_only"}},
            {"statement_id":"duplicate","kind":"default","scope":{},"effect":{"disposition":"log_only"}}
        ]),
    )
    .await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("invalid-policy-send"),
    )
    .await
    .unwrap();
    assert_eq!(
        blocked["delivery"]["disposition"],
        "block_and_request_authority"
    );
    let trace = blocked["delivery"]["policy_trace"].to_string();
    for expected in [
        "unsupported escalation policy field",
        "unsupported escalation predicate operator",
        "incompatible with that field's closed type",
        "incompatible with list field",
        "malformed default statement",
        "invalid_or_duplicate_statement_id",
    ] {
        assert!(trace.contains(expected), "missing {expected}: {trace}");
    }
}

#[tokio::test]
async fn frozen_target_principal_prevents_authority_transfer_but_allows_credential_rotation() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy(&registry, &db, "block_and_request_authority").await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("binding-drift-send"),
    )
    .await
    .unwrap();
    let intervention_id = blocked["delivery"]["intervention_id"].as_str().unwrap();
    let initial = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    let cancel_args = json!({
        "action":"cancel",
        "intervention_id":intervention_id,
        "expected_intervention_seq":initial["projection_seq"],
        "idempotency_key":"rotation-cancel",
        "reason":"Decline this delivery before rotating the local credential."
    });
    let cancelled = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        cancel_args.clone(),
    )
    .await
    .unwrap();

    sqlx::query("UPDATE bindings SET identifier='acct_recipient_rotated' WHERE record_id=? AND system='account' AND is_canonical=1")
        .bind(RECIPIENT_PERSON).execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    let rotated_retry = call(
        &registry,
        &db,
        "acct_recipient_rotated",
        "manage_interventions",
        cancel_args,
    )
    .await
    .unwrap();
    assert_eq!(rotated_retry["projection_seq"], cancelled["projection_seq"]);
    assert_eq!(rotated_retry["target"]["principal_id"], RECIPIENT_PRINCIPAL);

    sqlx::query("UPDATE bindings SET identifier='native/rebound' WHERE record_id=? AND system='native-principal' AND is_canonical=1")
        .bind(RECIPIENT_PERSON).execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    let drift = call(
        &registry,
        &db,
        "acct_recipient_rotated",
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(drift.contains("intervention unavailable"), "{drift}");
}

#[tokio::test]
async fn send_idempotency_is_scoped_to_the_frozen_sender_principal() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("shared-principal-key"),
    )
    .await
    .unwrap();
    let mut second_args = send_args("shared-principal-key");
    second_args["addressed_to"] = json!([SENDER_PERSON]);
    let second = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_messages",
        second_args,
    )
    .await
    .unwrap();
    assert_ne!(first["id"], second["id"]);
}

#[tokio::test]
async fn silent_and_log_policies_deliver_without_interventions() {
    for disposition in ["silent_autonomy", "log_only"] {
        let db = create_database(":memory:").await.unwrap();
        install_people(&db).await;
        let registry = registry();
        bind_policy(&registry, &db, disposition).await;
        let mut args = send_args(&format!("{disposition}-send"));
        args["origin"] = json!({
            "type":"direct",
            "participant_ids":[SENDER_PERSON,RECIPIENT_PERSON,THIRD_PERSON]
        });
        args["addressed_to"] = json!([RECIPIENT_PERSON, THIRD_PERSON]);
        let sent = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
            .await
            .unwrap();
        assert_eq!(sent["delivery"]["status"], "delivered");
        assert!(sent["delivery"]["intervention_id"].is_null());
    }
}

#[tokio::test]
async fn intervention_producing_multi_recipient_send_is_rejected_atomically() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let mut args = send_args("multi-notify-rejected");
    args["origin"] = json!({
        "type":"direct",
        "participant_ids":[SENDER_PERSON,RECIPIENT_PERSON,THIRD_PERSON]
    });
    args["addressed_to"] = json!([RECIPIENT_PERSON, THIRD_PERSON]);
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("exactly one recipient"), "{error}");
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Message'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(messages, 0);
}

#[tokio::test]
async fn conflicting_hard_rules_fail_closed() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy_statements(
        &registry,
        &db,
        "hard-conflict",
        json!([
            {"statement_id":"allow","kind":"hard_rule","scope":{},"when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},"effect":{"disposition":"silent_autonomy"}},
            {"statement_id":"block","kind":"hard_rule","scope":{},"when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},"effect":{"disposition":"block_and_request_authority"}}
        ]),
    )
    .await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("hard-conflict-send"),
    )
    .await
    .unwrap();
    assert_eq!(blocked["delivery"]["status"], "blocked");
    assert!(blocked["delivery"]["policy_trace"]
        .to_string()
        .contains("hard_rule_conflict"));
}

#[tokio::test]
async fn cancellation_is_guarded_idempotent_and_cannot_unlock_history_sharing() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy(&registry, &db, "block_and_request_authority").await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("cancelled-send"),
    )
    .await
    .unwrap();
    let message_id = blocked["id"].as_str().unwrap();
    let intervention_id = blocked["delivery"]["intervention_id"].as_str().unwrap();
    let view = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap();
    assert_eq!(view["action"], "get");
    assert_eq!(
        view["guard_tokens"]["expected_intervention_seq"],
        view["projection_seq"]
    );
    assert_eq!(
        view["guard_tokens"]["expected_evaluation_digest"],
        blocked["delivery"]["evaluation_digest"]
    );
    let stale = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"cancel",
            "intervention_id":intervention_id,
            "expected_intervention_seq":1,
            "idempotency_key":"cancelled-send-stale",
            "reason":"Attempt with a stale projection."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(stale.contains("stale projection"), "{stale}");
    let args = json!({
        "action":"cancel",
        "intervention_id":intervention_id,
        "expected_intervention_seq":view["projection_seq"],
        "idempotency_key":"cancelled-send-once",
        "reason":"The recipient declines this exact delivery."
    });
    let cancelled = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(cancelled["action"], "cancel");
    assert_eq!(cancelled["write_receipt"]["status"], "cancelled");
    assert_eq!(cancelled["write_receipt"]["replayed"], false);
    assert_eq!(
        cancelled["write_receipt"]["terminal_event"]["record_id"],
        message_id
    );
    assert_eq!(
        cancelled["write_receipt"]["terminal_event"]["type"],
        "intervention.cancelled.v1"
    );
    assert_eq!(
        cancelled["write_receipt"]["terminal_event"]["seq"],
        cancelled["projection_seq"]
    );
    assert!(cancelled["write_receipt"]["terminal_event"]["event_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(cancelled["write_receipt"]["delivery_event_id"].is_null());
    assert_eq!(
        cancelled["write_receipt"]["transition"]["action_digest"],
        blocked["delivery"]["action_digest"]
    );
    assert_eq!(
        cancelled["write_receipt"]["transition"]["idempotency_key"],
        "cancelled-send-once"
    );
    assert_eq!(
        cancelled["write_receipt"]["transition"]["reason"],
        "The recipient declines this exact delivery."
    );
    assert_eq!(
        cancelled["write_receipt"]["transition"]["evidence_refs"],
        json!([])
    );
    assert_eq!(
        cancelled["write_receipt"]["terminal_event"]["record_id"],
        cancelled["trigger"]["message_id"]
    );
    assert_eq!(
        cancelled["write_receipt"]["terminal_event"]["seq"],
        cancelled["projection_seq"]
    );
    let rendered_cancelled = render::render("manage_interventions", &cancelled).unwrap();
    for expected in [
        "Intervention cancel write receipt: applied.",
        "Terminal event:",
        "Transition:",
        "intervention.cancelled.v1",
        cancelled["write_receipt"]["terminal_event"]["event_id"]
            .as_str()
            .unwrap(),
        blocked["delivery"]["action_digest"].as_str().unwrap(),
        "cancelled-send-once",
        "The recipient declines this exact delivery.",
    ] {
        assert!(
            rendered_cancelled.contains(expected),
            "missing {expected}: {rendered_cancelled}"
        );
    }
    let retry = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        args,
    )
    .await
    .unwrap();
    assert_eq!(retry["action"], "cancel");
    assert_eq!(cancelled["projection_seq"], retry["projection_seq"]);
    assert_eq!(retry["state"]["execution"]["state"], "cancelled");
    assert_eq!(retry["write_receipt"]["status"], "cancelled");
    assert_eq!(retry["write_receipt"]["replayed"], true);
    assert_eq!(
        retry["write_receipt"]["terminal_event"],
        cancelled["write_receipt"]["terminal_event"]
    );
    assert_eq!(
        retry["write_receipt"]["transition"],
        cancelled["write_receipt"]["transition"]
    );
    assert!(retry["write_receipt"]["delivery_event_id"].is_null());
    let rendered_retry = render::render("manage_interventions", &retry).unwrap();
    assert!(
        rendered_retry.starts_with(
            "Intervention cancel write receipt: idempotent replay; no new write was performed by this call."
        ),
        "{rendered_retry}"
    );
    assert!(
        rendered_retry.contains(
            cancelled["write_receipt"]["terminal_event"]["event_id"]
                .as_str()
                .unwrap()
        ),
        "{rendered_retry}"
    );
    let share = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"share_history",
            "recipient_id":RECIPIENT_PERSON,
            "message_ids":[message_id],
            "reason":"A cancelled draft must remain undisclosed."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(share.contains("undelivered draft"), "{share}");
}

#[tokio::test]
async fn intervention_lookup_and_target_failures_share_one_unavailable_response() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    bind_policy(&registry, &db, "block_and_request_authority").await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        send_args("unavailable-shape"),
    )
    .await
    .unwrap();
    let intervention_id = blocked["delivery"]["intervention_id"].as_str().unwrap();
    let unavailable_get = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await
    .unwrap_err()
    .to_string();
    let missing_get = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":"missing"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(unavailable_get, missing_get);
    for action in ["cancel", "resume_delivery"] {
        let mut existing = json!({
            "action":action,
            "intervention_id":intervention_id,
            "expected_intervention_seq":1,
            "idempotency_key":format!("unavailable-{action}"),
            "reason":"Exercise the normalized unavailable response."
        });
        if action == "resume_delivery" {
            existing["expected_evaluation_digest"] =
                blocked["delivery"]["evaluation_digest"].clone();
            existing["authority_evidence_record_id"] = json!("irrelevant");
        }
        let mut missing = existing.clone();
        missing["intervention_id"] = json!("missing");
        let target_error = call(
            &registry,
            &db,
            SENDER_ACCOUNT,
            "manage_interventions",
            existing,
        )
        .await
        .unwrap_err()
        .to_string();
        let missing_error = call(
            &registry,
            &db,
            SENDER_ACCOUNT,
            "manage_interventions",
            missing,
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(target_error, missing_error, "{action}");
        assert!(target_error.contains("intervention unavailable"));
    }
}

/// Create the Collection a channel post is filed in, granting the sender the
/// Edit the home guard requires and a third account the View that the post must
/// inherit rather than reassert.
async fn channel(registry: &ToolRegistry, db: &Db) -> String {
    let folder = call(
        registry,
        db,
        SENDER_ACCOUNT,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Launch channel"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    replace_explicit_policy(
        db,
        "test:policy",
        &folder,
        vec![
            AllowEntry::account(SENDER_ACCOUNT, Capability::Edit),
            AllowEntry::account(THIRD_ACCOUNT, Capability::View),
        ],
    )
    .await
    .unwrap();
    folder
}

fn channel_post_args(key: &str, home_id: &str) -> Value {
    json!({
        "action":"send",
        "body":"The launch channel now has a Monday date.",
        "origin":{"type":"collection","collection_id":home_id},
        "addressed_to":[],
        "expectation":"none",
        "home_id":home_id,
        "idempotency_key":key,
        "reason":"Post the launch date to the channel without tasking anybody."
    })
}

async fn message_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Message'")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn channel_post_delivers_without_recipients_and_inherits_collection_visibility() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db).await;
    let posted = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        channel_post_args("channel-post-1", &folder),
    )
    .await
    .unwrap();
    let message_id = posted["id"].as_str().unwrap();
    assert_eq!(posted["delivery"]["status"], "delivered");
    assert_eq!(posted["delivery"]["disposition"], "notify_and_proceed");
    // The evaluation still ran against the sender and the typed send: what an
    // unaddressed post drops is the intervention leg that needs a target person.
    assert!(posted["delivery"]["intervention_id"].is_null());
    assert_eq!(
        posted["delivery"]["policy_trace"]["final_disposition"],
        "notify_and_proceed"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM record_policies WHERE record_id=?")
            .bind(message_id)
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0,
        "a channel post must not seal itself away from its Collection"
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(message_id)
            .fetch_one(db.pool())
            .await
            .unwrap()
            .unwrap(),
        folder
    );
    assert_eq!(
        effective_capability(&db, Principal::bound(THIRD_ACCOUNT, true), message_id)
            .await
            .unwrap(),
        Capability::View
    );
    assert_eq!(
        effective_capability(&db, Principal::bound(RECIPIENT_ACCOUNT, true), message_id)
            .await
            .unwrap(),
        Capability::None
    );
    // Nobody is addressed, so nobody carries an obligation and no candidate is
    // proposed: the silence is the defined outcome, not an accident.
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM message_audiences
              WHERE message_id=? AND source='addressed_to'"
        )
        .bind(message_id)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_candidates WHERE message_id=?"
        )
        .bind(message_id)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
    let retry = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        channel_post_args("channel-post-1", &folder),
    )
    .await
    .unwrap();
    assert_eq!(retry["id"], posted["id"]);
    assert_eq!(retry["delivery"]["idempotent_retry"], true);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn unaddressed_send_without_an_origin_is_still_refused() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let mut args = channel_post_args("no-home", "unused");
    args.as_object_mut().unwrap().remove("home_id");
    args.as_object_mut().unwrap().remove("origin");
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing field `origin`"), "{error}");
    assert_eq!(message_count(&db).await, 0);
}

#[tokio::test]
async fn channel_post_requires_the_expectation_that_obliges_nobody() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db).await;
    let mut args = channel_post_args("obliging-channel-post", &folder);
    args["expectation"] = json!("reply");
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("expectation 'none'"), "{error}");
    assert_eq!(message_count(&db).await, 0);
}

#[tokio::test]
async fn channel_post_cannot_mention_a_principal_it_does_not_address() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db).await;
    let mut args = channel_post_args("mentioning-channel-post", &folder);
    args["body"] = json!("Recipient owns the launch date.");
    args["mentions"] = json!([{
        "mention_id":"channel-post-mention",
        "target_kind":"principal",
        "target_id":RECIPIENT_PERSON,
        "span_start":0,
        "span_end":9,
        "authored_label":"Recipient"
    }]);
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("must already be addressed"), "{error}");
    assert_eq!(message_count(&db).await, 0);
}

#[tokio::test]
async fn blocking_policy_refuses_a_channel_post_atomically() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db).await;
    bind_policy(&registry, &db, "block_and_request_authority").await;
    let mut args = channel_post_args("blocked-channel-post", &folder);
    args["preview"] = json!(DISCLOSURE_PREVIEW);
    let error = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("addresses nobody who could grant it"),
        "{error}"
    );
    assert_eq!(message_count(&db).await, 0);
}

#[tokio::test]
async fn addressed_send_into_a_collection_still_seals_to_its_audience() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db).await;
    let mut args = send_args("addressed-into-channel");
    args["home_id"] = json!(&folder);
    let sent = call(&registry, &db, SENDER_ACCOUNT, "manage_messages", args)
        .await
        .unwrap();
    let message_id = sent["id"].as_str().unwrap();
    assert_eq!(sent["delivery"]["status"], "delivered");
    assert!(sent["delivery"]["intervention_id"].is_string());
    assert_eq!(
        effective_capability(&db, Principal::bound(RECIPIENT_ACCOUNT, true), message_id)
            .await
            .unwrap(),
        Capability::View
    );
    assert_eq!(
        effective_capability(&db, Principal::bound(THIRD_ACCOUNT, true), message_id)
            .await
            .unwrap(),
        Capability::None,
        "addressing keeps sealing the Message to its audience, home or not"
    );
}
