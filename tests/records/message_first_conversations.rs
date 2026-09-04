use native_ce::authorization::{effective_capability, Capability, Principal};
use native_ce::conformance::rebuild_and_diff;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

// Record ids must be canonical v4/v7 UUIDs. These are pinned literals whose
// counter suffixes keep the same relative sort order the readable slugs had
// (dana < intruder < recipient < sender), so any id-ordered assertion is
// unchanged.
const DANA: &str = "4e55a9e0-0000-4000-8000-000000000001";
const INTRUDER: &str = "4e55a9e0-0000-4000-8000-000000000002";
const RECIPIENT: &str = "4e55a9e0-0000-4000-8000-000000000003";
const SENDER: &str = "4e55a9e0-0000-4000-8000-000000000004";

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

async fn install_people(db: &Db) {
    for (record_id, principal, account) in [
        (SENDER, "native/sender", "acct_sender"),
        (RECIPIENT, "native/recipient", "acct_recipient"),
        (DANA, "native/dana", "acct_dana"),
        (INTRUDER, "native/intruder", "acct_intruder"),
    ] {
        create_raw_record(
            db,
            json!({"id":record_id,"type":"Entity","kind":"person","name":record_id}),
        )
        .await
        .unwrap();
        for (system, identifier) in [("native-principal", principal), ("account", account)] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical)
                 VALUES (?,?,?,1)",
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

async fn message(registry: &ToolRegistry, db: &Db, body: &str) -> String {
    call(
        registry,
        db,
        "manage_messages",
        json!({
            "action":"send",
            "body":body,
            "owner_id":SENDER,
            "origin":{"type":"direct","participant_ids":[SENDER,RECIPIENT]},
            "addressed_to":[RECIPIENT],
            "expectation":"none",
            "idempotency_key":format!("test-send-{}",uuid::Uuid::new_v4()),
            "reason":"Create the addressed Message fixture through the policy gate."
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .into()
}

async fn conversation(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({"type":"Conversation","kind":"discussion","name":name}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn audience_is_sealed_and_rebuildable() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let message = message(&registry, &db, "hello").await;

    let audience: Vec<(String, String)> = sqlx::query_as(
        "SELECT principal_id,source FROM message_audiences
          WHERE message_id=? ORDER BY source,principal_id",
    )
    .bind(&message)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        audience,
        vec![
            ("native/recipient".into(), "addressed_to".into()),
            ("native/sender".into(), "sender".into()),
        ]
    );
    let status: String =
        sqlx::query_scalar("SELECT status FROM message_audience_state WHERE message_id=?")
            .bind(&message)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(status, "declared");

    let add = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({"action":"add","source_id":message,"target_id":DANA,"relationship":"addressed_to"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(add.contains("immutable Message content"), "{add}");
    let mutate = call_as(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "id": message, "body": "rewritten",
            "if_body_digest": current_body_digest(&registry, &db, &message).await,
            "reason": "Attempt mutation"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(mutate.contains("immutable creation content"), "{mutate}");
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn addressed_to_excludes_the_sender() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    let error = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_messages",
        json!({
            "action":"send",
            "body":"to myself",
            "owner_id":SENDER,
            "origin":{"type":"direct","participant_ids":[SENDER,RECIPIENT]},
            "addressed_to":[SENDER],
            "expectation":"none",
            "idempotency_key":"test-self-send",
            "reason":"Sender is not a recipient"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("must exclude the Message sender"), "{error}");
}

#[tokio::test]
async fn duplicate_classification_is_a_noop_and_move_is_atomic() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let message = message(&registry, &db, "classify me").await;
    let first = conversation(&registry, &db, "First").await;
    let second = conversation(&registry, &db, "Second").await;

    let classified = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"classify","message_id":message,"conversation_id":first}),
    )
    .await;
    assert_eq!(classified["changed"], true);
    let events_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='link.added'",
    )
    .bind(&message)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let duplicate = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"classify","message_id":message,"conversation_id":first}),
    )
    .await;
    assert_eq!(duplicate["status"], "unchanged");
    let events_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='link.added'",
    )
    .bind(&message)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(events_after, events_before);

    let not_a_conversation = DANA;
    let failed = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_messages",
        json!({"action":"move","message_id":message,"from_conversation_id":first,"to_conversation_id":not_a_conversation}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(failed.contains("Conversation target"), "{failed}");
    let still_first: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM message_conversations WHERE message_id=? AND conversation_id=?)",
    )
    .bind(&message)
    .bind(&first)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(still_first, "failed move must roll back its removal");

    call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"move","message_id":message,"from_conversation_id":first,"to_conversation_id":second}),
    )
    .await;
    let classifications: Vec<String> =
        sqlx::query_scalar("SELECT conversation_id FROM message_conversations WHERE message_id=?")
            .bind(&message)
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(classifications, [second]);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn history_share_is_authorized_atomic_idempotent_and_snapshot_bounded() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let topic = conversation(&registry, &db, "A topic").await;
    let first = message(&registry, &db, "first").await;
    call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"classify","message_id":first,"conversation_id":topic}),
    )
    .await;
    // This Message exists at the frontier but is classified only afterwards.
    let second = message(&registry, &db, "second").await;
    let frontier: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    // Conversely, the first Message belongs at the frontier even though its
    // classification is removed afterwards.
    call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"unclassify","message_id":first,"conversation_id":topic}),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"classify","message_id":second,"conversation_id":topic}),
    )
    .await;

    let policy_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let unauthorized = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_intruder"),
        "manage_messages",
        json!({"action":"share_history","recipient_id":DANA,"conversation_id":topic,"snapshot_seq":frontier,"reason":"Bring Dana into the selected prior context"}),
    )
    .await
    .unwrap_err();
    assert!(unauthorized.to_string().contains("does not exist"));
    let policy_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        policy_after, policy_before,
        "unauthorized share must write nothing"
    );

    let shared = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"share_history","recipient_id":DANA,"conversation_id":topic,"snapshot_seq":frontier,"reason":"Bring Dana into the selected prior context"}),
    )
    .await;
    assert_eq!(shared["shared"], json!([first]));
    assert_eq!(shared["message_ids"], json!([first]));
    assert_eq!(
        shared["action_attestation_ids"].as_array().unwrap().len(),
        1
    );
    let retry = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"share_history","recipient_id":DANA,"conversation_id":topic,"snapshot_seq":frontier,"reason":"Bring Dana into the selected prior context"}),
    )
    .await;
    assert_eq!(retry["status"], "unchanged");
    assert!(retry.get("action_attestation_ids").is_none());

    assert_eq!(
        effective_capability(&db, Principal::bound("acct_dana", true), &first)
            .await
            .unwrap(),
        Capability::View
    );
    assert_eq!(
        effective_capability(&db, Principal::bound("acct_dana", true), &second)
            .await
            .unwrap(),
        Capability::None
    );
    let shared_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type='message.shared'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(shared_events, 1);

    // Exact-set identity does not include the moving content head. Retrying
    // after an unrelated content append must not write another share or policy.
    let explicit = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"share_history","recipient_id":DANA,"message_ids":[second],"reason":"Share one exact Message"}),
    )
    .await;
    assert_eq!(explicit["shared"], json!([second]));
    assert_eq!(
        explicit["action_attestation_ids"].as_array().unwrap().len(),
        1
    );
    conversation(&registry, &db, "Unrelated activity").await;
    let content_before_retry: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let policy_before_retry: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let explicit_retry = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"share_history","recipient_id":DANA,"message_ids":[second],"reason":"Share one exact Message"}),
    )
    .await;
    assert_eq!(explicit_retry["status"], "unchanged");
    let content_after_retry: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let policy_after_retry: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(content_after_retry, content_before_retry);
    assert_eq!(policy_after_retry, policy_before_retry);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn history_share_issues_one_attestation_per_new_message() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = message(&registry, &db, "first item").await;
    let second = message(&registry, &db, "second item").await;
    let shared = call(
        &registry,
        &db,
        "manage_messages",
        json!({
            "action":"share_history",
            "recipient_id":DANA,
            "message_ids":[first,second],
            "reason":"Share exactly two Messages"
        }),
    )
    .await;
    let ids = shared["action_attestation_ids"].as_array().unwrap();
    assert_eq!(shared["shared"].as_array().unwrap().len(), 2);
    assert_eq!(ids.len(), 2);
    for id in ids {
        let members: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_action_outputs WHERE action_attestation_id=? AND output_domain='content'",
        )
        .bind(id.as_str().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(members, 1);
    }
    db.close().await;
}

#[tokio::test]
async fn structured_mentions_create_body_free_candidates_and_exact_human_evidence() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let message=call(&registry,&db,"manage_messages",json!({
        "action":"send","body":"Hi Recipient","owner_id":SENDER,
        "origin":{"type":"direct","participant_ids":[SENDER,RECIPIENT]},
        "addressed_to":[RECIPIENT],"expectation":"none","idempotency_key":"structured-mention-send",
        "reason":"Exercise immutable structured mention delivery.",
        "mentions":[{"mention_id":"mention-1","target_kind":"principal","target_id":RECIPIENT,"span_start":3,"span_end":12,"authored_label":"Recipient"}]
    })).await["id"].as_str().unwrap().to_string();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM message_mentions WHERE message_id=? AND effective=1"
        )
        .bind(&message)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    let payload: String =
        sqlx::query_scalar("SELECT payload FROM notification_candidate_events WHERE message_id=?")
            .bind(&message)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(!payload.contains("Hi Recipient"));
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let ids = vec![message.clone()];
    let token = issuer
        .issue("acct_recipient", "acknowledged", &ids, 60)
        .unwrap();
    let caller = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
        .unwrap();
    let acknowledged=call_as(&registry,&db,caller,"manage_messages",json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":{message.clone():0},"idempotency_key":"ack-1","reason":"Explicitly reviewed"})).await.unwrap();
    assert_eq!(acknowledged["results"][0]["stage"], "acknowledged");
    assert!(
        acknowledged.get("action_attestation_ids").is_none(),
        "awareness-only batch items are outside the v1 content-event attestation boundary"
    );
    let attention=call_as(&registry,&db,Caller::authenticated("acct_recipient"),"manage_messages",json!({"action":"set_preference","message_id":message,"preference":"flag_attention","expected_version":0,"idempotency_key":"flag-1","reason":"Show this again"})).await.unwrap();
    assert_eq!(attention["attention_flag"], true);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT stage FROM human_message_awareness WHERE message_id=?"
        )
        .bind(&message)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        "acknowledged"
    );
}

#[tokio::test]
async fn multibyte_reply_with_mention_threads_and_indexes_utf8_bytes() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let root = message(&registry, &db, "root question").await;
    // "Héllo recipient": é is two UTF-8 bytes, so "recipient" spans bytes
    // 7..16. A reply threads with a creation-time reply_to link and carries
    // the mention in the same send.
    let reply = call(
        &registry,
        &db,
        "manage_messages",
        json!({
            "action":"send","body":"Héllo recipient","owner_id":SENDER,
            "origin":{"type":"direct","participant_ids":[SENDER,RECIPIENT]},
            "addressed_to":[RECIPIENT],"expectation":"none",
            "links":[{"target_id":root,"relationship":"reply_to"}],
            "mentions":[{"mention_id":"mention-1","target_kind":"principal","target_id":RECIPIENT,"span_start":7,"span_end":16,"authored_label":"recipient"}],
            "idempotency_key":"multibyte-reply-send",
            "reason":"Reply with a mention after multibyte prose."
        }),
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=? AND relationship='reply_to'"
        )
        .bind(reply["id"].as_str().unwrap())
        .bind(&root)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM message_mentions WHERE message_id=? AND effective=1"
        )
        .bind(reply["id"].as_str().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    // Character-count offsets (6..15) split the multibyte prefix and miss the
    // authored slice, so the same send shape with char offsets is refused.
    // The call helper unwraps success; reach the fallible seam directly.
    let char_error = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_messages",
        json!({
            "action":"send","body":"Héllo recipient","owner_id":SENDER,
            "origin":{"type":"direct","participant_ids":[SENDER,RECIPIENT]},
            "addressed_to":[RECIPIENT],"expectation":"none",
            "links":[{"target_id":root,"relationship":"reply_to"}],
            "mentions":[{"mention_id":"mention-1","target_kind":"principal","target_id":RECIPIENT,"span_start":6,"span_end":15,"authored_label":"recipient"}],
            "idempotency_key":"multibyte-reply-char-offsets-retry",
            "reason":"Same reply with character-count offsets."
        }),
    )
    .await
    .unwrap_err();
    assert!(
        char_error.to_string().contains("mention span"),
        "char-count offsets must fail span validation: {char_error}"
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn ordinary_agent_cannot_claim_human_awareness_or_reroute_without_policy_authority() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let message = message(&registry, &db, "guarded").await;
    let error=call_as(&registry,&db,Caller::authenticated("acct_recipient"),"manage_messages",json!({"action":"mutate_human_awareness","message_ids":[message.clone()],"stage":"acknowledged","expected_versions":{message.clone():0},"idempotency_key":"forged","reason":"agent claim"})).await.unwrap_err();
    let contract = native_ce::awareness::messaging_surface_contract();
    assert_eq!(
        contract["agent_states"],
        json!([
            "unhandled",
            "triaged",
            "deferred",
            "escalated",
            "acted",
            "resolved"
        ])
    );
    assert!(error.to_string().contains(
        contract["errors"]["human_attestation_required"]
            .as_str()
            .unwrap()
    ));
    let route=call_as(&registry,&db,Caller::authenticated("acct_recipient"),"manage_messages",json!({"action":"set_routing","message_id":message,"obligation_state":"open","executor_route":"agent","policy_version":"v1","expected_version":0,"idempotency_key":"route","reason":"agent decides"})).await.unwrap_err();
    assert!(route.to_string().contains("trusted policy"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn inbox_snapshot_excludes_concurrent_arrivals_and_attention_does_not_rewind_awareness() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = message(&registry, &db, "first").await;
    let caller = Caller::authenticated("acct_recipient");
    let page = call_as(
        &registry,
        &db,
        caller.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":1}),
    )
    .await
    .unwrap();
    native_ce::awareness::validate_messaging_surface_response(&page).unwrap();
    let mut missing_authorization_head = page.clone();
    missing_authorization_head["heads"]
        .as_object_mut()
        .unwrap()
        .remove("authorization");
    assert!(
        native_ce::awareness::validate_messaging_surface_response(&missing_authorization_head)
            .unwrap_err()
            .to_string()
            .contains("authorization")
    );
    assert_eq!(page["items"][0]["message_id"], first);
    let snapshot = page["snapshot"].as_str().unwrap().to_string();
    assert_eq!(snapshot.len(), 36, "opaque token stays bounded");
    let mut forged = snapshot.clone();
    forged.replace_range(0..1, if &snapshot[0..1] == "a" { "b" } else { "a" });
    let forged_error = call_as(
        &registry,
        &db,
        caller.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":10,"snapshot":forged,"after":0}),
    )
    .await
    .unwrap_err();
    assert!(forged_error.to_string().contains("cursor_reset_required"));
    let second = message(&registry, &db, "second").await;
    let pinned = call_as(
        &registry,
        &db,
        caller,
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":10,"snapshot":snapshot,"after":0}),
    )
    .await
    .unwrap();
    assert_eq!(pinned["newer_available"], true);
    assert!(pinned["heads"]["authorization"].is_number());
    assert!(pinned["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["message_id"] != second));
    assert_eq!(pinned["newer_available"], true);
}

#[tokio::test]
async fn inbox_pages_pin_view_state_exclude_later_grants_and_apply_live_revocation() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let old = message(&registry, &db, "old second page").await;
    let newest = message(&registry, &db, "new first page").await;
    let hidden = call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"send","body":"later grant","owner_id":SENDER,"origin":{"type":"direct","participant_ids":[SENDER,DANA]},"addressed_to":[DANA],"expectation":"none","idempotency_key":"later-grant-send","reason":"Create a Message hidden from the later recipient."}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let caller = Caller::authenticated("acct_recipient");
    let page = call_as(
        &registry,
        &db,
        caller.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(page["items"][0]["message_id"], newest);
    let snapshot = page["snapshot"].as_str().unwrap().to_string();

    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let ids = vec![old.clone()];
    let token = issuer
        .issue("acct_recipient", "acknowledged", &ids, 60)
        .unwrap();
    let human = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
        .unwrap();
    call_as(
        &registry,
        &db,
        human,
        "manage_messages",
        json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":{old.clone():0},"idempotency_key":"pin-view","reason":"Changed after first page"}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "manage_messages",
        json!({"action":"share_history","recipient_id":RECIPIENT,"message_ids":[hidden.clone()],"reason":"Grant after snapshot"}),
    )
    .await;
    let pinned = call_as(
        &registry,
        &db,
        caller.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":10,"snapshot":snapshot,"after":1}),
    )
    .await
    .unwrap();
    assert_eq!(pinned["newer_available"], true);
    assert!(pinned["heads"]["authorization"].is_number());
    assert!(pinned["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["message_id"] == old));
    assert!(pinned["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["message_id"] != hidden));

    native_ce::authorization::replace_explicit_policy(&db, "test:live-revoke", &old, vec![])
        .await
        .unwrap();
    let revoked = call_as(
        &registry,
        &db,
        caller,
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":10,"snapshot":page["snapshot"],"after":1}),
    )
    .await
    .unwrap();
    assert_eq!(revoked["newer_available"], true);
    assert!(revoked["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["message_id"] != old));
}

#[tokio::test]
async fn stale_exact_human_batch_rolls_back_on_revocation_and_never_grows_to_new_arrivals() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = message(&registry, &db, "first exact").await;
    let revoked = message(&registry, &db, "revoked exact").await;
    let new_arrival = message(&registry, &db, "not in exact batch").await;
    let ids = vec![first.clone(), revoked.clone()];
    let page = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":200}),
    )
    .await
    .unwrap();
    let snapshot = page["snapshot"].as_str().unwrap().to_string();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let token = issuer
        .issue("acct_recipient", "acknowledged", &ids, 60)
        .unwrap();
    let caller = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
        .unwrap();
    native_ce::authorization::replace_explicit_policy(&db, "test:revocation", &revoked, vec![])
        .await
        .unwrap();
    let error = call_as(
        &registry,
        &db,
        caller,
        "manage_messages",
        json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":{first.clone():0,revoked.clone():0},"idempotency_key":"exact-batch","snapshot":snapshot,"reason":"Reviewed the pinned selection"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("does not exist"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM human_message_awareness WHERE message_id IN (?,?,?)"
        )
        .bind(first)
        .bind(revoked)
        .bind(new_arrival)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn tampered_human_attestation_is_rejected_before_a_caller_gets_human_authority() {
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let ids = vec!["message:a".to_string()];
    let mut token = issuer
        .issue("acct_recipient", "acknowledged", &ids, 60)
        .unwrap();
    token.push('x');
    let error = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
        .unwrap_err();
    assert!(error.to_string().contains("human interaction attestation"));
}

#[tokio::test]
async fn human_batch_idempotency_binds_the_sorted_exact_set_and_versions() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = message(&registry, &db, "batch first").await;
    let second = message(&registry, &db, "batch second").await;
    let page = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":200}),
    )
    .await
    .unwrap();
    let snapshot = page["snapshot"].as_str().unwrap().to_string();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let first_ids = vec![first.clone()];
    let first_token = issuer
        .issue("acct_recipient", "acknowledged", &first_ids, 60)
        .unwrap();
    let first_caller = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &first_token, "acknowledged", &first_ids)
        .unwrap();
    call_as(
        &registry,
        &db,
        first_caller,
        "manage_messages",
        json!({"action":"mutate_human_awareness","message_ids":first_ids,"stage":"acknowledged","expected_versions":{first.clone():0},"idempotency_key":"batch-command","reason":"Reviewed exact set"}),
    )
    .await
    .unwrap();

    for ids in [vec![second.clone()], vec![first.clone(), second.clone()]] {
        let token = issuer
            .issue("acct_recipient", "acknowledged", &ids, 60)
            .unwrap();
        let caller = Caller::authenticated("acct_recipient")
            .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
            .unwrap();
        let expected = if ids.len() == 1 {
            json!({second.clone():0})
        } else {
            json!({first.clone():1,second.clone():0})
        };
        let error = call_as(
            &registry,
            &db,
            caller,
            "manage_messages",
            json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":expected,"idempotency_key":"batch-command","snapshot":snapshot.clone(),"reason":"Changed exact set"}),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("different intent"));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM human_message_awareness WHERE message_id=?"
        )
        .bind(second)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn human_batch_rejects_a_visible_message_outside_the_pinned_snapshot() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let pinned = message(&registry, &db, "pinned").await;
    let page = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":200}),
    )
    .await
    .unwrap();
    let snapshot = page["snapshot"].as_str().unwrap().to_string();
    let later = message(&registry, &db, "visible but later").await;
    let ids = vec![pinned.clone(), later.clone()];
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let token = issuer
        .issue("acct_recipient", "acknowledged", &ids, 60)
        .unwrap();
    let caller = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
        .unwrap();
    let error = call_as(
        &registry,
        &db,
        caller,
        "manage_messages",
        json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":{pinned:0,later:0},"idempotency_key":"snapshot-membership","snapshot":snapshot,"reason":"Apply exact pinned selection"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("not contained"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM human_message_awareness")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn exact_human_batch_retry_survives_snapshot_cache_eviction() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = message(&registry, &db, "retry first").await;
    let second = message(&registry, &db, "retry second").await;
    let ids = vec![first.clone(), second.clone()];
    let page = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":200}),
    )
    .await
    .unwrap();
    let snapshot = page["snapshot"].as_str().unwrap().to_string();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let token = issuer
        .issue("acct_recipient", "acknowledged", &ids, 60)
        .unwrap();
    let caller = Caller::authenticated("acct_recipient")
        .with_human_interaction_token(&issuer, &token, "acknowledged", &ids)
        .unwrap();
    call_as(
        &registry,
        &db,
        caller.clone(),
        "manage_messages",
        json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":{first.clone():0,second.clone():0},"idempotency_key":"evicted-snapshot-retry","snapshot":snapshot,"reason":"Apply pinned batch"}),
    )
    .await
    .unwrap();

    for _ in 0..128 {
        call_as(
            &registry,
            &db,
            Caller::authenticated("acct_recipient"),
            "manage_messages",
            json!({"action":"list_inbox","view":"browse","limit":1}),
        )
        .await
        .unwrap();
    }
    let evicted = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"all_new","limit":200,"snapshot":snapshot,"after":0}),
    )
    .await
    .unwrap_err();
    assert!(evicted.to_string().contains("cursor_reset_required"));

    let retry = call_as(
        &registry,
        &db,
        caller,
        "manage_messages",
        json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"acknowledged","expected_versions":{first:0,second:0},"idempotency_key":"evicted-snapshot-retry","snapshot":snapshot,"reason":"Retry pinned batch"}),
    )
    .await
    .unwrap();
    assert!(retry["results"]
        .as_array()
        .unwrap()
        .iter()
        .all(|result| result["idempotent"] == true && result["version"] == 1));
}

#[tokio::test]
async fn agent_lane_requires_verified_executor_and_semantic_evidence() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let message = message(&registry, &db, "agent evidence").await;
    let arbitrary = call(
        &registry,
        &db,
        "create_record",
        json!({"type":"Document","kind":"note","name":"visible but unrelated","owner_id":RECIPIENT}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let untrusted = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"set_agent_disposition","message_id":message,"state":"triaged","expected_version":0,"idempotency_key":"untrusted-agent","evidence":[],"reason":"Asserted run is not authority"}),
    )
    .await
    .unwrap_err();
    assert!(untrusted.to_string().contains("server-verified executor"));

    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let ids = vec![message.clone()];
    let action = "agent-executor:executor-1:delegation-1";
    let token = issuer.issue("acct_recipient", action, &ids, 60).unwrap();
    let agent = Caller::authenticated("acct_recipient")
        .with_agent_executor_token(&issuer, &token, "executor-1", "delegation-1", &ids)
        .unwrap();
    let error = call_as(
        &registry,
        &db,
        agent,
        "manage_messages",
        json!({"action":"set_agent_disposition","message_id":message,"state":"resolved","expected_version":0,"idempotency_key":"bad-evidence","evidence":[{"record_id":arbitrary,"role":"reply"}],"reason":"Unrelated record must not resolve"}),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("does not satisfy governed Message semantics"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn competing_corrections_withdraw_candidates_and_tombstones_withdraw_mentions() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let create_mention = |body: &str, supersedes: Option<&str>| {
        let mut value = json!({
            "action":"send","body":body,"owner_id":SENDER,
            "origin":{"type":"direct","participant_ids":[SENDER,RECIPIENT]},
            "addressed_to":[RECIPIENT],"expectation":"none","idempotency_key":format!("mention-send-{body}"),
            "reason":"Exercise correction semantics for a structured mention.",
            "mentions":[{"mention_id":format!("mention-{body}"),"target_kind":"principal","target_id":RECIPIENT,"span_start":0,"span_end":body.len(),"authored_label":body}]
        });
        if let Some(target) = supersedes {
            value["links"] = json!([{"target_id":target,"relationship":"supersedes"}]);
        }
        value
    };
    let original = call(
        &registry,
        &db,
        "manage_messages",
        create_mention("Recipient", None),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let first_correction = call(
        &registry,
        &db,
        "manage_messages",
        create_mention("Corrected", Some(&original)),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let second_correction = call(
        &registry,
        &db,
        "manage_messages",
        create_mention("Alternative", Some(&original)),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_candidates WHERE status='effective' AND message_id IN (?,?,?)")
            .bind(&original).bind(&first_correction).bind(&second_correction)
            .fetch_one(db.pool()).await.unwrap(),
        0
    );

    call(
        &registry,
        &db,
        "delete_record",
        json!({"id":first_correction,"reason":"Withdraw the correction"}),
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM message_mentions WHERE message_id=? AND effective=1"
        )
        .bind(first_correction)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}
