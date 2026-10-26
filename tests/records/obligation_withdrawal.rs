//! Notification candidates leave when what they announced is over. A
//! `human_obligation` candidate is withdrawn for exactly the recipients whose
//! expectation closed (a reply, an acknowledgement, a closing
//! no-longer-relevant mark); `principal_mention` candidates stay until the
//! message is opened. Archiving withdraws a recipient's candidates of every kind.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::message_expectation::{derive_message_expectation_state, MessageExpectationState};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const A_ACCOUNT: &str = "acct_withdraw_a";
const B_ACCOUNT: &str = "acct_withdraw_b";
const C_ACCOUNT: &str = "acct_withdraw_c";
const A: &str = "6d330000-0000-4000-8000-000000000001";
const B: &str = "6d330000-0000-4000-8000-000000000002";
const C: &str = "6d330000-0000-4000-8000-000000000003";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    mut args: Value,
) -> native_ce::Result<Value> {
    args["reason"] = json!("Exercise obligation withdrawal in an integration fixture.");
    registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_messages",
            crate::common::with_test_reason("manage_messages", args),
        )
        .await
}

async fn install_people(db: &Db) {
    for (record_id, principal, account) in [
        (A, "native/withdraw-a", A_ACCOUNT),
        (B, "native/withdraw-b", B_ACCOUNT),
        (C, "native/withdraw-c", C_ACCOUNT),
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

/// A direct message from `from` to `to` inside a context that also contains
/// `bystanders`; extra args merge over it.
async fn dm(
    registry: &ToolRegistry,
    db: &Db,
    from: (&str, &str),
    to: &str,
    bystanders: &[&str],
    key: &str,
    extra: Value,
) -> String {
    let mut participants = vec![from.1, to];
    participants.extend_from_slice(bystanders);
    let mut args = json!({
        "action":"send","body":"hello there","expectation":"none","idempotency_key":key,
        "origin":{"type":"direct","participant_ids":participants},
        "addressed_to":[to],
    });
    args.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    call(registry, db, from.0, args).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// `(recipient account, reason)` of every effective candidate on a message.
async fn effective(db: &Db, message: &str) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT recipient_account_id,reason FROM notification_candidates
          WHERE message_id=? AND status='effective' ORDER BY recipient_account_id,reason",
    )
    .bind(message)
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn proposals(db: &Db, message: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidate_events WHERE message_id=? AND action='proposed'",
    )
    .bind(message)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// The reasons one account holds effective candidates for on a message.
async fn held_by(db: &Db, message: &str, account: &str) -> Vec<(String, String)> {
    effective(db, message)
        .await
        .into_iter()
        .filter(|(holder, _)| holder == account)
        .collect()
}

fn pair(account: &str, reason: &str) -> (String, String) {
    (account.to_owned(), reason.to_owned())
}

/// A request from A to B that carries both an obligation and a mention of B,
/// so B holds a `human_obligation` and a `principal_mention` candidate.
async fn request_with_mention(
    registry: &ToolRegistry,
    db: &Db,
    expectation: &str,
    bystanders: &[&str],
    key: &str,
) -> String {
    let message = dm(
        registry,
        db,
        (A_ACCOUNT, A),
        B,
        bystanders,
        key,
        json!({"body":"B please","expectation":expectation,"mentions":[{
            "mention_id":format!("mention-{key}"),"target_kind":"principal","target_id":B,
            "span_start":0,"span_end":1,"authored_label":"B"
        }]}),
    )
    .await;
    assert_eq!(
        held_by(db, &message, B_ACCOUNT).await,
        vec![
            pair(B_ACCOUNT, "human_obligation"),
            pair(B_ACCOUNT, "principal_mention")
        ],
        "the request starts with both candidates for B"
    );
    message
}

async fn mark(registry: &ToolRegistry, db: &Db, account: &str, message: &str, key: &str) {
    call(
        registry,
        db,
        account,
        json!({"action":"mark_no_longer_relevant","message_id":message,"idempotency_key":key}),
    )
    .await
    .unwrap();
}

async fn state(db: &Db, message: &str, account: &str) -> MessageExpectationState {
    derive_message_expectation_state(db, message, account)
        .await
        .unwrap()
        .state
}

#[tokio::test]
async fn a_reply_withdraws_the_obligation_for_the_replier_and_keeps_the_mention() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = request_with_mention(&registry, &db, "reply", &[C], "reply-req").await;

    // A reply from someone who was not asked closes nothing for B.
    dm(
        &registry,
        &db,
        (C_ACCOUNT, C),
        A,
        &[B],
        "reply-by-c",
        json!({"links":[{"target_id":request,"relationship":"reply_to"}]}),
    )
    .await;
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Open
    );
    assert_eq!(held_by(&db, &request, B_ACCOUNT).await.len(), 2);

    dm(
        &registry,
        &db,
        (B_ACCOUNT, B),
        A,
        &[C],
        "reply-by-b",
        json!({"links":[{"target_id":request,"relationship":"reply_to"}]}),
    )
    .await;
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Satisfied
    );
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "principal_mention")],
        "the obligation goes; the mention clears only when the message is opened"
    );
}

#[tokio::test]
async fn an_acknowledgement_withdraws_the_obligation() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = request_with_mention(&registry, &db, "ack", &[], "ack-req").await;

    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction",
               "message_id":request,"idempotency_key":"ack-1"}),
    )
    .await
    .unwrap();
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Satisfied
    );
    assert_eq!(
        effective(&db, &request).await,
        vec![pair(B_ACCOUNT, "principal_mention")]
    );
}

#[tokio::test]
async fn a_recipients_closing_mark_withdraws_and_unmarking_does_not_re_propose() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = request_with_mention(&registry, &db, "decision", &[], "mark-req").await;
    let proposed = proposals(&db, &request).await;

    mark(&registry, &db, B_ACCOUNT, &request, "mark-1").await;
    assert_eq!(
        effective(&db, &request).await,
        vec![pair(B_ACCOUNT, "principal_mention")]
    );

    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"unmark_no_longer_relevant","message_id":request,"idempotency_key":"unmark-1"}),
    )
    .await
    .unwrap();
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Open,
        "the expectation is open again, so the amber dot returns"
    );
    assert_eq!(
        effective(&db, &request).await,
        vec![pair(B_ACCOUNT, "principal_mention")],
        "but unmarking proposes no new notification"
    );
    assert_eq!(proposals(&db, &request).await, proposed);
}

#[tokio::test]
async fn the_senders_closing_mark_withdraws_for_every_recipient_who_still_holds_one() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[C],
        "sender-mark-req",
        json!({"expectation":"reply"}),
    )
    .await;
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "human_obligation")]
    );

    mark(&registry, &db, A_ACCOUNT, &request, "sender-mark").await;
    assert_eq!(held_by(&db, &request, B_ACCOUNT).await, vec![]);
    assert_eq!(
        held_by(&db, &request, C_ACCOUNT).await,
        vec![pair(C_ACCOUNT, "routine_arrival")],
        "only the obligation goes; the bystander's arrival is not an obligation"
    );
}

#[tokio::test]
async fn a_third_partys_mark_closes_nothing_and_withdraws_nothing() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = request_with_mention(&registry, &db, "reply", &[C], "third-req").await;
    let before = effective(&db, &request).await;

    mark(&registry, &db, C_ACCOUNT, &request, "third-mark").await;
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Open
    );
    assert_eq!(effective(&db, &request).await, before);
}

#[tokio::test]
async fn archiving_withdraws_every_kind_for_that_recipient_only() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    let archive = |message: String, version: i64, key: &'static str| {
        let (registry, db) = (&registry, &db);
        async move {
            call(
                registry,
                db,
                B_ACCOUNT,
                json!({"action":"set_preference","message_id":message,"preference":"archive",
                       "expected_version":version,"idempotency_key":key}),
            )
            .await
            .unwrap();
        }
    };

    // human_obligation + principal_mention
    let request = request_with_mention(&registry, &db, "reply", &[], "archive-req").await;
    archive(request.clone(), 0, "archive-1").await;
    assert_eq!(effective(&db, &request).await, vec![]);

    // routine_arrival, with C hearing the same message too
    let plain = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[C],
        "archive-plain",
        json!({}),
    )
    .await;
    assert_eq!(
        effective(&db, &plain).await,
        vec![
            pair(B_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );
    archive(plain.clone(), 0, "archive-2").await;
    assert_eq!(
        effective(&db, &plain).await,
        vec![pair(C_ACCOUNT, "routine_arrival")],
        "C's candidate is not B's to archive"
    );

    // snooze_due
    let snoozed = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "archive-snooze",
        json!({}),
    )
    .await;
    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_preference","message_id":snoozed,"preference":"snooze",
               "snoozed_until":"2099-01-01T00:00:00Z","expected_version":0,
               "idempotency_key":"snooze-1"}),
    )
    .await
    .unwrap();
    assert_eq!(
        effective(&db, &snoozed).await,
        vec![pair(B_ACCOUNT, "snooze_due")]
    );
    archive(snoozed.clone(), 1, "archive-3").await;
    assert_eq!(effective(&db, &snoozed).await, vec![]);

    // Restoring brings nothing back.
    let before = proposals(&db, &request).await;
    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_preference","message_id":request,"preference":"restore",
               "expected_version":1,"idempotency_key":"restore-1"}),
    )
    .await
    .unwrap();
    assert_eq!(effective(&db, &request).await, vec![]);
    assert_eq!(proposals(&db, &request).await, before);
}

#[tokio::test]
async fn a_closure_written_outside_the_message_tools_is_withheld_at_harvest_and_revalidation() {
    use native_ce::awareness::{
        harvest_host_notification_candidates, revalidate_host_notification_candidate,
    };
    use native_ce::events::LinkAddedPayload;
    use native_ce::store::{add_link_as, create_record_as};

    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "backstop-req",
        json!({"expectation":"action"}),
    )
    .await;
    let harvest = |db: Db| async move {
        harvest_host_notification_candidates(&db, B_ACCOUNT, true, 0, 500)
            .await
            .unwrap()
    };
    let before = harvest(db.clone()).await;
    assert_eq!(before.candidates.len(), 1);
    assert!(!before.candidates[0].muted);
    let candidate = before.candidates[0].candidate_id.clone();

    // B's own mark, written straight to the log rather than through
    // manage_messages, so no withdrawal runs. The candidate stays effective.
    let mark = uuid::Uuid::new_v4().to_string();
    create_record_as(
        &db,
        json!({"id":mark,"type":"Annotation","kind":"no_longer_relevant",
               "name":"mark","body":"","owner_id":B}),
        Some(B_ACCOUNT),
    )
    .await
    .unwrap();
    add_link_as(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: mark,
            target_id: request.clone(),
            relationship: "resolves".into(),
            note: Some("no_longer_relevant".into()),
        },
        Some(B_ACCOUNT),
    )
    .await
    .unwrap();
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Satisfied
    );
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "human_obligation")]
    );

    let after = harvest(db.clone()).await;
    assert!(after.candidates[0].muted, "a closed obligation is withheld");
    let revalidated = revalidate_host_notification_candidate(&db, &candidate, B_ACCOUNT, true)
        .await
        .unwrap()
        .unwrap();
    assert!(!revalidated.effective_viewable_unmuted);
}

async fn events(db: &Db, message: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM notification_candidate_events WHERE message_id=?")
        .bind(message)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn route(db: &Db, account: &str, message: &str, obligation: &str, version: i64, key: &str) {
    db.drain_captures_for_tests().await;
    let pool = crate::common::fixture_write_pool(db).await;
    let mut tx = pool.begin().await.unwrap();
    let mut act_alloc = native_ce::act::ActAllocation::new();
    native_ce::awareness::set_routing(
        &mut tx,
        &native_ce::awareness::MutationContext {
            subject_account_id: account,
            authenticated_actor: account,
            executor_kind: "system",
            executor_ref: Some("obligation-withdrawal-test"),
            delegation_ref: None,
            reason_code: "Set routing in the obligation withdrawal fixture.",
        },
        message,
        obligation,
        if obligation == "open" {
            "human"
        } else {
            "closed"
        },
        None,
        version,
        key,
        &mut act_alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn an_explicitly_reopened_obligation_is_not_closed_by_earlier_evidence() {
    use native_ce::awareness::{
        harvest_host_notification_candidates, revalidate_host_notification_candidate,
    };

    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[C],
        "reopen-req",
        json!({"expectation":"ack"}),
    )
    .await;
    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction",
               "message_id":request,"idempotency_key":"reopen-ack"}),
    )
    .await
    .unwrap();
    assert_eq!(held_by(&db, &request, B_ACCOUNT).await, vec![]);

    // B reopens the obligation. The old acknowledgement still satisfies the
    // derived expectation, but the inbox, which follows the routing, says open.
    route(&db, B_ACCOUNT, &request, "open", 1, "reopen-route").await;
    assert_eq!(
        state(&db, &request, B_ACCOUNT).await,
        MessageExpectationState::Satisfied
    );
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "human_obligation")],
        "the reopen proposes a fresh candidate"
    );

    // A third party's mark closes nothing, so it withdraws nothing.
    mark(&registry, &db, C_ACCOUNT, &request, "reopen-third").await;
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "human_obligation")]
    );

    // And delivery does not withhold it on the strength of the old evidence.
    let harvested = harvest_host_notification_candidates(&db, B_ACCOUNT, true, 0, 500)
        .await
        .unwrap();
    let reopened = harvested
        .candidates
        .iter()
        .find(|candidate| candidate.reason == "human_obligation")
        .unwrap();
    assert!(!reopened.muted);
    assert!(
        revalidate_host_notification_candidate(&db, &reopened.candidate_id, B_ACCOUNT, true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
    );

    // Closing the routing again withdraws it.
    route(&db, B_ACCOUNT, &request, "satisfied", 2, "reopen-close").await;
    assert_eq!(held_by(&db, &request, B_ACCOUNT).await, vec![]);
}

#[tokio::test]
async fn a_failed_closure_check_fails_closed_instead_of_approving_delivery() {
    use native_ce::awareness::revalidate_host_notification_candidate;

    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;

    // An effective obligation candidate whose "message" is not a Message, so
    // the derivation cannot run.
    db.drain_captures_for_tests().await;
    let pool = crate::common::fixture_write_pool(&db).await;
    let mut tx = pool.begin().await.unwrap();
    let mut act_alloc = native_ce::act::ActAllocation::new();
    let candidate = native_ce::awareness::append_notification_candidate_in(
        &mut tx,
        B_ACCOUNT,
        A,
        "human_obligation",
        "routine",
        None,
        "metadata_only",
        "portable_default",
        "test-v1",
        "record.created",
        "src-fail-closed",
        &mut act_alloc,
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();

    assert!(
        revalidate_host_notification_candidate(&db, &candidate, B_ACCOUNT, true)
            .await
            .is_err(),
        "an error must propagate, never read as deliverable"
    );
}

/// Seed an obligation candidate for `account` on `message`.
async fn seed_obligation(db: &Db, account: &str, message: &str, source: &str) {
    db.drain_captures_for_tests().await;
    let pool = crate::common::fixture_write_pool(db).await;
    let mut tx = pool.begin().await.unwrap();
    let mut act_alloc = native_ce::act::ActAllocation::new();
    native_ce::awareness::append_notification_candidate_in(
        &mut tx,
        account,
        message,
        "human_obligation",
        "routine",
        None,
        "metadata_only",
        "portable_default",
        "messaging-awareness-v1",
        "record.created",
        source,
        &mut act_alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// This slice refuses a policy-evaluated send to two addressees, so the second
/// recipient's obligation is seeded the way a send would have proposed it.
#[tokio::test]
async fn partial_closure_withdraws_only_the_recipient_who_replied() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[C],
        "partial-req",
        json!({"expectation":"reply"}),
    )
    .await;
    seed_obligation(&db, C_ACCOUNT, &request, "src-partial-c").await;
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "human_obligation")]
    );

    dm(
        &registry,
        &db,
        (B_ACCOUNT, B),
        A,
        &[C],
        "partial-reply",
        json!({"links":[{"target_id":request,"relationship":"reply_to"}]}),
    )
    .await;
    let obligations = |rows: Vec<(String, String)>| -> Vec<(String, String)> {
        rows.into_iter()
            .filter(|(_, reason)| reason == "human_obligation")
            .collect()
    };
    assert_eq!(
        obligations(effective(&db, &request).await),
        vec![pair(C_ACCOUNT, "human_obligation")],
        "B's obligation closed; C's did not"
    );
    assert_eq!(
        state(&db, &request, C_ACCOUNT).await,
        MessageExpectationState::Open
    );

    dm(
        &registry,
        &db,
        (C_ACCOUNT, C),
        A,
        &[B],
        "partial-reply-c",
        json!({"links":[{"target_id":request,"relationship":"reply_to"}]}),
    )
    .await;
    assert_eq!(obligations(effective(&db, &request).await), vec![]);
}

#[tokio::test]
async fn a_reply_to_a_reply_closes_only_the_obligation_it_answers() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "chain-1",
        json!({"expectation":"reply"}),
    )
    .await;
    let second = dm(
        &registry,
        &db,
        (B_ACCOUNT, B),
        A,
        &[],
        "chain-2",
        json!({"expectation":"reply","links":[{"target_id":first,"relationship":"reply_to"}]}),
    )
    .await;
    assert_eq!(
        effective(&db, &first).await,
        vec![],
        "B's reply closed A's request"
    );
    assert_eq!(
        effective(&db, &second).await,
        vec![pair(A_ACCOUNT, "human_obligation")],
        "and asks A in turn"
    );

    dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "chain-3",
        json!({"links":[{"target_id":second,"relationship":"reply_to"}]}),
    )
    .await;
    assert_eq!(
        effective(&db, &second).await,
        vec![],
        "A's reply closed B's question"
    );
    assert_eq!(effective(&db, &first).await, vec![]);
}

#[tokio::test]
async fn a_blocked_reply_closes_nothing_until_resume_delivery_delivers_it() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "blocked-req",
        json!({"expectation":"reply"}),
    )
    .await;

    // B's policy holds B's own sends for authority.
    let policy = call_tool(
        &registry,
        &db,
        B_ACCOUNT,
        "create_record",
        json!({
            "type":"Document","kind":"escalation-policy","name":"Block B's sends",
            "body":serde_json::to_string(&json!({
                "format":"native.escalation-policy.v1",
                "issuer_principal_id":"native/withdraw-b",
                "statements":[{
                    "statement_id":"block-b","kind":"hard_rule",
                    "scope":{"action.destination_kind":["same_workspace"]},
                    "when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},
                    "effect":{"disposition":"block_and_request_authority"}
                }]
            })).unwrap()
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call_tool(
        &registry,
        &db,
        B_ACCOUNT,
        "manage_instructions",
        json!({
            "action":"create_binding","scope":"member","source_record_id":policy,
            "position":0,"idempotency_key":"bind-block-b",
            "reason":"Bind the blocking policy for the withdrawal fixture."
        }),
    )
    .await;

    let blocked = call_tool(
        &registry,
        &db,
        B_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send","body":"B's answer, held for A's authority","expectation":"none",
            "preview":"B answers the request.","idempotency_key":"blocked-answer",
            "origin":{"type":"direct","participant_ids":[B,A]},
            "addressed_to":[A],
            "links":[{"target_id":&request,"relationship":"reply_to"}],
            "reason":"A reply that policy holds back."
        }),
    )
    .await;
    assert_eq!(blocked["delivery"]["delivered"], false);
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "human_obligation")],
        "an undelivered reply answers nothing"
    );

    let intervention_id = blocked["delivery"]["intervention_id"].as_str().unwrap();
    let view = call_tool(
        &registry,
        &db,
        A_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await;
    let decision = call_tool(
        &registry,
        &db,
        A_ACCOUNT,
        "create_record",
        json!({"type":"Resolution","kind":"decision","name":"Approve B's reply",
               "body":"Approved for this exact send only."}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call_tool(
        &registry,
        &db,
        A_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"resume_delivery","intervention_id":intervention_id,
            "expected_intervention_seq":view["projection_seq"],
            "expected_evaluation_digest":blocked["delivery"]["evaluation_digest"],
            "authority_evidence_record_id":decision,
            "idempotency_key":"resume-blocked-answer",
            "reason":"Approve this exact reply."
        }),
    )
    .await;
    assert_eq!(
        held_by(&db, &request, B_ACCOUNT).await,
        vec![],
        "delivery by resume_delivery closes the obligation"
    );
}

async fn call_tool(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    tool: &str,
    args: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn replaying_a_closing_write_appends_no_further_events() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    // reply: the same keyed send twice
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "replay-req",
        json!({"expectation":"reply"}),
    )
    .await;
    let links = json!({"links":[{"target_id":&request,"relationship":"reply_to"}]});
    let reply = dm(
        &registry,
        &db,
        (B_ACCOUNT, B),
        A,
        &[],
        "replay-reply",
        links.clone(),
    )
    .await;
    let after_reply = events(&db, &request).await;
    assert_eq!(held_by(&db, &request, B_ACCOUNT).await, vec![]);
    let again = dm(
        &registry,
        &db,
        (B_ACCOUNT, B),
        A,
        &[],
        "replay-reply",
        links,
    )
    .await;
    assert_eq!(again, reply, "an exact retry is the same message");
    assert_eq!(events(&db, &request).await, after_reply);

    // acknowledgement: the same key twice
    let ask = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "replay-ack-req",
        json!({"expectation":"ack"}),
    )
    .await;
    let ack = json!({"action":"satisfy_acknowledgement_expectation_with_reaction",
                     "message_id":ask,"idempotency_key":"replay-ack"});
    call(&registry, &db, B_ACCOUNT, ack.clone()).await.unwrap();
    let after_ack = events(&db, &ask).await;
    assert_eq!(held_by(&db, &ask, B_ACCOUNT).await, vec![]);
    call(&registry, &db, B_ACCOUNT, ack).await.unwrap();
    assert_eq!(events(&db, &ask).await, after_ack);

    // mark: the same key twice, then a fresh key on the already-marked message
    let marked = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "replay-mark-req",
        json!({"expectation":"reply"}),
    )
    .await;
    mark(&registry, &db, B_ACCOUNT, &marked, "replay-mark").await;
    let after_mark = events(&db, &marked).await;
    assert_eq!(held_by(&db, &marked, B_ACCOUNT).await, vec![]);
    mark(&registry, &db, B_ACCOUNT, &marked, "replay-mark").await;
    mark(&registry, &db, B_ACCOUNT, &marked, "replay-mark-again").await;
    assert_eq!(events(&db, &marked).await, after_mark);
}

#[tokio::test]
async fn archiving_again_withdraws_what_was_proposed_since() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let message = dm(&registry, &db, (A_ACCOUNT, A), B, &[], "again", json!({})).await;
    let pref = |preference: &str, version: i64, key: &str| {
        let mut args = json!({"action":"set_preference","message_id":message,
            "preference":preference,"expected_version":version,"idempotency_key":key});
        if preference == "snooze" {
            args["snoozed_until"] = json!("2099-01-01T00:00:00Z");
        }
        args
    };
    call(&registry, &db, B_ACCOUNT, pref("archive", 0, "again-1"))
        .await
        .unwrap();
    call(&registry, &db, B_ACCOUNT, pref("snooze", 1, "again-2"))
        .await
        .unwrap();
    assert_eq!(
        held_by(&db, &message, B_ACCOUNT).await,
        vec![pair(B_ACCOUNT, "snooze_due")]
    );
    call(&registry, &db, B_ACCOUNT, pref("archive", 2, "again-3"))
        .await
        .unwrap();
    assert_eq!(held_by(&db, &message, B_ACCOUNT).await, vec![]);
}

/// The closure check derives on the connection revalidation already holds, so
/// callers beyond the pool size cannot starve one another waiting for a second.
#[tokio::test]
async fn concurrent_revalidations_beyond_the_pool_size_all_complete() {
    use native_ce::awareness::revalidate_host_notification_candidate;

    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let request = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        B,
        &[],
        "pool-req",
        json!({"expectation":"reply"}),
    )
    .await;
    let candidate: String = sqlx::query_scalar(
        "SELECT candidate_id FROM notification_candidates WHERE message_id=? AND reason='human_obligation'",
    )
    .bind(&request)
    .fetch_one(db.pool())
    .await
    .unwrap();

    let results = futures::future::join_all((0..16).map(|_| {
        let (db, candidate) = (db.clone(), candidate.clone());
        tokio::spawn(async move {
            revalidate_host_notification_candidate(&db, &candidate, B_ACCOUNT, true).await
        })
    }))
    .await;
    for result in results {
        let revalidated = result.unwrap().unwrap().unwrap();
        assert!(revalidated.effective_viewable_unmuted);
    }
}
