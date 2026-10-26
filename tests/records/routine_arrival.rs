//! `routine_arrival` notification candidates: a plain DM, or a reply in a
//! thread you are in, proposes one candidate per other participant, governed
//! by the recipient's own arrival preference and per-conversation mute.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::awareness::{
    harvest_host_notification_candidates, revalidate_host_notification_candidate,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const A_ACCOUNT: &str = "acct_arrival_a";
const B_ACCOUNT: &str = "acct_arrival_b";
const C_ACCOUNT: &str = "acct_arrival_c";
const A: &str = "6d320000-0000-4000-8000-000000000001";
const B: &str = "6d320000-0000-4000-8000-000000000002";
const C: &str = "6d320000-0000-4000-8000-000000000003";

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
    if matches!(
        args["action"].as_str(),
        Some("send" | "set_preference" | "set_notification_preference")
    ) {
        args["reason"] = json!("Exercise routine arrival candidates in an integration fixture.");
    }
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
        (A, "native/arrival-a", A_ACCOUNT),
        (B, "native/arrival-b", B_ACCOUNT),
        (C, "native/arrival-c", C_ACCOUNT),
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

async fn channel(registry: &ToolRegistry, db: &Db) -> String {
    channel_by(registry, db, A_ACCOUNT, &[A_ACCOUNT, B_ACCOUNT, C_ACCOUNT]).await
}

/// A Collection created by `owner` and editable by `members`.
async fn channel_by(registry: &ToolRegistry, db: &Db, owner: &str, members: &[&str]) -> String {
    let result = registry
        .call(
            db.clone(),
            Caller::authenticated(owner),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({"type":"Collection","kind":"folder","name":"Arrival channel"}),
            ),
        )
        .await
        .unwrap();
    let id = result["id"].as_str().unwrap().to_owned();
    set_channel_members(db, &id, members).await;
    id
}

async fn set_channel_members(db: &Db, collection: &str, members: &[&str]) {
    replace_explicit_policy(
        db,
        "test:arrival-channel-policy",
        collection,
        members
            .iter()
            .map(|account| AllowEntry::account(*account, Capability::Edit))
            .collect(),
    )
    .await
    .unwrap();
}

/// A direct message from `from` to the `others`; extra args merge over it.
async fn dm(
    registry: &ToolRegistry,
    db: &Db,
    from: (&str, &str),
    others: &[&str],
    key: &str,
    extra: Value,
) -> String {
    let mut participants = vec![from.1];
    participants.extend_from_slice(others);
    let mut args = json!({
        "action":"send","body":"hello there","expectation":"none","idempotency_key":key,
        "origin":{"type":"direct","participant_ids":participants},
        // Policy takes one addressee per send; the rest of the context still hears.
        "addressed_to":[others[0]],
    });
    args.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    call(registry, db, from.0, args).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A post in the channel, optionally a reply to `root`.
async fn post(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    collection: &str,
    root: Option<&str>,
    key: &str,
) -> String {
    let mut args = json!({
        "action":"send","body":"channel post","expectation":"none","idempotency_key":key,
        "origin":{"type":"collection","collection_id":collection},
        "addressed_to":[],"home_id":collection,
    });
    if let Some(root) = root {
        args["links"] = json!([{"target_id":root,"relationship":"reply_to"}]);
    }
    call(registry, db, account, args).await.unwrap()["id"]
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

fn pair(account: &str, reason: &str) -> (String, String) {
    (account.to_owned(), reason.to_owned())
}

async fn set_arrival(registry: &ToolRegistry, db: &Db, account: &str, arrival: &str, key: &str) {
    call(
        registry,
        db,
        account,
        json!({"action":"set_notification_preference","arrival":arrival,"idempotency_key":key}),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_dm_notifies_the_other_participant_and_never_the_sender() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    let pair_dm = dm(&registry, &db, (A_ACCOUNT, A), &[B], "pair", json!({})).await;
    assert_eq!(
        effective(&db, &pair_dm).await,
        vec![pair(B_ACCOUNT, "routine_arrival")],
        "only the other participant is notified; the sender gets nothing"
    );

    // Every other participant of a group context is notified, again not the sender.
    let group = dm(&registry, &db, (B_ACCOUNT, B), &[A, C], "group", json!({})).await;
    assert_eq!(
        effective(&db, &group).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );
    let evaluator: String = sqlx::query_scalar(
        "SELECT evaluator_kind FROM notification_candidates WHERE message_id=? LIMIT 1",
    )
    .bind(&pair_dm)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(evaluator, "recipient_policy");
    assert!(
        native_ce::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn a_thread_reply_notifies_the_root_author_and_earlier_repliers_only() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection = channel(&registry, &db).await;

    // A channel post is not a DM and addresses nobody: no candidates.
    let root = post(&registry, &db, A_ACCOUNT, &collection, None, "root").await;
    assert_eq!(effective(&db, &root).await, vec![]);

    // B replies: the root's author hears; C, who has not taken part, does not.
    let first = post(&registry, &db, B_ACCOUNT, &collection, Some(&root), "r1").await;
    assert_eq!(
        effective(&db, &first).await,
        vec![pair(A_ACCOUNT, "routine_arrival")]
    );

    // C replies: now both the root author and the earlier replier hear.
    let second = post(&registry, &db, C_ACCOUNT, &collection, Some(&root), "r2").await;
    assert_eq!(
        effective(&db, &second).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(B_ACCOUNT, "routine_arrival")
        ]
    );

    // A replies to a reply: still the one thread; B and C hear, A does not.
    let third = post(&registry, &db, A_ACCOUNT, &collection, Some(&first), "r3").await;
    assert_eq!(
        effective(&db, &third).await,
        vec![
            pair(B_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );
}

#[tokio::test]
async fn a_mention_or_obligation_already_covering_the_recipient_is_not_duplicated() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    let mentioned = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        &[B, C],
        "mention",
        json!({"body":"B and C","mentions":[{
            "mention_id":"arrival-mention","target_kind":"principal","target_id":B,
            "span_start":0,"span_end":1,"authored_label":"B"
        }]}),
    )
    .await;
    assert_eq!(
        effective(&db, &mentioned).await,
        vec![
            pair(B_ACCOUNT, "principal_mention"),
            pair(C_ACCOUNT, "routine_arrival")
        ],
        "the mentioned recipient keeps just the mention"
    );

    let asked = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        &[B],
        "obligation",
        json!({"expectation":"reply"}),
    )
    .await;
    assert_eq!(
        effective(&db, &asked).await,
        vec![pair(B_ACCOUNT, "human_obligation")]
    );
}

#[tokio::test]
async fn the_arrival_preference_governs_creation_and_harvest() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    // Default is all, and it reads back.
    let default = call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"get_notification_preference"}),
    )
    .await
    .unwrap();
    assert_eq!(default["arrival"], "all");
    let all = dm(&registry, &db, (A_ACCOUNT, A), &[B], "all", json!({})).await;
    assert_eq!(
        effective(&db, &all).await,
        vec![pair(B_ACCOUNT, "routine_arrival")]
    );

    // Harvest checks it again: flipping to off withholds the candidate that
    // was created while the preference was all.
    let before = harvest_host_notification_candidates(&db, B_ACCOUNT, true, 0, 10)
        .await
        .unwrap();
    assert_eq!(before.candidates.len(), 1);
    assert!(!before.candidates[0].muted);
    set_arrival(&registry, &db, B_ACCOUNT, "off", "pref-1").await;
    let after = harvest_host_notification_candidates(&db, B_ACCOUNT, true, 0, 10)
        .await
        .unwrap();
    assert!(after.candidates[0].muted, "withheld by preference");
    assert!(
        !revalidate_host_notification_candidate(
            &db,
            &before.candidates[0].candidate_id,
            B_ACCOUNT,
            true
        )
        .await
        .unwrap()
        .unwrap()
        .effective_viewable_unmuted,
        "and at delivery revalidation"
    );

    // off: no routine arrival is created. Mentions and obligations are
    // untouched: they are still created and still harvest and revalidate as
    // deliverable.
    set_arrival(&registry, &db, B_ACCOUNT, "off", "pref-2-again").await;
    let off = dm(&registry, &db, (A_ACCOUNT, A), &[B], "off", json!({})).await;
    assert_eq!(effective(&db, &off).await, vec![]);
    let off_mention = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        &[B],
        "off-mention",
        json!({"body":"B","mentions":[{
            "mention_id":"arrival-off-mention","target_kind":"principal","target_id":B,
            "span_start":0,"span_end":1,"authored_label":"B"
        }]}),
    )
    .await;
    let off_obligation = dm(
        &registry,
        &db,
        (A_ACCOUNT, A),
        &[B],
        "off-obligation",
        json!({"expectation":"reply"}),
    )
    .await;
    assert_eq!(
        effective(&db, &off_mention).await,
        vec![pair(B_ACCOUNT, "principal_mention")]
    );
    assert_eq!(
        effective(&db, &off_obligation).await,
        vec![pair(B_ACCOUNT, "human_obligation")]
    );
    let off_harvest = harvest_host_notification_candidates(&db, B_ACCOUNT, true, 0, 50)
        .await
        .unwrap();
    for reason in ["principal_mention", "human_obligation"] {
        let rows: Vec<_> = off_harvest
            .candidates
            .iter()
            .filter(|candidate| candidate.reason == reason)
            .collect();
        assert!(!rows.is_empty(), "{reason} still harvests under off");
        assert!(
            rows.iter().all(|candidate| !candidate.muted),
            "{reason} is deliverable under off"
        );
        for row in rows {
            assert!(
                revalidate_host_notification_candidate(&db, &row.candidate_id, B_ACCOUNT, true)
                    .await
                    .unwrap()
                    .unwrap()
                    .effective_viewable_unmuted,
                "{reason} revalidates under off"
            );
        }
    }
    // The routine arrival created while the preference was `all` stays withheld.
    assert!(off_harvest
        .candidates
        .iter()
        .filter(|candidate| candidate.reason == "routine_arrival")
        .all(|candidate| candidate.muted));

    // The preference is the caller's own: A is still on the default.
    let other = call(
        &registry,
        &db,
        A_ACCOUNT,
        json!({"action":"get_notification_preference"}),
    )
    .await
    .unwrap();
    assert_eq!(other["arrival"], "all");

    // Back to all: arrivals resume. Reusing a key for a different value is refused.
    set_arrival(&registry, &db, B_ACCOUNT, "all", "pref-3").await;
    let resumed = dm(&registry, &db, (A_ACCOUNT, A), &[B], "resumed", json!({})).await;
    assert_eq!(
        effective(&db, &resumed).await,
        vec![pair(B_ACCOUNT, "routine_arrival")]
    );
    let reused = call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_notification_preference","arrival":"off","idempotency_key":"pref-3"}),
    )
    .await;
    assert!(reused.is_err());
    let invalid = call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_notification_preference","arrival":"sometimes","idempotency_key":"pref-4"}),
    )
    .await;
    assert!(invalid.is_err());
}

#[tokio::test]
async fn muting_a_conversation_keeps_its_later_arrivals_quiet() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    // Direct context: B mutes the first message, so the next one in the same
    // exact participant set stays quiet for B; a different set is unaffected.
    let first = dm(&registry, &db, (A_ACCOUNT, A), &[B], "mute-1", json!({})).await;
    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_preference","message_id":first,"preference":"mute",
               "expected_version":0,"idempotency_key":"mute-dm"}),
    )
    .await
    .unwrap();
    let second = dm(&registry, &db, (A_ACCOUNT, A), &[B], "mute-2", json!({})).await;
    assert_eq!(effective(&db, &second).await, vec![]);
    let group = dm(&registry, &db, (A_ACCOUNT, A), &[B, C], "mute-3", json!({})).await;
    assert_eq!(
        effective(&db, &group).await,
        vec![
            pair(B_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );

    // Thread: B holds a pending arrival on C's reply, then mutes the root.
    // That pending candidate is withheld at harvest and at delivery
    // revalidation (for B, the muter), and B's later arrivals stay quiet while
    // the other participants are unaffected.
    let collection = channel(&registry, &db).await;
    let root = post(&registry, &db, A_ACCOUNT, &collection, None, "thread-root").await;
    let first = post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&root),
        "thread-1",
    )
    .await;
    assert_eq!(
        effective(&db, &first).await,
        vec![pair(A_ACCOUNT, "routine_arrival")]
    );
    let early = post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        Some(&root),
        "thread-2",
    )
    .await;
    assert_eq!(
        effective(&db, &early).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(B_ACCOUNT, "routine_arrival")
        ]
    );
    let pending_id: String = sqlx::query_scalar(
        "SELECT candidate_id FROM notification_candidates
          WHERE message_id=? AND recipient_account_id=? AND status='effective'",
    )
    .bind(&early)
    .bind(B_ACCOUNT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let harvested_muted = |account: &'static str| {
        let db = &db;
        let pending_id = pending_id.clone();
        async move {
            harvest_host_notification_candidates(db, account, true, 0, 50)
                .await
                .unwrap()
                .candidates
                .into_iter()
                .find(|candidate| candidate.candidate_id == pending_id)
                .map(|candidate| candidate.muted)
        }
    };
    assert_eq!(
        harvested_muted(B_ACCOUNT).await,
        Some(false),
        "deliverable before the mute"
    );
    assert!(
        revalidate_host_notification_candidate(&db, &pending_id, B_ACCOUNT, true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
    );

    call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_preference","message_id":root,"preference":"mute",
               "expected_version":0,"idempotency_key":"mute-thread"}),
    )
    .await
    .unwrap();
    assert_eq!(
        harvested_muted(B_ACCOUNT).await,
        Some(true),
        "muting the thread withholds B's pending arrival at harvest"
    );
    assert!(
        !revalidate_host_notification_candidate(&db, &pending_id, B_ACCOUNT, true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted,
        "and at delivery revalidation"
    );
    let a_view = harvest_host_notification_candidates(&db, A_ACCOUNT, true, 0, 10)
        .await
        .unwrap();
    assert!(
        a_view.candidates.iter().all(|candidate| !candidate.muted),
        "B's mute is private to B"
    );

    let late = post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&root),
        "thread-3",
    )
    .await;
    assert_eq!(
        effective(&db, &late).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );
    let reply_to_b = post(
        &registry,
        &db,
        A_ACCOUNT,
        &collection,
        Some(&late),
        "thread-4",
    )
    .await;
    assert_eq!(
        effective(&db, &reply_to_b).await,
        vec![pair(C_ACCOUNT, "routine_arrival")],
        "B muted the thread, so B is not notified of A's reply even though B replied"
    );
}

#[tokio::test]
async fn opening_and_snoozing_withdraw_the_arrival() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();

    let opened = dm(&registry, &db, (A_ACCOUNT, A), &[B], "open", json!({})).await;
    assert_eq!(
        effective(&db, &opened).await,
        vec![pair(B_ACCOUNT, "routine_arrival")]
    );
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-arrival");
    let ids = vec![opened.clone()];
    let token = issuer.issue(B_ACCOUNT, "opened", &ids, 60).unwrap();
    let caller = Caller::authenticated(B_ACCOUNT)
        .with_human_interaction_token(&issuer, &token, "opened", &ids)
        .unwrap();
    registry
        .call(
            db.clone(),
            caller,
            "manage_messages",
            crate::common::with_test_reason(
                "manage_messages",
                json!({"action":"mutate_human_awareness","message_ids":ids,"stage":"opened",
                       "expected_versions":{opened.clone():0},"idempotency_key":"open-1",
                       "reason":"Opened in the arrival fixture."}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(effective(&db, &opened).await, vec![]);

    let snoozed = dm(&registry, &db, (A_ACCOUNT, A), &[B], "snooze", json!({})).await;
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
        vec![pair(B_ACCOUNT, "snooze_due")],
        "snoozing withdraws the arrival and leaves only the reminder"
    );
}

#[tokio::test]
async fn a_recipient_who_can_no_longer_read_the_message_gets_no_candidate() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    // B owns the channel, so only A and C can lose access.
    let collection = channel_by(
        &registry,
        &db,
        B_ACCOUNT,
        &[A_ACCOUNT, B_ACCOUNT, C_ACCOUNT],
    )
    .await;
    let root = post(&registry, &db, A_ACCOUNT, &collection, None, "revoked-root").await;
    let before = post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        Some(&root),
        "revoked-1",
    )
    .await;
    assert_eq!(
        effective(&db, &before).await,
        vec![pair(A_ACCOUNT, "routine_arrival")]
    );

    // A loses the Collection. A is still the root's author, but cannot read
    // what B writes next, so no candidate is stored for A; C still hears.
    set_channel_members(&db, &collection, &[B_ACCOUNT, C_ACCOUNT]).await;
    let after = post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&root),
        "revoked-2",
    )
    .await;
    assert_eq!(
        effective(&db, &after).await,
        vec![pair(C_ACCOUNT, "routine_arrival")]
    );
    let stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND recipient_account_id=?",
    )
    .bind(&after)
    .bind(A_ACCOUNT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(stored, 0, "not even a withdrawn row");
}

async fn bind_blocking_policy(registry: &ToolRegistry, db: &Db) {
    let source = call_tool(
        registry,
        db,
        A_ACCOUNT,
        "create_record",
        json!({
            "type":"Document","kind":"escalation-policy","name":"Block A's sends",
            "body":serde_json::to_string(&json!({
                "format":"native.escalation-policy.v1",
                "issuer_principal_id":"native/arrival-a",
                "statements":[{
                    "statement_id":"block-a",
                    "kind":"hard_rule",
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
        registry,
        db,
        A_ACCOUNT,
        "manage_instructions",
        json!({
            "action":"create_binding","scope":"member","source_record_id":source,
            "position":0,"idempotency_key":"bind-block-a",
            "reason":"Bind the blocking policy for the arrival fixture."
        }),
    )
    .await;
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
async fn only_delivered_messages_make_authors_thread_participants() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection = channel(&registry, &db).await;

    // B starts the thread. A's policy then blocks A's own sends.
    let root = post(&registry, &db, B_ACCOUNT, &collection, None, "blocked-root").await;
    bind_blocking_policy(&registry, &db).await;
    let blocked = call_tool(
        &registry,
        &db,
        A_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send","body":"A's reply, held for B's authority","expectation":"none",
            "preview":"A reply to the launch thread.","idempotency_key":"blocked-reply",
            "origin":{"type":"collection","collection_id":&collection},
            "addressed_to":[B],"home_id":&collection,
            "links":[{"target_id":&root,"relationship":"reply_to"}],
            "reason":"A reply that policy holds back."
        }),
    )
    .await;
    assert_eq!(blocked["delivery"]["delivered"], false);
    let blocked_id = blocked["id"].as_str().unwrap().to_owned();
    assert_eq!(effective(&db, &blocked_id).await, vec![]);

    // C replies. A's only message is the undelivered draft, so A is not a
    // participant: only the root's author hears.
    let c_reply = post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        Some(&root),
        "blocked-c1",
    )
    .await;
    assert_eq!(
        effective(&db, &c_reply).await,
        vec![pair(B_ACCOUNT, "routine_arrival")]
    );

    // B authorises delivery. The resumed reply is now a delivered Message and
    // proposes arrivals to its thread (B, the root's author, and C), not A.
    let intervention_id = blocked["delivery"]["intervention_id"].as_str().unwrap();
    let view = call_tool(
        &registry,
        &db,
        B_ACCOUNT,
        "manage_interventions",
        json!({"action":"get","intervention_id":intervention_id}),
    )
    .await;
    let decision = call_tool(
        &registry,
        &db,
        B_ACCOUNT,
        "create_record",
        json!({"type":"Resolution","kind":"decision","name":"Approve A's reply",
               "body":"Approved for this exact send only."}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let resumed = call_tool(
        &registry,
        &db,
        B_ACCOUNT,
        "manage_interventions",
        json!({
            "action":"resume_delivery","intervention_id":intervention_id,
            "expected_intervention_seq":view["projection_seq"],
            "expected_evaluation_digest":blocked["delivery"]["evaluation_digest"],
            "authority_evidence_record_id":decision,
            "idempotency_key":"resume-blocked-reply",
            "reason":"Approve this exact reply."
        }),
    )
    .await;
    assert_eq!(resumed["state"]["execution"]["state"], "resumed");
    assert_eq!(
        effective(&db, &blocked_id).await,
        vec![
            pair(B_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ],
        "resume_delivery proposes arrivals, and never to the sender"
    );

    // Delivered later, A's reply now counts: a new reply by C reaches A too.
    let later = post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        Some(&root),
        "blocked-c2",
    )
    .await;
    assert_eq!(
        effective(&db, &later).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(B_ACCOUNT, "routine_arrival")
        ]
    );
}

#[tokio::test]
async fn a_thread_deeper_than_sixty_four_replies_keeps_its_root_and_its_mute() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection = channel(&registry, &db).await;

    // A starts the thread; B answers 70 levels deep, each reply to the last.
    let root = post(&registry, &db, A_ACCOUNT, &collection, None, "deep-root").await;
    let mut tip = root.clone();
    for level in 0..70 {
        tip = post(
            &registry,
            &db,
            B_ACCOUNT,
            &collection,
            Some(&tip),
            &format!("deep-{level}"),
        )
        .await;
    }
    // C replies at the bottom: the root's author, 71 levels up, still hears,
    // and so does B.
    let bottom = post(&registry, &db, C_ACCOUNT, &collection, Some(&tip), "deep-c").await;
    assert_eq!(
        effective(&db, &bottom).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(B_ACCOUNT, "routine_arrival")
        ]
    );
    // A reply straight to the root still sees the participant who is only
    // present deep in the chain.
    let shallow = post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&root),
        "deep-shallow",
    )
    .await;
    assert_eq!(
        effective(&db, &shallow).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );

    // A mutes the real root. The mute reaches a reply 71 levels below it.
    call(
        &registry,
        &db,
        A_ACCOUNT,
        json!({"action":"set_preference","message_id":root,"preference":"mute",
               "expected_version":0,"idempotency_key":"mute-deep-root"}),
    )
    .await
    .unwrap();
    let after_mute = post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        Some(&tip),
        "deep-c2",
    )
    .await;
    assert_eq!(
        effective(&db, &after_mute).await,
        vec![pair(B_ACCOUNT, "routine_arrival")],
        "A muted the root, so A is quiet however deep the reply"
    );
}

#[tokio::test]
async fn a_preference_key_is_reserved_even_when_the_value_does_not_change() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let set = |arrival: &'static str, key: &'static str| {
        let registry = &registry;
        let db = &db;
        async move {
            call(
                registry,
                db,
                B_ACCOUNT,
                json!({"action":"set_notification_preference","arrival":arrival,"idempotency_key":key}),
            )
            .await
        }
    };
    let current = || async {
        call(
            &registry,
            &db,
            B_ACCOUNT,
            json!({"action":"get_notification_preference"}),
        )
        .await
        .unwrap()["arrival"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    // `all` is already the default: the write is not a change, but it
    // reserves the key.
    let first = set("all", "key-k").await.unwrap();
    assert_eq!(first["changed"], false);
    assert_eq!(set("off", "key-j").await.unwrap()["changed"], true);
    assert_eq!(current().await, "off");

    // A retry of K converges on K's own intent without undoing the later
    // choice, and K cannot be reused for another value.
    let retry = set("all", "key-k").await.unwrap();
    assert_eq!(retry["idempotent"], true);
    assert_eq!(current().await, "off");
    assert!(set("dms_and_mentions", "key-k").await.is_err());
    assert_eq!(current().await, "off");

    // A retry of a changing write also stays put after a newer choice.
    set("dms_and_mentions", "key-m").await.unwrap();
    set("all", "key-n").await.unwrap();
    assert_eq!(
        set("dms_and_mentions", "key-m").await.unwrap()["idempotent"],
        true
    );
    assert_eq!(current().await, "all");
}

/// The engine cannot know a recipient's live role when a candidate is created,
/// so a participant downgraded to guest after taking part still gets a stored
/// candidate. Harvest and revalidation (live footing) are the binding check,
/// and no read surface may show that candidate.
#[tokio::test]
async fn a_downgraded_guests_stored_candidate_surfaces_nowhere() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    // Members-only Collection: access comes from the members baseline, not
    // from any account grant.
    let collection = channel_by(&registry, &db, A_ACCOUNT, &[]).await;
    replace_explicit_policy(
        &db,
        "test:arrival-members-only",
        &collection,
        vec![AllowEntry::members(Capability::Edit)],
    )
    .await
    .unwrap();
    let root = post(&registry, &db, B_ACCOUNT, &collection, None, "guest-root").await;
    post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        Some(&root),
        "guest-c",
    )
    .await;

    // C is downgraded to guest. A replies: creation cannot see C's new role,
    // so a candidate is stored for C (and for B).
    let reply = post(
        &registry,
        &db,
        A_ACCOUNT,
        &collection,
        Some(&root),
        "guest-a",
    )
    .await;
    assert_eq!(
        effective(&db, &reply).await,
        vec![
            pair(B_ACCOUNT, "routine_arrival"),
            pair(C_ACCOUNT, "routine_arrival")
        ]
    );
    let candidate_id: String = sqlx::query_scalar(
        "SELECT candidate_id FROM notification_candidates
          WHERE message_id=? AND recipient_account_id=?",
    )
    .bind(&reply)
    .bind(C_ACCOUNT)
    .fetch_one(db.pool())
    .await
    .unwrap();

    let (reply_ref, candidate_ref) = (&reply, &candidate_id);
    let guest = || Caller::authenticated(C_ACCOUNT).with_hosting_member(false);
    let member = || Caller::authenticated(C_ACCOUNT).with_hosting_member(true);
    let as_caller = |caller: Caller, args: Value| {
        let (registry, db) = (&registry, &db);
        async move {
            registry
                .call(
                    db.clone(),
                    caller,
                    "manage_messages",
                    crate::common::with_test_reason("manage_messages", args),
                )
                .await
        }
    };

    // Hosted delivery: harvest and revalidation use the live footing.
    let harvest = |is_member: bool| {
        let db = &db;
        async move {
            harvest_host_notification_candidates(db, C_ACCOUNT, is_member, 0, 50)
                .await
                .unwrap()
                .candidates
                .into_iter()
                .filter(|candidate| &candidate.candidate_id == candidate_ref)
                .count()
        }
    };
    assert_eq!(harvest(true).await, 1, "as a member the candidate is real");
    assert_eq!(harvest(false).await, 0, "harvest rejects it for a guest");
    let revalidated = |is_member: bool| {
        let db = &db;
        async move {
            revalidate_host_notification_candidate(db, candidate_ref, C_ACCOUNT, is_member)
                .await
                .unwrap()
                .unwrap()
                .effective_viewable_unmuted
        }
    };
    assert!(revalidated(true).await);
    assert!(!revalidated(false).await, "revalidation rejects it too");

    // Read surfaces: the candidate listing, the inbox and its candidate counts,
    // attention, and per-message state.
    let listed = |caller: Caller| {
        let as_caller = &as_caller;
        async move {
            as_caller(caller, json!({"action":"list_notification_candidates"}))
                .await
                .unwrap()["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|candidate| candidate["message_id"] == json!(reply_ref))
                .count()
        }
    };
    assert_eq!(listed(member()).await, 1);
    assert_eq!(listed(guest()).await, 0);

    let inbox = |caller: Caller| {
        let as_caller = &as_caller;
        async move {
            as_caller(
                caller,
                json!({"action":"list_inbox","view":"browse","limit":50}),
            )
            .await
            .unwrap()["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| item["message_id"] == json!(reply_ref))
                .map(|item| item["delivery"]["candidate_count"].as_i64().unwrap())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(inbox(member()).await, vec![1]);
    assert_eq!(inbox(guest()).await, Vec::<i64>::new());

    let attention = |caller: Caller| {
        let as_caller = &as_caller;
        async move {
            as_caller(caller, json!({"action":"get_attention"}))
                .await
                .unwrap()["has_new_messages"]
                .as_bool()
                .unwrap()
        }
    };
    assert!(attention(member()).await);
    assert!(!attention(guest()).await);

    let state = as_caller(
        guest(),
        json!({"action":"list_message_state","message_ids":[&reply]}),
    )
    .await;
    assert!(
        state.is_err() || !state.unwrap().to_string().contains(&reply),
        "per-message state does not name an unreadable message"
    );
}

/// A private draft (never delivered) can carry `reply_to` links to
/// two unrelated threads. Only delivered Messages join a thread, so the draft
/// must not bridge them.
#[tokio::test]
async fn an_undelivered_draft_does_not_bridge_two_threads() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection = channel(&registry, &db).await;

    // Two unrelated threads: A's, and C's.
    let a_root = post(
        &registry,
        &db,
        A_ACCOUNT,
        &collection,
        None,
        "bridge-a-root",
    )
    .await;
    let c_root = post(
        &registry,
        &db,
        C_ACCOUNT,
        &collection,
        None,
        "bridge-c-root",
    )
    .await;

    // A private draft (never sent, so never delivered) carries `reply_to`
    // links to both threads.
    let draft = call_tool(
        &registry,
        &db,
        A_ACCOUNT,
        "create_record",
        json!({
            "type":"Message","kind":"text","body":"private draft","addressed_to":[],
            "facets":{"expectation":"none"},
            "links":[
                {"target_id":&a_root,"relationship":"reply_to"},
                {"target_id":&c_root,"relationship":"reply_to"}
            ]
        }),
    )
    .await;
    let links: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id=? AND relationship='reply_to'",
    )
    .bind(draft["id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(links, 2, "the draft really links both threads");

    // B replies in A's thread. C is only in the other thread: no candidate for
    // C, while A, the root's author, hears.
    let reply = post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&a_root),
        "bridge-b",
    )
    .await;
    assert_eq!(
        effective(&db, &reply).await,
        vec![pair(A_ACCOUNT, "routine_arrival")]
    );
    // And the other way round: C's thread has no sign of A's.
    let c_reply = post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&c_root),
        "bridge-b2",
    )
    .await;
    assert_eq!(
        effective(&db, &c_reply).await,
        vec![pair(C_ACCOUNT, "routine_arrival")]
    );
}

#[tokio::test]
async fn the_arrival_preference_belongs_to_the_caller_alone() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let control_events = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    };
    let read = |account: &'static str| {
        let (registry, db) = (&registry, &db);
        async move {
            call(
                registry,
                db,
                account,
                json!({"action":"get_notification_preference"}),
            )
            .await
            .unwrap()["arrival"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };

    // Each caller reads and writes only their own preference; no argument can
    // name another account.
    set_arrival(&registry, &db, B_ACCOUNT, "off", "own-b").await;
    assert_eq!(read(B_ACCOUNT).await, "off");
    assert_eq!(read(A_ACCOUNT).await, "all", "B's choice is not A's");
    set_arrival(&registry, &db, A_ACCOUNT, "dms_and_mentions", "own-a").await;
    assert_eq!(read(A_ACCOUNT).await, "dms_and_mentions");
    assert_eq!(read(B_ACCOUNT).await, "off", "A's choice is not B's");
    let by_other_account = call(
        &registry,
        &db,
        A_ACCOUNT,
        json!({"action":"set_notification_preference","arrival":"all",
               "idempotency_key":"other","account_id":B_ACCOUNT}),
    )
    .await;
    assert!(by_other_account.is_err(), "no way to name another account");

    // A refused value leaves the control log untouched.
    let before = control_events().await;
    let refused = call(
        &registry,
        &db,
        B_ACCOUNT,
        json!({"action":"set_notification_preference","arrival":"loud","idempotency_key":"bad"}),
    )
    .await;
    assert!(refused.is_err());
    assert_eq!(control_events().await, before);
}

/// A channel post may mention a person who can see the Collection without
/// addressing them (A3). That mention candidate is the notification: a thread
/// participant mentioned in a reply gets exactly it, not a routine arrival on
/// top, while the other participants still hear the reply.
#[tokio::test]
async fn a_mention_of_an_unaddressed_thread_participant_is_the_only_candidate_they_get() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection = channel(&registry, &db).await;
    let root = post(&registry, &db, A_ACCOUNT, &collection, None, "mention-root").await;
    post(
        &registry,
        &db,
        B_ACCOUNT,
        &collection,
        Some(&root),
        "mention-b",
    )
    .await;

    let reply = call(
        &registry,
        &db,
        C_ACCOUNT,
        json!({
            "action":"send","body":"B, can you take this one?","expectation":"none",
            "idempotency_key":"mention-c","addressed_to":[],"home_id":&collection,
            "origin":{"type":"collection","collection_id":&collection},
            "links":[{"target_id":&root,"relationship":"reply_to"}],
            "mentions":[{
                "mention_id":"channel-thread-mention","target_kind":"principal",
                "target_id":B,"span_start":0,"span_end":1,"authored_label":"B"
            }]
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        effective(&db, &reply).await,
        vec![
            pair(A_ACCOUNT, "routine_arrival"),
            pair(B_ACCOUNT, "principal_mention")
        ],
        "B was mentioned, so B holds the mention and no routine arrival"
    );
    let for_b: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidates
          WHERE message_id=? AND recipient_account_id=?",
    )
    .bind(&reply)
    .bind(B_ACCOUNT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        for_b, 1,
        "exactly one candidate for the mentioned participant"
    );
}

/// The preference gates `routine_arrival` and nothing else: every other
/// reason notifies under every value, and `dms_and_mentions` admits a routine
/// arrival only when the Message was sent in a direct context.
#[test]
fn the_preference_gates_routine_arrivals_only() {
    use native_ce::awareness::arrival_preference_allows;
    let always = [
        "principal_mention",
        "human_obligation",
        "snooze_due",
        "human_intervention",
    ];
    for arrival in ["all", "dms_and_mentions", "off"] {
        for direct in [true, false] {
            for reason in always {
                assert!(
                    arrival_preference_allows(arrival, reason, direct),
                    "{arrival}/{reason}/{direct}"
                );
            }
        }
    }
    assert!(arrival_preference_allows("all", "routine_arrival", true));
    assert!(arrival_preference_allows("all", "routine_arrival", false));
    assert!(arrival_preference_allows(
        "dms_and_mentions",
        "routine_arrival",
        true
    ));
    assert!(!arrival_preference_allows(
        "dms_and_mentions",
        "routine_arrival",
        false
    ));
    assert!(!arrival_preference_allows("off", "routine_arrival", true));
    assert!(!arrival_preference_allows("off", "routine_arrival", false));
}

/// One scenario per preference value, each against a fresh database: a DM, a
/// channel-thread reply, a reply inside a DM thread, a mention and an
/// obligation, all for the same recipient (B). Whatever is created must also
/// harvest and revalidate as deliverable, and the same rule holds at harvest
/// when the value changes after the candidates exist.
#[tokio::test]
async fn each_preference_value_decides_dm_channel_thread_dm_thread_mention_and_obligation() {
    // (value, DM, channel-thread reply, DM-thread reply)
    let cases = [
        ("all", true, true, true),
        ("dms_and_mentions", true, false, true),
        ("off", false, false, false),
    ];
    for (value, dm_arrives, channel_arrives, dm_thread_arrives) in cases {
        let db = create_database(":memory:").await.unwrap();
        install_people(&db).await;
        let registry = registry();
        if value != "all" {
            set_arrival(&registry, &db, B_ACCOUNT, value, "scenario").await;
        }
        let routine = |arrives: bool| {
            if arrives {
                vec![pair(B_ACCOUNT, "routine_arrival")]
            } else {
                vec![]
            }
        };

        let direct = dm(&registry, &db, (A_ACCOUNT, A), &[B], "s-dm", json!({})).await;
        assert_eq!(
            effective(&db, &direct).await,
            routine(dm_arrives),
            "{value}: DM"
        );

        // A channel thread B is in: B starts it, A replies.
        let collection = channel(&registry, &db).await;
        let root = post(&registry, &db, B_ACCOUNT, &collection, None, "s-root").await;
        let channel_reply = post(
            &registry,
            &db,
            A_ACCOUNT,
            &collection,
            Some(&root),
            "s-chan",
        )
        .await;
        assert_eq!(
            effective(&db, &channel_reply).await,
            routine(channel_arrives),
            "{value}: channel-thread reply"
        );

        // A reply inside a DM thread is a DM message.
        let dm_reply = dm(
            &registry,
            &db,
            (A_ACCOUNT, A),
            &[B],
            "s-dm-thread",
            json!({"links":[{"target_id":&direct,"relationship":"reply_to"}]}),
        )
        .await;
        assert_eq!(
            effective(&db, &dm_reply).await,
            routine(dm_thread_arrives),
            "{value}: DM-thread reply"
        );

        // Mentions and obligations always notify.
        let mention = dm(
            &registry,
            &db,
            (A_ACCOUNT, A),
            &[B],
            "s-mention",
            json!({"body":"B","mentions":[{
                "mention_id":"scenario-mention","target_kind":"principal","target_id":B,
                "span_start":0,"span_end":1,"authored_label":"B"
            }]}),
        )
        .await;
        assert_eq!(
            effective(&db, &mention).await,
            vec![pair(B_ACCOUNT, "principal_mention")],
            "{value}: mention"
        );
        let obligation = dm(
            &registry,
            &db,
            (A_ACCOUNT, A),
            &[B],
            "s-obligation",
            json!({"expectation":"reply"}),
        )
        .await;
        assert_eq!(
            effective(&db, &obligation).await,
            vec![pair(B_ACCOUNT, "human_obligation")],
            "{value}: obligation"
        );

        // Everything created is deliverable at harvest and revalidation.
        let harvest = harvest_host_notification_candidates(&db, B_ACCOUNT, true, 0, 100)
            .await
            .unwrap();
        assert!(!harvest.candidates.is_empty());
        for candidate in &harvest.candidates {
            assert!(!candidate.muted, "{value}: {} withheld", candidate.reason);
            assert!(
                revalidate_host_notification_candidate(
                    &db,
                    &candidate.candidate_id,
                    B_ACCOUNT,
                    true
                )
                .await
                .unwrap()
                .unwrap()
                .effective_viewable_unmuted,
                "{value}: {} fails revalidation",
                candidate.reason
            );
        }
    }

    // Harvest applies the same rule when the value changes afterwards: with
    // `all` a DM arrival and a channel-thread arrival are created; switching to
    // `dms_and_mentions` withholds only the channel-thread one, and `off` both.
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let direct = dm(&registry, &db, (A_ACCOUNT, A), &[B], "h-dm", json!({})).await;
    let collection = channel(&registry, &db).await;
    let root = post(&registry, &db, B_ACCOUNT, &collection, None, "h-root").await;
    let channel_reply = post(
        &registry,
        &db,
        A_ACCOUNT,
        &collection,
        Some(&root),
        "h-chan",
    )
    .await;
    let withheld = |message: String, account: &'static str| {
        let db = &db;
        async move {
            let id: String = sqlx::query_scalar(
                "SELECT candidate_id FROM notification_candidates
                  WHERE message_id=? AND recipient_account_id=?",
            )
            .bind(&message)
            .bind(account)
            .fetch_one(db.pool())
            .await
            .unwrap();
            let harvested = harvest_host_notification_candidates(db, account, true, 0, 100)
                .await
                .unwrap()
                .candidates
                .into_iter()
                .find(|candidate| candidate.candidate_id == id)
                .unwrap()
                .muted;
            let revalidated = !revalidate_host_notification_candidate(db, &id, account, true)
                .await
                .unwrap()
                .unwrap()
                .effective_viewable_unmuted;
            assert_eq!(harvested, revalidated, "harvest and revalidation agree");
            harvested
        }
    };
    // B holds the DM arrival; the channel-thread reply notifies B (root author).
    assert!(!withheld(direct.clone(), B_ACCOUNT).await);
    assert!(!withheld(channel_reply.clone(), B_ACCOUNT).await);
    set_arrival(&registry, &db, B_ACCOUNT, "dms_and_mentions", "h-1").await;
    assert!(!withheld(direct.clone(), B_ACCOUNT).await);
    assert!(withheld(channel_reply.clone(), B_ACCOUNT).await);
    set_arrival(&registry, &db, B_ACCOUNT, "off", "h-2").await;
    assert!(withheld(direct, B_ACCOUNT).await);
    assert!(withheld(channel_reply, B_ACCOUNT).await);
}
