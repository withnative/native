use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

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

async fn send_to(
    registry: &ToolRegistry,
    db: &Db,
    body: &str,
    recipient: &str,
    expectation: &str,
) -> String {
    call(
        registry,
        db,
        "manage_messages",
        json!({
            "action":"send",
            "body":body,
            "owner_id":SENDER,
            "origin":{"type":"direct","participant_ids":[SENDER,recipient]},
            "addressed_to":[recipient],
            "expectation":expectation,
            "idempotency_key":format!("batching-send-{}-{}", body, uuid::Uuid::new_v4()),
            "reason":"Seed the inbox batching fixture through the policy gate."
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .into()
}

fn item_ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["message_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn batched_snapshot_preserves_multi_caller_visibility_archived_snoozed_and_pagination() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    // Newest-first candidate order: visible_b is newest, then snoozed, archived,
    // visible_a, and a hidden Message addressed to Dana that the recipient
    // must never see.
    let visible_a = send_to(&registry, &db, "visible a", RECIPIENT, "none").await;
    let hidden = send_to(&registry, &db, "hidden from recipient", DANA, "none").await;
    let archived = send_to(&registry, &db, "archived one", RECIPIENT, "none").await;
    let snoozed = send_to(&registry, &db, "snoozed one", RECIPIENT, "none").await;
    let visible_b = send_to(&registry, &db, "visible b", RECIPIENT, "none").await;

    let recipient = Caller::authenticated("acct_recipient");
    for (message, preference, extra, key) in [
        (archived.clone(), "archive", None, "batching-archive"),
        (
            snoozed.clone(),
            "snooze",
            Some("2999-01-01T00:00:00Z"),
            "batching-snooze",
        ),
    ] {
        let mut args = json!({"action":"set_preference","message_id":message,"preference":preference,"expected_version":0,"idempotency_key":key,"reason":"Pin archived/snoozed view behaviour."});
        if let Some(until) = extra {
            args["snoozed_until"] = json!(until);
        }
        call_as(&registry, &db, recipient.clone(), "manage_messages", args)
            .await
            .unwrap();
    }

    // Browse keeps everything visible to the recipient, including archived
    // and snoozed; the Dana-addressed Message stays hidden.
    let browse = call_as(
        &registry,
        &db,
        recipient.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":200}),
    )
    .await
    .unwrap();
    native_ce::awareness::validate_messaging_surface_response(&browse).unwrap();
    let browse_ids = item_ids(&browse);
    assert_eq!(browse_ids.len(), 4);
    assert!(browse_ids.contains(&visible_a));
    assert!(browse_ids.contains(&visible_b));
    assert!(browse_ids.contains(&archived));
    assert!(browse_ids.contains(&snoozed));
    assert!(
        !browse_ids.contains(&hidden),
        "Dana-addressed Message must stay hidden from the recipient"
    );

    // Frozen pagination: first page pins the snapshot; the second page walks
    // it with `after`. Page boundaries are derived from the full browse order
    // so the test does not depend on timestamp-tie granularity.
    let page = call_as(
        &registry,
        &db,
        recipient.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":2}),
    )
    .await
    .unwrap();
    assert_eq!(item_ids(&page), browse_ids[..2].to_vec());
    let snapshot = page["snapshot"].as_str().unwrap().to_string();
    let next_after = page["next_after"].as_u64().unwrap() as usize;
    let page2 = call_as(
        &registry,
        &db,
        recipient.clone(),
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":10,"snapshot":snapshot,"after":next_after}),
    )
    .await
    .unwrap();
    assert_eq!(item_ids(&page2), browse_ids[2..].to_vec());

    // A caller with no grant sees nothing but still gets a valid surface.
    let intruder_page = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_intruder"),
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":200}),
    )
    .await
    .unwrap();
    native_ce::awareness::validate_messaging_surface_response(&intruder_page).unwrap();
    assert!(intruder_page["items"].as_array().unwrap().is_empty());

    // Current-revocation page filtering still applies: revoking the grant
    // after the snapshot was pinned shrinks the later page. The membership
    // assertion first pins the test against vacuity — revoking an id that
    // was never on the page would pass trivially.
    let page2_ids = item_ids(&page2);
    assert!(
        page2_ids.contains(&visible_a),
        "revocation target must actually sit on the pinned second page"
    );
    native_ce::authorization::replace_explicit_policy(
        &db,
        "batching-test:revoke",
        &visible_a,
        vec![],
    )
    .await
    .unwrap();
    let reread = call_as(
        &registry,
        &db,
        recipient,
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":10,"snapshot":page["snapshot"].as_str().unwrap(),"after":next_after}),
    )
    .await
    .unwrap();
    assert!(
        !item_ids(&reread).contains(&visible_a),
        "live revocation must shrink a later page even though view state is frozen"
    );
}

#[tokio::test]
async fn batched_snapshot_carries_reactions_expectations_mentions_and_delivery() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let ack_message = send_to(&registry, &db, "ack please", RECIPIENT, "ack").await;
    let plain_message = send_to(&registry, &db, "plain", RECIPIENT, "none").await;

    // Open human-routed obligation so needs_me keeps the ack Message.
    {
        db.drain_captures_for_tests().await;
        let pool = crate::common::fixture_write_pool(&db).await;
        let mut tx = pool.begin().await.unwrap();
        let mut act_alloc = native_ce::act::ActAllocation::new();
        native_ce::awareness::set_routing(
            &mut tx,
            &native_ce::awareness::MutationContext {
                subject_account_id: "acct_recipient",
                authenticated_actor: "acct_recipient",
                executor_kind: "system",
                executor_ref: None,
                delegation_ref: None,
                reason_code: "Seed an open human-routed obligation.",
            },
            &ack_message,
            "open",
            "human",
            None,
            0,
            "batching-routing",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // Reactions from two distinct actors on the same Message.
    for (actor, key) in [
        ("acct_recipient", "batching-react-r"),
        ("acct_sender", "batching-react-s"),
    ] {
        call_as(
            &registry,
            &db,
            Caller::authenticated(actor),
            "manage_messages",
            json!({"action":"add_reaction","message_id":ack_message,"emoji":"👍","idempotency_key":key,"reason":"Seed batched reaction groups."}),
        )
        .await
        .unwrap();
    }

    let page = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":200}),
    )
    .await
    .unwrap();
    native_ce::awareness::validate_messaging_surface_response(&page).unwrap();
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let ack_item = items
        .iter()
        .find(|item| item["message_id"] == ack_message)
        .expect("ack Message survives batching");
    assert_eq!(ack_item["obligation"]["state"], "open");
    assert_eq!(ack_item["obligation"]["expectation_state"], "open");
    assert_eq!(ack_item["route"]["executor"], "human");
    let expected_reactions = ack_item["reactions"].clone();
    let groups = expected_reactions.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["emoji"], "👍");
    assert_eq!(groups[0]["count"], 2);
    assert_eq!(groups[0]["viewer_reacted"], true);
    let plain_item = items
        .iter()
        .find(|item| item["message_id"] == plain_message)
        .expect("plain Message survives batching");
    assert_eq!(
        plain_item["obligation"]["expectation_state"],
        "not_required"
    );
    assert!(plain_item["reactions"].as_array().unwrap().is_empty());

    // needs_me keeps the open human-routed ack Message with identical shape.
    let needs_me = call_as(
        &registry,
        &db,
        Caller::authenticated("acct_recipient"),
        "manage_messages",
        json!({"action":"list_inbox","view":"needs_me","limit":200}),
    )
    .await
    .unwrap();
    let pinned = needs_me["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["message_id"] == ack_message)
        .expect("open obligation stays in needs_me")
        .clone();
    assert_eq!(pinned["reactions"], expected_reactions);
}

#[tokio::test]
async fn batched_snapshot_excludes_malformed_authorization_shape_for_every_caller() {
    // A Message whose semantic-Unit bearer edge is cyclic fails the
    // trusted-local shape validation the scalar `can_record` gate enforced
    // after the legacy existence check. The batched path must exclude it for
    // local callers too — row existence plus type filtering alone is not the
    // equivalent gate. The preloaded fold evaluates the same bearer walk, so
    // hosted callers exclude it as well.
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let healthy = send_to(&registry, &db, "healthy", RECIPIENT, "none").await;
    let victim = send_to(&registry, &db, "cyclic bearer", RECIPIENT, "none").await;
    let pool = crate::common::fixture_write_pool(&db).await;
    let creation = sqlx::query(
        "SELECT id, seq, created_at FROM content_events WHERE record_id = ? AND type = 'record.created'",
    )
    .bind(&victim)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO semantic_units
            (unit_id, authority_bearer_record_id, creation_event_id, creation_event_seq, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&victim)
    .bind(&victim)
    .bind(creation.try_get::<String, _>("id").unwrap())
    .bind(creation.try_get::<i64, _>("seq").unwrap())
    .bind(creation.try_get::<String, _>("created_at").unwrap())
    .execute(&pool)
    .await
    .unwrap();

    for caller in [Caller::local(), Caller::authenticated("acct_recipient")] {
        let page = call_as(
            &registry,
            &db,
            caller,
            "manage_messages",
            json!({"action":"list_inbox","view":"browse","limit":200}),
        )
        .await
        .unwrap();
        native_ce::awareness::validate_messaging_surface_response(&page).unwrap();
        let ids = item_ids(&page);
        assert!(ids.contains(&healthy));
        assert!(
            !ids.contains(&victim),
            "cyclic Unit-bearer Message must stay excluded for every caller"
        );
    }
}
