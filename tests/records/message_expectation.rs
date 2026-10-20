use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::events::{LinkAddedPayload, LinkRemovedPayload};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::message_expectation::{
    derive_message_expectation_state, MessageExpectationEvidenceKind, MessageExpectationState,
    EXPECTATION_DERIVATION_VERSION, EXPECTATION_VALUES,
};
use native_ce::meta::{
    alias_value, promote_value, propose_value_with_metadata_as, VocabularyValueTerminality,
};
use native_ce::store::{
    add_link_as, append, archive_record as archive_record_as, create_record as create_raw_record,
    create_record_as, delete_record_as, remove_link_as, restore_record as restore_record_as,
    AppendSpec,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const SENDER: &str = "acct:sender";
const RECIPIENT: &str = "acct:recipient";
const OTHER: &str = "acct:someone-else";
// Record ids must be canonical v4/v7 UUIDs, so these fixture ids are pinned
// literals. The counters keep the relative sort order the readable slugs had
// (collection:expectation-test < person:recipient < person:sender <
// person:someone-else). The `acct:` constants above are account identifiers,
// not record ids, so they stay readable.
const SCHEMA_ANCHOR: &str = "e8bec700-0000-4000-8000-000000000001";
const RECIPIENT_PERSON: &str = "e8bec700-0000-4000-8000-000000000002";
const SENDER_PERSON: &str = "e8bec700-0000-4000-8000-000000000003";
const OTHER_PERSON: &str = "e8bec700-0000-4000-8000-000000000004";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    actor: &str,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            Caller::authenticated(actor),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn awaiting_reply(db: &Db, actor: &str) -> Vec<String> {
    let caller = Caller::authenticated(actor);
    native_ce::query::sql::query_sql(
        db,
        &caller,
        "SELECT message_id FROM messages_awaiting_reply ORDER BY message_id",
    )
    .await
    .unwrap()
    .rows
    .into_iter()
    .map(|row| row["message_id"].as_str().unwrap().to_owned())
    .collect()
}

async fn create_message(
    registry: &ToolRegistry,
    db: &Db,
    actor: &str,
    expectation: &str,
    links: Value,
) -> String {
    create_message_in_context(
        registry,
        db,
        actor,
        expectation,
        links,
        json!([SENDER_PERSON, RECIPIENT_PERSON]),
    )
    .await
}

async fn create_message_in_context(
    registry: &ToolRegistry,
    db: &Db,
    actor: &str,
    expectation: &str,
    links: Value,
    participant_ids: Value,
) -> String {
    let addressee = if actor == RECIPIENT {
        SENDER_PERSON
    } else {
        RECIPIENT_PERSON
    };
    let mut args = json!({
        "action": "send",
        "body": format!("{expectation} message"),
        "origin":{"type":"direct","participant_ids":participant_ids},
        "expectation": expectation,
        "addressed_to": [addressee],
        "idempotency_key": format!("test-send-{}", uuid::Uuid::new_v4()),
        "reason":"Exercise Message expectation derivation in this test fixture.",
    });
    if !links.is_null() {
        args["links"] = links;
    }
    call(registry, db, actor, "manage_messages", args)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn manage_link(
    _registry: &ToolRegistry,
    db: &Db,
    actor: &str,
    action: &str,
    source_id: &str,
    target_id: &str,
    relationship: &str,
) {
    // These tests deliberately stamp both authorized and unauthorized actors
    // into the event log. Bypass tool authorization so the derivation's own
    // provenance check, rather than manage_links, is the behavior under test.
    if action == "add" {
        add_link_as(
            db,
            LinkAddedPayload {
                id: None,
                source_id: source_id.to_owned(),
                target_id: target_id.to_owned(),
                relationship: relationship.to_owned(),
                note: None,
            },
            Some(actor),
        )
        .await
        .unwrap();
    } else {
        assert_eq!(action, "remove");
        remove_link_as(
            db,
            LinkRemovedPayload {
                source_id: source_id.to_owned(),
                target_id: target_id.to_owned(),
                relationship: relationship.to_owned(),
            },
            Some(actor),
        )
        .await
        .unwrap();
    }
}

async fn install_accounts(db: &Db) {
    for (person, account, name) in [
        (SENDER_PERSON, SENDER, "Sender"),
        (RECIPIENT_PERSON, RECIPIENT, "Recipient"),
        (OTHER_PERSON, OTHER, "Someone else"),
    ] {
        create_raw_record(
            db,
            json!({ "id": person, "type": "Entity", "kind": "person", "name": name }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(person)
        .bind(account)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'native-principal', ?, 1)",
        )
        .bind(person)
        .bind(
            format!("native/{name}")
                .to_ascii_lowercase()
                .replace(' ', "-"),
        )
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    }
    create_raw_record(
        db,
        json!({
            "id": SCHEMA_ANCHOR,
            "type": "Collection",
            "kind": "folder",
            "name": "Expectation test",
            "owner_id": SENDER_PERSON
        }),
    )
    .await
    .unwrap();
}

async fn latest_content_seq(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn set_open_human_routing(db: &Db, message_id: &str, idempotency_key: &str) {
    // This fixture uses a deferred transaction; exclude queued setup captures
    // before its read-to-write upgrade, just as before capture became async.
    db.drain_captures_for_tests().await;
    let pool = crate::common::fixture_write_pool(db).await;
    let mut tx = pool.begin().await.unwrap();
    let mut act_alloc = native_ce::act::ActAllocation::new();
    native_ce::awareness::set_routing(
        &mut tx,
        &native_ce::awareness::MutationContext {
            subject_account_id: RECIPIENT,
            authenticated_actor: RECIPIENT,
            executor_kind: "system",
            executor_ref: Some("message-reaction-test"),
            delegation_ref: None,
            reason_code: "Seed an open human-routed acknowledgement obligation.",
        },
        message_id,
        "open",
        "human",
        None,
        0,
        idempotency_key,
        &mut act_alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn message_reactions_are_idempotent_viewer_relative_and_side_effect_free() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let message = create_message(&registry, &db, SENDER, "ack", Value::Null).await;

    let add = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"add_reaction","message_id":message,"emoji":"👍","idempotency_key":"reaction-add","reason":"React without acknowledging."}),
    )
    .await
    .unwrap();
    assert_eq!(add["status"], "added");
    assert_eq!(add["changed"], true);
    let retry = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"add_reaction","message_id":message,"emoji":"👍","idempotency_key":"reaction-add","reason":"React without acknowledging."}),
    )
    .await
    .unwrap();
    assert_eq!(retry["status"], "added");
    assert_eq!(retry["changed"], true);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM content_events WHERE type='message.reaction.added.v1' AND json_extract(payload,'$.idempotency_key')='reaction-add'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );

    let state = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[message]}),
    )
    .await
    .unwrap();
    assert_eq!(state["schema"], "native.message-state.v1");
    assert_eq!(state["viewer_relative"], true);
    assert_eq!(state["snapshot_consistent"], true);
    assert!(state["content_head"].as_i64().is_some());
    assert_eq!(
        state["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    assert_eq!(state["messages"][0]["can_satisfy_acknowledgement"], true);
    let actor = &state["messages"][0]["reactions"][0]["actors"][0];
    assert_eq!(actor["record_id"], RECIPIENT_PERSON);
    assert_eq!(actor["name"], "Recipient");
    assert_eq!(actor["viewer"], true);
    assert!(actor.get("account_id").is_none());
    assert_eq!(
        derive_message_expectation_state(&db, &message, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM human_message_awareness")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM message_preferences")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );

    let reused = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"remove_reaction","message_id":message,"emoji":"👍","idempotency_key":"reaction-add","reason":"This is a different intent."}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(reused.contains("different intent"), "{reused}");
    let sender_remove = call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({"action":"remove_reaction","message_id":message,"emoji":"👍","idempotency_key":"sender-remove","reason":"Cannot remove another actor's reaction."}),
    )
    .await
    .unwrap();
    assert_eq!(sender_remove["changed"], false);
    assert_eq!(sender_remove["reactions"][0]["count"], 1);
    let sender_add = call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({"action":"add_reaction","message_id":message,"emoji":"👍","idempotency_key":"sender-add","reason":"Add a distinct actor reaction."}),
    )
    .await
    .unwrap();
    assert_eq!(sender_add["reactions"][0]["count"], 2);

    let removed = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"remove_reaction","message_id":message,"emoji":"👍","idempotency_key":"reaction-remove","reason":"Remove my own reaction."}),
    )
    .await
    .unwrap();
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["reactions"][0]["count"], 1);
    assert_eq!(
        removed["reactions"][0]["actors"][0]["record_id"],
        SENDER_PERSON
    );
}

#[tokio::test]
async fn message_reaction_acknowledgement_is_atomic_deduplicated_and_hidden() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let message = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    set_open_human_routing(&db, &message, "message-reaction-open-route").await;
    call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"set_preference","message_id":message,"preference":"flag_attention","expected_version":0,"idempotency_key":"reaction-attention","reason":"Preserve this independent preference."}),
    )
    .await
    .unwrap();

    let sender_rejected = call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":message,"idempotency_key":"reaction-ack-sender","reason":"A sender cannot satisfy the recipient's obligation."}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        sender_rejected.contains("caller cannot satisfy"),
        "{sender_rejected}"
    );

    let forged = uuid::Uuid::new_v4().to_string();
    create_record_as(
        &db,
        json!({
            "id":forged,"type":"Annotation","kind":"acknowledgement",
            "name":"Forged acknowledgement","owner_id":RECIPIENT_PERSON
        }),
        Some(SENDER),
    )
    .await
    .unwrap();
    manage_link(&registry, &db, SENDER, "add", &forged, &message, "part_of").await;
    manage_link(
        &registry,
        &db,
        SENDER,
        "add",
        &forged,
        &message,
        "acknowledges",
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &message, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let privacy_after = latest_content_seq(&db).await;

    let first_ack = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":message,"idempotency_key":"reaction-ack","reason":"Explicitly acknowledge with a reaction."}),
    );
    let concurrent_ack = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":message,"idempotency_key":"reaction-ack-concurrent","reason":"Concurrently acknowledge the same expectation."}),
    );
    let (acknowledged, concurrent) = tokio::join!(first_ack, concurrent_ack);
    let acknowledged = acknowledged.unwrap();
    let concurrent = concurrent.unwrap();
    assert_eq!(acknowledged["status"], "acknowledged");
    assert_eq!(concurrent["status"], "acknowledged");
    assert_eq!(acknowledged["emoji"], "👍");
    assert_ne!(acknowledged["changed"], concurrent["changed"]);
    let evidence = acknowledged["acknowledgement"]["evidence_record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(evidence, forged);
    assert_eq!(
        concurrent["acknowledgement"]["evidence_record_id"],
        evidence
    );
    assert_eq!(
        derive_message_expectation_state(&db, &message, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM records WHERE type='Annotation' AND kind='acknowledgement'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=? AND relationship IN ('part_of','acknowledges')"
        ).bind(&evidence).bind(&message).fetch_one(db.pool()).await.unwrap(),
        2
    );
    let routing: (String, String) = sqlx::query_as(
        "SELECT obligation_state,executor_route FROM message_inbox_routing WHERE subject_account_id=? AND message_id=?",
    ).bind(RECIPIENT).bind(&message).fetch_one(db.pool()).await.unwrap();
    assert_eq!(routing, ("satisfied".into(), "closed".into()));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT attention_flag FROM message_preferences WHERE subject_account_id=? AND message_id=?")
            .bind(RECIPIENT).bind(&message).fetch_one(db.pool()).await.unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM human_message_awareness")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );

    let second = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":message,"idempotency_key":"reaction-ack-again","reason":"Retry after the expectation is already satisfied."}),
    )
    .await
    .unwrap();
    assert_eq!(second["changed"], false);
    assert_eq!(second["acknowledgement"]["evidence_record_id"], evidence);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records WHERE kind='acknowledgement'")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        2
    );

    let discovery = call(
        &registry,
        &db,
        RECIPIENT,
        "query_record",
        json!({"steps":[{"step":"filter","ids":[evidence]}]}),
    )
    .await
    .unwrap();
    assert_eq!(discovery["returned"], 0);
    let direct_history = call(
        &registry,
        &db,
        RECIPIENT,
        "get_history",
        json!({"record_id":evidence}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        direct_history.contains("does not exist"),
        "{direct_history}"
    );
    for (tool, arguments) in [
        (
            "get_history",
            json!({"record_id":evidence,"for_run":"scout-chair-a748b2"}),
        ),
        (
            "whats_changed",
            json!({"scope_record_id":evidence,"after_local_seq":privacy_after,"limit":1000}),
        ),
    ] {
        let hidden = call(&registry, &db, RECIPIENT, tool, arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(hidden.contains("does not exist"), "{tool}: {hidden}");
    }
    for (tool, arguments) in [
        ("get_history", json!({"limit":1000})),
        (
            "whats_changed",
            json!({"after_local_seq":privacy_after,"limit":1000}),
        ),
    ] {
        let output = call(&registry, &db, RECIPIENT, tool, arguments)
            .await
            .unwrap();
        assert!(
            !output.to_string().contains(&evidence),
            "{tool} leaked evidence id"
        );
    }
    for statement in [
        format!("SELECT id FROM records WHERE id='{evidence}'"),
        format!("SELECT record_id,type FROM content_events WHERE record_id='{evidence}'"),
        format!("SELECT source_id,target_id FROM links WHERE source_id='{evidence}' OR target_id='{evidence}'"),
    ] {
        let result = native_ce::query::sql::query_sql(&db, &Caller::local(), &statement)
            .await
            .unwrap();
        assert!(result.rows.is_empty(), "query_sql leaked hidden acknowledgement evidence");
    }

    call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"remove_reaction","message_id":message,"emoji":"👍","idempotency_key":"reaction-ack-remove","reason":"Remove the visible reaction without revoking evidence."}),
    )
    .await
    .unwrap();
    assert_eq!(
        derive_message_expectation_state(&db, &message, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );
}

#[tokio::test]
async fn message_reaction_acknowledgement_rolls_back_on_late_routing_failure() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let message = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    set_open_human_routing(&db, &message, "rollback-ack:routing").await;
    let awareness_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM awareness_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let error = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":message,"idempotency_key":"rollback-ack","reason":"Force a late routing idempotency collision."}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("idempotency"), "{error}");
    assert_eq!(
        derive_message_expectation_state(&db, &message, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records WHERE kind='acknowledgement'")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM content_events WHERE type LIKE 'message.reaction.%'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        awareness_before
    );
    let routing: (String, String, i64) = sqlx::query_as(
        "SELECT obligation_state,executor_route,version FROM message_inbox_routing WHERE subject_account_id=? AND message_id=?",
    )
    .bind(RECIPIENT)
    .bind(&message)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(routing, ("open".into(), "human".into(), 1));
}

// A production append runs the insert trigger before Rust projection. Keep
// field-specific domain diagnostics and rollback while accepting both serde
// payload encodings. Wrong-typed references fail serde decoding rather than
// MessageReactionPayload::validate; SQL still identifies that field honestly.
#[tokio::test]
async fn reaction_trigger_diagnostics_preserve_atomicity_for_objects_and_sequences() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let message = create_message(&registry, &db, SENDER, "none", Value::Null).await;
    let mut cases = Vec::new();
    for kind in ["human_attested", "agent", "delegated_service"] {
        for reference in [
            None,
            Some(Value::Null),
            Some(json!("")),
            Some(json!("\u{2003}")),
            Some(json!(7)),
            Some(json!(true)),
            Some(json!({})),
        ] {
            cases.push((
                kind,
                reference,
                "👍",
                "add_reaction",
                "native.message-reaction.v1",
                "attested Message reaction executors require a nonblank executor_ref",
            ));
        }
    }
    for kind in ["local", "authenticated_principal"] {
        for reference in [
            Some(json!("ref")),
            Some(json!("")),
            Some(json!(7)),
            Some(json!(false)),
        ] {
            cases.push((
                kind,
                reference,
                "👍",
                "add_reaction",
                "native.message-reaction.v1",
                "unattested Message reaction executors cannot carry executor_ref",
            ));
        }
    }
    cases.push((
        "local",
        None,
        "❤️",
        "satisfy_acknowledgement_expectation_with_reaction",
        "native.message-reaction.v1",
        "acknowledgement reactions must use 👍",
    ));
    // The malformed format must remain generic, even with a missing agent ref.
    cases.push((
        "agent",
        None,
        "👍",
        "add_reaction",
        "invalid-format",
        "invalid Message reaction payload",
    ));
    let before: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT count(*) FROM content_event_reaction_meta)").fetch_one(db.pool()).await.unwrap();
    for (kind, reference, emoji, command, format, diagnostic) in cases {
        let mut object = json!({"format":format,"emoji":emoji,"idempotency_key":"diagnostic","command":command,"changed":true,"actor_account_id":RECIPIENT,"executor_kind":kind,"reason":"diagnostic"});
        if let Some(reference) = &reference {
            object["executor_ref"] = reference.clone();
        }
        let mut sequence = json!([
            format,
            emoji,
            "diagnostic",
            command,
            true,
            RECIPIENT,
            kind,
            reference.clone().unwrap_or(Value::Null),
            "diagnostic"
        ]);
        for encoding in 0..3 {
            let payload = match encoding {
                0 => object.clone(),
                1 => sequence.clone(),
                _ => {
                    sequence.as_array_mut().unwrap().push(Value::Null);
                    sequence.clone()
                }
            };
            let decoded = serde_json::from_value::<native_ce::events::MessageReactionPayload>(
                payload.clone(),
            );
            if reference
                .as_ref()
                .is_some_and(|value| !value.is_null() && !value.is_string())
            {
                assert!(decoded.is_err(), "typed serde ref accepted: {payload}");
            } else {
                let error = decoded
                    .unwrap()
                    .validate(Some(RECIPIENT))
                    .unwrap_err()
                    .to_string();
                if format == "native.message-reaction.v1" {
                    assert!(error.contains(diagnostic), "{error}");
                }
            }
            let error = append(
                &db,
                AppendSpec {
                    record_id: message.clone(),
                    event_type: "message.reaction.added.v1".into(),
                    payload,
                    actor: Some(RECIPIENT.into()),
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(error.contains(diagnostic), "{kind}/{encoding}: {error}");
            if format != "native.message-reaction.v1" {
                assert!(!error.contains("executor_ref"), "{error}");
            }
            let after: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT count(*) FROM content_event_reaction_meta)").fetch_one(db.pool()).await.unwrap();
            assert_eq!(after, before, "failed reaction left source/projection rows");
        }
    }
    for kind in [
        "human_attested",
        "agent",
        "delegated_service",
        "local",
        "authenticated_principal",
    ] {
        let reference = if matches!(kind, "local" | "authenticated_principal") {
            Value::Null
        } else {
            json!("valid-ref")
        };
        let object = json!({"format":"native.message-reaction.v1","emoji":"👍","idempotency_key":"valid","command":"add_reaction","changed":false,"actor_account_id":RECIPIENT,"executor_kind":kind,"executor_ref":reference,"reason":"valid"});
        let sequence = json!([
            "native.message-reaction.v1",
            "👍",
            "valid",
            "add_reaction",
            false,
            RECIPIENT,
            kind,
            reference,
            "valid"
        ]);
        for payload in [object, sequence] {
            serde_json::from_value::<native_ce::events::MessageReactionPayload>(payload.clone())
                .unwrap()
                .validate(Some(RECIPIENT))
                .unwrap();
            append(
                &db,
                AppendSpec {
                    record_id: message.clone(),
                    event_type: "message.reaction.added.v1".into(),
                    payload,
                    actor: Some(RECIPIENT.into()),
                },
            )
            .await
            .unwrap();
        }
    }
    let after: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT count(*) FROM content_event_reaction_meta)").fetch_one(db.pool()).await.unwrap();
    assert_eq!(after, (before.0 + 10, before.1 + 10));
    db.close().await;
}

#[tokio::test]
async fn message_reaction_rejects_federated_shadows_and_incoherent_replay() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let message = create_message(&registry, &db, SENDER, "ack", Value::Null).await;

    let invalid_emoji = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"add_reaction","message_id":message,"emoji":"漢字","idempotency_key":"invalid-emoji","reason":"Reject non-emoji Unicode."}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        invalid_emoji.contains("canonical v1 picker"),
        "{invalid_emoji}"
    );

    let incoherent = append(
        &db,
        AppendSpec {
            record_id: message.clone(),
            event_type: "message.reaction.added.v1".into(),
            payload: json!({
                "format":"native.message-reaction.v1",
                "emoji":"👍",
                "idempotency_key":"incoherent-replay",
                "command":"remove_reaction",
                "changed":true,
                "actor_account_id":RECIPIENT,
                "executor_kind":"authenticated_principal",
                "reason":"Reject event-type and command disagreement."
            }),
            actor: Some(RECIPIENT.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        incoherent.contains("event type and command disagree"),
        "{incoherent}"
    );
    let non_message = append(
        &db,
        AppendSpec {
            record_id: SCHEMA_ANCHOR.into(),
            event_type: "message.reaction.added.v1".into(),
            payload: json!({
                "format":"native.message-reaction.v1","emoji":"👍","idempotency_key":"wrong-target",
                "command":"add_reaction","changed":true,"actor_account_id":RECIPIENT,
                "executor_kind":"authenticated_principal","reason":"Reject a non-Message target."
            }),
            actor: Some(RECIPIENT.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(non_message.contains("live Message"), "{non_message}");
    let missing_executor_ref = append(
        &db,
        AppendSpec {
            record_id: message.clone(),
            event_type: "message.reaction.added.v1".into(),
            payload: json!({
                "format":"native.message-reaction.v1","emoji":"👍","idempotency_key":"missing-ref",
                "command":"add_reaction","changed":true,"actor_account_id":RECIPIENT,
                "executor_kind":"agent","reason":"Reject incomplete attribution."
            }),
            actor: Some(RECIPIENT.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        missing_executor_ref.contains("executor_ref"),
        "{missing_executor_ref}"
    );
    let wrong_ack_emoji = append(
        &db,
        AppendSpec {
            record_id: message.clone(),
            event_type: "message.reaction.added.v1".into(),
            payload: json!({
                "format":"native.message-reaction.v1","emoji":"❤️","idempotency_key":"wrong-ack-emoji",
                "command":"satisfy_acknowledgement_expectation_with_reaction","changed":true,
                "actor_account_id":RECIPIENT,"executor_kind":"authenticated_principal",
                "reason":"Acknowledgement must imply thumbs up."
            }),
            actor: Some(RECIPIENT.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(wrong_ack_emoji.contains("👍"), "{wrong_ack_emoji}");
    let missing_evidence = append(
        &db,
        AppendSpec {
            record_id: message.clone(),
            event_type: "message.reaction.added.v1".into(),
            payload: json!({
                "format":"native.message-reaction.v1","emoji":"👍","idempotency_key":"missing-evidence",
                "command":"satisfy_acknowledgement_expectation_with_reaction","changed":true,
                "actor_account_id":RECIPIENT,"executor_kind":"authenticated_principal",
                "reason":"Combined event requires prior durable evidence."
            }),
            actor: Some(RECIPIENT.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        missing_evidence.contains("no valid durable evidence"),
        "{missing_evidence}"
    );

    let source: (String, i64, String) = sqlx::query_as(
        "SELECT id,seq,created_at FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(&message)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO content_event_sources(event_id,origin_database_id,source_seq,source_record_id,source_principal,source_fingerprint) VALUES (?,'remote-db',?,?,'remote/person',?)",
    )
    .bind(&source.0)
    .bind(source.1)
    .bind(&message)
    .bind("0".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO replicated_message_provenance(source_event_id,content_version,operation,source_account_token,source_created_at,canonical_payload,payload_digest) VALUES (?,'native.message.v1','message.created','remote-account',?,'{}',?)",
    )
    .bind(&source.0)
    .bind(&source.2)
    .bind("1".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO destination_message_ingest(message_id,source_event_id,relay_state,ingest_state,received_at,sender_state) VALUES (?,?,'queued','applied',?,'principal_only')",
    )
    .bind(&message)
    .bind(&source.0)
    .bind(&source.2)
    .execute(&pool)
    .await
    .unwrap();

    let rejected = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({"action":"add_reaction","message_id":message,"emoji":"👍","idempotency_key":"federated-reaction","reason":"Federated shadows are read-only."}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(rejected.contains("local-database only"), "{rejected}");
}

#[tokio::test]
async fn local_message_creation_requires_valid_expectation_and_corrections_supersede() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    let missing = call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({ "action":"send", "body": "missing", "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]}, "addressed_to": [RECIPIENT_PERSON], "idempotency_key":"missing-expectation", "reason":"Test missing expectation rejection." }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(missing.contains("missing field `expectation`"), "{missing}");

    let future = propose_value_with_metadata_as(
        &db,
        "message-expectation",
        "maybe",
        None,
        10.0,
        VocabularyValueTerminality::Open,
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &future).await.unwrap();
    let invalid = call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({
            "action":"send",
            "body": "invalid",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]},
            "expectation": "maybe",
            "addressed_to": [RECIPIENT_PERSON],
            "idempotency_key":"invalid-expectation",
            "reason":"Test invalid expectation rejection."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(invalid.contains("Message expectation"), "{invalid}");
    assert!(invalid.contains("none | ack | reply | action | decision"));
    for (shape, anchored) in [
        ("Message", false),
        ("Message:text", false),
        ("Message", true),
    ] {
        let mut data = json!({ "shapes": {} });
        data["shapes"][shape] = json!({ "facets": { "expectation": {} } });
        let mut args = json!({ "action": "write", "data": data });
        if anchored {
            args["applies_to_collection_id"] = json!(SCHEMA_ANCHOR);
        }
        let loosen = call(&registry, &db, SENDER, "manage_schema_config", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            loosen.contains("cannot override protocol facet 'expectation'"),
            "{loosen}"
        );
    }
    call(
        &registry,
        &db,
        SENDER,
        "manage_schema_config",
        json!({
            "action": "write",
            "data": { "shapes": { "WorkItem": { "facets": { "expectation": {} } } } }
        }),
    )
    .await
    .unwrap();
    let resolved = call(
        &registry,
        &db,
        SENDER,
        "resolve_facets",
        json!({ "type": "Message", "kind": "text" }),
    )
    .await
    .unwrap();
    assert_eq!(
        resolved["shape"]["expectation"],
        json!({ "vocab_ref": "message-expectation", "required": true })
    );
    let still_missing = call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({ "action":"send", "body": "still missing", "origin":{"type":"direct","participant_ids":[SENDER_PERSON,RECIPIENT_PERSON]}, "addressed_to": [RECIPIENT_PERSON], "idempotency_key":"still-missing-expectation", "reason":"Test schema cannot loosen the expectation protocol." }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(still_missing.contains("missing field `expectation`"));

    for expectation in EXPECTATION_VALUES {
        create_message(&registry, &db, SENDER, expectation, Value::Null).await;
    }
    let original = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    let immutable = call(
        &registry,
        &db,
        SENDER,
        "update_record",
        json!({ "id": original, "facets": { "expectation": "none" } }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(immutable.contains("immutable"), "{immutable}");
    assert!(immutable.contains("superseding Message"), "{immutable}");

    let correction = create_message(
        &registry,
        &db,
        SENDER,
        "none",
        json!([{ "target_id": original, "relationship": "supersedes" }]),
    )
    .await;
    let link_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM links WHERE source_id = ? AND target_id = ? AND relationship = 'supersedes')",
    )
    .bind(correction)
    .bind(&original)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(link_exists);
    let original_value: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'expectation'",
    )
    .bind(original)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(original_value, "reply");
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn missing_is_unknown_and_none_is_not_required() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let legacy = create_raw_record(
        &db,
        json!({ "type": "Message", "kind": "text", "body": "legacy" }),
    )
    .await
    .unwrap();
    let unknown = derive_message_expectation_state(&db, &legacy, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(unknown.format, EXPECTATION_DERIVATION_VERSION);
    assert_eq!(unknown.expectation, None);
    assert_eq!(unknown.state, MessageExpectationState::Unknown);

    let none = create_message(&registry(), &db, SENDER, "none", Value::Null).await;
    let not_required = derive_message_expectation_state(&db, &none, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(not_required.expectation.as_deref(), Some("none"));
    assert_eq!(not_required.state, MessageExpectationState::NotRequired);
}

#[tokio::test]
async fn acknowledgement_and_structured_reply_satisfy_only_their_governed_cases() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    let ack_source = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    assert_eq!(
        derive_message_expectation_state(&db, &ack_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let acknowledgement = create_message(&registry, &db, RECIPIENT, "none", Value::Null).await;
    manage_link(
        &registry,
        &db,
        OTHER,
        "add",
        &acknowledgement,
        &ack_source,
        "acknowledges",
    )
    .await;
    let unauthorised_ack_seq = latest_content_seq(&db).await;
    assert_eq!(
        derive_message_expectation_state(&db, &ack_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    manage_link(
        &registry,
        &db,
        OTHER,
        "remove",
        &acknowledgement,
        &ack_source,
        "acknowledges",
    )
    .await;
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &acknowledgement,
        &ack_source,
        "acknowledges",
    )
    .await;
    let authorised_ack_seq = latest_content_seq(&db).await;
    let ack = derive_message_expectation_state(&db, &ack_source, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(ack.state, MessageExpectationState::Satisfied);
    assert_eq!(
        ack.evidence.unwrap().kind,
        MessageExpectationEvidenceKind::Acknowledgement
    );
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "remove",
        &acknowledgement,
        &ack_source,
        "acknowledges",
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &ack_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    for (seq, expected) in [
        (unauthorised_ack_seq, "open"),
        (authorised_ack_seq, "satisfied"),
    ] {
        let historical = call(
            &registry,
            &db,
            RECIPIENT,
            "get_record",
            json!({ "ids": [ack_source], "as_of": { "content_seq": seq } }),
        )
        .await
        .unwrap();
        assert_eq!(
            historical["records"][0]["message_expectation_state"]["state"],
            expected
        );
    }

    let context = json!([SENDER_PERSON, RECIPIENT_PERSON, OTHER_PERSON]);
    let reply_source = create_message_in_context(
        &registry,
        &db,
        SENDER,
        "reply",
        Value::Null,
        context.clone(),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:expectation",
        &reply_source,
        vec![
            AllowEntry::account(RECIPIENT, Capability::View),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();
    create_message_in_context(
        &registry,
        &db,
        OTHER,
        "none",
        json!([{ "target_id": reply_source, "relationship": "reply_to" }]),
        context.clone(),
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &reply_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let reply = create_message_in_context(
        &registry,
        &db,
        RECIPIENT,
        "none",
        json!([{ "target_id": reply_source, "relationship": "reply_to" }]),
        context,
    )
    .await;
    let satisfied = derive_message_expectation_state(&db, &reply_source, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(satisfied.state, MessageExpectationState::Satisfied);
    assert_eq!(satisfied.evidence.unwrap().record_id, reply);
}

#[tokio::test]
async fn awaiting_reply_relation_is_caller_relative_and_ignores_hidden_reply_evidence() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let context = json!([SENDER_PERSON, RECIPIENT_PERSON, OTHER_PERSON]);

    let source = create_message_in_context(
        &registry,
        &db,
        SENDER,
        "reply",
        Value::Null,
        context.clone(),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:awaiting-reply",
        &source,
        vec![
            AllowEntry::account(RECIPIENT, Capability::View),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        awaiting_reply(&db, RECIPIENT).await,
        std::slice::from_ref(&source)
    );
    assert!(awaiting_reply(&db, OTHER).await.is_empty());

    // A reply-like link by somebody other than the addressed recipient is not
    // qualifying evidence and leaves the obligation open.
    create_message_in_context(
        &registry,
        &db,
        OTHER,
        "none",
        json!([{ "target_id": source.clone(), "relationship": "reply_to" }]),
        context.clone(),
    )
    .await;
    assert_eq!(
        awaiting_reply(&db, RECIPIENT).await,
        std::slice::from_ref(&source)
    );

    // This is structurally a qualifying recipient-authored reply, but its
    // record is hidden from that same viewer. The governed negative relation
    // must ignore it and expose no evidence identifier or count.
    let hidden_reply = create_record_as(
        &db,
        json!({
            "type":"Message", "kind":"text", "name":"Hidden qualifying reply",
            "body":"hidden reply", "home_id":SCHEMA_ANCHOR
        }),
        Some(RECIPIENT),
    )
    .await
    .unwrap();
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &hidden_reply,
        &source,
        "reply_to",
    )
    .await;
    let hidden_reply_seq = latest_content_seq(&db).await;
    sqlx::query(
        "INSERT INTO message_audiences
            (message_id,principal_id,source,grant_id,event_seq,created_at)
         VALUES (?,'native/sender','addressed_to','test-hidden',?,?)",
    )
    .bind(&hidden_reply)
    .bind(hidden_reply_seq)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:awaiting-reply",
        &hidden_reply,
        vec![AllowEntry::account(SENDER, Capability::View)],
    )
    .await
    .unwrap();
    assert_eq!(
        derive_message_expectation_state(&db, &source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );
    assert_eq!(
        awaiting_reply(&db, RECIPIENT).await,
        std::slice::from_ref(&source)
    );

    replace_explicit_policy(
        &db,
        "test:awaiting-reply",
        &hidden_reply,
        vec![
            AllowEntry::account(SENDER, Capability::View),
            AllowEntry::account(RECIPIENT, Capability::View),
        ],
    )
    .await
    .unwrap();
    assert!(awaiting_reply(&db, RECIPIENT).await.is_empty());

    let addressed_elsewhere =
        create_message_in_context(&registry, &db, RECIPIENT, "reply", Value::Null, context).await;
    assert!(!awaiting_reply(&db, RECIPIENT)
        .await
        .contains(&addressed_elsewhere));

    let unreadable = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    replace_explicit_policy(
        &db,
        "test:awaiting-reply",
        &unreadable,
        vec![AllowEntry::account(SENDER, Capability::View)],
    )
    .await
    .unwrap();
    assert!(!awaiting_reply(&db, RECIPIENT).await.contains(&unreadable));

    let unavailable = native_ce::query::sql::query_sql(
        &db,
        &Caller::authenticated("account-without-current-member"),
        "SELECT message_id FROM messages_awaiting_reply",
    )
    .await
    .unwrap_err();
    assert_eq!(
        unavailable.to_string(),
        "query_sql [engine]: current member unavailable"
    );
}

#[tokio::test]
async fn reply_does_not_satisfy_action_or_decision_but_governed_evidence_does() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();
    let done = "vv:voc:lifecycle:completed".to_string();
    let action = create_message(&registry, &db, SENDER, "action", Value::Null).await;
    create_message(
        &registry,
        &db,
        RECIPIENT,
        "none",
        json!([{ "target_id": action, "relationship": "reply_to" }]),
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &action, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let work = call(
        &registry,
        &db,
        RECIPIENT,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "Perform requested work"
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    manage_link(&registry, &db, OTHER, "add", &work, &action, "derived_from").await;
    assert_eq!(
        derive_message_expectation_state(&db, &action, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    manage_link(
        &registry,
        &db,
        OTHER,
        "remove",
        &work,
        &action,
        "derived_from",
    )
    .await;
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &work,
        &action,
        "derived_from",
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &action, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    call(
        &registry,
        &db,
        RECIPIENT,
        "update_record",
        json!({ "id": work, "lifecycle": "completed" }),
    )
    .await
    .unwrap();
    let action_state = derive_message_expectation_state(&db, &action, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(action_state.state, MessageExpectationState::Satisfied);
    assert_eq!(action_state.evidence.unwrap().record_id, work);

    let wrong_owner_action = create_message(&registry, &db, SENDER, "action", Value::Null).await;
    let wrong_owner_work = create_record_as(
        &db,
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "Owned by someone else",
            "owner_id": OTHER_PERSON,
            "lifecycle": "completed"
        }),
        Some(RECIPIENT),
    )
    .await
    .unwrap();
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &wrong_owner_work,
        &wrong_owner_action,
        "derived_from",
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &wrong_owner_action, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );

    let legacy = propose_value_with_metadata_as(
        &db,
        "lifecycle",
        "complete",
        None,
        2.0,
        VocabularyValueTerminality::Open,
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &legacy).await.unwrap();
    let aliased_action = create_message(&registry, &db, SENDER, "action", Value::Null).await;
    call(
        &registry,
        &db,
        RECIPIENT,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "Historical lifecycle spelling",
            "lifecycle": "complete",
            "links": [{ "target_id": aliased_action, "relationship": "derived_from" }]
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        derive_message_expectation_state(&db, &aliased_action, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    alias_value(&db, &legacy, &done).await.unwrap();
    assert_eq!(
        derive_message_expectation_state(&db, &aliased_action, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );

    let decision = create_message(&registry, &db, SENDER, "decision", Value::Null).await;
    create_message(
        &registry,
        &db,
        RECIPIENT,
        "none",
        json!([{ "target_id": decision, "relationship": "reply_to" }]),
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &decision, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let resolution = call(
        &registry,
        &db,
        RECIPIENT,
        "create_record",
        json!({
            "type": "Resolution",
            "kind": "decision",
            "name": "Choose the governed option"
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    manage_link(
        &registry,
        &db,
        OTHER,
        "add",
        &resolution,
        &decision,
        "derived_from",
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &decision, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    manage_link(
        &registry,
        &db,
        OTHER,
        "remove",
        &resolution,
        &decision,
        "derived_from",
    )
    .await;
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &resolution,
        &decision,
        "derived_from",
    )
    .await;
    let decision_state = derive_message_expectation_state(&db, &decision, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(decision_state.state, MessageExpectationState::Satisfied);
    assert_eq!(decision_state.evidence.unwrap().record_id, resolution);

    let wrong_owner_decision =
        create_message(&registry, &db, SENDER, "decision", Value::Null).await;
    let wrong_owner_resolution = create_record_as(
        &db,
        json!({
            "type": "Resolution",
            "kind": "decision",
            "name": "Decision owned by someone else",
            "owner_id": OTHER_PERSON
        }),
        Some(RECIPIENT),
    )
    .await
    .unwrap();
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &wrong_owner_resolution,
        &wrong_owner_decision,
        "derived_from",
    )
    .await;
    assert_eq!(
        derive_message_expectation_state(&db, &wrong_owner_decision, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );

    let read = call(
        &registry,
        &db,
        RECIPIENT,
        "get_record",
        json!({ "ids": [decision] }),
    )
    .await
    .unwrap();
    assert_eq!(
        read["records"][0]["message_expectation_state"]["format"],
        EXPECTATION_DERIVATION_VERSION
    );
    assert_eq!(
        read["records"][0]["message_expectation_state"]["state"],
        "satisfied"
    );
    let expectation = &read["records"][0]["message_expectation_state"];
    let rendered = native_ce::mcp::render::render("get_record", &read).unwrap();
    assert!(rendered.contains(&serde_json::to_string(expectation).unwrap()));
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_mark_closes_any_expectation_for_recipient_or_sender() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    async fn mark(
        registry: &ToolRegistry,
        db: &Db,
        actor: &str,
        message_id: &str,
        note: Value,
        key: &str,
    ) -> Value {
        let mut args = json!({
            "action": "mark_no_longer_relevant",
            "message_id": message_id,
            "idempotency_key": key,
            "reason": "Settled outside Native; closing the request without replying.",
        });
        if !note.is_null() {
            args["note"] = note;
        }
        call(registry, db, actor, "manage_messages", args)
            .await
            .unwrap()
    }

    async fn unmark(
        registry: &ToolRegistry,
        db: &Db,
        actor: &str,
        message_id: &str,
        key: &str,
    ) -> Value {
        call(
            registry,
            db,
            actor,
            "manage_messages",
            json!({
                "action": "unmark_no_longer_relevant",
                "message_id": message_id,
                "idempotency_key": key,
                "reason": "Reopening; the request still stands.",
            }),
        )
        .await
        .unwrap()
    }

    // A recipient mark closes every expectation value; undoing reopens it.
    for expectation in ["ack", "reply", "action", "decision"] {
        let source = create_message(&registry, &db, SENDER, expectation, Value::Null).await;
        assert_eq!(
            derive_message_expectation_state(&db, &source, RECIPIENT)
                .await
                .unwrap()
                .state,
            MessageExpectationState::Open
        );
        let marked = mark(
            &registry,
            &db,
            RECIPIENT,
            &source,
            Value::Null,
            &format!("mark-{expectation}"),
        )
        .await;
        assert_eq!(marked["status"], "marked");
        assert_eq!(marked["changed"], true);
        let closed = derive_message_expectation_state(&db, &source, RECIPIENT)
            .await
            .unwrap();
        assert_eq!(closed.state, MessageExpectationState::Satisfied);
        let evidence = closed.evidence.unwrap();
        assert_eq!(
            evidence.kind,
            MessageExpectationEvidenceKind::NoLongerRelevant
        );
        assert_eq!(evidence.by.as_deref(), Some("recipient"));
        assert_eq!(
            evidence.record_id,
            marked["evidence_record_id"].as_str().unwrap()
        );
        let unmarked = unmark(
            &registry,
            &db,
            RECIPIENT,
            &source,
            &format!("unmark-{expectation}"),
        )
        .await;
        assert_eq!(unmarked["status"], "unmarked");
        assert_eq!(unmarked["changed"], true);
        assert_eq!(
            derive_message_expectation_state(&db, &source, RECIPIENT)
                .await
                .unwrap()
                .state,
            MessageExpectationState::Open
        );
    }

    // A sender mark withdraws the request; the note is stored as the body.
    let reply_source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    let marked = mark(
        &registry,
        &db,
        SENDER,
        &reply_source,
        json!("Settled on the call."),
        "sender-mark",
    )
    .await;
    assert_eq!(marked["changed"], true);
    let withdrawn = derive_message_expectation_state(&db, &reply_source, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(withdrawn.state, MessageExpectationState::Satisfied);
    let evidence = withdrawn.evidence.unwrap();
    assert_eq!(
        evidence.kind,
        MessageExpectationEvidenceKind::NoLongerRelevant
    );
    assert_eq!(evidence.by.as_deref(), Some("sender"));
    let read = call(
        &registry,
        &db,
        RECIPIENT,
        "get_record",
        json!({ "ids": [evidence.record_id] }),
    )
    .await
    .unwrap();
    assert_eq!(read["records"][0]["body"], "Settled on the call.");

    // A mark without a note stores an empty body.
    let bare = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    let marked = mark(&registry, &db, RECIPIENT, &bare, Value::Null, "bare-mark").await;
    let evidence_id = marked["evidence_record_id"].as_str().unwrap().to_owned();
    let read = call(
        &registry,
        &db,
        RECIPIENT,
        "get_record",
        json!({ "ids": [evidence_id] }),
    )
    .await
    .unwrap();
    assert_eq!(read["records"][0]["body"], "");

    // A third party's mark is recorded but does not satisfy, and their
    // unmark removes only their own mark.
    let context = json!([SENDER_PERSON, RECIPIENT_PERSON, OTHER_PERSON]);
    let third_party_source =
        create_message_in_context(&registry, &db, SENDER, "reply", Value::Null, context).await;
    let other_mark = mark(
        &registry,
        &db,
        OTHER,
        &third_party_source,
        Value::Null,
        "other-mark",
    )
    .await;
    assert_eq!(other_mark["changed"], true);
    assert_eq!(
        derive_message_expectation_state(&db, &third_party_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let other_unmark = unmark(&registry, &db, OTHER, &third_party_source, "other-unmark").await;
    assert_eq!(other_unmark["changed"], true);
    assert_eq!(
        derive_message_expectation_state(&db, &third_party_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let _ = mark(
        &registry,
        &db,
        RECIPIENT,
        &third_party_source,
        Value::Null,
        "recipient-mark-after-other",
    )
    .await;
    let closed = derive_message_expectation_state(&db, &third_party_source, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(closed.state, MessageExpectationState::Satisfied);
    assert_eq!(closed.evidence.unwrap().by.as_deref(), Some("recipient"));
    // Someone else's unmark removes nothing and leaves the mark closed.
    let noop = unmark(
        &registry,
        &db,
        OTHER,
        &third_party_source,
        "other-unmark-noop",
    )
    .await;
    assert_eq!(noop["changed"], false);
    assert_eq!(
        derive_message_expectation_state(&db, &third_party_source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );

    // Real evidence still wins when both exist.
    let ack_source = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    let acknowledgement = create_message(&registry, &db, RECIPIENT, "none", Value::Null).await;
    manage_link(
        &registry,
        &db,
        RECIPIENT,
        "add",
        &acknowledgement,
        &ack_source,
        "acknowledges",
    )
    .await;
    let _ = mark(
        &registry,
        &db,
        RECIPIENT,
        &ack_source,
        Value::Null,
        "mark-after-ack",
    )
    .await;
    let real_first = derive_message_expectation_state(&db, &ack_source, RECIPIENT)
        .await
        .unwrap();
    assert_eq!(real_first.state, MessageExpectationState::Satisfied);
    assert_eq!(
        real_first.evidence.unwrap().kind,
        MessageExpectationEvidenceKind::Acknowledgement
    );

    // A duplicate idempotency key replays the original receipt without new
    // side effects; a reused key for a different message conflicts.
    let first = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    let one = mark(&registry, &db, RECIPIENT, &first, Value::Null, "dup-key").await;
    let two = mark(&registry, &db, RECIPIENT, &first, Value::Null, "dup-key").await;
    assert_eq!(two["changed"], true);
    assert_eq!(one["evidence_record_id"], two["evidence_record_id"]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM links WHERE target_id=? AND relationship='resolves' AND note='no_longer_relevant'"
        )
        .bind(&first)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        1
    );
    let second = create_message(&registry, &db, SENDER, "ack", Value::Null).await;
    let conflict = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "mark_no_longer_relevant",
            "message_id": second,
            "idempotency_key": "dup-key",
            "reason": "Reusing a key for a different message.",
        }),
    )
    .await
    .unwrap_err();
    assert!(
        conflict.is_idempotency_conflict(),
        "unexpected error: {conflict}"
    );
    let un_one = unmark(&registry, &db, RECIPIENT, &first, "dup-unmark").await;
    assert_eq!(un_one["changed"], true);
    let un_two = unmark(&registry, &db, RECIPIENT, &first, "dup-unmark").await;
    assert_eq!(un_two["changed"], true);

    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_mark_drops_and_restores_messages_awaiting_reply() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    let source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    assert_eq!(
        awaiting_reply(&db, RECIPIENT).await,
        std::slice::from_ref(&source)
    );
    call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "mark_no_longer_relevant",
            "message_id": source,
            "idempotency_key": "awaiting-mark",
            "reason": "Settled outside Native.",
        }),
    )
    .await
    .unwrap();
    assert!(awaiting_reply(&db, RECIPIENT).await.is_empty());
    call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "unmark_no_longer_relevant",
            "message_id": source,
            "idempotency_key": "awaiting-unmark",
            "reason": "Still needed after all.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        awaiting_reply(&db, RECIPIENT).await,
        std::slice::from_ref(&source)
    );

    // A sender withdrawal drops the row for the recipient as well.
    let withdrawn = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    call(
        &registry,
        &db,
        SENDER,
        "manage_messages",
        json!({
            "action": "mark_no_longer_relevant",
            "message_id": withdrawn,
            "note": "Withdrawing my own request.",
            "idempotency_key": "sender-withdraw",
            "reason": "Withdrawing my own request.",
        }),
    )
    .await
    .unwrap();
    let remaining = awaiting_reply(&db, RECIPIENT).await;
    assert_eq!(remaining, std::slice::from_ref(&source));
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_replay_after_unmark_returns_the_original_receipt() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    async fn mark(registry: &ToolRegistry, db: &Db, key: &str, message_id: &str) -> Value {
        call(
            registry,
            db,
            RECIPIENT,
            "manage_messages",
            json!({
                "action": "mark_no_longer_relevant",
                "message_id": message_id,
                "idempotency_key": key,
                "reason": "Settled outside Native.",
            }),
        )
        .await
        .unwrap()
    }

    let source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    // Scenario A: the first k1 call is a no-op over the k0 mark. Unmarking
    // and retrying k1 must replay k1's own receipt, not an error and not
    // live state.
    let original = mark(&registry, &db, "replay-k0", &source).await;
    assert_eq!(original["changed"], true);
    let evidence_id = original["evidence_record_id"].clone();
    let noop = mark(&registry, &db, "replay-k1", &source).await;
    assert_eq!(noop["changed"], false);
    assert_eq!(noop["evidence_record_id"], evidence_id);
    let unmarked = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "unmark_no_longer_relevant",
            "message_id": source,
            "idempotency_key": "replay-unmark",
            "reason": "Reopening.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(unmarked["changed"], true);
    assert_eq!(
        derive_message_expectation_state(&db, &source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    let replayed = mark(&registry, &db, "replay-k1", &source).await;
    assert_eq!(replayed, noop);

    // Scenario B: re-marking under k2 creates a new record with a new id,
    // and retrying k1 still replays k1's receipt rather than k2's.
    let relinked = mark(&registry, &db, "replay-k2", &source).await;
    assert_eq!(relinked["changed"], true);
    assert_ne!(relinked["evidence_record_id"], evidence_id);
    assert_eq!(
        derive_message_expectation_state(&db, &source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );
    let replayed = mark(&registry, &db, "replay-k1", &source).await;
    assert_eq!(replayed, noop);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_deleted_or_archived_mark_does_not_satisfy() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    for case in ["deleted", "archived"] {
        let source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
        let marked = call(
            &registry,
            &db,
            RECIPIENT,
            "manage_messages",
            json!({
                "action": "mark_no_longer_relevant",
                "message_id": source,
                "idempotency_key": format!("mark-{case}"),
                "reason": "Settled outside Native.",
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            derive_message_expectation_state(&db, &source, RECIPIENT)
                .await
                .unwrap()
                .state,
            MessageExpectationState::Satisfied
        );
        let evidence_id = marked["evidence_record_id"].as_str().unwrap();
        // Stamp the removal into the log directly, as the link fixtures do:
        // the mark clones view-only visibility, so the tools would refuse.
        if case == "deleted" {
            delete_record_as(&db, evidence_id, Some(RECIPIENT))
                .await
                .unwrap();
        } else {
            archive_record_as(&db, evidence_id).await.unwrap();
        }
        assert_eq!(
            derive_message_expectation_state(&db, &source, RECIPIENT)
                .await
                .unwrap()
                .state,
            MessageExpectationState::Open,
            "{case} mark still satisfies"
        );
        assert!(
            awaiting_reply(&db, RECIPIENT).await.contains(&source),
            "{case} mark disagrees with messages_awaiting_reply"
        );
    }
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_remark_after_removal_uses_a_fresh_record() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    async fn mark(
        registry: &ToolRegistry,
        db: &Db,
        key: &str,
        message_id: &str,
        note: Value,
    ) -> Value {
        let mut args = json!({
            "action": "mark_no_longer_relevant",
            "message_id": message_id,
            "idempotency_key": key,
            "reason": "Settled outside Native.",
        });
        if !note.is_null() {
            args["note"] = note;
        }
        call(registry, db, RECIPIENT, "manage_messages", args)
            .await
            .unwrap()
    }

    async fn state(db: &Db, message_id: &str) -> MessageExpectationState {
        derive_message_expectation_state(db, message_id, RECIPIENT)
            .await
            .unwrap()
            .state
    }

    // A pre-existing unrelated record cannot block a mark: evidence ids are
    // random, so there is nothing to squat.
    let source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    let squat = create_raw_record(
        &db,
        json!({ "type": "Annotation", "kind": "no_longer_relevant", "name": "squat" }),
    )
    .await
    .unwrap();
    let first = mark(&registry, &db, "fresh-k1", &source, Value::Null).await;
    assert_eq!(first["changed"], true);
    assert_ne!(first["evidence_record_id"].as_str().unwrap(), squat);
    assert_eq!(
        state(&db, &source).await,
        MessageExpectationState::Satisfied
    );

    for (case, remove) in [("deleted", true), ("archived", false)] {
        let message = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
        let before = mark(&registry, &db, &format!("{case}-k1"), &message, Value::Null).await;
        let before_id = before["evidence_record_id"].as_str().unwrap().to_owned();
        if remove {
            delete_record_as(&db, &before_id, Some(RECIPIENT))
                .await
                .unwrap();
        } else {
            archive_record_as(&db, &before_id).await.unwrap();
        }
        assert_eq!(state(&db, &message).await, MessageExpectationState::Open);
        // Re-marking succeeds on a fresh record with the new note and closes
        // the expectation again; unmarking then reopens it.
        let after = mark(
            &registry,
            &db,
            &format!("{case}-k2"),
            &message,
            json!("Second thoughts, still settled."),
        )
        .await;
        assert_eq!(after["changed"], true);
        let after_id = after["evidence_record_id"].as_str().unwrap().to_owned();
        assert_ne!(after_id, before_id);
        assert_eq!(
            state(&db, &message).await,
            MessageExpectationState::Satisfied
        );
        let read = call(
            &registry,
            &db,
            RECIPIENT,
            "get_record",
            json!({ "ids": [after_id] }),
        )
        .await
        .unwrap();
        assert_eq!(
            read["records"][0]["body"],
            "Second thoughts, still settled."
        );
        let unmarked = call(
            &registry,
            &db,
            RECIPIENT,
            "manage_messages",
            json!({
                "action": "unmark_no_longer_relevant",
                "message_id": message,
                "idempotency_key": format!("{case}-unmark"),
                "reason": "Reopening.",
            }),
        )
        .await
        .unwrap();
        assert_eq!(unmarked["changed"], true);
        assert_eq!(state(&db, &message).await, MessageExpectationState::Open);
    }
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_unmark_removes_every_live_mark() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    let source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    let first = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "mark_no_longer_relevant",
            "message_id": source,
            "idempotency_key": "two-marks-k1",
            "reason": "Settled outside Native.",
        }),
    )
    .await
    .unwrap();
    let first_id = first["evidence_record_id"].as_str().unwrap().to_owned();
    // Archiving hides the mark, so a re-mark mints a second record; a
    // restore then leaves two live marks for the same caller.
    archive_record_as(&db, &first_id).await.unwrap();
    let second = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "mark_no_longer_relevant",
            "message_id": source,
            "idempotency_key": "two-marks-k2",
            "reason": "Settled outside Native.",
        }),
    )
    .await
    .unwrap();
    let second_id = second["evidence_record_id"].as_str().unwrap().to_owned();
    assert_ne!(second_id, first_id);
    restore_record_as(&db, &first_id).await.unwrap();
    assert_eq!(
        derive_message_expectation_state(&db, &source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Satisfied
    );
    let unmarked = call(
        &registry,
        &db,
        RECIPIENT,
        "manage_messages",
        json!({
            "action": "unmark_no_longer_relevant",
            "message_id": source,
            "idempotency_key": "two-marks-unmark",
            "reason": "Reopening.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(unmarked["changed"], true);
    assert_eq!(
        derive_message_expectation_state(&db, &source, RECIPIENT)
            .await
            .unwrap()
            .state,
        MessageExpectationState::Open
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM links WHERE target_id=? AND relationship='resolves' AND note='no_longer_relevant'"
        )
        .bind(&source)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn no_longer_relevant_mark_requires_message_view() {
    let db = create_database(":memory:").await.unwrap();
    install_accounts(&db).await;
    let registry = registry();

    // OTHER is outside this two-person direct context and cannot view the
    // message, so both mark and unmark are refused without writing.
    let source = create_message(&registry, &db, SENDER, "reply", Value::Null).await;
    for action in ["mark_no_longer_relevant", "unmark_no_longer_relevant"] {
        let error = call(
            &registry,
            &db,
            OTHER,
            "manage_messages",
            json!({
                "action": action,
                "message_id": source,
                "idempotency_key": format!("denied-{action}"),
                "reason": "Attempting without view access.",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not exist"), "{action}: {error}");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM links WHERE target_id=? AND relationship='resolves' AND note='no_longer_relevant'"
        )
        .bind(&source)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}
