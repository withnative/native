//! Per-workspace act number (decision 4e152d5, task acd735f): R1–R7
//! acceptance coverage through the public tool surface.
//!
//! The unit-level proofs (rollback gaplessness, five-domain sharing, table
//! exhaustiveness, migration cutover, interchange revisions) live beside the
//! implementation in `src/act.rs`, `src/migrations.rs` and
//! `src/interchange.rs`. These integration tests pin the two behaviours that
//! must hold end to end: the verified cross-domain `delete_record` Message
//! fixture stamps one act, and multi-event batch writes share one act.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const SENDER_ACCOUNT: &str = "acct_sender";
const RECIPIENT_ACCOUNT: &str = "acct_recipient";
const RECIPIENT_PERSON: &str = "27e70000-0000-4000-8000-000000000002";
const SENDER_PERSON: &str = "27e70000-0000-4000-8000-000000000003";
const SENDER_PRINCIPAL: &str = "native/sender";
const RECIPIENT_PRINCIPAL: &str = "native/recipient";

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

async fn call_local(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn content_act(db: &Db, record_id: &str, event_type: &str) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id = ? AND type = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .bind(event_type)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

async fn install_people(db: &Db) {
    for (record_id, principal, account) in [
        (SENDER_PERSON, SENDER_PRINCIPAL, SENDER_ACCOUNT),
        (RECIPIENT_PERSON, RECIPIENT_PRINCIPAL, RECIPIENT_ACCOUNT),
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

async fn event_act(db: &Db, table: &str, seq: i64) -> Option<i64> {
    sqlx::query_scalar(&format!("SELECT act FROM {table} WHERE seq = ?"))
        .bind(seq)
        .fetch_optional(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
        .flatten()
}

/// Acceptance criterion 1: two events written by one transaction across two
/// different domains carry the same act number. The fixture is the verified
/// real instance — deleting a Message appends `record.deleted` to
/// `content_events` and a withdrawal to `notification_candidate_events`
/// inside one backend-owned transaction.
#[tokio::test]
async fn delete_message_stamps_one_act_across_content_and_candidates() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let message_id = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action": "send",
            "body": "Recipient",
            "origin": {"type": "direct", "participant_ids": [SENDER_PERSON, RECIPIENT_PERSON]},
            "addressed_to": [RECIPIENT_PERSON],
            "expectation": "none",
            "mentions": [{
                "mention_id": "act-fixture-mention",
                "target_kind": "principal",
                "target_id": RECIPIENT_PERSON,
                "span_start": 0,
                "span_end": 9,
                "authored_label": "Recipient"
            }],
            "idempotency_key": "act-fixture-send",
            "reason": "Send the mention that the delete fixture will withdraw."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let candidates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidates WHERE message_id = ? AND status = 'effective'",
    )
    .bind(&message_id)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(candidates, 1, "fixture must hold a live candidate");

    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "delete_record",
        json!({ "id": message_id, "reason": "Withdraw the act fixture message." }),
    )
    .await
    .unwrap();

    let pool = crate::common::fixture_write_pool(&db).await;
    let deletion_act: Option<i64> = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id = ? AND type = 'record.deleted' ORDER BY seq DESC LIMIT 1",
    )
    .bind(&message_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let withdrawal_acts: Vec<Option<i64>> = sqlx::query_scalar(
        "SELECT act FROM notification_candidate_events WHERE message_id = ? AND action = 'withdrawn' ORDER BY seq",
    )
    .bind(&message_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        !withdrawal_acts.is_empty(),
        "delete must withdraw candidates"
    );
    let deletion_act = deletion_act.expect("deletion event carries an act");
    assert!(
        withdrawal_acts.iter().all(|act| *act == Some(deletion_act)),
        "one transaction must stamp one act across domains"
    );
    db.close().await;
}

/// Acceptance criterion 3 (batch case): one transaction consumes exactly
/// one act however many events it writes. `append_batch` writes several
/// content events atomically; all must share the batch's act.
#[tokio::test]
async fn append_batch_shares_one_act_across_all_events() {
    let db = create_database(":memory:").await.unwrap();
    let events = native_ce::store::append_batch(
        &db,
        vec![
            native_ce::store::AppendSpec {
                record_id: "3a7e4000-0000-4000-8000-000000000001".into(),
                event_type: "record.created".into(),
                payload: json!({"type": "Document", "kind": "note", "name": "batch one"}),
                actor: None,
            },
            native_ce::store::AppendSpec {
                record_id: "3a7e4000-0000-4000-8000-000000000001".into(),
                event_type: "record.updated".into(),
                payload: json!({"summary": "batch two"}),
                actor: None,
            },
            native_ce::store::AppendSpec {
                record_id: "3a7e4000-0000-4000-8000-000000000002".into(),
                event_type: "record.created".into(),
                payload: json!({"type": "Document", "kind": "note", "name": "batch three"}),
                actor: None,
            },
        ],
    )
    .await
    .unwrap();
    assert_eq!(events.len(), 3);
    let mut acts = Vec::new();
    for event in &events {
        acts.push(event_act(&db, "content_events", event.local_seq).await);
    }
    let first = acts[0].expect("batched event carries an act");
    assert!(
        acts.iter().all(|act| *act == Some(first)),
        "one batch must stamp one act, got {acts:?}"
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// Task de24703: the produced act is returned on write responses.
// ---------------------------------------------------------------------------
//
// Criterion 1 is pinned below through representative writes across the three
// canonical logs this task's response fields touch — content (`create_record`,
// `manage_facet_observations`, `manage_links`, `manage_messages.send`), policy
// (`manage_record_policy`) and relationship (`manage_relationships`) — plus the
// shared observation response builder that also covers the portable backends.
// It does not enumerate all ten canonical logs: the remaining tools share the
// same echo-after-commit mechanism, and the multi-log test below pins
// cross-domain equality through the message delete path instead of repeating
// every tool. The portable Postgres/Turso response path is covered by the
// shared builders but is not exercised here (it needs a backend the local
// default test build does not run); that gap is recorded, not hidden.

/// de24703 criterion 1: a write through each representative tool class
/// returns an act, and the value matches the act stamped on the canonical
/// events that write appended.
#[tokio::test]
async fn write_responses_echo_the_act_stamped_on_their_events() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();

    // Lifecycle: record creation stamps `record.created` on content_events.
    let created = call_local(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Act echo fixture",
            "body": "first",
        }),
    )
    .await
    .unwrap();
    let create_act = created["act"]
        .as_i64()
        .expect("create_record must return its act");
    let created_id = created["id"].as_str().unwrap();
    assert_eq!(
        content_act(&db, created_id, "record.created").await,
        Some(create_act),
        "create_record act must match its content event"
    );

    // Observations: a facet set stamps `facet.set` via the shared response
    // builder.
    let observed = call_local(
        &registry,
        &db,
        "manage_facet_observations",
        json!({
            "action": "set",
            "record_id": created_id,
            "key": "current",
            "value": 10,
            "as_of": "2026-08-01T00:00:00Z",
            "reason": "Record the measurement behind this act.",
        }),
    )
    .await
    .unwrap();
    let observation_act = observed["act"]
        .as_i64()
        .expect("observation set must return its act");
    assert_eq!(
        content_act(&db, created_id, "facet.set").await,
        Some(observation_act),
        "observation act must match its content event"
    );

    // Links: `mentions` between Documents is content-owned, so the add lands
    // on content_events through the links `write_response` helper.
    let target = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "Link target"}),
    )
    .await
    .unwrap();
    let target_id = target["id"].as_str().unwrap().to_string();
    let linked = call_local(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "add",
            "source_id": created_id,
            "target_id": target_id,
            "relationship": "mentions",
        }),
    )
    .await
    .unwrap();
    let link_act = linked["act"]
        .as_i64()
        .expect("manage_links add must return its act");
    assert_eq!(
        content_act(&db, created_id, "link.added").await,
        Some(link_act),
        "link act must match its content event"
    );

    // Policy: a grant stamps the policy log, a non-content canonical domain.
    let granted = call_local(
        &registry,
        &db,
        "manage_record_policy",
        json!({
            "action": "grant",
            "record_id": created_id,
            "subject": {"kind": "account", "account_id": "acct:act-echo"},
            "capability": "view",
            "reason": "Grant a reviewer visibility for this act.",
        }),
    )
    .await
    .unwrap();
    let policy_act = granted["act"]
        .as_i64()
        .expect("policy grant must return its act");
    let policy_row_act: Option<i64> = sqlx::query_scalar(
        "SELECT act FROM policy_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(created_id)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(
        policy_row_act,
        Some(policy_act),
        "policy act must match its policy event"
    );

    // Relationships: an assertion stamps the relationship log, the other
    // non-content canonical domain exercised through tools here.
    let asserted = call_local(
        &registry,
        &db,
        "manage_relationships",
        json!({
            "action": "assert",
            "relationship_type": "depends_on",
            "endpoints": [
                {"role": "subject", "record_id": created_id},
                {"role": "object", "record_id": target_id},
            ],
            "on_behalf_of": "semantic-context-only",
            "idempotency_key": "act-echo-assert-1",
        }),
    )
    .await
    .unwrap();
    let relationship_act = asserted["act"]
        .as_i64()
        .expect("relationship assert must return its act");
    let event_ids: Vec<String> = asserted["output_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !event_ids.is_empty(),
        "assert must report its output events"
    );
    let stamped: Vec<Option<i64>> = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT act FROM relationship_events WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(serde_json::to_string(&event_ids).unwrap())
    .fetch_all(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(stamped.len(), event_ids.len());
    assert!(
        stamped.iter().all(|act| *act == Some(relationship_act)),
        "relationship act must match every stamped event, got {stamped:?}"
    );

    // Messaging: a send is a record create with delivery semantics; its
    // response act must match the `record.created` it appended.
    install_people(&db).await;
    let sent = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action": "send",
            "body": "Recipient",
            "origin": {"type": "direct", "participant_ids": [SENDER_PERSON, RECIPIENT_PERSON]},
            "addressed_to": [RECIPIENT_PERSON],
            "expectation": "none",
            "idempotency_key": "act-echo-send",
            "reason": "Send the message whose act the response must echo."
        }),
    )
    .await
    .unwrap();
    let sent_act = sent["act"]
        .as_i64()
        .expect("manage_messages send must return its act");
    let sent_id = sent["id"].as_str().unwrap();
    assert_eq!(
        content_act(&db, sent_id, "record.created").await,
        Some(sent_act),
        "send act must match its record.created event"
    );
    db.close().await;
}

/// de24703 criterion 2: a single write spanning more than one canonical log
/// returns exactly one act, equal on every event it appended. Deleting a
/// delivered Message appends `record.deleted` to content_events and a
/// withdrawal to notification_candidate_events in one transaction; the
/// delete_record response must carry the one act stamped on both.
#[tokio::test]
async fn delete_message_response_carries_the_single_act_stamped_across_logs() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let message_id = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action": "send",
            "body": "Recipient",
            "origin": {"type": "direct", "participant_ids": [SENDER_PERSON, RECIPIENT_PERSON]},
            "addressed_to": [RECIPIENT_PERSON],
            "expectation": "none",
            "mentions": [{
                "mention_id": "act-response-mention",
                "target_kind": "principal",
                "target_id": RECIPIENT_PERSON,
                "span_start": 0,
                "span_end": 9,
                "authored_label": "Recipient"
            }],
            "idempotency_key": "act-response-send",
            "reason": "Send the mention that the response-act fixture will withdraw."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let deleted = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "delete_record",
        json!({ "id": message_id, "reason": "Withdraw the response-act fixture message." }),
    )
    .await
    .unwrap();
    let response_act = deleted["act"]
        .as_i64()
        .expect("delete_record must return its act");

    let pool = crate::common::fixture_write_pool(&db).await;
    let deletion_act: Option<i64> = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id = ? AND type = 'record.deleted' ORDER BY seq DESC LIMIT 1",
    )
    .bind(&message_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        deletion_act,
        Some(response_act),
        "delete response act must match the deletion event"
    );
    let withdrawal_acts: Vec<Option<i64>> = sqlx::query_scalar(
        "SELECT act FROM notification_candidate_events WHERE message_id = ? AND action = 'withdrawn' ORDER BY seq",
    )
    .bind(&message_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        !withdrawal_acts.is_empty(),
        "delete must withdraw candidates"
    );
    assert!(
        withdrawal_acts.iter().all(|act| *act == Some(response_act)),
        "one delete must stamp one act across logs, got {withdrawal_acts:?}"
    );
    db.close().await;
}

/// de24703 criterion 3 (true no-op half): a call that appends nothing —
/// an unkeyed state no-op — omits the act key entirely. The assertion is key
/// absence, not a null value, because "no act" and "act unchanged" are
/// different facts.
#[tokio::test]
async fn true_no_op_writes_omit_the_act_key() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();
    let created = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "No-op fixture"}),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    // Archive is idempotent by state, not by key: the second archive appends
    // nothing and must omit act.
    let first_archive = call_local(
        &registry,
        &db,
        "archive_record",
        json!({"id": id, "archived": true, "reason": "Archive the no-op fixture."}),
    )
    .await
    .unwrap();
    assert_eq!(first_archive["changed"], true);
    assert!(
        first_archive["act"].is_i64(),
        "the archiving write must return its act: {first_archive}"
    );
    let second_archive = call_local(
        &registry,
        &db,
        "archive_record",
        json!({"id": id, "archived": true, "reason": "Archive the no-op fixture again."}),
    )
    .await
    .unwrap();
    assert_eq!(second_archive["changed"], false);
    assert!(
        second_archive.get("act").is_none(),
        "an already-archived archive must omit act entirely: {second_archive}"
    );

    // A grant already satisfied by inheritance is a no-op and appends no
    // policy event, so it must omit act too.
    let inherited_noop = call_local(
        &registry,
        &db,
        "manage_record_policy",
        json!({
            "action": "grant",
            "record_id": id,
            "subject": {"kind": "members"},
            "capability": "view",
            "reason": "Confirm the inherited members grant is already satisfied.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(inherited_noop["changed"], false);
    assert!(
        inherited_noop.get("act").is_none(),
        "a satisfied policy grant must omit act entirely: {inherited_noop}"
    );
    db.close().await;
}

/// de24703 criterion 3 (keyed replay half): a keyed idempotent replay of a
/// write that did append returns the original write's act, so the replay is
/// indistinguishable from the call that did the work.
#[tokio::test]
async fn keyed_replays_return_the_original_write_act() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();

    let args = json!({
        "id": "4b7e5000-0000-4000-8000-000000000001",
        "type": "Document",
        "kind": "note",
        "name": "Replay act fixture",
        "idempotency_key": "act-replay-create",
    });
    let first = call_local(&registry, &db, "create_record", args.clone())
        .await
        .unwrap();
    let first_act = first["act"].as_i64().expect("first write returns act");
    let replay = call_local(&registry, &db, "create_record", args)
        .await
        .unwrap();
    assert_eq!(replay["id"], first["id"]);
    assert_eq!(
        replay["act"].as_i64(),
        Some(first_act),
        "keyed create replay must return the original write's act: {replay}"
    );
    assert_eq!(
        content_act(&db, first["id"].as_str().unwrap(), "record.created").await,
        Some(first_act),
        "the replayed act must be the one stamped on the original event"
    );

    let subject = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "WorkItem", "kind": "task", "name": "replay subject"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let object = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "Outcome", "kind": "target", "name": "replay object"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let assertion = json!({
        "action": "assert",
        "relationship_type": "depends_on",
        "endpoints": [
            {"role": "subject", "record_id": subject},
            {"role": "object", "record_id": object},
        ],
        "on_behalf_of": "semantic-context-only",
        "idempotency_key": "act-replay-assert-1",
    });
    let asserted = call_local(&registry, &db, "manage_relationships", assertion.clone())
        .await
        .unwrap();
    let asserted_act = asserted["act"].as_i64().expect("first assert returns act");
    let duplicate = call_local(&registry, &db, "manage_relationships", assertion)
        .await
        .unwrap();
    assert_eq!(duplicate["status"], "asserted");
    assert_eq!(
        duplicate["act"].as_i64(),
        Some(asserted_act),
        "relationship duplicate must return the original write's act: {duplicate}"
    );

    // Interventions: a cancel writes once; the idempotent retry replays the
    // receipt and returns the original act.
    install_people(&db).await;
    bind_blocking_policy(&registry, &db).await;
    let blocked = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action": "send",
            "body": "We confirm the public launch will happen on Monday.",
            "preview": "Launch confirmation for Monday, addressed to the intended recipient.",
            "origin": {"type": "direct", "participant_ids": [SENDER_PERSON, RECIPIENT_PERSON]},
            "addressed_to": [RECIPIENT_PERSON],
            "expectation": "reply",
            "idempotency_key": "act-replay-send",
            "reason": "Send the delivery the replay fixture will cancel."
        }),
    )
    .await
    .unwrap();
    let intervention_id = blocked["delivery"]["intervention_id"]
        .as_str()
        .unwrap()
        .to_string();
    let view = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        json!({"action": "get", "intervention_id": intervention_id}),
    )
    .await
    .unwrap();
    let cancel_args = json!({
        "action": "cancel",
        "intervention_id": intervention_id,
        "expected_intervention_seq": view["projection_seq"],
        "idempotency_key": "act-replay-cancel-once",
        "reason": "The recipient declines this exact delivery.",
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
    assert_eq!(cancelled["write_receipt"]["replayed"], false);
    let cancelled_act = cancelled["act"].as_i64().expect("first cancel returns act");
    let retry = call(
        &registry,
        &db,
        RECIPIENT_ACCOUNT,
        "manage_interventions",
        cancel_args,
    )
    .await
    .unwrap();
    assert_eq!(retry["write_receipt"]["replayed"], true);
    assert_eq!(
        retry["act"].as_i64(),
        Some(cancelled_act),
        "intervention retry must return the original write's act: {retry}"
    );
    db.close().await;
}

/// de24703 review fix: the relationship half of the attestation-output join is
/// not unique on `id` alone. Federated import stamps a foreign issuer origin
/// and a local ingest act on ingested peer events, so a peer event reusing a
/// canonical UUID that a local keyed write already used leaves two rows sharing
/// that id. An unqualified join matches both and `MAX(act)` — which is how the
/// act is recovered for a replay — can return the peer-ingest act instead of
/// the original write's. The keyed replay must report the original act, because
/// a replay must be indistinguishable from the call that did the work.
#[tokio::test]
async fn keyed_relationship_replay_ignores_a_foreign_colliding_event() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();

    let subject = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "WorkItem", "kind": "task", "name": "collision subject"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let object = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "Outcome", "kind": "target", "name": "collision object"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let assertion = json!({
        "action": "assert",
        "relationship_type": "depends_on",
        "endpoints": [
            {"role": "subject", "record_id": subject},
            {"role": "object", "record_id": object},
        ],
        "on_behalf_of": "semantic-context-only",
        "idempotency_key": "act-foreign-collision-assert",
    });
    let asserted = call_local(&registry, &db, "manage_relationships", assertion.clone())
        .await
        .unwrap();
    let original_act = asserted["act"].as_i64().expect("first assert returns act");

    // The local relationship event the keyed write appended, and the act it
    // carries. The replay recovers the act from this row (through the
    // attestation's recorded output), so the foreign row below is the decoy.
    let (local_event_id, local_origin, local_event_act): (String, String, Option<i64>) =
        sqlx::query_as(
            "SELECT id, relationship_origin_db_id, act FROM relationship_events ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(
        local_event_act,
        Some(original_act),
        "the original write's act is stamped on its relationship event"
    );

    // A federated peer event reusing the canonical UUID under its own issuer
    // origin, carrying a larger ingest act. `relationship_events` is UNIQUE
    // `(issuer_origin_db_id, id)`, so this is a legal second row.
    let foreign_issuer = "ndb_ffffffffffffffffffffffffffffffff";
    assert_eq!(foreign_issuer.len(), 36);
    let decoy_act = original_act + 1_000_000;
    sqlx::query(
        "INSERT INTO relationship_events(
             id, stream_kind, stream_id, stream_version, relationship_origin_db_id,
             relationship_id, type, payload, actor, issuer_origin_db_id,
             occurred_at, ingested_at, act
         ) VALUES(?,'assertion',?,1,?,?,'assertion.created.v1','{}','peer',
                  ?,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',?)",
    )
    .bind(&local_event_id)
    .bind(format!("{local_event_id}-peer"))
    .bind(&local_origin)
    .bind(&local_event_id)
    .bind(foreign_issuer)
    .bind(decoy_act)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let replay = call_local(&registry, &db, "manage_relationships", assertion)
        .await
        .unwrap();
    assert_eq!(replay["status"], "asserted");
    assert_eq!(
        replay["act"].as_i64(),
        Some(original_act),
        "a keyed relationship replay must return the original write's act, \
         never a foreign-ingest act on a colliding id: {replay}"
    );
    db.close().await;
}

/// Member-scope escalation policy pinning `send_message` to
/// `block_and_request_authority`, so the omission fixture can cancel a
/// blocked delivery. Mirrors the interventions suite's own fixture.
async fn bind_blocking_policy(registry: &ToolRegistry, db: &Db) {
    let source = call(
        registry,
        db,
        SENDER_ACCOUNT,
        "create_record",
        json!({
            "type": "Document",
            "kind": "escalation-policy",
            "name": "Agent escalation policy",
            "body": serde_json::to_string(&json!({
                "format": "native.escalation-policy.v1",
                "issuer_principal_id": SENDER_PRINCIPAL,
                "statements": [{
                    "statement_id": "release-agent-send",
                    "kind": "hard_rule",
                    "scope": {"action.destination_kind": ["same_workspace"]},
                    "when": {"all": [{"field": "action.operation", "op": "eq", "value": "send_message"}]},
                    "effect": {"disposition": "block_and_request_authority"}
                }]
            }))
            .unwrap()
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
            "action": "create_binding",
            "scope": "member",
            "source_record_id": source,
            "position": 0,
            "idempotency_key": "bind-act-omission-policy",
            "reason": "Bind the principal's explicit policy source for this test."
        }),
    )
    .await
    .unwrap();
}

/// de24703 criterion 4: acts returned by successive writes in one workspace
/// are non-decreasing, and at least one value is tied to the actual event row
/// rather than only to the ordering.
#[tokio::test]
async fn successive_writes_return_non_decreasing_acts() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();
    let mut acts = Vec::new();
    let mut ids = Vec::new();
    for name in ["first", "second", "third"] {
        let created = call_local(
            &registry,
            &db,
            "create_record",
            json!({"type": "Document", "kind": "note", "name": name}),
        )
        .await
        .unwrap();
        acts.push(
            created["act"]
                .as_i64()
                .unwrap_or_else(|| panic!("write {name} must return its act")),
        );
        ids.push(created["id"].as_str().unwrap().to_string());
    }
    assert!(
        acts.windows(2).all(|pair| pair[0] <= pair[1]),
        "successive acts must be non-decreasing, got {acts:?}"
    );
    // Ordering alone would pass on a monotonic-but-wrong implementation, so
    // pin every returned value to the act actually stamped on its event.
    for (name, (id, act)) in ["first", "second", "third"]
        .iter()
        .zip(ids.iter().zip(&acts))
    {
        assert_eq!(
            content_act(&db, id, "record.created").await,
            Some(*act),
            "write {name} act must match its record.created event"
        );
    }
    db.close().await;
}

/// de24703 criterion 5: read-only tools are unchanged — their responses
/// carry no act key.
#[tokio::test]
async fn read_only_tools_return_no_act_key() {
    let registry = registry();
    let db = create_database(":memory:").await.unwrap();
    let created = call_local(
        &registry,
        &db,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "Read fixture"}),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();

    let read = call_local(&registry, &db, "get_record", json!({"ids": [id]}))
        .await
        .unwrap();
    assert!(
        read.get("act").is_none(),
        "get_record must not carry an act key, got {read}"
    );

    let history = call_local(&registry, &db, "get_history", json!({"record_id": id}))
        .await
        .unwrap();
    assert!(
        history.get("act").is_none(),
        "get_history must not carry an act key, got {history}"
    );
    db.close().await;
}
