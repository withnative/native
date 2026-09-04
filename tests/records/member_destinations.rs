//! The destination rail's send-side coupling, end to end.
//!
//! Task 1's decided rule: sending a Message into a Collection adds that
//! Collection to the sender's rail; merely opening or browsing one does not.
//! These tests exercise that through the real tool surface rather than through
//! `awareness`'s own entry points, because the whole point of the rule is where
//! delivery happens.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const SENDER_ACCOUNT: &str = "acct_sender";
const READER_ACCOUNT: &str = "acct_reader";
const SENDER_PERSON: &str = "27e70000-0000-4000-8000-000000000001";
const READER_PERSON: &str = "27e70000-0000-4000-8000-000000000002";

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
        (SENDER_PERSON, "native/sender", SENDER_ACCOUNT),
        (READER_PERSON, "native/reader", READER_ACCOUNT),
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

/// A Collection both people can see and the sender can file into.
async fn channel(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    let folder = call(
        registry,
        db,
        SENDER_ACCOUNT,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":name}),
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
            AllowEntry::account(READER_ACCOUNT, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    folder
}

async fn rail(registry: &ToolRegistry, db: &Db, account: &str) -> Vec<String> {
    call(
        registry,
        db,
        account,
        "manage_messages",
        json!({"action":"list_destinations"}),
    )
    .await
    .unwrap()["destinations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["collection_id"].as_str().unwrap().to_string())
        .collect()
}

/// The whole listing, entries and all, for whichever breadth was asked for.
async fn rail_entries(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    include_removed: bool,
) -> Vec<Value> {
    call(
        registry,
        db,
        account,
        "manage_messages",
        json!({"action":"list_destinations","include_removed":include_removed}),
    )
    .await
    .unwrap()["destinations"]
        .as_array()
        .unwrap()
        .clone()
}

fn channel_post(key: &str, home_id: &str) -> Value {
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

#[tokio::test]
async fn sending_into_a_collection_joins_the_senders_rail_and_only_the_senders() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db, "Launch channel").await;

    assert!(rail(&registry, &db, SENDER_ACCOUNT).await.is_empty());

    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        channel_post("post-1", &folder),
    )
    .await
    .unwrap();

    assert_eq!(rail(&registry, &db, SENDER_ACCOUNT).await, vec![folder]);
    // Delivery is not joining. A reader who can see the Collection has not
    // sent into it, so their rail is untouched.
    assert!(rail(&registry, &db, READER_ACCOUNT).await.is_empty());
}

#[tokio::test]
async fn an_addressed_send_with_a_home_joins_exactly_as_a_channel_post_does() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db, "Addressed channel").await;

    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"Please confirm Monday.",
            "origin":{"type":"collection","collection_id":&folder},
            "addressed_to":[READER_PERSON],
            "expectation":"ack",
            "home_id":&folder,
            "idempotency_key":"addressed-1",
            "reason":"Ask the reader to confirm the launch date."
        }),
    )
    .await
    .unwrap();

    // The rule is about `home_id`, not about addressing.
    assert_eq!(rail(&registry, &db, SENDER_ACCOUNT).await, vec![folder]);
    assert!(rail(&registry, &db, READER_ACCOUNT).await.is_empty());
}

#[tokio::test]
async fn a_send_without_a_home_joins_nothing() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"A note with no destination.",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,READER_PERSON]},
            "addressed_to":[READER_PERSON],
            "expectation":"none",
            "idempotency_key":"homeless-1",
            "reason":"Send an unfiled Message."
        }),
    )
    .await
    .unwrap();
    assert!(rail(&registry, &db, SENDER_ACCOUNT).await.is_empty());
}

#[tokio::test]
async fn browsing_a_collection_and_its_messages_never_joins() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db, "Browsed channel").await;
    let message = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        channel_post("post-1", &folder),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Everything a reader can do short of sending.
    call(
        &registry,
        &db,
        READER_ACCOUNT,
        "get_record",
        json!({"ids":[&folder]}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        READER_ACCOUNT,
        "get_record",
        json!({"ids":[&message]}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        READER_ACCOUNT,
        "query_record",
        json!({"steps":[{"step":"filter","types":["Message"]}],"limit":50}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        READER_ACCOUNT,
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();

    assert!(
        rail(&registry, &db, READER_ACCOUNT).await.is_empty(),
        "opening, listing and browsing must not join a rail"
    );
    assert_eq!(
        rail(&registry, &db, SENDER_ACCOUNT).await,
        vec![folder],
        "the sender's own join must survive everyone else's reads"
    );
}

#[tokio::test]
async fn the_rail_can_be_left_and_a_later_send_rejoins_it() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db, "Left channel").await;
    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        channel_post("post-1", &folder),
    )
    .await
    .unwrap();

    let left = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"remove",
            "expected_version":1,
            "idempotency_key":"leave-1",
            "reason":"Leave the channel."
        }),
    )
    .await
    .unwrap();
    assert_eq!(left["present"], false);
    assert_eq!(left["version"], 2);
    assert!(rail(&registry, &db, SENDER_ACCOUNT).await.is_empty());

    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        channel_post("post-2", &folder),
    )
    .await
    .unwrap();
    assert_eq!(rail(&registry, &db, SENDER_ACCOUNT).await, vec![folder]);
}

#[tokio::test]
async fn adding_a_destination_requires_seeing_it_and_the_content_log_is_unmoved() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Private channel"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    replace_explicit_policy(
        &db,
        "test:policy",
        &folder,
        vec![AllowEntry::account(SENDER_ACCOUNT, Capability::Edit)],
    )
    .await
    .unwrap();

    let awareness_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM awareness_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let refused = call(
        &registry,
        &db,
        READER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"add",
            "expected_version":0,
            "idempotency_key":"reader-add",
            "reason":"Try to join a Collection I cannot see."
        }),
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("does not exist"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        awareness_before,
        "denied admission must append no awareness event"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM member_destinations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0,
        "denied admission must create no projection row"
    );

    let document = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Not a destination"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let wrong_shape = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":document,
            "destination":"add",
            "expected_version":0,
            "idempotency_key":"document-add",
            "reason":"Try to put a Document on the destination rail."
        }),
    )
    .await
    .unwrap_err();
    assert!(
        wrong_shape
            .to_string()
            .contains("must be a live, unarchived, enduring Collection kind:folder"),
        "{wrong_shape}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        awareness_before,
        "a visible non-Collection must append no awareness event"
    );

    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"add",
            "expected_version":0,
            "idempotency_key":"sender-add",
            "reason":"Join my own channel."
        }),
    )
    .await
    .unwrap();
    assert_eq!(rail(&registry, &db, SENDER_ACCOUNT).await, vec![folder]);

    // The destination lane is awareness-tier state. It must not have moved the
    // content log, and the content rebuild must still be exact.
    rebuild_and_diff(&db).await.unwrap();
}

#[tokio::test]
async fn the_inbox_groups_by_destination_without_a_second_query() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let launch = channel(&registry, &db, "Launch channel").await;
    let design = channel(&registry, &db, "Design channel").await;
    for (key, home) in [
        ("post-launch", &launch),
        ("post-launch-2", &launch),
        ("post-design", &design),
    ] {
        call(
            &registry,
            &db,
            SENDER_ACCOUNT,
            "manage_messages",
            channel_post(key, home),
        )
        .await
        .unwrap();
    }
    // One addressed Message sent without a home. It is not homeless: the
    // engine files it under `native:unfiled`, so grouping by destination is
    // total and a client never has to special-case a missing key.
    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"send",
            "body":"A note with no destination.",
            "origin":{"type":"direct","participant_ids":[SENDER_PERSON,READER_PERSON]},
            "addressed_to":[READER_PERSON],
            "expectation":"none",
            "idempotency_key":"homeless-1",
            "reason":"Send an unfiled Message."
        }),
    )
    .await
    .unwrap();

    let inbox = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":50}),
    )
    .await
    .unwrap();
    assert_eq!(inbox["schema"], "native.message-inbox.v2");
    let items = inbox["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);

    let mut by_destination = std::collections::BTreeMap::<String, usize>::new();
    for item in items {
        assert!(
            item.get("home_id").is_some(),
            "every item must carry home_id"
        );
        let key = item["home_id"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| "<unfiled>".into());
        *by_destination.entry(key).or_default() += 1;
    }
    assert_eq!(by_destination.get(&launch), Some(&2));
    assert_eq!(by_destination.get(&design), Some(&1));
    assert_eq!(
        by_destination.get(native_ce::schema::UNFILED_RECORD_ID),
        Some(&1),
        "a Message sent without a home groups under the Unfiled Collection"
    );
}

/// A version no client can read is not a version a client can state. Removal
/// keeps the row at a non-zero version deliberately, so a rejoin must assert
/// that number rather than 0 — and until `include_removed` existed, the only
/// place the number appeared was the prose of the conflict error. This is the
/// whole leave-and-rejoin round trip done through the API alone.
#[tokio::test]
async fn a_removed_destinations_version_is_readable_and_a_rejoin_can_state_it() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let folder = channel(&registry, &db, "Rejoinable channel").await;

    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"add",
            "expected_version":0,
            "idempotency_key":"join-1",
            "reason":"Join the channel."
        }),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"remove",
            "expected_version":1,
            "idempotency_key":"leave-1",
            "reason":"Leave the channel."
        }),
    )
    .await
    .unwrap();

    // The default listing is the member's actual rail, unchanged: the removed
    // Collection is not on it.
    assert!(rail_entries(&registry, &db, SENDER_ACCOUNT, false)
        .await
        .is_empty());
    assert!(rail(&registry, &db, SENDER_ACCOUNT).await.is_empty());

    // Asked for, the tombstone is there, marked as such, carrying the version.
    let full = rail_entries(&registry, &db, SENDER_ACCOUNT, true).await;
    assert_eq!(full.len(), 1);
    assert_eq!(full[0]["collection_id"].as_str().unwrap(), folder);
    assert_eq!(full[0]["present"], false);
    let learned = full[0]["version"].as_i64().unwrap();
    assert_eq!(learned, 2);

    // Tombstone visibility follows live authorization too. Give the non-owner
    // reader their own removed entry, then revoke their Collection access.
    for (destination, expected_version, key) in
        [("add", 0, "reader-join"), ("remove", 1, "reader-leave")]
    {
        call(
            &registry,
            &db,
            READER_ACCOUNT,
            "manage_messages",
            json!({
                "action":"set_destination",
                "collection_id":&folder,
                "destination":destination,
                "expected_version":expected_version,
                "idempotency_key":key,
                "reason":"Exercise the reader's own removed destination."
            }),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        rail_entries(&registry, &db, READER_ACCOUNT, true).await[0]["version"],
        2
    );
    replace_explicit_policy(
        &db,
        "test:revoke",
        &folder,
        vec![AllowEntry::account(SENDER_ACCOUNT, Capability::Edit)],
    )
    .await
    .unwrap();
    assert!(rail_entries(&registry, &db, READER_ACCOUNT, true)
        .await
        .is_empty());
    replace_explicit_policy(
        &db,
        "test:restore",
        &folder,
        vec![
            AllowEntry::account(SENDER_ACCOUNT, Capability::Edit),
            AllowEntry::account(READER_ACCOUNT, Capability::Edit),
        ],
    )
    .await
    .unwrap();

    // Stating the learned version rejoins. Nothing about the CAS relaxed: the
    // client simply knows what to assert without reading an error string.
    let rejoined = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"add",
            "expected_version":learned,
            "idempotency_key":"rejoin-1",
            "reason":"Pin the channel again."
        }),
    )
    .await
    .unwrap();
    assert_eq!(rejoined["changed"], true);
    assert_eq!(rejoined["present"], true);
    assert_eq!(rejoined["version"], learned + 1);
    assert_eq!(
        rail(&registry, &db, SENDER_ACCOUNT).await,
        vec![folder.clone()]
    );

    // And the CAS still bites: 0 is still wrong for a row that has history.
    let stale = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&folder,
            "destination":"remove",
            "expected_version":0,
            "idempotency_key":"stale-1",
            "reason":"Leave with a stale version."
        }),
    )
    .await
    .unwrap_err();
    assert!(stale.to_string().contains("version conflict"));

    rebuild_and_diff(&db).await.unwrap();
}

/// The default listing keeps meaning what it means today, and every entry says
/// so rather than leaving membership to be inferred from which call was made.
#[tokio::test]
async fn the_default_listing_is_still_the_rail_and_every_entry_states_presence() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let launch = channel(&registry, &db, "Launch channel").await;
    let design = channel(&registry, &db, "Design channel").await;
    for (key, home) in [("post-launch", &launch), ("post-design", &design)] {
        call(
            &registry,
            &db,
            SENDER_ACCOUNT,
            "manage_messages",
            channel_post(key, home),
        )
        .await
        .unwrap();
    }
    call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({
            "action":"set_destination",
            "collection_id":&design,
            "destination":"remove",
            "expected_version":1,
            "idempotency_key":"leave-design",
            "reason":"Leave the design channel."
        }),
    )
    .await
    .unwrap();

    // Omitting the argument entirely is the old call, with the old answer.
    let omitted = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        "manage_messages",
        json!({"action":"list_destinations"}),
    )
    .await
    .unwrap();
    assert_eq!(omitted["viewer_relative"], true);
    let entries = omitted["destinations"].as_array().unwrap().clone();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["collection_id"].as_str().unwrap(), launch);
    assert_eq!(entries[0]["present"], true);
    assert!(entries[0]["joined_at"].is_string());
    assert_eq!(entries[0]["joined_by"], "send");

    // Explicitly false is the same answer as omitting it.
    assert_eq!(
        rail_entries(&registry, &db, SENDER_ACCOUNT, false).await,
        entries
    );

    // Widened, the live rail still comes first and the tombstone follows it.
    let full = rail_entries(&registry, &db, SENDER_ACCOUNT, true).await;
    assert_eq!(full.len(), 2);
    assert_eq!(full[0]["collection_id"].as_str().unwrap(), launch);
    assert_eq!(full[0]["present"], true);
    assert_eq!(full[1]["collection_id"].as_str().unwrap(), design);
    assert_eq!(full[1]["present"], false);

    // A rail is personal state either way. Widening the read never reaches
    // another member's rail, present or removed.
    assert!(rail_entries(&registry, &db, READER_ACCOUNT, true)
        .await
        .is_empty());
}
