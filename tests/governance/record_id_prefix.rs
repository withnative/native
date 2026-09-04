//! Unique-prefix resolution of abbreviated record ids at the tool boundary.
//!
//! The resolution lives in one chokepoint (`src/mcp/record_ref.rs`, applied in
//! `dispatch_with_request_port`), so these tests exercise it through the real
//! MCP dispatch rather than by calling the resolver directly. What is being
//! asserted is the *boundary* contract: which inputs expand, which are left
//! exactly as written, and what never reaches durable state.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::events::EventRow;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

/// Records are given deliberate ids so the prefix relationships under test are
/// stated rather than hoped for. All of these are canonical-UUID-shaped —
/// lowercase 8-4-4-4-12 hex — which is exactly the shape prefix matching is
/// allowed to see.
const UNIQUE: &str = "1a2b3c4d-0000-4000-8000-00000000ffff";
const TWIN_A: &str = "dede01aa-0000-4000-8000-000000000001";
const TWIN_B: &str = "dede01bb-0000-4000-8000-000000000002";
const HIDDEN: &str = "c0ffee11-0000-4000-8000-000000000003";
/// Shares its opening six characters with the short caller-chosen id `abc123`,
/// which is what makes exact-before-prefix observable.
const SHADOWED: &str = "abc1234a-0000-4000-8000-000000000004";
/// Placement has its own shape contract, so `home_id` needs a real folder.
const FOLDER: &str = "f01de400-0000-4000-8000-000000000005";

/// Caller-chosen ids, written by an older build. A record id admitted today
/// must be a canonical UUID, so no caller can mint these any more — but
/// databases written before that rule still hold them, and resolution has to
/// keep answering for them, which is exactly what rule 2 of
/// `src/mcp/record_ref.rs` is about. They are therefore seeded the way history
/// arrives: one projected `record.created` event, as in
/// `record_id_validation::fresh_genesis_is_exact_and_historical_malformed_ids_still_replay`.
///
/// The *shapes* here are load-bearing and must not be canonicalised:
/// - `EXACT` is a strict prefix of [`SHADOWED`] (`abc1234a-…`); without that
///   relationship the exact-before-prefix test asserts nothing.
/// - `ORDER_ONE` and `ORDER_TWO` both begin `order`, a non-hex human prefix
///   that matches two records, and they sort in that order.
const EXACT: &str = "abc123";
const ORDER_ONE: &str = "order-one";
const ORDER_TWO: &str = "order-two";

/// The id asserted by `create_record.id` in the assertion test. A canonical
/// UUID that shares its first five characters with [`SHADOWED`], so it stays
/// adjacent to the record a prefix scan would have been tempted to reach.
const ASSERTED: &str = "abc1240a-0000-4000-8000-000000000006";

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

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    call_as(registry, db, Caller::local(), tool, args)
        .await
        .unwrap_err()
        .to_string()
}

async fn make(registry: &ToolRegistry, db: &Db, id: &str, name: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({ "id": id, "type": "Document", "kind": "note", "name": name }),
    )
    .await;
}

async fn make_folder(registry: &ToolRegistry, db: &Db, id: &str, name: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({
            "id": id, "type": "Collection", "kind": "folder",
            "name": name, "persistence": "enduring"
        }),
    )
    .await;
}

/// Write one record the way an older build left it behind: a `record.created`
/// event inserted directly and projected, bypassing today's id admission rule
/// without bypassing the projector. Nothing else about the record differs from
/// one the tool would have written.
async fn make_historical(db: &Db, id: &str, name: &str) {
    let mut event = EventRow {
        local_seq: -1,
        id: format!("historical-record-created:{id}"),
        record_id: id.into(),
        event_type: "record.created".into(),
        payload: Some(
            json!({
                "type": "Document",
                "kind": "note",
                "name": name,
                "home_id": native_ce::schema::UNFILED_RECORD_ID,
                "persistence": "enduring"
            })
            .to_string(),
        ),
        actor: Some("engine:migration".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: native_ce::events::CausalEnvelopeV1::legacy_unknown(),
        created_at: "2026-01-01T00:00:00.000Z".into(),
    };
    let pool = crate::common::fixture_write_pool(db).await;
    let mut tx = pool.begin().await.unwrap();
    event.local_seq = sqlx::query_scalar(
        "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
         VALUES(?,?,?,?,?,?,1,'legacy_unknown') RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    native_ce::projector::project(&mut tx, &event)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    pool.close().await;
}

fn hosted(account: &str) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context("host:test", "db:test")
        .with_hosting_owner(false)
}

async fn bind_account(db: &Db, person: &str, account: &str) {
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    for (id, name) in [
        (UNIQUE, "Unique"),
        (TWIN_A, "Twin A"),
        (TWIN_B, "Twin B"),
        (HIDDEN, "Hidden"),
        (SHADOWED, "Shadowed"),
    ] {
        make(&registry, &db, id, name).await;
    }
    // Caller-chosen ids, seeded as history. `order` prefixes both of the
    // ordered pair, and `abc123` is a six-character id that a prefix scan
    // would otherwise be tempted to expand into SHADOWED.
    for (id, name) in [
        (ORDER_ONE, "Order one"),
        (ORDER_TWO, "Order two"),
        (EXACT, "Exactly abc123"),
    ] {
        make_historical(&db, id, name).await;
    }
    make_folder(&registry, &db, FOLDER, "Folder").await;
    (db, registry)
}

fn status_of(read: &Value, index: usize) -> &str {
    read["records"][index]["status"].as_str().unwrap()
}

#[tokio::test]
async fn a_six_character_prefix_addresses_a_record_on_reads_and_on_writes() {
    let (db, registry) = fixture().await;

    let read = call(&registry, &db, "get_record", json!({ "ids": ["1a2b3c"] })).await;
    assert_eq!(status_of(&read, 0), "found");
    assert_eq!(read["records"][0]["id"], UNIQUE);

    // The write surface has to resolve too, or a caller who can read by prefix
    // still has to expand it by hand to do anything.
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": "1a2b3c4d", "name": "Renamed through a prefix" }),
    )
    .await;
    assert_eq!(updated["id"], UNIQUE);
    assert_eq!(updated["name"], "Renamed through a prefix");

    // A parameter that is neither `id` nor `record_id`: placement still moves.
    let homed = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TWIN_A, "home_id": "f01de4" }),
    )
    .await;
    assert_eq!(homed["home_id"], FOLDER);
    db.close().await;
}

#[tokio::test]
async fn dash_normalisation_survives_the_ninth_character() {
    let (db, registry) = fixture().await;
    // Below eight characters a dash-free abbreviation and the stored id are
    // identical; at nine they diverge, because the stored form has a dash
    // where the dash-free form has its ninth hex digit.
    for abbreviation in ["1a2b3c4d0", "1a2b3c4d-0", "1a2b3c4d-00"] {
        let read = call(
            &registry,
            &db,
            "get_record",
            json!({ "ids": [abbreviation] }),
        )
        .await;
        assert_eq!(
            status_of(&read, 0),
            "found",
            "{abbreviation} must reach {UNIQUE}"
        );
        assert_eq!(read["records"][0]["id"], UNIQUE);
    }
    db.close().await;
}

#[tokio::test]
async fn an_exact_id_is_always_itself_and_never_enters_prefix_matching() {
    let (db, registry) = fixture().await;

    // `abc123` exists and also prefixes SHADOWED. Exact match wins; the
    // ambiguity that a prefix scan would have reported never arises.
    let read = call(&registry, &db, "get_record", json!({ "ids": [EXACT] })).await;
    assert_eq!(status_of(&read, 0), "found");
    assert_eq!(read["records"][0]["id"], EXACT);
    assert_eq!(read["records"][0]["name"], "Exactly abc123");

    // Caller-chosen and engine-owned ids resolve as themselves.
    for id in [ORDER_ONE, "native:root", "native:unfiled", UNIQUE] {
        let read = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
        assert_eq!(status_of(&read, 0), "found", "{id} must resolve as itself");
        assert_eq!(read["records"][0]["id"], id);
    }
    db.close().await;
}

#[tokio::test]
async fn a_human_chosen_prefix_resolves_to_nothing() {
    let (db, registry) = fixture().await;
    // `order` prefixes both `order-one` and `order-two`, which is precisely
    // why the caller-chosen namespace is excluded from prefix matching: it is
    // not uniformly distributed. The value is passed through untouched and the
    // ordinary not-found answer stands — no expansion, no ambiguity report.
    let read = call(&registry, &db, "get_record", json!({ "ids": ["order"] })).await;
    assert_eq!(status_of(&read, 0), "not_found");
    assert_eq!(read["records"][0]["id"], "order");

    // Even at six or more characters, a non-hex id is not an abbreviation.
    let read = call(&registry, &db, "get_record", json!({ "ids": ["order-"] })).await;
    assert_eq!(status_of(&read, 0), "not_found");
    assert_eq!(read["records"][0]["id"], "order-");
    db.close().await;
}

#[tokio::test]
async fn a_prefix_below_the_floor_does_not_resolve() {
    let (db, registry) = fixture().await;
    // Five hex characters is one short of the floor, and there is exactly one
    // record it could have reached — so this is the floor being enforced, not
    // an ambiguity being reported.
    let read = call(&registry, &db, "get_record", json!({ "ids": ["1a2b3"] })).await;
    assert_eq!(status_of(&read, 0), "not_found");
    assert_eq!(read["records"][0]["id"], "1a2b3");
    db.close().await;
}

#[tokio::test]
async fn an_ambiguous_prefix_names_the_records_it_matched() {
    let (db, registry) = fixture().await;
    let error = call_err(&registry, &db, "get_record", json!({ "ids": ["dede01"] })).await;
    assert!(error.contains("ambiguous"), "{error}");
    assert!(error.contains("dede01"), "{error}");
    // Actionable means the caller can pick one without another round trip.
    assert!(error.contains(TWIN_A), "{error}");
    assert!(error.contains(TWIN_B), "{error}");

    // Lengthening the abbreviation past the collision resolves it.
    let read = call(&registry, &db, "get_record", json!({ "ids": ["dede01a"] })).await;
    assert_eq!(status_of(&read, 0), "found");
    assert_eq!(read["records"][0]["id"], TWIN_A);
    db.close().await;
}

#[tokio::test]
async fn resolution_never_reports_a_record_the_caller_cannot_see() {
    let (db, registry) = fixture().await;
    let alice = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bea = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Bea" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    bind_account(&db, &alice, "acct:alice").await;
    bind_account(&db, &bea, "acct:bea").await;

    for (record, entries) in [
        (
            HIDDEN,
            vec![AllowEntry::account("acct:alice", Capability::Manage)],
        ),
        (
            TWIN_A,
            vec![
                AllowEntry::account("acct:alice", Capability::Manage),
                AllowEntry::account("acct:bea", Capability::View),
            ],
        ),
        (
            TWIN_B,
            vec![AllowEntry::account("acct:alice", Capability::Manage)],
        ),
    ] {
        replace_explicit_policy(&db, "test:policy", record, entries)
            .await
            .unwrap();
    }

    // `c0ffee` matches exactly one record, which Bea cannot see. That must be
    // answered identically to `bbbbbb`, which matches nothing at all —
    // otherwise resolution is an existence oracle.
    let unseen = call_as(
        &registry,
        &db,
        hosted("acct:bea"),
        "get_record",
        json!({ "ids": ["c0ffee", "bbbbbb"] }),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&unseen, 0), "not_found");
    assert_eq!(status_of(&unseen, 1), "not_found");
    assert_eq!(unseen["records"][0]["id"], "c0ffee");
    assert_eq!(unseen["records"][1]["id"], "bbbbbb");

    // Alice, who can see it, gets the expansion.
    let seen = call_as(
        &registry,
        &db,
        hosted("acct:alice"),
        "get_record",
        json!({ "ids": ["c0ffee"] }),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&seen, 0), "found");
    assert_eq!(seen["records"][0]["id"], HIDDEN);

    // The scoping cuts the other way too: `dede01` straddles two records, but
    // only one of them is Bea's, so for her it is unambiguous.
    let straddled = call_as(
        &registry,
        &db,
        hosted("acct:bea"),
        "get_record",
        json!({ "ids": ["dede01"] }),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&straddled, 0), "found");
    assert_eq!(straddled["records"][0]["id"], TWIN_A);

    let ambiguous = call_as(
        &registry,
        &db,
        hosted("acct:alice"),
        "get_record",
        json!({ "ids": ["dede01"] }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
    db.close().await;
}

#[tokio::test]
async fn nothing_durable_ever_stores_a_prefix() {
    let (db, registry) = fixture().await;

    call(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "add",
            "source_id": "1a2b3c",
            "target_id": "dede01a",
            "relationship": "relates_to"
        }),
    )
    .await;
    let (source, target): (String, String) =
        sqlx::query_as("SELECT source_id, target_id FROM links WHERE relationship='relates_to'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(source, UNIQUE);
    assert_eq!(target, TWIN_A);

    // Links declared inline on a create are resolved by the same pass, because
    // the chokepoint walks the whole argument tree rather than a fixed list of
    // top-level parameters.
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Inline links",
            "home_id": "f01de4",
            "links": [{ "target_id": "c0ffee", "relationship": "relates_to" }]
        }),
    )
    .await;
    let created_id = created["id"].as_str().unwrap();
    assert_eq!(created["home_id"], FOLDER);
    let inline: String =
        sqlx::query_scalar("SELECT target_id FROM links WHERE source_id=? AND relationship=?")
            .bind(created_id)
            .bind("relates_to")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(inline, HIDDEN);

    // No prefix survives anywhere in the durable id columns.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE length(source_id) < 36 OR length(target_id) < 36",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(leaked, 0);
    db.close().await;
}

#[tokio::test]
async fn message_mentions_persist_the_full_uuid() {
    let (db, registry) = fixture().await;
    let sender = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Sender" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let recipient = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Recipient" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (record, principal, account) in [
        (&sender, "native/sender", "acct:sender"),
        (&recipient, "native/recipient", "acct:recipient"),
    ] {
        for (system, identifier) in [("native-principal", principal), ("account", account)] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?,?,?,1)",
            )
            .bind(record)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
        }
    }

    let message = call(
        &registry,
        &db,
        "manage_messages",
        json!({
            "action": "send",
            "body": "See the unique record",
            "owner_id": &sender,
            "origin":{"type":"direct","participant_ids":[&sender,&recipient]},
            "addressed_to": [&recipient],
            "expectation": "none",
            "idempotency_key": "prefix-mention",
            "reason": "Exercise prefix resolution inside a structured mention.",
            "mentions": [{
                "mention_id": "mention-1",
                "target_kind": "record",
                "target_id": "1a2b3c",
                "span_start": 8,
                "span_end": 14,
                "authored_label": "unique"
            }]
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let stored: String =
        sqlx::query_scalar("SELECT target_record_id FROM message_mentions WHERE message_id=?")
            .bind(&message)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(stored, UNIQUE);
    db.close().await;
}

#[tokio::test]
async fn create_record_id_is_an_assertion_and_is_never_resolved() {
    let (db, registry) = fixture().await;

    // An abbreviation that resolves to UNIQUE through every other parameter.
    // As `create_record.id` it is an assertion, so it is judged as a *new* id
    // and refused for its shape. The refusal is the observation: had it been
    // resolved, the call would have reached UNIQUE and failed on the primary
    // key instead, with an entirely different error.
    let abbreviated = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Abbreviated", "id": "1a2b3c" }),
    )
    .await;
    assert!(
        abbreviated.contains("canonical lowercase UUID"),
        "{abbreviated}"
    );
    let untouched = call(&registry, &db, "get_record", json!({ "ids": [UNIQUE] })).await;
    assert_eq!(untouched["records"][0]["name"], "Unique");

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Asserted", "id": ASSERTED }),
    )
    .await;
    assert_eq!(created["id"], ASSERTED);

    // The stored id is exactly what was asserted, and a second assertion of
    // the same id still collides on the primary key rather than resolving to
    // anything.
    let read = call(&registry, &db, "get_record", json!({ "ids": [ASSERTED] })).await;
    assert_eq!(read["records"][0]["id"], ASSERTED);
    assert_eq!(read["records"][0]["name"], "Asserted");
    let duplicate = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Again", "id": ASSERTED }),
    )
    .await;
    assert!(duplicate.to_lowercase().contains("unique"), "{duplicate}");

    // And the pre-existing shape contract is untouched.
    let reserved = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Reserved", "id": "native:nope" }),
    )
    .await;
    assert!(reserved.contains("reserved"), "{reserved}");

    let malformed = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Bad", "id": "no spaces allowed" }),
    )
    .await;
    assert!(malformed.contains("record id"), "{malformed}");
    db.close().await;
}
