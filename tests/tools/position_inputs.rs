//! Event-id position inputs (design 08b4c21, slice S3a).
//!
//! Positions can be named by content event id, by every caller. This pins:
//! each new input round-trips; an undo flow works from a write receipt alone;
//! a hidden event's id resolves to a position and nothing else; and unknown,
//! pruned, non-v4 (for non-owners) and out-of-reach ids are refused alike.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const UNKNOWN_V4: &str = "5b6f0d52-9d1c-4a8e-8f0b-3c2d1e0f9a8b";
const NON_V4: &str = "00000000-0000-1000-8000-0000000000aa";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

fn owner() -> Caller {
    Caller::local()
}

fn member() -> Caller {
    Caller::authenticated("acct:member")
        .with_hosting_context("host:member", "db:test")
        .with_hosting_owner(false)
        .with_hosting_member(true)
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

async fn refusal_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> String {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .expect_err(&format!("{tool} should refuse"))
        .to_string()
}

async fn create_note(registry: &ToolRegistry, db: &Db, name: &str, body: &str) -> String {
    call_as(
        registry,
        db,
        owner(),
        "create_record",
        json!({
            "type": "Document", "kind": "note", "name": name, "body": body,
            "home_id": "native:root"
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn body_at(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    id: &str,
    as_of: Value,
) -> Option<String> {
    let read = call_as(
        registry,
        db,
        caller,
        "get_record",
        json!({ "ids": [id], "as_of": as_of }),
    )
    .await;
    read["records"][0]["body"].as_str().map(str::to_owned)
}

async fn event_id_for(db: &Db, record_id: &str, event_type: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .bind(event_type)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

async fn digest_of(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    let record = call_as(registry, db, owner(), "get_record", json!({ "ids": [id] })).await;
    record["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn rewrite_body(registry: &ToolRegistry, db: &Db, id: &str, body: &str) -> Value {
    let digest = digest_of(registry, db, id).await;
    call_as(
        registry,
        db,
        owner(),
        "update_record",
        json!({ "id": id, "body_set": body, "if_body_digest": digest }),
    )
    .await
}

#[tokio::test]
async fn undo_flow_uses_the_receipt_event_id_to_read_and_restore_prior_state() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = create_note(&registry, &db, "Plan", "first draft").await;

    let receipt = rewrite_body(&registry, &db, &id, "second draft").await;
    let previous_seq = receipt["previous_seq"].as_i64().unwrap();
    let previous_event_id = receipt["previous_event_id"].as_str().unwrap().to_owned();
    let expected: String = sqlx::query_scalar("SELECT id FROM content_events WHERE seq=?")
        .bind(previous_seq)
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(previous_event_id, expected, "id and seq name one event");

    // Owner and member both read the prior state by event id alone.
    for caller in [owner(), member()] {
        let prior = body_at(
            &registry,
            &db,
            caller,
            &id,
            json!({ "event_id": previous_event_id }),
        )
        .await;
        assert_eq!(prior.as_deref(), Some("first draft"));
    }
    // The numeric form still works for the owner and agrees.
    assert_eq!(
        body_at(
            &registry,
            &db,
            owner(),
            &id,
            json!({ "content_seq": previous_seq })
        )
        .await
        .as_deref(),
        Some("first draft")
    );

    // Restore: write the prior body back.
    let prior = body_at(
        &registry,
        &db,
        member(),
        &id,
        json!({ "event_id": previous_event_id }),
    )
    .await
    .unwrap();
    let restored = rewrite_body(&registry, &db, &id, &prior).await;
    assert!(restored["previous_event_id"].is_string());
    let now = call_as(
        &registry,
        &db,
        member(),
        "get_record",
        json!({ "ids": [&id] }),
    )
    .await;
    assert_eq!(now["records"][0]["body"], "first draft");
    db.close().await;
}

#[tokio::test]
async fn a_new_record_receipt_has_a_null_previous_event_id() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let created = call_as(
        &registry,
        &db,
        owner(),
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Fresh", "home_id": "native:root" }),
    )
    .await;
    assert!(created["previous_seq"].is_null(), "{created}");
    assert!(created["previous_event_id"].is_null(), "{created}");
    db.close().await;
}

#[tokio::test]
async fn as_of_event_id_round_trips_on_every_read_that_takes_as_of() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = create_note(&registry, &db, "Plan", "alpha").await;
    let first = event_id_for(&db, &id, "record.created").await;
    let receipt = rewrite_body(&registry, &db, &id, "beta").await;
    let anchor = receipt["previous_event_id"].as_str().unwrap().to_owned();
    assert_eq!(anchor.len(), 36);
    let _ = first;

    for caller in [owner(), member()] {
        // get_record
        assert_eq!(
            body_at(
                &registry,
                &db,
                caller.clone(),
                &id,
                json!({ "event_id": anchor })
            )
            .await
            .as_deref(),
            Some("alpha")
        );
        // query_record
        let queried = call_as(
            &registry,
            &db,
            caller.clone(),
            "query_record",
            json!({
                "steps": [{ "step": "filter", "ids": [id] }],
                "as_of": { "event_id": anchor }
            }),
        )
        .await;
        assert_eq!(queried["as_of"], json!({ "event_id": anchor }));
        assert_eq!(queried["records"][0]["body"], "alpha");
        // get_structure
        let structure = call_as(
            &registry,
            &db,
            caller.clone(),
            "get_structure",
            json!({ "root_id": "native:root", "as_of": { "event_id": anchor } }),
        )
        .await;
        assert_eq!(structure["as_of"], json!({ "event_id": anchor }));
    }
    // The empty prefix has a position too.
    let origin = body_at(
        &registry,
        &db,
        member(),
        &id,
        json!({ "event_id": "origin" }),
    )
    .await;
    assert_eq!(origin, None);
    db.close().await;
}

#[tokio::test]
async fn canvas_reads_accept_as_of_event_id() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let canvas = call_as(
        &registry,
        &db,
        owner(),
        "create_record",
        json!({ "type": "Document", "kind": "canvas", "name": "Sketch", "home_id": "native:root" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = event_id_for(&db, &canvas, "record.created").await;
    let scene = call_as(
        &registry,
        &db,
        owner(),
        "read_canvas",
        json!({ "action": "get_scene", "canvas_id": canvas, "as_of": { "event_id": created } }),
    )
    .await;
    assert_eq!(scene["as_of"], json!({ "event_id": created }));
    db.close().await;
}

#[tokio::test]
async fn query_record_continuation_names_the_page_by_event_id_for_non_owners_only() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    for index in 0..3 {
        create_note(&registry, &db, &format!("Page {index}"), "x").await;
    }
    let page = |caller: Caller| {
        let registry = &registry;
        let db = &db;
        async move {
            call_as(
                registry,
                db,
                caller,
                "query_record",
                json!({
                    "steps": [{ "step": "filter", "types": ["Document"] }],
                    "limit": 1
                }),
            )
            .await
        }
    };
    let owner_page = page(owner()).await;
    assert!(owner_page["next_request"]["as_of"]["content_seq"].is_i64());
    assert!(owner_page["next_request"]["as_of"]
        .get("event_id")
        .is_none());

    let member_page = page(member()).await;
    let as_of = &member_page["next_request"]["as_of"];
    assert!(as_of.get("content_seq").is_none(), "{member_page}");
    assert_eq!(as_of["event_id"].as_str().map(str::len), Some(36));

    // Passed back verbatim, the continuation reads the next page.
    let next = call_as(
        &registry,
        &db,
        member(),
        "query_record",
        member_page["next_request"].clone(),
    )
    .await;
    assert_eq!(next["offset"], json!(1));
    assert_eq!(next["records"].as_array().map(Vec::len), Some(1));
    db.close().await;
}

#[tokio::test]
async fn render_record_version_diff_accepts_before_event_id() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = create_note(&registry, &db, "Plan", "one").await;
    let receipt = rewrite_body(&registry, &db, &id, "two").await;
    let anchor = receipt["previous_event_id"].as_str().unwrap();
    let by_seq = call_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": id, "before_seq": receipt["previous_seq"] }),
    )
    .await;
    let by_id = call_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": id, "before_event_id": anchor }),
    )
    .await;
    // Naming the position by event id returns the same diff without the
    // counters a non-owner's numeric request would have echoed.
    assert_numberless("by event id", &by_id);
    let mut by_seq_numberless = by_seq.clone();
    by_seq_numberless["before"]
        .as_object_mut()
        .unwrap()
        .remove("as_of_seq");
    by_seq_numberless["after"]
        .as_object_mut()
        .unwrap()
        .remove("as_of_seq");
    for event in by_seq_numberless["events"].as_array_mut().unwrap() {
        event.as_object_mut().unwrap().remove("local_seq");
    }
    assert_eq!(by_seq_numberless, by_id);
    // Owners get the same diff either way, numbers included.
    let owner_by_id = call_as(
        &registry,
        &db,
        owner(),
        "render_record_version_diff",
        json!({ "record_id": id, "before_event_id": anchor }),
    )
    .await;
    let owner_by_seq = call_as(
        &registry,
        &db,
        owner(),
        "render_record_version_diff",
        json!({ "record_id": id, "before_seq": receipt["previous_seq"] }),
    )
    .await;
    assert_eq!(owner_by_id, owner_by_seq);
    assert!(owner_by_id["before"]["as_of_seq"].is_i64(), "{owner_by_id}");
    let both = refusal_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": id, "before_event_id": anchor, "before_seq": 1 }),
    )
    .await;
    assert!(both.contains("exactly one"), "{both}");
    db.close().await;
}

#[tokio::test]
async fn if_previous_event_id_guards_like_if_content_seq() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = create_note(&registry, &db, "Doomed", "x").await;
    let stale = event_id_for(&db, &id, "record.created").await;
    rewrite_body(&registry, &db, &id, "y").await;

    // A precondition naming a superseded event conflicts, exactly as a
    // superseded if_content_seq does.
    let conflict = refusal_as(
        &registry,
        &db,
        owner(),
        "delete_record",
        json!({ "id": id, "if_previous_event_id": stale }),
    )
    .await;
    assert!(conflict.contains("content revision conflict"), "{conflict}");

    let latest: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let deleted = call_as(
        &registry,
        &db,
        owner(),
        "delete_record",
        json!({ "id": id, "if_previous_event_id": latest }),
    )
    .await;
    assert!(deleted["previous_event_id"].is_string(), "{deleted}");

    let both = refusal_as(
        &registry,
        &db,
        owner(),
        "delete_record",
        json!({ "id": id, "if_previous_event_id": latest, "if_content_seq": 1 }),
    )
    .await;
    assert!(both.contains("not both"), "{both}");
    db.close().await;
}

/// A hidden record's events still occupy positions. Naming one as an `as_of`
/// is allowed (it is timing), and returns only what the caller can already
/// see: nothing about the hidden record's identity, type, actor or content.
#[tokio::test]
async fn a_hidden_event_id_resolves_to_a_position_and_reveals_nothing() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let visible = create_note(&registry, &db, "Visible plan", "visible body").await;
    let hidden = create_note(&registry, &db, "Hidden dossier", "classified-needle").await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("someone-else", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden_event = event_id_for(&db, &hidden, "record.created").await;

    let as_of = json!({ "event_id": hidden_event });
    let mut surfaces = Vec::new();
    surfaces.push(
        call_as(
            &registry,
            &db,
            member(),
            "get_record",
            json!({ "ids": [&visible], "as_of": as_of }),
        )
        .await,
    );
    surfaces.push(
        call_as(
            &registry,
            &db,
            member(),
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["Document"] }], "as_of": as_of }),
        )
        .await,
    );
    surfaces.push(
        call_as(
            &registry,
            &db,
            member(),
            "get_structure",
            json!({ "root_id": "native:root", "as_of": as_of }),
        )
        .await,
    );
    for surface in &surfaces {
        let text = surface.to_string();
        for needle in ["Hidden dossier", "classified-needle", hidden.as_str()] {
            assert!(!text.contains(needle), "{needle} leaked: {text}");
        }
    }
    // The hidden record itself is not readable at that position either.
    let direct = call_as(
        &registry,
        &db,
        member(),
        "get_record",
        json!({ "ids": [&hidden], "as_of": as_of }),
    )
    .await;
    assert!(
        !direct.to_string().contains("classified-needle"),
        "{direct}"
    );

    // A hidden id is no more resolvable than an unknown one where an id is
    // turned into the event it names.
    let for_hidden = refusal_as(
        &registry,
        &db,
        member(),
        "get_event_context",
        json!({ "event_id": hidden_event }),
    )
    .await;
    let for_unknown = refusal_as(
        &registry,
        &db,
        member(),
        "get_event_context",
        json!({ "event_id": UNKNOWN_V4 }),
    )
    .await;
    // The refusal echoes the id the caller supplied; with that substituted,
    // the two are the same text.
    assert_eq!(
        for_hidden.replace(&hidden_event, "<event>"),
        for_unknown.replace(UNKNOWN_V4, "<event>")
    );
    assert!(!for_hidden.contains(&hidden), "{for_hidden}");
    db.close().await;
}

/// Unknown, pruned and non-v4 (for a non-owner) ids give byte-identical
/// refusals, on every position input, and the text carries no number.
#[tokio::test]
async fn unresolvable_positions_share_one_refusal() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = create_note(&registry, &db, "Plan", "one").await;
    rewrite_body(&registry, &db, &id, "two").await;
    let receipt = rewrite_body(&registry, &db, &id, "three").await;
    // The "two" event: it will be renamed to a replicated-looking id.
    let live_anchor = receipt["previous_event_id"].as_str().unwrap().to_owned();
    // A later record whose event will be pruned.
    let later = create_note(&registry, &db, "Later", "z").await;
    let pruned = event_id_for(&db, &later, "record.created").await;

    // An event that exists but whose id is not v4-shaped (a replicated id).
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER content_events_no_delete")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET id=? WHERE id=?")
        .bind(NON_V4)
        .bind(&live_anchor)
        .execute(&pool)
        .await
        .unwrap();
    // A pruned id: the event is gone.
    sqlx::query("DELETE FROM content_events WHERE id=?")
        .bind(&pruned)
        .execute(&pool)
        .await
        .unwrap();

    type Build = fn(&str, &str) -> Value;
    let inputs: [(&str, Build); 2] = [
        (
            "get_record",
            |id, event| json!({ "ids": [id], "as_of": { "event_id": event } }),
        ),
        (
            "render_record_version_diff",
            |id, event| json!({ "record_id": id, "before_event_id": event }),
        ),
    ];
    for (tool, build) in inputs {
        let unknown = refusal_as(&registry, &db, member(), tool, build(&id, UNKNOWN_V4)).await;
        let pruned_text = refusal_as(&registry, &db, member(), tool, build(&id, &pruned)).await;
        let non_v4 = refusal_as(&registry, &db, member(), tool, build(&id, NON_V4)).await;
        let uppercase = refusal_as(
            &registry,
            &db,
            member(),
            tool,
            build(&id, &UNKNOWN_V4.to_uppercase()),
        )
        .await;
        assert_eq!(unknown, pruned_text, "{tool}: pruned differs from unknown");
        assert_eq!(unknown, non_v4, "{tool}: non-v4 differs from unknown");
        assert_eq!(unknown, uppercase, "{tool}: uppercase differs from unknown");
        assert!(
            unknown.contains("unknown position"),
            "{tool}: unexpected refusal {unknown}"
        );
        assert!(
            !unknown.chars().any(|c| c.is_ascii_digit()),
            "{tool}: the refusal carries a number: {unknown}"
        );
    }

    // The same non-v4 id is not a guard target for the owner: it exists, so
    // it resolves.
    let owner_read = call_as(
        &registry,
        &db,
        owner(),
        "get_record",
        json!({ "ids": [&id], "as_of": { "event_id": NON_V4 } }),
    )
    .await;
    assert_eq!(owner_read["records"][0]["body"], "two");
    let member_read = refusal_as(
        &registry,
        &db,
        member(),
        "get_record",
        json!({ "ids": [&id], "as_of": { "event_id": NON_V4 } }),
    )
    .await;
    assert!(member_read.contains("unknown position"), "{member_read}");
    db.close().await;
}

#[tokio::test]
async fn owners_keep_the_numeric_forms() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = create_note(&registry, &db, "Plan", "one").await;
    let receipt = rewrite_body(&registry, &db, &id, "two").await;
    assert!(receipt["previous_seq"].is_i64(), "{receipt}");
    let by_seq = body_at(
        &registry,
        &db,
        owner(),
        &id,
        json!({ "content_seq": receipt["previous_seq"] }),
    )
    .await;
    assert_eq!(by_seq.as_deref(), Some("one"));
    let read = call_as(
        &registry,
        &db,
        owner(),
        "get_record",
        json!({ "ids": [&id] }),
    )
    .await;
    assert!(read["records"][0]["version"]
        .as_str()
        .unwrap()
        .starts_with("rec:"));
    db.close().await;
}

/// Keys that carry a workspace counter. A non-owner naming a position by event
/// id must get none of them back, at any depth.
const COUNTER_KEYS: &[&str] = &[
    "resolved_content_seq",
    "content_head_seq",
    "content_seq",
    "as_of_seq",
    "local_seq",
];

fn counter_paths(value: &Value, path: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let here = format!("{path}.{key}");
                if COUNTER_KEYS.contains(&key.as_str()) && !child.is_null() {
                    out.push(here.clone());
                }
                counter_paths(child, &here, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                counter_paths(child, &format!("{path}[{index}]"), out);
            }
        }
        _ => {}
    }
}

fn assert_numberless(label: &str, value: &Value) {
    let mut found = Vec::new();
    counter_paths(value, "$", &mut found);
    assert!(
        found.is_empty(),
        "{label} carries counters {found:?}: {value}"
    );
}

/// M1 (review cbf90e9): a hidden event id resolves to a position, never to a
/// count. The success bodies and the error text of every event-id read carry
/// no sequence number for a non-owner, while owners keep theirs.
#[tokio::test]
async fn a_non_owner_event_id_read_carries_no_sequence_number() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let visible = create_note(&registry, &db, "Visible plan", "visible body").await;
    let hidden = create_note(&registry, &db, "Hidden dossier", "classified-needle").await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("someone-else", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden_event = event_id_for(&db, &hidden, "record.created").await;
    let later = create_note(&registry, &db, "Later note", "after the hidden event").await;
    create_note(&registry, &db, "Another", "x").await;
    let as_of = json!({ "event_id": hidden_event });

    let reads = [
        ("get_record", json!({ "ids": [&visible], "as_of": as_of })),
        (
            "query_record",
            json!({
                "steps": [{ "step": "filter", "types": ["Document"] }],
                "limit": 1,
                "as_of": as_of
            }),
        ),
        (
            "get_structure",
            json!({ "root_id": "native:root", "as_of": as_of }),
        ),
    ];
    for (tool, args) in reads {
        let body = call_as(&registry, &db, member(), tool, args.clone()).await;
        assert_numberless(tool, &body);
        assert_eq!(body["as_of"], as_of, "{tool}: {body}");
        // The owner reading the same position keeps the numeric metadata.
        let owner_body = call_as(&registry, &db, owner(), tool, args).await;
        assert!(
            owner_body["resolved_content_seq"].is_i64(),
            "{tool}: owners keep resolved_content_seq: {owner_body}"
        );
        assert!(
            owner_body["content_head_seq"].is_i64(),
            "{tool}: {owner_body}"
        );
    }

    // The query page's continuation stays an event id and reads on.
    let late_event = event_id_for(&db, &later, "record.created").await;
    let page = call_as(
        &registry,
        &db,
        member(),
        "query_record",
        reads_query_args(&json!({ "event_id": late_event })),
    )
    .await;
    assert_numberless("query_record page", &page);
    assert_eq!(page["has_more"], json!(true), "{page}");
    assert!(
        page["next_request"]["as_of"]["event_id"].is_string(),
        "{page}"
    );
    let next = call_as(
        &registry,
        &db,
        member(),
        "query_record",
        page["next_request"].clone(),
    )
    .await;
    assert_numberless("query_record continuation", &next);

    // render_record_version_diff by event id: no as_of_seq, no event counters.
    let diff = call_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": &visible, "before_event_id": hidden_event }),
    )
    .await;
    assert_numberless("render_record_version_diff", &diff);
    assert_eq!(diff["before"]["record"]["id"], json!(visible));

    // A record that did not yet exist at the position: the error names the
    // record and says nothing of a sequence.
    let missing = refusal_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": &later, "before_event_id": hidden_event }),
    )
    .await;
    assert_eq!(
        missing,
        format!("record {later} has no state at that position")
    );

    // The owner's numeric forms are unchanged.
    let owner_diff = call_as(
        &registry,
        &db,
        owner(),
        "render_record_version_diff",
        json!({ "record_id": &visible, "before_event_id": hidden_event }),
    )
    .await;
    assert!(owner_diff["before"]["as_of_seq"].is_i64(), "{owner_diff}");
    db.close().await;
}

fn reads_query_args(as_of: &Value) -> Value {
    json!({
        "steps": [{ "step": "filter", "types": ["Document"] }],
        "limit": 1,
        "as_of": as_of
    })
}

/// M2 (review cbf90e9): `before_event_id` goes through the holding-aware
/// resolver. Under a finite window `origin` sits below the floor, and it is
/// refused with the same numberless text as an unknown id.
#[tokio::test]
async fn before_event_id_below_a_finite_holding_floor_gets_the_uniform_refusal() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_note(&registry, &db, "Old", "one").await;
    let kept = create_note(&registry, &db, "Kept", "two").await;

    // Fabricate a window the way compaction will: drop everything older than
    // `kept`'s creation act from every canonical log.
    let pool = crate::common::fixture_write_pool(&db).await;
    let cut_act: i64 = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(&kept)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&pool)
        .await
        .unwrap();
    for table in native_ce::act::CANONICAL_EVENT_TABLES {
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {table}_no_delete"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(&format!("DELETE FROM {table} WHERE act < ?"))
            .bind(cut_act)
            .execute(&pool)
            .await
            .unwrap();
    }
    let floor: i64 = sqlx::query_scalar("SELECT MIN(seq) FROM content_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(floor > 1, "the fixture must have a finite window");

    let unknown = refusal_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": &kept, "before_event_id": UNKNOWN_V4 }),
    )
    .await;
    let below_floor = refusal_as(
        &registry,
        &db,
        member(),
        "render_record_version_diff",
        json!({ "record_id": &kept, "before_event_id": "origin" }),
    )
    .await;
    assert_eq!(unknown, below_floor);
    assert!(unknown.contains("unknown position"), "{unknown}");
    assert!(!unknown.contains("not_held"), "{unknown}");
    assert!(!unknown.chars().any(|c| c.is_ascii_digit()), "{unknown}");
    // The same position through the as_of lens agrees.
    let lens = refusal_as(
        &registry,
        &db,
        member(),
        "get_record",
        json!({ "ids": [&kept], "as_of": { "event_id": "origin" } }),
    )
    .await;
    assert_eq!(lens, unknown);

    db.close().await;
}

async fn drop_event_log_guards(pool: &sqlx::SqlitePool) {
    for trigger in ["content_events_no_update", "content_events_no_delete"] {
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger}"))
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(pool)
        .await
        .unwrap();
}

fn page_args() -> Value {
    json!({
        "steps": [{ "step": "filter", "types": ["Document"] }],
        "limit": 1
    })
}

/// L1 (review cbf90e9): a continuation names the greatest event at or below
/// the snapshot's sequence, so a numeric `as_of` that lands on a gap in the
/// sequence still pages for a non-owner.
#[tokio::test]
async fn a_continuation_at_a_sequence_gap_names_the_event_below_it() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_note(&registry, &db, "One", "x").await;
    create_note(&registry, &db, "Two", "x").await;
    let doomed = create_note(&registry, &db, "Doomed", "x").await;
    create_note(&registry, &db, "Three", "x").await;
    create_note(&registry, &db, "Four", "x").await;
    let pool = crate::common::fixture_write_pool(&db).await;
    drop_event_log_guards(&pool).await;
    let gap: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE record_id=?")
        .bind(&doomed)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM content_events WHERE record_id=?")
        .bind(&doomed)
        .execute(&pool)
        .await
        .unwrap();
    let below: String =
        sqlx::query_scalar("SELECT id FROM content_events WHERE seq < ? ORDER BY seq DESC LIMIT 1")
            .bind(gap)
            .fetch_one(&pool)
            .await
            .unwrap();

    let mut args = page_args();
    args["as_of"] = json!({ "content_seq": gap });
    let page = call_as(&registry, &db, member(), "query_record", args).await;
    assert_eq!(page["has_more"], json!(true), "{page}");
    assert_eq!(
        page["next_request"]["as_of"],
        json!({ "event_id": below }),
        "{page}"
    );
    let next = call_as(
        &registry,
        &db,
        member(),
        "query_record",
        page["next_request"].clone(),
    )
    .await;
    assert_eq!(next["offset"], json!(1), "{next}");
    db.close().await;
}

/// L1: when the final event has an id a non-owner cannot resolve again (a
/// replicated Message keeps the peer's id), no honest event-id token exists
/// for that snapshot. A page that needs a continuation is refused, numberless;
/// a single page that does not is unaffected, and owners are unaffected.
#[tokio::test]
async fn a_non_v4_head_refuses_a_continuation_but_not_a_complete_page() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create_note(&registry, &db, "One", "x").await;
    create_note(&registry, &db, "Two", "x").await;
    let pool = crate::common::fixture_write_pool(&db).await;
    drop_event_log_guards(&pool).await;
    sqlx::query("UPDATE content_events SET id=? WHERE seq=(SELECT MAX(seq) FROM content_events)")
        .bind(NON_V4)
        .execute(&pool)
        .await
        .unwrap();

    let refused = refusal_as(&registry, &db, member(), "query_record", page_args()).await;
    assert!(refused.contains("cannot be continued"), "{refused}");
    assert!(!refused.chars().any(|c| c.is_ascii_digit()), "{refused}");

    let mut whole = page_args();
    whole["limit"] = json!(50);
    let complete = call_as(&registry, &db, member(), "query_record", whole).await;
    assert_eq!(complete["has_more"], json!(false), "{complete}");
    assert_eq!(complete["next_request"], Value::Null, "{complete}");

    let owner_page = call_as(&registry, &db, owner(), "query_record", page_args()).await;
    assert!(owner_page["next_request"]["as_of"]["content_seq"].is_i64());
    db.close().await;
}

/// L4 (review cbf90e9): `if_previous_event_id` for a non-owner. A non-v4 id
/// and an id from another record are refused/conflict without a number.
#[tokio::test]
async fn a_non_owner_if_previous_event_id_is_refused_without_a_number() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let target = create_note(&registry, &db, "Target", "x").await;
    let other = create_note(&registry, &db, "Other", "y").await;
    let other_event = event_id_for(&db, &other, "record.created").await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &target,
        vec![AllowEntry::account("acct:member", Capability::Manage)],
    )
    .await
    .unwrap();
    let pool = crate::common::fixture_write_pool(&db).await;
    drop_event_log_guards(&pool).await;
    sqlx::query("UPDATE content_events SET id=? WHERE id=?")
        .bind(NON_V4)
        .bind(event_id_for(&db, &target, "record.created").await)
        .execute(&pool)
        .await
        .unwrap();

    let non_v4 = refusal_as(
        &registry,
        &db,
        owner_like_writer(),
        "delete_record",
        json!({ "id": target, "if_previous_event_id": NON_V4 }),
    )
    .await;
    let unknown = refusal_as(
        &registry,
        &db,
        owner_like_writer(),
        "delete_record",
        json!({ "id": target, "if_previous_event_id": UNKNOWN_V4 }),
    )
    .await;
    assert_eq!(non_v4, unknown);
    assert!(non_v4.contains("unknown position"), "{non_v4}");

    // A real event of a different record is a stale precondition: it resolves
    // (timing only) and conflicts with the target's latest event.
    let conflict = refusal_as(
        &registry,
        &db,
        owner_like_writer(),
        "delete_record",
        json!({ "id": target, "if_previous_event_id": other_event }),
    )
    .await;
    assert!(conflict.contains("content revision conflict"), "{conflict}");
    assert!(!conflict.chars().any(|c| c.is_ascii_digit()), "{conflict}");
    db.close().await;
}

/// The writer used for the precondition tests: a member with Manage on the
/// records, so the call reaches the precondition rather than a permission
/// refusal. Not an owner, so event ids are resolved under the non-owner guard.
fn owner_like_writer() -> Caller {
    member()
}
