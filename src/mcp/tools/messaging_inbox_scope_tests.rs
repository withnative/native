//! `list_inbox scope:"direct"`: bounded candidate selection, truncation
//! disclosure, pagination, previews and leak-freedom (hosted route).
use super::*;
use crate::mcp::tools::participants::tests::{fixture, registry, ALICE, BOB};
use serde_json::json;

use super::inbox_identity_tests::{add_person, call, inbox, send_direct};

const CAROL: &str = "ca401000-0000-4000-8000-000000000003";

pub(crate) async fn scoped(db: &Db, account: &str, view: &str, extra: Value) -> Value {
    let mut args = json!({"action":"list_inbox","view":view,"scope":"direct","limit":200});
    for (k, v) in extra.as_object().into_iter().flatten() {
        args[k] = v.clone();
    }
    call(db, account, args).await.unwrap()
}

fn bodies(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["body"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A legacy Message: no declared communication origin. Created as a
/// sender-only draft (the only shape `create_record` allows), then given an
/// `addressed_to` audience row the way a pre-origin import leaves it.
pub(crate) async fn legacy_message(db: &Db, from: &str, body: &str, to: &[&str]) -> String {
    let id = registry()
        .call(
            db.clone(),
            Caller::authenticated(from),
            "create_record",
            json!({"type":"Message","kind":"text","body":body,"addressed_to":[],"facets":{"expectation":"none"},"reason":"fixture"}),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let status: String =
        sqlx::query_scalar("SELECT status FROM message_origin_state WHERE message_id=?")
            .bind(&id)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(status, "legacy_unknown");
    for person in to {
        sqlx::query(
            "INSERT INTO message_audiences(message_id,principal_id,source,grant_id,event_seq,created_at)
             SELECT ?,b.identifier,'addressed_to','legacy-grant',1,'2026-01-01T00:00:00Z'
               FROM bindings b WHERE b.record_id=? AND b.system='native-principal' AND b.is_canonical=1",
        )
        .bind(&id)
        .bind(person)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
    // Let the addressees read it, as a delivered pre-origin message would be.
    if !to.is_empty() {
        let mut entries = vec![AllowEntry::account(from, Capability::Manage)];
        for person in to {
            let account: String = sqlx::query_scalar(
                "SELECT identifier FROM bindings WHERE record_id=? AND system='account' AND is_canonical=1",
            )
            .bind(person)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            entries.push(AllowEntry::account(&account, Capability::View));
        }
        crate::authorization::replace_explicit_policy(db, "local", &id, entries)
            .await
            .unwrap();
    }
    id
}

#[tokio::test]
async fn direct_scope_returns_sent_received_group_and_legacy_but_not_collection_posts() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    add_person(&db, CAROL, "carol").await;
    send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "received", "none").await;
    send_direct(&db, "bob", &[ALICE, BOB], &[ALICE], "sent", "none").await;
    send_direct(&db, "alice", &[ALICE, BOB, CAROL], &[BOB], "group", "none").await;
    // Not Bob's: a DM between Alice and Carol, and a collection post.
    send_direct(&db, "alice", &[ALICE, CAROL], &[CAROL], "other-dm", "none").await;
    call(&db, "alice", json!({"action":"send","body":"channel post","origin":{"type":"collection","collection_id":shared},
        "addressed_to":[],"expectation":"none","idempotency_key":"chan","reason":"fixture"})).await.unwrap();
    legacy_message(&db, "alice", "legacy to bob", &[BOB]).await;
    legacy_message(&db, "bob", "legacy from bob", &[ALICE]).await;
    legacy_message(&db, "alice", "legacy not bob", &[]).await;

    let page = scoped(&db, "bob", "browse", json!({})).await;
    let mut got = bodies(&page);
    got.sort();
    let mut want: Vec<String> = [
        "hello group",
        "hello received",
        "hello sent",
        "legacy from bob",
        "legacy to bob",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    want.sort();
    assert_eq!(got, want, "{page}");
    assert_eq!(page["scope"], "direct");
    assert_eq!(page["truncated"], false);
    assert_eq!(page["candidate_cap"], 2000);
    assert_eq!(page["schema"], "native.message-inbox.v3");
    // Unscoped behaviour is unchanged: no scope fields, collection posts present, full bodies.
    let all = inbox(&db, "bob", "browse").await;
    assert!(all.get("scope").is_none() && all.get("truncated").is_none());
    assert!(bodies(&all).iter().any(|b| b == "channel post"));
    // Hydration and identity both ran for the scoped page.
    let group = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["body"] == "hello group")
        .unwrap();
    assert!(
        group["human"].is_object() && group["attention"].is_object(),
        "{group}"
    );
    assert_eq!(group["participant_count"], 3);
    assert_eq!(group["sender"]["person_id"], ALICE);
}

/// A Message authored in Unfiled: its collection origin is Unfiled itself.
async fn unfiled_post(db: &Db, from: &str, body: &str, to: &[&str]) {
    let expectation = if to.is_empty() { "none" } else { "reply" };
    call(db, from, json!({"action":"send","body":body,"origin":{"type":"collection","collection_id":"native:unfiled"},
        "addressed_to":to,"expectation":expectation,"idempotency_key":body,"reason":"fixture"}))
        .await
        .unwrap();
}

#[tokio::test]
async fn direct_scope_includes_the_viewers_notes_to_self_and_never_anyone_elses() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    unfiled_post(&db, "bob", "bob note", &[]).await;
    unfiled_post(&db, "alice", "alice note", &[]).await;
    // Not a note to self: addressed to someone, or filed in the collection.
    unfiled_post(&db, "bob", "bob addressed post", &[ALICE]).await;
    call(&db, "bob", json!({"action":"send","body":"bob channel post","origin":{"type":"collection","collection_id":shared},
        "addressed_to":[],"expectation":"none","idempotency_key":"bob-chan","reason":"fixture"})).await.unwrap();

    let page = scoped(&db, "bob", "browse", json!({})).await;
    assert_eq!(bodies(&page), vec!["bob note".to_string()], "{page}");
    let note = &page["items"][0];
    assert_eq!(note["conversation"], json!({"type":"self"}));
    assert_eq!(note["participant_count"], 1);
    assert_eq!(note["participants"].as_array().unwrap().len(), 1);
    assert_eq!(note["participants"][0]["person_id"], BOB);
    assert_eq!(note["participants"][0]["viewer"], true);
    assert_eq!(note["sender"]["person_id"], BOB);
    // Alice sees her own note and none of Bob's.
    let alice = scoped(&db, "alice", "browse", json!({})).await;
    assert_eq!(bodies(&alice), vec!["alice note".to_string()], "{alice}");
}

#[tokio::test]
async fn legacy_direct_items_list_their_sender_and_addressees_and_omit_hidden_ones() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    add_person(&db, CAROL, "carol").await;
    legacy_message(&db, "alice", "legacy duo", &[BOB]).await;
    legacy_message(&db, "alice", "legacy trio", &[BOB, CAROL]).await;
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        CAROL,
        vec![AllowEntry::account("carol", Capability::Manage)],
    )
    .await
    .unwrap();
    let page = scoped(&db, "bob", "browse", json!({})).await;
    let find = |body: &str| {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["body"] == body)
            .unwrap()
            .clone()
    };
    let duo = find("legacy duo");
    assert_eq!(duo["conversation"], json!({"type":"legacy"}));
    assert_eq!(duo["participant_count"], 2);
    assert_eq!(duo["participants"][0]["person_id"], BOB);
    assert_eq!(duo["participants"][0]["viewer"], true);
    assert_eq!(duo["participants"][1]["person_id"], ALICE);
    // Carol is not visible to Bob: omitted, not counted, not named.
    let trio = find("legacy trio");
    assert_eq!(trio["participant_count"], 2, "{trio}");
    let text = trio.to_string();
    assert!(!text.contains(CAROL) && !text.contains("carol"), "{text}");
}

#[tokio::test]
async fn a_legacy_message_the_viewer_sent_stays_in_scope_when_its_owner_differs() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    legacy_message(&db, "bob", "bob legacy sent", &[ALICE]).await;
    // Ownership drifted away from the sender (re-pointed, imported without
    // an owner): the sender audience row is what makes it Bob's.
    sqlx::query("UPDATE records SET owner_id=? WHERE body='bob legacy sent'")
        .bind(ALICE)
        .execute(db.write_pool())
        .await
        .unwrap();
    // An ownerless one too (imported without an owner).
    legacy_message(&db, "bob", "bob legacy ownerless", &[ALICE]).await;
    sqlx::query("UPDATE records SET owner_id=NULL WHERE body='bob legacy ownerless'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let page = scoped(&db, "bob", "browse", json!({})).await;
    let mut got = bodies(&page);
    got.sort();
    assert_eq!(
        got,
        vec![
            "bob legacy ownerless".to_string(),
            "bob legacy sent".to_string()
        ],
        "{page}"
    );
    let sent = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["body"] == "bob legacy sent")
        .unwrap();
    assert_eq!(sent["participant_count"], 2);
    assert_eq!(sent["participants"][0]["person_id"], BOB);
    assert_eq!(sent["participants"][1]["person_id"], ALICE);
}

#[tokio::test]
async fn direct_scope_truncation_is_disclosed_and_keeps_the_newest() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    for n in 0..5 {
        send_direct(
            &db,
            "alice",
            &[ALICE, BOB],
            &[BOB],
            &format!("t{n}"),
            "none",
        )
        .await;
    }
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(Some(3)));
    let page = scoped(&db, "bob", "browse", json!({})).await;
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(None));
    assert_eq!(page["truncated"], true);
    assert_eq!(page["candidate_cap"], 3);
    assert_eq!(bodies(&page), vec!["hello t4", "hello t3", "hello t2"]);
}

#[tokio::test]
async fn direct_scope_pages_are_consistent_across_pages_and_new_messages() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    for n in 0..5 {
        send_direct(
            &db,
            "alice",
            &[ALICE, BOB],
            &[BOB],
            &format!("p{n}"),
            "none",
        )
        .await;
    }
    let first = scoped(&db, "bob", "browse", json!({"limit":2})).await;
    assert_eq!(bodies(&first), vec!["hello p4", "hello p3"]);
    let snapshot = first["snapshot"].as_str().unwrap().to_owned();
    // A newer DM lands between pages; the pinned snapshot does not move.
    send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "late", "none").await;
    let second = scoped(
        &db,
        "bob",
        "browse",
        json!({"limit":2,"snapshot":snapshot,"after":first["next_after"]}),
    )
    .await;
    assert_eq!(bodies(&second), vec!["hello p2", "hello p1"]);
    assert_eq!(second["newer_available"], true);
    let third = scoped(
        &db,
        "bob",
        "browse",
        json!({"limit":2,"snapshot":snapshot,"after":second["next_after"]}),
    )
    .await;
    assert_eq!(bodies(&third), vec!["hello p0"]);
    assert_eq!(third["next_after"], Value::Null);
    // The cursor is bound to the scope: reusing it unscoped is refused.
    let err = call(
        &db,
        "bob",
        json!({"action":"list_inbox","view":"browse","limit":2,"snapshot":snapshot,"after":2}),
    )
    .await;
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("cursor_reset_required"));
}

#[tokio::test]
async fn direct_scope_leaks_nothing_about_a_hidden_participant() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    add_person(&db, CAROL, "carol").await;
    let id = send_direct(&db, "alice", &[ALICE, BOB, CAROL], &[BOB], "trio", "none").await;
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        CAROL,
        vec![AllowEntry::account("carol", Capability::Manage)],
    )
    .await
    .unwrap();
    let page = scoped(&db, "bob", "browse", json!({})).await;
    let m = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["message_id"] == id.as_str())
        .unwrap();
    assert_eq!(m["participant_count"], 2);
    let text = m.to_string();
    assert!(!text.contains(CAROL) && !text.contains("carol"), "{text}");
    assert_eq!(m["conversation"], json!({"type":"direct"}));
}

#[tokio::test]
async fn previews_default_to_360_with_scope_and_can_be_set_or_left_full() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let long = "é".repeat(400);
    call(
        &db,
        "alice",
        json!({"action":"send","body":long,"origin":{"type":"direct","participant_ids":[ALICE,BOB]},
        "addressed_to":[BOB],"expectation":"none","idempotency_key":"long","reason":"fixture"}),
    )
    .await
    .unwrap();
    let page = scoped(&db, "bob", "browse", json!({})).await;
    let m = &page["items"][0];
    assert_eq!(m["body"].as_str().unwrap().chars().count(), 360);
    assert_eq!(m["body_truncated"], true);
    let page = scoped(&db, "bob", "browse", json!({"preview_chars":5})).await;
    assert_eq!(page["items"][0]["body"], "ééééé");
    let page = scoped(&db, "bob", "browse", json!({"preview_chars":1000})).await;
    assert_eq!(page["items"][0]["body_truncated"], false);
    // Without scope or preview_chars the body is whole, as before.
    let all = inbox(&db, "bob", "browse").await;
    assert_eq!(
        all["items"][0]["body"].as_str().unwrap().chars().count(),
        400
    );
    assert!(all["items"][0].get("body_truncated").is_none());
    // Explicit preview on an unscoped inbox applies too.
    let all = call(
        &db,
        "bob",
        json!({"action":"list_inbox","view":"browse","preview_chars":10}),
    )
    .await
    .unwrap();
    assert_eq!(
        all["items"][0]["body"].as_str().unwrap().chars().count(),
        10
    );
}

#[tokio::test]
async fn scope_arguments_are_validated_and_an_unresolved_viewer_fails_closed() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    for (args, needle) in [
        (json!({"scope":"channels"}), "must be \"direct\""),
        (
            json!({"scope":"direct","conversation_id":shared}),
            "mutually exclusive",
        ),
        (json!({"preview_chars":0}), "preview_chars"),
        (json!({"preview_chars":1001}), "preview_chars"),
    ] {
        let mut full = json!({"action":"list_inbox","view":"browse"});
        for (k, v) in args.as_object().unwrap() {
            full[k] = v.clone();
        }
        let err = call(&db, "alice", full).await.unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    }
    // An account with no Person binding cannot be given an empty list by mistake.
    let err = scoped_err(&db, "stranger").await;
    assert!(err.contains("current member identity"), "{err}");
}

async fn scoped_err(db: &Db, account: &str) -> String {
    call(
        db,
        account,
        json!({"action":"list_inbox","view":"browse","scope":"direct"}),
    )
    .await
    .unwrap_err()
    .to_string()
}

#[tokio::test]
async fn scoped_needs_me_keeps_only_obligations_in_the_viewers_dms() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "ask", "reply").await;
    send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "fyi", "none").await;
    let page = scoped(&db, "bob", "needs_me", json!({})).await;
    assert_eq!(bodies(&page), vec!["hello ask"]);
    assert_eq!(page["items"][0]["obligation"]["state"], "open");
}

/// Cost evidence, on the full real query, with `ANALYZE` statistics (production
/// has them): the plan never scans `records`, `message_audiences`,
/// `message_origin_principals` or `message_origin_state`, only probes them by
/// key, and the SQLite VM step count stays flat as unrelated Messages grow
/// 100 -> 500. Unrelated legacy drafts are the case that used to flip the
/// planner into scanning `message_origin_state` once statistics existed.
/// Seed one unit of unrelated traffic for a cost workload.
async fn grow(db: &Db, shared: &str, workload: &str, n: usize) {
    let post = |from: &'static str, body: String, to: Vec<&'static str>| {
        let db = db.clone();
        let shared = shared.to_owned();
        async move {
            let expectation = if to.is_empty() { "none" } else { "reply" };
            call(&db, from, json!({"action":"send","body":body,"origin":{"type":"collection","collection_id":shared},
                "addressed_to":to,"expectation":expectation,"idempotency_key":body,"reason":"fixture"}))
                .await
                .unwrap();
        }
    };
    let draft = |n: usize| {
        let db = db.clone();
        async move {
            registry()
                .call(
                    db,
                    Caller::authenticated("alice"),
                    "create_record",
                    json!({"type":"Message","kind":"text","body":format!("draft {n}"),"addressed_to":[],
                           "facets":{"expectation":"none"},"reason":"fixture"}),
                )
                .await
                .unwrap();
        }
    };
    match workload {
        "unrelated drafts" => draft(n).await,
        "viewer addressed collection posts" => {
            post("bob", format!("bob addressed {n}"), vec![ALICE]).await
        }
        "viewer unaddressed channel posts" => post("bob", format!("bob channel {n}"), vec![]).await,
        "other users unaddressed notes" => {
            unfiled_post(db, "alice", &format!("alice note {n}"), &[]).await
        }
        _ => match n % 4 {
            0 => draft(n).await,
            1 => post("bob", format!("bob addressed {n}"), vec![ALICE]).await,
            2 => post("bob", format!("bob channel {n}"), vec![]).await,
            _ => unfiled_post(db, "alice", &format!("alice note {n}"), &[]).await,
        },
    }
}

#[tokio::test]
async fn the_real_candidate_query_stays_flat_with_statistics_as_unrelated_messages_grow() {
    use rusqlite::{Connection, OpenFlags};
    for workload in [
        "unrelated drafts",
        "viewer addressed collection posts",
        "viewer unaddressed channel posts",
        "other users unaddressed notes",
        "mixture",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.db");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        let (shared, _) = fixture(&db).await;
        for n in 0..3 {
            send_direct(
                &db,
                "alice",
                &[ALICE, BOB],
                &[BOB],
                &format!("mine{n}"),
                "none",
            )
            .await;
        }
        legacy_message(&db, "alice", "legacy to bob", &[BOB]).await;
        unfiled_post(&db, "bob", "bob note", &[]).await;
        let measure = |path: std::path::PathBuf| {
            let connection =
                Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let person = BOB;
            let params = rusqlite::params!["[\"native/bob\"]", person];
            let plan: Vec<String> = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {DIRECT_SCOPE_IDS_SQL}"))
                .unwrap()
                .query_map(params, |row| row.get::<_, String>(3))
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            let mut statement = connection.prepare(DIRECT_SCOPE_IDS_SQL).unwrap();
            let rows = statement
                .query_map(params, |row| row.get::<_, String>(0))
                .unwrap()
                .count();
            let steps = statement.get_status(rusqlite::StatementStatus::VmStep);
            (plan.join("\n"), rows, steps)
        };
        let assert_keyed = |plan: &str| {
            for table in [
                "records",
                "message_audiences",
                "message_origin_principals",
                "message_origin_state",
            ] {
                for line in plan.lines() {
                    let line = line.trim();
                    assert!(
                        !(line.starts_with(&format!("SCAN {table}"))
                            || line.starts_with("SCAN r ")
                            || line.starts_with("SCAN s ")
                            || line.starts_with("SCAN ma ")
                            || line.starts_with("SCAN mop ")),
                        "{workload}: {table} must be probed by key, not scanned:\n{plan}\n---"
                    );
                }
            }
            assert!(!plan.contains("idx_records_kind"), "{plan}");
            assert!(
                plan.contains("idx_message_origin_principals_principal"),
                "{plan}"
            );
            assert!(plan.contains("idx_records_unfiled_message_owner"), "{plan}");
            assert!(plan.contains("idx_message_audiences_principal"), "{plan}");
        };
        for n in 0..40 {
            grow(&db, &shared, workload, n).await;
        }
        sqlx::query("ANALYZE")
            .execute(db.write_pool())
            .await
            .unwrap();
        let (plan_small, rows_small, steps_small) = measure(path.clone());
        assert_keyed(&plan_small);
        for n in 40..200 {
            grow(&db, &shared, workload, n).await;
        }
        sqlx::query("ANALYZE")
            .execute(db.write_pool())
            .await
            .unwrap();
        let (plan_large, rows_large, steps_large) = measure(path.clone());
        assert_keyed(&plan_large);
        assert_eq!(
            rows_small, 5,
            "{workload}: the viewer's DMs, legacy message and note to self only"
        );
        assert_eq!(rows_large, 5, "{workload}");
        // Other people's traffic and unrelated drafts must not move the read.
        // The viewer's own sent and addressed posts do: the legacy arm visits
        // each of the viewer's audience rows (`idx_message_audiences_principal`
        // does not carry `source`), about 12 VM steps per row (bounded at 14). The note arm
        // and the viewer's authored legacy Messages come from the keyed
        // `idx_records_unfiled_message_owner` and add nothing.
        let viewer_rows_added = match workload {
            "viewer addressed collection posts" | "viewer unaddressed channel posts" => 160,
            "mixture" => 80,
            _ => 0,
        };
        let allowed = steps_small + 50 + 14 * viewer_rows_added;
        assert!(
            steps_large <= allowed,
            "{workload}: VM steps {steps_small} -> {steps_large} exceed {allowed}\n{plan_large}"
        );
    }
}

#[tokio::test]
async fn a_note_whose_principal_was_re_pointed_at_the_viewer_is_not_the_viewers_note() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    unfiled_post(&db, "alice", "alice note", &[]).await;
    let id: String = sqlx::query_scalar("SELECT id FROM records WHERE body='alice note'")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        &id,
        vec![
            AllowEntry::account("alice", Capability::Manage),
            AllowEntry::account("bob", Capability::View),
        ],
    )
    .await
    .unwrap();
    // Alice's historical principal now resolves to Bob.
    sqlx::query(
        "UPDATE bindings SET record_id=?, is_canonical=0 WHERE system='native-principal' AND identifier='native/alice'",
    )
    .bind(BOB)
    .execute(db.write_pool())
    .await
    .unwrap();
    let page = scoped(&db, "bob", "browse", json!({})).await;
    assert!(bodies(&page).is_empty(), "{page}");
    let all = inbox(&db, "bob", "browse").await;
    let item = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["body"] == "alice note")
        .unwrap();
    assert_ne!(item["conversation"]["type"], "self", "{item}");
}

#[tokio::test]
async fn an_unaddressed_channel_post_filed_into_unfiled_is_not_a_note_to_self() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    call(&db, "bob", json!({"action":"send","body":"bob channel post","origin":{"type":"collection","collection_id":shared},
        "addressed_to":[],"expectation":"none","idempotency_key":"bob-chan","reason":"fixture"})).await.unwrap();
    sqlx::query("UPDATE records SET home_id='native:unfiled' WHERE body='bob channel post'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let page = scoped(&db, "bob", "browse", json!({})).await;
    assert!(bodies(&page).is_empty(), "{page}");
    let all = inbox(&db, "bob", "browse").await;
    let item = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["body"] == "bob channel post")
        .unwrap();
    assert_eq!(item["conversation"]["type"], "collection", "{item}");
}

#[tokio::test]
async fn unreadable_newer_dms_do_not_use_the_cap_or_set_truncated() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let older: Vec<String> = {
        let mut ids = Vec::new();
        for n in 0..2 {
            ids.push(
                send_direct(
                    &db,
                    "alice",
                    &[ALICE, BOB],
                    &[BOB],
                    &format!("old{n}"),
                    "none",
                )
                .await,
            );
        }
        ids
    };
    // Five newer DMs that name Bob but that he cannot read.
    for n in 0..5 {
        let id = send_direct(
            &db,
            "alice",
            &[ALICE, BOB],
            &[BOB],
            &format!("hidden{n}"),
            "none",
        )
        .await;
        crate::authorization::replace_explicit_policy(
            &db,
            "local",
            &id,
            vec![AllowEntry::account("alice", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(Some(3)));
    let page = scoped(&db, "bob", "browse", json!({})).await;
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(None));
    assert_eq!(
        page["truncated"], false,
        "unreadable messages are not 'more': {page}"
    );
    let got: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(got.len(), 2);
    for id in &older {
        assert!(got.contains(&id.as_str()));
    }
    // With more readable messages than the cap, truncation is still disclosed.
    for n in 0..3 {
        send_direct(
            &db,
            "alice",
            &[ALICE, BOB],
            &[BOB],
            &format!("new{n}"),
            "none",
        )
        .await;
    }
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(Some(3)));
    let page = scoped(&db, "bob", "browse", json!({})).await;
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(None));
    assert_eq!(page["truncated"], true);
    assert_eq!(page["items"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn dms_under_a_retained_principal_alias_survive_a_promotion() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let before = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "before", "none").await;
    // Bob's principal A is retired as an alias and B is promoted.
    sqlx::query("UPDATE bindings SET is_canonical=0 WHERE system='native-principal' AND identifier='native/bob'")
        .execute(db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,'native-principal','native/bob-b',1)")
        .bind(BOB).execute(db.write_pool()).await.unwrap();
    let after = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "after", "none").await;
    let page = scoped(&db, "bob", "browse", json!({})).await;
    let got: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert!(
        got.contains(&before.as_str()) && got.contains(&after.as_str()),
        "{page}"
    );
    // Identity still resolves the aliased participant to the same Person.
    let old = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["message_id"] == before.as_str())
        .unwrap();
    assert_eq!(old["participant_count"], 2);
    assert_eq!(old["participants"][0]["person_id"], BOB);
    assert_eq!(old["participants"][0]["viewer"], true);
}

#[tokio::test]
async fn every_scoped_view_rehydrates_the_page_so_an_edit_between_pages_shows() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let first = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "ask1", "reply").await;
    let second = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "ask2", "reply").await;
    let page = |extra: Value| {
        let db = db.clone();
        async move { scoped(&db, "bob", "needs_me", extra).await }
    };
    let one = page(json!({"limit":1})).await;
    assert_eq!(one["items"][0]["message_id"], second.as_str());
    let snapshot = one["snapshot"].as_str().unwrap().to_owned();
    // The author edits the page-two message while the snapshot is held.
    call(
        &db,
        "alice",
        json!({"action":"edit","message_id":first,"body":"edited ask1",
        "idempotency_key":"edit-ask1","reason":"fixture"}),
    )
    .await
    .unwrap();
    let two = page(json!({"limit":1,"snapshot":snapshot,"after":one["next_after"]})).await;
    assert_eq!(two["items"][0]["message_id"], first.as_str());
    assert_eq!(two["items"][0]["body"], "edited ask1", "{two}");
}

/// A revocation and edit that land between the page's authorization check and
/// its body read must not leak the new body. Authorization, hydration and
/// identity share one read transaction (one snapshot), so the page shows what
/// the viewer was authorized for in that snapshot. Forced deterministically
/// with the page seam; needs a file database so a second connection can write
/// while the page's read snapshot is open.
#[tokio::test]
async fn a_revocation_and_edit_between_authorization_and_hydration_cannot_leak_the_new_body() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(dir.path().join("race.db").to_str().unwrap())
        .await
        .unwrap();
    fixture(&db).await;
    let id = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "secret", "reply").await;
    // Pin a snapshot first; the held page is then re-fetched with the seam armed.
    let first = scoped(&db, "bob", "needs_me", json!({"limit": 1})).await;
    let snapshot = first["snapshot"].as_str().unwrap().to_owned();
    assert_eq!(first["items"][0]["body"], "hello secret");

    let seam_db = db.clone();
    let seam_id = id.clone();
    let seam: PageSeam = std::sync::Arc::new(move || {
        let db = seam_db.clone();
        let id = seam_id.clone();
        Box::pin(async move {
            crate::authorization::replace_explicit_policy(
                &db,
                "local",
                &id,
                vec![AllowEntry::account("alice", Capability::Manage)],
            )
            .await
            .unwrap();
            call(
                &db,
                "alice",
                json!({"action":"edit","message_id":id,"body":"SECRET v2",
                "idempotency_key":"race-edit","reason":"fixture"}),
            )
            .await
            .unwrap();
        })
    });
    INBOX_PAGE_SEAM.with(|s| *s.borrow_mut() = Some(seam));
    let racing = scoped(
        &db,
        "bob",
        "needs_me",
        json!({"limit":1,"snapshot":snapshot,"after":0}),
    )
    .await;
    INBOX_PAGE_SEAM.with(|s| *s.borrow_mut() = None);
    let text = racing.to_string();
    assert!(
        !text.contains("SECRET v2"),
        "the edit must not be visible to a revoked viewer: {text}"
    );
    // The next fetch sees the revocation and drops the message.
    let after = scoped(
        &db,
        "bob",
        "needs_me",
        json!({"limit":1,"snapshot":snapshot,"after":0}),
    )
    .await;
    assert_eq!(after["items"], json!([]));
    assert!(!after.to_string().contains("SECRET v2"));
}

/// Unreadable candidates fill more than one 500-item visibility batch: the
/// readable older DMs sit in the second batch and must still be found, and
/// `truncated` must stay false.
#[tokio::test]
async fn unreadable_candidates_spanning_a_batch_boundary_do_not_hide_older_readable_dms() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let older: Vec<String> = {
        let mut ids = Vec::new();
        for n in 0..2 {
            ids.push(
                send_direct(
                    &db,
                    "alice",
                    &[ALICE, BOB],
                    &[BOB],
                    &format!("old{n}"),
                    "none",
                )
                .await,
            );
        }
        ids
    };
    for n in 0..505 {
        let id = send_direct(
            &db,
            "alice",
            &[ALICE, BOB],
            &[BOB],
            &format!("h{n}"),
            "none",
        )
        .await;
        crate::authorization::replace_explicit_policy(
            &db,
            "local",
            &id,
            vec![AllowEntry::account("alice", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(Some(3)));
    let page = scoped(&db, "bob", "browse", json!({})).await;
    DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(None));
    assert_eq!(page["truncated"], false, "{}", page["truncated"]);
    let got: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(got.len(), 2);
    for id in &older {
        assert!(got.contains(&id.as_str()));
    }
}
