//! `list_inbox` identity disclosure (`native.message-inbox.v3`): sender,
//! participants, reply_to_id and conversation, as seen by each viewer.
use super::*;
use crate::mcp::tools::participants::tests::{fixture, registry, ALICE, BOB};
use serde_json::json;

const CAROL: &str = "ca401000-0000-4000-8000-000000000003";

pub(crate) async fn call(db: &Db, account: &str, args: Value) -> Result<Value> {
    registry()
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_messages",
            args,
        )
        .await
}

/// A Person with an account and a native principal binding, like the fixture's.
pub(crate) async fn add_person(db: &Db, id: &str, account: &str) {
    add_named_person(db, id, account, account).await
}

pub(crate) async fn add_named_person(db: &Db, id: &str, account: &str, name: &str) {
    crate::store::create_record(
        db,
        json!({"id":id,"type":"Entity","kind":"person","name":name,"home_id":crate::schema::ROOT_RECORD_ID}),
    )
    .await
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    for (system, ident) in [
        ("account", account.to_owned()),
        ("native-principal", format!("native/{account}")),
    ] {
        crate::identity::add_binding_internal_in(
            &mut tx,
            "local",
            "fixture identity",
            id,
            system,
            &ident,
            true,
            &mut act,
        )
        .await
        .unwrap();
    }
    db.commit_authorization(tx).await.unwrap();
}

pub(crate) async fn send_direct(
    db: &Db,
    from: &str,
    people: &[&str],
    to: &[&str],
    key: &str,
    expectation: &str,
) -> String {
    call(
        db,
        from,
        json!({"action":"send","body":format!("hello {key}"),
               "origin":{"type":"direct","participant_ids":people},
               "addressed_to":to,"expectation":expectation,"idempotency_key":key,"reason":"fixture"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub(crate) async fn inbox(db: &Db, account: &str, view: &str) -> Value {
    call(
        db,
        account,
        json!({"action":"list_inbox","view":view,"limit":200}),
    )
    .await
    .unwrap()
}

fn item<'a>(inbox: &'a Value, id: &str) -> &'a Value {
    inbox["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["message_id"] == id)
        .unwrap_or_else(|| panic!("{id} missing from {inbox}"))
}

#[tokio::test]
async fn the_inbox_serves_the_v3_schema_string() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let page = inbox(&db, "alice", "browse").await;
    assert_eq!(page["schema"], "native.message-inbox.v3");
}

#[tokio::test]
async fn direct_items_carry_sender_participants_and_conversation_on_browse_and_needs_me() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let id = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "dm-1", "reply").await;

    for view in ["browse", "needs_me"] {
        let page = inbox(&db, "bob", view).await;
        let m = item(&page, &id);
        assert_eq!(m["sender"]["person_id"], ALICE, "{view}");
        assert_eq!(m["sender"]["name"], "alice");
        assert_eq!(m["sender"]["viewer"], false);
        assert_eq!(m["sender"]["state"], "person");
        assert_eq!(m["participant_count"], 2);
        let people = m["participants"].as_array().unwrap();
        assert_eq!(people.len(), 2);
        // The viewer's own slot comes first.
        assert_eq!(people[0]["person_id"], BOB);
        assert_eq!(people[0]["viewer"], true);
        assert_eq!(people[1]["person_id"], ALICE);
        assert_eq!(m["reply_to_id"], Value::Null);
        // A direct context has no key in this version.
        assert_eq!(m["conversation"], json!({"type": "direct"}));
        // No account string leaks anywhere on the item.
        assert!(!m.to_string().contains("native/alice"), "{m}");
    }
}

#[tokio::test]
async fn browse_includes_the_viewers_own_sent_messages_with_viewer_true_sender() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let id = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "dm-sent", "none").await;
    let page = inbox(&db, "alice", "browse").await;
    let m = item(&page, &id);
    assert_eq!(m["sender"]["viewer"], true);
    assert_eq!(m["sender"]["person_id"], ALICE);
    assert_eq!(m["attention"]["unread"], false);
    // needs_me is for obligations on the viewer: a sent Message is not one.
    let needs = inbox(&db, "alice", "needs_me").await;
    assert!(!needs["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["message_id"] == id));
}

#[tokio::test]
async fn collection_messages_have_no_participants_and_a_collection_key_and_reply_to_id() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let send = |from: &'static str, key: &'static str, reply: Option<String>| {
        let db = db.clone();
        let shared = shared.clone();
        async move {
            let mut args = json!({"action":"send","body":key,"origin":{"type":"collection","collection_id":shared},
                "addressed_to":[],"expectation":"none","idempotency_key":key,"reason":"fixture"});
            if let Some(target) = reply {
                args["links"] = json!([{"target_id":target,"relationship":"reply_to"}]);
            }
            call(&db, from, args).await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let root = send("alice", "root-post", None).await;
    let reply = send("bob", "reply-post", Some(root.clone())).await;
    let page = inbox(&db, "alice", "browse").await;
    let m = item(&page, &reply);
    assert_eq!(m["reply_to_id"], root.as_str());
    assert_eq!(m["participants"], json!([]));
    assert_eq!(m["participant_count"], 0);
    assert_eq!(m["conversation"]["type"], "collection");
    assert_eq!(m["conversation"]["key"], format!("collection:{shared}"));
    assert_eq!(m["sender"]["person_id"], BOB);
    assert_eq!(item(&page, &root)["reply_to_id"], Value::Null);
}

#[tokio::test]
async fn reply_to_id_is_null_when_the_target_is_hidden_from_the_viewer() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let send = |from: &'static str, key: &'static str, reply: Option<String>| {
        let db = db.clone();
        let shared = shared.clone();
        async move {
            let mut args = json!({"action":"send","body":key,"origin":{"type":"collection","collection_id":shared},
                "addressed_to":[],"expectation":"none","idempotency_key":key,"reason":"fixture"});
            if let Some(target) = reply {
                args["links"] = json!([{"target_id":target,"relationship":"reply_to"}]);
            }
            call(&db, from, args).await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let root = send("alice", "hidden-root", None).await;
    let reply = send("bob", "reply-to-hidden", Some(root.clone())).await;
    // Alice withdraws the root from Bob after the reply exists.
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        &root,
        vec![AllowEntry::account("alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let bob_page = inbox(&db, "bob", "browse").await;
    assert!(!bob_page["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["message_id"] == root.as_str()));
    let m = item(&bob_page, &reply);
    assert_eq!(m["reply_to_id"], Value::Null, "{m}");
    assert!(
        !m.to_string().contains(&root),
        "hidden target id must not appear: {m}"
    );
    // Alice can still see her own root, so the reply points at it for her.
    let alice_page = inbox(&db, "alice", "browse").await;
    assert_eq!(item(&alice_page, &reply)["reply_to_id"], root.as_str());
}

#[tokio::test]
async fn an_invisible_participant_is_omitted_and_not_counted() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    add_person(&db, CAROL, "carol").await;
    let id = send_direct(
        &db,
        "alice",
        &[ALICE, BOB, CAROL],
        &[BOB],
        "dm-trio",
        "none",
    )
    .await;
    // Before Carol's Person goes private, Bob sees all three.
    let before = inbox(&db, "bob", "browse").await;
    assert_eq!(item(&before, &id)["participant_count"], 3);
    // Carol's Person record becomes private to Carol after the Message exists.
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        CAROL,
        vec![AllowEntry::account("carol", Capability::Manage)],
    )
    .await
    .unwrap();

    let page = inbox(&db, "bob", "browse").await;
    let m = item(&page, &id);
    assert_eq!(
        m["participant_count"], 2,
        "hidden members are not counted: {m}"
    );
    let people = m["participants"].as_array().unwrap();
    assert_eq!(people.len(), 2, "hidden members get no slot: {people:?}");
    assert!(people.iter().all(|p| p["state"] == "person"));
    let text = m.to_string();
    assert!(!text.contains(CAROL), "{text}");
    assert!(!text.contains("carol"), "{text}");
    assert_eq!(m["conversation"], json!({"type": "direct"}));
    // Carol herself sees her own slot first.
    let carol_page = inbox(&db, "carol", "browse").await;
    let own = item(&carol_page, &id)["participants"][0].clone();
    assert_eq!(own["viewer"], true);
    assert_eq!(own["person_id"], CAROL);
}

#[tokio::test]
async fn identity_is_resolved_per_page_under_current_authority_not_frozen_in_the_snapshot() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    add_person(&db, CAROL, "carol").await;
    let post = |from: &'static str, key: &'static str, reply: Option<String>| {
        let db = db.clone();
        let shared = shared.clone();
        async move {
            let mut args = json!({"action":"send","body":key,"origin":{"type":"collection","collection_id":shared},
                "addressed_to":[],"expectation":"none","idempotency_key":key,"reason":"fixture"});
            if let Some(target) = reply {
                args["links"] = json!([{"target_id":target,"relationship":"reply_to"}]);
            }
            call(&db, from, args).await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    // Oldest to newest: root, trio DM, reply to root, filler. Pages of one item
    // come newest first: filler, reply, trio.
    let root = post("alice", "p-root", None).await;
    let trio = send_direct(&db, "alice", &[ALICE, BOB, CAROL], &[BOB], "p-trio", "none").await;
    let reply = post("bob", "p-reply", Some(root.clone())).await;
    post("alice", "p-filler", None).await;

    let page = |after: Option<u64>, snapshot: Option<String>| {
        let db = db.clone();
        async move {
            let mut args = json!({"action":"list_inbox","view":"browse","limit":1});
            if let Some(after) = after {
                args["after"] = json!(after);
            }
            if let Some(snapshot) = snapshot {
                args["snapshot"] = json!(snapshot);
            }
            call(&db, "bob", args).await.unwrap()
        }
    };
    let first = page(None, None).await;
    assert_eq!(first["items"][0]["body"], "p-filler");
    let snapshot = first["snapshot"].as_str().unwrap().to_owned();

    // While page 1 is held, Carol's Person and the reply's target go private.
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        CAROL,
        vec![AllowEntry::account("carol", Capability::Manage)],
    )
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        &root,
        vec![AllowEntry::account("alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let second = page(first["next_after"].as_u64(), Some(snapshot.clone())).await;
    let m = item(&second, &reply);
    assert_eq!(m["reply_to_id"], Value::Null, "{m}");
    assert!(!m.to_string().contains(&root), "{m}");
    let third = page(second["next_after"].as_u64(), Some(snapshot)).await;
    let m = item(&third, &trio);
    assert_eq!(m["participant_count"], 2, "{m}");
    let text = m.to_string();
    assert!(!text.contains(CAROL) && !text.contains("carol"), "{text}");
}

#[tokio::test]
async fn a_persona_speaker_adds_kind_and_assurance_to_the_sender() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let persona = registry()
        .call(db.clone(), Caller::authenticated("alice"), "manage_participants",
            json!({"action":"register_persona","name":"Chief","home_id":crate::schema::ROOT_RECORD_ID,
                   "facets":{"colour":"blue","model_route":"operator"},"reason":"fixture"}))
        .await.unwrap()["persona_id"].as_str().unwrap().to_owned();
    let id = call(&db, "alice", json!({"action":"send","body":"spoken","speaker":{"persona_id":persona},
        "origin":{"type":"collection","collection_id":shared},"addressed_to":[],"expectation":"none",
        "idempotency_key":"spoken","reason":"fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let page = inbox(&db, "bob", "browse").await;
    let sender = &item(&page, &id)["sender"];
    assert_eq!(
        sender["speaker"],
        json!({"kind":"persona","assurance":"client_asserted"}),
        "{sender}"
    );
    assert_eq!(sender["person_id"], ALICE);
}

#[tokio::test]
async fn the_viewers_own_unreadable_person_keeps_their_slot_with_a_null_name() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let id = send_direct(&db, "alice", &[ALICE, BOB], &[BOB], "dm-own", "none").await;
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        BOB,
        vec![AllowEntry::account("alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let page = inbox(&db, "bob", "browse").await;
    let m = item(&page, &id);
    let own = &m["participants"][0];
    assert_eq!(own["viewer"], true);
    assert_eq!(own["person_id"], BOB);
    assert_eq!(own["name"], Value::Null);
    assert_eq!(m["participant_count"], 2);
}

#[tokio::test]
async fn a_group_dm_lists_at_most_eight_participants_but_counts_all_and_keeps_the_viewer() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let mut ids = vec![ALICE.to_owned(), BOB.to_owned()];
    for n in 0..9 {
        let id = format!("ca401000-0000-4000-8000-0000000001{n:02}");
        add_person(&db, &id, &format!("guest{n}")).await;
        ids.push(id);
    }
    assert_eq!(ids.len(), 11);
    let people: Vec<&str> = ids.iter().map(String::as_str).collect();
    // One addressee: a multi-recipient send is held for authority in this slice.
    let id = send_direct(&db, "alice", &people, &[BOB], "dm-big", "none").await;

    // Bob's id sorts late among the principals; the cap must not drop his slot.
    let page = inbox(&db, "bob", "browse").await;
    let m = item(&page, &id);
    assert_eq!(m["participant_count"], 11, "visible count, not capped");
    let listed = m["participants"].as_array().unwrap();
    assert_eq!(listed.len(), PARTICIPANT_CAP_FOR_TESTS);
    assert_eq!(listed[0]["viewer"], true);
    assert_eq!(listed[0]["person_id"], BOB);
}

const PARTICIPANT_CAP_FOR_TESTS: usize = 8;

#[test]
fn the_participant_cap_constant_matches_the_documented_eight() {
    assert_eq!(
        crate::awareness::INBOX_PARTICIPANT_CAP,
        PARTICIPANT_CAP_FOR_TESTS
    );
}

#[tokio::test]
async fn a_collection_key_is_given_only_to_a_viewer_who_can_see_the_collection() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = call(&db, "alice", json!({"action":"send","body":"in-room","origin":{"type":"collection","collection_id":shared},
        "addressed_to":[],"expectation":"none","idempotency_key":"in-room","reason":"fixture"}))
        .await.unwrap()["id"].as_str().unwrap().to_owned();
    // Bob keeps the Message through its own policy but loses the Collection.
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
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        &shared,
        vec![AllowEntry::account("alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let bob = inbox(&db, "bob", "browse").await;
    assert_eq!(
        item(&bob, &id)["conversation"],
        json!({"type": "collection"})
    );
    // (`home_id` is the pre-existing field naming the home; only the new key is withheld.)
    let alice = inbox(&db, "alice", "browse").await;
    assert_eq!(
        item(&alice, &id)["conversation"]["key"],
        format!("collection:{shared}")
    );
}

#[tokio::test]
async fn deleting_a_participants_person_between_pages_keeps_the_rest_consistent_and_leak_free() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    add_person(&db, CAROL, "carol").await;
    // Oldest to newest: trio DM, a post by Carol, filler. One item per page:
    // filler, carol-post, trio.
    let trio = send_direct(
        &db,
        "alice",
        &[ALICE, BOB, CAROL],
        &[BOB],
        "del-trio",
        "none",
    )
    .await;
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![
            AllowEntry::account("alice", Capability::Manage),
            AllowEntry::account("bob", Capability::Edit),
            AllowEntry::account("carol", Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let by_carol = call(&db, "carol", json!({"action":"send","body":"del-post","origin":{"type":"collection","collection_id":shared},
        "addressed_to":[],"expectation":"none","idempotency_key":"del-post","reason":"fixture"}))
        .await.unwrap()["id"].as_str().unwrap().to_owned();
    call(&db, "alice", json!({"action":"send","body":"del-filler","origin":{"type":"collection","collection_id":shared},
        "addressed_to":[],"expectation":"none","idempotency_key":"del-filler","reason":"fixture"})).await.unwrap();
    let page = |after: Option<u64>, snapshot: Option<String>| {
        let db = db.clone();
        async move {
            let mut args = json!({"action":"list_inbox","view":"browse","limit":1});
            if let Some(after) = after {
                args["after"] = json!(after);
            }
            if let Some(snapshot) = snapshot {
                args["snapshot"] = json!(snapshot);
            }
            call(&db, "bob", args).await.unwrap()
        }
    };
    let first = page(None, None).await;
    let snapshot = first["snapshot"].as_str().unwrap().to_owned();
    // Carol's Person is deleted while the snapshot is held.
    registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "delete_record",
            json!({"id": CAROL, "reason": "fixture"}),
        )
        .await
        .unwrap();
    let second = page(first["next_after"].as_u64(), Some(snapshot.clone())).await;
    let m = item(&second, &by_carol);
    assert_eq!(
        m["sender"],
        json!({"person_id": null, "name": null, "viewer": false, "state": "hidden"}),
        "{m}"
    );
    assert!(
        !m.to_string().contains(CAROL) && !m.to_string().contains("carol"),
        "{m}"
    );
    let third = page(second["next_after"].as_u64(), Some(snapshot)).await;
    let m = item(&third, &trio);
    assert_eq!(m["participant_count"], 2, "{m}");
    assert_eq!(m["participants"].as_array().unwrap().len(), 2);
    assert_eq!(m["sender"]["person_id"], ALICE);
    assert_eq!(m["conversation"], json!({"type": "direct"}));
    assert!(
        !m.to_string().contains(CAROL) && !m.to_string().contains("carol"),
        "{m}"
    );
}
