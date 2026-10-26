use super::*;
use crate::mcp::tools::participants::tests::{fixture, registry, ALICE, BOB};
use serde_json::json;

async fn call(db: &Db, account: &str, args: Value) -> Result<Value> {
    registry()
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_messages",
            args,
        )
        .await
}

async fn send_as(
    db: &Db,
    account: &str,
    origin: &str,
    key: &str,
    body: &str,
    recipients: &[&str],
    extra: Value,
) -> String {
    let mut args = json!({
        "action":"send","body":body,"origin":{"type":"collection","collection_id":origin},
        "addressed_to":recipients,"expectation":"none","idempotency_key":key,"reason":"fixture"
    });
    for (field, value) in extra.as_object().into_iter().flatten() {
        args[field] = value.clone();
    }
    call(db, account, args).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn delete_args(id: &str, key: &str) -> Value {
    json!({"action":"delete","message_id":id,"idempotency_key":key,"reason":"Taking it back."})
}

async fn context(db: &Db, account: &str, shared: &str) -> Value {
    call(
        db,
        account,
        json!({"action":"list_context","origin":{"type":"collection","collection_id":shared}}),
    )
    .await
    .unwrap()
}

fn listed_ids(context: &Value) -> Vec<String> {
    context["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn count(db: &Db, sql: &str, bind: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn author_delete_tombstones_hides_withdraws_and_keeps_history() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(
        &db,
        "alice",
        &shared,
        "send-1",
        "Hi Bob, secret plan",
        &[BOB],
        json!({"mentions":[{"mention_id":"m1","target_kind":"principal","target_id":BOB,"span_start":3,"span_end":6,"authored_label":"Bob"}]}),
    )
    .await;
    assert!(listed_ids(&context(&db, "bob", &shared).await).contains(&id));
    let effective =
        "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='effective'";
    assert_eq!(count(&db, effective, &id).await, 1, "mention candidate");

    let receipt = call(&db, "alice", delete_args(&id, "del-1")).await.unwrap();
    assert_eq!(receipt["status"], "deleted");
    assert_eq!(receipt["message_id"], id.as_str());
    assert!(receipt["deleted_at"].is_string(), "{receipt}");

    // Gone from every reader, for the author and for the recipient.
    for account in ["alice", "bob"] {
        assert!(!listed_ids(&context(&db, account, &shared).await).contains(&id));
        let error = call(
            &db,
            account,
            json!({"action":"list_message_state","message_ids":[id]}),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("does not exist"), "{error}");
        assert_eq!(
            call(&db, account, json!({"action":"list_unclassified"}))
                .await
                .unwrap()["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["id"] == id.as_str())
                .count(),
            0
        );
    }
    assert_eq!(
        call(&db, "bob", json!({"action":"get_attention"}))
            .await
            .unwrap()["has_new_messages"],
        false
    );

    // Notification candidates are withdrawn, not left effective.
    assert_eq!(count(&db, effective, &id).await, 0);
    assert!(count(&db, "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='withdrawn'", &id).await >= 1);

    // A reaction on the deleted message is refused.
    let error = call(
        &db,
        "bob",
        json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"react-1","reason":"fixture"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("does not exist"), "{error}");

    // The content is not erased: the row keeps its body and the log keeps the
    // creation event and the deletion with its reason.
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NOT NULL AND body='Hi Bob, secret plan'", &id).await,
        1
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.created' AND payload LIKE '%secret plan%'", &id).await,
        1
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.deleted' AND payload LIKE '%Taking it back.%'", &id).await,
        1
    );
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn only_the_author_can_delete_including_persona_messages() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let plain = send_as(
        &db,
        "alice",
        &shared,
        "plain",
        "plain note",
        &[BOB],
        json!({}),
    )
    .await;
    // Bob can see and Edit the message through the shared folder; that is not
    // authorship.
    let error = call(&db, "bob", delete_args(&plain, "bob-del"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("only the author"), "{error}");
    // An account with no access learns nothing about it.
    let error = call(&db, "mallory", delete_args(&plain, "mallory-del"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not exist"), "{error}");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL",
            &plain
        )
        .await,
        1
    );

    let persona = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            json!({"action":"register_persona","name":"Chief","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"}),
        )
        .await
        .unwrap()["persona_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let spoken = send_as(
        &db,
        "alice",
        &shared,
        "persona",
        "as the chief",
        &[BOB],
        json!({"speaker":{"persona_id":persona}}),
    )
    .await;
    let error = call(&db, "bob", delete_args(&spoken, "bob-del-2"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sent as a persona"), "{error}");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL",
            &spoken
        )
        .await,
        1
    );
    // Bob's own message is not Alice's to delete either, whatever her rights.
    let bobs = send_as(&db, "bob", &shared, "bobs", "from bob", &[ALICE], json!({})).await;
    let error = call(&db, "alice", delete_args(&bobs, "alice-del"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("only the author"), "{error}");
    // The persona's owner is its sender and may delete it.
    call(&db, "alice", delete_args(&spoken, "alice-del-2"))
        .await
        .unwrap();
    call(&db, "bob", delete_args(&bobs, "bob-del-3"))
        .await
        .unwrap();
    db.close().await;
}

#[tokio::test]
async fn delete_is_keyed_replays_and_refuses_a_second_delete_plainly() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(&db, "alice", &shared, "s", "oops", &[BOB], json!({})).await;
    let other = send_as(&db, "alice", &shared, "s2", "other", &[BOB], json!({})).await;
    let first = call(&db, "alice", delete_args(&id, "del")).await.unwrap();
    let deletions =
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.deleted'";
    // Same key, same intent: the first receipt again, nothing new written.
    let replay = call(&db, "alice", delete_args(&id, "del")).await.unwrap();
    assert_eq!(replay, first);
    assert_eq!(count(&db, deletions, &id).await, 1);
    // The key cannot be reused for a different message.
    let error = call(&db, "alice", delete_args(&other, "del"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("idempotency"), "{error}");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL",
            &other
        )
        .await,
        1
    );
    // A fresh key on an already-deleted message is a clear refusal to its author
    // and indistinguishable from missing to anyone else.
    let error = call(&db, "alice", delete_args(&id, "again"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("already deleted"), "{error}");
    let error = call(&db, "bob", delete_args(&id, "again-bob"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not exist"), "{error}");
    assert_eq!(count(&db, deletions, &id).await, 1);
    // Blank reason and blank key are refused rather than ignored.
    let mut blank = delete_args(&other, "k");
    blank["reason"] = json!("  ");
    assert!(call(&db, "alice", blank).await.is_err());
    assert!(call(&db, "alice", delete_args(&other, "  ")).await.is_err());
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL",
            &other
        )
        .await,
        1
    );
    db.close().await;
}

#[tokio::test]
async fn deleted_parent_with_live_replies_is_a_bodyless_stub_and_a_childless_one_vanishes() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let parent = send_as(&db, "alice", &shared, "p", "parent text", &[BOB], json!({})).await;
    let childless = send_as(
        &db,
        "alice",
        &shared,
        "c",
        "childless text",
        &[BOB],
        json!({}),
    )
    .await;
    let reply = send_as(
        &db,
        "bob",
        &shared,
        "r",
        "bob replies",
        &[ALICE],
        json!({"links":[{"target_id":parent,"relationship":"reply_to"}]}),
    )
    .await;
    let before = context(&db, "bob", &shared).await;
    assert_eq!(before["deleted_parents"], json!([]));
    call(&db, "alice", delete_args(&parent, "dp"))
        .await
        .unwrap();
    call(&db, "alice", delete_args(&childless, "dc"))
        .await
        .unwrap();
    for account in ["alice", "bob"] {
        let after = context(&db, account, &shared).await;
        let ids = listed_ids(&after);
        assert_eq!(ids, vec![reply.clone()], "only the live reply is listed");
        assert_eq!(after["messages"][0]["reply_to_ids"], json!([parent]));
        assert_eq!(
            after["deleted_parents"].as_array().unwrap().len(),
            1,
            "{after}"
        );
        let stub = &after["deleted_parents"][0];
        assert_eq!(stub["id"], parent.as_str());
        assert_eq!(stub["deleted"], true);
        assert!(stub["body"].is_null());
        assert!(stub["deleted_at"].is_string());
        assert_eq!(
            stub.as_object().unwrap().len(),
            5,
            "no name, author or audience: {stub}"
        );
        let text = after.to_string();
        assert!(!text.contains("parent text") && !text.contains("childless text"));
        assert!(!text.contains(&childless));
    }
    db.close().await;
}

#[tokio::test]
async fn direct_message_author_can_delete_and_the_view_only_recipient_cannot() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let dm = call(
        &db,
        "alice",
        json!({"action":"send","body":"just between us","origin":{"type":"direct","participant_ids":[ALICE,BOB]},
               "addressed_to":[BOB],"expectation":"none","idempotency_key":"dm","reason":"fixture"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The recipient reads it with View only: refused, and the message stays.
    assert!(call(&db, "bob", delete_args(&dm, "bob-dm")).await.is_err());
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL",
            &dm
        )
        .await,
        1
    );
    // The author's Edit comes from owning the Message, not from a grant.
    call(&db, "alice", delete_args(&dm, "alice-dm"))
        .await
        .unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NOT NULL",
            &dm
        )
        .await,
        1
    );
    db.close().await;
}

async fn sql(db: &Db, account: &str, sql: &str) -> Vec<Value> {
    crate::query::sql::query_sql(
        db,
        &crate::query::principal::QueryPrincipal::authenticated(account, true),
        sql,
    )
    .await
    .unwrap()
    .rows
}

#[tokio::test]
async fn deleted_messages_relation_names_only_deleted_reply_parents_the_caller_can_reach() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let parent = send_as(&db, "alice", &shared, "p", "parent text", &[BOB], json!({})).await;
    let childless = send_as(
        &db,
        "alice",
        &shared,
        "c",
        "childless text",
        &[BOB],
        json!({}),
    )
    .await;
    let live_parent = send_as(&db, "alice", &shared, "l", "still here", &[BOB], json!({})).await;
    let reply = send_as(
        &db,
        "bob",
        &shared,
        "r",
        "bob replies",
        &[ALICE],
        json!({"links":[{"target_id":parent,"relationship":"reply_to"}]}),
    )
    .await;
    send_as(
        &db,
        "bob",
        &shared,
        "r2",
        "bob replies again",
        &[ALICE],
        json!({"links":[{"target_id":live_parent,"relationship":"reply_to"}]}),
    )
    .await;
    let deleted =
        "SELECT message_id, reply_id, deleted_at, deleted_at_ms FROM deleted_messages ORDER BY message_id, reply_id";
    assert!(
        sql(&db, "bob", deleted).await.is_empty(),
        "nothing deleted yet"
    );

    call(&db, "alice", delete_args(&parent, "dp"))
        .await
        .unwrap();
    call(&db, "alice", delete_args(&childless, "dc"))
        .await
        .unwrap();
    for account in ["alice", "bob"] {
        let rows = sql(&db, account, deleted).await;
        assert_eq!(
            rows.len(),
            1,
            "{account}: only the parent a live reply points at: {rows:?}"
        );
        assert_eq!(rows[0]["message_id"], parent.as_str());
        assert_eq!(rows[0]["reply_id"], reply.as_str());
        assert!(rows[0]["deleted_at"].is_string());
        assert!(rows[0]["deleted_at_ms"].as_i64().unwrap() > 0);
        // The parent is gone from `records` and `links` loses the reply's row,
        // so only `deleted_messages` says the reply was a reply to a deleted one.
        assert!(sql(
            &db,
            account,
            &format!("SELECT id FROM records WHERE id IN ('{parent}','{childless}')")
        )
        .await
        .is_empty());
        assert!(sql(
            &db,
            account,
            &format!("SELECT 1 FROM links WHERE source_id='{reply}' AND relationship='reply_to'")
        )
        .await
        .is_empty());
        let joined = sql(&db, account, &format!(
            "SELECT r.id, d.message_id FROM records r JOIN deleted_messages d ON d.reply_id=r.id WHERE r.id='{reply}'")).await;
        assert_eq!(
            joined.len(),
            1,
            "{account}: the reader can confirm the deletion"
        );
    }
    // An account that cannot see the reply learns nothing.
    assert!(sql(&db, "mallory", deleted).await.is_empty());
    // Once the only reply is deleted too, the parent stops being named.
    call(&db, "bob", delete_args(&reply, "dr")).await.unwrap();
    assert!(sql(&db, "alice", deleted).await.is_empty());
    db.close().await;
}

// ---------------------------------------------------------------------------
// edit
// ---------------------------------------------------------------------------

fn edit_args(id: &str, body: &str, key: &str) -> Value {
    json!({"action":"edit","message_id":id,"body":body,"idempotency_key":key,"reason":"Fixing a typo."})
}

fn mention_of_bob(body_start: usize) -> Value {
    json!({"mention_id":"m1","target_kind":"principal","target_id":BOB,
           "span_start":body_start,"span_end":body_start + 3,"authored_label":"Bob"})
}

async fn send_with_bob_mention(db: &Db, shared: &str, key: &str) -> String {
    send_as(
        db,
        "alice",
        shared,
        key,
        "Hi Bob, original",
        &[BOB],
        json!({"mentions":[mention_of_bob(3)]}),
    )
    .await
}

#[tokio::test]
async fn author_edit_replaces_the_text_keeps_history_and_shows_as_edited_through_sql() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_with_bob_mention(&db, &shared, "send-1").await;
    let awareness_before = count(
        &db,
        "SELECT COUNT(*) FROM human_message_awareness WHERE message_id=?",
        &id,
    )
    .await;
    let candidate_events = "SELECT COUNT(*) FROM notification_candidate_events WHERE message_id=?";
    let candidates_before = count(&db, candidate_events, &id).await;
    assert!(candidates_before >= 1);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='message.revision.recorded.v1'", &id).await, 0);

    let receipt = call(
        &db,
        "alice",
        edit_args(&id, "Hi Bob, revised text", "edit-1"),
    )
    .await
    .unwrap();
    assert_eq!(receipt["status"], "edited");
    assert_eq!(receipt["message_id"], id.as_str());
    assert_eq!(receipt["edit_count"], 1);
    assert!(receipt["edited_at"].is_string(), "{receipt}");

    // Everyone sees the new text, through the tool and through SQL.
    for account in ["alice", "bob"] {
        let listed = context(&db, account, &shared).await;
        assert_eq!(
            listed["messages"][0]["body"], "Hi Bob, revised text",
            "{account}: {listed}"
        );
        let rows = sql(
            &db,
            account,
            &format!("SELECT body FROM records WHERE id='{id}'"),
        )
        .await;
        assert_eq!(rows[0]["body"], "Hi Bob, revised text");
        // The cheap "(edited)" marker the app reads: edit events in content_events.
        let marker = sql(
            &db,
            account,
            &format!(
                "SELECT count(*) AS edit_count, max(created_at_ms) AS edited_at_ms
               FROM content_events WHERE record_id='{id}' AND type='message.revision.recorded.v1'"
            ),
        )
        .await;
        assert_eq!(marker[0]["edit_count"], 1);
        assert!(marker[0]["edited_at_ms"].as_i64().unwrap() > 0);
    }
    // An unedited message has no marker.
    let other = send_as(
        &db,
        "alice",
        &shared,
        "o",
        "never edited",
        &[BOB],
        json!({}),
    )
    .await;
    let marker = sql(&db, "bob", &format!(
        "SELECT count(*) AS n FROM content_events WHERE record_id='{other}' AND type='message.revision.recorded.v1'")).await;
    assert_eq!(marker[0]["n"], 0);

    // Every earlier version stays recoverable from the log.
    let events: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT seq,type,payload FROM content_events WHERE record_id=? AND type IN ('record.created','message.revision.recorded.v1') ORDER BY seq",
    )
    .bind(&id)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(events.len(), 2);
    assert!(events[0].2.contains("Hi Bob, original"));
    assert!(events[1].2.contains("Hi Bob, revised text") && events[1].2.contains("Fixing a typo."));
    let at = |seq| crate::record_body::body_at_seq_in_pool(db.pool(), &id, seq);
    assert_eq!(at(events[0].0).await.unwrap().unwrap(), b"Hi Bob, original");
    assert_eq!(
        at(events[1].0).await.unwrap().unwrap(),
        b"Hi Bob, revised text"
    );

    // No new alert, no change to anyone's awareness.
    assert_eq!(count(&db, candidate_events, &id).await, candidates_before);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM human_message_awareness WHERE message_id=?",
            &id
        )
        .await,
        awareness_before
    );
    // The mention survives because its span still reads "Bob".
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM message_mentions WHERE message_id=? AND effective=1",
            &id
        )
        .await,
        1
    );
    assert_eq!(count(&db, "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='effective'", &id).await, 1);

    // A second edit counts up; the marker counts both.
    let second = call(
        &db,
        "alice",
        edit_args(&id, "Hi Bob, revised again", "edit-2"),
    )
    .await
    .unwrap();
    assert_eq!(second["edit_count"], 2);
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn edit_refuses_non_authors_persona_messages_deleted_blank_and_unchanged() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(&db, "alice", &shared, "s", "original", &[BOB], json!({})).await;
    let body_of = |d: Db, id: String| async move {
        sqlx::query_scalar::<_, String>("SELECT body FROM records WHERE id=?")
            .bind(id)
            .fetch_one(d.write_pool())
            .await
            .unwrap()
    };

    // Bob can edit the shared folder but is not the author; mallory sees nothing.
    let error = call(&db, "bob", edit_args(&id, "hijacked", "b1"))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("only the author can edit"),
        "{error}"
    );
    let error = call(&db, "mallory", edit_args(&id, "hijacked", "m1"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not exist"), "{error}");
    assert_eq!(body_of(db.clone(), id.clone()).await, "original");

    // Persona messages: the owner may edit, anyone else is refused.
    let persona = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            json!({"action":"register_persona","name":"Chief","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"}),
        )
        .await
        .unwrap()["persona_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let spoken = send_as(
        &db,
        "alice",
        &shared,
        "p",
        "as chief",
        &[BOB],
        json!({"speaker":{"persona_id":persona}}),
    )
    .await;
    let error = call(&db, "bob", edit_args(&spoken, "hijacked", "b2"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sent as a persona"), "{error}");
    call(
        &db,
        "alice",
        edit_args(&spoken, "as chief, corrected", "a-persona"),
    )
    .await
    .unwrap();

    // A view-only DM recipient cannot edit; the author can.
    let dm = call(
        &db, "alice",
        json!({"action":"send","body":"just us","origin":{"type":"direct","participant_ids":[ALICE,BOB]},
               "addressed_to":[BOB],"expectation":"none","idempotency_key":"dm","reason":"fixture"}),
    )
    .await
    .unwrap()["id"].as_str().unwrap().to_owned();
    assert!(call(&db, "bob", edit_args(&dm, "hijacked", "b3"))
        .await
        .is_err());
    call(&db, "alice", edit_args(&dm, "just us, edited", "a-dm"))
        .await
        .unwrap();

    // Blank and unchanged bodies are refused, and so is a blank reason.
    let error = call(&db, "alice", edit_args(&id, "   ", "k-blank"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("blank"), "{error}");
    let error = call(&db, "alice", edit_args(&id, "original", "k-unchanged"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unchanged"), "{error}");
    let mut no_reason = edit_args(&id, "new", "k-reason");
    no_reason["reason"] = json!(" ");
    assert!(call(&db, "alice", no_reason).await.is_err());
    // Past the shared body limit the projector refuses it and nothing changes.
    let huge = "x".repeat(crate::body_blocks::MAX_PROJECTED_BODY_BYTES + 1);
    assert!(call(&db, "alice", edit_args(&id, &huge, "k-huge"))
        .await
        .is_err());
    assert_eq!(body_of(db.clone(), id.clone()).await, "original");
    let revisions = "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='message.revision.recorded.v1'";
    assert_eq!(count(&db, revisions, &id).await, 0);

    // Deleted: refused by name to the author, as missing to anyone else, and
    // a replay of an edit that already happened still returns its receipt.
    let first = call(&db, "alice", edit_args(&id, "edited once", "k-once"))
        .await
        .unwrap();
    call(&db, "alice", delete_args(&id, "del")).await.unwrap();
    let error = call(&db, "alice", edit_args(&id, "after delete", "k-late"))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("deleted and cannot be edited"),
        "{error}"
    );
    let error = call(&db, "bob", edit_args(&id, "after delete", "k-late-bob"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not exist"), "{error}");
    assert_eq!(
        call(&db, "alice", edit_args(&id, "edited once", "k-once"))
            .await
            .unwrap(),
        first
    );
    assert_eq!(count(&db, revisions, &id).await, 1);
    db.close().await;
}

#[tokio::test]
async fn edit_is_keyed_and_replays_without_writing() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(&db, "alice", &shared, "s", "original", &[BOB], json!({})).await;
    let revisions = "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='message.revision.recorded.v1'";
    let first = call(&db, "alice", edit_args(&id, "edited", "e"))
        .await
        .unwrap();
    let replay = call(&db, "alice", edit_args(&id, "edited", "e"))
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(count(&db, revisions, &id).await, 1);
    // The same key with a different body is a conflict, not a second edit.
    let error = call(&db, "alice", edit_args(&id, "something else", "e"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("idempotency"), "{error}");
    assert_eq!(count(&db, revisions, &id).await, 1);
    // A different key carrying the now-current body is the unchanged refusal.
    assert!(call(&db, "alice", edit_args(&id, "edited", "e2"))
        .await
        .is_err());
    db.close().await;
}

#[tokio::test]
async fn edit_keeps_mention_spans_honest_and_never_adds_an_alert() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let effective =
        "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='effective'";
    let live_mentions = "SELECT COUNT(*) FROM message_mentions WHERE message_id=? AND effective=1";

    // Omitted mentions: kept only while the span still reads the same label.
    let kept = send_with_bob_mention(&db, &shared, "k").await;
    call(&db, "alice", edit_args(&kept, "Hi Bob, same spot", "ek"))
        .await
        .unwrap();
    assert_eq!(count(&db, live_mentions, &kept).await, 1);
    assert_eq!(count(&db, effective, &kept).await, 1);

    // Omitted mentions follow their label when text moves; one whose label is
    // gone is retired with its alert.
    let moved = send_with_bob_mention(&db, &shared, "m").await;
    assert_eq!(count(&db, effective, &moved).await, 1);
    call(&db, "alice", edit_args(&moved, "Dear Bob, shifted", "em"))
        .await
        .unwrap();
    assert_eq!(
        count(&db, live_mentions, &moved).await,
        1,
        "relocated, not dropped"
    );
    assert_eq!(count(&db, effective, &moved).await, 1, "and still alerting");
    let gone = send_with_bob_mention(&db, &shared, "v").await;
    call(&db, "alice", edit_args(&gone, "Dear friend, shifted", "ev"))
        .await
        .unwrap();
    assert_eq!(
        count(&db, live_mentions, &gone).await,
        0,
        "stale span must not survive"
    );
    assert_eq!(
        count(&db, effective, &gone).await,
        0,
        "retired mention withdraws its candidate"
    );
    assert!(
        count(
            &db,
            "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='withdrawn'",
            &gone
        )
        .await
            >= 1
    );

    // Supplied mentions re-span the same person against the new text.
    let respan = send_with_bob_mention(&db, &shared, "r").await;
    call(
        &db, "alice",
        json!({"action":"edit","message_id":respan,"body":"Dear Bob, shifted","mentions":[mention_of_bob(5)],
               "idempotency_key":"er","reason":"Re-span."}),
    )
    .await
    .unwrap();
    let rows: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT span_start,span_end,authored_label FROM message_mentions WHERE message_id=? AND effective=1",
    )
    .bind(&respan)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(rows, vec![(5, 8, "Bob".to_owned())]);
    assert_eq!(
        count(&db, effective, &respan).await,
        1,
        "still mentioned, still one candidate"
    );

    // A span that does not read its label, or a person not already mentioned, is refused.
    let guard = send_with_bob_mention(&db, &shared, "g").await;
    let wrong = call(
        &db, "alice",
        json!({"action":"edit","message_id":guard,"body":"Dear Bob, shifted","mentions":[mention_of_bob(3)],
               "idempotency_key":"eg1","reason":"Bad span."}),
    )
    .await
    .unwrap_err();
    assert!(wrong.to_string().contains("span"), "{wrong}");
    let stranger = call(
        &db, "alice",
        json!({"action":"edit","message_id":guard,"body":"Dear Alice, shifted","mentions":[
            {"mention_id":"m2","target_kind":"principal","target_id":ALICE,"span_start":5,"span_end":10,"authored_label":"Alice"}],
               "idempotency_key":"eg2","reason":"New target."}),
    )
    .await
    .unwrap_err();
    assert!(
        stranger.to_string().contains("cannot add a mention"),
        "{stranger}"
    );
    assert_eq!(count(&db, live_mentions, &guard).await, 1);
    assert_eq!(count(&db, effective, &guard).await, 1);
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// review fixes
// ---------------------------------------------------------------------------

async fn tool(db: &Db, account: &str, name: &str, args: Value) -> Result<Value> {
    registry()
        .call(db.clone(), Caller::authenticated(account), name, args)
        .await
}

#[tokio::test]
async fn re_pointing_an_account_at_the_author_does_not_hand_over_authorship() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(
        &db,
        "alice",
        &shared,
        "s",
        "alice wrote this",
        &[BOB],
        json!({}),
    )
    .await;
    // Bob's canonical account is moved onto Alice's live Person with no
    // identity-layer record of it, while her own credential stays there as an
    // alias. The binding now says Bob *is* Alice, but the Message was sent by
    // the other credential and nothing audited vouches for the move.
    sqlx::query("UPDATE bindings SET is_canonical=0 WHERE record_id=? AND system='account'")
        .bind(ALICE)
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE bindings SET record_id=?,is_canonical=1 WHERE system='account' AND identifier='bob'")
        .bind(ALICE)
        .execute(db.write_pool())
        .await
        .unwrap();
    let error = call(&db, "bob", edit_args(&id, "bob rewrote it", "e"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("only the author"), "{error}");
    let error = call(&db, "bob", delete_args(&id, "d")).await.unwrap_err();
    assert!(error.to_string().contains("only the author"), "{error}");
    assert_eq!(count(&db, "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL AND body='alice wrote this'", &id).await, 1);
    db.close().await;
}

fn identity_context() -> crate::identity::MutationContext<'static> {
    crate::identity::MutationContext {
        actor: "local",
        reason: "credential migration",
        run_key: None,
        parent_key: None,
        intent: None,
        is_member: true,
        internal: true,
        source_read_authorized: false,
    }
}

#[tokio::test]
async fn a_verified_credential_migration_keeps_authorship() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let before = send_as(
        &db,
        "alice",
        &shared,
        "s1",
        "sent before the move",
        &[BOB],
        json!({}),
    )
    .await;
    let doomed = send_as(
        &db,
        "alice",
        &shared,
        "s2",
        "also before the move",
        &[BOB],
        json!({}),
    )
    .await;
    // The same Person gets a new canonical credential through the identity
    // layer; the old one is kept on her as a non-canonical alias.
    let claim = crate::identity::BindingClaim {
        system: "account".into(),
        identifier: "alice-new".into(),
    };
    let context = identity_context();
    crate::identity::add_binding(&db, &context, ALICE, &claim, false)
        .await
        .unwrap();
    crate::identity::canonicalize_binding(&db, &context, ALICE, &claim)
        .await
        .unwrap();
    assert_eq!(count(&db, "SELECT COUNT(*) FROM bindings WHERE record_id=? AND system='account' AND identifier='alice' AND is_canonical=0", ALICE).await, 1);
    // Her new credential edits and deletes what the old one sent.
    call(
        &db,
        "alice-new",
        edit_args(&before, "edited after the move", "e"),
    )
    .await
    .unwrap();
    call(&db, "alice-new", delete_args(&doomed, "d"))
        .await
        .unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND body='edited after the move'",
            &before
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NOT NULL",
            &doomed
        )
        .await,
        1
    );
    // Someone else still cannot.
    let error = call(&db, "bob", edit_args(&before, "hijacked", "b"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("only the author"), "{error}");
    db.close().await;
}

#[tokio::test]
async fn a_deleted_parent_the_caller_could_not_see_is_not_named_to_them() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    // Carol may read the channel, but the parent is later restricted to
    // Alice and Bob alone.
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![
            crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::Manage,
            ),
            crate::authorization::AllowEntry::account(
                "bob",
                crate::authorization::Capability::Edit,
            ),
            crate::authorization::AllowEntry::account(
                "carol",
                crate::authorization::Capability::View,
            ),
        ],
    )
    .await
    .unwrap();
    let parent = send_as(
        &db,
        "alice",
        &shared,
        "p",
        "private parent",
        &[BOB],
        json!({}),
    )
    .await;
    let reply = send_as(
        &db,
        "bob",
        &shared,
        "r",
        "bob replies",
        &[ALICE],
        json!({"links":[{"target_id":parent,"relationship":"reply_to"}]}),
    )
    .await;
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        &parent,
        vec![
            crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::Manage,
            ),
            crate::authorization::AllowEntry::account(
                "bob",
                crate::authorization::Capability::Edit,
            ),
        ],
    )
    .await
    .unwrap();
    call(&db, "alice", delete_args(&parent, "dp"))
        .await
        .unwrap();
    let deleted = "SELECT message_id, reply_id FROM deleted_messages";
    for account in ["alice", "bob"] {
        assert_eq!(
            sql(&db, account, deleted).await.len(),
            1,
            "{account} could see the parent"
        );
        assert_eq!(
            context(&db, account, &shared).await["deleted_parents"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    // Carol sees the reply and nothing about its private parent.
    let carol_context = context(&db, "carol", &shared).await;
    assert_eq!(listed_ids(&carol_context), vec![reply.clone()]);
    assert_eq!(carol_context["deleted_parents"], json!([]));
    assert!(
        !carol_context.to_string().contains("deleted_at\":\"2"),
        "{carol_context}"
    );
    assert!(sql(&db, "carol", deleted).await.is_empty());
    assert_eq!(
        sql(
            &db,
            "carol",
            &format!("SELECT id FROM records WHERE id='{reply}'")
        )
        .await
        .len(),
        1
    );
    db.close().await;
}

#[tokio::test]
async fn removing_a_mention_withdraws_the_candidate_recorded_for_its_original_account() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_with_bob_mention(&db, &shared, "m").await;
    let effective = "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND recipient_account_id='bob' AND status='effective'";
    assert_eq!(count(&db, effective, &id).await, 1);
    // Bob's canonical account changes after the mention was delivered.
    sqlx::query("UPDATE bindings SET identifier='bob-new' WHERE record_id=? AND system='account'")
        .bind(BOB)
        .execute(db.write_pool())
        .await
        .unwrap();
    call(&db, "alice", edit_args(&id, "Hello there, rewritten", "e"))
        .await
        .unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM message_mentions WHERE message_id=? AND effective=1",
            &id
        )
        .await,
        0
    );
    assert_eq!(
        count(&db, effective, &id).await,
        0,
        "the original account's candidate must be withdrawn"
    );
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn compact_replay_of_a_keyed_update_keeps_the_edited_body() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(&db, "alice", &shared, "s", "original", &[BOB], json!({})).await;
    call(&db, "alice", edit_args(&id, "first edit", "e1"))
        .await
        .unwrap();
    let update = json!({"id":id,"summary":"a note","idempotency_key":"u1","reason":"annotate"});
    let first = tool(&db, "alice", "update_record", update.clone())
        .await
        .unwrap();
    call(&db, "alice", edit_args(&id, "second edit", "e2"))
        .await
        .unwrap();
    let replay = tool(&db, "alice", "update_record", update).await.unwrap();
    let digest = first["body_digest"].clone();
    assert!(digest.is_string(), "{first}");
    assert_eq!(
        replay["body_digest"], digest,
        "replay must pin the body at the original write: {replay}"
    );
    let empty = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(b""))
    };
    assert!(!digest.as_str().unwrap().contains(&empty));
    db.close().await;
}

#[tokio::test]
async fn freshness_reads_the_latest_revision_of_an_edited_message() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(&db, "alice", &shared, "s", "original", &[BOB], json!({})).await;
    let created = crate::freshness::current_record_body_revision(&db, &id)
        .await
        .unwrap();
    call(&db, "alice", edit_args(&id, "edited body", "e1"))
        .await
        .unwrap();
    let revision_event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='message.revision.recorded.v1'",
    )
    .bind(&id)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let current = crate::freshness::current_record_body_revision(&db, &id)
        .await
        .unwrap();
    assert_ne!(current.revision_event_id, created.revision_event_id);
    assert_eq!(current.revision_event_id, revision_event);
    assert_ne!(current.sha256, created.sha256);
    // The revision stays addressable by its event id as an exact body reference.
    let by_id = crate::freshness::record_body_revision(&db, &id, &revision_event)
        .await
        .unwrap();
    assert_eq!(by_id, current);
    db.close().await;
}

#[tokio::test]
async fn history_reports_an_edit_as_a_body_change() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let id = send_as(&db, "alice", &shared, "s", "original", &[BOB], json!({})).await;
    call(&db, "alice", edit_args(&id, "edited body", "e1"))
        .await
        .unwrap();
    let history = tool(
        &db,
        "alice",
        "get_history",
        json!({"record_id":id,"detail":"metadata"}),
    )
    .await
    .unwrap();
    let edit = history["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "message.revision.recorded.v1")
        .unwrap_or_else(|| panic!("edit missing from history: {history}"));
    assert_eq!(edit["changed_fields"], json!(["body"]), "{edit}");
    db.close().await;
}

#[tokio::test]
async fn a_dropped_mention_withdraws_its_own_candidate_even_after_its_account_became_an_alias() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    const CAROL: &str = "ca401000-0000-4000-8000-000000000003";
    crate::store::create_record(
        &db,
        json!({"id":CAROL,"type":"Entity","kind":"person","name":"carol","home_id":crate::schema::ROOT_RECORD_ID}),
    )
    .await
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    for (system, ident) in [("account", "carol"), ("native-principal", "native/carol")] {
        crate::identity::add_binding_internal_in(
            &mut tx, "local", "fixture", CAROL, system, ident, true, &mut act,
        )
        .await
        .unwrap();
    }
    db.commit_authorization(tx).await.unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![
            crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::Manage,
            ),
            crate::authorization::AllowEntry::account(
                "bob",
                crate::authorization::Capability::Edit,
            ),
            crate::authorization::AllowEntry::account(
                "carol",
                crate::authorization::Capability::Edit,
            ),
        ],
    )
    .await
    .unwrap();
    let id = send_as(
        &db, "alice", &shared, "two", "Hi Bob and Carol", &[],
        json!({"mentions":[
            {"mention_id":"mb","target_kind":"principal","target_id":BOB,"span_start":3,"span_end":6,"authored_label":"Bob"},
            {"mention_id":"mc","target_kind":"principal","target_id":CAROL,"span_start":11,"span_end":16,"authored_label":"Carol"}]}),
    )
    .await;
    let effective = |who: &'static str| {
        let id = id.clone();
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND recipient_account_id=? AND reason='principal_mention' AND status='effective'")
                .bind(id).bind(who).fetch_one(db.write_pool()).await.unwrap()
        }
    };
    assert_eq!((effective("bob").await, effective("carol").await), (1, 1));
    // Bob's old credential is re-bound as an alias of Carol's Person.
    sqlx::query("UPDATE bindings SET record_id=?,is_canonical=0 WHERE system='account' AND identifier='bob'")
        .bind(CAROL)
        .execute(db.write_pool())
        .await
        .unwrap();
    // Drop Bob's mention, keep Carol's, re-spanned in the new text.
    call(
        &db, "alice",
        json!({"action":"edit","message_id":id,"body":"Hi Carol only","idempotency_key":"e","reason":"Drop Bob.",
               "mentions":[{"mention_id":"mc","target_kind":"principal","target_id":CAROL,"span_start":3,"span_end":8,"authored_label":"Carol"}]}),
    )
    .await
    .unwrap();
    assert_eq!(
        effective("bob").await,
        0,
        "the candidate proposed for the dropped mention is withdrawn"
    );
    assert_eq!(
        effective("carol").await,
        1,
        "the kept mention keeps its candidate"
    );
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// mention relocation when `edit` omits `mentions`
// ---------------------------------------------------------------------------

async fn live_spans(db: &Db, id: &str) -> Vec<(String, i64, i64, String)> {
    sqlx::query_as(
        "SELECT mention_id,span_start,span_end,authored_label FROM message_mentions
          WHERE message_id=? AND effective=1 ORDER BY span_start",
    )
    .bind(id)
    .fetch_all(db.write_pool())
    .await
    .unwrap()
}

/// Carol, a second mentionable person who can read the channel.
const CAROL_PERSON: &str = "ca401000-0000-4000-8000-000000000004";

async fn add_carol(db: &Db) {
    crate::store::create_record(
        db,
        json!({"id":CAROL_PERSON,"type":"Entity","kind":"person","name":"carol","home_id":crate::schema::ROOT_RECORD_ID}),
    )
    .await
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    for (system, ident) in [("account", "carol"), ("native-principal", "native/carol")] {
        crate::identity::add_binding_internal_in(
            &mut tx,
            "local",
            "fixture",
            CAROL_PERSON,
            system,
            ident,
            true,
            &mut act,
        )
        .await
        .unwrap();
    }
    db.commit_authorization(tx).await.unwrap();
    crate::authorization::replace_explicit_policy(
        db,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![
            crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::Manage,
            ),
            crate::authorization::AllowEntry::account(
                "bob",
                crate::authorization::Capability::Edit,
            ),
            crate::authorization::AllowEntry::account(
                "carol",
                crate::authorization::Capability::Edit,
            ),
        ],
    )
    .await
    .unwrap();
}

fn mention_json(id: &str, target: &str, body: &str, label: &str) -> Value {
    let start = body.find(label).unwrap();
    json!({"mention_id":id,"target_kind":"principal","target_id":target,
           "span_start":start,"span_end":start + label.len(),"authored_label":label})
}

async fn channel_post(
    db: &Db,
    shared: &str,
    key: &str,
    body: &str,
    mentions: Vec<Value>,
) -> String {
    send_as(
        db,
        "alice",
        shared,
        key,
        body,
        &[],
        json!({"mentions":mentions}),
    )
    .await
}

#[tokio::test]
async fn omitted_mentions_follow_their_label_when_text_is_inserted_before_them() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let effective =
        "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='effective'";
    // ASCII: a typo fixed ahead of the mention.
    let body = "Hi Bob, original";
    let id = channel_post(
        &db,
        &shared,
        "a",
        body,
        vec![mention_json("m1", BOB, body, "Bob")],
    )
    .await;
    call(
        &db,
        "alice",
        edit_args(&id, "Well hello there Bob, original", "ea"),
    )
    .await
    .unwrap();
    assert_eq!(
        live_spans(&db, &id).await,
        vec![("m1".to_owned(), 17, 20, "Bob".to_owned())]
    );
    assert_eq!(
        count(&db, effective, &id).await,
        1,
        "same person, still alerted once"
    );
    // Non-ASCII label, with an emoji ahead of it: spans are UTF-8 bytes.
    let body = "Hi Zoë, original";
    let id = channel_post(
        &db,
        &shared,
        "b",
        body,
        vec![mention_json("m1", BOB, body, "Zoë")],
    )
    .await;
    call(&db, "alice", edit_args(&id, "🎉 Hi Zoë, original", "eb"))
        .await
        .unwrap();
    let spans = live_spans(&db, &id).await;
    let start = "🎉 Hi ".len() as i64;
    assert_eq!(
        spans,
        vec![(
            "m1".to_owned(),
            start,
            start + "Zoë".len() as i64,
            "Zoë".to_owned()
        )]
    );
    let revised: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(&revised[spans[0].1 as usize..spans[0].2 as usize], "Zoë");
    // Removing text before it moves it back.
    call(&db, "alice", edit_args(&id, "Zoë, original", "eb2"))
        .await
        .unwrap();
    assert_eq!(live_spans(&db, &id).await[0].1, 0);
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn omitted_mentions_whose_label_is_gone_are_dropped_and_withdrawn_one_at_a_time() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    add_carol(&db).await;
    let effective = |who: &'static str, id: String, db: Db| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND recipient_account_id=? AND reason='principal_mention' AND status='effective'")
            .bind(id).bind(who).fetch_one(db.write_pool()).await.unwrap()
    };
    let body = "Bob and Carol, hello";
    let id = channel_post(
        &db,
        &shared,
        "two",
        body,
        vec![
            mention_json("mb", BOB, body, "Bob"),
            mention_json("mc", CAROL_PERSON, body, "Carol"),
        ],
    )
    .await;
    assert_eq!(
        (
            effective("bob", id.clone(), db.clone()).await,
            effective("carol", id.clone(), db.clone()).await
        ),
        (1, 1)
    );
    // Bob's label is deleted outright; Carol's moves.
    call(
        &db,
        "alice",
        edit_args(&id, "Hello again, Carol, welcome", "e1"),
    )
    .await
    .unwrap();
    let spans = live_spans(&db, &id).await;
    assert_eq!(spans.len(), 1);
    assert_eq!(
        (
            spans[0].0.as_str(),
            spans[0].1,
            spans[0].2,
            spans[0].3.as_str()
        ),
        ("mc", 13, 18, "Carol")
    );
    assert_eq!(
        effective("bob", id.clone(), db.clone()).await,
        0,
        "dropped mention withdraws its candidate"
    );
    assert_eq!(
        effective("carol", id.clone(), db.clone()).await,
        1,
        "kept mention keeps its candidate"
    );
    // Nobody is ever added: a label that merely appears does not mention anyone.
    call(
        &db,
        "alice",
        edit_args(&id, "Hello again, Carol, welcome Bob", "e2"),
    )
    .await
    .unwrap();
    assert_eq!(live_spans(&db, &id).await.len(), 1);
    assert_eq!(effective("bob", id.clone(), db.clone()).await, 0);
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn a_repeated_label_is_matched_in_order() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    add_carol(&db).await;
    // Two mentions share one label; each keeps its own target.
    let body = "Sam, Sam!";
    let first = body.find("Sam").unwrap();
    let second = body.rfind("Sam").unwrap();
    let id = channel_post(
        &db, &shared, "rep", body,
        vec![
            json!({"mention_id":"m1","target_kind":"principal","target_id":BOB,"span_start":first,"span_end":first+3,"authored_label":"Sam"}),
            json!({"mention_id":"m2","target_kind":"principal","target_id":CAROL_PERSON,"span_start":second,"span_end":second+3,"authored_label":"Sam"}),
        ],
    )
    .await;
    call(&db, "alice", edit_args(&id, ">> Sam, Sam!", "e"))
        .await
        .unwrap();
    let spans = live_spans(&db, &id).await;
    assert_eq!(
        spans,
        vec![
            ("m1".to_owned(), 3, 6, "Sam".to_owned()),
            ("m2".to_owned(), 8, 11, "Sam".to_owned()),
        ]
    );
    let targets: Vec<(String, String)> = sqlx::query_as(
        "SELECT mention_id,target_record_id FROM message_mentions WHERE message_id=? AND effective=1 ORDER BY mention_id",
    )
    .bind(&id)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        targets,
        vec![
            ("m1".to_owned(), BOB.to_owned()),
            ("m2".to_owned(), CAROL_PERSON.to_owned())
        ]
    );
    // With one occurrence left, the earlier mention takes it and the later drops.
    call(&db, "alice", edit_args(&id, "just Sam", "e2"))
        .await
        .unwrap();
    assert_eq!(
        live_spans(&db, &id).await,
        vec![("m1".to_owned(), 5, 8, "Sam".to_owned())]
    );
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// relocation rules and cutover ordering
// ---------------------------------------------------------------------------

fn mention_at(
    id: &str,
    label: &str,
    original: &str,
    nth: usize,
) -> crate::events::MessageRevisionMention {
    let start = original.match_indices(label).nth(nth).unwrap().0;
    crate::events::MessageRevisionMention {
        mention_id: id.into(),
        target_kind: "principal".into(),
        target_binding: format!("native/{id}"),
        target_record_id: format!("person-{id}"),
        span_start: start as i64,
        span_end: (start + label.len()) as i64,
        authored_label: label.into(),
    }
}

/// `(id, start, end)` of every mention that survives relocation.
fn relocated(
    original: &str,
    new_body: &str,
    mentions: &[crate::events::MessageRevisionMention],
) -> Vec<(String, usize, usize)> {
    super::relocate_mentions(Some(original), new_body, mentions)
        .into_iter()
        .map(|m| (m.mention_id, m.span_start as usize, m.span_end as usize))
        .collect()
}

#[test]
fn relocation_never_matches_inside_a_longer_word() {
    let bob = [mention_at("a", "Bob", "Hi Bob, x", 0)];
    assert!(relocated("Hi Bob, x", "Hi Bobby", &bob).is_empty());
    assert!(relocated("Hi Bob, x", "Hi Bob_2 and aBob", &bob).is_empty());
    // The standalone occurrence later in the text is the one that counts.
    assert_eq!(
        relocated("Hi Bob, x", "Hi Bobby and Bob.", &bob),
        vec![("a".into(), 13, 16)]
    );
    // Unicode-aware: letters and digits outside ASCII are word characters.
    let zoe = [mention_at("z", "Zoë", "Hi Zoë, x", 0)];
    assert!(relocated("Hi Zoë, x", "Hi Zoëy", &zoe).is_empty());
    assert!(relocated("Hi Zoë, x", "Hi Zoë1", &zoe).is_empty());
    assert!(relocated("Hi Zoë, x", "Hi éZoë", &zoe).is_empty());
    assert_eq!(
        relocated("Hi Zoë, x", "🎉 Zoë.", &zoe),
        vec![("z".into(), 5, 9)]
    );
}

#[test]
fn relocation_skips_code_spans_fences_and_urls() {
    let bob = [mention_at("a", "Bob", "Hi Bob, x", 0)];
    assert!(relocated("Hi Bob, x", "Hi `Bob`", &bob).is_empty());
    assert!(relocated("Hi Bob, x", "Hi ``a `Bob` b``", &bob).is_empty());
    assert_eq!(
        relocated("Hi Bob, x", "Hi `Bob` and Bob", &bob),
        vec![("a".into(), 13, 16)]
    );
    assert!(relocated("Hi Bob, x", "```\nBob\n```", &bob).is_empty());
    assert!(
        relocated("Hi Bob, x", "~~~rust\nlet Bob = 1;\n", &bob).is_empty(),
        "unclosed fence runs to the end"
    );
    assert_eq!(
        relocated("Hi Bob, x", "```\nBob\n```\nBob", &bob),
        vec![("a".into(), 12, 15)]
    );
    assert!(relocated("Hi Bob, x", "see https://example.com/Bob ok", &bob).is_empty());
    assert!(relocated("Hi Bob, x", "see HTTP://example.com/?u=Bob ok", &bob).is_empty());
    assert_eq!(
        relocated("Hi Bob, x", "see https://example.com/Bob then Bob", &bob),
        vec![("a".into(), 33, 36)]
    );
    // An unclosed backtick is plain text.
    assert_eq!(
        relocated("Hi Bob, x", "it's ` Bob", &bob),
        vec![("a".into(), 7, 10)]
    );
}

#[test]
fn relocation_keeps_the_at_sign_the_author_wrote() {
    // The label sat right after an '@': an unprefixed occurrence is not it.
    let at_bob = [mention_at("a", "Bob", "Hi @Bob", 0)];
    assert_eq!(
        relocated("Hi @Bob", "Bob said hi @Bob", &at_bob),
        vec![("a".into(), 13, 16)]
    );
    assert!(relocated("Hi @Bob", "Bob only", &at_bob).is_empty());
    // A label that includes the '@' carries it with it, and still must stand clear of a word.
    let with_at = [mention_at("a", "@Bob", "Hi @Bob", 0)];
    assert_eq!(
        relocated("Hi @Bob", "yo @Bob", &with_at),
        vec![("a".into(), 3, 7)]
    );
    assert!(relocated("Hi @Bob", "x@Bob", &with_at).is_empty());
    assert!(relocated("Hi @Bob", "yo Bob", &with_at).is_empty());
    // A plain label does not suddenly require one.
    let plain = [mention_at("a", "Bob", "Hi Bob", 0)];
    assert_eq!(
        relocated("Hi Bob", "yo @Bob", &plain),
        vec![("a".into(), 4, 7)]
    );
}

#[test]
fn overlapping_mentions_both_survive_relocation() {
    // 'Ann' [0,3) and 'Anna' [0,4) for different people, as send accepts them.
    let original = "Anna says hi";
    let mentions = [
        mention_at("m1", "Ann", original, 0),
        mention_at("m2", "Anna", original, 0),
    ];
    assert_eq!(
        relocated(original, "Oh Anna says hi", &mentions),
        vec![("m1".into(), 3, 6), ("m2".into(), 3, 7)]
    );
    // Non-overlapping repeats still advance past the previous match.
    let sam = "Sam, Sam!";
    let repeats = [
        mention_at("m1", "Sam", sam, 0),
        mention_at("m2", "Sam", sam, 1),
    ];
    assert_eq!(
        relocated(sam, ">> Sam, Sam!", &repeats),
        vec![("m1".into(), 3, 6), ("m2".into(), 8, 11)]
    );
}

#[tokio::test]
async fn edit_applies_the_tightened_relocation_and_overlapping_mentions_end_to_end() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    add_carol(&db).await;
    let effective =
        "SELECT COUNT(*) FROM notification_candidates WHERE message_id=? AND status='effective'";
    // 'Bob' must not relocate into 'Bobby': the mention drops with its alert.
    let body = "Hi Bob, original";
    let id = channel_post(
        &db,
        &shared,
        "a",
        body,
        vec![mention_json("m1", BOB, body, "Bob")],
    )
    .await;
    assert_eq!(count(&db, effective, &id).await, 1);
    call(&db, "alice", edit_args(&id, "Hi Bobby, original", "ea"))
        .await
        .unwrap();
    assert_eq!(live_spans(&db, &id).await, vec![]);
    assert_eq!(count(&db, effective, &id).await, 0);
    // Overlapping mentions of different people both survive an insertion.
    let original = "Anna says hi";
    let id = channel_post(
        &db, &shared, "b", original,
        vec![
            json!({"mention_id":"m1","target_kind":"principal","target_id":BOB,"span_start":0,"span_end":3,"authored_label":"Ann"}),
            json!({"mention_id":"m2","target_kind":"principal","target_id":CAROL_PERSON,"span_start":0,"span_end":4,"authored_label":"Anna"}),
        ],
    )
    .await;
    call(&db, "alice", edit_args(&id, "Oh Anna says hi", "eb"))
        .await
        .unwrap();
    assert_eq!(
        live_spans(&db, &id).await,
        vec![
            ("m1".to_owned(), 3, 6, "Ann".to_owned()),
            ("m2".to_owned(), 3, 7, "Anna".to_owned()),
        ]
    );
    assert_eq!(count(&db, effective, &id).await, 2);
    assert!(
        crate::conformance::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn a_stamped_binding_change_never_precedes_an_unstamped_proposal() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let insert = |identifier: &'static str,
                  person: &'static str,
                  act: Option<i64>,
                  at: &'static str| {
        let db = db.clone();
        async move {
            sqlx::query("INSERT INTO binding_audit(id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,created_at,act) VALUES (?,?,?,?,NULL,?,NULL,1,'local','fixture',?,?)")
                .bind(format!("audit-{identifier}-{person}-{at}"))
                .bind("add")
                .bind("account")
                .bind(identifier)
                .bind(person)
                .bind(at)
                .bind(act)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
    };
    // A pre-cutover (unstamped) binding of 'old-acct', and a stamped one of
    // 'new-acct' whose timestamp is rolled back to before the proposal.
    insert("old-acct", ALICE, None, "2020-01-01T00:00:00.000Z").await;
    insert("new-acct", BOB, Some(1_000_000), "2020-06-01T00:00:00.000Z").await;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    // Unstamped proposal (legacy), later in wall-clock time than both rows.
    let legacy = "2021-01-01T00:00:00.000Z";
    assert_eq!(
        super::account_person_at_proposal_in(&mut tx, "old-acct", None, legacy)
            .await
            .unwrap()
            .as_deref(),
        Some(ALICE),
        "an unstamped row before an unstamped proposal orders by time"
    );
    assert_eq!(
        super::account_person_at_proposal_in(&mut tx, "new-acct", None, legacy)
            .await
            .unwrap(),
        None,
        "a stamped change never precedes an unstamped proposal, whatever the clock says"
    );
    assert_eq!(
        super::account_person_at_proposal_in(&mut tx, "old-acct", None, "2019-01-01T00:00:00.000Z")
            .await
            .unwrap(),
        None,
        "two unstamped sides still order by timestamp"
    );
    // A stamped proposal: unstamped rows are pre-cutover, so they precede it
    // even with a later timestamp; stamped rows order by act.
    assert_eq!(
        super::account_person_at_proposal_in(
            &mut tx,
            "old-acct",
            Some(5),
            "2000-01-01T00:00:00.000Z"
        )
        .await
        .unwrap()
        .as_deref(),
        Some(ALICE)
    );
    assert_eq!(
        super::account_person_at_proposal_in(&mut tx, "new-acct", Some(999_999), legacy)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        super::account_person_at_proposal_in(
            &mut tx,
            "new-acct",
            Some(1_000_000),
            "1999-01-01T00:00:00.000Z"
        )
        .await
        .unwrap()
        .as_deref(),
        Some(BOB)
    );
    tx.rollback().await.unwrap();
    db.close().await;
}
