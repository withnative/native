use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::events::LinkAddedPayload;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{add_link, create_record as create_raw_record};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const SENDER_ACCOUNT: &str = "acct_origin_sender";
const READER_ACCOUNT: &str = "acct_origin_reader";
const THIRD_ACCOUNT: &str = "acct_origin_third";
const SENDER: &str = "6d310000-0000-4000-8000-000000000001";
const READER: &str = "6d310000-0000-4000-8000-000000000002";
const THIRD: &str = "6d310000-0000-4000-8000-000000000003";

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
    if args["action"] == "send" {
        args.as_object_mut().unwrap().insert(
            "reason".into(),
            json!("Exercise the explicit Message-origin contract in an integration fixture."),
        );
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
        (SENDER, "native/origin-sender", SENDER_ACCOUNT),
        (READER, "native/origin-reader", READER_ACCOUNT),
        (THIRD, "native/origin-third", THIRD_ACCOUNT),
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

async fn collection(registry: &ToolRegistry, db: &Db) -> String {
    let result = registry
        .call(
            db.clone(),
            Caller::authenticated(SENDER_ACCOUNT),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({"type":"Collection","kind":"folder","name":"Origin channel"}),
            ),
        )
        .await
        .unwrap();
    let id = result["id"].as_str().unwrap().to_owned();
    replace_explicit_policy(
        db,
        "test:origin-channel-policy",
        &id,
        vec![
            AllowEntry::account(SENDER_ACCOUNT, Capability::Edit),
            AllowEntry::account(READER_ACCOUNT, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn addressed_collection_origin_inherits_and_never_enters_the_direct_context() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection_id = collection(&registry, &db).await;
    let sent = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send",
            "body":"Please acknowledge this channel contribution.",
            "origin":{"type":"collection","collection_id":&collection_id},
            "addressed_to":[READER],
            "expectation":"ack",
            "idempotency_key":"origin-channel-addressed"
        }),
    )
    .await
    .unwrap();
    let message_id = sent["id"].as_str().unwrap();

    let explicit_policy: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM record_policies WHERE record_id=?")
            .bind(message_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        explicit_policy, 0,
        "addressing must not seal a channel contribution"
    );

    let channel = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"collection","collection_id":&collection_id}}),
    )
    .await
    .unwrap();
    assert_eq!(channel["messages"][0]["id"], message_id);
    let direct = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"direct","participant_ids":[SENDER,READER]}}),
    )
    .await
    .unwrap();
    assert_eq!(direct["messages"], json!([]));
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn exact_direct_sets_are_isolated_and_rebuild_from_content_events_alone() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let pair = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"pair","origin":{"type":"direct","participant_ids":[SENDER,READER]},
            "addressed_to":[READER],"expectation":"none","idempotency_key":"origin-pair"
        }),
    )
    .await
    .unwrap();
    let group = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"group","origin":{"type":"direct","participant_ids":[THIRD,READER,SENDER]},
            "addressed_to":[READER],"expectation":"none","idempotency_key":"origin-group"
        }),
    )
    .await
    .unwrap();

    assert_eq!(pair["home_id"], native_ce::schema::UNFILED_RECORD_ID);
    assert_eq!(pair["communication_origin"]["type"], "direct");
    let pair_stream = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"direct","participant_ids":[READER,SENDER]}}),
    )
    .await
    .unwrap();
    assert_eq!(pair_stream["messages"].as_array().unwrap().len(), 1);
    assert_eq!(pair_stream["messages"][0]["id"], pair["id"]);
    let group_stream = call(
        &registry,
        &db,
        THIRD_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"direct","participant_ids":[READER,THIRD,SENDER]}}),
    )
    .await
    .unwrap();
    assert_eq!(group_stream["messages"].as_array().unwrap().len(), 1);
    assert_eq!(group_stream["messages"][0]["id"], group["id"]);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn replies_retain_their_authored_origin_and_legacy_drafts_stay_unknown() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let root = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"root","origin":{"type":"direct","participant_ids":[SENDER,READER]},
            "addressed_to":[READER],"expectation":"reply","idempotency_key":"origin-root"
        }),
    )
    .await
    .unwrap();
    let reply = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"reply","origin":{"type":"direct","participant_ids":[READER,SENDER]},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":root["id"],"relationship":"reply_to"}],
            "idempotency_key":"origin-reply"
        }),
    )
    .await
    .unwrap();
    let correction = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"corrected root","origin":{"type":"direct","participant_ids":[READER,SENDER]},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":root["id"],"relationship":"supersedes"}],
            "idempotency_key":"origin-correction"
        }),
    )
    .await
    .unwrap();
    assert_eq!(reply["communication_origin"], root["communication_origin"]);
    let stream = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"direct","participant_ids":[READER,SENDER]}}),
    )
    .await
    .unwrap();
    let persisted_reply = stream["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["id"] == reply["id"])
        .unwrap();
    assert_eq!(persisted_reply["reply_to_ids"], json!([root["id"]]));
    let persisted_correction = stream["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["id"] == correction["id"])
        .unwrap();
    assert_eq!(persisted_correction["supersedes_id"], root["id"]);

    let mismatch = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"wrong context","origin":{"type":"direct","participant_ids":[READER,SENDER,THIRD]},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":root["id"],"relationship":"reply_to"}],
            "idempotency_key":"origin-wrong-reply"
        }),
    )
    .await
    .unwrap_err();
    assert!(mismatch.to_string().contains("replies must retain"));

    let other_context = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"group root","origin":{"type":"direct","participant_ids":[SENDER,READER,THIRD]},
            "addressed_to":[READER],"expectation":"none","idempotency_key":"origin-group-root"
        }),
    )
    .await
    .unwrap();
    let cross_context_correction = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"wrong correction context","origin":{"type":"direct","participant_ids":[READER,SENDER]},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":other_context["id"],"relationship":"supersedes"}],
            "idempotency_key":"origin-wrong-correction"
        }),
    )
    .await
    .unwrap_err();
    assert!(cross_context_correction
        .to_string()
        .contains("corrections must retain"));

    let multiple_corrections = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"ambiguous correction","origin":{"type":"direct","participant_ids":[READER,SENDER]},
            "addressed_to":[SENDER],"expectation":"none","links":[
                {"target_id":root["id"],"relationship":"supersedes"},
                {"target_id":reply["id"],"relationship":"supersedes"}
            ],
            "idempotency_key":"origin-ambiguous-correction"
        }),
    )
    .await
    .unwrap_err();
    assert!(multiple_corrections
        .to_string()
        .contains("at most one canonical supersedes target"));

    let draft = registry
        .call(
            db.clone(),
            Caller::authenticated(SENDER_ACCOUNT),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({"type":"Message","kind":"text","body":"draft","addressed_to":[],"facets":{"expectation":"none"}}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(draft["communication_origin"]["type"], "legacy_unknown");
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn context_links_are_complete_and_retain_id_only_edges_to_hidden_targets() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let root = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"private root","origin":{"type":"direct","participant_ids":[SENDER,READER]},
            "addressed_to":[READER],"expectation":"none","idempotency_key":"projected-hidden-root"
        }),
    )
    .await
    .unwrap();
    let reply = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"visible reply","origin":{"type":"direct","participant_ids":[READER,SENDER]},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":root["id"],"relationship":"reply_to"}],
            "idempotency_key":"projected-visible-reply"
        }),
    )
    .await
    .unwrap();
    let correction = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"visible correction","origin":{"type":"direct","participant_ids":[READER,SENDER]},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":root["id"],"relationship":"supersedes"}],
            "idempotency_key":"projected-visible-correction"
        }),
    )
    .await
    .unwrap();

    for index in 0..200 {
        let target_id = format!("7e310000-0000-4000-8000-{index:012x}");
        create_raw_record(
            &db,
            json!({"id":target_id,"type":"Document","kind":"note","name":format!("filler {index}")}),
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some(format!("test:filler:{index}")),
                source_id: reply["id"].as_str().unwrap().into(),
                target_id,
                relationship: "relates_to".into(),
                note: None,
            },
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        "test:hidden-context-link-target",
        root["id"].as_str().unwrap(),
        vec![AllowEntry::account(SENDER_ACCOUNT, Capability::View)],
    )
    .await
    .unwrap();

    let stream = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"direct","participant_ids":[READER,SENDER]}}),
    )
    .await
    .unwrap();
    let messages = stream["messages"].as_array().unwrap();
    assert!(!messages.iter().any(|message| message["id"] == root["id"]));
    let projected_reply = messages
        .iter()
        .find(|message| message["id"] == reply["id"])
        .unwrap();
    assert_eq!(projected_reply["reply_to_ids"], json!([root["id"]]));
    let projected_correction = messages
        .iter()
        .find(|message| message["id"] == correction["id"])
        .unwrap();
    assert_eq!(projected_correction["supersedes_id"], root["id"]);
}

#[tokio::test]
async fn collection_origin_anchors_filing_and_context_replies() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let first = collection(&registry, &db).await;
    let second = collection(&registry, &db).await;

    let mismatched = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"must not leak","origin":{"type":"collection","collection_id":&first},
            "home_id":&second,"addressed_to":[],"expectation":"none","idempotency_key":"origin-home-mismatch"
        }),
    )
    .await
    .unwrap_err();
    assert!(mismatched
        .to_string()
        .contains("must be filed in that Collection"));

    let root = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","body":"channel root","origin":{"type":"collection","collection_id":&first},
            "addressed_to":[READER],"expectation":"reply","idempotency_key":"origin-channel-root"
        }),
    )
    .await
    .unwrap();
    let reply = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({
            "action":"send","body":"channel reply","origin":{"type":"collection","collection_id":&first},
            "addressed_to":[SENDER],"expectation":"none","links":[{"target_id":root["id"],"relationship":"reply_to"}],
            "idempotency_key":"origin-channel-reply"
        }),
    )
    .await
    .unwrap();
    assert_eq!(reply["communication_origin"], root["communication_origin"]);

    let refile = registry
        .call(
            db.clone(),
            Caller::authenticated(SENDER_ACCOUNT),
            "update_record",
            crate::common::with_test_reason(
                "update_record",
                json!({"id":root["id"],"home_id":&second}),
            ),
        )
        .await
        .unwrap_err();
    assert!(refile.to_string().contains("must remain filed"));
}

#[tokio::test]
async fn context_pages_are_authored_ordered_and_do_not_count_hidden_messages() {
    let db = create_database(":memory:").await.unwrap();
    install_people(&db).await;
    let registry = registry();
    let collection_id = collection(&registry, &db).await;
    let older = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","id":"ffffffff-ffff-4fff-8fff-ffffffffffff","body":"visible older",
            "origin":{"type":"collection","collection_id":&collection_id},"addressed_to":[],
            "expectation":"none","idempotency_key":"origin-visible-older"
        }),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let hidden = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"send","id":"00000000-0000-4000-8000-000000000010","body":"hidden newer",
            "origin":{"type":"collection","collection_id":&collection_id},"addressed_to":[],
            "expectation":"none","idempotency_key":"origin-hidden-newer"
        }),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:narrow-hidden-message",
        hidden["id"].as_str().unwrap(),
        vec![AllowEntry::account(SENDER_ACCOUNT, Capability::View)],
    )
    .await
    .unwrap();

    let reader_page = call(
        &registry,
        &db,
        READER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"collection","collection_id":&collection_id},"limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(reader_page["messages"][0]["id"], older["id"]);
    assert_eq!(reader_page["has_more"], false);
    assert_eq!(reader_page["next_cursor"], Value::Null);

    let sender_page = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({"action":"list_context","origin":{"type":"collection","collection_id":&collection_id},"limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(sender_page["messages"][0]["id"], hidden["id"]);
    assert_eq!(sender_page["has_more"], true);
    let next = call(
        &registry,
        &db,
        SENDER_ACCOUNT,
        json!({
            "action":"list_context","origin":{"type":"collection","collection_id":&collection_id},"limit":1,
            "cursor":sender_page["next_cursor"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(next["messages"][0]["id"], older["id"]);
    assert_eq!(next["has_more"], false);
}
