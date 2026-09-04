#![cfg(feature = "postgres-tests")]

use std::net::SocketAddr;
use std::time::Duration;

use crate::contract::{ContractHarness, PostgresHarness, TestCaller};
use native_ce::mcp::fetch::FetchConfig;
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::postgres::{
    install_projection_failure_trigger, register_postgres_slice_tools,
    register_postgres_tools_with, PostgresDb,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

async fn harness() -> PostgresHarness {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        panic!("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres attachment contract receipts")
    });
    PostgresHarness::connect_with_fetch_config(&url, FetchConfig::default())
        .await
        .expect("connect to NATIVE_CE_POSTGRES_TEST_URL")
}

async fn bearer<H: ContractHarness>(harness: &H, database: &H::Database, id: &str) {
    harness
        .call(
            database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": "Attachment bearer",
                "home_id": "native:unfiled",
                "reason": "Create the attachment contract bearer."
            }),
        )
        .await
        .unwrap();
}

async fn server(
    body: &'static str,
    mime: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (address, task)
}

async fn tombstone(database: &PostgresDb, record_id: &str) {
    let records = database.qualified_table("records").unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET deleted_at='2026-08-14T00:00:00Z' WHERE id=$1"
    ))
    .bind(record_id)
    .execute(database.pool())
    .await
    .unwrap();
}

async fn restrict_to_account(database: &PostgresDb, record_id: &str, account_id: &str) {
    let records = database.qualified_table("records").unwrap();
    let policies = database.qualified_table("record_policies").unwrap();
    let entries = database.qualified_table("policy_entries").unwrap();
    let mut transaction = database.pool().begin().await.unwrap();
    sqlx::query(&format!("INSERT INTO {policies}(record_id) VALUES($1)"))
        .bind(record_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET policy_anchor_id=$1 WHERE id=$2"
    ))
    .bind(record_id)
    .bind(record_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES($1,'account',$2,'allow','edit')"
    ))
    .bind(record_id)
    .bind(account_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

async fn listener() -> (SocketAddr, TcpListener) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    (address, listener)
}

async fn assert_no_request(listener: TcpListener) {
    assert!(
        timeout(Duration::from_millis(150), listener.accept())
            .await
            .is_err(),
        "attachment preflight made an HTTP request"
    );
}

async fn blob_count(database: &PostgresDb) -> i64 {
    let blobs = database.qualified_table("blobs").unwrap();
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {blobs}"))
        .fetch_one(database.pool())
        .await
        .unwrap()
}

const URL_CANCEL_ADVISORY_LOCK: i64 = 899_034;

async fn install_url_cancellation_trigger(database: &PostgresDb) {
    let schema = database.schema();
    let events = database.qualified_table("content_events").unwrap();
    let function = format!("\"{schema}\".contract_block_fetched_attachment");
    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF NEW.type='record.created' AND NEW.payload->>'name'='__cancel_after_fetch__' THEN \
             PERFORM pg_advisory_xact_lock({URL_CANCEL_ADVISORY_LOCK}); \
           END IF; \
           RETURN NEW; \
         END $$"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER contract_block_fetched_attachment \
         BEFORE INSERT ON {events} FOR EACH ROW \
         EXECUTE FUNCTION {function}()"
    ))
    .execute(database.pool())
    .await
    .unwrap();
}

fn spawn_call(
    database: PostgresDb,
    tool: &'static str,
    arguments: serde_json::Value,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_postgres_slice_tools(&mut registry).unwrap();
        registry
            .call_engine(
                EngineHandle::Postgres(database),
                Caller::local(),
                tool,
                arguments,
            )
            .await
    })
}

fn spawn_url_call(
    database: PostgresDb,
    arguments: serde_json::Value,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_postgres_tools_with(
            &mut registry,
            FetchConfig {
                allow_loopback: true,
                ..FetchConfig::default()
            },
        )
        .unwrap();
        registry
            .call_engine(
                EngineHandle::Postgres(database),
                Caller::local(),
                "attach_from_url",
                arguments,
            )
            .await
    })
}

async fn wait_for_blocked_relation(database: &PostgresDb, relation: &str) {
    timeout(Duration::from_secs(5), async {
        loop {
            let pattern = format!("%{relation}%");
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1)",
            )
            .bind(pattern)
            .fetch_one(database.pool())
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("attachment operation did not reach its blocked physical relation");
}

#[tokio::test]
async fn postgres_attach_text_contract() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000008").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "9c150000-0000-4000-8000-001000000008",
                "text": "portable bytes",
                "filename": "portable.txt",
                "mime": "text/plain"
            }),
        )
        .await
        .unwrap();
    assert_eq!(attached["name"], "portable.txt");
    assert_eq!(attached["blob"]["size_bytes"], 14);
    assert_eq!(attached["blob"]["mime"], "text/plain");
    assert_eq!(
        attached["blob"]["sha256"],
        hex::encode(Sha256::digest(b"portable bytes"))
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attachment_shared_lifecycle_corpus() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    let receipt = crate::contract::scenarios::attachment_lifecycle(&harness, &database)
        .await
        .unwrap();
    assert_eq!(
        receipt,
        json!({
            "create":{"name":"portable.txt","mime":"text/plain","size_bytes":25,"sha256":hex::encode(Sha256::digest(b"portable attachment bytes"))},
            "range":{"content":"attachment","encoding":"utf-8","length":10,"eof":false},
            "listed":1,"inspected_detached":false,
            "detach":{"detached":true,"blob_retained":true},
            "listed_after_detach":0,"read_after_detach_missing":true
        })
    );
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attach_from_url_contract() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        panic!("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres attachment contract receipts")
    });
    let (address, task) = server("url bytes", "text/plain; charset=utf-8").await;
    let config = FetchConfig {
        allow_loopback: true,
        timeout: Duration::from_millis(100),
        ..FetchConfig::default()
    };
    let harness = PostgresHarness::connect_with_fetch_config(&url, config)
        .await
        .unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000013").await;
    let source = format!("http://{address}/source.txt");
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_from_url",
            json!({
                "record_id": "9c150000-0000-4000-8000-001000000013",
                "url": source,
                "name": "Fetched source"
            }),
        )
        .await
        .unwrap();
    task.await.unwrap();
    assert_eq!(attached["blob"]["size_bytes"], 9);
    assert_eq!(attached["blob"]["mime"], "text/plain; charset=utf-8");
    assert_eq!(attached["final_url"], source);
    assert_eq!(attached["redirects"], 0);
    let record = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({ "ids": [attached["attachment_id"]] }),
        )
        .await
        .unwrap();
    assert!(record["records"][0]["facets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|facet| facet["key"] == "source_url" && facet["value"] == source));
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attach_from_url_preflight_rejects_missing_unauthorized_and_tombstoned_targets_without_http(
) {
    let config = FetchConfig {
        allow_loopback: true,
        timeout: Duration::from_millis(100),
        ..FetchConfig::default()
    };
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        panic!("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres attachment contract receipts")
    });
    let harness = PostgresHarness::connect_with_fetch_config(&url, config)
        .await
        .unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000011").await;
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000009").await;
    tombstone(&database, "9c150000-0000-4000-8000-001000000009").await;
    restrict_to_account(
        &database,
        "9c150000-0000-4000-8000-001000000011",
        "acct:attachment-owner",
    )
    .await;

    for (record_id, caller, expected) in [
        (
            "9c150000-0000-4000-8000-001000000004",
            TestCaller::Local,
            "record 9c150000-0000-4000-8000-001000000004 does not exist",
        ),
        (
            "9c150000-0000-4000-8000-001000000011",
            TestCaller::Member {
                account_id: "acct:attachment-denied".into(),
            },
            "record 9c150000-0000-4000-8000-001000000011 does not exist",
        ),
        (
            "9c150000-0000-4000-8000-001000000009",
            TestCaller::Local,
            "record 9c150000-0000-4000-8000-001000000009 is deleted (tombstoned)",
        ),
    ] {
        let (address, listener) = listener().await;
        let result = timeout(
            Duration::from_secs(2),
            harness.call(
                &database,
                caller,
                "attach_from_url",
                json!({
                    "record_id": record_id,
                    "url": format!("http://{address}/should-not-be-requested")
                }),
            ),
        )
        .await
        .expect("preflight did not finish before any HTTP request")
        .unwrap_err();
        assert_eq!(result.to_string(), format!("attach_from_url: {expected}"));
        assert_no_request(listener).await;
    }
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attach_from_url_post_fetch_cancellation_cleanup_and_reuse_contract() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        panic!("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres attachment contract receipts")
    });
    let harness = PostgresHarness::connect_with_fetch_config(
        &url,
        FetchConfig {
            allow_loopback: true,
            ..FetchConfig::default()
        },
    )
    .await
    .unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000012").await;
    install_url_cancellation_trigger(&database).await;

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(URL_CANCEL_ADVISORY_LOCK)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (address, fetched) = server("cancelled url bytes", "text/plain").await;
    let cancelled = spawn_url_call(
        database.clone(),
        json!({
            "record_id":"9c150000-0000-4000-8000-001000000012",
            "url":format!("http://{address}/cancelled"),
            "name":"__cancel_after_fetch__"
        }),
    );
    fetched.await.unwrap();
    wait_for_blocked_relation(&database, "content_events").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    blocker.commit().await.unwrap();
    assert_eq!(blob_count(&database).await, 0);
    let after_cancel = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({"action":"list","record_id":"9c150000-0000-4000-8000-001000000012"}),
        )
        .await
        .unwrap();
    assert!(after_cancel["attachments"].as_array().unwrap().is_empty());

    let (address, fetched) = server("reused url bytes", "text/plain").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_from_url",
            json!({
                "record_id":"9c150000-0000-4000-8000-001000000012",
                "url":format!("http://{address}/reused")
            }),
        )
        .await
        .unwrap();
    fetched.await.unwrap();
    assert_eq!(blob_count(&database).await, 1);
    let reused = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({"attachment_id":attached["attachment_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(reused["content"], "reused url bytes");
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_read_attachment_contract() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000006").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-001000000006", "text": "0123456789" }),
        )
        .await
        .unwrap();
    let read = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({
                "attachment_id": attached["attachment_id"],
                "offset": 3,
                "length": 4
            }),
        )
        .await
        .unwrap();
    assert_eq!(read["content"], "3456");
    assert_eq!(read["length"], 4);
    assert!(!read["eof"].as_bool().unwrap());
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": attached["attachment_id"], "length": 0 }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "read_attachment: 'length' must be between 1 and 524288"
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_manage_attachments_contract() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000003").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "9c150000-0000-4000-8000-001000000003",
                "text": "managed bytes",
                "filename": "managed.txt"
            }),
        )
        .await
        .unwrap();
    let listed = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-001000000003" }),
        )
        .await
        .unwrap();
    assert_eq!(listed["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(listed["attachments"][0]["name"], "managed.txt");
    let inspected = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "inspect", "attachment_id": attached["attachment_id"] }),
        )
        .await
        .unwrap();
    assert_eq!(inspected["detached"], false);
    let events = database.qualified_table("content_events").unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap();
    let previous_seq: i64 =
        sqlx::query_scalar(&format!("SELECT MAX(seq) FROM {events} WHERE record_id=$1"))
            .bind(attachment_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let tombstones_before: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {events} WHERE record_id=$1 AND type='record.deleted'"
    ))
    .bind(attachment_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let arguments = json!({
        "action": "detach",
        "attachment_id": attachment_id,
        "if_content_seq": previous_seq,
    });
    let (first, second) = tokio::join!(
        harness.call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            arguments.clone(),
        ),
        harness.call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            arguments,
        ),
    );
    let (detached, non_success) = match (first, second) {
        (Ok(detached), Err(non_success)) | (Err(non_success), Ok(detached)) => {
            (detached, non_success)
        }
        (first, second) => {
            panic!("expected one detach and one authoritative failure, got {first:?}, {second:?}")
        }
    };
    let non_success = non_success.to_string();
    assert!(
        non_success.contains("content revision conflict")
            || (non_success.contains("manage_attachments: attachment")
                && non_success.contains("does not exist")),
        "the losing detach must fail authoritatively after the shared content-log transaction: {non_success}"
    );
    assert_eq!(detached["blob_retained"], true);
    let tombstones_after: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {events} WHERE record_id=$1 AND type='record.deleted'"
    ))
    .bind(attachment_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(tombstones_after, tombstones_before + 1);
    let after = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-001000000003" }),
        )
        .await
        .unwrap();
    assert!(after["attachments"].as_array().unwrap().is_empty());
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attachment_authorization_and_stable_limits_contract() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000002").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000002","text":"guarded bytes"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap();
    restrict_to_account(
        &database,
        "9c150000-0000-4000-8000-001000000002",
        "acct:attachment-owner",
    )
    .await;
    let editor = TestCaller::Member {
        account_id: "acct:attachment-owner".into(),
    };
    let editor_list = harness
        .call(
            &database,
            editor.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"9c150000-0000-4000-8000-001000000002"}),
        )
        .await
        .unwrap();
    assert_eq!(editor_list["attachments"].as_array().unwrap().len(), 1);
    harness
        .call(
            &database,
            editor.clone(),
            "manage_attachments",
            json!({"action":"inspect","attachment_id":attachment_id}),
        )
        .await
        .unwrap();
    let editor_detach = harness
        .call(
            &database,
            editor,
            "manage_attachments",
            json!({"action":"detach","attachment_id":attachment_id}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        editor_detach.to_string(),
        format!("manage_attachments: attachment {attachment_id} does not exist"),
        "Edit must allow list/inspect but not the distinct Manage capability required by detach"
    );

    let events = database.qualified_table("content_events").unwrap();
    let tombstones_before: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {events} WHERE record_id=$1 AND type='record.deleted'"
    ))
    .bind(attachment_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let denied = TestCaller::Member {
        account_id: "acct:attachment-denied".into(),
    };
    for (tool, arguments, expected) in [
        (
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000002","text":"must not persist"}),
            "attach_text: record 9c150000-0000-4000-8000-001000000002 does not exist".to_string(),
        ),
        (
            "read_attachment",
            json!({"attachment_id":attachment_id}),
            format!("read_attachment: attachment {attachment_id} does not exist"),
        ),
        (
            "manage_attachments",
            json!({"action":"inspect","attachment_id":attachment_id}),
            format!("manage_attachments: attachment {attachment_id} does not exist"),
        ),
    ] {
        let error = harness
            .call(&database, denied.clone(), tool, arguments)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), expected, "{tool}");
    }
    let missing_bearer = "9c150000-0000-4000-8000-001000000005";
    let denied_list = harness
        .call(
            &database,
            denied.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"9c150000-0000-4000-8000-001000000002"}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing_list = harness
        .call(
            &database,
            denied.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":missing_bearer}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied_list.replace("9c150000-0000-4000-8000-001000000002", "<record>"),
        missing_list.replace(missing_bearer, "<record>"),
        "denied list must not reveal whether the bearer exists"
    );

    let missing_attachment = "9c150000-0000-4000-8000-001000000004";
    let denied_detach = harness
        .call(
            &database,
            denied.clone(),
            "manage_attachments",
            json!({"action":"detach","attachment_id":attachment_id}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing_detach = harness
        .call(
            &database,
            denied,
            "manage_attachments",
            json!({"action":"detach","attachment_id":missing_attachment}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied_detach.replace(attachment_id, "<attachment>"),
        missing_detach.replace(missing_attachment, "<attachment>"),
        "denied detach must not reveal whether the attachment exists"
    );
    let tombstones_after: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {events} WHERE record_id=$1 AND type='record.deleted'"
    ))
    .bind(attachment_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(tombstones_after, tombstones_before);
    assert_eq!(blob_count(&database).await, 1);

    for (arguments, expected) in [
        (
            json!({"attachment_id":attachment_id,"length":0}),
            "read_attachment: 'length' must be between 1 and 524288",
        ),
        (
            json!({"attachment_id":attachment_id,"length":524289}),
            "read_attachment: 'length' must be between 1 and 524288",
        ),
    ] {
        let error = harness
            .call(&database, TestCaller::Local, "read_attachment", arguments)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
    let url_limit = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_from_url",
            json!({"record_id":"9c150000-0000-4000-8000-001000000002","url":"https://example.com/x","max_bytes":0}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        url_limit.to_string(),
        "attach_from_url: 'max_bytes' must be between 1 and 20971520"
    );
    let text_limit = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000002","text":"x".repeat(20 * 1024 * 1024 + 1)}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        text_limit.to_string(),
        "attach_text: text exceeds the 20971520 byte cap"
    );
    assert_eq!(blob_count(&database).await, 1);
    let still_listed = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({"action":"list","record_id":"9c150000-0000-4000-8000-001000000002"}),
        )
        .await
        .unwrap();
    assert_eq!(still_listed["attachments"].as_array().unwrap().len(), 1);
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attachment_write_rollback_and_reuse_contract() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        panic!("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres attachment contract receipts")
    });
    let harness = PostgresHarness::connect_with_fetch_config(
        &url,
        FetchConfig {
            allow_loopback: true,
            ..FetchConfig::default()
        },
    )
    .await
    .unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000007").await;
    install_projection_failure_trigger(&database).await.unwrap();

    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000007","text":"rolled back","name":"__reject_projection__"}),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("storage operation failed"),
        "{error}"
    );
    assert_eq!(blob_count(&database).await, 0);

    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000007","text":"committed"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap();
    let (address, task) = server("url rollback", "text/plain").await;
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_from_url",
            json!({"record_id":"9c150000-0000-4000-8000-001000000007","url":format!("http://{address}/rollback"),"name":"__reject_projection__"}),
        )
        .await
        .unwrap_err();
    task.await.unwrap();
    assert!(
        error.to_string().contains("storage operation failed"),
        "{error}"
    );
    assert_eq!(blob_count(&database).await, 1);
    let readable = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({"attachment_id":attachment_id}),
        )
        .await
        .unwrap();
    assert_eq!(readable["content"], "committed");
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attachment_cancellation_cleanup_and_reuse_contract() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "9c150000-0000-4000-8000-001000000001").await;
    let events = database.qualified_table("content_events").unwrap();
    let blobs = database.qualified_table("blobs").unwrap();

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {events} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let create = spawn_call(
        database.clone(),
        "attach_text",
        json!({"record_id":"9c150000-0000-4000-8000-001000000001","text":"cancelled"}),
    );
    wait_for_blocked_relation(&database, "content_events").await;
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    blocker.commit().await.unwrap();
    assert_eq!(blob_count(&database).await, 0);

    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000001","text":"0123456789"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap().to_string();

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {blobs} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let read = spawn_call(
        database.clone(),
        "read_attachment",
        json!({"attachment_id":attachment_id,"offset":2,"length":4}),
    );
    wait_for_blocked_relation(&database, "blobs").await;
    read.abort();
    assert!(read.await.unwrap_err().is_cancelled());
    blocker.commit().await.unwrap();
    let reused = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({"attachment_id":attachment_id,"offset":2,"length":4}),
        )
        .await
        .unwrap();
    assert_eq!(reused["content"], "2345");

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {events} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let detach = spawn_call(
        database.clone(),
        "manage_attachments",
        json!({"action":"detach","attachment_id":attachment_id}),
    );
    wait_for_blocked_relation(&database, "content_events").await;
    detach.abort();
    assert!(detach.await.unwrap_err().is_cancelled());
    blocker.commit().await.unwrap();
    let still_readable = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({"attachment_id":attachment_id}),
        )
        .await
        .unwrap();
    assert_eq!(still_readable["content"], "0123456789");
    let detached = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({"action":"detach","attachment_id":attachment_id}),
        )
        .await
        .unwrap();
    assert_eq!(detached["blob_retained"], true);
    assert_eq!(blob_count(&database).await, 1);
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attachment_logical_database_topology_contract() {
    let harness = harness().await;
    let alpha = harness.fresh_logical_database().await.unwrap();
    let beta = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &alpha, "9c150000-0000-4000-8000-001000000010").await;
    bearer(&harness, &beta, "9c150000-0000-4000-8000-001000000010").await;
    let alpha_attachment = harness
        .call(
            &alpha,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000010","text":"alpha"}),
        )
        .await
        .unwrap();
    let beta_attachment = harness
        .call(
            &beta,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"9c150000-0000-4000-8000-001000000010","text":"beta"}),
        )
        .await
        .unwrap();
    assert_ne!(
        alpha_attachment["attachment_id"],
        beta_attachment["attachment_id"]
    );
    assert_ne!(alpha.schema(), beta.schema());
    for (database, foreign_id) in [
        (&alpha, beta_attachment["attachment_id"].as_str().unwrap()),
        (&beta, alpha_attachment["attachment_id"].as_str().unwrap()),
    ] {
        let missing = harness
            .call(
                database,
                TestCaller::Local,
                "read_attachment",
                json!({"attachment_id":foreign_id}),
            )
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("does not exist"));
        assert_eq!(blob_count(database).await, 1);
        harness.assert_replay_equivalent(database).await.unwrap();
    }
    harness.close(&alpha).await;
    harness.close(&beta).await;
    harness.shutdown().await;
}
