#![cfg(feature = "turso-tests")]

use std::net::SocketAddr;
use std::time::Duration;

use crate::contract::{ContractHarness, TestCaller, TursoHarness};
use native_ce::mcp::fetch::FetchConfig;
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::turso_local::{register_turso_local_tools, register_turso_local_tools_with};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

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

fn spawn_call(
    database: native_ce::turso_local::TursoLocalDb,
    tool: &'static str,
    arguments: serde_json::Value,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_turso_local_tools(&mut registry).unwrap();
        registry
            .call_engine(
                EngineHandle::TursoLocal(database),
                Caller::local(),
                tool,
                arguments,
            )
            .await
    })
}

fn spawn_url_call(
    database: native_ce::turso_local::TursoLocalDb,
    arguments: serde_json::Value,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_turso_local_tools_with(
            &mut registry,
            FetchConfig {
                allow_loopback: true,
                ..FetchConfig::default()
            },
        )
        .unwrap();
        registry
            .call_engine(
                EngineHandle::TursoLocal(database),
                Caller::local(),
                "attach_from_url",
                arguments,
            )
            .await
    })
}

#[tokio::test]
async fn turso_attach_text_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000008").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "70250000-0000-4000-8000-001000000008",
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
}

#[tokio::test]
async fn turso_attachment_shared_lifecycle_corpus() {
    let harness = TursoHarness::new();
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
}

#[tokio::test]
async fn turso_attach_from_url_contract() {
    let (address, task) = server("url bytes", "text/plain; charset=utf-8").await;
    let config = FetchConfig {
        allow_loopback: true,
        ..FetchConfig::default()
    };
    let harness = TursoHarness::new_with_fetch_config(config);
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000012").await;
    let source = format!("http://{address}/source.txt");
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_from_url",
            json!({
                "record_id": "70250000-0000-4000-8000-001000000012",
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
}

#[tokio::test]
async fn turso_attach_from_url_preflight_rejects_missing_unauthorized_and_tombstoned_targets_without_http(
) {
    let harness = TursoHarness::new_with_fetch_config(FetchConfig {
        allow_loopback: true,
        timeout: Duration::from_millis(100),
        ..FetchConfig::default()
    });
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000011").await;
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000009").await;
    harness
        .tombstone_record_for_test(&database, "70250000-0000-4000-8000-001000000009")
        .await
        .unwrap();
    harness
        .restrict_record_to_account_for_test(
            &database,
            "70250000-0000-4000-8000-001000000011",
            "acct:attachment-owner",
        )
        .await
        .unwrap();

    for (record_id, caller, expected) in [
        (
            "70250000-0000-4000-8000-001000000004",
            TestCaller::Local,
            "record 70250000-0000-4000-8000-001000000004 does not exist",
        ),
        (
            "70250000-0000-4000-8000-001000000011",
            TestCaller::Member {
                account_id: "acct:attachment-denied".into(),
            },
            "record 70250000-0000-4000-8000-001000000011 does not exist",
        ),
        (
            "70250000-0000-4000-8000-001000000009",
            TestCaller::Local,
            "record 70250000-0000-4000-8000-001000000009 is deleted (tombstoned)",
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
}

#[tokio::test]
async fn turso_attach_from_url_post_fetch_cancellation_cleanup_and_reuse_contract() {
    let harness = TursoHarness::new_with_fetch_config(FetchConfig {
        allow_loopback: true,
        ..FetchConfig::default()
    });
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000013").await;
    let runtime = database.runtime_for_test().unwrap();

    let (address, fetched) = server("cancelled url bytes", "text/plain").await;
    runtime.contract_arm_post_handler_write_block("attach_from_url");
    let cancelled = spawn_url_call(
        runtime.clone(),
        json!({
            "record_id":"70250000-0000-4000-8000-001000000013",
            "url":format!("http://{address}/cancelled")
        }),
    );
    fetched.await.unwrap();
    runtime.contract_wait_for_write_block().await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 0);
    let after_cancel = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-001000000013"}),
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
                "record_id":"70250000-0000-4000-8000-001000000013",
                "url":format!("http://{address}/reused")
            }),
        )
        .await
        .unwrap();
    fetched.await.unwrap();
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 1);
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
}

#[tokio::test]
async fn turso_read_attachment_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000006").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({ "record_id": "70250000-0000-4000-8000-001000000006", "text": "0123456789" }),
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
}

#[tokio::test]
async fn turso_manage_attachments_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000003").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "70250000-0000-4000-8000-001000000003",
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
            json!({ "action": "list", "record_id": "70250000-0000-4000-8000-001000000003" }),
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
    let attachment_id = attached["attachment_id"].as_str().unwrap();
    let history = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({ "record_id": attachment_id }),
        )
        .await
        .unwrap();
    let previous_seq = history["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["local_seq"].as_i64())
        .max()
        .unwrap();
    let tombstones_before = harness
        .content_event_type_count_for_test(&database, attachment_id, "record.deleted")
        .await
        .unwrap();
    let stale = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({
                "action": "detach",
                "attachment_id": attachment_id,
                "if_content_seq": previous_seq - 1,
            }),
        )
        .await
        .unwrap_err();
    assert!(
        stale.to_string().contains("content revision conflict"),
        "{stale}"
    );
    assert_eq!(
        harness
            .content_event_type_count_for_test(&database, attachment_id, "record.deleted")
            .await
            .unwrap(),
        tombstones_before
    );
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
    let (detached, already_detached) = match (first, second) {
        (Ok(detached), Err(already_detached)) | (Err(already_detached), Ok(detached)) => {
            (detached, already_detached)
        }
        (first, second) => {
            panic!(
                "expected one detach and one already-detached failure, got {first:?}, {second:?}"
            )
        }
    };
    assert!(
        already_detached.to_string().contains("does not exist"),
        "{already_detached}"
    );
    assert_eq!(detached["blob_retained"], true);
    let tombstones_after = harness
        .content_event_type_count_for_test(&database, attachment_id, "record.deleted")
        .await
        .unwrap();
    assert_eq!(tombstones_after, tombstones_before + 1);
    let after = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "list", "record_id": "70250000-0000-4000-8000-001000000003" }),
        )
        .await
        .unwrap();
    assert!(after["attachments"].as_array().unwrap().is_empty());
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_attachment_authorization_and_stable_limits_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000002").await;
    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000002","text":"guarded bytes"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap();
    harness
        .restrict_record_to_account_for_test(
            &database,
            "70250000-0000-4000-8000-001000000002",
            "acct:attachment-owner",
        )
        .await
        .unwrap();
    let editor = TestCaller::Member {
        account_id: "acct:attachment-owner".into(),
    };
    let editor_list = harness
        .call(
            &database,
            editor.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-001000000002"}),
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

    let tombstones_before = harness
        .content_event_type_count_for_test(&database, attachment_id, "record.deleted")
        .await
        .unwrap();
    let denied = TestCaller::Member {
        account_id: "acct:attachment-denied".into(),
    };
    for (tool, arguments, expected) in [
        (
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000002","text":"must not persist"}),
            "attach_text: record 70250000-0000-4000-8000-001000000002 does not exist".to_string(),
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
    let missing_bearer = "70250000-0000-4000-8000-001000000005";
    let denied_list = harness
        .call(
            &database,
            denied.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-001000000002"}),
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
        denied_list.replace("70250000-0000-4000-8000-001000000002", "<record>"),
        missing_list.replace(missing_bearer, "<record>"),
        "denied list must not reveal whether the bearer exists"
    );

    let missing_attachment = "70250000-0000-4000-8000-001000000004";
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
    let tombstones_after = harness
        .content_event_type_count_for_test(&database, attachment_id, "record.deleted")
        .await
        .unwrap();
    assert_eq!(tombstones_after, tombstones_before);
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 1);

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
            json!({"record_id":"70250000-0000-4000-8000-001000000002","url":"https://example.com/x","max_bytes":0}),
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
            json!({"record_id":"70250000-0000-4000-8000-001000000002","text":"x".repeat(20 * 1024 * 1024 + 1)}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        text_limit.to_string(),
        "attach_text: text exceeds the 20971520 byte cap"
    );
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 1);
    let still_listed = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-001000000002"}),
        )
        .await
        .unwrap();
    assert_eq!(still_listed["attachments"].as_array().unwrap().len(), 1);
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_attachment_write_rollback_and_reuse_contract() {
    let harness = TursoHarness::new_with_fetch_config(FetchConfig {
        allow_loopback: true,
        ..FetchConfig::default()
    });
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000007").await;
    let runtime = database.runtime_for_test().unwrap();

    runtime.contract_arm_post_handler_write_failure("attach_text");
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000007","text":"rolled back"}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "contract forced attach_text failure after production handler work"
    );
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 0);

    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000007","text":"committed"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap().to_string();

    let (address, server) = server("url rollback", "text/plain").await;
    runtime.contract_arm_post_handler_write_failure("attach_from_url");
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_from_url",
            json!({"record_id":"70250000-0000-4000-8000-001000000007","url":format!("http://{address}/rollback")}),
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(
        error.to_string(),
        "contract forced attach_from_url failure after production handler work"
    );
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 1);

    runtime.contract_arm_post_handler_write_failure("manage_attachments");
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({"action":"detach","attachment_id":attachment_id}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "contract forced manage_attachments failure after production handler work"
    );
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
}

#[tokio::test]
async fn turso_attachment_cancellation_cleanup_and_reuse_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &database, "70250000-0000-4000-8000-001000000001").await;
    let runtime = database.runtime_for_test().unwrap();

    runtime.contract_arm_post_handler_write_block("attach_text");
    let create = spawn_call(
        runtime.clone(),
        "attach_text",
        json!({"record_id":"70250000-0000-4000-8000-001000000001","text":"cancelled"}),
    );
    runtime.contract_wait_for_write_block().await;
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 0);

    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000001","text":"0123456789"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap().to_string();

    runtime.contract_arm_snapshot_block("read_attachment");
    let read = spawn_call(
        runtime.clone(),
        "read_attachment",
        json!({"attachment_id":attachment_id,"offset":2,"length":4}),
    );
    runtime.contract_wait_for_snapshot_block().await;
    read.abort();
    assert!(read.await.unwrap_err().is_cancelled());
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

    runtime.contract_arm_post_handler_write_block("manage_attachments");
    let detach = spawn_call(
        runtime.clone(),
        "manage_attachments",
        json!({"action":"detach","attachment_id":attachment_id}),
    );
    runtime.contract_wait_for_write_block().await;
    detach.abort();
    assert!(detach.await.unwrap_err().is_cancelled());
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
    assert_eq!(harness.blob_count_for_test(&database).await.unwrap(), 1);
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_attachment_logical_database_topology_contract() {
    let harness = TursoHarness::new();
    let alpha = harness.fresh_logical_database().await.unwrap();
    let beta = harness.fresh_logical_database().await.unwrap();
    bearer(&harness, &alpha, "70250000-0000-4000-8000-001000000010").await;
    bearer(&harness, &beta, "70250000-0000-4000-8000-001000000010").await;
    let alpha_attachment = harness
        .call(
            &alpha,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000010","text":"alpha"}),
        )
        .await
        .unwrap();
    let beta_attachment = harness
        .call(
            &beta,
            TestCaller::Local,
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-001000000010","text":"beta"}),
        )
        .await
        .unwrap();
    assert_ne!(
        alpha_attachment["attachment_id"],
        beta_attachment["attachment_id"]
    );
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
        assert_eq!(harness.blob_count_for_test(database).await.unwrap(), 1);
        harness.assert_replay_equivalent(database).await.unwrap();
    }
    assert_ne!(
        alpha.runtime_for_test().unwrap().logical_database_id(),
        beta.runtime_for_test().unwrap().logical_database_id()
    );
    harness.close(&alpha).await;
    harness.close(&beta).await;
}
