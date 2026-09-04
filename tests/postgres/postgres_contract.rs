#![cfg(feature = "postgres-tests")]

use crate::contract::{
    scenarios, ContractHarness, DeliveredMessageFixture, PostgresHarness, TestCaller,
};
use native_ce::create_database;
use native_ce::events::FacetSetPayload;
use native_ce::interchange::export_canonical_interchange;
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::postgres::query_sql::{
    qualification_query_sql, qualification_query_sql_with_backend_pid,
};
use native_ce::postgres::{
    current_search_path, event_count, event_sequences, install_projection_failure_trigger,
    migration_version, physical_tables, projection_exists, register_postgres_slice_tools,
    PostgresBlob, PostgresCluster, PostgresControlEvent, PostgresLogKind, PostgresMetaEvent,
    PostgresPolicyEvent, PostgresSchemaCurrency,
};
use native_ce::query::sql::query_sql as sqlite_query_sql;
use native_ce::query::sql_contract::{
    QuerySqlParameter, QuerySqlRequest, LOGICAL_RELATIONS, MAX_CELL_ENCODED_BYTES, MAX_COLUMNS,
    MAX_RESULT_ENCODED_BYTES, MAX_ROWS,
};

use native_ce::store::{create_record, set_facet};
use serde_json::json;
use sha2::{Digest, Sha256};

async fn configured_harness() -> Option<PostgresHarness> {
    PostgresHarness::from_env()
        .await
        .expect("connect to NATIVE_CE_POSTGRES_TEST_URL")
}

#[tokio::test]
async fn postgres_describe_schema_is_normalized_allowlisted_and_owner_gated() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": scenarios::DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID,
                "type": "Collection",
                "kind": "folder",
                "name": "Hidden schema configuration bearer",
                "persistence": "enduring",
                "reason": "Create the governed describe-schema authorization fixture."
            }),
        )
        .await
        .unwrap();
    database
        .append_policy_event(PostgresPolicyEvent {
            id: "event:describe-schema:hidden-policy".into(),
            record_id: scenarios::DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID.into(),
            event_type: "policy.replaced".into(),
            payload: Some(json!({
                "entries":[{
                    "subject_kind":"account",
                    "subject_id":"acct:other-schema-reader",
                    "effect":"allow",
                    "capability":"edit"
                }]
            })),
            actor: "contract:describe-schema".into(),
            reason: "Restrict the hidden schema configuration bearer.".into(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
        .await
        .unwrap();
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    for event in [
        PostgresMetaEvent {
            id: "event:describe-schema:kind".into(),
            subject_id: scenarios::DESCRIBE_SCHEMA_KIND_ID.into(),
            event_type: "vocab_value.proposed".into(),
            payload: scenarios::describe_schema_kind_payload(),
            actor: Some("contract:describe-schema".into()),
            created_at: created_at.clone(),
        },
        PostgresMetaEvent {
            id: "event:describe-schema:global-config".into(),
            subject_id: scenarios::DESCRIBE_SCHEMA_GLOBAL_CONFIG_ID.into(),
            event_type: "schema_config.set".into(),
            payload: json!({
                "layer": "user",
                "name": "Describe schema global contract",
                "data": scenarios::describe_schema_global_config_data(),
                "applies_to_collection_id": null,
                "version_lineage": null
            }),
            actor: Some("contract:describe-schema".into()),
            created_at: created_at.clone(),
        },
        PostgresMetaEvent {
            id: "event:describe-schema:hidden-config".into(),
            subject_id: scenarios::DESCRIBE_SCHEMA_HIDDEN_CONFIG_ID.into(),
            event_type: "schema_config.set".into(),
            payload: json!({
                "layer": "user",
                "name": "Describe schema hidden contract",
                "data": scenarios::describe_schema_hidden_config_data(),
                "applies_to_collection_id": scenarios::DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID,
                "version_lineage": null
            }),
            actor: Some("contract:describe-schema".into()),
            created_at: created_at.clone(),
        },
    ] {
        database.append_meta_event(event).await.unwrap();
    }
    let owner = harness
        .call(
            &database,
            TestCaller::Local,
            "describe_schema",
            json!({"include_ddl":true}),
        )
        .await
        .unwrap();
    assert_eq!(owner["engine"]["storage_profile"], "postgres-server");
    assert_eq!(
        owner["engine"]["ddl_fingerprint"],
        "3ee20c39d45c4c8d7cf2738685f6b311164264d5ba3ae23d4955e0cfe3e74b6a"
    );
    assert_eq!(owner["tables"].as_array().unwrap().len(), 35);
    assert_eq!(owner["ddl_statements"].as_array().unwrap().len(), 54);
    let ddl = owner["ddl_statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|statement| statement.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "PRIMARY KEY",
        "FOREIGN KEY",
        "CHECK",
        "DEFAULT",
        "CREATE INDEX",
        "CREATE UNIQUE INDEX",
        "CREATE TRIGGER",
        "CREATE OR REPLACE FUNCTION",
    ] {
        assert!(
            ddl.contains(required),
            "complete Postgres DDL lacks {required}"
        );
    }
    let records = owner["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|table| table["name"] == "records")
        .unwrap();
    let archived = records["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|column| column["name"] == "archived")
        .unwrap();
    assert_eq!(archived["type"], "BOOLEAN");
    assert_eq!(archived["physical_type"], "boolean");
    assert!(owner["resolved_schema_config"]["shapes"].is_object());
    assert!(owner["kind_registry"]["Document"].is_array());
    let encoded = serde_json::to_string(&owner).unwrap();
    assert!(!encoded.contains(database.schema()));
    assert!(!encoded.contains("pg_catalog"));
    assert!(!encoded.contains("information_schema"));
    let repeated = harness
        .call(&database, TestCaller::Local, "describe_schema", json!({}))
        .await
        .unwrap();
    assert_eq!(repeated["tables"], owner["tables"]);
    assert_eq!(repeated["kind_registry"], owner["kind_registry"]);
    assert_eq!(
        repeated["engine"]["ddl_fingerprint"],
        owner["engine"]["ddl_fingerprint"]
    );

    let member = harness
        .call(
            &database,
            TestCaller::member("acct:schema-reader"),
            "describe_schema",
            json!({}),
        )
        .await
        .unwrap();
    scenarios::assert_describe_schema_shared_contract(&owner, &member);
    assert!(member["tables"]
        .as_array()
        .unwrap()
        .iter()
        .all(|table| table["name"] != "meta_events"));
    assert!(member.get("ddl_statements").is_none());
    let denied = harness
        .call(
            &database,
            TestCaller::member("acct:schema-reader"),
            "describe_schema",
            json!({"include_ddl":true}),
        )
        .await
        .unwrap_err();
    assert!(denied.to_string().contains("database owner host role"));
    let invalid = harness
        .call(
            &database,
            TestCaller::Local,
            "describe_schema",
            json!({"unknown":true}),
        )
        .await
        .unwrap_err();
    assert!(invalid
        .to_string()
        .contains("invalid arguments for describe_schema"));
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

fn postgres_url() -> Option<String> {
    std::env::var("NATIVE_CE_POSTGRES_TEST_URL").ok()
}

fn sha256_json(value: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(value).unwrap()))
}

fn assert_query_sql_error_category(error: &native_ce::Error, expected: &str) {
    let rendered = error.to_string();
    assert!(
        rendered.starts_with(&format!("query_sql [{expected}]: ")),
        "expected query_sql [{expected}], got {rendered}"
    );
}

async fn assert_postgres_backend_disappears(
    database: &native_ce::postgres::PostgresDb,
    backend_pid: i32,
) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(backend_pid)
                    .fetch_one(database.pool())
                    .await
                    .unwrap();
            if !exists {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("cancelled query backend {backend_pid} remained live"));
}

fn canonical_with_event_gap(bytes: &[u8]) -> Vec<u8> {
    let mut bundle: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let section_index = bundle["sections"]
        .as_array()
        .unwrap()
        .iter()
        .position(|section| section["name"] == "content_events")
        .unwrap();
    let seq_index = bundle["sections"][section_index]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .position(|column| column["name"] == "seq")
        .unwrap();
    for row in bundle["sections"][section_index]["rows"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .skip(1)
    {
        let value = row[seq_index]["value"].as_i64().unwrap();
        row[seq_index]["value"] = json!(value + 1);
    }
    bundle["manifest"]["sections"][section_index]["sha256"] =
        json!(sha256_json(&bundle["sections"][section_index]));
    bundle["manifest"]["content_sha256"] = json!(sha256_json(&bundle["sections"]));
    serde_json::to_vec(&bundle).unwrap()
}

#[tokio::test]
async fn postgres_record_lifecycle_and_replay_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::record_lifecycle(&harness, &database)
        .await
        .unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_visibility_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::visibility(&harness, &database).await.unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_get_history_uses_one_authorization_snapshot_during_revocation() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    for (id, name, account, principal) in [
        (
            "9c150000-0000-4000-8000-002000000030",
            "Sender",
            "acct:history-sender",
            "native/history-sender",
        ),
        (
            "9c150000-0000-4000-8000-002000000029",
            "Recipient",
            "acct:history-recipient",
            "native/history-recipient",
        ),
    ] {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id":id, "type":"Entity", "kind":"person", "name":name,
                    "reason":"Create the history snapshot principal."
                }),
            )
            .await
            .unwrap();
        harness
            .provision_member(&database, id, account, principal)
            .await
            .unwrap();
    }
    harness
        .deliver_message_fixture(
            &database,
            TestCaller::member("acct:history-sender"),
            crate::contract::DeliveredMessageFixture {
                id: "9c150000-0000-4000-8000-002000000031",
                name: "Snapshot message",
                body: "authorization and selection share one instant",
                addressed_to: &["9c150000-0000-4000-8000-002000000029"],
                idempotency_key: "history:snapshot-delivery",
            },
        )
        .await
        .unwrap();

    let events = database.qualified_table("content_events").unwrap();
    let audience = database.qualified_table("message_audience").unwrap();
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {events} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();

    let history_database = database.clone();
    let history = tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_postgres_slice_tools(&mut registry).unwrap();
        registry
            .call_engine(
                EngineHandle::Postgres(history_database),
                Caller::authenticated("acct:history-recipient")
                    .with_hosting_context("history-recipient", "history-database")
                    .with_hosting_owner(false),
                "get_history",
                json!({"record_id":"9c150000-0000-4000-8000-002000000031","detail":"full"}),
            )
            .await
    });

    let blocked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%ORDER BY seq LIMIT%')",
            )
            .fetch_one(database.pool())
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        blocked.is_ok(),
        "get_history did not reach its event selection"
    );

    sqlx::query(&format!(
        "DELETE FROM {audience} WHERE message_id=$1 AND account_id=$2"
    ))
    .bind("9c150000-0000-4000-8000-002000000031")
    .bind("acct:history-recipient")
    .execute(database.pool())
    .await
    .unwrap();
    blocker.commit().await.unwrap();

    let before_revocation = history.await.unwrap().unwrap();
    assert_eq!(
        before_revocation["events"][0]["payload"]["body"],
        "authorization and selection share one instant"
    );
    let after_revocation = harness
        .call(
            &database,
            TestCaller::member("acct:history-recipient"),
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-002000000031"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        after_revocation.contains("does not exist"),
        "{after_revocation}"
    );

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_get_history_errors_are_stable_and_missing_equivalent() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let local_missing = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-002000000028"}),
        )
        .await
        .unwrap_err()
        .to_string();
    let member_missing = harness
        .call(
            &database,
            TestCaller::member("acct:outsider"),
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-002000000028"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        local_missing,
        "get_history: record 9c150000-0000-4000-8000-002000000028 does not exist"
    );
    assert_eq!(member_missing, local_missing);

    let whole_log = harness
        .call(&database, TestCaller::Local, "get_history", json!({}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        whole_log,
        "get_history: Postgres requires record_id; whole-log history is not qualified"
    );
    let malformed = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-002000000028","unexpected":true}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        malformed.contains("invalid arguments for get_history")
            && malformed.contains("unknown field `unexpected`"),
        "{malformed}"
    );

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_get_and_update_routes_return_exact_stable_errors() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let get_error = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-002000000054"],"include_interpretation":true}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        get_error,
        "postgres-server operation 'get_record interpretation projection' is unsupported by the qualified domain boundary"
    );
    let update_error = harness
        .call(
            &database,
            TestCaller::Local,
            "update_record",
            json!({"id":"9c150000-0000-4000-8000-002000000054","reason":"  "}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(update_error, "update_record: 'reason' must not be blank");
    postgres_delete_is_terminal_and_returns_stable_errors(&harness).await;
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_read_cancellation_releases_transactions_and_connections() {
    const CANCEL_ID: &str = "c0ffee00-0000-4000-8000-000000000001";
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":CANCEL_ID,"type":"Document","kind":"note","reason":"Create read cancellation fixture."}),
        )
        .await
        .unwrap();

    for (tool, table, query_signature, arguments) in [
        (
            "get_record",
            database.qualified_table("schema_config").unwrap(),
            "CREATE OR REPLACE TEMPORARY VIEW schema_config AS",
            json!({"ids":[CANCEL_ID]}),
        ),
        (
            "get_history",
            database.qualified_table("content_events").unwrap(),
            "SELECT seq, id, record_id, type, payload::text AS payload, actor, run_key, parent_key, intent, created_at::text AS created_at",
            json!({"record_id":CANCEL_ID}),
        ),
        (
            "describe_schema",
            database.qualified_table("schema_config").unwrap(),
            "CREATE OR REPLACE TEMPORARY VIEW schema_config AS",
            json!({}),
        ),
        (
            "search",
            database.qualified_table("records").unwrap(),
            "CREATE OR REPLACE TEMPORARY VIEW records AS",
            json!({"query":"cancellation"}),
        ),
    ] {
        let mut blocker = database.pool().begin().await.unwrap();
        sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
            .execute(&mut *blocker)
            .await
            .unwrap();
        let call_database = database.clone();
        let call = tokio::spawn(async move {
            let mut registry = ToolRegistry::new();
            register_surface_tools(&mut registry).unwrap();
            register_postgres_slice_tools(&mut registry).unwrap();
            registry
                .call_engine(
                    EngineHandle::Postgres(call_database),
                    Caller::local(),
                    tool,
                    arguments,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND position($1 in query)>0 AND position($2 in query)>0)",
                )
                .bind(query_signature)
                .bind(table.rsplit('.').next().unwrap_or(&table))
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
        .unwrap_or_else(|_| panic!("{tool} did not reach its exact blocked read query"));
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        blocker.rollback().await.unwrap();
        let reused = harness
            .call(
                &database,
                TestCaller::Local,
                tool,
                match tool {
                    "get_record" => json!({"ids":[CANCEL_ID]}),
                    "get_history" => json!({"record_id":CANCEL_ID}),
                    "describe_schema" => json!({}),
                    "search" => json!({"query":"cancellation"}),
                    _ => unreachable!(),
                },
            )
            .await
            .unwrap();
        assert!(reused.is_object());
    }
    let records = database.qualified_table("records").unwrap();
    for (tool, query_signature, arguments) in [
        (
            "get_structure",
            "CREATE OR REPLACE TEMPORARY VIEW records",
            json!({"root_id":CANCEL_ID,"max_depth":0}),
        ),
        (
            "get_dashboard",
            "CREATE OR REPLACE TEMPORARY VIEW records",
            json!({"scope":CANCEL_ID}),
        ),
        (
            "render_record",
            "CREATE OR REPLACE TEMPORARY VIEW records",
            json!({"id":CANCEL_ID}),
        ),
    ] {
        let mut blocker = database.pool().begin().await.unwrap();
        sqlx::query(&format!("LOCK TABLE {records} IN ACCESS EXCLUSIVE MODE"))
            .execute(&mut *blocker)
            .await
            .unwrap();
        let call_database = database.clone();
        let call_arguments = arguments.clone();
        let call = tokio::spawn(async move {
            let mut registry = ToolRegistry::new();
            register_surface_tools(&mut registry).unwrap();
            register_postgres_slice_tools(&mut registry).unwrap();
            registry
                .call_engine(
                    EngineHandle::Postgres(call_database),
                    Caller::local(),
                    tool,
                    call_arguments,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND position($1 in query)>0)",
                )
                .bind(query_signature)
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
        .unwrap_or_else(|_| panic!("{tool} did not reach its exact blocked portable view query"));
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        blocker.rollback().await.unwrap();
        assert!(harness
            .call(&database, TestCaller::Local, tool, arguments)
            .await
            .unwrap()
            .is_object());
    }
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_unauthorized_derived_records_are_missing_equivalent() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000027","type":"Document","kind":"note","reason":"Create a private derived fixture."}),
        )
        .await
        .unwrap();
    let records = database.qualified_table("records").unwrap();
    let policies = database.qualified_table("record_policies").unwrap();
    let entries = database.qualified_table("policy_entries").unwrap();
    let mut tx = database.pool().begin().await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO {policies}(record_id) VALUES('9c150000-0000-4000-8000-002000000027')"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET record_type='Annotation',kind='comment',policy_anchor_id='9c150000-0000-4000-8000-002000000027' WHERE id='9c150000-0000-4000-8000-002000000027'"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES('9c150000-0000-4000-8000-002000000027','account','acct:owner','allow','view')"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let caller = TestCaller::member("acct:outsider");
    let records = harness
        .call(
            &database,
            caller.clone(),
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-002000000027","9c150000-0000-4000-8000-002000000026"]}),
        )
        .await
        .unwrap();
    assert_eq!(records["records"][0]["status"], "not_found");
    assert_eq!(records["records"][1]["status"], "not_found");
    for id in [
        "9c150000-0000-4000-8000-002000000027",
        "9c150000-0000-4000-8000-002000000026",
    ] {
        let error = harness
            .call(
                &database,
                caller.clone(),
                "get_history",
                json!({"record_id":id}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exist"), "{error}");
        assert!(!error.contains("derived artifact"), "{error}");
    }

    let authorized = harness
        .call(
            &database,
            TestCaller::member("acct:owner"),
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-002000000027"]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(authorized.contains("derived artifact authorization not qualified"));

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_get_record_uses_one_snapshot_across_ids_policy_and_facets() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    for id in [
        "9c150000-0000-4000-8000-002000000052",
        "9c150000-0000-4000-8000-002000000053",
    ] {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","body":"before","reason":"Create multi-id snapshot fixture."}),
            )
            .await
            .unwrap();
    }
    let records = database.qualified_table("records").unwrap();
    let policies = database.qualified_table("record_policies").unwrap();
    let entries = database.qualified_table("policy_entries").unwrap();
    let facets = database.qualified_table("facet_values").unwrap();
    let mut setup = database.pool().begin().await.unwrap();
    for id in [
        "9c150000-0000-4000-8000-002000000052",
        "9c150000-0000-4000-8000-002000000053",
    ] {
        sqlx::query(&format!("INSERT INTO {policies}(record_id) VALUES($1)"))
            .bind(id)
            .execute(&mut *setup)
            .await
            .unwrap();
        sqlx::query(&format!(
            "UPDATE {records} SET policy_anchor_id=$1 WHERE id=$1"
        ))
        .bind(id)
        .execute(&mut *setup)
        .await
        .unwrap();
        sqlx::query(&format!("INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES($1,'account','acct:snapshot','allow','view')"))
            .bind(id)
            .execute(&mut *setup)
            .await
            .unwrap();
    }
    setup.commit().await.unwrap();

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {facets} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let read_database = database.clone();
    let read = tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_postgres_slice_tools(&mut registry).unwrap();
        registry
            .call_engine(
                EngineHandle::Postgres(read_database),
                Caller::authenticated("acct:snapshot")
                    .with_hosting_context("snapshot", "snapshot-database")
                    .with_hosting_owner(false),
                "get_record",
                json!({"ids":["9c150000-0000-4000-8000-002000000052","9c150000-0000-4000-8000-002000000053"]}),
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%facet_values%')",
            )
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
    .expect("get_record did not reach its first facet projection read");

    let mut mutation = database.pool().begin().await.unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET body='after' WHERE id='9c150000-0000-4000-8000-002000000053'"
    ))
    .execute(&mut *mutation)
    .await
    .unwrap();
    sqlx::query(&format!(
        "DELETE FROM {entries} WHERE subject_id='acct:snapshot'"
    ))
    .execute(&mut *mutation)
    .await
    .unwrap();
    mutation.commit().await.unwrap();
    blocker.commit().await.unwrap();

    let snapshot = read.await.unwrap().unwrap();
    assert_eq!(snapshot["records"][0]["status"], "found");
    assert_eq!(snapshot["records"][1]["status"], "found");
    assert_eq!(snapshot["records"][1]["body"], "before");
    let after = harness
        .call(
            &database,
            TestCaller::member("acct:snapshot"),
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-002000000052","9c150000-0000-4000-8000-002000000053"]}),
        )
        .await
        .unwrap();
    assert_eq!(after["records"][0]["status"], "not_found");
    assert_eq!(after["records"][1]["status"], "not_found");

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_link_mutation_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::link_mutation(&harness, &database).await.unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_authoritative_replay_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::replay(&harness, &database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_query_sql_full_boundary_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    for (person_id, name) in [
        ("9c150000-0000-4000-8000-002000000034", "Alice"),
        ("9c150000-0000-4000-8000-002000000035", "Bea"),
    ] {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id": person_id,
                    "type": "Entity",
                    "kind": "person",
                    "name": name,
                    "reason": "Create a query_sql principal fixture."
                }),
            )
            .await
            .unwrap();
    }
    harness
        .provision_member(
            &database,
            "9c150000-0000-4000-8000-002000000034",
            "acct:alice",
            "principal:alice",
        )
        .await
        .unwrap();
    harness
        .provision_member(
            &database,
            "9c150000-0000-4000-8000-002000000035",
            "acct:bea",
            "principal:bea",
        )
        .await
        .unwrap();
    for (record_id, account_id) in [
        ("9c150000-0000-4000-8000-100000000001", "acct:alice"),
        ("9c150000-0000-4000-8000-100000000003", "acct:bea"),
    ] {
        harness
            .call(
                &database,
                TestCaller::Member {
                    account_id: account_id.into(),
                },
                "create_record",
                json!({
                    "id":record_id,"type":"Document","kind":"note","name":record_id,
                    "reason":"Create an isolated query_sql principal fixture."
                }),
            )
            .await
            .unwrap();
        let policies = database.qualified_table("record_policies").unwrap();
        let entries = database.qualified_table("policy_entries").unwrap();
        let records = database.qualified_table("records").unwrap();
        let mut tx = database.pool().begin().await.unwrap();
        sqlx::query(&format!("INSERT INTO {policies}(record_id) VALUES($1)"))
            .bind(record_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(&format!(
            "UPDATE {records} SET policy_anchor_id=$1 WHERE id=$1"
        ))
        .bind(record_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(&format!("INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES($1,'account',$2,'allow','view')"))
            .bind(record_id)
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    let query = |sql: &str| QuerySqlRequest {
        sql: sql.into(),
        parameters: vec![],
    };
    // The `...-100` id block is the load-bearing part of these two fixtures'
    // ids: it replaces the old `private:` slug prefix, so the LIKE below still
    // selects exactly the per-account private records and nothing else.
    let alice = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT id FROM records WHERE id LIKE '9c150000-0000-4000-8000-100%' ORDER BY id"),
    )
    .await
    .unwrap();
    let bea = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:bea"),
        query("SELECT id FROM records WHERE id LIKE '9c150000-0000-4000-8000-100%' ORDER BY id"),
    )
    .await
    .unwrap();
    assert_eq!(
        alice.rows,
        [json!({"id":"9c150000-0000-4000-8000-100000000001"})]
    );
    assert_eq!(
        bea.rows,
        [json!({"id":"9c150000-0000-4000-8000-100000000003"})]
    );
    let registered = harness
        .call(
            &database,
            TestCaller::Member {
                account_id: "acct:alice".into(),
            },
            "query_sql",
            json!({"sql":"SELECT id FROM records WHERE id='9c150000-0000-4000-8000-100000000001'"}),
        )
        .await
        .unwrap();
    assert_eq!(
        registered["rows"],
        json!([{"id":"9c150000-0000-4000-8000-100000000001"}])
    );
    let engine_info = harness
        .call(&database, TestCaller::Local, "engine_info", json!({}))
        .await
        .unwrap();
    assert_eq!(engine_info["storage_profile"]["revision"], 5);

    let events = database.qualified_table("content_events").unwrap();
    sqlx::query(&format!("INSERT INTO {events}(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES (100,'observation:old','9c150000-0000-4000-8000-100000000001','facet.set',$1::jsonb,'acct:alice','2026-01-03T00:00:00Z',1,'legacy_unknown'),(101,'observation:correction','9c150000-0000-4000-8000-100000000001','facet.set',$2::jsonb,'acct:alice','2026-01-02T00:00:00Z',1,'legacy_unknown'),(102,'internal:later','9c150000-0000-4000-8000-100000000001','reconciliation.recorded.v1','{{}}'::jsonb,'acct:alice','2026-01-09T00:00:00Z',1,'legacy_unknown')"))
        .bind(json!({"key":"score","value":"10","as_of":"2026-01-01T00:00:00Z"}).to_string())
        .bind(json!({"key":"score","value":"11","as_of":"2026-01-01T00:00:00Z"}).to_string())
        .execute(database.pool())
        .await
        .unwrap();
    let derived = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT value,op,as_of,event_seq FROM facet_observations WHERE record_id='9c150000-0000-4000-8000-100000000001' AND key='score'"),
    )
    .await
    .unwrap();
    assert_eq!(
        derived.rows,
        [json!({
            "value":"11","op":"set","as_of":"2026-01-01T00:00:00Z","event_seq":101
        })]
    );
    let current_facet = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT value,value_num,vocab_ref,created_at FROM facet_values WHERE record_id='9c150000-0000-4000-8000-100000000001' AND key='score'"),
    )
    .await
    .unwrap();
    assert_eq!(current_facet.rows.len(), 1);
    assert_eq!(current_facet.rows[0]["value"], "11");
    assert_eq!(current_facet.rows[0]["value_num"], 11.0);
    assert_eq!(current_facet.rows[0]["vocab_ref"], serde_json::Value::Null);
    assert_eq!(current_facet.rows[0]["created_at"], "2026-01-03T00:00:00Z");
    let activity = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT last_activity_at,updated_at FROM records WHERE id='9c150000-0000-4000-8000-100000000001'"),
    )
    .await
    .unwrap();
    assert_eq!(activity.rows[0]["last_activity_at"], "2026-01-02T00:00:00Z");
    assert_ne!(
        activity.rows[0]["last_activity_at"],
        activity.rows[0]["updated_at"]
    );

    let records = database.qualified_table("records").unwrap();
    let links = database.qualified_table("links").unwrap();
    let facets = database.qualified_table("facet_values").unwrap();
    let blobs = database.qualified_table("blobs").unwrap();
    sqlx::query(&format!(
        "INSERT INTO {records}(id,record_type,kind,name,policy_anchor_id,deleted_at,created_at,updated_at) VALUES \
         ('9c150000-0000-4000-8000-200000000002','Document','attachment','visible attachment',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000001','Annotation','comment','visible annotation',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000003','Annotation','attribution','hidden attribution',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000008','Annotation','comment','missing bearer',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000009','Annotation','comment','multiple bearer',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000011','Annotation','comment','tomb bearer',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000010','Document','note','deleted bearer','9c150000-0000-4000-8000-200000000010','2026-01-02T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000004','Annotation','comment','cycle a',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000005','Annotation','comment','cycle b',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000012','Entity','semantic-unit','unit','9c150000-0000-4000-8000-100000000001',NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000006','Annotation','comment','derived unit',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'), \
         ('9c150000-0000-4000-8000-200000000007','Document','attachment','hidden attachment',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {links}(id,source_id,target_id,relationship,created_at) VALUES \
         ('fixture:link:attachment','9c150000-0000-4000-8000-200000000002','9c150000-0000-4000-8000-100000000001','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:annotation','9c150000-0000-4000-8000-200000000001','9c150000-0000-4000-8000-100000000001','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:attribution','9c150000-0000-4000-8000-200000000003','9c150000-0000-4000-8000-100000000001','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:multiple:a','9c150000-0000-4000-8000-200000000009','9c150000-0000-4000-8000-100000000001','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:multiple:b','9c150000-0000-4000-8000-200000000009','9c150000-0000-4000-8000-100000000003','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:tomb','9c150000-0000-4000-8000-200000000011','9c150000-0000-4000-8000-200000000010','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:cycle-a','9c150000-0000-4000-8000-200000000004','9c150000-0000-4000-8000-200000000005','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:cycle-b','9c150000-0000-4000-8000-200000000005','9c150000-0000-4000-8000-200000000004','part_of','2026-01-01T00:00:00Z'), \
         ('fixture:link:unit','9c150000-0000-4000-8000-200000000006','9c150000-0000-4000-8000-200000000012','part_of','2026-01-01T00:00:00Z')"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {events}(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES \
         (1000,'fixture:event:attribution','9c150000-0000-4000-8000-200000000003','attribution.asserted.v1','{{}}'::jsonb,'acct:alice','2026-01-01T00:00:00Z',1,'legacy_unknown'), \
         (1001,'fixture:event:attribution-facet','9c150000-0000-4000-8000-200000000003','facet.set','{{\"key\":\"score\",\"value\":\"99\"}}'::jsonb,'acct:alice','2026-01-01T00:00:00Z',1,'legacy_unknown')"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {records}(id,record_type,kind,name,created_at,updated_at) \
         SELECT '9c150000-0000-4000-8000-2009'||lpad(series::text,8,'0'),'Annotation','comment','depth', \
                '2026-01-01T00:00:00Z','2026-01-01T00:00:00Z' \
         FROM generate_series(0,100) series"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {links}(id,source_id,target_id,relationship,created_at) \
         SELECT 'fixture:link:depth:'||series,'9c150000-0000-4000-8000-2009'||lpad(series::text,8,'0'),'9c150000-0000-4000-8000-2009'||lpad((series+1)::text,8,'0'),'part_of','2026-01-01T00:00:00Z'::timestamptz \
         FROM generate_series(0,99) series \
         UNION ALL SELECT 'fixture:link:depth:100','9c150000-0000-4000-8000-200900000100','9c150000-0000-4000-8000-100000000001','part_of','2026-01-01T00:00:00Z'::timestamptz"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {blobs}(id,bytes,mime,size_bytes,sha256,original_filename,created_at) VALUES \
         ('blob:visible',decode('00ff','hex'),'application/octet-stream',2,$1,'visible.bin','2026-01-01T00:00:00Z'), \
         ('blob:hidden',decode('01','hex'),'application/octet-stream',1,$2,'hidden.bin','2026-01-01T00:00:00Z')"
    ))
    .bind("0".repeat(64))
    .bind("1".repeat(64))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {facets}(record_id,key,value) VALUES \
         ('9c150000-0000-4000-8000-200000000002','blob_ref',to_jsonb('blob:visible'::text)), \
         ('9c150000-0000-4000-8000-200000000007','blob_ref',to_jsonb('blob:hidden'::text))"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    let derived_visibility = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        // Id shape is load-bearing here. The derived fixtures live in the
        // `...-200` block and the 101-record depth chain in the nested
        // `...-2009` sub-block, so this keeps the old
        // `LIKE 'fixture:%' AND NOT LIKE 'fixture:depth:%'` selection exactly,
        // and `ORDER BY id` keeps its old alphabetical result order.
        query("SELECT id FROM records WHERE id LIKE '9c150000-0000-4000-8000-200%' AND id NOT LIKE '9c150000-0000-4000-8000-2009%' ORDER BY id"),
    )
    .await
    .unwrap();
    assert_eq!(
        derived_visibility.rows,
        [
            json!({"id":"9c150000-0000-4000-8000-200000000001"}),
            json!({"id":"9c150000-0000-4000-8000-200000000002"})
        ]
    );
    for sql in [
        "SELECT id FROM records WHERE id='9c150000-0000-4000-8000-200000000003'",
        "SELECT id FROM content_events WHERE record_id='9c150000-0000-4000-8000-200000000003'",
        "SELECT id FROM links WHERE source_id='9c150000-0000-4000-8000-200000000003'",
        "SELECT record_id FROM facet_values WHERE record_id='9c150000-0000-4000-8000-200000000003'",
        "SELECT record_id FROM facet_observations WHERE record_id='9c150000-0000-4000-8000-200000000003'",
    ] {
        for caller in [Caller::authenticated("acct:alice"), Caller::local()] {
            assert!(
                qualification_query_sql(database.clone(), caller, query(sql))
                    .await
                    .unwrap()
                    .rows
                    .is_empty(),
                "attribution leaked through PostgreSQL query_sql: {sql}"
            );
        }
    }
    assert!(
        qualification_query_sql(
            database.clone(),
            Caller::authenticated("acct:alice"),
            query("SELECT id FROM records WHERE id='9c150000-0000-4000-8000-200900000000'"),
        )
        .await
        .unwrap()
        .rows
        .is_empty(),
        "a bearer more than the canonical edge limit away must be invisible"
    );
    assert_eq!(
        qualification_query_sql(
            database.clone(),
            Caller::authenticated("acct:alice"),
            query("SELECT id,bytes FROM blobs ORDER BY id"),
        )
        .await
        .unwrap()
        .rows,
        [json!({"id":"blob:visible","bytes":"AP8="})]
    );

    let typed = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        QuerySqlRequest {
            sql: "SELECT $1 AS boolean_value,$2 AS integer_value,$3 AS real_value,$4 AS text_value,$5 AS bytes_value,$6 AS json_value,$7 AS timestamp_value".into(),
            parameters: vec![
                QuerySqlParameter::Boolean { value: Some(true) },
                QuerySqlParameter::Integer { value: Some(i64::MAX.to_string()) },
                QuerySqlParameter::Real { value: Some(1.5) },
                QuerySqlParameter::Text { value: Some("native".into()) },
                QuerySqlParameter::Bytes { value: Some("AP8=".into()) },
                QuerySqlParameter::Json { value: Some(r#"{"stable":true}"#.into()) },
                QuerySqlParameter::Timestamp { value: Some("2026-08-10T12:00:00Z".into()) },
            ],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        typed.rows,
        [json!({
            "boolean_value":true,
            "integer_value":i64::MAX,
            "real_value":1.5,
            "text_value":"native",
            "bytes_value":"AP8=",
            "json_value":r#"{"stable": true}"#,
            "timestamp_value":"2026-08-10T12:00:00Z"
        })]
    );
    let huge_json = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        QuerySqlRequest {
            sql: "SELECT $1 AS value".into(),
            parameters: vec![QuerySqlParameter::Json {
                value: Some(r#"{"huge":1234567890123456789012345678901234567890}"#.into()),
            }],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        huge_json.rows[0]["value"],
        r#"{"huge": 1234567890123456789012345678901234567890}"#
    );
    let vocabularies = database.qualified_table("vocabularies").unwrap();
    let vocabulary_values = database.qualified_table("vocabulary_values").unwrap();
    let schema_config = database.qualified_table("schema_config").unwrap();
    sqlx::query(&format!(
        "INSERT INTO {vocabularies}(id,name,created_at) VALUES('fixture:vocab','Fixture vocabulary','2026-01-01T00:00:00Z') ON CONFLICT DO NOTHING"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {vocabulary_values}(id,vocabulary_id,value,status,ordinal,terminality,metadata) VALUES('fixture:vocab:value','fixture:vocab','fixture','active',1,'open','{{}}'::jsonb) ON CONFLICT DO NOTHING"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {schema_config}(id,layer,name,data,created_at) VALUES('fixture:config','user','Fixture config','{{}}','2026-01-01T00:00:00Z') ON CONFLICT DO NOTHING"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    let policies = database.qualified_table("record_policies").unwrap();
    let entries = database.qualified_table("policy_entries").unwrap();
    sqlx::query(&format!(
        "INSERT INTO {policies}(record_id) VALUES('9c150000-0000-4000-8000-002000000034') ON CONFLICT DO NOTHING"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET policy_anchor_id='9c150000-0000-4000-8000-002000000034' WHERE id='9c150000-0000-4000-8000-002000000034'"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES('9c150000-0000-4000-8000-002000000034','account','acct:alice','allow','view') ON CONFLICT DO NOTHING"
    ))
    .execute(database.pool())
    .await
    .unwrap();

    let sqlite = create_database(":memory:").await.unwrap();
    sqlx::raw_sql(
        "INSERT INTO records(id,type,kind,name,policy_anchor_id,created_at,updated_at,last_activity_at) VALUES
         ('9c150000-0000-4000-8000-002000000034','Entity','person','Alice','9c150000-0000-4000-8000-002000000034','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
         ('9c150000-0000-4000-8000-100000000001','Document','note','9c150000-0000-4000-8000-100000000001','9c150000-0000-4000-8000-100000000001','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z'),
         ('9c150000-0000-4000-8000-200000000002','Document','attachment','visible attachment',NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
         INSERT INTO record_policies(record_id,created_at) VALUES
         ('9c150000-0000-4000-8000-002000000034','2026-01-01T00:00:00Z'),('9c150000-0000-4000-8000-100000000001','2026-01-01T00:00:00Z');
         INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES
         ('9c150000-0000-4000-8000-002000000034','account','acct:alice','allow','view'),('9c150000-0000-4000-8000-100000000001','account','acct:alice','allow','view');
         INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('9c150000-0000-4000-8000-002000000034','account','acct:alice',1);
         INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES
         (100,'observation:old','9c150000-0000-4000-8000-100000000001','facet.set','{\"key\":\"score\",\"value\":\"10\",\"as_of\":\"2026-01-01T00:00:00Z\"}','acct:alice','2026-01-03T00:00:00Z',1,'legacy_unknown'),
         (101,'observation:correction','9c150000-0000-4000-8000-100000000001','facet.set','{\"key\":\"score\",\"value\":\"11\",\"as_of\":\"2026-01-01T00:00:00Z\"}','acct:alice','2026-01-02T00:00:00Z',1,'legacy_unknown');
         INSERT INTO links(id,source_id,target_id,relationship,created_at) VALUES('fixture:link:attachment','9c150000-0000-4000-8000-200000000002','9c150000-0000-4000-8000-100000000001','part_of','2026-01-01T00:00:00Z');
         INSERT INTO facet_values(id,record_id,key,value,created_at) VALUES('fv:9c150000-0000-4000-8000-100000000001:score','9c150000-0000-4000-8000-100000000001','score','11','2026-01-03T00:00:00Z'),('fv:9c150000-0000-4000-8000-200000000002:blob_ref','9c150000-0000-4000-8000-200000000002','blob_ref','blob:visible','2026-01-01T00:00:00Z');
         INSERT INTO facet_observations(id,record_id,key,value,op,as_of,observed_at,event_seq) VALUES('fo:9c150000-0000-4000-8000-100000000001:score:2026-01-01T00:00:00Z','9c150000-0000-4000-8000-100000000001','score','11','set','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',101);
         INSERT INTO blobs(id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,created_at) VALUES('blob:visible',X'00ff','application/octet-stream',2,'0000000000000000000000000000000000000000000000000000000000000000','visible.bin','inline','2026-01-01T00:00:00Z');
         INSERT INTO vocabularies(id,name,created_at) VALUES('fixture:vocab','Fixture vocabulary','2026-01-01T00:00:00Z');
         INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) VALUES('fixture:vocab:value','fixture:vocab','fixture','active',1,'open','{}');
         INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('fixture:config','user','Fixture config','{}','2026-01-01T00:00:00Z');",
    )
    .execute(sqlite.qualification_write_pool())
    .await
    .unwrap();
    let parity_queries = [
        (
            "records",
            "SELECT * FROM records WHERE id='9c150000-0000-4000-8000-200000000002'",
        ),
        (
            "content_events",
            "SELECT local_seq,id,record_id,type,created_at FROM content_events WHERE id IN ('observation:old','observation:correction') ORDER BY local_seq",
        ),
        (
            "links",
            "SELECT id,source_id,target_id,relationship,note,created_at FROM links WHERE id='fixture:link:attachment'",
        ),
        (
            "facet_values",
            "SELECT id,record_id,key,value,value_num,vocab_ref,created_at FROM facet_values WHERE id='fv:9c150000-0000-4000-8000-100000000001:score'",
        ),
        (
            "facet_observations",
            "SELECT id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq FROM facet_observations WHERE id='fo:9c150000-0000-4000-8000-100000000001:score:2026-01-01T00:00:00Z'",
        ),
        (
            "bindings",
            "SELECT record_id,system,identifier,CASE WHEN is_canonical THEN 1 ELSE 0 END AS is_canonical,url,etag,last_seen_at FROM bindings WHERE record_id='9c150000-0000-4000-8000-002000000034'",
        ),
        (
            "blobs",
            "SELECT id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref,created_at FROM blobs WHERE id='blob:visible'",
        ),
        (
            "vocabularies",
            "SELECT id,name,created_at FROM vocabularies WHERE id='fixture:vocab'",
        ),
        (
            "vocabulary_values",
            "SELECT id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of FROM vocabulary_values WHERE id='fixture:vocab:value'",
        ),
        (
            "schema_config",
            "SELECT id,layer,name,data,applies_to_collection_id,version_lineage,created_at FROM schema_config WHERE id='fixture:config'",
        ),
    ];
    let postgres_relations = LOGICAL_RELATIONS
        .iter()
        .filter(|relation| relation.profiles.contains(&"postgres-server"))
        .collect::<Vec<_>>();
    assert_eq!(parity_queries.len(), postgres_relations.len());
    for (relation, (relation_name, sql)) in postgres_relations.into_iter().zip(parity_queries) {
        assert_eq!(relation_name, relation.name);
        let postgres_result = qualification_query_sql(
            database.clone(),
            Caller::authenticated("acct:alice"),
            query(sql),
        )
        .await
        .unwrap();
        let sqlite_result = sqlite_query_sql(&sqlite, &Caller::authenticated("acct:alice"), sql)
            .await
            .unwrap();
        assert!(!postgres_result.rows.is_empty(), "{}", relation.name);
        assert_eq!(
            postgres_result.columns, relation.columns,
            "{}",
            relation.name
        );
        assert_eq!(
            postgres_result.columns, sqlite_result.columns,
            "{}",
            relation.name
        );
        assert_eq!(
            postgres_result.rows, sqlite_result.rows,
            "{}",
            relation.name
        );
    }
    sqlite.close().await;

    let duplicate = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT 1 AS duplicate,2 AS duplicate"),
    )
    .await
    .unwrap_err();
    assert!(duplicate.to_string().contains("[duplicate_columns]"));
    let too_many_columns = (0..=MAX_COLUMNS)
        .map(|index| format!("{index} AS c{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let columns_error = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query(&format!("SELECT {too_many_columns}")),
    )
    .await
    .unwrap_err();
    assert!(columns_error.to_string().contains("[result_too_large]"));

    sqlx::query(&format!(
        "INSERT INTO {events}(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) \
         SELECT series,'load:'||series,'9c150000-0000-4000-8000-100000000001','record.updated','{{}}'::jsonb,'acct:alice','2026-01-04T00:00:00Z'::timestamptz,1,'legacy_unknown' \
         FROM generate_series(10000,11000) series"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    let total_result_cell = "x".repeat(MAX_CELL_ENCODED_BYTES / 2);
    assert!(serde_json::to_vec(&total_result_cell).unwrap().len() < MAX_CELL_ENCODED_BYTES);
    assert!(
        (serde_json::to_vec(&total_result_cell).unwrap().len() + 12) * MAX_ROWS
            > MAX_RESULT_ENCODED_BYTES
    );
    let total_result_rows =
        MAX_RESULT_ENCODED_BYTES / (serde_json::to_vec(&total_result_cell).unwrap().len() + 12) + 1;
    assert!(total_result_rows < MAX_ROWS);
    let total_result_values = std::iter::repeat_n("($1)", total_result_rows)
        .collect::<Vec<_>>()
        .join(",");
    let total_result_error = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        QuerySqlRequest {
            sql: format!(
                "SELECT value FROM (VALUES {total_result_values}) AS bounded_result(value)"
            ),
            parameters: vec![QuerySqlParameter::Text {
                value: Some(total_result_cell),
            }],
        },
    )
    .await
    .unwrap_err();
    assert!(
        total_result_error
            .to_string()
            .contains("[result_too_large]"),
        "{total_result_error}"
    );
    let capped = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT local_seq FROM content_events ORDER BY local_seq"),
    )
    .await
    .unwrap();
    assert_eq!(capped.row_count, MAX_ROWS);
    assert!(capped.truncated);
    let timeout = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT count(*) FROM content_events a CROSS JOIN content_events b CROSS JOIN content_events c"),
    )
    .await
    .unwrap_err();
    assert!(timeout.to_string().contains("[timeout]"), "{timeout}");
    assert_eq!(
        qualification_query_sql(
            database.clone(),
            Caller::authenticated("acct:alice"),
            query("SELECT id FROM records WHERE id='9c150000-0000-4000-8000-100000000001'"),
        )
        .await
        .unwrap()
        .rows,
        [json!({"id":"9c150000-0000-4000-8000-100000000001"})]
    );
    let (cancelled_pid_sender, cancelled_pid_receiver) = tokio::sync::oneshot::channel();
    let cancelled_database = database.clone();
    let cancelled = tokio::spawn(async move {
        qualification_query_sql_with_backend_pid(
            cancelled_database,
            Caller::authenticated("acct:alice"),
            query("SELECT count(*) FROM content_events a CROSS JOIN content_events b CROSS JOIN content_events c"),
            cancelled_pid_sender,
        )
        .await
    });
    let cancelled_pid =
        tokio::time::timeout(std::time::Duration::from_secs(5), cancelled_pid_receiver)
            .await
            .expect("cancelled query did not reach its physical backend")
            .expect("cancelled query dropped before reporting its physical backend");
    let cancelled_backend_was_live: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
            .bind(cancelled_pid)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(cancelled_backend_was_live);
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert_postgres_backend_disappears(&database, cancelled_pid).await;

    let (follow_up_pid_sender, follow_up_pid_receiver) = tokio::sync::oneshot::channel();
    let follow_up = qualification_query_sql_with_backend_pid(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT id FROM records WHERE id='9c150000-0000-4000-8000-100000000001'"),
        follow_up_pid_sender,
    );
    let observe_follow_up = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), follow_up_pid_receiver)
            .await
            .expect("clean follow-up did not reach its physical backend")
            .expect("clean follow-up dropped before reporting its physical backend")
    };
    let (follow_up, follow_up_pid) = tokio::join!(follow_up, observe_follow_up);
    assert_ne!(
        cancelled_pid, follow_up_pid,
        "the clean follow-up must not reuse the cancelled physical backend"
    );
    assert_eq!(
        follow_up.unwrap().rows,
        [json!({"id":"9c150000-0000-4000-8000-100000000001"})]
    );

    let unsupported_array_request = query("SELECT ARRAY[1,2] AS unsupported_array");
    native_ce::postgres::query_sql::validate(&unsupported_array_request).unwrap();
    let unsupported_array = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        unsupported_array_request,
    )
    .await
    .unwrap_err();
    assert_query_sql_error_category(&unsupported_array, "syntax_or_type");

    let invalid_parameters = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        QuerySqlRequest {
            sql: "SELECT 1".into(),
            parameters: vec![QuerySqlParameter::Text {
                value: Some("unused".into()),
            }],
        },
    )
    .await
    .unwrap_err();
    assert_query_sql_error_category(&invalid_parameters, "invalid_arguments");

    sqlx::query(&format!("UPDATE {records} SET body=$2 WHERE id=$1"))
        .bind("9c150000-0000-4000-8000-100000000001")
        .bind("x".repeat(MAX_CELL_ENCODED_BYTES + 1))
        .execute(database.pool())
        .await
        .unwrap();
    let cell_error = qualification_query_sql(
        database.clone(),
        Caller::authenticated("acct:alice"),
        query("SELECT body FROM records WHERE id='9c150000-0000-4000-8000-100000000001'"),
    )
    .await
    .unwrap_err();
    assert!(cell_error.to_string().contains("[result_too_large]"));

    for (unsafe_sql, expected_category) in [
        ("SELECT * FROM pg_catalog.pg_roles", "unauthorized_relation"),
        ("SELECT current_setting('role')", "unsafe_statement"),
        ("SELECT * FROM public.records", "unauthorized_relation"),
    ] {
        let error = qualification_query_sql(
            database.clone(),
            Caller::authenticated("acct:alice"),
            query(unsafe_sql),
        )
        .await
        .unwrap_err();
        assert_query_sql_error_category(&error, expected_category);
    }
    let first_pid = database.qualification_query_backend_pid().await.unwrap();
    let second_pid = database.qualification_query_backend_pid().await.unwrap();
    assert_ne!(
        first_pid, second_pid,
        "query pool must physically discard every connection"
    );
    let role_flags = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool, bool)>(
        "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=$1",
    )
    .bind(database.query_role_name())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        role_flags,
        (false, false, false, false, false, false, false)
    );
    let membership = sqlx::query_as::<_, (bool, bool, bool)>(
        "SELECT membership.admin_option,membership.inherit_option,membership.set_option FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname=current_user",
    )
    .bind(database.query_role_name())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(membership, (false, false, true));

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_guarded_write_race_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::guarded_write_race(&harness, &database)
        .await
        .unwrap();
    postgres_delete_guarded_race_has_one_tombstone(&harness).await;
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_null_body_digest_guard_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::null_body_digest_guard(&harness, &database)
        .await
        .unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_timestamp_precondition_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::timestamp_precondition(&harness, &database)
        .await
        .unwrap();
    let live = database.logical_snapshot().await.unwrap();
    let record = live["content"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == "c07a0000-0000-4000-8000-000000000013")
        .unwrap();
    let created_at =
        chrono::DateTime::parse_from_rfc3339(record["created_at"].as_str().unwrap()).unwrap();
    let updated_at =
        chrono::DateTime::parse_from_rfc3339(record["updated_at"].as_str().unwrap()).unwrap();
    assert!(updated_at > created_at);
    // Replay equivalence now compares both timestamp fields above, so this is
    // an explicit live-vs-rebuilt assertion for the optimistic-write token.
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_logical_database_isolation_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    scenarios::logical_database_isolation(&harness)
        .await
        .unwrap();
    postgres_delete_is_logically_isolated(&harness).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_ddl_migration_and_pool_contract() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let search_path_before = current_search_path(&database).await.unwrap();

    assert_eq!(migration_version(&database).await.unwrap(), 6);
    assert_eq!(
        physical_tables(&database).await.unwrap(),
        [
            "authorization_revision",
            "binding_audit",
            "binding_systems",
            "bindings",
            "blobs",
            "content_event_causal_cutover",
            "content_event_causal_frontier",
            "content_event_sources",
            "content_events",
            "control_events",
            "control_projections",
            "database_identity",
            "database_identity_audit",
            "event_cursor",
            "facet_values",
            "instruction_bindings",
            "links",
            "log_cursors",
            "message_audience",
            "meta_events",
            "notification_candidate_events",
            "notification_candidates",
            "onboarding_programme_sources",
            "onboarding_programmes",
            "policy_entries",
            "policy_events",
            "record_policies",
            "records",
            "request_interactions",
            "run_contexts",
            "schema_config",
            "schema_migrations",
            "storage_portability_policy",
            "vocabularies",
            "vocabulary_values",
        ]
    );

    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000020",
                "type": "Document",
                "kind": "note",
                "name": "Qualified-table pool check",
                "reason": "Prove pooled connections do not depend on search_path."
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        current_search_path(&database).await.unwrap(),
        search_path_before,
        "the logical database must not leak session-local search_path state"
    );
    assert_eq!(event_sequences(&database).await.unwrap(), [1]);

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_legacy_v3_shape_never_reports_ready_under_the_v5_runtime() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let migrations = database.qualified_table("schema_migrations").unwrap();
    let binding_audit = database.qualified_table("binding_audit").unwrap();
    let mut tx = database.pool().begin().await.unwrap();
    sqlx::query(&format!("DELETE FROM {migrations} WHERE version IN (5,6)"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(&format!("INSERT INTO {migrations}(version) VALUES(3)"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(&format!(
        "DROP TRIGGER binding_audit_append_only ON {binding_audit}"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let health = database.health().await.unwrap();
    assert_eq!(health.observed_schema_version, Some(3));
    assert_eq!(health.expected_schema_version, 6);
    assert_eq!(health.schema_currency, PostgresSchemaCurrency::Behind);
    assert!(!health.ready);
    assert!(!health.write_ready);

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_policy_anchor_is_fail_closed_and_members_shape_is_guarded() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();

    let root = harness
        .call(
            &database,
            TestCaller::Member {
                account_id: "acct:any-member".into(),
            },
            "get_record",
            json!({"ids":["native:root"]}),
        )
        .await
        .unwrap();
    assert_eq!(root["records"][0]["status"], "found");

    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":"9c150000-0000-4000-8000-300000000004",
                "type":"Document",
                "kind":"note",
                "name":"Missing anchor",
                "reason":"Create a fail-closed authorization fixture."
            }),
        )
        .await
        .unwrap();
    let records = database.qualified_table("records").unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET policy_anchor_id=NULL WHERE id='9c150000-0000-4000-8000-300000000004'"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    let hidden = harness
        .call(
            &database,
            TestCaller::Member {
                account_id: "acct:any-member".into(),
            },
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-300000000004"]}),
        )
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    let malformed_for_trusted = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-300000000004"]}),
        )
        .await
        .unwrap_err();
    assert!(malformed_for_trusted
        .to_string()
        .contains("effective policy anchor"));

    for (suffix, entry) in [
        (
            "invalid-members",
            json!({"subject_kind":"members","subject_id":"not-native-members","effect":"allow","capability":"manage"}),
        ),
        (
            "deny",
            json!({"subject_kind":"account","subject_id":"acct:denied","effect":"deny","capability":"view"}),
        ),
        (
            "malformed",
            json!({"subject_kind":"account","subject_id":"acct:malformed","effect":"allow","capability":"view","unexpected":true}),
        ),
    ] {
        let invalid = database
            .append_policy_event(PostgresPolicyEvent {
                id: format!("policy:rejected:{suffix}"),
                record_id: "native:root".into(),
                event_type: "policy.replaced".into(),
                payload: Some(json!({"entries":[entry]})),
                actor: "contract:test".into(),
                reason: "Prove normalized policy shape fails closed.".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            })
            .await
            .unwrap_err();
        assert!(
            invalid
                .to_string()
                .contains("unsupported normalized policy entry")
                || invalid.to_string().contains("unknown field"),
            "{invalid}"
        );
    }
    assert!(database
        .authoritative_events(PostgresLogKind::Policy)
        .await
        .unwrap()
        .is_empty());

    for (id, home_id) in [
        ("9c150000-0000-4000-8000-300000000005", "native:root"),
        (
            "9c150000-0000-4000-8000-300000000002",
            "9c150000-0000-4000-8000-300000000005",
        ),
        (
            "9c150000-0000-4000-8000-300000000001",
            "9c150000-0000-4000-8000-300000000005",
        ),
        (
            "9c150000-0000-4000-8000-300000000003",
            "9c150000-0000-4000-8000-300000000001",
        ),
    ] {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id":id,"type":"Document","kind":"note","name":id,
                    "home_id":home_id,"reason":"Build a policy propagation fixture."
                }),
            )
            .await
            .unwrap();
    }
    let policy_payload = json!({"entries":[{
        "subject_kind":"account","subject_id":"acct:allowed","effect":"allow","capability":"view"
    }]});
    for (record_id, suffix) in [
        ("9c150000-0000-4000-8000-300000000001", "boundary"),
        ("9c150000-0000-4000-8000-300000000005", "parent"),
    ] {
        database
            .append_policy_event(PostgresPolicyEvent {
                id: format!("policy:event:{suffix}"),
                record_id: record_id.into(),
                event_type: "policy.replaced".into(),
                payload: Some(policy_payload.clone()),
                actor: "contract:test".into(),
                reason: "Prove nearest-anchor propagation.".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            })
            .await
            .unwrap();
    }
    let anchors: Vec<(String, Option<String>)> = sqlx::query_as(&format!(
        // The policy fixtures share the `...-300` id block, and are numbered in
        // their old alphabetical order so `ORDER BY id` still yields
        // boundary, child, grandchild, parent.
        "SELECT id,policy_anchor_id FROM {records} WHERE id LIKE '9c150000-0000-4000-8000-300%' AND id <> '9c150000-0000-4000-8000-300000000004' ORDER BY id"
    ))
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        anchors,
        [
            (
                "9c150000-0000-4000-8000-300000000001".into(),
                Some("9c150000-0000-4000-8000-300000000001".into())
            ),
            (
                "9c150000-0000-4000-8000-300000000002".into(),
                Some("9c150000-0000-4000-8000-300000000005".into())
            ),
            (
                "9c150000-0000-4000-8000-300000000003".into(),
                Some("9c150000-0000-4000-8000-300000000001".into())
            ),
            (
                "9c150000-0000-4000-8000-300000000005".into(),
                Some("9c150000-0000-4000-8000-300000000005".into())
            ),
        ]
    );
    database
        .append_policy_event(PostgresPolicyEvent {
            id: "policy:event:restore-parent".into(),
            record_id: "9c150000-0000-4000-8000-300000000005".into(),
            event_type: "policy.inheritance_restored".into(),
            payload: None,
            actor: "contract:test".into(),
            reason: "Restore the nearest parent anchor.".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .await
        .unwrap();
    let restored: Vec<(String, Option<String>)> = sqlx::query_as(&format!(
        "SELECT id,policy_anchor_id FROM {records} WHERE id IN ('9c150000-0000-4000-8000-300000000005','9c150000-0000-4000-8000-300000000002','9c150000-0000-4000-8000-300000000001','9c150000-0000-4000-8000-300000000003') ORDER BY id"
    ))
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        restored,
        [
            (
                "9c150000-0000-4000-8000-300000000001".into(),
                Some("9c150000-0000-4000-8000-300000000001".into())
            ),
            (
                "9c150000-0000-4000-8000-300000000002".into(),
                Some("native:root".into())
            ),
            (
                "9c150000-0000-4000-8000-300000000003".into(),
                Some("9c150000-0000-4000-8000-300000000001".into())
            ),
            (
                "9c150000-0000-4000-8000-300000000005".into(),
                Some("native:root".into())
            ),
        ]
    );

    for round in 0..8 {
        let parent = database.clone();
        let child = database.clone();
        let parent_payload = policy_payload.clone();
        let child_payload = policy_payload.clone();
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            tokio::try_join!(
                parent.append_policy_event(PostgresPolicyEvent {
                    id: format!("policy:race:parent:{round}"),
                    record_id: "9c150000-0000-4000-8000-300000000005".into(),
                    event_type: "policy.replaced".into(),
                    payload: Some(parent_payload),
                    actor: "contract:test".into(),
                    reason: "Exercise cursor-first parent locking.".into(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                }),
                child.append_policy_event(PostgresPolicyEvent {
                    id: format!("policy:race:child:{round}"),
                    record_id: "9c150000-0000-4000-8000-300000000002".into(),
                    event_type: "policy.replaced".into(),
                    payload: Some(child_payload),
                    actor: "contract:test".into(),
                    reason: "Exercise cursor-first child locking.".into(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                })
            )
        })
        .await
        .expect("concurrent parent/child policy writes must not deadlock")
        .unwrap();
    }

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_independent_logs_are_gapless_atomic_idempotent_and_replayable() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let now = chrono::Utc::now().to_rfc3339();

    let left = database.clone();
    let right = database.clone();
    let (left_origin, right_origin) = tokio::join!(
        left.ensure_database_identity("contract:test", "Mint the durable test origin."),
        right.ensure_database_identity("contract:test", "Mint the durable test origin.")
    );
    assert_eq!(left_origin.unwrap(), right_origin.unwrap());
    let identity_audit = database.qualified_table("database_identity_audit").unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {identity_audit}"))
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );

    let rejected = database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:rejected".into(),
            subject_id: "voc:rejected".into(),
            event_type: "unknown.meta.event".into(),
            payload: json!({}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap_err();
    assert!(rejected.to_string().contains("unknown Postgres meta event"));
    assert!(database
        .authoritative_events(PostgresLogKind::Meta)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        database
            .append_meta_event(PostgresMetaEvent {
                id: "meta:accepted".into(),
                subject_id: "voc:accepted".into(),
                event_type: "vocabulary.created".into(),
                payload: json!({"name":"Accepted"}),
                actor: Some("contract:test".into()),
                created_at: now.clone(),
            })
            .await
            .unwrap(),
        1
    );
    let phantom = database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:phantom".into(),
            subject_id: "voc:value:missing".into(),
            event_type: "vocab_value.promoted".into(),
            payload: json!({}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap_err();
    assert!(phantom.to_string().contains("matched no row"));
    database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:value:canonical".into(),
            subject_id: "voc:value:canonical".into(),
            event_type: "vocab_value.proposed".into(),
            payload: json!({"vocabulary_id":"voc:accepted","value":"canonical","gloss":null,"status":"active","ordinal":1.0,"terminality":"open","metadata":{}}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap();
    let invalid_terminality = database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:value:invalid-terminality".into(),
            subject_id: "voc:value:invalid-terminality".into(),
            event_type: "vocab_value.proposed".into(),
            payload: json!({"vocabulary_id":"voc:accepted","value":"invalid terminality","gloss":null,"status":"proposed","ordinal":3.0,"terminality":"eventually","metadata":{}}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap_err();
    assert!(
        invalid_terminality
            .to_string()
            .contains("vocabulary_values_terminality_check"),
        "{invalid_terminality}"
    );
    database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:value:alias".into(),
            subject_id: "voc:value:alias".into(),
            event_type: "vocab_value.proposed".into(),
            payload: json!({"vocabulary_id":"voc:accepted","value":"alias","gloss":null,"status":"proposed","ordinal":2.0,"terminality":"open","metadata":{}}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap();
    database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:value:aliased".into(),
            subject_id: "voc:value:alias".into(),
            event_type: "vocab_value.aliased".into(),
            payload: json!({"alias_of":"voc:value:canonical"}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap();
    database
        .append_meta_event(PostgresMetaEvent {
            id: "meta:value:promoted".into(),
            subject_id: "voc:value:alias".into(),
            event_type: "vocab_value.promoted".into(),
            payload: json!({}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap();
    let values = database.qualified_table("vocabulary_values").unwrap();
    let promoted: (String, Option<String>) = sqlx::query_as(&format!(
        "SELECT status,alias_of FROM {values} WHERE id='voc:value:alias'"
    ))
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(promoted, ("active".into(), None));

    let control = PostgresControlEvent {
        id: "control:accepted".into(),
        idempotency_key: "control:idempotency:accepted".into(),
        event_type: "member_context.provisioned".into(),
        schema_version: 1,
        aggregate_kind: "member_context".into(),
        aggregate_id: "acct:member".into(),
        actor: "contract:test".into(),
        run_key: Some("scout-chair-000001".into()),
        reason: "Prove control idempotency.".into(),
        payload: json!({"account_id":"acct:member","person_record_id":"native:root","root_record_id":"native:root","created_at":now.clone()}),
        created_at: now.clone(),
    };
    assert_eq!(
        database
            .append_control_event(control.clone())
            .await
            .unwrap(),
        1
    );
    let mut cross_run = control.clone();
    cross_run.id = "control:retry-generated-id".into();
    cross_run.run_key = Some("other-agent-000002".into());
    cross_run.created_at = (chrono::Utc::now() + chrono::Duration::seconds(1)).to_rfc3339();
    assert_eq!(database.append_control_event(cross_run).await.unwrap(), 1);

    for invalid in [
        PostgresControlEvent {
            id: "control:unknown".into(),
            idempotency_key: "control:idempotency:unknown".into(),
            event_type: "unknown.control".into(),
            ..control.clone()
        },
        PostgresControlEvent {
            id: "control:wrong-kind".into(),
            idempotency_key: "control:idempotency:wrong-kind".into(),
            aggregate_kind: "member".into(),
            ..control.clone()
        },
    ] {
        assert!(database.append_control_event(invalid).await.is_err());
    }

    let orphan_binding_change = PostgresControlEvent {
        id: "control:orphan-binding-change".into(),
        idempotency_key: "control:idempotency:orphan-binding-change".into(),
        event_type: "instruction_binding.changed".into(),
        schema_version: 1,
        aggregate_kind: "instruction_binding".into(),
        aggregate_id: "binding:missing".into(),
        actor: "contract:test".into(),
        run_key: None,
        reason: "Reject a change before creation.".into(),
        payload: json!({"id":"binding:missing","scope_kind":"database","scope_id":"native:root","source_record_id":"native:root","position":1,"enabled":true,"created_by":"contract:test","created_at":now.clone(),"updated_at":now.clone()}),
        created_at: now.clone(),
    };
    let changed_before_created = database
        .append_control_event(orphan_binding_change)
        .await
        .unwrap_err();
    assert!(
        changed_before_created
            .to_string()
            .contains("did not match exactly one projection row"),
        "{changed_before_created}"
    );

    let obligation_id =
        native_ce::control::member_obligation_aggregate_id("acct:missing", "programme:missing", 1);
    let progress_without_obligation = database
        .append_control_event(PostgresControlEvent {
            id: "control:orphan-progress".into(),
            idempotency_key: "control:idempotency:orphan-progress".into(),
            event_type: "member_obligation.progressed".into(),
            schema_version: 1,
            aggregate_kind: "member_obligation".into(),
            aggregate_id: obligation_id,
            actor: "contract:test".into(),
            run_key: None,
            reason: "Reject progress without a pending obligation.".into(),
            payload: json!({"account_id":"acct:missing","programme_id":"programme:missing","generation":1,"phase":"anchor_established","updated_at":now.clone(),"evidence":{"basis":"user_stated"},"resume_after":null,"artifact_id":null}),
            created_at: now.clone(),
        })
        .await
        .unwrap_err();
    assert!(
        progress_without_obligation
            .to_string()
            .contains("requires a pending obligation"),
        "{progress_without_obligation}"
    );

    let mut mismatch = control;
    mismatch.payload["root_record_id"] = json!("other-root");
    let mismatch = database.append_control_event(mismatch).await.unwrap_err();
    assert!(mismatch.to_string().contains("different immutable event"));
    assert_eq!(
        database
            .authoritative_events(PostgresLogKind::Control)
            .await
            .unwrap()
            .len(),
        1
    );
    let projections = database.qualified_table("control_projections").unwrap();
    let canonical_projection: serde_json::Value = sqlx::query_scalar(&format!(
        "SELECT payload FROM {projections} WHERE aggregate_kind='canonical_control' AND aggregate_id='state'"
    ))
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        canonical_projection["member_contexts"][0]["account_id"],
        "acct:member"
    );
    database.assert_replay_equivalent().await.unwrap();

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_blob_identity_binding_and_record_shapes_fail_closed() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let bytes = b"blob-one".to_vec();
    let digest = hex::encode(Sha256::digest(&bytes));
    let blob = PostgresBlob {
        id: "blob:one".into(),
        bytes: Some(bytes.clone()),
        mime: Some("text/plain".into()),
        size_bytes: bytes.len() as i64,
        sha256: digest,
        original_filename: Some("one.txt".into()),
        storage_tier: "inline".into(),
        external_ref: None,
    };
    let mut bad_digest = blob.clone();
    bad_digest.id = "blob:bad-digest".into();
    bad_digest.sha256 = "0".repeat(64);
    assert!(database
        .put_blob(&bad_digest)
        .await
        .unwrap_err()
        .to_string()
        .contains("does not match inline bytes"));
    database.put_blob(&blob).await.unwrap();
    database.put_blob(&blob).await.unwrap();
    let mut collision = blob.clone();
    collision.bytes = Some(b"blob-two".to_vec());
    collision.sha256 = hex::encode(Sha256::digest(collision.bytes.as_ref().unwrap()));
    assert!(database
        .put_blob(&collision)
        .await
        .unwrap_err()
        .to_string()
        .contains("different content"));

    for arguments in [
        json!({"id":"9c150000-0000-4000-8000-002000000050","type":"Unknown","kind":"note","reason":"Reject unknown type."}),
        json!({"id":"9c150000-0000-4000-8000-002000000049","type":"Document","kind":"note","persistence":"forever","reason":"Reject persistence."}),
        json!({"id":"9c150000-0000-4000-8000-002000000046","type":"Document","kind":"note","home_id":"9c150000-0000-4000-8000-002000000032","reason":"Reject missing home."}),
        json!({"id":"9c150000-0000-4000-8000-002000000048","type":"Document","kind":"note","owner_id":"9c150000-0000-4000-8000-002000000033","reason":"Reject missing owner."}),
        json!({"id":"9c150000-0000-4000-8000-002000000044","type":"Annotation","kind":"citation","reason":"Reject unqualified derived authorization."}),
        json!({"id":"9c150000-0000-4000-8000-002000000045","type":"Document","kind":"attachment","reason":"Reject unqualified attachment authorization."}),
    ] {
        assert!(harness
            .call(&database, TestCaller::Local, "create_record", arguments)
            .await
            .is_err());
    }
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000047","type":"Document","kind":"note","reason":"Create incompatible binding target."}),
        )
        .await
        .unwrap();
    assert!(database
        .provision_member(
            "9c150000-0000-4000-8000-002000000047",
            "acct:not-person",
            "principal:not-person"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("Entity/person"));
    assert!(database
        .provision_member("native:root", " ", "principal:bad")
        .await
        .is_err());

    let audit = database.qualified_table("binding_audit").unwrap();
    assert!(sqlx::query(&format!(
        "INSERT INTO {audit}(id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,created_at) VALUES('bad:audit','add','account','acct:bad','native:root','native:root',TRUE,TRUE,'contract:test','malformed',transaction_timestamp())"
    ))
    .execute(database.pool())
    .await
    .is_err());
    let identity_audit = database.qualified_table("database_identity_audit").unwrap();
    assert!(sqlx::query(&format!(
        "INSERT INTO {identity_audit}(id,action,new_origin_db_id,actor,reason,created_at) VALUES('bad:identity','mint','ndb_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','contract:test','malformed',transaction_timestamp())"
    ))
    .execute(database.pool())
    .await
    .is_err());

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_create_record_validates_ids_before_append() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let events = database.qualified_table("content_events").unwrap();
    let records = database.qualified_table("records").unwrap();
    let initial_events: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    let initial_records: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {records}"))
        .fetch_one(database.pool())
        .await
        .unwrap();

    let mut malformed = vec![
        "".to_string(),
        "two words".into(),
        " leading".into(),
        "trailing ".into(),
        "line\nbreak".into(),
        "record/slash".into(),
        "café".into(),
        // Kept in lockstep with the SQLite table in tests/governance/record_id_validation.rs.
        "a\"b\\c".into(),
    ];
    malformed.push("p".repeat(129));
    for id in malformed {
        let error = harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id":id, "type":"Document", "kind":"note",
                    "reason":"Reject a malformed Postgres record id."
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "record id must contain 1..=128 ASCII bytes using only [A-Za-z0-9._:-]"
        );
        let event_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
            .fetch_one(database.pool())
            .await
            .unwrap();
        let record_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {records}"))
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(
            (event_count, record_count),
            (initial_events, initial_records)
        );
    }

    let reserved = harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":"native:anything", "type":"Document", "kind":"note",
                "reason":"Reject a reserved Postgres record id."
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        reserved.to_string(),
        "record id prefix 'native:' is reserved for engine-owned records"
    );
    let event_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    let record_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {records}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        (event_count, record_count),
        (initial_events, initial_records)
    );

    // The 128-byte boundary used to be the widest accepted id. It satisfies the
    // shape gate and is rejected by the UUID rule instead, so the two errors
    // stay distinguishable. Kept in lockstep with the SQLite table in
    // tests/governance/record_id_validation.rs.
    let boundary = "p".repeat(128);
    let boundary_error = harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":boundary, "type":"Document", "kind":"note",
                "reason":"Reject the former Postgres record id boundary."
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        boundary_error.to_string(),
        "record id must be a canonical lowercase UUID of version 4 or 7"
    );

    let accepted = "9c150000-0000-4000-8000-009800000001";
    let created = harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":accepted, "type":"Document", "kind":"note",
                "reason":"Accept a canonical Postgres record id."
            }),
        )
        .await
        .unwrap();
    assert_eq!(created["id"], accepted);
    let before_retry_events: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert!(harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":accepted, "type":"Document", "kind":"note",
                "reason":"Retry the same Postgres record id."
            }),
        )
        .await
        .is_err());
    let after_retry_events: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(after_retry_events, before_retry_events);

    let generated = harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "type":"Document", "kind":"note",
                "reason":"Verify generated Postgres record id shape."
            }),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let uuid = uuid::Uuid::parse_str(&generated).unwrap();
    assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
    assert_eq!(uuid.hyphenated().to_string(), generated);

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_suggestion_authoring_retains_the_explicit_annotation_boundary() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "postgres:suggestion-unsupported",
                "type": "Annotation",
                "kind": "suggestion",
                "lifecycle": "open",
                "facets": { "proposal.precondition": "none" },
                "reason": "Pin the existing Postgres annotation boundary."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "create_record: derived artifact authorization is not qualified for Postgres"
    );
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_authoritative_logs_are_append_only_and_cursor_checked() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000001","type":"Document","kind":"note","reason":"Create content event."}),
        )
        .await
        .unwrap();
    database
        .append_meta_event(PostgresMetaEvent {
            id: "append-only:meta".into(),
            subject_id: "append-only:vocabulary".into(),
            event_type: "vocabulary.created".into(),
            payload: json!({"name":"Append only"}),
            actor: Some("contract:test".into()),
            created_at: now.clone(),
        })
        .await
        .unwrap();
    database
        .append_policy_event(PostgresPolicyEvent {
            id: "append-only:policy".into(),
            record_id: "9c150000-0000-4000-8000-002000000001".into(),
            event_type: "policy.replaced".into(),
            payload: Some(json!({"entries":[{"subject_kind":"account","subject_id":"acct:one","effect":"allow","capability":"view"}]})),
            actor: "contract:test".into(),
            reason: "Create policy event.".into(),
            created_at: now.clone(),
        })
        .await
        .unwrap();
    database
        .append_control_event(PostgresControlEvent {
            id: "append-only:control".into(),
            idempotency_key: "append-only:control:key".into(),
            event_type: "member_context.provisioned".into(),
            schema_version: 1,
            aggregate_kind: "member_context".into(),
            aggregate_id: "acct:append-only".into(),
            actor: "contract:test".into(),
            run_key: None,
            reason: "Create control event.".into(),
            payload: json!({"account_id":"acct:append-only","person_record_id":"native:root","root_record_id":"native:root","created_at":now.clone()}),
            created_at: now,
        })
        .await
        .unwrap();
    for table in [
        "content_events",
        "meta_events",
        "policy_events",
        "control_events",
    ] {
        let table = database.qualified_table(table).unwrap();
        let error = sqlx::query(&format!("DELETE FROM {table} WHERE seq=1"))
            .execute(database.pool())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("append-only"), "{error}");
    }
    database.assert_replay_equivalent().await.unwrap();
    let cursors = database.qualified_table("log_cursors").unwrap();
    sqlx::query(&format!(
        "UPDATE {cursors} SET last_seq=last_seq+1 WHERE log_name='meta'"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    assert!(database
        .assert_replay_equivalent()
        .await
        .unwrap_err()
        .to_string()
        .contains("cursor/sequence integrity failed"));

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_snapshots_are_repeatable_during_concurrent_appends() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let writer_db = database.clone();
    let writer_barrier = barrier.clone();
    let writer = tokio::spawn(async move {
        writer_barrier.wait().await;
        let now = chrono::Utc::now().to_rfc3339();
        writer_db
            .append_meta_event(PostgresMetaEvent {
                id: "snapshot:vocabulary".into(),
                subject_id: "snapshot:vocabulary".into(),
                event_type: "vocabulary.created".into(),
                payload: json!({"name":"Snapshot concurrency"}),
                actor: Some("contract:snapshot-writer".into()),
                created_at: now.clone(),
            })
            .await
            .unwrap();
        for index in 0..24 {
            writer_db
                .append_meta_event(PostgresMetaEvent {
                    id: format!("snapshot:value:event:{index}"),
                    subject_id: format!("snapshot:value:{index}"),
                    event_type: "vocab_value.proposed".into(),
                    payload: json!({"vocabulary_id":"snapshot:vocabulary","value":format!("value {index}"),"gloss":null,"status":"proposed","ordinal":index as f64,"terminality":"open","metadata":{}}),
                    actor: Some("contract:snapshot-writer".into()),
                    created_at: now.clone(),
                })
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
    });

    barrier.wait().await;
    for _ in 0..24 {
        let snapshot = database.logical_snapshot().await.unwrap();
        let meta_cursor = snapshot["cursors"]["authoritative"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["log_name"] == "meta")
            .unwrap()["last_seq"]
            .as_i64()
            .unwrap();
        assert_eq!(
            snapshot["logs"]["meta"].as_array().unwrap().len() as i64,
            meta_cursor
        );
        tokio::task::yield_now().await;
    }
    writer.await.unwrap();
    database.assert_replay_equivalent().await.unwrap();

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_replay_proofs_are_repeatable_during_concurrent_appends() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let writer_db = database.clone();
    let writer_barrier = barrier.clone();
    let writer = tokio::spawn(async move {
        writer_barrier.wait().await;
        let now = chrono::Utc::now().to_rfc3339();
        writer_db
            .append_meta_event(PostgresMetaEvent {
                id: "replay:vocabulary".into(),
                subject_id: "replay:vocabulary".into(),
                event_type: "vocabulary.created".into(),
                payload: json!({"name":"Replay concurrency"}),
                actor: Some("contract:replay-writer".into()),
                created_at: now.clone(),
            })
            .await
            .unwrap();
        for index in 0..12 {
            writer_db
                .append_meta_event(PostgresMetaEvent {
                    id: format!("replay:value:event:{index}"),
                    subject_id: format!("replay:value:{index}"),
                    event_type: "vocab_value.proposed".into(),
                    payload: json!({"vocabulary_id":"replay:vocabulary","value":format!("value {index}"),"gloss":null,"status":"proposed","ordinal":index as f64,"terminality":"open","metadata":{}}),
                    actor: Some("contract:replay-writer".into()),
                    created_at: now.clone(),
                })
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
    });

    barrier.wait().await;
    for _ in 0..12 {
        database.assert_replay_equivalent().await.unwrap();
        tokio::task::yield_now().await;
    }
    writer.await.unwrap();
    database.assert_replay_equivalent().await.unwrap();

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_realtime_wakes_only_after_committed_requests() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let mut receiver = database.realtime_hub().subscribe();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000042","type":"Document","kind":"note","reason":"Prove committed wake."}),
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .expect("committed request must wake")
        .unwrap();

    install_projection_failure_trigger(&database).await.unwrap();
    assert!(harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000043","type":"Document","kind":"note","name":"__reject_projection__","reason":"Prove rollback silence."}),
        )
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), receiver.recv())
            .await
            .is_err()
    );

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_event_and_projection_are_atomic_with_stable_errors() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    install_projection_failure_trigger(&database).await.unwrap();

    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000024",
                "type": "Document",
                "kind": "note",
                "name": "__reject_projection__",
                "reason": "Force a projection failure inside the write transaction."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "create_record: storage operation failed");
    assert!(!error.contains("projection rejected"));
    assert_eq!(
        event_count(&database, "9c150000-0000-4000-8000-002000000024")
            .await
            .unwrap(),
        0
    );
    assert!(
        !projection_exists(&database, "9c150000-0000-4000-8000-002000000024")
            .await
            .unwrap()
    );
    assert!(event_sequences(&database).await.unwrap().is_empty());

    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000007",
                "type": "Document",
                "kind": "note",
                "name": "Accepted after rollback",
                "reason": "Prove the transactional event cursor also rolled back."
            }),
        )
        .await
        .unwrap();
    assert_eq!(event_sequences(&database).await.unwrap(), [1]);

    let listed = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_links",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-002000000007" }),
        )
        .await
        .unwrap();
    assert_eq!(listed["record_id"], "9c150000-0000-4000-8000-002000000007");
    assert_eq!(listed["links_out"], json!([]));
    assert_eq!(listed["links_in"], json!([]));

    let unsupported = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_messages",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-002000000007" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        unsupported,
        "tool manage_messages is not implemented for the postgres backend"
    );

    postgres_delete_projection_failure_rolls_back_event_and_projection(&harness).await;

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_update_projection_failure_rolls_back_event_and_projection() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9c150000-0000-4000-8000-009900000003";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":id,"type":"Document","kind":"note","name":"Before","body":"before","reason":"Create update rollback fixture."}),
        )
        .await
        .unwrap();
    let before_sequences = event_sequences(&database).await.unwrap();
    install_projection_failure_trigger(&database).await.unwrap();

    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": id, "name": "After", "body": "after",
                "if_body_digest": hex::encode(Sha256::digest(b"before")),
                "reason": "Force update projection failure."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "update_record: storage operation failed");
    assert_eq!(event_sequences(&database).await.unwrap(), before_sequences);
    assert_eq!(event_count(&database, id).await.unwrap(), 1);
    let record = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    assert_eq!(record["records"][0]["name"], "Before");
    assert_eq!(record["records"][0]["body"], "before");

    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000025","type":"Document","kind":"note","reason":"Prove a connection remains reusable."}),
        )
        .await
        .unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_archive_projection_failure_rolls_back_event_and_projection() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9c150000-0000-4000-8000-009900000001";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":id,"type":"Document","kind":"note","name":"Before","reason":"Create archive rollback fixture."}),
        )
        .await
        .unwrap();
    let before_sequences = event_sequences(&database).await.unwrap();
    install_projection_failure_trigger(&database).await.unwrap();

    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "archive_record",
            json!({"id":id,"reason":"Force archive projection failure."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "archive_record: storage operation failed");
    assert_eq!(event_sequences(&database).await.unwrap(), before_sequences);
    assert_eq!(event_count(&database, id).await.unwrap(), 1);
    let record = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    assert_eq!(record["records"][0]["archived"], false);

    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000008","type":"Document","kind":"note","reason":"Prove a connection remains reusable."}),
        )
        .await
        .unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

async fn postgres_delete_projection_failure_rolls_back_event_and_projection(
    harness: &PostgresHarness,
) {
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9c150000-0000-4000-8000-009900000002";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":id,"type":"Document","kind":"note","name":"Before","reason":"Create delete rollback fixture."}),
        )
        .await
        .unwrap();
    let before_sequences = event_sequences(&database).await.unwrap();
    install_projection_failure_trigger(&database).await.unwrap();

    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "delete_record",
            json!({"id":id,"reason":"Force delete projection failure."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "delete_record: storage operation failed");
    assert_eq!(event_sequences(&database).await.unwrap(), before_sequences);
    assert_eq!(event_count(&database, id).await.unwrap(), 1);
    let record = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    assert!(record["records"][0]["deleted_at"].is_null());

    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000018","type":"Document","kind":"note","reason":"Prove a connection remains reusable."}),
        )
        .await
        .unwrap();
    harness.close(&database).await;
}

async fn postgres_delete_guarded_race_has_one_tombstone(harness: &PostgresHarness) {
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9c150000-0000-4000-8000-002000000017";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":id,"type":"Document","kind":"note","reason":"Create guarded delete fixture."}),
        )
        .await
        .unwrap();
    let history = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({"record_id":id}),
        )
        .await
        .unwrap();
    let revision = history["events"][0]["local_seq"].as_i64().unwrap();
    let left = harness.call(
        &database,
        TestCaller::Local,
        "delete_record",
        json!({"id":id,"if_content_seq":revision,"reason":"Race guarded deletion."}),
    );
    let right = harness.call(
        &database,
        TestCaller::Local,
        "delete_record",
        json!({"id":id,"if_content_seq":revision,"reason":"Race guarded deletion."}),
    );
    let (left, right) = tokio::join!(left, right);
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let loser = left.err().or_else(|| right.err()).unwrap().to_string();
    assert!(
        loser.contains("tombstoned") || loser.contains("revision conflict"),
        "{loser}"
    );
    assert_eq!(event_count(&database, id).await.unwrap(), 2);
    let record = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    assert!(record["records"][0]["deleted_at"].is_string());
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

async fn postgres_delete_is_terminal_and_returns_stable_errors(harness: &PostgresHarness) {
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9c150000-0000-4000-8000-002000000019";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":id,"type":"Document","kind":"note","body":"preserved","reason":"Create terminal delete fixture."}),
        )
        .await
        .unwrap();
    let deleted = harness
        .call(
            &database,
            TestCaller::Local,
            "delete_record",
            json!({"id":id,"reason":"Tombstone the fixture."}),
        )
        .await
        .unwrap();
    assert_eq!(deleted["deleted"], true);
    assert!(deleted["deleted_at"].is_string());
    let second = harness
        .call(
            &database,
            TestCaller::Local,
            "delete_record",
            json!({"id":id,"reason":"Retry the terminal mutation."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        second,
        format!("cannot apply record.deleted: record {id} is deleted (tombstoned)")
    );
    let update = harness
        .call(
            &database,
            TestCaller::Local,
            "update_record",
            json!({"id":id,"body":"must not land","reason":"Prove the tombstone freezes writes."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(update.contains("does not exist"), "{update}");
    let missing = harness
        .call(
            &database,
            TestCaller::Local,
            "delete_record",
            json!({"id":"9c150000-0000-4000-8000-002000000016","reason":"Prove stable absence."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        missing,
        "delete_record: record 9c150000-0000-4000-8000-002000000016 does not exist"
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    postgres_message_delete_withdraws_candidates_and_retains_adjunct_state(harness, &database)
        .await;
    harness.close(&database).await;
}

async fn postgres_message_delete_withdraws_candidates_and_retains_adjunct_state(
    harness: &PostgresHarness,
    database: &native_ce::postgres::PostgresDb,
) {
    let message_id = "9c150000-0000-4000-8000-002000000014";
    let target_id = "9c150000-0000-4000-8000-002000000015";
    for (id, record_type, kind) in [
        ("9c150000-0000-4000-8000-002000000012", "Entity", "person"),
        ("9c150000-0000-4000-8000-002000000011", "Entity", "person"),
        (target_id, "Document", "note"),
    ] {
        harness
            .call(
                database,
                TestCaller::Local,
                "create_record",
                json!({"id":id,"type":record_type,"kind":kind,"reason":"Create delete adjunct fixture."}),
            )
            .await
            .unwrap();
    }
    harness
        .provision_member(
            database,
            "9c150000-0000-4000-8000-002000000012",
            "acct:delete-adjunct-sender",
            "native/delete-adjunct-sender",
        )
        .await
        .unwrap();
    harness
        .provision_member(
            database,
            "9c150000-0000-4000-8000-002000000011",
            "acct:recipient",
            "native/delete-adjunct-recipient",
        )
        .await
        .unwrap();
    harness
        .deliver_message_fixture(
            database,
            TestCaller::member("acct:delete-adjunct-sender"),
            DeliveredMessageFixture {
                id: message_id,
                name: "Delete adjunct message",
                body: "Message candidate must be withdrawn.",
                addressed_to: &["9c150000-0000-4000-8000-002000000011"],
                idempotency_key: "contract:delete-adjunct-delivery",
            },
        )
        .await
        .unwrap();
    let entries = database.qualified_table("policy_entries").unwrap();
    let links = database.qualified_table("links").unwrap();
    let events = database
        .qualified_table("notification_candidate_events")
        .unwrap();
    let candidates = database.qualified_table("notification_candidates").unwrap();
    database
        .append_policy_event(PostgresPolicyEvent {
            id: uuid::Uuid::new_v4().to_string(),
            record_id: message_id.into(),
            event_type: "policy.replaced".into(),
            payload: Some(json!({"entries":[{"subject_kind":"account","subject_id":"acct:retained","effect":"allow","capability":"manage"}]})),
            actor: "contract".into(),
            reason: "Retain an authoritative explicit policy across Message deletion.".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .await
        .unwrap();
    harness.call(database, TestCaller::Local, "manage_links", json!({"action":"add","source_id":message_id,"target_id":target_id,"relationship":"relates_to","note":"Retained generic link."})).await.unwrap();
    let mut tx = database.pool().begin().await.unwrap();
    let proposed_seq: i64 = sqlx::query_scalar(&format!("INSERT INTO {events}(id,candidate_key,action,recipient_account_id,message_id,reason,priority,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES('candidate:proposed','candidate:key','proposed','acct:recipient',$1,'routine_arrival','routine','metadata_only','portable_default','v1','message.delivered','delivery:event','{{\"schema\":\"native.notification-candidate.v1\"}}'::jsonb,transaction_timestamp()) RETURNING seq"))
        .bind(message_id).fetch_one(&mut *tx).await.unwrap();
    sqlx::query(&format!("INSERT INTO {candidates}(candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,candidate_event_seq,status,created_at) VALUES('candidate:proposed','candidate:key','acct:recipient',$1,'routine_arrival','routine','metadata_only','portable_default','v1','message.delivered','delivery:event',$2,'effective',transaction_timestamp())"))
        .bind(message_id).bind(proposed_seq).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();

    harness
        .call(
            database,
            TestCaller::Local,
            "delete_record",
            json!({"id":message_id,"reason":"Withdraw candidate while retaining adjunct state."}),
        )
        .await
        .unwrap();
    let retained_policy: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {entries} WHERE policy_anchor_id=$1 AND subject_id='acct:retained'"
    ))
    .bind(message_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let retained_links: i64 =
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {links} WHERE source_id=$1"))
            .bind(message_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let withdrawal: (String, String, String, String) = sqlx::query_as(&format!("SELECT candidate.status,event.action,event.source_event_type,event.source_event_id FROM {candidates} candidate JOIN {events} event ON event.seq=candidate.candidate_event_seq WHERE candidate.candidate_id='candidate:proposed'"))
        .fetch_one(database.pool()).await.unwrap();
    let deletion_event_id: String = sqlx::query_scalar(&format!(
        "SELECT id FROM {} WHERE record_id=$1 AND type='record.deleted'",
        database.qualified_table("content_events").unwrap()
    ))
    .bind(message_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(retained_policy, 1);
    assert_eq!(retained_links, 1);
    assert_eq!(withdrawal.0, "withdrawn");
    assert_eq!(withdrawal.1, "withdrawn");
    assert_eq!(withdrawal.2, "record.deleted");
    assert_eq!(withdrawal.3, deletion_event_id);
    database.assert_replay_equivalent().await.unwrap();
}

async fn postgres_delete_is_logically_isolated(harness: &PostgresHarness) {
    let left = harness.fresh_logical_database().await.unwrap();
    let right = harness.fresh_logical_database().await.unwrap();
    let id = "9c150000-0000-4000-8000-002000000013";
    for database in [&left, &right] {
        harness
            .call(
                database,
                TestCaller::Local,
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","reason":"Create isolated delete fixture."}),
            )
            .await
            .unwrap();
    }
    harness
        .call(
            &left,
            TestCaller::Local,
            "delete_record",
            json!({"id":id,"reason":"Delete only the left logical record."}),
        )
        .await
        .unwrap();
    let left_record = harness
        .call(&left, TestCaller::Local, "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    let right_record = harness
        .call(&right, TestCaller::Local, "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    assert!(left_record["records"][0]["deleted_at"].is_string());
    assert!(right_record["records"][0]["deleted_at"].is_null());
    harness.close(&left).await;
    harness.close(&right).await;
}

#[tokio::test]
async fn postgres_same_id_concurrent_create_has_one_gapless_durable_winner() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let left = harness.call(
        &database,
        TestCaller::Local,
        "create_record",
        json!({"id":"9c150000-0000-4000-8000-002000000010","type":"Document","kind":"note","body":"left","reason":"Race the same identifier."}),
    );
    let right = harness.call(
        &database,
        TestCaller::Local,
        "create_record",
        json!({"id":"9c150000-0000-4000-8000-002000000010","type":"Document","kind":"note","body":"right","reason":"Race the same identifier."}),
    );
    let (left, right) = tokio::join!(left, right);
    let (winner, loser) = match (left, right) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        outcome => panic!("expected exactly one create winner, got {outcome:?}"),
    };
    assert_eq!(loser.to_string(), "create_record: uniqueness conflict");
    assert!(matches!(winner["body"].as_str(), Some("left" | "right")));
    assert_eq!(
        event_count(&database, "9c150000-0000-4000-8000-002000000010")
            .await
            .unwrap(),
        1
    );
    assert_eq!(event_sequences(&database).await.unwrap(), [1]);
    let history = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-002000000010"}),
        )
        .await
        .unwrap();
    assert_eq!(history["events"].as_array().unwrap().len(), 1);
    assert_eq!(history["events"][0]["type"], "record.created");

    harness.close(&database).await;
    harness.shutdown().await;
}

async fn wait_for_blocked_content_event_insert(database: &native_ce::postgres::PostgresDb) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%content_events%')",
            )
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
    .expect("governed write did not reach its blocked authoritative append");
}

async fn call_postgres_in_spawn(
    database: native_ce::postgres::PostgresDb,
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

#[tokio::test]
async fn postgres_governed_writes_rollback_on_in_flight_cancellation_and_reuse_connections() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    let events = database.qualified_table("content_events").unwrap();

    // create_record has already inserted its projection when the authoritative
    // append blocks; dropping the future must roll both changes back.
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {events} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let create = call_postgres_in_spawn(
        database.clone(),
        "create_record",
        json!({"id":"9c150000-0000-4000-8000-002000000009","type":"Document","kind":"note","reason":"Cancel after projection work starts."}),
    )
    .await;
    wait_for_blocked_content_event_insert(&database).await;
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    blocker.commit().await.unwrap();
    assert!(
        !projection_exists(&database, "9c150000-0000-4000-8000-002000000009")
            .await
            .unwrap()
    );
    assert_eq!(
        event_count(&database, "9c150000-0000-4000-8000-002000000009")
            .await
            .unwrap(),
        0
    );
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-002000000009","type":"Document","kind":"note","body":"committed","reason":"Reuse after cancellation."}),
        )
        .await
        .unwrap();

    // update_record, archive_record and delete_record append before their projection update;
    // cancellation while that append is blocked must leave both unchanged.
    for (tool, arguments) in [
        (
            "update_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000009", "body": "cancelled",
                "if_body_digest": hex::encode(Sha256::digest(b"committed")),
                "reason": "Cancel update append."
            }),
        ),
        (
            "archive_record",
            json!({"id":"9c150000-0000-4000-8000-002000000009","reason":"Cancel archive append."}),
        ),
        (
            "delete_record",
            json!({"id":"9c150000-0000-4000-8000-002000000009","reason":"Cancel delete append."}),
        ),
    ] {
        let before = event_count(&database, "9c150000-0000-4000-8000-002000000009")
            .await
            .unwrap();
        let mut blocker = database.pool().begin().await.unwrap();
        sqlx::query(&format!("LOCK TABLE {events} IN ACCESS EXCLUSIVE MODE"))
            .execute(&mut *blocker)
            .await
            .unwrap();
        let write = call_postgres_in_spawn(database.clone(), tool, arguments).await;
        wait_for_blocked_content_event_insert(&database).await;
        write.abort();
        assert!(write.await.unwrap_err().is_cancelled());
        blocker.commit().await.unwrap();
        assert_eq!(
            event_count(&database, "9c150000-0000-4000-8000-002000000009")
                .await
                .unwrap(),
            before
        );
        let record = harness
            .call(
                &database,
                TestCaller::Local,
                "get_record",
                json!({"ids":["9c150000-0000-4000-8000-002000000009"]}),
            )
            .await
            .unwrap();
        assert_eq!(record["records"][0]["body"], "committed");
        assert_eq!(record["records"][0]["archived"], false);
    }

    harness
        .call(
            &database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000009", "body": "reused",
                "if_body_digest": hex::encode(Sha256::digest(b"committed")),
                "reason": "Prove write connection reuse."
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "archive_record",
            json!({"id":"9c150000-0000-4000-8000-002000000009","reason":"Prove archive connection reuse."}),
        )
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "delete_record",
            json!({"id":"9c150000-0000-4000-8000-002000000009","reason":"Prove delete connection reuse."}),
        )
        .await
        .unwrap();
    assert_eq!(event_sequences(&database).await.unwrap(), [1, 2, 3, 4]);

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_imports_and_verifies_the_bounded_canonical_slice() {
    let Some(url) = postgres_url() else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let source_path = temp.path().join("canonical-source.db");
    let source = create_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    create_record(
        &source,
        json!({
            "id": "9c150000-0000-4000-8000-002000000039",
            "type": "Document",
            "kind": "note",
            "name": "Canonical Postgres proof",
            "body": "same logical state"
        }),
    )
    .await
    .unwrap();
    create_record(
        &source,
        json!({
            "id": "9c150000-0000-4000-8000-002000000038",
            "type": "Document",
            "kind": "note"
        }),
    )
    .await
    .unwrap();
    set_facet(
        &source,
        "9c150000-0000-4000-8000-002000000039",
        FacetSetPayload {
            key: "priority".into(),
            value: Some("high".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let canonical = export_canonical_interchange(&source).await.unwrap();
    let mut artifact_registry = ToolRegistry::new();
    register_surface_tools(&mut artifact_registry).unwrap();
    artifact_registry
        .call_engine(
            EngineHandle::Sqlite(source.clone()),
            Caller::local(),
            "attach_text",
            json!({
                "record_id": "9c150000-0000-4000-8000-002000000039",
                "text": "derived attachment",
                "filename": "derived.txt"
            }),
        )
        .await
        .unwrap();
    let derived_canonical = export_canonical_interchange(&source).await.unwrap();

    let cluster = PostgresCluster::connect(&url).await.unwrap();
    let rejected_derived = cluster
        .import_canonical_interchange(&derived_canonical)
        .await
        .unwrap_err();
    assert!(
        rejected_derived
            .to_string()
            .contains("does not admit derived record"),
        "{rejected_derived}"
    );
    let cleanup_tag = uuid::Uuid::new_v4().simple().to_string();
    let cleanup_tag = &cleanup_tag[..8];
    let (database, report) = cluster
        .import_canonical_interchange_with_tag(&canonical, cleanup_tag)
        .await
        .unwrap();
    assert_eq!(
        cluster.logical_schemas_with_tag(cleanup_tag).await.unwrap(),
        [database.schema().to_owned()]
    );
    assert_eq!(
        report
            .verified_projection_coverage
            .iter()
            .map(|coverage| coverage.section.as_str())
            .collect::<Vec<_>>(),
        [
            "content_events",
            "content_event_causal_frontier",
            "content_event_causal_cutover",
            "records",
            "facet_values",
            "derived:event_cursor",
            "storage_portability_policy"
        ]
    );
    assert!(report
        .unmaterialized_sections
        .iter()
        .any(|section| section.name == "policy_events" && section.row_count > 0));
    database
        .verify_canonical_interchange(&canonical)
        .await
        .unwrap();
    let gapped = canonical_with_event_gap(&canonical);
    assert!(database
        .verify_canonical_interchange(&gapped)
        .await
        .unwrap_err()
        .to_string()
        .contains("requires gapless content event positions"));
    database.assert_replay_equivalent().await.unwrap();
    let records_table = database.qualified_table("records").unwrap();
    let nameless: String = sqlx::query_scalar(&format!(
        "SELECT name FROM {records_table} WHERE id='9c150000-0000-4000-8000-002000000038'"
    ))
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(nameless, "");

    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    register_postgres_slice_tools(&mut registry).unwrap();
    let arguments = json!({"ids": ["9c150000-0000-4000-8000-002000000039"]});
    let sqlite_record = registry
        .call_engine(
            EngineHandle::Sqlite(source.clone()),
            Caller::local(),
            "get_record",
            arguments.clone(),
        )
        .await
        .unwrap();
    let postgres_record = registry
        .call_engine(
            EngineHandle::Postgres(database.clone()),
            Caller::local(),
            "get_record",
            arguments,
        )
        .await
        .unwrap();
    for field in ["id", "type", "kind", "name", "body"] {
        assert_eq!(
            sqlite_record["records"][0][field], postgres_record["records"][0][field],
            "MCP-visible field {field} diverged"
        );
    }

    let events = database.qualified_table("content_events").unwrap();
    sqlx::query(&format!(
        "UPDATE {events} SET created_at=created_at + INTERVAL '1 second' WHERE seq=1"
    ))
    .execute(database.pool())
    .await
    .unwrap_err();

    let cursor = database.qualified_table("event_cursor").unwrap();
    sqlx::query(&format!("UPDATE {cursor} SET last_seq=last_seq+1"))
        .execute(database.pool())
        .await
        .unwrap();
    assert!(database
        .verify_canonical_interchange(&canonical)
        .await
        .unwrap_err()
        .to_string()
        .contains("missing, extra, or changed state"));
    sqlx::query(&format!("UPDATE {cursor} SET last_seq=last_seq-1"))
        .execute(database.pool())
        .await
        .unwrap();

    let records = records_table;
    sqlx::query(&format!(
        "UPDATE {records} SET name='semantically changed' WHERE id=$1"
    ))
    .bind("9c150000-0000-4000-8000-002000000039")
    .execute(database.pool())
    .await
    .unwrap();
    let error = database
        .verify_canonical_interchange(&canonical)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing, extra, or changed state"));

    sqlx::query(&format!(
        "UPDATE {records} SET name='Canonical Postgres proof' WHERE id=$1"
    ))
    .bind("9c150000-0000-4000-8000-002000000039")
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {records}(id,record_type,kind,name,persistence) \
         VALUES('9c150000-0000-4000-8000-002000000036','Document','note','Extra','enduring')"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    assert!(database
        .verify_canonical_interchange(&canonical)
        .await
        .unwrap_err()
        .to_string()
        .contains("missing, extra, or changed state"));
    sqlx::query(&format!(
        "DELETE FROM {records} WHERE id='9c150000-0000-4000-8000-002000000036'"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "DELETE FROM {records} WHERE id='9c150000-0000-4000-8000-002000000039'"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    assert!(database
        .verify_canonical_interchange(&canonical)
        .await
        .unwrap_err()
        .to_string()
        .contains("missing, extra, or changed state"));

    database.drop_schema().await.unwrap();
    assert!(cluster
        .logical_schemas_with_tag(cleanup_tag)
        .await
        .unwrap()
        .is_empty());
    source.close().await;
    cluster.close().await;
}

#[tokio::test]
async fn postgres_canonical_import_rejects_unsupported_events_without_consuming_source() {
    let Some(url) = postgres_url() else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let source_path = temp.path().join("unsupported-source.db");
    let source = create_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    let first = create_record(
        &source,
        json!({"id":"9c150000-0000-4000-8000-002000000037","type":"Document","kind":"note","name":"First"}),
    )
    .await
    .unwrap();
    let second = create_record(
        &source,
        json!({"id":"9c150000-0000-4000-8000-002000000040","type":"Document","kind":"note","name":"Second"}),
    )
    .await
    .unwrap();
    native_ce::store::add_link(
        &source,
        native_ce::events::LinkAddedPayload {
            id: Some("portable:unsupported-link".into()),
            source_id: first,
            target_id: second,
            relationship: "relates_to".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    let canonical = export_canonical_interchange(&source).await.unwrap();
    let cluster = PostgresCluster::connect(&url).await.unwrap();
    let cleanup_tag = uuid::Uuid::new_v4().simple().to_string();
    let cleanup_tag = &cleanup_tag[..8];
    let schemas_before = cluster.logical_schemas_with_tag(cleanup_tag).await.unwrap();

    let gapped = canonical_with_event_gap(&canonical);
    let gap_error = cluster
        .import_canonical_interchange_with_tag(&gapped, cleanup_tag)
        .await
        .unwrap_err()
        .to_string();
    assert!(gap_error.contains("requires gapless content event positions"));
    assert_eq!(
        cluster.logical_schemas_with_tag(cleanup_tag).await.unwrap(),
        schemas_before
    );

    let error = cluster
        .import_canonical_interchange_with_tag(&canonical, cleanup_tag)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unsupported Postgres canonical event type link.added"));
    assert_eq!(
        cluster.logical_schemas_with_tag(cleanup_tag).await.unwrap(),
        schemas_before
    );

    create_record(
        &source,
        json!({"id":"9c150000-0000-4000-8000-002000000041","type":"Document","kind":"note","name":"Usable"}),
    )
    .await
    .unwrap();
    source.close().await;
    cluster.close().await;
}

#[tokio::test]
async fn postgres_attachment_roundtrip_windowed_reads_and_replay() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000002",
                "type": "Document",
                "kind": "note",
                "name": "Bearer",
                "home_id": "native:unfiled",
                "reason": "Create an attachment bearer."
            }),
        )
        .await
        .unwrap();

    let attached = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "9c150000-0000-4000-8000-002000000002",
                "text": "portable bytes",
                "filename": "proof.txt"
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        attached["record_id"],
        "9c150000-0000-4000-8000-002000000002"
    );
    assert_eq!(attached["name"], "proof.txt");
    assert_eq!(attached["blob"]["mime"], "text/plain; charset=utf-8");
    assert_eq!(attached["blob"]["size_bytes"], 14);
    assert_eq!(attached["blob"]["original_filename"], "proof.txt");
    assert_eq!(attached["blob"]["storage_tier"], "inline");
    let attachment_id = attached["attachment_id"].as_str().unwrap().to_string();

    let full = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": attachment_id }),
        )
        .await
        .unwrap();
    assert_eq!(full["content"], "portable bytes");
    assert_eq!(full["content_encoding"], "utf-8");
    assert_eq!(full["offset"], 0);
    assert_eq!(full["length"], 14);
    assert_eq!(full["eof"], true);
    assert_eq!(full["deleted_at"], json!(null));
    assert_eq!(full["name"], "proof.txt");
    assert_eq!(full["blob"]["sha256"], attached["blob"]["sha256"]);

    let window = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": attachment_id, "offset": 1, "length": 4 }),
        )
        .await
        .unwrap();
    assert_eq!(window["content"], "orta");
    assert_eq!(window["offset"], 1);
    assert_eq!(window["length"], 4);
    assert_eq!(window["eof"], false);

    let tail = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": attachment_id, "offset": 9 }),
        )
        .await
        .unwrap();
    assert_eq!(tail["content"], "bytes");
    assert_eq!(tail["length"], 5);
    assert_eq!(tail["eof"], true);

    let beyond = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": attachment_id, "offset": 100 }),
        )
        .await
        .unwrap();
    assert_eq!(beyond["content"], "");
    assert_eq!(beyond["length"], 0);
    assert_eq!(beyond["eof"], true);

    for length in [0_u64, 512 * 1024 + 1] {
        let error = harness
            .call(
                &database,
                TestCaller::Local,
                "read_attachment",
                json!({ "attachment_id": attachment_id, "length": length }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "read_attachment: 'length' must be between 1 and 524288"
        );
    }

    let binary = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "9c150000-0000-4000-8000-002000000002",
                "text": "raw",
                "mime": "application/octet-stream"
            }),
        )
        .await
        .unwrap();
    assert_eq!(binary["name"], "attachment");
    let binary_id = binary["attachment_id"].as_str().unwrap().to_string();
    let encoded = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": binary_id }),
        )
        .await
        .unwrap();
    assert_eq!(encoded["content_encoding"], "base64");
    assert_eq!(encoded["content"], "cmF3");

    let listed = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-002000000002" }),
        )
        .await
        .unwrap();
    let listed_attachments = listed["attachments"].as_array().unwrap();
    assert_eq!(listed_attachments.len(), 2);
    // Sub-millisecond creations may tie on created_at, so find by id rather
    // than assuming the tie-broken order.
    let text_entry = listed_attachments
        .iter()
        .find(|entry| entry["attachment_id"] == json!(attachment_id.as_str()))
        .unwrap();
    assert_eq!(text_entry["name"], "proof.txt");
    assert_eq!(text_entry["mime"], "text/plain; charset=utf-8");
    assert_eq!(text_entry["size_bytes"], 14);
    assert_eq!(text_entry["storage_tier"], "inline");

    let inspected = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "inspect", "attachment_id": attachment_id }),
        )
        .await
        .unwrap();
    assert_eq!(inspected["attachment_id"], attachment_id);
    assert_eq!(inspected["detached"], false);
    assert_eq!(inspected["deleted_at"], json!(null));
    assert_eq!(inspected["blob"]["size_bytes"], 14);

    let detached = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "detach", "attachment_id": attachment_id }),
        )
        .await
        .unwrap();
    assert_eq!(detached["detached"], true);
    assert_eq!(detached["blob_retained"], true);
    assert_eq!(detached["blob_id"], attached["blob"]["id"]);

    let listed_after = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-002000000002" }),
        )
        .await
        .unwrap();
    let remaining = listed_after["attachments"].as_array().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["attachment_id"], binary_id);

    for (tool, arguments) in [
        (
            "manage_attachments",
            json!({ "action": "inspect", "attachment_id": attachment_id }),
        ),
        (
            "manage_attachments",
            json!({ "action": "detach", "attachment_id": attachment_id }),
        ),
        ("read_attachment", json!({ "attachment_id": attachment_id })),
    ] {
        let error = harness
            .call(&database, TestCaller::Local, tool, arguments)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!("{tool}: attachment {attachment_id} does not exist")
        );
    }

    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attach_text_enforces_the_size_cap_and_stable_errors() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000003",
                "type": "Document",
                "kind": "note",
                "home_id": "native:unfiled",
                "reason": "Create a size-cap fixture."
            }),
        )
        .await
        .unwrap();

    // Omitted homes use the canonical unfiled home on every backend.
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000004",
                "type": "Document",
                "kind": "note",
                "reason": "Create a homeless bearer fixture."
            }),
        )
        .await
        .unwrap();
    let unfiled = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-002000000004", "text": "unplaced" }),
        )
        .await
        .unwrap();
    assert_eq!(unfiled["record_id"], "9c150000-0000-4000-8000-002000000004");

    let oversized = "a".repeat(20 * 1024 * 1024 + 1);
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-002000000003", "text": oversized }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "attach_text: text exceeds the 20971520 byte cap");

    let missing_bearer = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-002000000005", "text": "orphan" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        missing_bearer,
        "attach_text: record 9c150000-0000-4000-8000-002000000005 does not exist"
    );

    let missing_attachment = harness
        .call(
            &database,
            TestCaller::Local,
            "read_attachment",
            json!({ "attachment_id": "9c150000-0000-4000-8000-002000000006" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        missing_attachment,
        "read_attachment: attachment 9c150000-0000-4000-8000-002000000006 does not exist"
    );

    let missing_record = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-002000000005" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        missing_record,
        "manage_attachments: record 9c150000-0000-4000-8000-002000000005 does not exist"
    );

    // An ordinary record id is never a valid attachment id.
    let not_an_attachment = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_attachments",
            json!({ "action": "inspect", "attachment_id": "9c150000-0000-4000-8000-002000000003" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        not_an_attachment,
        "manage_attachments: attachment 9c150000-0000-4000-8000-002000000003 does not exist"
    );

    let invalid_facet = harness
        .call(
            &database,
            TestCaller::Local,
            "attach_text",
            json!({
                "record_id": "9c150000-0000-4000-8000-002000000003",
                "text": "facets",
                "facets": { "flag": true }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        invalid_facet,
        "Postgres facets require string, number, or object values"
    );

    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_attachment_visibility_follows_bearer_authorization() {
    let Some(harness) = configured_harness().await else {
        return;
    };
    let database = harness.fresh_logical_database().await.unwrap();
    for (person_id, name) in [
        ("9c150000-0000-4000-8000-002000000034", "Alice"),
        ("9c150000-0000-4000-8000-002000000035", "Bea"),
    ] {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id": person_id,
                    "type": "Entity",
                    "kind": "person",
                    "name": name,
                    "reason": "Create an attachment principal fixture."
                }),
            )
            .await
            .unwrap();
    }
    harness
        .provision_member(
            &database,
            "9c150000-0000-4000-8000-002000000034",
            "acct:alice",
            "principal:alice",
        )
        .await
        .unwrap();
    harness
        .provision_member(
            &database,
            "9c150000-0000-4000-8000-002000000035",
            "acct:bea",
            "principal:bea",
        )
        .await
        .unwrap();

    // A member-owned bearer visible to every member through the root policy.
    harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-002000000051",
                "type": "Document",
                "kind": "note",
                "name": "Shared",
                "home_id": "native:unfiled",
                "reason": "Create a member-visible attachment bearer."
            }),
        )
        .await
        .unwrap();
    let shared = harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-002000000051", "text": "member bytes" }),
        )
        .await
        .unwrap();
    let shared_id = shared["attachment_id"].as_str().unwrap().to_string();
    let read_as_bea = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "read_attachment",
            json!({ "attachment_id": shared_id }),
        )
        .await
        .unwrap();
    assert_eq!(read_as_bea["content"], "member bytes");
    // Detach requires manage; a non-owner member holds only the root edit
    // grant, so the attachment stays hidden from the mutation.
    let denied_detach = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "manage_attachments",
            json!({ "action": "detach", "attachment_id": shared_id }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied_detach,
        format!("manage_attachments: attachment {shared_id} does not exist")
    );
    let owner_detach = harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "manage_attachments",
            json!({ "action": "detach", "attachment_id": shared_id }),
        )
        .await
        .unwrap();
    assert_eq!(owner_detach["detached"], true);

    // A bearer re-anchored to a policy only Alice can see.
    harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-100000000001",
                "type": "Document",
                "kind": "note",
                "name": "Private",
                "home_id": "native:unfiled",
                "reason": "Create an isolated attachment bearer."
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-100000000002",
                "type": "Document",
                "kind": "note",
                "name": "Restrictive attachment home",
                "home_id": "native:unfiled",
                "reason": "Create the attachment policy home fixture."
            }),
        )
        .await
        .unwrap();
    let policies = database.qualified_table("record_policies").unwrap();
    let entries = database.qualified_table("policy_entries").unwrap();
    let records = database.qualified_table("records").unwrap();
    let mut tx = database.pool().begin().await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO {policies}(record_id) VALUES('9c150000-0000-4000-8000-100000000001')"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET policy_anchor_id='9c150000-0000-4000-8000-100000000001' WHERE id='9c150000-0000-4000-8000-100000000001'"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES('9c150000-0000-4000-8000-100000000001','account','acct:alice','allow','edit')"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES('9c150000-0000-4000-8000-100000000001','account','acct:viewer','allow','view')"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let private = harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-100000000001", "text": "private bytes" }),
        )
        .await
        .unwrap();
    let private_id = private["attachment_id"].as_str().unwrap().to_string();
    // Give the derived attachment its own restrictive projected home. The
    // viewer is granted only on the bearer above; this row deliberately
    // excludes the viewer so the old double-authorization path would deny it.
    let attachment_home = "9c150000-0000-4000-8000-100000000002";
    let mut attachment_tx = database.pool().begin().await.unwrap();
    sqlx::query(&format!("INSERT INTO {policies}(record_id) VALUES($1)"))
        .bind(attachment_home)
        .execute(&mut *attachment_tx)
        .await
        .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES($1,'account','acct:alice','allow','view')"
    ))
    .bind(attachment_home)
    .execute(&mut *attachment_tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE {records} SET home_id=$1, policy_anchor_id=$1 WHERE id=$2"
    ))
    .bind(attachment_home)
    .bind(&private_id)
    .execute(&mut *attachment_tx)
    .await
    .unwrap();
    attachment_tx.commit().await.unwrap();

    let read_as_alice = harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "read_attachment",
            json!({ "attachment_id": private_id }),
        )
        .await
        .unwrap();
    assert_eq!(read_as_alice["content"], "private bytes");

    let hidden_read = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "read_attachment",
            json!({ "attachment_id": private_id }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden_read,
        format!("read_attachment: attachment {private_id} does not exist")
    );
    let viewer_record = harness
        .call(
            &database,
            TestCaller::member("acct:viewer"),
            "get_record",
            json!({ "ids": [private_id] }),
        )
        .await
        .unwrap();
    assert_eq!(viewer_record["records"][0]["id"], private_id);
    let viewer_history = harness
        .call(
            &database,
            TestCaller::member("acct:viewer"),
            "get_history",
            json!({ "record_id": private_id }),
        )
        .await
        .unwrap();
    assert!(!viewer_history["events"].as_array().unwrap().is_empty());
    let hidden_history = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "get_history",
            json!({ "record_id": private_id }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden_history,
        format!("get_history: record {private_id} does not exist")
    );
    sqlx::query(&format!(
        "UPDATE {records} SET deleted_at='2026-08-14T00:00:00Z' WHERE id='9c150000-0000-4000-8000-100000000001'"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    let tombstoned_history = harness
        .call(
            &database,
            TestCaller::member("acct:alice"),
            "get_history",
            json!({ "record_id": private_id }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        tombstoned_history,
        format!("get_history: record {private_id} does not exist")
    );
    let tombstoned_record = harness
        .call(
            &database,
            TestCaller::member("acct:viewer"),
            "get_record",
            json!({ "ids": [private_id] }),
        )
        .await
        .unwrap();
    assert_eq!(tombstoned_record["records"][0]["status"], "not_found");
    let hidden_list = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "manage_attachments",
            json!({ "action": "list", "record_id": "9c150000-0000-4000-8000-100000000001" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden_list,
        "manage_attachments: record 9c150000-0000-4000-8000-100000000001 does not exist"
    );
    let hidden_attach = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-100000000001", "text": "denied" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden_attach,
        "attach_text: record 9c150000-0000-4000-8000-100000000001 does not exist"
    );

    // A caller with record access but no portable account binding cannot
    // attach, and the denied write leaves no orphaned blob bytes behind.
    let blobs = database.qualified_table("blobs").unwrap();
    let blobs_before: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {blobs}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    let unbound = harness
        .call(
            &database,
            TestCaller::member("acct:ghost"),
            "attach_text",
            json!({ "record_id": "9c150000-0000-4000-8000-002000000051", "text": "must roll back" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        unbound,
        "attach_text: caller has no portable account binding"
    );
    let blobs_after: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {blobs}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(blobs_after, blobs_before);

    postgres_record_references(&harness, &database)
        .await
        .unwrap();

    // No replay assertion here: the re-anchoring fixture above writes policy
    // projections directly (the policy tools are not yet on this backend), so
    // this database intentionally holds state that no log replays.
    harness.close(&database).await;
    harness.shutdown().await;
}

async fn postgres_record_references(
    harness: &PostgresHarness,
    database: &native_ce::postgres::PostgresDb,
) -> native_ce::Result<()> {
    scenarios::record_reference_resolution(harness, database).await?;

    // Hold the physical half-open range to the primary-key path. Disabling
    // sequential scans only removes the small-fixture cost preference; the
    // planner still has to prove that these predicates are indexable.
    let records = database.qualified_table("records")?;
    let mut plan_transaction = database.pool().begin().await?;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *plan_transaction)
        .await?;
    let plan = sqlx::query_scalar::<_, String>(&format!(
        "EXPLAIN (FORMAT TEXT) SELECT id FROM {records} \
         WHERE id >= $1 AND id < $2 AND deleted_at IS NULL \
         AND length(id) = $3 ORDER BY id LIMIT $4"
    ))
    .bind("abc123")
    .bind("abc123g")
    .bind(36_i32)
    .bind(257_i64)
    .fetch_all(&mut *plan_transaction)
    .await?
    .join("\n");
    assert!(
        plan.contains("Index") && plan.contains("id >=") && plan.contains("id <"),
        "the Postgres prefix range must use the record primary-key path: {plan}"
    );
    plan_transaction.rollback().await?;
    Ok(())
}
