#![cfg(feature = "postgres-tests")]

use crate::contract::{ContractHarness, PostgresHarness, TestCaller};
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::postgres::{register_postgres_tools, PostgresDb};
use serde_json::json;

#[tokio::test]
async fn postgres_facets_are_governed_bounded_and_replayable() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres facet receipts");
    let harness = PostgresHarness::connect(&url).await.unwrap();
    crate::contract::scenarios::portable_facets(&harness)
        .await
        .unwrap();
    harness.shutdown().await;
    postgres_same_time_facet_corrections_serialize_before_snapshot_reads().await;
    postgres_facet_operations_cancel_at_operation_boundaries_and_reuse().await;
}

async fn postgres_same_time_facet_corrections_serialize_before_snapshot_reads() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres facet receipts");
    let harness = PostgresHarness::connect(&url).await.unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-005000000002","type":"Outcome","kind":"target","name":"Concurrent correction","facets":{"current":0},"reason":"Exercise concurrent same-time correction serialization."}),
        )
        .await
        .unwrap();
    let left = harness.call(
        &database,
        TestCaller::Local,
        "manage_facet_observations",
        json!({"action":"set","record_id":"9c150000-0000-4000-8000-005000000002","key":"current","value":101,"as_of":"2026-08-17T00:00:00Z","reason":"Concurrent left correction."}),
    );
    let right = harness.call(
        &database,
        TestCaller::Local,
        "manage_facet_observations",
        json!({"action":"set","record_id":"9c150000-0000-4000-8000-005000000002","key":"current","value":202,"as_of":"2026-08-17T00:00:00Z","reason":"Concurrent right correction."}),
    );
    let (left, right) = tokio::join!(left, right);
    let left = left.unwrap();
    let right = right.unwrap();
    let (earlier, later, expected_latest) =
        if left["event_seq"].as_i64().unwrap() < right["event_seq"].as_i64().unwrap() {
            (&left, &right, "202")
        } else {
            (&right, &left, "101")
        };
    assert_eq!(later["previous_seq"], earlier["event_seq"]);
    let listed = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_facet_observations",
            json!({"action":"list","record_id":"9c150000-0000-4000-8000-005000000002","key":"current","from_as_of":"2026-08-17T00:00:00Z","to_as_of":"2026-08-17T00:00:00Z"}),
        )
        .await
        .unwrap();
    assert_eq!(listed["observations"].as_array().unwrap().len(), 1);
    assert_eq!(listed["observations"][0]["event_seq"], later["event_seq"]);
    assert_eq!(listed["observations"][0]["value"], expected_latest);
    harness.close(&database).await;
    harness.shutdown().await;
}

fn spawn_postgres_facet_call(
    database: PostgresDb,
    tool: &'static str,
    arguments: serde_json::Value,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_postgres_tools(&mut registry).unwrap();
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

async fn wait_for_facet_lock(database: &PostgresDb, signature: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND position($1 in query)>0)",
            )
            .bind(signature)
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
    .unwrap_or_else(|_| panic!("facet call did not reach blocked query {signature}"));
}

async fn postgres_facet_operations_cancel_at_operation_boundaries_and_reuse() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres facet receipts");
    let harness = PostgresHarness::connect(&url).await.unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-005000000001","type":"Outcome","kind":"target","name":"Facet cancellation","reason":"Create facet cancellation fixture."}),
        )
        .await
        .unwrap();

    let cursors = database.qualified_table("log_cursors").unwrap();
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {cursors} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let write = spawn_postgres_facet_call(
        database.clone(),
        "manage_facet_observations",
        json!({"action":"set","record_id":"9c150000-0000-4000-8000-005000000001","key":"current","value":1,"as_of":"2026-08-17T00:00:00Z","reason":"Cancel facet write before commit."}),
    );
    wait_for_facet_lock(&database, "SET last_seq=last_seq").await;
    write.abort();
    assert!(write.await.unwrap_err().is_cancelled());
    blocker.rollback().await.unwrap();
    let empty = harness
        .call(
            &database,
            TestCaller::Local,
            "manage_facet_observations",
            json!({"action":"list","record_id":"9c150000-0000-4000-8000-005000000001","key":"current"}),
        )
        .await
        .unwrap();
    assert!(empty["observations"].as_array().unwrap().is_empty());

    let schema = database.qualified_table("schema_config").unwrap();
    for (operation, arguments) in [
        (
            "resolve_facets",
            json!({"record_id":"9c150000-0000-4000-8000-005000000001"}),
        ),
        (
            "suggest_facet_values",
            json!({"record_id":"9c150000-0000-4000-8000-005000000001","facet_key":"current"}),
        ),
    ] {
        let mut blocker = database.pool().begin().await.unwrap();
        sqlx::query(&format!("LOCK TABLE {schema} IN ACCESS EXCLUSIVE MODE"))
            .execute(&mut *blocker)
            .await
            .unwrap();
        let read = spawn_postgres_facet_call(database.clone(), operation, arguments.clone());
        wait_for_facet_lock(&database, "CREATE OR REPLACE TEMPORARY VIEW schema_config").await;
        read.abort();
        assert!(read.await.unwrap_err().is_cancelled());
        blocker.rollback().await.unwrap();
        assert!(harness
            .call(&database, TestCaller::Local, operation, arguments)
            .await
            .unwrap()
            .is_object());
    }
    harness.close(&database).await;
    harness.shutdown().await;
}
