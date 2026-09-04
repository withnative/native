#![cfg(feature = "postgres-tests")]

use crate::contract::{scenarios, ContractHarness, PostgresHarness, TestCaller};
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::postgres::{register_postgres_slice_tools, PostgresDb};
use serde_json::json;

async fn harness() -> PostgresHarness {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for identity contract receipts");
    PostgresHarness::connect(&url)
        .await
        .expect("connect to NATIVE_CE_POSTGRES_TEST_URL")
}

fn spawn_resolve(
    database: PostgresDb,
    identifier: &'static str,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_postgres_slice_tools(&mut registry).unwrap();
        registry
            .call_engine(
                EngineHandle::Postgres(database),
                Caller::local(),
                "resolve_external",
                json!({
                    "bindings":[{"system":"native-principal","identifier":identifier}],
                    "reason":"Exercise the Postgres identity transaction boundary."
                }),
            )
            .await
    })
}

async fn wait_for_blocked_audit(database: &PostgresDb) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%binding_audit%')",
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
    .expect("identity write did not reach its blocked audit append");
}

#[tokio::test]
async fn postgres_identity_binding_full_boundary_contract() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::identity_bindings(&harness, &database)
        .await
        .unwrap();
    let audit = database.qualified_table("binding_audit").unwrap();
    let positions: Vec<i64> = sqlx::query_scalar(&format!("SELECT seq FROM {audit} ORDER BY seq"))
        .fetch_all(database.pool())
        .await
        .unwrap();
    assert_eq!(
        positions,
        (1..=positions.len() as i64).collect::<Vec<_>>(),
        "binding audit positions are transactionally gapless"
    );
    let mutation = sqlx::query(&format!(
        "UPDATE {audit} SET reason='forbidden rewrite' WHERE seq=1"
    ))
    .execute(database.pool())
    .await
    .unwrap_err();
    let mutation_code = mutation
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.into_owned());
    assert_eq!(mutation_code.as_deref(), Some("55000"));

    let left = harness.call(
        &database, TestCaller::Local, "resolve_external",
        json!({"bindings":[{"system":"native-principal","identifier":"native/postgres-race"}],"reason":"Race a portable binding resolution."}),
    );
    let right = harness.call(
        &database, TestCaller::Local, "resolve_external",
        json!({"bindings":[{"system":"native-principal","identifier":"native/postgres-race"}],"reason":"Race a portable binding resolution."}),
    );
    let (left, right) = tokio::join!(left, right);
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left["record_id"], right["record_id"]);
    let created = [left["created"].as_bool(), right["created"].as_bool()]
        .into_iter()
        .filter(|value| *value == Some(true))
        .count();
    assert_eq!(created, 1);

    let other = harness.fresh_logical_database().await.unwrap();
    let isolated = harness.call(
        &other, TestCaller::Local, "resolve_external",
        json!({"bindings":[{"system":"native-principal","identifier":"native/postgres-race"}],"reason":"Prove logical database isolation."}),
    ).await.unwrap();
    assert_eq!(isolated["status"], "created");
    assert_ne!(isolated["record_id"], left["record_id"]);

    harness.close(&database).await;
    harness.close(&other).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_identity_cancellation_rolls_back_and_reuses_the_pool() {
    let harness = harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    let audit = database.qualified_table("binding_audit").unwrap();
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {audit} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();

    let call = spawn_resolve(database.clone(), "native/postgres-cancelled");
    wait_for_blocked_audit(&database).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    blocker.commit().await.unwrap();
    let retried = spawn_resolve(database.clone(), "native/postgres-cancelled")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried["status"], "created");
    harness.assert_replay_equivalent(&database).await.unwrap();

    harness.close(&database).await;
    harness.shutdown().await;
}
