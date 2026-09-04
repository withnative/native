//! Backend-neutral engine contract, currently executed by SQLite.

use crate::contract::{scenarios, ContractHarness, SqliteHarness};

#[tokio::test]
async fn sqlite_record_lifecycle_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::record_lifecycle(&harness, &database)
        .await
        .unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_link_mutation_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::link_mutation(&harness, &database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_visibility_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::visibility(&harness, &database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_authoritative_replay_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::replay(&harness, &database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_guarded_write_race_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::guarded_write_race(&harness, &database)
        .await
        .unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_null_body_digest_guard_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::null_body_digest_guard(&harness, &database)
        .await
        .unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_timestamp_precondition_contract() {
    let harness = SqliteHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::timestamp_precondition(&harness, &database)
        .await
        .unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn sqlite_logical_database_isolation_contract() {
    let harness = SqliteHarness::new();
    scenarios::logical_database_isolation(&harness)
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_logical_query_reference_contract() {
    scenarios::portable_logical_query(&SqliteHarness::new(), false)
        .await
        .unwrap();
}

#[test]
fn sqlite_facets_match_the_portable_backend_corpus() {
    std::thread::Builder::new()
        .name("sqlite-portable-facets-test".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    scenarios::portable_facets(&SqliteHarness::new())
                        .await
                        .unwrap();
                });
        })
        .unwrap()
        .join()
        .expect("portable facets test thread must not panic");
}

#[test]
fn shared_scenarios_do_not_cross_the_physical_storage_boundary() {
    let source = include_str!("../contract/scenarios.rs");
    for forbidden in [
        "Db::pool",
        ".pool()",
        "sqlx::",
        "query_sql",
        "create_database",
        "tempfile",
        "Sqlite",
    ] {
        assert!(
            !source.contains(forbidden),
            "shared contract scenarios contain backend-specific token {forbidden:?}"
        );
    }
}
