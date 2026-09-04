#![cfg(feature = "postgres-tests")]

//! Postgres execution of the shared scenario corpus. The table and its
//! expectations live in `tests/contract/corpus.rs`; this runner only supplies
//! the backend harness.

use crate::contract::{ContractHarness, PostgresHarness, TestCaller};
use native_ce::portable_sql::Backend;
use serde_json::json;
use sqlx::{Executor, Row};

#[tokio::test]
async fn postgres_executes_the_full_shared_scenario_corpus() {
    let Some(harness) = PostgresHarness::from_env()
        .await
        .expect("connect to NATIVE_CE_POSTGRES_TEST_URL")
    else {
        return;
    };
    let run = crate::corpus::run_full_corpus(&harness, Backend::Postgres)
        .await
        .unwrap();
    crate::corpus::assert_run_is_complete(&run);
    crate::contract::scenarios::portable_native_search(&harness)
        .await
        .unwrap();

    let left = harness.fresh_logical_database().await.unwrap();
    let right = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &left,
            TestCaller::Local,
            "create_record",
            json!({"id":"9c150000-0000-4000-8000-006000000001","type":"Document","kind":"note","name":"isolatedlexeme","reason":"Prove search topology."}),
        )
        .await
        .unwrap();
    assert_eq!(
        harness
            .call(
                &right,
                TestCaller::Local,
                "search",
                json!({"query":"isolatedlexeme"}),
            )
            .await
            .unwrap()["returned"],
        0
    );
    let records = left.qualified_table("records").unwrap();
    let mut transaction = left.pool().begin().await.unwrap();
    transaction
        .execute("SET LOCAL enable_seqscan=off")
        .await
        .unwrap();
    let plan = sqlx::query(&format!(
        "EXPLAIN WITH native_matches AS MATERIALIZED (\
             SELECT id FROM {records} \
             WHERE to_tsvector('english',coalesce(name,'') || ' ' || coalesce(body,'')) \
                   @@ plainto_tsquery('english','isolatedlexeme')\
         ) \
         SELECT id FROM native_matches \
         WHERE id = ANY(ARRAY['9c150000-0000-4000-8000-006000000001']::text[])"
    ))
    .fetch_all(&mut *transaction)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.try_get::<String, _>(0).unwrap())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(plan.contains("records_native_fts"), "{plan}");
    transaction.rollback().await.unwrap();
    harness.close(&left).await;
    harness.close(&right).await;
    harness.shutdown().await;
}
