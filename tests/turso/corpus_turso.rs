#![cfg(feature = "turso-tests")]

//! Turso-local execution of the shared scenario corpus. The table and its
//! expectations live in `tests/contract/corpus.rs`; this runner only supplies
//! the backend harness.

use crate::contract::{ContractHarness, TursoHarness};
use native_ce::portable_sql::Backend;

#[tokio::test]
async fn turso_local_executes_the_full_shared_scenario_corpus() {
    let harness = TursoHarness::new();
    let run = crate::corpus::run_full_corpus(&harness, Backend::Turso)
        .await
        .unwrap();
    crate::corpus::assert_run_is_complete(&run);
    crate::contract::scenarios::portable_native_search(&harness)
        .await
        .unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    let plan = harness.search_query_plan_for_test(&database).await.unwrap();
    assert!(
        plan.iter().any(|line| line == "QUERY INDEX METHOD fts"),
        "{plan:?}"
    );
    harness.close(&database).await;
}
