#![cfg(feature = "postgres-tests")]

use crate::contract::PostgresHarness;

#[tokio::test]
async fn postgres_portable_views_are_bounded_filtered_and_deterministic() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres view receipts");
    let harness = PostgresHarness::connect(&url).await.unwrap();
    crate::contract::scenarios::portable_views(&harness)
        .await
        .unwrap();
    harness.shutdown().await;
}
