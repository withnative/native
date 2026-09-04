#![cfg(feature = "turso-tests")]

use crate::contract::TursoHarness;

#[tokio::test]
async fn turso_live_logical_query_is_bounded_filtered_and_deterministic() {
    crate::contract::scenarios::portable_logical_query(&TursoHarness::new(), true)
        .await
        .unwrap();
}
