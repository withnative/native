#![cfg(feature = "turso-tests")]

use crate::contract::TursoHarness;

#[tokio::test]
async fn turso_portable_views_are_bounded_filtered_and_deterministic() {
    crate::contract::scenarios::portable_views(&TursoHarness::new())
        .await
        .unwrap();
}
