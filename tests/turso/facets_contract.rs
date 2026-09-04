#![cfg(feature = "turso-tests")]

use crate::contract::TursoHarness;

#[test]
fn turso_facets_are_governed_bounded_and_replayable() {
    std::thread::Builder::new()
        .name("turso-portable-facets-test".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    crate::contract::scenarios::portable_facets(&TursoHarness::new())
                        .await
                        .unwrap();
                    crate::turso_runtime::facet_operations_cancel_at_their_own_transaction_boundaries_and_reuse()
                        .await;
                });
        })
        .unwrap()
        .join()
        .expect("portable Turso facets test thread must not panic");
}
