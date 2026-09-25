#![cfg(feature = "postgres-tests")]

//! Postgres rebuild-and-diff — the content-domain instrument that proves the
//! stored `content_events` log folds to the stored projections (Native task
//! 510691f). The fold is driven through the same `apply_projection` every live
//! mutation uses, into a fresh scratch schema, and every compared column is
//! diffed against the live snapshot.
//!
//! Harness convention, chosen rather than inherited: this module does NOT treat
//! an unset `NATIVE_CE_POSTGRES_TEST_URL` as "skip". `postgres_contract.rs`
//! silently returns from every body when the variable is absent, so
//! `--features postgres-tests` can pass having executed nothing and say so
//! nowhere — exactly the trap this task exists to close. This module follows
//! `facets_contract.rs` and panics when the variable is missing, so a green run
//! can only mean a real fold ran against a live server. The cost is deliberate:
//! a local `--features postgres-tests` run without a server fails loudly
//! instead of pretending to be green.
//!
//! One test proves the instrument can pass on a real log; the second proves it
//! can fail, by directly corrupting one projection row and requiring the diff
//! to catch it. A check that cannot fail proves nothing.

use crate::contract::{ContractHarness, DeliveredMessageFixture, PostgresHarness, TestCaller};
use native_ce::postgres::{event_sequences, PostgresContentRebuildDiff, PostgresDb};
use serde_json::json;

const REBUILD_REASON: &str =
    "Exercise the Postgres content rebuild-and-diff conformance instrument.";

async fn live_harness() -> PostgresHarness {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL").expect(
        "NATIVE_CE_POSTGRES_TEST_URL is required: the Postgres rebuild-and-diff must run \
         against a live server rather than silently skipping",
    );
    PostgresHarness::connect(&url)
        .await
        .expect("connect to NATIVE_CE_POSTGRES_TEST_URL")
}

fn describe_diff(diff: &PostgresContentRebuildDiff) -> String {
    let mut lines = vec![format!(
        "content rebuild-and-diff replayed {} events into a fresh schema",
        diff.event_count
    )];
    for table in &diff.tables {
        lines.push(format!(
            "  {}: live {} rows, rebuilt {} rows, {} mismatches",
            table.table,
            table.live,
            table.rebuilt,
            table.mismatches.len()
        ));
        for mismatch in table.mismatches.iter().take(5) {
            lines.push(format!("    {mismatch}"));
        }
    }
    lines.join("\n")
}

/// Build one content log that exercises every content projection table: records
/// (create/update/archive), facet_values, links, and message_audience.
async fn seed_rebuild_fixture(harness: &PostgresHarness, database: &PostgresDb) {
    for (id, kind, name) in [
        (
            "510691f0-0000-4000-8000-000000000010",
            "person",
            "Rebuild sender",
        ),
        (
            "510691f0-0000-4000-8000-000000000011",
            "person",
            "Rebuild recipient",
        ),
    ] {
        harness
            .call(
                database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id": id,
                    "type": "Entity",
                    "kind": kind,
                    "name": name,
                    "reason": REBUILD_REASON,
                }),
            )
            .await
            .unwrap();
    }
    harness
        .provision_member(
            database,
            "510691f0-0000-4000-8000-000000000010",
            "acct:rebuild-sender",
            "native/rebuild-sender",
        )
        .await
        .unwrap();
    harness
        .provision_member(
            database,
            "510691f0-0000-4000-8000-000000000011",
            "acct:rebuild-recipient",
            "native/rebuild-recipient",
        )
        .await
        .unwrap();
    harness
        .call(
            database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "510691f0-0000-4000-8000-000000000001",
                "type": "Outcome",
                "kind": "target",
                "name": "Rebuild target",
                "reason": REBUILD_REASON,
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "510691f0-0000-4000-8000-000000000002",
                "type": "WorkItem",
                "kind": "task",
                "name": "Rebuild source",
                "facets": { "effort": "small" },
                "links": [{
                    "target_id": "510691f0-0000-4000-8000-000000000001",
                    "relationship": "implements"
                }],
                "reason": REBUILD_REASON,
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": "510691f0-0000-4000-8000-000000000002",
                "name": "Rebuild source updated",
                "facets": { "effort": "medium" },
                "reason": REBUILD_REASON,
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            database,
            TestCaller::Local,
            "archive_record",
            json!({
                "id": "510691f0-0000-4000-8000-000000000001",
                "reason": REBUILD_REASON,
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": "510691f0-0000-4000-8000-000000000003",
                "type": "WorkItem",
                "kind": "task",
                "name": "Rebuild tombstone",
                "reason": REBUILD_REASON,
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            database,
            TestCaller::Local,
            "delete_record",
            json!({
                "id": "510691f0-0000-4000-8000-000000000003",
                "reason": REBUILD_REASON,
            }),
        )
        .await
        .unwrap();
    harness
        .deliver_message_fixture(
            database,
            TestCaller::member("acct:rebuild-sender"),
            DeliveredMessageFixture {
                id: "510691f0-0000-4000-8000-000000000012",
                name: "Rebuild message",
                body: "A message whose audience must survive the fold.",
                addressed_to: &["510691f0-0000-4000-8000-000000000011"],
                idempotency_key: "postgres-rebuild-and-diff:message",
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_content_rebuild_and_diff_reproduces_its_own_log() {
    let harness = live_harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    seed_rebuild_fixture(&harness, &database).await;

    // Positive evidence the fixture really appended a gapless log from seq 1,
    // and that the check replays exactly that log.
    let sequences = event_sequences(&database).await.unwrap();
    eprintln!("live content_events seqs: {sequences:?}");
    assert!(
        !sequences.is_empty(),
        "the fixture must append content events before the fold can be checked"
    );
    assert_eq!(
        sequences,
        (1..=sequences.len() as i64).collect::<Vec<_>>(),
        "content log must be gapless from seq 1"
    );
    // Prove the compared `deleted_at` column is non-null on the live side, so
    // its equality is a real comparison rather than two nulls.
    let records_table = database.qualified_table("records").unwrap();
    let tombstoned: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {records_table} WHERE deleted_at IS NOT NULL"
    ))
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        tombstoned, 1,
        "the fixture must produce exactly one tombstoned record"
    );

    let diff = database.rebuild_and_diff_content().await.unwrap();
    eprintln!("{}", describe_diff(&diff));
    assert_eq!(
        diff.event_count,
        sequences.len(),
        "the check must replay every content event"
    );
    let records = diff
        .tables
        .iter()
        .find(|table| table.table == "records")
        .expect("records is a compared table");
    assert!(
        records.live > 0,
        "the fixture must produce live projection rows"
    );
    let audience = diff
        .tables
        .iter()
        .find(|table| table.table == "message_audience")
        .expect("message_audience is a compared table");
    assert!(
        audience.live > 0,
        "the delivered Message must project an audience row"
    );
    assert!(
        diff.equal,
        "Postgres content fold diverged from its own log:\n{}",
        describe_diff(&diff)
    );

    harness.close(&database).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_content_rebuild_and_diff_detects_projection_drift() {
    let harness = live_harness().await;
    let database = harness.fresh_logical_database().await.unwrap();
    seed_rebuild_fixture(&harness, &database).await;

    // Directly corrupt one projection row. This is a test fixture, not a write
    // path: the log still says "Rebuild source updated", so the rebuilt value
    // must differ and the check must say so.
    let records = database.qualified_table("records").unwrap();
    let updated = sqlx::query(&format!(
        "UPDATE {records} SET name='deliberately corrupted' WHERE id=$1"
    ))
    .bind("510691f0-0000-4000-8000-000000000002")
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(updated.rows_affected(), 1);

    let diff = database.rebuild_and_diff_content().await.unwrap();
    assert!(
        !diff.equal,
        "a projection row mutated behind the log must be detected"
    );
    let records_diff = diff
        .tables
        .iter()
        .find(|table| table.table == "records")
        .expect("records is a compared table");
    assert!(
        !records_diff.mismatches.is_empty(),
        "the corrupted row must appear as a mismatch:\n{}",
        describe_diff(&diff)
    );

    harness.close(&database).await;
    harness.shutdown().await;
}
