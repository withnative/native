//! Focused regression coverage for the multiplayer board assessment (01cbd13).
//!
//! A card move is one open-facet write. Two accounts moving the same card must
//! both leave attributable events, while the current projection reflects the
//! event SQLite serialized last.

use std::sync::Arc;

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::json;
use sqlx::Row;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_card_moves_preserve_both_events_and_project_the_last() {
    let db = db().await;
    let registry = Arc::new(registry());
    let card_id = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": "Shared card",
                "reason": "Seed the card used by the multiplayer regression test."
            }),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (actor, stage) in [("acct_richard", "in_progress"), ("acct_george", "done")] {
        let (registry, db, card_id, barrier) = (
            Arc::clone(&registry),
            db.clone(),
            card_id.clone(),
            Arc::clone(&barrier),
        );
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            registry
                .call(
                    db,
                    Caller::authenticated(actor),
                    "update_record",
                    json!({
                        "id": card_id,
                        "facets": { "stage": stage },
                        "reason": "Move the shared card to the selected stage."
                    }),
                )
                .await
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    let events = sqlx::query(
        "SELECT seq, actor, json_extract(payload, '$.value') AS value
           FROM content_events
          WHERE record_id = ? AND type = 'facet.set' AND json_extract(payload, '$.key') = 'stage'
          ORDER BY seq",
    )
    .bind(&card_id)
    .fetch_all(db.pool())
    .await
    .unwrap();

    assert_eq!(
        events.len(),
        2,
        "neither account's move is lost from history"
    );
    assert!(events[0].get::<i64, _>("seq") < events[1].get::<i64, _>("seq"));

    let mut actors = events
        .iter()
        .map(|row| row.get::<String, _>("actor"))
        .collect::<Vec<_>>();
    actors.sort();
    assert_eq!(actors, ["acct_george", "acct_richard"]);

    let last_value = events[1].get::<String, _>("value");
    let projected_value: String =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = 'stage'")
            .bind(&card_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(projected_value, last_value);

    db.close().await;
}
