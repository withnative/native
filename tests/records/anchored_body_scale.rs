// Scale guard: opening an anchored record must not cost the workspace log.
//
// Builds one passage-anchored comment, then appends N and 30N unrelated
// content events. Uses only long-stable public API so the same test runs
// against pre-fix code, where it must fail.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

/// Median `get_record` (with comments) latency over three runs.
async fn read_ms(registry: &ToolRegistry, db: &Db, target: &str) -> Duration {
    let mut samples = Vec::with_capacity(3);
    for _ in 0..3 {
        let started = Instant::now();
        let read = call(
            registry,
            db,
            "get_record",
            json!({ "ids": [target], "include_comments": true }),
        )
        .await;
        assert_eq!(
            read["records"][0]["comments"][0]["target"]["anchored"]["excerpt"]["text"],
            "probe passage"
        );
        samples.push(started.elapsed());
    }
    samples.sort();
    samples[1]
}

async fn probe_target(registry: &ToolRegistry, db: &Db, comment_id: &str) -> String {
    let target = call(
        registry,
        db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Probe", "body": "a scale probe passage here" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        registry,
        db,
        "create_record",
        json!({
            "id": comment_id,
            "type": "Annotation",
            "kind": "comment",
            "body": "scale probe comment",
            "lifecycle": "open",
            "links": [{ "target_id": target, "relationship": "part_of" }],
            "target": {
                "target_record_id": target,
                "source_slot": "body",
                "purpose": "comment_context",
                "selectors": [
                    { "type": "text_quote", "exact": "probe passage", "prefix": "a scale ", "suffix": " here" },
                    { "type": "data_position", "start": 8, "end": 21 }
                ]
            }
        }),
    )
    .await;
    target
}

#[tokio::test]
async fn anchored_comment_reads_stay_flat_as_the_unrelated_log_grows() {
    let db = db().await;
    let registry = registry();

    // Unrelated log growth: valid `record.updated` rows inserted directly
    // into the content log for one filler record. The whole-log replay must
    // still project every one of them (body write plus FTS maintenance), so
    // replay cost separates from the fixed scratch open/schema overhead at
    // modest counts; the per-record fold never reads these rows at all.
    // Payloads carry ~20KB bodies so the replay's FTS churn resembles a real
    // workspace log rather than a micro-benchmark of empty updates.
    //
    // Ordering matters: a body anchor replays the log prefix *up to its own
    // source seq*, so the fillers must precede the anchored record. Each
    // phase therefore builds an identically shaped probe target after its
    // fillers and times opening that target.
    let filler = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Filler", "body": "filler zero" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let padding: String = "x".repeat(20_000);
    async fn grow(db: &Db, filler: &str, padding: &str, from: i64, to: i64) {
        let pool = crate::common::fixture_write_pool(db).await;
        let mut tx = pool.begin().await.unwrap();
        for i in from..to {
            let payload =
                serde_json::json!({ "body": format!("unrelated filler body {i} {padding}") })
                    .to_string();
            sqlx::query(
                "INSERT INTO content_events
                    (id, record_id, type, payload, causal_envelope_version, causal_status)
                 VALUES (?, ?, 'record.updated', ?, 1, 'complete')",
            )
            .bind(format!("filler-bulk-event-{i}"))
            .bind(filler)
            .bind(payload)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }
    const N: i64 = 100;
    grow(&db, &filler, &padding, 0, N).await;
    let small_target = probe_target(&registry, &db, "c0aa0000-0000-4000-8000-000000000201").await;
    // Warm up pools, statement caches, and the read path itself so both
    // phases below measure steady-state resolution, not cold start.
    let _ = read_ms(&registry, &db, &small_target).await;
    let small = read_ms(&registry, &db, &small_target).await;
    grow(&db, &filler, &padding, N, 30 * N).await;
    let large_target = probe_target(&registry, &db, "c0aa0000-0000-4000-8000-000000000202").await;
    let large = read_ms(&registry, &db, &large_target).await;

    // Absolute ceiling first (generous: a slow runner must not flake), then
    // the ratio that fails on whole-log replay. The floor keeps a fast
    // `small` from turning noise into a failure.
    assert!(
        large < Duration::from_secs(10),
        "anchored read took {large:?} with 30N unrelated events"
    );
    let floor = Duration::from_millis(20);
    println!(
        "anchored read latency: {small:?} at {N} unrelated events, {large:?} at {} events",
        30 * N
    );
    assert!(
        large <= 4 * small.max(floor),
        "anchored read grew with the unrelated log: {small:?} at N events versus {large:?} at 30N"
    );
}
