//! Reproducible, opt-in measurements for the semantic bulk operations.
//!
//! Elapsed time is diagnostic evidence rather than a correctness gate. The
//! ordinary suite returns immediately unless the explicit measurement
//! environment flag is set. Run it single-threaded with `--nocapture` to emit
//! one compact JSON report. Assertions cover equivalent semantic completion,
//! never relative timing.

use std::time::Instant;

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde::Serialize;
use serde_json::{json, Value};

const WORKLOAD_SIZE: usize = 8;
const UPDATE_WORKLOAD_SIZE: usize = 51;

#[derive(Serialize)]
struct Measurement {
    operation: &'static str,
    strategy: &'static str,
    operation_round_trips: usize,
    compact_request_bytes: usize,
    compact_response_bytes: usize,
    elapsed_us: u128,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    workload_size: usize,
    update_workload_size: usize,
    timing_scope: &'static str,
    singular_resolve_baseline: &'static str,
    measurements: Vec<Measurement>,
}

async fn seed_update_fixture(registry: &ToolRegistry, db: &Db) -> Vec<String> {
    let mut ids = Vec::with_capacity(UPDATE_WORKLOAD_SIZE);
    for index in 0..UPDATE_WORKLOAD_SIZE {
        let response = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type":"WorkItem",
                    "kind":"task",
                    "name":format!("Measured update target {index:02}"),
                    "facets":{"triage":"untriaged"},
                    "reason":"Seed the homogeneous update measurement fixture."
                }),
            )
            .await
            .unwrap();
        ids.push(response["id"].as_str().unwrap().to_owned());
    }
    ids
}

async fn measure_update(registry: &ToolRegistry) -> Vec<Measurement> {
    let bulk_db = create_database(":memory:").await.unwrap();
    let singular_db = create_database(":memory:").await.unwrap();
    let bulk_ids = seed_update_fixture(registry, &bulk_db).await;
    let singular_ids = seed_update_fixture(registry, &singular_db).await;
    let reason =
        "Measure one homogeneous current-facet update against repeated update_record calls.";
    let (bulk, bulk_responses) = measure(
        registry,
        &bulk_db,
        "update_record.multi",
        "homogeneous_multi_target",
        vec![(
            "update_record",
            json!({
                "ids":bulk_ids.clone(),
                "facets":{"triage":"completed"},
                "if_facets":{"triage":"untriaged"},
                "reason":reason
            }),
        )],
    )
    .await;
    let (singular, singular_responses) = measure(
        registry,
        &singular_db,
        "update_record.multi",
        "repeated_singular",
        singular_ids
            .iter()
            .map(|id| {
                (
                    "update_record",
                    json!({"id":id,"facets":{"triage":"completed"},"reason":reason}),
                )
            })
            .collect(),
    )
    .await;

    assert_eq!(bulk_responses[0]["requested"], UPDATE_WORKLOAD_SIZE);
    assert_eq!(bulk_responses[0]["changed"], UPDATE_WORKLOAD_SIZE);
    assert_eq!(singular_responses.len(), UPDATE_WORKLOAD_SIZE);
    for (db, ids) in [(&bulk_db, &bulk_ids), (&singular_db, &singular_ids)] {
        let completed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_values WHERE key='triage' AND value='completed'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(completed as usize, ids.len());
    }
    vec![bulk, singular]
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn measure(
    registry: &ToolRegistry,
    db: &Db,
    operation: &'static str,
    strategy: &'static str,
    calls: Vec<(&'static str, Value)>,
) -> (Measurement, Vec<Value>) {
    let compact_request_bytes = calls
        .iter()
        .map(|(tool, arguments)| {
            serde_json::to_vec(&json!({"tool":tool,"arguments":arguments}))
                .unwrap()
                .len()
        })
        .sum();
    let operation_round_trips = calls.len();
    let started = Instant::now();
    let mut responses = Vec::with_capacity(operation_round_trips);
    for (tool, arguments) in calls {
        responses.push(
            registry
                .call(db.clone(), Caller::local(), tool, arguments)
                .await
                .unwrap(),
        );
    }
    let elapsed_us = started.elapsed().as_micros();
    let compact_response_bytes = responses
        .iter()
        .map(|response| serde_json::to_vec(response).unwrap().len())
        .sum();
    (
        Measurement {
            operation,
            strategy,
            operation_round_trips,
            compact_request_bytes,
            compact_response_bytes,
            elapsed_us,
        },
        responses,
    )
}

fn create_arguments(index: usize) -> Value {
    json!({
        "type":"Document",
        "kind":"note",
        "name":format!("Measured create {index:02}"),
        "body":format!("Deterministic measurement payload {index:02}."),
        "reason":"Measure semantic bulk creation against repeated create_record calls."
    })
}

async fn measure_create(registry: &ToolRegistry) -> Vec<Measurement> {
    let bulk_db = create_database(":memory:").await.unwrap();
    let singular_db = create_database(":memory:").await.unwrap();
    let records = (0..WORKLOAD_SIZE)
        .map(|index| {
            let mut value = create_arguments(index);
            value.as_object_mut().unwrap().remove("reason");
            value
        })
        .collect::<Vec<_>>();
    let (bulk, bulk_responses) = measure(
        registry,
        &bulk_db,
        "create_many",
        "semantic_bulk",
        vec![(
            "create_many",
            json!({
                "records":records,
                "reason":"Measure semantic bulk creation against repeated create_record calls."
            }),
        )],
    )
    .await;
    let (singular, singular_responses) = measure(
        registry,
        &singular_db,
        "create_many",
        "repeated_singular",
        (0..WORKLOAD_SIZE)
            .map(|index| ("create_record", create_arguments(index)))
            .collect(),
    )
    .await;

    assert_eq!(bulk_responses[0]["ok"], true);
    assert_eq!(
        bulk_responses[0]["ids"].as_array().unwrap().len(),
        WORKLOAD_SIZE
    );
    assert_eq!(singular_responses.len(), WORKLOAD_SIZE);
    assert!(singular_responses
        .iter()
        .all(|response| response["id"].is_string()));
    for db in [&bulk_db, &singular_db] {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE name LIKE 'Measured create %'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(count as usize, WORKLOAD_SIZE);
    }
    vec![bulk, singular]
}

async fn seed_resolution_fixture(registry: &ToolRegistry, db: &Db) -> Vec<String> {
    let names = (0..WORKLOAD_SIZE)
        .map(|index| format!("resolveprobe{index:02}"))
        .collect::<Vec<_>>();
    for name in &names {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type":"Entity",
                    "kind":"person",
                    "name":name,
                    "reason":"Seed the exact-name resolution measurement fixture."
                }),
            )
            .await
            .unwrap();
    }
    names
}

async fn measure_resolve(registry: &ToolRegistry) -> Vec<Measurement> {
    let bulk_db = create_database(":memory:").await.unwrap();
    let singular_db = create_database(":memory:").await.unwrap();
    let names = seed_resolution_fixture(registry, &bulk_db).await;
    assert_eq!(seed_resolution_fixture(registry, &singular_db).await, names);
    let (bulk, bulk_responses) = measure(
        registry,
        &bulk_db,
        "resolve_many",
        "semantic_bulk",
        vec![(
            "resolve_many",
            json!({"names":names,"type":"Entity","kind":"person"}),
        )],
    )
    .await;
    let (singular, singular_responses) = measure(
        registry,
        &singular_db,
        "resolve_many",
        "repeated_singular_search_exact_filter",
        names
            .iter()
            .map(|name| ("search", json!({"query":name,"limit":10})))
            .collect(),
    )
    .await;

    let results = bulk_responses[0]["results"].as_array().unwrap();
    assert_eq!(results.len(), WORKLOAD_SIZE);
    assert!(results.iter().all(|result| result["status"] == "resolved"));
    for (name, response) in names.iter().zip(&singular_responses) {
        let exact = response["hits"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|hit| hit["name"] == name.as_str())
            .count();
        assert_eq!(exact, 1, "singular search did not yield one exact match");
    }
    vec![bulk, singular]
}

async fn seed_policy_fixture(registry: &ToolRegistry, db: &Db) -> Vec<String> {
    let mut ids = Vec::with_capacity(WORKLOAD_SIZE);
    for index in 0..WORKLOAD_SIZE {
        let response = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type":"Document",
                    "kind":"note",
                    "name":format!("Measured policy target {index:02}"),
                    "reason":"Seed the exact policy convergence measurement fixture."
                }),
            )
            .await
            .unwrap();
        ids.push(response["id"].as_str().unwrap().to_owned());
    }
    ids
}

async fn measure_policy(registry: &ToolRegistry) -> Vec<Measurement> {
    let bulk_db = create_database(":memory:").await.unwrap();
    let singular_db = create_database(":memory:").await.unwrap();
    let bulk_ids = seed_policy_fixture(registry, &bulk_db).await;
    let singular_ids = seed_policy_fixture(registry, &singular_db).await;
    let bulk_items = bulk_ids
        .iter()
        .enumerate()
        .map(|(index, record_id)| {
            json!({
                "record_id":record_id,
                "subject":{"kind":"account","account_id":format!("acct:measured:{index:02}")},
                "capability":"view"
            })
        })
        .collect::<Vec<_>>();
    let (bulk, bulk_responses) = measure(
        registry,
        &bulk_db,
        "manage_record_policy.set_many",
        "semantic_bulk",
        vec![(
            "manage_record_policy",
            json!({
                "action":"set_many",
                "items":bulk_items,
                "reason":"Measure atomic exact policy convergence against repeated grants."
            }),
        )],
    )
    .await;
    let (singular, singular_responses) = measure(
        registry,
        &singular_db,
        "manage_record_policy.set_many",
        "repeated_singular",
        singular_ids
            .iter()
            .enumerate()
            .map(|(index, record_id)| {
                (
                    "manage_record_policy",
                    json!({
                        "action":"grant",
                        "record_id":record_id,
                        "subject":{"kind":"account","account_id":format!("acct:measured:{index:02}")},
                        "capability":"view",
                        "reason":"Measure atomic exact policy convergence against repeated grants."
                    }),
                )
            })
            .collect(),
    )
    .await;

    assert_eq!(bulk_responses[0]["item_count"], WORKLOAD_SIZE);
    assert_eq!(bulk_responses[0]["changed_count"], WORKLOAD_SIZE);
    assert_eq!(singular_responses.len(), WORKLOAD_SIZE);
    for (db, ids) in [(&bulk_db, &bulk_ids), (&singular_db, &singular_ids)] {
        for (index, record_id) in ids.iter().enumerate() {
            let listed = registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "manage_record_policy",
                    json!({"action":"list","record_id":record_id}),
                )
                .await
                .unwrap();
            assert!(listed["entries"].as_array().unwrap().iter().any(|entry| {
                entry["subject"]["account_id"] == format!("acct:measured:{index:02}")
                    && entry["capability"] == "view"
            }));
        }
    }
    vec![bulk, singular]
}

#[tokio::test(flavor = "current_thread")]
async fn semantic_bulk_operations_measurement_report() {
    if std::env::var("NATIVE_RUN_SEMANTIC_BULK_MEASUREMENT").as_deref() != Ok("1") {
        return;
    }
    let registry = registry();
    let mut measurements = measure_create(&registry).await;
    measurements.extend(measure_resolve(&registry).await);
    measurements.extend(measure_policy(&registry).await);
    measurements.extend(measure_update(&registry).await);
    let report = Report {
        schema: "native.semantic-bulk-measurement.v1",
        workload_size: WORKLOAD_SIZE,
        update_workload_size: UPDATE_WORKLOAD_SIZE,
        timing_scope: "in-process ToolRegistry::call only; fixture setup and semantic validation excluded",
        singular_resolve_baseline: "one search call per name followed by client-side exact-name filtering; no singular exact-resolve tool exists",
        measurements,
    };
    println!("{}", serde_json::to_string(&report).unwrap());
}
