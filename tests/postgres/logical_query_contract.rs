#![cfg(feature = "postgres-tests")]

use crate::contract::{ContractHarness, PostgresHarness, TestCaller};
use serde_json::json;

#[tokio::test]
async fn postgres_live_logical_query_is_bounded_filtered_and_deterministic() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres query receipts");
    let harness = PostgresHarness::connect(&url).await.unwrap();
    crate::contract::scenarios::portable_logical_query(&harness, true)
        .await
        .unwrap();
    harness.shutdown().await;
}

#[tokio::test]
async fn postgres_facet_numeric_projection_is_total_and_canonical() {
    let url = std::env::var("NATIVE_CE_POSTGRES_TEST_URL")
        .expect("NATIVE_CE_POSTGRES_TEST_URL is required for Postgres query receipts");
    let harness = PostgresHarness::connect(&url).await.unwrap();
    let database = harness.fresh_logical_database().await.unwrap();
    let folder = "9c150000-0000-4000-8000-007000000007";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":folder,"type":"Collection","kind":"folder",
                "name":"Numeric projection","home_id":"native:unfiled",
                "reason":"Exercise total Postgres numeric facet projection."
            }),
        )
        .await
        .unwrap();
    let fixtures = [
        ("9c150000-0000-4000-8000-007000000002", "Numeric JSON", "2"),
        (
            "9c150000-0000-4000-8000-007000000008",
            "Numeric text",
            "\"3\"",
        ),
        (
            "9c150000-0000-4000-8000-007000000010",
            "Numeric whitespace",
            "\" \\t4\\n \"",
        ),
        (
            "9c150000-0000-4000-8000-007000000003",
            "Numeric looking",
            "\"05\"",
        ),
        (
            "9c150000-0000-4000-8000-007000000001",
            "Numeric invalid",
            "\"not-a-number\"",
        ),
        (
            "9c150000-0000-4000-8000-007000000005",
            "Numeric null",
            "null",
        ),
        (
            "9c150000-0000-4000-8000-007000000006",
            "Numeric overflow",
            "\"1e400\"",
        ),
        (
            "9c150000-0000-4000-8000-007000000009",
            "A positive underflow",
            "\"1e-400\"",
        ),
        (
            "9c150000-0000-4000-8000-007000000004",
            "Z negative underflow",
            "\"-1e-400\"",
        ),
    ];
    for (id, name, _) in fixtures {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id":id,"type":"Document","kind":"note","name":name,
                    "home_id":folder,"facets":{"amount":"seed"},
                    "reason":"Exercise total Postgres numeric facet projection."
                }),
            )
            .await
            .unwrap();
    }
    let facet_values = database.qualified_table("facet_values").unwrap();
    for (id, _, physical_json) in fixtures {
        sqlx::query(&format!(
            "UPDATE {facet_values} SET value=$2::jsonb WHERE record_id=$1 AND key='amount'"
        ))
        .bind(id)
        .bind(physical_json)
        .execute(database.pool())
        .await
        .unwrap();
    }

    let filtered = harness
        .call(
            &database,
            TestCaller::Local,
            "query_record",
            json!({
                "steps":[{"step":"filter","ancestor_id":folder,"facets":[{"key":"amount","gte":2}]}],
                "facet_order":{"key":"amount","lane":"number","direction":"desc"},
                "limit":100,"offset":0
            }),
        )
        .await
        .unwrap();
    assert_eq!(filtered["total"], 3);
    assert_eq!(
        filtered["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "9c150000-0000-4000-8000-007000000010",
            "9c150000-0000-4000-8000-007000000008",
            "9c150000-0000-4000-8000-007000000002"
        ]
    );

    let zero_and_finite = harness
        .call(
            &database,
            TestCaller::Local,
            "query_record",
            json!({
                "steps":[{"step":"filter","ancestor_id":folder,"facets":[{"key":"amount","gte":0}]}],
                "facet_order":{"key":"amount","lane":"number","direction":"asc"},
                "order":"name_asc","limit":100,"offset":0
            }),
        )
        .await
        .unwrap();
    assert_eq!(zero_and_finite["total"], 5);
    assert_eq!(
        zero_and_finite["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "9c150000-0000-4000-8000-007000000004",
            "9c150000-0000-4000-8000-007000000009",
            "9c150000-0000-4000-8000-007000000002",
            "9c150000-0000-4000-8000-007000000008",
            "9c150000-0000-4000-8000-007000000010"
        ]
    );

    database.drop_schema().await.unwrap();
    harness.shutdown().await;
}
