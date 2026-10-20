//! Independent facet-observation occurrence, authorization and catalog oracles.
use super::*;
use crate::events::FacetSetPayload;
use crate::store::{create_record, set_facet, unset_facet};
use serde_json::json;

const COLUMNS: [&str; 16] = [
    "observation_id",
    "record_id",
    "key",
    "as_of",
    "ordinal",
    "path",
    "parent_path",
    "parent_ordinal",
    "member_key",
    "array_index",
    "depth",
    "node_type",
    "text_value",
    "number_text",
    "bool_value",
    "interpretation",
];

fn local() -> QueryPrincipal {
    crate::mcp::Caller::local().into()
}

async fn record(db: &Db, id: &str, name: &str) {
    create_record(
        db,
        json!({
            "id": id,
            "type": "Document",
            "kind": "note",
            "name": name,
            "home_id": crate::schema::ROOT_RECORD_ID
        }),
    )
    .await
    .unwrap();
}

async fn observation(db: &Db, record_id: &str, key: &str, value: &str, as_of: &str) {
    set_facet(
        db,
        record_id,
        FacetSetPayload {
            key: key.into(),
            value: Some(value.into()),
            vocab_ref: None,
            as_of: Some(as_of.into()),
            observation_only: false,
        },
    )
    .await
    .unwrap();
}

async fn rows(db: &Db, caller: QueryPrincipal, key: &str) -> SqlResult {
    query_sql(
        db,
        caller,
        &format!(
            "SELECT n.observation_id,n.record_id,n.key,n.as_of,n.ordinal,n.path,\
                    n.member_key,n.array_index,n.depth,n.node_type,\
                    n.text_value,n.number_text,n.bool_value,n.interpretation \
             FROM facet_observation_json_nodes n WHERE n.key='{key}' ORDER BY n.ordinal"
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn facet_observation_nodes_object_rows_and_interpretation() {
    let db = crate::create_database(":memory:").await.unwrap();
    record(&db, "9e795ca1-0000-4000-8000-000000000021", "visible").await;
    observation(
        &db,
        "9e795ca1-0000-4000-8000-000000000021",
        "config",
        r#"{"team":"core","members":[1,2],"active":true}"#,
        "2024-01-01T00:00:00Z",
    )
    .await;
    let result = rows(&db, local(), "config").await;
    assert_eq!(
        result.columns,
        [
            "observation_id",
            "record_id",
            "key",
            "as_of",
            "ordinal",
            "path",
            "member_key",
            "array_index",
            "depth",
            "node_type",
            "text_value",
            "number_text",
            "bool_value",
            "interpretation"
        ]
    );
    let observation_id = "fo:9e795ca1-0000-4000-8000-000000000021:config:2024-01-01T00:00:00Z";
    assert_eq!(
        result.rows,
        vec![
            json!({"observation_id":observation_id,"record_id":"9e795ca1-0000-4000-8000-000000000021","key":"config","as_of":"2024-01-01T00:00:00Z","ordinal":0,"path":"","member_key":null,"array_index":null,"depth":0,"node_type":"object","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"observation_id":observation_id,"record_id":"9e795ca1-0000-4000-8000-000000000021","key":"config","as_of":"2024-01-01T00:00:00Z","ordinal":1,"path":"/team","member_key":"team","array_index":null,"depth":1,"node_type":"string","text_value":"core","number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"observation_id":observation_id,"record_id":"9e795ca1-0000-4000-8000-000000000021","key":"config","as_of":"2024-01-01T00:00:00Z","ordinal":2,"path":"/members","member_key":"members","array_index":null,"depth":1,"node_type":"array","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"observation_id":observation_id,"record_id":"9e795ca1-0000-4000-8000-000000000021","key":"config","as_of":"2024-01-01T00:00:00Z","ordinal":3,"path":"/members/0","member_key":null,"array_index":0,"depth":2,"node_type":"number","text_value":null,"number_text":"1","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"observation_id":observation_id,"record_id":"9e795ca1-0000-4000-8000-000000000021","key":"config","as_of":"2024-01-01T00:00:00Z","ordinal":4,"path":"/members/1","member_key":null,"array_index":1,"depth":2,"node_type":"number","text_value":null,"number_text":"2","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"observation_id":observation_id,"record_id":"9e795ca1-0000-4000-8000-000000000021","key":"config","as_of":"2024-01-01T00:00:00Z","ordinal":5,"path":"/active","member_key":"active","array_index":null,"depth":1,"node_type":"boolean","text_value":null,"number_text":null,"bool_value":1,"interpretation":"parsed_text_candidate"}),
        ]
    );
}

#[tokio::test]
async fn facet_observation_nodes_follow_observation_visibility() {
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let db = crate::create_database(":memory:").await.unwrap();
    const A: &str = "9e795ca1-0000-4000-8000-000000000022";
    const B: &str = "9e795ca1-0000-4000-8000-000000000023";
    record(&db, A, "alice").await;
    record(&db, B, "bea").await;
    replace_explicit_policy(
        &db,
        "policy:facet-observation-nodes",
        A,
        vec![AllowEntry::account(
            "acct:facet-observation-alice",
            Capability::View,
        )],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "policy:facet-observation-nodes",
        B,
        vec![AllowEntry::account(
            "acct:facet-observation-bea",
            Capability::View,
        )],
    )
    .await
    .unwrap();
    for id in [A, B] {
        observation(
            &db,
            id,
            "config",
            r#"{"team":"core"}"#,
            "2024-01-01T00:00:00Z",
        )
        .await;
    }
    let alice = QueryPrincipal::authenticated("acct:facet-observation-alice", true);
    let bea = QueryPrincipal::authenticated("acct:facet-observation-bea", true);
    // A node is visible iff its observation row is.
    assert_eq!(rows(&db, alice.clone(), "config").await.rows.len(), 2);
    assert_eq!(rows(&db, bea.clone(), "config").await.rows.len(), 2);
    // The fence is exactly the facet_observations join, not a re-implementation.
    let hidden = query_sql(
        &db,
        alice.clone(),
        &format!(
            "SELECT count(*) AS n FROM facet_observation_json_nodes n JOIN facet_observations o ON o.id=n.observation_id \
             WHERE o.record_id='{B}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(hidden.rows, vec![json!({"n":0})]);
    let bea_hidden = query_sql(
        &db,
        bea,
        &format!(
            "SELECT count(*) AS n FROM facet_observation_json_nodes n JOIN facet_observations o ON o.id=n.observation_id \
             WHERE o.record_id='{A}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(bea_hidden.rows, vec![json!({"n":0})]);
}

#[tokio::test]
async fn facet_observation_nodes_scalar_malformed_and_unset_have_no_rows() {
    let db = crate::create_database(":memory:").await.unwrap();
    record(&db, "9e795ca1-0000-4000-8000-000000000024", "scalar").await;
    observation(
        &db,
        "9e795ca1-0000-4000-8000-000000000024",
        "count",
        "5",
        "2024-02-01T00:00:00Z",
    )
    .await;
    observation(
        &db,
        "9e795ca1-0000-4000-8000-000000000024",
        "note",
        r#""plain text""#,
        "2024-02-02T00:00:00Z",
    )
    .await;
    observation(
        &db,
        "9e795ca1-0000-4000-8000-000000000024",
        "broken",
        "{oops",
        "2024-02-03T00:00:00Z",
    )
    .await;
    observation(
        &db,
        "9e795ca1-0000-4000-8000-000000000024",
        "ok",
        r#"{"a":1}"#,
        "2024-02-04T00:00:00Z",
    )
    .await;
    unset_facet(&db, "9e795ca1-0000-4000-8000-000000000024", "gone")
        .await
        .unwrap();
    for key in ["count", "note", "broken", "gone"] {
        assert!(
            rows(&db, local(), key).await.rows.is_empty(),
            "{key} must have no nodes"
        );
        // The observation row itself is unaffected.
        let observation_rows = query_sql(
            &db,
            local(),
            &format!("SELECT count(*) AS n FROM facet_observations WHERE key='{key}'"),
        )
        .await
        .unwrap();
        assert_eq!(observation_rows.rows, vec![json!({"n":1})], "{key}");
    }
    assert_eq!(rows(&db, local(), "ok").await.rows.len(), 2);
}

#[tokio::test]
async fn facet_observation_nodes_catalog_lists_relation_and_columns() {
    let db = crate::create_database(":memory:").await.unwrap();
    let catalog = query_sql(
        &db,
        local(),
        "SELECT identity,semantic_version,caller_relative,completeness,profiles \
         FROM catalog_relations WHERE relation_name='facet_observation_json_nodes'",
    )
    .await
    .unwrap();
    assert_eq!(
        catalog.rows,
        vec![json!({
            "identity": "native.query-sql.facet-observation-json-nodes",
            "semantic_version": 1,
            "caller_relative": 1,
            "completeness": "complete",
            "profiles": "sqlite-local"
        })]
    );
    let columns = query_sql(
        &db,
        local(),
        "SELECT column_name FROM catalog_columns \
         WHERE relation_name='facet_observation_json_nodes' ORDER BY column_position",
    )
    .await
    .unwrap();
    assert_eq!(
        columns.rows,
        COLUMNS.map(|column| json!({"column_name": column}))
    );
    // Physical access and the main schema stay blocked.
    for sql in [
        "SELECT * FROM main.facet_observation_json_nodes",
        "INSERT INTO facet_observation_json_nodes(observation_id,ordinal) VALUES('x',0)",
        "DELETE FROM facet_observation_json_nodes",
    ] {
        assert!(query_sql(&db, local(), sql).await.is_err(), "{sql}");
    }
}

#[test]
fn facet_observation_nodes_saved_pins_and_unsupported_profiles() {
    use native_query_contract::rule_contract::check_relation_pin;
    let snapshot = current_catalog_snapshot();
    assert_eq!(
        sql_contract::logical_columns(
            "facet_observation_json_nodes",
            sql_contract::QuerySqlProfile::SqliteLocal
        )
        .unwrap(),
        COLUMNS
    );
    for profile in [
        sql_contract::QuerySqlProfile::PostgresServer,
        sql_contract::QuerySqlProfile::TursoLocal,
    ] {
        assert!(
            sql_contract::logical_columns("facet_observation_json_nodes", profile).is_none(),
            "{profile:?} must refuse facet_observation_json_nodes"
        );
    }
    let readset = extract_rule_input_dependencies(
        "SELECT n.ordinal,n.number_text FROM facet_observation_json_nodes n \
         JOIN facet_observations o ON o.id=n.observation_id WHERE o.key='config' ORDER BY n.ordinal",
    )
    .unwrap();
    let pin = readset
        .relations
        .iter()
        .find(|pin| pin.identity == "native.query-sql.facet-observation-json-nodes")
        .unwrap();
    assert_eq!(pin.semantic_version, 1);
    for pin in &readset.relations {
        check_relation_pin(&snapshot, pin).unwrap();
    }
}
