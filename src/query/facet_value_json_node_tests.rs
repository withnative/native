//! Independent facet-value occurrence, authorization and catalog oracles.
use super::*;
use crate::events::FacetSetPayload;
use crate::store::{create_record, set_facet};
use serde_json::json;

const COLUMNS: [&str; 13] = [
    "facet_id",
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

async fn facet(db: &Db, record_id: &str, key: &str, value: &str) {
    set_facet(
        db,
        record_id,
        FacetSetPayload {
            key: key.into(),
            value: Some(value.into()),
            vocab_ref: None,
            as_of: None,
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
            "SELECT n.ordinal,n.path,n.member_key,n.array_index,n.depth,n.node_type,\
                    n.text_value,n.number_text,n.bool_value,n.interpretation \
             FROM facet_value_json_nodes n JOIN facet_values f ON f.id=n.facet_id \
             WHERE f.key='{key}' ORDER BY n.ordinal"
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn facet_value_nodes_object_rows_and_interpretation() {
    let db = crate::create_database(":memory:").await.unwrap();
    record(&db, "9e795ca1-0000-4000-8000-000000000011", "visible").await;
    facet(
        &db,
        "9e795ca1-0000-4000-8000-000000000011",
        "config",
        r#"{"team":"core","members":[1,2],"active":true}"#,
    )
    .await;
    let result = rows(&db, local(), "config").await;
    assert_eq!(
        result.columns,
        [
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
    assert_eq!(
        result.rows,
        vec![
            json!({"ordinal":0,"path":"","member_key":null,"array_index":null,"depth":0,"node_type":"object","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"ordinal":1,"path":"/team","member_key":"team","array_index":null,"depth":1,"node_type":"string","text_value":"core","number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"ordinal":2,"path":"/members","member_key":"members","array_index":null,"depth":1,"node_type":"array","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"ordinal":3,"path":"/members/0","member_key":null,"array_index":0,"depth":2,"node_type":"number","text_value":null,"number_text":"1","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"ordinal":4,"path":"/members/1","member_key":null,"array_index":1,"depth":2,"node_type":"number","text_value":null,"number_text":"2","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"ordinal":5,"path":"/active","member_key":"active","array_index":null,"depth":1,"node_type":"boolean","text_value":null,"number_text":null,"bool_value":1,"interpretation":"parsed_text_candidate"}),
        ]
    );
}

#[tokio::test]
async fn facet_value_nodes_follow_facet_visibility() {
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let db = crate::create_database(":memory:").await.unwrap();
    const A: &str = "9e795ca1-0000-4000-8000-000000000012";
    const B: &str = "9e795ca1-0000-4000-8000-000000000013";
    record(&db, A, "alice").await;
    record(&db, B, "bea").await;
    replace_explicit_policy(
        &db,
        "policy:facet-nodes",
        A,
        vec![AllowEntry::account("acct:facet-alice", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "policy:facet-nodes",
        B,
        vec![AllowEntry::account("acct:facet-bea", Capability::View)],
    )
    .await
    .unwrap();
    for id in [A, B] {
        facet(&db, id, "config", r#"{"team":"core"}"#).await;
    }
    let alice = QueryPrincipal::authenticated("acct:facet-alice", true);
    let bea = QueryPrincipal::authenticated("acct:facet-bea", true);
    // A node is visible iff its facet row is.
    assert_eq!(rows(&db, alice.clone(), "config").await.rows.len(), 2);
    assert_eq!(rows(&db, bea.clone(), "config").await.rows.len(), 2);
    let hidden = query_sql(
        &db,
        alice.clone(),
        &format!(
            "SELECT count(*) AS n FROM facet_value_json_nodes n JOIN facet_values f ON f.id=n.facet_id \
             WHERE f.record_id='{B}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(hidden.rows, vec![json!({"n":0})]);
    // The fence is the same join the facet view uses, not a re-implementation:
    // bea still sees her own node.
    let bea_hidden = query_sql(
        &db,
        bea,
        &format!(
            "SELECT count(*) AS n FROM facet_value_json_nodes n JOIN facet_values f ON f.id=n.facet_id \
             WHERE f.record_id='{A}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(bea_hidden.rows, vec![json!({"n":0})]);
}

#[tokio::test]
async fn facet_value_nodes_scalar_and_malformed_have_no_rows() {
    let db = crate::create_database(":memory:").await.unwrap();
    record(&db, "9e795ca1-0000-4000-8000-000000000014", "scalar").await;
    facet(&db, "9e795ca1-0000-4000-8000-000000000014", "count", "5").await;
    facet(
        &db,
        "9e795ca1-0000-4000-8000-000000000014",
        "note",
        r#""plain text""#,
    )
    .await;
    facet(
        &db,
        "9e795ca1-0000-4000-8000-000000000014",
        "broken",
        "{oops",
    )
    .await;
    facet(
        &db,
        "9e795ca1-0000-4000-8000-000000000014",
        "ok",
        r#"{"a":1}"#,
    )
    .await;
    for key in ["count", "note", "broken"] {
        assert!(
            rows(&db, local(), key).await.rows.is_empty(),
            "{key} must have no nodes"
        );
        // The facet row itself is unaffected.
        let facet_rows = query_sql(
            &db,
            local(),
            &format!("SELECT count(*) AS n FROM facet_values WHERE key='{key}'"),
        )
        .await
        .unwrap();
        assert_eq!(facet_rows.rows, vec![json!({"n":1})], "{key}");
    }
    assert_eq!(rows(&db, local(), "ok").await.rows.len(), 2);
}

#[tokio::test]
async fn facet_value_nodes_catalog_lists_relation_and_columns() {
    let db = crate::create_database(":memory:").await.unwrap();
    let catalog = query_sql(
        &db,
        local(),
        "SELECT identity,semantic_version,caller_relative,completeness,profiles \
         FROM catalog_relations WHERE relation_name='facet_value_json_nodes'",
    )
    .await
    .unwrap();
    assert_eq!(
        catalog.rows,
        vec![json!({
            "identity": "native.query-sql.facet-value-json-nodes",
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
         WHERE relation_name='facet_value_json_nodes' ORDER BY column_position",
    )
    .await
    .unwrap();
    assert_eq!(
        columns.rows,
        COLUMNS.map(|column| json!({"column_name": column}))
    );
    // Physical access and the main schema stay blocked.
    for sql in [
        "SELECT * FROM main.facet_value_json_nodes",
        "INSERT INTO facet_value_json_nodes(facet_id,ordinal) VALUES('x',0)",
        "DELETE FROM facet_value_json_nodes",
    ] {
        assert!(query_sql(&db, local(), sql).await.is_err(), "{sql}");
    }
}

#[test]
fn facet_value_nodes_saved_pins_and_unsupported_profiles() {
    use native_query_contract::rule_contract::check_relation_pin;
    let snapshot = current_catalog_snapshot();
    assert_eq!(
        sql_contract::logical_columns(
            "facet_value_json_nodes",
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
            sql_contract::logical_columns("facet_value_json_nodes", profile).is_none(),
            "{profile:?} must refuse facet_value_json_nodes"
        );
    }
    let readset = extract_rule_input_dependencies(
        "SELECT n.ordinal,n.number_text FROM facet_value_json_nodes n \
         JOIN facet_values f ON f.id=n.facet_id WHERE f.key='config' ORDER BY n.ordinal",
    )
    .unwrap();
    let pin = readset
        .relations
        .iter()
        .find(|pin| pin.identity == "native.query-sql.facet-value-json-nodes")
        .unwrap();
    assert_eq!(pin.semantic_version, 1);
    for pin in &readset.relations {
        check_relation_pin(&snapshot, pin).unwrap();
    }
}
