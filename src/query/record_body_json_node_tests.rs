//! Independent record-body occurrence, authorization and catalog oracles.
use super::*;
use crate::store::{create_record, delete_record, update_record};
use serde_json::json;

const COLUMNS: [&str; 13] = [
    "record_id",
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

async fn record(db: &Db, id: &str, name: &str, body: &str) {
    create_record(
        db,
        json!({
            "id": id,
            "type": "Document",
            "kind": "note",
            "name": name,
            "home_id": crate::schema::ROOT_RECORD_ID,
            "body": body,
        }),
    )
    .await
    .unwrap();
}

async fn rows(db: &Db, caller: QueryPrincipal, id: &str) -> SqlResult {
    query_sql(
        db,
        caller,
        &format!(
            "SELECT n.record_id,n.ordinal,n.path,\
                    n.member_key,n.array_index,n.depth,n.node_type,\
                    n.text_value,n.number_text,n.bool_value,n.interpretation \
             FROM record_body_json_nodes n WHERE n.record_id='{id}' ORDER BY n.ordinal"
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn record_body_nodes_object_rows_and_interpretation() {
    let db = crate::create_database(":memory:").await.unwrap();
    const ID: &str = "9e795ca1-0000-4000-8000-000000000031";
    record(
        &db,
        ID,
        "visible",
        r#"{"team":"core","members":[1,2],"active":true}"#,
    )
    .await;
    let result = rows(&db, local(), ID).await;
    assert_eq!(
        result.columns,
        [
            "record_id",
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
            json!({"record_id":ID,"ordinal":0,"path":"","member_key":null,"array_index":null,"depth":0,"node_type":"object","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":1,"path":"/team","member_key":"team","array_index":null,"depth":1,"node_type":"string","text_value":"core","number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":2,"path":"/members","member_key":"members","array_index":null,"depth":1,"node_type":"array","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":3,"path":"/members/0","member_key":null,"array_index":0,"depth":2,"node_type":"number","text_value":null,"number_text":"1","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":4,"path":"/members/1","member_key":null,"array_index":1,"depth":2,"node_type":"number","text_value":null,"number_text":"2","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":5,"path":"/active","member_key":"active","array_index":null,"depth":1,"node_type":"boolean","text_value":null,"number_text":null,"bool_value":1,"interpretation":"parsed_text_candidate"}),
        ]
    );
}

#[tokio::test]
async fn record_body_nodes_preserve_duplicates_escapes_and_number_tokens() {
    let db = crate::create_database(":memory:").await.unwrap();
    const ID: &str = "9e795ca1-0000-4000-8000-000000000032";
    // Raw stored text, not a Value object: duplicate keys, escaped pointer
    // segments and exact number lexemes must survive the projection.
    record(&db, ID, "lexemes", r#"{"a/b":1.00,"a/b":2E+09,"c~d":null}"#).await;
    let result = query_sql(
        &db,
        local(),
        &format!(
            "SELECT n.ordinal,n.path,n.parent_path,n.parent_ordinal,\
                    n.member_key,n.node_type,n.number_text \
             FROM record_body_json_nodes n WHERE n.record_id='{ID}' ORDER BY n.ordinal"
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        result.rows,
        vec![
            json!({"ordinal":0,"path":"","parent_path":null,"parent_ordinal":null,"member_key":null,"node_type":"object","number_text":null}),
            json!({"ordinal":1,"path":"/a~1b","parent_path":"","parent_ordinal":0,"member_key":"a/b","node_type":"number","number_text":"1.00"}),
            json!({"ordinal":2,"path":"/a~1b","parent_path":"","parent_ordinal":0,"member_key":"a/b","node_type":"number","number_text":"2E+09"}),
            json!({"ordinal":3,"path":"/c~0d","parent_path":"","parent_ordinal":0,"member_key":"c~d","node_type":"null","number_text":null}),
        ]
    );
}

#[tokio::test]
async fn record_body_nodes_replace_on_update_with_actual_values() {
    let db = crate::create_database(":memory:").await.unwrap();
    const ID: &str = "9e795ca1-0000-4000-8000-000000000033";
    record(&db, ID, "rewrite", r#"{"a":1}"#).await;
    assert_eq!(rows(&db, local(), ID).await.rows.len(), 2);
    update_record(&db, ID, json!({"body": r#"{"a":2,"b":[true]}"#}))
        .await
        .unwrap();
    let result = rows(&db, local(), ID).await;
    assert_eq!(
        result.rows,
        vec![
            json!({"record_id":ID,"ordinal":0,"path":"","member_key":null,"array_index":null,"depth":0,"node_type":"object","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":1,"path":"/a","member_key":"a","array_index":null,"depth":1,"node_type":"number","text_value":null,"number_text":"2","bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":2,"path":"/b","member_key":"b","array_index":null,"depth":1,"node_type":"array","text_value":null,"number_text":null,"bool_value":null,"interpretation":"parsed_text_candidate"}),
            json!({"record_id":ID,"ordinal":3,"path":"/b/0","member_key":null,"array_index":0,"depth":2,"node_type":"boolean","text_value":null,"number_text":null,"bool_value":1,"interpretation":"parsed_text_candidate"}),
        ]
    );
}

#[tokio::test]
async fn record_body_nodes_follow_record_visibility() {
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let db = crate::create_database(":memory:").await.unwrap();
    const A: &str = "9e795ca1-0000-4000-8000-000000000034";
    const B: &str = "9e795ca1-0000-4000-8000-000000000035";
    record(&db, A, "alice", r#"{"team":"core"}"#).await;
    record(&db, B, "bea", r#"{"team":"core"}"#).await;
    replace_explicit_policy(
        &db,
        "policy:record-body-nodes",
        A,
        vec![AllowEntry::account(
            "acct:record-body-alice",
            Capability::View,
        )],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "policy:record-body-nodes",
        B,
        vec![AllowEntry::account(
            "acct:record-body-bea",
            Capability::View,
        )],
    )
    .await
    .unwrap();
    let alice = QueryPrincipal::authenticated("acct:record-body-alice", true);
    let bea = QueryPrincipal::authenticated("acct:record-body-bea", true);
    // A node is visible iff its record is.
    assert_eq!(rows(&db, alice.clone(), A).await.rows.len(), 2);
    assert_eq!(rows(&db, bea.clone(), B).await.rows.len(), 2);
    // The fence is exactly the records join, not a re-implementation.
    let hidden = query_sql(
        &db,
        alice.clone(),
        &format!(
            "SELECT count(*) AS n FROM record_body_json_nodes n JOIN records r ON r.id=n.record_id \
             WHERE r.id='{B}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(hidden.rows, vec![json!({"n":0})]);
    let bea_hidden = query_sql(
        &db,
        bea,
        &format!(
            "SELECT count(*) AS n FROM record_body_json_nodes n JOIN records r ON r.id=n.record_id \
             WHERE r.id='{A}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(bea_hidden.rows, vec![json!({"n":0})]);
}

#[tokio::test]
async fn record_body_nodes_hidden_and_tombstoned_absent_but_retained() {
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let db = crate::create_database(":memory:").await.unwrap();
    const HIDDEN: &str = "9e795ca1-0000-4000-8000-000000000036";
    const DELETED: &str = "9e795ca1-0000-4000-8000-000000000037";
    record(&db, HIDDEN, "hidden", r#"{"a":1}"#).await;
    record(&db, DELETED, "deleted", r#"{"a":1}"#).await;
    replace_explicit_policy(
        &db,
        "policy:record-body-hidden",
        HIDDEN,
        vec![AllowEntry::account(
            "acct:record-body-owner",
            Capability::View,
        )],
    )
    .await
    .unwrap();
    delete_record(&db, DELETED).await.unwrap();
    let outsider = QueryPrincipal::authenticated("acct:record-body-outsider", true);
    assert!(rows(&db, outsider.clone(), HIDDEN).await.rows.is_empty());
    assert!(rows(&db, local(), DELETED).await.rows.is_empty());
    // Nodes stay in the physical table for both.
    for id in [HIDDEN, DELETED] {
        let physical: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM main.record_body_json_nodes WHERE record_id=?",
        )
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(physical, 2, "{id}");
    }
}

#[tokio::test]
async fn record_body_nodes_catalog_lists_relation_and_columns() {
    let db = crate::create_database(":memory:").await.unwrap();
    let catalog = query_sql(
        &db,
        local(),
        "SELECT identity,semantic_version,caller_relative,completeness,profiles \
         FROM catalog_relations WHERE relation_name='record_body_json_nodes'",
    )
    .await
    .unwrap();
    assert_eq!(
        catalog.rows,
        vec![json!({
            "identity": "native.query-sql.record-body-json-nodes",
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
         WHERE relation_name='record_body_json_nodes' ORDER BY column_position",
    )
    .await
    .unwrap();
    assert_eq!(
        columns.rows,
        COLUMNS.map(|column| json!({"column_name": column}))
    );
    // Physical access and the main schema stay blocked.
    for sql in [
        "SELECT * FROM main.record_body_json_nodes",
        "INSERT INTO record_body_json_nodes(record_id,ordinal) VALUES('x',0)",
        "DELETE FROM record_body_json_nodes",
    ] {
        assert!(query_sql(&db, local(), sql).await.is_err(), "{sql}");
    }
}

#[test]
fn record_body_nodes_saved_pins_and_unsupported_profiles() {
    use native_query_contract::rule_contract::check_relation_pin;
    let snapshot = current_catalog_snapshot();
    assert_eq!(
        sql_contract::logical_columns(
            "record_body_json_nodes",
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
            sql_contract::logical_columns("record_body_json_nodes", profile).is_none(),
            "{profile:?} must refuse record_body_json_nodes"
        );
    }
    let readset = extract_rule_input_dependencies(
        "SELECT n.ordinal,n.number_text FROM record_body_json_nodes n \
         JOIN records r ON r.id=n.record_id WHERE r.name='x' ORDER BY n.ordinal",
    )
    .unwrap();
    let pin = readset
        .relations
        .iter()
        .find(|pin| pin.identity == "native.query-sql.record-body-json-nodes")
        .unwrap();
    assert_eq!(pin.semantic_version, 1);
    for pin in &readset.relations {
        check_relation_pin(&snapshot, pin).unwrap();
    }
}
