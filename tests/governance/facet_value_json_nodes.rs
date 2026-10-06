//! Facet-value JSON occurrence projection (engine 82).
//!
//! Only object/array roots flatten, every node is a `parsed_text_candidate`,
//! and a malformed, scalar or over-budget value leaves the facet write intact
//! with no nodes.

use native_ce::conformance::rebuild_and_diff;
use native_ce::events::FacetSetPayload;
use native_ce::interchange::{
    export_canonical_interchange, import_canonical_interchange, ImportContinuity,
};
use native_ce::json_nodes::MAX_JSON_SOURCE_BYTES;
use native_ce::store::{create_record, set_facet, unset_facet};
use native_ce::{create_database, Db};
use serde_json::json;

type NodeRow = (
    i64,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
);

fn facet(key: &str, value: Option<&str>) -> FacetSetPayload {
    FacetSetPayload {
        key: key.into(),
        value: value.map(str::to_string),
        vocab_ref: None,
        as_of: None,
        observation_only: false,
    }
}

async fn nodes(db: &Db, record_id: &str, key: &str) -> Vec<NodeRow> {
    sqlx::query_as(
        "SELECT ordinal,path,parent_path,node_type,text_value,number_text,bool_value
         FROM facet_value_json_nodes WHERE facet_id=? ORDER BY ordinal",
    )
    .bind(format!("fv:{record_id}:{key}"))
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn one_record(db: &Db) -> String {
    create_record(
        db,
        json!({ "type": "Document", "kind": "note", "name": "facet nodes" }),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn object_and_array_facets_flatten_to_typed_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    set_facet(&db, &id, facet("obj", Some(r#"{"a":1,"b":[true,"x"]}"#)))
        .await
        .unwrap();
    let object_nodes = nodes(&db, &id, "obj").await;
    assert_eq!(
        object_nodes,
        vec![
            (0, "".into(), None, "object".into(), None, None, None),
            (
                1,
                "/a".into(),
                Some("".into()),
                "number".into(),
                None,
                Some("1".into()),
                None
            ),
            (
                2,
                "/b".into(),
                Some("".into()),
                "array".into(),
                None,
                None,
                None
            ),
            (
                3,
                "/b/0".into(),
                Some("/b".into()),
                "boolean".into(),
                None,
                None,
                Some(1)
            ),
            (
                4,
                "/b/1".into(),
                Some("/b".into()),
                "string".into(),
                Some("x".into()),
                None,
                None
            ),
        ]
    );

    set_facet(&db, &id, facet("arr", Some(r#"[1,{"k":"v"}]"#)))
        .await
        .unwrap();
    assert_eq!(
        nodes(&db, &id, "arr").await,
        vec![
            (0, "".into(), None, "array".into(), None, None, None),
            (
                1,
                "/0".into(),
                Some("".into()),
                "number".into(),
                None,
                Some("1".into()),
                None
            ),
            (
                2,
                "/1".into(),
                Some("".into()),
                "object".into(),
                None,
                None,
                None
            ),
            (
                3,
                "/1/k".into(),
                Some("/1".into()),
                "string".into(),
                Some("v".into()),
                None,
                None
            ),
        ]
    );
}

#[tokio::test]
async fn stored_text_that_parses_as_json_object_flattens_even_when_authored_as_a_string() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;
    // A facet written as the string `{"a":1}` stores exactly those bytes: the
    // event format erased the authored type, so it is a text candidate.
    set_facet(&db, &id, facet("texty", Some(r#"{"a":1}"#)))
        .await
        .unwrap();
    assert_eq!(
        nodes(&db, &id, "texty").await,
        vec![
            (0, "".into(), None, "object".into(), None, None, None),
            (
                1,
                "/a".into(),
                Some("".into()),
                "number".into(),
                None,
                Some("1".into()),
                None
            ),
        ]
    );
}

#[tokio::test]
async fn scalar_and_malformed_facets_have_no_nodes_and_still_write() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;
    for (key, value) in [
        ("num", "5"),
        ("plain", "plain text"),
        ("quoted", "\"plain text\""),
        ("malformed", "{oops"),
    ] {
        set_facet(&db, &id, facet(key, Some(value)))
            .await
            .unwrap_or_else(|error| panic!("facet {key} write must succeed: {error}"));
        assert!(nodes(&db, &id, key).await.is_empty(), "facet {key}");
    }
}

#[tokio::test]
async fn over_budget_facets_write_with_no_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    let oversize = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_JSON_SOURCE_BYTES));
    assert!(oversize.len() > MAX_JSON_SOURCE_BYTES);
    set_facet(&db, &id, facet("big", Some(&oversize)))
        .await
        .expect("an over-size facet write succeeds");
    assert!(nodes(&db, &id, "big").await.is_empty());

    let many = format!("[{}]", vec!["0"; 5000].join(","));
    set_facet(&db, &id, facet("many", Some(&many)))
        .await
        .expect("a too-many-nodes facet write succeeds");
    assert!(nodes(&db, &id, "many").await.is_empty());
}

#[tokio::test]
async fn updating_and_unsetting_a_facet_replaces_and_removes_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    set_facet(&db, &id, facet("k", Some(r#"{"a":1}"#)))
        .await
        .unwrap();
    assert_eq!(nodes(&db, &id, "k").await.len(), 2);

    set_facet(&db, &id, facet("k", Some(r#"{"b":2}"#)))
        .await
        .unwrap();
    assert_eq!(
        nodes(&db, &id, "k").await,
        vec![
            (0, "".into(), None, "object".into(), None, None, None),
            (
                1,
                "/b".into(),
                Some("".into()),
                "number".into(),
                None,
                Some("2".into()),
                None
            ),
        ]
    );

    set_facet(&db, &id, facet("k", Some("now a scalar")))
        .await
        .unwrap();
    assert!(nodes(&db, &id, "k").await.is_empty());

    set_facet(&db, &id, facet("k", Some(r#"{"c":3}"#)))
        .await
        .unwrap();
    assert_eq!(nodes(&db, &id, "k").await.len(), 2);
    unset_facet(&db, &id, "k").await.unwrap();
    assert!(nodes(&db, &id, "k").await.is_empty());
}

#[tokio::test]
async fn content_rebuild_reproduces_facet_nodes_exactly() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;
    set_facet(&db, &id, facet("obj", Some(r#"{"a":[1,2,3]}"#)))
        .await
        .unwrap();
    set_facet(&db, &id, facet("arr", Some(r#"[{"k":"v"}]"#)))
        .await
        .unwrap();
    set_facet(&db, &id, facet("plain", Some("text")))
        .await
        .unwrap();

    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(result.equal, "{result:#?}");
}

#[tokio::test]
async fn canonical_import_rebuilds_identical_facet_nodes() {
    let temp = tempfile::tempdir().unwrap();
    let source = create_database(temp.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    let id = one_record(&source).await;
    set_facet(&source, &id, facet("obj", Some(r#"{"a":[1,2]}"#)))
        .await
        .unwrap();
    set_facet(&source, &id, facet("plain", Some("text")))
        .await
        .unwrap();
    let expected = nodes(&source, &id, "obj").await;
    assert!(!expected.is_empty());

    let bundle = export_canonical_interchange(&source).await.unwrap();
    source.close().await;
    let imported = import_canonical_interchange(
        &bundle,
        &temp.path().join("imported.db"),
        ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();

    assert_eq!(nodes(&imported, &id, "obj").await, expected);
    assert!(nodes(&imported, &id, "plain").await.is_empty());
    imported.close().await;
}
