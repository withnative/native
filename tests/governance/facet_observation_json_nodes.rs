//! Facet-observation JSON occurrence projection (engine 85): the facet-history
//! twin of `facet_value_json_nodes`.
//!
//! Only observation text that parses as a JSON object or array flattens. A
//! scalar, malformed, NULL (unset) or over-budget value leaves the observation
//! write intact with no nodes. Nodes follow the observation row, so several
//! observations of one key each keep their own, and a correction on
//! `(record_id, key, as_of)` replaces them.

use native_ce::conformance::rebuild_and_diff;
use native_ce::events::{EventRow, FacetSetPayload, FacetUnsetPayload};
use native_ce::interchange::{
    export_canonical_interchange, import_canonical_interchange, ImportContinuity,
};
use native_ce::json_nodes::MAX_JSON_SOURCE_BYTES;
use native_ce::store::{append, create_record, AppendSpec};
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

async fn set_at(
    db: &Db,
    record_id: &str,
    key: &str,
    value: Option<&str>,
    as_of: &str,
    observation_only: bool,
) -> EventRow {
    append(
        db,
        AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.set".into(),
            payload: serde_json::to_value(FacetSetPayload {
                key: key.into(),
                value: value.map(str::to_string),
                vocab_ref: None,
                as_of: Some(as_of.into()),
                observation_only,
            })
            .unwrap(),
            actor: None,
        },
    )
    .await
    .unwrap()
}

async fn unset_at(db: &Db, record_id: &str, key: &str, as_of: &str) -> EventRow {
    append(
        db,
        AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.unset".into(),
            payload: serde_json::to_value(FacetUnsetPayload {
                key: key.into(),
                as_of: Some(as_of.into()),
                observation_only: false,
            })
            .unwrap(),
            actor: None,
        },
    )
    .await
    .unwrap()
}

async fn nodes(db: &Db, record_id: &str, key: &str, as_of: &str) -> Vec<NodeRow> {
    sqlx::query_as(
        "SELECT ordinal,path,parent_path,node_type,text_value,number_text,bool_value
         FROM facet_observation_json_nodes WHERE observation_id=? ORDER BY ordinal",
    )
    .bind(format!("fo:{record_id}:{key}:{as_of}"))
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn total_nodes(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM facet_observation_json_nodes")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn one_record(db: &Db) -> String {
    create_record(
        db,
        json!({ "type": "Document", "kind": "note", "name": "observation nodes" }),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn object_and_array_observations_flatten_to_typed_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    set_at(
        &db,
        &id,
        "obj",
        Some(r#"{"a":1,"b":[true,"x"]}"#),
        "2026-07-01",
        false,
    )
    .await;
    assert_eq!(
        nodes(&db, &id, "obj", "2026-07-01").await,
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

    set_at(
        &db,
        &id,
        "arr",
        Some(r#"[1,{"k":"v"}]"#),
        "2026-07-01",
        false,
    )
    .await;
    assert_eq!(
        nodes(&db, &id, "arr", "2026-07-01").await,
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
async fn scalar_malformed_null_and_unset_observations_have_no_nodes_and_still_write() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;
    for (key, value) in [
        ("num", Some("5")),
        ("plain", Some("plain text")),
        ("quoted", Some("\"plain text\"")),
        ("malformed", Some("{oops")),
        ("null_value", None),
    ] {
        set_at(&db, &id, key, value, "2026-07-01", false).await;
        assert!(
            nodes(&db, &id, key, "2026-07-01").await.is_empty(),
            "observation {key}"
        );
    }
    unset_at(&db, &id, "gone", "2026-07-01").await;
    assert!(nodes(&db, &id, "gone", "2026-07-01").await.is_empty());

    // Every write above landed as an observation row despite having no nodes.
    let observations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM facet_observations WHERE record_id=?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(observations, 6);
    assert_eq!(total_nodes(&db).await, 0);
}

#[tokio::test]
async fn over_budget_observations_write_with_no_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    let oversize = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_JSON_SOURCE_BYTES));
    assert!(oversize.len() > MAX_JSON_SOURCE_BYTES);
    set_at(&db, &id, "big", Some(&oversize), "2026-07-01", false).await;
    assert!(nodes(&db, &id, "big", "2026-07-01").await.is_empty());

    let many = format!("[{}]", vec!["0"; 5000].join(","));
    set_at(&db, &id, "many", Some(&many), "2026-07-01", false).await;
    assert!(nodes(&db, &id, "many", "2026-07-01").await.is_empty());
    assert_eq!(total_nodes(&db).await, 0);
}

#[tokio::test]
async fn several_observations_of_one_key_each_keep_their_own_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    set_at(&db, &id, "cfg", Some(r#"{"a":1}"#), "2026-07-01", false).await;
    set_at(&db, &id, "cfg", Some(r#"{"b":2}"#), "2026-07-02", false).await;
    set_at(&db, &id, "cfg", Some("[true]"), "2026-07-03", false).await;
    set_at(&db, &id, "cfg", Some("plain"), "2026-07-04", false).await;

    let paths = |rows: Vec<NodeRow>| -> Vec<String> { rows.into_iter().map(|row| row.1).collect() };
    assert_eq!(
        paths(nodes(&db, &id, "cfg", "2026-07-01").await),
        ["", "/a"]
    );
    assert_eq!(
        paths(nodes(&db, &id, "cfg", "2026-07-02").await),
        ["", "/b"]
    );
    assert_eq!(
        paths(nodes(&db, &id, "cfg", "2026-07-03").await),
        ["", "/0"]
    );
    assert!(nodes(&db, &id, "cfg", "2026-07-04").await.is_empty());
    assert_eq!(total_nodes(&db).await, 6);

    // Current-value nodes follow only the latest write, not the history.
    let current: i64 = sqlx::query_scalar("SELECT count(*) FROM facet_value_json_nodes")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(current, 0);
}

#[tokio::test]
async fn observation_only_writes_project_history_without_current_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;

    set_at(&db, &id, "cfg", Some(r#"{"a":1}"#), "2026-07-01", true).await;
    assert_eq!(nodes(&db, &id, "cfg", "2026-07-01").await.len(), 2);
    let current: i64 = sqlx::query_scalar("SELECT count(*) FROM facet_value_json_nodes")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(current, 0);
}

#[tokio::test]
async fn correcting_or_unsetting_an_observation_replaces_and_clears_its_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;
    let as_of = "2026-07-01";

    set_at(&db, &id, "k", Some(r#"{"a":1}"#), as_of, false).await;
    assert_eq!(nodes(&db, &id, "k", as_of).await.len(), 2);

    // Same (record, key, as_of): the correction replaces the observation row,
    // so its nodes must be replaced rather than accumulated.
    set_at(&db, &id, "k", Some(r#"{"b":[1,2]}"#), as_of, false).await;
    let paths: Vec<String> = nodes(&db, &id, "k", as_of)
        .await
        .into_iter()
        .map(|row| row.1)
        .collect();
    assert_eq!(paths, ["", "/b", "/b/0", "/b/1"]);

    set_at(&db, &id, "k", Some("now a scalar"), as_of, false).await;
    assert!(nodes(&db, &id, "k", as_of).await.is_empty());

    set_at(&db, &id, "k", Some(r#"{"c":3}"#), as_of, false).await;
    assert_eq!(nodes(&db, &id, "k", as_of).await.len(), 2);
    // An unset at the same valid time overwrites the set observation.
    unset_at(&db, &id, "k", as_of).await;
    assert!(nodes(&db, &id, "k", as_of).await.is_empty());
    assert_eq!(total_nodes(&db).await, 0);

    let op: String = sqlx::query_scalar(
        "SELECT op FROM facet_observations WHERE record_id=? AND key='k' AND as_of=?",
    )
    .bind(&id)
    .bind(as_of)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(op, "unset");
}

#[tokio::test]
async fn unsetting_at_a_later_time_leaves_earlier_observation_nodes() {
    let db = create_database(":memory:").await.unwrap();
    let id = one_record(&db).await;
    set_at(&db, &id, "k", Some(r#"{"a":1}"#), "2026-07-01", false).await;
    unset_at(&db, &id, "k", "2026-07-02").await;
    assert_eq!(nodes(&db, &id, "k", "2026-07-01").await.len(), 2);
    assert!(nodes(&db, &id, "k", "2026-07-02").await.is_empty());
}

async fn seed_history(db: &Db) -> String {
    let id = one_record(db).await;
    set_at(
        db,
        &id,
        "obj",
        Some(r#"{"a":[1,2,3]}"#),
        "2026-07-01",
        false,
    )
    .await;
    set_at(db, &id, "obj", Some(r#"{"a":[4]}"#), "2026-07-02", false).await;
    // A correction and an unset-over-set, so replay must reproduce both.
    set_at(db, &id, "obj", Some(r#"{"z":true}"#), "2026-07-02", false).await;
    set_at(db, &id, "arr", Some(r#"[{"k":"v"}]"#), "2026-07-01", false).await;
    unset_at(db, &id, "arr", "2026-07-01").await;
    set_at(db, &id, "hist", Some("[1]"), "2026-07-01", true).await;
    set_at(db, &id, "plain", Some("text"), "2026-07-01", false).await;
    set_at(db, &id, "bad", Some("{oops"), "2026-07-01", false).await;
    id
}

#[tokio::test]
async fn content_rebuild_reproduces_observation_nodes_exactly() {
    let db = create_database(":memory:").await.unwrap();
    let id = seed_history(&db).await;
    assert_eq!(nodes(&db, &id, "obj", "2026-07-02").await.len(), 2);
    assert!(total_nodes(&db).await > 0);

    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(result.equal, "{result:#?}");
}

#[tokio::test]
async fn canonical_import_rebuilds_identical_observation_nodes_and_skips_bad_rows() {
    let temp = tempfile::tempdir().unwrap();
    let source = create_database(temp.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    let id = seed_history(&source).await;
    let expected = (
        nodes(&source, &id, "obj", "2026-07-01").await,
        nodes(&source, &id, "obj", "2026-07-02").await,
        nodes(&source, &id, "hist", "2026-07-01").await,
    );
    assert!(expected.0.len() > 1 && !expected.1.is_empty() && !expected.2.is_empty());

    let bundle = export_canonical_interchange(&source).await.unwrap();
    source.close().await;
    let imported = import_canonical_interchange(
        &bundle,
        &temp.path().join("imported.db"),
        ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();

    assert_eq!(nodes(&imported, &id, "obj", "2026-07-01").await, expected.0);
    assert_eq!(nodes(&imported, &id, "obj", "2026-07-02").await, expected.1);
    assert_eq!(
        nodes(&imported, &id, "hist", "2026-07-01").await,
        expected.2
    );
    for key in ["plain", "bad", "arr"] {
        assert!(nodes(&imported, &id, key, "2026-07-01").await.is_empty());
    }
    imported.close().await;
}
