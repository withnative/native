//! Exercises the production library (cfg(test) is NOT enabled there).
use sqlx::{Connection, SqliteConnection};

#[tokio::test]
async fn production_projector_refuses_test_only_admission_receipt_before_any_projection() {
    let mut connection = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true),
    )
    .await
    .unwrap();
    for statement in native_ce::schema::DDL_STATEMENTS {
        sqlx::query(statement)
            .execute(&mut connection)
            .await
            .unwrap();
    }
    let event = native_ce::meta::MetaEventRow {
        seq: 1,
        id: "fixture-event".into(),
        subject_id: "workspace-rule:6e61746976653a726f6f74:test_ns:records".into(),
        event_type: "workspace_rule_installation.set.v1".into(),
        payload: Some(
            include_str!("../fixtures/workspace-rule/test-only-snapshot.json")
                .trim_end()
                .into(),
        ),
        actor: Some("acct:alice".into()),
        created_at: "2026-10-03T00:00:00Z".into(),
    };
    let error = native_ce::projector::meta::project_meta(&mut connection, &event)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fixture validation evidence cannot admit installations"),
        "{error}"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM workspace_rule_installations")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(count, 0);
    connection.close().await.unwrap();
}
