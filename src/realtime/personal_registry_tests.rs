use super::*;
use crate::control::{
    self, AlphaTabOrderPayload, AlphaTabStatePayload, ControlEventPayload, NewControlEvent,
};
use serde_json::json;

const ARTIFACT: &str = "c07f0000-0000-4000-8000-000000000010";
const ACCOUNT: &str = "alice";

async fn sql(db: &Db, statement: &str) {
    sqlx::query(statement)
        .execute(db.write_pool())
        .await
        .unwrap();
}

async fn install(db: &Db, account: &str, package: &str) {
    let payload = AlphaTabStatePayload {
        account_id: account.into(),
        package: package.into(),
        version: "0.1.0".into(),
        digest: format!("sha256:{}", "a".repeat(64)),
        artifact_id: ARTIFACT.into(),
        consented_source_revision: "rev-1".into(),
        declaration_digest: "b".repeat(64),
        consented_declaration: json!({"needs": [], "effects": []}),
        adoption: control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into(),
        request: None,
        previous_event_id: None,
    };
    control::append_control_event(
        db,
        NewControlEvent::authored(
            format!("install:{account}:{package}"),
            control::alpha_tab_aggregate_id(account, package),
            account,
            None,
            "registry observation fixture",
            ControlEventPayload::AlphaTabInstalled(payload),
        )
        .unwrap(),
    )
    .await
    .unwrap();
}

async fn fixture(url: &str) -> Db {
    let db = crate::create_database(url).await.unwrap();
    crate::store::create_record(
        &db,
        json!({"id":ARTIFACT,"type":"Document","kind":"artifact","name":"fixture","body":"inert"}),
    )
    .await
    .unwrap();
    install(&db, ACCOUNT, "app.first").await;
    control::append_control_event(
        &db,
        NewControlEvent::authored(
            "order",
            control::alpha_tab_order_aggregate_id(ACCOUNT),
            ACCOUNT,
            None,
            "registry order fixture",
            ControlEventPayload::AlphaTabOrderSet(AlphaTabOrderPayload {
                account_id: ACCOUNT.into(),
                tab_order: vec![],
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    db
}

#[tokio::test]
async fn personal_alpha_registry_complete_fields_despite_larger_order_max() {
    let db = fixture(":memory:").await;
    crate::store::create_record(&db, json!({"id":"c07f0000-0000-4000-8000-000000000011","type":"Document","kind":"artifact","name":"other","body":"inert"})).await.unwrap();
    let baseline = probe(&db, ACCOUNT).await.unwrap();
    let max: i64 = sqlx::query_scalar("SELECT MAX(event_seq) FROM (SELECT event_seq FROM alpha_tab_installs UNION ALL SELECT event_seq FROM alpha_tab_orders)").fetch_one(db.pool()).await.unwrap();
    sql(
        &db,
        "CREATE TABLE saved_install AS SELECT * FROM alpha_tab_installs",
    )
    .await;
    // Actual SQL drift/restore of every non-key stored field. The later order
    // masks these changes from a MAX-only observation.
    for assignment in [
        "version='0.2.0'",
        "digest='changed'",
        "artifact_id='c07f0000-0000-4000-8000-000000000011'",
        "consented_source_revision='rev-2'",
        "declaration_digest=printf('%064d',0)",
        "consented_declaration='{\"needs\":[],\"effects\":[],\"extra\":\"é\\n\"}'",
        "adoption='shell_adopt.v1'",
        "request='é\nrequest'",
        "status='disabled'",
        "updated_at='restored-time'",
        "package='app.renamed'",
        "account_id='other'",
    ] {
        sql(&db, &format!("UPDATE alpha_tab_installs SET {assignment}")).await;
        assert!(
            probe(&db, ACCOUNT).await.unwrap() != baseline,
            "field drift must invalidate"
        );
        let after: i64 = sqlx::query_scalar("SELECT MAX(event_seq) FROM (SELECT event_seq FROM alpha_tab_installs UNION ALL SELECT event_seq FROM alpha_tab_orders)").fetch_one(db.pool()).await.unwrap();
        assert_eq!(max, after);
        sql(&db, "DELETE FROM alpha_tab_installs").await;
        sql(
            &db,
            "INSERT INTO alpha_tab_installs SELECT * FROM saved_install",
        )
        .await;
        assert!(probe(&db, ACCOUNT).await.unwrap() == baseline);
    }
    // A valid FK can still be a divergent projection; exact event metadata is
    // included rather than replaced by a reconstructed declaration digest.
    for assignment in [
        "event_id=(SELECT event_id FROM alpha_tab_orders)",
        "event_seq=(SELECT event_seq FROM alpha_tab_orders)",
        "body_read_admission_event_id=(SELECT event_id FROM alpha_tab_orders)",
    ] {
        sql(&db, &format!("UPDATE alpha_tab_installs SET {assignment}")).await;
        assert!(probe(&db, ACCOUNT).await.unwrap() != baseline);
        sql(&db, "DELETE FROM alpha_tab_installs").await;
        sql(
            &db,
            "INSERT INTO alpha_tab_installs SELECT * FROM saved_install",
        )
        .await;
    }
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_tombstone_absence_order_and_foreign_scope() {
    let db = fixture(":memory:").await;
    let baseline = probe(&db, ACCOUNT).await.unwrap();
    install(&db, "bea", "app.foreign").await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == baseline);
    sql(
        &db,
        "UPDATE alpha_tab_installs SET status='removed' WHERE account_id='alice'",
    )
    .await;
    let tombstone = probe(&db, ACCOUNT).await.unwrap();
    assert!(tombstone != baseline);
    sql(
        &db,
        "DELETE FROM alpha_tab_installs WHERE account_id='alice'",
    )
    .await;
    let missing = probe(&db, ACCOUNT).await.unwrap();
    assert!(missing != tombstone);
    sql(&db, "DELETE FROM alpha_tab_orders WHERE account_id='alice'").await;
    assert!(probe(&db, ACCOUNT).await.unwrap() != missing);
    // An unchanged, later install also masks deletion of an older install
    // from MAX, even when there is no order row.
    install(&db, ACCOUNT, "app.older").await;
    install(&db, ACCOUNT, "app.later").await;
    let both = probe(&db, ACCOUNT).await.unwrap();
    let max: i64 = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM alpha_tab_installs WHERE account_id='alice'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    sql(
        &db,
        "DELETE FROM alpha_tab_installs WHERE package='app.older'",
    )
    .await;
    let remaining_max: i64 = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM alpha_tab_installs WHERE account_id='alice'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(max, remaining_max);
    assert!(probe(&db, ACCOUNT).await.unwrap() != both);
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_order_fields_and_identical_replay() {
    let db = fixture(":memory:").await;
    let baseline = probe(&db, ACCOUNT).await.unwrap();
    sql(
        &db,
        "CREATE TABLE saved_order AS SELECT * FROM alpha_tab_orders",
    )
    .await;
    for assignment in [
        "tab_order='[\"agents\"]'",
        "updated_at='restored'",
        "account_id='bea'",
        "event_id=(SELECT event_id FROM alpha_tab_installs)",
        "event_seq=(SELECT event_seq FROM alpha_tab_installs)",
    ] {
        sql(&db, &format!("UPDATE alpha_tab_orders SET {assignment}")).await;
        assert!(probe(&db, ACCOUNT).await.unwrap() != baseline);
        sql(&db, "DELETE FROM alpha_tab_orders").await;
        sql(
            &db,
            "INSERT INTO alpha_tab_orders SELECT * FROM saved_order",
        )
        .await;
    }
    let mut conn = db.write_pool().acquire().await.unwrap();
    let events = control::read_all_control_events(&mut conn).await.unwrap();
    drop(conn);
    sql(&db, "DELETE FROM alpha_tab_installs").await;
    sql(&db, "DELETE FROM alpha_tab_orders").await;
    sql(&db, "DELETE FROM control_event_applications").await;
    let mut conn = db.write_pool().acquire().await.unwrap();
    control::replay_control(&mut conn, &events).await.unwrap();
    drop(conn);
    assert!(probe(&db, ACCOUNT).await.unwrap() == baseline);
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_complete_scan_stable_physical_order() {
    let db = fixture(":memory:").await;
    for index in 0..300 {
        install(&db, ACCOUNT, &format!("app.bulk{index:03}")).await;
    }
    let baseline = probe(&db, ACCOUNT).await.unwrap();
    sql(
        &db,
        "CREATE TABLE saved_install AS SELECT * FROM alpha_tab_installs",
    )
    .await;
    sql(&db, "DELETE FROM alpha_tab_installs").await;
    sql(
        &db,
        "INSERT INTO alpha_tab_installs SELECT * FROM saved_install ORDER BY package DESC",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == baseline);
    sql(
        &db,
        "UPDATE alpha_tab_installs SET version='tail-changed' WHERE package='app.bulk299'",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() != baseline);
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_refuses_malformed_storage_without_token() {
    let db = fixture(":memory:").await;
    sql(&db, "UPDATE alpha_tab_installs SET version=x'6162'").await;
    assert!(probe(&db, ACCOUNT).await.is_err());
    assert!(probe(&db, " ").await.is_err());
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_one_snapshot_across_both_tables() {
    let dir = tempfile::tempdir().unwrap();
    let db = fixture(dir.path().join("snapshot.sqlite").to_str().unwrap()).await;
    let baseline = probe(&db, ACCOUNT).await.unwrap();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let reading_db = db.clone();
    let gate = (entered.clone(), release.clone());
    let reader =
        tokio::spawn(BETWEEN_TABLES.scope(gate, async move { probe(&reading_db, ACCOUNT).await }));
    entered.notified().await;
    let mut writer = db.write_pool().begin().await.unwrap();
    sqlx::query("UPDATE alpha_tab_installs SET version='concurrent'")
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query("UPDATE alpha_tab_orders SET tab_order='[\"agents\"]'")
        .execute(&mut *writer)
        .await
        .unwrap();
    writer.commit().await.unwrap();
    release.notify_one();
    assert!(reader.await.unwrap().unwrap() == baseline);
    assert!(probe(&db, ACCOUNT).await.unwrap() != baseline);
    db.close().await;
}

#[test]
fn personal_alpha_registry_framing_null_utf8_and_concatenation() {
    assert!(next_count(u64::MAX).is_err());
    fn parts(a: &str, b: &str) -> PersonalAlphaRegistryFingerprint {
        let mut encoding = Encoding::new(ACCOUNT).unwrap();
        encoding.text(a).unwrap();
        encoding.text(b).unwrap();
        encoding.finish()
    }
    assert!(parts("ab", "c") != parts("a", "bc"));
    assert!(parts("é\n", "\0") != parts("é", "\n\0"));
    let mut null = Encoding::new(ACCOUNT).unwrap();
    null.0.update([0x00]);
    let mut empty = Encoding::new(ACCOUNT).unwrap();
    empty.text("").unwrap();
    assert!(null.finish() != empty.finish());
}

#[tokio::test]
async fn personal_alpha_registry_schema79_complete_column_coverage() {
    let db = fixture(":memory:").await;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(db.pool())
        .await
        .unwrap();
    // Schema82 preserves the exact alpha-tab columns introduced by schema79.
    assert_eq!(version, 82);
    // Independent current-DDL expectation: an omitted encoder column must fail.
    let expected = [
        "account_id",
        "package",
        "version",
        "digest",
        "artifact_id",
        "consented_source_revision",
        "declaration_digest",
        "consented_declaration",
        "adoption",
        "request",
        "status",
        "event_id",
        "event_seq",
        "updated_at",
        "adoption_provenance",
        "body_read_admission_event_id",
    ];
    let actual: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('alpha_tab_installs') ORDER BY cid")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(INSTALL_COLUMNS, expected);
    let orders: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('alpha_tab_orders') ORDER BY cid")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        orders,
        [
            "account_id",
            "tab_order",
            "event_id",
            "event_seq",
            "updated_at"
        ]
    );
    assert_eq!(
        ORDER_COLUMNS,
        [
            "account_id",
            "tab_order",
            "event_id",
            "event_seq",
            "updated_at"
        ]
    );
    let baseline = probe(&db, ACCOUNT).await.unwrap(); // all three nullable fields NULL
    let seq: i64 = sqlx::query_scalar("SELECT event_seq FROM alpha_tab_installs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let mut previous = baseline.clone();
    for text in [
        r#"{}"#,
        r#"{"launch_id":"private-a","authored_run_key":"private-run"}"#,
        r#"{"launch_id":"private-b","authored_run_key":"private-run"}"#,
        r#"{ "launch_id":"private-b","authored_run_key":"private-run" }"#,
    ] {
        sqlx::query("UPDATE alpha_tab_installs SET adoption_provenance=?")
            .bind(text)
            .execute(db.write_pool())
            .await
            .unwrap();
        let next = probe(&db, ACCOUNT).await.unwrap();
        assert!(
            next != baseline && next != previous,
            "all exact stored bytes participate, including display-redacted fields"
        );
        assert!(next == probe(&db, ACCOUNT).await.unwrap());
        previous = next;
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT event_seq FROM alpha_tab_installs")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        seq
    );
    sql(
        &db,
        "UPDATE alpha_tab_installs SET adoption_provenance=NULL",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == baseline);
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_schema78_same_seq_real_rebuild() {
    use crate::control::alpha_tab_provenance_tests;
    let (db, pin, _) =
        alpha_tab_provenance_tests::fixture(Some(control::ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let original = probe(&db, &pin.account_id).await.unwrap();
    let row_before: (String, i64, Option<String>) =
        sqlx::query_as("SELECT event_id,event_seq,adoption_provenance FROM alpha_tab_installs")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(row_before.2.is_some());
    let counts_before: (i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM control_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(db.pool()).await.unwrap();
    // Explicit test-owned projection corruption, not a consent or restore API.
    sql(
        &db,
        "UPDATE alpha_tab_installs SET adoption_provenance=NULL",
    )
    .await;
    let changed = probe(&db, &pin.account_id).await.unwrap();
    assert!(changed != original);
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    control::rebuild_alpha_tab_projections_in(&mut tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(probe(&db, &pin.account_id).await.unwrap() == original);
    let row_after: (String, i64, Option<String>) =
        sqlx::query_as("SELECT event_id,event_seq,adoption_provenance FROM alpha_tab_installs")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(row_before, row_after);
    let counts_after: (i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM control_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(db.pool()).await.unwrap();
    assert_eq!(counts_before, counts_after);
    assert!(
        crate::conformance::rebuild_and_diff_control(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_schema79_nullable_types_and_account_privacy() {
    let db = fixture(":memory:").await;
    install(&db, "other-account", "other.app").await;
    let own = probe(&db, ACCOUNT).await.unwrap();
    sql(&db, "UPDATE alpha_tab_installs SET adoption_provenance='{\"private\":\"foreign\"}' WHERE account_id='other-account'").await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == own);
    sql(
        &db,
        "UPDATE alpha_tab_installs SET adoption_provenance='{}' WHERE account_id='alice'",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() != own);
    sql(
        &db,
        "UPDATE alpha_tab_installs SET adoption_provenance=NULL WHERE account_id='alice'",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == own);
    // The nullable body pointer is observed as stored state, not admission.
    sql(&db, "UPDATE alpha_tab_installs SET body_read_admission_event_id=(SELECT event_id FROM alpha_tab_orders WHERE account_id='alice') WHERE account_id='other-account'").await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == own);
    sql(&db, "UPDATE alpha_tab_installs SET body_read_admission_event_id=(SELECT event_id FROM alpha_tab_orders WHERE account_id='alice') WHERE account_id='alice'").await;
    assert!(probe(&db, ACCOUNT).await.unwrap() != own);
    sql(
        &db,
        "UPDATE alpha_tab_installs SET body_read_admission_event_id=NULL WHERE account_id='alice'",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == own);
    // Intentionally malformed projection, not canonical admission/reopen proof.
    // No affinities: numeric writes remain numeric rather than TEXT casts.
    sql(
        &db,
        "ALTER TABLE alpha_tab_installs RENAME TO saved_projection",
    )
    .await;
    sql(&db, "CREATE TABLE alpha_tab_installs (account_id,package,version,digest,artifact_id,consented_source_revision,declaration_digest,consented_declaration,adoption,request,status,event_id,event_seq,updated_at,adoption_provenance,body_read_admission_event_id)").await;
    sql(
        &db,
        "INSERT INTO alpha_tab_installs SELECT * FROM saved_projection",
    )
    .await;
    // Intentionally no-FK/no-affinity table above: NULL, empty and exact
    // UTF8 pointer bytes remain distinct; malformed values create no authority.
    let mut previous = own.clone();
    for text in ["", "é\0", "e\u{301}\0"] {
        sqlx::query(
            "UPDATE alpha_tab_installs SET body_read_admission_event_id=? WHERE account_id='alice'",
        )
        .bind(text)
        .execute(db.write_pool())
        .await
        .unwrap();
        let next = probe(&db, ACCOUNT).await.unwrap();
        assert!(next != own && next != previous);
        assert!(next == probe(&db, ACCOUNT).await.unwrap());
        previous = next;
    }
    sql(
        &db,
        "UPDATE alpha_tab_installs SET body_read_admission_event_id=NULL WHERE account_id='alice'",
    )
    .await;
    assert!(probe(&db, ACCOUNT).await.unwrap() == own);
    for column in ["adoption_provenance", "body_read_admission_event_id"] {
        for (expression, expected_type) in
            [("42", "integer"), ("1.25", "real"), ("x'7b7d'", "blob")]
        {
            sql(
                &db,
                &format!(
                    "UPDATE alpha_tab_installs SET {column}={expression} WHERE account_id='alice'"
                ),
            )
            .await;
            let storage: String = sqlx::query_scalar(&format!(
                "SELECT typeof({column}) FROM alpha_tab_installs WHERE account_id='alice'"
            ))
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(storage, expected_type);
            let error = match probe(&db, ACCOUNT).await {
                Ok(_) => panic!("wrong storage type must refuse the complete token"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("personal alpha registry observation failed"));
            assert!(
                !error.contains(ACCOUNT) && !error.contains("foreign") && !error.contains("7b7d")
            );
            // A bad foreign row never participates in this account's SELECT.
            assert!(probe(&db, "other-account").await.is_ok());
        }
        sql(
            &db,
            &format!("UPDATE alpha_tab_installs SET {column}=NULL WHERE account_id='alice'"),
        )
        .await;
        assert!(probe(&db, ACCOUNT).await.unwrap() == own);
    }
    db.close().await;
}
