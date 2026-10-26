//! The former per-record staging path is an independent result oracle.
use super::*;

async fn equivalent(db: &Db, account: &str) -> Value {
    let args = json!({"sql":"SELECT * FROM record_lifecycle_interpretations ORDER BY record_id"});
    let grouped = ordinary_kernel_call(db, account, "query_sql", args.clone())
        .await
        .unwrap();
    let full = crate::mcp::kernel_v2::sql::with_full_lifecycle_staging(ordinary_kernel_call(
        db,
        account,
        "query_sql",
        args,
    ))
    .await
    .unwrap();
    assert_eq!(grouped["rows"], full["rows"]);
    assert_eq!(grouped["truncated"], full["truncated"]);
    grouped
}

#[tokio::test]
async fn grouped_lifecycle_staging_matches_full_for_direct_derived_revocation_and_replay() {
    let f = Fixture::new().await;
    super::sql_fixture::prepare_visibility_fixture(&f).await;
    let mut options = f.options(&[], false);
    options.all = true;
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let db = f.db().await;
    for account in ["account-a", "account-b"] {
        let out = equivalent(&db, account).await;
        for (id, visible) in [
            ("direct-public", true),
            ("comment-public", true),
            ("attachment-public", true),
            ("direct-private", account == "account-a"),
            ("comment-private", account == "account-a"),
            ("attachment-private", account == "account-a"),
        ] {
            assert_eq!(
                out["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["record_id"] == id),
                visible,
                "{account}: {id}"
            );
        }
        if account == "account-a" {
            assert_eq!(
                out["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["record_id"] == "private")
                    .unwrap()["axis_key"],
                "scoped_status"
            );
        }
    }
    // A native relocation changes the self-home interpretation bearer, while
    // retaining the record-local private policy. Both paths must see the move.
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"private","home_id":"native:root","lifecycle":"open"}),
    )
    .await
    .unwrap();
    let moved = equivalent(&db, "account-a").await;
    assert_eq!(
        moved["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["record_id"] == "private")
            .unwrap()["axis_key"],
        "work_status"
    );
    let admin = &report.principals["account-a"];
    k::replace_home_policy(
        &db,
        admin,
        crate::events::KERNEL_ROOT_ID,
        &[(admin, "manage")],
    )
    .await
    .unwrap();
    let revoked = equivalent(&db, "account-b").await;
    assert!(!revoked["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["record_id"] == "direct-public"));
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    for account in ["account-a", "account-b"] {
        equivalent(&db, account).await;
    }
    db.close().await;
}
