//! Authorizer-selected facet columns must match full materialization.
use super::*;

async fn equivalent(db: &Db, account: &str) {
    for sql in [
        "SELECT count(*) AS n FROM facet_values",
        "SELECT record_id,key FROM facet_values ORDER BY record_id,key",
        "SELECT key,value FROM facet_values WHERE record_id='direct-public' ORDER BY key LIMIT 2",
        "SELECT DISTINCT value_num FROM facet_values ORDER BY value_num",
        "SELECT key,vocab_ref,created_at,created_at_ms FROM facet_values ORDER BY record_id,key",
        "SELECT * FROM facet_values ORDER BY record_id,key",
        "SELECT r.id,(SELECT f.value FROM facet_values f WHERE f.record_id=r.id AND f.key='fixture_key') AS cell FROM records r ORDER BY r.id",
    ] {
        let args = json!({"sql":sql});
        let projected = ordinary_kernel_call(db,account,"query_sql",args.clone()).await.unwrap();
        let full = crate::mcp::kernel_v2::sql::with_full_facet_staging(
            ordinary_kernel_call(db,account,"query_sql",args),
        ).await.unwrap();
        assert_eq!(projected["rows"],full["rows"],"{account}: {sql}");
        assert_eq!(projected["truncated"],full["truncated"]);
    }
    // Workspace pins declare the facet relation by ID, then consume every
    // facet cell. Their internal staging must retain the full row contract.
    let opened = ordinary_kernel_call(
        db,
        account,
        "get_workspace_snapshot",
        json!({"action":"open"}),
    )
    .await
    .unwrap();
    assert!(opened["snapshot_token"].is_string(), "{opened}");
    let page = ordinary_kernel_call(db, account, "get_workspace_snapshot", json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"facets","limit":1000})).await.unwrap();
    assert_eq!(page["has_more"], false);
    let expected = crate::mcp::kernel_v2::sql::with_full_facet_staging(ordinary_kernel_call(db, account, "query_sql", json!({"sql":"SELECT json_object('id',id,'record_id',record_id,'key',key,'value',value,'value_num',value_num,'vocab_ref',vocab_ref,'created_at',created_at) AS cell FROM facet_values ORDER BY id"}))).await.unwrap();
    let mut actual = page["rows"].as_array().unwrap().clone();
    actual.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    // Snapshot rows use SQLite JSON encoding before typed decoding. Compare
    // the same encoding, including its existing floating-point formatting.
    let expected: Vec<serde_json::Value> = expected["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| serde_json::from_str(row["cell"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn projected_facet_columns_match_full_for_direct_derived_revocation_and_replay() {
    let f = Fixture::new().await;
    super::sql_fixture::prepare_visibility_fixture(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    for id in [
        "task",
        "secret",
        "direct-public",
        "direct-private",
        "comment-public",
        "comment-private",
        "attachment-public",
        "attachment-private",
    ] {
        sqlx::query("INSERT INTO facet_values(record_id,key,value,value_num,vocab_ref,created_at) VALUES(?,'fixture_key','Synthetic',12.5,'custom','2026-01-02T03:04:05.678Z')")
            .bind(id).execute(&mut source).await.unwrap();
    }
    for id in [
        "task",
        "secret",
        "direct-public",
        "direct-private",
        "comment-public",
        "comment-private",
        "attachment-public",
        "attachment-private",
    ] {
        sqlx::query("INSERT INTO facet_observations(record_id,key,as_of,event_seq) VALUES(?,'fixture_key','2026-01-02T03:04:05.678Z',1)")
            .bind(id).execute(&mut source).await.unwrap();
    }
    source.close().await.unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    let db = f.db().await;
    for (account, expected) in [("account-a", 8), ("account-b", 4)] {
        let rows=ordinary_kernel_call(&db,account,"query_sql",json!({"sql":"SELECT record_id FROM facet_values WHERE key='fixture_key' ORDER BY record_id"})).await.unwrap();
        assert_eq!(rows["rows"].as_array().unwrap().len(), expected);
    }
    for account in ["account-a", "account-b"] {
        equivalent(&db, account).await;
    }
    let admin = &report.principals["account-a"];
    k::replace_home_policy(
        &db,
        admin,
        crate::events::KERNEL_ROOT_ID,
        &[(admin, "manage")],
    )
    .await
    .unwrap();
    equivalent(&db, "account-b").await;
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    for account in ["account-a", "account-b"] {
        equivalent(&db, account).await;
    }
    db.close().await;
}
