use super::*;

async fn equivalent(db: &Db, account: &str) {
    for args in [
        json!({"sql":"SELECT r.id, h.id AS home, h.home_id AS grand FROM records r LEFT JOIN records h ON h.id = r.home_id WHERE r.id='private-child'"}),
        json!({"sql":"SELECT id,type,kind,body,home_id,updated_at FROM records WHERE id IN ('direct-public','direct-private','comment-public','comment-private','attachment-public','attachment-private','private') ORDER BY id"}),
        json!({"sql":"SELECT r.id,r.home_id,r.lifecycle FROM records r WHERE r.deleted_at IS NULL AND (r.id=?1 OR r.id IN ('task',NULL)) ORDER BY r.id","parameters":[{"type":"text","value":"private"}]}),
        json!({"sql":"SELECT count(*) AS n FROM records WHERE id=?1","parameters":[{"type":"text","value":null}]}),
        json!({"sql":"SELECT key,value,value_num,created_at_ms FROM facet_values WHERE record_id=?1 ORDER BY key","parameters":[{"type":"text","value":"task"}]}),
        json!({"sql":"SELECT i.record_id,i.status,i.raw,v.value FROM record_lifecycle_interpretations i LEFT JOIN vocabulary_values v ON v.vocabulary_id=i.vocabulary_id WHERE i.record_id IN ('task','direct-public','direct-private','comment-public','comment-private','attachment-public','attachment-private') ORDER BY i.record_id,v.id"}),
        json!({"sql":"SELECT id FROM records WHERE id='task' OR kind='comment' ORDER BY id"}),
        json!({"sql":"SELECT id,(SELECT count(*) FROM records) AS n FROM records WHERE id='task'"}),
        json!({"sql":"SELECT r.id,h.id AS home FROM records r LEFT JOIN records h ON h.id=r.home_id WHERE r.id='task'"}),
        json!({"sql":"SELECT r.id,h.id AS home,h.name FROM records r FULL JOIN records h ON r.home_id=h.id WHERE r.id IN ('task','private','direct-private','comment-public') ORDER BY r.id,h.id"}),
        json!({"sql":"SELECT r.id,h.id AS home FROM records r RIGHT JOIN records h ON h.id=r.home_id WHERE r.id=NULL ORDER BY r.id,h.id"}),
        json!({"sql":"SELECT r.id,r.name,r.summary,substr(r.body,1,200) AS body,r.updated_at,r.created_at_ms,h.name AS home_name FROM records r LEFT JOIN records h ON h.id=r.home_id WHERE r.id='task' ORDER BY r.id"}),
        json!({"sql":"SELECT r.type,r.kind,count(*) AS n,max(r.updated_at_ms) AS updated,sum(r.last_activity_at_ms % 100003) AS activity FROM records r GROUP BY r.type,r.kind ORDER BY r.type,r.kind"}),
        json!({"sql":"SELECT id,type,kind,name,substr(body,1,200) AS body,home_id,created_at_ms FROM records WHERE kind IN ('comment','attachment') ORDER BY id"}),
        json!({"sql":"WITH t AS (SELECT id,home_id FROM records WHERE kind='task') SELECT t.id AS task,r.id AS comment,r.name FROM t LEFT JOIN records r ON r.home_id=t.home_id AND r.kind='comment' ORDER BY t.id,r.id"}),
        json!({"sql":"SELECT r.id,r.type,r.name FROM records r WHERE r.type IN ('WorkItem','Message') ORDER BY r.id"}),
        json!({"sql":"SELECT id,is_current,successor_count FROM records WHERE id IN ('task','private') ORDER BY id"}),
        json!({"sql":"SELECT i.record_id,i.status,i.raw,i.axis_key,i.vocabulary_id FROM record_lifecycle_interpretations i WHERE i.record_id IN ('private-child','private') ORDER BY i.record_id"}),
        json!({"sql":"SELECT r.id,r.type,r.kind,r.name,r.lifecycle,r.updated_at,(SELECT f.value FROM facet_values f WHERE f.record_id=r.id AND f.key='priority') AS priority FROM records r WHERE r.id IN ('task','private','direct-public','direct-private','comment-public','comment-private','attachment-public','attachment-private') AND NOT EXISTS(SELECT 1 FROM facet_values a WHERE a.record_id=r.id AND a.key='archived') ORDER BY r.id"}),
        json!({"sql":"SELECT r.id,(SELECT count(*) FROM facet_values f WHERE f.record_id=r.id),(SELECT count(*) FROM facet_values) AS all_facets FROM records r WHERE r.id='task'"}),
        json!({"sql":"SELECT r.id,(SELECT count(*) FROM facet_values r WHERE r.key='priority') AS n FROM records r WHERE r.id='task'"}),
        json!({"sql":"SELECT r.id,(SELECT count(*) FROM facet_values f WHERE f.record_id=r.id OR f.key='priority') AS n FROM records r WHERE r.id='task'"}),
    ] {
        let scoped = ordinary_kernel_call(db, account, "query_sql", args.clone())
            .await
            .unwrap();
        let full = crate::mcp::kernel_v2::sql::with_full_record_scope_staging(
            ordinary_kernel_call(db, account, "query_sql", args),
        )
        .await
        .unwrap();
        assert_eq!(scoped["rows"], full["rows"]);
        assert_eq!(scoped["truncated"], full["truncated"]);
    }
}

#[tokio::test]
async fn finite_record_scope_matches_full_for_direct_derived_moves_revocation_and_replay() {
    let f = Fixture::new().await;
    super::sql_fixture::prepare_visibility_fixture(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,home_id,owner_id,lifecycle,policy_anchor_id,created_at,updated_at,archived) VALUES('private-child','WorkItem','task','Synthetic private child','private','person-a','preserved','private','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0)").await.unwrap();
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
    let db = f.db().await;
    // A singleton scope must not borrow the grandparent from unrelated IDs.
    let probe = json!({"sql":"SELECT r.id, h.id AS home, h.home_id AS grand FROM records r LEFT JOIN records h ON h.id = r.home_id WHERE r.id='private-child'"});
    let scoped = ordinary_kernel_call(&db, "account-a", "query_sql", probe.clone())
        .await
        .unwrap();
    let full = crate::mcp::kernel_v2::sql::with_full_record_scope_staging(ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        probe,
    ))
    .await
    .unwrap();
    assert_eq!(
        full["rows"],
        json!([{"id":"private-child","home":"private","grand":"folder"}])
    );
    assert_eq!(scoped["rows"], full["rows"]);
    ordinary_kernel_call(&db,"account-b","create_record",json!({"type":"Annotation","kind":"comment","body":"Synthetic native public comment","links":[{"target_id":"task","relationship":"part_of"}]})).await.unwrap();
    ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Annotation","kind":"comment","body":"Synthetic native private comment","links":[{"target_id":"direct-private","relationship":"part_of"}]})).await.unwrap();

    ordinary_kernel_call(
        &db,
        "account-a",
        "manage_links",
        json!({"action":"add","source_id":"epic","target_id":"task","relationship":"supersedes"}),
    )
    .await
    .unwrap();
    ordinary_kernel_call(
        &db,
        "account-a",
        "manage_links",
        json!({"action":"add","source_id":"secret","target_id":"task","relationship":"supersedes"}),
    )
    .await
    .unwrap();
    for account in ["account-a", "account-b"] {
        equivalent(&db, account).await;
    }
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"private","home_id":"native:root","lifecycle":"open"}),
    )
    .await
    .unwrap();
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
