use super::*;
use kernel::sql_record_projection as projection;

async fn compare(w: &World) {
    let actors:Vec<(String,String)>=sqlx::query_as("SELECT principal_id,auth_binding FROM kernel_principals WHERE kind='account' ORDER BY principal_id").fetch_all(w.db.pool()).await.unwrap();
    for (actor, credential) in &actors {
        for statement in [
            "SELECT * FROM records ORDER BY id",
            "SELECT type,kind,count(*) AS n FROM records GROUP BY type,kind ORDER BY type,kind",
            "SELECT id,name,updated_at_ms FROM records WHERE body IS NOT NULL ORDER BY updated_at_ms DESC,id LIMIT 2",
            "SELECT id,home_id,is_current,successor_count FROM records WHERE is_current=1 ORDER BY id",
        ] {
            let args=json!({"sql":statement});
            let (actual,stats)=sql::measured(sql::query_sql(&w.db,actor,args.clone())).await;
            assert_eq!(stats.record_projection_installations,1,"{statement}");
            let expected=sql::with_record_projection_oracle(sql::query_sql(&w.db,actor,args)).await.unwrap();
            assert_eq!(actual.unwrap(),expected,"{actor}: {statement}");
        }
        let args = json!({"steps":[{"step":"filter","name_contains":"a"}],"limit":10});
        let (actual, stats) =
            sql::measured(call_as(w, credential, "query_record", args.clone())).await;
        let expected =
            sql::with_record_projection_oracle(call_as(w, credential, "query_record", args))
                .await
                .unwrap();
        assert!(stats.record_projection_installations > 0);
        assert_eq!(actual.unwrap(), expected, "{actor}: composed query_record");
    }
}

#[tokio::test]
async fn kernel_v2_record_projection_parity_tail_and_replay() {
    let w = world().await;
    kernel::create_principal(&w.db, "account", "Restricted", "acct:restricted", &w.admin)
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "supersedes", None)
        .await
        .unwrap();
    projection::catch_up(&w.db).await.unwrap();
    assert!(w.db.sql_record_projection_generation().is_some());
    compare(&w).await;
    // Ordinary writes need not wait for background maintenance. Changed rows
    // must reflect the current snapshot through the permanent oracle.
    kernel::revise_as(
        &w.db,
        &w.admin,
        &w.first,
        json!({"body":"new body"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    compare(&w).await;
    projection::catch_up(&w.db).await.unwrap();
    compare(&w).await;
    // Caller-relative currency and placement never freeze into shared rows.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "supersedes", None)
        .await
        .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    compare(&w).await;
    projection::catch_up(&w.db).await.unwrap();
    compare(&w).await;
    let before = kernel::projection_dump::dump(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    // A rebuild drops the state even without advancing the event head.
    let (_, stats) = sql::measured(sql::query_sql(
        &w.db,
        &w.admin,
        json!({"sql":"SELECT id FROM records ORDER BY id"}),
    ))
    .await;
    assert_eq!(stats.record_projection_installations, 0);
    assert_eq!(before, kernel::projection_dump::dump(&w.db).await.unwrap());
    projection::catch_up(&w.db).await.unwrap();
    compare(&w).await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_record_projection_hidden_predicates_and_oracle_row() {
    let w = world().await;
    for id in [&w.first, &w.second] {
        kernel::revise_as(
            &w.db,
            &w.admin,
            id,
            json!({"body":"{}"}).as_object().unwrap(),
        )
        .await
        .unwrap();
    }
    projection::catch_up(&w.db).await.unwrap();
    // A cached hidden malformed body is never evaluated by caller predicates.
    let visible_json = sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT id FROM records WHERE json_extract(body,'$.x')=1 ORDER BY id"}),
    )
    .await
    .unwrap();
    assert_eq!(visible_json["row_count"], 0);
    // Both hidden body and hidden field values can be malformed; maintenance
    // skips an unprojectable row, while callers retain lazy error behaviour.
    // A raw fixture edit bypasses the production event writers. Invalidate
    // in that transaction so this exercises a cold unprojectable row.
    let mut edit = w.db.write_pool().begin().await.unwrap();
    // Summary has no JSON expression index, so the deliberately invalid
    // value can reach the projection rather than fail at index upkeep.
    sqlx::query(
        "INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'summary','malformed',created_seq FROM kernel_records WHERE id=?",
    )
    .bind(&w.hidden)
    .execute(&mut *edit)
    .await
    .unwrap();
    projection::reset_on(&mut edit).await.unwrap();
    edit.commit().await.unwrap();
    projection::catch_up(&w.db).await.unwrap();
    let cached: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_sql_record_projection WHERE id=?)")
            .bind(&w.hidden)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert!(!cached);
    for statement in [
        "SELECT id FROM records WHERE json_extract(body,'$.x')=1 ORDER BY id",
        "SELECT count(*) AS n FROM records WHERE length(body)>1000000",
        "SELECT id FROM records WHERE id='not-visible' AND json_extract(body,'$.x')=1 ORDER BY id",
    ] {
        let args = json!({"sql":statement});
        let actual = sql::query_sql(&w.db, &w.viewer, args.clone()).await;
        let expected =
            sql::with_record_projection_oracle(sql::query_sql(&w.db, &w.viewer, args)).await;
        // Compare failures as well as results; optimisation must preserve
        // the original expression's error behaviour.
        assert_eq!(
            actual.map(|v| v.to_string()).map_err(|e| e.to_string()),
            expected.map(|v| v.to_string()).map_err(|e| e.to_string()),
            "{statement}"
        );
    }
    // Id-only reads must remain usable even for an admitted oracle-only row.
    let args = json!({"sql":"SELECT id FROM records ORDER BY id"});
    assert_eq!(
        sql::query_sql(&w.db, &w.admin, args.clone()).await.unwrap(),
        sql::with_record_projection_oracle(sql::query_sql(&w.db, &w.admin, args))
            .await
            .unwrap()
    );
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_record_projection_reopen_reuses_generation_and_inspection_is_inert() {
    let w = world().await;
    let mut coord = w.db.pool().acquire().await.unwrap();
    let coordinates = crate::standby::kernel_v2::coordinates(&mut coord)
        .await
        .unwrap();
    drop(coord);
    let before = kernel::projection_dump::dump(&w.db).await.unwrap();
    // Inspection/read alone never creates cache state.
    sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT id FROM records ORDER BY id"}),
    )
    .await
    .unwrap();
    let absent: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='kernel_sql_record_projection')",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(absent);
    projection::catch_up(&w.db).await.unwrap();
    assert_eq!(before, kernel::projection_dump::dump(&w.db).await.unwrap());
    let mut coord = w.db.pool().acquire().await.unwrap();
    assert_eq!(
        coordinates,
        crate::standby::kernel_v2::coordinates(&mut coord)
            .await
            .unwrap()
    );
    drop(coord);
    let generation = w.db.sql_record_projection_generation().unwrap();
    // Normal open trusts compatible transaction-maintained rows without a
    // full source scan. A semantic mismatch triggers a rebuild.
    w.db.trust_sql_record_projection_generation(None);
    projection::catch_up(&w.db).await.unwrap();
    assert_eq!(
        w.db.sql_record_projection_generation().as_deref(),
        Some(generation.as_str())
    );
    sqlx::query("UPDATE kernel_sql_record_projection_state SET fingerprint='incompatible',written_at=0 WHERE singleton=1 AND ? IS NOT NULL")
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    w.db.trust_sql_record_projection_generation(None);
    projection::catch_up(&w.db).await.unwrap();
    assert_ne!(
        w.db.sql_record_projection_generation().as_deref(),
        Some(generation.as_str())
    );
    compare(&w).await;
    // Unexpected attached objects invalidate reads. Repair drops a trigger
    // before touching cached rows, so a stale trigger cannot poison deletes.
    sqlx::query("CREATE TRIGGER record_cache_poison AFTER DELETE ON kernel_sql_record_projection BEGIN SELECT RAISE(ABORT,'poison'); END").execute(w.db.write_pool()).await.unwrap();
    let (result, stats) = sql::measured(sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT id FROM records ORDER BY id"}),
    ))
    .await;
    result.unwrap();
    assert_eq!(stats.record_projection_installations, 0);
    projection::catch_up(&w.db).await.unwrap();
    compare(&w).await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_record_projection_multiple_batches_and_composed_scale_parity() {
    let w = world().await;
    // A bounded synthetic mix: 75% compatibility carriers, 25% typed notes.
    // The manual scale override exercises HQ-size row counts without copying HQ.
    let scale: i64 = std::env::var("NATIVE_RECORD_PROJECTION_SCALE")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(2048);
    assert!((512..=17000).contains(&scale));
    install_comment_carrier(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let task=call_as(&w,"acct:admin","create_record",json!({"type":"WorkItem","kind":"task","name":"Alpha scale task","summary":"Synthetic record metadata. ".repeat(8),"home_id":home,"lifecycle":"open"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    sqlx::query("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO kernel_records SELECT 'scale:'||i,r.home_id,r.owner_id,r.primary_type,r.kind,r.accession||':scale:'||i,r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=CASE WHEN i%4=0 THEN ?2 ELSE ?3 END")
        .bind(scale).bind(&w.first).bind(&task).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT r.id,f.name,f.value_json,f.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE r.id LIKE 'scale:%' AND f.record_id=CASE WHEN CAST(substr(r.id,7) AS INTEGER)%4=0 THEN ?1 ELSE ?2 END").bind(&w.first).bind(&task).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_metadata SELECT r.id,m.persistence,m.maturity,m.last_activity_at,m.event_seq FROM kernel_records r CROSS JOIN kernel_record_metadata m WHERE r.id LIKE 'scale:%' AND m.record_id=CASE WHEN CAST(substr(r.id,7) AS INTEGER)%4=0 THEN ?1 ELSE ?2 END").bind(&w.first).bind(&task).execute(w.db.write_pool()).await.unwrap();
    projection::catch_up(&w.db).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel_sql_record_projection WHERE id LIKE 'scale:%'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(count, scale);
    let grouped="SELECT type,lifecycle,count(*) AS n FROM records GROUP BY type,lifecycle ORDER BY type,lifecycle";
    let wide="SELECT id,type,kind,name,summary,lifecycle,persistence,maturity,archived,updated_at_ms,last_activity_at_ms,home_id,successor_count FROM records WHERE name LIKE '%Alpha%' ORDER BY updated_at DESC,id LIMIT 10";
    for (label, statement, composed) in [
        ("grouped", grouped, false),
        ("composed metadata", wide, true),
    ] {
        let run = || async {
            let args = json!({"sql":statement});
            if composed {
                sql::with_query_read_session(
                    &w.db,
                    &w.viewer,
                    &[statement],
                    sql::query_sql(&w.db, &w.viewer, args),
                )
                .await
            } else {
                sql::query_sql(&w.db, &w.viewer, args).await
            }
        };
        // Warm both adapters. Alternate order in a small bounded comparison;
        // the synthetic rows deliberately do not model record hydration.
        run().await.unwrap();
        sql::with_record_projection_oracle(run()).await.unwrap();
        let mut projected = std::time::Duration::ZERO;
        let mut oracle = std::time::Duration::ZERO;
        for pass in 0..4 {
            let (actual, expected) = if pass % 2 == 0 {
                let started = std::time::Instant::now();
                let actual = run().await.unwrap();
                projected += started.elapsed();
                let started = std::time::Instant::now();
                let expected = sql::with_record_projection_oracle(run()).await.unwrap();
                oracle += started.elapsed();
                (actual, expected)
            } else {
                let started = std::time::Instant::now();
                let expected = sql::with_record_projection_oracle(run()).await.unwrap();
                oracle += started.elapsed();
                let started = std::time::Instant::now();
                let actual = run().await.unwrap();
                projected += started.elapsed();
                (actual, expected)
            };
            assert_eq!(actual, expected);
        }
        eprintln!("synthetic {scale}-row mixed carriers {label}, 4 alternating warm reads: projection={projected:?}, oracle={oracle:?}");
        let (actual, stats) = sql::measured(run()).await;
        actual.unwrap();
        eprintln!(
            "{label} projected staging: {}us, admission: {}us, VM ops: {}",
            stats.staging_us, stats.sql_admission_us, stats.staging_vm_ops
        );
        assert!(stats.record_projection_installations > 0);
    }
    w.db.close().await;
}
