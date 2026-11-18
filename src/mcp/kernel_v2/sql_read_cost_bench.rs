//! Fixed server workload; declaration SQL is loaded from shipped source.
use super::super::super::sql;
use super::*;

fn queries(id: &str) -> Vec<(String, Vec<Value>)> {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("web/apps/src/apps/docs/declaration.json"),
    )
    .unwrap();
    let declaration: Value = serde_json::from_str(&source).unwrap();
    let text = |v: &str| json!({"type":"text","value":v});
    let mut out = Vec::new();
    for key in [
        "docs.page",
        "docs.body",
        "docs.links",
        "docs.stamp",
        "docs.recent",
    ] {
        let need = declaration["needs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["key"] == key)
            .unwrap();
        for section in if key == "docs.links" {
            vec!["details", "threads", "history"]
        } else {
            vec![""]
        } {
            let params = need["params"]
                .as_array()
                .map(|p| {
                    p.iter()
                        .map(|p| {
                            text(match p["name"].as_str().unwrap() {
                                "record_id" => id,
                                "section" => section,
                                _ => "",
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            out.push((
                format!(
                    "{key}{}",
                    if section.is_empty() {
                        String::new()
                    } else {
                        format!(".{section}")
                    }
                ),
                vec![json!({"sql":need["sql"],"parameters":params})],
            ));
        }
    }
    for (name, statement) in [
        ("comments.page", "SELECT s.id, substr(s.body,1,4000) AS body FROM links l JOIN records s ON s.id=l.source_id WHERE l.target_id=?1 AND l.relationship='part_of' AND s.type='Annotation' AND s.kind='comment' ORDER BY l.created_at_ms DESC,s.id LIMIT 20"),
        ("history.window", "SELECT id,local_seq,type FROM content_events WHERE record_id=?1 ORDER BY local_seq DESC LIMIT 12"),
        ("aggregate.join", "SELECT r.type,count(e.id) AS n FROM records r JOIN content_events e ON e.record_id=r.id GROUP BY r.type ORDER BY r.type"),
    ] { out.push((name.into(), vec![json!({"sql":statement,"parameters":if statement.contains("?1") {vec![text(id)]} else {vec![]}})])); }
    out.push((
        "docs.batch".into(),
        out.iter().take(6).flat_map(|(_, q)| q.clone()).collect(),
    ));
    out
}

#[tokio::test]
#[ignore = "synthetic 1x/10x deterministic read-cost baseline; scripts/read-cost-baseline.py"]
async fn kernel_v2_read_cost_baseline() {
    let repetitions: usize = std::env::var("READ_COST_REPETITIONS")
        .unwrap_or("3".into())
        .parse()
        .unwrap();
    assert!(repetitions > 0);
    // `demand`: serve through live demand-scoped visibility (S1a), and compare
    // each first-use envelope with today's full staging.
    let demand = std::env::var("READ_COST_MODE").as_deref() == Ok("demand");
    let w = hq_world_size(None, 16700, 2616).await;
    install_comment_carrier(&w).await;
    let restricted =
        kernel::create_principal(&w.db, "account", "Restricted", "acct:restricted", &w.admin)
            .await
            .unwrap();
    for i in 0..3 {
        call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":format!("Synthetic comment {i}"),"links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap();
    }
    for revision in 0..12 {
        kernel::revise_as(
            &w.db,
            &w.admin,
            &w.first,
            json!({"body":format!("Revision {revision:02}: {}", "x".repeat(8192))})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();
    }
    let fixed_fields: Vec<(String, String)> = sqlx::query_as(
        "SELECT name,value_json FROM kernel_record_fields WHERE record_id=? ORDER BY name",
    )
    .bind(&w.first)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    for scale in [1, 10] {
        if scale == 10 {
            expand_unrelated(&w).await;
        }
        let fields: Vec<(String, String)> = sqlx::query_as(
            "SELECT name,value_json FROM kernel_record_fields WHERE record_id=? ORDER BY name",
        )
        .bind(&w.first)
        .fetch_all(w.db.pool())
        .await
        .unwrap();
        assert_eq!(fields, fixed_fields);
        w.db.settle_sql_event_projection().await;
        kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        kernel::sql_record_projection::catch_up(&w.db)
            .await
            .unwrap();
        sql::visible_cache::disable_for_test(&w.db);
        sql::visible_cache::enable_for_test(&w.db).await;
        // Same target and its own data in both sizes. Background templates,
        // fields, links, facets and events grow; no real workspace is accessed.
        let only = std::env::var("READ_COST_QUERIES").unwrap_or_default();
        for (name, batch) in queries(&w.first) {
            if !only.is_empty() && !only.split(',').any(|q| q == name) {
                continue;
            }
            for repetition in 0..=repetitions {
                let started = std::time::Instant::now();
                let run = || {
                    Box::pin(async {
                        if batch.len() == 1 {
                            return sql::query_sql(&w.db, &w.viewer, batch[0].clone())
                                .await
                                .map(|v| vec![v]);
                        }
                        sql::with_bound_query_read_session(&w.db, &w.viewer, &batch, async {
                            let mut results = Vec::new();
                            for args in &batch {
                                results.push(sql::query_sql(&w.db, &w.viewer, args.clone()).await?);
                            }
                            Ok(results)
                        })
                        .await
                    })
                };
                let ((result, stats), cost) = sql::read_cost::measure(sql::measured(async {
                    if demand {
                        sql::demand::with_enabled_for_test(run()).await
                    } else {
                        run().await
                    }
                }))
                .await;
                let result = result.unwrap_or_else(|e| panic!("{scale}x {name}: {e}"));
                if demand && repetition == 0 {
                    let (expected, _) =
                        sql::read_cost::measure(sql::with_full_read_oracle(run())).await;
                    assert_eq!(
                        result,
                        expected.unwrap(),
                        "full-staging mismatch {scale}x {name}"
                    );
                    eprintln!(
                        "DEMAND_EQUIVALENCE scale={scale} query={name} path={:?} pass",
                        stats.demand
                    );
                }
                eprintln!(
                    "READ_COST {}",
                    json!({"scale":scale,"query":name,"repetition":repetition,"state":if repetition==0 {"first-use; OS cache uncontrolled"} else {"warm sequential"},"cost":cost,"phases_us":stats,"wall_us":started.elapsed().as_micros(),"result_rows":result.iter().map(|r| r["row_count"].as_u64().unwrap()).sum::<u64>()})
                );
            }
        }
        // Small access matrix: an admin sees the private row; ordinary and
        // restricted principals cannot. Restricted has no workspace grant.
        for (actor, id, expected) in [
            (&w.admin, &w.hidden, 1),
            (&w.viewer, &w.hidden, 0),
            (&restricted, &w.first, 0),
        ] {
            let v=sql::query_sql(&w.db,actor,json!({"sql":"SELECT id FROM records WHERE id=?1","parameters":[{"type":"text","value":id}]})).await.unwrap();
            assert_eq!(v["row_count"], expected);
        }
    }
    w.db.close().await;
}

/// Grow only the bulk-fixture prefixes, in the same database. The measured
/// document, its comment IDs, timestamps, event seqs, links and body are never
/// recreated. Every unrelated source row/event has exactly nine new copies.
async fn expand_unrelated(w: &World) {
    let mut tx = w.db.write_pool().begin().await.unwrap();
    sqlx::query("CREATE TEMP TABLE cost_copies(n INTEGER PRIMARY KEY); INSERT INTO cost_copies VALUES(1),(2),(3),(4),(5),(6),(7),(8),(9)").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT 'copy:'||c.n||':'||r.id,r.home_id,r.owner_id,r.primary_type,r.kind,'copy:'||c.n||':'||r.accession,r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM kernel_records r CROSS JOIN cost_copies c WHERE r.id GLOB 'hq:*' OR r.id GLOB 'private:*'").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT 'copy:'||c.n||':'||f.record_id,f.name,f.value_json,f.created_seq FROM kernel_record_fields f CROSS JOIN cost_copies c WHERE f.record_id GLOB 'hq:*' OR f.record_id GLOB 'private:*'").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status,created_at) SELECT 'copy:'||c.n||':'||e.id,'copy:'||c.n||':'||e.record_id,e.type,e.payload,e.actor,e.causal_envelope_version,e.causal_status,e.created_at FROM content_events e CROSS JOIN cost_copies c WHERE e.id GLOB 'hq-event:*'").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_links(source_id,target_id,relationship,created_seq) SELECT 'copy:'||c.n||':'||l.source_id,CASE WHEN l.target_id GLOB 'hq:*' OR l.target_id GLOB 'private:*' THEN 'copy:'||c.n||':'||l.target_id ELSE l.target_id END,l.relationship,l.created_seq FROM kernel_links l CROSS JOIN cost_copies c WHERE l.source_id GLOB 'hq:*'").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) SELECT 'copy:'||c.n||':'||f.record_id,f.key,f.value,f.as_of,f.event_seq FROM kernel_facets f CROSS JOIN cost_copies c WHERE f.record_id GLOB 'hq:*'").execute(&mut *tx).await.unwrap();
    sqlx::query("DROP TABLE cost_copies")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    let (records, events): (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM kernel_records WHERE id GLOB 'hq:*' OR id GLOB 'private:*' OR id GLOB 'copy:*'),(SELECT count(*) FROM content_events WHERE id GLOB 'hq-event:*' OR id GLOB 'copy:*')").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(records, 170000);
    assert_eq!(events, 3292000);
    eprintln!("READ_COST_FIXTURE 10x unrelated_records={records} unrelated_events={events}; selected IDs and history retained");
}
