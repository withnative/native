//! Synthetic HQ-scale diagnostic, deliberately outside the ordinary test suite.
//! Run: cargo test -p native-ce --lib --features v2-kernel-probe kernel_v2_sql_hq_scale_bench -- --ignored --nocapture
use super::*;

/// Extract the actual shell first-page SQL rather than maintaining a second copy.
/// Graph reads this index via store.js (embedded in web/shell via /alpha/).
fn shell_page(function: &str) -> String {
    let source = include_str!("../../../experiments/demo-shell/public/lib/indexSql.js");
    let columns = source
        .split("export const COLUMNS = \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    source
        .split(&format!("export function {function}(after) {{"))
        .nth(1)
        .unwrap()
        .split("sql: `")
        .nth(1)
        .unwrap()
        .split('`')
        .next()
        .unwrap()
        .replace("${COLUMNS}", columns)
        .replace("${PAGE}", "1000")
}

#[tokio::test]
#[ignore = "HQ-scale SQL staging benchmark; bulk fixture and wall-clock diagnostics"]
async fn kernel_v2_sql_hq_scale_bench() {
    let w = hq_world(None).await;
    let index_sql = shell_page("indexPage");
    let text = |value: &str| json!({"type":"text","value":value});
    let shapes = [
        (
            "workspace_group",
            json!({"sql":"SELECT type, kind, count(*) AS n FROM records GROUP BY type, kind"}),
        ),
        (
            "workspace_event_join",
            json!({"sql":"SELECT r.id, count(e.id) AS n FROM records r JOIN content_events e ON e.record_id=r.id GROUP BY r.id ORDER BY n DESC, r.id LIMIT 20"}),
        ),
        (
            "shell_index_first",
            json!({"sql":index_sql,"parameters":[text("")]}),
        ),
        (
            "shell_index_late",
            json!({"sql":index_sql,"parameters":[text("hq:11000")]}),
        ),
        (
            "graph_facets_first",
            json!({"sql":shell_page("facetPage"),"parameters":[text(""),text(""),text("")]}),
        ),
        (
            "graph_links_first",
            json!({"sql":shell_page("linkPage"),"parameters":[text(""),text(""),text(""),text(""),text(""),text("")]}),
        ),
        (
            "narrow_id",
            json!({"sql":"SELECT id, type, kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at FROM records WHERE id=?1", "parameters":[text("hq:11700")]}),
        ),
        (
            "hidden_id",
            json!({"sql":"SELECT id FROM records WHERE id=?1", "parameters":[text("private:00001")]}),
        ),
    ];
    for (shape, args) in shapes {
        let started = std::time::Instant::now();
        let (result, stats) = super::super::sql::measured(call(&w, "query_sql", args)).await;
        let elapsed = started.elapsed();
        let (timeout, outcome) = match result {
            Ok(value) => {
                if shape == "hidden_id" {
                    assert_eq!(value["row_count"], 0);
                }
                if shape == "narrow_id" {
                    assert_eq!(value["row_count"], 1);
                }
                (false, format!("rows={}", value["row_count"]))
            }
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("[timeout]"),
                    "{shape}: unexpected error: {message}"
                );
                (
                    message.contains("SQL relation staging exceeded query deadline"),
                    message,
                )
            }
        };
        eprintln!("HQ_BENCH shape={shape} staging_timeout={timeout} wall_ms={:.3} outcome={outcome} stats={stats:?}", elapsed.as_secs_f64()*1000.0);
    }
    // The preferred graph boot is a backend snapshot; SQL above is its fallback.
    // Measure that real MCP path too, including every immutable section page.
    let started = std::time::Instant::now();
    let (opened, stats) =
        super::super::sql::measured(call(&w, "get_workspace_snapshot", json!({"action":"open"})))
            .await;
    let opened = opened.unwrap();
    eprintln!(
        "HQ_BENCH shape=graph_snapshot_open wall_ms={:.3} unavailable={} stats={stats:?}",
        started.elapsed().as_secs_f64() * 1000.0,
        opened["unavailable"]
    );
    if let Some(token) = opened["snapshot_token"].as_str() {
        let started = std::time::Instant::now();
        let mut pages = 0;
        let mut counts = Vec::new();
        for section in ["records", "facets", "links"] {
            let mut after = Value::Null;
            let mut count = 0;
            loop {
                let page = call(
                    &w,
                    "get_workspace_snapshot",
                    json!({"action":"page",
                    "snapshot_token":token,"section":section,"limit":1000,"after_id":after}),
                )
                .await
                .unwrap();
                assert_ne!(page["restart_required"], true, "{page}");
                assert_ne!(page["unavailable"], true, "{page}");
                let rows = page["rows"].as_array().unwrap();
                assert!(!rows.iter().any(|row| row["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("private:"))));
                count += rows.len();
                pages += 1;
                if page["has_more"] != true {
                    break;
                }
                after = page["after_id"].clone();
                assert!(!after.is_null(), "{page}");
                assert!(pages < 100);
            }
            counts.push((section, count));
        }
        eprintln!(
            "HQ_BENCH shape=graph_snapshot_pages wall_ms={:.3} pages={pages} counts={counts:?}",
            started.elapsed().as_secs_f64() * 1000.0
        );
    } else {
        assert_eq!(opened["unavailable"], true, "{opened}");
    }
    w.db.close().await;
}

async fn hq_world(imported_percent: Option<u32>) -> World {
    hq_world_size(imported_percent, 11700, 2616).await
}

async fn hq_world_size(imported_percent: Option<u32>, records: i64, hot_events: i64) -> World {
    let setup = std::time::Instant::now();
    let w = world().await;
    // Real definition/pin/ACL setup; bulk projections below bypass the write API.
    let kinds = ["note", "spec", "decision"];
    let definition = json!({"family":"fixture.hq", "version":1,
        "interpreter":"native.defn/2", "primary_type":"Document",
        "kinds": kinds.iter().map(|kind| json!({"token":kind,
            "description":"HQ benchmark", "maturity":"current",
            "identity":{"field":"title"}, "links":[],
            "fields":[{"name":"title","type":"text","required":true},
                {"name":"body","type":"text","required":false},
                {"name":"summary","type":"text","required":false}]})).collect::<Vec<_>>()});
    let pin = kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.hq",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let mut templates = Vec::new();
    for i in 0..9 {
        let home = kernel::create_home(
            &w.db,
            KERNEL_ROOT_ID,
            Some(&[(&w.viewer, "view")]),
            &w.admin,
        )
        .await
        .unwrap();
        let id = kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.hq",
            kinds[i % 3],
            json!({"title":format!("Template {i}"),"summary":"HQ benchmark template",
                "body":"Synthetic current body"})
            .as_object()
            .unwrap(),
            &home,
        )
        .await
        .unwrap();
        templates.push(id);
    }
    let hidden_home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.hidden)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let carrier = if imported_percent.is_some() {
        Some(event_profile::prepare_carrier(&w).await)
    } else {
        None
    };
    let mut tx = w.db.write_pool().begin().await.unwrap();
    sqlx::query("CREATE TEMP TABLE bench_n AS WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?) SELECT x FROM n").bind(records)
        .execute(&mut *tx).await.unwrap();
    // 11,700 added visible records, 300 private records; all headers have genuine
    // type/kind pins. Hot records are spread across homes, not one privileged home.
    for (i, template) in templates.iter().enumerate() {
        sqlx::query("INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('hq:%05d',n.x),r.home_id,r.owner_id,r.primary_type,r.kind,printf('hq-accession:%05d',n.x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM bench_n n CROSS JOIN kernel_records r WHERE r.id=? AND (n.x-1)%9=?")
            .bind(template).bind(i as i64).execute(&mut *tx).await.unwrap();
    }
    sqlx::query("INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('private:%05d',n.x),?,r.owner_id,r.primary_type,r.kind,printf('private-accession:%05d',n.x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM bench_n n CROSS JOIN kernel_records r WHERE r.id=? AND n.x<=?")
        .bind(&hidden_home).bind(&templates[0]).bind(300 * (records / 16700).max(1)).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT r.id,f.name,CASE WHEN f.name='title' THEN json_quote('HQ record '||r.id) WHEN f.name='summary' THEN json_quote('Synthetic summary for '||r.id) ELSE f.value_json END,r.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE (r.id GLOB 'hq:*' OR r.id GLOB 'private:*') AND f.record_id=?")
        .bind(&templates[0]).execute(&mut *tx).await.unwrap();
    // 11,700*4 + 100*2612 = 308,000 events, plus 1,200 hidden events.
    // Native revision envelopes exercise the real event-ID selection, header
    // redaction, and index creation. Payloads/bodies are small and repetitive;
    // this does NOT model HQ's imported legacy envelopes/subject disclosures.
    sqlx::query("CREATE TEMP TABLE bench_events AS WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?) SELECT x FROM n").bind(hot_events)
        .execute(&mut *tx).await.unwrap();
    sqlx::query("CREATE INDEX temp.bench_events_x ON bench_events(x)")
        .execute(&mut *tx)
        .await
        .unwrap();
    if let Some(percent) = imported_percent {
        event_profile::mixed_events(&w, &mut tx, carrier.as_deref().unwrap(), percent, 11700).await;
    } else {
        // Separate indexed ranges avoid a records × hot-history Cartesian
        // filter during setup (billions of rejected candidates at 10x).
        for predicate in [
            "(r.id GLOB 'hq:*' OR r.id GLOB 'private:*') AND n.x<=4",
            "r.id GLOB 'hq:*' AND r.id<='hq:00100' AND n.x>4",
        ] {
            sqlx::query(&format!("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status,created_at) SELECT printf('hq-event:%s:%d',r.id,n.x),r.id,'kernel.record_revised.v2',json_object('fields',json_object('body','Synthetic revision '||n.x)),?,1,'legacy_unknown',r.created_at FROM kernel_records r CROSS JOIN bench_events n WHERE {predicate}"))
                .bind(&w.admin).execute(&mut *tx).await.unwrap();
        }
    }
    // 15,600 synthetic directed edges, plus an edge to a hidden endpoint. These
    // use real kernel_links projection rows; link events are not synthesized.
    sqlx::query("INSERT INTO kernel_links(source_id,target_id,relationship,created_seq) SELECT printf('hq:%05d',x),printf('hq:%05d',x%11700+1),'relates_to',r.created_seq FROM bench_n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&templates[0]).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_links(source_id,target_id,relationship,created_seq) SELECT printf('hq:%05d',x),printf('hq:%05d',(x+99)%11700+1),'relates_to',r.created_seq FROM bench_n CROSS JOIN kernel_records r WHERE r.id=? AND x%3=0")
        .bind(&templates[0]).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_links(source_id,target_id,relationship,created_seq) SELECT 'hq:00001',?, 'relates_to',created_seq FROM kernel_records WHERE id=?")
        .bind(&w.hidden).bind(&templates[0]).execute(&mut *tx).await.unwrap();
    // Exercise the graph's facet chain with three current facets per record.
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) SELECT r.id,k.key,k.value,r.created_at,r.created_seq FROM kernel_records r CROSS JOIN (SELECT 'lifecycle' AS key,'open' AS value UNION ALL SELECT 'priority','normal' UNION ALL SELECT 'account','HQ') k WHERE r.id GLOB 'hq:*'")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("DROP TABLE bench_n; DROP TABLE bench_events")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id GLOB 'hq:*' AND id GLOB 'hq-event:*'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(events, records * 4 + 100 * (hot_events - 4));
    eprintln!("HQ fixture: added {records} visible + {} hidden records, {events} visible source events; setup={:?}", 300 * (records / 16700).max(1), setup.elapsed());

    w
}

#[path = "sql_event_bench.rs"]
mod event_profile;

#[path = "sql_read_cost_bench.rs"]
mod read_cost_baseline;
