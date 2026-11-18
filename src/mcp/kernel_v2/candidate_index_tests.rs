//! Candidate-index admission, additive preparation and maintained-key proofs.
use super::*;

const INDEXES: [&str; 2] = ["idx_kernel_record_names", "idx_kernel_record_logical_homes"];

async fn event_log(db: &Db) -> Vec<crate::events::EventRow> {
    let mut connection = db.pool().acquire().await.unwrap();
    crate::conformance::rebuild::read_events_after_seq(&mut connection, i64::MIN)
        .await
        .unwrap()
}

async fn index_exists(db: &Db, name: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?)")
        .bind(name)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn schema_version(db: &Db) -> i64 {
    sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn api<'a>(
    w: &'a World,
    credential: &'a str,
    tool: &'a str,
    args: Value,
) -> futures::future::BoxFuture<'a, Result<Value>> {
    Box::pin(call_as(w, credential, tool, args))
}

#[tokio::test]
async fn record_reads_candidate_indexes_require_explicit_old_file_preparation() {
    let mut w = Box::pin(world()).await;
    for index in INDEXES {
        assert!(
            index_exists(&w.db, index).await,
            "fresh schema lacks {index}"
        );
        let events = event_log(&w.db).await;
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
        let schema = schema_version(&w.db).await;
        let error = kernel::verify_v2_ready(&w.db).await.unwrap_err();
        assert!(error.to_string().contains(index), "{error}");
        w.db.close().await;
        let path = w._dir.path().join("v2.db");
        let Err(error) = kernel::open_marked_v2_database(path.to_str().unwrap()).await else {
            panic!("serving must refuse an unprepared old file");
        };
        assert!(error.to_string().contains(index), "{error}");
        // The controlled preparation opener admits old schemas; serving does
        // not silently add an index while opening or reporting readiness.
        w.db = crate::db::open_existing_v2_file(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(schema_version(&w.db).await, schema);
        assert!(!index_exists(&w.db, index).await);
        assert_eq!(event_log(&w.db).await, events);
        Box::pin(kernel::prepare_v2_database(&w.db)).await.unwrap();
        kernel::verify_v2_ready(&w.db).await.unwrap();
        assert!(index_exists(&w.db, index).await);
        assert_eq!(event_log(&w.db).await, events);
        let prepared_schema = schema_version(&w.db).await;
        w.db.close().await;
        w.db = kernel::open_marked_v2_database(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(schema_version(&w.db).await, prepared_schema);
        assert_eq!(event_log(&w.db).await, events);
        let resolved = api(
            &w,
            "acct:viewer",
            "resolve_many",
            json!({"names":["Alpha"]}),
        )
        .await
        .unwrap();
        assert_eq!(resolved["results"][0]["match"]["id"], w.first);
        assert_eq!(schema_version(&w.db).await, prepared_schema);
    }
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_candidate_indexes_do_not_gate_low_level_writes() {
    let w = Box::pin(world()).await;
    for index in INDEXES {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let destination = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    Box::pin(kernel::revise_as(
        &w.db,
        &w.admin,
        &w.first,
        json!({"body":"Low-level changed body"})
            .as_object()
            .unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(kernel::rehome_record_as(
        &w.db,
        &w.admin,
        &w.first,
        &destination,
    ))
    .await
    .unwrap();
    let current = kernel::read_record_as(&w.db, &w.viewer, &w.first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.fields["body"], "Low-level changed body");
    assert_eq!(current.fields["title"], "Alpha");
    assert_eq!(current.home_id, destination);
    for index in INDEXES {
        assert!(!index_exists(&w.db, index).await);
    }
    let events = event_log(&w.db).await;
    Box::pin(kernel::prepare_v2_database(&w.db)).await.unwrap();
    assert_eq!(event_log(&w.db).await, events);
    let resolved = api(
        &w,
        "acct:viewer",
        "resolve_many",
        json!({"names":["Alpha"]}),
    )
    .await
    .unwrap();
    assert_eq!(resolved["results"][0]["match"]["id"], w.first);
    w.db.close().await;
}

fn maintained_answers<'a>(
    w: &'a World,
    record: &'a str,
    old_folder: &'a str,
    new_folder: &'a str,
) -> futures::future::BoxFuture<'a, Vec<Value>> {
    Box::pin(async move {
        let mut answers = Vec::new();
        for (credential, actor) in [("acct:admin", &w.admin), ("acct:viewer", &w.viewer)] {
            let args = json!({"names":["Before index rename","Fresh index \"λ\""]});
            let expected = record_reads::with_full_small_read_staging(api(
                w,
                credential,
                "resolve_many",
                args.clone(),
            ))
            .await
            .unwrap();
            let resolved = api(w, credential, "resolve_many", args).await.unwrap();
            assert_eq!(resolved, expected);
            assert_eq!(resolved["results"][0]["status"], "not_found");
            assert_eq!(resolved["results"][1]["match"]["id"], record);
            answers.push(resolved);
            let (get, _, _) = bounded_placement_get_pair(
                w,
                credential,
                actor,
                json!({"ids":[old_folder,new_folder,record],"children_limit":50}),
            )
            .await;
            assert!(!get["records"][0]["children"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == record));
            assert!(get["records"][1]["children"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == record));
            assert_eq!(get["records"][2]["home_id"], new_folder);
            answers.push(get);
            let args = json!({"id":record});
            let expected = record_reads::with_full_small_read_staging(api(
                w,
                credential,
                "render_record",
                args.clone(),
            ))
            .await
            .unwrap();
            let rendered = api(w, credential, "render_record", args).await.unwrap();
            assert_eq!(rendered, expected);
            answers.push(rendered);
        }
        answers
    })
}

#[tokio::test]
async fn record_reads_candidate_indexes_maintain_fresh_keys_and_rebuild_after_replay() {
    let w = Box::pin(world()).await;
    Box::pin(install_comment_carrier(&w)).await;
    let package = crate::v2_standard::document_package();
    let installed = Box::pin(kernel::install_package_as(&w.db, &w.admin, &package))
        .await
        .unwrap();
    Box::pin(kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    ))
    .await
    .unwrap();
    for index in INDEXES {
        assert!(index_exists(&w.db, index).await);
    }
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut folders = Vec::new();
    for name in ["Initial indexed folder", "Fresh indexed destination"] {
        folders.push(
            api(
                &w,
                "acct:admin",
                "create_record",
                json!({"type":"Collection","kind":"folder","name":name,"home_id":home}),
            )
            .await
            .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let record = api(&w, "acct:admin", "create_record",
        json!({"type":"Document","kind":"note","name":"Before index rename","body":"canonical key maintenance","home_id":folders[0]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    api(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":record,"name":"Fresh index \"λ\""}),
    )
    .await
    .unwrap();
    // This destination has never appeared in this record's move history.
    api(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":record,"home_id":folders[1]}),
    )
    .await
    .unwrap();
    let events = event_log(&w.db).await;
    let expected = maintained_answers(&w, &record, &folders[0], &folders[1]).await;
    // Replaying with indexes installed must maintain the name keys as fields
    // are cleared/refolded, without changing the authoritative content log.
    Box::pin(kernel::replay_all_projections(&w.db))
        .await
        .unwrap();
    assert_eq!(event_log(&w.db).await, events);
    assert_eq!(
        maintained_answers(&w, &record, &folders[0], &folders[1]).await,
        expected
    );
    for index in INDEXES {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    // The explicit additive path rebuilds the lookup structures from retained
    // fields/history; no replay or event mutation is needed for this repair.
    Box::pin(kernel::prepare_v2_database(&w.db)).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    assert_eq!(event_log(&w.db).await, events);
    assert_eq!(
        maintained_answers(&w, &record, &folders[0], &folders[1]).await,
        expected
    );
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_candidate_index_preparation_refuses_malformed_projection_atomically() {
    let w = Box::pin(world()).await;
    for index in ["idx_kernel_record_event_clock", INDEXES[0], INDEXES[1]] {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let malformed = "{retained malformed title";
    sqlx::query("UPDATE kernel_record_fields SET value_json=? WHERE record_id=? AND name='title'")
        .bind(malformed)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let events = event_log(&w.db).await;
    let error = Box::pin(kernel::prepare_v2_database(&w.db))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("malformed JSON"), "{error}");
    let retained: String = sqlx::query_scalar(
        "SELECT value_json FROM kernel_record_fields WHERE record_id=? AND name='title'",
    )
    .bind(&w.first)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(retained, malformed);
    assert_eq!(event_log(&w.db).await, events);
    // Clock creation precedes name-index creation in the additive transaction.
    // Its absence proves failure did not leave earlier index work committed.
    for index in ["idx_kernel_record_event_clock", INDEXES[0], INDEXES[1]] {
        assert!(
            !index_exists(&w.db, index).await,
            "partial preparation left {index}"
        );
    }
    assert!(kernel::verify_v2_ready(&w.db).await.is_err());
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_malformed_moves_already_refuse_without_new_lookup_index() {
    let w = Box::pin(world()).await;
    sqlx::query("DROP INDEX idx_kernel_record_logical_homes")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(index_exists(&w.db, "idx_kernel_historical_home").await);
    let events = event_log(&w.db).await;
    // The retained schema's historical-home expression already extracts move
    // JSON; malformed receipts cannot newly enter it while the new index is
    // absent. Do not rewrite or normalize retained payloads during preparation.
    let error = sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES('bad-move-json',?1,'kernel.record_rehomed.v2','{',?2,'2026-01-01T00:00:00Z',1,'legacy_unknown')")
        .bind(&w.first).bind(&w.admin).execute(w.db.write_pool()).await.expect_err("malformed move must be refused by the existing schema");
    assert!(error.to_string().contains("malformed JSON"), "{error}");
    assert_eq!(event_log(&w.db).await, events);
    assert!(!index_exists(&w.db, INDEXES[1]).await);
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_lookup_preparation_refuses_wrong_definition_and_rolls_back() {
    let w = Box::pin(world()).await;
    // Keep replacement on one connection: a different pooled connection can
    // still have the old schema cached when CREATE is prepared after DROP.
    let mut fixture = w.db.write_pool().acquire().await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_record_names")
        .execute(&mut *fixture)
        .await
        .unwrap();
    let conflicting = "CREATE INDEX idx_kernel_record_names ON kernel_record_fields(record_id)";
    sqlx::query(conflicting)
        .execute(&mut *fixture)
        .await
        .unwrap();
    drop(fixture);
    // Both names exist: ordinary serving must check the retained definitions,
    // not merely admit an index with the expected name.
    let error = kernel::verify_v2_ready(&w.db).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unexpected definition for idx_kernel_record_names"),
        "{error}"
    );
    sqlx::query("DROP INDEX idx_kernel_record_logical_homes")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let events = event_log(&w.db).await;
    let schema = schema_version(&w.db).await;
    let error = kernel::prepare_record_lookup_indexes(&w.db)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unexpected definition for idx_kernel_record_names"),
        "{error}"
    );
    assert!(!index_exists(&w.db, INDEXES[1]).await);
    assert_eq!(schema_version(&w.db).await, schema);
    let retained: String =
        sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE name='idx_kernel_record_names'")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(retained, conflicting);
    assert_eq!(event_log(&w.db).await, events);

    // The broader explicit metadata upgrade must reject the same conflict and
    // undo earlier index creation in its own transaction as well.
    sqlx::query("DROP INDEX idx_kernel_record_event_clock")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let schema = schema_version(&w.db).await;
    let error = kernel::ensure_record_metadata(&w.db).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unexpected definition for idx_kernel_record_names"),
        "{error}"
    );
    assert!(!index_exists(&w.db, "idx_kernel_record_event_clock").await);
    assert!(!index_exists(&w.db, INDEXES[1]).await);
    assert_eq!(schema_version(&w.db).await, schema);
    assert_eq!(event_log(&w.db).await, events);
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_lookup_preparation_requires_remaining_readiness_atomically() {
    let w = Box::pin(world()).await;
    // Retain a schema-warm writer while another connection drops the indexes.
    let mut writer = w.db.write_pool().acquire().await.unwrap();
    let clock_probe = "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='idx_kernel_record_event_clock'";
    let clock_before: i64 = sqlx::query_scalar(clock_probe)
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    assert_eq!(clock_before, 1);
    for index in [INDEXES[0], INDEXES[1], "idx_kernel_record_event_clock"] {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let events = event_log(&w.db).await;
    let schema = schema_version(&w.db).await;
    let error = kernel::prepare_record_lookup_indexes(&w.db)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("missing idx_kernel_record_event_clock"),
        "{error}"
    );
    for index in [INDEXES[0], INDEXES[1], "idx_kernel_record_event_clock"] {
        assert!(!index_exists(&w.db, index).await);
    }
    assert_eq!(schema_version(&w.db).await, schema);
    assert_eq!(event_log(&w.db).await, events);

    // Repairing the unrelated dependency permits the narrow preparation. It
    // builds only the requested indexes, with no retained-log changes.
    // Refresh this physical writer's schema view before preparing CREATE: a
    // different pooled connection may still cache the index from before DROP.
    let clock_exists: i64 = sqlx::query_scalar(clock_probe)
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    assert_eq!(clock_exists, 0);
    sqlx::query(kernel::record_metadata::CLOCK_INDEX)
        .execute(&mut *writer)
        .await
        .unwrap();
    drop(writer);
    kernel::prepare_record_lookup_indexes(&w.db).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    for index in INDEXES {
        assert!(index_exists(&w.db, index).await);
    }
    assert_eq!(event_log(&w.db).await, events);
    let schema = schema_version(&w.db).await;
    kernel::prepare_record_lookup_indexes(&w.db).await.unwrap();
    assert_eq!(schema_version(&w.db).await, schema);
    assert_eq!(event_log(&w.db).await, events);
    w.db.close().await;
}

/// P2 link-endpoint indexes: fixed anchor degree stays covered while the
/// unrelated graph grows, with baseline-vs-candidate work evidence from the
/// same shipping sqlx/SQLite engine (never the Python sqlite3).
/// Diagnostic rows use FK-valid endpoint records; production constraints are
/// untouched. The global duplicate-provider guard keeps its own scan and is
/// asserted separately, so plan assertions require endpoint-branch SEARCH
/// rather than the absence of every SCAN.
const LINK_ENDPOINT_INDEXES: [&str; 4] = [
    "idx_kernel_link4_edges_source",
    "idx_kernel_link4_edges_target",
    "idx_kernel_provider_link_rows_source",
    "idx_kernel_provider_link_rows_target",
];

#[tokio::test]
async fn link_candidates_endpoint_indexes_cover_fixed_anchor_degree() {
    use super::super::read_surface::{candidate_query, direct_candidates_on, AnchorPlan};
    use std::collections::BTreeSet;
    const NEW_INDEXES: [&str; 4] = LINK_ENDPOINT_INDEXES;
    const ENDPOINT_POOL: i64 = 7_000;
    const SMALL_LINK4: i64 = 1_000;
    const SMALL_PROVIDER_ROWS: i64 = 1_000;
    const LARGE_LINK4: i64 = 15_000;
    const LARGE_PROVIDER_ROWS: i64 = 15_000;
    let w = world().await;
    // Baseline configuration for this run: drop the product endpoint indexes
    // when a fresh file carries them, so the first measurements below run
    // without them on this same engine.
    for index in NEW_INDEXES {
        sqlx::query(&format!("DROP INDEX IF EXISTS {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let anchor = w.first.clone();
    let ep = w.second.clone();
    let subj = "subj-p1-endpoint-probe";
    // FK-valid synthetic endpoints: bare records homed at the kernel root.
    // One shared pool serves both the link4 and provider bulk below.
    sqlx::query(&format!(
        "INSERT INTO kernel_records(id,home_id,created_seq,created_at) SELECT 'un-'||x,'{root}',1,'2026-01-01T00:00:00Z' FROM (WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<{ENDPOINT_POOL}) SELECT x FROM n)",
        root = crate::events::KERNEL_ROOT_ID
    ))
    .execute(w.db.write_pool())
    .await
    .unwrap();
    // Fixed-degree edges touching the anchor: two link4 endpoints plus one
    // provider aggregate whose subject closure must be staged.
    sqlx::query(
        "INSERT INTO kernel_link4_edges(edge_id,principal_id,operation_key,source_id,target_id,predicate,witness_json,created_seq) VALUES('e-anchor-out','p-anchor','k-anchor-out',?1,?2,'relates_to','{}',1),('e-anchor-in','p-anchor','k-anchor-in',?2,?1,'relates_to','{}',2)",
    )
    .bind(&anchor)
    .bind(&ep)
    .execute(w.db.write_pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO kernel_provider_subjects(subject_id,aggregate_id) VALUES(?1,'agg-anchor-1'),(?2,'agg-anchor-1')")
        .bind(&anchor)
        .bind(subj)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_provider_link_rows(aggregate_id,ordinal,id,source_id,target_id,note,created_at,created_at_ms,raw_json,if_absent) VALUES('agg-anchor-1',0,'prow-anchor-1',?1,?2,NULL,'2026-01-01T00:00:00Z',0,'{}',0)")
        .bind(&anchor)
        .bind(subj)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    async fn bulk(w: &World, link4: i64, provider_rows: i64, from: i64) {
        sqlx::query(&format!(
            "INSERT INTO kernel_link4_edges(edge_id,principal_id,operation_key,source_id,target_id,predicate,witness_json,created_seq) SELECT 'e-u-'||x,'p-u','k-u-'||x,'un-'||((x%7000)+1),'un-'||(((x+331)%7000)+1),'relates_to','{{}}',100+x FROM (WITH RECURSIVE n(x) AS (SELECT {from} UNION ALL SELECT x+1 FROM n WHERE x<{from}+{link4}-1) SELECT x FROM n)"
        ))
        .execute(w.db.write_pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO kernel_provider_link_rows(aggregate_id,ordinal,id,source_id,target_id,note,created_at,created_at_ms,raw_json,if_absent) SELECT 'uagg-'||(x/10),x%10,'urow-'||x,'un-'||((x%7000)+1),'un-'||(((x+577)%7000)+1),NULL,'2026-01-01T00:00:00Z',0,'{{}}',0 FROM (WITH RECURSIVE n(x) AS (SELECT {from} UNION ALL SELECT x+1 FROM n WHERE x<{from}+{provider_rows}-1) SELECT x FROM n)"
        ))
        .execute(w.db.write_pool())
        .await
        .unwrap();
    }
    // Fresh connection per measurement: pooled connections can reuse cached
    // statements and schema views, which would attribute a stale plan to the
    // live configuration. The index presence check below runs on this same
    // connection before anything is prepared on it.
    async fn plan_and_candidates(
        path: &std::path::Path,
        plan: &AnchorPlan,
        label: &str,
        expect_indexes: bool,
    ) -> (Vec<String>, BTreeSet<String>, std::time::Duration, u64) {
        use sqlx::Connection as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let url = path.to_str().unwrap();
        let mut conn = sqlx::SqliteConnection::connect(url).await.unwrap();
        for index in NEW_INDEXES {
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?)",
            )
            .bind(index)
            .fetch_one(&mut conn)
            .await
            .unwrap();
            assert_eq!(
                present, expect_indexes,
                "{label}: {index} presence mismatch on the measuring connection"
            );
        }
        let (sql, arg) = candidate_query(plan).unwrap();
        let explain: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(&format!("EXPLAIN QUERY PLAN {sql}"))
                .bind(&arg)
                .fetch_all(&mut conn)
                .await
                .unwrap();
        let details: Vec<String> = explain.into_iter().map(|row| row.3).collect();
        let vm_steps = std::sync::Arc::new(AtomicUsize::new(0));
        let counting = vm_steps.clone();
        conn.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || {
                counting.fetch_add(1, Ordering::Relaxed);
                true
            });
        let started = std::time::Instant::now();
        let candidates = direct_candidates_on(&mut conn, plan).await.unwrap();
        let elapsed = started.elapsed();
        conn.lock_handle().await.unwrap().remove_progress_handler();
        let vm_steps = vm_steps.load(Ordering::Relaxed) as u64;
        conn.close().await.unwrap();
        eprintln!("LINK_CANDIDATES {label}: {} candidates, {vm_steps} VM steps in {elapsed:?}\n{label} plan:\n{}", candidates.len(), details.join("\n"));
        (details, candidates, elapsed, vm_steps)
    }
    let db_path = w._dir.path().join("v2.db");
    let plan = AnchorPlan::Ids(vec![anchor.clone()]);
    bulk(&w, SMALL_LINK4, SMALL_PROVIDER_ROWS, 1).await;
    let (small_plan, small_sets, small_elapsed, small_vm) =
        plan_and_candidates(&db_path, &plan, "baseline-small", false).await;
    bulk(
        &w,
        LARGE_LINK4 - SMALL_LINK4,
        LARGE_PROVIDER_ROWS - SMALL_PROVIDER_ROWS,
        1 + SMALL_LINK4,
    )
    .await;
    let (large_plan, large_sets, large_elapsed, large_vm) =
        plan_and_candidates(&db_path, &plan, "baseline-large", false).await;
    assert_eq!(
        small_sets, large_sets,
        "candidate set must not grow with unrelated edges"
    );
    // Product preparation installs the endpoint indexes on this same engine.
    async fn db_bytes(w: &World) -> i64 {
        let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(w.db.write_pool())
            .await
            .unwrap();
        let size: i64 = sqlx::query_scalar("PRAGMA page_size")
            .fetch_one(w.db.write_pool())
            .await
            .unwrap();
        pages * size
    }
    let bytes_before = db_bytes(&w).await;
    let ensure_started = std::time::Instant::now();
    kernel::ensure_link_read_indexes(&w.db).await.unwrap();
    let ensure_elapsed = ensure_started.elapsed();
    let bytes_after = db_bytes(&w).await;
    eprintln!(
        "endpoint index build on 15k link4 edges + 15k provider rows: {ensure_elapsed:?}, storage {bytes_before} -> {bytes_after} bytes (delta {})",
        bytes_after - bytes_before
    );
    let (candidate_plan, candidate_sets, candidate_elapsed, candidate_vm) =
        plan_and_candidates(&db_path, &plan, "candidate-large", true).await;
    assert_eq!(
        large_sets, candidate_sets,
        "indexes must not change the candidate set"
    );
    for table in ["kernel_link4_edges", "kernel_provider_link_rows"] {
        assert!(
            candidate_plan
                .iter()
                .any(|line| line.contains("SEARCH") && line.contains(table)),
            "endpoint branch must seek {table}; candidate plan:\n{}\nbaseline plan:\n{}",
            candidate_plan.join("\n"),
            large_plan.join("\n")
        );
    }
    eprintln!(
        "LINK_CANDIDATES scaling: baseline-small {small_elapsed:?} ({small_vm} VM steps), baseline-large {large_elapsed:?} ({large_vm} VM steps), candidate-large {candidate_elapsed:?} ({candidate_vm} VM steps)"
    );
    assert!(
        candidate_vm < large_vm,
        "endpoint indexes must reduce executed VM work at scale: baseline-large {large_vm} vs candidate-large {candidate_vm}"
    );
    assert!(
        small_plan
            .iter()
            .any(|line| line.contains("kernel_link4_edges")),
        "baseline plan should mention link4 endpoints:\n{}",
        small_plan.join("\n")
    );
    for id in [&anchor, &ep, &subj.to_string(), &w.hidden] {
        assert!(
            candidate_sets.contains(id),
            "candidate set misses {id}: {candidate_sets:?}"
        );
    }
    assert!(
        candidate_sets.len() <= 8,
        "candidate set grew with unrelated edges: {candidate_sets:?}"
    );
    assert!(!candidate_sets.contains("un-7"), "unrelated row leaked");
    // Global duplicate-ID guard still forces the full-staging fallback and
    // must not be removed by the endpoint indexes.
    sqlx::query("INSERT INTO kernel_provider_link_rows(aggregate_id,ordinal,id,source_id,target_id,note,created_at,created_at_ms,raw_json,if_absent) VALUES('agg-dup-a',0,'dup-id','d-src-a','d-dst-a',NULL,'2026-01-01T00:00:00Z',0,'{}',0),('agg-dup-b',0,'dup-id','d-src-b','d-dst-b',NULL,'2026-01-01T00:00:00Z',0,'{}',0)")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    let fallback = direct_candidates_on(&mut conn, &plan).await.unwrap();
    drop(conn);
    assert!(
        fallback.is_empty(),
        "duplicate provider ids must fall back to full staging: {fallback:?}"
    );
    w.db.close().await;
}

/// Older files can still serve with the original plan. Explicit preparation
/// adds the accelerators without changing history or standby identity.
#[tokio::test]
async fn link_endpoint_indexes_are_optional_and_prepare_without_changing_identity() {
    let mut w = Box::pin(world()).await;
    for index in LINK_ENDPOINT_INDEXES {
        assert!(
            index_exists(&w.db, index).await,
            "fresh schema lacks {index}"
        );
    }
    let mut conn = w.db.pool().acquire().await.unwrap();
    let before = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let events = event_log(&w.db).await;
    for index in LINK_ENDPOINT_INDEXES {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let schema = schema_version(&w.db).await;
    kernel::verify_v2_ready(&w.db).await.unwrap();
    w.db.close().await;
    let path = w._dir.path().join("v2.db");
    w.db = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(schema_version(&w.db).await, schema);
    for index in LINK_ENDPOINT_INDEXES {
        assert!(!index_exists(&w.db, index).await);
    }
    assert_eq!(event_log(&w.db).await, events);
    // Same-name substitution must fail preparation and roll back all other
    // endpoint indexes created in that transaction.
    let conflicting = LINK_ENDPOINT_INDEXES[3];
    sqlx::query(&format!(
        "CREATE INDEX {conflicting} ON kernel_provider_link_rows(ordinal)"
    ))
    .execute(w.db.write_pool())
    .await
    .unwrap();
    let error = kernel::prepare_record_lookup_indexes(&w.db)
        .await
        .unwrap_err();
    assert!(error.to_string().contains(conflicting), "{error}");
    for index in &LINK_ENDPOINT_INDEXES[..3] {
        assert!(!index_exists(&w.db, index).await);
    }
    sqlx::query(&format!("DROP INDEX {conflicting}"))
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::prepare_record_lookup_indexes(&w.db).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    for index in LINK_ENDPOINT_INDEXES {
        assert!(index_exists(&w.db, index).await);
    }
    assert_eq!(event_log(&w.db).await, events);
    let mut conn = w.db.pool().acquire().await.unwrap();
    let after = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        before, after,
        "endpoint preparation cannot change generation identity"
    );
    w.db.close().await;
}

/// Fixture composition (programme 2fa4edd): the four optional endpoint
/// indexes, absent and then installed by the shipped preparation path, change
/// no read semantics under own-row narrowing, the visible-set cache, or the
/// staged relations the Slice B oracle digests. The prepared state is
/// asserted index-by-index so a no-op preparation cannot pass.
#[tokio::test]
async fn endpoint_index_preparation_composes_with_narrowing_and_visible_cache() {
    use super::sql::visible_cache as vcache;
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let kept = make_suggestion(&w, &v1, None, "keep", "none").await;
    let rejected = make_suggestion(&w, &v1, None, "drop", "none").await;
    call_as(
        &w,
        "acct:admin",
        "resolve_suggestions",
        json!({"action":"reject","suggestion_ids":[rejected],"reason":"composition fixture"}),
    )
    .await
    .unwrap();
    // Unrelated records outside every anchor, so narrowing has rows to skip
    // and "narrowing engaged" is a real assertion.
    let elsewhere = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let note = |title: &str| json!({"title": title}).as_object().unwrap().clone();
    for title in ["Unrelated a", "Unrelated b", "Unrelated c", "Unrelated d"] {
        kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            &note(title),
            &elsewhere,
        )
        .await
        .unwrap();
    }
    let queries = [
        json!({"steps":[{"step":"filter","ids":[w.first]},{"step":"traverse","target":"links","relationship":"part_of","direction":"in"},{"step":"filter","kinds":["suggestion"],"lifecycle":["rejected"],"include_archived":true}],"order":"created_desc","limit":20}),
        json!({"steps":[{"step":"filter","ids":[w.first]},{"step":"traverse","target":"links","direction":"both"},{"step":"filter","kinds":["suggestion"],"lifecycle":["open"]}],"order":"name_asc","limit":20}),
        json!({"steps":[{"step":"filter","ids":[w.first, w.second]},{"step":"traverse","target":"links"}],"order":"updated_desc","limit":50}),
        json!({"steps":[{"step":"filter","home_id":KERNEL_ROOT_ID,"updated_since":"2000-01-01T00:00:00Z"}],"order":"name_asc","limit":50}),
    ];
    let mut observed: Vec<Vec<Value>> = Vec::new();
    for prepared in [false, true] {
        if prepared {
            kernel::prepare_record_lookup_indexes(&w.db).await.unwrap();
        } else {
            for index in LINK_ENDPOINT_INDEXES {
                sqlx::query(&format!("DROP INDEX IF EXISTS {index}"))
                    .execute(w.db.write_pool())
                    .await
                    .unwrap();
            }
        }
        for index in LINK_ENDPOINT_INDEXES {
            assert_eq!(
                index_exists(&w.db, index).await,
                prepared,
                "{index} must be {} in this state",
                if prepared { "present" } else { "absent" }
            );
        }
        let mut outputs = Vec::new();
        for args in &queries {
            assert!(
                super::read_surface::recognize_args(args).is_some(),
                "{args}"
            );
            let (narrowed, full) = staged_narrowed_and_full(&w, "acct:admin", args).await;
            assert!(
                narrowed < full,
                "{args}: narrowing engaged ({narrowed} vs {full})"
            );
            for credential in ["acct:admin", "acct:viewer"] {
                assert_narrowed_identical(&w, credential, args).await;
                outputs.push(
                    call_as(&w, credential, "query_record", args.clone())
                        .await
                        .unwrap_or_else(|e| json!({"error": e.to_string()})),
                );
            }
        }
        // Full-staging query_record shapes (never narrowed, so the visible-set
        // cache applies): unanchored own-row filters. Cache-off baseline here.
        let full_queries = [
            json!({"steps":[{"step":"filter","kinds":["suggestion"],"lifecycle":["rejected"],"include_archived":true}],"order":"created_desc","limit":20}),
            json!({"steps":[{"step":"filter","types":["Document"],"updated_since":"2000-01-01T00:00:00Z"}],"order":"name_asc","limit":50}),
        ];
        let mut full_baseline = Vec::new();
        for args in &full_queries {
            assert!(
                super::read_surface::recognize_args(args).is_none(),
                "must stay on full staging: {args}"
            );
            for credential in ["acct:admin", "acct:viewer"] {
                full_baseline.push(
                    call_as(&w, credential, "query_record", args.clone())
                        .await
                        .unwrap_or_else(|e| json!({"error": e.to_string()})),
                );
            }
        }
        // Cache on vs off, compared per query and per principal: query_sql and
        // full-staging query_record go through the cache (miss, then hit);
        // narrowed query_record never does and must still match exactly.
        // Then the Slice B staged-relation digest with the cache on.
        let fresh_admin = fresh_as(&w, "acct:admin").await;
        let fresh_viewer = fresh_as(&w, "acct:viewer").await;
        vcache::enable_for_test(&w.db).await;
        for _ in 0..2 {
            assert_eq!(ids_as(&w, "acct:admin").await, fresh_admin);
            assert_eq!(ids_as(&w, "acct:viewer").await, fresh_viewer);
            let before = vcache::stats(&w.db);
            let mut i = 0;
            for args in &full_queries {
                for credential in ["acct:admin", "acct:viewer"] {
                    let cached = call_as(&w, credential, "query_record", args.clone())
                        .await
                        .unwrap_or_else(|e| json!({"error": e.to_string()}));
                    assert_eq!(cached, full_baseline[i], "cache-on {credential} {args}");
                    i += 1;
                }
            }
            let after = vcache::stats(&w.db);
            assert!(
                after.hits + after.misses + after.patches
                    > before.hits + before.misses + before.patches,
                "full-staging query_record went through the cache: {before:?} -> {after:?}"
            );
            let mut i = 0;
            for args in &queries {
                for credential in ["acct:admin", "acct:viewer"] {
                    let cached = call_as(&w, credential, "query_record", args.clone())
                        .await
                        .unwrap_or_else(|e| json!({"error": e.to_string()}));
                    assert_eq!(cached, outputs[i], "cache-on narrowed {credential} {args}");
                    i += 1;
                }
            }
        }
        assert!(vcache::stats(&w.db).hits >= 1);
        vcache::disable_for_test(&w.db);
        outputs.extend(full_baseline);
        outputs.push(fresh_admin);
        outputs.push(fresh_viewer);
        for actor in [&w.admin, &w.viewer] {
            outputs.push(super::sql::event_equivalence::compare_cached(&w.db, actor).await);
        }
        observed.push(outputs);
    }
    assert_eq!(
        observed[0], observed[1],
        "endpoint index preparation must not change any read result"
    );
    let _ = kept;
}
