//! Test-only before/after comparison; never normalizes identities or values.
use super::*;
use sha2::{Digest, Sha256};
use sqlx::{Executor, Statement, TypeInfo, ValueRef};

tokio::task_local! { static BASELINE: (); static SLICE_A: (); }
pub(super) fn slice_a_enabled() -> bool {
    SLICE_A.try_with(|_| ()).is_ok()
}
pub(crate) async fn slice_a_scope<F: std::future::Future>(work: F) -> F::Output {
    SLICE_A.scope((), work).await
}
pub(super) fn baseline_enabled() -> bool {
    BASELINE.try_with(|_| ()).is_ok()
}
pub(crate) async fn baseline_scope<F: std::future::Future>(work: F) -> F::Output {
    BASELINE.scope((), work).await
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Full,
    History,
    Scan,
}
async fn dump(db: &Db, actor: &str, mode: Mode) -> Value {
    let mut conn = db.governed_pool().acquire().await.unwrap();
    conn.close_on_drop();
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    let mut reads: BTreeSet<(String, String)> = ["records", "content_events", "actors", "viewer"]
        .into_iter()
        .flat_map(|relation| {
            columns(relation)
                .unwrap()
                .iter()
                .map(move |column| (relation.to_owned(), column.to_string()))
        })
        .collect();
    if matches!(mode, Mode::Scan) {
        reads.retain(|(r, _)| r != "content_events" && r != "actors");
    }
    let window = if matches!(mode, Mode::History) {
        let seq: i64 = sqlx::query_scalar(
            "SELECT seq FROM main.content_events WHERE id='slice-a:window-a:00'",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        Some(HistoryWindow {
            after: Some(seq - 1),
            newest: false,
            limit: 1,
        })
    } else {
        None
    };
    let projected = matches!(mode, Mode::Full)
        && !baseline_enabled()
        && !slice_a_enabled()
        && kernel::sql_event_projection::frontier_on(
            &mut conn,
            db.sql_event_projection_generation(),
        )
        .await
        .unwrap()
        .is_some();
    install_relations(
        &mut conn,
        actor,
        &reads,
        LinkScope::All,
        None,
        window,
        None,
        None,
        None,
        0,
        true,
        None,
        db.sql_event_projection_generation(),
        db.sql_record_projection_generation().as_deref(),
    )
    .await
    .unwrap();
    if matches!(mode, Mode::Full)
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE id='slice-a:claim-admin')",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap()
    {
        assert_edge_cases(&mut conn, actor).await;
    }
    if projected {
        let installed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master WHERE name='_v2_projection_sets')",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert!(
            installed,
            "valid frontier must exercise the projection path"
        );
    }
    let result = match mode {
        Mode::Full => hash_relations(&mut conn).await,
        Mode::History => {
            let first = hash_relations(&mut conn).await;
            let subjects_first: Vec<String> =
                sqlx::query_scalar("SELECT id FROM temp._v2_legacy_visible_subjects ORDER BY id")
                    .fetch_all(&mut *conn)
                    .await
                    .unwrap();
            let cursor: i64 = sqlx::query_scalar(
                "SELECT max(seq) FROM main.content_events WHERE id GLOB 'slice-a:window-a:*'",
            )
            .fetch_one(&mut *conn)
            .await
            .unwrap();
            sqlx::query("DROP TABLE temp._v2_history_candidates")
                .execute(&mut *conn)
                .await
                .unwrap();
            let root = kernel::kernel_effective_capability_on(
                &mut conn,
                actor,
                crate::events::KERNEL_ROOT_ID,
            )
            .await
            .unwrap()
            .allows(Capability::View);
            install_history_window(
                &mut conn,
                actor,
                root,
                HistoryWindow {
                    after: Some(cursor),
                    newest: false,
                    limit: 1,
                },
            )
            .await
            .unwrap();
            let subjects_second: Vec<String> =
                sqlx::query_scalar("SELECT id FROM temp._v2_legacy_visible_subjects ORDER BY id")
                    .fetch_all(&mut *conn)
                    .await
                    .unwrap();
            assert_ne!(
                subjects_first, subjects_second,
                "two windows must rebuild different visible subject sets"
            );
            assert!(subjects_second.iter().any(|s| s == "hq:00002"));
            json!({"first":first,"second":hash_relations(&mut conn).await,"subjects_first":subjects_first,"subjects_second":subjects_second})
        }
        Mode::Scan => {
            let ids = vec!["hq:00004".to_owned()];
            let mut rows = SNAPSHOT_VM_DEADLINE
                .scope(
                    Instant::now() + Duration::from_secs(30),
                    scan_attribution_on(&mut conn, actor, &ids, None),
                )
                .await
                .unwrap()
                .expect("fixture scan must complete");
            rows.sort();
            let binding: String = sqlx::query_scalar(
                "SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?",
            )
            .bind(actor)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
            let expected: i64 =
                sqlx::query_scalar("SELECT seq FROM main.content_events WHERE id=?")
                    .bind(format!("slice-a:scan:{binding}:false"))
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].2,
                Some(expected),
                "scan must seek past newest hidden header into the older authored window"
            );
            json!({"relations":hash_relations(&mut conn).await,"scan_rows":rows})
        }
    };
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    result
}

async fn hash_relations(conn: &mut sqlx::SqliteConnection) -> Value {
    // e586c99cf predates original settlement and treats its new private event
    // as an unknown record event. Keep the frozen reference bytes and the live
    // selector witness. Apply ONLY this reviewed post-reference policy to the
    // oracle; never derive an exception list from today's production selector.
    // Current staging gets no filtering: either private type leaking is a failure.
    if baseline_enabled() {
        sqlx::query("DELETE FROM temp._v2_event_rows WHERE type='kernel.mcp_write_fenced.v1'")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let internal: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.id,e.type FROM temp.content_events p JOIN main.content_events e ON e.id=p.id WHERE e.type IN ('kernel.mcp_write_fenced.v1','kernel.mcp_write_receipt_recorded.v1') ORDER BY p.id",
    ).fetch_all(&mut *conn).await.unwrap();
    assert!(
        internal.is_empty(),
        "private recovery events exposed in public SQL: {internal:?}"
    );
    // Include every public relation actually installed, not just the event
    // columns read by the profiling query. Internal _v2_* work tables are not
    // public relations and may legitimately differ between algorithms.
    let relations:Vec<String>=sqlx::query_scalar("SELECT name FROM temp.sqlite_master WHERE type IN ('table','view') AND name NOT GLOB '_v2_*' AND name NOT GLOB 'sqlite_*' ORDER BY name")
        .fetch_all(&mut *conn).await.unwrap();
    let mut result = serde_json::Map::new();
    for relation in relations {
        let query = format!("SELECT * FROM temp.\"{}\"", relation.replace('"', "\"\""));
        let statement = (&mut *conn).prepare(&query).await.unwrap();
        let names: Vec<_> = statement
            .columns()
            .iter()
            .map(|c| c.name().to_owned())
            .collect();
        let rows = sqlx::query(&query).fetch_all(&mut *conn).await.unwrap();
        let mut hashes = Vec::<[u8; 32]>::with_capacity(rows.len());
        for row in &rows {
            let mut values = Vec::new();
            for i in 0..row.len() {
                let raw = row.try_get_raw(i).unwrap();
                let value = if raw.is_null() {
                    json!(["null"])
                } else {
                    match raw.type_info().name() {
                        "INTEGER" => json!(["integer", row.get::<i64, _>(i)]),
                        "REAL" => json!(["real_bits", row.get::<f64, _>(i).to_bits()]),
                        "TEXT" => json!(["text", row.get::<String, _>(i)]),
                        "BLOB" => json!(["blob", row.get::<Vec<u8>, _>(i)]),
                        name => panic!("unhandled dynamic SQLite type {name}"),
                    }
                };
                values.push(value);
            }
            hashes.push(Sha256::digest(serde_json::to_vec(&values).unwrap()).into());
        }
        hashes.sort_unstable(); // Preserve duplicate row multiplicity.
        let mut digest = Sha256::new();
        digest.update(serde_json::to_vec(&names).unwrap());
        digest.update((hashes.len() as u64).to_le_bytes());
        for hash in hashes {
            digest.update(hash);
        }
        result.insert(
            relation,
            json!({"rows":rows.len(),"sha256":format!("{:x}",digest.finalize())}),
        );
    }
    Value::Object(result)
}

pub(crate) async fn compare(db: &Db, actor: &str) -> Value {
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(include_bytes!("event_staging_baseline.rs"))
        ),
        "63e0514e7a135b166bda763673fb9f53b696b4c34458078d4f31e4a6a542fb47",
        "frozen e586c99cf reference changed"
    );
    let before = baseline_scope(dump(db, actor, Mode::Full)).await;
    let after = dump(db, actor, Mode::Full).await;
    assert_eq!(
        before, after,
        "staged public relations differ from e586c99cf for {actor}"
    );
    for mode in [Mode::History, Mode::Scan] {
        let expected = baseline_scope(dump(db, actor, mode)).await;
        let actual = dump(db, actor, mode).await;
        assert_eq!(
            expected, actual,
            "{mode:?} staged relations differ for {actor}"
        );
    }
    before
}

// Assertions run against the frozen and optimized relations independently.
async fn assert_edge_cases(conn: &mut sqlx::SqliteConnection, actor: &str) {
    let binding: String =
        sqlx::query_scalar("SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    for (id, own_binding) in [
        ("slice-a:claim-admin", "acct:admin"),
        ("slice-a:claim-viewer", "acct:viewer"),
    ] {
        let row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT run_key,parent_key FROM temp.content_events WHERE id=?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(
            row,
            if binding == own_binding {
                (Some("slice-run".into()), Some("slice-parent".into()))
            } else {
                (None, None)
            },
            "claim disclosure: {id} for {binding}"
        );
    }
    for (id, expected) in [
        ("slice-a:provider-empty", 0),
        ("slice-a:generic-mismatch", 1),
        ("slice-a:comment-visible", 1),
        ("slice-a:comment-hidden", i64::from(binding == "acct:admin")),
    ] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp.content_events WHERE id=?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, expected, "admission: {id} for {binding}");
    }
    let restricted:Vec<(String,String)>=sqlx::query_as("SELECT m.source_id,h.owner FROM main.kernel_legacy_sql_events m JOIN main.kernel_legacy_history h ON h.seq=m.seq WHERE m.source_id GLOB 'slice-a:window-*'").fetch_all(&mut *conn).await.unwrap();
    assert_eq!(restricted.len(), 32);
    for (id, owner) in restricted {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp.content_events WHERE id=?")
            .bind(&id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            count,
            i64::from(binding == "acct:admin" || binding == owner),
            "restricted owner admission {id} for {binding}"
        );
    }
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT type FROM temp.content_events WHERE id='slice-a:reaction-mixed'",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        vec!["message.reaction.added.v1"],
        "mixed add/remove stays one added event"
    );
}

/// Slice B's permanent oracle is today's Slice A staging, independently
/// checked against the frozen pre-A path by `compare` above.
pub(crate) async fn compare_projection(db: &Db, actor: &str) -> Value {
    let expected = slice_a_scope(dump(db, actor, Mode::Full)).await;
    let actual = dump(db, actor, Mode::Full).await;
    assert_eq!(
        expected, actual,
        "projection/tail differs from Slice A for {actor}"
    );
    actual
}

/// Visible-set cache equivalence (Native b171a9d, after #3234): the full
/// staged-relation digest with the cache on (a miss that publishes, then a
/// hit) equals the uncached digest for this caller.
pub(crate) async fn compare_cached(db: &Db, actor: &str) -> Value {
    let expected = dump(db, actor, Mode::Full).await;
    super::visible_cache::enable_for_test(db).await;
    let miss = super::visible_cache::scoped(db, dump(db, actor, Mode::Full)).await;
    let hit = super::visible_cache::scoped(db, dump(db, actor, Mode::Full)).await;
    assert_eq!(
        expected, miss,
        "cache-on (miss) staged relations differ for {actor}"
    );
    assert_eq!(
        expected, hit,
        "cache-on (hit) staged relations differ for {actor}"
    );
    let stats = super::visible_cache::stats(db);
    super::visible_cache::disable_for_test(db);
    assert!(stats.hits >= 1, "the cached path was exercised: {stats:?}");
    hit
}
