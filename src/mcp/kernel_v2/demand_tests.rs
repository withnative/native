//! Demand-scoped point reads (design 73ad275 S1): spike A2's adversarial
//! query/role suite against today's full staging, with hidden malformed
//! values, and a live policy change between reads.
use super::*;

const ADVERSARIAL: &[&str] = &[
    "SELECT id,name,summary,updated_at_ms FROM records WHERE id=?1 ORDER BY id",
    "SELECT a.id,b.name FROM records a JOIN records b ON b.id=?2 WHERE a.id=?1 ORDER BY a.id,b.id",
    "SELECT a.id,b.name FROM records a LEFT JOIN records b ON b.id=?2 WHERE a.id=?1 ORDER BY a.id,b.id",
    "SELECT a.id,b.name FROM records a JOIN records b ON b.id=a.id WHERE a.id=?1 ORDER BY a.id,b.id",
    "SELECT a.id,b.name FROM records a JOIN records b ON b.id=a.home_id WHERE a.id=?1 ORDER BY a.id",
    "SELECT a.id,b.id AS h FROM records a LEFT JOIN records b ON b.id=a.home_id LEFT JOIN records c ON c.id=a.home_id WHERE a.id=?1",
    "SELECT a.id,b.id AS h FROM records a LEFT JOIN records b ON a.home_id=b.id WHERE a.id=?1 OR b.name='Beta'",
    "SELECT id FROM records WHERE id NOT IN (?1) ORDER BY id",
    "SELECT id FROM records WHERE id=?1 OR name='Beta' ORDER BY id",
    "SELECT count(*) AS n FROM records WHERE id=?1",
    "SELECT type,count(*) AS n FROM records GROUP BY type ORDER BY type",
    "SELECT id,name FROM records ORDER BY name DESC,id LIMIT 1",
    "SELECT id,home_id,is_current,successor_count FROM records WHERE id=?1 ORDER BY id",
    "SELECT id FROM records WHERE json_extract(body,'$.x')=1 ORDER BY id",
    "SELECT id FROM records WHERE json_extract(summary,'$.x')=1 ORDER BY id",
    "SELECT id FROM records WHERE id=?1 AND json_extract(body,'$.x')=1 ORDER BY id",
    "SELECT json_extract(body,'$.x') AS x FROM records ORDER BY id",
    "SELECT id,(SELECT count(*) FROM records) AS n FROM records WHERE id=?1 ORDER BY id",
    "SELECT missing_column FROM records WHERE id=?1 ORDER BY id",
    "SELECT id FROM records WHERE id=?1 UNION ALL SELECT id FROM records ORDER BY id",
    "SELECT r.id,(SELECT f.value FROM facet_values f WHERE f.record_id=r.id AND f.key='runtime') AS runtime FROM records r WHERE r.id=?1",
];

async fn compare(
    w: &World,
    actor: &str,
    statement: &str,
) -> (std::result::Result<Value, String>, sql::Stats) {
    let values = if statement.contains("?2") {
        vec![&w.first, &w.second]
    } else if statement.contains("?1") {
        vec![&w.first]
    } else {
        vec![]
    };
    let args = json!({"sql":statement,"parameters":values.into_iter().map(|v|json!({"type":"text","value":v})).collect::<Vec<_>>()});
    let (actual, stats) = sql::measured(sql::query_sql(&w.db, actor, args.clone())).await;
    let actual = actual.map_err(|e| e.to_string());
    let expected = sql::with_full_read_oracle(Box::pin(sql::query_sql(&w.db, actor, args)))
        .await
        .map_err(|e| e.to_string());
    assert_eq!(actual, expected, "{actor}: {statement}");
    (actual, stats)
}

#[tokio::test]
async fn demand_scoped_adversarial_queries_match_full_staging() {
    let w = world().await;
    let restricted = kernel::create_principal(
        &w.db,
        "account",
        "Restricted",
        "acct:demand-restricted",
        &w.admin,
    )
    .await
    .unwrap();
    for (id, body) in [
        (&w.first, "{\"x\":1}"),
        (&w.second, "{\"x\":2}"),
        (&w.hidden, "not JSON"),
    ] {
        kernel::revise_as(
            &w.db,
            &w.admin,
            id,
            json!({"body":body}).as_object().unwrap(),
        )
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'summary','malformed',created_seq FROM kernel_records WHERE id=?").bind(&w.hidden).execute(w.db.write_pool()).await.unwrap();
    kernel::sql_record_projection::catch_up(&w.db)
        .await
        .unwrap();
    let mut served = 0;
    for actor in [&w.viewer, &w.admin, &restricted] {
        for statement in ADVERSARIAL {
            let (_, stats) = compare(&w, actor, statement).await;
            served += usize::from(stats.demand.is_some());
        }
    }
    assert!(
        served >= 12,
        "the finite statements must take the demand path: {served}"
    );
    // A hidden invalid JSON body never reaches the member's expression; the
    // same SQL errors for the admin, who can see it.
    let args = json!({"sql":"SELECT id FROM records WHERE json_extract(body,'$.x')=1 AND id IN (?1,?2) ORDER BY id","parameters":[{"type":"text","value":w.first},{"type":"text","value":w.hidden}]});
    let (member, stats) = sql::measured(sql::demand::with_enabled_for_test(Box::pin(
        sql::query_sql(&w.db, &w.viewer, args.clone()),
    )))
    .await;
    assert_eq!(stats.demand, Some("exact_body"));
    assert_eq!(member.unwrap()["row_count"], 1);
    assert!(
        sql::demand::with_enabled_for_test(Box::pin(sql::query_sql(&w.db, &w.admin, args)))
            .await
            .is_err()
    );
    // No stored state: a policy write between reads takes effect at once.
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let (before, _) = compare(
        &w,
        &w.viewer,
        "SELECT id,home_id FROM records WHERE id=?1 ORDER BY id",
    )
    .await;
    assert_eq!(before.unwrap()["row_count"], 1);
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    let (after, stats) = compare(
        &w,
        &w.viewer,
        "SELECT id,home_id FROM records WHERE id=?1 ORDER BY id",
    )
    .await;
    assert_eq!(stats.demand, Some("docs_page"));
    assert_eq!(after.unwrap()["row_count"], 0);
    w.db.close().await;
}

/// The installed-app route stages through a bound read session; the shipped
/// Docs needs take the same demand path there and equal full staging.
#[tokio::test]
async fn demand_scoped_bound_session_docs_needs_match_full_staging() {
    let w = world().await;
    let declaration: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("web/apps/src/apps/docs/declaration.json"),
        )
        .unwrap(),
    )
    .unwrap();
    for key in ["docs.body", "docs.page"] {
        let need = declaration["needs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["key"] == key)
            .unwrap();
        for (actor, id) in [
            (&w.viewer, &w.first),
            (&w.viewer, &w.hidden),
            (&w.admin, &w.hidden),
        ] {
            let batch = vec![json!({"sql":need["sql"],"parameters":[{"type":"text","value":id}]})];
            let run = || {
                sql::with_bound_query_read_session(&w.db, actor, &batch, async {
                    sql::query_sql(&w.db, actor, batch[0].clone()).await
                })
            };
            let (actual, stats) =
                sql::measured(sql::demand::with_enabled_for_test(Box::pin(run()))).await;
            assert!(stats.demand.is_some(), "{key}: demand path");
            let expected = sql::with_full_read_oracle(Box::pin(run())).await;
            assert_eq!(
                actual.map_err(|e| e.to_string()),
                expected.map_err(|e| e.to_string()),
                "{key} {actor} {id}"
            );
        }
    }
    w.db.close().await;
}

/// Exercise release defaults without the S1a opt-in. Independently disabling
/// either shape must route just that shape to the old staging path.
#[tokio::test]
async fn demand_serving_defaults_and_manual_shape_settings() {
    let w = world().await;
    assert_eq!(
        sql::demand::settings_plan(None, None),
        sql::demand::Plan {
            exact_body: true,
            docs_page: true,
            home_chain: false,
        }
    );
    assert!(!sql::demand::settings_plan(Some("invalid"), None).exact_body);
    for (statement, shape) in [
        ("SELECT id,body FROM records WHERE id=?1", "exact_body"),
        ("SELECT id,home_id FROM records WHERE id=?1", "docs_page"),
    ] {
        let args = json!({"sql":statement,"parameters":[{"type":"text","value":w.first}]});
        let expected = sql::with_full_read_oracle(sql::query_sql(&w.db, &w.viewer, args.clone()))
            .await
            .unwrap();
        let (served, stats) = sql::measured(sql::query_sql(&w.db, &w.viewer, args.clone())).await;
        assert_eq!(served.unwrap(), expected);
        assert_eq!(stats.demand, Some(shape));
        assert!(stats.demand_rechecked > 0);
        assert_eq!(stats.demand_fallbacks, 0);
        for (exact, page) in [(Some("0"), None), (None, Some("off"))] {
            let plan = sql::demand::settings_plan(exact, page);
            let enabled = if shape == "exact_body" {
                plan.exact_body
            } else {
                plan.docs_page
            };
            let (answer, stats) = sql::measured(sql::demand::with_plan_for_test(
                plan,
                sql::query_sql(&w.db, &w.viewer, args.clone()),
            ))
            .await;
            assert_eq!(answer.unwrap(), expected);
            assert_eq!(stats.demand, enabled.then_some(shape));
            assert_eq!(stats.demand_rechecked > 0, enabled);
        }
    }
    w.db.close().await;
}

/// Mutate the fast admission to accept a hidden row. The separate point gate
/// must reject it and the caller must receive the entire old-path answer.
/// Cover standalone queries and the installed-app bound-session route.
#[tokio::test]
async fn demand_serving_recheck_stops_mutated_admission_and_falls_back() {
    let w = world().await;
    for statement in [
        "SELECT id,body FROM records WHERE id IN (?1,?2) ORDER BY id",
        "SELECT id,home_id FROM records WHERE id IN (?1,?2) ORDER BY id",
    ] {
        let args = json!({"sql":statement,"parameters":[{"type":"text","value":w.first},{"type":"text","value":w.hidden}]});
        let expected = sql::with_full_read_oracle(sql::query_sql(&w.db, &w.viewer, args.clone()))
            .await
            .unwrap();
        assert_eq!(expected["row_count"], 1);
        for bound in [false, true] {
            let batch = vec![args.clone()];
            let run = async {
                if bound {
                    sql::with_bound_query_read_session(
                        &w.db,
                        &w.viewer,
                        &batch,
                        sql::query_sql(&w.db, &w.viewer, args.clone()),
                    )
                    .await
                } else {
                    sql::query_sql(&w.db, &w.viewer, args.clone()).await
                }
            };
            let (answer, stats) = sql::measured(sql::demand::with_broken_admission(run)).await;
            assert_eq!(answer.unwrap(), expected, "bound={bound}: {statement}");
            assert_eq!(
                stats.demand_recheck_rejections, 1,
                "the point gate must catch the mutation"
            );
            assert_eq!(stats.demand_fallbacks, 1, "the old path must answer");
        }
    }
    w.db.close().await;
}

/// A fast-path caller error must not replace an answer the old path can
/// produce. In a bound read, restaging retains the exact main snapshot even
/// if canonical content changes after its initial staging.
#[tokio::test]
async fn demand_serving_caller_error_retries_old_path() {
    let w = world().await;
    for statement in [
        "SELECT id,body FROM records WHERE id=?1",
        "SELECT id,home_id FROM records WHERE id=?1",
    ] {
        let args = json!({"sql":statement,"parameters":[{"type":"text","value":w.first}]});
        let expected = sql::with_full_read_oracle(sql::query_sql(&w.db, &w.viewer, args.clone()))
            .await
            .unwrap();
        for bound in [false, true] {
            let batch = vec![args.clone()];
            let run = async {
                if bound {
                    sql::with_bound_query_read_session(&w.db, &w.viewer, &batch, async {
                        // The read has already pinned its main snapshot.
                        kernel::revise_as(
                            &w.db,
                            &w.admin,
                            &w.first,
                            json!({"body":"updated after pin"}).as_object().unwrap(),
                        )
                        .await
                        .unwrap();
                        sql::query_sql(&w.db, &w.viewer, args.clone()).await
                    })
                    .await
                } else {
                    sql::query_sql(&w.db, &w.viewer, args.clone()).await
                }
            };
            let (answer, stats) = sql::measured(sql::demand::with_failed_caller(run)).await;
            assert_eq!(answer.unwrap(), expected, "bound={bound}: {statement}");
            assert_eq!(stats.demand_fallbacks, 1);
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn demand_serving_caller_resource_errors_are_not_retried() {
    let w = world().await;
    // A finite page of plain records guarantees a real caller progress tick
    // even after bound-session materialisation, without a complex expression.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<128) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('caller-limit:%03d',x),r.home_id,r.owner_id,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    let ids = (1..=128)
        .map(|i| format!("caller-limit:{i:03}"))
        .collect::<Vec<_>>();
    let placeholders = (1..=128)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    for bound in [false, true] {
        // The cell ceiling is hit by the actual caller SQL, after staging.
        let large = json!({"sql":"SELECT id,replace(printf('%0260000d',1),'0',char(1)) AS big FROM records WHERE id=?1", "parameters":[{"type":"text","value":w.first}]});
        let timed = json!({"sql":format!("SELECT id,body FROM records WHERE id IN ({placeholders}) ORDER BY id"), "parameters":ids.iter().map(|id| json!({"type":"text","value":id})).collect::<Vec<_>>()});
        for (args, elapsed, class) in [
            (large, std::time::Duration::ZERO, "result_too_large"),
            (timed, std::time::Duration::from_secs(120), "timeout"),
        ] {
            let batch = vec![args.clone()];
            let query = sql::with_elapsed(
                std::time::Duration::ZERO,
                elapsed,
                sql::query_sql(&w.db, &w.viewer, args),
            );
            let (result, stats) = if bound {
                sql::measured(sql::with_bound_query_read_session(
                    &w.db, &w.viewer, &batch, query,
                ))
                .await
            } else {
                sql::measured(query).await
            };
            let error = match result {
                Err(error) => error.to_string(),
                Ok(_) => panic!("expected caller {class}, bound={bound}"),
            };
            assert_eq!(
                stats.demand,
                Some("exact_body"),
                "bound={bound}, class={class}, caller_executions={}, error={error}",
                stats.caller_executions
            );
            assert!(
                error.starts_with(&format!("query_sql [{class}]")),
                "{error}"
            );
            assert_eq!(
                stats.demand_fallbacks, 0,
                "caller limits must not execute SQL twice: bound={bound}"
            );
            assert_eq!(stats.caller_executions, 1);
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn demand_serving_bound_retry_preserves_lazy_body_and_candidates() {
    let w = world().await;
    kernel::revise_as(
        &w.db,
        &w.admin,
        &w.second,
        json!({"body":"x".repeat(crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize + 4096)})
            .as_object()
            .unwrap(),
    )
    .await
    .unwrap();
    let args = json!({"sql":"SELECT id,body FROM records WHERE id=?1", "parameters":[{"type":"text","value":w.first}]});
    let expected = sql::query_sql(&w.db, &w.viewer, args.clone())
        .await
        .unwrap();
    let batch = vec![args.clone()];
    let (actual, stats) = sql::measured(sql::demand::with_failed_caller(
        sql::with_bound_query_read_session(&w.db, &w.viewer, &batch, async {
            let answer = sql::query_sql(&w.db, &w.viewer, args).await?;
            sql::in_snapshot(&w.db, &w.viewer, |conn| {
                Box::pin(async move {
                    let view: String = sqlx::query_scalar(
                        "SELECT sql FROM sqlite_temp_master WHERE name='records'",
                    )
                    .fetch_one(&mut *conn)
                    .await?;
                    assert!(view.contains("_v2_composed_records"));
                    assert!(
                        view.contains("_v2_record_oracle"),
                        "body remains lazy after retry"
                    );
                    Ok(())
                })
            })
            .await?;
            Ok(answer)
        }),
    ))
    .await;
    assert_eq!(actual.unwrap(), expected);
    assert_eq!(stats.demand_fallbacks, 1);
    assert_eq!(stats.staged_records, 1);
    w.db.close().await;
}

#[tokio::test]
async fn demand_serving_failed_restage_cannot_serve_partial_session() {
    let w = world().await;
    let args = json!({"sql":"SELECT id,body FROM records WHERE id=?1", "parameters":[{"type":"text","value":w.first}]});
    let batch = vec![args.clone()];
    let (result, stats) = sql::measured(sql::demand::with_failed_caller(
        sql::demand::with_failed_restage(sql::with_bound_query_read_session(
            &w.db,
            &w.viewer,
            &batch,
            async {
                // The injected restage empties visibility and then hits an actual
                // SQLite SELECT interrupt. A later query must never return [].
                let first = sql::query_sql(&w.db, &w.viewer, args.clone())
                    .await
                    .unwrap_err()
                    .to_string();
                assert!(first.starts_with("query_sql [timeout]"), "{first}");
                let later = sql::query_sql(&w.db, &w.viewer, args)
                    .await
                    .unwrap_err()
                    .to_string();
                assert_eq!(later, first, "the original restage refusal is sticky");
                let hydrated = sql::in_snapshot(&w.db, &w.viewer, |_conn| {
                    Box::pin(async {
                        Err::<(), Error>(Error::engine(
                            "snapshot enrichment ran over partial staging",
                        ))
                    })
                })
                .await
                .unwrap_err()
                .to_string();
                assert_eq!(hydrated, first);
                Ok(())
            },
        )),
    ))
    .await;
    result.unwrap();
    assert_eq!(stats.demand_fallbacks, 1);
    assert_eq!(stats.caller_executions, 1, "no later caller SQL may run");
    w.db.close().await;
}
