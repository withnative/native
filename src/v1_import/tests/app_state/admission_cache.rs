use super::*;
use crate::mcp::{app_attribution::AppAttribution, Caller, EngineHandle, ToolRegistry};

fn app_caller() -> Caller {
    Caller::authenticated("account-b")
        .with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", "install-b").unwrap())
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    registry
}

async fn create_document(db: &Db, actor: &str, home: &str) -> String {
    k::create_package_record_as(
        db,
        actor,
        home,
        "Document",
        "note",
        &uuid::Uuid::new_v4().to_string(),
        crate::v2_standard::DOCUMENT_FAMILY,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn native_app_query_record_source_admission_is_bounded_per_snapshot() {
    let f = Fixture::new().await;
    // A substantial frozen bundle exposes repeated source work without needing
    // wall-clock thresholds. Keep the artifact below its 512 KiB body limit.
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Docs reader</title></head><body><main>{}</main></body></html>",
        "Retained document reader interface and bundled help text. ".repeat(7400)
    );
    assert!(body.len() > 390 * 1024 && body.len() < 512 * 1024);
    // Bundle size should exercise source loading, without exhausting the
    // separate static-DOM limit before the app-attributed read can begin.
    crate::artifact_html::validate(&body).expect("large app fixture must be admissible HTML");
    let (db, report) = native_install_fixture_with_body(&f, &body).await;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let source = k::read_record_as(&db, a, "secret").await.unwrap().unwrap();
    k::replace_home_policy(&db, a, &source.home_id, &[(b, "view")])
        .await
        .unwrap();
    let hidden_home = k::create_home(&db, &source.home_id, Some(&[]), a)
        .await
        .unwrap();
    let hidden = create_document(&db, a, &hidden_home).await;
    let mut ids = Vec::new();
    for _ in 0..500 {
        ids.push(create_document(&db, a, &source.home_id).await);
    }
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let registry = registry();
    let small_args = json!({"steps":[{"step":"filter","types":["Document"],"ids":[ids[0], ids[1], hidden]}],"order":"updated_desc","limit":500});
    // Recent lists by type rather than expanding hundreds of IDs into SQL
    // parameters. Imported Documents may also contribute to the total.
    let large_args = json!({"steps":[{"step":"filter","types":["Document"]}],"order":"updated_desc","limit":500});
    let (small, small_count) = k::app_installs::with_source_admission_count(registry.call_engine(
        EngineHandle::KernelV2(db.clone()),
        app_caller(),
        "query_record",
        small_args,
    ))
    .await;
    let small = small.unwrap();
    assert_eq!(small["total"], 2);
    assert_eq!(small["records"].as_array().unwrap().len(), 2);
    let (large, large_count) = k::app_installs::with_source_admission_count(registry.call_engine(
        EngineHandle::KernelV2(db.clone()),
        app_caller(),
        "query_record",
        large_args.clone(),
    ))
    .await;
    let large = large.unwrap();
    assert!(large["total"].as_u64().unwrap() >= 500);
    let records = large["records"].as_array().unwrap();
    assert_eq!(records.len(), 500);
    assert!(!records.iter().any(|row| row["id"] == hidden));
    for id in &ids {
        assert!(records.iter().any(|row| row["id"] == *id));
    }
    assert!(
        small_count > 0,
        "the counter must observe real source admission"
    );
    assert!(
        large_count <= small_count + 2 && large_count < 20,
        "source admission must stay bounded as hydration grows: small={small_count}, large={large_count}"
    );
    let direct = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "query_record",
            large_args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(large["total"], direct["total"]);
    assert_eq!(large["records"], direct["records"]);

    // Browser get_record reenters in_snapshot once per record while owning
    // one SQL session. Its admissions must survive those callback boundaries.
    let mut batch_counts = Vec::new();
    for size in [2, 30] {
        let (batch, count) = k::app_installs::with_source_admission_count(registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            app_caller(),
            "get_record",
            json!({"ids": &ids[..size], "include_comments": false}),
        ))
        .await;
        assert_eq!(batch.unwrap()["records"].as_array().unwrap().len(), size);
        batch_counts.push(count);
    }
    assert!(
        batch_counts[0] > 0 && batch_counts[1] <= batch_counts[0] + 2 && batch_counts[1] < 20,
        "composed batch admissions: {batch_counts:?}"
    );

    // These small-read MCP operations are outside the installed-app read
    // allowlist. Keep the refusal explicit instead of widening app authority
    // to make a performance probe reach the handler.
    for (tool, arguments) in [
        ("render_record", json!({"id":ids[0]})),
        ("resolve_many", json!({"names":["Admission document"]})),
        (
            "resolve_many",
            json!({"names":vec!["Admission document";100]}),
        ),
    ] {
        let error = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                app_caller(),
                tool,
                arguments,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("app_operation_unsupported_on_v2"),
            "{tool}: {error}"
        );
    }

    eprintln!("full app-source admissions: query_record(2)={small_count}, query_record(500)={large_count}, get_record(2,30)={batch_counts:?}");

    // Keep the outer request cache alive across two actual read snapshots.
    // A successful app read must not authorize a later snapshot after removal.
    k::read_cache::scope_request(async {
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                app_caller(),
                "query_record",
                large_args.clone(),
            )
            .await
            .unwrap();
        k::app_installs::remove_as(&db, b, "agent.docs", "install-b")
            .await
            .unwrap();
        assert!(registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                app_caller(),
                "query_record",
                large_args,
            )
            .await
            .is_err());
    })
    .await;
    db.close().await;
}

fn dispatch_for(caller: &Caller) -> crate::provenance::ProvenanceDispatch {
    crate::provenance::ProvenanceDispatch::from_caller(
        caller,
        "query_record",
        &json!({"steps":[],"limit":1}),
        None,
    )
}

#[tokio::test]
async fn native_app_source_admission_cache_is_bound_to_exact_pinned_scope_and_claim() {
    use std::sync::Arc;

    let f = Fixture::new().await;
    let (db, report) = native_install_fixture_with_body(&f, OPERATOR_APP_BODY).await;
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let source = k::read_record_as(&db, a, "secret").await.unwrap().unwrap();
    k::replace_home_policy(&db, a, &source.home_id, &[(b, "view")])
        .await
        .unwrap();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let dispatch = dispatch_for(&app_caller());
    dispatch
        .scope(k::read_cache::scope_request(async {
            let mut tx = db.write_pool().begin().await.unwrap();
            let key = k::read_cache::key_on(&mut tx, b, "admission-isolation")
                .await
                .unwrap();
            assert!(key.is_some());
            let connection = k::read_cache::connection_id(&mut tx);
            let parent = k::read_cache::in_pinned_snapshot(key.clone(), connection, async {
                let (parent, count) = k::app_installs::with_source_admission_count(async {
                    let first = k::app_installs::admit_dispatched_on(&mut tx, b)
                        .await
                        .unwrap()
                        .unwrap();
                    let second = k::app_installs::admit_dispatched_on(&mut tx, b)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(Arc::ptr_eq(&first, &second));
                    first
                })
                .await;
                assert_eq!(count, 1, "identical claims reuse one source admission");

                // Every part of the caller/claim binding must be checked before
                // a successful admission can be reused.
                for (account, package, version, generation) in [
                    ("account-a", "agent.docs", "0.8.2", "install-b"),
                    ("account-b", "other.app", "0.8.2", "install-b"),
                    ("account-b", "agent.docs", "wrong-version", "install-b"),
                    ("account-b", "agent.docs", "0.8.2", "wrong-generation"),
                ] {
                    let caller = Caller::authenticated(account).with_host_asserted_app(
                        AppAttribution::new(package, version, generation).unwrap(),
                    );
                    assert!(dispatch_for(&caller)
                        .scope(k::app_installs::admit_dispatched_on(&mut tx, b))
                        .await
                        .is_err());
                }
                assert!(k::app_installs::admit_dispatched_on(&mut tx, a)
                    .await
                    .is_err());
                let mut other = db.write_pool().acquire().await.unwrap();
                let error = k::app_installs::admit_dispatched_on(&mut other, b)
                    .await
                    .err()
                    .expect("a pinned scope must refuse another physical connection");
                assert!(error.to_string().contains("connection mismatch"));
                drop(other);

                // A nested scope on the same snapshot has its own admission
                // map, then restores its parent's exact successful result.
                let nested = k::read_cache::in_pinned_snapshot(
                    key.clone(),
                    connection,
                    k::app_installs::admit_dispatched_on(&mut tx, b),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(!Arc::ptr_eq(&parent, &nested));
                let restored = k::app_installs::admit_dispatched_on(&mut tx, b)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(Arc::ptr_eq(&parent, &restored));

                // Drive a nested scope through admission, then cancel while
                // it is pending. Dropping its future must restore the parent.
                let admitted_before_cancel = std::sync::atomic::AtomicBool::new(false);
                let mut cancelled = Box::pin(k::read_cache::in_pinned_snapshot(
                    key.clone(),
                    connection,
                    async {
                        let nested = k::app_installs::admit_dispatched_on(&mut tx, b)
                            .await
                            .unwrap()
                            .unwrap();
                        assert!(!Arc::ptr_eq(&parent, &nested));
                        admitted_before_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                        std::future::pending::<()>().await;
                    },
                ));
                std::future::poll_fn(|cx| {
                    use std::future::Future;
                    assert!(cancelled.as_mut().poll(cx).is_pending());
                    if admitted_before_cancel.load(std::sync::atomic::Ordering::Relaxed) {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                drop(cancelled);
                let restored = k::app_installs::admit_dispatched_on(&mut tx, b)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(Arc::ptr_eq(&parent, &restored));
                parent
            })
            .await;
            tx.rollback().await.unwrap();

            let mut next = db.write_pool().begin().await.unwrap();
            let next_key = k::read_cache::key_on(&mut next, b, "admission-isolation")
                .await
                .unwrap();
            assert!(key == next_key, "no content or metadata heads changed");
            let (fresh, count) =
                k::app_installs::with_source_admission_count(k::read_cache::in_pinned_snapshot(
                    next_key,
                    k::read_cache::connection_id(&mut next),
                    k::app_installs::admit_dispatched_on(&mut next, b),
                ))
                .await;
            let fresh = fresh.unwrap().unwrap();
            assert_eq!(count, 1, "a separate snapshot must admit source again");
            assert!(!Arc::ptr_eq(&parent, &fresh));

            let (_, count) = k::app_installs::with_source_admission_count(async {
                let first = k::app_installs::admit_dispatched_on(&mut next, b)
                    .await
                    .unwrap()
                    .unwrap();
                let second = k::app_installs::admit_dispatched_on(&mut next, b)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(!Arc::ptr_eq(&first, &second));
            })
            .await;
            assert_eq!(count, 2, "unpinned admission always checks live authority");
            next.rollback().await.unwrap();
        }))
        .await;
    db.close().await;
}

async fn changes_app_fixture(f: &Fixture) -> (Db, String) {
    let (db, report) = native_install_fixture_with_body(f, OPERATOR_APP_BODY).await;
    let a = &report.principals["account-a"];
    let b = report.principals["account-b"].clone();
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let source = k::read_record_as(&db, a, "secret").await.unwrap().unwrap();
    k::replace_home_policy(&db, a, &source.home_id, &[(&b, "view")])
        .await
        .unwrap();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    (db, b)
}

#[tokio::test]
async fn native_app_changes_empty_poll_rechecks_consent_before_registry_return() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let f = Fixture::new().await;
    let (db, b) = changes_app_fixture(&f).await;
    let registry = registry();
    let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let args = json!({"after_local_seq":head,"through_local_seq":head});
    let ordinary = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "whats_changed",
            args.clone(),
        )
        .await
        .unwrap();
    let valid = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            app_caller(),
            "whats_changed",
            args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        valid, ordinary,
        "valid app and ordinary empty polls disclose the same cursor"
    );
    assert_eq!(valid["changes"], json!([]));

    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let read = crate::mcp::kernel_v2::with_read_return_barrier(
        entered.clone(),
        resume.clone(),
        registry.call_engine(
            EngineHandle::KernelV2(db.clone()),
            app_caller(),
            "whats_changed",
            args.clone(),
        ),
    );
    let revoke = async {
        entered.notified().await;
        k::app_installs::remove_as(&db, &b, "agent.docs", "install-b")
            .await
            .unwrap();
        resume.notify_one();
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(read, revoke)
    })
    .await
    .expect("registered read reached the barrier");
    assert!(
        result.is_err(),
        "a cursor from a now-revoked app must not leave the registry: {result:?}"
    );
    // The outer dispatch preflight already refuses claims revoked before a call.
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            app_caller(),
            "whats_changed",
            args.clone()
        )
        .await
        .is_err());
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "whats_changed",
            args
        )
        .await
        .is_ok());
    db.close().await;
}

#[tokio::test]
async fn native_app_changes_message_snapshot_admits_even_when_sequence_is_absent() {
    let f = Fixture::new().await;
    let (db, b) = changes_app_fixture(&f).await;
    let dispatch = dispatch_for(&app_caller());
    let read = || async {
        let mut tx = db.pool().begin().await.unwrap();
        let result = k::messaging::change_on(&mut tx, &b, 0).await;
        tx.rollback().await.unwrap();
        result
    };
    assert!(dispatch.scope(read()).await.unwrap().is_none());
    k::app_installs::remove_as(&db, &b, "agent.docs", "install-b")
        .await
        .unwrap();
    // This deliberately bypasses registry preflight to exercise the canonical
    // snapshot boundary under real app provenance after consent has changed.
    assert!(dispatch.scope(read()).await.is_err());
    assert!(
        read().await.unwrap().is_none(),
        "ordinary callers remain unchanged"
    );
    db.close().await;
}

/// whats_changed pins its one snapshot: app admission for messaging changes is
/// reused only within that actual connection, never across snapshots, and a
/// read on any other connection inside the scope fails closed. Also reports
/// (does not assert) the per-event admission cost the pin removes.
#[tokio::test]
async fn native_app_changes_pinned_snapshot_reuses_admission_only_on_its_connection() {
    use std::time::Instant;
    let f = Fixture::new().await;
    let (db, b) = changes_app_fixture(&f).await;
    let dispatch = dispatch_for(&app_caller());
    const EVENTS: usize = 200;

    // Live: every change_on evaluates admission afresh.
    let (live, live_admissions) =
        k::app_installs::with_source_admission_count(dispatch.scope(async {
            let mut tx = db.pool().begin().await.unwrap();
            let started = Instant::now();
            for _ in 0..EVENTS {
                assert!(k::messaging::change_on(&mut tx, &b, 0)
                    .await
                    .unwrap()
                    .is_none());
            }
            let elapsed = started.elapsed();
            tx.rollback().await.unwrap();
            elapsed
        }))
        .await;

    // Pinned to the one connection, exactly as whats_changed now scopes it.
    let (pinned, pinned_admissions) = k::app_installs::with_source_admission_count(dispatch.scope(
        k::read_cache::scope_request(async {
            let mut tx = db.pool().begin().await.unwrap();
            let key = k::read_cache::key_on(&mut tx, &b, "changes_snapshot")
                .await
                .unwrap();
            let connection = k::read_cache::connection_id(&mut tx);
            let started = Instant::now();
            k::read_cache::in_pinned_snapshot_with_admissions(
                key,
                connection,
                Default::default(),
                async {
                    for _ in 0..EVENTS {
                        assert!(k::messaging::change_on(&mut tx, &b, 0)
                            .await
                            .unwrap()
                            .is_none());
                    }
                },
            )
            .await;
            let elapsed = started.elapsed();
            tx.rollback().await.unwrap();
            elapsed
        }),
    ))
    .await;
    eprintln!("change_on x{EVENTS} under an app claim: live {live:?} ({live_admissions} source admissions), pinned {pinned:?} ({pinned_admissions})");
    assert_eq!(live_admissions, EVENTS, "unpinned, every call admits");
    assert_eq!(
        pinned_admissions, 1,
        "pinned, one admission serves the whole snapshot"
    );

    // A different connection inside the pinned scope is refused, not reused.
    let mismatch = dispatch
        .scope(k::read_cache::scope_request(async {
            let mut pinned_tx = db.pool().begin().await.unwrap();
            let mut other = db.pool().begin().await.unwrap();
            let key = k::read_cache::key_on(&mut pinned_tx, &b, "changes_snapshot")
                .await
                .unwrap();
            let connection = k::read_cache::connection_id(&mut pinned_tx);
            let result = k::read_cache::in_pinned_snapshot_with_admissions(
                key,
                connection,
                Default::default(),
                async { k::messaging::change_on(&mut other, &b, 0).await },
            )
            .await;
            other.rollback().await.unwrap();
            pinned_tx.rollback().await.unwrap();
            result
        }))
        .await;
    let refusal =
        mismatch.expect_err("another connection inside the pinned scope must fail closed");
    assert!(
        refusal
            .to_string()
            .contains("pinned app admission connection mismatch"),
        "{refusal}"
    );

    // Revocation: a later snapshot admits afresh and refuses; nothing carried over.
    k::app_installs::remove_as(&db, &b, "agent.docs", "install-b")
        .await
        .unwrap();
    let later = dispatch
        .scope(k::read_cache::scope_request(async {
            let mut tx = db.pool().begin().await.unwrap();
            let key = k::read_cache::key_on(&mut tx, &b, "changes_snapshot")
                .await
                .unwrap();
            let connection = k::read_cache::connection_id(&mut tx);
            let result = k::read_cache::in_pinned_snapshot_with_admissions(
                key,
                connection,
                Default::default(),
                async { k::messaging::change_on(&mut tx, &b, 0).await },
            )
            .await;
            tx.rollback().await.unwrap();
            result
        }))
        .await;
    assert!(
        later.is_err(),
        "a revoked claim is refused in a later pinned snapshot"
    );
    db.close().await;
}

/// End to end: an app-claimed whats_changed over a non-empty window succeeds,
/// so every read inside the pinned scope uses the scope's own connection.
#[tokio::test]
async fn native_app_changes_full_window_runs_inside_its_pinned_snapshot() {
    let f = Fixture::new().await;
    let (db, _b) = changes_app_fixture(&f).await;
    let registry = registry();
    let args = json!({"after_local_seq":0,"limit":1000});
    let ordinary = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "whats_changed",
            args.clone(),
        )
        .await
        .unwrap();
    let app = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            app_caller(),
            "whats_changed",
            args,
        )
        .await
        .unwrap();
    assert!(
        !ordinary["changes"].as_array().unwrap().is_empty(),
        "fixture window is non-empty"
    );
    assert_eq!(
        app["changes"], ordinary["changes"],
        "app and ordinary callers see the same window"
    );
    db.close().await;
}
