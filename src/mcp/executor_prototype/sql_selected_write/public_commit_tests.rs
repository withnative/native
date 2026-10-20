use super::super::super::*;
use super::tests::{Fixture, A, B, D, F};
use crate::authorization::Capability;

async fn fixture_server(
    f: &Fixture,
    caller: Caller,
    enabled: bool,
) -> ExecutorPrototypeStdioServer {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    let experimental =
        crate::mcp::ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
    crate::mcp::register_allowlisted_experimental_tools(&mut registry, &experimental).unwrap();
    let telemetry = ExecutorTelemetryContext::new(
        Arc::new(super::super::super::super::telemetry::TestTelemetrySink::default()),
        super::super::super::super::telemetry::DEFAULT_RETENTION_DAYS,
    )
    .unwrap();
    let server = ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
        Arc::new(registry),
        f.db.clone(),
        caller,
        None,
        telemetry,
        experimental,
    )
    .await
    .unwrap();
    if enabled {
        server.with_local_sql_commit().unwrap()
    } else {
        server
    }
}
fn message(arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql_write","arguments":arguments}})
}
fn request(write: Value) -> Value {
    let mut args = Fixture::request(write);
    args["execution_profile"] = json!(super::PROFILE);
    args
}
async fn prepare(server: &ExecutorPrototypeStdioServer, args: Value) -> Value {
    server
        .handle_message(message(json!({"operation":"sql_write","arguments":args})))
        .await
        .unwrap()
}
fn execute_args(prepared: &Value) -> Value {
    let p = &prepared["result"]["structuredContent"];
    json!({"operation":"sql_write","plan_id":p["plan_id"],"target":p["target"],"effect_summary":p["effect_summary"]})
}
async fn execute(server: &ExecutorPrototypeStdioServer, args: Value) -> Value {
    server.handle_message(message(args)).await.unwrap()
}
fn error(response: &Value) -> &Value {
    &response["result"]["structuredContent"]["plan_error"]["code"]
}

#[tokio::test]
async fn opted_in_facet_link_and_archived_workflows_commit_and_replay_original_receipts() {
    for op in ["set_facet", "add_link", "archive"] {
        let f = Fixture::new().await;
        let write = match op {
            "set_facet" => json!({"op":op,"key":"review","value":"pending"}),
            "add_link" => {
                f.public(
                    "manage_links",
                    json!({"action":"add","source_id":A,"target_id":D,"relationship":"relates_to"}),
                )
                .await;
                json!({"op":op,"target_id":D})
            }
            _ => {
                for id in [A, B] {
                    f.public(
                        "archive_record",
                        json!({"id":id,"reason":"already archived"}),
                    )
                    .await;
                }
                json!({"op":op})
            }
        };
        let server = fixture_server(&f, Caller::local(), true).await;
        let p = prepare(&server, request(write)).await;
        assert!(response_succeeded(&p), "{p}");
        assert!(p["result"]["structuredContent"]["effect_summary"]
            .as_str()
            .unwrap()
            .starts_with("Commit atomically in SQLite:"));
        assert!(p["result"]["structuredContent"]["target"]
            .as_str()
            .unwrap()
            .starts_with("Commit to "));
        let before = f.counts().await;
        assert!(response_succeeded(&p), "{p}");
        let args = execute_args(&p);
        let result = execute(&server, args.clone()).await;
        assert!(response_succeeded(&result), "{result}");
        let receipt = &result["result"]["structuredContent"];
        assert_eq!(receipt["status"], "committed");
        assert_eq!(receipt["profile"], super::PROFILE);
        let after = f.counts().await;
        assert_eq!(after.3, before.3 + 1, "one durable batch receipt");
        assert_eq!(after.4, before.4 + 1, "one act");
        match op {
            "set_facet" => {
                assert_eq!(after.0, before.0 + 2, "equal values still assert");
                assert_eq!(receipt["results"][0]["state_changed"], false);
            }
            "add_link" => {
                assert_eq!(after.0, before.0);
                assert_eq!(
                    after.1,
                    before.1 + 3,
                    "existing support plus new proposition/support"
                );
            }
            _ => {
                assert_eq!(after.0, before.0);
                assert_eq!(after.1, before.1);
                assert_eq!(after.2, before.2 + 1, "empty command anchor");
            }
        }
        f.public(
            "update_record",
            json!({"id":A,"name":"later independent edit","reason":"after commit"}),
        )
        .await;
        let stable = f.counts().await;
        let replay = execute(&server, args).await;
        assert!(response_succeeded(&replay), "{replay}");
        for key in [
            "plan_id",
            "profile",
            "status",
            "act",
            "target_count",
            "results",
            "anchor_id",
            "item_attestation_ids",
        ] {
            assert_eq!(replay["result"]["structuredContent"][key], receipt[key]);
        }
        assert_eq!(f.counts().await, stable);
        f.conform().await;
    }
}

#[tokio::test]
async fn preview_consent_is_not_the_allowlist_and_old_preview_never_becomes_commit() {
    let f = Fixture::new().await;
    let server = fixture_server(&f, Caller::local(), false).await;
    let refused = prepare(&server, request(json!({"op":"archive"}))).await;
    assert_eq!(error(&refused), "commit_unavailable");
    let preview = prepare(&server, Fixture::request(json!({"op":"archive"}))).await;
    assert!(response_succeeded(&preview), "{preview}");
    let server = server.with_local_sql_commit().unwrap();
    let before = f.counts().await;
    for _ in 0..2 {
        let current = execute(&server, execute_args(&preview)).await;
        assert!(response_succeeded(&current), "{current}");
        assert_eq!(
            current["result"]["structuredContent"]["source_dispatch_count"],
            0
        );
    }
    assert_eq!(f.counts().await, before);
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .claim_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    let direct = server
        .registry
        .call(
            f.db.clone(),
            Caller::local(),
            "sql_write",
            request(json!({"op":"archive"})),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(direct.contains(crate::mcp::tools::sql_write::DIRECT_REFUSAL));
    let legacy = prepare(&server, json!({"statement":"SELECT id FROM records","reason":"legacy","execution_profile":super::PROFILE})).await;
    assert!(!response_succeeded(&legacy));
    let commit = prepare(&server, request(json!({"op":"archive"}))).await;
    assert!(response_succeeded(&commit), "{commit}");
    let disabled = fixture_server(&f, Caller::local(), false).await;
    assert_eq!(
        error(&execute(&disabled, execute_args(&commit)).await),
        "commit_unavailable"
    );
    assert_eq!(f.counts().await, before);
    let mut hosted = fixture_server(&f, Caller::local(), false).await;
    hosted.hosted_membership_plans = true;
    assert!(hosted.with_local_sql_commit().is_err());
    let mut unavailable = server;
    unavailable.registry = {
        let mut r = ToolRegistry::new();
        r.set_standby_read_only(true);
        Arc::new(r)
    };
    assert!(unavailable.with_local_sql_commit().is_err());
}

#[tokio::test]
async fn stale_source_and_late_selection_changes_never_append_and_cannot_reexecute_claim() {
    let f = Fixture::new().await;
    let mut server = fixture_server(&f, Caller::local(), true).await;
    let mut args = request(json!({"op":"archive"}));
    args["sources"] = json!([{"record_id":D,"reason":"source basis"}]);
    let p = prepare(&server, args).await;
    assert!(response_succeeded(&p), "{p}");
    f.public(
        "update_record",
        json!({"id":D,"body_append":" changed source basis","reason":"drift"}),
    )
    .await;
    let before = f.counts().await;
    let stale = execute(&server, execute_args(&p)).await;
    assert_eq!(error(&stale), "plan_stale", "{stale}");
    assert_eq!(f.counts().await, before);
    let p = prepare(&server, request(json!({"op":"archive"}))).await;
    let gate = DispatchGate::new();
    server.write_runtime.as_mut().unwrap().dispatch_gate = Some(gate.clone());
    let server = Arc::new(server);
    assert!(response_succeeded(&p), "{p}");
    let args = execute_args(&p);
    let task = {
        let server = server.clone();
        let args = args.clone();
        tokio::spawn(async move { execute(&server, args).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.entered.acquire())
        .await
        .expect("dispatch entered")
        .unwrap()
        .forget();
    f.public(
        "update_record",
        json!({"id":A,"name":"changed inside fence","reason":"drift"}),
    )
    .await;
    let before = f.counts().await;
    gate.release.add_permits(1);
    let stale = task.await.unwrap();
    assert_eq!(error(&stale), "plan_stale", "{stale}");
    assert_eq!(f.counts().await, before);
    let retry = execute(&server, args).await;
    assert_eq!(error(&retry), "plan_execution_indeterminate", "{retry}");
    assert_eq!(f.counts().await, before);
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .dispatch_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn positive_receipt_reconciles_failed_sidecar_completion_with_original_attempt() {
    let f = Fixture::new().await;
    let server = fixture_server(&f, Caller::local(), true).await;
    let p = prepare(
        &server,
        request(json!({"op":"set_facet","key":"review","value":"done"})),
    )
    .await;
    assert!(response_succeeded(&p), "{p}");
    let args = execute_args(&p);
    let store = &server.write_runtime.as_ref().unwrap().store;
    store.block_completion_for_test(true).await.unwrap();
    let result = execute(&server, args.clone()).await;
    assert_eq!(error(&result), "plan_execution_indeterminate", "{result}");
    let plan_id = args["plan_id"].as_str().unwrap();
    let state = store.load(plan_id, now_ms()).await.unwrap().unwrap().state;
    let StoredState::Indeterminate { attempt_id, .. } = state else {
        panic!("original fence not retained")
    };
    let before = f.counts().await;
    assert_eq!(before.3, 1);
    store.block_completion_for_test(false).await.unwrap();
    let (recovered, concurrent) = tokio::join!(
        execute(&server, args.clone()),
        execute(&server, args.clone())
    );
    assert!(response_succeeded(&concurrent), "{concurrent}");
    assert_eq!(recovered, concurrent);
    assert!(response_succeeded(&recovered), "{recovered}");
    assert_eq!(f.counts().await, before);
    assert!(matches!(
        store.load(plan_id, now_ms()).await.unwrap().unwrap().state,
        StoredState::Completed { .. }
    ));
    assert!(!attempt_id.is_empty());
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .dispatch_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(response_succeeded(&execute(&server, args).await));
}

#[tokio::test]
async fn claimed_without_positive_receipt_stays_indeterminate_without_dispatch() {
    let f = Fixture::new().await;
    let server = fixture_server(&f, Caller::local(), true).await;
    let p = prepare(&server, request(json!({"op":"archive"}))).await;
    assert!(response_succeeded(&p), "{p}");
    let args = execute_args(&p);
    let store = &server.write_runtime.as_ref().unwrap().store;
    let ClaimOutcome::Claimed { attempt_id, .. } = store
        .claim(args["plan_id"].as_str().unwrap(), now_ms())
        .await
        .unwrap()
    else {
        panic!("claim")
    };
    let before = f.counts().await;
    for _ in 0..2 {
        let result = execute(&server, args.clone()).await;
        assert_eq!(error(&result), "plan_execution_indeterminate", "{result}");
    }
    assert_eq!(f.counts().await, before);
    assert!(
        matches!(store.load(args["plan_id"].as_str().unwrap(), now_ms()).await.unwrap().unwrap().state, StoredState::Executing { attempt_id: ref owner, .. } if owner == &attempt_id)
    );
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .dispatch_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn modern_commit_and_replay_carry_result_type() {
    let f = Fixture::new().await;
    let server = fixture_server(&f, Caller::local(), true).await;
    let meta = || {
        json!({
            "io.modelcontextprotocol/protocolVersion": crate::mcp::PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}
        })
    };
    let modern_call = |id: i64, arguments: Value| json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"sql_write","arguments":arguments,"_meta":meta()}});
    let prepared = server
        .handle_message(modern_call(
            1,
            json!({"operation":"sql_write","arguments":request(json!({"op":"archive"}))}),
        ))
        .await
        .unwrap();
    assert!(response_succeeded(&prepared), "{prepared}");
    assert_eq!(prepared["result"]["resultType"], "complete");
    let p = &prepared["result"]["structuredContent"];
    let args = json!({"operation":"sql_write","plan_id":p["plan_id"],"target":p["target"],"effect_summary":p["effect_summary"]});
    let committed = server
        .handle_message(modern_call(2, args.clone()))
        .await
        .unwrap();
    assert!(response_succeeded(&committed), "{committed}");
    assert_eq!(
        committed["result"]["structuredContent"]["status"],
        "committed"
    );
    assert_eq!(
        committed["result"]["resultType"], "complete",
        "modern sql_write commit must carry resultType: {committed}"
    );
    let replay = server.handle_message(modern_call(3, args)).await.unwrap();
    assert!(response_succeeded(&replay), "{replay}");
    assert_eq!(
        replay["result"]["_meta"]["nativeWritePlanReplay"]["idempotentReplay"],
        true
    );
    assert_eq!(
        replay["result"]["resultType"], "complete",
        "modern sql_write replay must carry resultType: {replay}"
    );
}

#[tokio::test]
async fn completed_receipt_allows_edit_demotion_but_refuses_view_loss() {
    let f = Fixture::new().await;
    let account = "acct:sql-public-reader";
    for id in [F, A, B] {
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:sql-public",
            id,
            vec![crate::authorization::AllowEntry::account(
                account,
                Capability::Manage,
            )],
        )
        .await
        .unwrap();
    }
    let server = fixture_server(&f, Caller::authenticated(account), true).await;
    let p = prepare(&server, request(json!({"op":"archive"}))).await;
    assert!(response_succeeded(&p), "{p}");
    assert!(response_succeeded(&p), "{p}");
    let args = execute_args(&p);
    let first = execute(&server, args.clone()).await;
    assert!(response_succeeded(&first), "{first}");
    assert!(first["result"]["structuredContent"]["act"].is_null());
    crate::authorization::replace_explicit_policy(
        &f.db,
        "test:sql-public",
        A,
        vec![crate::authorization::AllowEntry::account(
            account,
            Capability::View,
        )],
    )
    .await
    .unwrap();
    let replay = execute(&server, args.clone()).await;
    assert!(response_succeeded(&replay), "{replay}");
    assert!(replay["result"]["structuredContent"]["act"].is_null());
    assert_eq!(
        replay["result"]["structuredContent"],
        first["result"]["structuredContent"]
    );
    crate::authorization::replace_explicit_policy(&f.db, "test:sql-public", A, vec![])
        .await
        .unwrap();
    let before = f.counts().await;
    let denied = execute(&server, args).await;
    assert_eq!(error(&denied), "receipt_unavailable", "{denied}");
    assert!(!denied.to_string().contains(A));
    assert_eq!(f.counts().await, before);
}

#[tokio::test]
async fn concurrent_calls_share_permanent_claim_and_identical_replay() {
    let f = Fixture::new().await;
    let mut server = fixture_server(&f, Caller::local(), true).await;
    let p = prepare(&server, request(json!({"op":"archive"}))).await;
    assert!(response_succeeded(&p), "{p}");
    let args = execute_args(&p);
    let gate = DispatchGate::new();
    server.write_runtime.as_mut().unwrap().dispatch_gate = Some(gate.clone());
    let server = Arc::new(server);
    let running = {
        let server = server.clone();
        let args = args.clone();
        tokio::spawn(async move { execute(&server, args).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.entered.acquire())
        .await
        .expect("dispatch entered")
        .unwrap()
        .forget();
    let blocked = execute(&server, args.clone()).await;
    assert_eq!(error(&blocked), "plan_execution_indeterminate", "{blocked}");
    gate.release.add_permits(1);
    assert!(response_succeeded(&running.await.unwrap()));
    let before = f.counts().await;
    let (a, b) = tokio::join!(execute(&server, args.clone()), execute(&server, args));
    assert!(response_succeeded(&a), "{a}");
    assert_eq!(a, b);
    assert_eq!(f.counts().await, before);
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .dispatch_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn late_relationship_failure_rolls_back_domain_provenance_and_receipt() {
    let f = Fixture::new().await;
    let server = fixture_server(&f, Caller::local(), true).await;
    let p = prepare(&server, request(json!({"op":"add_link","target_id":D}))).await;
    let before = f.counts().await;
    let failed = super::FAIL_AFTER
        .scope(2, execute(&server, execute_args(&p)))
        .await;
    assert_eq!(error(&failed), "plan_execution_indeterminate", "{failed}");
    assert_eq!(f.counts().await, before);
    let retry = execute(&server, execute_args(&p)).await;
    assert_eq!(error(&retry), "plan_execution_indeterminate", "{retry}");
    assert_eq!(f.counts().await, before);
    f.conform().await;
}

#[tokio::test]
async fn permission_drift_and_approval_echo_refuse_before_claim() {
    let f = Fixture::new().await;
    let account = "acct:sql-public-editor";
    for id in [F, A, B] {
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:sql-public",
            id,
            vec![crate::authorization::AllowEntry::account(
                account,
                Capability::Manage,
            )],
        )
        .await
        .unwrap();
    }
    let server = fixture_server(&f, Caller::authenticated(account), true).await;
    let p = prepare(&server, request(json!({"op":"archive"}))).await;
    assert!(response_succeeded(&p), "{p}");
    let mut echo = execute_args(&p);
    echo["effect_summary"] = json!("unchecked replacement approval");
    assert_eq!(
        error(&execute(&server, echo).await),
        "visible_effect_mismatch"
    );
    crate::authorization::replace_explicit_policy(
        &f.db,
        "test:sql-public",
        A,
        vec![crate::authorization::AllowEntry::account(
            account,
            Capability::Edit,
        )],
    )
    .await
    .unwrap();
    let before = f.counts().await;
    let stale = execute(&server, execute_args(&p)).await;
    assert_eq!(error(&stale), "plan_stale", "{stale}");
    assert_eq!(f.counts().await, before);
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .claim_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn dispatch_deadline_rolls_back_or_replays_landed_commit_without_redispatch() {
    use std::time::{Duration, Instant};
    for landed in [false, true] {
        let f = Fixture::new().await;
        let server = fixture_server(&f, Caller::local(), true).await;
        let p = prepare(&server, request(json!({"op":"archive"}))).await;
        assert!(response_succeeded(&p), "{p}");
        let args = execute_args(&p);
        let before = f.counts().await;
        let started = Instant::now();
        let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel();
        let gate = Arc::new(crate::db::enrolled::TestGate {
            phase: if landed {
                crate::db::enrolled::Phase::AfterCommit
            } else {
                crate::db::enrolled::Phase::BeforeCommit
            },
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Semaphore::new(0),
            outcome: std::sync::Mutex::new(None),
            writer_close_ack: std::sync::atomic::AtomicBool::new(false),
        });
        let result = sql_commit::TEST_GUARDED_DISPATCH
            .scope(
                (),
                crate::db::enrolled::TEST_GATE.scope(gate, execute(&server, args.clone())),
            )
            .await;
        assert!(
            entered_rx.try_recv().is_ok(),
            "must reach the transaction phase before timeout"
        );
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(error(&result), "plan_execution_indeterminate", "{result}");
        assert!(
            result
                .to_string()
                .contains("guarded dispatch exceeded 5 seconds"),
            "{result}"
        );
        let store = &server.write_runtime.as_ref().unwrap().store;
        let plan_id = args["plan_id"].as_str().unwrap();
        let StoredState::Indeterminate { .. } =
            store.load(plan_id, now_ms()).await.unwrap().unwrap().state
        else {
            panic!("deadline must preserve the original attempt as indeterminate")
        };
        let after = f.counts().await;
        if landed {
            assert_eq!(after.3, before.3 + 1);
            assert_eq!(after.0, before.0 + 2);
        } else {
            assert_eq!(
                after, before,
                "canceled transaction must roll back every effect"
            );
        }
        for _ in 0..2 {
            let retry = execute(&server, args.clone()).await;
            if landed {
                assert!(response_succeeded(&retry), "{retry}");
                assert_eq!(retry["result"]["structuredContent"]["status"], "committed");
                assert!(matches!(
                    store.load(plan_id, now_ms()).await.unwrap().unwrap().state,
                    StoredState::Completed {
                        source_dispatch_count: 1,
                        ..
                    }
                ));
            } else {
                assert_eq!(error(&retry), "plan_execution_indeterminate", "{retry}");
            }
            assert_eq!(f.counts().await, after);
        }
        assert_eq!(
            server
                .write_runtime
                .as_ref()
                .unwrap()
                .dispatch_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        f.conform().await;
    }
}

#[tokio::test]
async fn guarded_replay_deadline_preserves_completed_state_and_later_receipt_recovery() {
    use std::time::{Duration, Instant};
    let f = Fixture::new().await;
    let server = fixture_server(&f, Caller::local(), true).await;
    let p = prepare(&server, request(json!({"op":"archive"}))).await;
    let args = execute_args(&p);
    let committed = execute(&server, args.clone()).await;
    assert!(response_succeeded(&committed), "{committed}");
    let store = &server.write_runtime.as_ref().unwrap().store;
    let plan_id = args["plan_id"].as_str().unwrap();
    let state = store.load(plan_id, now_ms()).await.unwrap().unwrap().state;
    let before = f.counts().await;
    let gate = DispatchGate::new();
    let started = Instant::now();
    let timed_out = sql_commit::TEST_GUARDED_DISPATCH
        .scope(
            (),
            super::REPLAY_GATE.scope(gate.clone(), execute(&server, args.clone())),
        )
        .await;
    assert_eq!(
        gate.entered.available_permits(),
        1,
        "replay acquired its connection"
    );
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(
        error(&timed_out),
        "plan_execution_indeterminate",
        "{timed_out}"
    );
    assert!(timed_out
        .to_string()
        .contains("guarded durable receipt replay exceeded 5 seconds"));
    assert_eq!(
        timed_out["result"]["structuredContent"]["plan_error"]["continuation"]["retryable"],
        true
    );
    assert_eq!(
        store.load(plan_id, now_ms()).await.unwrap().unwrap().state,
        state
    );
    assert_eq!(f.counts().await, before);
    let recovered = execute(&server, args).await;
    assert!(response_succeeded(&recovered), "{recovered}");
    assert_eq!(
        recovered["result"]["structuredContent"],
        committed["result"]["structuredContent"]
    );
    assert_eq!(f.counts().await, before);
    assert_eq!(
        server
            .write_runtime
            .as_ref()
            .unwrap()
            .dispatch_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}
