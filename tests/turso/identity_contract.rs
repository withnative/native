#![cfg(feature = "turso-tests")]

use crate::contract::{scenarios, ContractHarness, TestCaller, TursoHarness};
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::turso_local::{register_turso_local_tools, TursoLocalDb};
use serde_json::json;

fn spawn_resolve(
    database: TursoLocalDb,
    identifier: &'static str,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        register_turso_local_tools(&mut registry).unwrap();
        registry
            .call_engine(
                EngineHandle::TursoLocal(database),
                Caller::local(),
                "resolve_external",
                json!({
                    "bindings":[{"system":"native-principal","identifier":identifier}],
                    "reason":"Exercise the Turso identity transaction boundary."
                }),
            )
            .await
    })
}

#[tokio::test]
async fn turso_identity_binding_full_boundary_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::identity_bindings(&harness, &database)
        .await
        .unwrap();
    let runtime = database.runtime_for_test().unwrap();
    let commit_count = runtime.contract_commit_count_for_test();
    let mut tailer = runtime.subscribe_realtime();
    let hit = harness
        .call(
            &database,
            TestCaller::member("acct:identity-alpha"),
            "resolve_external",
            json!({
                "bindings":[{"system":"native-principal","identifier":"native/resolved-alpha"}],
                "reason":"Prove a pure idempotent hit rolls back without realtime completion."
            }),
        )
        .await
        .unwrap();
    assert_eq!(hit["status"], "resolved");
    assert_eq!(hit["created"], false);
    assert_eq!(hit["bindings_added"], json!([]));
    assert_eq!(runtime.contract_commit_count_for_test(), commit_count);
    assert!(tailer.try_next().unwrap().is_none());
    let binding_no_op = harness
        .call(
            &database,
            TestCaller::member("acct:identity-alpha"),
            "manage_bindings",
            json!({
                "action":"add","record_id":hit["record_id"],
                "binding":{"system":"native-principal","identifier":"native/resolved-alpha"},
                "canonical":false,"reason":"Prove a binding no-op rolls back."
            }),
        )
        .await
        .unwrap();
    assert_eq!(binding_no_op["status"], "unchanged");
    assert_eq!(runtime.contract_commit_count_for_test(), commit_count);
    assert!(tailer.try_next().unwrap().is_none());
    let mutation = database
        .runtime_for_test()
        .unwrap()
        .contract_rewrite_binding_audit_for_test()
        .await
        .unwrap_err()
        .to_string();
    assert!(
        mutation.contains("binding_audit is append-only"),
        "{mutation}"
    );

    let left = harness.call(
        &database, TestCaller::Local, "resolve_external",
        json!({"bindings":[{"system":"native-principal","identifier":"native/turso-race"}],"reason":"Race a portable binding resolution."}),
    );
    let right = harness.call(
        &database, TestCaller::Local, "resolve_external",
        json!({"bindings":[{"system":"native-principal","identifier":"native/turso-race"}],"reason":"Race a portable binding resolution."}),
    );
    let (left, right) = tokio::join!(left, right);
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left["record_id"], right["record_id"]);
    let created = [left["created"].as_bool(), right["created"].as_bool()]
        .into_iter()
        .filter(|value| *value == Some(true))
        .count();
    assert_eq!(created, 1);

    let other = harness.fresh_logical_database().await.unwrap();
    let isolated = harness.call(
        &other, TestCaller::Local, "resolve_external",
        json!({"bindings":[{"system":"native-principal","identifier":"native/turso-race"}],"reason":"Prove logical database isolation."}),
    ).await.unwrap();
    assert_eq!(isolated["status"], "created");
    assert_ne!(isolated["record_id"], left["record_id"]);

    harness.close(&database).await;
    harness.close(&other).await;
}

#[tokio::test]
async fn turso_identity_cancellation_rolls_back_and_reuses_the_engine() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let runtime = database.runtime_for_test().unwrap();
    runtime.contract_arm_post_handler_write_block("resolve_external");
    let call = spawn_resolve(runtime.clone(), "native/turso-cancelled");
    runtime.contract_wait_for_write_block().await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());

    let retried = spawn_resolve(runtime, "native/turso-cancelled")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried["status"], "created");
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}
