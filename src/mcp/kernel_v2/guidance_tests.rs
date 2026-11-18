//! KernelV2 serves build-owned guidance: `read_guide` and `quickstart`.
use super::*;
use crate::mcp::kernel_v2::tests::registry;

async fn v2_database() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = kernel::create_v2_database(
        dir.path().join("v2.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    (dir, db)
}

async fn call(db: &Db, caller: Caller, name: &str, arguments: Value) -> Result<Value> {
    registry()
        .call_engine(EngineHandle::KernelV2(db.clone()), caller, name, arguments)
        .await
}

fn admin() -> Caller {
    Caller::authenticated("acct:admin")
}

/// A hosted non-owner: the same admitted principal, without the owner role.
fn member_caller() -> Caller {
    Caller::authenticated("acct:admin")
        .with_hosting_context("principal-alias", "database-alias")
        .with_hosting_member(true)
}

/// The served value without the universal run-context echo, which dispatch
/// appends to every read response and which is not part of the tool payload.
fn payload(mut value: Value) -> Value {
    let removed = value
        .as_object_mut()
        .expect("object response")
        .remove("run_context");
    assert!(removed.is_some(), "dispatch appends the run-context echo");
    value
}

/// One ordinary-surface executor operation is advertised on KernelV2 exactly
/// when `build_contracts` admitted it, which it does only for a registered
/// engine handler. `classify_call` reads that pinned contract map directly.
#[cfg(feature = "mcp-executor-prototype")]
#[test]
fn v2_executor_catalogue_advertises_build_owned_guidance() {
    use crate::mcp::executor_prototype::ExecutorPrototypeStdioServer;
    use crate::mcp::{ExperimentalExecutors, McpSurfaceMode};

    fn advertised(registry: &ToolRegistry, executor: &str, operation: &str) -> bool {
        ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
            registry,
            &ExperimentalExecutors::empty(),
            McpSurfaceMode::Executor,
            EngineKind::KernelV2,
        )
        .unwrap()
        .classify_call(executor, Some(operation))
        .is_some()
    }

    let with_v2 = registry();
    assert!(with_v2.has_engine_operation("read_guide", EngineKind::KernelV2, None));
    assert!(with_v2.has_engine_operation("quickstart", EngineKind::KernelV2, None));
    for (executor, operation) in [
        ("guidance_read", "read_guide"),
        ("guidance_read", "quickstart"),
    ] {
        assert!(
            advertised(&with_v2, executor, operation),
            "KernelV2 must advertise {executor}.{operation}"
        );
    }

    // Without the KernelV2 handlers the same audit rows are not executable, so
    // the operations are absent: registration above is what advertises them.
    let mut without_v2 = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut without_v2).unwrap();
    crate::mcp::tools::register_surface_tools(&mut without_v2).unwrap();
    for (executor, operation) in [
        ("guidance_read", "read_guide"),
        ("guidance_read", "quickstart"),
    ] {
        assert!(
            !advertised(&without_v2, executor, operation),
            "{executor}.{operation} must not be advertised without a KernelV2 handler"
        );
    }
}

#[tokio::test]
async fn read_guide_serves_the_compiled_corpus_on_v2() {
    // The corpus is compiled into the binary, so a freshly created v2 database
    // with no workspace records serves it, exactly as on v1.
    let (_dir, db) = v2_database().await;
    for topic in ["query-sql", "app-builder-1.0.0", "product-model"] {
        let value = call(&db, admin(), "read_guide", json!({"topic":topic}))
            .await
            .unwrap();
        assert_eq!(
            payload(value),
            crate::mcp::guides::read_guide_value(json!({"topic":topic})).unwrap(),
            "v2 read_guide must serve the v1 compiled guide verbatim"
        );
    }
    let error = call(&db, admin(), "read_guide", json!({"topic":"not-a-topic"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown topic 'not-a-topic'"), "{error}");
    assert!(error.contains("valid topics"), "{error}");
    let error = call(
        &db,
        admin(),
        "read_guide",
        json!({"topic":"query-sql","extra":true}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown field"), "{error}");
}

#[tokio::test]
async fn quickstart_serves_the_build_owned_launcher_on_v2() {
    let (_dir, db) = v2_database().await;
    let value = call(&db, admin(), "quickstart", json!({})).await.unwrap();
    assert_eq!(
        value,
        crate::mcp::tools::quickstart::quickstart_value(json!({})).unwrap(),
        "v2 quickstart must serve the v1 build-owned launcher verbatim"
    );
    // QuickStart inspects no workspace state: the value names no run or record.
    let serialized = value.to_string();
    for forbidden in [
        "run_key",
        "workspace_root",
        "record_count",
        "schema_version",
    ] {
        assert!(!serialized.contains(forbidden), "{forbidden}: {serialized}");
    }
    // The same closed argument contract as v1: no run context is accepted.
    let error = call(&db, admin(), "quickstart", json!({"run_key":"new"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field"), "{error}");
    assert!(error.contains("run_key"), "{error}");
}

/// Guidance is static compiled data: the served payload is identical for an
/// owner and for a hosted member, because neither handler takes a caller.
///
/// Admission is a property of the v2 dispatch seam, not of guidance. The
/// registry resolves the caller's principal for every `KernelV2` call before
/// any handler runs, so an unbound credential is refused for guidance and for
/// `describe_schema` alike. Guidance therefore cannot be "reachable while
/// describe_schema is not": what is caller-independent is the payload, and
/// what is caller-dependent in `describe_schema` is only the member/owner tier
/// and the owner-only DDL.
#[tokio::test]
async fn guidance_payload_does_not_depend_on_the_caller() {
    let (_dir, db) = v2_database().await;
    assert_eq!(
        payload(
            call(&db, admin(), "read_guide", json!({"topic":"about"}))
                .await
                .unwrap()
        ),
        payload(
            call(&db, member_caller(), "read_guide", json!({"topic":"about"}))
                .await
                .unwrap()
        )
    );
    assert_eq!(
        call(&db, admin(), "quickstart", json!({})).await.unwrap(),
        call(&db, member_caller(), "quickstart", json!({}))
            .await
            .unwrap()
    );
    for tool in ["read_guide", "quickstart", "describe_schema"] {
        let arguments = match tool {
            "read_guide" => json!({"topic":"about"}),
            _ => json!({}),
        };
        let error = call(&db, Caller::authenticated("acct:unbound"), tool, arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no principal auth_binding"),
            "{tool} must refuse an unbound caller at the v2 dispatch seam: {error}"
        );
    }
}
