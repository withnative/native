//! KernelV2 describes its own installed physical catalogue.
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

async fn call(db: &Db, caller: Caller, arguments: Value) -> Result<Value> {
    registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller,
            "describe_schema",
            arguments,
        )
        .await
}

/// A hosted non-owner: the same admitted principal, without the owner role.
fn member_caller() -> Caller {
    Caller::authenticated("acct:admin")
        .with_hosting_context("principal-alias", "database-alias")
        .with_hosting_member(true)
}

fn table<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value["tables"]
        .as_array()?
        .iter()
        .find(|table| table["name"] == name)
}

#[tokio::test]
async fn describes_the_installed_v2_catalogue() {
    let (_dir, db) = v2_database().await;
    let value = call(&db, Caller::authenticated("acct:admin"), json!({}))
        .await
        .unwrap();
    assert_eq!(value["engine"]["name"], "native-kernel-v2");
    assert_eq!(value["engine"]["schema_version"], 0);
    assert_eq!(value["engine"]["user_version"], 0);
    let digest = value["engine"]["ddl_fingerprint"].as_str().unwrap();
    assert_eq!(digest.len(), 64, "{digest}");
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(value["logical_relations"]
        .as_str()
        .unwrap()
        .contains("catalog_columns"));
    assert!(value["model"]
        .as_str()
        .unwrap()
        .contains("content_events is authoritative"));

    // The physical tier v2 actually installs: the retained v1 store log, the
    // kernel projections and the definition registry.
    for expected in [
        "content_events",
        "kernel_records",
        "kernel_facets",
        "kernel_principals",
        "meta_events",
        "definition_artifacts",
    ] {
        assert!(table(&value, expected).is_some(), "missing {expected}");
    }
    assert_eq!(
        table(&value, "content_events").unwrap()["role"],
        "authoritative (append-only content event log)"
    );
    assert_eq!(
        table(&value, "kernel_records").unwrap()["role"],
        "projection (rebuildable by kernel replay; never write directly)"
    );

    // v1's logical tables are relations over these projections, not physical
    // tables; listing them as tables would invent storage that v2 does not keep.
    for absent in [
        "records",
        "links",
        "facet_values",
        "facet_observations",
        "policy_entries",
    ] {
        assert!(
            table(&value, absent).is_none(),
            "{absent} is a logical relation, not v2 storage"
        );
    }

    for table in value["tables"].as_array().unwrap() {
        let name = table["name"].as_str().unwrap();
        assert!(!table["role"].as_str().unwrap().is_empty(), "{name} role");
        let columns = table["columns"].as_array().unwrap();
        assert!(!columns.is_empty(), "{name} has no columns");
        for column in columns {
            assert!(column["name"].as_str().is_some(), "{name} column name");
            assert!(column["type"].as_str().is_some(), "{name} column type");
            assert!(column["notnull"].is_boolean(), "{name} column notnull");
            assert!(column["pk"].is_boolean(), "{name} column pk");
        }
    }
    let content_events = table(&value, "content_events").unwrap()["columns"]
        .as_array()
        .unwrap();
    assert!(content_events.iter().any(|column| column["name"] == "id"));
    assert!(content_events
        .iter()
        .any(|column| column["name"] == "payload"));

    // `include_ddl` is the database owner's physical contract, as on v1.
    assert!(value.get("ddl_statements").is_none());
    let with_ddl = call(
        &db,
        Caller::authenticated("acct:admin"),
        json!({"include_ddl": true}),
    )
    .await
    .unwrap();
    assert_eq!(with_ddl["tables"], value["tables"]);
    let statements = with_ddl["ddl_statements"].as_array().unwrap();
    assert!(statements.iter().any(|statement| statement
        .as_str()
        .unwrap()
        .contains("CREATE TABLE content_events")));
    assert!(statements.iter().any(|statement| statement
        .as_str()
        .unwrap()
        .contains("CREATE TABLE kernel_records")));
    // Every installed table carries its statement, so the DDL list is exactly
    // the table list.
    assert_eq!(
        statements.len(),
        with_ddl["tables"].as_array().unwrap().len()
    );
}

/// The exact catalogue a member sees. This list is deliberately literal: the
/// tool reads the live `sqlite_schema`, so a newly installed table must be
/// classified (member-visible or owner-only) before this test passes again.
const MEMBER_VISIBLE: &[&str] = &[
    "act_cutover",
    "act_state",
    "canvas_batches",
    "canvas_objects",
    "consumer_requirements",
    "content_event_causal_cutover",
    "content_event_causal_frontier",
    "content_event_heads",
    "content_events",
    "definition_adoptions",
    "definition_artifacts",
    "kernel_adoptions",
    "kernel_app_actions",
    "kernel_app_consent_revocations",
    "kernel_app_install_outcomes",
    "kernel_app_installs",
    "kernel_app_package_sources",
    "kernel_app_state",
    "kernel_artifact_closures",
    "kernel_canvas_activations",
    "kernel_canvas_source_events",
    "kernel_comment_anchors",
    "kernel_facet_time_invalid",
    "kernel_facet_time_meta",
    "kernel_facet_time_rows",
    "kernel_facets",
    "kernel_generic_links",
    "kernel_lifecycle",
    "kernel_link4_edges",
    "kernel_links",
    "kernel_message_destinations",
    "kernel_message_interactions",
    "kernel_message_people",
    "kernel_message_receipts",
    "kernel_messages",
    "kernel_notification_preferences",
    "kernel_package_selections",
    "kernel_personas",
    "kernel_provider_link_heads",
    "kernel_provider_link_rows",
    "kernel_publications",
    "kernel_record_bodies",
    "kernel_record_fields",
    "kernel_record_metadata",
    "kernel_records",
    "kernel_roots",
    "kernel_runs",
    "kernel_saved_tabs",
    "kernel_slot_lineage",
    "kernel_slots",
    "package_artifacts",
    "rule_installations",
];

fn names(value: &Value) -> Vec<String> {
    value["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|table| table["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn describes_exactly_the_classified_catalogue_to_a_member() {
    let (_dir, db) = v2_database().await;
    let member = call(&db, member_caller(), json!({})).await.unwrap();
    assert_eq!(names(&member), MEMBER_VISIBLE.to_vec());
    for expected in ["content_events", "kernel_records", "definition_artifacts"] {
        assert!(table(&member, expected).is_some(), "missing {expected}");
    }
    for owner_only in [
        "meta_events",
        "kernel_principals",
        "kernel_policies",
        "kernel_policy_entries",
        "kernel_root_bootstrap",
        "kernel_identity_bindings",
        "kernel_instruction_bindings",
        "kernel_account_configs",
        "kernel_hcp_entries",
        "kernel_message_candidates",
        "kernel_legacy_sql_events",
        "kernel_mcp_write_receipts",
        "kernel_provider_state",
        "kernel_blobs",
        "kernel_search_fts",
    ] {
        assert!(
            !MEMBER_VISIBLE.contains(&owner_only),
            "{owner_only} is the owner tier, as in v1"
        );
        assert!(table(&member, owner_only).is_none(), "{owner_only} leaked");
    }
    // The member view describes the same tiers it does see.
    assert_eq!(
        table(&member, "content_events").unwrap()["columns"],
        table(
            &call(&db, Caller::authenticated("acct:admin"), json!({}))
                .await
                .unwrap(),
            "content_events"
        )
        .unwrap()["columns"],
        "a classified table is described identically to member and owner"
    );
    let error = call(&db, member_caller(), json!({"include_ddl": true}))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("database owner host role required for physical DDL"),
        "{error}"
    );
}

/// An unclassified table is invisible to members even though it exists, and
/// visible to the owner: the allowlist fails closed as the engine grows.
#[tokio::test]
async fn hides_an_unclassified_table_from_members() {
    let (_dir, db) = v2_database().await;
    sqlx::query("CREATE TABLE kernel_future_repair_state(id TEXT PRIMARY KEY, secret TEXT)")
        .execute(db.write_pool())
        .await
        .unwrap();
    let member = call(&db, member_caller(), json!({})).await.unwrap();
    assert!(table(&member, "kernel_future_repair_state").is_none());
    let owner = call(&db, Caller::authenticated("acct:admin"), json!({}))
        .await
        .unwrap();
    assert!(table(&owner, "kernel_future_repair_state").is_some());
}

#[tokio::test]
async fn keeps_v1_argument_and_admission_contracts() {
    let (_dir, db) = v2_database().await;
    let error = call(
        &db,
        Caller::authenticated("acct:admin"),
        json!({"unknown":true}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown field"), "{error}");
    // A v2 surface serves an admitted principal only; an unbound credential
    // gets no catalogue at all.
    let error = call(&db, Caller::authenticated("acct:unbound"), json!({}))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("no principal auth_binding"), "{error}");
}

#[cfg(feature = "mcp-executor-prototype")]
#[test]
fn v2_executor_catalogue_advertises_describe_schema() {
    use crate::mcp::executor_prototype::ExecutorPrototypeStdioServer;
    use crate::mcp::{ExperimentalExecutors, McpSurfaceMode};

    fn advertised(registry: &ToolRegistry) -> bool {
        ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
            registry,
            &ExperimentalExecutors::empty(),
            McpSurfaceMode::Executor,
            EngineKind::KernelV2,
        )
        .unwrap()
        .classify_call("schema_read", Some("describe_schema"))
        .is_some()
    }

    let with_v2 = registry();
    assert!(with_v2.has_engine_operation("describe_schema", EngineKind::KernelV2, None));
    assert!(advertised(&with_v2));
    let mut without_v2 = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut without_v2).unwrap();
    crate::mcp::tools::register_surface_tools(&mut without_v2).unwrap();
    assert!(!advertised(&without_v2));
}
