//! Scoped saved-tab executor contract proof.
use super::*;

#[cfg(feature = "v2-kernel-probe")]
#[test]
fn saved_tabs_kernel_executor_contracts_match_scoped_source_actions() {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let catalogue = build_ordinary_catalogue(
        &registry,
        crate::mcp::registry::EngineKind::KernelV2,
        false,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    for (action, executor, args) in [
        ("list", "records_read", json!({"limit":50})),
        ("get", "records_read", json!({"record_id":"tab"})),
        (
            "create",
            "records_write",
            json!({"creation_key":"local-slot","app":"agent.docs","initial_record_id":null,"reason":"admitted tab"}),
        ),
        (
            "rename",
            "records_write",
            json!({"record_id":"tab","expected_revision":"saved-tab:5","operation_id":"rename-op","custom_title":null,"reason":"personal reset"}),
        ),
        (
            "retire",
            "records_write",
            json!({"record_id":"tab","expected_revision":"saved-tab:5","operation_id":"forget-op","reason":"forget tab"}),
        ),
    ] {
        let contract =
            &catalogue.contracts[&(executor.into(), format!("manage_saved_tabs.{action}"))];
        assert_eq!(contract.source_tool, "manage_saved_tabs");
        assert_eq!(
            contract.access,
            if executor == "records_read" {
                OperationAccess::Read
            } else {
                OperationAccess::Mutation
            }
        );
        let validator = jsonschema::validator_for(&contract.input_schema).unwrap();
        assert!(
            validator.is_valid(&args),
            "{action}: {}",
            contract.input_schema
        );
        let mut spoof = args;
        spoof["principal_id"] = json!("foreign");
        assert!(!validator.is_valid(&spoof));
    }
}
