use super::*;

#[tokio::test]
async fn development_package_contracts_are_read_only_and_kernel_v2_only() {
    let _serial = crate::package_cel_dev::RUNTIME_TEST.lock().await;
    let mut registry = ToolRegistry::new();
    super::super::register_builtin_tools(&mut registry).unwrap();
    super::super::register_surface_tools(&mut registry).unwrap();
    super::super::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let experimental = ExperimentalExecutors::default();
    let catalogue = build_ordinary_catalogue(
        &registry,
        super::super::registry::EngineKind::KernelV2,
        false,
        &experimental,
    )
    .unwrap();
    let sqlite = build_ordinary_catalogue(
        &registry,
        super::super::registry::EngineKind::Sqlite,
        false,
        &experimental,
    )
    .unwrap();
    let rows = project_catalog_operations_snapshot(
        &catalogue.contracts,
        &catalogue.operations_by_executor,
    );
    for name in ["describe_package_operations", "call_package_operation"] {
        let row = rows
            .iter()
            .find(|row| row.operation == name && row.executor == "records_read")
            .unwrap();
        assert_eq!(row.access, "read");
        assert!(!row.plan_required);
        let key = ("records_read".into(), name.into());
        let contract = &catalogue.contracts[&key];
        assert_eq!(contract.access, OperationAccess::Read);
        assert_eq!(contract.source_tool, name);
        if name == "describe_package_operations" {
            assert_eq!(contract.input_schema["type"], "object");
            assert_eq!(
                contract.input_schema["oneOf"][0]["required"],
                json!(["record_id"])
            );
            assert_eq!(
                contract.input_schema["oneOf"][1]["required"],
                json!(["scope_home", "namespace", "name"])
            );
        }
        assert!(contract.input_schema["properties"]
            .get("executable")
            .is_none());
        assert!(catalogue.operations_by_executor["records_read"].contains(&name.to_string()));
        assert!(!sqlite.contracts.contains_key(&key));
        let descriptor = catalogue
            .descriptors
            .iter()
            .find(|d| d["name"] == "records_read")
            .unwrap();
        assert!(descriptor["inputSchema"]["properties"]["operation"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!(name)));
    }

    // Generic JSON-RPC client proof over both independently authored packages.
    // A private test construction omits the write plan store; reads follow the
    // production executor contract and actual KernelV2 source handler.
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Admin", "test:transport")
            .await
            .unwrap();
    let server = ExecutorPrototypeStdioServer::new_with_plan_store(
        Arc::new(registry),
        EngineHandle::KernelV2(db.clone()),
        Caller::authenticated("test:transport"),
        None,
        ExecutorConstruction {
            plan_store: None,
            hosted_authority: None,
            pinned_catalogue: None,
            experimental: ExperimentalExecutors::empty(),
            lean: false,
            telemetry: TelemetryConstruction::Disabled,
            transport: telemetry::TelemetryTransport::Stdio,
            deployment_mutation_barrier: None,
        },
    )
    .await
    .unwrap();
    for (bytes, source, expected) in [
        (
            include_str!("../../examples/packages/cel-scalar-dev/quote.package.json"),
            r#"{"subtotal":1000,"discount_pct":10}"#,
            json!(900),
        ),
        (
            include_str!("../../examples/packages/cel-scalar-dev/dispatch.package.json"),
            r#"{"country":"GB","weight_kg":12.5,"prepaid":true}"#,
            json!(true),
        ),
    ] {
        let manifest = crate::package_manifest::PackageManifest::from_canonical_value(
            &serde_json::from_str(bytes).unwrap(),
        )
        .unwrap();
        let identity = crate::kernel::install_package_as(&db, &admin, &manifest)
            .await
            .unwrap();
        crate::kernel::adopt_package_at(
            &db,
            &admin,
            crate::events::KERNEL_ROOT_ID,
            &manifest,
            Some(&identity),
            &manifest.declared_reads,
        )
        .await
        .unwrap();
        let op = &manifest.operations[0];
        let id = crate::kernel::create_as(
            &db,
            &admin,
            &op.family,
            &op.kind,
            json!({"inputs_json":source}).as_object().unwrap(),
            crate::events::KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        let discovery = server.handle_message(json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
            "params":{"name":"records_read","arguments":{"operation":"describe_package_operations","format":"json",
                "arguments":{"record_id":id}}}})).await.unwrap();
        let discovered = &discovery["result"]["structuredContent"]["packages"][0];
        assert_eq!(discovered["namespace"], manifest.namespace, "{discovery}");
        assert_eq!(discovered["name"], manifest.name);
        for invalid in [
            json!({"record_id":id,"namespace":"forged"}),
            json!({"scope_home":"x","namespace":"x"}),
            json!({"record_id":id,"executable":{}}),
        ] {
            let refused=server.handle_message(json!({"jsonrpc":"2.0","id":10,"method":"tools/call",
                "params":{"name":"records_read","arguments":{"operation":"describe_package_operations","format":"json","arguments":invalid}}})).await.unwrap();
            assert!(
                refused.get("error").is_some() || refused["result"]["isError"] == true,
                "{refused}"
            );
        }
        let response = server.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"records_read","arguments":{"operation":"call_package_operation","format":"json",
                "arguments":{"namespace":manifest.namespace,"name":manifest.name,"package_operation":"compute","record_id":id}}}})).await.unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["result"]["value"], expected,
            "{response}"
        );
    }
}
