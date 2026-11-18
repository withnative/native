//! Serving catalogue discovery must execute on the engine it describes.
use super::*;

#[test]
fn kernel_v2_argument_contracts_reject_unimplemented_shapes() {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    let v1 = registry.get("batch_write").unwrap().input_schema.clone();
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    let catalogue = build_ordinary_catalogue(
        &registry,
        crate::mcp::registry::EngineKind::KernelV2,
        false,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    let validate = |name: &str, args: Value| {
        let contract = &catalogue.contracts[&("records_write".to_owned(), name.to_owned())];
        jsonschema::validator_for(&contract.input_schema)
            .unwrap()
            .is_valid(&args)
    };
    assert!(validate(
        "batch_write",
        json!({"reason":"archive", "items":[{"op":"update","id":"record","if_policy_revision":"revision"},{"op":"archive","id":"record"}]})
    ));
    for item in [
        json!({"op":"update","id":"record","name":"new"}),
        json!({"op":"update","id":"record","body_append":"text"}),
        json!({"op":"update","id":"record","body_set":null}),
        json!({"op":"update","id":"record","body_replace":[{"old":"old","new":"new"}]}),
        json!({"op":"add_link","source_id":"a","target_id":"b","relationship":"relates_to"}),
    ] {
        let args = json!({"reason":"patch","items":[item]});
        assert!(validate("batch_write", args.clone()), "{args}");
    }
    for item in [
        json!({"op":"update","id":"record","body":"deprecated alias"}),
        json!({"op":"update","id":"record","body_set":"one","body_append":"two"}),
        json!({"operation":"update_record","arguments":{"id":"record","name":"new"}}),
        json!({"op":"update","id":"record"}),
    ] {
        let args = json!({"reason":"patch","items":[item]});
        assert!(!validate("batch_write", args.clone()), "{args}");
    }
    for sources in [
        json!([]),
        json!(["basis"]),
        json!([{"record_id":"basis","reason":"consulted","revision_event_id":"revision"}]),
    ] {
        assert!(validate(
            "batch_write",
            json!({"reason":"shared basis","sources":sources,"items":[{"op":"update","id":"record","body_append":"text"}]})
        ));
    }
    assert!(!validate(
        "batch_write",
        json!({"reason":"invalid sources","sources":null,"items":[{"op":"update","id":"record","body_append":"text"}]})
    ));
    assert!(validate(
        "update_record",
        json!({"id":"record","reason":"edit","body_append":"text"})
    ));
    assert!(validate(
        "update_record",
        json!({"record_id":"record","reason":"edit","body_append":"text"})
    ));
    for selector in ["id", "record_id"] {
        for sources in [
            json!([]),
            json!(["basis"]),
            json!([{"record_id":"basis","reason":"consulted","role":"context","revision_event_id":"revision"}]),
        ] {
            let mut args = json!({"reason":"edit","body_append":"text","sources":sources});
            args[selector] = json!("record");
            assert!(validate("update_record", args.clone()), "{args}");
        }
    }
    assert!(validate(
        "attach_text",
        json!({"record_id":"record","text":"content"})
    ));
    assert!(validate(
        "attach_text",
        json!({"id":"record","text":"content"})
    ));
    assert!(validate(
        "attach_text",
        json!({"ids":["record"],"text":"content"})
    ));
    assert!(!validate(
        "attach_text",
        json!({"record_id":"record","text":"content","owner_id":"other"})
    ));
    assert_eq!(
        registry.get("batch_write").unwrap().input_schema,
        v1,
        "v1 contract unchanged"
    );
    assert!(
        catalogue.contracts[&("records_write".into(), "batch_write".into())]
            .tool_description
            .contains("guard-only")
    );
}

#[tokio::test]
async fn kernel_v2_serving_catalogue_is_scoped_and_matches_contracts() {
    let dir = tempfile::tempdir().unwrap();
    let (db, actor) = crate::kernel::create_v2_database(
        dir.path().join("v2.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    let registry = Arc::new(registry);
    let server = ExecutorPrototypeStdioServer::new_with_plan_store(
        registry.clone(),
        EngineHandle::KernelV2(db.clone()),
        Caller::authenticated("acct:admin"),
        None,
        ExecutorConstruction {
            plan_store: Some(
                plan_store::PlanStore::open_for_database(db.path())
                    .await
                    .unwrap(),
            ),
            hosted_authority: None,
            pinned_catalogue: None,
            experimental: ExperimentalExecutors::empty(),
            lean: true,
            telemetry: TelemetryConstruction::Disabled,
            transport: telemetry::TelemetryTransport::Stdio,
            deployment_mutation_barrier: None,
        },
    )
    .await
    .unwrap();
    assert!(server
        .contracts
        .contains_key(&("external_import".into(), "attach_from_url".into())));
    assert!(server
        .contracts
        .contains_key(&("records_write".into(), "create_many".into())));
    let v1 = build_ordinary_catalogue(
        &registry,
        crate::mcp::registry::EngineKind::Sqlite,
        false,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    let missing: Vec<_> = v1
        .contracts
        .keys()
        .filter(|key| !server.contracts.contains_key(*key))
        .map(|(executor, operation)| format!("{executor}.{operation}"))
        .collect();
    eprintln!(
        "V1 operations absent from this v2 catalogue (requires explicit disposition): {missing:?}"
    );
    for sql in [
        lean::LEAN_CATALOG_QUERY,
        "SELECT executor, operation, contract_digest FROM catalog_operations ORDER BY executor, operation",
    ] {
        let response = server.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"sql_read","arguments":{"operation":"query_sql","format":"json",
                "arguments":{"sql":sql}}}})).await.unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
        let rows = response["result"]["structuredContent"]["rows"].as_array().unwrap();
        assert!(!rows.is_empty(), "{response}");
        for row in rows {
            let key = (row["executor"].as_str().unwrap().to_owned(), row["operation"].as_str().unwrap().to_owned());
            let contract = &server.contracts[&key];
            if let Some(digest) = row.get("contract_digest") { assert_eq!(digest, &json!(contract.digest)); }
        }
        if sql.contains("contract_digest") { assert_eq!(rows.len(), server.contracts.len()); }
    }
    // A later bare call must not inherit the catalogue from a pooled slot.
    let args = json!({"sql":"SELECT executor FROM catalog_operations ORDER BY executor"});
    let error = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("acct:admin"),
            "query_sql",
            args.clone(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("serving executor catalogue"),
        "{error}"
    );
    // SQL names are resolved by SQLite; a same-named CTE needs no snapshot.
    let result = crate::mcp::kernel_v2::sql::query_sql(&db, &actor,
        json!({"sql":"WITH catalog_operations(executor) AS (SELECT 'local') SELECT executor FROM catalog_operations"})).await.unwrap();
    assert_eq!(result["rows"][0]["executor"], "local");
}

#[test]
fn node_v2_contracts_match_hosted_catalogue_and_validate_shapes() {
    let mut registry = ToolRegistry::new();
    super::super::register_builtin_tools(&mut registry).unwrap();
    super::super::register_surface_tools(&mut registry).unwrap();
    super::super::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    // Use the production hosted pinning entry point, whose hosted flag
    // and engine filtering must agree with node admission.
    let catalogue = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
        &registry,
        &ExperimentalExecutors::empty(),
        super::super::McpSurfaceMode::Executor,
        super::super::registry::EngineKind::KernelV2,
    )
    .unwrap();
    let node = NodeOperationContracts::hosted_kernel_v2().unwrap();
    for operation in [
        "update_record",
        "manage_links.add",
        "attach_text",
        "batch_write",
    ] {
        let hosted = catalogue
            .contracts
            .get(&("records_write".into(), operation.into()))
            .unwrap();
        assert_eq!(
            node.digest("records_write", operation),
            Some(hosted.digest.as_str())
        );
        assert_eq!(
            declared_requires_acceptance("records_write", operation),
            Some(false)
        );
    }
    for sources in [json!([]), json!(["70110000-0000-4000-8000-000000000002"])] {
        assert!(node.validate("records_write", "batch_write", &json!({"operation":"batch_write","arguments":{
            "reason":"body cohort", "sources":sources, "items":[{"op":"update","id":"70110000-0000-4000-8000-000000000001","body_append":"kept"}]
        }}), true).unwrap().is_ok());
    }
    let id = "70110000-0000-4000-8000-000000000001";
    let envelope = |arguments| json!({"operation":"update_record", "arguments":arguments});
    assert!(node
        .validate(
            "records_write",
            "update_record",
            &envelope(
                json!({"id":id,"body_append":"kept","reason":"fixture","response_mode":"full"})
            ),
            true
        )
        .unwrap()
        .is_ok());
    assert!(node
        .validate(
            "records_write",
            "update_record",
            &envelope(
                json!({"id":id,"body_append":"kept","reason":"fixture","response_mode":"brief"})
            ),
            true
        )
        .unwrap()
        .is_err());
    assert!(node
        .validate(
            "records_write",
            "update_record",
            &envelope(json!({"id":id,"owner_id":"other","reason":"fixture"})),
            true
        )
        .unwrap()
        .is_err());
    assert_ne!(
        node.digest("records_write", "update_record"),
        NodeOperationContracts::local()
            .unwrap()
            .digest("records_write", "update_record")
    );
}
