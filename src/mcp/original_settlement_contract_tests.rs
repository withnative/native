use super::*;
#[test]
fn original_settlement_compiled_contracts_and_qualification_fixture_evidence() {
    // Saved installed-node QUALIFICATION TEST FIXTURE, not a live user journal.
    type FixtureRow = (
        u32,
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static str,
    );
    const FIXTURE: &[FixtureRow] = &[
        (
            7,
            "records_write",
            "update_record",
            "update_record",
            None,
            "4eb0ca37e1d1caa6d8981b65f4f7ed5f26ab6f929c9de0d2304d57635798cc3a",
        ),
        (
            9,
            "records_write",
            "update_record",
            "update_record",
            None,
            "4eb0ca37e1d1caa6d8981b65f4f7ed5f26ab6f929c9de0d2304d57635798cc3a",
        ),
        (
            9,
            "records_write",
            "create_record",
            "create_record",
            None,
            "79c37864d58d7fa2b3e55e2f13cb075658cae8ecd01b2f84b3e8d80b944dfff2",
        ),
        (
            9,
            "records_lifecycle",
            "archive_record",
            "archive_record",
            None,
            "1a5246b61da5afaa2feb85945b918b45780c9b0b9f15a0c32afc88283831c57f",
        ),
        (
            9,
            "records_write",
            "manage_links.add",
            "manage_links",
            Some("add"),
            "fc94ae7c32c84e0a8409fb06b9814ac6f55962835d56b9893f313cfcd758321c",
        ),
        (
            8,
            "records_write",
            "create_record",
            "create_record",
            None,
            "79c37864d58d7fa2b3e55e2f13cb075658cae8ecd01b2f84b3e8d80b944dfff2",
        ),
        (
            9,
            "records_write",
            "manage_links.remove",
            "manage_links",
            Some("remove"),
            "b3df2597d4ea4ce1b0a43a749a85eca5ce6ec9d357394fae6a6d1f08aac7d1dd",
        ),
    ];
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    let default_catalogue = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
        &registry,
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Executor,
        crate::mcp::registry::EngineKind::KernelV2,
    )
    .unwrap();
    crate::mcp::kernel_v2::register_original_settlement_contract_profile(&mut registry).unwrap();
    let catalogue = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
        &registry,
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Executor,
        crate::mcp::registry::EngineKind::KernelV2,
    )
    .unwrap();
    for (v, e, c, s, a, observed) in FIXTURE {
        assert_eq!(
            original_settlement_contract(*v, s, *a, e, c, Some(observed))
                .unwrap()
                .as_deref(),
            Some(*observed),
            "reviewed qualification-fixture digest must remain pinned"
        );
        let compiled = catalogue.contract_digest_for_test(e, c).unwrap();
        let actual = compiled;
        assert!(original_settlement_contract(*v,s,*a,e,c,Some(compiled)).unwrap().is_some(), "current compiled contract {e}/{c}={compiled} requires a reviewed append to the literal table");
        println!(
            "current default catalogue {e}/{c}: compiled={}",
            default_catalogue.contract_digest_for_test(e, c).unwrap()
        );
        println!("qualification-fixture evidence {e}/{c}: observed={observed} compiled={actual} equal={}",actual==*observed);
        assert!(
            original_settlement_contract(*v, s, *a, "other_executor", c, None)
                .unwrap()
                .is_none()
        );
    }
    // Catalog selectors cannot be substituted across the shared native namespace.
    for (source, action, catalog) in [
        ("manage_links", Some("remove"), "manage_links.add"),
        ("manage_links", Some("add"), "manage_links.remove"),
        ("manage_links.add", Some("add"), "manage_links.add"),
    ] {
        assert!(
            original_settlement_contract(9, source, action, "records_write", catalog, None)
                .unwrap()
                .is_none()
        );
    }
    assert!(original_settlement_contract(
        7,
        "archive_record",
        None,
        "records_lifecycle",
        "archive_record",
        None
    )
    .unwrap()
    .is_none());
    assert_ne!(
        original_settlement_contract(
            9,
            "manage_links",
            Some("add"),
            "records_write",
            "manage_links.add",
            None
        )
        .unwrap(),
        original_settlement_contract(
            9,
            "manage_links",
            Some("remove"),
            "records_write",
            "manage_links.remove",
            None
        )
        .unwrap()
    );
}

#[test]
fn original_settlement_variant_nine_create_and_update_use_evidenced_retained_profiles() {
    // Restricted extraction from the consumer's qualification fixture: only
    // version, executor, operation, digest at indices 0, 2 and 6 were read.
    let evidence: Value = serde_json::from_str(include_str!(
        "original_settlement_variant_nine_evidence.json"
    ))
    .unwrap();
    for row in evidence["rows"].as_array().unwrap() {
        assert_eq!(row["version"], 9);
        assert_eq!(row["executor"], "records_write");
        let op = row["operation"].as_str().unwrap();
        let digest = row["contract_digest"].as_str().unwrap();
        assert_eq!(
            original_settlement_contract(9, op, None, "records_write", op, Some(digest))
                .unwrap()
                .as_deref(),
            Some(digest)
        );
    }
    assert!(original_settlement_contract(
        9,
        "create_record",
        None,
        "records_write",
        "create_record",
        Some("f78f2d13c41eb5e481b4bb63e1be105acd03a28c2b3ea3aa164b7f6c49ebe881")
    )
    .unwrap()
    .is_none());
    for source in ["create_record", "update_record"] {
        assert!(original_settlement_contract(
            9,
            source,
            None,
            "records_write",
            source,
            Some(&"a".repeat(64))
        )
        .unwrap()
        .is_none());
    }
}
