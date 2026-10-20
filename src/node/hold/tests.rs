use super::*;

#[test]
fn only_the_listed_writes_are_holdable_and_update_record_only_for_a_plain_append() {
    let ok = |op: &str, args: Value| is_holdable("records_write", op, &args);
    assert!(ok("create_record", json!({"type":"Document"})));
    assert!(ok("create_many", json!({"records":[]})));
    assert!(ok("manage_links.add", json!({})));
    assert!(ok("attach_text", json!({"text":"x"})));
    assert!(ok(
        "update_record",
        json!({"id":"r","reason":"why","body_append":"more","idempotency_key":"k","sources":[]})
    ));
    // Not an append, or an append with company.
    assert!(!ok(
        "update_record",
        json!({"id":"r","reason":"x","body_set":"y"})
    ));
    assert!(!ok(
        "update_record",
        json!({"id":"r","reason":"x","body_append":"y","summary":"z"})
    ));
    assert!(!ok(
        "update_record",
        json!({"id":"r","reason":"x","body_append":"y","if_body_digest":"d"})
    ));
    assert!(!ok(
        "update_record",
        json!({"ids":["a"],"reason":"x","body_append":"y"})
    ));
    assert!(!ok(
        "update_record",
        json!({"id":"r","reason":"x","body_append":""})
    ));
    // Everything else, and the same name under another executor.
    for op in [
        "manage_links.remove",
        "delete_record",
        "set_intent",
        "correct_record_type",
    ] {
        assert!(!ok(op, json!({})));
    }
    assert!(!is_holdable("records_read", "create_record", &json!({})));
    assert!(!is_holdable(
        "records_write",
        "create_record",
        &json!("not an object")
    ));
}

#[test]
fn node_chosen_ids_are_valid_stable_and_leave_caller_ids_alone() {
    let call = json!({"type":"Document","kind":"note","name":"A note","reason":"r","idempotency_key":"k1"});
    let digest = intent_digest(&call);
    let mut first = call.clone();
    let plan = prepare("create_record", &mut first, "k1", &digest);
    let id = plan.record_id.clone().unwrap();
    assert_eq!(first["id"], json!(id));
    assert_eq!(plan.title.as_deref(), Some("A note"));
    // The engine's id pattern: lowercase UUIDv4, RFC variant.
    let bytes = id.as_bytes();
    assert_eq!(id.len(), 36);
    assert_eq!(bytes[14], b'4');
    assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
    assert_eq!(id, id.to_lowercase());
    // A repeat of the call, fields in another order, rebuilds the same id.
    let reordered = json!({"idempotency_key":"k1","reason":"r","name":"A note","kind":"note","type":"Document"});
    assert_eq!(intent_digest(&reordered), digest);
    let mut again = reordered;
    assert_eq!(
        prepare("create_record", &mut again, "k1", &digest).record_id,
        Some(id.clone())
    );
    // A different key or different content gives a different id.
    let mut other = call.clone();
    assert_ne!(
        prepare("create_record", &mut other, "k2", &digest).record_id,
        Some(id)
    );
    // The caller's own id is kept as it is.
    let mut own = json!({"type":"Document","id":"70110000-0000-4000-8000-000000000001"});
    let digest = intent_digest(&own);
    let plan = prepare("create_record", &mut own, "k1", &digest);
    assert_eq!(
        plan.record_id.as_deref(),
        Some("70110000-0000-4000-8000-000000000001")
    );
    assert_eq!(own["id"], "70110000-0000-4000-8000-000000000001");
}

#[test]
fn create_many_gives_every_item_without_an_id_its_own_and_reports_them_in_order() {
    let mut call = json!({"reason":"r","records":[
        {"type":"Document","kind":"note","name":"First"},
        {"type":"Document","kind":"note","id":"70110000-0000-4000-8000-000000000002"},
        {"type":"Document","kind":"note","name":"Third"},
    ]});
    let digest = intent_digest(&call);
    let plan = prepare("create_many", &mut call, "k", &digest);
    assert_eq!(plan.record_ids.len(), 3);
    assert_eq!(plan.record_ids[1], "70110000-0000-4000-8000-000000000002");
    assert_ne!(plan.record_ids[0], plan.record_ids[2]);
    assert_eq!(call["records"][0]["id"], json!(plan.record_ids[0]));
    assert_eq!(plan.title.as_deref(), Some("First (+2 more)"));
    assert!(plan.record_id.is_none());
}

#[test]
fn other_writes_report_the_record_they_target() {
    let mut append = json!({"id":"r1","body_append":"x","reason":"r"});
    assert_eq!(
        prepare("update_record", &mut append, "k", "d")
            .record_id
            .as_deref(),
        Some("r1")
    );
    let mut link = json!({"source_id":"s","target_id":"t","relationship":"relates_to"});
    assert_eq!(
        prepare("manage_links.add", &mut link, "k", "d")
            .record_id
            .as_deref(),
        Some("s")
    );
    let mut text = json!({"ids":["p"],"text":"x","filename":"a.txt"});
    let plan = prepare("attach_text", &mut text, "k", "d");
    assert_eq!(
        (plan.record_id.as_deref(), plan.title.as_deref()),
        (Some("p"), Some("a.txt"))
    );
}

#[test]
fn read_only_is_recognised_in_every_shape_hosted_uses_and_nothing_else() {
    let tool_result = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retryable":true},"isError":true}}"#;
    let framed = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{
        "http_status":503,"code":"DEPLOYMENT_READ_ONLY","applied":false,
        "upstream_body":{"error":{"code":"DEPLOYMENT_READ_ONLY","applied":false},"applied":false}}}})
    .to_string();
    let top_level = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{
        "upstream_body":{"error_code":"DEPLOYMENT_READ_ONLY","applied":false}}}})
    .to_string();
    for reply in [tool_result, framed.as_str(), top_level.as_str()] {
        assert!(is_deployment_read_only(reply), "{reply}");
    }
    for reply in [
        r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"error_code":"DEPLOYMENT_DRAINING","applied":false},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"error_code":"replay_bound_exceeded","applied":"partial"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"error_code":"DEPLOYMENT_READ_ONLY","applied":true},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"DEPLOYMENT_READ_ONLY"}]}}"#,
        "not json",
    ] {
        assert!(!is_deployment_read_only(reply), "{reply}");
    }
}

/// The node holds a write only because resending it with its key is safe, so
/// every operation it may hold must take `idempotency_key` in the engine's own
/// contract. Checked against the engine's contracts, not a copy of them.
#[test]
fn every_holdable_operation_accepts_idempotency_key_in_its_contract() {
    for (executor, operation) in HOLDABLE {
        let schema =
            crate::mcp::executor_prototype::ordinary_input_schema_for_tests(executor, operation)
                .unwrap_or_else(|| panic!("{executor}.{operation} has no ordinary contract"));
        assert!(
            super::super::gate::schema_accepts_key(&schema),
            "{executor}.{operation} does not accept idempotency_key: {schema}"
        );
    }
    // The check has teeth: an operation that takes no key fails it.
    let schema = crate::mcp::executor_prototype::ordinary_input_schema_for_tests(
        "coordination_write",
        "set_intent",
    )
    .expect("set_intent has an ordinary contract");
    assert!(!super::super::gate::schema_accepts_key(&schema));
}

#[test]
fn references_come_only_from_the_fields_that_hold_them() {
    let a = "70110000-0000-4000-8000-0000000000a1";
    let b = "70110000-0000-4000-8000-0000000000b2";
    let refs = |op: &str, args: Value| references(op, &args);
    assert_eq!(refs("update_record", json!({"id":a,"reason":"r"})), vec![a]);
    assert_eq!(refs("update_record", json!({"record_id":a})), vec![a]);
    assert_eq!(
        refs(
            "manage_links.add",
            json!({"source_id":a,"target_id":b,"note":a})
        ),
        vec![a, b]
    );
    assert_eq!(
        refs("attach_text", json!({"record_id":a,"text":b})),
        vec![a]
    );
    assert_eq!(refs("attach_text", json!({"ids":[a],"text":"t"})), vec![a]);
    assert_eq!(
        refs(
            "create_record",
            json!({"home_id":a,"links":[{"target_id":b,"relationship":"relates_to"}]})
        ),
        vec![a, b]
    );
    assert_eq!(
        refs(
            "create_many",
            json!({"records":[{"home_id":a},{"links":[{"target_id":b},{"target_ref":"x"}]}]})
        ),
        vec![a, b]
    );
    // Free text, whatever it says, is not a reference.
    for (op, args) in [
        (
            "create_record",
            json!({"name":a,"body":a,"summary":b,"reason":a,"facets":{"k":a}}),
        ),
        (
            "update_record",
            json!({"id":"other","reason":a,"body_append":a}),
        ),
        (
            "create_many",
            json!({"reason":a,"records":[{"name":a,"body":b}]}),
        ),
        (
            "attach_text",
            json!({"record_id":"other","text":a,"filename":b,"name":a}),
        ),
        (
            "manage_links.add",
            json!({"source_id":"x","target_id":"y","note":a}),
        ),
    ] {
        assert!(
            !refs(op, args.clone()).contains(&a.to_owned()),
            "{op} {args}"
        );
    }
}
