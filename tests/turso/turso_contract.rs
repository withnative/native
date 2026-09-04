#![cfg(feature = "turso-tests")]

//! Deterministic Turso-local execution of the shared storage contract.

use crate::contract::{
    scenarios, ContractHarness, DeliveredMessageFixture, TestCaller, TursoHarness,
};
use serde_json::json;
use sha2::Digest;

#[tokio::test]
async fn turso_local_describe_schema_is_normalized_allowlisted_and_owner_gated() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": scenarios::DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID,
                "type": "Collection",
                "kind": "folder",
                "name": "Hidden schema configuration bearer",
                "persistence": "enduring",
                "reason": "Create the governed describe-schema authorization fixture."
            }),
        )
        .await
        .unwrap();
    harness
        .restrict_record_to_account_for_test(
            &database,
            scenarios::DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID,
            "acct:other-schema-reader",
        )
        .await
        .unwrap();
    database
        .runtime_for_test()
        .unwrap()
        .contract_install_describe_schema_fixture_for_test(
            scenarios::DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID,
            scenarios::DESCRIBE_SCHEMA_KIND_ID,
            scenarios::describe_schema_kind_payload(),
            scenarios::DESCRIBE_SCHEMA_GLOBAL_CONFIG_ID,
            scenarios::describe_schema_global_config_data(),
            scenarios::DESCRIBE_SCHEMA_HIDDEN_CONFIG_ID,
            scenarios::describe_schema_hidden_config_data(),
        )
        .await
        .unwrap();
    let owner = harness
        .call(
            &database,
            TestCaller::Local,
            "describe_schema",
            json!({"include_ddl":true}),
        )
        .await
        .unwrap();
    assert_eq!(owner["engine"]["storage_profile"], "turso-local");
    assert_eq!(
        owner["engine"]["ddl_fingerprint"],
        "3b147534372585937388cc3868bce30d3b2bacf837d3378b5cc4792198a37dc9"
    );
    assert_eq!(owner["tables"].as_array().unwrap().len(), 33);
    assert_eq!(owner["ddl_statements"].as_array().unwrap().len(), 87);
    let ddl = owner["ddl_statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|statement| statement.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_uppercase();
    for required in [
        "PRIMARYKEY",
        "REFERENCES",
        "CHECK",
        "DEFAULT",
        "CREATEINDEX",
        "CREATEUNIQUEINDEX",
        "CREATETRIGGER",
        "USING FTS",
    ] {
        assert!(
            ddl.contains(required),
            "complete Turso DDL lacks {required}"
        );
    }
    let facet_values = owner["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|table| table["name"] == "facet_values")
        .unwrap();
    let value_num = facet_values["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|column| column["name"] == "value_num")
        .unwrap();
    assert_eq!(value_num["type"], "REAL");
    assert_eq!(value_num["physical_type"], "REAL");
    assert!(owner["resolved_schema_config"]["shapes"].is_object());
    assert!(owner["kind_registry"]["Document"].is_array());
    let encoded = serde_json::to_string(&owner).unwrap();
    assert!(!encoded.contains("sqlite_schema"));
    assert!(!encoded.contains("_native_turso_runtime"));
    let repeated = harness
        .call(&database, TestCaller::Local, "describe_schema", json!({}))
        .await
        .unwrap();
    assert_eq!(repeated["tables"], owner["tables"]);
    assert_eq!(repeated["kind_registry"], owner["kind_registry"]);
    assert_eq!(
        repeated["engine"]["ddl_fingerprint"],
        owner["engine"]["ddl_fingerprint"]
    );

    let member = harness
        .call(
            &database,
            TestCaller::member("acct:schema-reader"),
            "describe_schema",
            json!({}),
        )
        .await
        .unwrap();
    scenarios::assert_describe_schema_shared_contract(&owner, &member);
    assert!(member["tables"]
        .as_array()
        .unwrap()
        .iter()
        .all(|table| table["name"] != "meta_events"));
    assert!(member.get("ddl_statements").is_none());
    let denied = harness
        .call(
            &database,
            TestCaller::member("acct:schema-reader"),
            "describe_schema",
            json!({"include_ddl":true}),
        )
        .await
        .unwrap_err();
    assert!(denied.to_string().contains("database owner host role"));
    let invalid = harness
        .call(
            &database,
            TestCaller::Local,
            "describe_schema",
            json!({"unknown":true}),
        )
        .await
        .unwrap_err();
    assert!(invalid
        .to_string()
        .contains("invalid arguments for describe_schema"));
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;

    let index_drift = harness.fresh_logical_database().await.unwrap();
    index_drift
        .runtime_for_test()
        .unwrap()
        .contract_drop_describe_schema_index_for_test()
        .await
        .unwrap();
    let index_error = harness
        .call(
            &index_drift,
            TestCaller::Local,
            "describe_schema",
            json!({}),
        )
        .await
        .unwrap_err();
    assert!(
        index_error
            .to_string()
            .contains("installed Turso-local DDL differs from the frozen compiled contract"),
        "{index_error}"
    );
    harness.close(&index_drift).await;

    let trigger_drift = harness.fresh_logical_database().await.unwrap();
    trigger_drift
        .runtime_for_test()
        .unwrap()
        .contract_drop_describe_schema_trigger_for_test()
        .await
        .unwrap();
    let trigger_error = harness
        .call(
            &trigger_drift,
            TestCaller::Local,
            "describe_schema",
            json!({}),
        )
        .await
        .unwrap_err();
    assert!(
        trigger_error
            .to_string()
            .contains("installed Turso-local DDL differs from the frozen compiled contract"),
        "{trigger_error}"
    );
    harness.close(&trigger_drift).await;
}

#[tokio::test]
async fn turso_local_record_lifecycle_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    turso_record_lifecycle_and_references(&harness, &database)
        .await
        .unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_visibility_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::visibility(&harness, &database).await.unwrap();
    // Owned by `scenarios::` in tests/contract/ — this id must match the
    // record that scenario creates, not a turso-local one.
    let allowed_history = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-00000000000d" }),
        )
        .await
        .unwrap();
    assert_eq!(
        allowed_history["events"].as_array().map(|events| events
            .iter()
            .map(|event| event["type"].as_str())
            .collect::<Vec<_>>()),
        Some(vec![Some("record.created"), Some("facet.set")])
    );
    let denied_history = harness
        .call(
            &database,
            TestCaller::member("acct:cara"),
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-00000000000d" }),
        )
        .await
        .unwrap_err();
    // The shipped runtime deliberately makes denied reads indistinguishable
    // from absence; the miniature returned an observable empty event list.
    assert!(
        denied_history.to_string().contains("does not exist"),
        "{denied_history}"
    );
    let denied_mutation = harness
        .call(
            &database,
            TestCaller::member("acct:bea"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-00000000000d",
                "body": "unauthorized mutation",
                "reason": "Prove a recipient cannot mutate the sender's Message."
            }),
        )
        .await
        .unwrap_err();
    assert!(
        denied_mutation.to_string().contains("does not exist"),
        "{denied_mutation}"
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_link_mutation_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    // Preserve the known relationship gap as executable production truth.
    // The removed miniature accepted these mutations and therefore overstated
    // parity; the shipped runtime fails closed until that slice is implemented.
    let error = scenarios::link_mutation(&harness, &database)
        .await
        .expect_err("generic relationships are not yet in the production Turso slice");
    assert!(
        error
            .to_string()
            .contains("relationship-owned link mutation"),
        "{error}"
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_authoritative_replay_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    // This portable scenario begins with the same unsupported relationship
    // mutation. Dedicated tests below still exercise successful production
    // replay, gap detection and corrupt-event divergence.
    let error = scenarios::replay(&harness, &database)
        .await
        .expect_err("generic relationships are not yet in the production Turso slice");
    assert!(
        error
            .to_string()
            .contains("relationship-owned link mutation"),
        "{error}"
    );
    // Owned by `scenarios::` in tests/contract/ — this id must match the
    // record that scenario creates, not a turso-local one.
    let source = harness
        .call(
            &database,
            TestCaller::Local,
            "get_record",
            json!({"ids":["c07a0000-0000-4000-8000-00000000000f"]}),
        )
        .await
        .unwrap();
    assert_eq!(
        source["records"][0],
        json!({"id":"c07a0000-0000-4000-8000-00000000000f","status":"not_found"}),
        "the failed production create must not leave a projected source record"
    );
    assert_eq!(
        harness
            .content_event_count_for_test(&database, "c07a0000-0000-4000-8000-00000000000f")
            .await
            .unwrap(),
        0,
        "the failed production create must roll back its authoritative event"
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_comment_event_shape_replays_equivalently() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-002000000001","type":"Document","kind":"note","name":"Bearer",
                "reason":"Create the comment bearer fixture."
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-002000000003","type":"Annotation","kind":"comment","name":"Root","body":"Question","lifecycle":"open",
                "links":[{"target_id":"70250000-0000-4000-8000-002000000001","relationship":"part_of"}],
                "reason":"Create the root comment fixture."
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-002000000002","type":"Annotation","kind":"comment","name":"Reply","body":"Answer",
                "links":[{"target_id":"70250000-0000-4000-8000-002000000003","relationship":"part_of"}],
                "reason":"Create the reply comment fixture."
            }),
        )
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "update_record",
            json!({"id":"70250000-0000-4000-8000-002000000003","lifecycle":"resolved","summary":"Settled","reason":"Resolve the comment fixture."}),
        )
        .await
        .unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_replay_rejects_a_missing_intermediate_event() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::record_lifecycle(&harness, &database)
        .await
        .unwrap();
    harness.delete_event_for_test(&database, 4).await.unwrap();
    let error = harness
        .assert_replay_equivalent(&database)
        .await
        .unwrap_err();
    // Production replay reports the projection mismatch rather than exposing
    // the miniature's record-id/payload validation wording.
    assert!(
        error.to_string().contains("positions are not gapless"),
        "{error}"
    );
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_replay_rejects_a_corrupt_event() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::record_lifecycle(&harness, &database)
        .await
        .unwrap();
    let history = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-000000000010" }),
        )
        .await
        .unwrap();
    let created_local_seq = history["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "record.created")
        .and_then(|event| event["local_seq"].as_i64())
        .unwrap();
    harness
        .corrupt_event_for_test(&database, created_local_seq)
        .await
        .unwrap();
    let error = harness
        .assert_replay_equivalent(&database)
        .await
        .unwrap_err();
    // The production replay fold now rejects the malformed creation at its
    // first invalid field, before it can reach the final projection comparison.
    assert!(
        error.to_string().contains("cannot apply record.created")
            && error.to_string().contains("requires a kind"),
        "{error}"
    );
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_replay_and_write_share_one_admission_boundary() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::record_lifecycle(&harness, &database)
        .await
        .unwrap();

    let replay = harness.assert_replay_equivalent(&database);
    // Owned by `scenarios::` in tests/contract/ — this id must match the
    // record that scenario creates, not a turso-local one.
    let update = harness.call(
        &database,
        TestCaller::Local,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-000000000008",
            "body": "committed before or after one consistent replay",
            "if_body_digest": hex::encode(sha2::Sha256::digest(b"created")),
            "reason": "Exercise replay/write serialization."
        }),
    );
    let (replay, update) = tokio::join!(replay, update);
    replay.unwrap();
    update.unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_guarded_write_race_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::guarded_write_race(&harness, &database)
        .await
        .unwrap();
    turso_local_delete_guarded_race_has_one_tombstone(&harness).await;
    turso_local_message_delete_withdraws_candidates_and_retains_adjunct_state(&harness).await;
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

async fn turso_local_message_delete_withdraws_candidates_and_retains_adjunct_state(
    harness: &TursoHarness,
) {
    let database = harness.fresh_logical_database().await.unwrap();
    let message_id = "70250000-0000-4000-8000-002000000006";
    let target_id = "70250000-0000-4000-8000-002000000007";
    for (id, record_type, kind) in [
        ("70250000-0000-4000-8000-002000000005", "Entity", "person"),
        ("70250000-0000-4000-8000-002000000004", "Entity", "person"),
        (target_id, "Document", "note"),
    ] {
        harness
            .call(
                &database,
                TestCaller::Local,
                "create_record",
                json!({"id":id,"type":record_type,"kind":kind,"reason":"Create delete adjunct fixture."}),
            )
            .await
            .unwrap();
    }
    harness
        .provision_member(
            &database,
            "70250000-0000-4000-8000-002000000005",
            "acct:delete-adjunct-sender",
            "native/delete-adjunct-sender",
        )
        .await
        .unwrap();
    harness
        .provision_member(
            &database,
            "70250000-0000-4000-8000-002000000004",
            "acct:recipient",
            "native/delete-adjunct-recipient",
        )
        .await
        .unwrap();
    harness
        .deliver_message_fixture(
            &database,
            TestCaller::member("acct:delete-adjunct-sender"),
            DeliveredMessageFixture {
                id: message_id,
                name: "Delete adjunct message",
                body: "Message candidate must be withdrawn.",
                addressed_to: &["70250000-0000-4000-8000-002000000004"],
                idempotency_key: "contract:delete-adjunct-delivery",
            },
        )
        .await
        .unwrap();
    harness
        .seed_delete_adjunct_state_for_test(&database, message_id, target_id)
        .await
        .unwrap();
    harness
        .call(
            &database,
            TestCaller::Local,
            "delete_record",
            json!({"id":message_id,"reason":"Withdraw candidate while retaining adjunct state."}),
        )
        .await
        .unwrap();
    let state = harness
        .delete_adjunct_state_for_test(&database, message_id)
        .await
        .unwrap();
    assert_eq!(state["policy_entries"], 1);
    assert_eq!(state["links"], 1);
    assert_eq!(state["status"], "withdrawn");
    assert_eq!(state["action"], "withdrawn");
    assert_eq!(state["source_event_type"], "record.deleted");
    assert_eq!(state["source_event_id"], state["deletion_event_id"]);
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

async fn turso_local_delete_guarded_race_has_one_tombstone(harness: &TursoHarness) {
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "70250000-0000-4000-8000-002000000008";
    harness
        .call(
            &database,
            TestCaller::Local,
            "create_record",
            json!({"id":id,"type":"Document","kind":"note","reason":"Create guarded delete fixture."}),
        )
        .await
        .unwrap();
    let history = harness
        .call(
            &database,
            TestCaller::Local,
            "get_history",
            json!({"record_id":id}),
        )
        .await
        .unwrap();
    let revision = history["events"][0]["local_seq"].as_i64().unwrap();
    let left = harness.call(
        &database,
        TestCaller::Local,
        "delete_record",
        json!({"id":id,"if_content_seq":revision,"reason":"Race guarded deletion."}),
    );
    let right = harness.call(
        &database,
        TestCaller::Local,
        "delete_record",
        json!({"id":id,"if_content_seq":revision,"reason":"Race guarded deletion."}),
    );
    let (left, right) = tokio::join!(left, right);
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let loser = left.err().or_else(|| right.err()).unwrap().to_string();
    assert!(
        loser.contains("tombstoned") || loser.contains("revision conflict"),
        "{loser}"
    );
    assert_eq!(
        harness
            .content_event_count_for_test(&database, id)
            .await
            .unwrap(),
        2
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_null_body_digest_guard_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::null_body_digest_guard(&harness, &database)
        .await
        .unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_timestamp_precondition_contract() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    scenarios::timestamp_precondition(&harness, &database)
        .await
        .unwrap();
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_logical_database_isolation_contract() {
    let harness = TursoHarness::new();
    scenarios::logical_database_isolation(&harness)
        .await
        .unwrap();
}

async fn turso_record_lifecycle_and_references(
    harness: &TursoHarness,
    database: &<TursoHarness as ContractHarness>::Database,
) -> native_ce::Result<()> {
    scenarios::record_lifecycle(harness, database).await?;
    scenarios::record_reference_resolution(harness, database).await?;
    let plan = harness
        .record_reference_query_plan_for_test(database)
        .await?
        .join("\n");
    assert!(
        plan.contains("SEARCH") && plan.contains("id>=? AND id<?"),
        "the Turso prefix range must use the record primary-key path: {plan}"
    );
    Ok(())
}
