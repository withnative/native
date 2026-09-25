#![cfg(feature = "turso-tests")]

//! Deterministic Turso-local execution of the shared storage contract.

use crate::contract::{
    scenarios, ContractHarness, DeliveredMessageFixture, TestCaller, TursoHarness,
};
use native_ce::mentions::{scan_body, MENTION_PARSER_VERSION};
use serde_json::{json, Value};
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
        "cb602bcd40071ca3e66a1b3ca41f4f3fafa0024d2fd448204b72d697f4bcb9c9"
    );
    assert_eq!(owner["tables"].as_array().unwrap().len(), 34);
    assert_eq!(owner["ddl_statements"].as_array().unwrap().len(), 90);
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
    let encoded = serde_json::to_string(&owner).unwrap();
    assert!(!encoded.contains("sqlite_schema"));
    assert!(!encoded.contains("_native_turso_runtime"));
    let repeated = harness
        .call(&database, TestCaller::Local, "describe_schema", json!({}))
        .await
        .unwrap();
    assert_eq!(repeated["tables"], owner["tables"]);
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
    // The governed record-shape half of the same fixture now lives in
    // preview_record_shape, the tool that owns effective write shape.
    let shape_arguments = json!({"type":"Document","kind":scenarios::DESCRIBE_SCHEMA_KIND_TOKEN});
    let owner_shape = harness
        .call(
            &database,
            TestCaller::Local,
            "preview_record_shape",
            shape_arguments.clone(),
        )
        .await
        .unwrap();
    let member_shape = harness
        .call(
            &database,
            TestCaller::member("acct:schema-reader"),
            "preview_record_shape",
            shape_arguments,
        )
        .await
        .unwrap();
    scenarios::assert_record_shape_shared_contract(&owner_shape, &member_shape);
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

// ---------------------------------------------------------------------------
// record_mentions current-state projection (plan a9392df slice 4).
//
// The Turso adapter serves no product read for `record_mentions`, so these
// tests read the folded rows through a raw local connection. Every test also
// asserts replay equivalence, which snapshots the same table and folds the
// captured event log back through the Turso projector.
// ---------------------------------------------------------------------------

const MENTION_BODY_A: &str = "See abc1234 and [[My Note]] end.";
const MENTION_BODY_B: &str = "Now https://n8v.to/def5678 only.";

async fn raw_local_connection(
    database: &<TursoHarness as ContractHarness>::Database,
) -> (turso::Database, turso::Connection) {
    let path = database.runtime_for_test().unwrap().path().to_path_buf();
    let raw = turso::Builder::new_local(path.to_str().unwrap())
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    (raw, connection)
}

async fn mention_rows(
    database: &<TursoHarness as ContractHarness>::Database,
    source_id: &str,
) -> Vec<Value> {
    let (raw, connection) = raw_local_connection(database).await;
    let mut rows = connection
        .query(
            "SELECT occurrence_ix, source_event_seq, span_start, span_end, \
             authored_reference, lookup_key, form, parser_version \
             FROM record_mentions WHERE source_id=?1 ORDER BY occurrence_ix",
            [source_id.to_string()],
        )
        .await
        .unwrap();
    let mut values = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        values.push(json!({
            "occurrence_ix": row.get::<i64>(0).unwrap(),
            "source_event_seq": row.get::<i64>(1).unwrap(),
            "span_start": row.get::<i64>(2).unwrap(),
            "span_end": row.get::<i64>(3).unwrap(),
            "authored_reference": row.get::<String>(4).unwrap(),
            "lookup_key": row.get::<String>(5).unwrap(),
            "form": row.get::<String>(6).unwrap(),
            "parser_version": row.get::<i64>(7).unwrap(),
        }));
    }
    drop(rows);
    drop(connection);
    drop(raw);
    values
}

async fn stored_body(
    database: &<TursoHarness as ContractHarness>::Database,
    record_id: &str,
) -> Option<String> {
    let (raw, connection) = raw_local_connection(database).await;
    let mut rows = connection
        .query(
            "SELECT body FROM records WHERE id=?1",
            [record_id.to_string()],
        )
        .await
        .unwrap();
    let value = rows
        .next()
        .await
        .unwrap()
        .and_then(|row| row.get::<Option<String>>(0).unwrap());
    drop(rows);
    drop(connection);
    drop(raw);
    value
}

async fn latest_content_seq(
    database: &<TursoHarness as ContractHarness>::Database,
    record_id: &str,
) -> i64 {
    let (raw, connection) = raw_local_connection(database).await;
    let mut rows = connection
        .query(
            "SELECT MAX(seq) FROM content_events WHERE record_id=?1",
            [record_id.to_string()],
        )
        .await
        .unwrap();
    let value = rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap();
    drop(rows);
    drop(connection);
    drop(raw);
    value
}

fn expected_mention_rows(source_event_seq: i64, body: &str) -> Vec<Value> {
    scan_body(body)
        .iter()
        .enumerate()
        .map(|(occurrence_ix, occurrence)| {
            json!({
                "occurrence_ix": occurrence_ix as i64,
                "source_event_seq": source_event_seq,
                "span_start": occurrence.span_start as i64,
                "span_end": occurrence.span_end as i64,
                "authored_reference": occurrence.authored_reference.clone(),
                "lookup_key": occurrence.lookup_key.clone(),
                "form": occurrence.form.as_str(),
                "parser_version": MENTION_PARSER_VERSION,
            })
        })
        .collect()
}

async fn create_mention_record(
    harness: &TursoHarness,
    database: &<TursoHarness as ContractHarness>::Database,
    id: &str,
    body: Value,
) {
    harness
        .call(
            database,
            TestCaller::Local,
            "create_record",
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": "mention fold",
                "body": body,
                "reason": "Fold current-body record mentions."
            }),
        )
        .await
        .unwrap();
}

async fn update_mention_record(
    harness: &TursoHarness,
    database: &<TursoHarness as ContractHarness>::Database,
    id: &str,
    fields: Value,
) {
    let mut arguments = fields.as_object().unwrap().clone();
    if arguments.contains_key("body") {
        // A whole-body replacement of an already-non-empty body is guarded.
        let current = stored_body(database, id).await;
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            current.as_deref().unwrap_or("").as_bytes(),
        ));
        arguments.insert("if_body_digest".into(), json!(digest));
    }
    arguments.insert("id".into(), json!(id));
    arguments.insert("reason".into(), json!("Update the mention fixture."));
    harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            Value::Object(arguments),
        )
        .await
        .unwrap();
}

async fn delete_mention_record(
    harness: &TursoHarness,
    database: &<TursoHarness as ContractHarness>::Database,
    id: &str,
) {
    harness
        .call(
            database,
            TestCaller::Local,
            "delete_record",
            json!({"id": id, "reason": "Remove the mention fixture."}),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn turso_local_create_folds_current_body_mentions() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000001";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    let seq = latest_content_seq(&database, id).await;
    let rows = mention_rows(&database, id).await;
    assert_eq!(rows, expected_mention_rows(seq, MENTION_BODY_A));
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|row| row["parser_version"] == 1));
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_create_without_mentions_leaves_no_rows() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    for (id, body) in [
        ("9f000000-0000-4000-8000-000000000002", json!(null)),
        ("9f000000-0000-4000-8000-000000000003", json!("")),
        (
            "9f000000-0000-4000-8000-000000000004",
            json!("plain prose without references"),
        ),
    ] {
        create_mention_record(&harness, &database, id, body).await;
        assert!(mention_rows(&database, id).await.is_empty());
    }
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_body_update_replaces_mentions_with_new_provenance() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000005";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    update_mention_record(&harness, &database, id, json!({"body": MENTION_BODY_B})).await;
    let seq = latest_content_seq(&database, id).await;
    let rows = mention_rows(&database, id).await;
    assert_eq!(rows, expected_mention_rows(seq, MENTION_BODY_B));
    assert_eq!(rows.len(), 1, "{rows:?}");
    // Old occurrences are absent: replacement, never accumulation.
    assert!(!rows
        .iter()
        .any(|row| row["authored_reference"] == "abc1234"));
    assert!(!rows
        .iter()
        .any(|row| row["authored_reference"] == "My Note"));
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_metadata_only_update_preserves_mention_provenance() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000006";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    let before_seq = latest_content_seq(&database, id).await;
    let before = mention_rows(&database, id).await;
    assert_eq!(before.len(), 2);
    update_mention_record(
        &harness,
        &database,
        id,
        json!({"name": "renamed", "summary": "touched"}),
    )
    .await;
    // A new event exists, but the body it carries is unchanged.
    assert!(latest_content_seq(&database, id).await > before_seq);
    assert_eq!(mention_rows(&database, id).await, before);
    assert_eq!(
        mention_rows(&database, id).await,
        expected_mention_rows(before_seq, MENTION_BODY_A)
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_null_or_empty_body_update_leaves_no_mentions() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000007";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    assert_eq!(mention_rows(&database, id).await.len(), 2);
    update_mention_record(&harness, &database, id, json!({"body": null})).await;
    assert!(mention_rows(&database, id).await.is_empty());
    // Re-adding a body folds it again under the re-add event's sequence.
    update_mention_record(&harness, &database, id, json!({"body": MENTION_BODY_B})).await;
    let seq = latest_content_seq(&database, id).await;
    assert_eq!(
        mention_rows(&database, id).await,
        expected_mention_rows(seq, MENTION_BODY_B)
    );
    update_mention_record(&harness, &database, id, json!({"body": ""})).await;
    assert!(mention_rows(&database, id).await.is_empty());
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_delete_removes_mentions() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000008";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    assert_eq!(mention_rows(&database, id).await.len(), 2);
    delete_mention_record(&harness, &database, id).await;
    assert!(mention_rows(&database, id).await.is_empty());
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

/// The product `update_record` handler refuses a non-string body, so this
/// reaches the projector through the raw append seam. `records.body` is TEXT,
/// so the fold must scan the value's JSON rendering rather than skip the
/// update, or a string->non-string transition would drift between live
/// folding, the migration backfill (which reads the stored column) and replay.
#[tokio::test]
async fn turso_local_non_string_body_update_scans_stored_json_text() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000009";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    assert_eq!(mention_rows(&database, id).await.len(), 2);
    for (value, stored) in [
        (
            json!({"note": "keep abc1234 in mind"}),
            r#"{"note":"keep abc1234 in mind"}"#,
        ),
        (
            json!(["deadbee and [[Wiki Name]]"]),
            r#"["deadbee and [[Wiki Name]]"]"#,
        ),
    ] {
        harness
            .append_record_updated_for_test(&database, id, json!({"body": value}))
            .await
            .unwrap();
        assert_eq!(stored_body(&database, id).await.as_deref(), Some(stored));
        let seq = latest_content_seq(&database, id).await;
        assert_eq!(
            mention_rows(&database, id).await,
            expected_mention_rows(seq, stored)
        );
    }
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

/// `coerce_body` renders booleans and numbers as the `TEXT` affinity would, so
/// a boolean or numeric replacement must fold that stored text (no references,
/// no rows) rather than leaving the previous body's rows in place.
#[tokio::test]
async fn turso_local_boolean_and_numeric_bodies_replace_mentions() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000017";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    assert_eq!(mention_rows(&database, id).await.len(), 2);
    for (value, stored) in [(json!(true), "1"), (json!(0), "0"), (json!(42), "42")] {
        harness
            .append_record_updated_for_test(&database, id, json!({"body": value}))
            .await
            .unwrap();
        assert_eq!(stored_body(&database, id).await.as_deref(), Some(stored));
        assert!(mention_rows(&database, id).await.is_empty());
    }
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

/// A body write that fails after its handler but before commit must roll back
/// its mention replacement with the rest of the transaction, leaving the
/// previous body's rows and provenance intact.
#[tokio::test]
async fn turso_local_failed_body_write_rolls_back_mention_rows() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let id = "9f000000-0000-4000-8000-000000000018";
    create_mention_record(&harness, &database, id, json!(MENTION_BODY_A)).await;
    let seq = latest_content_seq(&database, id).await;
    let before = mention_rows(&database, id).await;
    assert_eq!(before, expected_mention_rows(seq, MENTION_BODY_A));

    database
        .runtime_for_test()
        .unwrap()
        .contract_arm_post_handler_write_failure("update_record");
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        MENTION_BODY_A.as_bytes(),
    ));
    let error = harness
        .call(
            &database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": id,
                "body": MENTION_BODY_B,
                "if_body_digest": digest,
                "reason": "Force post-handler mention rollback."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("forced update_record failure"), "{error}");
    assert_eq!(mention_rows(&database, id).await, before);
    assert_eq!(
        mention_rows(&database, id).await,
        expected_mention_rows(seq, MENTION_BODY_A)
    );
    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}

#[tokio::test]
async fn turso_local_mentions_replay_equivalent_after_mixed_history() {
    let harness = TursoHarness::new();
    let database = harness.fresh_logical_database().await.unwrap();
    let kept = "9f000000-0000-4000-8000-000000000011";
    let replaced = "9f000000-0000-4000-8000-000000000012";
    let renamed = "9f000000-0000-4000-8000-000000000013";
    let emptied = "9f000000-0000-4000-8000-000000000014";
    let tombstoned = "9f000000-0000-4000-8000-000000000015";
    let plain = "9f000000-0000-4000-8000-000000000016";

    create_mention_record(&harness, &database, kept, json!(MENTION_BODY_A)).await;
    create_mention_record(&harness, &database, replaced, json!(MENTION_BODY_A)).await;
    update_mention_record(
        &harness,
        &database,
        replaced,
        json!({"body": MENTION_BODY_B}),
    )
    .await;
    create_mention_record(&harness, &database, renamed, json!(MENTION_BODY_B)).await;
    update_mention_record(
        &harness,
        &database,
        renamed,
        json!({"summary": "metadata only"}),
    )
    .await;
    create_mention_record(&harness, &database, emptied, json!(MENTION_BODY_A)).await;
    update_mention_record(&harness, &database, emptied, json!({"body": null})).await;
    create_mention_record(&harness, &database, tombstoned, json!(MENTION_BODY_A)).await;
    delete_mention_record(&harness, &database, tombstoned).await;
    create_mention_record(&harness, &database, plain, json!("no references here")).await;

    assert_eq!(mention_rows(&database, kept).await.len(), 2);
    assert_eq!(mention_rows(&database, replaced).await.len(), 1);
    assert_eq!(mention_rows(&database, renamed).await.len(), 1);
    assert!(mention_rows(&database, emptied).await.is_empty());
    assert!(mention_rows(&database, tombstoned).await.is_empty());
    assert!(mention_rows(&database, plain).await.is_empty());

    harness.assert_replay_equivalent(&database).await.unwrap();
    harness.close(&database).await;
}
