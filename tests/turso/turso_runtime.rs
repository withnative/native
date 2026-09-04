#![cfg(feature = "turso-tests")]

use native_ce::create_database;
use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, Caller, EngineHandle, ToolRegistry,
};
use native_ce::turso_local::{
    register_turso_local_tools, TursoLocalRuntimeConfig, TURSO_LOCAL_RUNTIME_CONFIG_FORMAT,
};
use serde_json::{json, Value};
use sha2::Digest as _;

fn config(directory: &std::path::Path, logical_database_id: &str) -> TursoLocalRuntimeConfig {
    TursoLocalRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format":"native.turso-local-runtime.v1",
            "logical_database_id":logical_database_id,
            "data_directory":directory,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_turso_local_tools(&mut registry).unwrap();
    registry
}

fn spawn_local_call(
    db: native_ce::turso_local::TursoLocalDb,
    tool: &'static str,
    arguments: serde_json::Value,
) -> tokio::task::JoinHandle<native_ce::Result<serde_json::Value>> {
    tokio::spawn(async move {
        registry()
            .call_engine(
                EngineHandle::TursoLocal(db),
                Caller::local(),
                tool,
                arguments,
            )
            .await
    })
}

/// SHA-256 of a known body, for the guarded whole-body write contract.
fn body_digest(body: &str) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(body.as_bytes()))
}

#[tokio::test]
async fn production_record_routes_return_exact_stable_errors() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-stable-record-errors")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db);
    let caller = Caller::local();
    for (tool, arguments, expected) in [
        (
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000051","type":"Document","kind":"note","reason":"  "}),
            "create_record: 'reason' must not be blank",
        ),
        (
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000053","reason":""}),
            "update_record: 'reason' must not be blank",
        ),
        (
            "archive_record",
            json!({"id":"70250000-0000-4000-8000-005000000053","reason":"\t"}),
            "archive_record: 'reason' must not be blank",
        ),
        (
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000053","reason":"\n"}),
            "delete_record: 'reason' must not be blank",
        ),
        (
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000053"}),
            "get_history: record 70250000-0000-4000-8000-005000000053 does not exist",
        ),
        (
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000053"],"include_interpretation":true}),
            "turso-local operation 'get_record interpretation projection' is unsupported by the qualified domain boundary",
        ),
    ] {
        let error = registry
            .call_engine(engine.clone(), caller.clone(), tool, arguments)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, expected, "{tool}");
    }

    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000052","type":"Document","kind":"note","reason":"Create terminal deletion fixture."}),
        )
        .await
        .unwrap();
    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000052","reason":"Tombstone the stable-error fixture."}),
        )
        .await
        .unwrap();
    let terminal = registry
        .call_engine(
            engine,
            caller,
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000052","reason":"Retry the terminal mutation."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        terminal,
        "cannot apply record.deleted: record 70250000-0000-4000-8000-005000000052 is deleted (tombstoned)"
    );
}

#[tokio::test]
async fn governed_work_kinds_default_and_validate_complete_prospective_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let runtime_config = config(directory.path(), "runtime-work-kind-lifecycle");
    corrupt_runtime(
        &runtime_config,
        "INSERT INTO vocabulary_values(id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of) SELECT 'vv:test:kind:WorkItem:future',vocabulary_id,'future','Future test work kind','active',999.0,'open',metadata,NULL FROM vocabulary_values WHERE id='vv:voc:kind:WorkItem:epic' UNION ALL SELECT 'vv:test:kind:WorkItem:initiative',vocabulary_id,'initiative','Deprecated epic alias','deprecated',998.0,'open',metadata,id FROM vocabulary_values WHERE id='vv:voc:kind:WorkItem:epic'",
    )
    .await;
    let db = runtime_config.open().await.unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db);
    let caller = Caller::local();

    let defaulted_epic = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000016",
                "type": "WorkItem",
                "kind": "epic",
                "reason": "Create an epic with its governed default."
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        defaulted_epic["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    let defaulted_alias = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000039",
                "type": "WorkItem",
                "kind": "initiative",
                "reason": "Canonicalize an admitted epic alias before lifecycle governance."
            }),
        )
        .await
        .unwrap();
    assert_eq!(defaulted_alias["kind"], "epic");
    assert_eq!(
        defaulted_alias["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    let invalid_epic = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000035",
                "type": "WorkItem",
                "kind": "epic",
                "lifecycle": "bespoke",
                "reason": "Reject an invalid epic lifecycle."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        invalid_epic.contains("not an active member"),
        "{invalid_epic}"
    );

    let future = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000036",
                "type": "WorkItem",
                "kind": "future",
                "reason": "Create an admitted future work kind without a default."
            }),
        )
        .await
        .unwrap();
    assert_eq!(future["lifecycle_interpretation"]["status"], "absent");

    let ungoverned_lifecycle = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000037",
                "type": "WorkItem",
                "kind": "future",
                "lifecycle": "open",
                "reason": "Reject lifecycle without an effective binding."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        ungoverned_lifecycle.contains("lifecycle is not governed"),
        "{ungoverned_lifecycle}"
    );

    let missing_on_entry = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000036",
                "kind": "epic",
                "reason": "Reject entry into a required lifecycle shape without a repair."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        missing_on_entry.contains("missing required facet 'lifecycle'"),
        "{missing_on_entry}"
    );

    let repaired_entry = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000036",
                "kind": "epic",
                "lifecycle": "open",
                "reason": "Enter the epic kind with the required lifecycle in one batch."
            }),
        )
        .await
        .unwrap();
    assert_eq!(repaired_entry["kind"], "epic");
    assert_eq!(
        repaired_entry["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    let preserved_into_ungoverned = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000016",
                "kind": "future",
                "reason": "Reject preserving lifecycle into an ungoverned kind."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        preserved_into_ungoverned.contains("lifecycle is not governed"),
        "{preserved_into_ungoverned}"
    );

    let cleared_into_ungoverned = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000016",
                "kind": "future",
                "lifecycle": null,
                "reason": "Leave governed work status while clearing it in one batch."
            }),
        )
        .await
        .unwrap();
    assert_eq!(cleared_into_ungoverned["kind"], "future");
    assert_eq!(
        cleared_into_ungoverned["lifecycle_interpretation"]["status"],
        "absent"
    );

    let task = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-005000000038",
                "type": "WorkItem",
                "kind": "task",
                "reason": "Create a defaulted task for governed kind transitions."
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        task["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    for kind in ["epic", "task"] {
        let transitioned = registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": "70250000-0000-4000-8000-005000000038",
                    "kind": kind,
                    "reason": "Preserve valid work status across governed work kinds."
                }),
            )
            .await
            .unwrap();
        assert_eq!(transitioned["kind"], kind);
        assert_eq!(
            transitioned["lifecycle_interpretation"]["value"]["canonical"],
            "open"
        );
    }
}

#[tokio::test]
async fn suggestion_lifecycle_authoring_and_repair_match_the_sqlite_writer() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-suggestion-lifecycle")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    let caller = Caller::local();

    let missing = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000014",
                "type": "Annotation",
                "kind": "suggestion",
                "facets": { "proposal.precondition": "none" },
                "reason": "Reject a missing lifecycle."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        missing.contains("must be authored with lifecycle 'open'"),
        "{missing}"
    );

    for (index, (id, lifecycle)) in [("terminal", "accepted"), ("invalid", "opne")]
        .into_iter()
        .enumerate()
    {
        let error = registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "id": format!("5a99e571-0000-4000-8000-{:012}", 400 + index),
                    "type": "Annotation",
                    "kind": "suggestion",
                    "lifecycle": lifecycle,
                    "facets": { "proposal.precondition": "none" },
                    "reason": "Reject a non-open suggestion lifecycle."
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("terminal transitions") || error.contains("active member"),
            "{id}: {error}"
        );
    }

    let create_conflict = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000011",
                "type": "Annotation",
                "kind": "suggestion",
                "facets": {
                    "lifecycle": "accepted",
                    "proposal.precondition": "none"
                },
                "reason": "Refuse the facet carrier."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(create_conflict.contains("spine facet"), "{create_conflict}");

    let created = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000015",
                "type": "Annotation",
                "kind": "suggestion",
                "lifecycle": "open",
                "facets": { "proposal.precondition": "none" },
                "links": [{
                    "target_id": native_ce::schema::UNFILED_RECORD_ID,
                    "relationship": "part_of"
                }],
                "reason": "Author through the top-level carrier."
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        created["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    for lifecycle in [Value::Null, json!("accepted"), json!("opne")] {
        let error = registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": "5a99e571-0000-4000-8000-000000000015",
                    "lifecycle": lifecycle,
                    "reason": "Reject an ordinary suggestion transition."
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cannot be cleared")
                || error.contains("terminal transitions")
                || error.contains("active member"),
            "{error}"
        );
    }

    let refused = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000015",
                "facets": { "lifecycle": "accepted" },
                "reason": "Refuse the facet carrier."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("spine facet"), "{refused}");

    db.contract_create_suggestion_record_for_test(
        "5a99e571-0000-4000-8000-000000000013",
        Some(native_ce::schema::UNFILED_RECORD_ID),
        Some(native_ce::schema::UNFILED_RECORD_ID),
        false,
    )
    .await
    .unwrap();
    let repaired = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000013",
                "lifecycle": "open",
                "reason": "Repair an imported legacy suggestion."
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        repaired["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000012",
                "type": "Annotation",
                "kind": "note",
                "links": [{
                    "target_id": native_ce::schema::UNFILED_RECORD_ID,
                    "relationship": "part_of"
                }],
                "reason": "Create a non-suggestion annotation."
            }),
        )
        .await
        .unwrap();
    let entered = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000012",
                "kind": "suggestion",
                "lifecycle": "open",
                "facets": { "proposal.precondition": "none" },
                "reason": "Enter the governed suggestion kind."
            }),
        )
        .await
        .unwrap();
    assert_eq!(entered["kind"], "suggestion");
    assert_eq!(
        entered["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    let left = registry
        .call_engine(
            engine,
            caller,
            "update_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000012",
                "kind": "note",
                "lifecycle": null,
                "reason": "Leave the governed suggestion kind."
            }),
        )
        .await
        .unwrap();
    assert_eq!(left["kind"], "note");
    assert_eq!(left["lifecycle_interpretation"]["status"], "absent");
}

/// The engine parity half of the SQLite assertion: governing suggestions must
/// not open `facets.lifecycle` as a second write form here either.
#[tokio::test]
async fn turso_refuses_the_lifecycle_facet_form_for_non_suggestion_shapes() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-task-lifecycle-facet-form")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db);
    let caller = Caller::local();
    let created = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000016",
                "type": "WorkItem",
                "kind": "task",
                "facets": { "lifecycle": "in_progress" },
                "reason": "Refuse the facet carrier on create."
            }),
        )
        .await
        .expect_err("the facet carrier must be refused")
        .to_string();
    assert!(created.contains("spine facet"), "{created}");
    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000016",
                "type": "WorkItem",
                "kind": "task",
                "lifecycle": "in_progress",
                "reason": "Author through the top-level carrier."
            }),
        )
        .await
        .unwrap();
    let updated = registry
        .call_engine(
            engine,
            caller,
            "update_record",
            json!({
                "id": "5a99e571-0000-4000-8000-000000000016",
                "facets": { "lifecycle": "completed" },
                "reason": "Refuse the facet carrier on update."
            }),
        )
        .await
        .expect_err("the facet carrier must be refused")
        .to_string();
    assert!(updated.contains("spine facet"), "{updated}");
}

#[tokio::test]
async fn production_same_id_concurrent_create_has_one_durable_winner() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-create-race")
        .open()
        .await
        .unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let mut calls = Vec::new();
    for body in ["winner-a", "winner-b"] {
        let db = db.clone();
        let barrier = barrier.clone();
        calls.push(tokio::spawn(async move {
            barrier.wait().await;
            registry()
                .call_engine(
                    EngineHandle::TursoLocal(db),
                    Caller::local(),
                    "create_record",
                    json!({"id":"70250000-0000-4000-8000-005000000022","type":"Document","kind":"note","body":body,"reason":"Race the same explicit identifier."}),
                )
                .await
        }));
    }
    barrier.wait().await;
    let first = calls.remove(0).await.unwrap();
    let second = calls.remove(0).await.unwrap();
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = first.err().or_else(|| second.err()).unwrap().to_string();
    assert_eq!(loser, "create_record: uniqueness conflict");
    assert_eq!(
        db.contract_content_event_count_for_test("70250000-0000-4000-8000-005000000022")
            .await
            .unwrap(),
        1
    );
    let record = registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000022"]}),
        )
        .await
        .unwrap();
    assert!(matches!(
        record["records"][0]["body"].as_str(),
        Some("winner-a" | "winner-b")
    ));
    let history = registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000022"}),
        )
        .await
        .unwrap();
    assert_eq!(history["events"].as_array().unwrap().len(), 1);
    registry()
        .call_engine(
            EngineHandle::TursoLocal(db),
            Caller::local(),
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000023","type":"Document","kind":"note","reason":"Prove engine reuse after the stable loser."}),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn production_read_cancellation_releases_snapshots_for_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-read-cancellation")
        .open()
        .await
        .unwrap();
    for id in [
        "70250000-0000-4000-8000-005000000038",
        "70250000-0000-4000-8000-005000000039",
    ] {
        registry()
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","name":"cancellationlexeme","reason":"Create read cancellation fixture."}),
            )
            .await
            .unwrap();
    }
    db.contract_arm_snapshot_block("get_record");
    let read = spawn_local_call(
        db.clone(),
        "get_record",
        json!({"ids":["70250000-0000-4000-8000-005000000038","70250000-0000-4000-8000-005000000039"]}),
    );
    db.contract_wait_for_snapshot_block().await;
    read.abort();
    assert!(read.await.unwrap_err().is_cancelled());
    let reused = registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000038"]}),
        )
        .await
        .unwrap();
    assert_eq!(
        reused["records"][0]["id"],
        "70250000-0000-4000-8000-005000000038"
    );

    db.contract_arm_snapshot_block("get_history");
    let history = spawn_local_call(
        db.clone(),
        "get_history",
        json!({"record_id":"70250000-0000-4000-8000-005000000038"}),
    );
    db.contract_wait_for_snapshot_block().await;
    history.abort();
    assert!(history.await.unwrap_err().is_cancelled());
    let reused = registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000038"}),
        )
        .await
        .unwrap();
    assert_eq!(reused["events"].as_array().unwrap().len(), 1);

    for (operation, arguments) in [
        (
            "get_structure",
            json!({"root_id":"70250000-0000-4000-8000-005000000038","max_depth":0}),
        ),
        (
            "get_dashboard",
            json!({"scope":"70250000-0000-4000-8000-005000000038"}),
        ),
        (
            "render_record",
            json!({"id":"70250000-0000-4000-8000-005000000038"}),
        ),
        ("search", json!({"query":"cancellationlexeme"})),
    ] {
        db.contract_arm_snapshot_block(operation);
        let read = spawn_local_call(db.clone(), operation, arguments.clone());
        db.contract_wait_for_snapshot_block().await;
        read.abort();
        assert!(read.await.unwrap_err().is_cancelled());
        assert!(registry()
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                operation,
                arguments,
            )
            .await
            .unwrap()
            .is_object());
    }

    db.contract_arm_snapshot_block("describe_schema");
    let schema = spawn_local_call(db.clone(), "describe_schema", json!({}));
    db.contract_wait_for_snapshot_block().await;
    schema.abort();
    assert!(schema.await.unwrap_err().is_cancelled());
    let reused = registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "describe_schema",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(reused["engine"]["storage_profile"], "turso-local");

    db.contract_arm_snapshot_block("get_history");
    db.contract_release_snapshot_block();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        registry().call_engine(
            EngineHandle::TursoLocal(db),
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000038"}),
        ),
    )
    .await
    .expect("a release issued before checkpoint entry must remain durable")
    .unwrap();
}

pub(crate) async fn facet_operations_cancel_at_their_own_transaction_boundaries_and_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-facet-cancellation")
        .open()
        .await
        .unwrap();
    registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000001","type":"Outcome","kind":"target","name":"Facet cancellation","reason":"Create facet cancellation fixture."}),
        )
        .await
        .unwrap();

    db.contract_arm_post_handler_write_block("manage_facet_observations");
    let write = spawn_local_call(
        db.clone(),
        "manage_facet_observations",
        json!({"action":"set","record_id":"70250000-0000-4000-8000-005000000001","key":"current","value":1,"as_of":"2026-08-17T00:00:00Z","reason":"Cancel facet write before commit."}),
    );
    db.contract_wait_for_write_block().await;
    write.abort();
    assert!(write.await.unwrap_err().is_cancelled());
    let empty = registry()
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "manage_facet_observations",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-005000000001","key":"current"}),
        )
        .await
        .unwrap();
    assert!(empty["observations"].as_array().unwrap().is_empty());

    for (operation, arguments) in [
        (
            "resolve_facets",
            json!({"record_id":"70250000-0000-4000-8000-005000000001"}),
        ),
        (
            "suggest_facet_values",
            json!({"record_id":"70250000-0000-4000-8000-005000000001","facet_key":"current"}),
        ),
    ] {
        db.contract_arm_snapshot_block(operation);
        let read = spawn_local_call(db.clone(), operation, arguments.clone());
        db.contract_wait_for_snapshot_block().await;
        read.abort();
        assert!(read.await.unwrap_err().is_cancelled());
        assert!(registry()
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                operation,
                arguments,
            )
            .await
            .unwrap()
            .is_object());
    }
}

#[tokio::test]
async fn member_history_discloses_another_actors_run_context_only_with_view_of_their_person() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-history-redaction")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    for (id, name, account, principal) in [
        (
            "70250000-0000-4000-8000-005000000004",
            "Sender",
            "acct:history-sender",
            "native/history-sender",
        ),
        (
            "70250000-0000-4000-8000-005000000002",
            "Recipient",
            "acct:history-recipient",
            "native/history-recipient",
        ),
    ] {
        registry
            .call_engine(
                engine.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":id, "type":"Entity", "kind":"person", "name":name,
                    "reason":"Create the run-context history principal."
                }),
            )
            .await
            .unwrap();
        db.contract_provision_member(id, account, principal)
            .await
            .unwrap();
    }
    db.contract_deliver_message_fixture_with_run_context(
        "acct:history-sender",
        "70250000-0000-4000-8000-005000000003",
        "Run-context message",
        "recipient-visible body",
        &["70250000-0000-4000-8000-005000000002"],
        Some("scout-chair-a748b2"),
        Some("pilot-river-b748b2"),
        Some("Prepare the private message."),
    )
    .await
    .unwrap();

    let trusted_history = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000003"}),
        )
        .await
        .unwrap();
    let stored = &trusted_history["events"][0];
    assert_eq!(stored["actor"], "acct:history-sender");
    assert_eq!(stored["run_key"], "scout-chair-a748b2");
    assert_eq!(stored["parent_key"], "pilot-river-b748b2");
    assert_eq!(stored["intent"], "Prepare the private message.");

    let history = registry
        .call_engine(
            engine.clone(),
            Caller::authenticated("acct:history-recipient"),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000003"}),
        )
        .await
        .unwrap();
    let events = history["events"].as_array().unwrap();
    assert!(!events.is_empty());
    for event in events {
        assert_eq!(event["actor"], "acct:history-sender", "{event}");
        assert_eq!(event["run_key"], "scout-chair-a748b2", "{event}");
        assert_eq!(event["parent_key"], "pilot-river-b748b2", "{event}");
        assert_eq!(event["intent"], "Prepare the private message.", "{event}");
    }

    // Withdraw only `View` of the sender's person record. The run context is
    // disclosed because the person is readable, so it has to disappear with it.
    db.contract_restrict_record_to_account_for_test(
        "70250000-0000-4000-8000-005000000004",
        "acct:history-sender",
    )
    .await
    .unwrap();
    let history = registry
        .call_engine(
            engine,
            Caller::authenticated("acct:history-recipient"),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000003"}),
        )
        .await
        .unwrap();
    let events = history["events"].as_array().unwrap();
    assert!(!events.is_empty());
    for event in events {
        assert!(event["actor"].is_null(), "{event}");
        assert!(event["run_key"].is_null(), "{event}");
        assert!(event["parent_key"].is_null(), "{event}");
        assert!(event["intent"].is_null(), "{event}");
    }
}

#[tokio::test]
async fn production_record_writes_roll_back_post_handler_failures_and_reuse_engine() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-write-rollback")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    let caller = Caller::local();

    db.contract_arm_post_handler_write_failure("create_record");
    let create_error = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","type":"Document","kind":"note","body":"v1","reason":"Force post-handler create rollback."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        create_error,
        "contract forced create_record failure after production handler work"
    );
    let missing = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000042"]}),
        )
        .await
        .unwrap();
    assert_eq!(missing["records"][0]["status"], "not_found");

    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","type":"Document","kind":"note","body":"v1","reason":"Reuse engine after create rollback."}),
        )
        .await
        .unwrap();
    let history = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000042"}),
        )
        .await
        .unwrap();
    assert_eq!(history["events"].as_array().unwrap().len(), 1);

    db.contract_arm_post_handler_write_failure("update_record");
    let update_error = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","body":"must rollback","facets":{"priority":"high"},"if_body_digest":body_digest("v1"),"reason":"Force post-handler update rollback."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        update_error,
        "contract forced update_record failure after production handler work"
    );
    let unchanged = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000042"]}),
        )
        .await
        .unwrap();
    assert_eq!(unchanged["records"][0]["body"], "v1");
    assert_eq!(unchanged["records"][0]["facets"], json!([]));
    let history = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000042"}),
        )
        .await
        .unwrap();
    assert_eq!(history["events"].as_array().unwrap().len(), 1);
    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","body":"v2","if_body_digest":body_digest("v1"),"reason":"Reuse engine after update rollback."}),
        )
        .await
        .unwrap();

    db.contract_arm_post_handler_write_failure("archive_record");
    let archive_error = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "archive_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","reason":"Force post-handler archive rollback."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        archive_error,
        "contract forced archive_record failure after production handler work"
    );
    let unchanged = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000042"]}),
        )
        .await
        .unwrap();
    assert_eq!(unchanged["records"][0]["body"], "v2");
    assert_eq!(unchanged["records"][0]["archived"], false);
    let history = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000042"}),
        )
        .await
        .unwrap();
    assert_eq!(history["events"].as_array().unwrap().len(), 2);
    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "archive_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","reason":"Reuse engine after archive rollback."}),
        )
        .await
        .unwrap();

    db.contract_arm_post_handler_write_failure("delete_record");
    let delete_error = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","reason":"Force post-handler delete rollback."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        delete_error,
        "contract forced delete_record failure after production handler work"
    );
    let unchanged = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000042"]}),
        )
        .await
        .unwrap();
    assert!(unchanged["records"][0]["deleted_at"].is_null());
    registry
        .call_engine(
            engine,
            caller,
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000042","reason":"Reuse engine after delete rollback."}),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn production_record_writes_rollback_in_flight_cancellation_and_reuse_engine() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-write-cancellation")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());

    db.contract_arm_post_handler_write_block("create_record");
    let create = spawn_local_call(
        db.clone(),
        "create_record",
        json!({"id":"70250000-0000-4000-8000-005000000017","type":"Document","kind":"note","body":"v1","reason":"Cancel an admitted create before commit."}),
    );
    db.contract_wait_for_write_block().await;
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    let missing = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000017"]}),
        )
        .await
        .unwrap();
    assert_eq!(missing["records"][0]["status"], "not_found");
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "create_record",
            json!({"id":"70250000-0000-4000-8000-005000000017","type":"Document","kind":"note","body":"v1","reason":"Reuse after create cancellation."}),
        )
        .await
        .unwrap();

    db.contract_arm_post_handler_write_block("update_record");
    let update = spawn_local_call(
        db.clone(),
        "update_record",
        json!({"id":"70250000-0000-4000-8000-005000000017","body":"cancelled","if_body_digest":body_digest("v1"),"reason":"Cancel an admitted update before commit."}),
    );
    db.contract_wait_for_write_block().await;
    update.abort();
    assert!(update.await.unwrap_err().is_cancelled());
    let unchanged = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000017"]}),
        )
        .await
        .unwrap();
    assert_eq!(unchanged["records"][0]["body"], "v1");
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000017","body":"v2","if_body_digest":body_digest("v1"),"reason":"Reuse after update cancellation."}),
        )
        .await
        .unwrap();

    db.contract_arm_post_handler_write_block("archive_record");
    let archive = spawn_local_call(
        db.clone(),
        "archive_record",
        json!({"id":"70250000-0000-4000-8000-005000000017","reason":"Cancel an admitted archive before commit."}),
    );
    db.contract_wait_for_write_block().await;
    archive.abort();
    assert!(archive.await.unwrap_err().is_cancelled());
    let unchanged = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000017"]}),
        )
        .await
        .unwrap();
    assert_eq!(unchanged["records"][0]["body"], "v2");
    assert_eq!(unchanged["records"][0]["archived"], false);
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "archive_record",
            json!({"id":"70250000-0000-4000-8000-005000000017","reason":"Reuse after archive cancellation."}),
        )
        .await
        .unwrap();

    db.contract_arm_post_handler_write_block("delete_record");
    let delete = spawn_local_call(
        db.clone(),
        "delete_record",
        json!({"id":"70250000-0000-4000-8000-005000000017","reason":"Cancel an admitted delete before commit."}),
    );
    db.contract_wait_for_write_block().await;
    delete.abort();
    assert!(delete.await.unwrap_err().is_cancelled());
    let unchanged = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000017"]}),
        )
        .await
        .unwrap();
    assert!(unchanged["records"][0]["deleted_at"].is_null());
    registry
        .call_engine(
            engine,
            Caller::local(),
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000017","reason":"Reuse after delete cancellation."}),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn production_record_and_history_reads_use_one_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-read-snapshots")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    for id in [
        "70250000-0000-4000-8000-005000000045",
        "70250000-0000-4000-8000-005000000046",
    ] {
        registry
            .call_engine(
                engine.clone(),
                Caller::local(),
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","body":"before","reason":"Create snapshot fixture."}),
            )
            .await
            .unwrap();
    }

    db.contract_arm_snapshot_block("get_record");
    let read = spawn_local_call(
        db.clone(),
        "get_record",
        json!({"ids":["70250000-0000-4000-8000-005000000045","70250000-0000-4000-8000-005000000046"]}),
    );
    db.contract_wait_for_snapshot_block().await;
    let conflict = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000046","body":"after","if_body_digest":body_digest("before"),"reason":"Mutate between multi-id reads."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(conflict.contains("storage conflict"), "{conflict}");
    db.contract_release_snapshot_block();
    let snapshot = read.await.unwrap().unwrap();
    assert_eq!(snapshot["records"][0]["body"], "before");
    assert_eq!(snapshot["records"][1]["body"], "before");
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000046","body":"after","if_body_digest":body_digest("before"),"reason":"Commit after the multi-id snapshot releases."}),
        )
        .await
        .unwrap();
    let fresh = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000046"]}),
        )
        .await
        .unwrap();
    assert_eq!(fresh["records"][0]["body"], "after");

    let before = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000045"}),
        )
        .await
        .unwrap();
    db.contract_arm_snapshot_block("get_history");
    let history = spawn_local_call(
        db.clone(),
        "get_history",
        json!({"record_id":"70250000-0000-4000-8000-005000000045"}),
    );
    db.contract_wait_for_snapshot_block().await;
    let conflict = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000045","body":"after","if_body_digest":body_digest("before"),"reason":"Append between history authorization and selection."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(conflict.contains("storage conflict"), "{conflict}");
    db.contract_release_snapshot_block();
    let snapshot = history.await.unwrap().unwrap();
    assert_eq!(snapshot["events"], before["events"]);
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "update_record",
            json!({"id":"70250000-0000-4000-8000-005000000045","body":"after","if_body_digest":body_digest("before"),"reason":"Commit after the history snapshot releases."}),
        )
        .await
        .unwrap();
    let fresh = registry
        .call_engine(
            engine,
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000045"}),
        )
        .await
        .unwrap();
    assert_eq!(
        fresh["events"].as_array().unwrap().len(),
        before["events"].as_array().unwrap().len() + 1
    );
}

#[tokio::test]
async fn runtime_owns_one_file_per_logical_database_and_fails_closed_on_second_owner() {
    let directory = tempfile::tempdir().unwrap();
    let alpha_config = config(directory.path(), "runtime-alpha");
    let beta_config = config(directory.path(), "runtime-beta");
    assert_ne!(alpha_config.database_path(), beta_config.database_path());

    let alpha = alpha_config.open().await.unwrap();
    assert_eq!(alpha.logical_database_id(), "runtime-alpha");
    assert!(alpha.path().is_file());
    let health = alpha.health().await.unwrap();
    assert!(health.ready);
    assert!(health.write_ready);
    assert_eq!(
        health.physical_overlays,
        [
            "projection.facet-value-number",
            "search.turso-fts",
            "topology.logical-database-identity",
        ]
    );

    let error = alpha_config.open().await.unwrap_err().to_string();
    assert_eq!(
        error,
        "Turso-local database is already owned by another runtime process"
    );
    let beta = beta_config.open().await.unwrap();
    assert_eq!(beta.logical_database_id(), "runtime-beta");

    let registry = registry();
    for database in [&alpha, &beta] {
        registry
            .call_engine(
                EngineHandle::TursoLocal(database.clone()),
                Caller::local(),
                "create_record",
                json!({"id":"70250000-0000-4000-8000-005000000024","type":"Document","kind":"note","reason":"Create an isolated deletion fixture."}),
            )
            .await
            .unwrap();
    }
    registry
        .call_engine(
            EngineHandle::TursoLocal(alpha.clone()),
            Caller::local(),
            "delete_record",
            json!({"id":"70250000-0000-4000-8000-005000000024","reason":"Delete only the alpha record."}),
        )
        .await
        .unwrap();
    let beta_record = registry
        .call_engine(
            EngineHandle::TursoLocal(beta.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000024"]}),
        )
        .await
        .unwrap();
    assert!(beta_record["records"][0]["deleted_at"].is_null());
    drop(beta);
    drop(alpha);

    let reopened = alpha_config.open().await.unwrap();
    assert_eq!(reopened.logical_database_id(), "runtime-alpha");
    let alpha_record = registry
        .call_engine(
            EngineHandle::TursoLocal(reopened),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000024"]}),
        )
        .await
        .unwrap();
    assert!(alpha_record["records"][0]["deleted_at"].is_string());
}

#[tokio::test]
async fn production_realtime_tailer_reports_committed_requests_only() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-realtime")
        .open()
        .await
        .unwrap();
    let mut tailer = db.subscribe_realtime();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db);

    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000040",
                "type":"Document",
                "kind":"note",
                "name":"Realtime",
                "reason":"Prove the production Turso realtime tailer seam."
            }),
        )
        .await
        .unwrap();
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), tailer.next())
        .await
        .expect("committed request must notify the production tailer")
        .unwrap();
    assert_eq!(event.generation, 1);

    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000040"]}),
        )
        .await
        .unwrap();
    assert_eq!(tailer.try_next().unwrap(), None, "reads must stay silent");

    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000040",
                "body":"rejected",
                "reason":""
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        tailer.try_next().unwrap(),
        None,
        "a rejected request must not publish a commit notification"
    );
}

#[tokio::test]
async fn production_update_record_cas_composes_with_body_digest_and_rejects_without_writes() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-update-cas")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db);
    let caller = Caller::local();

    let created = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000018",
                "type":"Document",
                "kind":"note",
                "name":"CAS",
                "body":"v1",
                "reason":"Create the CAS fixture."
            }),
        )
        .await
        .unwrap();
    let first_token = created["updated_at"].as_str().unwrap().to_owned();
    let equivalent_offset = chrono::DateTime::parse_from_rfc3339(&first_token)
        .unwrap()
        .with_timezone(&chrono::FixedOffset::east_opt(3_600).unwrap())
        .to_rfc3339();
    let digest = hex::encode(sha2::Sha256::digest(b"v1"));

    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::authenticated("account:unauthorized"),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000018",
                "body":"must not reveal timestamp state",
                "home_id":"native:unfiled",
                "if_unmodified_since":"not-rfc3339",
                "reason":"Prove authorization runs before token comparison."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(!denied.is_empty());
    assert!(!denied.contains("RFC3339"), "{denied}");

    let updated = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000018",
                "body":"v2",
                "facets":{"priority":"high"},
                "if_body_digest":digest,
                "if_unmodified_since":equivalent_offset,
                "reason":"Apply matching record-wide and body guards together."
            }),
        )
        .await
        .unwrap();
    let second_token = updated["updated_at"].as_str().unwrap().to_owned();
    assert!(
        chrono::DateTime::parse_from_rfc3339(&second_token).unwrap()
            > chrono::DateTime::parse_from_rfc3339(&first_token).unwrap()
    );

    let facet_only = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000018",
                "facets":{"priority":"urgent"},
                "if_unmodified_since":second_token,
                "reason":"Advance the record token through a facet-only mutation."
            }),
        )
        .await
        .unwrap();
    let third_token = facet_only["updated_at"].as_str().unwrap().to_owned();
    assert!(
        chrono::DateTime::parse_from_rfc3339(&third_token).unwrap()
            > chrono::DateTime::parse_from_rfc3339(&second_token).unwrap()
    );
    let history_before = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000018"}),
        )
        .await
        .unwrap();
    let event_count_before = history_before["events"].as_array().unwrap().len();

    let stale = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000018",
                "body":"must not commit",
                "if_unmodified_since":first_token,
                "reason":"Prove a stale token rolls back without writes."
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(stale, native_ce::Error::Conflict(_)));

    let malformed = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000018",
                "body":"must not commit either",
                "if_unmodified_since":"yesterday",
                "reason":"Prove malformed tokens fail before writes."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(malformed.contains("must be an RFC3339 timestamp"));

    let after = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000018"]}),
        )
        .await
        .unwrap();
    assert_eq!(after["records"][0]["body"], "v2");
    assert_eq!(after["records"][0]["updated_at"], third_token);
    let history_after = registry
        .call_engine(
            engine,
            caller,
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000018"}),
        )
        .await
        .unwrap();
    assert_eq!(
        history_after["events"].as_array().unwrap().len(),
        event_count_before
    );
}

#[tokio::test]
async fn production_attribution_identity_requires_the_unsupported_dedicated_command() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-attribution-identity-guards")
        .open()
        .await
        .unwrap();
    let mut tailer = db.subscribe_realtime();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    let caller = Caller::local();

    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000010",
                "type":"Document",
                "kind":"note",
                "name":"Attribution guard bearer",
                "reason":"Create the authorization bearer for the re-kind fixture."
            }),
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), tailer.next())
        .await
        .expect("the committed bearer must notify the production tailer")
        .unwrap();

    let create_error = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000037",
                "type":"Annotation",
                "kind":"attribution",
                "name":"Forbidden raw attribution",
                "reason":"Prove Turso requires the dedicated attribution aggregate command."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        create_error,
        "create_record: governed Annotation kind:attribution must be created with create_attribution so bearer, exact target, assertion, evidence, and action attestation commit atomically"
    );
    assert_eq!(tailer.try_next().unwrap(), None);

    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000036",
                "type":"Annotation",
                "kind":"citation",
                "name":"Ordinary annotation",
                "links":[{
                    "target_id":"70250000-0000-4000-8000-005000000010",
                    "relationship":"part_of"
                }],
                "reason":"Create the re-kind guard fixture."
            }),
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), tailer.next())
        .await
        .expect("the committed fixture must notify the production tailer")
        .unwrap();
    let history_before = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000036"}),
        )
        .await
        .unwrap();
    let update_error = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000036",
                "kind":"attribution",
                "reason":"Prove ordinary re-kind cannot manufacture attribution authority."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        update_error,
        "update_record: governed attribution identity cannot be added in place; use create_attribution"
    );
    assert_eq!(tailer.try_next().unwrap(), None);
    let after = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000037","70250000-0000-4000-8000-005000000036"]}),
        )
        .await
        .unwrap();
    assert_eq!(after["records"][0]["status"], "not_found");
    assert_eq!(after["records"][1]["kind"], "citation");
    let history_after = registry
        .call_engine(
            engine,
            caller,
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000036"}),
        )
        .await
        .unwrap();
    assert_eq!(history_after["events"], history_before["events"]);
}

#[tokio::test]
async fn production_comment_threads_cover_aliases_replies_resolution_and_immutable_bearers() {
    let directory = tempfile::tempdir().unwrap();
    let runtime_config = config(directory.path(), "runtime-comments");
    let db = runtime_config.open().await.unwrap();
    let path = db.path().to_path_buf();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    let caller = Caller::local();

    for (id, kind, name) in [
        (
            "70250000-0000-4000-8000-005000000013",
            "note",
            "Comment bearer",
        ),
        (
            "70250000-0000-4000-8000-005000000026",
            "person",
            "Human author",
        ),
        (
            "70250000-0000-4000-8000-005000000009",
            "person",
            "Agent author",
        ),
    ] {
        let record_type = if kind == "person" {
            "Entity"
        } else {
            "Document"
        };
        registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "id":id,
                    "type":record_type,
                    "kind":kind,
                    "name":name,
                    "reason":"Create a Turso comment runtime fixture."
                }),
            )
            .await
            .unwrap();
    }
    corrupt_turso_file(
        &path,
        &[
            "INSERT INTO vocabulary_values(id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of) SELECT 'vv:test:comment-alias',vocabulary_id,'remark',gloss,'deprecated',ordinal,terminality,metadata,id FROM vocabulary_values WHERE id='vv:voc:kind:Annotation:comment'",
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('70250000-0000-4000-8000-005000000026','account','acct:human',1)",
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES('70250000-0000-4000-8000-005000000009','account','acct:agent',1)",
        ],
    )
    .await;
    let human = Caller::authenticated("acct:human")
        .with_run_context(Some("scout-chair-a748b2".into()), None);
    let agent = Caller::authenticated("acct:agent")
        .with_run_context(Some("heron-river-c748b2".into()), None);

    let root = registry
        .call_engine(
            engine.clone(),
            human.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000021",
                "type":"Annotation",
                "kind":"remark",
                "name":"Human comment",
                "body":"Should this ship?",
                "lifecycle":"open",
                "owner_id":"70250000-0000-4000-8000-005000000026",
                "links":[{"target_id":"70250000-0000-4000-8000-005000000013","relationship":"part_of"}],
                "reason":"Open a comment through an active alias.",
                "run_key":"scout-chair-a748b2"
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        root["kind"], "comment",
        "writes canonicalize active aliases"
    );

    registry
        .call_engine(
            engine.clone(),
            agent.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000019",
                "type":"Annotation",
                "kind":"comment",
                "name":"Agent reply",
                "body":"Yes, with the guarded transition.",
                "owner_id":"70250000-0000-4000-8000-005000000009",
                "links":[{"target_id":"70250000-0000-4000-8000-005000000021","relationship":"part_of"}],
                "reason":"Reply to the human-authored root.",
                "run_key":"heron-river-c748b2"
            }),
        )
        .await
        .unwrap();
    let auto_owned_reply = registry
        .call_engine(
            engine.clone(),
            agent.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000020",
                "type":"Annotation",
                "kind":"comment",
                "name":"Second agent reply",
                "body":"And the caller identity owns this automatically.",
                "links":[{"target_id":"70250000-0000-4000-8000-005000000021","relationship":"part_of"}],
                "reason":"Prove omitted owner auto-attribution.",
                "run_key":"heron-river-c748b2"
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        auto_owned_reply["owner_id"],
        "70250000-0000-4000-8000-005000000009"
    );
    corrupt_turso_file(
        &path,
        &["UPDATE records SET created_at='2026-08-10T12:00:00.000Z' WHERE id IN ('70250000-0000-4000-8000-005000000019','70250000-0000-4000-8000-005000000020')"],
    )
    .await;

    let bearer = registry
        .call_engine(
            engine.clone(),
            human.clone(),
            "get_record",
            json!({
                "ids":["70250000-0000-4000-8000-005000000013"],
                "include_comments":true,
                "comments_limit":1,
                "comments_offset":0
            }),
        )
        .await
        .unwrap();
    assert_eq!(bearer["records"][0]["comment_count"], 1);
    assert_eq!(
        bearer["records"][0]["comments"][0]["id"],
        "70250000-0000-4000-8000-005000000021"
    );
    assert_eq!(
        bearer["records"][0]["comments"][0]["owner_id"],
        "70250000-0000-4000-8000-005000000026"
    );

    let replies = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({
                "ids":["70250000-0000-4000-8000-005000000021"],
                "children_limit":0,
                "links_limit":0,
                "include_comments":true,
                "comments_limit":50,
                "comments_offset":0
            }),
        )
        .await
        .unwrap();
    assert_eq!(replies["records"][0]["comment_count"], 2);
    // Both replies share a forced `created_at`, so the id is the whole sort key:
    // reply summaries come back `created_at ASC, id ASC`, and `...019` must stay
    // lexically less than `...020`.
    assert_eq!(
        replies["records"][0]["comments"][0]["id"],
        "70250000-0000-4000-8000-005000000019"
    );
    let second_reply_page = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({
                "ids":["70250000-0000-4000-8000-005000000021"],
                "include_comments":true,
                "comments_limit":1,
                "comments_offset":1
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        second_reply_page["records"][0]["comments"][0]["id"],
        "70250000-0000-4000-8000-005000000020"
    );

    let resolved = registry
        .call_engine(
            engine.clone(),
            human.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000021",
                "lifecycle":"resolved",
                "summary":"The guarded transition is in place.",
                "reason":"Resolve the root atomically.",
                "run_key":"scout-chair-a748b2"
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        resolved["lifecycle_interpretation"]["value"]["canonical"],
        "resolved"
    );
    assert_eq!(resolved["summary"], "The guarded transition is in place.");
    let root_events_before_rejections = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000021"}),
        )
        .await
        .unwrap()["events"]
        .as_array()
        .unwrap()
        .len();
    let reply_events_before_rejections = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000019"}),
        )
        .await
        .unwrap()["events"]
        .as_array()
        .unwrap()
        .len();

    let reopen = registry
        .call_engine(
            engine.clone(),
            human.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000021",
                "lifecycle":"open",
                "summary":null,
                "reason":"Reopening is deliberately unsupported."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        reopen.contains("root-only open -> resolved transition"),
        "{reopen}"
    );

    let reply_resolution = registry
        .call_engine(
            engine.clone(),
            agent.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000019",
                "lifecycle":"resolved",
                "summary":"Replies cannot own thread state.",
                "reason":"Prove reply resolution fails atomically."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(reply_resolution.contains("replies must have null lifecycle"));
    let identity_change = registry
        .call_engine(
            engine.clone(),
            human.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000021",
                "kind":"citation",
                "reason":"Governed comment identity is immutable."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(identity_change.contains("comment identity cannot be removed"));

    let after_rejections = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000021","70250000-0000-4000-8000-005000000019"]}),
        )
        .await
        .unwrap();
    assert_eq!(
        after_rejections["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "resolved"
    );
    assert_eq!(
        after_rejections["records"][0]["summary"],
        "The guarded transition is in place."
    );
    assert_eq!(
        after_rejections["records"][1]["lifecycle_interpretation"]["status"],
        "absent"
    );
    assert!(after_rejections["records"][1]["summary"].is_null());
    for (id, expected) in [
        (
            "70250000-0000-4000-8000-005000000021",
            root_events_before_rejections,
        ),
        (
            "70250000-0000-4000-8000-005000000019",
            reply_events_before_rejections,
        ),
    ] {
        let history = registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "get_history",
                json!({"record_id":id}),
            )
            .await
            .unwrap();
        assert_eq!(history["events"].as_array().unwrap().len(), expected);
    }

    for action in ["add", "remove"] {
        let error = registry
            .call_engine(
                engine.clone(),
                human.clone(),
                "manage_links",
                json!({
                    "action":action,
                    "source_id":"70250000-0000-4000-8000-005000000021",
                    "target_id":"70250000-0000-4000-8000-005000000013",
                    "relationship":"part_of"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("part_of bearer is immutable"), "{error}");
    }

    let history = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000021"}),
        )
        .await
        .unwrap();
    assert!(history["events"].as_array().unwrap().len() >= 3);
    assert!(
        history["events"].as_array().unwrap().iter().all(|event| {
            event["actor"] == "acct:human" && event["run_key"] == "scout-chair-a748b2"
        }),
        "{history}"
    );
    let reply_history = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000019"}),
        )
        .await
        .unwrap();
    assert!(reply_history["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| {
            event["actor"] == "acct:agent" && event["run_key"] == "heron-river-c748b2"
        }));

    let false_owner = registry
        .call_engine(
            engine.clone(),
            agent,
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000025",
                "type":"Annotation",
                "kind":"comment",
                "name":"False owner",
                "body":"Must not be attributed to the human.",
                "owner_id":"70250000-0000-4000-8000-005000000026",
                "links":[{"target_id":"70250000-0000-4000-8000-005000000013","relationship":"part_of"}],
                "reason":"Prove caller-to-owner enforcement.",
                "run_key":"heron-river-c748b2"
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(false_owner.contains("caller's verified portable identity"));

    corrupt_turso_file(
        &path,
        &[
            "INSERT INTO record_policies(record_id) VALUES('70250000-0000-4000-8000-005000000013')",
            "UPDATE records SET policy_anchor_id='70250000-0000-4000-8000-005000000013' WHERE id='70250000-0000-4000-8000-005000000013'",
            "INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES('70250000-0000-4000-8000-005000000013','account','acct:allowed','allow','view')",
        ],
    )
    .await;
    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::authenticated("acct:denied"),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000013"],"include_comments":true}),
        )
        .await
        .unwrap();
    assert_eq!(denied["records"][0]["status"], "not_found");
    let denied_history = registry
        .call_engine(
            engine.clone(),
            Caller::authenticated("acct:denied"),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000021"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(!denied_history.is_empty());
    assert!(!denied_history.contains("Should this ship?"));
    let allowed = registry
        .call_engine(
            engine,
            Caller::authenticated("acct:allowed"),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000013"],"include_comments":true}),
        )
        .await
        .unwrap();
    assert_eq!(allowed["records"][0]["comment_count"], 1);
}

#[tokio::test]
async fn production_comment_windows_filter_malformed_rows_before_counting_and_paging() {
    let directory = tempfile::tempdir().unwrap();
    let runtime_config = config(directory.path(), "runtime-comment-filtering");
    let db = runtime_config.open().await.unwrap();
    let path = db.path().to_path_buf();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    let caller = Caller::local();

    for id in [
        "70250000-0000-4000-8000-005000000014",
        "70250000-0000-4000-8000-005000000015",
    ] {
        registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","name":id,"reason":"Create a paging bearer."}),
            )
            .await
            .unwrap();
    }
    for (id, body) in [
        ("70250000-0000-4000-8000-005000000043", "First valid root"),
        ("70250000-0000-4000-8000-005000000044", "Second valid root"),
    ] {
        registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "id":id,"type":"Annotation","kind":"comment","name":id,"body":body,"lifecycle":"open",
                    "links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"}],
                    "reason":"Create a valid root for deterministic paging."
                }),
            )
            .await
            .unwrap();
    }
    for id in [
        "70250000-0000-4000-8000-005000000012",
        "70250000-0000-4000-8000-005000000011",
    ] {
        registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","name":id,"body":"temporary","reason":"Create a row for malformed-state filtering."}),
            )
            .await
            .unwrap();
    }
    corrupt_turso_file(
        &path,
        &[
            "UPDATE records SET created_at='2026-08-10T13:00:00.000Z' WHERE id IN ('70250000-0000-4000-8000-005000000043','70250000-0000-4000-8000-005000000044')",
            "UPDATE records SET type='Annotation',kind='comment',body='' WHERE id='70250000-0000-4000-8000-005000000012'",
            "UPDATE records SET type='Annotation',kind='comment',body='two bearers',lifecycle='open' WHERE id='70250000-0000-4000-8000-005000000011'",
            "INSERT INTO links(id,source_id,target_id,relationship) VALUES('link:bad-empty','70250000-0000-4000-8000-005000000012','70250000-0000-4000-8000-005000000014','part_of')",
            "INSERT INTO links(id,source_id,target_id,relationship) VALUES('link:bad-double-a','70250000-0000-4000-8000-005000000011','70250000-0000-4000-8000-005000000014','part_of')",
            "INSERT INTO links(id,source_id,target_id,relationship) VALUES('link:bad-double-b','70250000-0000-4000-8000-005000000011','70250000-0000-4000-8000-005000000015','part_of')",
        ],
    )
    .await;

    let first = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000014"],"include_comments":true,"comments_limit":1,"comments_offset":0}),
        )
        .await
        .unwrap();
    assert_eq!(first["records"][0]["comment_count"], 2);
    assert_eq!(first["records"][0]["comments"].as_array().unwrap().len(), 1);
    // Both roots were forced to the same `created_at` above, so the id is the
    // whole sort key here: root summaries come back `created_at DESC, id DESC`.
    // `...044` must therefore stay lexically greater than `...043`.
    let first_id = first["records"][0]["comments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(first_id, "70250000-0000-4000-8000-005000000044");

    let second = registry
        .call_engine(
            engine,
            caller,
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000014"],"include_comments":true,"comments_limit":1,"comments_offset":1}),
        )
        .await
        .unwrap();
    assert_eq!(second["records"][0]["comment_count"], 2);
    let second_id = second["records"][0]["comments"][0]["id"].as_str().unwrap();
    assert_eq!(second_id, "70250000-0000-4000-8000-005000000043");
}

#[tokio::test]
async fn production_comment_creation_rejects_every_invalid_shape_without_writes() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-comment-create-guards")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db);
    let caller = Caller::local();
    for id in [
        "70250000-0000-4000-8000-005000000014",
        "70250000-0000-4000-8000-005000000015",
    ] {
        registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "create_record",
                json!({"id":id,"type":"Document","kind":"note","name":id,"reason":"Create a comment guard bearer."}),
            )
            .await
            .unwrap();
    }
    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000050","type":"Annotation","kind":"comment","name":"root","body":"valid","lifecycle":"open",
                "links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"}],"reason":"Create the valid depth fixture."
            }),
        )
        .await
        .unwrap();
    registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000049","type":"Annotation","kind":"comment","name":"reply","body":"valid reply",
                "links":[{"target_id":"70250000-0000-4000-8000-005000000050","relationship":"part_of"}],"reason":"Create the valid reply depth fixture."
            }),
        )
        .await
        .unwrap();

    let cases = [
        (
            "70250000-0000-4000-8000-005000000027",
            json!({"body":"   ","links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"}]}),
            "nonblank body",
        ),
        (
            "70250000-0000-4000-8000-005000000034",
            json!({"body":"body","links":[]}),
            "exactly one outgoing part_of",
        ),
        (
            "70250000-0000-4000-8000-005000000033",
            json!({"body":"body","links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"},{"target_id":"70250000-0000-4000-8000-005000000015","relationship":"part_of"}]}),
            "exactly one outgoing part_of",
        ),
        (
            "70250000-0000-4000-8000-005000000028",
            json!({"body":"nested","links":[{"target_id":"70250000-0000-4000-8000-005000000049","relationship":"part_of"}]}),
            "reply-to-reply nesting",
        ),
        (
            "70250000-0000-4000-8000-005000000029",
            json!({"body":"body","lifecycle":"closed","links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"}]}),
            "lifecycle must be null, open, or resolved",
        ),
        (
            "70250000-0000-4000-8000-005000000032",
            json!({"body":"body","lifecycle":"open","summary":"premature","links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"}]}),
            "summary is only valid on a resolved root",
        ),
        (
            "70250000-0000-4000-8000-005000000031",
            json!({"body":"body","lifecycle":"resolved","summary":"premature","links":[{"target_id":"70250000-0000-4000-8000-005000000014","relationship":"part_of"}]}),
            "cannot be created resolved",
        ),
        (
            "70250000-0000-4000-8000-005000000030",
            json!({"body":"body","lifecycle":"open","links":[{"target_id":"70250000-0000-4000-8000-005000000050","relationship":"part_of"}]}),
            "replies must have null lifecycle",
        ),
    ];
    let mut rejected_ids = Vec::new();
    for (id, additions, expected) in cases {
        let mut arguments = json!({
            "id":id,"type":"Annotation","kind":"comment","name":id,
            "reason":"Prove invalid comment creation rolls back."
        });
        arguments
            .as_object_mut()
            .unwrap()
            .extend(additions.as_object().unwrap().clone());
        let error = registry
            .call_engine(engine.clone(), caller.clone(), "create_record", arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{id}: {error}");
        rejected_ids.push(id);
    }
    let after = registry
        .call_engine(engine, caller, "get_record", json!({"ids":rejected_ids}))
        .await
        .unwrap();
    assert!(after["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| { record["status"] == "not_found" }));
}

#[tokio::test]
async fn governed_comment_state_machine_matches_sqlite_on_both_registered_engines() {
    let directory = tempfile::tempdir().unwrap();
    let sqlite = create_database(":memory:").await.unwrap();
    let turso = config(directory.path(), "runtime-comment-cross-engine")
        .open()
        .await
        .unwrap();
    let registry = registry();
    let mut observations = Vec::new();
    for engine in [
        EngineHandle::Sqlite(sqlite),
        EngineHandle::TursoLocal(turso),
    ] {
        let caller = Caller::local();
        registry
            .call_engine(
                engine.clone(), caller.clone(), "create_record",
                json!({"id":"70250000-0000-4000-8000-005000000005","type":"Document","kind":"note","name":"Bearer","reason":"Create cross-engine bearer."}),
            )
            .await
            .unwrap();
        registry
            .call_engine(
                engine.clone(), caller.clone(), "create_record",
                json!({"id":"70250000-0000-4000-8000-005000000008","type":"Annotation","kind":"comment","name":"Root","body":"Question","lifecycle":"open","links":[{"target_id":"70250000-0000-4000-8000-005000000005","relationship":"part_of"}],"reason":"Create cross-engine root."}),
            )
            .await
            .unwrap();
        registry
            .call_engine(
                engine.clone(), caller.clone(), "create_record",
                json!({"id":"70250000-0000-4000-8000-005000000007","type":"Annotation","kind":"comment","name":"Reply","body":"Answer","links":[{"target_id":"70250000-0000-4000-8000-005000000008","relationship":"part_of"}],"reason":"Create cross-engine reply."}),
            )
            .await
            .unwrap();
        let nested = registry
            .call_engine(
                engine.clone(), caller.clone(), "create_record",
                json!({"id":"70250000-0000-4000-8000-005000000006","type":"Annotation","kind":"comment","name":"Nested","body":"Too deep","links":[{"target_id":"70250000-0000-4000-8000-005000000007","relationship":"part_of"}],"reason":"Compare cross-engine depth guards."}),
            )
            .await
            .unwrap_err()
            .to_string();
        let resolved = registry
            .call_engine(
                engine.clone(), caller.clone(), "update_record",
                json!({"id":"70250000-0000-4000-8000-005000000008","lifecycle":"resolved","summary":"Settled","reason":"Compare cross-engine resolution."}),
            )
            .await
            .unwrap();
        let reopen = registry
            .call_engine(
                engine.clone(), caller.clone(), "update_record",
                json!({"id":"70250000-0000-4000-8000-005000000008","lifecycle":"open","summary":null,"reason":"Compare cross-engine reopen refusal."}),
            )
            .await
            .unwrap_err()
            .to_string();
        let bearer = registry
            .call_engine(
                engine.clone(),
                caller.clone(),
                "get_record",
                json!({"ids":["70250000-0000-4000-8000-005000000005"],"include_comments":true}),
            )
            .await
            .unwrap();
        let root = registry
            .call_engine(
                engine,
                caller,
                "get_record",
                json!({"ids":["70250000-0000-4000-8000-005000000008"],"include_comments":true}),
            )
            .await
            .unwrap();
        observations.push(json!({
            "nested_error":nested,
            "resolved_lifecycle":resolved["lifecycle_interpretation"]["value"]["canonical"],
            "resolved_summary":resolved["summary"],
            "reopen_error":reopen,
            "root_count":bearer["records"][0]["comment_count"],
            "root_id":bearer["records"][0]["comments"][0]["id"],
            "reply_count":root["records"][0]["comment_count"],
            "reply_id":root["records"][0]["comments"][0]["id"],
        }));
    }
    assert_eq!(observations[0], observations[1]);
}

#[tokio::test]
async fn engine_handle_routes_the_qualified_domain_slice_and_isolated_query_sql() {
    let directory = tempfile::tempdir().unwrap();
    let db = config(directory.path(), "runtime-routing")
        .open()
        .await
        .unwrap();
    let path = db.path().to_path_buf();
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    let caller = Caller::local();

    let created = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000041",
                "type":"Document",
                "kind":"note",
                "name":"Runtime",
                "body":"v1",
                "facets":{"estimate":3,"priority":"high"},
                "reason":"Exercise the promoted Turso-local route."
            }),
        )
        .await
        .unwrap();
    assert_eq!(created["id"], "70250000-0000-4000-8000-005000000041");
    assert_eq!(created["body"], "v1");

    let updated = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "update_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000041",
                "body":"v2",
                "facets":{"priority":"urgent"},
                "if_body_digest":body_digest("v1"),
                "reason":"Exercise an atomic event and projection update."
            }),
        )
        .await
        .unwrap();
    assert_eq!(updated["body"], "v2");

    let attached = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-005000000041","text":"portable bytes","filename":"proof.txt"}),
        )
        .await
        .unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap().to_string();
    let bytes = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "read_attachment",
            json!({"attachment_id":attachment_id,"offset":1,"length":4}),
        )
        .await
        .unwrap();
    assert_eq!(bytes["content"], "orta");
    assert_eq!(bytes["offset"], 1);

    let listed = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-005000000041"}),
        )
        .await
        .unwrap();
    assert_eq!(listed["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(listed["attachments"][0]["attachment_id"], attachment_id);
    let inspected = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "manage_attachments",
            json!({"action":"inspect","attachment_id":attachment_id}),
        )
        .await
        .unwrap();
    assert_eq!(inspected["attachment_id"], attachment_id);
    assert_eq!(inspected["detached"], false);

    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::authenticated("account-without-portable-binding"),
            "attach_text",
            json!({"record_id":"70250000-0000-4000-8000-005000000041","text":"must roll back"}),
        )
        .await
        .unwrap_err();
    assert!(denied
        .to_string()
        .contains("caller has no portable account binding"));
    let listed_after_rollback = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-005000000041"}),
        )
        .await
        .unwrap();
    assert_eq!(
        listed_after_rollback["attachments"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let history = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-005000000041"}),
        )
        .await
        .unwrap();
    assert!(history["events"].as_array().unwrap().len() >= 3);

    let detached = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "manage_attachments",
            json!({"action":"detach","attachment_id":attachment_id}),
        )
        .await
        .unwrap();
    assert_eq!(detached["detached"], true);
    assert_eq!(detached["blob_retained"], true);
    let listed_after_detach = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "manage_attachments",
            json!({"action":"list","record_id":"70250000-0000-4000-8000-005000000041"}),
        )
        .await
        .unwrap();
    assert!(listed_after_detach["attachments"]
        .as_array()
        .unwrap()
        .is_empty());

    let info = registry
        .call_engine(engine.clone(), caller.clone(), "engine_info", json!({}))
        .await
        .unwrap();
    assert_eq!(info["storage_profile"]["revision"], 4);
    assert_eq!(info["health"]["profile_revision"], 4);
    assert_eq!(
        info["query_sql"],
        native_ce::query::sql_contract::capability(
            native_ce::query::sql_contract::QuerySqlProfile::TursoLocal
        )
    );

    let query = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "query_sql",
            json!({"sql":"SELECT 1"}),
        )
        .await
        .unwrap();
    assert_eq!(query["columns"], json!(["1"]));
    assert_eq!(query["rows"], json!([{"1":1}]));
    let enriched = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000041"],"resolve":true}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        enriched,
        "turso-local operation 'get_record enrichment selectors' is unsupported by the qualified domain boundary"
    );
    let interpretation = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-005000000041"],"include_interpretation":true}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        interpretation,
        "turso-local operation 'get_record interpretation projection' is unsupported by the qualified domain boundary"
    );

    drop(engine);
    drop(db);
    let raw = turso::Builder::new_local(path.to_str().unwrap())
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    let mut rows = connection
        .query("SELECT COUNT(*) FROM blobs", ())
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        1,
        "the rejected authenticated attach rolled back its pre-validation blob while detach retained the committed blob"
    );
    drop(connection);
    drop(raw);
}

#[test]
fn runtime_config_rejects_ambiguous_or_non_portable_paths() {
    let relative = TursoLocalRuntimeConfig::from_json(
        br#"{"format":"native.turso-local-runtime.v1","logical_database_id":"db","data_directory":"relative"}"#,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        relative,
        "Turso-local data_directory must be an absolute path"
    );

    let directory = tempfile::tempdir().unwrap();
    for logical_database_id in [" db", "db ", "\tdb"] {
        let bytes = serde_json::to_vec(&json!({
            "format":TURSO_LOCAL_RUNTIME_CONFIG_FORMAT,
            "logical_database_id":logical_database_id,
            "data_directory":directory.path(),
        }))
        .unwrap();
        assert_eq!(
            TursoLocalRuntimeConfig::from_json(&bytes)
                .unwrap_err()
                .to_string(),
            "Turso-local logical_database_id must contain 1..=255 non-control characters with no leading or trailing whitespace"
        );
    }
}

#[tokio::test]
async fn existing_pre_runtime_file_fails_closed_without_migration() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), "legacy-profile-file");
    let path = config.database_path();
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        connection
            .execute("CREATE TABLE legacy_probe(value TEXT NOT NULL)", ())
            .unwrap();
        connection
            .execute("INSERT INTO legacy_probe(value) VALUES('untouched')", ())
            .unwrap();
    }
    let before_bytes = std::fs::read(&path).unwrap();
    let before_digest = sha2::Sha256::digest(&before_bytes);
    let mut before_entries = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    before_entries.sort();
    let before_schema = {
        let connection = rusqlite::Connection::open(&path).unwrap();
        let rows = connection
            .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")
            .unwrap()
            .query_map((), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        rows
    };

    let error = config.open().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "Turso-local schema version 1 is not supported (required current version {})",
            native_ce::CURRENT_ENGINE_SCHEMA_VERSION
        )
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let value: String = connection
        .query_row("SELECT value FROM legacy_probe", (), |row| row.get(0))
        .unwrap();
    assert_eq!(value, "untouched");
    let after_schema = connection
        .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map((), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(after_schema, before_schema);
    drop(connection);
    assert_eq!(
        sha2::Sha256::digest(std::fs::read(&path).unwrap()),
        before_digest
    );
    let mut after_entries = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    after_entries.sort();
    assert_eq!(
        after_entries, before_entries,
        "preflight must create no sidecars"
    );
}

#[tokio::test]
async fn legacy_v38_shape_fails_closed_without_migration() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), "legacy-v38-shape");
    let database = config.open().await.unwrap();
    let path = config.database_path();
    database
        .contract_downgrade_shape_to_v38_for_test()
        .await
        .unwrap();
    drop(database);
    let before = std::fs::read(&path).unwrap();
    let error = config.open().await.unwrap_err().to_string();
    assert_eq!(
        error,
        format!(
            "Turso-local schema version 38 is not supported (required current version {})",
            native_ce::CURRENT_ENGINE_SCHEMA_VERSION
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

async fn corrupt_runtime(config: &TursoLocalRuntimeConfig, sql: &str) {
    let runtime = config.open().await.unwrap();
    let path = runtime.path().to_path_buf();
    drop(runtime);
    corrupt_turso_file(&path, &[sql]).await;
}

async fn corrupt_turso_file(path: &std::path::Path, statements: &[&str]) {
    let raw = turso::Builder::new_local(path.to_str().unwrap())
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    for statement in statements {
        connection.execute(*statement, ()).await.unwrap();
    }
    drop(connection);
    drop(raw);
}

async fn corrupt_live_runtime(
    config: &TursoLocalRuntimeConfig,
    sql: &str,
) -> native_ce::turso_local::TursoLocalDb {
    corrupt_live_runtime_steps(config, &[sql]).await
}

async fn corrupt_live_runtime_steps(
    config: &TursoLocalRuntimeConfig,
    statements: &[&str],
) -> native_ce::turso_local::TursoLocalDb {
    let runtime = config.open().await.unwrap();
    let path = runtime.path().to_path_buf();
    corrupt_turso_file(&path, statements).await;
    runtime
}

#[tokio::test]
async fn health_covers_every_qualified_projection_before_handlers_reach_it() {
    let directory = tempfile::tempdir().unwrap();
    for (name, table) in [
        ("annotation-targets", "annotation_targets"),
        ("semantic-units", "semantic_units"),
        ("message-audience", "message_audience_state"),
        ("facet-observations", "facet_observations"),
        ("message-mentions", "message_mentions"),
        ("message-conversations", "message_conversations"),
    ] {
        let runtime_config = config(directory.path(), &format!("corrupt-{name}"));
        let runtime = corrupt_live_runtime(&runtime_config, &format!("DROP TABLE {table}")).await;
        let health = runtime.health().await.unwrap();
        assert!(!health.ready, "missing {table} must fail readiness");
        assert!(
            !health.write_ready,
            "missing {table} must fail write readiness"
        );
    }

    let missing_state = config(directory.path(), "corrupt-state-before-handler");
    let runtime = corrupt_live_runtime(&missing_state, "DROP TABLE annotation_targets").await;
    let health = runtime.health().await.unwrap();
    assert!(!health.ready && !health.write_ready);
    let failure = registry()
        .call_engine(
            EngineHandle::TursoLocal(runtime),
            Caller::local(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000048",
                "type":"Document",
                "kind":"note",
                "name":"Must fail",
                "reason":"Readiness must fail before the qualified state query does."
            }),
        )
        .await
        .unwrap_err();
    assert!(!failure.to_string().is_empty());

    let missing_observations = config(directory.path(), "corrupt-observation-before-handler");
    let runtime =
        corrupt_live_runtime(&missing_observations, "DROP TABLE facet_observations").await;
    let health = runtime.health().await.unwrap();
    assert!(!health.ready && !health.write_ready);
    let failure = registry()
        .call_engine(
            EngineHandle::TursoLocal(runtime),
            Caller::local(),
            "create_record",
            json!({
                "id":"70250000-0000-4000-8000-005000000047",
                "type":"Document",
                "kind":"note",
                "name":"Must roll back",
                "facets":{"priority":"high"},
                "reason":"Readiness must fail before the facet observation write does."
            }),
        )
        .await
        .unwrap_err();
    assert!(!failure.to_string().is_empty());

    let missing_index = config(directory.path(), "corrupt-required-index");
    let runtime = corrupt_live_runtime(&missing_index, "DROP INDEX idx_links_source").await;
    let health = runtime.health().await.unwrap();
    assert!(!health.ready && !health.write_ready);
}

#[tokio::test]
async fn same_name_wrong_shape_tables_and_indexes_fail_exact_schema_readiness() {
    async fn assert_rejected(runtime_config: &TursoLocalRuntimeConfig, statements: &[&str]) {
        let runtime = corrupt_live_runtime_steps(runtime_config, statements).await;
        let health = runtime.health().await.unwrap();
        assert!(!health.ready && !health.write_ready);
        drop(runtime);
        assert_eq!(
            runtime_config.open().await.unwrap_err().to_string(),
            "Turso-local required schema is incomplete"
        );
    }

    let directory = tempfile::tempdir().unwrap();
    let facet_observations = config(directory.path(), "malformed-facet-observations");
    assert_rejected(
        &facet_observations,
        &[
            "DROP TABLE facet_observations",
            "CREATE TABLE facet_observations (id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE, key TEXT NOT NULL, value TEXT, op TEXT NOT NULL CHECK (op IN ('set','unset')), vocab_ref TEXT, as_of TEXT NOT NULL, observed_at TEXT NOT NULL, UNIQUE (record_id,key,as_of))",
            "CREATE INDEX idx_facet_observations_series ON facet_observations(record_id,key,as_of)",
            "CREATE INDEX idx_facet_observations_key ON facet_observations(key,as_of)",
        ],
    )
    .await;

    let blobs = config(directory.path(), "malformed-blobs");
    assert_rejected(
        &blobs,
        &[
            "DROP TABLE blobs",
            "CREATE TABLE blobs (id TEXT PRIMARY KEY, bytes BLOB, mime TEXT, size_bytes INTEGER, sha256 TEXT, original_filename TEXT, storage_tier TEXT NOT NULL DEFAULT 'inline', external_ref TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
            "CREATE INDEX idx_blobs_sha ON blobs(sha256)",
        ],
    )
    .await;

    let binding_index = config(directory.path(), "malformed-binding-index");
    assert_rejected(
        &binding_index,
        &[
            "DROP INDEX idx_bindings_external_identity",
            "CREATE INDEX idx_bindings_external_identity ON bindings(system,identifier)",
        ],
    )
    .await;
}

#[tokio::test]
async fn reopen_rejects_overlay_schema_policy_and_seed_corruption() {
    let directory = tempfile::tempdir().unwrap();

    let overlay = config(directory.path(), "corrupt-overlay");
    corrupt_runtime(&overlay, "DROP INDEX records_name_turso_fts").await;
    assert_eq!(
        overlay.open().await.unwrap_err().to_string(),
        "Turso-local database is missing a required physical overlay"
    );

    let schema = config(directory.path(), "corrupt-schema");
    corrupt_runtime(&schema, "DROP TABLE blobs").await;
    assert_eq!(
        schema.open().await.unwrap_err().to_string(),
        "Turso-local required schema is incomplete"
    );

    let policy = config(directory.path(), "corrupt-policy");
    corrupt_runtime(
        &policy,
        "DELETE FROM policy_entries WHERE policy_anchor_id='native:root'",
    )
    .await;
    assert_eq!(
        policy.open().await.unwrap_err().to_string(),
        "Turso-local content/policy genesis is incomplete"
    );

    let policy_anchor = config(directory.path(), "corrupt-policy-anchor");
    corrupt_runtime(
        &policy_anchor,
        "UPDATE records SET policy_anchor_id=NULL WHERE id='native:unfiled'",
    )
    .await;
    assert_eq!(
        policy_anchor.open().await.unwrap_err().to_string(),
        "Turso-local content/policy genesis is incomplete"
    );

    let seed = config(directory.path(), "corrupt-seed");
    corrupt_runtime(
        &seed,
        "DELETE FROM vocabulary_values WHERE id='vv:voc:kind:Collection:folder'",
    )
    .await;
    assert_eq!(
        seed.open().await.unwrap_err().to_string(),
        "Turso-local governed vocabulary genesis is incomplete"
    );
}
