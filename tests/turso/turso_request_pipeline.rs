#![cfg(feature = "turso-tests")]
//! Production request-pipeline authority for the local Turso runtime.
//!
//! Every test here drives a real `EngineHandle::TursoLocal` through the
//! registered MCP surface, so the wrapper under test is the production
//! `TursoRuntimeRequestLifecycle` port and not a lifecycle double.
//!
//! `SHARED_STABLE_ERRORS` and `DUPLICATE_CREATE_ERROR` are byte-identical to
//! the constants in `tests/postgres/postgres_request_pipeline.rs`: the same
//! logical fault must produce the same exact text on both production routes.
//!
//! Two tests attach a stand-in handler to an admitted tool name. That is
//! deliberate: this profile's fixed-profile admission rejects unclassified
//! extension tools before any handler runs, and no qualified Turso tool emits
//! transient evidence yet. Only the leaf handler is a stand-in — the engine
//! handle, the lifecycle port, the admission decision and the dispatch are all
//! production.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, Caller, CustomInteractionPolicy, EngineHandle,
    EngineKind, EvidenceKind, ToolExposure, ToolRegistry, ToolResult, TransientEvidence,
};
use native_ce::storage_profile::{PortabilityEnforcement, PortabilityPolicyUpdate, StorageTarget};
use native_ce::turso_local::{
    register_turso_local_tools, TursoLocalDb, TursoLocalRuntimeConfig,
    TURSO_LOCAL_RUNTIME_CONFIG_FORMAT,
};
use native_ce::{Db, Error, Result};
use serde_json::{json, Value};

const PROBE: &str = "request_pipeline_probe";

/// Logical faults whose exact stable text every adapter must produce.
/// Mirrored verbatim by `tests/postgres/postgres_request_pipeline.rs`.
// The two record ids below are load-bearing text, not just fixtures: this
// table is compared byte for byte against its counterpart, so the ids must
// stay identical in both files (and `...0002` must stay a record that is
// never created, because the last row asserts its not-found text).
const SHARED_STABLE_ERRORS: [(&str, &str); 4] = [
    (
        r#"{"id":"70250000-0000-4000-8000-000000000001","type":"Document","kind":"note","reason":"  "}"#,
        "create_record: 'reason' must not be blank",
    ),
    (
        r#"{"id":"70250000-0000-4000-8000-000000000002","reason":""}"#,
        "update_record: 'reason' must not be blank",
    ),
    (
        r#"{"id":"70250000-0000-4000-8000-000000000002","reason":"\t"}"#,
        "archive_record: 'reason' must not be blank",
    ),
    (
        r#"{"record_id":"70250000-0000-4000-8000-000000000002"}"#,
        "get_history: record 70250000-0000-4000-8000-000000000002 does not exist",
    ),
];

const SHARED_STABLE_ERROR_TOOLS: [&str; 4] = [
    "create_record",
    "update_record",
    "archive_record",
    "get_history",
];

/// The one exact stable text both production routes must produce when a create
/// loses the identifier race. Canonicalized in this loop: the tool-name prefix
/// matches the other shared stable errors, and `uniqueness conflict` is the
/// shared `portable_sql::SqlError::stable_message` category for a duplicate
/// key. Mirrored verbatim by the counterpart request-pipeline file.
const DUPLICATE_CREATE_ERROR: &str = "create_record: uniqueness conflict";

async fn production_handle(directory: &std::path::Path, logical_database_id: &str) -> TursoLocalDb {
    TursoLocalRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format": TURSO_LOCAL_RUNTIME_CONFIG_FORMAT,
            "logical_database_id": logical_database_id,
            "data_directory": directory,
        }))
        .unwrap(),
    )
    .unwrap()
    .open()
    .await
    .unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_turso_local_tools(&mut registry).unwrap();
    registry
}

/// A registry without the qualified Turso tool set, so a stand-in handler can
/// be attached to an admitted tool name. See the module note.
fn registry_without_turso_handlers() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    registry
}

fn register_probe_tool(registry: &mut ToolRegistry) {
    registry
        .register_custom(
            PROBE,
            CustomInteractionPolicy::NoRecordInteractions,
            ToolExposure::extension(true),
            "request pipeline probe",
            json!({"type":"object","properties":{"echo":{"type":"string"}}}),
            |_db: Db, _caller: Caller, _arguments: Value| async move {
                Ok::<_, Error>(json!({"unused": true}))
            },
        )
        .unwrap();
}

fn evidence() -> Result<Vec<TransientEvidence>> {
    Ok(vec![
        TransientEvidence::image("viewport-1440x900", "image/png", b"pixels")?,
        TransientEvidence::pdf("print", b"%PDF-1.7")?,
    ])
}

fn assert_evidence(carried: &[TransientEvidence]) {
    assert_eq!(carried.len(), 2);
    assert_eq!(carried[0].handle, "viewport-1440x900");
    assert_eq!(carried[0].kind, EvidenceKind::Image);
    assert_eq!(carried[0].media_type, "image/png");
    assert_eq!(carried[0].bytes, b"pixels".to_vec());
    assert_eq!(carried[1].handle, "print");
    assert_eq!(carried[1].kind, EvidenceKind::Document);
    assert_eq!(carried[1].media_type, "application/pdf");
    assert_eq!(carried[1].bytes, b"%PDF-1.7".to_vec());
}

async fn create(
    registry: &ToolRegistry,
    db: &TursoLocalDb,
    caller: Caller,
    id: &str,
    overrides: Value,
) -> Result<Value> {
    let mut payload = json!({
        "id": id,
        "type": "Document",
        "kind": "note",
        "name": id,
        "reason": "Exercise the production Turso request pipeline."
    });
    let object = payload.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        object.insert(key.clone(), value.clone());
    }
    registry
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            caller,
            "create_record",
            payload,
        )
        .await
}

/// The durable annotations the wrapper handed the backend, read through the
/// qualified history route rather than the physical file.
async fn persisted_annotations(
    registry: &ToolRegistry,
    db: &TursoLocalDb,
    record_id: &str,
) -> Value {
    let history = registry
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_history",
            json!({"record_id": record_id}),
        )
        .await
        .unwrap();
    let first = history["events"][0].clone();
    json!({
        "actor": first["actor"],
        "run_key": first["run_key"],
        "parent_key": first["parent_key"],
        "intent": first["intent"],
    })
}

/// Set a strict policy through the shipped runtime API.
///
/// This profile declares no canonical-interchange import, so `TursoLocalDb`
/// owns the ingress directly. Nothing test-only is involved: the same public
/// call a product caller would make performs the compare-and-set, the target
/// intersection and the durable write.
async fn install_strict_policy(db: &TursoLocalDb, targets: Vec<StorageTarget>) -> Value {
    let report = db
        .update_portability_policy(PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: targets,
            allow_conversions: vec![],
        })
        .await
        .unwrap();
    // The policy this runtime authors is computed from this runtime's own
    // profile, not the compiled active profile that belongs to SQLite.
    assert_eq!(
        report["source"],
        json!({"id": "turso-local", "revision": 4, "mode": "embedded"}),
        "Turso-authored policy must own its source profile"
    );
    report
}

fn sqlite_local_target() -> StorageTarget {
    StorageTarget {
        id: "sqlite-local".into(),
        revision: 1,
        mode: "embedded".into(),
    }
}

fn postgres_server_target() -> StorageTarget {
    StorageTarget {
        id: "postgres-server".into(),
        revision: 2,
        mode: "network".into(),
    }
}

#[tokio::test]
async fn production_requests_never_leak_identity_intent_or_annotations() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-isolation").await;
    let registry = Arc::new(registry());

    for (id, account) in [
        ("70250000-0000-4000-8000-004000000017", "acct:pipeline-a"),
        ("70250000-0000-4000-8000-004000000018", "acct:pipeline-b"),
    ] {
        registry
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                "create_record",
                json!({
                    "id": id,
                    "type": "Entity",
                    "kind": "person",
                    "name": id,
                    "reason": "Create the request-pipeline isolation principal."
                }),
            )
            .await
            .unwrap();
        db.contract_provision_member(id, account, &format!("native/{id}"))
            .await
            .unwrap();
    }

    // Concurrent calls over one reused handle, each with its own identity and
    // its own correlation.
    //
    // Before either run has declared an intent, neither request may fabricate
    // one or inherit one from reused runtime state.
    let identities = [
        (
            Caller::authenticated("acct:pipeline-a"),
            "scout-chair-a748b2",
        ),
        (
            Caller::authenticated("acct:pipeline-b"),
            "otter-river-b849c3",
        ),
    ];
    let mut calls = Vec::new();
    for (index, (caller, run_key)) in identities.clone().into_iter().enumerate() {
        let registry = Arc::clone(&registry);
        let db = db.clone();
        calls.push(tokio::spawn(async move {
            let id = format!("70250000-0000-4000-8000-0041{index:08x}");
            create(
                &registry,
                &db,
                caller.clone(),
                &id,
                json!({"run_key": run_key, "parent_key": "heron-bread-c94ad4"}),
            )
            .await
            .unwrap();
            (id, caller, run_key)
        }));
    }
    for call in calls {
        let (id, caller, run_key) = call.await.unwrap();
        assert_eq!(
            persisted_annotations(&registry, &db, &id).await,
            json!({
                "actor": caller.credential(),
                "run_key": run_key,
                "parent_key": "heron-bread-c94ad4",
                "intent": Value::Null,
            }),
            "{id}"
        );
    }

    // A later call on the same reused handle inherits nothing from the calls
    // before it — not the identity, not the correlation.
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000035",
        json!({}),
    )
    .await
    .unwrap();
    let unannotated =
        persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000035").await;
    assert_eq!(unannotated["run_key"], Value::Null);
    assert_eq!(unannotated["parent_key"], Value::Null);
    assert_eq!(unannotated["intent"], Value::Null);
    assert_ne!(unannotated["actor"], "acct:pipeline-a");
    assert_ne!(unannotated["actor"], "acct:pipeline-b");
}

#[tokio::test]
async fn production_positive_intent_is_exact_run_scoped_durable_and_replayed() {
    const RUN_A: &str = "scout-chair-a748b2";
    const RUN_B: &str = "otter-river-b849c3";
    let directory = tempfile::tempdir().unwrap();
    let config = TursoLocalRuntimeConfig {
        format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
        logical_database_id: "request-pipeline-positive-intent".into(),
        data_directory: directory.path().to_path_buf(),
    };
    let registry = Arc::new(registry());

    {
        let db = config.open().await.unwrap();
        let mut declarations = Vec::new();
        for (run_key, intent) in [(RUN_A, "Review alpha"), (RUN_B, "Review beta")] {
            let registry = Arc::clone(&registry);
            let db = db.clone();
            declarations.push(tokio::spawn(async move {
                registry
                    .call_engine(
                        EngineHandle::TursoLocal(db),
                        Caller::local(),
                        "set_intent",
                        json!({"run_key":run_key,"intent":intent}),
                    )
                    .await
                    .unwrap()
            }));
        }
        let declared_a = declarations.remove(0).await.unwrap();
        let declared_b = declarations.remove(0).await.unwrap();
        assert_eq!(declared_a["accepted_intent"], "Review alpha");
        assert_eq!(declared_a["run_context"]["intent"], "Review alpha");
        assert_eq!(declared_b["run_context"]["intent"], "Review beta");
        assert_eq!(
            declared_a["briefing"]["this_run"]["declarations"]["total_count"],
            0
        );

        create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000010",
            json!({"run_key":RUN_A}),
        )
        .await
        .unwrap();
        create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000015",
            json!({"run_key":RUN_B}),
        )
        .await
        .unwrap();
        create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000014",
            json!({}),
        )
        .await
        .unwrap();
        assert_eq!(
            persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000010").await
                ["intent"],
            "Review alpha"
        );
        assert_eq!(
            persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000015").await
                ["intent"],
            "Review beta"
        );
        assert_eq!(
            persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000014").await
                ["intent"],
            Value::Null
        );

        let rejected = registry
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                "set_intent",
                json!({"run_key":RUN_A,"intent":7}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            rejected,
            "invalid arguments for set_intent: invalid type: integer `7`, expected a string"
        );
        let after_rejection = create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000012",
            json!({"run_key":RUN_A}),
        )
        .await
        .unwrap();
        assert_eq!(after_rejection["run_context"]["intent"], "Review alpha");

        let identical = registry
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                "set_intent",
                json!({"run_key":RUN_A,"intent":"Review alpha"}),
            )
            .await
            .unwrap();
        assert_eq!(identical["run_context"]["intent"], "Review alpha");
        let after_identical = create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000011",
            json!({"run_key":RUN_A}),
        )
        .await
        .unwrap();
        assert_eq!(after_identical["run_context"]["intent"], "Review alpha");

        registry
            .call_engine(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                "set_intent",
                json!({"run_key":RUN_A,"intent":"Ship alpha"}),
            )
            .await
            .unwrap();
        let updated = create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000013",
            json!({"run_key":RUN_A}),
        )
        .await
        .unwrap();
        assert_eq!(updated["run_context"]["intent"], "Ship alpha");
        assert_eq!(
            persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000013").await
                ["intent"],
            "Ship alpha"
        );
        let beta_after_alpha_change = create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000016",
            json!({"run_key":RUN_B}),
        )
        .await
        .unwrap();
        assert_eq!(
            beta_after_alpha_change["run_context"]["intent"],
            "Review beta"
        );
        assert_eq!(
            persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000016").await
                ["intent"],
            "Review beta"
        );
        db.contract_assert_replay_equivalent().await.unwrap();
    }

    let reopened = config.open().await.unwrap();
    let after_reopen = create(
        &registry,
        &reopened,
        Caller::local(),
        "70250000-0000-4000-8000-004000000009",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    assert_eq!(after_reopen["run_context"]["intent"], "Ship alpha");
    assert_eq!(
        persisted_annotations(&registry, &reopened, "70250000-0000-4000-8000-004000000009").await
            ["intent"],
        "Ship alpha"
    );
}

#[tokio::test]
async fn production_minting_consults_persisted_evidence_and_never_borrows_an_identity() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-minting").await;
    let registry = registry();

    // Establish durable evidence for one agent identity.
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000033",
        json!({"run_key": "scout-chair-a748b2"}),
    )
    .await
    .unwrap();

    // A bare mint must establish a *fresh* persistent identity, so the used
    // agent key is now unavailable however the run id is drawn. Before the
    // minting change this always returned a `scout-chair` key.
    let mut minted = Vec::new();
    for index in 0..4 {
        let outcome = registry
            .call_engine_detailed(
                EngineHandle::TursoLocal(db.clone()),
                Caller::local(),
                "create_record",
                json!({
                    "id": format!("70250000-0000-4000-8000-0042{index:08x}"),
                    "type": "Document",
                    "kind": "note",
                    "reason": "Mint a fresh run identity.",
                    "run_key": "new"
                }),
            )
            .await
            .unwrap();
        outcome.outcome.unwrap();
        let key = outcome.run_context["run_key"].as_str().unwrap().to_string();
        let agent_key = key.rsplit_once('-').unwrap().0.to_string();
        assert_ne!(
            agent_key, "scout-chair",
            "bare mint reused an agent identity that persisted evidence already claims: {key}"
        );
        assert!(!minted.contains(&key), "minted run key {key} twice");
        minted.push(key);
    }

    // Minting under an existing identity keeps that identity and never repeats
    // a persisted key.
    let scoped = registry
        .call_engine_detailed(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-004000000022",
                "type": "Document",
                "kind": "note",
                "reason": "Mint under an existing agent identity.",
                "run_key": "new:scout-chair"
            }),
        )
        .await
        .unwrap();
    scoped.outcome.unwrap();
    let scoped_key = scoped.run_context["run_key"].as_str().unwrap();
    assert!(scoped_key.starts_with("scout-chair-"), "{scoped_key}");
    assert_ne!(scoped_key, "scout-chair-a748b2");
}

/// A malformed `new:<agent>` sentinel never reaches the lifecycle port at all:
/// the shared validator rejects the agent key first, so this proves the shared
/// malformed-input path, NOT the backend's mint-failure path. The deterministic
/// mint-failure proof is the next test.
#[tokio::test]
async fn production_malformed_agent_sentinel_is_rejected_before_the_lifecycle_port() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-malformed-agent").await;
    let registry = registry();

    // The shared fold turns a malformed sentinel into `KeyOutcome::Malformed`,
    // which is NOT an operation rejection: the request succeeds and simply runs
    // uncorrelated, and the echo says so. Changing that would be a product-wide
    // change to the shared run-context semantics, which this task does not make.
    let outcome = registry
        .call_engine_detailed(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-004000000019",
                "type": "Document",
                "kind": "note",
                "reason": "Request a mint under an agent identity that cannot be minted.",
                "run_key": "new:not-a-real-agent"
            }),
        )
        .await
        .unwrap();
    outcome
        .outcome
        .expect("the operation itself is not rejected");
    assert_eq!(outcome.run_context["run_key"], Value::Null);
    let notes = outcome.run_context["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|note| note.as_str().unwrap().contains("not attached to a run")),
        "the caller is not told the call is uncorrelated: {notes:?}"
    );
    assert_eq!(
        persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000019").await,
        json!({
            "actor": "local",
            "run_key": Value::Null,
            "parent_key": Value::Null,
            "intent": Value::Null,
        })
    );
}

#[tokio::test]
async fn production_mint_failure_leaves_the_call_uncorrelated_without_rejecting_it() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-mint-failure").await;
    let registry = registry();

    // A well-formed sentinel that the lifecycle port itself cannot satisfy.
    // Minting only fails in production when the durable evidence read fails or
    // the namespace is exhausted, so the contract harness arms that branch
    // once; everything else on this path is the shipped code.
    db.contract_arm_run_key_mint_failure();
    let outcome = registry
        .call_engine_detailed(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-004000000021",
                "type": "Document",
                "kind": "note",
                "reason": "Mint while the run-key evidence is unavailable.",
                "run_key": "new"
            }),
        )
        .await
        .unwrap();
    outcome
        .outcome
        .expect("the operation itself is not rejected");
    assert_eq!(outcome.run_context["run_key"], Value::Null);
    assert_eq!(
        persisted_annotations(&registry, &db, "70250000-0000-4000-8000-004000000021").await
            ["run_key"],
        Value::Null
    );

    // The arming is one-shot: the very next mint succeeds, so a transient mint
    // failure cannot leave the handle permanently uncorrelated.
    let recovered = registry
        .call_engine_detailed(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "create_record",
            json!({
                "id": "70250000-0000-4000-8000-004000000020",
                "type": "Document",
                "kind": "note",
                "reason": "Mint after the evidence read recovers.",
                "run_key": "new"
            }),
        )
        .await
        .unwrap();
    recovered.outcome.unwrap();
    assert!(recovered.run_context["run_key"].is_string());
}

#[tokio::test]
async fn production_realtime_wakes_once_after_commit_and_stays_silent_otherwise() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-realtime").await;
    let registry = registry();
    let mut tailer = db.subscribe_realtime();

    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000028",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), tailer.next())
            .await
            .expect("committed work wakes the listener")
            .unwrap()
            .generation,
        1
    );
    assert!(
        tailer.try_next().unwrap().is_none(),
        "one committed request produced more than one wakeup"
    );

    registry
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000028"]}),
        )
        .await
        .unwrap();
    assert!(
        tailer.try_next().unwrap().is_none(),
        "a read produced a realtime wakeup"
    );

    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000029",
        json!({"reason":"  "}),
    )
    .await
    .unwrap_err();
    assert!(
        tailer.try_next().unwrap().is_none(),
        "a rejected request produced a realtime wakeup"
    );

    // The losing writer appends inside its transaction and then rolls back.
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000028",
        json!({}),
    )
    .await
    .unwrap_err();
    assert!(
        tailer.try_next().unwrap().is_none(),
        "a rolled-back request produced a realtime wakeup"
    );
}

#[tokio::test]
async fn production_cancellation_is_silent_and_leaves_the_handle_reusable() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-cancel").await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let entries = Arc::new(AtomicUsize::new(0));

    let mut blocking = registry_without_turso_handlers();
    {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        let entries = Arc::clone(&entries);
        blocking
            .register_engine_handler(
                "ping",
                EngineKind::TursoLocal,
                move |_engine, _caller, _arguments| {
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    let entries = Arc::clone(&entries);
                    async move {
                        entries.fetch_add(1, Ordering::AcqRel);
                        entered.notify_one();
                        release.notified().await;
                        Ok::<_, Error>(json!({"ok": true}))
                    }
                },
            )
            .unwrap();
    }
    let blocking = Arc::new(blocking);
    let mut tailer = db.subscribe_realtime();

    let call = tokio::spawn({
        let blocking = Arc::clone(&blocking);
        let db = db.clone();
        async move {
            blocking
                .call_engine(
                    EngineHandle::TursoLocal(db),
                    Caller::local(),
                    "ping",
                    json!({}),
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("the handler was entered");
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    assert_eq!(entries.load(Ordering::Acquire), 1);
    assert!(
        tailer.try_next().unwrap().is_none(),
        "a cancelled request produced a realtime wakeup"
    );

    // The write gate, the realtime channel and the qualified routes all remain
    // usable on the same handle.
    let registry = Arc::new(registry());
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000003",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), tailer.next())
            .await
            .expect("the handle still wakes listeners after a cancellation")
            .unwrap()
            .generation,
        1
    );
    let record = registry
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000003"]}),
        )
        .await
        .unwrap();
    assert_eq!(
        record["records"][0]["id"],
        "70250000-0000-4000-8000-004000000003"
    );

    // Reach the run-context operation's own transaction boundary: the upsert
    // has executed, but cancellation before commit must restore the prior
    // value and leave the same embedded handle reusable.
    const RUN: &str = "scout-chair-a748b2";
    registry
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "set_intent",
            json!({"run_key":RUN,"intent":"Preserved intent"}),
        )
        .await
        .unwrap();
    db.contract_arm_intent_persist_block();
    let intent = tokio::spawn({
        let registry = Arc::clone(&registry);
        let db = db.clone();
        async move {
            registry
                .call_engine(
                    EngineHandle::TursoLocal(db),
                    Caller::local(),
                    "set_intent",
                    json!({"run_key":RUN,"intent":"Must roll back"}),
                )
                .await
        }
    });
    db.contract_wait_for_intent_persist_block().await;
    intent.abort();
    assert!(intent.await.unwrap_err().is_cancelled());
    let preserved = create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000007",
        json!({"run_key":RUN}),
    )
    .await
    .unwrap();
    assert_eq!(preserved["run_context"]["intent"], "Preserved intent");
    registry
        .call_engine(
            EngineHandle::TursoLocal(db.clone()),
            Caller::local(),
            "set_intent",
            json!({"run_key":RUN,"intent":"Reusable handle"}),
        )
        .await
        .unwrap();
    let reused = create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000008",
        json!({"run_key":RUN}),
    )
    .await
    .unwrap();
    assert_eq!(reused["run_context"]["intent"], "Reusable handle");

    release.notify_waiters();
}

#[tokio::test]
async fn production_fixed_profile_admission_admits_qualified_pairs_and_denies_unqualified_pairs() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-admission").await;
    let entries = Arc::new(AtomicUsize::new(0));
    let mut registry = registry();
    register_probe_tool(&mut registry);
    {
        let entries = Arc::clone(&entries);
        registry
            .register_engine_handler(
                PROBE,
                EngineKind::TursoLocal,
                move |_engine, _caller, _arguments| {
                    let entries = Arc::clone(&entries);
                    async move {
                        entries.fetch_add(1, Ordering::AcqRel);
                        Ok::<_, Error>(json!({"reached": true}))
                    }
                },
            )
            .unwrap();
    }
    let engine = EngineHandle::TursoLocal(db.clone());

    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000001",
        json!({}),
    )
    .await
    .unwrap();
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000002",
        json!({}),
    )
    .await
    .unwrap();

    // Qualified operation/capability pairs: capability-less diagnostic, the
    // ids-only read, the record-local history read, and the trusted link add.
    for (tool, arguments) in [
        ("ping", json!({})),
        (
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000001"]}),
        ),
        (
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-004000000001"}),
        ),
        (
            "manage_links",
            json!({
                "action":"add",
                "source_id":"70250000-0000-4000-8000-004000000001",
                "target_id":"70250000-0000-4000-8000-004000000002",
                "relationship":"part_of"
            }),
        ),
    ] {
        registry
            .call_engine(engine.clone(), Caller::local(), tool, arguments)
            .await
            .unwrap_or_else(|error| panic!("{tool} must be admitted: {error}"));
    }

    // An unqualified pair is denied by the wrapper before the handler runs.
    let denied = registry
        .call_engine(engine.clone(), Caller::local(), PROBE, json!({"echo":"x"}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied,
        format!(
            "turso-local fixed-profile admission rejected operation '{PROBE}' with capability 'native.extension.unclassified'"
        )
    );
    assert_eq!(
        entries.load(Ordering::Acquire),
        0,
        "a denied request reached its handler"
    );

    // The denial is per request: the admitted routes still work afterwards.
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000001"]}),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn production_persisted_strict_policy_admits_qualified_pairs() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-policy-admit").await;
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000023",
        json!({}),
    )
    .await
    .unwrap();

    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000024",
        json!({}),
    )
    .await
    .unwrap();

    // The intersection is computed from this profile's own capabilities. Only
    // `link-add` and `guarded-write` are declared full-and-portable here, so
    // those are what a strict policy targeting sqlite-local can admit.
    let report = install_strict_policy(&db, vec![sqlite_local_target()]).await;
    assert_eq!(report["policy_revision"], 1);
    assert_eq!(report["enforcement"], "strict");
    assert_eq!(
        report["admissible_capabilities"],
        json!(["native.guarded-write.v1", "native.operation.link-add.v1"]),
        "the Turso capability intersection, not SQLite's"
    );

    // The ingress is fail-closed and transactional: a stale compare-and-set and
    // a malformed strict policy are both rejected, and neither disturbs the
    // policy already in force.
    let stale = db
        .update_portability_policy(PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: vec![postgres_server_target()],
            allow_conversions: vec![],
        })
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        stale,
        "strict_portability_revision_conflict: expected=0; actual=1"
    );
    let targetless = db
        .update_portability_policy(PortabilityPolicyUpdate {
            if_policy_revision: 1,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: vec![],
            allow_conversions: vec![],
        })
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        targetless,
        "strict portability requires at least one exact target profile"
    );

    // A qualified pair: the trusted link add names `link-add`, which survives
    // this intersection, and the fixed profile admits it too.
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "manage_links",
            json!({
                "action":"add",
                "source_id":"70250000-0000-4000-8000-004000000023",
                "target_id":"70250000-0000-4000-8000-004000000024",
                "relationship":"part_of"
            }),
        )
        .await
        .unwrap();

    // Capability-less diagnostics stay callable under strict enforcement.
    registry
        .call_engine(engine.clone(), Caller::local(), "ping", json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn production_persisted_strict_policy_denies_unqualified_pairs() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-policy-deny").await;
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000023",
        json!({}),
    )
    .await
    .unwrap();

    // The fixed profile admits both pairs below, so a denial can only come from
    // the persisted policy. This profile declares `record-read` and
    // `domain-mcp` only partially, so neither survives its own intersection and
    // the blocker names this profile as the source that cannot offer them.
    install_strict_policy(&db, vec![sqlite_local_target()]).await;
    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000023"]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied,
        "strict_portability_blocked: operation=get_record; capability=native.operation.record-read.v1; target=turso-local@4(embedded); reason=source_capability_not_available"
    );

    // A write is denied by the same intersection rather than silently applied.
    let write = create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000025",
        json!({}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        write,
        "strict_portability_blocked: operation=create_record; capability=native.domain-mcp.v1; target=turso-local@4(embedded); reason=source_capability_not_available"
    );

    // Capability-less diagnostics remain callable even though no ordinary
    // capability survives this intersection.
    registry
        .call_engine(engine.clone(), Caller::local(), "ping", json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn production_stricter_policy_cannot_commit_between_admission_and_execution() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-policy-race").await;
    let registry = Arc::new(registry());
    let engine = EngineHandle::TursoLocal(db.clone());
    for id in [
        "70250000-0000-4000-8000-004000000026",
        "70250000-0000-4000-8000-004000000027",
    ] {
        create(&registry, &db, Caller::local(), id, json!({}))
            .await
            .unwrap();
    }

    // With no policy in force, this read is admitted. Block it after admission
    // and inside its own execution, so the window the policy gate has to close
    // is genuinely open.
    db.contract_arm_snapshot_block("get_record");
    let read = tokio::spawn({
        let registry = Arc::clone(&registry);
        let engine = engine.clone();
        async move {
            registry
                .call_engine(
                    engine,
                    Caller::local(),
                    "get_record",
                    json!({"ids":["70250000-0000-4000-8000-004000000026","70250000-0000-4000-8000-004000000027"]}),
                )
                .await
        }
    });
    db.contract_wait_for_snapshot_block().await;

    // A stricter policy now tries to land mid-request. It must not.
    let update = tokio::spawn({
        let db = db.clone();
        async move {
            db.update_portability_policy(PortabilityPolicyUpdate {
                if_policy_revision: 0,
                enforcement: PortabilityEnforcement::Strict,
                target_profiles: vec![sqlite_local_target()],
                allow_conversions: vec![],
            })
            .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), async {
            while !update.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err(),
        "a stricter policy committed while an admitted request was still executing"
    );

    // Releasing the request lets it finish under the policy it was admitted
    // against, and only then may the update proceed.
    db.contract_release_snapshot_block();
    let records = read.await.unwrap().unwrap();
    assert_eq!(
        records["records"][0]["id"],
        "70250000-0000-4000-8000-004000000026"
    );
    update.await.unwrap().unwrap();

    // The new policy governs everything after it, so the same read is denied.
    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000026"]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        denied.starts_with("strict_portability_blocked: operation=get_record;"),
        "{denied}"
    );
}

#[tokio::test]
async fn production_transient_evidence_survives_backend_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-evidence").await;
    let mut registry = registry_without_turso_handlers();
    registry
        .register_engine_handler(
            "ping",
            EngineKind::TursoLocal,
            |_engine, _caller, _arguments| async move {
                Ok::<_, Error>(ToolResult::rich(json!({"ok": true}), evidence()?))
            },
        )
        .unwrap();
    registry
        .register_engine_handler(
            "get_history",
            EngineKind::TursoLocal,
            |_engine, _caller, _arguments| async move {
                Ok::<_, Error>(ToolResult::rich(json!({"events": []}), evidence()?))
            },
        )
        .unwrap();
    let engine = EngineHandle::TursoLocal(db.clone());

    // The capability-less admission path.
    let diagnostic = registry
        .call_engine_detailed(engine.clone(), Caller::local(), "ping", json!({}))
        .await
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(diagnostic.structured, json!({"ok": true}));
    assert_evidence(&diagnostic.evidence);

    // The classified admission path, with the run-context echo intact.
    let outcome = registry
        .call_engine_detailed(
            engine,
            Caller::local(),
            "get_history",
            json!({"record_id":"70250000-0000-4000-8000-004000000006","run_key":"scout-chair-a748b2"}),
        )
        .await
        .unwrap();
    assert_eq!(outcome.run_context["run_key"], "scout-chair-a748b2");
    let classified = outcome.outcome.unwrap();
    assert_eq!(classified.structured, json!({"events": []}));
    assert_evidence(&classified.evidence);

    // Transient means transient: no handle and no byte may reach the
    // authoritative log, and the database must still replay equivalently after
    // carrying evidence. This is what makes the envelope non-authoritative
    // rather than merely undocumented.
    let events = db.contract_all_content_event_text_for_test().await.unwrap();
    for disclosure in [
        "viewport-1440x900",
        "print",
        "pixels",
        "%PDF-1.7",
        "image/png",
    ] {
        assert!(
            !events.contains(disclosure),
            "transient evidence {disclosure} reached the authoritative log"
        );
    }
    db.contract_assert_replay_equivalent().await.unwrap();
}

#[tokio::test]
async fn production_realtime_listeners_are_scoped_to_their_logical_database() {
    // Two independent runtimes, each owning its own file and its own hub.
    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let first = production_handle(first_directory.path(), "request-pipeline-realtime-a").await;
    let second = production_handle(second_directory.path(), "request-pipeline-realtime-b").await;
    let registry = registry();
    let mut first_listener = first.subscribe_realtime();
    let mut second_listener = second.subscribe_realtime();

    create(
        &registry,
        &first,
        Caller::local(),
        "70250000-0000-4000-8000-004000000032",
        json!({}),
    )
    .await
    .unwrap();

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), first_listener.next())
            .await
            .expect("the committing database wakes its own listener")
            .unwrap()
            .generation,
        1
    );
    assert!(
        first_listener.try_next().unwrap().is_none(),
        "the committing database woke its listener more than once"
    );
    assert!(
        second_listener.try_next().unwrap().is_none(),
        "a commit on one logical database woke an independent database's listener"
    );

    // The second database is live, not merely quiet: its own commit wakes only
    // its own listener.
    create(
        &registry,
        &second,
        Caller::local(),
        "70250000-0000-4000-8000-004000000032",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), second_listener.next())
            .await
            .expect("the second database wakes its own listener")
            .unwrap()
            .generation,
        1
    );
    assert!(
        first_listener.try_next().unwrap().is_none(),
        "a commit on the second database woke the first database's listener"
    );
}

#[tokio::test]
async fn production_cancelled_admission_releases_a_waiting_policy_writer() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-cancel-policy").await;
    let registry = Arc::new(registry());
    let engine = EngineHandle::TursoLocal(db.clone());
    for id in [
        "70250000-0000-4000-8000-004000000004",
        "70250000-0000-4000-8000-004000000005",
    ] {
        create(&registry, &db, Caller::local(), id, json!({}))
            .await
            .unwrap();
    }

    // Block a governed read inside its execution, so it holds the admission
    // read lease. The block is a deterministic checkpoint, not a sleep.
    db.contract_arm_snapshot_block("get_record");
    let read = tokio::spawn({
        let registry = Arc::clone(&registry);
        let engine = engine.clone();
        async move {
            registry
                .call_engine(
                    engine,
                    Caller::local(),
                    "get_record",
                    json!({"ids":["70250000-0000-4000-8000-004000000004","70250000-0000-4000-8000-004000000005"]}),
                )
                .await
        }
    });
    db.contract_wait_for_snapshot_block().await;

    // A stricter policy writer queues behind that lease.
    let update = tokio::spawn({
        let db = db.clone();
        async move {
            db.update_portability_policy(PortabilityPolicyUpdate {
                if_policy_revision: 0,
                enforcement: PortabilityEnforcement::Strict,
                target_profiles: vec![sqlite_local_target()],
                allow_conversions: vec![],
            })
            .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), async {
            while !update.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err(),
        "the policy writer did not wait behind the admitted request"
    );

    // Cancelling the admitted request must release the lease it held, rather
    // than stranding the writer behind a future nobody will finish.
    read.abort();
    assert!(read.await.unwrap_err().is_cancelled());
    update
        .await
        .unwrap()
        .expect("the waiting policy writer completes once the lease is released");

    // And the policy it wrote governs the next request.
    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000004"]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied,
        "strict_portability_blocked: operation=get_record; capability=native.operation.record-read.v1; target=turso-local@4(embedded); reason=source_capability_not_available"
    );
}

#[tokio::test]
async fn production_persisted_strict_policy_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let registry = registry();

    // Install through the shipped runtime route, then prove the live handle
    // enforces it, so reopen is compared against a known-good baseline.
    let installed = {
        let db = production_handle(directory.path(), "request-pipeline-reopen").await;
        create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000030",
            json!({}),
        )
        .await
        .unwrap();
        create(
            &registry,
            &db,
            Caller::local(),
            "70250000-0000-4000-8000-004000000031",
            json!({}),
        )
        .await
        .unwrap();
        let report = install_strict_policy(&db, vec![sqlite_local_target()]).await;
        assert_eq!(report["policy_revision"], 1);
        report
    };
    // Every clone is dropped here, which releases the process ownership lock.

    let reopened = production_handle(directory.path(), "request-pipeline-reopen").await;
    let engine = EngineHandle::TursoLocal(reopened.clone());

    // The strict policy is durable, not a property of the previous process.
    let denied = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":["70250000-0000-4000-8000-004000000030"]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied,
        "strict_portability_blocked: operation=get_record; capability=native.operation.record-read.v1; target=turso-local@4(embedded); reason=source_capability_not_available"
    );

    // The same intersection still admits what it admitted before the reopen.
    registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "manage_links",
            json!({
                "action":"add",
                "source_id":"70250000-0000-4000-8000-004000000030",
                "target_id":"70250000-0000-4000-8000-004000000031",
                "relationship":"part_of"
            }),
        )
        .await
        .unwrap();
    registry
        .call_engine(engine.clone(), Caller::local(), "ping", json!({}))
        .await
        .unwrap();

    // The reopened runtime reads back the same authored policy, so a later
    // compare-and-set continues from the persisted revision.
    let stale = reopened
        .update_portability_policy(PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: vec![sqlite_local_target()],
            allow_conversions: vec![],
        })
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        stale,
        format!(
            "strict_portability_revision_conflict: expected=0; actual={}",
            installed["policy_revision"].as_i64().unwrap()
        )
    );
}

#[tokio::test]
async fn production_request_pipeline_stable_errors_match_the_shared_table() {
    let directory = tempfile::tempdir().unwrap();
    let db = production_handle(directory.path(), "request-pipeline-errors").await;
    let registry = registry();
    let engine = EngineHandle::TursoLocal(db.clone());
    for (index, (arguments, expected)) in SHARED_STABLE_ERRORS.into_iter().enumerate() {
        let tool = SHARED_STABLE_ERROR_TOOLS[index];
        let error = registry
            .call_engine(
                engine.clone(),
                Caller::local(),
                tool,
                serde_json::from_str(arguments).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, expected, "{tool}");
    }

    let unknown = registry
        .call_engine(engine.clone(), Caller::local(), "no_such_tool", json!({}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(unknown, "unknown tool: no_such_tool");
    let search = registry
        .call_engine(
            engine.clone(),
            Caller::local(),
            "search",
            json!({"query":"anything"}),
        )
        .await
        .unwrap();
    assert_eq!(search["returned"], 0);

    // A driver fault is reported through the shared stable category vocabulary
    // (`portable_sql::SqlError::stable_message`), not as raw driver text.
    create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000034",
        json!({}),
    )
    .await
    .unwrap();
    let duplicate = create(
        &registry,
        &db,
        Caller::local(),
        "70250000-0000-4000-8000-004000000034",
        json!({}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(duplicate, DUPLICATE_CREATE_ERROR);
    for disclosure in ["SQLITE_", "UNIQUE constraint", "rowid"] {
        assert!(
            !duplicate.contains(disclosure),
            "stable error disclosed {disclosure}: {duplicate}"
        );
    }
}
