#![cfg(feature = "postgres-tests")]
//! Production request-pipeline authority for the Postgres runtime.
//!
//! Every test here drives a provisioned or imported `EngineHandle::Postgres`
//! through the registered MCP surface, so the wrapper under test is the
//! production `PostgresRequestLifecycle` port and not a lifecycle double.
//!
//! This suite deliberately fails rather than skipping when no server is
//! configured. A request-pipeline authority that reports success without
//! executing anything is worse than a red lane, because the green is read as
//! evidence.
//!
//! `SHARED_STABLE_ERRORS` and `DUPLICATE_CREATE_ERROR` are byte-identical to
//! the constants in `tests/turso/turso_request_pipeline.rs`: the same logical
//! fault must produce the same exact text on both production routes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use native_ce::events::FacetSetPayload;
use native_ce::interchange::export_canonical_interchange;
use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, Caller, CustomInteractionPolicy, EngineHandle,
    EngineKind, EvidenceKind, ToolExposure, ToolRegistry, ToolResult, TransientEvidence,
};
use native_ce::postgres::{
    register_postgres_tools, PostgresCluster, PostgresDb, PostgresRuntimeConfig,
};
use native_ce::storage_profile::{
    update_portability_policy, PortabilityEnforcement, PortabilityPolicyUpdate, StorageTarget,
};
use native_ce::store::{create_record as store_create_record, set_facet};
use native_ce::{Db, Error, Result};
use serde_json::{json, Value};
use sqlx::Row;

const PROBE: &str = "request_pipeline_probe";
const EVIDENCE_PROBE: &str = "request_pipeline_evidence";
const BLOCKING_PROBE: &str = "request_pipeline_block";
const IMPORTED_RECORD: &str = "9c150000-0000-4000-8000-003000000001";

/// Logical faults whose exact stable text every adapter must produce.
/// Mirrored verbatim by `tests/turso/turso_request_pipeline.rs`.
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

fn postgres_url() -> String {
    std::env::var("NATIVE_CE_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        panic!(
            "NATIVE_CE_POSTGRES_TEST_URL is not set. The Postgres request-pipeline authority \
             requires a disposable Postgres server whose role can CREATE SCHEMA and CREATE ROLE. \
             This suite fails rather than reporting success it did not earn."
        )
    })
}

/// Provision a production runtime handle: least-privilege role, owned schema,
/// and a shared connection pool, so pooled reuse is real rather than simulated.
fn production_config(tag: &str) -> PostgresRuntimeConfig {
    let url = postgres_url();
    let logical_database_id = format!("{tag}-{}", uuid::Uuid::new_v4().simple());
    PostgresRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format": "native.postgres-runtime.v1",
            "logical_database_id": logical_database_id,
            "endpoint_url": url,
            "runtime_password": "request-pipeline-password",
            "tls_mode": "disable",
            "application_name": "native-ce-request-pipeline",
            "pool": {
                "min_connections": 0,
                "max_connections": 2,
                "acquisition_timeout_ms": 5000,
                "idle_lifetime_ms": 30000,
                "max_lifetime_ms": 60000
            },
            "timeouts": {
                "statement_timeout_ms": 10000,
                "lock_timeout_ms": 2000
            },
            "admin_url": url,
            "ownership_token": "request-pipeline-ownership-token"
        }))
        .unwrap(),
    )
    .unwrap()
}

async fn production_handle(tag: &str) -> PostgresDb {
    let config = production_config(tag);
    let (db, _report) = config.provision_and_connect().await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_postgres_tools(&mut registry).unwrap();
    registry
}

/// A registered extension tool that reports exactly what the request wrapper
/// handed the backend handler. The SQLite arm is never dispatched here; it
/// exists only because a tool must be registered before an engine handler can
/// be attached to it.
fn register_probe(registry: &mut ToolRegistry, name: &'static str) {
    registry
        .register_custom(
            name,
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

fn observed(caller: &Caller, arguments: &Value) -> Value {
    json!({
        "actor": caller.actor(),
        "credential": caller.credential(),
        "run_key": caller.run_key(),
        "parent_key": caller.parent_key(),
        "intent": caller.intent(),
        "arguments": arguments,
    })
}

fn registry_with_run_context_probe() -> ToolRegistry {
    let mut registry = registry();
    register_probe(&mut registry, PROBE);
    registry
        .register_engine_handler(
            PROBE,
            EngineKind::Postgres,
            |_engine, caller: Caller, arguments: Value| async move {
                Ok::<_, Error>(observed(&caller, &arguments))
            },
        )
        .unwrap();
    registry
}

/// The durable annotations the wrapper handed the backend for one record.
async fn persisted_annotations(db: &PostgresDb, record_id: &str) -> Value {
    let events = db.qualified_table("content_events").unwrap();
    let row = sqlx::query(&format!(
        "SELECT actor,run_key,parent_key,intent FROM {events} WHERE record_id=$1 ORDER BY seq LIMIT 1"
    ))
    .bind(record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    json!({
        "actor": row.try_get::<Option<String>, _>("actor").unwrap(),
        "run_key": row.try_get::<Option<String>, _>("run_key").unwrap(),
        "parent_key": row.try_get::<Option<String>, _>("parent_key").unwrap(),
        "intent": row.try_get::<Option<String>, _>("intent").unwrap(),
    })
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
        revision: 5,
        mode: "network".into(),
    }
}

/// Carry a strict policy into Postgres through the supported product ingress.
///
/// The policy is authored by the real SQLite writer, exported as a canonical
/// document, and imported by the public Postgres importer. No test writes the
/// physical policy row: if the importer does not materialize the policy, these
/// tests cannot pass.
async fn imported_handle_with_strict_policy(
    tag: &str,
    targets: Vec<StorageTarget>,
) -> (PostgresCluster, PostgresDb) {
    let url = postgres_url();
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join(format!("{tag}.db"));
    let source = native_ce::create_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    store_create_record(
        &source,
        json!({
            "id": IMPORTED_RECORD,
            "type": "Document",
            "kind": "note",
            "name": "Request pipeline strict subject",
            "body": "imported through the canonical route"
        }),
    )
    .await
    .unwrap();
    set_facet(
        &source,
        IMPORTED_RECORD,
        FacetSetPayload {
            key: "priority".into(),
            value: Some("high".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    update_portability_policy(
        &source,
        PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: targets,
            allow_conversions: vec![],
        },
    )
    .await
    .unwrap();
    let canonical = export_canonical_interchange(&source).await.unwrap();
    source.close().await;

    let cluster = PostgresCluster::connect(&url).await.unwrap();
    let (db, report) = cluster
        .import_canonical_interchange(&canonical)
        .await
        .unwrap();
    // The importer must now report the policy truthfully: verified, not
    // unmaterialized.
    assert!(
        !report
            .unmaterialized_sections
            .iter()
            .any(|section| section.name == "storage_portability_policy"),
        "the importer still reports the policy unmaterialized: {:?}",
        report.unmaterialized_sections
    );
    let coverage = report
        .verified_projection_coverage
        .iter()
        .find(|coverage| coverage.section == "storage_portability_policy")
        .expect("the importer reports verified policy coverage");
    assert!(coverage.fields.contains(&"enforcement".to_string()));
    assert!(coverage.fields.contains(&"catalog_sha256".to_string()));
    assert!(
        !coverage.fields.contains(&"updated_at".to_string()),
        "updated_at is normalized and must not be claimed as verified"
    );
    (cluster, db)
}

async fn create(
    registry: &ToolRegistry,
    db: &PostgresDb,
    caller: Caller,
    id: &str,
    overrides: Value,
) -> Result<Value> {
    let mut payload = json!({
        "id": id,
        "type": "Document",
        "kind": "note",
        "name": id,
        "reason": "Exercise the production Postgres request pipeline."
    });
    let object = payload.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        object.insert(key.clone(), value.clone());
    }
    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            caller,
            "create_record",
            payload,
        )
        .await
}

#[tokio::test]
async fn production_requests_never_leak_identity_intent_or_annotations() {
    let db = production_handle("request-pipeline-isolation").await;
    let registry = Arc::new(registry_with_run_context_probe());

    // Two identities, each with its own run.
    //
    // Before either run has declared an intent, neither request may fabricate
    // one or inherit one from pooled connection state.
    for (id, account) in [
        ("9c150000-0000-4000-8000-003000000015", "acct:pipeline-a"),
        ("9c150000-0000-4000-8000-003000000016", "acct:pipeline-b"),
    ] {
        create(
            &registry,
            &db,
            Caller::local(),
            id,
            json!({"type":"Entity","kind":"person"}),
        )
        .await
        .unwrap();
        db.provision_member(id, account, &format!("native/{id}"))
            .await
            .unwrap();
    }
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

    // Concurrent calls share one pool. Each must observe only its own caller
    // identity and its own keys, and must acquire no intent at all.
    let mut calls = Vec::new();
    for (caller, run_key) in identities.clone() {
        let registry = Arc::clone(&registry);
        let db = db.clone();
        calls.push(tokio::spawn(async move {
            let observed = registry
                .call_engine(
                    EngineHandle::Postgres(db),
                    caller.clone(),
                    PROBE,
                    json!({"run_key": run_key, "parent_key": "heron-bread-c94ad4", "echo": run_key}),
                )
                .await
                .unwrap();
            (caller, run_key, observed)
        }));
    }
    for call in calls {
        let (caller, run_key, observed) = call.await.unwrap();
        assert_eq!(observed["credential"], caller.credential());
        assert_eq!(observed["run_key"], run_key);
        assert_eq!(observed["parent_key"], "heron-bread-c94ad4");
        assert_eq!(observed["intent"], Value::Null, "intent was fabricated");
        // The wrapper strips the correlation arguments before the handler and
        // leaves everything else exactly as the caller sent it.
        assert_eq!(observed["arguments"], json!({"echo": run_key}));
        assert_eq!(observed["run_context"]["run_key"], run_key);
    }

    // Sequential reuse of the same pooled connections must not inherit the
    // previous call's identity, correlation or intent — in the handler or in
    // the durable annotations.
    create(
        &registry,
        &db,
        Caller::authenticated("acct:pipeline-a"),
        "9c150000-0000-4000-8000-003000000003",
        json!({"run_key":"scout-chair-a748b2","parent_key":"heron-bread-c94ad4"}),
    )
    .await
    .unwrap();
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000024",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000003").await,
        json!({
            "actor": "acct:pipeline-a",
            "run_key": "scout-chair-a748b2",
            "parent_key": "heron-bread-c94ad4",
            "intent": Value::Null,
        })
    );
    let unannotated = persisted_annotations(&db, "9c150000-0000-4000-8000-003000000024").await;
    assert_eq!(unannotated["run_key"], Value::Null);
    assert_eq!(unannotated["parent_key"], Value::Null);
    assert_eq!(unannotated["intent"], Value::Null);
    assert_ne!(unannotated["actor"], "acct:pipeline-a");

    // A call with no run context inherits nothing at all.
    let bare = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            PROBE,
            json!({"echo": "no-keys"}),
        )
        .await
        .unwrap();
    assert_eq!(bare["run_key"], Value::Null);
    assert_eq!(bare["parent_key"], Value::Null);
    assert_eq!(bare["intent"], Value::Null);

    db.close().await;
}

#[tokio::test]
async fn production_positive_intent_is_exact_run_scoped_durable_and_replayed() {
    const RUN_A: &str = "scout-chair-a748b2";
    const RUN_B: &str = "otter-river-b849c3";
    let config = production_config("request-pipeline-positive-intent");
    let (db, _report) = config.provision_and_connect().await.unwrap();
    let registry = Arc::new(registry());

    // Distinct declarations may race on one pooled runtime; each upsert owns
    // only its exact full key.
    let mut declarations = Vec::new();
    for (run_key, intent) in [(RUN_A, "Review alpha"), (RUN_B, "Review beta")] {
        let registry = Arc::clone(&registry);
        let db = db.clone();
        declarations.push(tokio::spawn(async move {
            registry
                .call_engine(
                    EngineHandle::Postgres(db),
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
        "9c150000-0000-4000-8000-003000000007",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000012",
        json!({"run_key":RUN_B}),
    )
    .await
    .unwrap();
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000011",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000007").await["intent"],
        "Review alpha"
    );
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000012").await["intent"],
        "Review beta"
    );
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000011").await["intent"],
        Value::Null
    );

    // A rejected handler never reaches the persistence hook and leaves the
    // previous value intact. Identical redeclaration is idempotent; changed
    // prose replaces the current value for this key only.
    let rejected = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
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
        "9c150000-0000-4000-8000-003000000009",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    assert_eq!(after_rejection["run_context"]["intent"], "Review alpha");

    let identical = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
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
        "9c150000-0000-4000-8000-003000000008",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    assert_eq!(after_identical["run_context"]["intent"], "Review alpha");

    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
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
        "9c150000-0000-4000-8000-003000000010",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    assert_eq!(updated["run_context"]["intent"], "Ship alpha");
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000010").await["intent"],
        "Ship alpha"
    );
    let beta_after_alpha_change = create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000013",
        json!({"run_key":RUN_B}),
    )
    .await
    .unwrap();
    assert_eq!(
        beta_after_alpha_change["run_context"]["intent"],
        "Review beta"
    );
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000013").await["intent"],
        "Review beta"
    );
    db.close().await;
    let reopened = config.connect().await.unwrap();
    let after_reopen = create(
        &registry,
        &reopened,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000006",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    assert_eq!(after_reopen["run_context"]["intent"], "Ship alpha");
    assert_eq!(
        persisted_annotations(&reopened, "9c150000-0000-4000-8000-003000000006").await["intent"],
        "Ship alpha"
    );
    reopened.close().await;

    // Production runtime roles are deliberately unable to CREATE SCHEMA, so
    // the authoritative replay scratch area is an operator-owned proof. Drive
    // the same registered route on that handle before asking it to rebuild.
    let cluster = PostgresCluster::connect(&postgres_url()).await.unwrap();
    let replay_db = cluster.fresh_logical_database().await.unwrap();
    registry
        .call_engine(
            EngineHandle::Postgres(replay_db.clone()),
            Caller::local(),
            "set_intent",
            json!({"run_key":RUN_A,"intent":"Replay authority"}),
        )
        .await
        .unwrap();
    create(
        &registry,
        &replay_db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000014",
        json!({"run_key":RUN_A}),
    )
    .await
    .unwrap();
    replay_db.assert_replay_equivalent().await.unwrap();
    replay_db.drop_schema().await.unwrap();
    cluster.close().await;
}

/// Minting must consult durable evidence, so every call here is a production
/// `create_record` that actually writes a content event.
///
/// An earlier version of this test minted through the read-only probe. That
/// proved nothing: `request_interactions` is deliberately excluded from
/// collision evidence, and the probe writes neither `content_events` nor
/// `run_contexts`, so no minted key left a trace for the next mint to avoid.
#[tokio::test]
async fn production_minting_consults_persisted_evidence_and_never_borrows_an_identity() {
    let db = production_handle("request-pipeline-minting").await;
    let registry = registry();

    let mint = |id: String, run_key: &'static str| {
        let registry = &registry;
        let db = &db;
        async move {
            let outcome = registry
                .call_engine_detailed(
                    EngineHandle::Postgres(db.clone()),
                    Caller::local(),
                    "create_record",
                    json!({
                        "id": id,
                        "type": "Document",
                        "kind": "note",
                        "reason": "Mint a run identity through a durable write.",
                        "run_key": run_key
                    }),
                )
                .await
                .unwrap();
            outcome.outcome.expect("the create itself must succeed");
            outcome.run_context["run_key"]
                .as_str()
                .expect("a minted run key")
                .to_string()
        }
    };

    // Durable evidence for one agent identity, written by a production route.
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000022",
        json!({"run_key": "scout-chair-a748b2"}),
    )
    .await
    .unwrap();
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000022").await["run_key"],
        "scout-chair-a748b2"
    );

    // A bare mint establishes a *fresh* persistent identity, so the agent key
    // the seeded evidence already claims is unavailable however the run id is
    // drawn. Each mint also writes its own event, so later mints must avoid the
    // earlier ones too.
    let mut minted = Vec::new();
    for index in 0..4 {
        let id = format!("9c150000-0000-4000-8000-0032{index:08x}");
        let key = mint(id.clone(), "new").await;
        let agent_key = key.rsplit_once('-').unwrap().0.to_string();
        assert_ne!(
            agent_key, "scout-chair",
            "bare mint reused an agent identity that persisted evidence already claims: {key}"
        );
        assert!(!minted.contains(&key), "minted run key {key} twice");
        // The minted key reached the durable log, which is what makes it
        // evidence for the next mint rather than a number the echo invented.
        assert_eq!(persisted_annotations(&db, &id).await["run_key"], key);
        minted.push(key);
    }

    // Minting under an existing identity keeps that identity and never repeats
    // a persisted key.
    let scoped = mint(
        "9c150000-0000-4000-8000-003000000017".into(),
        "new:scout-chair",
    )
    .await;
    assert!(scoped.starts_with("scout-chair-"), "{scoped}");
    assert_ne!(
        scoped, "scout-chair-a748b2",
        "scoped mint reissued the persisted full key"
    );
    assert_eq!(
        persisted_annotations(&db, "9c150000-0000-4000-8000-003000000017").await["run_key"],
        scoped
    );

    db.close().await;
}

#[tokio::test]
async fn production_realtime_wakes_once_after_commit_and_stays_silent_otherwise() {
    let db = production_handle("request-pipeline-realtime").await;
    let registry = registry();
    let mut wakeups = db.realtime_hub().subscribe();

    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000018",
        json!({}),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), wakeups.recv())
        .await
        .expect("committed work wakes the listener")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), wakeups.recv())
            .await
            .is_err(),
        "one committed request produced more than one wakeup"
    );

    // A read must not wake anyone.
    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-003000000018"]}),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), wakeups.recv())
            .await
            .is_err(),
        "a read produced a realtime wakeup"
    );

    // An argument failure never reaches storage, so nothing may wake.
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000019",
        json!({"reason":"  "}),
    )
    .await
    .unwrap_err();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), wakeups.recv())
            .await
            .is_err(),
        "a rejected request produced a realtime wakeup"
    );

    // A rolled-back write appends inside the transaction and then loses the
    // identifier race, so the request must remain silent.
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000018",
        json!({}),
    )
    .await
    .unwrap_err();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), wakeups.recv())
            .await
            .is_err(),
        "a rolled-back request produced a realtime wakeup"
    );

    db.close().await;
}

#[tokio::test]
async fn production_cancellation_is_silent_and_leaves_the_handle_reusable() {
    let db = production_handle("request-pipeline-cancel").await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let entries = Arc::new(AtomicUsize::new(0));
    let mut registry = registry();
    register_probe(&mut registry, BLOCKING_PROBE);
    {
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        let entries = Arc::clone(&entries);
        registry
            .register_engine_handler(
                BLOCKING_PROBE,
                EngineKind::Postgres,
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
    let registry = Arc::new(registry);
    let mut wakeups = db.realtime_hub().subscribe();

    let call = tokio::spawn({
        let registry = Arc::clone(&registry);
        let db = db.clone();
        async move {
            registry
                .call_engine(
                    EngineHandle::Postgres(db),
                    Caller::local(),
                    BLOCKING_PROBE,
                    json!({"run_key":"scout-chair-a748b2"}),
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
        tokio::time::timeout(Duration::from_millis(150), wakeups.recv())
            .await
            .is_err(),
        "a cancelled request produced a realtime wakeup"
    );

    // The admission lease, the pool and the wakeup channel all remain usable.
    create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000002",
        json!({}),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), wakeups.recv())
        .await
        .expect("the handle still wakes listeners after a cancellation")
        .unwrap();
    let record = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-003000000002"]}),
        )
        .await
        .unwrap();
    assert_eq!(
        record["records"][0]["id"],
        "9c150000-0000-4000-8000-003000000002"
    );

    // Reach the run-context operation's own transaction boundary: the upsert
    // has executed, but cancellation before commit must restore the prior
    // value and leave the same pooled handle reusable.
    const RUN: &str = "scout-chair-a748b2";
    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
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
                    EngineHandle::Postgres(db),
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
        "9c150000-0000-4000-8000-003000000004",
        json!({"run_key":RUN}),
    )
    .await
    .unwrap();
    assert_eq!(preserved["run_context"]["intent"], "Preserved intent");
    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
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
        "9c150000-0000-4000-8000-003000000005",
        json!({"run_key":RUN}),
    )
    .await
    .unwrap();
    assert_eq!(reused["run_context"]["intent"], "Reusable handle");

    release.notify_waiters();
    db.close().await;
}

#[tokio::test]
async fn production_strict_portability_admits_qualified_pairs_through_the_imported_policy() {
    // Pinned back to the source profile: the ids-only read capability survives
    // the intersection, so the qualified pair is admitted.
    let (cluster, db) =
        imported_handle_with_strict_policy("strict-admit", vec![sqlite_local_target()]).await;
    let mut registry = registry();
    register_probe(&mut registry, PROBE);
    registry
        .register_engine_handler(
            PROBE,
            EngineKind::Postgres,
            |_engine, caller: Caller, arguments: Value| async move {
                Ok::<_, Error>(observed(&caller, &arguments))
            },
        )
        .unwrap();

    let admitted = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":[IMPORTED_RECORD]}),
        )
        .await
        .unwrap();
    assert_eq!(admitted["records"][0]["id"], IMPORTED_RECORD);

    // An unclassified extension capability is not declared by the source
    // profile at all, so strict mode denies it under the same policy.
    let unclassified = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            PROBE,
            json!({"echo":"denied"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        unclassified,
        format!(
            "strict_portability_blocked: operation={PROBE}; capability=native.extension.unclassified; target=sqlite-local@2(embedded); reason=source_capability_not_available"
        )
    );

    // The denial is per request, not sticky.
    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":[IMPORTED_RECORD]}),
        )
        .await
        .unwrap();

    db.drop_schema().await.unwrap();
    cluster.close().await;
}

#[tokio::test]
async fn production_strict_portability_denies_unqualified_pairs_through_the_imported_policy() {
    // Pinned to a target that only partially supports the read capability.
    let (cluster, db) =
        imported_handle_with_strict_policy("strict-deny", vec![postgres_server_target()]).await;
    let registry = registry();

    let denied = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":[IMPORTED_RECORD]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        denied,
        "strict_portability_blocked: operation=get_record; capability=native.operation.record-read.v1; target=postgres-server@5(network); reason=target_support_partial"
    );

    // No ordinary capability survives this intersection, yet the
    // capability-less diagnostics must stay callable.
    registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "ping",
            json!({}),
        )
        .await
        .unwrap();
    let info = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "engine_info",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(info["storage_profile"]["id"], "postgres-server");

    db.drop_schema().await.unwrap();
    cluster.close().await;
}

#[tokio::test]
async fn production_transient_evidence_survives_backend_dispatch() {
    // Admin-backed contract fixture, required only because the replay check at
    // the end rebuilds authoritative state into an isolated sibling schema,
    // which the least-privilege runtime role deliberately cannot create. The
    // request lifecycle and engine route below are unchanged production: the
    // same registry dispatch over the same EngineHandle::Postgres.
    let cluster = PostgresCluster::connect(&postgres_url()).await.unwrap();
    let db = cluster.fresh_logical_database().await.unwrap();
    let mut registry = registry();
    register_probe(&mut registry, EVIDENCE_PROBE);
    registry
        .register_engine_handler(
            EVIDENCE_PROBE,
            EngineKind::Postgres,
            |_engine, _caller, _arguments| async move {
                Ok::<_, Error>(ToolResult::rich(
                    json!({"ok": true}),
                    vec![
                        TransientEvidence::image("viewport-1440x900", "image/png", b"pixels")?,
                        TransientEvidence::pdf("print", b"%PDF-1.7")?,
                    ],
                ))
            },
        )
        .unwrap();

    let outcome = registry
        .call_engine_detailed(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            EVIDENCE_PROBE,
            json!({"run_key":"scout-chair-a748b2"}),
        )
        .await
        .unwrap();
    assert_eq!(outcome.run_context["run_key"], "scout-chair-a748b2");
    let result = outcome.outcome.unwrap();
    assert_eq!(result.structured, json!({"ok": true}));
    assert_eq!(result.evidence.len(), 2);

    let image = &result.evidence[0];
    assert_eq!(image.handle, "viewport-1440x900");
    assert_eq!(image.kind, EvidenceKind::Image);
    assert_eq!(image.media_type, "image/png");
    assert_eq!(image.bytes, b"pixels".to_vec());

    let document = &result.evidence[1];
    assert_eq!(document.handle, "print");
    assert_eq!(document.kind, EvidenceKind::Document);
    assert_eq!(document.media_type, "application/pdf");
    assert_eq!(document.bytes, b"%PDF-1.7".to_vec());

    // Transient means transient: no handle and no byte may reach the
    // authoritative log, and the database must still replay equivalently after
    // carrying evidence.
    let events = db.qualified_table("content_events").unwrap();
    for disclosure in [
        "viewport-1440x900",
        "print",
        "pixels",
        "%PDF-1.7",
        "image/png",
    ] {
        let leaked: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {events} WHERE payload::text LIKE $1 OR id LIKE $1 \
             OR record_id LIKE $1 OR COALESCE(actor,'') LIKE $1"
        ))
        .bind(format!("%{disclosure}%"))
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            leaked, 0,
            "transient evidence {disclosure} reached the authoritative log"
        );
    }
    db.assert_replay_equivalent().await.unwrap();

    db.drop_schema().await.unwrap();
    cluster.close().await;
}

#[tokio::test]
async fn production_realtime_listeners_are_scoped_to_their_logical_database() {
    // Two independently provisioned logical databases, each with its own
    // schema, pool and realtime hub.
    let first = production_handle("request-pipeline-realtime-a").await;
    let second = production_handle("request-pipeline-realtime-b").await;
    let registry = registry();
    let mut first_listener = first.realtime_hub().subscribe();
    let mut second_listener = second.realtime_hub().subscribe();

    create(
        &registry,
        &first,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000020",
        json!({}),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), first_listener.recv())
        .await
        .expect("the committing database wakes its own listener")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), first_listener.recv())
            .await
            .is_err(),
        "the committing database woke its listener more than once"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), second_listener.recv())
            .await
            .is_err(),
        "a commit on one logical database woke an independent database's listener"
    );

    // The second database is live, not merely quiet.
    create(
        &registry,
        &second,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000020",
        json!({}),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), second_listener.recv())
        .await
        .expect("the second database wakes its own listener")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), first_listener.recv())
            .await
            .is_err(),
        "a commit on the second database woke the first database's listener"
    );

    // A read and a rejected write are silent on both.
    registry
        .call_engine(
            EngineHandle::Postgres(first.clone()),
            Caller::local(),
            "get_record",
            json!({"ids":["9c150000-0000-4000-8000-003000000020"]}),
        )
        .await
        .unwrap();
    create(
        &registry,
        &first,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000021",
        json!({"reason":"  "}),
    )
    .await
    .unwrap_err();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), first_listener.recv())
            .await
            .is_err(),
        "a read or rejected write produced a realtime wakeup"
    );

    first.close().await;
    second.close().await;
}

#[tokio::test]
async fn production_record_routes_return_exact_stable_errors() {
    let db = production_handle("request-pipeline-errors").await;
    let registry = registry();
    for (index, (arguments, expected)) in SHARED_STABLE_ERRORS.into_iter().enumerate() {
        let tool = SHARED_STABLE_ERROR_TOOLS[index];
        let error = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::local(),
                tool,
                serde_json::from_str(arguments).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, expected, "{tool}");
    }

    // Registry-level faults are adapter independent apart from the named
    // backend, and never disclose the physical schema.
    let unknown = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
            Caller::local(),
            "no_such_tool",
            json!({}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(unknown, "unknown tool: no_such_tool");
    let search = registry
        .call_engine(
            EngineHandle::Postgres(db.clone()),
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
        "9c150000-0000-4000-8000-003000000023",
        json!({}),
    )
    .await
    .unwrap();
    let duplicate = create(
        &registry,
        &db,
        Caller::local(),
        "9c150000-0000-4000-8000-003000000023",
        json!({}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(duplicate, DUPLICATE_CREATE_ERROR);
    for disclosure in ["SQLSTATE", "duplicate key value", "pg_temp", db.schema()] {
        assert!(
            !duplicate.contains(disclosure),
            "stable error disclosed {disclosure}: {duplicate}"
        );
    }

    db.close().await;
}
