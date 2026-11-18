//! Replay conformance (task 11c04ff, decision 2aacbb7 point 2).
//!
//! Every write that is declared local-first (`requires_acceptance = false`)
//! must be safe to replay: the node applies it to its local copy, journals it,
//! and may later send it to hosted again, or rebuild its copy from base plus
//! journal. This test runs each such operation against a seeded base and
//! checks, by logical state, that
//!
//! - **rebuild**: a fresh fork of the base with the journal replayed (the call
//!   once) ends in the same state as the fork the call was first applied to;
//! - **redelivery**: the same call delivered twice, with the same key, ends in
//!   the same state as delivering it once, and the second delivery is accepted.
//!
//! "Fork" is a disposable `VACUUM INTO` copy of the base, the same way
//! `crate::fork::ForkManager` makes one; "journal" is the list of calls
//! applied to it. The `ForkManager` itself admits only `create_record` and
//! `update_record`, so this test drives the registry directly on the copies.
//!
//! The same pass runs on two engines ([`Engine::Sqlite`] and
//! [`Engine::KernelV2`]): production hosted runs KernelV2, and some operations
//! (`merge_body`, `manage_saved_tabs.*`) exist only there. The fixtures, the
//! comparison and the named lists are shared; where an engine needs something
//! different it is a small explicit per-engine table (history tables,
//! `NOT_SERVED_ON_<engine>`, per-engine known failures).
//!
//! An operation with no fixture must be on the engine's not-yet-covered list,
//! with a reason.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(feature = "v2-kernel-probe")]
use native_ce::mcp::executor_prototype::replay_operations_on_kernel_v2;
use native_ce::mcp::executor_prototype::{
    declared_local_first_operations, replay_operations, ReplayOperation,
};
#[cfg(feature = "v2-kernel-probe")]
use native_ce::mcp::{kernel_v2::register_kernel_v2_tools, register_builtin_tools, EngineHandle};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, open_existing_database_at, Db};
use serde_json::{json, Value};
use sha2::Digest;

/// A canonical account token for the hosted owner who claims a record.
const ALICE: &str = "acct_0123456789abcdef0123456789abcdef";
/// The account that owns the KernelV2 seed database and runs its fixtures.
/// Canonical `acct_` hex shape: `manage_saved_tabs` only serves callers
/// whose credential is one, and the seed owner must qualify.
#[cfg(feature = "v2-kernel-probe")]
const V2_ADMIN: &str = "acct_fedcba9876543210fedcba9876543210";

/// The engine a replay pass runs on. SQLite is the ordinary local engine;
/// KernelV2 is what production hosted runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Engine {
    Sqlite,
    #[cfg(feature = "v2-kernel-probe")]
    KernelV2,
}
/// The stance date the attribution fixture states, so it is compared as given.
const HISTORIC_STANCE: &str = "2026-01-01T00:00:00.000Z";
const RUN_KEY: &str = "scout-chair-c748b2";
const REASON: &str = "Replay conformance fixture: the call's subject is not this reason.";

// ---------------------------------------------------------------------------
// The base and its forks
// ---------------------------------------------------------------------------

/// A seeded base database and the ids the fixtures refer to.
struct World {
    dir: tempfile::TempDir,
    engine: Engine,
    base: Db,
    registry: Arc<ToolRegistry>,
    ids: BTreeMap<&'static str, String>,
    receipts: BTreeMap<&'static str, Value>,
    forks: std::sync::atomic::AtomicUsize,
    /// The home new KernelV2 records are filed under. SQLite fixtures name
    /// no home.
    #[cfg(feature = "v2-kernel-probe")]
    home: String,
}

impl World {
    fn id(&self, name: &str) -> String {
        self.ids
            .get(name)
            .unwrap_or_else(|| panic!("seed has no {name}"))
            .clone()
    }

    /// The caller replay fixtures run as. SQLite runs local; KernelV2
    /// authenticates as the seed database's owner.
    #[cfg(feature = "v2-kernel-probe")]
    fn caller(&self) -> Caller {
        match self.engine {
            Engine::Sqlite => Caller::local(),
            Engine::KernelV2 => Caller::authenticated(V2_ADMIN),
        }
    }
}

async fn seed_call(world_registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    world_registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap_or_else(|error| panic!("seed {tool} failed: {error}"))
}

async fn seed() -> World {
    seed_on(Engine::Sqlite).await
}

async fn seed_on(engine: Engine) -> World {
    match engine {
        Engine::Sqlite => seed_sqlite().await,
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => seed_v2().await,
    }
}

async fn seed_sqlite() -> World {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.sqlite");
    let base = create_database(path.to_str().unwrap()).await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let registry = Arc::new(registry);
    let mut ids = BTreeMap::new();
    for (name, record_type, kind, body) in [
        ("note_a", "Document", "note", "alpha beta"),
        ("note_b", "Document", "note", "second note"),
        ("note_c", "Document", "note", "to archive"),
        ("note_d", "Document", "note", "observed"),
        ("note_e", "Document", "note", "line one\n"),
        ("note_f", "Document", "note", "attachment host"),
        ("task_t", "WorkItem", "task", "a task"),
    ] {
        let receipt = seed_call(
            &registry,
            &base,
            "create_record",
            json!({"type": record_type, "kind": kind, "name": name, "body": body,
                   "reason": REASON}),
        )
        .await;
        ids.insert(name, receipt["id"].as_str().unwrap().to_owned());
    }
    let mut receipts = BTreeMap::new();

    // A link to remove.
    seed_call(
        &registry,
        &base,
        "manage_links",
        json!({"action": "add", "source_id": ids["note_a"].clone(), "target_id": ids["task_t"].clone(),
               "relationship": "derived_from"}),
    )
    .await;

    // An observation to unset.
    seed_call(
        &registry,
        &base,
        "manage_facet_observations",
        json!({"action": "set", "record_id": ids["note_d"].clone(), "key": "current", "value": "11",
               "as_of": "2026-08-01T00:00:00Z", "reason": REASON}),
    )
    .await;

    // Two open suggestions, on separate targets.
    for (name, target) in [
        ("suggestion_reject", "sugg_target_1"),
        ("suggestion_accept", "sugg_target_2"),
    ] {
        let target_id = seed_call(
            &registry,
            &base,
            "create_record",
            json!({"type": "Document", "kind": "note", "name": target, "body": "alpha beta",
                   "reason": REASON}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let suggestion = seed_call(
            &registry,
            &base,
            "create_record",
            json!({"type": "Annotation", "kind": "suggestion", "name": name,
                   "lifecycle": "open", "body": "gamma", "reason": REASON,
                   "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
                   "links": [{"target_id": target_id, "relationship": "part_of"}]}),
        )
        .await;
        ids.insert(name, suggestion["id"].as_str().unwrap().to_owned());
    }

    // A citation to reanchor, on a bearer task.
    let citation = seed_call(
        &registry,
        &base,
        "create_record",
        json!({"type": "Annotation", "kind": "citation", "name": "Evidence",
               "body": "Why this matters", "reason": REASON,
               "links": [{"target_id": ids["task_t"].clone(), "relationship": "part_of"}],
               "target": {"target_record_id": ids["note_a"].clone(), "source_slot": "body",
                          "selectors": [{"type": "text_quote", "exact": "alpha"}]}}),
    )
    .await;
    ids.insert("citation", citation["id"].as_str().unwrap().to_owned());

    // Three relationship assertions, one for each follow-up action. Only
    // `assigned_to` is governed for contest.
    let local_person = bound_person(&registry, &base, "assignee", "local", None).await;
    ids.insert("local_person", local_person);
    for (name, relationship, source, target) in [
        (
            "relationship_contest",
            "assigned_to",
            "task_t",
            "local_person",
        ),
        ("relationship_retract", "depends_on", "note_a", "note_c"),
        ("relationship_evidence", "depends_on", "note_b", "note_c"),
    ] {
        let receipt = seed_call(
            &registry,
            &base,
            "manage_relationships",
            json!({"action": "assert", "relationship_type": relationship,
                   "endpoints": [{"role": "subject", "record_id": ids[source].clone()},
                                 {"role": "object", "record_id": ids[target].clone()}],
                   "idempotency_key": format!("seed-{name}")}),
        )
        .await;
        receipts.insert(name, receipt);
    }

    // An unowned record for a hosted owner to claim.
    bound_person(&registry, &base, "alice", ALICE, None).await;
    let ownerless = seed_call(
        &registry,
        &base,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "ownerless", "body": "abandoned",
               "reason": REASON}),
    )
    .await;
    ids.insert("ownerless", ownerless["id"].as_str().unwrap().to_owned());

    // An attribution by an agent over a considered note.
    let bearer = seed_call(
        &registry,
        &base,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "claim bearer",
               "body": "A considered view.", "reason": REASON}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ids.insert("bearer", bearer.clone());
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
    let attribution = registry
        .call(
            base.clone(),
            agent_caller(&issuer, &bearer),
            "create_attribution",
            attribution_args(&base, &bearer).await,
        )
        .await
        .unwrap_or_else(|error| panic!("seed create_attribution failed: {error}"));
    receipts.insert("attribution", attribution);

    // Messages between two people, and rooms to sort them into.
    let sender = bound_person(
        &registry,
        &base,
        "msg sender",
        "acct_msg_sender",
        Some("native/msg-sender"),
    )
    .await;
    let recipient = bound_person(
        &registry,
        &base,
        "msg recipient",
        "acct_msg_recipient",
        Some("native/msg-recipient"),
    )
    .await;
    for room in ["room_a", "room_b"] {
        let id = seed_call(
            &registry,
            &base,
            "create_record",
            json!({"type": "Conversation", "kind": "discussion", "name": room, "reason": REASON}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        ids.insert(room, id);
    }
    for message in ["message_classify", "message_unclassify", "message_move"] {
        let sent = seed_call(
            &registry,
            &base,
            "manage_messages",
            json!({"action": "send", "body": message, "owner_id": sender,
                   "origin": {"type": "direct", "participant_ids": [sender, recipient]},
                   "addressed_to": [recipient], "expectation": "none",
                   "idempotency_key": format!("seed-{message}"), "reason": REASON}),
        )
        .await;
        ids.insert(message, sent["id"].as_str().unwrap().to_owned());
    }
    for message in ["message_unclassify", "message_move"] {
        seed_call(
            &registry,
            &base,
            "manage_messages",
            json!({"action": "classify", "message_id": ids[message].clone(),
                   "conversation_id": ids["room_a"].clone()}),
        )
        .await;
    }
    // One more message, classified with a verified provenance interaction
    // through the real token path: its attestation carries the receipt row
    // the comparison covers. No fixture touches it, so every fork carries
    // the seed's identical copy and losing it fails loudly.
    let receipt_message = seed_call(
        &registry,
        &base,
        "manage_messages",
        json!({"action": "send", "body": "receipt bearer", "owner_id": sender,
               "origin": {"type": "direct", "participant_ids": [sender, recipient]},
               "addressed_to": [recipient], "expectation": "none",
               "idempotency_key": "seed-message-receipt", "reason": REASON}),
    )
    .await;
    let receipt_args = json!({"action": "classify", "message_id": receipt_message["id"].clone(),
               "conversation_id": ids["room_a"].clone()});
    let receipt_issuer =
        native_ce::provenance::ProvenanceInteractionTokenIssuer::random("replay-seed");
    let receipt_scope =
        native_ce::provenance::verified_action_scope("manage_messages", &receipt_args);
    let receipt_token = receipt_issuer.issue("local", &receipt_scope, 60).unwrap();
    registry
        .call(
            base.clone(),
            Caller::local()
                .with_provenance_interaction_token(&receipt_issuer, &receipt_token, &receipt_scope)
                .unwrap(),
            "manage_messages",
            receipt_args,
        )
        .await
        .unwrap();

    // A task already claimed, for release; a run, for set_intent and close_run.
    let claimed = seed_call(
        &registry,
        &base,
        "create_record",
        json!({"type": "WorkItem", "kind": "task", "name": "claimed task", "reason": REASON}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ids.insert("task_claimed", claimed.clone());
    seed_call(
        &registry,
        &base,
        "start_work",
        json!({"record_id": claimed, "action": "claim"}),
    )
    .await;
    seed_call(
        &registry,
        &base,
        "set_intent",
        json!({"intent": "replay conformance", "run_key": RUN_KEY}),
    )
    .await;

    // Seeded rows for the compared provenance tables that fixtures never
    // write. Each is fully consistent (the attribution and validity rows
    // reference a real seeded keyed attestation, the cancellation carries
    // its matching control event, the validity pair ends restored, and the
    // interaction receipt above came through the real token path), but no
    // fixture replays these triples, so every fork carries the seed's
    // identical copy. The attribution, cancellation and validity rows are
    // direct inserts, with the reason: the validity seam is not MCP-exposed,
    // cancellation needs a verified held command the harness cannot mint,
    // and attribution needs a hosted-shell-vouched install the harness
    // cannot register.
    let keyed_attestation: (String,) = sqlx::query_as(
        "SELECT id FROM provenance_action_attestations WHERE operation = 'manage_relationships' AND command_identity_digest IS NOT NULL ORDER BY issued_at LIMIT 1",
    )
    .fetch_one(base.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO provenance_action_app_attributions (action_attestation_id, package, version, install_event_id, assertion) VALUES (?, 'agent.test', '1', 'install', 'host')",
    )
    .bind(&keyed_attestation.0)
    .execute(&crate::common::fixture_write_pool(&base).await)
    .await
    .unwrap();
    let origin: (String,) =
        sqlx::query_as("SELECT origin_db_id FROM database_identity WHERE singleton = 1")
            .fetch_one(base.pool())
            .await
            .unwrap();
    let app_none = hex::encode(sha2::Sha256::digest(
        serde_jcs::to_vec(&json!({"assertion": "none"})).unwrap(),
    ));
    let evidence = json!({
        "origin_db_id": origin.0,
        "principal": "local",
        "operation": "create_record",
        "command_identity_digest": "c".repeat(64),
        "action_digest": "a".repeat(64),
        "intent_digest": Value::Null,
        "app_context_digest": app_none,
    });
    let identity = hex::encode(sha2::Sha256::digest(serde_jcs::to_vec(&evidence).unwrap()));
    let cancel_event = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO control_events (id, idempotency_key, type, schema_version, aggregate_kind, aggregate_id, actor, run_key, reason, payload, created_at, act) VALUES (?, ?, 'held_command.cancelled.v1', 1, 'held_command', ?, 'local', NULL, 'Cancelled an unaccepted held command.', ?, '2026-01-02T00:00:00.000Z', NULL)",
    )
    .bind(&cancel_event)
    .bind(format!("held-command-cancel:{identity}"))
    .bind(&identity)
    .bind(serde_json::to_string(&evidence).unwrap())
    .execute(&crate::common::fixture_write_pool(&base).await)
    .await
    .unwrap();
    // The open path requires one application row per control event, as the
    // runtime writes beside every append.
    let cancel_seq: (i64,) = sqlx::query_as("SELECT seq FROM control_events WHERE id = ?")
        .bind(&cancel_event)
        .fetch_one(base.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO control_event_applications(event_id, event_seq, applied_at) VALUES(?, ?, '2026-01-02T00:00:00.000Z')",
    )
    .bind(&cancel_event)
    .bind(cancel_seq.0)
    .execute(&crate::common::fixture_write_pool(&base).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO provenance_local_command_cancellations (event_id, origin_db_id, principal, operation, command_identity_digest, action_digest, intent_digest, app_context_digest) VALUES (?, ?, 'local', 'create_record', ?, ?, NULL, ?)",
    )
    .bind(&cancel_event)
    .bind(&origin.0)
    .bind("c".repeat(64))
    .bind("a".repeat(64))
    .bind(&app_none)
    .execute(&crate::common::fixture_write_pool(&base).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO provenance_attestation_validity_events (id, attestation_id, ordinal, status, reason, issuer, issued_at, act) VALUES ('seed-validity-0', ?, 0, 'invalidated', 'compromise', 'operator', '2026-01-03T00:00:00.000Z', NULL), ('seed-validity-1', ?, 1, 'restored', 'resolved', 'operator', '2026-01-03T00:00:00.000Z', NULL)",
    )
    .bind(&keyed_attestation.0)
    .bind(&keyed_attestation.0)
    .execute(&crate::common::fixture_write_pool(&base).await)
    .await
    .unwrap();

    // The `provenance_action_events` history exclusion rests on this: the
    // legacy-integrity branch reads that table only for schema-version-1
    // attestations, and every attestation here is v2.
    let legacy: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM provenance_action_attestations WHERE schema_version <> 2",
    )
    .fetch_one(base.pool())
    .await
    .unwrap();
    assert_eq!(legacy.0, 0, "the seed mints no legacy attestations");

    World {
        dir,
        engine: Engine::Sqlite,
        base,
        registry,
        ids,
        receipts,
        forks: Default::default(),
        #[cfg(feature = "v2-kernel-probe")]
        home: String::new(),
    }
}

/// The KernelV2 seed: the same logical records the SQLite seed holds, filed
/// under one home, so the shared fixtures run on both engines. Anything the
/// KernelV2 catalogue does not serve is not seeded here; it is named in
/// [`NOT_SERVED_ON_KERNEL_V2`].
#[cfg(feature = "v2-kernel-probe")]
async fn seed_v2() -> World {
    use native_ce::events::KERNEL_ROOT_ID;
    use native_ce::v2_standard::{claims_v1, document4_package, relates_to, saved_tabs, v1_compat};

    // `merge_body` ships dark behind this flag; the seed stands in for a host
    // that has it on. Process-wide like production `install`, and read by no
    // other test in this binary.
    native_ce::body_merge_flag::install(native_ce::body_merge_flag::BodyMergeConfig {
        enabled: true,
        accounts: None,
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base-v2.sqlite");
    let (base, admin) =
        native_ce::kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", V2_ADMIN)
            .await
            .unwrap();
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_kernel_v2_tools(&mut registry).unwrap();
    let registry = Arc::new(registry);
    for package in [
        v1_compat::package(),
        document4_package(),
        relates_to::package(),
        saved_tabs::package(),
        claims_v1::package(),
    ] {
        let identity = package.identity().unwrap();
        native_ce::kernel::install_package_as(&base, &admin, &package)
            .await
            .unwrap();
        native_ce::kernel::adopt_package_at(
            &base,
            &admin,
            KERNEL_ROOT_ID,
            &package,
            Some(&identity),
            &package.declared_reads,
        )
        .await
        .unwrap();
    }
    let home = native_ce::kernel::create_home(&base, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let mut ids = BTreeMap::new();
    let receipts = BTreeMap::new();
    let world = World {
        dir,
        engine: Engine::KernelV2,
        base,
        registry,
        ids: BTreeMap::new(),
        receipts,
        forks: Default::default(),
        home: home.clone(),
    };
    for (name, record_type, kind, body) in [
        ("note_a", "Document", "note", "alpha beta"),
        ("note_b", "Document", "note", "second note"),
        ("note_c", "Document", "note", "to archive"),
        ("note_e", "Document", "note", "line one\n"),
        ("note_f", "Document", "note", "attachment host"),
        ("task_t", "WorkItem", "task", "a task"),
    ] {
        let receipt = seed_v2_call(
            &world,
            "create_record",
            json!({"type": record_type, "kind": kind, "name": name, "body": body,
                   "home_id": home, "reason": REASON}),
        )
        .await;
        ids.insert(name, receipt["id"].as_str().unwrap().to_owned());
    }
    // A link to remove, with an authored historical timestamp: the provider
    // row carries it verbatim, so replay compares it instead of masking it.
    // (The MCP surface cannot author one — manage_links hardcodes
    // `claimed_timestamp: None` — so the seed goes through the provider
    // directly. Rows the fixture's own calls mint stay engine-stamped and
    // are masked only when they cannot be authored.)
    let authored = "2026-09-01T00:00:00.000Z";
    let request = native_ce::kernel::prepare_provider_as(
        &world.base,
        &admin,
        &ids["note_a"],
        &ids["task_t"],
        "seed-link-remove-1",
        native_ce::v2_standard::relates_to::Command::Assert {
            sources: vec![native_ce::v2_standard::relates_to::Source {
                source_id: uuid::Uuid::new_v4().to_string(),
                from: ids["note_a"].clone(),
                to: ids["task_t"].clone(),
                claimed_author: None,
                claimed_timestamp: Some(authored.into()),
                note: None,
            }],
        },
    )
    .await
    .unwrap();
    native_ce::kernel::commit_provider_as(&world.base, &admin, &request)
        .await
        .unwrap();
    // A task already claimed, for the claim fixture's sibling.
    let claimed = seed_v2_call(
        &world,
        "create_record",
        json!({"type": "WorkItem", "kind": "task", "name": "claimed task",
               "home_id": home, "reason": REASON}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ids.insert("task_claimed", claimed.clone());
    seed_v2_call(
        &world,
        "start_work",
        json!({"record_id": claimed, "action": "claim", "run_key": RUN_KEY}),
    )
    .await;
    seed_v2_call(
        &world,
        "set_intent",
        json!({"intent": "replay conformance", "run_key": RUN_KEY}),
    )
    .await;
    // A saved tab to rename and retire.
    let tab = seed_v2_call(
        &world,
        "manage_saved_tabs",
        json!({"action": "create", "creation_key": "seed-tab", "app": "docs",
               "initial_record_id": Value::Null, "reason": REASON}),
    )
    .await["tab"]
        .clone();
    ids.insert("seed_tab", tab["record_id"].as_str().unwrap().to_owned());
    ids.insert(
        "seed_tab_revision",
        tab["revision"].as_str().unwrap().to_owned(),
    );
    World { ids, ..world }
}

/// One seed call on the KernelV2 world, as its owner.
#[cfg(feature = "v2-kernel-probe")]
async fn seed_v2_call(world: &World, tool: &str, args: Value) -> Value {
    world
        .registry
        .call_engine(
            EngineHandle::KernelV2(world.base.clone()),
            Caller::authenticated(V2_ADMIN),
            tool,
            args,
        )
        .await
        .unwrap_or_else(|error| panic!("seed {tool} failed: {error}"))
}

/// A person record with a canonical account binding, written through the
/// identity API so the binding has its audit history.
async fn bound_person(
    registry: &ToolRegistry,
    db: &Db,
    name: &str,
    account: &str,
    principal: Option<&str>,
) -> String {
    let person = seed_call(
        registry,
        db,
        "create_record",
        json!({"type": "Entity", "kind": "person", "name": name, "reason": REASON}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (system, identifier) in [("account", Some(account)), ("native-principal", principal)] {
        let Some(identifier) = identifier else {
            continue;
        };
        native_ce::identity::add_binding(
            db,
            &native_ce::identity::MutationContext {
                actor: "local",
                reason: "replay conformance person",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: true,
                source_read_authorized: false,
            },
            &person,
            &native_ce::identity::BindingClaim {
                system: system.into(),
                identifier: identifier.into(),
            },
            true,
        )
        .await
        .unwrap();
    }
    person
}

fn agent_caller(
    issuer: &native_ce::awareness::HumanInteractionTokenIssuer,
    bearer: &str,
) -> Caller {
    let ids = vec![bearer.to_string()];
    let token = issuer
        .issue(
            "local",
            "agent-executor:test-agent:test-delegation",
            &ids,
            60,
        )
        .unwrap();
    Caller::local()
        .with_agent_executor_token(issuer, &token, "test-agent", "test-delegation", &ids)
        .unwrap()
}

/// An assessment attribution over `bearer`'s current body.
async fn attribution_args(db: &Db, bearer: &str) -> Value {
    use sha2::{Digest, Sha256};
    let (event_id, body): (String, String) = sqlx::query_as(
        "SELECT e.id, r.body FROM records r JOIN content_events e ON e.record_id = r.id
          WHERE r.id = ? AND e.type = 'record.created'",
    )
    .bind(bearer)
    .fetch_one(db.pool())
    .await
    .unwrap();
    json!({
        "idempotency_key": format!("assess-{}", uuid::Uuid::new_v4()),
        "bearer_id": bearer,
        "target": {"source_event_id": event_id,
                   "source_body_sha256": hex::encode(Sha256::digest(body.as_bytes())),
                   "scope": "whole_revision", "selectors": []},
        "subject": {"kind": "self_agent_execution"},
        "relation": "expresses_view", "polarity": "affirmed", "confidence": "likely",
        "transformation": "summary",
        "rationale": "The agent assesses that the exact revision is its own view.",
    })
}

/// A disposable copy of the base, made the way `ForkManager` makes one. Both
/// engines keep their state in SQLite files, so the same copy works for each;
/// only the opener differs, since v1 serving refuses v2 files.
async fn fork(world: &World, name: &str) -> Db {
    let n = world
        .forks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = world.dir.path().join(format!("{name}-{n}.sqlite"));
    sqlx::query("VACUUM INTO ?")
        .bind(path.to_str().unwrap())
        .execute(world.base.pool())
        .await
        .unwrap();
    match world.engine {
        Engine::Sqlite => open_existing_database_at(&path).await.unwrap(),
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => native_ce::kernel::open_marked_v2_database(path.to_str().unwrap())
            .await
            .unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Logical state
// ---------------------------------------------------------------------------

/// The only tables left out of the comparison, by exact name, each because it
/// records how or when something happened rather than what is true. Every
/// other table in the schema is compared, so a new table is compared until
/// someone adds it here in a reviewed edit; `the_comparison_leaves_out_only_history`
/// checks this list against the schema.
/// Provenance split: every provenance table is COMPARED except
/// `provenance_action_events`, which stays history. The attestation,
/// output-membership and authority tables are the keyed-retry path, not
/// logs: retry lookup joins attestations to authority
/// (`provenance::lookup_authorized_command_identity_in`), rebuilds the
/// response from outputs (`mcp::tools::keyed_replay::lookup_and_load_in`),
/// and held cancellation reads the same rows
/// (`provenance::cancellation::lookup`). The app-attribution table is read
/// by `require_command_app_in` (`src/provenance.rs`) from keyed lookup; the
/// cancellation table is read by `anchored_in`
/// (`src/provenance/cancellation.rs`) via the guard every keyed lookup runs;
/// the validity table is read by held cancellation lookup to reject
/// invalidated attestations; the interaction-receipt table backs the
/// cancellation evidence integrity check. A replay that dropped or altered
/// any of these rows would keep every other compared table identical, so
/// they are all compared like KernelV2's `kernel_provider_receipts`:
/// minted ids get content labels, only named incidental fields mask, and
/// digests validate before masking. Output event ids resolve to labels
/// derived from the referenced event's content, so a retargeted output
/// cannot compare equal. `provenance_action_events` stays excluded for two
/// narrow reasons, not because nothing reads it. The legacy-integrity branch
/// reads it, but only for schema-version-1 attestations
/// (`src/provenance.rs`), and no fixture creates one: every attestation here
/// is v2, pinned by the seed assertion below. The contribution reader
/// (`attestation_for_event_in` in `src/contribution.rs`) serves record views,
/// which no replay fixture invokes. If either stops holding, compare the
/// table instead: unlike the tables above, nothing in these states consults
/// it, so excluding it cannot hide a replay divergence here.
const HISTORY_TABLES: &[(&str, &str)] = &[
    ("content_events", "event log"),
    ("relationship_events", "event log"),
    ("control_events", "event log"),
    ("awareness_events", "event log"),
    ("meta_events", "event log"),
    ("policy_events", "event log"),
    ("derivation_events", "event log"),
    ("notification_candidate_events", "event log"),
    ("relationship_federation_events", "event log"),
    ("provenance_action_events", "provenance of acts"),
    ("read_log_calls", "read log"),
    ("read_log_record_ids", "read log"),
    ("read_log_touches", "read log"),
    ("act_cutover", "act counter"),
    ("act_state", "act counter"),
];

/// Tables that hold live configuration or state and have been mistaken for
/// history before (`artifact_*` and `derivation_artifact_*` contain "act_").
/// They must always be compared.
const LIVE_TABLES_THAT_MUST_BE_COMPARED: &[&str] = &[
    "records",
    "links",
    "facet_values",
    "artifact_inputs",
    "artifact_module_grants",
    "derivation_artifact_role_heads",
    "relationships",
    "bindings",
];

/// Columns holding integer milliseconds since the epoch, by exact name: the
/// same instant as [`TIME_COLUMNS`] in a different storage class. Two correct
/// runs differ in them, so a value inside the call's window is masked.
const TIME_MS_COLUMNS: &[&str] = &["created_at_ms"];

/// Columns, by exact name wherever they occur, that hold the time something
/// happened. Two correct runs differ in them. Whether such a column is set at
/// all is still compared (a tombstone's `deleted_at` is NULL or not), only the
/// instant is not.
const TIME_COLUMNS: &[&str] = &[
    "as_of",
    "acknowledged_at",
    "added_at",
    "anchored_at",
    "applied_at",
    "asserted_at",
    "assigned_at",
    "bound_at",
    "claimed_at",
    "classified_at",
    "completed_at",
    "confirmed_at",
    "created_at",
    "cutover_at",
    "deleted_at",
    "detached_at",
    "ended_at",
    "expires_at",
    "failed_at",
    "first_presented_at",
    "ingested_at",
    "issued_at",
    "joined_at",
    "last_activity_at",
    "last_applied_at",
    "last_presented_at",
    "last_seen_at",
    "lease_expires_at",
    "migrated_at",
    "next_attempt_at",
    "observed_at",
    "occurred_at",
    "opened_at",
    "published_at",
    "received_at",
    "recomputed_at",
    "retired_at",
    "retracted_at",
    "revoked_at",
    "selected_at",
    "source_created_at",
    "started_at",
    "updated_at",
    "verified_at",
];

/// Specific (table, column) cells that are not time columns but are still
/// different between two correct runs, each with the reason. Found by running
/// the check; nothing is added without a reason.
const INCIDENTAL_CELLS: &[(&str, &str, &str)] = &[
    (
        "relationship_local_admissions",
        "local_evidence_digest",
        "a digest over evidence that names minted ids",
    ),
    (
        "effective_relationships",
        "assertion_set_digest",
        "a digest over the minted assertion ids",
    ),
    (
        "provenance_action_attestations",
        "output_event_set_digest",
        "a digest over the outputs, which name minted events",
    ),
];

/// Engine-generated timestamps nested inside JSON blobs, by table, column
/// and JSON path. Each is stamped by the call itself, so two correct runs
/// differ in it; masking applies only inside the call's window. Anything not
/// named here compares verbatim: authored JSON and body text are never
/// masked. Found by running the check; nothing is added without a reason.
const INCIDENTAL_JSON_TIMES: &[(&str, &str, &[&str])] = &[
    ("kernel_mcp_write_receipts", "receipt_json", &["updated_at"]),
    (
        "kernel_mcp_write_receipts",
        "receipt_json",
        &["write_receipt", "event", "created_at"],
    ),
    // A batched create quotes each record beside its own id.
    (
        "kernel_mcp_write_receipts",
        "receipt_json",
        &["record", "updated_at"],
    ),
    (
        "kernel_mcp_write_receipts",
        "receipt_json",
        &["record", "write_receipt", "event", "created_at"],
    ),
    (
        "kernel_mcp_write_receipts",
        "receipt_json",
        &["blob", "created_at"],
    ),
    ("kernel_attachment_blobs", "metadata", &["created_at"]),
    (
        "kernel_provider_state",
        "state_json",
        &["state", "holder", "claimed_at"],
    ),
    (
        "kernel_provider_state",
        "state_json",
        &["state", "assertions", "*", "asserted_at"],
    ),
    (
        "kernel_provider_state",
        "state_json",
        &["state", "assertions", "*", "retracted_at"],
    ),
];

/// Engine-generated values nested inside JSON blobs that are never
/// comparable across runs, by table, column and JSON path.
/// `request_digest` digests the relationship provider request including the
/// minted operation key, so two correct runs differ in it; the runtime
/// rechecks it on redelivery, and the claim's domain effect is compared in
/// the kernel tables. The claim `request_checksum` is NOT masked: the
/// fixture passes an explicit operation key, so it compares verbatim, and
/// corrupting it must fail.
const INCIDENTAL_JSON_VALUES: &[(&str, &str, &[&str])] = &[(
    "kernel_provider_receipts",
    "request_json",
    &["request_digest"],
)];

/// JSON columns holding an array whose order follows minted ids rather than
/// meaning, so it is compared as a set. Every other array is ordered.
const ORDER_FREE_JSON_COLUMNS: &[(&str, &str)] =
    &[("effective_relationships", "knowledge_watermark")];

const UUID: &str = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/// One compared table: its single-column primary key, if any, and its rows as
/// column to `quote()`d value (every value text, whatever its storage class).
struct Table {
    key: Option<String>,
    rows: Vec<BTreeMap<String, String>>,
}

type State = BTreeMap<String, Table>;

/// Names of every table in the schema, and of the ones to leave out because
/// they are not data: SQLite's own, virtual tables and their shadow tables.
async fn schema_tables(db: &Db) -> (Vec<String>, BTreeSet<String>) {
    let all: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(db.pool())
            .await
            .unwrap();
    let virtual_tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE 'CREATE VIRTUAL TABLE%'",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    let derived = all
        .iter()
        .filter(|name| {
            name.starts_with("sqlite_")
                || virtual_tables
                    .iter()
                    .any(|v| *name == v || name.starts_with(&format!("{v}_")))
        })
        .cloned()
        .collect();
    (all, derived)
}

fn is_history(engine: Engine, name: &str) -> bool {
    HISTORY_TABLES.iter().any(|(table, _)| *table == name)
        || history_tables_extra(engine)
            .iter()
            .any(|(table, _)| *table == name)
}

/// History tables the engine adds beyond the shared [`HISTORY_TABLES`]. Each
/// has the same bar: it records how or when something happened, not what is
/// true. Empty until the KernelV2 pass names its first one with a reason.
fn history_tables_extra(engine: Engine) -> &'static [(&'static str, &'static str)] {
    match engine {
        Engine::Sqlite => &[],
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => KERNEL_V2_HISTORY_TABLES,
    }
}

/// Extra history tables on KernelV2: tables that exist only there and record
/// how or when something happened rather than what is true. Empty today:
/// `kernel_provider_receipts` is compared, with only its named incidental
/// fields masked, because deleting or corrupting a receipt must fail.
#[cfg(feature = "v2-kernel-probe")]
const KERNEL_V2_HISTORY_TABLES: &[(&str, &str)] = &[];

/// Row counts of the history tables, for saying what a call that changed no
/// logical state did write.
async fn history_counts(engine: Engine, db: &Db) -> BTreeMap<String, i64> {
    let mut counts = BTreeMap::new();
    for (table, _) in HISTORY_TABLES.iter().chain(history_tables_extra(engine)) {
        if let Ok(n) = sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM \"{table}\""))
            .fetch_one(db.pool())
            .await
        {
            counts.insert(table.to_string(), n);
        }
    }
    counts
}

/// Every table that is not history, with its rows.
async fn logical_state(engine: Engine, db: &Db) -> State {
    let (all, derived) = schema_tables(db).await;
    let mut state = State::new();
    for table in all
        .into_iter()
        .filter(|t| !is_history(engine, t) && !derived.contains(t))
    {
        let columns: Vec<String> =
            sqlx::query_scalar(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .fetch_all(db.pool())
                .await
                .unwrap();
        let keys: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM pragma_table_info('{table}') WHERE pk > 0"
        ))
        .fetch_all(db.pool())
        .await
        .unwrap();
        let object = columns
            .iter()
            .map(|c| format!("'{c}', quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join(", ");
        let rows: Vec<String> =
            sqlx::query_scalar(&format!("SELECT json_object({object}) FROM \"{table}\""))
                .fetch_all(db.pool())
                .await
                .unwrap();
        state.insert(
            table,
            Table {
                key: (keys.len() == 1).then(|| keys[0].clone()),
                rows: rows
                    .iter()
                    .map(|row| serde_json::from_str::<BTreeMap<String, String>>(row).unwrap())
                    .collect(),
            },
        );
    }
    state
}

/// Makes two runs of the same correct call comparable and nothing more.
///
/// - **Minted ids.** A new id is labelled by the row whose key it is (its
///   table and its content with other new ids blanked), so which new record a
///   row points at is compared, while which random id it got is not. Two new
///   ids in one table with the same content cannot be told apart, so that is
///   reported as an ambiguity rather than compared: the fixture must make
///   them differ.
/// - **Times.** A value in a named time column or JSON path is masked only
///   when it falls inside the time window of the call that produced the
///   state, and only when it differs from the base's value for the same
///   row: seed data is identical on every fork, so a time stored in a row
///   the call did not touch is compared as it is, even inside the window.
/// - **Named cells** ([`INCIDENTAL_CELLS`], [`ORDER_FREE_JSON_COLUMNS`]) are
///   masked or compared as sets; text is otherwise compared as it is.
struct Normaliser {
    base_ids: BTreeSet<String>,
    /// Single-column primary key per table, where the base has one.
    base_keys: BTreeMap<String, String>,
    /// Base rows by (table, primary-key value): the seed copy, identical on
    /// every fork. A time value that matches its base row is always
    /// compared verbatim, so masking can never manufacture a
    /// window-straddle difference on seeded data.
    base_rows: BTreeMap<(String, String), BTreeMap<String, String>>,
    uuid: regex::Regex,
    whole_uuid: regex::Regex,
    time: regex::Regex,
    /// When the call that produced the state ran, with a little slack. `None`
    /// masks no time.
    window: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

/// New ids that share a label: the comparison cannot tell them apart.
#[derive(Debug)]
struct Ambiguous {
    table: String,
    row: String,
}

/// An output that references an event the comparison cannot see: the
/// referenced row is missing from the event tables, so no content label
/// exists for it. Fails the check the way an ambiguity does.
#[derive(Debug)]
struct Unresolved {
    table: String,
    row: String,
}

/// Why labelling a state failed.
#[derive(Debug)]
enum LabelError {
    Ambiguous(Ambiguous),
    Unresolved(Unresolved),
}

/// One event an output can reference, read from the event tables even though
/// those tables stay excluded from the comparison. Only the content the
/// label needs is kept: the subject identity, the event type, the payload,
/// and — for relationship events, whose ids are only unique per issuer —
/// the issuing origin.
struct EventView {
    parts: Vec<String>,
    typ: String,
    payload: Value,
    issuer: String,
}

/// The events outputs can reference, split by domain: content ids are only
/// unique within content_events, and relationship ids only per issuer, so a
/// single id-keyed map would let a same-id row in the other domain shadow
/// the referenced event. `content_events` and `relationship_events` stay
/// excluded from the comparison, but output event ids resolve to labels
/// derived from this content, so retargeting an output at another event
/// cannot compare equal. A table that does not exist on the engine
/// (KernelV2 has no SQLite event log) contributes nothing; an output that
/// references a missing row then fails loudly as unresolved.
#[derive(Default)]
struct EventMaps {
    content: BTreeMap<String, EventView>,
    relationship: BTreeMap<(String, String), EventView>,
}

/// Every event an output membership row can reference, by domain.
async fn output_event_rows(db: &Db) -> EventMaps {
    let mut events = EventMaps::default();
    let has = |table: &str| {
        let table = table.to_owned();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(db.pool())
            .await
            .unwrap_or(0)
                > 0
        }
    };
    if has("content_events").await {
        let rows: Vec<(String, String, String, String)> =
            sqlx::query_as("SELECT id, record_id, type, payload FROM content_events")
                .fetch_all(db.pool())
                .await
                .unwrap();
        for (id, record_id, typ, payload) in rows {
            events.content.insert(
                id,
                EventView {
                    parts: vec![record_id],
                    typ,
                    payload: serde_json::from_str(&payload).unwrap_or(Value::String(payload)),
                    issuer: String::new(),
                },
            );
        }
    }
    if has("relationship_events").await {
        let rows: Vec<(String, String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, stream_kind, stream_id, relationship_id, type, payload, issuer_origin_db_id FROM relationship_events",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        for (id, kind, stream, relationship, typ, payload, issuer) in rows {
            events.relationship.insert(
                (issuer.clone(), id),
                EventView {
                    parts: vec![kind, stream, relationship],
                    typ,
                    payload: serde_json::from_str(&payload).unwrap_or(Value::String(payload)),
                    issuer,
                },
            );
        }
    }
    events
}

/// A copy of one compared table.
fn clone_table(table: &Table) -> Table {
    Table {
        key: table.key.clone(),
        rows: table.rows.clone(),
    }
}

/// A copy of one compared state.
fn clone_state(state: &State) -> State {
    state
        .iter()
        .map(|(name, table)| (name.clone(), clone_table(table)))
        .collect()
}

/// Re-encode a JSON value the way `quote()` quotes text: single quotes
/// doubled, wrapped in single quotes. Key order is the decoded map's order,
/// which is deterministic on both sides.
fn requote(value: &Value) -> String {
    format!(
        "'{}'",
        serde_json::to_string(value).unwrap().replace('\'', "''")
    )
}

impl Normaliser {
    fn new(base: &State) -> Self {
        let uuid = regex::Regex::new(UUID).unwrap();
        let base_ids = base
            .values()
            .flat_map(|table| &table.rows)
            .flat_map(|row| row.values())
            .flat_map(|cell| uuid.find_iter(cell).map(|m| m.as_str().to_owned()))
            .collect();
        let mut base_keys = BTreeMap::new();
        let mut base_rows = BTreeMap::new();
        for (name, table) in base {
            let Some(key) = table.key.as_ref() else {
                continue;
            };
            base_keys.insert(name.clone(), key.clone());
            for row in &table.rows {
                if let Some(pk) = row.get(key) {
                    base_rows.insert(
                        (name.clone(), pk.clone()),
                        row.iter()
                            .map(|(column, cell)| (column.clone(), cell.clone()))
                            .collect(),
                    );
                }
            }
        }
        Self {
            base_ids,
            base_keys,
            base_rows,
            whole_uuid: regex::Regex::new(&format!("^{UUID}$")).unwrap(),
            uuid,
            time: regex::Regex::new(r"\d{4}-\d\d-\d\dT[\d:.]+Z").unwrap(),
            window: None,
        }
    }

    /// The same, for a state produced by a call that ran between two instants.
    fn during(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let slack = chrono::Duration::milliseconds(50);
        Self {
            base_ids: self.base_ids.clone(),
            base_keys: self.base_keys.clone(),
            base_rows: self.base_rows.clone(),
            uuid: self.uuid.clone(),
            whole_uuid: self.whole_uuid.clone(),
            time: self.time.clone(),
            window: Some((start - slack, end + slack)),
        }
    }

    fn in_window(&self, instant: &str) -> bool {
        let Some((start, end)) = self.window else {
            return false;
        };
        chrono::DateTime::parse_from_rfc3339(instant)
            .map(|t| start <= t && t <= end)
            .unwrap_or(false)
    }

    fn in_window_ms(&self, millis: i64) -> bool {
        let Some((start, end)) = self.window else {
            return false;
        };
        // No extra slack here: `during` already widens the window.
        start.timestamp_millis() <= millis && millis <= end.timestamp_millis()
    }

    /// A stored value as JSON: `quote()` text unquoted, and JSON parsed.
    fn decode(quoted: &str) -> Value {
        if quoted == "NULL" {
            return Value::Null;
        }
        let text = quoted
            .strip_prefix('\'')
            .and_then(|q| q.strip_suffix('\''))
            .map(|q| q.replace("''", "'"));
        match text {
            Some(text) => match serde_json::from_str::<Value>(&text) {
                Ok(json @ (Value::Object(_) | Value::Array(_))) => json,
                _ => Value::String(text),
            },
            None => Value::String(quoted.to_owned()),
        }
    }

    /// Mask the named engine-generated values inside one JSON blob: a
    /// timestamp only when it falls inside the call's window, an
    /// always-masked value unconditionally. Every other string in the blob
    /// compares verbatim, as does a path whose value still matches the
    /// base row: only values the call changed or added get window-masked.
    fn mask_named_json(
        &self,
        table: &str,
        column: &str,
        value: &Value,
        base: Option<&Value>,
    ) -> Value {
        let mut value = value.clone();
        for (entry_table, entry_column, path) in INCIDENTAL_JSON_TIMES {
            if (*entry_table, *entry_column) != (table, column) {
                continue;
            }
            value = self.mask_time_at_path(&value, base, path);
        }
        for (entry_table, entry_column, path) in INCIDENTAL_JSON_VALUES {
            if (*entry_table, *entry_column) != (table, column) {
                continue;
            }
            value = Self::mask_value_at_path(&value, path);
        }
        value
    }

    /// Mask a timestamp at one JSON path, but only when it falls inside the
    /// call's window: a historic instant at the same path still compares,
    /// as does a value that still matches the base row at that path.
    /// `*` addresses every element of a JSON array, index-aligned with the
    /// base row's array.
    fn mask_time_at_path(&self, value: &Value, base: Option<&Value>, path: &[&str]) -> Value {
        match (value, path) {
            (Value::Object(map), [key, rest @ ..]) => {
                let mut map = map.clone();
                if let Some(item) = map.get(*key) {
                    let base_item = base.and_then(|b| b.as_object()).and_then(|m| m.get(*key));
                    map.insert(
                        (*key).to_owned(),
                        self.mask_time_at_path(item, base_item, rest),
                    );
                }
                Value::Object(map)
            }
            (Value::Array(items), ["*", rest @ ..]) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| {
                        let base_item = base.and_then(|b| b.as_array()).and_then(|a| a.get(i));
                        self.mask_time_at_path(item, base_item, rest)
                    })
                    .collect(),
            ),
            (Value::String(text), []) => {
                if base.is_some_and(|b| b.as_str() == Some(text)) {
                    value.clone()
                } else if self.time.is_match(text) && self.in_window(text) {
                    Value::String("<incidental>".to_owned())
                } else {
                    value.clone()
                }
            }
            _ => value.clone(),
        }
    }

    /// Mask a value at one JSON path unconditionally. Only for values that
    /// are never comparable across runs, each named with its reason.
    fn mask_value_at_path(value: &Value, path: &[&str]) -> Value {
        match (value, path) {
            (Value::Object(map), [key, rest @ ..]) => {
                let mut map = map.clone();
                if let Some(item) = map.get(*key) {
                    map.insert((*key).to_owned(), Self::mask_value_at_path(item, rest));
                }
                Value::Object(map)
            }
            (_, []) => Value::String("<incidental>".to_owned()),
            _ => value.clone(),
        }
    }

    /// Resolve receipt short refs to the sibling id they quote, so the
    /// comparison labels both together. Only the named short-ref keys,
    /// only inside the named receipt blobs, and only when the quote is a
    /// hex prefix of the sibling id that is unique across every id in the
    /// state: anything else (a forged or an ambiguous quote) is left
    /// literal and still compares. Objects nest (a batched create quotes
    /// each record beside its own id), so the walk recurses.
    fn resolve_object_refs(
        &self,
        obj: &mut serde_json::Map<String, Value>,
        ids: &BTreeSet<String>,
    ) {
        if let Some(Value::String(sibling)) = obj.get("id").cloned() {
            let simple: String = sibling.chars().filter(|c| *c != '-').collect();
            for key in ["short_ref", "display_reference"] {
                let quote = match obj.get(key) {
                    Some(Value::String(quote)) => quote.clone(),
                    _ => continue,
                };
                let unique = !quote.is_empty()
                    && quote.chars().all(|c| c.is_ascii_hexdigit())
                    && simple.starts_with(quote.as_str())
                    && ids
                        .iter()
                        .filter(|id| id.starts_with(quote.as_str()))
                        .count()
                        == 1;
                if unique {
                    obj.insert(key.to_owned(), Value::String(sibling.clone()));
                }
            }
        }
        for value in obj.values_mut() {
            match value {
                Value::Object(nested) => self.resolve_object_refs(nested, ids),
                Value::Array(items) => {
                    for item in items.iter_mut() {
                        if let Value::Object(nested) = item {
                            self.resolve_object_refs(nested, ids);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn resolve_receipt_refs(&self, state: &State) -> State {
        let mut ids = BTreeSet::new();
        for table in state.values() {
            for row in &table.rows {
                for cell in row.values() {
                    ids.extend(
                        self.uuid
                            .find_iter(cell)
                            .map(|m| m.as_str().replace('-', "")),
                    );
                }
            }
        }
        let mut resolved = State::new();
        for (name, table) in state {
            if name != "kernel_mcp_write_receipts" {
                resolved.insert(name.clone(), clone_table(table));
                continue;
            }
            let mut rows = Vec::new();
            for row in &table.rows {
                let Some(cell) = row.get("receipt_json") else {
                    rows.push(row.clone());
                    continue;
                };
                let Value::Object(mut blob) = Self::decode(cell) else {
                    rows.push(row.clone());
                    continue;
                };
                self.resolve_object_refs(&mut blob, &ids);
                let mut row = row.clone();
                row.insert("receipt_json".to_owned(), requote(&Value::Object(blob)));
                rows.push(row);
            }
            resolved.insert(
                name.clone(),
                Table {
                    key: table.key.clone(),
                    rows,
                },
            );
        }
        resolved
    }

    /// Mask the row time of provider links the engine stamped itself. A
    /// link whose assertion carries an authored `claimed_timestamp`
    /// compares verbatim — even an in-window replacement must fail — so
    /// only rows with no authored source are masked, and only inside the
    /// call's window. The top-level `created_at` columns already follow the
    /// window rule on their own.
    fn mask_unclaimed_link_times(&self, state: &State) -> State {
        let mut authored = BTreeSet::new();
        if let Some(table) = state.get("kernel_provider_state") {
            for row in &table.rows {
                let Some(cell) = row.get("state_json") else {
                    continue;
                };
                let decoded = Self::decode(cell);
                let Some(assertions) = decoded
                    .pointer("/state/assertions")
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                for assertion in assertions {
                    let Some(sources) = assertion.get("sources").and_then(Value::as_array) else {
                        continue;
                    };
                    for source in sources {
                        let (Some(from), Some(to), Some(Value::String(_))) = (
                            source.get("from").and_then(Value::as_str),
                            source.get("to").and_then(Value::as_str),
                            source.get("claimed_timestamp"),
                        ) else {
                            continue;
                        };
                        authored.insert((from.to_owned(), to.to_owned()));
                    }
                }
            }
        }
        let mut masked = clone_state(state);
        let Some(table) = masked.get_mut("kernel_provider_link_rows") else {
            return masked;
        };
        for row in &mut table.rows {
            let (Some(source), Some(target)) = (
                row.get("source_id")
                    .and_then(|c| Self::decode(c).as_str().map(str::to_owned)),
                row.get("target_id")
                    .and_then(|c| Self::decode(c).as_str().map(str::to_owned)),
            ) else {
                continue;
            };
            if authored.contains(&(source, target)) {
                continue;
            }
            let Some(cell) = row.get("raw_json") else {
                continue;
            };
            let Value::Array(mut items) = Self::decode(cell) else {
                continue;
            };
            let Some(Value::String(at)) = items.get(4) else {
                continue;
            };
            if self.time.is_match(at) && self.in_window(at) {
                items[4] = Value::String("<incidental>".to_owned());
                row.insert("raw_json".to_owned(), requote(&Value::Array(items)));
            }
        }
        masked
    }

    /// Recompute every provider receipt digest from its stored request and
    /// require it to match, before the comparison masks it. The digest
    /// covers fork-minted keys, so two correct runs store different digests
    /// for the same logical write; masking is only sound after this proves
    /// each stored digest is consistent with its request. A corrupted
    /// digest fails here instead of comparing equal. A digest key that is
    /// present but not a string fails too; rows without either key belong
    /// to receipt types that carry none, and a deleted key still fails
    /// downstream because the honest row keeps it.
    fn assert_provider_digests(state: &State) -> Result<(), String> {
        let Some(table) = state.get("kernel_provider_receipts") else {
            return Ok(());
        };
        for row in &table.rows {
            let Some(cell) = row.get("request_json") else {
                return Err("provider receipt has no request_json".to_owned());
            };
            let Value::Object(request) = Self::decode(cell) else {
                return Err("provider receipt request is not JSON".to_owned());
            };
            for key in ["request_checksum", "request_digest"] {
                let Some(stored) = request.get(key) else {
                    continue;
                };
                let Some(stored) = stored.as_str() else {
                    return Err(format!("provider receipt {key} is not a string"));
                };
                let mut unsigned = request.clone();
                unsigned.insert(key.to_owned(), Value::String(String::new()));
                let bytes = serde_json::to_vec(&unsigned)
                    .map_err(|e| format!("request is not JSON: {e}"))?;
                let digest = hex::encode(sha2::Sha256::digest(&bytes));
                if digest != stored {
                    return Err(format!(
                        "provider receipt digest {key} does not match its stored request"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Recompute every action attestation digest from its stored companions
    /// and require it to match, before the comparison masks
    /// `output_event_set_digest`. The output-set digest covers fork-minted
    /// event ids, so two correct runs store different digests for the same
    /// logical write; masking is only sound after this proves each stored
    /// digest is consistent with its rows. A corrupted output membership or
    /// a forged digest fails here instead of comparing equal.
    fn assert_attestation_digests(state: &State) -> Result<(), String> {
        let Some(table) = state.get("provenance_action_attestations") else {
            return Ok(());
        };
        let outputs = state.get("provenance_action_outputs");
        for row in &table.rows {
            let Some(id_cell) = row.get("id") else {
                return Err("action attestation has no id".to_owned());
            };
            let Some(operation_cell) = row.get("operation") else {
                return Err("action attestation has no operation".to_owned());
            };
            let Value::String(operation) = Self::decode(operation_cell) else {
                return Err("action attestation operation is not text".to_owned());
            };
            let Some(commitment_cell) = row.get("action_commitment") else {
                return Err("action attestation has no action_commitment".to_owned());
            };
            let Value::Object(commitment) = Self::decode(commitment_cell) else {
                return Err("action attestation commitment is not JSON".to_owned());
            };
            let arguments_digest = match commitment.get("arguments_digest").and_then(Value::as_str)
            {
                Some(digest) => digest.to_owned(),
                None => {
                    return Err("action attestation commitment has no arguments_digest".to_owned())
                }
            };
            if commitment.len() != 2
                || commitment.get("operation").and_then(Value::as_str) != Some(operation.as_str())
                || arguments_digest.len() != 64
                || arguments_digest.bytes().any(|b| !b.is_ascii_hexdigit())
            {
                return Err("action attestation commitment is not exact".to_owned());
            }
            let Some(digest_cell) = row.get("action_digest") else {
                return Err("action attestation has no action_digest".to_owned());
            };
            let Value::String(action_digest) = Self::decode(digest_cell) else {
                return Err("action attestation action_digest is not text".to_owned());
            };
            let canonical = serde_jcs::to_vec(&Value::Object(commitment))
                .map_err(|e| format!("action attestation commitment is not JSON: {e}"))?;
            if hex::encode(sha2::Sha256::digest(&canonical)) != action_digest {
                return Err(
                    "action attestation action_digest does not match its stored commitment"
                        .to_owned(),
                );
            }
            let Some(set_cell) = row.get("output_event_set_digest") else {
                return Err("action attestation has no output_event_set_digest".to_owned());
            };
            let Value::String(stored_set) = Self::decode(set_cell) else {
                return Err("action attestation output_event_set_digest is not text".to_owned());
            };
            let Value::String(id) = Self::decode(id_cell) else {
                return Err("action attestation id is not text".to_owned());
            };
            let mut members: Vec<(i64, Value)> = Vec::new();
            if let Some(outputs) = outputs {
                for output in &outputs.rows {
                    let Some(member_id) = output.get("action_attestation_id") else {
                        continue;
                    };
                    if Self::decode(member_id) != Value::String(id.clone()) {
                        continue;
                    }
                    let ordinal = match output.get("ordinal").map(|cell| Self::decode(cell)) {
                        Some(Value::String(text)) => text.parse::<i64>().map_err(|_| {
                            "action attestation output ordinal is not an integer".to_owned()
                        })?,
                        _ => {
                            return Err("action attestation output has no ordinal".to_owned());
                        }
                    };
                    let domain = match output.get("output_domain").map(|cell| Self::decode(cell)) {
                        Some(Value::String(domain)) => domain,
                        _ => {
                            return Err("action attestation output has no output_domain".to_owned());
                        }
                    };
                    let event = match output.get("output_event_id").map(|cell| Self::decode(cell)) {
                        Some(Value::String(event)) => event,
                        _ => {
                            return Err(
                                "action attestation output has no output_event_id".to_owned()
                            );
                        }
                    };
                    members.push((ordinal, json!({"domain": domain, "event_id": event})));
                }
            }
            members.sort_by_key(|(ordinal, _)| *ordinal);
            let ordered: Vec<Value> = members.into_iter().map(|(_, v)| v).collect();
            let bytes = serde_jcs::to_vec(&Value::Array(ordered))
                .map_err(|e| format!("action attestation outputs are not JSON: {e}"))?;
            if hex::encode(sha2::Sha256::digest(&bytes)) != stored_set {
                return Err(
                    "action attestation output_event_set_digest does not match its stored outputs"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    /// Apply `f` to every string in `value`.
    fn map_strings(value: &Value, f: &dyn Fn(&str) -> String) -> Value {
        match value {
            Value::String(text) => Value::String(f(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| Self::map_strings(v, f)).collect())
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), Self::map_strings(v, f)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// New ids become `<new-id>`: the form that does not depend on which random
    /// ids a run happened to mint.
    fn blank(&self, text: &str) -> String {
        self.uuid
            .replace_all(text, |m: &regex::Captures| {
                if self.base_ids.contains(&m[0]) {
                    m[0].to_owned()
                } else {
                    "<new-id>".to_owned()
                }
            })
            .into_owned()
    }

    /// Whether this cell is byte-identical to the base's value for the same
    /// row, matched by the table's single-column primary key. Seed data is
    /// identical on every fork: `false` for new rows and whenever the row
    /// or value cannot be matched.
    fn base_cell_equal(&self, table: &str, row: &BTreeMap<String, String>, column: &str) -> bool {
        let Some(key) = self.base_keys.get(table) else {
            return false;
        };
        let Some(pk) = row.get(key) else {
            return false;
        };
        let Some(base_row) = self.base_rows.get(&(table.to_owned(), pk.clone())) else {
            return false;
        };
        let (Some(base_cell), Some(cell)) = (base_row.get(column), row.get(column)) else {
            return false;
        };
        base_cell == cell
    }

    /// The base's decoded value for this cell, when the row matches a base
    /// row by primary key: `None` for new rows, so JSON-path masking keeps
    /// its window rule there.
    fn base_value(
        &self,
        table: &str,
        row: &BTreeMap<String, String>,
        column: &str,
    ) -> Option<Value> {
        let key = self.base_keys.get(table)?;
        let pk = row.get(key)?;
        let base_row = self.base_rows.get(&(table.to_owned(), pk.clone()))?;
        Some(Self::decode(base_row.get(column)?))
    }

    /// A facet observation made by the engine during the call has that moment
    /// as its `as_of` and in its id. One with an `as_of` the caller chose, or
    /// one the call did not make, is compared in full.
    fn observed_during_call(&self, table: &str, row: &BTreeMap<String, String>) -> bool {
        table == "facet_observations"
            && row.get("as_of") == row.get("observed_at")
            && matches!(
                row.get("observed_at").map(|q| Self::decode(q)),
                Some(Value::String(at)) if self.in_window(&at)
            )
    }

    /// One row's cells after masking and ordering, with `f` applied to every
    /// string left (to blank or label new ids).
    fn cells(
        &self,
        table: &str,
        row: &BTreeMap<String, String>,
        f: &dyn Fn(&str) -> String,
    ) -> BTreeMap<String, Value> {
        let call_made_it = self.observed_during_call(table, row);
        row.iter()
            .map(|(column, quoted)| {
                let named = INCIDENTAL_CELLS
                    .iter()
                    .any(|(t, c, _)| (*t, *c) == (table, column.as_str()));
                let during_call = TIME_COLUMNS.contains(&column.as_str())
                    && matches!(
                        Self::decode(quoted),
                        Value::String(at) if self.in_window(&at)
                    );
                // Every non-JSON cell decodes to text, whatever its storage
                // class, so millisecond instants arrive as strings too.
                let during_call_ms = TIME_MS_COLUMNS.contains(&column.as_str())
                    && matches!(
                        Self::decode(quoted),
                        Value::String(at)
                            if at.parse::<i64>().is_ok_and(|ms| self.in_window_ms(ms))
                    );
                // Seed data is identical on every fork: a cell the call left
                // alone compares verbatim even when it falls inside the
                // call's window, so masking can never manufacture a
                // window-straddle difference on seeded rows. Only values
                // that changed or are new get window-masked.
                let unchanged_from_base = self.base_cell_equal(table, row, column);
                let incidental = !unchanged_from_base
                    && (named
                        || during_call
                        || during_call_ms
                        || (column == "as_of" && call_made_it))
                    && quoted != "NULL";
                if incidental {
                    return (column.clone(), Value::String("<incidental>".into()));
                }
                let mut value = Self::decode(quoted);
                // Mask only the named engine-generated JSON paths. Anything
                // else in a blob, including authored JSON and body text,
                // compares verbatim. Receipt short refs resolve earlier, in
                // [`Self::state`], where the sibling context exists. Paths
                // whose value still matches the base row stay verbatim.
                if !matches!(value, Value::String(_)) {
                    let base = self.base_value(table, row, column);
                    value = self.mask_named_json(table, column, &value, base.as_ref());
                }
                if column == "id" && call_made_it {
                    value = Self::map_strings(&value, &|t| {
                        self.time.replace_all(t, "<incidental>").into_owned()
                    });
                }
                if ORDER_FREE_JSON_COLUMNS.contains(&(table, column.as_str())) {
                    if let Value::Array(items) = &mut value {
                        // Sorted by its blanked form, so the order does not
                        // depend on which ids were minted.
                        items.sort_by_key(|item| {
                            Self::map_strings(item, &|t| self.blank(t)).to_string()
                        });
                    }
                }
                (column.clone(), Self::map_strings(&value, f))
            })
            .collect()
    }

    /// Rows as sorted text, the first ambiguity in how new ids are labelled,
    /// or the first output that references an event the comparison cannot
    /// see. Output event ids resolve to labels derived from the referenced
    /// event's content, so retargeting an output at another event changes
    /// its row instead of comparing equal; an id with no event row fails
    /// loudly instead of comparing as a blank.
    fn state(
        &self,
        state: &State,
        events: &EventMaps,
    ) -> Result<BTreeMap<String, Vec<String>>, LabelError> {
        // Resolve receipt short refs first, so both the label shapes below
        // and the final comparison see the sibling id, not the prefix.
        // Then mask engine-stamped link rows, so authored timestamps keep
        // comparing verbatim.
        let resolved = self.resolve_receipt_refs(state);
        let masked = self.mask_unclaimed_link_times(&resolved);
        let state = &masked;
        let mut labels: BTreeMap<String, String> = BTreeMap::new();
        let mut owners: BTreeMap<String, String> = BTreeMap::new();
        for (name, table) in state {
            let Some(key) = &table.key else { continue };
            for row in &table.rows {
                let Some(id) = row.get(key).map(|quoted| Self::decode(quoted)) else {
                    continue;
                };
                let Some(id) = id.as_str() else { continue };
                if !self.whole_uuid.is_match(id) || self.base_ids.contains(id) {
                    continue;
                }
                let shape =
                    serde_json::to_string(&self.cells(name, row, &|t| self.blank(t))).unwrap();
                let label = format!(
                    "{name}#{}",
                    &hex::encode(sha2::Sha256::digest(&shape))[..10]
                );
                match owners.get(&label) {
                    Some(other) if other != id => {
                        return Err(LabelError::Ambiguous(Ambiguous {
                            table: name.clone(),
                            row: shape,
                        }))
                    }
                    _ => {
                        owners.insert(label.clone(), id.to_owned());
                    }
                }
                // An id keyed in more than one table gets the smallest label.
                labels
                    .entry(id.to_owned())
                    .and_modify(|existing| {
                        if label < *existing {
                            *existing = label.clone();
                        }
                    })
                    .or_insert(label);
            }
        }
        let relabel = |text: &str| {
            self.uuid
                .replace_all(text, |m: &regex::Captures| {
                    if self.base_ids.contains(&m[0]) {
                        m[0].to_owned()
                    } else {
                        labels
                            .get(&m[0])
                            .map_or_else(|| "<new-id>".to_owned(), |l| format!("<{l}>"))
                    }
                })
                .into_owned()
        };
        // Labels for the events outputs reference, resolved in the output's
        // own domain: content ids against content_events, relationship ids
        // against (issuer, id) using the attestation's issuer origin.
        // Relationship ids are only unique per issuer, and the two tables
        // can share an id, so an id-only lookup could supply the wrong
        // event's label. Each label derives from the referenced event's
        // content (subject identity, type, payload, and issuer for
        // relationship events) with minted ids resolved through the same
        // labels, so two correct runs label the same logical event the same
        // way and retargeting changes the row. Payload timestamps stay
        // verbatim: a survey of every fixture's outputs shows payloads carry
        // no engine-stamped instants (those live in the created_at,
        // occurred_at and ingested_at columns, which labels exclude), only
        // historic or authored ones, which must keep comparing. A future
        // engine-stamped payload instant would fork honest labels loudly
        // through honest_runs_agree instead of comparing equal, at which
        // point it gets a named entry with its reason — nothing is masked
        // without one. Two distinct events sharing one label fail loudly as
        // an ambiguous referenced event instead of letting their outputs
        // swap silently.
        let mut content_labels: BTreeMap<String, String> = BTreeMap::new();
        let mut relationship_labels: BTreeMap<(String, String), String> = BTreeMap::new();
        let mut content_owners: BTreeMap<String, String> = BTreeMap::new();
        let mut relationship_owners: BTreeMap<String, (String, String)> = BTreeMap::new();
        // Content and relationship events live in separate namespaces, so a
        // same-id row in the other domain can never shadow the referenced
        // event or collide with its label.
        for (id, view) in &events.content {
            let parts: Vec<String> = view.parts.iter().map(|p| relabel(p)).collect();
            let payload = Self::map_strings(&view.payload, &|text| relabel(text));
            let payload = serde_json::to_string(&payload).unwrap();
            let shape = format!("content|{}|{}|{}", parts.join("|"), view.typ, payload);
            let label = format!(
                "event#{}",
                &hex::encode(sha2::Sha256::digest(shape.as_bytes()))[..10]
            );
            if let Some(owner) = content_owners.get(&label) {
                if owner != id {
                    return Err(LabelError::Unresolved(Unresolved {
                        table: "content_events".to_owned(),
                        row: format!(
                            "ambiguous referenced event: two distinct events {owner} and {id} share one content label, so swapping their outputs cannot be compared"
                        ),
                    }));
                }
            }
            content_owners.insert(label.clone(), id.clone());
            content_labels.insert(id.clone(), label);
        }
        for (key, view) in &events.relationship {
            let parts: Vec<String> = view.parts.iter().map(|p| relabel(p)).collect();
            let payload = Self::map_strings(&view.payload, &|text| relabel(text));
            let payload = serde_json::to_string(&payload).unwrap();
            let shape = format!(
                "relationship|{}|{}|{}|{}",
                view.issuer,
                parts.join("|"),
                view.typ,
                payload
            );
            let label = format!(
                "event#{}",
                &hex::encode(sha2::Sha256::digest(shape.as_bytes()))[..10]
            );
            if let Some(owner) = relationship_owners.get(&label) {
                if owner != key {
                    return Err(LabelError::Unresolved(Unresolved {
                        table: "relationship_events".to_owned(),
                        row: format!(
                            "ambiguous referenced event: two distinct events {} and {} share one content label, so swapping their outputs cannot be compared",
                            owner.1, key.1
                        ),
                    }));
                }
            }
            relationship_owners.insert(label.clone(), key.clone());
            relationship_labels.insert(key.clone(), label);
        }
        // The issuer origin of each attestation, for relationship lookups.
        let mut attestation_issuers: BTreeMap<String, String> = BTreeMap::new();
        if let Some(table) = state.get("provenance_action_attestations") {
            for row in &table.rows {
                let (Some(id), Some(issuer)) = (
                    row.get("id").map(|c| Self::decode(c)),
                    row.get("issuer_origin_database_id")
                        .map(|c| Self::decode(c)),
                ) else {
                    continue;
                };
                if let (Value::String(id), Value::String(issuer)) = (id, issuer) {
                    attestation_issuers.insert(id, issuer);
                }
            }
        }
        let mut out = BTreeMap::new();
        for (name, table) in state {
            let mut rows = Vec::new();
            for row in &table.rows {
                let mut rendered = self.cells(name, row, &relabel);
                if name == "provenance_action_outputs" {
                    let (Some(event), Some(domain), Some(attestation)) = (
                        row.get("output_event_id").map(|c| Self::decode(c)),
                        row.get("output_domain").map(|c| Self::decode(c)),
                        row.get("action_attestation_id").map(|c| Self::decode(c)),
                    ) else {
                        return Err(LabelError::Unresolved(Unresolved {
                            table: name.clone(),
                            row: "an output has no output_event_id, output_domain or action_attestation_id"
                                .to_owned(),
                        }));
                    };
                    let (Value::String(event), Value::String(domain), Value::String(attestation)) =
                        (event, domain, attestation)
                    else {
                        return Err(LabelError::Unresolved(Unresolved {
                            table: name.clone(),
                            row: "an output_event_id, output_domain or action_attestation_id is not text"
                                .to_owned(),
                        }));
                    };
                    let label = match domain.as_str() {
                        "content" => content_labels.get(&event).cloned(),
                        "relationship" => {
                            attestation_issuers.get(&attestation).and_then(|issuer| {
                                relationship_labels
                                    .get(&(issuer.clone(), event.clone()))
                                    .cloned()
                            })
                        }
                        _ => None,
                    };
                    let Some(label) = label else {
                        let ordinal = row
                            .get("ordinal")
                            .map(|c| Self::decode(c).to_string())
                            .unwrap_or_else(|| "?".to_owned());
                        return Err(LabelError::Unresolved(Unresolved {
                            table: name.clone(),
                            row: format!(
                                "output {ordinal} of attestation {attestation} references unknown event in its domain"
                            ),
                        }));
                    };
                    rendered.insert("output_event_id".to_owned(), Value::String(label));
                }
                rows.push(serde_json::to_string(&rendered).unwrap());
            }
            rows.sort();
            out.insert(name.clone(), rows);
        }
        Ok(out)
    }
}

/// A readable first difference between two normalised states, down to the
/// cells that differ.
fn diff(
    expected: &BTreeMap<String, Vec<String>>,
    actual: &BTreeMap<String, Vec<String>>,
) -> Option<String> {
    for (table, rows) in expected {
        let other = actual.get(table).cloned().unwrap_or_default();
        if *rows != other {
            let missing: Vec<&String> = rows.iter().filter(|r| !other.contains(r)).collect();
            let extra: Vec<&String> = other.iter().filter(|r| !rows.contains(r)).collect();
            let cells = match (missing.first(), extra.first()) {
                (Some(a), Some(b)) => {
                    let a: BTreeMap<String, Value> = serde_json::from_str(a).unwrap();
                    let b: BTreeMap<String, Value> = serde_json::from_str(b).unwrap();
                    a.iter()
                        .filter(|(column, value)| b.get(*column) != Some(*value))
                        .map(|(column, value)| format!("{column}: {value} vs {}", b[column]))
                        .collect::<Vec<_>>()
                        .join("; ")
                }
                (Some(a), None) => format!("only in first: {a}"),
                (None, Some(b)) => format!("only in second: {b}"),
                (None, None) => "same rows, different multiplicity".to_owned(),
            };
            return Some(format!(
                "table {table}: {} rows vs {}; {cells}",
                rows.len(),
                other.len()
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

/// What to call, and as whom.
struct Call {
    args: Value,
    caller: Caller,
    /// Whether the call takes a `reason`. The contract may declare it on some
    /// action of the tool but not this one.
    reason: bool,
    /// Whether the call is keyed. An operation that refuses a key is replayed
    /// unkeyed, which is how a host would have to send it.
    keyed: bool,
}

fn local(args: Value) -> Option<Call> {
    Some(Call {
        args,
        caller: Caller::local(),
        reason: true,
        keyed: true,
    })
}

fn local_without_reason(args: Value) -> Option<Call> {
    Some(Call {
        reason: false,
        ..local(args)?
    })
}

fn local_unkeyed(args: Value) -> Option<Call> {
    Some(Call {
        keyed: false,
        ..local(args)?
    })
}

/// Whether the world runs the KernelV2 engine. Gated: SQLite-only graphs have
/// the one variant and never ask.
#[cfg(feature = "v2-kernel-probe")]
fn is_v2(world: &World) -> bool {
    match world.engine {
        Engine::Sqlite => false,
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => true,
    }
}

/// The call as the source tool takes it: the operation's selector, a reason
/// and a key where the contract accepts them.
fn source_arguments(operation: &ReplayOperation, call: &Call, key: &str) -> Value {
    let mut args = call.args.clone();
    let object = args
        .as_object_mut()
        .expect("fixture arguments are an object");
    if let Some((field, value)) = &operation.selector {
        object.insert(field.clone(), json!(value));
    }
    if operation.accepts_reason && call.reason {
        object.entry("reason").or_insert_with(|| json!(REASON));
    }
    if operation.accepts_idempotency_key && call.keyed {
        object
            .entry("idempotency_key")
            .or_insert_with(|| json!(key));
    }
    args
}

async fn apply(
    world: &World,
    db: &Db,
    operation: &ReplayOperation,
    call: &Call,
    args: &Value,
) -> Result<Value, String> {
    match world.engine {
        Engine::Sqlite => world
            .registry
            .call(
                db.clone(),
                call.caller.clone(),
                &operation.source_tool,
                args.clone(),
            )
            .await
            .map_err(|error| error.to_string()),
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => world
            .registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                call.caller.clone(),
                &operation.source_tool,
                args.clone(),
            )
            .await
            .map_err(|error| error.to_string()),
    }
}

/// Where a replay check failed, and how. The phase lets known debt name the
/// one failure it expects instead of accepting any error.
#[derive(Debug, PartialEq, Eq)]
struct Failure {
    phase: Phase,
    message: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Phase {
    /// The first application to a fork was refused.
    First,
    /// Replaying the journal on a rebuilt fork was refused or differed.
    Rebuild,
    /// The second delivery was refused.
    RedeliveryRefused,
    /// The second delivery answered `conflict` (or similar).
    RedeliveryConflict,
    /// The second delivery changed the state again.
    RedeliveryState,
    /// Two new records are indistinguishable, so their wiring cannot be
    /// compared: the fixture must make them differ.
    AmbiguousIdentity,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.phase, self.message)
    }
}

fn failure(phase: Phase, message: impl Into<String>) -> Failure {
    Failure {
        phase,
        message: message.into(),
    }
}

/// How a replayed operation passed.
#[derive(Debug, PartialEq, Eq)]
enum Passed {
    /// Rebuild and redelivery both reach the same logical state.
    Replayed,
    /// The call wrote only history (logs), so there is no logical state to
    /// duplicate. Only operations named in [`WRITES_ONLY_HISTORY`] may.
    OnlyHistory(Vec<String>),
}

/// The state of `db` after a call that ran between `start` and `end`.
/// Provider receipt and action attestation digests are validated before
/// masking, so a corrupted checksum fails the replay check itself instead
/// of comparing equal.
async fn normalised(
    engine: Engine,
    normaliser: &Normaliser,
    db: &Db,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    phase: Phase,
) -> Result<BTreeMap<String, Vec<String>>, Failure> {
    let raw = logical_state(engine, db).await;
    Normaliser::assert_provider_digests(&raw).map_err(|m| failure(phase, m))?;
    Normaliser::assert_attestation_digests(&raw).map_err(|m| failure(phase, m))?;
    let events = output_event_rows(db).await;
    normaliser
        .during(start, end)
        .state(&raw, &events)
        .map_err(|e| match e {
            LabelError::Ambiguous(a) => failure(
                Phase::AmbiguousIdentity,
                format!(
                    "ambiguous minted identity in table {}: two new records have the same \
                     content, so which one a row points at cannot be compared. Either the \
                     call created the same record twice (a duplicate), or the fixture must \
                     give them distinct content or explicit ids: {}",
                    a.table, a.row
                ),
            ),
            LabelError::Unresolved(u) => failure(
                phase,
                format!(
                    "unresolved output reference in table {}: {}",
                    u.table, u.row
                ),
            ),
        })
}

/// Interaction capture runs off the response path on a bounded queue, so a
/// call's read-log rows can land after its response. Drain them before taking
/// any baseline or observing any applied database, or the comparison can look
/// at state before the capture has committed.
async fn drained(db: &Db, phase: Phase) -> Result<(), Failure> {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        db.drain_captures_for_tests(),
    )
    .await
    .map_err(|_| {
        failure(
            phase,
            "interaction captures did not drain within 30s; state observation would be unreliable",
        )
    })?;
    Ok(())
}

/// Run both replay checks for one operation. `Err` says what differed.
async fn check_replay(
    world: &World,
    operation: &ReplayOperation,
    call: &Call,
) -> Result<Passed, Failure> {
    let key = format!("replay-{}-{}", operation.executor, operation.operation);
    let args = source_arguments(operation, call, &key);
    drained(&world.base, Phase::First).await?;
    let base_state = logical_state(world.engine, &world.base).await;
    let base_events = output_event_rows(&world.base).await;
    let normaliser = Normaliser::new(&base_state);

    // The call applied once to a fork.
    let first = fork(world, "first").await;
    let started = chrono::Utc::now();
    apply(world, &first, operation, call, &args)
        .await
        .map_err(|e| {
            failure(
                Phase::First,
                format!("the call is refused on a fresh fork of the seeded base: {e}"),
            )
        })?;
    drained(&first, Phase::First).await?;
    let applied = normalised(
        world.engine,
        &normaliser,
        &first,
        started,
        chrono::Utc::now(),
        Phase::First,
    )
    .await?;
    // The base, with no time masked: nothing in it was written by the call.
    let unchanged = normaliser
        .state(&base_state, &base_events)
        .expect("the base labels unambiguously");
    if diff(&unchanged, &applied).is_none() {
        let before = history_counts(world.engine, &world.base).await;
        let after = history_counts(world.engine, &first).await;
        let wrote: Vec<_> = after
            .iter()
            .filter(|(table, n)| before.get(*table) != Some(n))
            .map(|(table, _)| table.as_str())
            .collect();
        // An empty write set is also reported, not refused here: `coverage`
        // routes it through the engine's writes-only-history list, so a
        // stateless-by-design operation can be named there while a broken
        // fixture still fails.
        return Ok(Passed::OnlyHistory(
            wrote.iter().map(|t| t.to_string()).collect(),
        ));
    }

    // Rebuild: a new fork from the base, the journal replayed.
    let rebuilt = fork(world, "rebuilt").await;
    let started = chrono::Utc::now();
    apply(world, &rebuilt, operation, call, &args)
        .await
        .map_err(|e| {
            failure(
                Phase::Rebuild,
                format!("replaying the journal is refused: {e}"),
            )
        })?;
    drained(&rebuilt, Phase::Rebuild).await?;
    let rebuilt_state = normalised(
        world.engine,
        &normaliser,
        &rebuilt,
        started,
        chrono::Utc::now(),
        Phase::Rebuild,
    )
    .await?;
    if let Some(difference) = diff(&applied, &rebuilt_state) {
        return Err(failure(
            Phase::Rebuild,
            format!("rebuild differs from the original: {difference}"),
        ));
    }

    // Redelivery: the same call delivered twice.
    let twice = fork(world, "twice").await;
    let started = chrono::Utc::now();
    let delivered = apply(world, &twice, operation, call, &args)
        .await
        .map_err(|e| failure(Phase::First, format!("the first delivery is refused: {e}")))?;
    let redelivered = apply(world, &twice, operation, call, &args)
        .await
        .map_err(|e| {
            failure(
                Phase::RedeliveryRefused,
                format!("the second delivery is refused: {e}"),
            )
        })?;
    // The second answer may say it changed nothing, but it must not report a
    // conflict: a host that sees a conflict for a write it already applied
    // would turn a write that stuck into a refused draft.
    if let Some(status) = redelivered["status"].as_str() {
        if ["conflict", "refused", "failed", "error"].contains(&status) {
            return Err(failure(
                Phase::RedeliveryConflict,
                format!(
                    "redelivery reports `{status}` for a write already applied: first \
                     {delivered}; second {redelivered}"
                ),
            ));
        }
    }
    drained(&twice, Phase::RedeliveryState).await?;
    let twice_state = normalised(
        world.engine,
        &normaliser,
        &twice,
        started,
        chrono::Utc::now(),
        Phase::RedeliveryState,
    )
    .await?;
    if let Some(difference) = diff(&applied, &twice_state) {
        return Err(failure(
            Phase::RedeliveryState,
            format!("redelivery changes the state again: {difference}"),
        ));
    }
    for db in [first, rebuilt, twice] {
        db.close().await;
    }
    Ok(Passed::Replayed)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The call for each local-first operation on the world's engine. `None` means
/// no fixture on this engine. Fixtures are shared: one arm per operation, with
/// a small per-engine adjustment where the engines differ (caller, home,
/// relationship names, keys the other engine refuses).
async fn fixture(world: &World, executor: &str, operation: &str) -> Option<Call> {
    let call = fixture_inner(world, executor, operation).await?;
    #[cfg(feature = "v2-kernel-probe")]
    let call = v2_call(world, executor, operation, call);
    Some(call)
}

/// Run a shared fixture call as the KernelV2 seed owner, with the small
/// argument adjustments that engine needs. SQLite calls pass through
/// unchanged. Gated: the SQLite-only feature graph never sees v2 shapes.
#[cfg(feature = "v2-kernel-probe")]
fn v2_call(world: &World, executor: &str, operation: &str, mut call: Call) -> Call {
    if !is_v2(world) {
        return call;
    }
    // The SQLite local caller has no principal on KernelV2.
    call.caller = world.caller();
    match (executor, operation) {
        ("records_write", "create_record") => {
            // KernelV2 mints every id and files new records under a home.
            call.args.as_object_mut().unwrap().remove("id");
            call.args["home_id"] = json!(world.home.clone());
        }
        ("records_write", "manage_links.add") | ("records_write", "manage_links.remove") => {
            call.args["relationship"] = json!("relates_to");
            // The v2 contract still advertises `reason`, but the handler
            // refuses it: v2 links carry no reason.
            call.args.as_object_mut().unwrap().remove("reason");
        }
        ("records_write", "batch_write") => {
            // The v2 batch takes guard-only updates and archive transitions;
            // renames ride `update_record` instead. Archive two records.
            call.args["items"] = json!([
                {"op": "archive", "id": world.id("note_b")},
                {"op": "archive", "id": world.id("task_t")},
            ]);
        }
        ("coordination_write", "start_work.claim") => {
            // KernelV2 coordination runs under a run_key the pipeline picks
            // up from the arguments; the SQLite claim carries none.
            call.args["run_key"] = json!(RUN_KEY);
            // The claim receipt digests the whole request including this key,
            // so a minted key would fork every digest. An explicit key keeps
            // the checksum comparable verbatim across forks and redeliveries.
            call.args["operation_key"] = json!("replay-start-work-claim");
        }
        _ => {}
    }
    call
}

/// Fixtures for the KernelV2-only operations: `merge_body` and
/// `manage_saved_tabs.*` have no SQLite handler. Returns `None` for every
/// other operation (so the shared arms below run) and on SQLite.
#[cfg(feature = "v2-kernel-probe")]
async fn fixture_v2_only(world: &World, executor: &str, operation: &str) -> Option<Call> {
    if !is_v2(world) {
        return None;
    }
    let v2 = |args: Value| {
        Some(Call {
            args,
            caller: world.caller(),
            reason: true,
            keyed: true,
        })
    };
    match (executor, operation) {
        ("records_write", "merge_body") => {
            let record_id = world.id("note_e");
            let seq: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id = ?",
            )
            .bind(&record_id)
            .fetch_one(world.base.pool())
            .await
            .unwrap();
            v2(json!({
                "record_id": record_id,
                "base_version": format!("rec:{seq}"),
                "base_text": "line one\n",
                "my_text": "line one\nappended\n",
                "reason": REASON,
            }))
        }
        ("records_write", "manage_saved_tabs.create") => v2(json!({
            "action": "create",
            "creation_key": "replay-tab",
            "app": "docs",
            "initial_record_id": Value::Null,
            "reason": REASON,
        })),
        ("records_write", "manage_saved_tabs.rename") => v2(json!({
            "action": "rename",
            "record_id": world.id("seed_tab"),
            "expected_revision": world.id("seed_tab_revision"),
            "operation_id": "replay-rename",
            "custom_title": "Renamed once",
            "reason": REASON,
        })),
        ("records_write", "manage_saved_tabs.retire") => v2(json!({
            "action": "retire",
            "record_id": world.id("seed_tab"),
            "expected_revision": world.id("seed_tab_revision"),
            "operation_id": "replay-retire",
            "reason": REASON,
        })),
        _ => None,
    }
}

/// The engine-independent shape of each fixture call. The few arms that differ
/// per engine branch on [`is_v2`]; everything else runs unchanged on both.
async fn fixture_inner(world: &World, executor: &str, operation: &str) -> Option<Call> {
    let id = |name: &str| world.id(name);
    let receipt = |name: &str, field: &str| world.receipts[name][field].clone();
    // KernelV2-only operations have no SQLite handler, so they never reach
    // the shared arms below on that engine.
    #[cfg(feature = "v2-kernel-probe")]
    if is_v2(world) {
        if let Some(call) = fixture_v2_only(world, executor, operation).await {
            return Some(call);
        }
        // These seeds exist only on SQLite (observations, citations,
        // suggestions, relationships, hosted claims, attributions, messages).
        // On KernelV2 the arms below would panic on missing ids, so there is
        // no fixture: a served one is named in the v2 not-yet-covered list.
        if matches!(
            (executor, operation),
            ("records_write", "manage_facet_observations.set")
                | ("records_write", "manage_facet_observations.unset")
                | ("records_write", "manage_citations.reanchor")
                | ("records_write", "resolve_suggestions.reject")
                | ("records_write", "resolve_suggestions.accept")
                | ("records_write", "manage_relationships.assert")
                | ("records_write", "manage_relationships.contest")
                | ("records_write", "manage_relationships.retract")
                | ("records_write", "manage_relationships.add_evidence")
                | ("records_write", "claim_unowned_record")
                | ("records_write", "create_attribution")
                | ("records_write", "manage_attributions.add_evidence")
                | ("records_write", "manage_attributions.retract")
                | ("messaging_write", "manage_messages.classify")
                | ("messaging_write", "manage_messages.unclassify")
                | ("messaging_write", "manage_messages.move")
        ) {
            return None;
        }
    }
    match (executor, operation) {
        ("records_write", "create_record") => local(json!({
            "type": "Document", "kind": "note", "name": "replayed note", "body": "made once",
            "id": "7e570000-0000-4000-8000-000000000001"
        })),
        ("records_write", "update_record") => local(json!({
            "id": id("note_a"), "body_append": " appended"
        })),
        ("records_write", "attach_text") => local(json!({
            "record_id": id("note_f"), "text": "attached text", "filename": "note.txt"
        })),
        ("records_write", "manage_links.add") => local(json!({
            "source_id": id("note_a"), "target_id": id("note_b"), "relationship": "derived_from"
        })),
        ("records_write", "manage_links.remove") => local(json!({
            "source_id": id("note_a"), "target_id": id("task_t"), "relationship": "derived_from"
        })),
        ("records_write", "manage_facet_observations.set") => local(json!({
            "record_id": id("note_d"), "key": "current", "value": "12",
            "as_of": "2026-09-01T00:00:00Z"
        })),
        ("records_write", "manage_facet_observations.unset") => local(json!({
            "record_id": id("note_d"), "key": "current", "as_of": "2026-08-01T00:00:00Z"
        })),
        ("records_lifecycle", "archive_record") => local(json!({"id": id("note_c")})),
        ("records_write", "manage_citations.reanchor") => local(json!({
            "citation_id": id("citation"),
            "target": {"target_record_id": id("note_a"), "source_slot": "body",
                       "selectors": [{"type": "text_quote", "exact": "beta"}]}
        })),
        ("records_write", "resolve_suggestions.reject") => local(json!({
            "suggestion_ids": [id("suggestion_reject")]
        })),
        ("records_write", "resolve_suggestions.accept") => local(json!({
            "suggestion_ids": [id("suggestion_accept")]
        })),
        ("records_write", "create_exploration") => local(json!({
            "exploration": {"create": {"name": "Options"}},
            "candidates": [{"type": "Document", "kind": "note", "name": "option one"},
                           {"type": "Document", "kind": "note", "name": "option two"}]
        })),
        ("records_write", "manage_relationships.assert") => local(json!({
            "relationship_type": "depends_on",
            "endpoints": [{"role": "subject", "record_id": id("note_c")},
                          {"role": "object", "record_id": id("note_a")}]
        })),
        ("records_write", "manage_relationships.contest") => local(json!({
            "relationship_origin_db_id": receipt("relationship_contest", "relationship_origin_db_id"),
            "relationship_id": receipt("relationship_contest", "relationship_id"),
            "on_behalf_of": "semantic-only"
        })),
        ("records_write", "manage_relationships.retract") => local(json!({
            "assertion_issuer_origin_db_id": receipt("relationship_retract", "assertion_issuer_origin_db_id"),
            "assertion_id": receipt("relationship_retract", "assertion_id")
        })),
        ("records_write", "manage_relationships.add_evidence") => local(json!({
            "assertion_issuer_origin_db_id": receipt("relationship_evidence", "assertion_issuer_origin_db_id"),
            "assertion_id": receipt("relationship_evidence", "assertion_id"),
            "evidence_id": id("note_a")
        })),
        ("records_write", "claim_unowned_record") => Some(Call {
            caller: crate::keyed_replay::hosted(ALICE).with_hosting_owner(true),
            ..local(json!({"record_id": id("ownerless")}))?
        }),
        ("records_write", "create_attribution") => {
            let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
            let bearer = id("bearer");
            let mut args = attribution_args(&world.base, &bearer).await;
            args.as_object_mut().unwrap().remove("idempotency_key");
            // A stated date, so nothing about the stance needs masking.
            args["stance_as_of"] = json!(HISTORIC_STANCE);
            Some(Call {
                caller: agent_caller(&issuer, &bearer),
                ..local_without_reason(args)?
            })
        }
        ("records_write", "manage_attributions.add_evidence") => local_without_reason(json!({
            "annotation_id": receipt("attribution", "annotation_id"),
            "evidence": {"role": "basis",
                         "action_attestation_id": receipt("attribution", "action_attestation_id")}
        })),
        ("records_write", "manage_attributions.retract") => local(json!({
            "annotation_id": receipt("attribution", "annotation_id")
        })),
        ("messaging_write", "manage_messages.classify") => local_without_reason(json!({
            "message_id": id("message_classify"), "conversation_id": id("room_a")
        })),
        ("messaging_write", "manage_messages.unclassify") => local_without_reason(json!({
            "message_id": id("message_unclassify"), "conversation_id": id("room_a")
        })),
        ("messaging_write", "manage_messages.move") => local_without_reason(json!({
            "message_id": id("message_move"), "from_conversation_id": id("room_a"),
            "to_conversation_id": id("room_b")
        })),
        ("coordination_write", "start_work.claim") => local_without_reason(json!({
            "record_id": id("task_t")
        })),
        ("coordination_write", "start_work.release") => local_without_reason(json!({
            "record_id": id("task_claimed")
        })),
        ("coordination_write", "set_intent") => local_without_reason(json!({
            "intent": "a new intent", "run_key": RUN_KEY
        })),
        ("coordination_write", "close_run") => local_without_reason(json!({
            "run_key": RUN_KEY
        })),
        ("identity_resolve", "resolve_external") => local(json!({
            "bindings": [{"system": "native-principal", "identifier": "native/replay-external"}],
            "hints": {"record_type": "Entity", "kind": "person", "name": "Replay External"}
        })),
        ("identity_resolve", "observe_external") => local(json!({
            "bindings": [{"system": "native-principal", "identifier": "native/replay-observed"}],
            "source_binding": {"system": "native-principal", "identifier": "native/replay-observed"},
            "hints": {"record_type": "Entity", "kind": "person", "name": "Replay Observed"},
            "quality": "reported", "materialization_policy": "identity_only", "as_of": null,
            "provenance": {"freshness": "unknown", "retention_state": "none",
                           "source_availability": "unknown", "refresh_outcome": "not_attempted"},
            "display_name": "Replay Observed", "snapshot_base64": null,
            "snapshot_mime": null, "snapshot_filename": null
        })),
        ("records_write", "batch_write") => local(json!({
            "items": [{"op": "update", "id": id("note_b"), "name": "renamed once"},
                      {"op": "update", "id": id("task_t"), "name": "task renamed once"}]
        })),
        ("guidance_read", "quickstart") => local_without_reason(json!({})),
        ("records_write", "create_many") => local(json!({
            "records": [{"type": "Document", "kind": "note", "name": "one"},
                        {"type": "Document", "kind": "note", "name": "two"}]
        })),
        _ => None,
    }
}

/// Every write that has a fixture, whatever its declaration, with its verdict:
/// how an undecided operation fares before it is declared local-first. A
/// separate test that does nothing unless asked
/// (`REPLAY_SURVEY=1 cargo test … survey -- --nocapture`), so the mandatory
/// test cannot be switched off. (`#[ignore]` would trip the repository's
/// ignored-test policy.) Surveys both engines: the SQLite catalogue and the
/// KernelV2 catalogue each get their own verdicts.
#[tokio::test]
async fn survey_every_fixtured_write() {
    if std::env::var_os("REPLAY_SURVEY").is_none() {
        return;
    }
    survey_engine(Engine::Sqlite, &replay_operations().unwrap()).await;
    #[cfg(feature = "v2-kernel-probe")]
    survey_engine(Engine::KernelV2, &replay_operations_on_kernel_v2().unwrap()).await;
}

async fn survey_engine(engine: Engine, operations: &[ReplayOperation]) {
    let world = seed_on(engine).await;
    let world = &world;
    for operation in operations {
        if let Some(call) = fixture(world, &operation.executor, &operation.operation).await {
            let verdict = check_replay(world, operation, &call).await;
            eprintln!(
                "SURVEY[{engine:?}] {}.{} [{:?}] => {}",
                operation.executor,
                operation.operation,
                operation.requires_acceptance,
                match verdict {
                    Ok(Passed::Replayed) => "PASS".to_owned(),
                    Ok(Passed::OnlyHistory(tables)) => format!("HISTORY-ONLY {tables:?}"),
                    Err(why) => {
                        let why = why.to_string();
                        format!("FAIL {}", &why[..why.len().min(300)])
                    }
                }
            );
        } else {
            eprintln!(
                "SURVEY[{engine:?}] {}.{} [{:?}] => NO FIXTURE",
                operation.executor, operation.operation, operation.requires_acceptance
            );
        }
    }
}

/// Local-first operations with no fixture yet. Honest debt, not an opt-out:
/// each has a reason, and the test fails if a listed operation gains a fixture
/// (take it off the list) or is no longer local-first.
const NOT_YET_COVERED: &[(&str, &str, &str)] = &[
    (
        "records_write",
        "merge_body",
        "the KernelV2 engine only: its handler does not exist on the SQLite engine this test runs",
    ),
    (
        "records_write",
        "manage_saved_tabs.create",
        "the KernelV2 engine only: its handler does not exist on the SQLite engine this test runs",
    ),
    (
        "records_write",
        "manage_saved_tabs.rename",
        "the KernelV2 engine only: its handler does not exist on the SQLite engine this test runs",
    ),
    (
        "records_write",
        "manage_saved_tabs.retire",
        "the KernelV2 engine only: its handler does not exist on the SQLite engine this test runs",
    ),
    (
        "artifacts_write",
        "advance_artifact_port_pin",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "instantiate_artifact",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_artifact_inputs.bind",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_artifact_inputs.bind_many",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_artifact_inputs.unbind",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_renderer_binding.bind",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_renderer_binding.unbind",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_surface_bindings.reset",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_surface_bindings.set",
        "needs an artifact, module or port fixture that has not been written yet",
    ),
    (
        "artifacts_read",
        "manage_alpha_tabs.admit_reveal_target",
        "needs an installed alpha tab fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.disable",
        "needs an installed alpha tab fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.live_unsubscribe",
        "needs an installed alpha tab fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.remove",
        "needs an installed alpha tab fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.reorder",
        "needs an installed alpha tab fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.restore",
        "needs an installed alpha tab fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_change_summaries.confirm",
        "needs a change-summary fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_change_summaries.create_or_reuse",
        "needs a change-summary fixture that has not been written yet",
    ),
    (
        "artifacts_write",
        "manage_change_summaries.revoke",
        "needs a change-summary fixture that has not been written yet",
    ),
    (
        "canvas_write",
        "manage_canvas.assert_connector",
        "needs a canvas fixture that has not been written yet",
    ),
    (
        "canvas_write",
        "manage_canvas.commit_batch",
        "needs a canvas fixture that has not been written yet",
    ),
    (
        "messaging_write",
        "manage_messages.add_reaction",
        "needs a message with reactions, expectations or relevance marks that the seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.remove_reaction",
        "needs a message with reactions, expectations or relevance marks that the seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.edit",
        "needs a message with reactions, expectations or relevance marks that the seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.mark_no_longer_relevant",
        "needs a message with reactions, expectations or relevance marks that the seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.unmark_no_longer_relevant",
        "needs a message with reactions, expectations or relevance marks that the seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.satisfy_acknowledgement_expectation_with_reaction",
        "needs a message with reactions, expectations or relevance marks that the seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_agent_disposition",
        "needs a participant, destination or notification-preference fixture that has not been written yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_destination",
        "needs a participant, destination or notification-preference fixture that has not been written yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_notification_preference",
        "needs a participant, destination or notification-preference fixture that has not been written yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_preference",
        "needs a participant, destination or notification-preference fixture that has not been written yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_routing",
        "needs a participant, destination or notification-preference fixture that has not been written yet",
    ),
    (
        "messaging_read",
        "manage_messages.get_notification_preference",
        "needs a participant, destination or notification-preference fixture that has not been written yet",
    ),
    (
        "records_write",
        "manage_account_config.ensure",
        "needs a registered account-config kind and an account footing that the seed does not build yet",
    ),
    (
        "records_write",
        "manage_account_config.replace",
        "needs a registered account-config kind and an account footing that the seed does not build yet",
    ),
    (
        "records_write",
        "prepare_named_views",
        "needs a named-view or saved-account fixture that has not been written yet",
    ),
    (
        "records_write",
        "record_view_revision",
        "needs a named-view or saved-account fixture that has not been written yet",
    ),
    (
        "records_write",
        "save_account",
        "needs a named-view or saved-account fixture that has not been written yet",
    ),
];

/// Local-first operations the ordinary SQLite catalogue does not serve at all.
const NOT_SERVED_ON_SQLITE: &[(&str, &str, &str)] = &[];

/// Local-first operations the KernelV2 catalogue does not serve. Production
/// hosted runs KernelV2, so anything here is SQLite-only surface (or a
/// KernelV2 gap to close deliberately, not by accident).
#[cfg(feature = "v2-kernel-probe")]
const NOT_SERVED_ON_KERNEL_V2: &[(&str, &str, &str)] = &[
    (
        "artifacts_read",
        "manage_alpha_tabs.admit_reveal_target",
        "no KernelV2 handler for installed alpha tabs",
    ),
    (
        "artifacts_write",
        "advance_artifact_port_pin",
        "no KernelV2 handler for artifact ports",
    ),
    (
        "artifacts_write",
        "instantiate_artifact",
        "no KernelV2 handler for artifact instantiation",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.disable",
        "no KernelV2 handler for installed alpha tabs",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.reorder",
        "no KernelV2 handler for installed alpha tabs",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.restore",
        "no KernelV2 handler for installed alpha tabs",
    ),
    (
        "artifacts_write",
        "manage_artifact_inputs.bind",
        "no KernelV2 handler for artifact inputs",
    ),
    (
        "artifacts_write",
        "manage_artifact_inputs.bind_many",
        "no KernelV2 handler for artifact inputs",
    ),
    (
        "artifacts_write",
        "manage_artifact_inputs.unbind",
        "no KernelV2 handler for artifact inputs",
    ),
    (
        "artifacts_write",
        "manage_change_summaries.confirm",
        "no KernelV2 handler for change summaries",
    ),
    (
        "artifacts_write",
        "manage_change_summaries.create_or_reuse",
        "no KernelV2 handler for change summaries",
    ),
    (
        "artifacts_write",
        "manage_change_summaries.revoke",
        "no KernelV2 handler for change summaries",
    ),
    (
        "artifacts_write",
        "manage_renderer_binding.bind",
        "no KernelV2 handler for renderer bindings",
    ),
    (
        "artifacts_write",
        "manage_renderer_binding.unbind",
        "no KernelV2 handler for renderer bindings",
    ),
    (
        "artifacts_write",
        "manage_surface_bindings.reset",
        "no KernelV2 handler for surface bindings",
    ),
    (
        "artifacts_write",
        "manage_surface_bindings.set",
        "no KernelV2 handler for surface bindings",
    ),
    (
        "identity_resolve",
        "resolve_external",
        "no KernelV2 handler for external resolution",
    ),
    (
        "records_write",
        "claim_unowned_record",
        "no KernelV2 handler for hosted claims",
    ),
    (
        "records_write",
        "create_attribution",
        "no KernelV2 handler for attributions",
    ),
    (
        "records_write",
        "create_exploration",
        "no KernelV2 handler for explorations",
    ),
    (
        "records_write",
        "manage_account_config.replace",
        "no KernelV2 handler for account-config replacement",
    ),
    (
        "records_write",
        "manage_attributions.add_evidence",
        "no KernelV2 handler for attributions",
    ),
    (
        "records_write",
        "manage_attributions.retract",
        "no KernelV2 handler for attributions",
    ),
    (
        "records_write",
        "manage_citations.reanchor",
        "KernelV2 serves only manage_citations.remove",
    ),
    (
        "records_write",
        "manage_facet_observations.set",
        "no KernelV2 handler for facet observations",
    ),
    (
        "records_write",
        "manage_facet_observations.unset",
        "no KernelV2 handler for facet observations",
    ),
    (
        "records_write",
        "manage_relationships.add_evidence",
        "no KernelV2 handler for relationships",
    ),
    (
        "records_write",
        "manage_relationships.assert",
        "no KernelV2 handler for relationships",
    ),
    (
        "records_write",
        "manage_relationships.contest",
        "no KernelV2 handler for relationships",
    ),
    (
        "records_write",
        "manage_relationships.retract",
        "no KernelV2 handler for relationships",
    ),
    (
        "records_write",
        "save_account",
        "no KernelV2 handler for saved accounts",
    ),
];

/// Local-first operations the KernelV2 catalogue serves but which have no
/// KernelV2 fixture yet. Honest debt, like [`NOT_YET_COVERED`] on SQLite: each
/// has a reason, and the test fails if a listed operation gains a fixture
/// (take it off the list) or is no longer local-first.
#[cfg(feature = "v2-kernel-probe")]
const NOT_YET_COVERED_ON_KERNEL_V2: &[(&str, &str, &str)] = &[
    (
        "artifacts_write",
        "manage_alpha_tabs.live_unsubscribe",
        "needs an installed alpha tab fixture the v2 seed does not build yet",
    ),
    (
        "artifacts_write",
        "manage_alpha_tabs.remove",
        "needs an installed alpha tab fixture the v2 seed does not build yet",
    ),
    (
        "canvas_write",
        "manage_canvas.assert_connector",
        "needs a canvas fixture the v2 seed does not build yet",
    ),
    (
        "canvas_write",
        "manage_canvas.commit_batch",
        "needs a canvas fixture the v2 seed does not build yet",
    ),
    (
        "messaging_read",
        "manage_messages.get_notification_preference",
        "needs a participant, destination or notification-preference fixture that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.add_reaction",
        "needs a message with reactions, expectations or relevance marks that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.classify",
        "needs a message fixture the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.edit",
        "needs a message with reactions, expectations or relevance marks that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.mark_no_longer_relevant",
        "needs a message with reactions, expectations or relevance marks that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.move",
        "needs a message fixture the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.remove_reaction",
        "needs a message with reactions, expectations or relevance marks that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.satisfy_acknowledgement_expectation_with_reaction",
        "needs a message with reactions, expectations or relevance marks that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_agent_disposition",
        "needs a participant, destination or notification-preference fixture that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_destination",
        "needs a participant, destination or notification-preference fixture that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_notification_preference",
        "needs a participant, destination or notification-preference fixture that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_preference",
        "needs a participant, destination or notification-preference fixture that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.set_routing",
        "needs a participant, destination or notification-preference fixture that the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.unclassify",
        "needs a message fixture the v2 seed does not build yet",
    ),
    (
        "messaging_write",
        "manage_messages.unmark_no_longer_relevant",
        "needs a message with reactions, expectations or relevance marks that the v2 seed does not build yet",
    ),
    (
        "records_write",
        "manage_account_config.ensure",
        "needs a registered account-config kind and an account footing that the v2 seed does not build yet",
    ),
    (
        "records_write",
        "prepare_named_views",
        "needs a named-view or saved-account fixture the v2 seed does not build yet",
    ),
    (
        "records_write",
        "record_view_revision",
        "needs a named-view or saved-account fixture the v2 seed does not build yet",
    ),
    (
        "records_write",
        "resolve_suggestions.accept",
        "needs a suggestion fixture the v2 seed does not build yet",
    ),
    (
        "records_write",
        "resolve_suggestions.reject",
        "needs a suggestion fixture the v2 seed does not build yet",
    ),
];

/// Local-first operations whose only KernelV2 write is to a log.
#[cfg(feature = "v2-kernel-probe")]
const WRITES_ONLY_HISTORY_ON_KERNEL_V2: &[(&str, &str, &str)] = &[(
    "guidance_read",
    "quickstart",
    "the v2 handler serves a static compiled value and writes no state at all, so replay is vacuous",
)];

/// Local-first operations that have a KernelV2 fixture and are known to fail
/// replay there. Debt that bites, like [`KNOWN_NOT_REPLAY_SAFE`] on SQLite.
/// Empty today: every such write either passes or is named elsewhere.
#[cfg(feature = "v2-kernel-probe")]
const KNOWN_NOT_REPLAY_SAFE_ON_KERNEL_V2: &[KnownFailure] = &[];

/// Local-first operations whose only write is to a log, so there is no
/// logical state to duplicate or diverge. Listed by hand: "writes only history"
/// is a claim someone should have looked at.
const WRITES_ONLY_HISTORY: &[(&str, &str, &str)] = &[
    (
        "coordination_write",
        "set_intent",
        "the declared intent is kept in the read log, not in a content table",
    ),
    (
        "guidance_read",
        "quickstart",
        "it only records that the guide was read",
    ),
];

/// Local-first operations that have a fixture and are known to fail replay.
/// Debt that bites: the test checks each really fails, so the entry cannot
/// outlive the problem, and removing the problem means removing the entry.
/// Empty today: `resolve_suggestions.accept` was the last entry and is now
/// keyed, so it replays.
const KNOWN_NOT_REPLAY_SAFE: &[KnownFailure] = &[];

/// A failure that is known and accepted for now: the first application and
/// the rebuild must succeed, and the redelivery must fail in exactly this way.
/// Any other failure of the operation fails the test.
struct KnownFailure {
    executor: &'static str,
    operation: &'static str,
    phase: Phase,
    message_contains: &'static str,
    reason: &'static str,
}

/// Replay every local-first operation in `operations` and account for every
/// one in `declared`. Returns how many were replayed and what went wrong.
/// The named lists are the engine's own: SQLite uses the shared consts, and
/// KernelV2 uses its small per-engine tables, so neither pass can hide behind
/// the other's debt.
async fn coverage(
    world: &World,
    operations: &[ReplayOperation],
    declared: &[(String, String)],
    known_failures: &[KnownFailure],
    not_served: &[(&str, &str, &str)],
    not_covered: &[(&str, &str, &str)],
    writes_only_history: &[(&str, &str, &str)],
) -> (usize, Vec<String>) {
    let engine = match world.engine {
        Engine::Sqlite => "SQLite",
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => "KernelV2",
    };
    let mut failures = Vec::new();
    let mut covered = 0;
    for operation in operations
        .iter()
        .filter(|o| o.requires_acceptance == Some(false))
    {
        let pair = (operation.executor.as_str(), operation.operation.as_str());
        let listed = |list: &[(&str, &str, &str)]| list.iter().any(|(e, o, _)| (*e, *o) == pair);
        let fixture = fixture(world, pair.0, pair.1).await;
        if listed(not_covered) {
            if fixture.is_some() {
                failures.push(format!(
                    "{}.{} has a fixture and is still listed as not covered on {engine}: remove it",
                    pair.0, pair.1
                ));
            }
            continue;
        }
        let Some(call) = fixture else {
            failures.push(format!(
                "{}.{} is local-first but has no replay fixture on {engine}: add one to \
                 fixture(), or list it as not covered with a reason",
                pair.0, pair.1
            ));
            continue;
        };
        covered += 1;
        let known = known_failures
            .iter()
            .find(|k| (k.executor, k.operation) == pair);
        match (check_replay(world, operation, &call).await, known) {
            (Ok(Passed::Replayed), None) => {}
            (Ok(Passed::OnlyHistory(tables)), None) => {
                if !listed(writes_only_history) {
                    failures.push(format!(
                        "{}.{} wrote only history on {engine} ({tables:?}), so its fixture proves \
                         nothing about replay: list it as writes-only history if that is right",
                        pair.0, pair.1
                    ));
                }
            }
            (Err(why), None) => failures.push(format!("{}.{}: {why}", pair.0, pair.1)),
            (Err(why), Some(known)) => {
                if why.phase != known.phase || !why.message.contains(known.message_contains) {
                    failures.push(format!(
                        "{}.{} is known to fail on {engine} as {:?} containing `{}` ({}), but \
                         failed differently: {why}",
                        pair.0, pair.1, known.phase, known.message_contains, known.reason
                    ));
                }
            }
            (Ok(_), Some(_)) => failures.push(format!(
                "{}.{} passes replay on {engine} but is listed as a known failure: remove it",
                pair.0, pair.1
            )),
        }
    }
    // A local-first operation the engine's catalogue does not serve cannot be
    // replayed here at all, so it must be named.
    for (executor, operation) in declared.iter().cloned() {
        let served = operations
            .iter()
            .any(|o| o.executor == executor && o.operation == operation);
        let named = not_served
            .iter()
            .any(|(e, o, _)| (*e, *o) == (executor.as_str(), operation.as_str()));
        match (served, named) {
            (false, false) => failures.push(format!(
                "{executor}.{operation} is declared local-first but the {engine} catalogue does \
                 not serve it, so it cannot be replayed here: list it as not served"
            )),
            (true, true) => failures.push(format!(
                "{executor}.{operation} is served on {engine} after all: remove it from the \
                 not-served list"
            )),
            _ => {}
        }
    }
    // Neither list may name something that is not a local-first write.
    for (executor, operation) in not_covered
        .iter()
        .chain(writes_only_history)
        .map(|(e, o, _)| (e, o))
        .chain(known_failures.iter().map(|k| (&k.executor, &k.operation)))
    {
        if !operations.iter().any(|o| {
            o.executor == *executor
                && o.operation == *operation
                && o.requires_acceptance == Some(false)
        }) {
            failures.push(format!(
                "{executor}.{operation} is listed as replay debt but is not a local-first write"
            ));
        }
    }
    (covered, failures)
}

#[tokio::test]
async fn every_local_first_write_survives_replay() {
    let world = seed().await;
    let (covered, failures) = coverage(
        &world,
        &replay_operations().unwrap(),
        &declared_local_first_operations(),
        KNOWN_NOT_REPLAY_SAFE,
        NOT_SERVED_ON_SQLITE,
        NOT_YET_COVERED,
        WRITES_ONLY_HISTORY,
    )
    .await;
    assert!(covered >= 20, "only {covered} operations were replayed");
    assert!(
        failures.is_empty(),
        "replay conformance:\n{}",
        failures.join("\n")
    );
}

/// The same mandatory pass on KernelV2: every local-first write the KernelV2
/// catalogue serves must either pass replay there or sit on a named per-engine
/// list with a reason. Production hosted runs this engine.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn every_local_first_write_survives_replay_on_kernel_v2() {
    let world = seed_on(Engine::KernelV2).await;
    let (covered, failures) = coverage(
        &world,
        &replay_operations_on_kernel_v2().unwrap(),
        &declared_local_first_operations(),
        KNOWN_NOT_REPLAY_SAFE_ON_KERNEL_V2,
        NOT_SERVED_ON_KERNEL_V2,
        NOT_YET_COVERED_ON_KERNEL_V2,
        WRITES_ONLY_HISTORY_ON_KERNEL_V2,
    )
    .await;
    assert!(covered >= 8, "only {covered} operations were replayed");
    assert!(
        failures.is_empty(),
        "replay conformance on KernelV2:\n{}",
        failures.join("\n")
    );
}

/// The test must be able to fail. These run the same check on calls that are
/// not replay-safe and require it to say so.
#[tokio::test]
async fn the_check_catches_operations_that_do_not_replay_safely() {
    let operations = replay_operations().unwrap();
    let operation = |executor: &str, name: &str| {
        operations
            .iter()
            .find(|o| o.executor == executor && o.operation == name)
            .unwrap_or_else(|| panic!("{executor}.{name} is not served"))
            .clone()
    };
    let world = seed().await;

    // A keyed append replays safely; the same append sent without its key
    // appends twice. This is the failure the keys exist to prevent.
    let update = operation("records_write", "update_record");
    let append = || json!({"id": world.id("note_a"), "body_append": " appended"});
    assert_eq!(
        check_replay(&world, &update, &local(append()).unwrap()).await,
        Ok(Passed::Replayed),
        "a keyed append replays safely"
    );
    let unkeyed = check_replay(&world, &update, &local_unkeyed(append()).unwrap())
        .await
        .expect_err("an unkeyed append must fail redelivery");
    // With attestations compared, the two deliveries also mint two
    // attestations with the same blanked content, which the comparison
    // reports as an ambiguity before it gets as far as counting rows.
    assert!(
        matches!(
            unkeyed.phase,
            Phase::RedeliveryState | Phase::AmbiguousIdentity
        ),
        "{unkeyed}"
    );

    // `create_many` creates every record again when it is sent without a key.
    let create_many = operation("records_write", "create_many");
    let batch = || {
        json!({"records": [{"type": "Document", "kind": "note", "name": "one"},
                           {"type": "Document", "kind": "note", "name": "two"}]})
    };
    let duplicated = check_replay(&world, &create_many, &local_unkeyed(batch()).unwrap())
        .await
        .expect_err("an unkeyed create_many must fail redelivery");
    // A duplicate is two identical new records, which the comparison reports
    // as an ambiguity before it gets as far as counting rows.
    assert!(
        matches!(
            duplicated.phase,
            Phase::RedeliveryState | Phase::AmbiguousIdentity
        ),
        "{duplicated}"
    );

    // A new local-first operation with no fixture and no named reason fails:
    // this is what makes local-first the safe default for new operations.
    let mut invented = update.clone();
    invented.operation = "invented_write".into();
    invented.requires_acceptance = Some(false);
    let (_, failures) = coverage(
        &world,
        &[invented],
        &[("records_write".to_owned(), "invented_write".to_owned())],
        &[],
        NOT_SERVED_ON_SQLITE,
        NOT_YET_COVERED,
        WRITES_ONLY_HISTORY,
    )
    .await;
    assert!(
        failures
            .iter()
            .any(|f| f.contains("invented_write is local-first but has no replay fixture")),
        "{failures:?}"
    );

    // Known debt names one failure. Any other failure of the same operation
    // fails the test: here an unkeyed append (which redelivers as a duplicate
    // write) is claimed to fail in a different way.
    let mut unkeyed_update = update.clone();
    unkeyed_update.accepts_idempotency_key = false;
    let wrong = [KnownFailure {
        executor: "records_write",
        operation: "update_record",
        phase: Phase::RedeliveryRefused,
        message_contains: "appended",
        reason: "wrong phase on purpose",
    }];
    let (_, failures) = coverage(
        &world,
        std::slice::from_ref(&unkeyed_update),
        &[("records_write".to_owned(), "update_record".to_owned())],
        &wrong,
        NOT_SERVED_ON_SQLITE,
        NOT_YET_COVERED,
        WRITES_ONLY_HISTORY,
    )
    .await;
    assert!(
        failures.iter().any(|f| f.contains("failed differently")),
        "{failures:?}"
    );
    // ... and a passing operation cannot sit on the debt list.
    let (_, failures) = coverage(
        &world,
        std::slice::from_ref(&update),
        &[("records_write".to_owned(), "update_record".to_owned())],
        &[KnownFailure {
            executor: "records_write",
            operation: "update_record",
            phase: Phase::RedeliveryState,
            message_contains: "",
            reason: "it does not fail",
        }],
        NOT_SERVED_ON_SQLITE,
        NOT_YET_COVERED,
        WRITES_ONLY_HISTORY,
    )
    .await;
    assert!(
        failures
            .iter()
            .any(|f| f.contains("passes replay on SQLite but is listed")),
        "{failures:?}"
    );
}

/// A keyed, multi-record `create_many` rebuilds and redelivers cleanly.
/// It stays `Required(ReplayDuplicates)` anyway: the unkeyed path
/// duplicates, and the node excludes it from automatic retry.
async fn keyed_create_many_replays_on(engine: Engine) {
    let world = seed_on(engine).await;
    let operation = operations_for(engine)
        .into_iter()
        .find(|o| o.executor == "records_write" && o.operation == "create_many")
        .unwrap_or_else(|| panic!("create_many is not served on {engine:?}"));
    let call = fixture(&world, "records_write", "create_many")
        .await
        .unwrap();
    assert_eq!(
        check_replay(&world, &operation, &call).await,
        Ok(Passed::Replayed),
        "a keyed create_many replays safely on {engine:?}"
    );
}

#[tokio::test]
async fn keyed_create_many_replays() {
    keyed_create_many_replays_on(Engine::Sqlite).await;
}

/// The KernelV2 half of the keyed `create_many` assertion, named for the
/// lane filter that runs it.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn keyed_create_many_replays_on_kernel_v2() {
    keyed_create_many_replays_on(Engine::KernelV2).await;
}

/// The same negative controls on KernelV2: the check must fail writes that do
/// not replay safely there too, and invented or indebted operations fail
/// loudly.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn the_check_catches_operations_that_do_not_replay_safely_on_kernel_v2() {
    let operations = replay_operations_on_kernel_v2().unwrap();
    let operation = |executor: &str, name: &str| {
        operations
            .iter()
            .find(|o| o.executor == executor && o.operation == name)
            .unwrap_or_else(|| panic!("{executor}.{name} is not served on KernelV2"))
            .clone()
    };
    let world = seed_on(Engine::KernelV2).await;

    // A keyed append replays safely; the same append sent without its key
    // appends twice.
    let update = operation("records_write", "update_record");
    let keyed = fixture(&world, "records_write", "update_record")
        .await
        .unwrap();
    assert_eq!(
        check_replay(&world, &update, &keyed).await,
        Ok(Passed::Replayed),
        "a keyed append replays safely on KernelV2"
    );
    let append = || json!({"id": world.id("note_a"), "body_append": " appended"});
    let unkeyed_call = Call {
        caller: world.caller(),
        ..local_unkeyed(append()).unwrap()
    };
    let unkeyed = check_replay(&world, &update, &unkeyed_call)
        .await
        .expect_err("an unkeyed append must fail redelivery on KernelV2");
    assert_eq!(unkeyed.phase, Phase::RedeliveryState, "{unkeyed}");

    // `create_many` creates every record again when it is sent without a key.
    let create_many = operation("records_write", "create_many");
    let batch = || {
        json!({"records": [{"type": "Document", "kind": "note", "name": "one"},
                           {"type": "Document", "kind": "note", "name": "two"}]})
    };
    let duplicated = check_replay(
        &world,
        &create_many,
        &Call {
            caller: world.caller(),
            ..local_unkeyed(batch()).unwrap()
        },
    )
    .await
    .expect_err("an unkeyed create_many must fail redelivery on KernelV2");
    assert!(
        matches!(
            duplicated.phase,
            Phase::RedeliveryState | Phase::AmbiguousIdentity
        ),
        "{duplicated}"
    );

    // A new local-first operation with no fixture and no named reason fails.
    let mut invented = update.clone();
    invented.operation = "invented_write".into();
    invented.requires_acceptance = Some(false);
    let (_, failures) = coverage(
        &world,
        &[invented],
        &[("records_write".to_owned(), "invented_write".to_owned())],
        &[],
        NOT_SERVED_ON_KERNEL_V2,
        NOT_YET_COVERED_ON_KERNEL_V2,
        WRITES_ONLY_HISTORY_ON_KERNEL_V2,
    )
    .await;
    assert!(
        failures
            .iter()
            .any(|f| f.contains("invented_write is local-first but has no replay fixture")),
        "{failures:?}"
    );

    // ... and a passing operation cannot sit on the debt list.
    let (_, failures) = coverage(
        &world,
        std::slice::from_ref(&update),
        &[("records_write".to_owned(), "update_record".to_owned())],
        &[KnownFailure {
            executor: "records_write",
            operation: "update_record",
            phase: Phase::RedeliveryState,
            message_contains: "",
            reason: "it does not fail",
        }],
        NOT_SERVED_ON_KERNEL_V2,
        NOT_YET_COVERED_ON_KERNEL_V2,
        WRITES_ONLY_HISTORY_ON_KERNEL_V2,
    )
    .await;
    assert!(
        failures
            .iter()
            .any(|f| f.contains("passes replay on KernelV2 but is listed")),
        "{failures:?}"
    );
}

// ---------------------------------------------------------------------------
// The comparison itself
// ---------------------------------------------------------------------------

/// What the comparison leaves out is a short list of named history tables,
/// each checked against the schema, so a live table cannot be dropped from it
/// by a name that happens to look like history.
#[tokio::test]
async fn the_comparison_leaves_out_only_history() {
    leaves_out_only_history(Engine::Sqlite).await;
}

/// The same integrity check on KernelV2: its extra history tables (if any)
/// are named and checked against its schema, and its live kernel tables are
/// compared.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn the_comparison_leaves_out_only_history_on_kernel_v2() {
    leaves_out_only_history(Engine::KernelV2).await;
}

/// Live KernelV2 tables that must always be compared: the backstop against a
/// history exclusion swallowing live state, mirroring
/// [`LIVE_TABLES_THAT_MUST_BE_COMPARED`] on SQLite.
#[cfg(feature = "v2-kernel-probe")]
const KERNEL_V2_LIVE_TABLES_THAT_MUST_BE_COMPARED: &[&str] = &[
    "kernel_records",
    "kernel_links",
    "kernel_generic_links",
    "kernel_saved_tabs",
];

async fn leaves_out_only_history(engine: Engine) {
    let world = seed_on(engine).await;
    let (all, derived) = schema_tables(&world.base).await;
    let state = logical_state(engine, &world.base).await;
    // The shared tables belong to the SQLite schema and are all present
    // there; KernelV2 has its own logs, so a shared table it never created is
    // nothing to exclude. Per-engine extras must exist on their engine.
    let extra = history_tables_extra(engine);
    for (table, kind) in HISTORY_TABLES.iter().chain(extra) {
        let present = all.iter().any(|t| t == table);
        assert!(
            ["event log", "provenance of acts", "read log", "act counter"].contains(kind),
            "{table}: `{kind}` is not a kind of history"
        );
        if extra.iter().any(|(t, _)| t == table) || engine == Engine::Sqlite {
            assert!(present, "{table} is not in the schema");
        }
        if present {
            assert!(
                !state.contains_key(*table),
                "{table} is compared and excluded"
            );
        }
    }
    let live: &[&str] = match engine {
        Engine::Sqlite => LIVE_TABLES_THAT_MUST_BE_COMPARED,
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => KERNEL_V2_LIVE_TABLES_THAT_MUST_BE_COMPARED,
    };
    for table in live {
        assert!(!is_history(engine, table), "{table} holds live state");
        assert!(state.contains_key(*table), "{table} is not compared");
    }
    // Every table is compared, named history, or SQLite's own and virtual ones.
    for table in &all {
        assert!(
            state.contains_key(table) || is_history(engine, table) || derived.contains(table),
            "{table} is silently left out"
        );
    }
    // The old heuristic dropped any name containing `act_`.
    if engine == Engine::Sqlite {
        for table in [
            "artifact_inputs",
            "artifact_module_grants",
            "derivation_artifact_role_heads",
        ] {
            assert!(state.contains_key(table), "{table} must be compared");
        }
    }
}

/// Two forks that apply the same fixture, and the window the calls ran in.
/// The tampering this checks is SQLite-shaped, so the comparison's own tests
/// stay on the SQLite world; the replay passes above run the same comparison
/// on both engines.
struct Pair {
    engine: Engine,
    honest: Db,
    tampered: Db,
    normaliser: Normaliser,
    started: chrono::DateTime<chrono::Utc>,
    ended: chrono::DateTime<chrono::Utc>,
}

/// The write catalogue for an engine's replay pass.
fn operations_for(engine: Engine) -> Vec<ReplayOperation> {
    match engine {
        Engine::Sqlite => replay_operations().unwrap(),
        #[cfg(feature = "v2-kernel-probe")]
        Engine::KernelV2 => replay_operations_on_kernel_v2().unwrap(),
    }
}

impl Pair {
    async fn new(world: &World, operation: &str) -> Self {
        let operations = operations_for(world.engine);
        let operation = operations
            .iter()
            .find(|o| o.operation == operation)
            .unwrap_or_else(|| panic!("{operation} is not served"));
        let call = fixture(world, &operation.executor, &operation.operation)
            .await
            .unwrap();
        let args = source_arguments(operation, &call, "control");
        let honest = fork(world, "honest").await;
        let tampered = fork(world, "tampered").await;
        let started = chrono::Utc::now();
        for db in [&honest, &tampered] {
            apply(world, db, operation, &call, &args).await.unwrap();
        }
        Self {
            engine: world.engine,
            honest,
            tampered,
            normaliser: Normaliser::new(&logical_state(world.engine, &world.base).await),
            started,
            ended: chrono::Utc::now(),
        }
    }

    async fn state(&self, db: &Db) -> BTreeMap<String, Vec<String>> {
        // A digest mismatch here means a tampered state, which the controls
        // assert on directly; honest states always validate.
        normalised(
            self.engine,
            &self.normaliser,
            db,
            self.started,
            self.ended,
            Phase::RedeliveryState,
        )
        .await
        .unwrap_or_else(|f| panic!("{f}"))
    }

    /// Two honest runs agree, so a difference after tampering is the tampering.
    async fn honest_runs_agree(&self) {
        assert_eq!(
            diff(
                &self.state(&self.honest).await,
                &self.state(&self.tampered).await
            ),
            None,
            "two honest runs differ, so the control proves nothing"
        );
    }

    /// Whether the tampering is seen.
    async fn tampering_is_seen(&self) -> bool {
        diff(
            &self.state(&self.honest).await,
            &self.state(&self.tampered).await,
        )
        .is_some()
    }

    async fn tamper(&self, sql: &str, binds: &[&str]) {
        let mut query = sqlx::query(sql);
        for bind in binds {
            query = query.bind(*bind);
        }
        query
            .execute(&crate::common::fixture_write_pool(&self.tampered).await)
            .await
            .unwrap();
    }
}

fn table_of(key: Option<&str>, rows: Vec<Vec<(&str, &str)>>) -> Table {
    Table {
        key: key.map(str::to_owned),
        rows: rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(c, v)| (c.to_owned(), v.to_owned()))
                    .collect()
            })
            .collect(),
    }
}

/// The engine-independent comparison checks: identical new rows are
/// ambiguous rather than guessed, and only the named column compares arrays
/// as a set. Shared by the SQLite and KernelV2 tampering suites.
fn synthetic_comparison_assertions(normaliser: &Normaliser) {
    // Two new rows with the same content cannot be told apart, so the
    // comparison says so instead of guessing.
    let twins = |a: &str, b: &str| {
        let mut state = State::new();
        state.insert(
            "records".to_owned(),
            table_of(
                Some("id"),
                vec![
                    vec![("id", a), ("name", "'same'")],
                    vec![("id", b), ("name", "'same'")],
                ],
            ),
        );
        state
    };
    let ambiguous = normaliser.state(
        &twins(
            "'7e570000-0000-4000-8000-0000000000a1'",
            "'7e570000-0000-4000-8000-0000000000a2'",
        ),
        &EventMaps::default(),
    );
    assert!(ambiguous.is_err(), "identical new rows were not flagged");

    // Array order is compared, except in the one column named as a set.
    let arrays = |array: &str| {
        let mut state = State::new();
        state.insert(
            "watched".to_owned(),
            table_of(None, vec![vec![("items", array)]]),
        );
        state.insert(
            "effective_relationships".to_owned(),
            table_of(None, vec![vec![("knowledge_watermark", array)]]),
        );
        normaliser.state(&state, &EventMaps::default()).unwrap()
    };
    let (forward, reversed) = (arrays(r#"'["a","b","c"]'"#), arrays(r#"'["c","b","a"]'"#));
    assert_ne!(
        forward["watched"], reversed["watched"],
        "reversed array went unnoticed"
    );
    assert_eq!(
        forward["effective_relationships"], reversed["effective_relationships"],
        "the named order-free column is compared as a set"
    );
}

/// The comparison must see each of these, and must refuse to guess when it
/// cannot tell two new records apart.
#[tokio::test]
async fn the_comparison_catches_what_it_must() {
    let world = seed().await;
    let base_state = logical_state(Engine::Sqlite, &world.base).await;
    let normaliser = Normaliser::new(&base_state);

    // A candidate attached to the wrong new record: only the link's target
    // moves, from the exploration to the other new candidate. Every id is
    // random, and nothing else about the row changes.
    let pair = Pair::new(&world, "create_exploration").await;
    pair.honest_runs_agree().await;
    let members: Vec<(String, String)> =
        sqlx::query_as("SELECT source_id, target_id FROM links WHERE relationship = 'member_of'")
            .fetch_all(pair.tampered.pool())
            .await
            .unwrap()
            .into_iter()
            .filter(|(source, _): &(String, String)| !normaliser.base_ids.contains(source))
            .collect();
    assert!(members.len() >= 2, "{members:?}");
    pair.tamper(
        "UPDATE links SET target_id = ? WHERE source_id = ? AND target_id = ?",
        &[&members[1].0, &members[0].0, &members[0].1],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a candidate attached to the wrong new record went unnoticed"
    );

    // The engine-independent checks run on both engines.
    synthetic_comparison_assertions(&normaliser);

    // A change in a table the old `act_` heuristic dropped is a change.
    let pair = Pair::new(&world, "create_record").await;
    let before = pair.state(&pair.honest).await;
    let mut changed = logical_state(pair.engine, &pair.honest).await;
    changed
        .get_mut("artifact_inputs")
        .expect("artifact_inputs is compared")
        .rows
        .push(BTreeMap::from([(
            "artifact_id".to_owned(),
            "'x'".to_owned(),
        )]));
    let events = output_event_rows(&pair.honest).await;
    let after = pair
        .normaliser
        .during(pair.started, pair.ended)
        .state(&changed, &events)
        .unwrap();
    assert!(
        diff(&before, &after).is_some(),
        "a change in artifact_inputs went unnoticed"
    );

    // A stance date the caller stated, replaced by today's.
    let pair = Pair::new(&world, "create_attribution").await;
    pair.honest_runs_agree().await;
    let today = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    pair.tamper(
        "UPDATE attribution_assertions SET stance_as_of = ? WHERE stance_as_of = ?",
        &[&today, HISTORIC_STANCE],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "an explicit stance date replaced by today's went unnoticed"
    );

    // An authored timestamp inside a body is compared verbatim, not masked
    // as JSON: replacing it on replay must fail.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    let now = pair.ended.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let body = format!("{{\"observed_at\": \"{now}\"}}");
    let target = world.id("note_b");
    pair.tamper(
        "UPDATE records SET body = ? WHERE id = ?",
        &[&body, &target],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a replaced authored timestamp in a body went unnoticed"
    );

    // An untouched record's creation time changed by the replay.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "UPDATE records SET created_at = '2001-01-01T00:00:00.000Z' WHERE id = ?",
        &[&world.id("note_b")],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a changed created_at on an untouched record went unnoticed"
    );
    // ... and the same time on a record the call did write is its own business.
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A replay that drops an older operation's authority row must fail:
    // retry lookup joins the authority table, so losing the row would let a
    // later retry of that key run again. The tables are append-only by
    // trigger, which a faulty restore would bypass along with the row, so
    // the control drops the guard to model the missing-row state.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "DROP TRIGGER provenance_local_attestation_authority_no_delete",
        &[],
    )
    .await;
    pair.tamper(
        "DELETE FROM provenance_local_attestation_authority WHERE operation = 'create_record'",
        &[],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a deleted authority row went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // Corrupting an existing attestation's output membership must fail the
    // replay check itself: the stored output-set digest is recomputed from
    // the rows before masking, so pointing the fixture's output at another
    // event cannot compare equal. Same trigger bypass as above.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper("DROP TRIGGER provenance_action_outputs_no_update", &[])
        .await;
    let seeded_event: (String,) =
        sqlx::query_as("SELECT id FROM content_events ORDER BY seq LIMIT 1")
            .fetch_one(pair.tampered.pool())
            .await
            .unwrap();
    pair.tamper(
        "UPDATE provenance_action_outputs SET output_event_id = ? WHERE action_attestation_id = \
         (SELECT id FROM provenance_action_attestations WHERE operation = 'update_record')",
        &[seeded_event.0.as_str()],
    )
    .await;
    let failure = normalised(
        Engine::Sqlite,
        &pair.normaliser,
        &pair.tampered,
        pair.started,
        pair.ended,
        Phase::RedeliveryState,
    )
    .await
    .expect_err("a corrupted output membership must fail the replay check");
    assert!(
        failure
            .to_string()
            .contains("output_event_set_digest does not match"),
        "wrong failure for a corrupted output membership: {failure}"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // Corrupting a stored attestation digest must fail the same way: the
    // digest is validated before it is masked, so a forgery cannot compare
    // equal. Same trigger bypass as above.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper("DROP TRIGGER provenance_action_attestations_no_update", &[])
        .await;
    pair
        .tamper(
            "UPDATE provenance_action_attestations SET output_event_set_digest = ? WHERE operation = 'update_record'",
            &[&"0".repeat(64)],
        )
        .await;
    let failure = normalised(
        Engine::Sqlite,
        &pair.normaliser,
        &pair.tampered,
        pair.started,
        pair.ended,
        Phase::RedeliveryState,
    )
    .await
    .expect_err("a forged attestation digest must fail the replay check");
    assert!(
        failure
            .to_string()
            .contains("output_event_set_digest does not match"),
        "wrong failure for a forged digest: {failure}"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A wrong output set with a recomputed, consistent digest must still
    // fail: output event ids resolve to labels from the referenced event's
    // content, and a fresh id has no event row, so it fails loudly as
    // unresolved instead of comparing as a blank. Same trigger bypass.
    let pair = Pair::new(&world, "create_exploration").await;
    pair.honest_runs_agree().await;
    pair.tamper("DROP TRIGGER provenance_action_outputs_no_update", &[])
        .await;
    pair.tamper("DROP TRIGGER provenance_action_attestations_no_update", &[])
        .await;
    let fresh_event = uuid::Uuid::new_v4().to_string();
    pair
        .tamper(
            "UPDATE provenance_action_outputs SET output_event_id = ? WHERE action_attestation_id = \
             (SELECT id FROM provenance_action_attestations WHERE operation = 'create_exploration') AND ordinal = 1",
            &[fresh_event.as_str()],
        )
        .await;
    let members: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT ordinal, output_domain, output_event_id FROM provenance_action_outputs WHERE action_attestation_id = \
         (SELECT id FROM provenance_action_attestations WHERE operation = 'create_exploration') ORDER BY ordinal",
    )
    .fetch_all(pair.tampered.pool())
    .await
    .unwrap();
    let recomputed = hex::encode(sha2::Sha256::digest(
        serde_jcs::to_vec(&Value::Array(
            members
                .into_iter()
                .map(|(_, domain, event)| json!({"domain": domain, "event_id": event}))
                .collect(),
        ))
        .unwrap(),
    ));
    pair
        .tamper(
            "UPDATE provenance_action_attestations SET output_event_set_digest = ? WHERE operation = 'create_exploration'",
            &[recomputed.as_str()],
        )
        .await;
    let failure = normalised(
        Engine::Sqlite,
        &pair.normaliser,
        &pair.tampered,
        pair.started,
        pair.ended,
        Phase::RedeliveryState,
    )
    .await
    .expect_err("a consistent but wrong output set must fail the replay check");
    assert!(
        failure.to_string().contains("references unknown event"),
        "wrong failure for a consistent but wrong output set: {failure}"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A replay that drops the seeded app attribution must fail: keyed
    // lookup reads it to admit the command's app context. Same trigger
    // bypass as above.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "DROP TRIGGER provenance_action_app_attributions_no_delete",
        &[],
    )
    .await;
    pair.tamper("DELETE FROM provenance_action_app_attributions", &[])
        .await;
    assert!(
        pair.tampering_is_seen().await,
        "a deleted app attribution went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A replay that drops the seeded cancellation must fail: the keyed
    // lookup guard reads it to refuse cancelled commands. The control
    // event it anchors stays excluded, as history. Same trigger bypass.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "DROP TRIGGER provenance_local_command_cancellations_no_delete",
        &[],
    )
    .await;
    pair.tamper("DELETE FROM provenance_local_command_cancellations", &[])
        .await;
    assert!(
        pair.tampering_is_seen().await,
        "a deleted cancellation went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A replay that drops or alters a seeded validity row must fail: held
    // cancellation lookup rejects invalidated attestations. Same trigger
    // bypass as above, once for the delete guard and once for the update
    // guard.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "DROP TRIGGER provenance_attestation_validity_events_no_delete",
        &[],
    )
    .await;
    pair.tamper(
        "DELETE FROM provenance_attestation_validity_events WHERE id = 'seed-validity-0'",
        &[],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a deleted validity row went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "DROP TRIGGER provenance_attestation_validity_events_no_update",
        &[],
    )
    .await;
    pair
        .tamper(
            "UPDATE provenance_attestation_validity_events SET status = 'restored' WHERE id = 'seed-validity-0'",
            &[],
        )
        .await;
    assert!(
        pair.tampering_is_seen().await,
        "an altered validity row went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // Losing the interaction receipt a seeded attestation references must
    // fail: the row is compared, and the attestation keeps pointing at it.
    // Same trigger bypass as above.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    let receipt: (String, String) = sqlx::query_as(
        "SELECT interaction_receipt_id, id FROM provenance_action_attestations WHERE interaction_receipt_id IS NOT NULL ORDER BY issued_at LIMIT 1",
    )
    .fetch_one(pair.tampered.pool())
    .await
    .unwrap();
    pair.tamper(
        "DROP TRIGGER provenance_interaction_receipts_no_delete",
        &[],
    )
    .await;
    pair.tamper("DROP TRIGGER provenance_action_attestations_no_update", &[])
        .await;
    pair.tamper(
        "UPDATE provenance_action_attestations SET interaction_receipt_id = NULL WHERE id = ?",
        &[receipt.1.as_str()],
    )
    .await;
    pair.tamper(
        "DELETE FROM provenance_interaction_receipts WHERE id = ?",
        &[receipt.0.as_str()],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a lost interaction receipt went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // Two distinct events sharing one content label must fail loudly as an
    // ambiguous referenced event: making the two create_many item events
    // identical, swapping their outputs and recomputing both digests must
    // not compare equal. Same trigger bypass as above.
    let pair = Pair::new(&world, "create_many").await;
    pair.honest_runs_agree().await;
    pair.tamper("DROP TRIGGER content_events_no_update", &[])
        .await;
    pair.tamper("DROP TRIGGER provenance_action_outputs_no_update", &[])
        .await;
    pair.tamper("DROP TRIGGER provenance_action_attestations_no_update", &[])
        .await;
    let items: Vec<(String, String)> = sqlx::query_as(
        "SELECT o.action_attestation_id, o.output_event_id FROM provenance_action_outputs o \
         JOIN provenance_action_attestations a ON a.id = o.action_attestation_id \
         WHERE a.operation = 'create_many' ORDER BY o.action_attestation_id",
    )
    .fetch_all(pair.tampered.pool())
    .await
    .unwrap();
    assert_eq!(items.len(), 2, "the fixture mints two item outputs");
    let first: (String, String) =
        sqlx::query_as("SELECT record_id, payload FROM content_events WHERE id = ?")
            .bind(&items[0].1)
            .fetch_one(pair.tampered.pool())
            .await
            .unwrap();
    pair.tamper(
        "UPDATE content_events SET record_id = ?, payload = ? WHERE id = ?",
        &[first.0.as_str(), first.1.as_str(), items[1].1.as_str()],
    )
    .await;
    // A three-step swap through a temporary id: the (domain, event) pair is
    // unique, so swapping two rows directly collides midway.
    let temp_event = uuid::Uuid::new_v4().to_string();
    pair.tamper(
        "UPDATE provenance_action_outputs SET output_event_id = ? WHERE action_attestation_id = ?",
        &[temp_event.as_str(), items[0].0.as_str()],
    )
    .await;
    pair.tamper(
        "UPDATE provenance_action_outputs SET output_event_id = ? WHERE action_attestation_id = ?",
        &[items[0].1.as_str(), items[1].0.as_str()],
    )
    .await;
    pair.tamper(
        "UPDATE provenance_action_outputs SET output_event_id = ? WHERE action_attestation_id = ?",
        &[items[1].1.as_str(), items[0].0.as_str()],
    )
    .await;
    for attestation in [&items[0].0, &items[1].0] {
        let members: Vec<(String, String)> = sqlx::query_as(
            "SELECT output_domain, output_event_id FROM provenance_action_outputs WHERE action_attestation_id = ? ORDER BY ordinal",
        )
        .bind(attestation)
        .fetch_all(pair.tampered.pool())
        .await
        .unwrap();
        let recomputed = hex::encode(sha2::Sha256::digest(
            serde_jcs::to_vec(&Value::Array(
                members
                    .into_iter()
                    .map(|(domain, event)| json!({"domain": domain, "event_id": event}))
                    .collect(),
            ))
            .unwrap(),
        ));
        pair.tamper(
            "UPDATE provenance_action_attestations SET output_event_set_digest = ? WHERE id = ?",
            &[recomputed.as_str(), attestation.as_str()],
        )
        .await;
    }
    let failure = normalised(
        Engine::Sqlite,
        &pair.normaliser,
        &pair.tampered,
        pair.started,
        pair.ended,
        Phase::RedeliveryState,
    )
    .await
    .expect_err("two identically shaped events must fail as ambiguous");
    assert!(
        failure.to_string().contains("ambiguous referenced event"),
        "wrong failure for identically shaped events: {failure}"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // An authored timestamp inside an event payload is compared verbatim,
    // not masked: replacing the fixture's stated as_of on replay must fail.
    // Same trigger bypass as above.
    let pair = Pair::new(&world, "manage_facet_observations.set").await;
    pair.honest_runs_agree().await;
    pair.tamper("DROP TRIGGER content_events_no_update", &[])
        .await;
    // The seed has its own facet observations, so the newest attestation —
    // the fixture's — is the target.
    let event: (String,) = sqlx::query_as(
        "SELECT o.output_event_id FROM provenance_action_outputs o \
         JOIN provenance_action_attestations a ON a.id = o.action_attestation_id \
         WHERE a.operation = 'manage_facet_observations' ORDER BY a.issued_at DESC LIMIT 1",
    )
    .fetch_one(pair.tampered.pool())
    .await
    .unwrap();
    let now = pair.ended.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    pair.tamper(
        "UPDATE content_events SET payload = replace(payload, '2026-09-01T00:00:00.000Z', ?) WHERE id = ?",
        &[now.as_str(), event.0.as_str()],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a replaced authored payload timestamp went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // An unrelated event with the same id in the other domain must not
    // supply the label: outputs resolve in their own domain, so planting a
    // relationship row under a content output's id leaves the label — and
    // the comparison — unchanged. Same trigger bypass as above, in reverse:
    // the decoy row is inserted, not deleted.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    let event: (String,) = sqlx::query_as(
        "SELECT o.output_event_id FROM provenance_action_outputs o \
         JOIN provenance_action_attestations a ON a.id = o.action_attestation_id \
         WHERE a.operation = 'update_record' LIMIT 1",
    )
    .fetch_one(pair.tampered.pool())
    .await
    .unwrap();
    let origin: (String,) =
        sqlx::query_as("SELECT origin_db_id FROM database_identity WHERE singleton = 1")
            .fetch_one(pair.tampered.pool())
            .await
            .unwrap();
    pair.tamper(
        "INSERT INTO relationship_events (id, stream_kind, stream_id, stream_version, relationship_origin_db_id, relationship_id, type, payload, actor, issuer_origin_db_id, occurred_at, ingested_at, act) VALUES (?, 'assertion', 'decoy', 1, ?, 'decoy', 'assertion.created.v1', '{}', 'local', ?, '2026-01-04T00:00:00.000Z', '2026-01-04T00:00:00.000Z', NULL)",
        &[
            event.0.as_str(),
            origin.0.as_str(),
            origin.0.as_str(),
        ],
    )
    .await;
    assert!(
        !pair.tampering_is_seen().await,
        "an unrelated same-ID row in the other domain disturbed the label"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A relationship output resolves against its attestation's issuer
    // origin: the events belong to one issuer, so moving the attestation's
    // claimed origin elsewhere leaves no row in the output's domain, and it
    // fails loudly as unresolved. The event rows themselves cannot move:
    // child tables reference them by (issuer, id), so the foreign key holds
    // them in place. Same trigger bypass as above.
    let pair = Pair::new(&world, "manage_relationships.assert").await;
    pair.honest_runs_agree().await;
    pair.tamper("DROP TRIGGER provenance_action_attestations_no_update", &[])
        .await;
    // The seed has its own relationship assertions, so the newest
    // attestation — the fixture's — is the target.
    let attestation: (String, String) = sqlx::query_as(
        "SELECT a.id, a.issuer_origin_database_id FROM provenance_action_attestations a \
         WHERE a.operation = 'manage_relationships' ORDER BY a.issued_at DESC LIMIT 1",
    )
    .fetch_one(pair.tampered.pool())
    .await
    .unwrap();
    let mut other: Vec<char> = attestation.1.chars().collect();
    let last = other.pop().unwrap();
    other.push(if last == '0' { '1' } else { '0' });
    let other: String = other.into_iter().collect();
    pair.tamper(
        "UPDATE provenance_action_attestations SET issuer_origin_database_id = ? WHERE id = ?",
        &[other.as_str(), attestation.0.as_str()],
    )
    .await;
    let failure = normalised(
        Engine::Sqlite,
        &pair.normaliser,
        &pair.tampered,
        pair.started,
        pair.ended,
        Phase::RedeliveryState,
    )
    .await
    .expect_err("an attestation moved to another issuer must fail the replay check");
    assert!(
        failure.to_string().contains("references unknown event"),
        "wrong failure for an attestation moved to another issuer: {failure}"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }
}

/// The same tampering integrity controls on KernelV2: the comparison must
/// see a rewired link between minted records, a forged receipt ref, a
/// deleted or corrupted claim receipt, a replaced authored date and a
/// touched record — and refuse to guess identical new rows.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn the_comparison_catches_what_it_must_on_kernel_v2() {
    let world = seed_on(Engine::KernelV2).await;
    let base_state = logical_state(Engine::KernelV2, &world.base).await;
    let normaliser = Normaliser::new(&base_state);

    // Two honest forks agree; the engine-independent checks run here too.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    synthetic_comparison_assertions(&normaliser);
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A link rewired between two records the call minted: only the
    // endpoints move. Every id is random, and nothing else changes.
    let operations = operations_for(Engine::KernelV2);
    let operation = operations
        .iter()
        .find(|o| o.operation == "create_many")
        .unwrap_or_else(|| panic!("create_many is not served on KernelV2"))
        .clone();
    let call = fixture(&world, "records_write", "create_many")
        .await
        .unwrap();
    let args = source_arguments(&operation, &call, "control");
    let honest = fork(&world, "honest").await;
    let tampered = fork(&world, "tampered").await;
    let started = chrono::Utc::now();
    let first = apply(&world, &honest, &operation, &call, &args)
        .await
        .unwrap();
    let second = apply(&world, &tampered, &operation, &call, &args)
        .await
        .unwrap();
    let ended = chrono::Utc::now();
    let (r1h, r2h) = (
        first["ids"][0].as_str().unwrap(),
        first["ids"][1].as_str().unwrap(),
    );
    let (r1t, r2t) = (
        second["ids"][0].as_str().unwrap(),
        second["ids"][1].as_str().unwrap(),
    );
    for (db, r1, r2) in [(&honest, r1h, r2h), (&tampered, r1t, r2t)] {
        sqlx::query(
            "INSERT INTO kernel_links(source_id, target_id, relationship, created_seq) \
             VALUES (?, ?, 'relates_to', 1)",
        )
        .bind(r1)
        .bind(r2)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    }
    let honest_state = normalised(
        Engine::KernelV2,
        &normaliser,
        &honest,
        started,
        ended,
        Phase::RedeliveryState,
    )
    .await
    .unwrap_or_else(|f| panic!("{f}"));
    let tampered_state = normalised(
        Engine::KernelV2,
        &normaliser,
        &tampered,
        started,
        ended,
        Phase::RedeliveryState,
    )
    .await
    .unwrap_or_else(|f| panic!("{f}"));
    assert_eq!(
        diff(&honest_state, &tampered_state),
        None,
        "two honest runs differ, so the control proves nothing"
    );
    sqlx::query("UPDATE kernel_links SET source_id = ?, target_id = ? WHERE source_id = ?")
        .bind(r2t)
        .bind(r1t)
        .bind(r1t)
        .execute(&crate::common::fixture_write_pool(&tampered).await)
        .await
        .unwrap();
    let rewired = normalised(
        Engine::KernelV2,
        &normaliser,
        &tampered,
        started,
        ended,
        Phase::RedeliveryState,
    )
    .await
    .unwrap_or_else(|f| panic!("{f}"));
    assert!(
        diff(&honest_state, &rewired).is_some(),
        "a link rewired between minted records went unnoticed"
    );
    for db in [honest, tampered] {
        db.close().await;
    }

    // A forged receipt short ref (another record's prefix) is not resolved
    // to anything: replacing it on replay must fail.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    let receipt: (String,) = sqlx::query_as(
        "SELECT receipt_json FROM kernel_mcp_write_receipts \
         WHERE receipt_json LIKE '%\"effect\":\"updated\"%'",
    )
    .fetch_one(pair.tampered.pool())
    .await
    .unwrap();
    let mut forged: Value = serde_json::from_str(&receipt.0).unwrap();
    let sibling = forged["id"].as_str().unwrap().to_owned();
    assert!(
        forged["short_ref"]
            .as_str()
            .unwrap()
            .starts_with(&sibling[..7]),
        "the fixture receipt carries no genuine short ref to forge"
    );
    forged["short_ref"] = json!(world.id("note_b")[..7]);
    forged["display_reference"] = json!(world.id("note_b")[..7]);
    let forged_json = serde_json::to_string(&forged).unwrap();
    pair.tamper(
        "UPDATE kernel_mcp_write_receipts SET receipt_json = ? \
         WHERE receipt_json LIKE '%\"effect\":\"updated\"%'",
        &[forged_json.as_str()],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a forged receipt short ref went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A deleted or corrupted claim receipt must fail: the receipts are
    // compared, only their named incidental fields masked.
    for tamper in [
        "DELETE FROM kernel_provider_receipts",
        "UPDATE kernel_provider_receipts SET request_json = '{\"forged\": true}'",
    ] {
        let pair = Pair::new(&world, "start_work.claim").await;
        pair.honest_runs_agree().await;
        pair.tamper(tamper, &[]).await;
        assert!(
            pair.tampering_is_seen().await,
            "a {tamper} claim receipt went unnoticed"
        );
        for db in [&pair.honest, &pair.tampered] {
            db.close().await;
        }
    }

    // Corrupting only a receipt checksum fails the integrity check that
    // runs before masking: the digest is recomputed from the stored
    // request, so a forgery cannot compare equal. The claim checksum
    // compares verbatim (the fixture passes an explicit operation key);
    // the relationship digest below is masked, which is why the check
    // must run first.
    // Corrupting only a receipt checksum fails the replay check itself:
    // validation recomputes the digest from the stored request before
    // masking, so a forgery cannot compare equal. The claim checksum
    // compares verbatim on top (the fixture passes an explicit operation
    // key); the relationship digest below is masked, which is why the
    // check must run first. Both controls go through the real normaliser
    // path, not around it. The SQLite twin lives in
    // `the_comparison_catches_what_it_must`: attestation digests are
    // validated the same way before masking, and SQLite's own controls
    // corrupt them through the same normaliser path.
    for (operation, key, agree) in [
        ("start_work.claim", "request_checksum", true),
        // The add leg cannot agree honestly: its link rows carry the
        // engine's own call time. Integrity is still per-state, so the
        // digest control runs without the agreement preamble.
        ("manage_links.add", "request_digest", false),
    ] {
        let pair = Pair::new(&world, operation).await;
        if agree {
            pair.honest_runs_agree().await;
        }
        let row: (i64, String) = sqlx::query_as(
            "SELECT rowid, request_json FROM kernel_provider_receipts \
             WHERE request_json LIKE ? LIMIT 1",
        )
        .bind(format!("%\"{key}\"%"))
        .fetch_one(pair.tampered.pool())
        .await
        .unwrap();
        let mut request: Value = serde_json::from_str(&row.1).unwrap();
        assert!(
            request.get(key).is_some(),
            "the {operation} receipt carries no {key} to corrupt"
        );
        request[key] = json!("forged");
        let forged = serde_json::to_string(&request).unwrap();
        let rowid = row.0.to_string();
        pair.tamper(
            "UPDATE kernel_provider_receipts SET request_json = ? WHERE rowid = ?",
            &[&forged, &rowid],
        )
        .await;
        let failure = normalised(
            Engine::KernelV2,
            &pair.normaliser,
            &pair.tampered,
            pair.started,
            pair.ended,
            Phase::RedeliveryState,
        )
        .await
        .expect_err("a forged receipt digest must fail the replay check");
        assert!(
            failure
                .to_string()
                .contains("does not match its stored request"),
            "wrong failure for a forged digest: {failure}"
        );
        for db in [&pair.honest, &pair.tampered] {
            db.close().await;
        }
    }

    // An authored timestamp inside a body is compared verbatim, not masked
    // as JSON: replacing it on replay must fail.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    let now = pair.ended.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let body = format!("{{\"observed_at\": \"{now}\"}}");
    let target = world.id("note_b");
    pair.tamper(
        "UPDATE kernel_record_bodies SET body = ? WHERE record_id = ?",
        &[&body, &target],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a replaced authored timestamp in a v2 body went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // An authored claimed timestamp compares verbatim, even in-window:
    // replacing it on replay must fail. (No masking applies to it: the
    // named JSON paths name only engine-stamped fields. SQLite has no
    // analogue — v1 links carry no timestamps — so this control is v2-only,
    // like the authored-body control is shared.)
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    let authored: (String,) = sqlx::query_as(
        "SELECT raw_json FROM kernel_provider_link_rows WHERE source_id = ? AND target_id = ?",
    )
    .bind(world.id("note_a"))
    .bind(world.id("task_t"))
    .fetch_one(pair.honest.pool())
    .await
    .unwrap();
    assert!(
        authored.0.contains("2026-09-01T00:00:00.000Z"),
        "the seed link carries no authored claimed timestamp: {authored:?}"
    );
    let now = pair.ended.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    pair.tamper(
        "UPDATE kernel_provider_link_rows SET raw_json = replace(raw_json, '2026-09-01T00:00:00.000Z', ?) WHERE source_id = ? AND target_id = ?",
        &[&now, &world.id("note_a"), &world.id("task_t")],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a replaced authored claimed timestamp went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // A field row pushed by the replay is a change.
    let pair = Pair::new(&world, "update_record").await;
    let before = pair.state(&pair.honest).await;
    let mut changed = logical_state(pair.engine, &pair.honest).await;
    changed
        .get_mut("kernel_record_fields")
        .expect("kernel_record_fields is compared")
        .rows
        .push(BTreeMap::from([
            ("record_id".to_owned(), format!("'{}'", world.id("note_b"))),
            ("name".to_owned(), "'x-proof'".to_owned()),
            ("value_json".to_owned(), "'\"x\"'".to_owned()),
            ("created_seq".to_owned(), "1".to_owned()),
        ]));
    let events = output_event_rows(&pair.honest).await;
    let after = pair
        .normaliser
        .during(pair.started, pair.ended)
        .state(&changed, &events)
        .unwrap();
    assert!(
        diff(&before, &after).is_some(),
        "a pushed field row went unnoticed"
    );
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }

    // An untouched record's creation time changed by the replay.
    let pair = Pair::new(&world, "update_record").await;
    pair.honest_runs_agree().await;
    pair.tamper(
        "UPDATE kernel_records SET created_at = '2001-01-01T00:00:00.000Z' WHERE id = ?",
        &[&world.id("note_b")],
    )
    .await;
    assert!(
        pair.tampering_is_seen().await,
        "a changed created_at on an untouched v2 record went unnoticed"
    );
    // ... and the same time on a record the call did write is its own business.
    for db in [&pair.honest, &pair.tampered] {
        db.close().await;
    }
}

/// The named masking rules, pinned: only the listed engine-generated JSON
/// paths mask, a historic instant at a named path still compares, and an
/// untampered receipt short ref resolves to its unique sibling while any
/// other quote is left alone. Authored JSON is never masked.
#[test]
fn the_comparison_masks_only_named_json_paths_and_unique_sibling_refs() {
    let normaliser = Normaliser::new(&State::new());
    let now = chrono::Utc::now();
    let scoped = normaliser.during(
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::seconds(1),
    );
    let instant = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // A named engine-generated instant is incidental in-window ...
    let receipt = json!({"id": "x", "updated_at": instant, "custom": instant});
    let masked =
        scoped.mask_named_json("kernel_mcp_write_receipts", "receipt_json", &receipt, None);
    assert_eq!(masked["updated_at"], Value::String("<incidental>".into()));
    // ... and an unnamed path compares even in-window.
    assert_eq!(masked["custom"], receipt["custom"]);
    // ... while a historic instant at the same path still compares.
    let old = json!({"id": "x", "updated_at": "2026-01-01T00:00:00.000Z"});
    let masked = scoped.mask_named_json("kernel_mcp_write_receipts", "receipt_json", &old, None);
    assert_eq!(
        masked["updated_at"],
        Value::String("2026-01-01T00:00:00.000Z".into())
    );
    let body = json!({"observed_at": instant});
    assert_eq!(
        scoped.mask_named_json("records", "body", &body, None),
        body,
        "authored JSON is never masked"
    );
    // The claim checksum compares verbatim: the fixture passes an explicit
    // operation key, so masking it would hide a forgery.
    let request = json!({"command": "Claim", "request_checksum": "ced9"});
    assert_eq!(
        scoped.mask_named_json("kernel_provider_receipts", "request_json", &request, None),
        request
    );
    // The relationship digest is masked, since it covers a minted key.
    let request = json!({"command": "Retract", "request_digest": "c7dd"});
    assert_eq!(
        scoped.mask_named_json("kernel_provider_receipts", "request_json", &request, None)
            ["request_digest"],
        Value::String("<incidental>".into())
    );

    // A top-level text cell keeps comparing literally, even in-window.
    let row = BTreeMap::from([("note".to_owned(), format!("'{instant}'"))]);
    let cells = scoped.cells("records", &row, &|text| text.to_owned());
    assert_eq!(cells["note"], Value::String(instant.clone()));

    // Integer-millisecond instants mask the same way, by column.
    let row = BTreeMap::from([(
        "created_at_ms".to_owned(),
        now.timestamp_millis().to_string(),
    )]);
    let cells = scoped.cells("kernel_provider_link_rows", &row, &|text| text.to_owned());
    assert_eq!(cells["created_at_ms"], Value::String("<incidental>".into()));
    let row = BTreeMap::from([("created_at_ms".to_owned(), "1000".to_owned())]);
    let cells = scoped.cells("kernel_provider_link_rows", &row, &|text| text.to_owned());
    assert_eq!(cells["created_at_ms"], Value::String("1000".into()));

    // A seeded timestamp inside the call window still compares: the base
    // row is identical on every fork, so the value is verbatim even though
    // it falls inside the window. New rows keep the window rule.
    let seeded_row = BTreeMap::from([
        ("id".to_owned(), "'note_b'".to_owned()),
        ("created_at".to_owned(), format!("'{instant}'")),
    ]);
    let mut base = State::new();
    base.insert(
        "kernel_records".to_owned(),
        Table {
            key: Some("id".to_owned()),
            rows: vec![seeded_row.clone()],
        },
    );
    let seeded_scoped = Normaliser::new(&base).during(
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::seconds(1),
    );
    let cells = seeded_scoped.cells("kernel_records", &seeded_row, &|text| text.to_owned());
    assert_eq!(cells["created_at"], Value::String(instant.clone()));
    // ... and the same holds for a named JSON path inside a seeded blob.
    let blob = json!({"state": {"holder": {"claimed_at": instant.clone()}}});
    let seeded_blob_row = BTreeMap::from([
        ("id".to_owned(), "'s1'".to_owned()),
        ("state_json".to_owned(), requote(&blob)),
    ]);
    let mut base = State::new();
    base.insert(
        "kernel_provider_state".to_owned(),
        Table {
            key: Some("id".to_owned()),
            rows: vec![seeded_blob_row.clone()],
        },
    );
    let seeded_scoped = Normaliser::new(&base).during(
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::seconds(1),
    );
    let cells = seeded_scoped.cells("kernel_provider_state", &seeded_blob_row, &|text| {
        text.to_owned()
    });
    assert_eq!(
        cells["state_json"]["state"]["holder"]["claimed_at"],
        Value::String(instant.clone())
    );

    // A short ref resolves to the sibling id it uniquely prefixes ...
    let id = "76a27a92-cab4-4d97-a575-4e6d01d5788e";
    let mut state = State::new();
    state.insert(
        "kernel_mcp_write_receipts".to_owned(),
        Table {
            key: None,
            rows: vec![BTreeMap::from([(
                "receipt_json".to_owned(),
                requote(&json!({"id": id, "short_ref": "76a27a9"})),
            )])],
        },
    );
    let resolved = scoped.resolve_receipt_refs(&state);
    let row = &resolved["kernel_mcp_write_receipts"].rows[0];
    assert_eq!(
        Normaliser::decode(&row["receipt_json"])["short_ref"],
        Value::String(id.into())
    );
    // ... a quote the sibling does not start with is left alone ...
    let mut state = State::new();
    state.insert(
        "kernel_mcp_write_receipts".to_owned(),
        Table {
            key: None,
            rows: vec![BTreeMap::from([(
                "receipt_json".to_owned(),
                requote(&json!({"id": id, "short_ref": "deadbee"})),
            )])],
        },
    );
    let resolved = scoped.resolve_receipt_refs(&state);
    let row = &resolved["kernel_mcp_write_receipts"].rows[0];
    assert_eq!(
        Normaliser::decode(&row["receipt_json"])["short_ref"],
        Value::String("deadbee".into())
    );
    // ... and so is a prefix shared by two records.
    let other = "76a27a9f-0000-4000-8000-000000000000";
    let mut state = State::new();
    state.insert(
        "kernel_mcp_write_receipts".to_owned(),
        Table {
            key: None,
            rows: vec![BTreeMap::from([
                (
                    "receipt_json".to_owned(),
                    requote(&json!({"id": id, "short_ref": "76a27a9"})),
                ),
                ("note".to_owned(), format!("'{other}'")),
            ])],
        },
    );
    let resolved = scoped.resolve_receipt_refs(&state);
    let row = &resolved["kernel_mcp_write_receipts"].rows[0];
    assert_eq!(
        Normaliser::decode(&row["receipt_json"])["short_ref"],
        Value::String("76a27a9".into()),
        "an ambiguous quote must not resolve"
    );

    // An authored link row time compares verbatim, even in-window; an
    // engine-stamped one masks only inside the window, and a historic one
    // is left alone.
    let sources = json!({"state": {"assertions": [{"sources": [
        {"from": "a1", "to": "b1", "claimed_timestamp": "2026-09-01T00:00:00.000Z"},
        {"from": "c1", "to": "d1", "claimed_timestamp": null},
    ]}]}});
    let stated = requote(&sources);
    let authored_row = requote(&json!(["id-a", "a1", "b1", null, instant.clone()]));
    let engine_row = requote(&json!(["id-e", "c1", "d1", null, instant.clone()]));
    let old_row = requote(&json!([
        "id-o",
        "c1",
        "d1",
        null,
        "2026-01-01T00:00:00.000Z"
    ]));
    let mut state = State::new();
    state.insert(
        "kernel_provider_state".to_owned(),
        table_of(None, vec![vec![("state_json", stated.as_str())]]),
    );
    state.insert(
        "kernel_provider_link_rows".to_owned(),
        table_of(
            None,
            vec![
                vec![
                    ("source_id", "'a1'"),
                    ("target_id", "'b1'"),
                    ("raw_json", authored_row.as_str()),
                ],
                vec![
                    ("source_id", "'c1'"),
                    ("target_id", "'d1'"),
                    ("raw_json", engine_row.as_str()),
                ],
                vec![
                    ("source_id", "'c1'"),
                    ("target_id", "'d1'"),
                    ("raw_json", old_row.as_str()),
                ],
            ],
        ),
    );
    let masked = scoped.mask_unclaimed_link_times(&state);
    let rows = &masked["kernel_provider_link_rows"].rows;
    assert_eq!(
        Normaliser::decode(&rows[0]["raw_json"])[4],
        json!(instant),
        "an authored timestamp is never masked, even in-window"
    );
    assert_eq!(
        Normaliser::decode(&rows[1]["raw_json"])[4],
        json!("<incidental>"),
        "an engine-stamped in-window time is masked"
    );
    assert_eq!(
        Normaliser::decode(&rows[2]["raw_json"])[4],
        json!("2026-01-01T00:00:00.000Z"),
        "an engine-stamped historic time still compares"
    );

    // A seeded row keeps its stamped time, even in-window: the base copy
    // is identical on every fork, so only values the call changed or added
    // get window-masked. A row the call added masks its engine-stamped time.
    let instant_cell = format!("'{instant}'");
    let mut base = State::new();
    base.insert(
        "kernel_policies".to_owned(),
        table_of(
            Some("root_id"),
            vec![vec![
                ("root_id", "'home-1'"),
                ("created_at", instant_cell.as_str()),
            ]],
        ),
    );
    let policy_scoped = Normaliser::new(&base).during(
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::seconds(1),
    );
    let mut state = State::new();
    state.insert(
        "kernel_policies".to_owned(),
        table_of(
            None,
            vec![
                vec![
                    ("root_id", "'home-1'"),
                    ("created_at", instant_cell.as_str()),
                ],
                vec![
                    ("root_id", "'home-2'"),
                    ("created_at", instant_cell.as_str()),
                ],
            ],
        ),
    );
    // A seeded row keeps even an in-window timestamp ...
    let cells = policy_scoped.cells("kernel_policies", &state["kernel_policies"].rows[0], &|t| {
        t.to_owned()
    });
    assert_eq!(
        cells["created_at"],
        Value::String(instant.clone()),
        "a seeded policy time is never masked"
    );
    // ... while a row the call added masks its engine-stamped time.
    let cells = policy_scoped.cells("kernel_policies", &state["kernel_policies"].rows[1], &|t| {
        t.to_owned()
    });
    assert_eq!(
        cells["created_at"],
        Value::String("<incidental>".into()),
        "an added policy row still masks its call time"
    );
}
