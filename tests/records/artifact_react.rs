//! Tab-governed message reactions (task `07ae879` I2): the install guard
//! admits the consented emoji subset, and the kernel re-proves need
//! membership, message View, locality and desired state in one write
//! transaction through the shared messaging internals. Never touches
//! acknowledgement state.
use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record as create_raw_record;
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

const ARTIFACT: &str = "66666666-6666-4666-8666-666666666666";
const CHAN: &str = "0a5e0000-0000-4000-8000-000000000021";
const ALICE: &str = "acct:alice";
const BOB: &str = "acct:bob";
const ALICE_PERSON: &str = "e8bec700-0000-4000-8000-000000000021";
const BOB_PERSON: &str = "e8bec700-0000-4000-8000-000000000022";
const CAROL: &str = "acct:carol";
const CAROL_PERSON: &str = "e8bec700-0000-4000-8000-000000000023";
const PACKAGE: &str = "agent.reactions";
const INVOCATION_VERSION: &str = "native.artifact-invocation.v1";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, caller: Caller, tool: &str, args: Value) -> Value {
    registry.call(db.clone(), caller, tool, args).await.unwrap()
}

/// The MDX v2 parser and its caches are process-wide, as the module suite's
/// guard already assumes.
fn integration_guard() -> &'static Arc<tokio::sync::Mutex<()>> {
    static GUARD: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    GUARD.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
}

async fn install_persons(db: &Db) {
    for (person, account, name) in [
        (ALICE_PERSON, ALICE, "Alice"),
        (BOB_PERSON, BOB, "Bob"),
        (CAROL_PERSON, CAROL, "Carol"),
    ] {
        create_raw_record(
            db,
            json!({ "id": person, "type": "Entity", "kind": "person", "name": name }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(person)
        .bind(account)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'native-principal', ?, 1)",
        )
        .bind(person)
        .bind(format!("native/{}", name.to_ascii_lowercase()))
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    }
}

async fn create_message(registry: &ToolRegistry, db: &Db) -> String {
    create_message_from(
        registry,
        db,
        ALICE,
        BOB_PERSON,
        None,
        vec![ALICE_PERSON, BOB_PERSON],
    )
    .await
}

async fn create_message_from(
    registry: &ToolRegistry,
    db: &Db,
    sender: &str,
    addressee: &str,
    expectation: Option<&str>,
    participants: Vec<&str>,
) -> String {
    let mut args = json!({
        "action": "send",
        "body": "reactable message",
        "origin": {"type": "direct", "participant_ids": participants},
        "addressed_to": [addressee],
        "expectation": "none",
        "idempotency_key": format!("react-setup-{}", uuid::Uuid::new_v4()),
        "reason": "Set up a reactable message for the tab reaction tests.",
    });
    if let Some(obligation) = expectation {
        args["expectation"] = json!(obligation);
    }
    let args = crate::common::with_test_reason("manage_messages", args);
    call(
        registry,
        db,
        Caller::authenticated(sender),
        "manage_messages",
        args,
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn react_mdx_source() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { chan: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "chan" } }],
  interactions: [{ id: "react", label: "React", effect: "message.react",
    slots: { message: { domain: { kind: "bound_input", port: "chan" } } },
    react: { emoji: ["👍", "❤️"] } }]
}

<Metric label="Total" value={1} />
"#
    .into()
}

fn html_interaction_source(source: &str) -> String {
    let parsed = native_artifact_runtime::mdx_v2::parse_artifact(source).unwrap();
    let native_artifact_runtime::mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
        unreachable!()
    };
    let declaration = json!({
        "schema": "native.html.artifact.v2", "inputs": manifest.inputs,
        "capability_requests": manifest.capability_requests, "interactions": manifest.interactions,
    });
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Interactions</title><script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script></head><body><main><h1>Interactions</h1></main></body></html>")
}

fn react_need_sql() -> String {
    "SELECT id FROM records WHERE type='Message' AND deleted_at IS NULL ORDER BY id ASC LIMIT 200"
        .into()
}

fn react_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "messages.channel", "label": "Channel", "sql": react_need_sql()}
        ],
        "effects": [{
            "effect": "message.react.v1",
            "emoji": ["👍", "❤️"],
            "target": {"need": "messages.channel"}
        }]
    })
}

fn digest_of(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

fn alpha_guard_pin_for(body: &str, declaration: &Value) -> (String, String) {
    use native_ce::mcp::tools::alpha_tabs::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    };
    let declaration_digest =
        alpha_tab_declaration_digest(declaration).expect("fixture declaration is well-formed");
    let digest = alpha_tab_digest(
        &alpha_tab_bundle_digest(body),
        &declaration_digest,
        "native.html.v1",
    );
    (digest, declaration_digest)
}

fn verified_caller(account: &str, args: &Value, mode: &str) -> Caller {
    use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
    let field = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
    let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
    let authority = alpha_tab_preview_authority_for(
        account,
        field("package"),
        field("version"),
        field("digest"),
        field("artifact_id"),
        field("source_revision"),
        &declaration,
    )
    .expect("fixture declaration is well-formed");
    if mode == "adopt" {
        Caller::authenticated(account).with_verified_alpha_tab_adopt(authority)
    } else {
        Caller::authenticated(account).with_verified_alpha_tab_preview(authority)
    }
}

async fn source_revision(db: &Db) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn verified_install(
    db: &Db,
    registry: &ToolRegistry,
    account: &str,
    body: &str,
    declaration: Value,
) -> (String, String, String, String) {
    let source_revision = source_revision(db).await;
    let (digest, declaration_digest) = alpha_guard_pin_for(body, &declaration);
    let install_args = json!({
        "action": "install", "package": PACKAGE, "version": "0.1.0",
        "digest": digest, "artifact_id": ARTIFACT,
        "source_revision": source_revision, "declaration": declaration,
        "reason": "Install the reactions tab.",
    });
    let installed = call(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        install_args,
    )
    .await;
    assert_eq!(installed["changed"], true, "{installed:#}");
    let install_event = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let preview_args = json!({
        "action": "preview", "package": PACKAGE, "version": "0.1.0",
        "digest": digest, "artifact_id": ARTIFACT,
        "source_revision": source_revision, "declaration": declaration,
        "reason": "Preview the reactions tab.",
    });
    let preview = call(
        registry,
        db,
        verified_caller(account, &preview_args, "preview"),
        "manage_alpha_tabs",
        preview_args,
    )
    .await;
    let adopt_args = json!({
        "action": "adopt", "package": PACKAGE, "version": "0.1.0",
        "digest": digest, "artifact_id": ARTIFACT,
        "source_revision": source_revision, "declaration": declaration,
        "receipt_id": preview["receipt"]["receipt_id"],
        "nonce": preview["receipt"]["nonce"],
        "preview_session": preview["receipt"]["preview_session"],
        "expected_install_event_id": install_event,
        "reason": "Adopt the reactions tab.",
    });
    let adopted = call(
        registry,
        db,
        verified_caller(account, &adopt_args, "adopt"),
        "manage_alpha_tabs",
        adopt_args,
    )
    .await;
    assert_eq!(
        adopted["install"]["adoption"], "shell_adopt.v1",
        "{adopted:#}"
    );
    let verified_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
    (verified_event, source_revision, digest, declaration_digest)
}

fn guard_json(
    event_id: &str,
    source_revision: &str,
    digest: &str,
    declaration_digest: &str,
) -> Value {
    json!({
        "package": PACKAGE, "expected_install_event_id": event_id,
        "artifact_id": ARTIFACT, "source_revision": source_revision,
        "version": "0.1.0", "digest": digest,
        "declaration_digest": declaration_digest,
    })
}

async fn grant_chan_input_read(registry: &ToolRegistry, db: &Db) {
    let subjects = call(
        registry,
        db,
        Caller::local(),
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    let subject = subjects["subjects"]
        .as_array()
        .and_then(|subjects| subjects.first().cloned())
        .expect("the artifact source requests input.read");
    let granted = call(
        registry,
        db,
        Caller::local(),
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"],
            "capability": "input.read", "scope": { "artifact_port": "chan" }
        }),
    )
    .await;
    assert_eq!(granted["status"], "granted", "{granted:#}");
}

struct ReactSetup {
    db: Db,
    registry: ToolRegistry,
    body_digest: String,
    message_id: String,
    guard: Value,
    _lock: tokio::sync::OwnedMutexGuard<()>,
}

async fn react_setup() -> ReactSetup {
    let lock = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    install_persons(&db).await;
    let html = html_interaction_source(&react_mdx_source());
    let created = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Reactions tab",
                "body": html, "facets": { "runtime": "native.html.v1" },
                "reason": "Declare a message.react entry against a bound channel."
            }),
        )
        .await
        .unwrap();
    assert!(created.get("error").is_none(), "{created:#}");
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({ "id": CHAN, "type": "Collection", "kind": "selection", "name": "Channel",
                    "reason": "Bind one deterministic artifact input." }),
        )
        .await
        .unwrap();
    let message_id = create_message(&registry, &db).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": message_id, "target_id": CHAN,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_inputs",
            json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "chan",
                    "collection_id": CHAN }),
        )
        .await
        .unwrap();
    grant_chan_input_read(&registry, &db).await;
    for id in [ARTIFACT, CHAN] {
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account(ALICE, Capability::View)],
        )
        .await
        .unwrap();
    }
    let declaration = react_declaration();
    let (verified, source_revision, digest, declaration_digest) =
        verified_install(&db, &registry, ALICE, &html, declaration).await;
    ReactSetup {
        db,
        registry,
        body_digest: digest_of(&html),
        message_id,
        guard: guard_json(&verified, &source_revision, &digest, &declaration_digest),
        _lock: lock,
    }
}

async fn reaction_events(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type LIKE 'message.reaction.%'")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn invoke_args(setup: &ReactSetup, values: Value, key: &str) -> Value {
    json!({
        "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
        "source_digest": setup.body_digest,
        "slots": { "message": setup.message_id },
        "values": values,
        "idempotency_key": key, "gesture": "click",
        "alpha_install_guard": setup.guard,
    })
}

fn assert_minimal_react_receipt(result: &Value) {
    assert!(result.get("action_attestation_ids").is_none(), "{result:#}");
    assert!(result.get("act").is_none(), "{result:#}");
    assert!(result.get("refresh").is_none(), "{result:#}");
    assert!(result.get("account").is_none(), "{result:#}");
    let text = result.to_string();
    assert!(!text.contains("\"seq\""), "{result:#}");
    assert!(!text.contains("reactions"), "{result:#}");
}

async fn invoke(setup: &ReactSetup, caller: Caller, values: Value, key: &str) -> Value {
    setup
        .registry
        .call(
            setup.db.clone(),
            caller,
            "invoke_artifact_interaction",
            invoke_args(setup, values, key),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn admitted_add_commits_the_minimal_receipt() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    let alice = Caller::authenticated(ALICE);
    let added = invoke(
        &setup,
        alice,
        json!({"emoji": "👍", "reacted": true}),
        "react:add:one",
    )
    .await;
    assert_eq!(added["status"], "committed", "{added:#}");
    assert_eq!(added["changes"][0]["key"], "reaction", "{added:#}");
    assert_eq!(
        added["changes"][0]["record_id"], setup.message_id,
        "{added:#}"
    );
    let after = &added["changes"][0]["after"];
    assert_eq!(after["message_id"], setup.message_id, "{added:#}");
    assert_eq!(after["emoji"], "👍", "{added:#}");
    assert_eq!(after["reacted"], true, "{added:#}");
    assert_eq!(after["changed"], true, "{added:#}");
    assert_minimal_react_receipt(&added);
    assert_eq!(reaction_events(&setup.db).await, 1);
}

#[tokio::test]
async fn admitted_remove_clears_a_present_reaction() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    let alice = Caller::authenticated(ALICE);
    invoke(
        &setup,
        alice.clone(),
        json!({"emoji": "❤️", "reacted": true}),
        "react:add:heart",
    )
    .await;
    assert_eq!(reaction_events(&setup.db).await, 1);
    let removed = invoke(
        &setup,
        alice,
        json!({"emoji": "❤️", "reacted": false}),
        "react:remove:heart",
    )
    .await;
    assert_eq!(removed["status"], "committed", "{removed:#}");
    let after = &removed["changes"][0]["after"];
    assert_eq!(after["emoji"], "❤️", "{removed:#}");
    assert_eq!(after["reacted"], false, "{removed:#}");
    assert_eq!(after["changed"], true, "{removed:#}");
    assert_eq!(reaction_events(&setup.db).await, 2);
}

#[tokio::test]
async fn already_matching_state_settles_changed_false_without_append() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    let alice = Caller::authenticated(ALICE);
    invoke(
        &setup,
        alice.clone(),
        json!({"emoji": "👍", "reacted": true}),
        "react:add:once",
    )
    .await;
    // Removing what was never added: desired state already holds.
    let noop = invoke(
        &setup,
        alice,
        json!({"emoji": "❤️", "reacted": false}),
        "react:noop:heart",
    )
    .await;
    assert_eq!(noop["status"], "committed", "{noop:#}");
    assert_eq!(noop["changes"][0]["after"]["changed"], false, "{noop:#}");
    assert_eq!(noop["changes"][0]["after"]["reacted"], false, "{noop:#}");
    assert_eq!(
        reaction_events(&setup.db).await,
        1,
        "the no-op appends nothing"
    );
}

#[tokio::test]
async fn same_key_same_command_replays_and_changed_key_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    let alice = Caller::authenticated(ALICE);
    let first = invoke(
        &setup,
        alice.clone(),
        json!({"emoji": "👍", "reacted": true}),
        "react:key:one",
    )
    .await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let replay = invoke(
        &setup,
        alice.clone(),
        json!({"emoji": "👍", "reacted": true}),
        "react:key:one",
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        replay["changes"][0]["after"]["idempotent_retry"], true,
        "{replay:#}"
    );
    assert_eq!(
        reaction_events(&setup.db).await,
        1,
        "replay appends nothing"
    );
    let conflict = invoke(
        &setup,
        alice,
        json!({"emoji": "❤️", "reacted": true}),
        "react:key:one",
    )
    .await;
    assert_eq!(conflict["status"], "rejected", "{conflict:#}");
    assert_eq!(
        conflict["error"]["code"], "idempotency_conflict",
        "{conflict:#}"
    );
    assert_eq!(
        reaction_events(&setup.db).await,
        1,
        "conflict writes nothing"
    );
}

async fn mark_federated(db: &Db, message_id: &str) {
    let source: (String, i64, String) = sqlx::query_as(
        "SELECT id,seq,created_at FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(message_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query(
        "INSERT INTO content_event_sources(event_id,origin_database_id,source_seq,source_record_id,source_principal,source_fingerprint) VALUES (?,'remote-db',?,?,'remote/person',?)",
    )
    .bind(&source.0)
    .bind(source.1)
    .bind(message_id)
    .bind("0".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO replicated_message_provenance(source_event_id,content_version,operation,source_account_token,source_created_at,canonical_payload,payload_digest) VALUES (?,'native.message.v1','message.created','remote-account',?,'{}',?)",
    )
    .bind(&source.0)
    .bind(&source.2)
    .bind("1".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO destination_message_ingest(message_id,source_event_id,relay_state,ingest_state,received_at,sender_state) VALUES (?,?,'queued','applied',?,'principal_only')",
    )
    .bind(message_id)
    .bind(&source.0)
    .bind(&source.2)
    .execute(&pool)
    .await
    .unwrap();
}

async fn assert_zero_events_and_rejected(result: &Value, db: &Db, code: &str) {
    assert_eq!(result["status"], "rejected", "{result:#}");
    assert_eq!(result["error"]["code"], code, "{result:#}");
    assert_eq!(
        reaction_events(db).await,
        0,
        "a refusal writes nothing: {result:#}"
    );
}

#[tokio::test]
async fn federated_messages_refuse() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    mark_federated(&setup.db, &setup.message_id).await;
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        json!({"emoji": "👍", "reacted": true}),
        "react:federated:one",
    )
    .await;
    assert_zero_events_and_rejected(&refused, &setup.db, "message_federated").await;
}

#[tokio::test]
async fn emoji_outside_the_consented_subset_refuses() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // 🎉 is canonical but neither the manifest nor the consent admits it.
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        json!({"emoji": "🎉", "reacted": true}),
        "react:subset:one",
    )
    .await;
    assert_zero_events_and_rejected(&refused, &setup.db, "invalid_declaration").await;
}

#[tokio::test]
async fn message_outside_the_need_or_binding_refuses() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // A non-message inside the binding: passes the binding gate, fails
    // the need gate, and writes nothing.
    let note = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "create_record",
            json!({ "type": "Document", "kind": "note", "name": "Not a message",
                    "reason": "Need-gate fixture." }),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        &note,
        vec![AllowEntry::account(ALICE, Capability::View)],
    )
    .await
    .unwrap();
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": note, "target_id": CHAN,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    let refused = invoke_args_replacement(&setup, &note, "react:need:one").await;
    assert_zero_events_and_rejected(&refused, &setup.db, "record_outside_need").await;
    // A message with no channel membership fails the earlier binding gate.
    let other = create_message(&setup.registry, &setup.db).await;
    let refused = invoke_args_replacement(&setup, &other, "react:binding:one").await;
    assert_zero_events_and_rejected(&refused, &setup.db, "record_outside_binding").await;
}

async fn invoke_args_replacement(setup: &ReactSetup, message_id: &str, key: &str) -> Value {
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "invoke_artifact_interaction",
            json!({
                "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
                "source_digest": setup.body_digest,
                "slots": { "message": message_id },
                "values": {"emoji": "👍", "reacted": true},
                "idempotency_key": key, "gesture": "click",
                "alpha_install_guard": setup.guard,
            }),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn stale_pin_refuses() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    let mut stale_guard = setup.guard.clone();
    stale_guard["expected_install_event_id"] = json!("stale-event");
    let refused = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "invoke_artifact_interaction",
            json!({
                "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
                "source_digest": setup.body_digest,
                "slots": { "message": setup.message_id },
                "values": {"emoji": "👍", "reacted": true},
                "idempotency_key": "react:stale:one", "gesture": "click",
                "alpha_install_guard": stale_guard,
            }),
        )
        .await
        .unwrap();
    assert_zero_events_and_rejected(&refused, &setup.db, "alpha_guard_cas_mismatch").await;
}

#[tokio::test]
async fn channel_view_revoked_refuses_unbound() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // Explicit policy cannot revoke origin-derived message visibility, so
    // this test revokes View on the bound channel instead: port resolution
    // stops the write before the transaction, and nothing is appended.
    replace_explicit_policy(&setup.db, "test:policy", CHAN, vec![])
        .await
        .unwrap();
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        json!({"emoji": "👍", "reacted": true}),
        "react:revoked:one",
    )
    .await;
    assert_zero_events_and_rejected(&refused, &setup.db, "named_input_unbound").await;
}

#[tokio::test]
async fn replay_after_view_loss_is_refused_not_replayed() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // Carol is a non-owner, non-participant viewer: an explicit grant lets
    // her commit, and revoking it afterwards pins the kernel's message-View
    // gate. (The owner floor is why this needs a non-owner: Alice, as
    // sender, keeps View through any explicit-policy change.)
    for id in [ARTIFACT, CHAN, setup.message_id.as_str()] {
        replace_explicit_policy(
            &setup.db,
            "test:policy",
            id,
            vec![AllowEntry::account(CAROL, Capability::View)],
        )
        .await
        .unwrap();
    }
    let declaration = react_declaration();
    let html = html_interaction_source(&react_mdx_source());
    let (verified, source_revision, digest, declaration_digest) =
        verified_install(&setup.db, &setup.registry, CAROL, &html, declaration).await;
    let guard = guard_json(&verified, &source_revision, &digest, &declaration_digest);
    let body_digest = digest_of(&html);
    let carol_args = |key: &str| {
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
            "source_digest": body_digest,
            "slots": { "message": setup.message_id },
            "values": {"emoji": "👍", "reacted": true},
            "idempotency_key": key, "gesture": "click",
            "alpha_install_guard": guard,
        })
    };
    let first = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(CAROL),
            "invoke_artifact_interaction",
            carol_args("react:carol:one"),
        )
        .await
        .unwrap();
    assert_eq!(first["status"], "committed", "{first:#}");
    assert_eq!(reaction_events(&setup.db).await, 1);
    // Lose View after the commit; the identical retry must be refused —
    // not settled with the replayed receipt — and write nothing.
    replace_explicit_policy(&setup.db, "test:policy", &setup.message_id, vec![])
        .await
        .unwrap();
    let retry = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(CAROL),
            "invoke_artifact_interaction",
            carol_args("react:carol:one"),
        )
        .await
        .unwrap();
    assert_eq!(retry["status"], "rejected", "{retry:#}");
    assert_eq!(retry["error"]["code"], "permission_denied", "{retry:#}");
    assert_eq!(
        reaction_events(&setup.db).await,
        1,
        "a refused replay writes nothing"
    );
}

#[tokio::test]
async fn malformed_invocations_refuse() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    let alice = Caller::authenticated(ALICE);
    // Missing reacted value.
    let missing = invoke(
        &setup,
        alice.clone(),
        json!({"emoji": "👍"}),
        "react:bad:one",
    )
    .await;
    assert_zero_events_and_rejected(&missing, &setup.db, "slot_unfilled").await;
    // Unknown extra value key.
    let extra = invoke(
        &setup,
        alice.clone(),
        json!({"emoji": "👍", "reacted": true, "other": 1}),
        "react:bad:two",
    )
    .await;
    assert_zero_events_and_rejected(&extra, &setup.db, "unknown_slot").await;
    // Blank message slot.
    let blank = setup
        .registry
        .call(
            setup.db.clone(),
            alice,
            "invoke_artifact_interaction",
            json!({
                "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
                "source_digest": setup.body_digest,
                "slots": { "message": "  " },
                "values": {"emoji": "👍", "reacted": true},
                "idempotency_key": "react:bad:three", "gesture": "click",
                "alpha_install_guard": setup.guard,
            }),
        )
        .await
        .unwrap();
    assert_zero_events_and_rejected(&blank, &setup.db, "slot_unfilled").await;
}

#[tokio::test]
async fn thumbs_up_never_satisfies_an_acknowledgement_expectation() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // An ack obligation addressed to alice, the tab caller.
    let message = create_message_from(
        &setup.registry,
        &setup.db,
        BOB,
        ALICE_PERSON,
        Some("ack"),
        vec![ALICE_PERSON, BOB_PERSON],
    )
    .await;
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": message, "target_id": CHAN,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    let added = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "invoke_artifact_interaction",
            json!({
                "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
                "source_digest": setup.body_digest,
                "slots": { "message": message },
                "values": {"emoji": "👍", "reacted": true},
                "idempotency_key": "react:ack:one", "gesture": "click",
                "alpha_install_guard": setup.guard,
            }),
        )
        .await
        .unwrap();
    assert_eq!(added["status"], "committed", "{added:#}");
    assert_eq!(
        native_ce::message_expectation::derive_message_expectation_state(
            &setup.db, &message, ALICE
        )
        .await
        .unwrap()
        .state,
        native_ce::message_expectation::MessageExpectationState::Open,
        "a tab 👍 add leaves the ack obligation open"
    );
}

#[tokio::test]
async fn viewer_without_view_on_the_message_is_refused() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // A message outside bob's visibility: direct between alice and carol.
    let private = create_message_from(
        &setup.registry,
        &setup.db,
        ALICE,
        CAROL_PERSON,
        None,
        vec![ALICE_PERSON, CAROL_PERSON],
    )
    .await;
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": private, "target_id": CHAN,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    // Bob installs the same tab so the guard is his; the message gates stop him.
    // Bob may view the artifact and the channel, but never the message.
    for id in [ARTIFACT, CHAN] {
        replace_explicit_policy(
            &setup.db,
            "test:policy",
            id,
            vec![AllowEntry::account(BOB, Capability::View)],
        )
        .await
        .unwrap();
    }
    let declaration = react_declaration();
    let html = html_interaction_source(&react_mdx_source());
    let (verified, source_revision, digest, declaration_digest) =
        verified_install(&setup.db, &setup.registry, BOB, &html, declaration).await;
    let refused = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(BOB),
            "invoke_artifact_interaction",
            json!({
                "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "react",
                "source_digest": digest_of(&html),
                "slots": { "message": private },
                "values": {"emoji": "👍", "reacted": true},
                "idempotency_key": "react:bob:one", "gesture": "click",
                "alpha_install_guard": guard_json(&verified, &source_revision, &digest, &declaration_digest),
            }),
        )
        .await
        .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    // Bob sees neither the need rows nor the record: whichever gate fires,
    // nothing is written and no acknowledgement state moves.
    assert!(
        [
            "record_outside_need",
            "record_outside_binding",
            "permission_denied"
        ]
        .contains(&refused["error"]["code"].as_str().unwrap_or("")),
        "{refused:#}"
    );
    let before = reaction_events(&setup.db).await;
    assert_eq!(before, 0, "B writes nothing: {refused:#}");
}

async fn last_reaction_payload(db: &Db) -> Value {
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type LIKE 'message.reaction.%' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[tokio::test]
async fn artifact_reaction_persists_origin() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    invoke(
        &setup,
        Caller::authenticated(ALICE),
        json!({"emoji": "👍", "reacted": true}),
        "react:origin:one",
    )
    .await;
    let payload = last_reaction_payload(&setup.db).await;
    let origin = payload
        .get("origin")
        .expect("artifact reaction carries origin");
    assert_eq!(origin["kind"], "artifact.interaction", "{origin:#}");
    assert_eq!(origin["effect"], "message.react", "{origin:#}");
    assert_eq!(origin["artifact_id"], ARTIFACT, "{origin:#}");
    assert_eq!(origin["entry_id"], "react", "{origin:#}");
    assert_eq!(origin["source_digest"], setup.body_digest, "{origin:#}");
    assert_eq!(origin["message_id"], setup.message_id, "{origin:#}");
    assert_eq!(origin["emoji"], "👍", "{origin:#}");
    assert_eq!(origin["reacted"], true, "{origin:#}");
    assert_eq!(origin["idempotency_key"], "react:origin:one", "{origin:#}");
    assert_eq!(origin["guard"]["package"], PACKAGE, "{origin:#}");
    assert_eq!(
        origin["guard"]["expected_install_event_id"], setup.guard["expected_install_event_id"],
        "{origin:#}"
    );
    assert!(origin["gesture"].is_string(), "{origin:#}");
}

#[tokio::test]
async fn replay_is_scoped_to_artifact_origin() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = react_setup().await;
    // An ordinary (non-artifact) reaction under the same key first: its
    // payload carries no origin.
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "manage_messages",
            crate::common::with_test_reason(
                "manage_messages",
                json!({"action": "add_reaction", "message_id": setup.message_id,
                       "emoji": "👍", "idempotency_key": "react:shared:key",
                       "reason": "Ordinary reaction sharing the tab key."}),
            ),
        )
        .await
        .unwrap();
    let plain = last_reaction_payload(&setup.db).await;
    assert!(
        plain.get("origin").is_none(),
        "ordinary reactions serialize without origin"
    );
    // The tab retry under the same key must conflict, not replay the
    // foreign row — and write nothing.
    let conflict = invoke(
        &setup,
        Caller::authenticated(ALICE),
        json!({"emoji": "👍", "reacted": true}),
        "react:shared:key",
    )
    .await;
    assert_eq!(conflict["status"], "rejected", "{conflict:#}");
    assert_eq!(
        conflict["error"]["code"], "idempotency_conflict",
        "{conflict:#}"
    );
    assert_eq!(
        reaction_events(&setup.db).await,
        1,
        "origin mismatch writes nothing"
    );
}
