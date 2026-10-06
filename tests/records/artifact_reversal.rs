//! Engine reversal core (D7 slice U2a): `revert_in` called directly, with no
//! public tool surface. Each test commits a forward tab write through
//! `invoke_artifact_interaction`, then reverses it and asserts the restored
//! state, the receipt, and the refusal or conflict legs.

use std::sync::{Arc, OnceLock};

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::tools::artifact_reversal::{revert_in, ReversalRequest};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::schema::{ROOT_RECORD_ID, UNFILED_RECORD_ID};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ARTIFACT: &str = "66666666-6666-4666-8666-666666666666";
const INSIDE: &str = "0a5e0000-0000-4000-8000-000000000002";
const OUTSIDE: &str = "0a5e0000-0000-4000-8000-000000000003";
const COLLECTION: &str = "0a5e0000-0000-4000-8000-000000000001";
const INVOCATION_VERSION: &str = "native.artifact-invocation.v1";
const BOB_PERSON: &str = "0a5e0000-0000-4000-8000-000000000021";

fn integration_guard() -> &'static Arc<tokio::sync::Mutex<()>> {
    static GUARD: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    GUARD.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
}

fn artifact_source(label: &str) -> String {
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "orders" }} }}],
  interactions: [
    {{ id: "mark_triaged", label: "Mark triaged", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input", port: "orders" }} }} }},
      facet: "triage", value: {{ from: "literal", value: "triaged" }} }},
    {{ id: "set_triage", label: "Set triage", effect: "facet.set",
      slots: {{
        record: {{ domain: {{ kind: "bound_input", port: "orders" }} }},
        choice: {{ domain: {{ kind: "values", values: ["triaged", "blocked"] }} }}
      }},
      facet: "triage", value: {{ from: "slot", slot: "choice" }} }},
    {{ id: "start_work", label: "Start work", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "lifecycle", value: {{ from: "literal", value: "in_progress" }} }},
    {{ id: "complete_work", label: "Complete work", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "lifecycle", value: {{ from: "literal", value: "completed" }} }},
    {{ id: "note_effort", label: "Note effort", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "effort", value: {{ from: "literal", value: "large" }} }}
  ]
}}

<Metric label={label:?} value={{1}} />
"#
    )
}

fn digest_of(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

/// Canonical digest of the empty value-domain fillings, which a reversal
/// always carries (its `values` map is empty).
fn empty_values_digest() -> String {
    hex::encode(Sha256::digest(serde_jcs::to_vec(&json!({})).unwrap()))
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, arguments)
        .await
        .unwrap()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), caller, tool, arguments).await
}

async fn fixture() -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let source = artifact_source("Orders");
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Triage board",
            "body": source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Declare interaction entries against a bound Collection."
        }),
    )
    .await;
    assert!(
        created.get("diagnostic").is_none() && created.get("error").is_none(),
        "{created:#}"
    );
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": COLLECTION, "type": "Collection", "kind": "selection", "name": "Orders",
                "reason": "Bind one deterministic artifact input." }),
    )
    .await;
    for id in [INSIDE, OUTSIDE] {
        call(
            &registry,
            &db,
            "create_record",
            json!({ "id": id, "type": "WorkItem", "kind": "task", "name": id,
                    "reason": "Populate the reversal fixture." }),
        )
        .await;
    }
    call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": INSIDE, "target_id": COLLECTION,
                "relationship": "member_of" }),
    )
    .await;
    let bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "orders",
                "collection_id": COLLECTION }),
    )
    .await;
    assert_eq!(bound["status"], "bound", "{bound:#}");
    grant_input_read(&registry, &db).await;
    (db, registry, digest_of(&source), guard)
}

async fn grant_input_read(registry: &ToolRegistry, db: &Db) {
    let subjects = call(
        registry,
        db,
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
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"],
            "capability": "input.read", "scope": { "artifact_port": "orders" }
        }),
    )
    .await;
    assert_eq!(granted["status"], "granted", "{granted:#}");
}

fn envelope(entry_id: &str, digest: &str, idempotency_key: &str) -> Value {
    json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": entry_id,
        "source_digest": digest,
        "idempotency_key": idempotency_key,
        "gesture": "click",
    })
}

async fn observed(registry: &ToolRegistry, db: &Db, record: &str, facet: &str) -> Value {
    let token = match facet_of(registry, db, record, facet).await {
        Some(value) => value["version"]
            .as_str()
            .expect("get_record issues a facet version")
            .to_owned(),
        None => "obs:0".into(),
    };
    json!({ record: { facet: token } })
}

async fn observed_spine(registry: &ToolRegistry, db: &Db, record: &str, facet: &str) -> Value {
    json!({ record: { facet: record_version(registry, db, record).await } })
}

/// The open-facet precondition including unset state: an unset facet still
/// holds its observation row, so `obs:0` would be stale after an undo.
async fn observed_including_unset(db: &Db, record: &str, facet: &str) -> Value {
    let seq: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM facet_observations WHERE record_id=? AND key=?",
    )
    .bind(record)
    .bind(facet)
    .fetch_one(db.pool())
    .await
    .unwrap();
    json!({ record: { facet: format!("obs:{}", seq.unwrap_or(0)) } })
}

async fn facet_of(registry: &ToolRegistry, db: &Db, id: &str, key: &str) -> Option<Value> {
    let record = call(registry, db, "get_record", json!({ "ids": [id] })).await;
    record["records"][0]["facets"]
        .as_array()
        .expect("get_record returns a facet array")
        .iter()
        .find(|facet| facet["key"] == key)
        .cloned()
}

async fn record_version(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["version"]
        .as_str()
        .expect("get_record exposes the record-wide CAS token")
        .to_owned()
}

async fn revert(
    db: &Db,
    caller: Caller,
    record: &str,
    entry: &str,
    original_key: &str,
    key: &str,
) -> Value {
    let request = ReversalRequest {
        artifact_id: ARTIFACT.into(),
        record_id: record.into(),
        entry_id: entry.into(),
        original_key: original_key.into(),
        idempotency_key: key.into(),
    };
    let result = revert_in(db, &caller, request).await.unwrap();
    serde_json::to_value(&result).expect("a reversal result always serializes")
}

async fn event_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn undo_facet_set_restores_the_prior_value() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("set_triage", &digest, "u-restore:1");
    first["slots"] = json!({ "record": INSIDE });
    first["values"] = json!({ "choice": "triaged" });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let mut second = envelope("set_triage", &digest, "u-restore:2");
    second["slots"] = json!({ "record": INSIDE });
    second["values"] = json!({ "choice": "blocked" });
    second["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", second).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let before = event_count(&db).await;
    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "set_triage",
        "u-restore:2",
        "u-restore:undo",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(undone["idempotency_key"], "u-restore:undo");
    assert_eq!(undone["changes"][0]["record_id"], INSIDE);
    assert_eq!(undone["changes"][0]["key"], "triage");
    assert_eq!(undone["changes"][0]["before"], "blocked");
    assert_eq!(undone["changes"][0]["after"], "triaged");
    let version = undone["changes"][0]["version"]
        .as_str()
        .expect("a version token");
    assert!(version.starts_with("obs:"), "{version}");
    assert!(undone.get("seq").is_none(), "{undone:#}");

    let facet = facet_of(&registry, &db, INSIDE, "triage")
        .await
        .expect("the facet is still set");
    assert_eq!(facet["value"], "triaged");
    assert_eq!(
        event_count(&db).await,
        before + 1,
        "one undo appends one event"
    );
}

#[tokio::test]
async fn undo_facet_set_with_no_prior_value_unsets_it() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("note_effort", &digest, "u-unset:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "effort").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "note_effort",
        "u-unset:1",
        "u-unset:undo",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(undone["changes"][0]["key"], "effort");
    assert_eq!(undone["changes"][0]["before"], "large");
    assert!(undone["changes"][0]["after"].is_null(), "{undone:#}");

    assert!(facet_of(&registry, &db, INSIDE, "effort").await.is_none());
    let unsets: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='facet.unset'
          AND json_extract(payload,'$.key')='effort'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(unsets, 1);
}

#[tokio::test]
async fn undo_start_moves_in_progress_back_to_open() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("start_work", &digest, "u-start:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["after"], "in_progress");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "start_work",
        "u-start:1",
        "u-start:undo",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(undone["changes"][0]["key"], "lifecycle");
    assert_eq!(undone["changes"][0]["before"], "in_progress");
    assert_eq!(undone["changes"][0]["after"], "open");
    let version = undone["changes"][0]["version"]
        .as_str()
        .expect("a version token");
    assert!(version.starts_with("rec:"), "{version}");

    let record = call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await;
    assert_eq!(
        record["records"][0]["lifecycle_interpretation"]["value"]["canonical"], "open",
        "{record:#}"
    );
    let updates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.updated'
          AND json_extract(payload,'$.origin.entry_id')='start_work'
          AND json_extract(payload,'$.origin.reverses') IS NOT NULL",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(updates, 1, "the undo lands as one record.updated");
}

#[tokio::test]
async fn undo_after_a_competing_change_conflicts_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-conflict:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let mut competing = envelope("set_triage", &digest, "u-conflict:2");
    competing["slots"] = json!({ "record": INSIDE });
    competing["values"] = json!({ "choice": "blocked" });
    competing["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", competing).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let before = event_count(&db).await;
    let conflict = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-conflict:1",
        "u-conflict:undo",
    )
    .await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict", "{conflict:#}");
    assert_eq!(event_count(&db).await, before, "a conflict appends nothing");
    // Disclosure permits the local caller to learn the competing actor.
    assert_eq!(conflict["competing_actor"]["id"], "local", "{conflict:#}");
    let facet = facet_of(&registry, &db, INSIDE, "triage")
        .await
        .expect("the competing value stands");
    assert_eq!(facet["value"], "blocked");
}

#[tokio::test]
async fn viewer_b_change_conflicts_with_disclosure_gating() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    grant_accounts(
        &db,
        &[
            ("acct:alice", true),
            ("acct:bob", true),
            ("acct:carol", true),
        ],
    )
    .await;
    let alice = Caller::authenticated("acct:alice");
    let bob = Caller::authenticated("acct:bob");
    let carol = Caller::authenticated("acct:carol");

    // Bob alone gets a bound identity alice may see; carol has none.
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence) \
         VALUES (?,'Entity','person','Bob',?,?,'enduring')",
    )
    .bind(BOB_PERSON)
    .bind(UNFILED_RECORD_ID)
    .bind(ROOT_RECORD_ID)
    .execute(&write_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
    )
    .bind(BOB_PERSON)
    .bind("acct:bob")
    .execute(&write_pool)
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:reversal-disclosure",
        BOB_PERSON,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();

    // A writes; B changes the item after A's write.
    let mut invocation = envelope("mark_triaged", &digest, "u-viewerb:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let competing = call_as(
        &registry,
        &db,
        bob,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "blocked" },
                "reason": "B moves the facet after A's write." }),
    )
    .await
    .unwrap();
    assert!(competing.get("error").is_none(), "{competing:#}");

    // A's undo conflicts with zero writes and names B: disclosure permits it.
    let before = event_count(&db).await;
    let conflict = revert(
        &db,
        alice.clone(),
        INSIDE,
        "mark_triaged",
        "u-viewerb:1",
        "u-viewerb:u1",
    )
    .await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict", "{conflict:#}");
    assert_eq!(event_count(&db).await, before, "a conflict appends nothing");
    assert_eq!(
        conflict["competing_actor"]["id"], "acct:bob",
        "{conflict:#}"
    );
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "blocked"
    );

    // Carol competes with no bound identity; A's undo still conflicts, but
    // the competing actor stays unnamed.
    let competing = call_as(
        &registry,
        &db,
        carol,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "triaged" },
                "reason": "Carol moves the facet with no bound identity." }),
    )
    .await
    .unwrap();
    assert!(competing.get("error").is_none(), "{competing:#}");
    let before = event_count(&db).await;
    let conflict = revert(
        &db,
        alice,
        INSIDE,
        "mark_triaged",
        "u-viewerb:1",
        "u-viewerb:u2",
    )
    .await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(event_count(&db).await, before, "a conflict appends nothing");
    assert!(
        conflict.get("competing_actor").is_none(),
        "an actor alice may not identify stays unnamed: {conflict:#}"
    );
}

async fn grant_account(db: &Db, account: &str, edit_inside: bool) {
    grant_accounts(db, &[(account, edit_inside)]).await;
}

async fn grant_accounts(db: &Db, accounts: &[(&str, bool)]) {
    let views = accounts
        .iter()
        .map(|(account, _)| AllowEntry::account(*account, Capability::View))
        .collect::<Vec<_>>();
    let mut edits = views.clone();
    for (account, want_edit) in accounts {
        if *want_edit {
            edits.push(AllowEntry::account(*account, Capability::Edit));
        }
    }
    for id in [ARTIFACT, COLLECTION] {
        replace_explicit_policy(db, "test:policy", id, views.clone())
            .await
            .unwrap();
    }
    replace_explicit_policy(db, "test:policy", INSIDE, edits)
        .await
        .unwrap();
}

#[tokio::test]
async fn undo_without_edit_is_refused() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    grant_account(&db, "acct:editor", true).await;
    let editor = Caller::authenticated("acct:editor");
    let mut invocation = envelope("mark_triaged", &digest, "u-perm:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        editor.clone(),
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    grant_account(&db, "acct:editor", false).await;
    let before = event_count(&db).await;
    let refused = revert(
        &db,
        editor,
        INSIDE,
        "mark_triaged",
        "u-perm:1",
        "u-perm:undo",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied", "{refused:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}

#[tokio::test]
async fn another_actors_key_returns_unknown_without_a_leak() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    grant_accounts(&db, &[("acct:alice", true), ("acct:bob", true)]).await;
    let alice = Caller::authenticated("acct:alice");
    let mut invocation = envelope("mark_triaged", &digest, "u-unknown:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let before = event_count(&db).await;
    let bob = Caller::authenticated("acct:bob");
    let unknown = revert(
        &db,
        bob,
        INSIDE,
        "mark_triaged",
        "u-unknown:1",
        "u-unknown:bob",
    )
    .await;
    assert_eq!(unknown["status"], "rejected", "{unknown:#}");
    assert_eq!(unknown["error"]["code"], "reversal_unknown", "{unknown:#}");
    let rendered = unknown.to_string();
    assert!(!rendered.contains(INSIDE), "{unknown:#}");
    assert!(!rendered.contains("triaged"), "{unknown:#}");
    assert!(!rendered.contains("acct:alice"), "{unknown:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}

fn create_artifact_source() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } }
  ],
  interactions: [
    { id: "create_task", label: "Create task", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "WorkItem" }, domain: { kind: "enum", values: ["WorkItem"] } },
        kind: { source: { from: "literal", value: "task" }, domain: { kind: "enum", values: ["task"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "title" }, domain: { kind: "string", min_length: 1, max_length: 80 } } },
        facets: {}
      } } }
  ]
}

<Metric label="Creation" value={1} />
"#
    .into()
}

async fn create_fixture() -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let source = create_artifact_source();
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Creation board",
            "body": source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Declare general record creation."
        }),
    )
    .await;
    assert!(created.get("error").is_none(), "{created:#}");
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": COLLECTION, "type": "Collection", "kind": "folder", "name": "Created here",
                "reason": "Bind one deterministic creation destination." }),
    )
    .await;
    let bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "orders",
                "collection_id": COLLECTION }),
    )
    .await;
    assert_eq!(bound["status"], "bound", "{bound:#}");
    grant_input_read(&registry, &db).await;
    (db, registry, digest_of(&source), guard)
}

#[tokio::test]
async fn created_records_are_not_reversible_in_this_slice() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = create_fixture().await;
    let invocation = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "create_task",
        "source_digest": digest,
        "values": { "title": "A created task" },
        "idempotency_key": "u-create:1",
        "gesture": "submit"
    });
    let first = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let created_id = first["refresh"]["record"]["id"]
        .as_str()
        .expect("created record identity")
        .to_string();

    let before = event_count(&db).await;
    // `comment.create` takes the same branch: any `record.created` original
    // is additive-or-withdrawable, never restorable here.
    let refused = revert(
        &db,
        Caller::local(),
        &created_id,
        "create_task",
        "u-create:1",
        "u-create:undo",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "not_reversible", "{refused:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}

#[tokio::test]
async fn the_same_undo_key_replays_without_appending() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("set_triage", &digest, "u-replay:1");
    first["slots"] = json!({ "record": INSIDE });
    first["values"] = json!({ "choice": "triaged" });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let mut second = envelope("set_triage", &digest, "u-replay:2");
    second["slots"] = json!({ "record": INSIDE });
    second["values"] = json!({ "choice": "blocked" });
    second["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", second).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "set_triage",
        "u-replay:2",
        "u-replay:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    let replayed = revert(
        &db,
        Caller::local(),
        INSIDE,
        "set_triage",
        "u-replay:2",
        "u-replay:u",
    )
    .await;
    assert_eq!(replayed["status"], "committed", "{replayed:#}");
    assert_eq!(replayed["changes"][0]["after"], "triaged");
    assert_eq!(replayed["changes"][0]["before"], "triaged");
    assert_eq!(
        replayed["changes"][0]["version"],
        undone["changes"][0]["version"]
    );
    let undos: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE json_extract(payload,'$.origin.idempotency_key')='u-replay:u'
            AND json_extract(payload,'$.origin.reverses') IS NOT NULL",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(undos, 1, "a replayed undo appends nothing");
}

#[tokio::test]
async fn a_different_key_for_a_reversed_original_is_refused() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-once:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-once:1",
        "u-once:u1",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    let before = event_count(&db).await;
    let refused = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-once:1",
        "u-once:u2",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "already_reversed", "{refused:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}

#[tokio::test]
async fn the_same_undo_key_against_a_different_original_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("mark_triaged", &digest, "u-xkey:1");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let mut second = envelope("set_triage", &digest, "u-xkey:2");
    second["slots"] = json!({ "record": INSIDE });
    second["values"] = json!({ "choice": "blocked" });
    second["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", second).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "set_triage",
        "u-xkey:2",
        "u-xkey:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(undone["changes"][0]["after"], "triaged");
    let before = event_count(&db).await;
    let refused = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-xkey:1",
        "u-xkey:u",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "idempotency_conflict",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}

#[tokio::test]
async fn a_forward_invocation_reusing_an_undo_key_does_not_replay_it() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-fwd:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-fwd:1",
        "u-fwd:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());

    // The forward replay predicate excludes reversal events, so the reused
    // key commits a fresh write instead of settling the undo's receipt.
    let mut reused = envelope("mark_triaged", &digest, "u-fwd:u");
    reused["slots"] = json!({ "record": INSIDE });
    reused["observed"] = observed_including_unset(&db, INSIDE, "triage").await;
    let fresh = call(&registry, &db, "invoke_artifact_interaction", reused).await;
    assert_eq!(fresh["status"], "committed", "{fresh:#}");
    assert_eq!(fresh["changes"][0]["after"], "triaged");
    let facet = facet_of(&registry, &db, INSIDE, "triage")
        .await
        .expect("the fresh write stands");
    assert_eq!(facet["value"], "triaged");
    let forwards: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE json_extract(payload,'$.origin.idempotency_key')='u-fwd:u'
            AND json_extract(payload,'$.origin.reverses') IS NULL",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(forwards, 1, "the reused key committed one forward event");
}

const GUARD_ACCOUNT: &str = "alice";
const GUARD_PACKAGE: &str = "agent.undo-probe";

fn guard_declaration() -> Value {
    json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]})
}

fn html_source(source: &str) -> String {
    let parsed = native_artifact_runtime::mdx_v2::parse_artifact(source).unwrap();
    let native_artifact_runtime::mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
        unreachable!()
    };
    let declaration = json!({
        "schema": "native.html.artifact.v2", "inputs": manifest.inputs,
        "capability_requests": manifest.capability_requests, "interactions": manifest.interactions,
    });
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Probe</title><script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script></head><body><main><h1>Probe</h1></main></body></html>")
}

async fn guard_source_revision(db: &Db, artifact_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(artifact_id)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

fn guard_pin_for(body: &str, declaration: &Value) -> (String, String) {
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

fn guard_preview_caller(account: &str, args: &Value) -> Caller {
    use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
    let field = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
    let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
    Caller::authenticated(account).with_verified_alpha_tab_preview(
        alpha_tab_preview_authority_for(
            account,
            field("package"),
            field("version"),
            field("digest"),
            field("artifact_id"),
            field("source_revision"),
            &declaration,
        )
        .expect("fixture declaration is well-formed"),
    )
}

fn guard_adopt_caller(account: &str, args: &Value) -> Caller {
    use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
    let field = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
    let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
    Caller::authenticated(account).with_verified_alpha_tab_adopt(
        alpha_tab_preview_authority_for(
            account,
            field("package"),
            field("version"),
            field("digest"),
            field("artifact_id"),
            field("source_revision"),
            &declaration,
        )
        .expect("fixture declaration is well-formed"),
    )
}

async fn guard_verified_install(
    db: &Db,
    registry: &ToolRegistry,
    account: &str,
    package: &str,
    body: &str,
    declaration: Value,
) -> (String, String, String, String) {
    let source_revision = guard_source_revision(db, ARTIFACT).await;
    let (digest, declaration_digest) = guard_pin_for(body, &declaration);
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_alpha_tabs",
            json!({
                "action": "install",
                "package": package,
                "version": "0.1.0",
                "digest": digest,
                "artifact_id": ARTIFACT,
                "source_revision": source_revision,
                "declaration": declaration,
                "reason": "Install the reversal probe tab.",
            }),
        )
        .await
        .unwrap();
    assert_eq!(installed["changed"], true, "{installed:#}");
    let install_event = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let preview_args = json!({
        "action": "preview",
        "package": package,
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": ARTIFACT,
        "source_revision": source_revision,
        "declaration": declaration,
        "reason": "Preview the reversal probe tab.",
    });
    let preview = registry
        .call(
            db.clone(),
            guard_preview_caller(account, &preview_args),
            "manage_alpha_tabs",
            preview_args,
        )
        .await
        .unwrap();
    let adopt_args = json!({
        "action": "adopt",
        "package": package,
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": ARTIFACT,
        "source_revision": source_revision,
        "declaration": declaration,
        "receipt_id": preview["receipt"]["receipt_id"],
        "nonce": preview["receipt"]["nonce"],
        "preview_session": preview["receipt"]["preview_session"],
        "expected_install_event_id": install_event,
        "reason": "Adopt the reversal probe tab.",
    });
    let adopted = registry
        .call(
            db.clone(),
            guard_adopt_caller(account, &adopt_args),
            "manage_alpha_tabs",
            adopt_args,
        )
        .await
        .unwrap();
    assert_eq!(
        adopted["install"]["adoption"], "shell_adopt.v1",
        "{adopted:#}"
    );
    let verified = adopted["install"]["event_id"].as_str().unwrap().to_string();
    (verified, source_revision, digest, declaration_digest)
}

fn guard_json(
    package: &str,
    event_id: &str,
    source_revision: &str,
    digest: &str,
    declaration_digest: &str,
) -> Value {
    json!({
        "package": package,
        "expected_install_event_id": event_id,
        "artifact_id": ARTIFACT,
        "source_revision": source_revision,
        "version": "0.1.0",
        "digest": digest,
        "declaration_digest": declaration_digest,
    })
}

async fn guarded_fixture() -> (
    Db,
    ToolRegistry,
    String,
    String,
    Value,
    Caller,
    tokio::sync::OwnedMutexGuard<()>,
) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let body = html_source(&artifact_source("Orders"));
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Probe board",
            "body": body, "facets": { "runtime": "native.html.v1" },
            "reason": "Declare guarded entries against a bound Collection."
        }),
    )
    .await;
    assert!(created.get("error").is_none(), "{created:#}");
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": COLLECTION, "type": "Collection", "kind": "selection", "name": "Orders",
                "reason": "Bind one deterministic artifact input." }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": INSIDE, "type": "WorkItem", "kind": "task", "name": INSIDE,
                "reason": "Populate the guarded reversal fixture." }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": INSIDE, "target_id": COLLECTION,
                "relationship": "member_of" }),
    )
    .await;
    let bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "orders",
                "collection_id": COLLECTION }),
    )
    .await;
    assert_eq!(bound["status"], "bound", "{bound:#}");
    grant_input_read(&registry, &db).await;
    grant_accounts(&db, &[(GUARD_ACCOUNT, true)]).await;
    let declaration = guard_declaration();
    let (verified, source_revision, digest, declaration_digest) = guard_verified_install(
        &db,
        &registry,
        GUARD_ACCOUNT,
        GUARD_PACKAGE,
        &body,
        declaration,
    )
    .await;
    let guard_value = guard_json(
        GUARD_PACKAGE,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let body_digest = digest_of(&body);
    let alice = Caller::authenticated(GUARD_ACCOUNT);
    (
        db,
        registry,
        body_digest,
        verified,
        guard_value,
        alice,
        guard,
    )
}

#[tokio::test]
async fn undo_survives_a_disabled_install() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, body_digest, verified, guard_value, alice, _guard) = guarded_fixture().await;
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "u-disabled:1",
            "alpha_install_guard": guard_value,
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable",
            "package": GUARD_PACKAGE,
            "expected_install_event_id": verified,
            "reason": "Pause the probe tab.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(disabled["install"]["status"], "disabled");

    let undone = revert(
        &db,
        alice,
        INSIDE,
        "mark_triaged",
        "u-disabled:1",
        "u-disabled:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn undo_survives_a_removed_install() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, body_digest, verified, guard_value, alice, _guard) = guarded_fixture().await;
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "u-removed:1",
            "alpha_install_guard": guard_value,
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let removed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "remove",
            "package": GUARD_PACKAGE,
            "expected_install_event_id": verified,
            "reason": "Remove the probe tab.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(removed["install"]["status"], "removed", "{removed:#}");

    let undone = revert(
        &db,
        alice,
        INSIDE,
        "mark_triaged",
        "u-removed:1",
        "u-removed:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn undo_is_refused_when_the_prior_value_left_the_vocabulary() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("start_work", &digest, "u-vocab:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": { "WorkItem:task": { "facets": {
            "lifecycle": { "required": true, "vocab": "lifecycle",
                           "axis": { "key": "work_status", "label": "Work status" },
                           "values": ["in_progress", "blocked"] }
        } } } } }),
    )
    .await;
    let before = event_count(&db).await;
    let refused = revert(
        &db,
        Caller::local(),
        INSIDE,
        "start_work",
        "u-vocab:1",
        "u-vocab:u",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "schema_violation", "{refused:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.keys().any(|candidate| candidate == key)
                || object.values().any(|child| contains_key(child, key))
        }
        Value::Array(items) => items.iter().any(|child| contains_key(child, key)),
        _ => false,
    }
}

#[tokio::test]
async fn undo_origin_names_its_key_and_the_original() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-origin:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-origin:1",
        "u-origin:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");

    let original_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.origin.idempotency_key')='u-origin:1'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let undo_payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=?
          AND json_extract(payload,'$.origin.idempotency_key')='u-origin:u'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let undo_payload: Value = serde_json::from_str(&undo_payload).unwrap();
    let origin = &undo_payload["origin"];
    assert_eq!(origin["idempotency_key"], "u-origin:u");
    assert_eq!(origin["entry_id"], "mark_triaged");
    assert_eq!(origin["artifact_id"], ARTIFACT);
    assert_eq!(origin["source_digest"], digest);
    assert_eq!(origin["gesture"], "submit");
    assert!(origin["alpha_install_guard"].is_null(), "{origin:#}");
    assert_eq!(origin["reverses"]["entry_id"], "mark_triaged");
    assert_eq!(origin["reverses"]["idempotency_key"], "u-origin:1");
    assert_eq!(origin["reverses"]["event_id"], original_id);
}

#[tokio::test]
async fn undo_receipt_carries_no_sequence_beyond_the_host_version() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-receipt:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-receipt:1",
        "u-receipt:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert!(!contains_key(&undone, "seq"), "{undone:#}");
    assert!(!contains_key(&undone, "event_seq"), "{undone:#}");
    let version = undone["changes"][0]["version"]
        .as_str()
        .expect("a version token");
    assert!(version.starts_with("obs:"), "{version}");
}

#[tokio::test]
async fn moving_to_completed_and_back_appends_exactly_two_events() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let before = event_count(&db).await;
    let mut invocation = envelope("complete_work", &digest, "u-completed:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["after"], "completed");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "complete_work",
        "u-completed:1",
        "u-completed:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(undone["changes"][0]["after"], "open");
    assert_eq!(
        event_count(&db).await,
        before + 2,
        "the pair appends no event other than the two lifecycle writes"
    );
}
#[tokio::test]
async fn unguarded_workbench_write_reverses_like_a_guarded_tab_write() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // No install guard anywhere: the plain mdx fixture never installs a tab
    // and the invocation carries no `alpha_install_guard`.
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-equiv:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    assert!(invocation.get("alpha_install_guard").is_none());
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let undone = revert(
        &db,
        Caller::local(),
        INSIDE,
        "mark_triaged",
        "u-equiv:1",
        "u-equiv:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");
    // Same receipt shape as the guarded legs: one change restoring the prior
    // value, with the host version and no sequence beyond it.
    assert_eq!(undone["changes"][0]["key"], "triage");
    assert_eq!(undone["changes"][0]["before"], "triaged");
    assert!(undone["changes"][0]["after"].is_null(), "{undone:#}");
    assert!(
        undone["changes"][0]["version"]
            .as_str()
            .is_some_and(|version| version.starts_with("obs:")),
        "{undone:#}"
    );
    assert!(!contains_key(&undone, "seq"), "{undone:#}");
    // Same origin shape: the undo's own key plus the original in `reverses`,
    // and a null install guard exactly as on the guarded path.
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=?
          AND json_extract(payload,'$.origin.idempotency_key')='u-equiv:u'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["origin"]["idempotency_key"], "u-equiv:u");
    assert_eq!(
        payload["origin"]["reverses"]["idempotency_key"],
        "u-equiv:1"
    );
    assert_eq!(payload["origin"]["reverses"]["entry_id"], "mark_triaged");
    assert!(
        payload["origin"]["alpha_install_guard"].is_null(),
        "{payload:#}"
    );
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}
const REFERENCE_COLLECTION: &str = "0a5e0000-0000-4000-8000-000000000010";
const COMMENT_PERSON: &str = "0a5e0000-0000-4000-8000-000000000011";

fn comment_mdx_source() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } }
  ],
  interactions: [
    { id: "post_root", label: "Post root", effect: "comment.create",
      slots: { bearer: { domain: { kind: "bound_input", port: "orders" } } },
      comment: { position: "root", body: { input: "text", max_bytes: 100 } } }
  ]
}

<Metric label="Total" value={1} />
"#
    .into()
}

fn comment_need_sql() -> String {
    "SELECT id FROM records WHERE deleted_at IS NULL AND ((type='Document' AND kind='note') OR (type='Annotation' AND kind='comment')) ORDER BY id ASC LIMIT 200".into()
}

fn comment_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread", "sql": comment_need_sql()}
        ],
        "effects": [{
            "effect": "comment.create.v1",
            "positions": ["root", "reply"],
            "max_body_bytes": 100,
            "target": {"need": "thread.items"}
        }]
    })
}

struct CommentFixture {
    db: Db,
    registry: ToolRegistry,
    body_digest: String,
    guard: Value,
    alice: Caller,
    token: String,
    _lock: tokio::sync::OwnedMutexGuard<()>,
}

async fn comment_fixture() -> CommentFixture {
    let lock = Arc::clone(integration_guard()).lock_owned().await;
    let html = html_source(&comment_mdx_source());
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Comment thread",
            "body": html, "facets": { "runtime": "native.html.v1" },
            "reason": "Declare a comment.create entry for the reversal probe."
        }),
    )
    .await;
    assert!(created.get("error").is_none(), "{created:#}");
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": COLLECTION, "type": "Collection", "kind": "folder", "name": "Threads",
                "persistence": "enduring", "reason": "Genuine folder filing home." }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": INSIDE, "type": "Document", "kind": "note", "name": "Thread root",
                "home_id": COLLECTION, "reason": "Note bearer inside the folder home." }),
    )
    .await;
    let thread_query = json!({
        "v": "0.2",
        "query": { "steps": [{
            "step": "filter",
            "kinds": ["note", "comment"],
            "home_id": COLLECTION,
        }]},
    })
    .to_string();
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": REFERENCE_COLLECTION, "type": "Collection", "kind": "query",
                "name": "Threads", "home_id": COLLECTION,
                "facets": { "query": thread_query },
                "reason": "Separate binding scope over the folder home." }),
    )
    .await;
    let bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "orders",
                "collection_id": REFERENCE_COLLECTION }),
    )
    .await;
    assert_eq!(bound["status"], "bound", "{bound:#}");
    grant_input_read(&registry, &db).await;
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence) \
         VALUES (?,'Entity','person','Comment viewer',?,?,'enduring')",
    )
    .bind(COMMENT_PERSON)
    .bind(UNFILED_RECORD_ID)
    .bind(ROOT_RECORD_ID)
    .execute(&write_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
    )
    .bind(COMMENT_PERSON)
    .bind(GUARD_ACCOUNT)
    .execute(&write_pool)
    .await
    .unwrap();
    for (id, edit) in [
        (ARTIFACT, false),
        (COLLECTION, true),
        (REFERENCE_COLLECTION, false),
        (INSIDE, true),
    ] {
        let mut allows = vec![AllowEntry::account(GUARD_ACCOUNT, Capability::View)];
        if edit {
            allows.push(AllowEntry::account(GUARD_ACCOUNT, Capability::Edit));
        }
        replace_explicit_policy(&db, "test:policy", id, allows)
            .await
            .unwrap();
    }
    let declaration = comment_declaration();
    let (verified, source_revision, digest, declaration_digest) = guard_verified_install(
        &db,
        &registry,
        GUARD_ACCOUNT,
        GUARD_PACKAGE,
        &html,
        declaration,
    )
    .await;
    let guard = guard_json(
        GUARD_PACKAGE,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let alice = Caller::authenticated(GUARD_ACCOUNT);
    let body_digest = digest_of(&html);
    let rendered = call_as(
        &registry,
        &db,
        alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let token = rendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .expect("real render mints a comment target token")
        .to_owned();
    CommentFixture {
        db,
        registry,
        body_digest,
        guard,
        alice,
        token,
        _lock: lock,
    }
}

#[tokio::test]
async fn comment_create_is_not_reversible() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = comment_fixture().await;
    let posted = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "post_root",
            "source_digest": setup.body_digest,
            "slots": { "bearer": INSIDE },
            "values": { "text": "A real comment" },
            "observed": { INSIDE: { "comment_target": setup.token } },
            "idempotency_key": "u-comment:1",
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(posted["status"], "committed", "{posted:#}");
    let created_id = posted["changes"][0]["record_id"]
        .as_str()
        .expect("created comment identity")
        .to_owned();

    let before = event_count(&setup.db).await;
    let refused = revert(
        &setup.db,
        setup.alice,
        &created_id,
        "post_root",
        "u-comment:1",
        "u-comment:u",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "not_reversible", "{refused:#}");
    assert_eq!(
        event_count(&setup.db).await,
        before,
        "a refusal appends nothing"
    );
}
#[tokio::test]
async fn same_undo_key_on_a_different_record_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    grant_accounts(&db, &[("acct:alice", true)]).await;
    let alice = Caller::authenticated("acct:alice");
    // Second writable record inside the bound input.
    call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": OUTSIDE, "target_id": COLLECTION,
                "relationship": "member_of" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:reversal-second-record",
        OUTSIDE,
        vec![
            AllowEntry::account("acct:alice", Capability::View),
            AllowEntry::account("acct:alice", Capability::Edit),
        ],
    )
    .await
    .unwrap();

    for (record, key) in [(INSIDE, "u-xrecord:1"), (OUTSIDE, "u-xrecord:2")] {
        let mut invocation = envelope("mark_triaged", &digest, key);
        invocation["slots"] = json!({ "record": record });
        invocation["observed"] = observed(&registry, &db, record, "triage").await;
        let committed = call_as(
            &registry,
            &db,
            alice.clone(),
            "invoke_artifact_interaction",
            invocation,
        )
        .await
        .unwrap();
        assert_eq!(committed["status"], "committed", "{committed:#}");
    }
    let undone = revert(
        &db,
        alice.clone(),
        INSIDE,
        "mark_triaged",
        "u-xrecord:1",
        "u-xrecord:u",
    )
    .await;
    assert_eq!(undone["status"], "committed", "{undone:#}");

    // §2.3a case 2: the same undo key against a different record conflicts
    // with zero writes — it never replays the other record's receipt and
    // never reverses a fresh original there.
    let before = event_count(&db).await;
    let refused = revert(
        &db,
        alice,
        OUTSIDE,
        "mark_triaged",
        "u-xrecord:2",
        "u-xrecord:u",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "idempotency_conflict",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
    assert_eq!(
        facet_of(&registry, &db, OUTSIDE, "triage").await.unwrap()["value"],
        "triaged"
    );
}

// NOTE (review 03fa0b5 finding 4, second half): the same forward key reused
// under a different entry cannot reach the reversal core — the dispatch layer
// reserves one provenance attestation per (principal, operation,
// digest(idempotency_key)), so the second invocation dies with a transport
// error before entry-scoped replay runs (UNIQUE
// idx_provenance_local_authority_command; command_identity_digest in
// src/provenance.rs). The `reverses.entry_id` predicate on the
// `already_reversed` probe therefore matches forward replay's entry-scoped
// identity without changing behaviour on any tool-reachable state.
fn reversal_envelope(digest: &str, entry: &str, original_key: &str, key: &str) -> Value {
    json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": entry,
        "source_digest": digest,
        "idempotency_key": key,
        "gesture": "submit",
        "reverses": { "entry_id": entry, "idempotency_key": original_key },
    })
}

#[tokio::test]
async fn reversal_through_the_public_tool_commits() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    grant_accounts(&db, &[("acct:alice", true)]).await;
    let alice = Caller::authenticated("acct:alice");
    let mut invocation = envelope("mark_triaged", &digest, "u-tool:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    // An Edit holder reverses through the public tool with no slots, values
    // or observed versions — the receipt is the ordinary committed shape.
    let undone = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        reversal_envelope(&digest, "mark_triaged", "u-tool:1", "u-tool:u"),
    )
    .await
    .unwrap();
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(undone["idempotency_key"], "u-tool:u");
    assert_eq!(undone["changes"][0]["key"], "triage");
    assert_eq!(undone["changes"][0]["before"], "triaged");
    assert!(undone["changes"][0]["after"].is_null(), "{undone:#}");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn reversal_with_a_valid_effect_gesture_token_records_evidence() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-gesture:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let ids = native_ce::awareness::effect_gesture_binding_ids(
        "local",
        ARTIFACT,
        None,
        None,
        "mark_triaged",
        &[INSIDE.to_string()],
        "u-gesture:u",
        &empty_values_digest(),
        native_ce::awareness::EffectGestureKind::Click,
    );
    let token = issuer
        .issue(
            "local",
            native_ce::awareness::EFFECT_GESTURE_REVERSAL_ACTION,
            &ids,
            30,
        )
        .unwrap();
    let caller = Caller::local().with_effect_gesture_token(
        &issuer,
        token,
        native_ce::awareness::EffectGestureKind::Click,
    );
    let undone = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        reversal_envelope(&digest, "mark_triaged", "u-gesture:1", "u-gesture:u"),
    )
    .await
    .unwrap();
    assert_eq!(undone["status"], "committed", "{undone:#}");
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=?
          AND json_extract(payload,'$.origin.idempotency_key')='u-gesture:u'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let event: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        event["origin"]["gesture_evidence"]["kind"], "click",
        "{event:#}"
    );
    assert_eq!(
        event["origin"]["gesture_evidence"]["verifier"], "effect_gesture.v1",
        "{event:#}"
    );
}

#[tokio::test]
async fn reversal_effect_gesture_mismatch_refuses_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-gesture-bad:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let click = native_ce::awareness::EffectGestureKind::Click;
    // A reversal is action-scoped and target-scoped: a forward-action token,
    // or one bound to a different record, is invalid.
    let cases = [
        (
            "action",
            native_ce::awareness::EFFECT_GESTURE_ACTION,
            INSIDE,
        ),
        (
            "target",
            native_ce::awareness::EFFECT_GESTURE_REVERSAL_ACTION,
            OUTSIDE,
        ),
    ];
    for (name, action, record) in cases {
        let ids = native_ce::awareness::effect_gesture_binding_ids(
            "local",
            ARTIFACT,
            None,
            None,
            "mark_triaged",
            &[record.to_string()],
            "u-gesture-bad:u",
            &empty_values_digest(),
            click,
        );
        let token = issuer.issue("local", action, &ids, 30).unwrap();
        let caller = Caller::local().with_effect_gesture_token(&issuer, token, click);
        let before = event_count(&db).await;
        let refused = call_as(
            &registry,
            &db,
            caller,
            "invoke_artifact_interaction",
            reversal_envelope(
                &digest,
                "mark_triaged",
                "u-gesture-bad:1",
                "u-gesture-bad:u",
            ),
        )
        .await
        .unwrap();
        assert_eq!(refused["status"], "rejected", "{name}: {refused:#}");
        assert_eq!(
            refused["error"]["code"], "gesture_attestation_invalid",
            "{name}: {refused:#}"
        );
        assert_eq!(event_count(&db).await, before, "{name} wrote");
    }
}

#[tokio::test]
async fn reversal_by_a_caller_below_edit_is_refused_without_writing() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    grant_accounts(&db, &[("acct:alice", true)]).await;
    let alice = Caller::authenticated("acct:alice");
    let mut invocation = envelope("mark_triaged", &digest, "u-tooldeny:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    grant_accounts(&db, &[("acct:alice", false)]).await;
    let before = event_count(&db).await;
    let refused = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        reversal_envelope(&digest, "mark_triaged", "u-tooldeny:1", "u-tooldeny:u"),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied", "{refused:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "triaged"
    );
}

#[tokio::test]
async fn reversal_shape_refusals_answer_invalid_invocation() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-toolshape:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let base = reversal_envelope(&digest, "mark_triaged", "u-toolshape:1", "u-toolshape:u");
    let mut cases = vec![
        ("slots", {
            let mut invalid = base.clone();
            invalid["slots"] = json!({ "record": INSIDE });
            invalid
        }),
        ("values", {
            let mut invalid = base.clone();
            invalid["values"] = json!({ "choice": "blocked" });
            invalid
        }),
        ("observed", {
            let mut invalid = base.clone();
            invalid["observed"] = json!({ INSIDE: { "triage": "obs:1" } });
            invalid
        }),
        ("entry_mismatch", {
            let mut invalid = base.clone();
            invalid["entry_id"] = json!("set_triage");
            invalid
        }),
    ];
    // A reversal carries no package claim: guard + reverses is refused too.
    // (The guard value is structurally valid; shape rejects the combination.)
    let mut guarded = base.clone();
    guarded["alpha_install_guard"] = json!({
        "package": "agent.undo-probe",
        "expected_install_event_id": "evt-1",
        "artifact_id": ARTIFACT,
        "source_revision": "evt-src-1",
        "version": "0.1.0",
        "digest": format!("sha256:{}", "b".repeat(64)),
        "declaration_digest": "c".repeat(64),
    });
    cases.push(("package_claim", guarded));

    let before = event_count(&db).await;
    for (name, invalid) in cases {
        let refused = call(&registry, &db, "invoke_artifact_interaction", invalid).await;
        assert_eq!(refused["status"], "invalid", "{name}: {refused:#}");
        assert_eq!(
            refused["error"]["code"], "invalid_invocation",
            "{name}: {refused:#}"
        );
    }
    assert_eq!(
        event_count(&db).await,
        before,
        "shape refusals append nothing"
    );
}

#[tokio::test]
async fn reversal_naming_a_different_source_is_refused() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-toolsource:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    // Well-formed but naming another render: the original's stored origin
    // decides, never the current render.
    let mut stale = reversal_envelope(&digest, "mark_triaged", "u-toolsource:1", "u-toolsource:u");
    stale["source_digest"] = json!("0".repeat(64));
    let before = event_count(&db).await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "stale_source_digest",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "triaged"
    );
}
#[tokio::test]
async fn reversal_naming_no_original_is_unknown_without_a_leak() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    // A real write exists, so the refusal cannot be mistaken for an empty log —
    // yet the named key was never used by this caller.
    let mut invocation = envelope("mark_triaged", &digest, "u-toolunknown:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let before = event_count(&db).await;
    let unknown = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        reversal_envelope(
            &digest,
            "mark_triaged",
            "u-toolunknown:nope",
            "u-toolunknown:u",
        ),
    )
    .await;
    assert_eq!(unknown["status"], "rejected", "{unknown:#}");
    assert_eq!(unknown["error"]["code"], "reversal_unknown", "{unknown:#}");
    let rendered = unknown.to_string();
    assert!(!rendered.contains(INSIDE), "{unknown:#}");
    assert!(!rendered.contains("triaged"), "{unknown:#}");
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
}
#[tokio::test]
async fn reversal_whose_key_spans_records_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "u-toolspan:1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    // The ambiguous precondition cannot arise through the tool — the dispatch
    // layer reserves one provenance attestation per (principal, operation,
    // key), so a second commit under one key dies before replay — but the
    // resolution lookup cannot know that. Mirror the real forward event onto
    // a second record to pin its fail-closed branch through the public tool.
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO content_events(id,record_id,type,payload,actor,run_key,parent_key,intent,
            causal_envelope_version,causal_status,created_at,act)
         SELECT ?,?,type,payload,actor,run_key,parent_key,intent,
            causal_envelope_version,causal_status,created_at,act
         FROM content_events WHERE record_id=? AND type='facet.set'
           AND json_extract(payload,'$.origin.idempotency_key')='u-toolspan:1'",
    )
    .bind("0a5e0000-0000-4000-8000-000000000099")
    .bind(OUTSIDE)
    .bind(INSIDE)
    .execute(&write_pool)
    .await
    .unwrap();

    let before = event_count(&db).await;
    let refused = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        reversal_envelope(&digest, "mark_triaged", "u-toolspan:1", "u-toolspan:u"),
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "idempotency_conflict",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "a refusal appends nothing");
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "triaged"
    );
}
// __NEXT__
