//! Host-mediated artifact interactions: a `native.mdx.v2` artifact invokes an
//! entry it DECLARED, and the host decides everything else.
//!
//! Each test here is one refusal or one commitment from the validation order in
//! `src/mcp/tools/artifact_interactions.rs`, exercised end to end through the
//! MCP tool surface rather than against the handler directly.

use std::sync::{Arc, OnceLock};

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

const ARTIFACT: &str = "66666666-6666-4666-8666-666666666666";
const INSIDE: &str = "0a5e0000-0000-4000-8000-000000000002";
const OUTSIDE: &str = "0a5e0000-0000-4000-8000-000000000003";
const COLLECTION: &str = "0a5e0000-0000-4000-8000-000000000001";
const RELATION_COLLECTION: &str = "0a5e0000-0000-4000-8000-000000000005";
const REFERENCE_COLLECTION: &str = "0a5e0000-0000-4000-8000-000000000010";
const CLEARING_ARTIFACT: &str = "0a5e0000-0000-4000-8000-000000000004";
const INVOCATION_VERSION: &str = "native.artifact-invocation.v1";

/// The MDX v2 parser and its caches are process-wide, as the module suite's
/// guard already assumes.
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
    {{ id: "clear_triage", label: "Clear triage", effect: "facet.unset",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "triage" }},
    {{ id: "start_work", label: "Start work", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "lifecycle", value: {{ from: "literal", value: "in_progress" }} }},
    {{ id: "clear_lifecycle", label: "Clear lifecycle", effect: "facet.unset",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "lifecycle" }},
    {{ id: "hand_over", label: "Hand over", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "owner", value: {{ from: "literal", value: "acct:someone" }} }},
    {{ id: "stall", label: "Stall", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "lifecycle", value: {{ from: "literal", value: "bogus_state" }} }},
    {{ id: "note_effort", label: "Note effort", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: "effort", value: {{ from: "literal", value: "large" }} }}
  ]
}}

<Metric label={label:?} value={{1}} />
"#
    )
}

fn create_artifact_source() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true },
    refs: { envelope: "native.collection-envelope.v1", required: false, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } },
    { capability: "input.read", scope: { port: "refs" } }
  ],
  interactions: [
    { id: "create_task", label: "Create task", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "WorkItem" }, domain: { kind: "enum", values: ["WorkItem"] } },
        kind: { source: { from: "literal", value: "task" }, domain: { kind: "enum", values: ["task"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "title" }, domain: { kind: "string", min_length: 1, max_length: 80 } } },
        facets: { triage: { label: "Triage", source: { from: "input", input: "triage" }, domain: { kind: "enum", values: ["ready", "blocked"] } } }
      } } },
    { id: "create_note", label: "Create note", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "Document" }, domain: { kind: "enum", values: ["Document"] } },
        kind: { source: { from: "literal", value: "note" }, domain: { kind: "enum", values: ["note"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "note_title" }, domain: { kind: "string", min_length: 1, max_length: 80 } }, body: { label: "Body", source: { from: "input", input: "note_body" }, domain: { kind: "string", min_length: 1, max_length: 500 } } },
        facets: {}
      } } },
    { id: "create_invalid_lifecycle", label: "Create invalid lifecycle", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "WorkItem" }, domain: { kind: "enum", values: ["WorkItem"] } },
        kind: { source: { from: "literal", value: "task" }, domain: { kind: "enum", values: ["task"] } },
        fields: {
          name: { label: "Title", source: { from: "input", input: "invalid_title" }, domain: { kind: "string", min_length: 1, max_length: 80 } },
          lifecycle: { source: { from: "literal", value: "definitely-not-governed" }, domain: { kind: "enum", values: ["definitely-not-governed"] } }
        },
        facets: {}
      } } },
    { id: "create_comment", label: "Create comment", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "Annotation" }, domain: { kind: "enum", values: ["Annotation"] } },
        kind: { source: { from: "literal", value: "comment" }, domain: { kind: "enum", values: ["comment"] } },
        fields: { body: { label: "Comment", source: { from: "input", input: "comment_body" }, domain: { kind: "string", min_length: 1, max_length: 500 } } },
        facets: {}
      } } },
    { id: "create_with_list", label: "Create with list", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "Document" }, domain: { kind: "enum", values: ["Document"] } },
        kind: { source: { from: "literal", value: "note" }, domain: { kind: "enum", values: ["note"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "list_title" }, domain: { kind: "string", min_length: 1, max_length: 80 } } },
        facets: { tags: { label: "Tags", source: { from: "input", input: "tags" }, domain: { kind: "list", min_items: 1, max_items: 3, item: { kind: "string", min_length: 1, max_length: 20 } } } }
      } } },
    { id: "create_with_boolean", label: "Create with boolean", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "Document" }, domain: { kind: "enum", values: ["Document"] } },
        kind: { source: { from: "literal", value: "note" }, domain: { kind: "enum", values: ["note"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "bool_title" }, domain: { kind: "string", min_length: 1, max_length: 80 } } },
        facets: { pinned: { label: "Pinned", source: { from: "input", input: "pinned" }, domain: { kind: "boolean" } } }
      } } },
    { id: "create_with_number", label: "Create with number", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "Document" }, domain: { kind: "enum", values: ["Document"] } },
        kind: { source: { from: "literal", value: "note" }, domain: { kind: "enum", values: ["note"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "number_title" }, domain: { kind: "string", min_length: 1, max_length: 80 } } },
        facets: { estimate: { label: "Estimate", source: { from: "input", input: "estimate" }, domain: { kind: "enum", values: [1.0, 2.0] } } }
      } } },
    { id: "create_with_ref", label: "Create with reference", effect: "record.create",
      create: { destination: { from: "bound_input", port: "orders" }, shape: {
        type: { source: { from: "literal", value: "Document" }, domain: { kind: "enum", values: ["Document"] } },
        kind: { source: { from: "literal", value: "note" }, domain: { kind: "enum", values: ["note"] } },
        fields: { name: { label: "Title", source: { from: "input", input: "ref_title" }, domain: { kind: "string", min_length: 1, max_length: 80 } } },
        facets: { related: { label: "Related", source: { from: "bound_input", slot: "related" }, domain: { kind: "bound_input", port: "refs" } } }
      } } }
  ]
}

<Metric label="Creation" value={1} />
"#
    .into()
}

fn digest_of(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

fn canonical_digest(value: &Value) -> String {
    hex::encode(Sha256::digest(serde_jcs::to_vec(value).unwrap()))
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

/// One artifact bound to one Collection holding exactly one of two records.
async fn fixture() -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let source = artifact_source("Orders");
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
                    "reason": "Populate the interaction fixture." }),
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

async fn create_fixture() -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let source = create_artifact_source();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Creation board",
            "body": source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Declare general record creation against a bound Collection."
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
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": REFERENCE_COLLECTION, "type": "Collection", "kind": "folder", "name": "References",
                "reason": "Bind an initially empty reference selector." }),
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
    let refs_bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "refs",
                "collection_id": REFERENCE_COLLECTION }),
    )
    .await;
    assert_eq!(refs_bound["status"], "bound", "{refs_bound:#}");
    grant_input_read(&registry, &db).await;
    grant_input_read_port(&registry, &db, "refs").await;
    (db, registry, digest_of(&source), guard)
}

/// The exact `input.read` grant rendering requires for a root-exposed port.
///
/// The write path requires it too: the caller's authority is not the
/// artifact's, and this grant is the human consent that THIS source may touch
/// this input.
async fn grant_input_read(registry: &ToolRegistry, db: &Db) {
    grant_input_read_port(registry, db, "orders").await;
}

async fn grant_input_read_port(registry: &ToolRegistry, db: &Db, port: &str) {
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
            "capability": "input.read", "scope": { "artifact_port": port }
        }),
    )
    .await;
    assert_eq!(granted["status"], "granted", "{granted:#}");
}

#[tokio::test]
async fn record_create_commits_once_with_initial_facets_and_an_authoritative_refresh() {
    let (db, registry, digest, _guard) = create_fixture().await;
    let invocation = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "create_task",
        "source_digest": digest,
        "values": { "title": "Ship general creation", "triage": "ready" },
        "idempotency_key": "create:task:one",
        "gesture": "submit"
    });
    let first = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let created_id = first["refresh"]["record"]["id"]
        .as_str()
        .expect("created record identity");
    assert_eq!(first["changes"][0]["record_id"], created_id);
    assert_eq!(first["refresh"]["record"]["name"], "Ship general creation");
    assert_eq!(first["refresh"]["record"]["home_id"], COLLECTION);

    let triage: String =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='triage'")
            .bind(created_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(triage, "ready");
    let origin_payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(created_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let origin_payload: Value = serde_json::from_str(&origin_payload).unwrap();
    assert_eq!(origin_payload["origin"]["kind"], "artifact.interaction");
    assert_eq!(origin_payload["origin"]["artifact_id"], ARTIFACT);
    assert_eq!(origin_payload["origin"]["entry_id"], "create_task");
    assert_eq!(origin_payload["origin"]["source_digest"], digest);
    assert!(origin_payload["origin"]["source_event_id"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(origin_payload["origin"]["invocation_digest"]
        .as_str()
        .is_some_and(|value| value.len() == 64));
    assert_eq!(
        origin_payload["origin"]["idempotency_key"],
        "create:task:one"
    );

    let replay = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(replay["refresh"]["record"]["id"], created_id);
    assert_eq!(replay["refresh"]["record"]["idempotent_retry"], true);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE home_id=? AND type='WorkItem' AND kind='task'",
    )
    .bind(COLLECTION)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1, "an idempotent replay must not create a duplicate");

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT,
            "body": format!("{}\n", create_artifact_source()),
            "if_body_digest": digest,
            "reason": "Revise the artifact after its creation committed."
        }),
    )
    .await;
    let after_source_edit = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(
        after_source_edit["status"], "committed",
        "{after_source_edit:#}"
    );
    assert_eq!(after_source_edit["refresh"]["record"]["id"], created_id);
    assert_eq!(
        after_source_edit["refresh"]["record"]["idempotent_retry"],
        true
    );

    let mut changed = invocation.clone();
    changed["values"]["title"] = json!("A different intent");
    let reused = call_as(
        &registry,
        &db,
        Caller::local(),
        "invoke_artifact_interaction",
        changed,
    )
    .await
    .expect_err("the tool idempotency boundary rejects changed action input");
    assert!(reused.to_string().contains("conflicting action input"));
}

#[tokio::test]
async fn record_create_rejects_out_of_domain_values_without_leaving_a_bearer() {
    let (db, registry, digest, _guard) = create_fixture().await;
    let rejected = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_task",
            "source_digest": digest,
            "values": { "title": "Must not exist", "triage": "undeclared" },
            "idempotency_key": "create:task:invalid"
        }),
    )
    .await;
    assert_eq!(rejected["status"], "rejected", "{rejected:#}");
    assert_eq!(rejected["error"]["code"], "value_outside_domain");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE home_id=? AND name='Must not exist'",
    )
    .bind(COLLECTION)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 0);

    let schema_rejected = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_invalid_lifecycle",
            "source_digest": digest,
            "values": { "invalid_title": "No partial bearer" },
            "idempotency_key": "create:task:schema-invalid"
        }),
    )
    .await;
    assert_eq!(schema_rejected["status"], "rejected", "{schema_rejected:#}");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE home_id=? AND name='No partial bearer'",
    )
    .bind(COLLECTION)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        count, 0,
        "governance failure must roll the entire create back"
    );
}

#[tokio::test]
async fn record_create_rechecks_destination_authority_at_invocation() {
    let (db, registry, digest, _guard) = create_fixture().await;
    let caller = Caller::authenticated("acct:bea");
    for record_id in [ARTIFACT, COLLECTION] {
        replace_explicit_policy(
            &db,
            "test:artifact-create-view-only",
            record_id,
            vec![AllowEntry::account("acct:bea", Capability::View)],
        )
        .await
        .unwrap();
    }
    let denied = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_task",
            "source_digest": digest,
            "values": { "title": "Unauthorized bearer", "triage": "ready" },
            "idempotency_key": "create:task:unauthorized"
        }),
    )
    .await
    .unwrap();
    assert_eq!(denied["status"], "rejected", "{denied:#}");
    assert_eq!(denied["error"]["code"], "permission_denied");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE home_id=? AND name='Unauthorized bearer'",
    )
    .bind(COLLECTION)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn record_create_is_general_and_render_availability_is_creation_aware() {
    let (db, registry, digest, _guard) = create_fixture().await;
    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(rendered["plan"]["observed"], json!({}));
    let supported = rendered["plan"]["interaction_availability"]["supported_entries"]
        .as_array()
        .expect("supported entries");
    assert!(supported.iter().any(|entry| entry == "create_task"));
    assert!(supported.iter().any(|entry| entry == "create_note"));
    assert!(!supported.iter().any(|entry| entry == "create_comment"));
    assert!(!supported.iter().any(|entry| entry == "create_with_list"));
    assert!(!supported.iter().any(|entry| entry == "create_with_boolean"));
    assert!(supported.iter().any(|entry| entry == "create_with_number"));
    assert!(
        !supported.iter().any(|entry| entry == "create_with_ref"),
        "an empty bound reference port must keep its unfillable entry unavailable: {rendered:#}"
    );
    assert_eq!(
        rendered["plan"]["interaction_availability"]["editable_records"],
        json!([]),
        "a writable destination is not an editable target record projection"
    );

    let note = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_note",
            "source_digest": digest,
            "values": { "note_title": "A real note", "note_body": "Not a WorkItem." },
            "idempotency_key": "create:note:one"
        }),
    )
    .await;
    assert_eq!(note["status"], "committed", "{note:#}");
    assert_eq!(note["refresh"]["record"]["type"], "Document");
    assert_eq!(note["refresh"]["record"]["kind"], "note");

    let numeric = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT,
            "entry_id": "create_with_number", "source_digest": digest,
            "values": { "number_title": "Numeric normalization", "estimate": 1 },
            "idempotency_key": "create:number:one"
        }),
    )
    .await;
    assert_eq!(numeric["status"], "committed", "{numeric:#}");
}

#[tokio::test]
async fn record_create_resolves_bound_references_inside_the_named_port_only() {
    const ALLOWED: &str = "0a5e0000-0000-4000-8000-000000000011";
    const OUTSIDE_REF: &str = "0a5e0000-0000-4000-8000-000000000012";
    let (db, registry, digest, _guard) = create_fixture().await;
    for (id, record_type, kind, name) in [
        (ALLOWED, "Document", "note", "Allowed reference"),
        (OUTSIDE_REF, "Document", "note", "Outside reference"),
    ] {
        let mut arguments = json!({ "id": id, "type": record_type, "kind": kind, "name": name,
                "reason": "Create bound-reference fixture." });
        if id == ALLOWED {
            arguments["home_id"] = json!(REFERENCE_COLLECTION);
        }
        call(&registry, &db, "create_record", arguments).await;
    }

    let outside = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT,
            "entry_id": "create_with_ref", "source_digest": digest,
            "values": { "ref_title": "Outside must fail" },
            "slots": { "related": OUTSIDE_REF }, "idempotency_key": "create:ref:outside"
        }),
    )
    .await;
    assert_eq!(outside["status"], "rejected", "{outside:#}");
    assert_eq!(outside["error"]["code"], "record_outside_binding");

    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(
        rendered["plan"]["interaction_availability"]["record_labels"][ALLOWED]["name"],
        "Allowed reference",
        "{rendered:#}"
    );
    let allowed = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT,
            "entry_id": "create_with_ref", "source_digest": digest,
            "values": { "ref_title": "Inside succeeds" },
            "slots": { "related": ALLOWED }, "idempotency_key": "create:ref:inside"
        }),
    )
    .await;
    assert_eq!(allowed["status"], "committed", "{allowed:#}");
    let created_id = allowed["refresh"]["record"]["id"].as_str().unwrap();
    let related: String =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='related'")
            .bind(created_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(related, ALLOWED);
}

/// A real v2 render reaches the telemetry snapshot, with its phases summing to
/// the render.
///
/// `native.mdx.v2` emitted nothing at all before this, and the snapshot that
/// would have shown it had no caller anywhere, so neither half of the claim
/// could be checked. Asserting it here rather than in the runtime crate is the
/// point: most of a v2 render happens in the host, and only an end-to-end call
/// proves the host's phases are actually reported.
#[tokio::test]
async fn a_v2_render_reaches_the_telemetry_snapshot_with_its_phases() {
    let (db, registry, _digest, _guard) = fixture().await;
    // Read under the fixture's guard, which every test in this file holds for
    // its whole body. The ring and its counters are process-global, so a
    // baseline taken outside that guard would race a concurrent render and make
    // the delta below flaky rather than wrong.
    let before = native_ce::mcp::tools::artifacts::mdx_telemetry_snapshot()["runtimes"]
        ["native.mdx.v2"]["attempts"]
        .as_u64()
        .unwrap_or_default();

    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");

    let snapshot = native_ce::mcp::tools::artifacts::mdx_telemetry_snapshot();
    let totals = &snapshot["runtimes"]["native.mdx.v2"];
    assert_eq!(
        totals["attempts"].as_u64().unwrap(),
        before + 1,
        "the render must be counted against its own runtime: {snapshot:#}"
    );

    // The event this render produced. Other suites share the process and its
    // ring, so find it rather than assuming an index.
    let event = snapshot["events"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["runtime"] == "native.mdx.v2" && event["artifact_id"] == ARTIFACT)
        .unwrap_or_else(|| panic!("the render must have left an event: {snapshot:#}"));

    // v2's own revision, not the 1 that used to be hardcoded.
    assert_eq!(
        event["adapter_revision"],
        native_artifact_runtime::mdx_v2::ADAPTER_REVISION,
        "a v2 event labelled as v1's revision is indistinguishable from a v1 one"
    );

    // The fields v1 populates, which is the floor this had to clear.
    for field in [
        "compile_micros",
        "execute_micros",
        "validate_micros",
        "input_records",
        "input_json_bytes",
        "output_nodes",
        "output_json_bytes",
    ] {
        assert!(
            event[field].is_number(),
            "v2 must populate {field}, which v1 already does: {event:#}"
        );
    }

    // And the host phases, which are the reason this task existed: measured,
    // they are most of a board's cold open and none of them were visible.
    for phase in [
        "snapshot_begin",
        "compile",
        "module_closure",
        "binding_projection",
        "resolve_inputs",
        "capability_preflight",
        "graph_link",
        "observed_versions",
        "input_assembly",
        "execute",
        "validate",
        "plan_assembly",
        "snapshot_release",
    ] {
        assert!(
            event["phases"][phase].is_number(),
            "phase {phase} must be reported: {event:#}"
        );
    }
    assert!(
        event["phases"].get("failed").is_none(),
        "a render that succeeded must not report a failed phase: {event:#}"
    );
}

/// A render that fails inside the snapshot charges the failing work to `failed`,
/// not to the teardown that happens to run next.
///
/// `snapshot_release` closes its boundary unconditionally after the inner render
/// returns, and every one of that render's ~20 early returns leaves a phase
/// open. Without the outcome check ahead of it, a failure's whole cost is swept
/// into `snapshot_release` and the `failed` phase measures a wrapper hop — the
/// phases still sum, so nothing looks wrong, and the attribution is simply a
/// lie. That is the failure mode telemetry is least able to survive, so it is
/// pinned here rather than left to reading.
#[tokio::test]
async fn a_failed_v2_render_charges_its_cost_to_failed_not_to_the_teardown() {
    let (db, registry, _digest, _guard) = fixture().await;
    // Revoking `input.read` fails the render at the capability preflight, which
    // is deep enough to have real phases behind it and a clear set that must
    // not appear ahead of it.
    let subjects = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    let subject = subjects["subjects"][0].clone();
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "revoke", "artifact_id": ARTIFACT, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"],
            "capability": "input.read", "scope": { "artifact_port": "orders" }
        }),
    )
    .await;

    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(rendered["status"], "error", "{rendered:#}");

    let snapshot = native_ce::mcp::tools::artifacts::mdx_telemetry_snapshot();
    let event = snapshot["events"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["runtime"] == "native.mdx.v2" && event["artifact_id"] == ARTIFACT)
        .unwrap_or_else(|| panic!("the failed render must have left an event: {snapshot:#}"));

    assert_eq!(
        event["diagnostic_code"], rendered["diagnostic"]["code"],
        "the event must carry the diagnostic the caller was given: {event:#}"
    );
    assert!(
        event["phases"]["failed"].is_number(),
        "the failing work needs a phase of its own: {event:#}"
    );
    // It reached the capability preflight and no further, so the phases behind
    // it are present and the ones ahead of it are absent rather than zero.
    for phase in ["snapshot_begin", "compile", "resolve_inputs"] {
        assert!(
            event["phases"][phase].is_number(),
            "phase {phase} ran before the failure and must be reported: {event:#}"
        );
    }
    for phase in [
        "graph_link",
        "observed_versions",
        "execute",
        "plan_assembly",
    ] {
        assert!(
            event["phases"].get(phase).is_none(),
            "a render that stopped at preflight must not report {phase}: {event:#}"
        );
    }
}

#[tokio::test]
async fn render_plan_carries_declared_entries_and_same_snapshot_versions() {
    let (db, registry, _digest, _guard) = fixture().await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "effort": "large" },
                "reason": "Give the render one present open facet." }),
    )
    .await;
    let effort_seq: i64 = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM facet_observations WHERE record_id=? AND key='effort'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let record_event_seq: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
            .bind(INSIDE)
            .fetch_one(db.pool())
            .await
            .unwrap();

    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let entry_ids = rendered["plan"]["interactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        entry_ids,
        vec![
            "mark_triaged",
            "set_triage",
            "clear_triage",
            "start_work",
            "clear_lifecycle",
            "hand_over",
            "stall",
            "note_effort",
        ]
    );
    assert_eq!(
        rendered["plan"]["interactions"][1]["slots"]["choice"]["domain"]["values"],
        json!(["triaged", "blocked"]),
        "the plan must preserve the validated manifest domain exactly"
    );
    assert!(
        !rendered["plan"]["tree"]
            .to_string()
            .contains("mark_triaged"),
        "entries are declared by the manifest, not derived from the rendered tree"
    );
    assert_eq!(rendered["plan"]["observed"][INSIDE]["triage"], "obs:0");
    assert_eq!(
        rendered["plan"]["observed"][INSIDE]["effort"],
        format!("obs:{effort_seq}")
    );
    assert_eq!(
        rendered["plan"]["observed"][INSIDE]["lifecycle"],
        format!("rec:{record_event_seq}")
    );
    assert!(rendered["plan"]["observed"].get(OUTSIDE).is_none());
}

/// Batched GROUP BY queries return no row for a missing record/version pair.
/// The render still has to issue the zero CAS tokens for required pairs while
/// leaving records outside the bound-input domain absent altogether.
#[tokio::test]
async fn render_plan_restores_zero_tokens_for_missing_grouped_rows() {
    let (db, registry, _digest, _guard) = fixture().await;
    let second_inside = "0a5e0000-0000-4000-8000-000000000005";
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": second_inside, "type": "WorkItem", "kind": "task",
                "name": second_inside, "reason": "Add a second in-scope grouped-query row." }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": second_inside, "target_id": COLLECTION,
                "relationship": "member_of" }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "triaged" },
                "reason": "Give one in-scope record a present grouped-query row." }),
    )
    .await;
    let triage_seq: i64 = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM facet_observations WHERE record_id=? AND key='triage'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let record_event_seq: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
            .bind(INSIDE)
            .fetch_one(db.pool())
            .await
            .unwrap();
    sqlx::query("DELETE FROM content_events WHERE record_id=?")
        .bind(second_inside)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(
        rendered["plan"]["observed"][INSIDE]["triage"],
        format!("obs:{triage_seq}")
    );
    assert_eq!(
        rendered["plan"]["observed"][second_inside]["triage"],
        "obs:0"
    );
    assert_eq!(
        rendered["plan"]["observed"][INSIDE]["lifecycle"],
        format!("rec:{record_event_seq}")
    );
    assert_eq!(
        rendered["plan"]["observed"][second_inside]["lifecycle"],
        "rec:0"
    );
    assert!(rendered["plan"]["observed"].get(OUTSIDE).is_none());
}

/// The compare-and-set precondition for one open facet, read back the way a
/// caller must read it. An absent facet has never been observed, which is
/// `obs:0`.
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

/// The record-level precondition a spine facet takes.
async fn observed_spine(registry: &ToolRegistry, db: &Db, record: &str, facet: &str) -> Value {
    json!({ record: { facet: record_version(registry, db, record).await } })
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

#[tokio::test]
async fn a_declared_entry_writes_an_open_facet_on_a_bound_record() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "k-1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let result = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(result["status"], "committed", "{result:#}");
    assert_eq!(result["changes"][0]["record_id"], INSIDE);
    assert_eq!(result["changes"][0]["key"], "triage");
    assert_eq!(result["changes"][0]["after"], "triaged");
    assert!(result["changes"][0]["before"].is_null());

    // The write is real, and the read path hands out the version token the next
    // invocation is required to quote.
    let facet = facet_of(&registry, &db, INSIDE, "triage")
        .await
        .expect("the facet was written");
    assert_eq!(facet["value"], "triaged");
    let version = facet["version"].as_str().expect("facet carries a version");
    assert!(version.starts_with("obs:"), "{version}");

    // Attributed to the actor AND to the originating artifact.
    let event = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT payload, actor FROM content_events
          WHERE record_id=? AND type='facet.set'
            AND json_extract(payload,'$.key')='triage' ORDER BY seq DESC LIMIT 1",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&event.0).unwrap();
    assert_eq!(payload["origin"]["artifact_id"], ARTIFACT);
    assert_eq!(payload["origin"]["entry_id"], "mark_triaged");
    assert_eq!(payload["origin"]["gesture"], "click");
    assert!(event.1.is_some(), "the event carries the acting identity");

    // The same invocation replayed commits once, not twice.
    let replay = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    let writes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.origin.idempotency_key')='k-1'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(writes, 1);
}

#[tokio::test]
async fn a_corrected_open_observation_keeps_its_old_token_authentic() {
    let (db, registry, digest, _guard) = fixture().await;
    let as_of = "2026-08-01T00:00:00Z";
    let first = call(
        &registry,
        &db,
        "manage_facet_observations",
        json!({
            "action": "set", "record_id": INSIDE, "key": "triage",
            "value": "triaged", "as_of": as_of,
            "reason": "Issue the first host-owned token for this valid time."
        }),
    )
    .await;
    let first_seq = first["event_seq"].as_i64().unwrap();
    let correction = call(
        &registry,
        &db,
        "manage_facet_observations",
        json!({
            "action": "set", "record_id": INSIDE, "key": "triage",
            "value": "blocked", "as_of": as_of,
            "reason": "Correct the observation at the same valid time."
        }),
    )
    .await;
    let correction_seq = correction["event_seq"].as_i64().unwrap();
    assert!(correction_seq > first_seq);
    let projected_seq: i64 = sqlx::query_scalar(
        "SELECT event_seq FROM facet_observations WHERE record_id=? AND key='triage' AND as_of=?",
    )
    .bind(INSIDE)
    .bind("2026-08-01T00:00:00.000Z")
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(projected_seq, correction_seq);

    let mut invocation = envelope("mark_triaged", &digest, "k-corrected-token");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = json!({ INSIDE: { "triage": format!("obs:{first_seq}") } });
    let conflict = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["current_version"], format!("obs:{correction_seq}"));
    let correction_event_id: String =
        sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND seq=?")
            .bind(INSIDE)
            .bind(correction_seq)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(conflict["conflicting_event_id"], correction_event_id);
}

#[tokio::test]
async fn a_value_outside_the_declared_domain_is_refused_rather_than_confirmed() {
    let (db, registry, digest, _guard) = fixture().await;
    let precondition = observed(&registry, &db, INSIDE, "triage").await;
    let mut invocation = envelope("set_triage", &digest, "k-domain");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["values"] = json!({ "choice": "elsewhere" });
    invocation["observed"] = precondition.clone();
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    // A domain failure is a rejection, never a confirmation prompt: no human
    // answer could make an undeclared value admissible.
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "value_outside_domain");
    assert!(refused["error"]["message"]
        .as_str()
        .unwrap()
        .contains("elsewhere"));
    assert!(refused.get("changes").is_none(), "{refused:#}");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());

    // A value of the right shape but the wrong type is refused the same way,
    // rather than reaching a stored form that has no representation for it.
    let mut typed = envelope("set_triage", &digest, "k-domain-typed");
    typed["slots"] = json!({ "record": INSIDE });
    typed["values"] = json!({ "choice": true });
    typed["observed"] = precondition.clone();
    let refused_bool = call(&registry, &db, "invoke_artifact_interaction", typed).await;
    assert_eq!(refused_bool["status"], "rejected", "{refused_bool:#}");
    assert_eq!(refused_bool["error"]["code"], "value_outside_domain");

    let mut declared = envelope("set_triage", &digest, "k-domain-ok");
    declared["slots"] = json!({ "record": INSIDE });
    declared["values"] = json!({ "choice": "blocked" });
    declared["observed"] = precondition;
    let committed = call(&registry, &db, "invoke_artifact_interaction", declared).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["after"], "blocked");
}

#[tokio::test]
async fn an_invocation_without_a_precondition_is_refused() {
    let (db, registry, digest, _guard) = fixture().await;
    // Omitting `observed` used to mean "write unconditionally", which is
    // exactly the silent last-write-wins the facet-scoped compare-and-set
    // decision refused. The pair being written must be observed.
    let mut unguarded = envelope("mark_triaged", &digest, "k-unguarded");
    unguarded["slots"] = json!({ "record": INSIDE });
    let refused = call(&registry, &db, "invoke_artifact_interaction", unguarded).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "precondition_required");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());

    // Observing some OTHER facet is not observing this one.
    let mut wrong_facet = envelope("mark_triaged", &digest, "k-wrong-facet");
    wrong_facet["slots"] = json!({ "record": INSIDE });
    wrong_facet["observed"] = observed(&registry, &db, INSIDE, "effort").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", wrong_facet).await;
    assert_eq!(
        refused["error"]["code"], "precondition_required",
        "{refused:#}"
    );

    // The token grammar is intentionally opaque rather than cryptographic,
    // so a syntactically valid token still has to name state the host issued.
    // An absent facet cannot conflict with an event that does not exist.
    let mut future = envelope("mark_triaged", &digest, "k-future-token");
    future["slots"] = json!({ "record": INSIDE });
    future["observed"] = json!({ INSIDE: { "triage": "obs:999999" } });
    let refused = call(&registry, &db, "invoke_artifact_interaction", future).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "invalid_precondition");

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "blocked" },
                "reason": "Create a real triage observation series." }),
    )
    .await;
    let triage_seq: i64 = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM facet_observations WHERE record_id=? AND key='triage'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "effort": "large" },
                "reason": "Create another facet's observation series." }),
    )
    .await;
    let effort_seq: i64 = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM facet_observations WHERE record_id=? AND key='effort'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let record_version = record_version(&registry, &db, INSIDE).await;

    for (key, entry, token) in [
        (
            "k-future-present",
            "mark_triaged",
            format!("obs:{}", triage_seq + 10_000),
        ),
        (
            "k-other-series",
            "mark_triaged",
            format!("obs:{effort_seq}"),
        ),
        ("k-open-record-token", "mark_triaged", record_version),
        (
            "k-spine-observation-token",
            "start_work",
            format!("obs:{triage_seq}"),
        ),
        ("k-forged-spine-token", "start_work", "rec:999999".into()),
    ] {
        let facet = if entry == "start_work" {
            "lifecycle"
        } else {
            "triage"
        };
        let mut invocation = envelope(entry, &digest, key);
        invocation["slots"] = json!({ "record": INSIDE });
        invocation["observed"] = json!({ INSIDE: { facet: token } });
        let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
        assert_eq!(refused["status"], "rejected", "{key}: {refused:#}");
        assert_eq!(
            refused["error"]["code"], "invalid_precondition",
            "{key}: {refused:#}"
        );
    }
}

#[tokio::test]
async fn an_artifact_naming_an_engine_dispatched_facet_or_an_unwritable_value_never_attests() {
    let (db, registry, _digest, _guard) = fixture().await;
    // `archive_record` owns `archived` and requires Manage; a declared entry
    // naming it would emit the byte-identical event after an Edit check. The
    // manifest validator refuses the body, so such an artifact never exists to
    // be invoked — the handler's own reserved-key refusal is the second lock.
    for (facet, value, expected) in [
        ("archived", "\"true\"", "engine-dispatched"),
        ("blob_ref", "\"blob:forged\"", "engine-dispatched"),
        // `runtime` is an ordinary open facet, but the engine dispatches on it:
        // setting it here would leave a Program whose declared interpreter no
        // longer matches its body, or an artifact flipped to a runtime its body
        // never validated against.
        ("runtime", "\"native.html.v1\"", "engine-dispatched"),
        ("triage", "true", "not a string, number or object"),
    ] {
        let body = format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "orders" }} }}],
  interactions: [
    {{ id: "sneak", label: "Sneak", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input" }} }} }},
      facet: {facet:?}, value: {{ from: "literal", value: {value} }} }}
  ]
}}

<Metric label="Sneak" value={{1}} />
"#
        );
        let refused = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": format!("0a5e0000-0000-4000-8000-0000000001{:02}", value.len()),
                    "type": "Document",
                    "kind": "artifact", "name": "Sneak", "body": body,
                    "facets": { "runtime": "native.mdx.v2" },
                    "reason": "An artifact must not be able to declare this."
                }),
            )
            .await
            .expect_err("the manifest validator refuses the body");
        let refused = refused.to_string();
        assert!(refused.contains(expected), "{refused}");
        assert!(refused.contains("interaction_entry_invalid"), "{refused}");
    }
}

#[tokio::test]
async fn a_required_facet_cannot_be_cleared_by_an_unset_entry() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut set = envelope("note_effort", &digest, "k-effort");
    set["slots"] = json!({ "record": INSIDE });
    set["observed"] = observed(&registry, &db, INSIDE, "effort").await;
    assert_eq!(
        call(&registry, &db, "invoke_artifact_interaction", set).await["status"],
        "committed"
    );
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "WorkItem:task": { "facets": { "effort": { "required": true } } }
        } } }),
    )
    .await;

    // An unset carries no value, so value governance has nothing to say about
    // it. The required-facet bracket is the check that bites, and it must run
    // for an unset for exactly that reason.
    let body = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({ "id": CLEARING_ARTIFACT, "type": "Document", "kind": "artifact",
                    "name": "Clear effort", "body": clearing_artifact(),
                    "facets": { "runtime": "native.mdx.v2" },
                    "reason": "Declare an entry that clears a required facet." }),
        )
        .await;
    assert!(body.is_ok(), "{body:#?}");
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": CLEARING_ARTIFACT,
                "port_name": "orders", "collection_id": COLLECTION }),
    )
    .await;
    let subjects = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": CLEARING_ARTIFACT }),
    )
    .await;
    let subject = subjects["subjects"][0].clone();
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": CLEARING_ARTIFACT,
            "subject_kind": "artifact_source", "subject_record_id": CLEARING_ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"],
            "capability": "input.read", "scope": { "artifact_port": "orders" }
        }),
    )
    .await;
    let mut clear = envelope("clear_effort", &digest_of(&clearing_artifact()), "k-clear");
    clear["artifact_id"] = json!(CLEARING_ARTIFACT);
    clear["slots"] = json!({ "record": INSIDE });
    clear["observed"] = observed(&registry, &db, INSIDE, "effort").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", clear).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "required_facet_missing");
    // The refusal rolled the append back with its transaction.
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "effort").await.unwrap()["value"],
        "large"
    );
}

#[tokio::test]
async fn an_idempotency_key_is_scoped_to_its_caller_artifact_and_entry() {
    let (db, registry, digest, _guard) = fixture().await;
    // The key is client-chosen. Scoped by record alone, one caller could
    // pre-burn a predictable key and silently null another principal's later
    // write while the host reported success.
    replace_explicit_policy(
        &db,
        "test:artifact-interaction-idempotency",
        INSIDE,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let mut first = envelope("mark_triaged", &digest, "shared-key");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        bea,
        "invoke_artifact_interaction",
        first.clone(),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let mut second = envelope("mark_triaged", &digest, "shared-key");
    second["slots"] = json!({ "record": INSIDE });
    second["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let also = call(&registry, &db, "invoke_artifact_interaction", second).await;
    assert_eq!(also["status"], "committed", "{also:#}");
    let writes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.origin.idempotency_key')='shared-key'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        writes, 2,
        "another principal's key must not swallow this caller's write"
    );
}

#[tokio::test]
async fn spine_clears_and_governed_identity_are_refused() {
    let (db, registry, digest, _guard) = fixture().await;
    for (entry, key) in [("clear_lifecycle", "lifecycle"), ("hand_over", "owner")] {
        let mut invocation = envelope(entry, &digest, &format!("k-{entry}"));
        invocation["slots"] = json!({ "record": INSIDE });
        invocation["observed"] = observed_spine(&registry, &db, INSIDE, key).await;
        let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
        assert_eq!(refused["status"], "rejected", "{refused:#}");
        assert_eq!(refused["error"]["code"], "unsupported_facet", "{refused:#}");
    }
    let record = call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await;
    assert!(record["records"][0]["owner_id"].is_null(), "{record:#}");
}

#[tokio::test]
async fn unfilled_and_undeclared_slots_are_refused() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut unfilled = envelope("mark_triaged", &digest, "k-unfilled");
    unfilled["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", unfilled).await;
    assert_eq!(refused["error"]["code"], "slot_unfilled", "{refused:#}");

    let mut no_value = envelope("set_triage", &digest, "k-novalue");
    no_value["slots"] = json!({ "record": INSIDE });
    no_value["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", no_value).await;
    assert_eq!(refused["error"]["code"], "slot_unfilled", "{refused:#}");

    let mut invented = envelope("mark_triaged", &digest, "k-invented");
    invented["slots"] = json!({ "record": INSIDE, "target": OUTSIDE });
    invented["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invented).await;
    assert_eq!(refused["error"]["code"], "unknown_slot", "{refused:#}");
}

#[tokio::test]
async fn a_revoked_input_read_grant_stops_writing_as_it_stops_rendering() {
    let (db, registry, digest, _guard) = fixture().await;
    let subjects = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    let subject = subjects["subjects"][0].clone();
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "revoke", "artifact_id": ARTIFACT, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"],
            "capability": "input.read", "scope": { "artifact_port": "orders" }
        }),
    )
    .await;
    let edited = artifact_source("Orders after revocation");
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": edited, "if_body_digest": digest,
                "reason": "A later compatible edit must not resurrect revoked consent." }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_carried_forward",
        "{updated:#}"
    );
    assert_eq!(
        updated["artifact_input_continuity"]["carried_binding_count"],
        1
    );
    assert_eq!(
        updated["artifact_input_continuity"]["carried_grant_count"],
        0
    );
    let grants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(grants, 0, "revoked consent must not be reconstructed");
    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(
        rendered["diagnostic"]["code"], "module_capability_denied",
        "{rendered:#}"
    );
    // The caller's authority is not the artifact's: revoking the consent that
    // this source may read the port must stop the write at the same moment.
    let mut invocation = envelope("mark_triaged", &digest_of(&edited), "k-revoked");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "module_capability_denied");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn an_unbound_required_port_refuses_the_write_as_it_refuses_the_render() {
    let (db, registry, digest, _guard) = fixture().await;
    let bindings = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "unbind", "artifact_id": ARTIFACT, "port_name": "orders",
                "collection_id": COLLECTION,
                "event_seq": bindings["bindings"][0]["event_seq"] }),
    )
    .await;
    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(
        rendered["diagnostic"]["code"], "named_input_missing",
        "{rendered:#}"
    );
    let mut invocation = envelope("mark_triaged", &digest, "k-unbound");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "named_input_missing",
        "{refused:#}"
    );
}

#[tokio::test]
async fn a_record_outside_the_bound_input_is_refused() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "k-2");
    invocation["slots"] = json!({ "record": OUTSIDE });
    invocation["observed"] = observed(&registry, &db, OUTSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "record_outside_binding");
    assert!(facet_of(&registry, &db, OUTSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn an_unqualified_interaction_cannot_write_through_a_relation_port() {
    let (db, registry, digest, _guard) = fixture().await;
    let source = artifact_source("Mixed read and write inputs")
        .replace(
            r#"inputs: { orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },"#,
            r#"inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true },
    related: { envelope: "native.relation-envelope.v1", required: true, expose_to_root: true }
  },"#,
        )
        .replace(
            r#"capability_requests: [{ capability: "input.read", scope: { port: "orders" } }],"#,
            r#"capability_requests: [
    { capability: "input.read", scope: { port: "orders" } },
    { capability: "input.read", scope: { port: "related" } }
  ],"#,
        );
    let source_digest = digest_of(&source);
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT, "body": source, "if_body_digest": digest,
            "reason": "Add a read-only relation beside the writable Collection port."
        }),
    )
    .await;
    assert!(updated.get("error").is_none(), "{updated:#}");
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": RELATION_COLLECTION, "type": "Collection", "kind": "selection",
            "name": "Read-only related records", "reason": "Bind the relation-only cohort."
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "add", "source_id": OUTSIDE, "target_id": RELATION_COLLECTION,
            "relationship": "member_of"
        }),
    )
    .await;
    for (port_name, collection_id) in [("orders", COLLECTION), ("related", RELATION_COLLECTION)] {
        call(
            &registry,
            &db,
            "manage_artifact_inputs",
            json!({
                "action": "bind", "artifact_id": ARTIFACT, "port_name": port_name,
                "collection_id": collection_id
            }),
        )
        .await;
    }
    let subjects = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    let subject = &subjects["subjects"][0];
    for port in ["orders", "related"] {
        call(
            &registry,
            &db,
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT,
                "subject_kind": "artifact_source", "subject_record_id": ARTIFACT,
                "subject_event_id": subject["subject_event_id"],
                "source_sha256": subject["source_sha256"],
                "capability": "input.read", "scope": { "artifact_port": port }
            }),
        )
        .await;
    }

    let mut invocation = envelope("clear_triage", &source_digest, "k-relation-read-only");
    invocation["slots"] = json!({ "record": OUTSIDE });
    invocation["observed"] = observed(&registry, &db, OUTSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "record_outside_binding");
    assert!(facet_of(&registry, &db, OUTSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn a_caller_without_edit_permission_is_refused() {
    let (db, registry, digest, _guard) = fixture().await;
    // The caller may SEE the record — so it resolves inside the bound input —
    // and still may not write it. Permission comes from the authenticated
    // principal inside the write transaction, never from the envelope.
    replace_explicit_policy(
        &db,
        "test:artifact-interaction-permission",
        INSIDE,
        vec![AllowEntry::account("acct:vic", Capability::View)],
    )
    .await
    .unwrap();
    let vic = Caller::authenticated("acct:vic")
        .with_hosting_context("host:vic", "db:test")
        .with_hosting_owner(false);
    let mut invocation = envelope("mark_triaged", &digest, "k-3");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call_as(
        &registry,
        &db,
        vic,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}

#[tokio::test]
async fn a_stale_source_digest_cannot_invoke_against_an_edited_manifest() {
    let (db, registry, digest, _guard) = fixture().await;
    let precondition = observed(&registry, &db, INSIDE, "triage").await;
    let edited = artifact_source("Orders (revised)");
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": edited, "if_body_digest": digest,
                "reason": "Edit the artifact under a rendered client." }),
    )
    .await;
    assert!(updated.get("error").is_none(), "{updated:#}");
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_carried_forward",
        "{updated:#}"
    );
    assert_eq!(
        updated["artifact_input_continuity"]["carried_binding_count"],
        1
    );
    assert_eq!(
        updated["artifact_input_continuity"]["carried_grant_count"],
        1
    );
    assert_eq!(updated["warnings"].as_array().unwrap().len(), 1);
    let mut invocation = envelope("mark_triaged", &digest, "k-4");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = precondition.clone();
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "stale_source_digest");
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());

    // Compatible edits explicitly carry the binding and exact input.read grant
    // to the new source. The old invocation is still stale, while the new one
    // works without a manual rebind or regrant.
    let current_digest = digest_of(&edited);
    let mut current = envelope("mark_triaged", &current_digest, "k-5");
    current["slots"] = json!({ "record": INSIDE });
    current["observed"] = precondition;
    let committed = call(&registry, &db, "invoke_artifact_interaction", current).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let carried: (String, String) = sqlx::query_as(
        "SELECT artifact_source_event_id,artifact_source_sha256 FROM artifact_inputs
          WHERE artifact_id=? AND port_name='orders'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(carried.1, current_digest);
    let grant_source: String = sqlx::query_scalar(
        "SELECT artifact_source_sha256 FROM artifact_module_grants
          WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(grant_source, current_digest);
    let carry_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=?
          AND type IN ('artifact.input_carried','artifact.module_grant_carried')",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(carry_events, 2);
    assert!(native_ce::conformance::run_conformance(&db).await.ok);

    // A carry is not an idempotent projection shortcut. Reordering it after
    // its predecessor has already been retired, or forging the predecessor
    // sequence to name the carried row, must both fail closed.
    let row = sqlx::query(
        "SELECT seq,payload,created_at FROM content_events WHERE record_id=?
          AND type='artifact.input_carried' ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let original_payload: Value = serde_json::from_str(&row.get::<String, _>("payload")).unwrap();
    for (id, payload) in [
        (
            "99999999-9999-4999-8999-999999999991",
            original_payload.clone(),
        ),
        ("99999999-9999-4999-8999-999999999992", {
            let mut forged = original_payload.clone();
            forged["predecessor_binding_event_seq"] = json!(row.get::<i64, _>("seq"));
            forged
        }),
    ] {
        let event = native_ce::events::EventRow {
            local_seq: row.get::<i64, _>("seq") + 100,
            id: id.into(),
            record_id: ARTIFACT.into(),
            event_type: "artifact.input_carried".into(),
            payload: Some(payload.to_string()),
            actor: Some("test:forged-carry".into()),
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: row.get("created_at"),
            causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
        };
        let mut conn = crate::common::fixture_write_pool(&db)
            .await
            .acquire()
            .await
            .unwrap();
        let error = native_ce::projector::project(&mut conn, &event)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("predecessor"), "{error}");
    }
}

#[tokio::test]
async fn changing_one_input_declaration_drops_all_exact_input_state() {
    let (db, registry, digest, _guard) = fixture().await;
    let changed = artifact_source("Orders").replace("required: true", "required: false");
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": changed, "if_body_digest": digest,
                "reason": "Change the declared input contract." }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"],
        "artifact_inputs_dropped_by_declaration_change",
        "{updated:#}"
    );
    assert_eq!(
        updated["artifact_input_continuity"]["dropped_binding_count"],
        1
    );
    assert_eq!(
        updated["artifact_input_continuity"]["dropped_grant_count"],
        1
    );
    assert_eq!(
        updated["artifact_input_continuity"]["restoration_tools"],
        json!(["manage_artifact_inputs", "manage_artifact_module_grants"])
    );
    let bindings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM artifact_inputs WHERE artifact_id=?")
            .bind(ARTIFACT)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let grants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!((bindings, grants), (0, 0));
    assert!(native_ce::conformance::run_conformance(&db).await.ok);
}

#[tokio::test]
async fn a_v2_body_edit_without_an_exact_snapshot_reports_no_existing_state() {
    let (db, registry, digest, _guard) = fixture().await;
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DELETE FROM artifact_module_grants WHERE artifact_id=?")
        .bind(ARTIFACT)
        .execute(&write_pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM artifact_inputs WHERE artifact_id=?")
        .bind(ARTIFACT)
        .execute(&write_pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM artifact_source_attestations WHERE artifact_id=?")
        .bind(ARTIFACT)
        .execute(&write_pool)
        .await
        .unwrap();

    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": artifact_source("No prior snapshot"),
                "if_body_digest": digest,
                "reason": "Exercise a legacy v2 source without exact projected input state." }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_no_existing_state",
        "{updated:#}"
    );
    assert_eq!(updated["warnings"].as_array().unwrap().len(), 1);
    assert!(updated["artifact_input_continuity"]["old_declaration_surface_sha256"].is_string());
    assert!(updated["artifact_input_continuity"]["new_declaration_surface_sha256"].is_string());
}

#[tokio::test]
async fn carry_events_cannot_skip_an_incompatible_intervening_revision() {
    let (db, registry, digest, _guard) = fixture().await;
    let compatible = artifact_source("Compatible A prime");
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": compatible, "if_body_digest": digest,
                "reason": "Create stale compatible state for the forgery fixture." }),
    )
    .await;
    let stale_binding = sqlx::query(
        "SELECT collection_id,artifact_source_attestation_event_id,artifact_source_event_id,
                artifact_source_sha256,event_seq FROM artifact_inputs
          WHERE artifact_id=? AND port_name='orders'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let old_collection: String = stale_binding.get("collection_id");
    let old_attestation: String = stale_binding.get("artifact_source_attestation_event_id");
    let old_source_event: String = stale_binding.get("artifact_source_event_id");
    let old_source_sha: String = stale_binding.get("artifact_source_sha256");
    let old_binding_seq: i64 = stale_binding.get("event_seq");
    let stale_grant = sqlx::query(
        "SELECT subject_kind,subject_record_id,subject_event_id,source_sha256,capability,
                scope_sha256,scope,event_seq FROM artifact_module_grants
          WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let old_subject_kind: String = stale_grant.get("subject_kind");
    let old_subject_record: String = stale_grant.get("subject_record_id");
    let old_subject_event: String = stale_grant.get("subject_event_id");
    let old_subject_sha: String = stale_grant.get("source_sha256");
    let old_capability: String = stale_grant.get("capability");
    let old_scope_sha: String = stale_grant.get("scope_sha256");
    let old_scope_text: String = stale_grant.get("scope");
    let old_grant_seq: i64 = stale_grant.get("event_seq");

    let incompatible =
        artifact_source("Incompatible B").replace("required: true", "required: false");
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": incompatible,
                "if_body_digest": digest_of(&compatible),
                "reason": "Insert an incompatible declaration revision." }),
    )
    .await;
    let restored = artifact_source("Compatible-looking A double prime");
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": restored,
                "if_body_digest": digest_of(&incompatible),
                "reason": "Return to the original declaration surface." }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "orders",
                "collection_id": COLLECTION }),
    )
    .await;
    grant_input_read(&registry, &db).await;
    let new_binding: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>(
            "SELECT payload FROM content_events WHERE record_id=? AND type='artifact.input_bound'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(ARTIFACT)
        .fetch_one(db.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    let new_grant: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>(
            "SELECT payload FROM content_events WHERE record_id=? AND type='artifact.module_grant_set'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(ARTIFACT)
        .fetch_one(db.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    let new_attestation = new_binding["artifact_source_attestation_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let new_source_event = new_binding["artifact_source_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let old_descriptor: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>(
            "SELECT descriptor FROM artifact_source_attestations WHERE attestation_event_id=?",
        )
        .bind(&old_attestation)
        .fetch_one(db.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    let new_descriptor: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>(
            "SELECT descriptor FROM artifact_source_attestations WHERE attestation_event_id=?",
        )
        .bind(&new_attestation)
        .fetch_one(db.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    let old_surface = canonical_digest(&old_descriptor["artifact_ports"]);
    let new_surface = canonical_digest(&new_descriptor["artifact_ports"]);
    assert_eq!(old_surface, new_surface);

    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "UPDATE artifact_inputs SET collection_id=?,artifact_source_attestation_event_id=?,
                artifact_source_event_id=?,artifact_source_sha256=?,event_seq=?
          WHERE artifact_id=? AND port_name='orders'",
    )
    .bind(&old_collection)
    .bind(&old_attestation)
    .bind(&old_source_event)
    .bind(&old_source_sha)
    .bind(old_binding_seq)
    .bind(ARTIFACT)
    .execute(&write_pool)
    .await
    .unwrap();
    sqlx::query(
        "DELETE FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT)
    .execute(&write_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO artifact_module_grants
          (artifact_id,subject_kind,subject_record_id,subject_event_id,source_sha256,
           artifact_source_attestation_event_id,artifact_source_event_id,artifact_source_sha256,
           capability,scope_sha256,scope,event_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(ARTIFACT)
    .bind(&old_subject_kind)
    .bind(&old_subject_record)
    .bind(&old_subject_event)
    .bind(&old_subject_sha)
    .bind(&old_attestation)
    .bind(&old_source_event)
    .bind(&old_source_sha)
    .bind(&old_capability)
    .bind(&old_scope_sha)
    .bind(&old_scope_text)
    .bind(old_grant_seq)
    .execute(&write_pool)
    .await
    .unwrap();

    let predecessor = json!({
        "artifact_id": ARTIFACT,
        "subject_kind": old_subject_kind,
        "subject_record_id": old_subject_record,
        "subject_event_id": old_subject_event,
        "source_sha256": old_subject_sha,
        "capability": old_capability,
        "scope": serde_json::from_str::<Value>(&old_scope_text).unwrap(),
        "scope_sha256": old_scope_sha,
    });
    let input_carry = json!({
        "binding": new_binding,
        "predecessor_binding_event_seq": old_binding_seq,
        "predecessor_source_attestation_event_id": old_attestation,
        "predecessor_source_event_id": old_source_event,
        "predecessor_source_sha256": old_source_sha,
        "old_declaration_surface_sha256": old_surface,
        "new_declaration_surface_sha256": new_surface,
    });
    let grant_carry = json!({
        "grant": new_grant,
        "predecessor": predecessor,
        "predecessor_grant_event_seq": old_grant_seq,
        "predecessor_source_attestation_event_id": input_carry["predecessor_source_attestation_event_id"],
        "predecessor_source_event_id": input_carry["predecessor_source_event_id"],
        "predecessor_source_sha256": input_carry["predecessor_source_sha256"],
        "old_declaration_surface_sha256": input_carry["old_declaration_surface_sha256"],
        "new_declaration_surface_sha256": input_carry["new_declaration_surface_sha256"],
    });
    let seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let created_at: String = sqlx::query_scalar(
        "SELECT created_at FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    for (event_type, payload, expected) in [
        ("artifact.input_carried", input_carry, "adjacent"),
        (
            "artifact.module_grant_carried",
            grant_carry.clone(),
            "adjacent",
        ),
        (
            "artifact.module_grant_carried",
            {
                let mut forged = grant_carry.clone();
                forged["predecessor_grant_event_seq"] = json!(old_grant_seq + 1);
                forged
            },
            "predecessor",
        ),
        (
            "artifact.module_grant_carried",
            {
                let mut forged = grant_carry;
                forged["grant"]["scope"]["artifact_port"] = json!("invented");
                forged["predecessor"]["scope"]["artifact_port"] = json!("invented");
                forged
            },
            "broadens",
        ),
    ] {
        let event = native_ce::events::EventRow {
            local_seq: seq + 100,
            id: uuid::Uuid::new_v4().to_string(),
            record_id: ARTIFACT.into(),
            event_type: event_type.into(),
            payload: Some(payload.to_string()),
            actor: Some("test:forged-carry".into()),
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: created_at.clone(),
            causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
        };
        let mut conn = crate::common::fixture_write_pool(&db)
            .await
            .acquire()
            .await
            .unwrap();
        let error = native_ce::projector::project(&mut conn, &event)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "expected {expected}: {error}");
    }
    assert_ne!(new_source_event, old_source_event);
}

#[tokio::test]
async fn an_entry_absent_from_the_declared_manifest_is_refused() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("archive_everything", &digest, "k-6");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "unknown_entry");
}

#[tokio::test]
async fn an_open_facet_that_moved_underneath_conflicts_instead_of_overwriting() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("mark_triaged", &digest, "k-7");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    assert_eq!(
        call(&registry, &db, "invoke_artifact_interaction", first).await["status"],
        "committed"
    );
    let stale_precondition = observed(&registry, &db, INSIDE, "triage").await;

    // Somebody else moves the same facet under the artifact's feet.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "blocked" },
                "reason": "Concurrent write from another surface." }),
    )
    .await;
    let conflicting_event: (String, Option<String>) = sqlx::query_as(
        "SELECT id,actor FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.key')='triage' ORDER BY seq DESC LIMIT 1",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    // Later activity on the same record must not relabel the facet conflict.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "summary": "Later unrelated activity",
                "reason": "Prove attribution follows the facet event, not latest history." }),
    )
    .await;

    let mut stale = envelope("set_triage", &digest, "k-8");
    stale["slots"] = json!({ "record": INSIDE });
    stale["values"] = json!({ "choice": "triaged" });
    stale["observed"] = stale_precondition.clone();
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict");
    assert!(conflict["error"]["retryable"].as_bool().unwrap());
    assert_eq!(conflict["conflicting_event_id"], conflicting_event.0);
    assert_eq!(
        conflict["competing_actor"]["id"],
        conflicting_event.1.unwrap()
    );
    assert!(conflict["competing_actor"].get("display_name").is_none());
    let current = conflict["current_version"].as_str().unwrap();
    assert!(
        current.starts_with("obs:")
            && json!({ INSIDE: { "triage": current } }) != stale_precondition,
        "{current}"
    );
    // The concurrent value survives — a conflict never overwrites.
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "blocked"
    );

    // Retried against what the host reported, the same entry commits.
    let mut retry = envelope("set_triage", &digest, "k-9");
    retry["slots"] = json!({ "record": INSIDE });
    retry["values"] = json!({ "choice": "triaged" });
    retry["observed"] = json!({ INSIDE: { "triage": current } });
    let committed = call(&registry, &db, "invoke_artifact_interaction", retry).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
}

#[tokio::test]
async fn conflict_omits_an_actor_the_caller_may_not_identify() {
    let (db, registry, digest, _guard) = fixture().await;
    replace_explicit_policy(
        &db,
        "test:artifact-interaction-conflict-disclosure",
        INSIDE,
        vec![AllowEntry::account("acct:vic", Capability::Edit)],
    )
    .await
    .unwrap();
    let stale_precondition = observed(&registry, &db, INSIDE, "triage").await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "blocked" },
                "reason": "Create a conflict owned by a hidden actor." }),
    )
    .await;
    let event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.key')='triage' ORDER BY seq DESC LIMIT 1",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();

    let mut stale = envelope("set_triage", &digest, "k-hidden-actor");
    stale["slots"] = json!({ "record": INSIDE });
    stale["values"] = json!({ "choice": "triaged" });
    stale["observed"] = stale_precondition;
    let vic = Caller::authenticated("acct:vic")
        .with_hosting_context("host:vic", "db:test")
        .with_hosting_owner(false);
    let conflict = call_as(&registry, &db, vic, "invoke_artifact_interaction", stale)
        .await
        .unwrap();
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["conflicting_event_id"], event_id);
    assert!(
        conflict.get("competing_actor").is_none(),
        "the exact event remains available without leaking its hidden actor: {conflict:#}"
    );
}

#[tokio::test]
async fn a_spine_facet_conflicts_at_record_level_and_that_difference_is_intended() {
    let (db, registry, digest, _guard) = fixture().await;
    // A spine facet NEVER produces an observation row: the projector updates
    // the `records` column and returns. So there is no per-facet version to
    // compare, and record-level is not a shortfall — it is the granularity at
    // which a spine facet actually moves.
    let observations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM facet_observations WHERE record_id=? AND key='lifecycle'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(observations, 0);

    let mut invocation = envelope("start_work", &digest, "k-10");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["after"], "in_progress");
    let record = call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await;
    assert_eq!(
        record["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "in_progress"
    );
    // It moved as a record.updated field event, exactly as every other spine
    // change in the engine does — no tool emits facet.set for a spine key.
    let spine_facet_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.key')='lifecycle'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(spine_facet_events, 0);
    let updates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.updated'
          AND json_extract(payload,'$.origin.entry_id')='start_work'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(updates, 1);

    // And the intended difference: an UNRELATED record-level change invalidates
    // a spine precondition, because record-level is the width of the token.
    let stale_token = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "summary": "Touched by another surface",
                "reason": "Move the record without touching lifecycle." }),
    )
    .await;
    let conflicting_event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let mut stale = envelope("start_work", &digest, "k-11");
    stale["slots"] = json!({ "record": INSIDE });
    stale["observed"] = stale_token;
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert!(conflict["current_version"]
        .as_str()
        .unwrap()
        .starts_with("rec:"));
    assert_eq!(conflict["conflicting_event_id"], conflicting_event_id);

    // An open facet on the same record is unaffected by that record-level
    // movement — the two mechanisms are separate on purpose.
    let mut open = envelope("mark_triaged", &digest, "k-12");
    open["slots"] = json!({ "record": INSIDE });
    open["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", open).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
}

#[tokio::test]
async fn a_spine_value_is_judged_by_the_same_governance_as_an_open_one() {
    let (db, registry, digest, _guard) = fixture().await;
    // A spine facet leaves as `record.updated`, so it never reaches
    // `facet_set_spec` — but it carries the same governing vocabulary and the
    // same declared `values` set as any other key, and `update_record` refuses
    // an out-of-vocabulary spine value through exactly this helper. Nothing
    // downstream would catch it: `records.lifecycle` has no DDL CHECK and the
    // projector deliberately does not validate spine values.
    //
    // No schema configuration is needed for this arm: the shipped pack already governs
    // `lifecycle` on `WorkItem:task` with the `lifecycle` vocabulary.
    let mut outside_vocabulary = envelope("stall", &digest, "k-spine-vocab");
    outside_vocabulary["slots"] = json!({ "record": INSIDE });
    outside_vocabulary["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let refused = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        outside_vocabulary,
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "schema_violation", "{refused:#}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("governing vocabulary"),
        "{refused:#}"
    );
    let record = call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await;
    // Untouched: a task is born `open`, and the refusal left it there.
    assert_eq!(
        record["records"][0]["lifecycle_interpretation"]["value"]["canonical"], "open",
        "{record:#}"
    );
    assert!(
        record["records"][0].get("lifecycle").is_none(),
        "{record:#}"
    );

    // The declared `values` set is a separate branch of the same helper. The
    // user layer may not loosen a spine facet the pack governs, so the shape
    // restates `required` and the vocabulary while it narrows the set.
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": { "WorkItem:task": { "facets": {
            "lifecycle": { "required": true, "vocab": "lifecycle", "values": ["open", "blocked"],
                "axis": { "key": "work_status", "label": "Work status" } }
        } } } } }),
    )
    .await;
    let mut outside_set = envelope("start_work", &digest, "k-spine-values");
    outside_set["slots"] = json!({ "record": INSIDE });
    outside_set["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", outside_set).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "schema_violation", "{refused:#}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("values set"),
        "{refused:#}"
    );

    // A declared member commits, so the refusals above are governance biting
    // rather than spine writes being broken.
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": { "WorkItem:task": { "facets": {
            "lifecycle": { "required": true, "vocab": "lifecycle",
                           "axis": { "key": "work_status", "label": "Work status" },
                           "values": ["open", "in_progress"] }
        } } } } }),
    )
    .await;
    let mut inside_set = envelope("start_work", &digest, "k-spine-ok");
    inside_set["slots"] = json!({ "record": INSIDE });
    inside_set["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", inside_set).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(
        call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await["records"][0]
            ["lifecycle_interpretation"]["value"]["canonical"],
        "in_progress"
    );
}

#[tokio::test]
async fn an_unset_entry_clears_the_facet_it_declared() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut set = envelope("mark_triaged", &digest, "k-13");
    set["slots"] = json!({ "record": INSIDE });
    set["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    call(&registry, &db, "invoke_artifact_interaction", set).await;
    let mut unset = envelope("clear_triage", &digest, "k-14");
    unset["slots"] = json!({ "record": INSIDE });
    unset["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let cleared = call(&registry, &db, "invoke_artifact_interaction", unset).await;
    assert_eq!(cleared["status"], "committed", "{cleared:#}");
    assert_eq!(cleared["changes"][0]["before"], "triaged");
    assert!(cleared["changes"][0]["after"].is_null());
    assert!(facet_of(&registry, &db, INSIDE, "triage").await.is_none());
}

/// A second artifact whose only entry clears the facet the schema requires.
fn clearing_artifact() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "orders" } }],
  interactions: [
    { id: "clear_effort", label: "Clear effort", effect: "facet.unset",
      slots: { record: { domain: { kind: "bound_input" } } },
      facet: "effort" }
  ]
}

<Metric label="Clear" value={1} />
"#
    .to_string()
}

/// The commit hands back the version token its OWN write left, so the next
/// compare-and-set — an undo, a correction, a reversal after the record has
/// left the artifact's bound query — has a precondition to quote without
/// re-reading. Re-reading is not an alternative: a read after the gesture can
/// observe somebody else's edit and then authorize overwriting it, which is
/// what the precondition exists to prevent.
#[tokio::test]
async fn a_committed_open_facet_change_carries_the_token_its_own_write_left() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("mark_triaged", &digest, "k-token-open-1");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first.clone()).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let token = committed["changes"][0]["version"]
        .as_str()
        .expect("a committed change carries the version it produced")
        .to_owned();
    // Open facets version by observation, and in the SAME encoding the read
    // path hands out — otherwise the token could not be quoted back.
    assert!(token.starts_with("obs:"), "{token}");
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["version"],
        token.as_str()
    );

    // A replay commits nothing, so it reports the token the original append
    // left rather than re-reading state it did not produce.
    let replay = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(replay["changes"][0]["version"], token.as_str());

    // The property the feature needs: the returned token is accepted as the
    // precondition of the immediately following invocation on the same facet.
    let mut second = envelope("set_triage", &digest, "k-token-open-2");
    second["slots"] = json!({ "record": INSIDE });
    second["values"] = json!({ "choice": "blocked" });
    second["observed"] = json!({ INSIDE: { "triage": token } });
    let second = call(&registry, &db, "invoke_artifact_interaction", second).await;
    assert_eq!(second["status"], "committed", "{second:#}");
    let second_token = second["changes"][0]["version"]
        .as_str()
        .expect("the second commit issues its own token")
        .to_owned();
    assert_ne!(second_token, token, "the token moved with the write");

    // And it is a real precondition, not a rubber stamp: a competing write
    // between the two invocations conflicts instead of overwriting.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "triaged" },
                "reason": "Concurrent write from another surface." }),
    )
    .await;
    let mut stale = envelope("set_triage", &digest, "k-token-open-3");
    stale["slots"] = json!({ "record": INSIDE });
    stale["values"] = json!({ "choice": "blocked" });
    stale["observed"] = json!({ INSIDE: { "triage": second_token } });
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict");
    // The competing value survives untouched.
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "triaged"
    );
}

/// The same guarantee for a spine facet, at the granularity a spine facet
/// actually moves at. The two mechanisms stay separate: a spine write leaves a
/// record token (`rec:`), never an observation token, because it never writes
/// an observation row.
#[tokio::test]
async fn a_committed_spine_change_carries_the_record_token_its_own_write_left() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("start_work", &digest, "k-token-spine-1");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let token = committed["changes"][0]["version"]
        .as_str()
        .expect("a committed spine change carries the version it produced")
        .to_owned();
    assert!(token.starts_with("rec:"), "{token}");
    assert_eq!(record_version(&registry, &db, INSIDE).await, token);
    // No observation row was written, so this token could only have come from
    // the record mechanism.
    let observations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM facet_observations WHERE record_id=? AND key='lifecycle'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(observations, 0);

    // Accepted as the precondition of the next invocation on the same facet.
    let mut second = envelope("start_work", &digest, "k-token-spine-2");
    second["slots"] = json!({ "record": INSIDE });
    second["observed"] = json!({ INSIDE: { "lifecycle": token } });
    let second = call(&registry, &db, "invoke_artifact_interaction", second).await;
    assert_eq!(second["status"], "committed", "{second:#}");
    let second_token = second["changes"][0]["version"]
        .as_str()
        .expect("the second spine commit issues its own token")
        .to_owned();
    assert_ne!(second_token, token);

    // A competing write to the record between the two invocations conflicts.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "lifecycle": "blocked",
                "summary": "Concurrent activity from another surface",
                "reason": "Move the record token underneath the artifact." }),
    )
    .await;
    let mut stale = envelope("start_work", &digest, "k-token-spine-3");
    stale["slots"] = json!({ "record": INSIDE });
    stale["observed"] = json!({ INSIDE: { "lifecycle": second_token } });
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict");
    let current = conflict["current_version"].as_str().unwrap();
    assert!(current.starts_with("rec:"), "{current}");
    assert_ne!(current, second_token);
    // The competing value survives untouched — a conflict never overwrites.
    // The open-facet sibling above asserts this; a spine facet needs it just as
    // much, and at record granularity it is the whole difference between a
    // refused stale token and a silent revert to `in_progress`.
    let record = call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await;
    assert_eq!(
        record["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "blocked"
    );
}

/// The security property the replay branch of `commit_declared_write` exists
/// to defend, held rather than merely commented.
///
/// A replayed invocation commits nothing, so it reports the token the ORIGINAL
/// append left — deliberately NOT a fresh read, because a fresh read after the
/// gesture could hand back a token minted by somebody else's later edit, and
/// the caller would then quote it to overwrite an edit it never saw. The cost
/// of that choice is that the replay's token is STALE once the facet has moved,
/// and the guarantee is that a stale token authorizes nothing.
#[tokio::test]
async fn a_replayed_open_facet_token_cannot_authorize_overwriting_a_competing_edit() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("mark_triaged", &digest, "k-replay-open-1");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first.clone()).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let original_token = committed["changes"][0]["version"]
        .as_str()
        .expect("a committed change carries the version it produced")
        .to_owned();

    // Somebody else moves the same facet before the replay arrives.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "facets": { "triage": "blocked" },
                "reason": "Concurrent write from another surface." }),
    )
    .await;
    let competing_token = facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["version"]
        .as_str()
        .expect("get_record issues a facet version")
        .to_owned();
    assert_ne!(competing_token, original_token, "the facet really moved");

    // The replay reports the ORIGINAL write's token, now stale, and never the
    // competing writer's — minting that one is exactly the failure this branch
    // refuses to commit.
    let replay = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(replay["changes"][0]["version"], original_token.as_str());
    assert_ne!(replay["changes"][0]["version"], competing_token.as_str());
    // `after` and `version` describe different instants on purpose: the state
    // is read now (the competing value), the token names the original write.
    assert_eq!(replay["changes"][0]["after"], "blocked");
    // And it committed nothing: one append still carries that key.
    let writes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='facet.set'
          AND json_extract(payload,'$.origin.idempotency_key')='k-replay-open-1'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(writes, 1, "a replay commits nothing");

    // The property. Quoting the replay's token back authorizes nothing.
    let mut stale = envelope("set_triage", &digest, "k-replay-open-2");
    stale["slots"] = json!({ "record": INSIDE });
    stale["values"] = json!({ "choice": "triaged" });
    stale["observed"] = json!({ INSIDE: { "triage": original_token } });
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict");
    assert_eq!(conflict["current_version"], competing_token.as_str());
    // The competing value survives intact.
    assert_eq!(
        facet_of(&registry, &db, INSIDE, "triage").await.unwrap()["value"],
        "blocked"
    );
}

/// The same property for a spine facet, whose replay token is reconstructed as
/// `FacetVersion::Record` instead. Record granularity makes the stale window
/// WIDER, not narrower — any event on the record invalidates the token — so the
/// guarantee has to hold here too, and it is the branch with no other coverage.
#[tokio::test]
async fn a_replayed_spine_token_cannot_authorize_overwriting_a_competing_edit() {
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("start_work", &digest, "k-replay-spine-1");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed_spine(&registry, &db, INSIDE, "lifecycle").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first.clone()).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let original_token = committed["changes"][0]["version"]
        .as_str()
        .expect("a committed spine change carries the version it produced")
        .to_owned();
    assert!(original_token.starts_with("rec:"), "{original_token}");

    // Somebody else moves the same spine facet before the replay arrives.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": INSIDE, "lifecycle": "blocked",
                "reason": "Concurrent write from another surface." }),
    )
    .await;
    let competing_token = record_version(&registry, &db, INSIDE).await;
    assert_ne!(competing_token, original_token, "the record really moved");

    // The replay reconstructs the ORIGINAL append's record token — in the
    // `rec:` encoding a spine facet is versioned at, never `obs:` — rather than
    // re-reading the record and handing back the competing writer's token.
    let replay = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    let replayed_token = replay["changes"][0]["version"]
        .as_str()
        .expect("a replayed spine change carries a version")
        .to_owned();
    assert_eq!(replayed_token, original_token);
    assert_ne!(replayed_token, competing_token);
    // Different instants again: the state is the competing value read now.
    assert_eq!(replay["changes"][0]["after"], "blocked");
    let updates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.updated'
          AND json_extract(payload,'$.origin.idempotency_key')='k-replay-spine-1'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(updates, 1, "a replay commits nothing");

    // The property, at record granularity.
    let mut stale = envelope("start_work", &digest, "k-replay-spine-2");
    stale["slots"] = json!({ "record": INSIDE });
    stale["observed"] = json!({ INSIDE: { "lifecycle": replayed_token } });
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict");
    assert_eq!(conflict["current_version"], competing_token.as_str());
    // The competing lifecycle survives intact: no silent revert to
    // `in_progress` on the strength of a token from before it landed.
    let record = call(&registry, &db, "get_record", json!({ "ids": [INSIDE] })).await;
    assert_eq!(
        record["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "blocked"
    );
}
