//! Host-mediated artifact interactions: a `native.mdx.v2` artifact invokes an
//! entry it DECLARED, and the host decides everything else.
//!
//! Each test here is one refusal or one commitment from the validation order in
//! `src/mcp/tools/artifact_interactions.rs`, exercised end to end through the
//! MCP tool surface rather than against the handler directly.

use std::sync::{Arc, OnceLock};

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::schema::{ROOT_RECORD_ID, UNFILED_RECORD_ID};
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
const COMMENT_PERSON: &str = "0a5e0000-0000-4000-8000-000000000011";
const COMMENT_SEED_ARTIFACT: &str = "0a5e0000-0000-4000-8000-000000000012";
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

/// A real MDX artifact whose single cited entry is a `comment.create`
/// declaration. Public activation is deliberately absent, so every invocation
/// of this entry must refuse without writing.
fn comment_artifact_source(entry_id: &str) -> String {
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "orders" }} }}],
  interactions: [{{ id: {entry_id:?}, label: "Post", effect: "comment.create",
    slots: {{ bearer: {{ domain: {{ kind: "bound_input", port: "orders" }} }} }},
    comment: {{ position: "root", body: {{ input: "text", max_bytes: 100 }} }} }}]
}}

<Metric label="Total" value={{1}} />
"#
    )
}

/// A real MDX artifact whose single cited entry is a `message.react`
/// declaration (task `07ae879` I1, declaration only). Every invocation of
/// this entry must refuse without writing until I2 lands the path.
fn react_artifact_source(entry_id: &str) -> String {
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "orders" }} }}],
  interactions: [{{ id: {entry_id:?}, label: "React", effect: "message.react",
    slots: {{ message: {{ domain: {{ kind: "bound_input", port: "orders" }} }} }},
    react: {{ emoji: ["👍"] }} }}]
}}

<Metric label="Total" value={{1}} />
"#
    )
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
    fixture_with_source(artifact_source("Orders"), "native.mdx.v2").await
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

async fn fixture_with_source(
    source: String,
    runtime: &str,
) -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Triage board",
            "body": source, "facets": { "runtime": runtime },
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

#[tokio::test]
async fn html_interactions_share_scope_domains_cas_replay_attribution_and_host_plan() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let source = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, digest, _guard) = fixture_with_source(source, "native.html.v1").await;
    let rendered = call(&registry, &db, "render_artifact", json!({"id":ARTIFACT})).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(rendered["plan"]["kind"], "isolated_html");
    assert_eq!(rendered["plan"]["body_digest"], digest);
    assert_eq!(rendered["plan"]["observed"][INSIDE]["triage"], "obs:0");
    assert!(rendered["plan"]["observed"].get(OUTSIDE).is_none());
    assert!(
        rendered["plan"]["interaction_availability"]["supported_entries"]
            .as_array()
            .unwrap()
            .contains(&json!("set_triage"))
    );
    assert!(rendered["input"].get("observed").is_none());
    assert!(rendered["input"].get("interactions").is_none());
    let descriptor: String = sqlx::query_scalar(
        "SELECT descriptor FROM artifact_source_attestations WHERE artifact_id=?",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let descriptor: Value = serde_json::from_str(&descriptor).unwrap();
    assert_eq!(descriptor["interactions"], rendered["plan"]["interactions"]);
    let invocation = json!({"version":INVOCATION_VERSION,"artifact_id":ARTIFACT,
        "entry_id":"set_triage","source_digest":digest,"slots":{"record":INSIDE},
        "values":{"choice":"triaged"},"observed":{INSIDE:{"triage":"obs:0"}},
        "idempotency_key":"html:one"});
    replace_explicit_policy(
        &db,
        "test:html-caller",
        INSIDE,
        vec![AllowEntry::account("acct:html-reader", Capability::View)],
    )
    .await
    .unwrap();
    let reader = Caller::authenticated("acct:html-reader")
        .with_hosting_context("host:html-reader", "db:test")
        .with_hosting_owner(false);
    let refused = call_as(
        &registry,
        &db,
        reader,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied", "{refused:#}");
    for (patch, expected) in [
        (
            json!({"slots":{"record":OUTSIDE},"observed":{}}),
            "record_outside_binding",
        ),
        (
            json!({"values":{"choice":"forged"}}),
            "value_outside_domain",
        ),
        (
            json!({"source_digest":"0".repeat(64)}),
            "stale_source_digest",
        ),
        (json!({"entry_id":"undeclared"}), "unknown_entry"),
    ] {
        let mut invalid = invocation.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let result = call(&registry, &db, "invoke_artifact_interaction", invalid).await;
        assert_eq!(result["status"], "rejected", "{result:#}");
        assert_eq!(result["error"]["code"], expected, "{result:#}");
    }
    let first = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let replay = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        replay["changes"][0]["version"],
        first["changes"][0]["version"]
    );
    let mut stale = invocation.clone();
    stale["idempotency_key"] = json!("html:two");
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='facet.set' AND json_extract(payload,'$.origin.artifact_id')=?")
        .bind(INSIDE).bind(ARTIFACT).fetch_one(db.pool()).await.unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["origin"]["source_digest"], digest);
    assert_eq!(payload["origin"]["entry_id"], "set_triage");
    let subjects = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({"action":"read","artifact_id":ARTIFACT}),
    )
    .await;
    let subject = &subjects["subjects"][0];
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action":"revoke","artifact_id":ARTIFACT,"subject_kind":"artifact_source",
            "subject_record_id":ARTIFACT,"subject_event_id":subject["subject_event_id"],
            "source_sha256":subject["source_sha256"],"capability":"input.read",
            "scope":{"artifact_port":"orders"}
        }),
    )
    .await;
    let denied = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(denied["status"], "rejected", "{denied:#}");
    assert_eq!(
        denied["error"]["code"], "module_capability_denied",
        "{denied:#}"
    );
}

async fn create_fixture() -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    create_fixture_with_source(create_artifact_source(), "native.mdx.v2").await
}

async fn create_fixture_with_source(
    source: String,
    runtime: &str,
) -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Creation board",
            "body": source, "facets": { "runtime": runtime },
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

#[tokio::test]
async fn html_interactions_record_create_is_governed_and_idempotent() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let source = html_interaction_source(&create_artifact_source());
    let (db, registry, digest, _guard) = create_fixture_with_source(source, "native.html.v1").await;
    let rendered = call(&registry, &db, "render_artifact", json!({"id":ARTIFACT})).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let availability = &rendered["plan"]["interaction_availability"];
    assert_eq!(
        availability["create_destinations"]["create_task"],
        COLLECTION
    );
    assert_eq!(
        availability["record_labels"][COLLECTION]["name"],
        "Created here"
    );
    assert!(!rendered["input"]
        .to_string()
        .contains("create_destinations"));
    assert!(!rendered["input"].to_string().contains("record_labels"));
    let invocation = json!({"version":INVOCATION_VERSION,"artifact_id":ARTIFACT,
        "entry_id":"create_task","source_digest":digest,
        "values":{"title":"Created from HTML","triage":"ready"},"idempotency_key":"html:create"});
    let first = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(first["status"], "committed", "{first:#}");
    assert_eq!(first["refresh"]["record"]["home_id"], COLLECTION);
    let replay = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        replay["refresh"]["record"]["id"],
        first["refresh"]["record"]["id"]
    );
    assert_eq!(replay["refresh"]["record"]["idempotent_retry"], true);
}

/// An HTML creation into its own bound input with the flag set refreshes the
/// created record, the post-write plan, and the input that plan was rendered
/// over — so the caller can synthesise a settled result and continue in place
/// without a second `render_artifact`. The digest always moves here: the new
/// row IS the changed input.
#[tokio::test]
async fn html_creation_with_the_flag_set_refreshes_record_plan_and_input() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let source = html_interaction_source(&create_artifact_source());
    let (db, registry, digest, _guard) = create_fixture_with_source(source, "native.html.v1").await;
    let before = call(&registry, &db, "render_artifact", json!({"id":ARTIFACT})).await;
    assert_eq!(before["status"], "rendered", "{before:#}");
    let committed = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_task",
            "source_digest": digest,
            "values": { "title": "Bonus input row", "triage": "ready" },
            "idempotency_key": "html:create:bonus-input",
            "gesture": "submit",
            "include_next_plan": true,
        }),
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let created_id = committed["refresh"]["record"]["id"]
        .as_str()
        .expect("a creation refreshes its record");
    let plan = &committed["refresh"]["plan"];
    assert_eq!(plan["kind"], "isolated_html", "{committed:#}");
    let input_digest = committed["refresh"]["input_digest"]
        .as_str()
        .expect("the bonus carries the digest the plan was rendered over");
    assert_ne!(
        input_digest,
        before["input_digest"].as_str().unwrap(),
        "the new row moves the digest: {committed:#}"
    );
    let input = &committed["refresh"]["input"];
    assert!(input.is_object(), "{committed:#}");
    assert!(
        input.to_string().contains(created_id),
        "the bonus input already holds the created row: {committed:#}"
    );
    // No launch rides along: a creation never changes the body, so the
    // caller continues in place on its live launch.
    assert!(
        committed["refresh"].get("launch").is_none(),
        "{committed:#}"
    );
    // And the bonus agrees with what a separate render would hand out, so
    // the caller can skip that second round trip.
    let after = call(&registry, &db, "render_artifact", json!({"id":ARTIFACT})).await;
    assert_eq!(after["status"], "rendered", "{after:#}");
    assert_eq!(after["input_digest"].as_str().unwrap(), input_digest);
    assert_eq!(
        after["plan"]["observed"].to_string(),
        plan["observed"].to_string(),
        "{after:#}"
    );
}

#[tokio::test]
async fn html_interactions_attestation_replay_rejects_forged_or_omitted_entries() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, _registry, _digest, _guard) = fixture_with_source(
        html_interaction_source(&artifact_source("Orders")),
        "native.html.v1",
    )
    .await;
    let descriptor: String = sqlx::query_scalar(
        "SELECT descriptor FROM artifact_source_attestations WHERE artifact_id=?",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let descriptor: Value = serde_json::from_str(&descriptor).unwrap();
    let seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for omit in [false, true] {
        let mut descriptor = descriptor.clone();
        let event_id = "daaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        descriptor["attestation_event_id"] = json!(event_id);
        if omit {
            descriptor.as_object_mut().unwrap().remove("interactions");
        } else {
            descriptor["interactions"][0]["value"]["value"] = json!("forged");
        }
        let digest = hex::encode(Sha256::digest(
            native_artifact_runtime::mdx_v2::canonical_json_bytes(&descriptor),
        ));
        let event = native_ce::events::EventRow {
            local_seq: seq + 1,
            id: event_id.into(),
            record_id: ARTIFACT.into(),
            event_type: "artifact.source_attested".into(),
            payload: Some(
                json!({"artifact_source":descriptor,"attestation_sha256":digest}).to_string(),
            ),
            actor: Some("test".into()),
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-09-17T00:00:00Z".into(),
            causal_envelope: native_ce::events::CausalEnvelopeV1::complete(
                native_ce::events::CausalFrontierV1::empty(),
            ),
            act: None,
        };
        let mut conn = db.pool().acquire().await.unwrap();
        let error = native_ce::projector::project(&mut conn, &event)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("exact declaration surface"), "{error}");
    }
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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

/// A comment citation is classified from its actual immutable source and
/// refused publicly (`comment_unavailable`); it must never fall through to the
/// generic creation kernel or write anything.
///
/// Fixture note (setup-only repair, root session61376): uses the single-orders
/// `fixture_with_source` helper because this source declares only `orders`;
/// the dual-port `create_fixture_with_source` would bind an undeclared `refs`
/// port and fail before invoke.
#[tokio::test]
async fn a_declared_comment_entry_is_publicly_unavailable_without_writing() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let source = comment_artifact_source("post");
    let (db, registry, digest, _guard) = fixture_with_source(source, "native.mdx.v2").await;
    let rejected = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "post",
            "source_digest": digest,
            "slots": { "bearer": INSIDE },
            "values": { "text": "hello" },
            "idempotency_key": "comment:unavailable",
            "gesture": "submit"
        }),
    )
    .await;
    assert_eq!(rejected["status"], "rejected", "{rejected:#}");
    assert_eq!(
        rejected["error"]["code"], "comment_unavailable",
        "{rejected:#}"
    );
    let comments: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Annotation'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        comments, 0,
        "a refused comment writes nothing: {rejected:#}"
    );
}

/// A declared `message.react` entry is declaration-only (task `07ae879`
/// I1): invocation refuses publicly (`react_unavailable`) and writes
/// nothing, even with a well-formed desired-state payload.
#[tokio::test]
async fn a_declared_react_entry_is_publicly_unavailable_without_writing() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let source = react_artifact_source("react");
    let (db, registry, digest, _guard) = fixture_with_source(source, "native.mdx.v2").await;
    let rejected = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "react",
            "source_digest": digest,
            "slots": { "message": INSIDE },
            "values": { "emoji": "👍", "reacted": true },
            "idempotency_key": "react:unavailable",
            "gesture": "submit"
        }),
    )
    .await;
    assert_eq!(rejected["status"], "rejected", "{rejected:#}");
    assert_eq!(
        rejected["error"]["code"], "react_unavailable",
        "{rejected:#}"
    );
    let reactions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE type LIKE 'message.reaction.%'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(reactions, 0, "a refused react writes nothing: {rejected:#}");
}

#[tokio::test]
async fn record_create_rejects_out_of_domain_values_without_leaving_a_bearer() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let rendered = call_as(
        &registry,
        &db,
        caller.clone(),
        "render_artifact",
        json!({"id":ARTIFACT}),
    )
    .await
    .unwrap();
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let availability = &rendered["plan"]["interaction_availability"];
    assert!(availability.get("create_destinations").is_none());
    assert!(availability["record_labels"].get(COLLECTION).is_none());
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let availability = &rendered["plan"]["interaction_availability"];
    let destinations = availability["create_destinations"].as_object().unwrap();
    assert_eq!(destinations.len(), supported.len());
    assert!(destinations
        .values()
        .all(|destination| destination == COLLECTION));
    assert_eq!(
        availability["record_labels"][COLLECTION]["name"],
        "Created here"
    );
    assert!(destinations.get("create_comment").is_none());
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    // content_events is append-only by trigger; this corruption fixture drops
    // only the delete guard and restores the exact sqlite_master SQL on the
    // same connection around the deletion, before rendering continues.
    let fixture_pool = crate::common::fixture_write_pool(&db).await;
    let mut fixture = fixture_pool.acquire().await.unwrap();
    let delete_guard: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_events_no_delete'",
    )
    .fetch_one(&mut *fixture)
    .await
    .unwrap();
    sqlx::query("DROP TRIGGER content_events_no_delete")
        .execute(&mut *fixture)
        .await
        .unwrap();
    sqlx::query("DELETE FROM content_events WHERE record_id=?")
        .bind(second_inside)
        .execute(&mut *fixture)
        .await
        .unwrap();
    sqlx::query(&delete_guard)
        .execute(&mut *fixture)
        .await
        .unwrap();
    drop(fixture);

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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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

/// An artifact whose interactions write typed time facets (task fef3469):
/// an instant with an offset, and a value that is not a date.
fn typed_time_artifact_source() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "orders" } }],
  interactions: [
    { id: "log_now", label: "Log", effect: "facet.set",
      slots: { record: { domain: { kind: "bound_input", port: "orders" } } },
      facet: "logged_at", value: { from: "literal", value: "2026-10-05T10:00:00+01:00" } },
    { id: "due_someday", label: "Someday", effect: "facet.set",
      slots: { record: { domain: { kind: "bound_input", port: "orders" } } },
      facet: "due", value: { from: "literal", value: "someday" } }
  ]
}

<Metric label="Typed time" value={1} />
"#
    .into()
}

/// A tab effect writes typed time facets through the same governance as
/// every other writer: a declared `instant` is stored normalised to UTC,
/// carries `time_kind` into `facet_times`, and the receipt reports the
/// stored value; a value a declared `date` cannot hold is refused and
/// nothing is written.
#[tokio::test]
async fn a_declared_time_facet_written_by_an_interaction_is_normalised_or_refused() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) =
        fixture_with_source(typed_time_artifact_source(), "native.mdx.v2").await;
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": { "WorkItem:task": { "facets": {
            "logged_at": { "type": "instant" },
            "due": { "type": "date" },
        } } } } }),
    )
    .await;

    let mut log = envelope("log_now", &digest, "typed-1");
    log["slots"] = json!({ "record": INSIDE });
    log["observed"] = observed(&registry, &db, INSIDE, "logged_at").await;
    let result = call(&registry, &db, "invoke_artifact_interaction", log).await;
    assert_eq!(result["status"], "committed", "{result:#}");
    assert_eq!(result["changes"][0]["after"], "2026-10-05T09:00:00.000Z");
    let facet = facet_of(&registry, &db, INSIDE, "logged_at")
        .await
        .expect("the typed facet was written");
    assert_eq!(facet["value"], "2026-10-05T09:00:00.000Z");
    let (kind, start_ms): (String, Option<i64>) = sqlx::query_as(
        "SELECT kind, start_ms FROM facet_times WHERE record_id = ? AND key = 'logged_at'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(kind, "instant");
    assert_eq!(start_ms, Some(1_791_190_800_000));
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id = ? AND type = 'facet.set'
          AND json_extract(payload, '$.key') = 'logged_at'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["time_kind"], "instant");
    assert_eq!(payload["origin"]["entry_id"], "log_now");

    let mut due = envelope("due_someday", &digest, "typed-2");
    due["slots"] = json!({ "record": INSIDE });
    due["observed"] = observed(&registry, &db, INSIDE, "due").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", due).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "schema_violation", "{refused:#}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("declared type 'date'")),
        "{refused:#}"
    );
    assert!(facet_of(&registry, &db, INSIDE, "due").await.is_none());
}

#[tokio::test]
async fn the_commit_origin_still_names_artifact_entry_digest_key_and_gesture() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // The durable origin is the entire ground `6f99174` rests on: removing the
    // Apply step must not weaken it. One facet write's event payload must still
    // name the exact artifact, entry, source digest, idempotency key and
    // gesture that produced it, so what the frame displayed is reconstructable.
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "origin:one");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let result = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(result["status"], "committed", "{result:#}");

    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events
          WHERE record_id=? AND type='facet.set'
            AND json_extract(payload,'$.origin.idempotency_key')='origin:one'",
    )
    .bind(INSIDE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    let origin = &payload["origin"];
    assert_eq!(origin["artifact_id"], ARTIFACT);
    assert_eq!(origin["entry_id"], "mark_triaged");
    assert_eq!(origin["source_digest"], digest);
    assert_eq!(origin["idempotency_key"], "origin:one");
    assert_eq!(origin["gesture"], "click");
}

#[tokio::test]
async fn a_corrected_open_observation_keeps_its_old_token_authentic() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let precondition = observed(&registry, &db, INSIDE, "triage").await;
    let edited = artifact_source("Orders (revised)");
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body_set": edited, "if_body_digest": digest,
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
            act: None,
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
        updated["artifact_input_continuity"]["status"], "artifact_inputs_dropped",
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

/// Two bound ports plus a navigation grant: the per-port carry fixture.
fn two_port_nav_source(label: &str) -> String {
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{
    orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }},
    refs: {{ envelope: "native.collection-envelope.v1", required: false, expose_to_root: true }}
  }},
  module_inputs: {{}},
  capability_requests: [
    {{ capability: "input.read", scope: {{ port: "orders" }} }},
    {{ capability: "input.read", scope: {{ port: "refs" }} }},
    {{ capability: "navigation.record.user_gesture", scope: {{}} }}
  ],
  interactions: [
    {{ id: "mark_triaged", label: "Mark triaged", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input", port: "orders" }} }} }},
      facet: "triage", value: {{ from: "literal", value: "triaged" }} }}
  ]
}}

<Metric label={label:?} value={{1}} />
"#
    )
}

async fn grant_navigation(registry: &ToolRegistry, db: &Db) {
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
        .expect("the artifact source requests navigation");
    let granted = call(
        registry,
        db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"],
            "capability": "navigation.record.user_gesture", "scope": {}
        }),
    )
    .await;
    assert_eq!(granted["status"], "granted", "{granted:#}");
}

async fn two_port_nav_fixture() -> (Db, ToolRegistry, String, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let source = two_port_nav_source("Two ports");
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Two-port board",
            "body": source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Bind two deterministic artifact inputs plus navigation."
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
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": REFERENCE_COLLECTION, "type": "Collection", "kind": "folder",
                "name": "References", "reason": "Bind the second deterministic input." }),
    )
    .await;
    for id in [INSIDE, OUTSIDE] {
        call(
            &registry,
            &db,
            "create_record",
            json!({ "id": id, "type": "WorkItem", "kind": "task", "name": id,
                    "reason": "Populate the per-port fixture." }),
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
    for (port, collection) in [("orders", COLLECTION), ("refs", REFERENCE_COLLECTION)] {
        let bound = call(
            &registry,
            &db,
            "manage_artifact_inputs",
            json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": port,
                    "collection_id": collection }),
        )
        .await;
        assert_eq!(bound["status"], "bound", "{bound:#}");
    }
    grant_input_read_port(&registry, &db, "orders").await;
    grant_input_read_port(&registry, &db, "refs").await;
    grant_navigation(&registry, &db).await;
    (db, registry, digest_of(&source), guard)
}

#[tokio::test]
async fn adding_a_port_carries_every_existing_binding_and_grant() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = two_port_nav_fixture().await;
    let added = two_port_nav_source("Two ports")
        .replace(
            "    refs: { envelope: \"native.collection-envelope.v1\", required: false, expose_to_root: true }",
            "    refs: { envelope: \"native.collection-envelope.v1\", required: false, expose_to_root: true },\n    extra: { envelope: \"native.collection-envelope.v1\", required: false, expose_to_root: true }",
        )
        .replace(
            "    { capability: \"navigation.record.user_gesture\", scope: {} }",
            "    { capability: \"input.read\", scope: { port: \"extra\" } },\n    { capability: \"navigation.record.user_gesture\", scope: {} }",
        );
    assert_ne!(added, two_port_nav_source("Two ports"));
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": added, "if_body_digest": digest,
                "reason": "Add an input port beside the bound ones." }),
    )
    .await;
    let continuity = &updated["artifact_input_continuity"];
    assert_eq!(
        continuity["status"], "artifact_inputs_carried_forward",
        "{updated:#}"
    );
    assert_eq!(continuity["carried_binding_count"], 2);
    assert_eq!(continuity["dropped_binding_count"], 0);
    assert_eq!(continuity["carried_grant_count"], 3);
    assert_eq!(continuity["dropped_grant_count"], 0);
    assert_eq!(continuity["changed_ports"], json!(["extra"]));
    assert_eq!(continuity["dropped"], json!([]));
    // The navigation grant carried across the port addition re-pins to the new
    // exact source rather than lingering on the old one.
    let new_event = updated["source_event_id"].as_str().unwrap();
    let nav_source: String = sqlx::query_scalar(
        "SELECT artifact_source_event_id FROM artifact_module_grants
          WHERE artifact_id=? AND capability='navigation.record.user_gesture'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(nav_source, new_event);
    let bindings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM artifact_inputs WHERE artifact_id=?")
            .bind(ARTIFACT)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let grants: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM artifact_module_grants WHERE artifact_id=?")
            .bind(ARTIFACT)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!((bindings, grants), (2, 3));
    assert!(native_ce::conformance::run_conformance(&db).await.ok);
}

#[tokio::test]
async fn changing_one_port_declaration_drops_only_that_port() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = two_port_nav_fixture().await;
    let changed = two_port_nav_source("Two ports").replace(
        "orders: { envelope: \"native.collection-envelope.v1\", required: true",
        "orders: { envelope: \"native.collection-envelope.v1\", required: false",
    );
    assert_ne!(changed, two_port_nav_source("Two ports"));
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": changed, "if_body_digest": digest,
                "reason": "Change one declared input contract." }),
    )
    .await;
    let continuity = &updated["artifact_input_continuity"];
    assert_eq!(
        continuity["status"], "artifact_inputs_partially_carried",
        "{updated:#}"
    );
    assert_eq!(continuity["carried_binding_count"], 1);
    assert_eq!(continuity["dropped_binding_count"], 1);
    assert_eq!(continuity["carried_grant_count"], 2);
    assert_eq!(continuity["dropped_grant_count"], 1);
    assert_eq!(continuity["changed_ports"], json!(["orders"]));
    assert_eq!(
        continuity["restoration_tools"],
        json!(["manage_artifact_inputs", "manage_artifact_module_grants"])
    );
    let dropped = continuity["dropped"].as_array().unwrap();
    assert_eq!(dropped.len(), 2, "{updated:#}");
    assert!(
        dropped.iter().any(|item| item["kind"] == "binding"
            && item["port"] == "orders"
            && item["collection_id"] == COLLECTION),
        "{updated:#}"
    );
    assert!(
        dropped.iter().any(|item| item["kind"] == "grant"
            && item["port"] == "orders"
            && item["capability"] == "input.read"
            && item["scope"] == json!({ "artifact_port": "orders" })),
        "{updated:#}"
    );
    // The untouched port keeps its binding and grant; the navigation grant is
    // not port-scoped and carries too.
    let new_event = updated["source_event_id"].as_str().unwrap();
    let orders_binding: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_inputs WHERE artifact_id=? AND port_name='orders'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let refs_binding: String = sqlx::query_scalar(
        "SELECT artifact_source_event_id FROM artifact_inputs
          WHERE artifact_id=? AND port_name='refs'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!((orders_binding, refs_binding.as_str()), (0, new_event));
    let remaining_grants: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT capability,scope,artifact_source_event_id FROM artifact_module_grants
          WHERE artifact_id=? ORDER BY capability",
    )
    .bind(ARTIFACT)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(remaining_grants.len(), 2, "{remaining_grants:?}");
    assert!(
        remaining_grants
            .iter()
            .all(|(_, _, source)| source == new_event),
        "{remaining_grants:?}"
    );
    assert!(
        remaining_grants
            .iter()
            .any(|(capability, scope, _)| capability == "input.read"
                && scope == r#"{"artifact_port":"refs"}"#),
        "{remaining_grants:?}"
    );
    assert!(
        remaining_grants
            .iter()
            .any(
                |(capability, scope, _)| capability == "navigation.record.user_gesture"
                    && scope == "{}"
            ),
        "{remaining_grants:?}"
    );
    assert!(native_ce::conformance::run_conformance(&db).await.ok);
}

#[tokio::test]
async fn a_navigation_grant_survives_an_input_declaration_change() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = two_port_nav_fixture().await;
    // Change every input port declaration while keeping the requests: both
    // bindings and both input.read grants must drop, the navigation grant
    // must carry.
    let changed = two_port_nav_source("Two ports")
        .replace(
            "orders: { envelope: \"native.collection-envelope.v1\", required: true",
            "orders: { envelope: \"native.collection-envelope.v1\", required: false",
        )
        .replace(
            "refs: { envelope: \"native.collection-envelope.v1\", required: false",
            "refs: { envelope: \"native.collection-envelope.v1\", required: true",
        );
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": changed, "if_body_digest": digest,
                "reason": "Change every declared input contract." }),
    )
    .await;
    let continuity = &updated["artifact_input_continuity"];
    assert_eq!(
        continuity["status"], "artifact_inputs_partially_carried",
        "{updated:#}"
    );
    assert_eq!(continuity["carried_binding_count"], 0);
    assert_eq!(continuity["dropped_binding_count"], 2);
    assert_eq!(continuity["carried_grant_count"], 1);
    assert_eq!(continuity["dropped_grant_count"], 2);
    assert_eq!(continuity["changed_ports"], json!(["orders", "refs"]));
    let bindings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM artifact_inputs WHERE artifact_id=?")
            .bind(ARTIFACT)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(bindings, 0);
    let new_event = updated["source_event_id"].as_str().unwrap();
    let nav_source: String = sqlx::query_scalar(
        "SELECT artifact_source_event_id FROM artifact_module_grants
          WHERE artifact_id=? AND capability='navigation.record.user_gesture'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(nav_source, new_event);
    let input_grants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_module_grants
          WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(input_grants, 0);
    assert!(native_ce::conformance::run_conformance(&db).await.ok);
}

#[tokio::test]
async fn a_grant_from_revision_n_is_not_honoured_at_revision_n_plus_one() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = two_port_nav_fixture().await;
    let revision_n_event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=?
          AND type IN ('record.created','record.updated','receipt.committed.v1')
          AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    // A label-only edit keeps every declaration, so everything carries — but
    // the source revision still advances to N+1.
    let relabelled = two_port_nav_source("Two ports relabelled");
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": relabelled, "if_body_digest": digest,
                "reason": "Advance the exact source without touching declarations." }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_carried_forward",
        "{updated:#}"
    );
    let revision_n_plus_one = updated["source_event_id"].as_str().unwrap().to_owned();
    assert_ne!(revision_n_plus_one, revision_n_event);
    // No grant or binding row still points at revision N: authority moved only
    // through re-attestation to N+1, never by inheritance.
    let stale_grants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_module_grants
          WHERE artifact_id=? AND artifact_source_event_id=?",
    )
    .bind(ARTIFACT)
    .bind(&revision_n_event)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let stale_bindings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_inputs
          WHERE artifact_id=? AND artifact_source_event_id=?",
    )
    .bind(ARTIFACT)
    .bind(&revision_n_event)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!((stale_grants, stale_bindings), (0, 0));
    // The re-attested grants are honoured at N+1 ...
    let rendered = call(&registry, &db, "render_artifact", json!({"id":ARTIFACT})).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    // ... while the old revision identity is dead.
    let mut invocation = envelope("mark_triaged", &digest, "k-stale-revision");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "stale_source_digest");
    assert!(native_ce::conformance::run_conformance(&db).await.ok);
}

#[tokio::test]
async fn a_forged_carry_for_a_changed_port_is_rejected() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = two_port_nav_fixture().await;
    // The revision-0 binding and its content-event sequence: the predecessor
    // a forged carry would have to name.
    let bound_rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT seq,payload FROM content_events
          WHERE record_id=? AND type='artifact.input_bound'",
    )
    .bind(ARTIFACT)
    .fetch_all(db.pool())
    .await
    .unwrap();
    let (bound_seq, bound) = bound_rows
        .into_iter()
        .map(|(seq, payload)| (seq, serde_json::from_str::<Value>(&payload).unwrap()))
        .find(|(_, payload)| payload["port_name"] == "orders")
        .expect("the orders port was bound");
    let old_attestation = bound["artifact_source_attestation_event_id"]
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
    // Change the orders declaration: the write path unbinds it.
    let changed = two_port_nav_source("Two ports").replace(
        "orders: { envelope: \"native.collection-envelope.v1\", required: true",
        "orders: { envelope: \"native.collection-envelope.v1\", required: false",
    );
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": ARTIFACT, "body": changed, "if_body_digest": digest,
                "reason": "Drop the orders binding for the forgery fixture." }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_partially_carried",
        "{updated:#}"
    );
    assert!(native_ce::conformance::run_conformance(&db).await.ok);
    let old_surface = updated["artifact_input_continuity"]["old_declaration_surface_sha256"]
        .as_str()
        .unwrap();
    let new_surface = updated["artifact_input_continuity"]["new_declaration_surface_sha256"]
        .as_str()
        .unwrap();
    // Calibration: the test's canonical digest must match the engine's surface
    // digest, or the forged payload below would prove nothing.
    assert_eq!(
        canonical_digest(&old_descriptor["artifact_ports"]),
        old_surface,
        "the test canonicalisation must match the engine"
    );
    let new_event = updated["source_event_id"].as_str().unwrap().to_owned();
    let new_digest = updated["body_digest"].as_str().unwrap().to_owned();
    let new_attestation: String = sqlx::query_scalar(
        "SELECT attestation_event_id FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=?",
    )
    .bind(ARTIFACT)
    .bind(&new_event)
    .fetch_one(db.pool())
    .await
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
    let new_orders = new_descriptor["artifact_ports"]["orders"].clone();
    // Resurrect the dropped predecessor row, as a stale cache would.
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO artifact_inputs
          (artifact_id,port_name,collection_id,artifact_source_attestation_event_id,
           artifact_source_event_id,artifact_source_sha256,event_seq)
         VALUES(?,?,?,?,?,?,?)",
    )
    .bind(ARTIFACT)
    .bind("orders")
    .bind(bound["collection_id"].as_str().unwrap())
    .bind(
        bound["artifact_source_attestation_event_id"]
            .as_str()
            .unwrap(),
    )
    .bind(bound["artifact_source_event_id"].as_str().unwrap())
    .bind(bound["artifact_source_sha256"].as_str().unwrap())
    .bind(bound_seq)
    .execute(&write_pool)
    .await
    .unwrap();
    // An otherwise-valid carry chaining the two revisions for the changed
    // port: predecessor, digests, adjacency and binding attestation all check
    // out, so only the per-port gate can refuse it.
    let attestation_value = json!({
        "namespace": "native.mdx.artifact-input-attestation.v1",
        "artifact_id": ARTIFACT,
        "artifact_source_event_id": new_event,
        "artifact_source_sha256": new_digest,
        "artifact_source_attestation_event_id": new_attestation,
        "port_name": "orders",
        "port_declaration": new_orders,
    });
    let forged = json!({
        "binding": {
            "artifact_id": ARTIFACT,
            "port_name": "orders",
            "collection_id": bound["collection_id"],
            "artifact_source_event_id": new_event,
            "artifact_source_sha256": new_digest,
            "artifact_source_attestation_event_id": new_attestation,
            "port_declaration": new_orders,
            "attestation_sha256": canonical_digest(&attestation_value),
        },
        "predecessor_binding_event_seq": bound_seq,
        "predecessor_source_attestation_event_id": bound["artifact_source_attestation_event_id"],
        "predecessor_source_event_id": bound["artifact_source_event_id"],
        "predecessor_source_sha256": bound["artifact_source_sha256"],
        "old_declaration_surface_sha256": old_surface,
        "new_declaration_surface_sha256": new_surface,
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
    let event = native_ce::events::EventRow {
        local_seq: seq + 100,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: ARTIFACT.into(),
        event_type: "artifact.input_carried".into(),
        payload: Some(forged.to_string()),
        actor: Some("test:forged-carry".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: created_at.clone(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
        act: None,
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
    assert!(
        error.contains("port declaration changed"),
        "a changed port must fail closed at the per-port gate: {error}"
    );
}

#[tokio::test]
async fn a_v2_body_edit_without_an_exact_snapshot_reports_no_existing_state() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
        json!({ "id": ARTIFACT, "body_set": artifact_source("No prior snapshot"),
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
            act: None,
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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
    let _runtime_config = crate::runtime_config_fixture::reader().await;
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

/// Without the opt-in the commit is the fast receipt: no render, no plan.
/// This is the pre-change envelope (the field omitted entirely) plus the
/// explicit `false`, both of which must behave identically.
#[tokio::test]
async fn an_omitted_next_plan_flag_keeps_the_fast_receipt() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "k-no-plan-1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    assert!(
        invocation.get("include_next_plan").is_none(),
        "this case covers the omitted field"
    );
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert!(committed["refresh"].is_null(), "{committed:#}");

    let mut explicit = envelope("set_triage", &digest, "k-no-plan-2");
    explicit["slots"] = json!({ "record": INSIDE });
    explicit["values"] = json!({ "choice": "blocked" });
    explicit["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    explicit["include_next_plan"] = json!(false);
    let second = call(&registry, &db, "invoke_artifact_interaction", explicit).await;
    assert_eq!(second["status"], "committed", "{second:#}");
    assert!(second["refresh"].is_null(), "{second:#}");
}

/// The one-exchange case: a committed facet write with the flag set carries
/// the next authoritative plan, and that plan already reflects the write.
#[tokio::test]
async fn a_committed_facet_write_returns_the_next_plan_when_asked() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut invocation = envelope("mark_triaged", &digest, "k-next-plan-1");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    invocation["include_next_plan"] = json!(true);
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let plan = &committed["refresh"]["plan"];
    assert!(plan.is_object(), "{committed:#}");
    assert!(
        committed["refresh"].get("record").is_none(),
        "a facet write refreshes only the plan: {committed:#}"
    );
    // The plan reflects the write: its observed token for the moved facet is
    // the token this very commit left, not the precondition it consumed.
    let token = committed["changes"][0]["version"]
        .as_str()
        .expect("a committed change carries the version it produced")
        .to_owned();
    assert_eq!(plan["observed"][INSIDE]["triage"], token.as_str());
    // And it agrees with what a separate render_artifact would hand out, so
    // the caller can skip that second round trip.
    let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(
        rendered["plan"]["observed"][INSIDE]["triage"],
        token.as_str()
    );
}

/// A result that did not commit never carries a plan, flag or not: the write
/// did not happen, so the plan the caller already holds is still current.
#[tokio::test]
async fn a_conflict_with_the_flag_set_carries_no_plan() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let mut first = envelope("mark_triaged", &digest, "k-conflict-plan-1");
    first["slots"] = json!({ "record": INSIDE });
    first["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", first).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    // Quote the now-stale precondition back with the flag set.
    let mut stale = envelope("set_triage", &digest, "k-conflict-plan-2");
    stale["slots"] = json!({ "record": INSIDE });
    stale["values"] = json!({ "choice": "blocked" });
    stale["observed"] = json!({ INSIDE: { "triage": "obs:0" } });
    stale["include_next_plan"] = json!(true);
    let conflict = call(&registry, &db, "invoke_artifact_interaction", stale).await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "facet_conflict");
    assert!(conflict["refresh"].is_null(), "{conflict:#}");
}

/// A creation already refreshes the created record; with the flag set the
/// plan joins it under the same `refresh`, rather than displacing it.
#[tokio::test]
async fn a_creation_with_the_flag_set_refreshes_both_record_and_plan() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = create_fixture().await;
    let committed = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_task",
            "source_digest": digest,
            "values": { "title": "Ship both refreshes", "triage": "ready" },
            "idempotency_key": "create:task:both",
            "gesture": "submit",
            "include_next_plan": true,
        }),
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert!(
        committed["refresh"]["record"]["id"].is_string(),
        "{committed:#}"
    );
    assert!(committed["refresh"]["plan"].is_object(), "{committed:#}");
    // The bonus mirrors the render shape generically: the safe-tree render
    // carries an input (but no top-level digest), so both ride along.
    assert!(committed["refresh"]["input"].is_object(), "{committed:#}");
}

/// A document that publishes its own view state travels the real bridge: the
/// body validates and renders to an isolated launch, the delivered bytes carry
/// the handoff surface, and a body rewrite renders a new digest for the host
/// to hand that state to. Nothing here changes validation or the authority
/// boundary — it exercises create, render, rewrite and launch delivery.
#[tokio::test]
async fn html_view_state_body_renders_and_its_launch_carries_the_handoff_bridge() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    const VIEW_ARTIFACT: &str = "9a210000-0000-4000-8000-000000000001";
    fn tabs_source(active: &str) -> String {
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
            <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
            <title>Workspace tabs</title></head><body><main><h1>Workspace</h1>\
            <div role=\"tablist\"><button type=\"button\" data-tab=\"usage\">Usage</button>\
            <button type=\"button\" data-tab=\"billing\">Billing</button></div>\
            <p data-active-tab>{active}</p></main><script>var tabs=\
            document.querySelectorAll('[data-tab]');function show(name){{for(var \
            i=0;i<tabs.length;i+=1){{tabs[i].setAttribute('aria-selected',\
            tabs[i].getAttribute('data-tab')===name?'true':'false')}};\
            document.querySelector('[data-active-tab]').textContent=name;\
            window.nativeArtifact.setViewState({{tab:name}},{{schema:'tabs.v1'}})}}\
            for(var j=0;j<tabs.length;j+=1){{(function(button){{button.\
            addEventListener('click',function(){{show(button.getAttribute('data-tab'))}})}})\
            (tabs[j])}}window.nativeArtifact.ready.then(function(delivery){{var \
            handed=delivery.viewState||window.nativeArtifact.viewState;\
            if(handed&&handed.value&&handed.value.tab){{show(handed.value.tab)}}}})\
            </script></body></html>"
        )
    }

    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let first = tabs_source("usage");
    let created = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": VIEW_ARTIFACT, "type": "Document", "kind": "artifact",
                "name": "Workspace tabs", "body": first,
                "facets": { "runtime": "native.html.v1" },
                "reason": "Prove a view-state body validates and renders.",
            }),
        )
        .await
        .unwrap();
    assert!(
        created.get("diagnostic").is_none() && created.get("error").is_none(),
        "{created:#}"
    );
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": VIEW_ARTIFACT }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(rendered["plan"]["kind"], "isolated_html");
    assert_eq!(rendered["plan"]["body_digest"], digest_of(&first));

    // The body rewrite a successor frame must restore across: a new digest,
    // still rendered, with the same bridge waiting underneath.
    let second = tabs_source("billing");
    assert_ne!(digest_of(&second), digest_of(&first));
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id": VIEW_ARTIFACT, "body": second,
                "if_body_digest": digest_of(&first),
                "reason": "Rewrite the body out of band, as the agent edit does.",
            }),
        )
        .await
        .unwrap();
    let rewritten = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": VIEW_ARTIFACT }),
    )
    .await;
    assert_eq!(rewritten["status"], "rendered", "{rewritten:#}");
    assert_eq!(rewritten["plan"]["body_digest"], digest_of(&second));

    // The real delivery path: validate, mint the one-use launch, redeem it
    // over HTTP, and prove the delivered bytes carry the handoff surface.
    let manifest = native_ce::artifact_html::validate(&second).unwrap();
    let config = native_ce::artifact_html::RuntimeConfig::new(
        "https://workbench.test",
        "https://artifacts.test",
    )
    .unwrap();
    let delivery = native_ce::artifact_html::LaunchDelivery::new(config);
    let issued = delivery
        .issue_launch(
            &second,
            &manifest,
            "principal",
            Some("db:test"),
            VIEW_ARTIFACT,
        )
        .unwrap();
    let token = issued.url.rsplit('/').next().unwrap().to_string();
    let app = delivery.router();
    let request = || {
        Request::builder()
            .uri(format!("/artifact-runtime/v1/launch/{token}"))
            .header("host", "artifacts.test")
            .body(Body::empty())
            .unwrap()
    };
    let wrong_host = Request::builder()
        .uri(format!("/artifact-runtime/v1/launch/{token}"))
        .header("host", "artifact.localhost:8080")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(wrong_host).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "a wrong host must not consume the instance ticket"
    );
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors https://workbench.test;"));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let delivered = String::from_utf8_lossy(&body);
    for marker in [
        "setViewState",
        "viewState",
        "type:\"view-state\"",
        "view_state",
        "from_body_digest",
        "native-html-init",
    ] {
        assert!(
            delivered.contains(marker),
            "delivered launch is missing the handoff surface: {marker}"
        );
    }
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::GONE,
        "the launch stays one-use with a view-state body"
    );
    drop(guard);
}

// --- Alpha personal-install guard (task 26ba75a L2 backend slice) ---
//
// An optional exact guard on a reversible facet intent, checked inside the
// facet write transaction against the same account's install. A refusal names
// the personal install only and never globally disables the artifact.

const ALPHA_GUARD_ACCOUNT: &str = "alice";
const ALPHA_GUARD_PACKAGE_A: &str = "agent.attention-cockpit";
const ALPHA_GUARD_PACKAGE_B: &str = "agent.team-pulse";

fn alpha_guard_declaration() -> Value {
    json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]})
}

fn alpha_guard_declaration_no_effect() -> Value {
    json!({"needs": ["attention.query.v1"], "effects": []})
}

async fn alpha_guard_source_revision(db: &Db, artifact_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(artifact_id)
    .fetch_one(db.pool())
    .await
    .unwrap()
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

fn alpha_guard_preview_caller(account: &str, args: &Value) -> Caller {
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

fn alpha_guard_adopt_caller(account: &str, args: &Value) -> Caller {
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

async fn alpha_guard_grants(db: &Db, account: &str) {
    replace_explicit_policy(
        db,
        "test:policy",
        ARTIFACT,
        vec![AllowEntry::account(account, Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        db,
        "test:policy",
        COLLECTION,
        vec![AllowEntry::account(account, Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        db,
        "test:policy",
        INSIDE,
        vec![
            AllowEntry::account(account, Capability::View),
            AllowEntry::account(account, Capability::Edit),
        ],
    )
    .await
    .unwrap();
}

/// Install + attested preview + attested adopt for one package, returning the
/// verified generation event plus the exact pin the guard must echo.
async fn alpha_guard_verified_install(
    db: &Db,
    registry: &ToolRegistry,
    account: &str,
    package: &str,
    body: &str,
    declaration: Value,
) -> (String, String, String, String) {
    let source_revision = alpha_guard_source_revision(db, ARTIFACT).await;
    let (digest, declaration_digest) = alpha_guard_pin_for(body, &declaration);
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
                "reason": "Install the guarded alpha tab.",
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
        "reason": "Preview the guarded alpha tab.",
    });
    let preview = registry
        .call(
            db.clone(),
            alpha_guard_preview_caller(account, &preview_args),
            "manage_alpha_tabs",
            preview_args,
        )
        .await
        .unwrap();
    let receipt_id = preview["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    let nonce = preview["receipt"]["nonce"].as_str().unwrap().to_string();
    let session = preview["receipt"]["preview_session"]
        .as_str()
        .unwrap()
        .to_string();
    let adopt_args = json!({
        "action": "adopt",
        "package": package,
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": ARTIFACT,
        "source_revision": source_revision,
        "declaration": declaration,
        "receipt_id": receipt_id,
        "nonce": nonce,
        "preview_session": session,
        "expected_install_event_id": install_event,
        "reason": "Adopt the guarded alpha tab.",
    });
    let adopted = registry
        .call(
            db.clone(),
            alpha_guard_adopt_caller(account, &adopt_args),
            "manage_alpha_tabs",
            adopt_args,
        )
        .await
        .unwrap();
    assert_eq!(
        adopted["install"]["adoption"], "shell_adopt.v1",
        "{adopted:#}"
    );
    let verified_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
    (verified_event, source_revision, digest, declaration_digest)
}

fn alpha_guard_json(
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

async fn alpha_guard_facet_value(db: &Db) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='triage'")
        .bind(INSIDE)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .flatten()
}

async fn alpha_guard_keyed_writes(db: &Db, key: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND json_extract(payload,'$.origin.idempotency_key')=?",
    )
    .bind(INSIDE)
    .bind(key)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn alpha_guard_commits_guarded_facet_set_and_preserves_unguarded_path() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let invocation = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "mark_triaged",
        "source_digest": body_digest,
        "slots": { "record": INSIDE },
        "observed": { INSIDE: { "triage": "obs:0" } },
        "idempotency_key": "alpha:guarded:one",
        "alpha_install_guard": guard,
    });
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
    assert_eq!(committed["changes"][0]["after"], "triaged");
    assert_eq!(
        alpha_guard_facet_value(&db).await.as_deref(),
        Some("triaged")
    );
    // Unguarded existing path is unchanged: same caller, fresh CAS, no guard.
    let version = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    let unguarded = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "set_triage",
        "source_digest": body_digest,
        "slots": { "record": INSIDE },
        "values": { "choice": "blocked" },
        "observed": { INSIDE: { "triage": version } },
        "idempotency_key": "alpha:unguarded:two",
    });
    let second = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        unguarded,
    )
    .await
    .unwrap();
    assert_eq!(second["status"], "committed", "{second:#}");
    assert_eq!(second["changes"][0]["after"], "blocked");
}

#[tokio::test]
async fn alpha_guard_refuses_disabled_and_stale_generation_before_write() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    // Baseline guarded write proves the pin.
    let baseline_guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let baseline = call_as(
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
            "idempotency_key": "alpha:disable:base",
            "alpha_install_guard": baseline_guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(baseline["status"], "committed", "{baseline:#}");
    let current = baseline["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    // Disable moves the generation; the old guard is now stale.
    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable",
            "package": ALPHA_GUARD_PACKAGE_A,
            "expected_install_event_id": verified,
            "reason": "Pause the guarded tab.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(disabled["install"]["status"], "disabled");
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    // Stale generation refuses before any write.
    let stale_guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let stale = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "set_triage",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": { "choice": "blocked" },
            "observed": { INSIDE: { "triage": current } },
            "idempotency_key": "alpha:disable:stale",
            "alpha_install_guard": stale_guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(stale["status"], "rejected", "{stale:#}");
    assert_eq!(
        stale["error"]["code"], "alpha_guard_cas_mismatch",
        "{stale:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:disable:stale").await,
        0
    );
    assert_eq!(
        alpha_guard_facet_value(&db).await.as_deref(),
        Some("triaged")
    );
    // A fresh generation against the disabled row refuses as disabled.
    let fresh_guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &disabled_event,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let refused = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "set_triage",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": { "choice": "blocked" },
            "observed": { INSIDE: { "triage": current } },
            "idempotency_key": "alpha:disable:fresh",
            "alpha_install_guard": fresh_guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_disabled",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:disable:fresh").await,
        0
    );
    assert_eq!(
        alpha_guard_facet_value(&db).await.as_deref(),
        Some("triaged")
    );
    // A disabled personal tab never globally disables the artifact: the same
    // caller without a guard still writes.
    let plain = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "set_triage",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": { "choice": "blocked" },
            "observed": { INSIDE: { "triage": current } },
            "idempotency_key": "alpha:disable:plain",
        }),
    )
    .await
    .unwrap();
    assert_eq!(plain["status"], "committed", "{plain:#}");
}

#[tokio::test]
async fn alpha_guard_sibling_install_stays_independent() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (event_a, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let (event_b, _, _, _) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_B,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    // Disable only the sibling.
    let disabled_b = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable",
            "package": ALPHA_GUARD_PACKAGE_B,
            "expected_install_event_id": event_b,
            "reason": "Pause the sibling tab.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(disabled_b["install"]["status"], "disabled");
    // The first tab's guard still commits.
    let guard_a = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &event_a,
        &source_revision,
        &digest,
        &declaration_digest,
    );
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
            "idempotency_key": "alpha:sibling:a",
            "alpha_install_guard": guard_a,
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    // The disabled sibling refuses on its own guard.
    let disabled_event_b = disabled_b["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let guard_b = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_B,
        &disabled_event_b,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let current = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "set_triage",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": { "choice": "blocked" },
            "observed": { INSIDE: { "triage": current } },
            "idempotency_key": "alpha:sibling:b",
            "alpha_install_guard": guard_b,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_disabled",
        "{refused:#}"
    );
}

#[tokio::test]
async fn alpha_guard_refuses_unconsented_effect_before_write() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // An otherwise valid verified pin whose consented effects omit
    // task.triage-set.v1 refuses: a declared v2 interaction or a matching
    // bundle digest alone is never effect consent.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration_no_effect(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let refused = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "alpha:effect:one",
            "alpha_install_guard": guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_effect_unconsented",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:effect:one").await, 0);
    assert_eq!(alpha_guard_facet_value(&db).await, None);
}

fn alpha_guard_lifecycle_declaration() -> Value {
    json!({"needs": ["attention.query.v1"], "effects": ["tasks.lifecycle-set.v1"]})
}

async fn alpha_guard_lifecycle_token(db: &Db, registry: &ToolRegistry) -> String {
    let rendered = call(registry, db, "render_artifact", json!({"id": ARTIFACT})).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    rendered["plan"]["observed"][INSIDE]["lifecycle"]
        .as_str()
        .expect("the plan versions the lifecycle spine key")
        .to_string()
}

async fn alpha_guard_lifecycle(db: &Db) -> Option<String> {
    sqlx::query_scalar("SELECT lifecycle FROM records WHERE id=?")
        .bind(INSIDE)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .flatten()
}

#[tokio::test]
async fn unguarded_lifecycle_start_keeps_declared_interaction_semantics() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // The Tasks open-only rule belongs to the personal-install guard. An
    // ordinary artifact with the same declared literal can still move a
    // blocked record to in_progress under its existing permissions and CAS.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) = fixture_with_source(body, "native.html.v1").await;
    let changed = call(
        &registry,
        &db,
        "update_record",
        json!({"record_id": INSIDE, "lifecycle": "blocked", "reason": "Set up unguarded transition."}),
    )
    .await;
    assert_eq!(
        changed["lifecycle_interpretation"]["value"]["canonical"], "blocked",
        "{changed:#}"
    );
    let token = alpha_guard_lifecycle_token(&db, &registry).await;
    let committed = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "start_work",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": {},
            "observed": { INSIDE: { "lifecycle": token } },
            "idempotency_key": "alpha:tasks:unguarded",
        }),
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(
        committed["changes"][0]["before"], "blocked",
        "{committed:#}"
    );
    assert_eq!(
        committed["changes"][0]["after"], "in_progress",
        "{committed:#}"
    );
}

#[tokio::test]
async fn alpha_guard_tasks_click_commits_open_to_in_progress_once() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // The Tasks click slice (21f44fc): a guarded facet.set on the lifecycle
    // spine key with a declared literal in_progress commits open →
    // in_progress exactly once per idempotency key, then replays and
    // conflicts like any spine write.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    assert_eq!(alpha_guard_lifecycle(&db).await.as_deref(), Some("open"));
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_lifecycle_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let invoke = |token: &str, key: &str| {
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "start_work",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": {},
            "observed": { INSIDE: { "lifecycle": token } },
            "idempotency_key": key,
            "alpha_install_guard": guard,
        })
    };
    let token = alpha_guard_lifecycle_token(&db, &registry).await;
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invoke(&token, "alpha:tasks:one"),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["key"], "lifecycle", "{committed:#}");
    assert_eq!(committed["changes"][0]["before"], "open", "{committed:#}");
    assert_eq!(
        committed["changes"][0]["after"], "in_progress",
        "{committed:#}"
    );
    assert_eq!(
        alpha_guard_lifecycle(&db).await.as_deref(),
        Some("in_progress")
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:tasks:one").await, 1);
    // Same key replays without a second append.
    let replayed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invoke(&token, "alpha:tasks:one"),
    )
    .await
    .unwrap();
    assert_eq!(replayed["status"], "committed", "{replayed:#}");
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:tasks:one").await, 1);
    // A fresh key on the stale token conflicts instead of overwriting.
    let fresh = alpha_guard_lifecycle_token(&db, &registry).await;
    assert_ne!(fresh, token);
    let conflicted = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invoke(&token, "alpha:tasks:two"),
    )
    .await
    .unwrap();
    assert_eq!(conflicted["status"], "conflict", "{conflicted:#}");
    assert_eq!(
        alpha_guard_lifecycle(&db).await.as_deref(),
        Some("in_progress")
    );
    // A second Start from the new state refuses: the transition source is
    // fixed to open, so the record cannot be moved twice.
    let refused = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invoke(&fresh, "alpha:tasks:three"),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "lifecycle_unexpected_state",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:tasks:three").await, 0);
}

#[tokio::test]
async fn authored_tasks_start_uses_real_bound_items_and_viewer_authority() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Model the authored Tasks Start declaration here: the public root-test
    // source boundary cannot embed a file from experiments/. Input and grant
    // changes still go through the public tools that a hosted owner uses.
    let _lock = Arc::clone(integration_guard()).lock_owned().await;
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Tasks Start</title><script type="application/json" id="native-artifact-manifest">{"schema":"native.html.artifact.v2","inputs":{"items":{"envelope":"native.collection-envelope.v1","expose_to_root":true,"required":true}},"capability_requests":[{"capability":"input.read","scope":{"port":"items"}}],"interactions":[{"id":"lifecycle_start","label":"Start work","effect":"facet.set","facet":"lifecycle","slots":{"record":{"domain":{"kind":"bound_input","port":"items"}}},"value":{"from":"literal","value":"in_progress"}}]}</script></head><body><main><h1>Tasks Start</h1></main></body></html>"#;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    for args in [
        json!({"id": ARTIFACT, "type": "Document", "kind": "artifact",
            "name": "Authored Tasks", "body": body,
            "facets": {"runtime": "native.html.v1"}, "reason": "Prove the authored Tasks source."}),
        json!({"id": COLLECTION, "type": "Collection", "kind": "selection",
            "name": "Tasks items", "reason": "Govern the Tasks input."}),
        json!({"id": INSIDE, "type": "WorkItem", "kind": "task",
            "name": "Start this task", "reason": "Populate the governed input."}),
    ] {
        call(&registry, &db, "create_record", args).await;
    }
    call(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "add", "source_id": INSIDE, "target_id": COLLECTION,
            "relationship": "member_of"
        }),
    )
    .await;
    let bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({
            "action": "bind", "artifact_id": ARTIFACT, "port_name": "items",
            "collection_id": COLLECTION
        }),
    )
    .await;
    assert_eq!(bound["status"], "bound", "{bound:#}");
    let subjects = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "read", "artifact_id": ARTIFACT
        }),
    )
    .await;
    let subject = subjects["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["subject_kind"] == "artifact_source")
        .expect("authored source requests input.read");
    let granted = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT,
            "subject_kind": "artifact_source", "subject_record_id": ARTIFACT,
            "subject_event_id": subject["subject_event_id"],
            "source_sha256": subject["source_sha256"], "capability": "input.read",
            "scope": {"artifact_port": "items"}
        }),
    )
    .await;
    assert_eq!(granted["status"], "granted", "{granted:#}");

    const BEA: &str = "bea";
    for id in [ARTIFACT, COLLECTION] {
        replace_explicit_policy(
            &db,
            "test:tasks-viewers",
            id,
            vec![
                AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
                AllowEntry::account(BEA, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        "test:tasks-viewers",
        INSIDE,
        vec![
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::Edit),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let bea = Caller::authenticated(BEA);
    for (viewer, may_edit) in [(alice.clone(), true), (bea.clone(), false)] {
        let rendered = call_as(
            &registry,
            &db,
            viewer,
            "render_artifact",
            json!({"id": ARTIFACT}),
        )
        .await
        .unwrap();
        assert_eq!(rendered["status"], "rendered", "{rendered:#}");
        assert_eq!(
            rendered["input"]["inputs"]["items"]["version"], "native.collection-envelope.v1",
            "{rendered:#}"
        );
        assert_eq!(
            rendered["input"]["inputs"]["items"]["collection"]["id"],
            COLLECTION
        );
        assert!(rendered["input"]["inputs"]["items"]["projection"]["binding_event_seq"].is_i64());
        assert_eq!(
            rendered["plan"]["interaction_availability"]["editable_records"]
                .as_array()
                .unwrap()
                .contains(&json!(INSIDE)),
            may_edit,
            "fresh render must distinguish View from Edit for host confirmation"
        );
        assert!(
            rendered["input"]["inputs"]["items"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == INSIDE),
            "{rendered:#}"
        );
        assert!(
            rendered["plan"]["interaction_availability"]["supported_entries"]
                .as_array()
                .unwrap()
                .contains(&json!("lifecycle_start")),
            "{rendered:#}"
        );
        assert!(
            rendered["plan"]["interaction_availability"]["records_by_port"]["items"]
                .as_array()
                .unwrap()
                .contains(&json!(INSIDE)),
            "{rendered:#}"
        );
    }

    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        "agent.tasks",
        body,
        alpha_guard_lifecycle_declaration(),
    )
    .await;
    let rendered = call_as(
        &registry,
        &db,
        alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let token = rendered["plan"]["observed"][INSIDE]["lifecycle"]
        .as_str()
        .expect("render supplies the CAS token");
    let (bea_event, bea_revision, bea_digest, bea_declaration_digest) =
        alpha_guard_verified_install(
            &db,
            &registry,
            BEA,
            "agent.tasks",
            body,
            alpha_guard_lifecycle_declaration(),
        )
        .await;
    let refused = call_as(
        &registry,
        &db,
        bea,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT,
            "entry_id": "lifecycle_start", "source_digest": digest_of(body),
            "slots": {"record": INSIDE}, "values": {},
            "observed": {INSIDE: {"lifecycle": token}},
            "idempotency_key": "authored:tasks:bea",
            "alpha_install_guard": alpha_guard_json("agent.tasks", &bea_event,
                &bea_revision, &bea_digest, &bea_declaration_digest),
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied", "{refused:#}");
    assert_eq!(alpha_guard_keyed_writes(&db, "authored:tasks:bea").await, 0);
    assert_eq!(alpha_guard_lifecycle(&db).await.as_deref(), Some("open"));
    // A host may have displayed this exact source/CAS while Alice could Edit.
    // Revocation leaves the target visible and the CAS unchanged, but fresh
    // availability must withhold Edit and the transaction must refuse the
    // captured invocation as well. ARM itself is browser-only and writes none.
    replace_explicit_policy(
        &db,
        "test:tasks-confirmation-revocation",
        INSIDE,
        vec![
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let narrowed = call_as(
        &registry,
        &db,
        alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    assert_eq!(narrowed["status"], "rendered", "{narrowed:#}");
    assert_eq!(narrowed["plan"]["observed"][INSIDE]["lifecycle"], token);
    assert!(
        !narrowed["plan"]["interaction_availability"]["editable_records"]
            .as_array()
            .unwrap()
            .contains(&json!(INSIDE))
    );
    let revoked = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT,
            "entry_id": "lifecycle_start", "source_digest": digest_of(body),
            "slots": {"record": INSIDE}, "values": {},
            "observed": {INSIDE: {"lifecycle": token}},
            "idempotency_key": "authored:tasks:revoked",
            "alpha_install_guard": alpha_guard_json("agent.tasks", &verified,
                &source_revision, &digest, &declaration_digest),
        }),
    )
    .await
    .unwrap();
    assert_eq!(revoked["status"], "rejected", "{revoked:#}");
    assert_eq!(revoked["error"]["code"], "permission_denied", "{revoked:#}");
    assert_eq!(
        alpha_guard_keyed_writes(&db, "authored:tasks:revoked").await,
        0
    );
    assert_eq!(alpha_guard_lifecycle(&db).await.as_deref(), Some("open"));
    replace_explicit_policy(
        &db,
        "test:tasks-confirmation-restoration",
        INSIDE,
        vec![
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::Edit),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let invocation = json!({
        "version": INVOCATION_VERSION, "artifact_id": ARTIFACT,
        "entry_id": "lifecycle_start", "source_digest": digest_of(body),
        "slots": {"record": INSIDE}, "values": {},
        "observed": {INSIDE: {"lifecycle": token}},
        "idempotency_key": "authored:tasks:start",
        "alpha_install_guard": alpha_guard_json("agent.tasks", &verified,
            &source_revision, &digest, &declaration_digest),
    });
    let committed = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(
        alpha_guard_lifecycle(&db).await.as_deref(),
        Some("in_progress")
    );
    let replay = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        alpha_guard_keyed_writes(&db, "authored:tasks:start").await,
        1
    );
}

#[tokio::test]
async fn alpha_guard_tasks_click_narrows_effect_authority_per_viewer() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    const BEA: &str = "bea";
    for id in [ARTIFACT, COLLECTION] {
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![
                AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
                AllowEntry::account(BEA, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        "test:policy",
        INSIDE,
        vec![
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::Edit),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let (alice_event, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_lifecycle_declaration(),
    )
    .await;
    let (bea_event, _, _, _) = alpha_guard_verified_install(
        &db,
        &registry,
        BEA,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_lifecycle_declaration(),
    )
    .await;
    let token = alpha_guard_lifecycle_token(&db, &registry).await;
    let invoke = |event: &str, key: &str| {
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "start_work",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": {},
            "observed": { INSIDE: { "lifecycle": token } },
            "idempotency_key": key,
            "alpha_install_guard": alpha_guard_json(
                ALPHA_GUARD_PACKAGE_A, event, &source_revision, &digest, &declaration_digest),
        })
    };
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "invoke_artifact_interaction",
        invoke(&bea_event, "alpha:tasks:bea"),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied", "{refused:#}");
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:tasks:bea").await, 0);
    assert_eq!(alpha_guard_lifecycle(&db).await.as_deref(), Some("open"));
    let committed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALPHA_GUARD_ACCOUNT),
        "invoke_artifact_interaction",
        invoke(&alice_event, "alpha:tasks:alice"),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(
        alpha_guard_lifecycle(&db).await.as_deref(),
        Some("in_progress")
    );
}

#[tokio::test]
async fn alpha_guard_tasks_click_refuses_triage_consented_install() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Triage consent never authorizes the lifecycle arm: the install must
    // consent to tasks.lifecycle-set.v1 specifically.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let triage_guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let token = alpha_guard_lifecycle_token(&db, &registry).await;
    let refused = call_as(
        &registry,
        &db,
        alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "start_work",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": {},
            "observed": { INSIDE: { "lifecycle": token } },
            "idempotency_key": "alpha:tasks:cross",
            "alpha_install_guard": triage_guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_effect_unconsented",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:tasks:cross").await, 0);
    assert_eq!(alpha_guard_lifecycle(&db).await.as_deref(), Some("open"));
}

#[tokio::test]
async fn alpha_guard_absent_preserves_existing_invocation() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // No install at all: the pre-guard envelope commits exactly as before.
    let (db, registry, digest, _lock) = fixture().await;
    let invocation = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "mark_triaged",
        "source_digest": digest,
        "slots": { "record": INSIDE },
        "observed": { INSIDE: { "triage": "obs:0" } },
        "idempotency_key": "alpha:plain:one",
    });
    let committed = call(&registry, &db, "invoke_artifact_interaction", invocation).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert!(committed.get("alpha_install_guard").is_none());
}

fn alpha_guard_dummy() -> Value {
    // Well-formed shape (passes envelope validation) with no install behind
    // it: scope checks run before any install lookup, so these refuse on
    // scope alone.
    json!({
        "package": "agent.attention-cockpit",
        "expected_install_event_id": "evt-dummy",
        "artifact_id": ARTIFACT,
        "source_revision": "rev-dummy",
        "version": "0.1.0",
        "digest": format!("sha256:{}", "d".repeat(64)),
        "declaration_digest": "e".repeat(64),
    })
}

#[tokio::test]
async fn alpha_guard_refuses_record_create_with_guard() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Consent to triage-set never authorizes record.create: the guarded
    // creation refuses before any write, even with a well-formed guard.
    let (db, registry, digest, _lock) = create_fixture().await;
    let refused = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "create_task",
            "source_digest": digest,
            "values": { "title": "Guarded creation", "triage": "ready" },
            "idempotency_key": "alpha:scope:create",
            "alpha_install_guard": alpha_guard_dummy(),
        }),
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_unsupported_effect",
        "{refused:#}"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE home_id=? AND type='WorkItem' AND kind='task'",
    )
    .bind(COLLECTION)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 0, "a guarded creation must not write");
}

#[tokio::test]
async fn alpha_guard_refuses_non_triage_facet_with_guard() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // A verified triage-consented pin plus the tasks lifecycle entry
    // still refuses: consent is per effect arm, so triage-set consent
    // never authorizes the lifecycle arm (which requires
    // tasks.lifecycle-set.v1). Scope is checked on the actual parsed
    // entry before any write.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let refused = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "start_work",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "lifecycle": "rec:0" } },
            "idempotency_key": "alpha:scope:lifecycle",
            "alpha_install_guard": guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_effect_unconsented",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:scope:lifecycle").await,
        0
    );
}

#[tokio::test]
async fn alpha_guard_refuses_undeclared_lifecycle_value_with_guard() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Lifecycle consent with a bogus-state entry still refuses on scope:
    // the tasks arm admits only the declared literal in_progress, so a
    // widened value fails before any write even when the effect is
    // consented.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_lifecycle_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let token = alpha_guard_lifecycle_token(&db, &registry).await;
    let refused = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "stall",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "values": {},
            "observed": { INSIDE: { "lifecycle": token } },
            "idempotency_key": "alpha:scope:bogus",
            "alpha_install_guard": guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_facet_unconsented",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:scope:bogus").await, 0);
}

#[tokio::test]
async fn alpha_guard_refuses_non_html_runtime_with_guard() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Guarded writes require native.html.v1, matching the alpha launch path.
    // An MDX artifact with a well-formed guard refuses before any write,
    // even though the same entry commits unguarded.
    let (db, registry, digest, _lock) = fixture().await;
    let refused = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "alpha:scope:mdx",
            "alpha_install_guard": alpha_guard_dummy(),
        }),
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_unsupported_runtime",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "alpha:scope:mdx").await, 0);
    assert_eq!(alpha_guard_facet_value(&db).await, None);
    // The same entry without a guard still commits: scope narrows only the
    // guarded path.
    let plain = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "alpha:scope:mdx-plain",
        }),
    )
    .await;
    assert_eq!(plain["status"], "committed", "{plain:#}");
}

// --- Guarded facet replay identity (P2-1): the persisted guard context is
// part of replay identity. Same actor/artifact/entry/record/key replays only
// under the identical guard context; anything else conflicts, never commits.

#[tokio::test]
async fn alpha_guard_replay_guarded_to_unguarded_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // A guarded commit followed by an unguarded retry under the same key must
    // conflict: the unguarded call must not inherit the guarded commit's
    // receipt and version token.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
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
            "idempotency_key": "alpha:replay:guarded-plain",
            "alpha_install_guard": guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let current = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    // Same actor/artifact/entry/record/key, guard dropped: the tool
    // command-identity boundary refuses the changed input before the handler
    // result surfaces, and the facet log-level guard comparison (the P2-1 fix)
    // conflicts the same way if the attestation side table ever diverges.
    let replay = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": current } },
            "idempotency_key": "alpha:replay:guarded-plain",
        }),
    )
    .await
    .expect_err("reusing a guarded key without its guard must not replay");
    assert!(
        replay.to_string().contains("conflicting action input"),
        "{replay:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:replay:guarded-plain").await,
        1,
        "a conflicting replay commits nothing"
    );
    assert_eq!(
        alpha_guard_facet_value(&db).await.as_deref(),
        Some("triaged")
    );
}

#[tokio::test]
async fn alpha_guard_replay_distinct_guard_contexts_conflict() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Two valid installs, one key: the second package's guard must not replay
    // the first package's commit, even though its own guard verifies.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (event_a, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let (event_b, _, _, _) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_B,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let guard_a = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &event_a,
        &source_revision,
        &digest,
        &declaration_digest,
    );
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
            "idempotency_key": "alpha:replay:a-to-b",
            "alpha_install_guard": guard_a,
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let current = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    // Same key under package B's own valid guard: the tool command-identity
    // boundary refuses the changed input (and the facet log-level guard
    // comparison conflicts the same way if the side table ever diverges), so
    // B never inherits A's receipt or version token.
    let guard_b = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_B,
        &event_b,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let replay = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": current } },
            "idempotency_key": "alpha:replay:a-to-b",
            "alpha_install_guard": guard_b,
        }),
    )
    .await
    .expect_err("reusing a guarded key under another package must not replay");
    assert!(
        replay.to_string().contains("conflicting action input"),
        "{replay:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:replay:a-to-b").await,
        1,
        "a conflicting replay commits nothing"
    );
    assert_eq!(
        alpha_guard_facet_value(&db).await.as_deref(),
        Some("triaged")
    );
}

#[tokio::test]
async fn alpha_guard_replay_same_guard_stays_idempotent() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // The identical guard context under the same key still replays idempotent:
    // committed, no second write, and the original version token is returned.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
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
            "idempotency_key": "alpha:replay:same-guard",
            "alpha_install_guard": guard.clone(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let original_token = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    let replay = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "alpha:replay:same-guard",
            "alpha_install_guard": guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        replay["changes"][0]["version"],
        original_token.as_str(),
        "{replay:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:replay:same-guard").await,
        1,
        "a replay commits nothing"
    );
}

#[tokio::test]
async fn alpha_guard_replay_unguarded_to_unguarded_still_replays() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Ordinary replay is untouched by the guard comparison: the same
    // unguarded invocation under the same key replays committed with the
    // original token and no second write. (Pre-guard legacy rows, whose origin
    // lacks the guard key entirely, normalize to the same null context; that
    // branch is pinned by the `facet_guard_context_matches` unit test, since
    // the test pool is read-only and cannot rewrite a row to legacy shape.)
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
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
            "idempotency_key": "alpha:replay:plain-plain",
        }),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let original_token = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    let replay = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "mark_triaged",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "triage": "obs:0" } },
            "idempotency_key": "alpha:replay:plain-plain",
        }),
    )
    .await
    .unwrap();
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        replay["changes"][0]["version"],
        original_token.as_str(),
        "{replay:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&db, "alpha:replay:plain-plain").await,
        1,
        "a replay commits nothing"
    );
}

// ---------------------------------------------------------------------------
// Facet-set object bounds (task `81372d1`): narrowed key/values/target need.
// ---------------------------------------------------------------------------

const FACET_SET_THIRD: &str = "0a5e0000-0000-4000-8000-000000000009";

fn facet_set_member_sql() -> String {
    format!(
        "SELECT w.id FROM links l JOIN records w ON w.id = l.source_id \
         WHERE l.relationship = 'member_of' AND l.target_id = '{COLLECTION}' \
         AND w.deleted_at IS NULL ORDER BY w.id ASC LIMIT 40"
    )
}

fn facet_set_need(key: &str, sql: &str) -> Value {
    json!({"need": "sql.snapshot.v1", "key": key, "label": "Grid", "sql": sql})
}

fn facet_set_bound(key: &str, values: Value, need: &str) -> Value {
    json!({"effect": "records.facet-set.v1", "key": key, "values": values,
        "target": {"need": need}})
}

fn facet_set_declaration(effects: Value, needs: Value) -> Value {
    json!({"needs": needs, "effects": effects})
}

fn facet_set_grid_declaration() -> Value {
    facet_set_declaration(
        json!([facet_set_bound(
            "effort",
            json!(["large", "small"]),
            "grid.items"
        )]),
        json!([
            "attention.query.v1",
            facet_set_need("grid.items", &facet_set_member_sql()),
        ]),
    )
}

async fn facet_set_effort_value(db: &Db) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='effort'")
        .bind(INSIDE)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .flatten()
}

struct FacetSetSetup {
    db: Db,
    registry: ToolRegistry,
    body_digest: String,
    guard: Value,
    alice: Caller,
    _lock: tokio::sync::OwnedMutexGuard<()>,
}

async fn facet_set_setup(declaration: Value) -> FacetSetSetup {
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        declaration,
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    FacetSetSetup {
        db,
        registry,
        body_digest,
        guard,
        alice,
        _lock: lock,
    }
}

async fn facet_set_invoke(
    setup: &FacetSetSetup,
    entry_id: &str,
    record_id: &str,
    observed: Value,
    key: &str,
) -> Value {
    call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": entry_id,
            "source_digest": setup.body_digest,
            "slots": { "record": record_id },
            "observed": { record_id: observed },
            "idempotency_key": key,
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn facet_set_guard_commits_narrowed_literal() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let committed = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:admit:one",
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(committed["changes"][0]["after"], "large");
    assert_eq!(
        facet_set_effort_value(&setup.db).await.as_deref(),
        Some("large")
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:admit:one").await,
        1
    );
}

#[tokio::test]
async fn facet_set_guard_refuses_undeclared_value() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let declaration = facet_set_declaration(
        json!([facet_set_bound("effort", json!(["small"]), "grid.items")]),
        json!([
            "attention.query.v1",
            facet_set_need("grid.items", &facet_set_member_sql()),
        ]),
    );
    let setup = facet_set_setup(declaration).await;
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:value:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_effect_unconsented",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:value:no").await,
        0
    );
    assert_eq!(facet_set_effort_value(&setup.db).await, None);
}

#[tokio::test]
async fn facet_set_guard_refuses_undeclared_key() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let declaration = facet_set_declaration(
        json!([facet_set_bound("priority", json!(["large"]), "grid.items")]),
        json!([
            "attention.query.v1",
            facet_set_need("grid.items", &facet_set_member_sql()),
        ]),
    );
    let setup = facet_set_setup(declaration).await;
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:key:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_effect_unconsented",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&setup.db, "facet:key:no").await, 0);
}

#[tokio::test]
async fn facet_set_install_refuses_bare_string_and_missing_need() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, _digest, _lock) = fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    for effects in [
        json!(["records.facet-set.v1"]),
        json!([facet_set_bound("effort", json!(["large"]), "grid.absent")]),
        json!([facet_set_bound(
            "owner",
            json!(["acct:someone"]),
            "grid.items"
        )]),
        json!([facet_set_bound(
            "lifecycle",
            json!(["in_progress"]),
            "grid.items"
        )]),
        json!([facet_set_bound("name", json!(["x"]), "grid.items")]),
        json!([facet_set_bound("archived", json!(["x"]), "grid.items")]),
    ] {
        let declaration = facet_set_declaration(
            effects,
            json!([
                "attention.query.v1",
                facet_set_need("grid.items", &facet_set_member_sql()),
            ]),
        );
        // Use a well-formed pin to reach the install parser with invalid
        // consent; the pin helper itself rejects protected-key bounds.
        let (digest, _declaration_digest) =
            alpha_guard_pin_for(&body, &facet_set_grid_declaration());
        let source_revision = alpha_guard_source_revision(&db, ARTIFACT).await;
        let error = registry
            .call(
                db.clone(),
                Caller::authenticated(ALPHA_GUARD_ACCOUNT),
                "manage_alpha_tabs",
                json!({
                    "action": "install",
                    "package": ALPHA_GUARD_PACKAGE_A,
                    "version": "0.1.0",
                    "digest": digest,
                    "artifact_id": ARTIFACT,
                    "source_revision": source_revision,
                    "declaration": declaration,
                    "reason": "Install the facet-set tab.",
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("invalid_effect"),
            "bare strings, missing needs and out-of-scope keys fail closed: {error}"
        );
    }
    let installs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alpha_tab_installs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(installs, 0, "refused installs write nothing");
}

#[tokio::test]
async fn facet_set_guard_refuses_outside_need_rows() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // INSIDE sits in the bound input, but the need delivers no rows, so the
    // target is outside the consented need while inside the binding.
    let declaration = facet_set_declaration(
        json!([facet_set_bound("effort", json!(["large"]), "grid.empty")]),
        json!([
            "attention.query.v1",
            facet_set_need(
                "grid.empty",
                "SELECT w.id FROM links l JOIN records w ON w.id = l.source_id \
                 WHERE l.relationship = 'member_of' AND w.lifecycle = 'completed' \
                 ORDER BY w.id ASC LIMIT 40",
            ),
        ]),
    );
    let setup = facet_set_setup(declaration).await;
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:need:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "record_outside_need",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:need:no").await,
        0
    );
}

#[tokio::test]
async fn facet_set_membership_never_queries_beyond_delivered_rows() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // A third member exists in the binding, but the need delivers only the
    // first row: an unbounded re-query would admit it, the capped check
    // must not.
    let setup = facet_set_setup(facet_set_declaration(
        json!([facet_set_bound("effort", json!(["large"]), "grid.first")]),
        json!([
            "attention.query.v1",
            facet_set_need(
                "grid.first",
                &format!(
                    "SELECT w.id FROM links l JOIN records w ON w.id = l.source_id \
                     WHERE l.relationship = 'member_of' AND l.target_id = '{COLLECTION}' \
                     AND w.deleted_at IS NULL ORDER BY w.id ASC LIMIT 1"
                ),
            ),
        ]),
    ))
    .await;
    call(
        &setup.registry,
        &setup.db,
        "create_record",
        json!({ "id": FACET_SET_THIRD, "type": "WorkItem", "kind": "task",
                "name": FACET_SET_THIRD, "reason": "Second bound member." }),
    )
    .await;
    call(
        &setup.registry,
        &setup.db,
        "manage_links",
        json!({ "action": "add", "source_id": FACET_SET_THIRD, "target_id": COLLECTION,
                "relationship": "member_of" }),
    )
    .await;
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        FACET_SET_THIRD,
        vec![
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        FACET_SET_THIRD,
        json!({ "effort": "obs:0" }),
        "facet:cap:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "record_outside_need",
        "{refused:#}"
    );
}

#[tokio::test]
async fn facet_set_guard_refuses_parameterized_and_time_dependent_needs() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let param_declaration = facet_set_declaration(
        json!([facet_set_bound("effort", json!(["large"]), "grid.param")]),
        json!([
            "attention.query.v1",
            json!({"need": "sql.snapshot.v1", "key": "grid.param", "label": "Param",
                "sql": "SELECT w.id FROM links l JOIN records w ON w.id = l.source_id \
                 WHERE l.relationship = 'member_of' AND w.id = ?1 ORDER BY w.id ASC LIMIT 40",
                "params": [{"name": "target", "type": "text", "required": true}]}),
        ]),
    );
    let setup = facet_set_setup(param_declaration).await;
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:param:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "facet_need_parameterized",
        "{refused:#}"
    );
    // Release the shared fixture guard before building a second fixture:
    // shadowing `setup` while the first still holds `_lock` deadlocks.
    drop(setup);
    let clock_declaration = facet_set_declaration(
        json!([facet_set_bound("effort", json!(["large"]), "grid.clock")]),
        json!([
            "attention.query.v1",
            facet_set_need(
                "grid.clock",
                "SELECT id FROM records WHERE deleted_at IS NULL AND last_activity_at_ms < now_ms() ORDER BY id ASC LIMIT 40",
            ),
        ]),
    );
    let setup = facet_set_setup(clock_declaration).await;
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:clock:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "facet_need_time_dependent",
        "{refused:#}"
    );
}

#[tokio::test]
async fn facet_set_guard_conflicts_on_stale_cas_and_replays_once() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let committed = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:cas:one",
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let version = committed["changes"][0]["version"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(version, "obs:0");
    let replay = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:cas:one",
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:cas:one").await,
        1,
        "a replay commits nothing"
    );
    // The initial token is now genuinely stale: the write above moved the
    // facet, so quoting obs:0 on a new key conflicts.
    let conflict = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:cas:two",
    )
    .await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:cas:two").await,
        0
    );
    // A forged token the engine never issued is not a CAS mismatch: it is
    // an invalid precondition, and it also writes nothing.
    let forged = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:999999" }),
        "facet:cas:three",
    )
    .await;
    assert_eq!(forged["status"], "rejected", "{forged:#}");
    assert_eq!(
        forged["error"]["code"], "invalid_precondition",
        "{forged:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:cas:three").await,
        0
    );
}

#[tokio::test]
async fn facet_set_consent_cannot_drive_the_lifecycle_arm() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // A facet-set install admits ordinary facets only: invoking the
    // lifecycle arm under it refuses, so no generic bound bypasses the
    // dedicated Start transition.
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let refused = facet_set_invoke(
        &setup,
        "start_work",
        INSIDE,
        json!({ "lifecycle": "rec:0" }),
        "facet:lifecycle:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_effect_unconsented",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:lifecycle:no").await,
        0
    );
}

#[tokio::test]
async fn facet_set_widened_declaration_breaks_the_guard_pin() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let body = html_interaction_source(&artifact_source("Orders"));
    let wide = facet_set_declaration(
        json!([facet_set_bound(
            "effort",
            json!(["large", "small", "urgent"]),
            "grid.items"
        )]),
        json!([
            "attention.query.v1",
            facet_set_need("grid.items", &facet_set_member_sql()),
        ]),
    );
    let (_, wide_declaration_digest) = alpha_guard_pin_for(&body, &wide);
    let mut widened_guard = setup.guard.clone();
    widened_guard["declaration_digest"] = json!(wide_declaration_digest);
    let refused = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "note_effort",
            "source_digest": setup.body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "effort": "obs:0" } },
            "idempotency_key": "facet:pin:no",
            "alpha_install_guard": widened_guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_pin_mismatch",
        "{refused:#}"
    );
}

#[tokio::test]
async fn facet_set_commit_leaves_reads_working_after_temp_cleanup() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let committed = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:clean:one",
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let read = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "get_record",
        json!({ "id": INSIDE }),
    )
    .await
    .unwrap();
    assert!(read.get("error").is_none(), "{read:#}");
    let queried = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "query_sql",
        json!({ "sql": "SELECT id FROM records WHERE id = '0a5e0000-0000-4000-8000-000000000002'" }),
    )
    .await
    .unwrap();
    assert!(queried.get("error").is_none(), "{queried:#}");
}

#[tokio::test]
async fn facet_set_replay_settles_after_target_leaves_need() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // The dynamic need gate runs after the replay branch: a target that has
    // since left the delivered rows still settles its prior receipt on an
    // identical retry, while a fresh key refuses.
    let setup = facet_set_setup(facet_set_declaration(
        json!([facet_set_bound("effort", json!(["large"]), "grid.named")]),
        json!([
            "attention.query.v1",
            facet_set_need(
                "grid.named",
                &format!(
                    "SELECT w.id FROM links l JOIN records w ON w.id = l.source_id \
                     WHERE l.relationship = 'member_of' AND l.target_id = '{COLLECTION}' \
                     AND w.name = '{INSIDE}' ORDER BY w.id ASC LIMIT 40"
                ),
            ),
        ]),
    ))
    .await;
    let committed = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:replay:gone",
    )
    .await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let renamed = call(
        &setup.registry,
        &setup.db,
        "update_record",
        json!({ "record_id": INSIDE, "name": "Moved", "reason": "Leave the declared need." }),
    )
    .await;
    assert!(renamed.get("error").is_none(), "{renamed:#}");
    let replay = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:replay:gone",
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:replay:gone").await,
        1,
        "a replay commits nothing"
    );
    let fresh = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:replay:fresh",
    )
    .await;
    assert_eq!(fresh["status"], "rejected", "{fresh:#}");
    assert_eq!(fresh["error"]["code"], "record_outside_need", "{fresh:#}");
}

#[tokio::test]
async fn facet_set_outside_binding_refuses_before_write() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // A facet-set entry traverses the same pre-transaction binding gate: a
    // record outside the bound input refuses before any transaction work.
    // (In-transaction mapping divergence is not deterministically
    // interleavable headless; the in-txn re-proof covers the race.)
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let refused = facet_set_invoke(
        &setup,
        "note_effort",
        OUTSIDE,
        json!({ "effort": "obs:0" }),
        "facet:binding:no",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "record_outside_binding",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:binding:no").await,
        0
    );
}

#[tokio::test]
async fn facet_set_guard_refuses_revoked_consent_before_write() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = facet_set_setup(facet_set_grid_declaration()).await;
    let event_id = setup.guard["expected_install_event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let disabled = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable",
            "package": ALPHA_GUARD_PACKAGE_A,
            "expected_install_event_id": event_id,
            "reason": "Pause the facet-set tab.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(disabled["install"]["status"], "disabled");
    // The pre-disable guard generation is stale: CAS mismatch fires before
    // the disabled gate, per validation order.
    let stale = facet_set_invoke(
        &setup,
        "note_effort",
        INSIDE,
        json!({ "effort": "obs:0" }),
        "facet:revoked:stale",
    )
    .await;
    assert_eq!(stale["status"], "rejected", "{stale:#}");
    assert_eq!(
        stale["error"]["code"], "alpha_guard_cas_mismatch",
        "{stale:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:revoked:stale").await,
        0
    );
    // A guard refreshed to the disabled generation reaches the disabled
    // gate instead.
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut refreshed = setup.guard.clone();
    refreshed["expected_install_event_id"] = json!(disabled_event);
    let refused = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "note_effort",
            "source_digest": setup.body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "effort": "obs:0" } },
            "idempotency_key": "facet:revoked:no",
            "alpha_install_guard": refreshed,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_disabled",
        "{refused:#}"
    );
    assert_eq!(
        alpha_guard_keyed_writes(&setup.db, "facet:revoked:no").await,
        0
    );
}

#[tokio::test]
async fn facet_set_legacy_string_install_keeps_legacy_refusal() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // An ordinary facet.set entry under a legacy string-only install (no
    // object bounds) keeps the historical scope refusal exactly — the
    // generic consent path never sees it.
    let body = html_interaction_source(&artifact_source("Orders"));
    let (db, registry, body_digest, _lock) =
        fixture_with_source(body.clone(), "native.html.v1").await;
    alpha_guard_grants(&db, ALPHA_GUARD_ACCOUNT).await;
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &body,
        alpha_guard_declaration(),
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let refused = call_as(
        &registry,
        &db,
        alice,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "note_effort",
            "source_digest": body_digest,
            "slots": { "record": INSIDE },
            "observed": { INSIDE: { "effort": "obs:0" } },
            "idempotency_key": "facet:legacy:no",
            "alpha_install_guard": guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "alpha_guard_facet_unconsented",
        "{refused:#}"
    );
    assert_eq!(alpha_guard_keyed_writes(&db, "facet:legacy:no").await, 0);
}

// ---------------------------------------------------------------------------
// b9fb9fd family1 public comment activation (three-file packet, base 4598).
//
// Real registry + genuine commands only; no fake receipts. Synthetic
// corruption rows are explicitly labeled and never seed successful receipts.
// ---------------------------------------------------------------------------

fn comment_public_mdx_source() -> String {
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
      comment: { position: "root", body: { input: "text", max_bytes: 100 } } },
    { id: "post_reply", label: "Post reply", effect: "comment.create",
      slots: { bearer: { domain: { kind: "bound_input", port: "orders" } } },
      comment: { position: "reply", body: { input: "text", max_bytes: 100 } } }
  ]
}

<Metric label="Total" value={1} />
"#
    .into()
}

fn comment_public_need_sql() -> String {
    "SELECT id FROM records WHERE deleted_at IS NULL AND ((type='Document' AND kind='note') OR (type='Annotation' AND kind='comment')) ORDER BY id ASC LIMIT 200".into()
}

fn comment_public_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread", "sql": comment_public_need_sql()}
        ],
        "effects": [{
            "effect": "comment.create.v1",
            "positions": ["root", "reply"],
            "max_body_bytes": 100,
            "target": {"need": "thread.items"}
        }]
    })
}

struct CommentPublicSetup {
    db: Db,
    registry: ToolRegistry,
    body_digest: String,
    guard: Value,
    alice: Caller,
    _lock: tokio::sync::OwnedMutexGuard<()>,
}

async fn comment_public_setup() -> CommentPublicSetup {
    let lock = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let mdx = comment_public_mdx_source();
    let html = html_interaction_source(&mdx);
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Comment thread",
            "body": html, "facets": { "runtime": "native.html.v1" },
            "reason": "Declare public comment entries against a bound Collection."
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
    // Explicitly labeled identity seed (test setup only, following the
    // private kernel fixture): the canonical portable person/account binding
    // the comment kernel requires (lifecycle3083). Seeds no receipts.
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
    .bind(ALPHA_GUARD_ACCOUNT)
    .execute(&write_pool)
    .await
    .unwrap();
    for (id, edit) in [
        (ARTIFACT, false),
        (COLLECTION, true),
        (REFERENCE_COLLECTION, false),
        (INSIDE, true),
    ] {
        let mut allows = vec![AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View)];
        if edit {
            allows.push(AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::Edit));
        }
        replace_explicit_policy(&db, "test:policy", id, allows)
            .await
            .unwrap();
    }
    let declaration = comment_public_declaration();
    let (verified, source_revision, digest, declaration_digest) = alpha_guard_verified_install(
        &db,
        &registry,
        ALPHA_GUARD_ACCOUNT,
        ALPHA_GUARD_PACKAGE_A,
        &html,
        declaration,
    )
    .await;
    let guard = alpha_guard_json(
        ALPHA_GUARD_PACKAGE_A,
        &verified,
        &source_revision,
        &digest,
        &declaration_digest,
    );
    let alice = Caller::authenticated(ALPHA_GUARD_ACCOUNT);
    let body_digest = digest_of(&html);
    CommentPublicSetup {
        db,
        registry,
        body_digest,
        guard,
        alice,
        _lock: lock,
    }
}

async fn comment_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type='Annotation' AND kind='comment'")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Pins the specific outer Sqlx Database error for malformed stored JSON
/// (SQLite code 1) without masking it into a generic refusal. Returns the
/// message so old and absent keys assert the identical specific error.
fn malformed_json_message(err: &native_ce::Error) -> &str {
    match err {
        native_ce::Error::Sqlx(sqlx::Error::Database(db)) => {
            assert_eq!(db.code().as_deref(), Some("1"), "{err:?}");
            assert!(db.message().contains("malformed JSON"), "{err:?}");
            db.message()
        }
        other => panic!("expected outer Sqlx Database error, got {other:?}"),
    }
}

/// Rows the registry wrapper can find for one operation: proves genuine
/// invoke history exists instead of assuming a commit leaves it.
async fn invoke_attestation_rows(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='invoke_artifact_interaction'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// Minimal generic seed source: one `record.create` entry with a
/// source-supported literal destination on the granted real folder. Seeds
/// genuine `invoke_artifact_interaction` history under a chosen key with no
/// bindings or grants of its own.
fn comment_history_seed_source() -> String {
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{}},
  module_inputs: {{}},
  capability_requests: [],
  interactions: [
    {{ id: "seed_note", label: "Seed", effect: "record.create",
      create: {{ destination: {{ from: "literal", record_id: "{COLLECTION}" }}, shape: {{
        type: {{ source: {{ from: "literal", value: "Document" }}, domain: {{ kind: "enum", values: ["Document"] }} }},
        kind: {{ source: {{ from: "literal", value: "note" }}, domain: {{ kind: "enum", values: ["note"] }} }},
        fields: {{ name: {{ label: "Title", source: {{ from: "input", input: "title" }}, domain: {{ kind: "string", min_length: 1, max_length: 80 }} }} }},
        facets: {{}}
      }} }} }}
  ]
}}

<Metric label="Seed" value={{1}} />
"#
    )
}

fn assert_minimal_comment_receipt(result: &Value) {
    assert!(result.get("action_attestation_ids").is_none(), "{result:#}");
    assert!(result.get("act").is_none(), "{result:#}");
    assert!(result.get("refresh").is_none(), "{result:#}");
    assert!(result.get("account").is_none(), "{result:#}");
    let text = result.to_string();
    assert!(!text.contains("\"seq\""), "{result:#}");
}

#[tokio::test]
async fn comment_public_guarded_root_and_reply_with_minimal_receipts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = comment_public_setup().await;
    let rendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let supported = rendered["plan"]["interaction_availability"]["supported_entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(supported.iter().any(|e| e == "post_root"), "{rendered:#}");
    assert!(supported.iter().any(|e| e == "post_reply"), "{rendered:#}");
    let token = rendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .expect("real render mints a comment target token")
        .to_owned();
    assert!(token.starts_with("ct:"), "{rendered:#}");
    let base = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "post_root",
        "source_digest": setup.body_digest,
        "slots": { "bearer": INSIDE },
        "values": { "text": "First root" },
        "observed": { INSIDE: { "comment_target": token } },
        "idempotency_key": "comment:root:one",
        "gesture": "submit",
        "alpha_install_guard": setup.guard,
    });
    let first = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        base.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["status"], "committed", "{first:#}");
    assert_eq!(first["changes"][0]["key"], "comment", "{first:#}");
    assert!(first["changes"][0]["before"].is_null(), "{first:#}");
    assert_eq!(first["changes"][0]["after"]["created"], true, "{first:#}");
    assert_eq!(
        first["changes"][0]["after"]["bearer_id"], INSIDE,
        "{first:#}"
    );
    assert_eq!(
        first["changes"][0]["after"]["position"], "root",
        "{first:#}"
    );
    assert_minimal_comment_receipt(&first);
    let root_id = first["changes"][0]["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(comment_count(&setup.db).await, 1);
    let replay = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        base.clone(),
    )
    .await
    .unwrap();
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(replay["changes"][0]["record_id"], root_id, "{replay:#}");
    assert_minimal_comment_receipt(&replay);
    assert_eq!(
        comment_count(&setup.db).await,
        1,
        "replay must not duplicate"
    );
    let mut omitted = base.clone();
    omitted.as_object_mut().unwrap().remove("observed");
    let omitted_replay = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        omitted,
    )
    .await
    .unwrap();
    assert_eq!(omitted_replay["status"], "committed", "{omitted_replay:#}");
    assert_eq!(
        omitted_replay["changes"][0]["record_id"], root_id,
        "{omitted_replay:#}"
    );
    assert_minimal_comment_receipt(&omitted_replay);
    assert_eq!(comment_count(&setup.db).await, 1);
    let mut changed = base.clone();
    changed["values"]["text"] = json!("A different intent");
    let changed_result = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        changed,
    )
    .await
    .unwrap();
    assert_eq!(changed_result["status"], "rejected", "{changed_result:#}");
    assert_eq!(
        changed_result["error"]["code"], "idempotency_conflict",
        "{changed_result:#}"
    );
    assert_minimal_comment_receipt(&changed_result);
    assert_eq!(comment_count(&setup.db).await, 1);
    let rerendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let reply_token = rerendered["plan"]["observed"][root_id.as_str()]["comment_target"]
        .as_str()
        .expect("flat reply bearer gets a real render token")
        .to_owned();
    let reply = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "post_reply",
            "source_digest": setup.body_digest,
            "slots": { "bearer": root_id.clone() },
            "values": { "text": "Flat reply" },
            "observed": { root_id: { "comment_target": reply_token } },
            "idempotency_key": "comment:reply:one",
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(reply["status"], "committed", "{reply:#}");
    assert_eq!(
        reply["changes"][0]["after"]["position"], "reply",
        "{reply:#}"
    );
    assert_minimal_comment_receipt(&reply);
    assert_eq!(comment_count(&setup.db).await, 2);
    let reply_id = reply["changes"][0]["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rerendered2 = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let nested_token = rerendered2["plan"]["observed"][reply_id.as_str()]["comment_target"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    if !nested_token.is_empty() {
        let nested = call_as(
            &setup.registry,
            &setup.db,
            setup.alice.clone(),
            "invoke_artifact_interaction",
            json!({
                "version": INVOCATION_VERSION,
                "artifact_id": ARTIFACT,
                "entry_id": "post_reply",
                "source_digest": setup.body_digest,
                "slots": { "bearer": reply_id.clone() },
                "values": { "text": "Reply to reply" },
                "observed": { reply_id: { "comment_target": nested_token } },
                "idempotency_key": "comment:reply:nested",
                "gesture": "submit",
                "alpha_install_guard": setup.guard,
            }),
        )
        .await
        .unwrap();
        assert_eq!(nested["status"], "rejected", "{nested:#}");
        assert_minimal_comment_receipt(&nested);
        assert_eq!(
            comment_count(&setup.db).await,
            2,
            "reply-to-flat-reply writes nothing"
        );
    }
}

#[tokio::test]
async fn comment_public_post_gate_conflict_is_honest_without_leak() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = comment_public_setup().await;
    let rendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let token = rendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .unwrap()
        .to_owned();
    let base = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "post_root",
        "source_digest": setup.body_digest,
        "slots": { "bearer": INSIDE },
        "values": { "text": "Conflict probe" },
        "observed": { INSIDE: { "comment_target": token } },
        "idempotency_key": "comment:conflict:one",
        "gesture": "submit",
        "alpha_install_guard": setup.guard,
    });
    let first = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        base.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["status"], "committed", "{first:#}");
    let mut omitted_same_key = base.clone();
    omitted_same_key.as_object_mut().unwrap().remove("observed");
    omitted_same_key["values"]["text"] = json!("Changed under same key");
    let same_key = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        omitted_same_key,
    )
    .await
    .unwrap();
    assert_eq!(same_key["status"], "rejected", "{same_key:#}");
    assert_eq!(
        same_key["error"]["code"], "idempotency_conflict",
        "{same_key:#}"
    );
    assert_minimal_comment_receipt(&same_key);
    let mut absent_key = base.clone();
    absent_key.as_object_mut().unwrap().remove("observed");
    absent_key["values"]["text"] = json!("Fresh key without CAS");
    absent_key["idempotency_key"] = json!("comment:conflict:absent");
    let absent = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        absent_key,
    )
    .await
    .unwrap();
    assert_eq!(absent["status"], "rejected", "{absent:#}");
    assert_eq!(
        absent["error"]["code"], "invalid_precondition",
        "{absent:#}"
    );
    assert_minimal_comment_receipt(&absent);
    assert_ne!(
        same_key["error"]["code"], absent["error"]["code"],
        "post-gate stages pin honestly: legacy same-key conflicts while absent-key needs CAS"
    );
}

#[tokio::test]
async fn comment_public_parent_edit_new_key_cas_conflict_is_minimal() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Genuine public parent edit, then a stale NEW key: the kernel's
    // post-gate replay finds nothing, and the fresh CAS recomputation
    // conflicts with the current opaque ct and the actual parent event
    // UUID — a minimal receipt with zero added comments. The edited parent
    // stays delivered and in-cohort throughout.
    let setup = comment_public_setup().await;
    let rendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let token = rendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .unwrap()
        .to_owned();
    let first = call_as(
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
            "values": { "text": "CAS probe root" },
            "observed": { INSIDE: { "comment_target": token } },
            "idempotency_key": "comment:cas:one",
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(first["status"], "committed", "{first:#}");
    assert_eq!(comment_count(&setup.db).await, 1);
    let edited = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "update_record",
        json!({
            "id": INSIDE,
            "name": "Thread root, edited",
            "reason": "Genuine public parent edit moving the thread CAS.",
        }),
    )
    .await
    .unwrap();
    assert!(edited.get("error").is_none(), "{edited:#}");
    let rerendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    assert_eq!(rerendered["status"], "rendered", "{rerendered:#}");
    let cohort = rerendered["plan"]["interaction_availability"]["records_by_port"]["orders"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        cohort.iter().any(|record| record == INSIDE),
        "edited parent stays delivered and in-cohort: {rerendered:#}"
    );
    let stale = call_as(
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
            "values": { "text": "Stale CAS new key" },
            "observed": { INSIDE: { "comment_target": token } },
            "idempotency_key": "comment:cas:stale-new",
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(stale["status"], "conflict", "{stale:#}");
    assert_eq!(stale["error"]["code"], "comment_conflict", "{stale:#}");
    let current_version = stale["current_version"].as_str().unwrap_or("");
    assert!(
        current_version.starts_with("ct:"),
        "conflict carries the current opaque ct: {stale:#}"
    );
    // Actual identity, not format alone: the conflict version equals the
    // freshly rerendered host-minted token for the edited parent.
    let fresh_token = rerendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        current_version, fresh_token,
        "conflict version is the actual current host-minted token: {stale:#}"
    );
    let conflicting_event_id = stale["conflicting_event_id"].as_str().unwrap_or("");
    assert_eq!(
        conflicting_event_id.len(),
        36,
        "conflict carries the actual parent event UUID: {stale:#}"
    );
    // Actual identity per the state helper's latest-event selection (ids, no
    // seq outward): the fresh parent content event after the genuine update.
    let latest_parent_event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(INSIDE)
    .fetch_one(setup.db.pool())
    .await
    .unwrap();
    assert_eq!(
        conflicting_event_id, latest_parent_event,
        "conflict names the actual latest parent event: {stale:#}"
    );
    assert_minimal_comment_receipt(&stale);
    assert_eq!(comment_count(&setup.db).await, 1);
}

#[tokio::test]
async fn comment_public_generic_preservation_and_create_control() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = create_fixture().await;
    let invocation = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "create_task",
        "source_digest": digest,
        "values": { "title": "Preserve me", "triage": "ready" },
        "idempotency_key": "generic:preserve:one",
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
        .unwrap()
        .to_owned();
    assert!(
        first.get("action_attestation_ids").is_none() || first["action_attestation_ids"].is_array()
    );
    let control = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Control",
                "reason": "Control proves the generic wrapper still attaches ids." }),
    )
    .await;
    assert!(
        control.get("action_attestation_ids").is_some()
            || control.get("action_attestation_id").is_some(),
        "create_record control still attaches ids: {control:#}"
    );
    let comment_source = comment_artifact_source("post");
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT,
            "body": format!("{}\n", comment_source),
            "if_body_digest": digest,
            "reason": "Edit source to Comment after generic commit."
        }),
    )
    .await;
    let write_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DELETE FROM artifact_source_attestations WHERE artifact_id=?")
        .bind(ARTIFACT)
        .execute(&write_pool)
        .await
        .unwrap();
    let replay = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        invocation.clone(),
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(replay["refresh"]["record"]["id"], created_id, "{replay:#}");
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
async fn comment_public_pregate_equality_no_guard_revoked_and_corrupt() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Pre-gate no-history pins with GENUINE registry history: a separate
    // generic literal-destination artifact commits under the SAME caller and
    // old key first, and the provenance row is asserted (never assumed).
    // Missing guard, genuine Edit revocation (View kept), wrong-source
    // digest, and real storage corruption then refuse old and absent keys
    // equivalently with zero added comments and minimal receipts. All
    // successful creations are genuine registry/kernel writes.
    const OLD_KEY: &str = "comment:pregate:one";
    let setup = comment_public_setup().await;
    let seed_source = comment_history_seed_source();
    let seed_created = call(
        &setup.registry,
        &setup.db,
        "create_record",
        json!({
            "id": COMMENT_SEED_ARTIFACT, "type": "Document", "kind": "artifact",
            "name": "History seed", "body": seed_source,
            "facets": { "runtime": "native.mdx.v2" },
            "reason": "Separate generic artifact seeding genuine invoke history under the old key.",
        }),
    )
    .await;
    assert!(seed_created.get("error").is_none(), "{seed_created:#}");
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        COMMENT_SEED_ARTIFACT,
        vec![AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View)],
    )
    .await
    .unwrap();
    let history_before = invoke_attestation_rows(&setup.db).await;
    let seed = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": COMMENT_SEED_ARTIFACT,
            "entry_id": "seed_note",
            "source_digest": digest_of(&seed_source),
            "values": { "title": "History seed" },
            "idempotency_key": OLD_KEY,
            "gesture": "submit",
        }),
    )
    .await
    .unwrap();
    assert_eq!(seed["status"], "committed", "{seed:#}");
    assert!(
        invoke_attestation_rows(&setup.db).await > history_before,
        "the old key must genuinely own registry history before the probes"
    );
    let rendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let token = rendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .unwrap()
        .to_owned();
    // (a) Missing guard: the composer refuses before any write, identically.
    let no_guard_old = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "post_root",
        "source_digest": setup.body_digest,
        "slots": { "bearer": INSIDE },
        "values": { "text": "No guard old key" },
        "observed": { INSIDE: { "comment_target": token } },
        "idempotency_key": OLD_KEY,
        "gesture": "submit"
    });
    let mut no_guard_new = no_guard_old.clone();
    no_guard_new["idempotency_key"] = json!("comment:pregate:absent");
    let old = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        no_guard_old,
    )
    .await
    .unwrap();
    let fresh = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        no_guard_new,
    )
    .await
    .unwrap();
    assert_eq!(old["status"], "rejected", "{old:#}");
    assert_eq!(fresh["status"], "rejected", "{fresh:#}");
    assert_eq!(old["error"]["code"], "alpha_guard_required", "{old:#}");
    assert_eq!(
        old["error"]["code"], fresh["error"]["code"],
        "{old:#} vs {fresh:#}"
    );
    assert_minimal_comment_receipt(&old);
    assert_minimal_comment_receipt(&fresh);
    assert_eq!(comment_count(&setup.db).await, 0);
    // (b) Genuine mounted-target Edit revocation with View kept: the kernel
    // refuses inside its write transaction, identically for both keys.
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        INSIDE,
        vec![AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View)],
    )
    .await
    .unwrap();
    let revoked_old = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "post_root",
        "source_digest": setup.body_digest,
        "slots": { "bearer": INSIDE },
        "values": { "text": "Revoked old key" },
        "observed": { INSIDE: { "comment_target": token } },
        "idempotency_key": OLD_KEY,
        "gesture": "submit",
        "alpha_install_guard": setup.guard,
    });
    let mut revoked_new = revoked_old.clone();
    revoked_new["idempotency_key"] = json!("comment:revoke:absent");
    let revoked = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        revoked_old,
    )
    .await
    .unwrap();
    let revoked_absent = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        revoked_new,
    )
    .await
    .unwrap();
    assert_eq!(revoked["status"], "rejected", "{revoked:#}");
    assert_eq!(revoked["error"]["code"], "permission_denied", "{revoked:#}");
    assert_eq!(
        revoked["error"]["code"], revoked_absent["error"]["code"],
        "{revoked:#} vs {revoked_absent:#}"
    );
    assert_minimal_comment_receipt(&revoked);
    assert_minimal_comment_receipt(&revoked_absent);
    assert_eq!(comment_count(&setup.db).await, 0);
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        INSIDE,
        vec![
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View),
            AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    // (c) Wrong-source digest: Unresolved, stale before any write, identical.
    let wrong_old = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "post_root",
        "source_digest": "0".repeat(64),
        "slots": { "bearer": INSIDE },
        "values": { "text": "Wrong source old" },
        "observed": { INSIDE: { "comment_target": token } },
        "idempotency_key": OLD_KEY,
        "gesture": "submit",
        "alpha_install_guard": setup.guard,
    });
    let mut wrong_new = wrong_old.clone();
    wrong_new["idempotency_key"] = json!("comment:wrong:absent");
    let wrong = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        wrong_old,
    )
    .await
    .unwrap();
    let wrong_absent = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        wrong_new,
    )
    .await
    .unwrap();
    assert_eq!(wrong["status"], "rejected", "{wrong:#}");
    assert_eq!(wrong["error"]["code"], "stale_source_digest", "{wrong:#}");
    assert_eq!(
        wrong["error"]["code"], wrong_absent["error"]["code"],
        "{wrong:#} vs {wrong_absent:#}"
    );
    assert_minimal_comment_receipt(&wrong);
    assert_minimal_comment_receipt(&wrong_absent);
    assert_eq!(comment_count(&setup.db).await, 0);
    // (d) Explicitly labeled negative STORAGE corruption (test-only): the
    // artifact's actual body-bearing content_events.payload is set to SQL
    // NULL and then to syntactically invalid JSON through the held write
    // pool, dropping only the update guard around the edits and restoring
    // guard bytes afterwards. The classifier's json_valid boundary reads
    // both as absent (Unresolved) and resolution diagnoses
    // invalid_artifact_body — never a commit, never attestation enrichment.
    let write_pool = crate::common::fixture_write_pool(&setup.db).await;
    let mut conn = write_pool.acquire().await.unwrap();
    let (event_id, original): (String, String) = sqlx::query_as(
        "SELECT id, payload FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT)
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let update_guard: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_events_no_update'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(&mut *conn)
        .await
        .unwrap();
    // SQL NULL stays a typed diagnostic; syntactically invalid stored JSON
    // raises the actual outer Sqlx Database error (code 1, malformed JSON)
    // through ordinary resolution — pinned specifically for BOTH keys, never
    // masked into a generic refusal, with zero writes either way.
    for (label, set, typed) in [
        (
            "null-payload",
            "UPDATE content_events SET payload = NULL WHERE id = ?",
            true,
        ),
        (
            "invalid-payload",
            "UPDATE content_events SET payload = '{corrupt' WHERE id = ?",
            false,
        ),
    ] {
        sqlx::query(set)
            .bind(&event_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        let corrupt_old = json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "post_root",
            "source_digest": setup.body_digest,
            "slots": { "bearer": INSIDE },
            "values": { "text": "Corrupt old key" },
            "observed": { INSIDE: { "comment_target": token } },
            "idempotency_key": OLD_KEY,
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        });
        let mut corrupt_new = corrupt_old.clone();
        corrupt_new["idempotency_key"] = json!(format!("comment:corrupt:{label}:absent"));
        if typed {
            let corrupt = call_as(
                &setup.registry,
                &setup.db,
                setup.alice.clone(),
                "invoke_artifact_interaction",
                corrupt_old,
            )
            .await
            .unwrap();
            let corrupt_absent = call_as(
                &setup.registry,
                &setup.db,
                setup.alice.clone(),
                "invoke_artifact_interaction",
                corrupt_new,
            )
            .await
            .unwrap();
            assert_eq!(corrupt["status"], "rejected", "{label} {corrupt:#}");
            assert_eq!(
                corrupt["error"]["code"], "invalid_artifact_body",
                "{label} {corrupt:#}"
            );
            assert_eq!(
                corrupt["error"]["code"], corrupt_absent["error"]["code"],
                "{label} {corrupt:#} vs {corrupt_absent:#}"
            );
            assert_minimal_comment_receipt(&corrupt);
            assert_minimal_comment_receipt(&corrupt_absent);
        } else {
            let err_old = call_as(
                &setup.registry,
                &setup.db,
                setup.alice.clone(),
                "invoke_artifact_interaction",
                corrupt_old,
            )
            .await
            .expect_err("invalid stored JSON must surface, never mask");
            let err_absent = call_as(
                &setup.registry,
                &setup.db,
                setup.alice.clone(),
                "invoke_artifact_interaction",
                corrupt_new,
            )
            .await
            .expect_err("invalid stored JSON must surface, never mask");
            assert_eq!(
                malformed_json_message(&err_old),
                malformed_json_message(&err_absent),
                "{label} {err_old:?} vs {err_absent:?}"
            );
        }
        assert_eq!(comment_count(&setup.db).await, 0);
    }
    sqlx::query("UPDATE content_events SET payload = ? WHERE id = ?")
        .bind(&original)
        .bind(&event_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(&update_guard)
        .execute(&mut *conn)
        .await
        .unwrap();
    let restored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='content_events_no_update'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(restored, 1);
    // Source-derived per-case value pins (not storage corruption): a null
    // body fails envelope shape (typed invalid/invalid_invocation), while a
    // non-string array body passes shape but lies outside the string domain
    // (rejected/value_outside_domain from the composer).
    for (label, values, status, code) in [
        (
            "null-body",
            json!({ "text": Value::Null }),
            "invalid",
            "invalid_invocation",
        ),
        (
            "non-string-value",
            json!({ "text": json!([]) }),
            "rejected",
            "value_outside_domain",
        ),
    ] {
        let attempt = call_as(
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
                "values": values,
                "observed": { INSIDE: { "comment_target": token } },
                "idempotency_key": format!("comment:shape:{label}"),
                "gesture": "submit",
                "alpha_install_guard": setup.guard,
            }),
        )
        .await
        .unwrap();
        assert_eq!(attempt["status"], status, "{attempt:#}");
        assert_eq!(attempt["error"]["code"], code, "{attempt:#}");
        assert_minimal_comment_receipt(&attempt);
    }
    assert_eq!(
        comment_count(&setup.db).await,
        0,
        "corruption refusals write nothing"
    );
}

#[tokio::test]
async fn comment_public_malformed_ct_old_vs_absent_key_preadmission() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Pre-admission pin (required, no-history): a malformed observed
    // comment_target token fails envelope shape, but the host still
    // requires artifact View and classifies the actual cited source before
    // answering `invalid_invocation`. Actual Comment/Unresolved marks
    // DomainOwned, so an old key and an absent key refuse identically with
    // zero writes and a minimal receipt (no wrapper attach/Err).
    let setup = comment_public_setup().await;
    let rendered = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "render_artifact",
        json!({"id": ARTIFACT}),
    )
    .await
    .unwrap();
    let token = rendered["plan"]["observed"][INSIDE]["comment_target"]
        .as_str()
        .expect("real render mints a comment target token")
        .to_owned();
    let valid = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "post_root",
        "source_digest": setup.body_digest,
        "slots": { "bearer": INSIDE },
        "values": { "text": "Malformed probe root" },
        "observed": { INSIDE: { "comment_target": token } },
        "idempotency_key": "comment:malformed:old",
        "gesture": "submit",
        "alpha_install_guard": setup.guard,
    });
    let history_before = invoke_attestation_rows(&setup.db).await;
    let committed = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        valid.clone(),
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    assert_eq!(comment_count(&setup.db).await, 1);
    assert!(
        invoke_attestation_rows(&setup.db).await > history_before,
        "the old key must genuinely own registry history before the malformed probes"
    );
    let mut old_malformed = valid.clone();
    old_malformed["observed"] = json!({ INSIDE: { "comment_target": "ct:dead" } });
    let mut absent_malformed = old_malformed.clone();
    absent_malformed["idempotency_key"] = json!("comment:malformed:absent");
    let old = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        old_malformed,
    )
    .await
    .unwrap();
    let absent = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "invoke_artifact_interaction",
        absent_malformed,
    )
    .await
    .unwrap();
    assert_eq!(old["status"], "invalid", "{old:#}");
    assert_eq!(absent["status"], "invalid", "{absent:#}");
    assert_eq!(old["error"]["code"], "invalid_invocation", "{old:#}");
    assert_eq!(
        old["error"]["code"], absent["error"]["code"],
        "{old:#} vs {absent:#}"
    );
    assert_minimal_comment_receipt(&old);
    assert_minimal_comment_receipt(&absent);
    assert_eq!(
        comment_count(&setup.db).await,
        1,
        "pre-admission malformed-ct refusals write nothing"
    );
}

#[tokio::test]
async fn comment_public_verified_other_malformed_shape_stays_legacy() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Legacy control (not a no-history requirement): a malformed shape on a
    // verified non-comment citation stays Legacy, so the existing wrapper
    // behavior is unchanged — an old key errs history-dependently while an
    // absent key stays typed-invalid. This pins that the refined placement
    // did not alter the generic valid retry/Err path.
    let (db, registry, digest, _guard) = create_fixture().await;
    let valid = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "create_task",
        "source_digest": digest,
        "values": { "title": "Legacy control", "triage": "ready" },
        "idempotency_key": "generic:malformed:old",
        "gesture": "submit"
    });
    let first = call(&registry, &db, "invoke_artifact_interaction", valid.clone()).await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let mut old_malformed = valid.clone();
    old_malformed["observed"] = json!({ INSIDE: { "triage": "bogus-token" } });
    let mut absent_malformed = old_malformed.clone();
    absent_malformed["idempotency_key"] = json!("generic:malformed:absent");
    let old = call_as(
        &registry,
        &db,
        Caller::local(),
        "invoke_artifact_interaction",
        old_malformed,
    )
    .await
    .expect_err("verified-Other malformed shape stays Legacy: old key errs");
    assert!(old.to_string().contains("conflicting action input"));
    let absent = call(
        &registry,
        &db,
        "invoke_artifact_interaction",
        absent_malformed,
    )
    .await;
    assert_eq!(absent["status"], "invalid", "{absent:#}");
    assert_eq!(absent["error"]["code"], "invalid_invocation", "{absent:#}");
}

#[tokio::test]
async fn comment_public_view_denied_malformed_shape_has_no_history() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // Fail-closed View: a caller who cannot see the artifact gets the
    // ordinary View failure (Err, never an Ok result the wrapper could
    // enrich), with zero writes — before any source/history diagnosis.
    let setup = comment_public_setup().await;
    let denied = call_as(
        &setup.registry,
        &setup.db,
        Caller::authenticated("bob-no-view"),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "post_root",
            "source_digest": setup.body_digest,
            "slots": { "bearer": INSIDE },
            "values": { "text": "Unseen" },
            "observed": { INSIDE: { "comment_target": "ct:dead" } },
            "idempotency_key": "comment:view:denied",
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .expect_err("an unreadable artifact propagates View failure, never an Ok result");
    assert_eq!(comment_count(&setup.db).await, 0);
    let _ = denied;
}

/// The stored `origin` object of the event carrying one idempotency key.
async fn stored_origin(db: &Db, key: &str) -> Value {
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=?
          AND json_extract(payload,'$.origin.idempotency_key')=?",
    )
    .bind(INSIDE)
    .bind(key)
    .fetch_one(db.pool())
    .await
    .unwrap();
    serde_json::from_str::<Value>(&payload).unwrap()["origin"].clone()
}

#[tokio::test]
async fn a_valid_effect_gesture_token_records_evidence_and_its_absence_does_not() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    // No token: the stored origin stays the ordinary shape.
    let mut plain = envelope("mark_triaged", &digest, "gesture:plain");
    plain["slots"] = json!({ "record": INSIDE });
    plain["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", plain).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let origin = stored_origin(&db, "gesture:plain").await;
    assert!(origin.get("gesture_evidence").is_none(), "{origin:#}");

    // A valid token for exactly this binding records evidence, additively.
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let ids = native_ce::awareness::effect_gesture_binding_ids(
        "local",
        ARTIFACT,
        None,
        None,
        "mark_triaged",
        &[INSIDE.to_string()],
        "gesture:token",
        &empty_values_digest(),
        native_ce::awareness::EffectGestureKind::Click,
    );
    let token = issuer
        .issue(
            "local",
            native_ce::awareness::EFFECT_GESTURE_ACTION,
            &ids,
            30,
        )
        .unwrap();
    let caller = Caller::local().with_effect_gesture_token(
        &issuer,
        token,
        native_ce::awareness::EffectGestureKind::Click,
    );
    let mut invocation = envelope("mark_triaged", &digest, "gesture:token");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let origin = stored_origin(&db, "gesture:token").await;
    assert_eq!(origin["gesture_evidence"]["kind"], "click", "{origin:#}");
    assert_eq!(
        origin["gesture_evidence"]["verifier"], "effect_gesture.v1",
        "{origin:#}"
    );
}

async fn event_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Mint a token for exactly this binding and attach it with `kind`. `kind` is
/// both what the token binds and the kind the Caller reports.
#[allow(clippy::too_many_arguments)] // The binding elements are explicit so each case reads as its one difference.
fn gesture_caller(
    issuer: &native_ce::awareness::HumanInteractionTokenIssuer,
    action: &str,
    package: Option<(&str, &str)>,
    generation: Option<&str>,
    entry: &str,
    target: &[String],
    key: &str,
    kind: native_ce::awareness::EffectGestureKind,
) -> Caller {
    gesture_caller_full(
        issuer,
        action,
        ARTIFACT,
        package,
        generation,
        entry,
        target,
        key,
        &empty_values_digest(),
        kind,
    )
}

/// Canonical digest of the empty value-domain fillings (the `mark_triaged`
/// arm carries a literal value, so its `values` map is empty).
fn empty_values_digest() -> String {
    canonical_digest(&json!({}))
}

#[allow(clippy::too_many_arguments)] // Every bound element is an argument on purpose.
fn gesture_caller_full(
    issuer: &native_ce::awareness::HumanInteractionTokenIssuer,
    action: &str,
    artifact: &str,
    package: Option<(&str, &str)>,
    generation: Option<&str>,
    entry: &str,
    target: &[String],
    key: &str,
    values_digest: &str,
    kind: native_ce::awareness::EffectGestureKind,
) -> Caller {
    let ids = native_ce::awareness::effect_gesture_binding_ids(
        "local",
        artifact,
        package,
        generation,
        entry,
        target,
        key,
        values_digest,
        kind,
    );
    let token = issuer.issue("local", action, &ids, 30).unwrap();
    Caller::local().with_effect_gesture_token(issuer, token, kind)
}

fn gesture_target() -> Vec<String> {
    vec![INSIDE.to_string()]
}

#[tokio::test]
async fn effect_gesture_element_mismatch_refuses_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    // A committed baseline, so a refusal must not move the target.
    let mut base = envelope("mark_triaged", &digest, "gesture:base");
    base["slots"] = json!({ "record": INSIDE });
    base["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call(&registry, &db, "invoke_artifact_interaction", base).await;
    assert_eq!(committed["status"], "committed", "{committed:#}");

    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let action = native_ce::awareness::EFFECT_GESTURE_ACTION;
    let key = "gesture:mismatch";
    let entry = "mark_triaged";
    let gesture_click: native_ce::awareness::EffectGestureKind =
        native_ce::awareness::EffectGestureKind::Click;
    // Each token's binding differs from the engine's computed binding in one
    // element only.
    let cases: Vec<(&str, Caller)> = vec![
        (
            "package",
            gesture_caller(
                &issuer,
                action,
                Some(("alpha", "wrong")),
                None,
                entry,
                &gesture_target(),
                key,
                gesture_click,
            ),
        ),
        (
            "install",
            gesture_caller(
                &issuer,
                action,
                None,
                Some("wrong"),
                entry,
                &gesture_target(),
                key,
                gesture_click,
            ),
        ),
        (
            "entry",
            gesture_caller(
                &issuer,
                action,
                None,
                None,
                "set_triage",
                &gesture_target(),
                key,
                gesture_click,
            ),
        ),
        (
            "target",
            gesture_caller(
                &issuer,
                action,
                None,
                None,
                entry,
                &[OUTSIDE.to_string()],
                key,
                gesture_click,
            ),
        ),
        (
            "key",
            gesture_caller(
                &issuer,
                action,
                None,
                None,
                entry,
                &gesture_target(),
                "gesture:other",
                gesture_click,
            ),
        ),
        (
            "action",
            gesture_caller(
                &issuer,
                native_ce::awareness::EFFECT_GESTURE_REVERSAL_ACTION,
                None,
                None,
                entry,
                &gesture_target(),
                key,
                gesture_click,
            ),
        ),
    ];
    for (name, caller) in cases {
        let before = event_count(&db).await;
        let mut invocation = envelope(entry, &digest, key);
        invocation["slots"] = json!({ "record": INSIDE });
        invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
        let refused = call_as(
            &registry,
            &db,
            caller,
            "invoke_artifact_interaction",
            invocation,
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

    // The Caller's gesture kind is part of the binding: a token minted for a
    // click but presented with a drop is invalid.
    let drop_mismatch = {
        let ids = native_ce::awareness::effect_gesture_binding_ids(
            "local",
            ARTIFACT,
            None,
            None,
            entry,
            &gesture_target(),
            key,
            &empty_values_digest(),
            gesture_click,
        );
        let token = issuer.issue("local", action, &ids, 30).unwrap();
        Caller::local().with_effect_gesture_token(
            &issuer,
            token,
            native_ce::awareness::EffectGestureKind::Drop,
        )
    };
    let before = event_count(&db).await;
    let mut invocation = envelope(entry, &digest, key);
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call_as(
        &registry,
        &db,
        drop_mismatch,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "gesture: {refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_invalid",
        "gesture: {refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "gesture wrote");
}

#[tokio::test]
async fn an_expired_effect_gesture_token_refuses_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let ids = native_ce::awareness::effect_gesture_binding_ids(
        "local",
        ARTIFACT,
        None,
        None,
        "mark_triaged",
        &gesture_target(),
        "gesture:expired",
        &empty_values_digest(),
        native_ce::awareness::EffectGestureKind::Click,
    );
    // TTL 1s, the shortest the issuer admits; wait past it.
    let token = issuer
        .issue(
            "local",
            native_ce::awareness::EFFECT_GESTURE_ACTION,
            &ids,
            1,
        )
        .unwrap();
    let caller = Caller::local().with_effect_gesture_token(
        &issuer,
        token,
        native_ce::awareness::EffectGestureKind::Click,
    );
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    let before = event_count(&db).await;
    let mut invocation = envelope("mark_triaged", &digest, "gesture:expired");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_invalid",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "expired wrote");
}

#[tokio::test]
async fn effect_gesture_enforcement_on_requires_a_token() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let before = event_count(&db).await;
    let mut invocation = envelope("mark_triaged", &digest, "gesture:required");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call_as(
        &registry,
        &db,
        Caller::local().with_effect_gesture_enforcement(true),
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_required",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "enforcement wrote");
}

#[tokio::test]
async fn effect_gesture_guarded_only_enforcement_scopes_to_guarded_invokes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    use native_ce::awareness::EffectGestureKind;
    let (db, registry, digest, _guard) = fixture().await;
    // Unguarded without a token takes the ordinary path and commits.
    let mut plain = envelope("mark_triaged", &digest, "gesture:scoped-plain");
    plain["slots"] = json!({ "record": INSIDE });
    plain["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        Caller::local().with_effect_gesture_enforcement_guarded_only(),
        "invoke_artifact_interaction",
        plain,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    // Guarded without a token is refused before any write, ahead of the
    // guard-scope checks (the dummy guard names no install).
    let before = event_count(&db).await;
    let mut guarded = envelope("mark_triaged", &digest, "gesture:scoped-guarded");
    guarded["slots"] = json!({ "record": INSIDE });
    guarded["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    guarded["alpha_install_guard"] = alpha_guard_dummy();
    let refused = call_as(
        &registry,
        &db,
        Caller::local().with_effect_gesture_enforcement_guarded_only(),
        "invoke_artifact_interaction",
        guarded,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_required",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "scoped enforcement wrote");
    // A present-but-invalid token still fails, even on an unguarded invoke.
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let target = gesture_target();
    let bad = gesture_caller(
        &issuer,
        native_ce::awareness::EFFECT_GESTURE_ACTION,
        None,
        None,
        "mark_triaged",
        &target,
        "gesture:scoped-other-key",
        EffectGestureKind::Click,
    )
    .with_effect_gesture_enforcement_guarded_only();
    let mut mismatched = envelope("mark_triaged", &digest, "gesture:scoped-invalid");
    mismatched["slots"] = json!({ "record": INSIDE });
    mismatched["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call_as(
        &registry,
        &db,
        bad,
        "invoke_artifact_interaction",
        mismatched,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_invalid",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "invalid token wrote");
}

#[tokio::test]
async fn the_invocation_body_gesture_field_is_not_in_the_binding() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    // Token bound for a click; the body says "drop", which is not part of the
    // binding, so it verifies. The stored origin reflects the body; the
    // evidence reflects the Caller.
    let caller = gesture_caller(
        &issuer,
        native_ce::awareness::EFFECT_GESTURE_ACTION,
        None,
        None,
        "mark_triaged",
        &gesture_target(),
        "gesture:body",
        native_ce::awareness::EffectGestureKind::Click,
    );
    let mut invocation = envelope("mark_triaged", &digest, "gesture:body");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["gesture"] = json!("drop");
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let origin = stored_origin(&db, "gesture:body").await;
    assert_eq!(origin["gesture"], "drop", "{origin:#}");
    assert_eq!(origin["gesture_evidence"]["kind"], "click", "{origin:#}");
}

#[tokio::test]
async fn effect_gesture_artifact_and_value_mismatch_refuse_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let click = native_ce::awareness::EffectGestureKind::Click;
    let action = native_ce::awareness::EFFECT_GESTURE_ACTION;
    // A token minted for a different artifact must not verify on this one.
    let cross_artifact = gesture_caller_full(
        &issuer,
        action,
        "00000000-0000-4000-8000-000000000099",
        None,
        None,
        "set_triage",
        &gesture_target(),
        "gesture:swap",
        &canonical_digest(&json!({ "choice": "triaged" })),
        click,
    );
    // A token minted for one written value must not verify for another.
    let cross_value = gesture_caller_full(
        &issuer,
        action,
        ARTIFACT,
        None,
        None,
        "set_triage",
        &gesture_target(),
        "gesture:swap",
        &canonical_digest(&json!({ "choice": "triaged" })),
        click,
    );
    for (name, caller) in [("artifact", cross_artifact), ("value", cross_value)] {
        let before = event_count(&db).await;
        let mut invocation = envelope("set_triage", &digest, "gesture:swap");
        invocation["slots"] = json!({ "record": INSIDE });
        // The real value differs from the token's bound value in the second case.
        invocation["values"] = json!({ "choice": "blocked" });
        invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
        let refused = call_as(
            &registry,
            &db,
            caller,
            "invoke_artifact_interaction",
            invocation,
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
async fn effect_gesture_cross_viewer_refuses_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = fixture().await;
    // Bob may see the artifact (so the View preflight passes) but the token
    // was minted for alice.
    replace_explicit_policy(
        &db,
        "test:gesture-viewer",
        ARTIFACT,
        vec![AllowEntry::account("acct:bob", Capability::View)],
    )
    .await
    .unwrap();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let ids = native_ce::awareness::effect_gesture_binding_ids(
        "acct:alice",
        ARTIFACT,
        None,
        None,
        "mark_triaged",
        &gesture_target(),
        "gesture:viewer",
        &empty_values_digest(),
        native_ce::awareness::EffectGestureKind::Click,
    );
    let token = issuer
        .issue(
            "acct:alice",
            native_ce::awareness::EFFECT_GESTURE_ACTION,
            &ids,
            30,
        )
        .unwrap();
    let caller = Caller::authenticated("acct:bob").with_effect_gesture_token(
        &issuer,
        token,
        native_ce::awareness::EffectGestureKind::Click,
    );
    let before = event_count(&db).await;
    let mut invocation = envelope("mark_triaged", &digest, "gesture:viewer");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let refused = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_invalid",
        "{refused:#}"
    );
    assert_eq!(event_count(&db).await, before, "cross-viewer wrote");
}

#[tokio::test]
async fn effect_gesture_invalid_on_create_refuses_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let (db, registry, digest, _guard) = create_fixture().await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    // Wrong artifact id: guaranteed invalid regardless of the create values.
    let caller = gesture_caller_full(
        &issuer,
        native_ce::awareness::EFFECT_GESTURE_ACTION,
        "00000000-0000-4000-8000-000000000098",
        None,
        None,
        "create_task",
        &[],
        "gesture:create",
        &canonical_digest(&json!({ "title": "x" })),
        native_ce::awareness::EffectGestureKind::Click,
    );
    let before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE home_id=? AND type='WorkItem'")
            .bind(COLLECTION)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let invocation = json!({
        "version": INVOCATION_VERSION,
        "artifact_id": ARTIFACT,
        "entry_id": "create_task",
        "source_digest": digest,
        "values": { "title": "Should not land", "triage": "ready" },
        "idempotency_key": "gesture:create",
        "gesture": "submit",
    });
    let refused = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_invalid",
        "{refused:#}"
    );
    let after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE home_id=? AND type='WorkItem'")
            .bind(COLLECTION)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(after, before, "an invalid token created a record");
}

#[tokio::test]
async fn effect_gesture_invalid_on_comment_refuses_with_zero_writes() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = comment_public_setup().await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    // A malformed token is invalid on any binding.
    let caller = setup.alice.clone().with_effect_gesture_token(
        &issuer,
        "not-a-token",
        native_ce::awareness::EffectGestureKind::Click,
    );
    let before = comment_count(&setup.db).await;
    let refused = call_as(
        &setup.registry,
        &setup.db,
        caller,
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION,
            "artifact_id": ARTIFACT,
            "entry_id": "post_root",
            "source_digest": setup.body_digest,
            "slots": { "bearer": INSIDE },
            "values": { "text": "Should not land" },
            "observed": { INSIDE: { "comment_target": "ct:00000000000000000000000000000000" } },
            "idempotency_key": "gesture:comment",
            "gesture": "submit",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await
    .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "gesture_attestation_invalid",
        "{refused:#}"
    );
    assert_eq!(
        comment_count(&setup.db).await,
        before,
        "an invalid token posted a comment"
    );
}
#[tokio::test]
async fn an_unguarded_artifact_token_binds_artifact_not_package() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    // An unguarded Workbench artifact has no package claim, so its token binds
    // `pkg`/`gen` absent and relies on viewer, artifact, entry, target, values,
    // key and gesture. That is the whole invocation it authorizes: the token
    // cannot be replayed on another artifact (bound id) or with another value
    // (bound digest), which is sufficient without a package.
    let (db, registry, digest, _guard) = fixture().await;
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("test-host");
    let ids = native_ce::awareness::effect_gesture_binding_ids(
        "local",
        ARTIFACT,
        None,
        None,
        "mark_triaged",
        &gesture_target(),
        "gesture:unguarded",
        &empty_values_digest(),
        native_ce::awareness::EffectGestureKind::Click,
    );
    assert!(!ids.iter().any(|id| id.starts_with("pkg=")), "{ids:?}");
    assert!(!ids.iter().any(|id| id.starts_with("gen=")), "{ids:?}");
    assert!(
        ids.iter().any(|id| id == &format!("artifact={ARTIFACT}")),
        "{ids:?}"
    );
    let token = issuer
        .issue(
            "local",
            native_ce::awareness::EFFECT_GESTURE_ACTION,
            &ids,
            30,
        )
        .unwrap();
    let caller = Caller::local().with_effect_gesture_token(
        &issuer,
        token,
        native_ce::awareness::EffectGestureKind::Click,
    );
    let mut invocation = envelope("mark_triaged", &digest, "gesture:unguarded");
    invocation["slots"] = json!({ "record": INSIDE });
    invocation["observed"] = observed(&registry, &db, INSIDE, "triage").await;
    let committed = call_as(
        &registry,
        &db,
        caller,
        "invoke_artifact_interaction",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "committed", "{committed:#}");
    let origin = stored_origin(&db, "gesture:unguarded").await;
    assert_eq!(origin["gesture_evidence"]["kind"], "click", "{origin:#}");
}

#[path = "comment_thread_sql.rs"]
mod comment_thread_sql;
