//! Tab-governed title renames (task `da148be`): the install guard admits
//! the consented need, and the kernel re-proves need membership, Edit and
//! the `rec:` CAS in one write transaction, appending one `record.updated`
//! with a durable origin. D7 Undo reverses the rename through `revert_in`.
use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

const ARTIFACT: &str = "66666666-6666-4666-8666-666666666666";
const GRID: &str = "0a5e0000-0000-4000-8000-000000000031";
const INSIDE: &str = "0a5e0000-0000-4000-8000-000000000032";
const OUTSIDE: &str = "0a5e0000-0000-4000-8000-000000000033";
const GRID_TWO: &str = "0a5e0000-0000-4000-8000-000000000034";
const INSIDE_TWO: &str = "0a5e0000-0000-4000-8000-000000000035";
const ALICE: &str = "acct:alice";
const BOB: &str = "acct:bob";
const PACKAGE: &str = "agent.rename";
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

fn title_mdx_source() -> String {
    r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { grid: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "grid" } }],
  interactions: [{ id: "rename", label: "Rename", effect: "title.set",
    slots: { record: { domain: { kind: "bound_input", port: "grid" } } },
    title: {} }]
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

fn title_need_sql() -> String {
    "SELECT id FROM records WHERE deleted_at IS NULL AND ((type='Document' AND kind='note') OR type='Message') ORDER BY id ASC LIMIT 200".into()
}

fn title_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "grid.items", "label": "Grid", "sql": title_need_sql()}
        ],
        "effects": [{
            "effect": "records.title-set.v1",
            "target": {"need": "grid.items"}
        }]
    })
}

/// A mixed manifest: `title.set` and an ordinary `title` facet share the
/// reserved observed key. Either both entries bind the same `grid` cohort
/// (overlap) or the facet entry binds a second `grid2` cohort (disjoint).
fn mixed_title_facet_mdx_source(disjoint: bool) -> String {
    let facet_port = if disjoint { "grid2" } else { "grid" };
    let inputs = if disjoint {
        r#"{
    grid: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true },
    grid2: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  }"#
    } else {
        r#"{ grid: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } }"#
    };
    let capability_requests = if disjoint {
        r#"[{ capability: "input.read", scope: { port: "grid" } }, { capability: "input.read", scope: { port: "grid2" } }]"#
    } else {
        r#"[{ capability: "input.read", scope: { port: "grid" } }]"#
    };
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {inputs},
  module_inputs: {{}},
  capability_requests: {capability_requests},
  interactions: [
    {{ id: "rename", label: "Rename", effect: "title.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input", port: "grid" }} }} }}, title: {{}} }},
    {{ id: "mark_legacy", label: "Mark legacy", effect: "facet.set",
      slots: {{ record: {{ domain: {{ kind: "bound_input", port: "{facet_port}" }} }} }},
      facet: "title", value: {{ from: "literal", value: "legacy" }} }}
  ]
}}

<Metric label="Total" value={{1}} />
"#
    )
}

fn mixed_title_facet_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "grid.items", "label": "Grid", "sql": title_need_sql()}
        ],
        "effects": [
            {"effect": "records.title-set.v1", "target": {"need": "grid.items"}},
            {"effect": "records.facet-set.v1", "key": "title", "values": ["legacy"],
             "target": {"need": "grid.items"}}
        ]
    })
}

/// Bind a second note collection to the artifact's `grid2` port, the way
/// `title_setup` binds `grid`. Used by the disjoint-cohort regression.
async fn bind_second_grid(setup: &TitleSetup, collection_id: &str, record_id: &str) {
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "create_record",
            json!({ "id": collection_id, "type": "Collection", "kind": "selection",
                    "name": "Grid two", "reason": "Second artifact input." }),
        )
        .await
        .unwrap();
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "create_record",
            json!({ "id": record_id, "type": "Document", "kind": "note",
                    "name": "Original two", "reason": "Second cohort fixture." }),
        )
        .await
        .unwrap();
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": record_id, "target_id": collection_id,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_artifact_inputs",
            json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "grid2",
                    "collection_id": collection_id }),
        )
        .await
        .unwrap();
    grant_input_read(&setup.registry, &setup.db, "grid2").await;
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
        "reason": "Install the rename tab.",
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
        "reason": "Preview the rename tab.",
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
        "reason": "Adopt the rename tab.",
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

async fn grant_input_read(registry: &ToolRegistry, db: &Db, port: &str) {
    let subjects = call(
        registry,
        db,
        Caller::local(),
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    // The source subject is one entry keyed by kind; its declared ports live
    // in `requests[].scope.port`. Select it by the port this grant resolves to,
    // so a two-port source grants each port to the same source identity.
    let subject = subjects["subjects"]
        .as_array()
        .and_then(|subjects| {
            subjects.iter().find(|subject| {
                subject["subject_kind"].as_str() == Some("artifact_source")
                    && subject["requests"].as_array().is_some_and(|requests| {
                        requests
                            .iter()
                            .any(|request| request["scope"]["port"].as_str() == Some(port))
                    })
            })
        })
        .cloned()
        .expect("the artifact source requests input.read for this port");
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
            "capability": "input.read", "scope": { "artifact_port": port }
        }),
    )
    .await;
    assert_eq!(granted["status"], "granted", "{granted:#}");
}

async fn grant_grid_input_read(registry: &ToolRegistry, db: &Db) {
    grant_input_read(registry, db, "grid").await;
}

struct TitleSetup {
    db: Db,
    registry: ToolRegistry,
    body_digest: String,
    record_id: String,
    guard: Value,
    _lock: tokio::sync::OwnedMutexGuard<()>,
}

async fn title_setup() -> TitleSetup {
    title_setup_with(title_mdx_source(), title_declaration()).await
}

async fn title_setup_with(mdx: String, declaration: Value) -> TitleSetup {
    let lock = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let html = html_interaction_source(&mdx);
    let created = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Rename tab",
                "body": html, "facets": { "runtime": "native.html.v1" },
                "reason": "Declare a title.set entry against a bound grid."
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
            json!({ "id": GRID, "type": "Collection", "kind": "selection", "name": "Grid",
                    "reason": "Bind one deterministic artifact input." }),
        )
        .await
        .unwrap();
    let record: Value = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({ "id": INSIDE, "type": "Document", "kind": "note", "name": "Original",
                    "reason": "Rename fixture." }),
        )
        .await
        .unwrap();
    assert!(record.get("error").is_none(), "{record:#}");
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": INSIDE, "target_id": GRID,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_inputs",
            json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "grid",
                    "collection_id": GRID }),
        )
        .await
        .unwrap();
    grant_grid_input_read(&registry, &db).await;
    for id in [ARTIFACT, GRID, INSIDE] {
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![
                AllowEntry::account(ALICE, Capability::View),
                AllowEntry::account(ALICE, Capability::Edit),
            ],
        )
        .await
        .unwrap();
    }
    let (verified, source_revision, digest, declaration_digest) =
        verified_install(&db, &registry, ALICE, &html, declaration).await;
    TitleSetup {
        db,
        registry,
        body_digest: digest_of(&html),
        record_id: INSIDE.to_string(),
        guard: guard_json(&verified, &source_revision, &digest, &declaration_digest),
        _lock: lock,
    }
}

/// Fresh `rec:` token for the record: the host mints these from the render
/// plan; tests read the same MAX(seq) the kernel recomputes.
async fn observed_token(db: &Db, record_id: &str) -> String {
    let seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    format!("rec:{seq}")
}

async fn title_updates(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE type='record.updated' AND json_extract(payload,'$.name') IS NOT NULL",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn record_name(db: &Db, record_id: &str) -> String {
    sqlx::query_scalar("SELECT name FROM records WHERE id=?")
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn invoke_args(setup: &TitleSetup, record_id: &str, title: &str, token: &str, key: &str) -> Value {
    let mut args = json!({
        "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "rename",
        "source_digest": setup.body_digest,
        "slots": { "record": record_id },
        "values": { "title": title },
        "observed": {},
        "idempotency_key": key, "gesture": "click",
        "alpha_install_guard": setup.guard,
    });
    args["observed"][record_id] = json!({ "title": token });
    args
}

async fn invoke(
    setup: &TitleSetup,
    caller: Caller,
    record_id: &str,
    title: &str,
    token: &str,
    key: &str,
) -> Value {
    setup
        .registry
        .call(
            setup.db.clone(),
            caller,
            "invoke_artifact_interaction",
            invoke_args(setup, record_id, title, token, key),
        )
        .await
        .unwrap()
}

fn assert_minimal_title_receipt(result: &Value) {
    assert!(result.get("action_attestation_ids").is_none(), "{result:#}");
    assert!(result.get("act").is_none(), "{result:#}");
    assert!(result.get("refresh").is_none(), "{result:#}");
    assert!(result.get("account").is_none(), "{result:#}");
    let text = result.to_string();
    assert!(!text.contains("\"seq\""), "{result:#}");
}

#[tokio::test]
async fn admitted_rename_commits_name_receipt() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let token = observed_token(&setup.db, &setup.record_id).await;
    let renamed = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:add:one",
    )
    .await;
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    assert_eq!(renamed["changes"][0]["key"], "name", "{renamed:#}");
    assert_eq!(
        renamed["changes"][0]["record_id"], setup.record_id,
        "{renamed:#}"
    );
    assert_eq!(renamed["changes"][0]["before"], "Original", "{renamed:#}");
    assert_eq!(renamed["changes"][0]["after"], "Renamed", "{renamed:#}");
    assert!(
        renamed["changes"][0]["version"]
            .as_str()
            .is_some_and(|v| v.starts_with("rec:")),
        "{renamed:#}"
    );
    assert_minimal_title_receipt(&renamed);
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Renamed");
    assert_eq!(title_updates(&setup.db).await, 1);
}

#[tokio::test]
async fn blank_and_whitespace_titles_refuse() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    for (title, key) in [("", "title:blank:one"), ("   ", "title:blank:two")] {
        let token = observed_token(&setup.db, &setup.record_id).await;
        let refused = invoke(
            &setup,
            Caller::authenticated(ALICE),
            &setup.record_id.clone(),
            title,
            &token,
            key,
        )
        .await;
        assert_eq!(refused["status"], "rejected", "{refused:#}");
        assert_eq!(refused["error"]["code"], "title_blank", "{refused:#}");
    }
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
    assert_eq!(
        title_updates(&setup.db).await,
        0,
        "blank renames write nothing"
    );
}

#[tokio::test]
async fn title_same_key_same_command_replays_and_changed_key_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let alice = Caller::authenticated(ALICE);
    let token = observed_token(&setup.db, &setup.record_id).await;
    let first = invoke(
        &setup,
        alice.clone(),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:key:one",
    )
    .await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let replay = invoke(
        &setup,
        alice.clone(),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:key:one",
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(
        replay["changes"][0]["record_id"], setup.record_id,
        "{replay:#}"
    );
    assert_eq!(replay["changes"][0]["before"], "Original", "{replay:#}");
    assert_eq!(replay["changes"][0]["after"], "Renamed", "{replay:#}");
    assert_eq!(
        replay["changes"][0]["version"], first["changes"][0]["version"],
        "{replay:#}"
    );
    assert_eq!(title_updates(&setup.db).await, 1, "replay appends nothing");
    let conflict = invoke(
        &setup,
        alice,
        &setup.record_id.clone(),
        "Other",
        &token,
        "title:key:one",
    )
    .await;
    assert_eq!(conflict["status"], "rejected", "{conflict:#}");
    assert_eq!(
        conflict["error"]["code"], "idempotency_conflict",
        "{conflict:#}"
    );
    assert_eq!(title_updates(&setup.db).await, 1, "conflict writes nothing");
}

#[tokio::test]
async fn replay_version_comes_from_the_original_event() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let alice = Caller::authenticated(ALICE);
    let token = observed_token(&setup.db, &setup.record_id).await;
    let first = invoke(
        &setup,
        alice.clone(),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:version:one",
    )
    .await;
    assert_eq!(first["status"], "committed", "{first:#}");
    let first_version = first["changes"][0]["version"].as_str().unwrap().to_string();
    // An intervening ordinary rename moves live state forward.
    setup
        .registry
        .call(
            setup.db.clone(),
            alice.clone(),
            "update_record",
            json!({ "id": setup.record_id, "name": "Touched", "reason": "Intervening edit." }),
        )
        .await
        .unwrap();
    let live = observed_token(&setup.db, &setup.record_id).await;
    assert_ne!(live, first_version, "the fixture moved live state");
    let replay = invoke(
        &setup,
        alice,
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:version:one",
    )
    .await;
    assert_eq!(replay["status"], "committed", "{replay:#}");
    assert_eq!(replay["changes"][0]["before"], "Original", "{replay:#}");
    assert_eq!(replay["changes"][0]["after"], "Renamed", "{replay:#}");
    assert_eq!(replay["changes"][0]["version"], first_version, "{replay:#}");
    assert_ne!(
        replay["changes"][0]["version"], live,
        "replay version is historical, not live"
    );
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Touched");
}

async fn assert_zero_updates_and_rejected(result: &Value, db: &Db, code: &str) {
    assert_eq!(result["status"], "rejected", "{result:#}");
    assert_eq!(result["error"]["code"], code, "{result:#}");
    assert_eq!(
        title_updates(db).await,
        0,
        "a refusal writes nothing: {result:#}"
    );
}

#[tokio::test]
async fn outside_need_and_binding_refuse() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let alice = Caller::authenticated(ALICE);
    // A task in the binding but outside the note-only need.
    let task: String = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "create_record",
            json!({ "type": "WorkItem", "kind": "task", "name": "Task",
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
        &task,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(ALICE, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": task, "target_id": GRID,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    let token = observed_token(&setup.db, &task).await;
    let refused = invoke(
        &setup,
        alice.clone(),
        &task,
        "Renamed",
        &token,
        "title:need:one",
    )
    .await;
    assert_zero_updates_and_rejected(&refused, &setup.db, "record_outside_need").await;
    // An unlinked note fails the earlier binding gate.
    let other: String = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "create_record",
            json!({ "type": "Document", "kind": "note", "name": "Elsewhere",
                    "reason": "Binding-gate fixture." }),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        &other,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(ALICE, Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let token = observed_token(&setup.db, &other).await;
    let refused = invoke(
        &setup,
        alice,
        &other,
        "Renamed",
        &token,
        "title:binding:one",
    )
    .await;
    assert_zero_updates_and_rejected(&refused, &setup.db, "record_outside_binding").await;
}

#[tokio::test]
async fn stale_cas_conflicts_without_writing() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let token = observed_token(&setup.db, &setup.record_id).await;
    // Move the record through the ordinary path first.
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "update_record",
            json!({ "id": setup.record_id, "name": "Touched", "reason": "Concurrent edit." }),
        )
        .await
        .unwrap();
    let before = title_updates(&setup.db).await;
    let conflict = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:stale:one",
    )
    .await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "title_conflict", "{conflict:#}");
    assert!(
        conflict["current_version"]
            .as_str()
            .is_some_and(|v| v.starts_with("rec:")),
        "{conflict:#}"
    );
    assert_eq!(
        title_updates(&setup.db).await,
        before,
        "a conflict writes nothing"
    );
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Touched");
}

#[tokio::test]
async fn revoked_edit_refuses() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    replace_explicit_policy(
        &setup.db,
        "test:policy",
        &setup.record_id,
        vec![AllowEntry::account(ALICE, Capability::View)],
    )
    .await
    .unwrap();
    let token = observed_token(&setup.db, &setup.record_id).await;
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:revoked:one",
    )
    .await;
    // View-only alice fails membership first (viewer-scoped need rows);
    // either way the rename is refused with zero writes.
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert!(
        [
            "record_outside_need",
            "record_outside_binding",
            "permission_denied"
        ]
        .contains(&refused["error"]["code"].as_str().unwrap_or("")),
        "{refused:#}"
    );
    assert_eq!(
        title_updates(&setup.db).await,
        0,
        "a refusal writes nothing"
    );
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
}

#[tokio::test]
async fn title_origin_is_persisted() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let token = observed_token(&setup.db, &setup.record_id).await;
    invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:origin:one",
    )
    .await;
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type='record.updated' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(setup.db.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(payload["name"], "Renamed", "{payload:#}");
    let origin = payload.get("origin").expect("title write carries origin");
    assert_eq!(origin["kind"], "artifact.interaction", "{origin:#}");
    assert_eq!(origin["effect"], "title.set", "{origin:#}");
    assert_eq!(origin["artifact_id"], ARTIFACT, "{origin:#}");
    assert_eq!(origin["entry_id"], "rename", "{origin:#}");
    assert_eq!(origin["source_digest"], setup.body_digest, "{origin:#}");
    assert_eq!(origin["record_id"], setup.record_id, "{origin:#}");
    assert_eq!(origin["title"], "Renamed", "{origin:#}");
    assert_eq!(origin["idempotency_key"], "title:origin:one", "{origin:#}");
    assert_eq!(origin["guard"]["package"], PACKAGE, "{origin:#}");
    assert!(origin["gesture"].is_string(), "{origin:#}");
}

#[tokio::test]
async fn second_viewer_without_access_is_refused() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    // Bob may view the artifact and the grid, but never the record.
    for id in [ARTIFACT, GRID] {
        replace_explicit_policy(
            &setup.db,
            "test:policy",
            id,
            vec![AllowEntry::account(BOB, Capability::View)],
        )
        .await
        .unwrap();
    }
    let declaration = title_declaration();
    let html = html_interaction_source(&title_mdx_source());
    let (verified, source_revision, digest, declaration_digest) =
        verified_install(&setup.db, &setup.registry, BOB, &html, declaration).await;
    let token = observed_token(&setup.db, &setup.record_id).await;
    let mut bob_args = json!({
        "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "rename",
        "source_digest": digest_of(&html),
        "slots": { "record": setup.record_id },
        "values": { "title": "Bobbed" },
        "observed": {},
        "idempotency_key": "title:bob:one", "gesture": "click",
        "alpha_install_guard": guard_json(&verified, &source_revision, &digest, &declaration_digest),
    });
    bob_args["observed"][&setup.record_id] = json!({ "title": token });
    let refused = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(BOB),
            "invoke_artifact_interaction",
            bob_args,
        )
        .await
        .unwrap();
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert!(
        [
            "record_outside_need",
            "record_outside_binding",
            "permission_denied"
        ]
        .contains(&refused["error"]["code"].as_str().unwrap_or("")),
        "{refused:#}"
    );
    assert_eq!(title_updates(&setup.db).await, 0, "B writes nothing");
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
}

#[tokio::test]
async fn undo_reverses_a_title_set_through_revert_in() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    use native_ce::mcp::tools::artifact_reversal::{revert_in, ReversalRequest};
    let setup = title_setup().await;
    let token = observed_token(&setup.db, &setup.record_id).await;
    let renamed = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:undo:one",
    )
    .await;
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Renamed");
    let undone = revert_in(
        &setup.db,
        &Caller::authenticated(ALICE),
        ReversalRequest {
            artifact_id: ARTIFACT.to_string(),
            record_id: setup.record_id.clone(),
            entry_id: "rename".to_string(),
            original_key: "title:undo:one".to_string(),
            idempotency_key: "title:undo:undo:one".to_string(),
        },
    )
    .await
    .unwrap();
    let undone = serde_json::to_value(&undone).unwrap();
    assert_eq!(undone["status"], "committed", "{undone:#}");
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
}

#[tokio::test]
async fn same_key_undo_replay_settles_without_appending() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    use native_ce::mcp::tools::artifact_reversal::{revert_in, ReversalRequest};
    let setup = title_setup().await;
    let token = observed_token(&setup.db, &setup.record_id).await;
    let renamed = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id.clone(),
        "Renamed",
        &token,
        "title:undo:replay:one",
    )
    .await;
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    let request = ReversalRequest {
        artifact_id: ARTIFACT.to_string(),
        record_id: setup.record_id.clone(),
        entry_id: "rename".to_string(),
        original_key: "title:undo:replay:one".to_string(),
        idempotency_key: "title:undo:replay:undo".to_string(),
    };
    let undone = revert_in(&setup.db, &Caller::authenticated(ALICE), request.clone())
        .await
        .unwrap();
    let undone = serde_json::to_value(&undone).unwrap();
    assert_eq!(undone["status"], "committed", "{undone:#}");
    let updates = title_updates(&setup.db).await;
    let replayed = revert_in(&setup.db, &Caller::authenticated(ALICE), request)
        .await
        .unwrap();
    let replayed = serde_json::to_value(&replayed).unwrap();
    assert_eq!(replayed["status"], "committed", "{replayed:#}");
    assert_eq!(replayed["changes"][0]["key"], "name", "{replayed:#}");
    assert_eq!(replayed["changes"][0]["after"], "Original", "{replayed:#}");
    assert!(
        replayed["changes"][0]["version"]
            .as_str()
            .is_some_and(|v| v.starts_with("rec:")),
        "{replayed:#}"
    );
    assert_eq!(
        title_updates(&setup.db).await,
        updates,
        "undo replay appends nothing"
    );
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
}

#[tokio::test]
async fn sealed_message_name_is_immutable() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    use native_ce::store::create_record as create_raw_record;
    let setup = title_setup().await;
    for (person, account, name) in [
        ("e8bec700-0000-4000-8000-000000000041", ALICE, "Alice"),
        ("e8bec700-0000-4000-8000-000000000042", BOB, "Bob"),
    ] {
        create_raw_record(
            &setup.db,
            json!({ "id": person, "type": "Entity", "kind": "person", "name": name }),
        )
        .await
        .unwrap();
        for system in ["account", "native-principal"] {
            let identifier = if system == "account" {
                account.to_string()
            } else {
                format!("native/{}", name.to_ascii_lowercase())
            };
            sqlx::query(
                "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                 VALUES (?, ?, ?, 1)",
            )
            .bind(person)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(&setup.db).await)
            .await
            .unwrap();
        }
    }
    let message: String = setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "manage_messages",
            json!({
                "action": "send", "body": "sealed message",
                "origin": {"type": "direct", "participant_ids": [
                    "e8bec700-0000-4000-8000-000000000041",
                    "e8bec700-0000-4000-8000-000000000042"]},
                "addressed_to": ["e8bec700-0000-4000-8000-000000000042"],
                "expectation": "none",
                "idempotency_key": format!("title-msg-{}", uuid::Uuid::new_v4()),
                "reason": "Sealed message fixture.",
            }),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "manage_links",
            json!({ "action": "add", "source_id": message, "target_id": GRID,
                    "relationship": "member_of" }),
        )
        .await
        .unwrap();
    let token = observed_token(&setup.db, &message).await;
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &message,
        "Renamed",
        &token,
        "title:msg:one",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "message_immutable", "{refused:#}");
    assert_eq!(
        title_updates(&setup.db).await,
        0,
        "immutable rename writes nothing"
    );
}

async fn render_plan(setup: &TitleSetup) -> Value {
    call(
        &setup.registry,
        &setup.db,
        Caller::local(),
        "render_artifact",
        json!({ "id": ARTIFACT }),
    )
    .await
}

fn rendered_title_token(rendered: &Value, record_id: &str) -> String {
    rendered["plan"]["observed"][record_id]["title"]
        .as_str()
        .unwrap_or_else(|| panic!("no title token in the render plan: {rendered:#}"))
        .to_string()
}

fn assert_no_empty_observed_key(rendered: &Value) {
    if let Some(records) = rendered["plan"]["observed"].as_object() {
        for (record_id, keys) in records {
            assert!(
                !keys.as_object().unwrap().contains_key(""),
                "record {record_id} carries an empty observed key: {rendered:#}"
            );
        }
    }
}

/// The live render plan mints the exact `rec:` token the guarded rename
/// kernel recomputes, for the title cohort only — and never an empty key.
#[tokio::test]
async fn real_render_plan_emits_cohort_bounded_title_rec_token() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::local(),
            "create_record",
            json!({ "id": OUTSIDE, "type": "Document", "kind": "note", "name": "Outside",
                    "reason": "A note outside the bound collection." }),
        )
        .await
        .unwrap();
    let rendered = render_plan(&setup).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_no_empty_observed_key(&rendered);
    let observed = &rendered["plan"]["observed"];
    assert!(
        observed.get(OUTSIDE).is_none(),
        "a record outside the title cohort is never observed: {rendered:#}"
    );
    let token = rendered_title_token(&rendered, &setup.record_id);
    assert!(
        token.starts_with("rec:"),
        "the emitted title token is a host record token: {rendered:#}"
    );
    // The host-emitted token drives the guarded rename with no test-side CAS.
    let renamed = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id,
        "Renamed from render",
        &token,
        "title:render:one",
    )
    .await;
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    assert_eq!(
        record_name(&setup.db, &setup.record_id).await,
        "Renamed from render"
    );
    assert_eq!(title_updates(&setup.db).await, 1);
}

/// A record mutation moves the freshly rendered token, and the superseded
/// token conflicts with zero writes — the host token is a real precondition.
#[tokio::test]
async fn fresh_render_token_moves_after_mutation_and_stale_token_conflicts() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup().await;
    let first = render_plan(&setup).await;
    let old_token = rendered_title_token(&first, &setup.record_id);
    // Move the record through the ordinary path so the record-wide token moves.
    setup
        .registry
        .call(
            setup.db.clone(),
            Caller::authenticated(ALICE),
            "update_record",
            json!({ "id": setup.record_id, "facets": { "effort": "large" },
                    "reason": "Concurrent facet edit." }),
        )
        .await
        .unwrap();
    let second = render_plan(&setup).await;
    let new_token = rendered_title_token(&second, &setup.record_id);
    assert_ne!(
        new_token, old_token,
        "a fresh render mints a new record token: {second:#}"
    );
    let before = title_updates(&setup.db).await;
    let conflict = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id,
        "Stale",
        &old_token,
        "title:stale-render:one",
    )
    .await;
    assert_eq!(conflict["status"], "conflict", "{conflict:#}");
    assert_eq!(conflict["error"]["code"], "title_conflict", "{conflict:#}");
    assert_eq!(
        title_updates(&setup.db).await,
        before,
        "a stale token writes nothing"
    );
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
}

/// Token-contract ambiguity, pinned: when a `title.set` cohort and an
/// ordinary `title` facet cohort overlap, the retained `obs:` token is never
/// overwritten. Title submission fails closed on the token class while the
/// legacy facet invocation stays usable.
#[tokio::test]
async fn overlapping_cohorts_keep_the_facet_token_and_title_fails_closed() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup_with(
        mixed_title_facet_mdx_source(false),
        mixed_title_facet_declaration(),
    )
    .await;
    let rendered = render_plan(&setup).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_no_empty_observed_key(&rendered);
    let token = rendered_title_token(&rendered, &setup.record_id);
    assert!(
        token.starts_with("obs:"),
        "the existing facet token is retained, not overwritten: {rendered:#}"
    );
    let before = title_updates(&setup.db).await;
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id,
        "Renamed",
        &token,
        "title:overlap:one",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "invalid_precondition",
        "{refused:#}"
    );
    assert_eq!(title_updates(&setup.db).await, before);
    assert_eq!(record_name(&setup.db, &setup.record_id).await, "Original");
    // The legacy facet invocation remains usable with the retained token.
    let facet = call(
        &setup.registry,
        &setup.db,
        Caller::authenticated(ALICE),
        "invoke_artifact_interaction",
        json!({
            "version": INVOCATION_VERSION, "artifact_id": ARTIFACT, "entry_id": "mark_legacy",
            "source_digest": setup.body_digest,
            "slots": { "record": setup.record_id },
            "observed": { setup.record_id.clone(): { "title": token } },
            "idempotency_key": "facet:overlap:one",
            "alpha_install_guard": setup.guard,
        }),
    )
    .await;
    assert_eq!(facet["status"], "committed", "{facet:#}");
    assert_eq!(facet["changes"][0]["after"], "legacy", "{facet:#}");
}

/// Disjoint title and facet cohorts are independent: the title cohort mints
/// its `rec:` token while the other record keeps its ordinary facet token.
#[tokio::test]
async fn disjoint_title_and_facet_cohorts_mint_both_tokens() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup_with(
        mixed_title_facet_mdx_source(true),
        mixed_title_facet_declaration(),
    )
    .await;
    bind_second_grid(&setup, GRID_TWO, INSIDE_TWO).await;
    let rendered = render_plan(&setup).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_no_empty_observed_key(&rendered);
    let title_token = rendered_title_token(&rendered, &setup.record_id);
    let facet_token = rendered_title_token(&rendered, INSIDE_TWO);
    assert!(
        title_token.starts_with("rec:"),
        "the title cohort mints a record token: {rendered:#}"
    );
    assert!(
        facet_token.starts_with("obs:"),
        "the disjoint facet cohort keeps its facet token: {rendered:#}"
    );
    let renamed = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &setup.record_id,
        "Disjoint rename",
        &title_token,
        "title:disjoint:one",
    )
    .await;
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    assert_eq!(
        record_name(&setup.db, &setup.record_id).await,
        "Disjoint rename"
    );
}

/// Delivered-need predicate for the 200/201 boundary: a name-scoped static
/// need whose own SQL limit (300) exceeds the engine's 200-row delivery cap, so
/// the cap — not the SQL LIMIT — decides the boundary. The name predicate
/// isolates the deterministic cohort from the artifact, the collection and any
/// unrelated fixture rows.
fn boundary_title_need_sql() -> String {
    "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'title-boundary-%' ORDER BY id ASC LIMIT 300".into()
}

fn boundary_title_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "grid.items", "label": "Grid", "sql": boundary_title_need_sql()}
        ],
        "effects": [{
            "effect": "records.title-set.v1",
            "target": {"need": "grid.items"}
        }]
    })
}

/// Helper: the count of `record.updated` events on one row, so a positive or a
/// refusal can assert its own exact event delta independent of global counts.
async fn row_update_events(db: &Db, record_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.updated'",
    )
    .bind(record_id)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// The actual title invoke at the delivered 200/201 boundary: a bound,
/// View+Edit-granted, genuinely delivered 200th row commits; the bound,
/// View+Edit-granted 201st — holding a genuine rendered `rec:` token — is
/// refused `record_outside_need` with zero append, proving the 200-row need cap
/// is enforced by membership delivery, not by the presence of a bound token.
/// The new title stays inside the need predicate (`title-boundary-…`).
/// `plan.observed` is the BOUND-PORT token cohort (`records_by_port`,
/// artifacts.rs), separate from the capped membership SQL in
/// `check_delivered_membership_in` (alpha_tabs.rs); the test asserts the exact
/// bound cohort and never treats `observed` as a delivered-200 subset. A real
/// ordinary governed `query_sql` read proves the exact rows/names afterwards;
/// the membership helper's TEMP internals stay source-known only and are not
/// asserted from an artifact re-render.
#[tokio::test]
async fn delivered_200_admits_and_the_201st_refuses_without_appending() {
    let _runtime_config = crate::runtime_config_fixture::reader().await;
    let setup = title_setup_with(title_mdx_source(), boundary_title_declaration()).await;
    // 205 deterministic rows whose leading hex keeps `ORDER BY id ASC` ==
    // creation order. Every row is bound into the artifact's grid and carries
    // real View+Edit for Alice, so a 200-row cohort cannot be an artefact of
    // missing permission or binding.
    let mut ids = Vec::with_capacity(205);
    for index in 0usize..205 {
        let id = format!("{index:08x}-0000-4000-8000-{index:012x}");
        let created = setup
            .registry
            .call(
                setup.db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id, "type": "Document", "kind": "note",
                    "name": format!("title-boundary-{index:03}"),
                    "reason": "Deterministic title 200/201 boundary cohort row."
                }),
            )
            .await
            .unwrap();
        assert!(created.get("error").is_none(), "{created:#}");
        let linked = setup
            .registry
            .call(
                setup.db.clone(),
                Caller::local(),
                "manage_links",
                json!({ "action": "add", "source_id": id, "target_id": GRID,
                        "relationship": "member_of" }),
            )
            .await
            .unwrap();
        assert!(linked.get("error").is_none(), "{linked:#}");
        replace_explicit_policy(
            &setup.db,
            "test:policy",
            &id,
            vec![
                AllowEntry::account(ALICE, Capability::View),
                AllowEntry::account(ALICE, Capability::Edit),
            ],
        )
        .await
        .expect("grant Alice View+Edit on each boundary cohort row");
        ids.push(id);
    }
    let expected_bound: std::collections::BTreeSet<&str> = ids
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(setup.record_id.as_str()))
        .collect();

    // Governed production render oracle: `plan.observed` is the BOUND-PORT
    // token cohort — every row linked `member_of` the bound grid collection
    // (`records_by_port`, artifacts.rs) — and is separate from the need's
    // CAPPED membership delivery. It must be exactly the 205 fixture rows plus
    // the setup note, never a delivered-200 subset. The need's own SQL LIMIT
    // (300) proves nothing here; the 200-row delivery cap is enforced at
    // membership time (`check_delivered_membership_in`, alpha_tabs.rs), not by
    // `observed`.
    let rendered = render_plan(&setup).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_no_empty_observed_key(&rendered);
    let observed = rendered["plan"]["observed"].as_object().unwrap();
    let observed_ids: std::collections::BTreeSet<&str> =
        observed.keys().map(String::as_str).collect();
    assert_eq!(
        observed_ids, expected_bound,
        "the observed title cohort is exactly the bound grid rows: {rendered:#}"
    );
    // Genuine rendered rec: tokens for BOTH boundary targets: the bound cohort
    // mints a token for the 201st too, and a bound token does not by itself
    // grant delivered membership.
    let token_200 = rendered_title_token(&rendered, &ids[199]);
    let token_201 = rendered_title_token(&rendered, &ids[200]);
    assert!(
        token_200.starts_with("rec:") && token_201.starts_with("rec:"),
        "{rendered:#}"
    );

    // 200th genuine invoke commits the exact single name change; the new title
    // stays inside the need predicate so the delivered cohort is unchanged.
    let admitted_name = "title-boundary-admitted-199";
    let admitted_events_before = row_update_events(&setup.db, &ids[199]).await;
    let updates_before = title_updates(&setup.db).await;
    let renamed = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &ids[199],
        admitted_name,
        &token_200,
        "title:boundary:200",
    )
    .await;
    assert_eq!(renamed["status"], "committed", "{renamed:#}");
    assert_eq!(
        renamed["changes"].as_array().map(Vec::len),
        Some(1),
        "the committed receipt carries exactly one change: {renamed:#}"
    );
    assert_eq!(renamed["changes"][0]["key"], "name", "{renamed:#}");
    assert_eq!(renamed["changes"][0]["record_id"], ids[199], "{renamed:#}");
    assert_eq!(
        renamed["changes"][0]["before"], "title-boundary-199",
        "{renamed:#}"
    );
    assert_eq!(renamed["changes"][0]["after"], admitted_name, "{renamed:#}");
    assert_minimal_title_receipt(&renamed);
    assert_eq!(record_name(&setup.db, &ids[199]).await, admitted_name);
    assert_eq!(
        title_updates(&setup.db).await,
        updates_before + 1,
        "the admitted write appends exactly one name update"
    );
    assert_eq!(
        row_update_events(&setup.db, &ids[199]).await,
        admitted_events_before + 1,
        "the admitted row gains exactly one update event"
    );

    // 201st genuine invoke: bound, View+Edit-granted and holding a genuine
    // rendered `rec:` token, but not among the 200 delivered need rows, so the
    // governed membership refuses with zero append and an unchanged name.
    let refused_events_before = row_update_events(&setup.db, &ids[200]).await;
    let updates_before_refusal = title_updates(&setup.db).await;
    let refused = invoke(
        &setup,
        Caller::authenticated(ALICE),
        &ids[200],
        "Boundary refused",
        &token_201,
        "title:boundary:201",
    )
    .await;
    assert_eq!(refused["status"], "rejected", "{refused:#}");
    assert_eq!(
        refused["error"]["code"], "record_outside_need",
        "{refused:#}"
    );
    assert_eq!(
        title_updates(&setup.db).await,
        updates_before_refusal,
        "the 201st appends nothing: {refused:#}"
    );
    assert_eq!(
        record_name(&setup.db, &ids[200]).await,
        "title-boundary-200"
    );
    assert_eq!(
        row_update_events(&setup.db, &ids[200]).await,
        refused_events_before,
        "the 201st row gains no update event"
    );

    // Fresh governed render oracle after the requests: the bound-port token
    // cohort is unchanged (the admitted row remains inside the predicate) and
    // real tokens are still minted for both boundary targets. This is a bound
    // map check, not a delivered-subset check.
    let rendered_after = render_plan(&setup).await;
    assert_eq!(rendered_after["status"], "rendered", "{rendered_after:#}");
    let observed_after = rendered_after["plan"]["observed"].as_object().unwrap();
    let observed_after_ids: std::collections::BTreeSet<&str> =
        observed_after.keys().map(String::as_str).collect();
    assert_eq!(
        observed_after_ids, expected_bound,
        "the bound title cohort is unchanged after the requests: {rendered_after:#}"
    );
    assert!(
        rendered_title_token(&rendered_after, &ids[199]).starts_with("rec:")
            && rendered_title_token(&rendered_after, &ids[200]).starts_with("rec:"),
        "{rendered_after:#}"
    );

    // Real ordinary governed query read (not an artifact re-render): Alice's
    // production `query_sql` still reads the exact rows and names after the
    // membership requests. This shows ordinary reads are unaffected; it does
    // not itself inspect the membership helper's TEMP internals, whose per-call
    // cleanup is source-known only.
    let read_admitted = call(
        &setup.registry,
        &setup.db,
        Caller::authenticated(ALICE),
        "query_sql",
        json!({ "sql": format!(
            "SELECT id, name FROM records WHERE id = '{}'", ids[199]
        ) }),
    )
    .await;
    assert!(read_admitted.get("error").is_none(), "{read_admitted:#}");
    let admitted_rows = read_admitted["rows"].as_array().unwrap();
    assert_eq!(admitted_rows.len(), 1, "{read_admitted:#}");
    assert_eq!(
        admitted_rows[0]["name"].as_str().unwrap_or(""),
        admitted_name,
        "{read_admitted:#}"
    );
    let read_refused = call(
        &setup.registry,
        &setup.db,
        Caller::authenticated(ALICE),
        "query_sql",
        json!({ "sql": format!(
            "SELECT id, name FROM records WHERE id = '{}'", ids[200]
        ) }),
    )
    .await;
    assert!(read_refused.get("error").is_none(), "{read_refused:#}");
    let refused_rows = read_refused["rows"].as_array().unwrap();
    assert_eq!(refused_rows.len(), 1, "{read_refused:#}");
    assert_eq!(
        refused_rows[0]["name"].as_str().unwrap_or(""),
        "title-boundary-200",
        "{read_refused:#}"
    );
}
