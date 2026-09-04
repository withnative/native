use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

// Record ids must be canonical v4/v7 UUIDs, so the input collections and their
// members are pinned literals. The `port_name`/`module_port`/`artifact_port`
// values that used to share these spellings are port names, not record ids, and
// deliberately keep their readable form.
const CUSTOMER_ONE: &str = "a771d000-0000-4000-8000-000000000001";
const CUSTOMERS: &str = "a771d000-0000-4000-8000-000000000002";
const ORDER_ONE: &str = "a771d000-0000-4000-8000-000000000003";
const ORDERS: &str = "a771d000-0000-4000-8000-000000000004";
const ROW_ONE: &str = "a771d000-0000-4000-8000-000000000005";
const ROWS: &str = "a771d000-0000-4000-8000-000000000006";
const SECRET: &str = "a771d000-0000-4000-8000-000000000007";

const MODULE_ID: &str = "11111111-1111-4111-8111-111111111111";
const ARTIFACT_A: &str = "44444444-4444-4444-8444-444444444444";
const ARTIFACT_B: &str = "55555555-5555-4555-8555-555555555555";

const HOME_ARTIFACT: &str = "a771e000-0000-4000-8000-000000000001";
const HOME_MESSAGES_QUERY: &str = "a771e000-0000-4000-8000-000000000002";
const HOME_LEGACY_QUERY: &str = "a771e000-0000-4000-8000-000000000003";
const HOME_LEGACY_RECORD: &str = "a771e000-0000-4000-8000-000000000004";
const HOME_SENDER_PERSON: &str = "a771e000-0000-4000-8000-000000000005";
const HOME_RECIPIENT_PERSON: &str = "a771e000-0000-4000-8000-000000000006";
const HOME_SENDER_ACCOUNT: &str = "acct:home-sender";
const HOME_RECIPIENT_ACCOUNT: &str = "acct:home-recipient";

const AGENTS_ARTIFACT: &str = "a771f000-0000-4000-8000-000000000001";
const AGENTS_PRESENCE_QUERY: &str = "a771f000-0000-4000-8000-000000000002";
const AGENTS_CLAIMS_QUERY: &str = "a771f000-0000-4000-8000-000000000003";
const AGENTS_CLAIMED_RECORD: &str = "a771f000-0000-4000-8000-000000000004";
const AGENTS_WRONG_PRESENCE_QUERY: &str = "a771f000-0000-4000-8000-000000000005";
const AGENTS_HIDDEN_CLAIMED_RECORD: &str = "a771f000-0000-4000-8000-000000000006";
const AGENTS_VIEWER_ACCOUNT: &str = "acct:agents-viewer";
const AGENTS_PRESENCE_SCHEMA: &str =
    "8d6517ffb73621e26c4ed8b2ae06a67b8ca4dd964298308c418e31d6bdb1d81f";
const AGENTS_CLAIMS_SCHEMA: &str =
    "17aadd275405361aee430ddbf210a565c1a9a55ba923f6e2f36f9c52f0105d3b";

fn canonical_sha256(value: &Value) -> String {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), canonical(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            value => value.clone(),
        }
    }
    hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical(value)).unwrap(),
    ))
}

fn normalize_agents_observation_metrics(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(normalize_agents_observation_metrics)
                .collect(),
        ),
        Value::Object(values) => {
            let mut normalized = values
                .iter()
                .map(|(key, value)| (key.clone(), normalize_agents_observation_metrics(value)))
                .collect::<serde_json::Map<_, _>>();
            if normalized.get("type").and_then(Value::as_str) == Some("Metric") {
                let label = normalized
                    .get("props")
                    .and_then(Value::as_object)
                    .and_then(|props| props.get("label"))
                    .and_then(Value::as_str);
                if matches!(label, Some("Activity observed" | "Claims observed")) {
                    normalized
                        .get_mut("props")
                        .and_then(Value::as_object_mut)
                        .expect("Metric props are validated")
                        .insert("value".into(), json!("<observation-time>"));
                }
            }
            Value::Object(normalized)
        }
        value => value.clone(),
    }
}

fn integration_guard() -> &'static Arc<tokio::sync::Mutex<()>> {
    static GUARD: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    GUARD.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
}

async fn fixture() -> (Db, ToolRegistry, tokio::sync::OwnedMutexGuard<()>) {
    let guard = Arc::clone(integration_guard()).lock_owned().await;
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry, guard)
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, arguments)
        .await
        .unwrap()
}

/// Read the current write token the way a caller must: through `get_record`.
/// Whole-body replacement is guarded, so the rewrites below carry the digest
/// they actually read rather than asserting an unguarded overwrite.
async fn current_body_digest(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["body_digest"]
        .as_str()
        .expect("get_record exposes body_digest")
        .to_owned()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> Value {
    registry
        .call(db.clone(), caller, tool, arguments)
        .await
        .unwrap()
}

fn module_source(label: &str) -> String {
    format!(
        r#"export const nativeModule = {{
  schema: "native.mdx.module.v1",
  inputs: {{}},
  exports: {{ Hello: {{ kind: "component", props: {{ label: {{ type: "string", required: true }} }}, uses_inputs: [] }} }},
  module_inputs: {{}},
  capability_requests: []
}}
export function Hello({{ label }}, native) {{ return <Callout tone="info" title={{{label:?}}}>{{label}}</Callout> }}
"#
    )
}

async fn create_module(registry: &ToolRegistry, db: &Db, source: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({
            "id": MODULE_ID, "type": "Program", "kind": "module", "name": "Shared UI",
            "body": source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Exercise portable immutable module publication."
        }),
    )
    .await;
}

async fn publish(registry: &ToolRegistry, db: &Db) -> Value {
    publish_module(registry, db, MODULE_ID).await
}

async fn publish_module(registry: &ToolRegistry, db: &Db, module_id: &str) -> Value {
    let row = sqlx::query(
        "SELECT e.id,json_extract(e.payload,'$.body') AS body FROM content_events e
          WHERE e.record_id=? AND json_type(e.payload,'$.body') IS NOT NULL ORDER BY e.seq DESC LIMIT 1",
    )
    .bind(module_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event_id: String = row.get("id");
    let body: String = row.get("body");
    call(
        registry,
        db,
        "manage_mdx_modules",
        json!({
            "action": "publish", "module_id": module_id,
            "expected_source_event_id": source_event_id,
            "expected_source_sha256": hex::encode(Sha256::digest(body.as_bytes())),
        }),
    )
    .await
}

fn artifact_source(publication: &Value) -> String {
    let event = publication["publication_event_id"].as_str().unwrap();
    let digest = publication["source_sha256"].as_str().unwrap();
    let specifier = format!("native:module/{MODULE_ID}@event-{event}?sha256={digest}");
    format!(
        r#"import {{ Hello }} from {specifier:?}
export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{}},
  module_inputs: {{ Hello: {{ publication_event_id: {event:?}, export: "Hello", ports: {{}} }} }},
  capability_requests: []
}}

<Hello label="Pinned" />
"#
    )
}

async fn create_artifact(registry: &ToolRegistry, db: &Db, id: &str, source: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({
            "id": id, "type": "Document", "kind": "artifact", "name": id,
            "body": source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Consume one exact reusable module release."
        }),
    )
    .await;
}

/// Pins the emitted `plan.styles` shape.
///
/// There is no Rust `SafeTreePlan` type: the plan is two `json!` literals in
/// `src/mcp/tools/artifacts.rs`, mirrored by hand in
/// `web/workbench/src/api/types.ts` with nothing enforcing the link. This test
/// is that link — it renders through the real tool and asserts the exact member
/// names the workbench reads, and the exact href the route in
/// `held/workbench/src/lib.rs` is registered to answer.
#[tokio::test]
async fn safe_tree_plan_carries_author_styles_and_omits_them_when_absent() {
    let (db, registry, _guard) = fixture().await;
    // The sheet carries one thing `css.rs` knows and two it does not: an
    // unknown at-rule, and an id selector it deliberately leaves unrewritten.
    // Both are flagged rather than rejected, and `plan.styles.flags` is where
    // that observation becomes visible to anyone outside the validator.
    let styled = r#"export const nativeArtifact = { schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: [] }
export const nativeStyles = ".card { color: red } @wobble { .card { color: blue } } #panel { color: green }"

<p class="card">styled</p>
"#;
    create_artifact(&registry, &db, ARTIFACT_A, styled).await;
    // A space in the database id, because the href has to survive one: the
    // workbench builds its tool URLs with `encodeURIComponent`, and this href
    // has to spell the same database the same way.
    replace_explicit_policy(
        &db,
        "test:styles",
        ARTIFACT_A,
        vec![AllowEntry::account("acct:cass", Capability::View)],
    )
    .await
    .unwrap();
    let cass = Caller::authenticated("acct:cass")
        .with_hosting_context("host:cass", "db one")
        .with_hosting_owner(false);
    let rendered = call_as(
        &registry,
        &db,
        cass.clone(),
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let styles = &rendered["plan"]["styles"];
    let digest = styles["digest"].as_str().expect("styles digest");
    assert_eq!(digest.len(), 64);
    assert_eq!(
        styles["href"],
        json!(format!(
            "/workbench/databases/db%20one/artifacts/{ARTIFACT_A}/styles/{digest}.css"
        ))
    );
    assert_eq!(
        styles
            .as_object()
            .expect("styles is an object")
            .keys()
            .collect::<Vec<_>>(),
        vec!["digest", "flags", "href"],
        "{rendered:#}"
    );
    // Sorted and de-duplicated by `css.rs`, carried across verbatim.
    assert_eq!(
        styles["flags"],
        json!([
            { "rule": "id_selector", "name": "panel" },
            { "rule": "unknown_at_rule", "name": "wobble" },
        ]),
        "{rendered:#}"
    );
    // The author class reaches the browser already prefixed, so the sheet and
    // the element agree without the workbench rewriting anything.
    assert_eq!(rendered["plan"]["tree"]["props"]["class"], "nsa-card");

    // A caller with no database in its context — in-process, stdio, or a test
    // like `call` below — gets no `styles` member at all rather than an href
    // that names no database and therefore cannot be served. Unstyled but
    // correct beats unstyled plus a broken request in the network log.
    let unhosted = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(unhosted["status"], "rendered", "{unhosted:#}");
    assert!(
        unhosted["plan"].get("styles").is_none(),
        "a caller with no database gets no stylesheet href: {unhosted:#}"
    );
    // The sheet is still applied to the tree either way: the styles member is
    // about *delivery*, and its absence must not change the render.
    assert_eq!(unhosted["plan"]["tree"], rendered["plan"]["tree"]);

    let plain = r#"export const nativeArtifact = { schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: [] }

<p>plain</p>
"#;
    create_artifact(&registry, &db, ARTIFACT_B, plain).await;
    replace_explicit_policy(
        &db,
        "test:styles",
        ARTIFACT_B,
        vec![AllowEntry::account("acct:cass", Capability::View)],
    )
    .await
    .unwrap();
    let bare = call_as(
        &registry,
        &db,
        cass,
        "render_artifact",
        json!({ "id": ARTIFACT_B }),
    )
    .await;
    assert_eq!(bare["status"], "rendered", "{bare:#}");
    assert!(
        bare["plan"].get("styles").is_none(),
        "an artifact with no styles carries no styles member: {bare:#}"
    );
}

#[tokio::test]
async fn current_and_historical_render_use_live_module_visibility() {
    let (db, registry, _guard) = fixture().await;
    create_module(&registry, &db, &module_source("hidden module source")).await;
    let release = publish(&registry, &db).await;
    create_artifact(&registry, &db, ARTIFACT_A, &artifact_source(&release)).await;

    let snapshot_event_id: String =
        sqlx::query_scalar("SELECT id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    replace_explicit_policy(
        &db,
        "test:live-module-visibility",
        ARTIFACT_A,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:live-module-visibility",
        MODULE_ID,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    for arguments in [
        json!({ "id": ARTIFACT_A }),
        json!({ "id": ARTIFACT_A, "as_of": { "event_id": snapshot_event_id } }),
    ] {
        let denied = call_as(&registry, &db, bea.clone(), "render_artifact", arguments).await;
        assert_eq!(
            denied["diagnostic"]["code"], "module_release_missing",
            "{denied:#}"
        );
        assert!(denied.get("plan").is_none(), "{denied:#}");
        let response = denied.to_string();
        assert!(!response.contains(MODULE_ID), "{denied:#}");
        assert!(!response.contains("hidden module source"), "{denied:#}");
    }
}

#[tokio::test]
async fn portable_release_pins_two_consumers_until_explicit_upgrade() {
    let (db, registry, _guard) = fixture().await;
    create_module(&registry, &db, &module_source("release one")).await;
    let first_release = publish(&registry, &db).await;
    assert_eq!(first_release["status"], "published", "{first_release:#}");
    assert_eq!(
        first_release["publication_event_id"],
        first_release["release"]["release_core"]["publication_event_id"]
    );
    assert!(first_release["local_event_seq"].is_number());
    for inspected in [
        call(
            &registry,
            &db,
            "manage_mdx_modules",
            json!({ "action": "inspect", "module_id": MODULE_ID }),
        )
        .await,
        call(
            &registry,
            &db,
            "manage_mdx_modules",
            json!({
                "action": "inspect",
                "module_id": MODULE_ID,
                "publication_event_id": first_release["publication_event_id"],
            }),
        )
        .await,
    ] {
        let releases = inspected["releases"].as_array().unwrap();
        assert!(!releases.is_empty(), "{inspected:#}");
        assert!(
            releases
                .iter()
                .all(|release| release["module_record_id"] == MODULE_ID),
            "{inspected:#}"
        );
    }

    let source = artifact_source(&first_release);
    create_artifact(&registry, &db, ARTIFACT_A, &source).await;
    create_artifact(&registry, &db, ARTIFACT_B, &source).await;
    let a1 = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    let b1 = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_B }),
    )
    .await;
    assert_eq!(a1["status"], "rendered", "{a1:#}");
    assert_eq!(b1["status"], "rendered", "{b1:#}");
    assert_eq!(a1["plan"]["cache"]["state"], "miss");
    assert_eq!(b1["plan"]["cache"]["state"], "hit");
    assert_eq!(a1["plan"]["tree"], b1["plan"]["tree"]);
    assert_eq!(a1["runtime"]["id"], "native.mdx.v2");
    assert_eq!(
        a1["plan"]["provenance"]["module_releases"][0]["publication_event_id"],
        first_release["publication_event_id"]
    );

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": MODULE_ID, "body": module_source("release two"),
            "if_body_digest": current_body_digest(&registry, &db, MODULE_ID).await,
            "reason": "Prove draft edits do not alter pinned consumers."
        }),
    )
    .await;
    let unchanged = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(unchanged["plan"]["tree"], a1["plan"]["tree"]);
    let historical = call(
        &registry,
        &db,
        "render_artifact",
        json!({
            "id": ARTIFACT_A,
            "as_of": { "event_id": a1["plan"]["provenance"]["snapshot_event_id"] }
        }),
    )
    .await;
    assert_eq!(
        historical["plan"]["tree"], a1["plan"]["tree"],
        "{historical:#}"
    );
    assert_eq!(
        historical["historical_render"]["offline_completeness"],
        "complete"
    );
    assert_eq!(
        historical["historical_render"]["requested_boundary"]["event_id"],
        a1["plan"]["provenance"]["snapshot_event_id"]
    );

    let second_release = publish(&registry, &db).await;
    let deprecated = call(
        &registry,
        &db,
        "manage_mdx_modules",
        json!({
            "action": "deprecate", "module_id": MODULE_ID,
            "publication_event_id": first_release["publication_event_id"],
            "expected_status_event_seq": first_release["local_event_seq"],
            "replacement": second_release["publication_event_id"],
        }),
    )
    .await;
    assert_eq!(deprecated["status"], "deprecated", "{deprecated:#}");
    let stale_status = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_mdx_modules",
            json!({
                "action": "withdraw", "module_id": MODULE_ID,
                "publication_event_id": first_release["publication_event_id"],
                "expected_status_event_seq": first_release["local_event_seq"],
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        stale_status.contains("status changed underneath"),
        "{stale_status}"
    );
    let still_pinned = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_B }),
    )
    .await;
    assert_eq!(still_pinned["plan"]["tree"], b1["plan"]["tree"]);
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT_A, "body": artifact_source(&second_release),
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "Explicitly upgrade only one consumer to the reviewed release."
        }),
    )
    .await;
    let upgraded = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(upgraded["status"], "rendered", "{upgraded:#}");
    assert_eq!(upgraded["plan"]["cache"]["state"], "miss");
    assert_ne!(upgraded["plan"]["tree"], a1["plan"]["tree"]);
    assert_eq!(
        upgraded["plan"]["provenance"]["module_releases"][0]["publication_event_id"],
        second_release["publication_event_id"]
    );

    let withdrawn = call(
        &registry,
        &db,
        "manage_mdx_modules",
        json!({
            "action": "withdraw", "module_id": MODULE_ID,
            "publication_event_id": second_release["publication_event_id"],
            "expected_status_event_seq": second_release["local_event_seq"],
        }),
    )
    .await;
    assert_eq!(withdrawn["status"], "withdrawn");
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(denied["diagnostic"]["code"], "module_release_withdrawn");
    let rebuilt = native_ce::conformance::run_conformance(&db).await;
    assert!(
        rebuilt.ok,
        "reusable module event graph must rebuild exactly: {rebuilt:?}"
    );
}

#[tokio::test]
async fn instantiated_v2_artifact_is_exactly_attested_renderable_and_rebuildable() {
    let (db, registry, _guard) = fixture().await;
    create_module(&registry, &db, &module_source("instantiated")).await;
    let release = publish(&registry, &db).await;
    create_artifact(&registry, &db, ARTIFACT_A, &artifact_source(&release)).await;

    let copy = call(
        &registry,
        &db,
        "instantiate_artifact",
        json!({ "source_id": ARTIFACT_A, "title": "Reusable copy" }),
    )
    .await;
    let copy_text = native_ce::mcp::render::render("instantiate_artifact", &copy).unwrap();
    assert!(
        copy_text.contains(&format!("source_id: {}", json!(ARTIFACT_A))),
        "the shared enriched-write renderer must retain instantiation receipts: {copy_text}"
    );
    let copy_id = copy["id"].as_str().unwrap();
    let source_event = sqlx::query(
        "SELECT id,json_extract(payload,'$.body') AS body FROM content_events
          WHERE record_id=? AND type='record.created'",
    )
    .bind(copy_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event_id: String = source_event.get("id");
    let body: String = source_event.get("body");
    let attestation = sqlx::query(
        "SELECT attestation_event_id,source_event_id,source_sha256
           FROM artifact_source_attestations WHERE artifact_id=?",
    )
    .bind(copy_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        attestation.get::<String, _>("source_event_id"),
        source_event_id
    );
    assert_eq!(
        attestation.get::<String, _>("source_sha256"),
        hex::encode(Sha256::digest(body.as_bytes()))
    );
    let attestation_event_id: String = attestation.get("attestation_event_id");
    let attestation_event_record: String = sqlx::query_scalar(
        "SELECT record_id FROM content_events WHERE id=? AND type='artifact.source_attested'",
    )
    .bind(attestation_event_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(attestation_event_record, copy_id);

    let rendered = call(&registry, &db, "render_artifact", json!({ "id": copy_id })).await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    let rebuilt = native_ce::conformance::run_conformance(&db).await;
    assert!(
        rebuilt.ok,
        "instantiated v2 graph must rebuild: {rebuilt:?}"
    );
}

#[tokio::test]
async fn v2_instantiation_fails_closed_and_rolls_back_attestation_projection_failure() {
    let (db, registry, _guard) = fixture().await;
    create_module(&registry, &db, &module_source("rollback")).await;
    let release = publish(&registry, &db).await;
    create_artifact(&registry, &db, ARTIFACT_A, &artifact_source(&release)).await;

    let records_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE records SET body='export const nativeArtifact = {' WHERE id=?")
        .bind(ARTIFACT_A)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let malformed = registry
        .call(
            db.clone(),
            Caller::local(),
            "instantiate_artifact",
            json!({ "source_id": ARTIFACT_A, "title": "Must not exist" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        malformed.contains("mdx") || malformed.contains("parse"),
        "{malformed}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        records_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        events_before
    );

    sqlx::query(
        "UPDATE records SET body=(SELECT json_extract(payload,'$.body') FROM content_events
          WHERE record_id=? AND type='record.created') WHERE id=?",
    )
    .bind(ARTIFACT_A)
    .bind(ARTIFACT_A)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let attestations_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM artifact_source_attestations")
            .fetch_one(db.pool())
            .await
            .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_instantiated_v2_attestation
         BEFORE INSERT ON artifact_source_attestations
         WHEN NEW.artifact_id <> '44444444-4444-4444-8444-444444444444'
         BEGIN SELECT RAISE(ABORT, 'injected v2 attestation projection failure'); END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "instantiate_artifact",
            json!({ "source_id": ARTIFACT_A, "title": "Must roll back" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("injected v2 attestation projection failure"),
        "{error}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        records_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        events_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM artifact_source_attestations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        attestations_before
    );
}

#[tokio::test]
async fn consumption_authority_denies_a_deleted_module_before_execution() {
    let (db, registry, _guard) = fixture().await;
    create_module(&registry, &db, &module_source("release one")).await;
    let release = publish(&registry, &db).await;
    create_artifact(&registry, &db, ARTIFACT_A, &artifact_source(&release)).await;
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");

    call(
        &registry,
        &db,
        "delete_record",
        json!({
            "id": MODULE_ID,
            "reason": "A deleted module must no longer be consumable even when an immutable release remains."
        }),
    )
    .await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_consumption_denied",
        "{denied:#}"
    );
    assert_eq!(denied["diagnostic"]["details"]["phase"], "authorize");
}

#[tokio::test]
async fn exact_imports_and_publish_occ_fail_closed() {
    let (db, registry, _guard) = fixture().await;
    create_module(&registry, &db, &module_source("one")).await;
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_mdx_modules",
            json!({
                "action": "publish", "module_id": MODULE_ID,
                "expected_source_event_id": "77777777-7777-4777-8777-777777777777",
                "expected_source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("source changed"), "{error}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM module_releases")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );

    let invalid = r#"import { X } from "./floating"
export const nativeArtifact = { schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: [] }

<X />"#;
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT_A, "type": "Document", "kind": "artifact", "name": "invalid",
                "body": invalid, "facets": { "runtime": "native.mdx.v2" },
                "reason": "Prove floating imports fail before append."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("module_specifier_invalid"), "{error}");
}

#[tokio::test]
async fn named_inputs_and_exact_release_grants_fail_closed_before_execution() {
    let (db, registry, _guard) = fixture().await;
    let source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true },
    customers: { envelope: "native.collection-envelope.v1", required: true }
  },
  exports: { Count: { kind: "component", props: {}, uses_inputs: ["orders", "customers"] } },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } },
    { capability: "input.read", scope: { port: "customers" } }
  ]
}

export function Count(_props, native) {
  return <Metric label="Total" value={native.inputs.orders.records.length + native.inputs.customers.records.length} />
}
"#;
    create_module(&registry, &db, source).await;
    let release = publish(&registry, &db).await;
    let event = release["publication_event_id"].as_str().unwrap();
    let digest = release["source_sha256"].as_str().unwrap();
    let artifact = format!(
        r#"import {{ Count }} from "native:module/{MODULE_ID}@event-{event}?sha256={digest}"
export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{
    orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: false }},
    customers: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: false }}
  }},
  module_inputs: {{ Count: {{ publication_event_id: "{event}", export: "Count", ports: {{ orders: "orders", customers: "customers" }} }} }},
  capability_requests: []
}}

<Count />
"#
    );
    create_artifact(&registry, &db, ARTIFACT_A, &artifact).await;

    for (id, name) in [(ORDERS, "Orders"), (CUSTOMERS, "Customers")] {
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id, "type": "Collection", "kind": "selection", "name": name,
                "reason": "Provide a deterministic named module input."
            }),
        )
        .await;
    }
    for (id, collection) in [(ORDER_ONE, ORDERS), (CUSTOMER_ONE, CUSTOMERS)] {
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id, "type": "WorkItem", "kind": "task", "name": id,
                "reason": "Populate a named Collection input."
            }),
        )
        .await;
        call(
            &registry,
            &db,
            "manage_links",
            json!({ "action": "add", "source_id": id, "target_id": collection, "relationship": "member_of" }),
        )
        .await;
    }
    let orders_bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "orders", "collection_id": ORDERS }),
    )
    .await;
    assert_eq!(orders_bound["status"], "bound", "{orders_bound:#}");
    let missing = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        missing["diagnostic"]["code"], "named_input_missing",
        "{missing:#}"
    );
    let customers_bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "customers", "collection_id": CUSTOMERS }),
    )
    .await;
    assert_eq!(customers_bound["status"], "bound", "{customers_bound:#}");
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_capability_denied",
        "{denied:#}"
    );

    for (module_port, artifact_port) in [("orders", "orders"), ("customers", "customers")] {
        call(
            &registry,
            &db,
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "module_release",
                "subject_record_id": MODULE_ID, "subject_event_id": event,
                "source_sha256": digest, "capability": "input.read",
                "scope": { "module_port": module_port, "artifact_port": artifact_port }
            }),
        )
        .await;
    }
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert!(rendered["plan"]["tree"].to_string().contains("\"value\":2"));

    let reordered = artifact.replace(
        "    orders: { envelope: \"native.collection-envelope.v1\", required: true, expose_to_root: false },\n    customers: { envelope: \"native.collection-envelope.v1\", required: true, expose_to_root: false }",
        "    customers: { envelope: \"native.collection-envelope.v1\", required: true, expose_to_root: false },\n    orders: { envelope: \"native.collection-envelope.v1\", required: true, expose_to_root: false }",
    );
    assert_ne!(reordered, artifact);
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT_A,
            "body": reordered,
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "A copy edit must preserve exact module input paths."
        }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_carried_forward",
        "{updated:#}"
    );
    assert_eq!(
        updated["artifact_input_continuity"]["carried_binding_count"],
        2
    );
    assert_eq!(
        updated["artifact_input_continuity"]["carried_grant_count"],
        2
    );
    let still_rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(still_rendered["status"], "rendered", "{still_rendered:#}");

    let incompatible_path = artifact.replace(
        "ports: { orders: \"orders\", customers: \"customers\" }",
        "ports: { orders: \"customers\", customers: \"orders\" }",
    );
    assert_ne!(incompatible_path, artifact);
    let partial = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT_A,
            "body": incompatible_path,
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "Swap module port paths without changing root declarations."
        }),
    )
    .await;
    assert_eq!(
        partial["artifact_input_continuity"]["status"], "artifact_inputs_partially_carried",
        "{partial:#}"
    );
    assert_eq!(
        partial["artifact_input_continuity"]["carried_binding_count"],
        2
    );
    assert_eq!(
        partial["artifact_input_continuity"]["carried_grant_count"],
        0
    );
    assert_eq!(
        partial["artifact_input_continuity"]["dropped_grant_count"],
        2
    );
    let remaining_grants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
    )
    .bind(ARTIFACT_A)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(remaining_grants, 0);
    let revoked = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        revoked["diagnostic"]["code"], "module_capability_denied",
        "{revoked:#}"
    );
}

#[tokio::test]
async fn messages_home_pane_reexecutes_governed_sql_beside_a_legacy_collection() {
    let (db, registry, _guard) = fixture().await;

    for (id, name) in [
        (HOME_SENDER_PERSON, "Home sender"),
        (HOME_RECIPIENT_PERSON, "Home recipient"),
    ] {
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id, "type": "Entity", "kind": "person", "name": name,
                "reason": "Resolve one authenticated Home fixture member."
            }),
        )
        .await;
    }
    let fixture_pool = crate::common::fixture_write_pool(&db).await;
    for (person, account, principal) in [
        (
            HOME_SENDER_PERSON,
            HOME_SENDER_ACCOUNT,
            "native/home-sender",
        ),
        (
            HOME_RECIPIENT_PERSON,
            HOME_RECIPIENT_ACCOUNT,
            "native/home-recipient",
        ),
    ] {
        for (system, identifier) in [("account", account), ("native-principal", principal)] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,1)",
            )
            .bind(person)
            .bind(system)
            .bind(identifier)
            .execute(&fixture_pool)
            .await
            .unwrap();
        }
    }
    for person in [HOME_SENDER_PERSON, HOME_RECIPIENT_PERSON] {
        replace_explicit_policy(
            &db,
            "test:messages-home-identities",
            person,
            vec![
                AllowEntry::account(HOME_SENDER_ACCOUNT, Capability::View),
                AllowEntry::account(HOME_RECIPIENT_ACCOUNT, Capability::View),
            ],
        )
        .await
        .unwrap();
    }

    let message = call_as(
        &registry,
        &db,
        Caller::authenticated(HOME_SENDER_ACCOUNT),
        "manage_messages",
        json!({
            "action": "send",
            "name": "Please confirm the launch",
            "body": "Can you confirm the launch window?",
            "origin": {
                "type": "direct",
                "participant_ids": [HOME_SENDER_PERSON, HOME_RECIPIENT_PERSON]
            },
            "addressed_to": [HOME_RECIPIENT_PERSON],
            "expectation": "reply",
            "idempotency_key": "messages-home-source",
            "reason": "Populate the awaiting-reply Home pane."
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    replace_explicit_policy(
        &db,
        "test:messages-home-source",
        &message,
        vec![AllowEntry::account(
            HOME_RECIPIENT_ACCOUNT,
            Capability::View,
        )],
    )
    .await
    .unwrap();

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": HOME_LEGACY_RECORD, "type": "WorkItem", "kind": "task",
            "name": "Legacy collection row",
            "reason": "Prove the pre-governed Collection input remains compatible."
        }),
    )
    .await;

    let columns = json!([
        { "name": "id", "type": "identifier", "nullable": false },
        { "name": "name", "type": "text", "nullable": false },
        { "name": "summary", "type": "text", "nullable": true },
        { "name": "created_at", "type": "timestamp", "nullable": false }
    ]);
    let messages_schema = canonical_sha256(&columns);
    let governed_query = json!({
        "v": "1.1",
        "kind": "governed_sql",
        "profile": { "id": "sqlite-local", "revision": 1 },
        "catalog_revision": 3,
        "relations": {
            "messages_awaiting_reply": {
                "identity": "native.query-sql.messages-awaiting-reply",
                "semantic_version": 1
            },
            "records": {
                "identity": "native.query-sql.records",
                "semantic_version": 1
            }
        },
        "sql": "SELECT awaiting.message_id AS id, records.name, records.body AS summary, records.created_at FROM messages_awaiting_reply awaiting JOIN records ON records.id=awaiting.message_id ORDER BY records.created_at DESC, awaiting.message_id ASC",
        "parameters": [],
        "output": {
            "columns": columns,
            "schema_sha256": messages_schema,
            "row_identity": ["id"],
            "order": [
                { "column": "created_at", "direction": "desc" },
                { "column": "id", "direction": "asc" }
            ]
        },
        "bounds": { "rows": 50 }
    });
    for arguments in [
        json!({
            "id": HOME_MESSAGES_QUERY, "type": "Collection", "kind": "query",
            "name": "Messages awaiting my reply",
            "facets": { "query": serde_json::to_string(&governed_query).unwrap() },
            "reason": "Bind the caller-relative Messages relation by durable query identity."
        }),
        json!({
            "id": HOME_LEGACY_QUERY, "type": "Collection", "kind": "query",
            "name": "Legacy Home records",
            "facets": { "query": serde_json::to_string(&json!({
                "v": "0.2",
                "query": {
                    "steps": [{ "step": "filter", "ids": [HOME_LEGACY_RECORD] }],
                    "order": "name_asc"
                }
            })).unwrap() },
            "reason": "Keep one legacy Collection-backed port beside the governed relation."
        }),
    ] {
        call(&registry, &db, "create_record", arguments).await;
    }

    let source = format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{
    messages: {{ envelope: "native.relation-envelope.v1", required: true, expose_to_root: true, schema_sha256: "{messages_schema}" }},
    legacy: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }}
  }},
  module_inputs: {{}},
  capability_requests: [
    {{ capability: "input.read", scope: {{ port: "messages" }} }},
    {{ capability: "input.read", scope: {{ port: "legacy" }} }},
    {{ capability: "navigation.record.user_gesture", scope: {{}} }}
  ]
}}

<Grid columns={{2}} gap={{3}}>
  <section>
    <h2>Messages</h2>
    {{native.inputs.messages.relation.rows.length
      ? <RecordTable records={{native.inputs.messages.relation.rows}} columns={{["name", "summary"]}} />
      : <EmptyState title="No messages awaiting your reply" />}}
  </section>
  <section>
    <h2>Records</h2>
    <RecordTable records={{native.inputs.legacy.records}} columns={{["name"]}} />
  </section>
</Grid>
"#
    );
    create_artifact(&registry, &db, HOME_ARTIFACT, &source).await;
    for id in [
        HOME_ARTIFACT,
        HOME_MESSAGES_QUERY,
        HOME_LEGACY_QUERY,
        HOME_LEGACY_RECORD,
    ] {
        replace_explicit_policy(
            &db,
            "test:messages-home-inputs",
            id,
            vec![AllowEntry::account(
                HOME_RECIPIENT_ACCOUNT,
                Capability::View,
            )],
        )
        .await
        .unwrap();
    }
    for (port_name, collection_id) in [
        ("messages", HOME_MESSAGES_QUERY),
        ("legacy", HOME_LEGACY_QUERY),
    ] {
        call(
            &registry,
            &db,
            "manage_artifact_inputs",
            json!({
                "action": "bind", "artifact_id": HOME_ARTIFACT,
                "port_name": port_name, "collection_id": collection_id
            }),
        )
        .await;
    }
    let grants = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": HOME_ARTIFACT }),
    )
    .await;
    let subject = &grants["subjects"][0];
    let subject_event_id = subject["subject_event_id"].as_str().unwrap();
    let source_sha256 = subject["source_sha256"].as_str().unwrap();
    for (capability, scope) in [
        ("input.read", json!({ "artifact_port": "messages" })),
        ("input.read", json!({ "artifact_port": "legacy" })),
        ("navigation.record.user_gesture", json!({})),
    ] {
        call(
            &registry,
            &db,
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": HOME_ARTIFACT,
                "subject_kind": "artifact_source", "subject_record_id": HOME_ARTIFACT,
                "subject_event_id": subject_event_id, "source_sha256": source_sha256,
                "capability": capability, "scope": scope
            }),
        )
        .await;
    }

    let recipient = Caller::authenticated(HOME_RECIPIENT_ACCOUNT);
    let initial = call_as(
        &registry,
        &db,
        recipient.clone(),
        "render_artifact",
        json!({ "id": HOME_ARTIFACT }),
    )
    .await;
    assert_eq!(initial["status"], "rendered", "{initial:#}");
    assert_eq!(initial["plan"]["tree"]["type"], "Grid");
    let initial_tree = initial["plan"]["tree"].to_string();
    assert!(initial_tree.contains(&message), "{initial:#}");
    assert!(initial_tree.contains(HOME_LEGACY_RECORD), "{initial:#}");
    assert!(!initial_tree.contains("No messages awaiting your reply"));

    call_as(
        &registry,
        &db,
        recipient.clone(),
        "manage_messages",
        json!({
            "action": "send",
            "body": "Confirmed.",
            "origin": {
                "type": "direct",
                "participant_ids": [HOME_SENDER_PERSON, HOME_RECIPIENT_PERSON]
            },
            "addressed_to": [HOME_SENDER_PERSON],
            "expectation": "none",
            "links": [{ "target_id": message, "relationship": "reply_to" }],
            "idempotency_key": "messages-home-reply",
            "reason": "Satisfy the Home pane's reply expectation."
        }),
    )
    .await;

    let refreshed = call_as(
        &registry,
        &db,
        recipient,
        "render_artifact",
        json!({ "id": HOME_ARTIFACT }),
    )
    .await;
    assert_eq!(refreshed["status"], "rendered", "{refreshed:#}");
    let refreshed_tree = refreshed["plan"]["tree"].to_string();
    assert!(!refreshed_tree.contains(&message), "{refreshed:#}");
    assert!(
        refreshed_tree.contains("No messages awaiting your reply"),
        "{refreshed:#}"
    );
    assert!(
        refreshed_tree.contains(HOME_LEGACY_RECORD),
        "legacy Collection input must survive governed relation refresh: {refreshed:#}"
    );
}

#[tokio::test]
async fn standalone_agents_artifact_joins_separate_governed_ports_and_expires_on_refresh() {
    let _guard = Arc::clone(integration_guard()).lock_owned().await;
    let database_dir = tempfile::tempdir().unwrap();
    let database_path = database_dir.path().join("agents-artifact.sqlite3");
    let db = create_database(&database_path.to_string_lossy())
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let presence_columns = json!([
        { "name": "activity_id", "type": "identifier", "nullable": false },
        { "name": "run_key", "type": "text", "nullable": false },
        { "name": "principal_ref", "type": "text", "nullable": false },
        { "name": "principal_display_name", "type": "text", "nullable": true },
        { "name": "started_at", "type": "timestamp", "nullable": false },
        { "name": "ended_at", "type": "timestamp", "nullable": true },
        { "name": "last_observed_activity_at", "type": "timestamp", "nullable": false },
        { "name": "active_until", "type": "timestamp", "nullable": false },
        { "name": "appears_active", "type": "boolean", "nullable": false }
    ]);
    let claims_columns = json!([
        { "name": "claim_id", "type": "identifier", "nullable": false },
        { "name": "activity_id", "type": "identifier", "nullable": false },
        { "name": "record_id", "type": "identifier", "nullable": false },
        { "name": "claimed_at", "type": "timestamp", "nullable": false },
        { "name": "released_at", "type": "timestamp", "nullable": true },
        { "name": "is_current", "type": "boolean", "nullable": false }
    ]);
    assert_eq!(canonical_sha256(&presence_columns), AGENTS_PRESENCE_SCHEMA);
    assert_eq!(canonical_sha256(&claims_columns), AGENTS_CLAIMS_SCHEMA);

    let presence_query = json!({
        "v": "1.1",
        "kind": "governed_sql",
        "profile": { "id": "sqlite-local", "revision": 1 },
        "catalog_revision": 3,
        "relations": {
            "agent_activity": {
                "identity": "native.semantic.agent_activity",
                "semantic_version": 2
            }
        },
        "sql": "SELECT activity_id,run_key,principal_ref,principal_display_name,started_at,ended_at,last_observed_activity_at,active_until,appears_active FROM agent_activity ORDER BY last_observed_activity_at DESC,activity_id ASC",
        "parameters": [],
        "output": {
            "columns": presence_columns,
            "schema_sha256": AGENTS_PRESENCE_SCHEMA,
            "row_identity": ["activity_id"],
            "order": [
                { "column": "last_observed_activity_at", "direction": "desc" },
                { "column": "activity_id", "direction": "asc" }
            ]
        },
        "bounds": { "rows": 50 }
    });
    let claims_query = json!({
        "v": "1.1",
        "kind": "governed_sql",
        "profile": { "id": "sqlite-local", "revision": 1 },
        "catalog_revision": 3,
        "relations": {
            "agent_activity_claims": {
                "identity": "native.semantic.agent_activity_claims",
                "semantic_version": 1
            }
        },
        "sql": "SELECT claim_id,activity_id,record_id,claimed_at,released_at,is_current FROM agent_activity_claims ORDER BY claimed_at DESC,claim_id ASC",
        "parameters": [],
        "output": {
            "columns": claims_columns,
            "schema_sha256": AGENTS_CLAIMS_SCHEMA,
            "row_identity": ["claim_id"],
            "order": [
                { "column": "claimed_at", "direction": "desc" },
                { "column": "claim_id", "direction": "asc" }
            ]
        },
        "bounds": { "rows": 50 }
    });
    let mut wrong_presence_query = presence_query.clone();
    wrong_presence_query["relations"] = json!({
        "records": {
            "identity": "native.query-sql.records",
            "semantic_version": 1
        }
    });
    wrong_presence_query["sql"] = json!(
        "SELECT id AS activity_id,id AS run_key,id AS principal_ref,NULL AS principal_display_name,created_at AS started_at,NULL AS ended_at,created_at AS last_observed_activity_at,created_at AS active_until,0 AS appears_active FROM records ORDER BY last_observed_activity_at DESC,activity_id ASC"
    );
    for (id, name, definition) in [
        (
            AGENTS_PRESENCE_QUERY,
            "Agent presence",
            presence_query.clone(),
        ),
        (AGENTS_CLAIMS_QUERY, "Agent claims", claims_query),
    ] {
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id,
                "type": "Collection",
                "kind": "query",
                "name": name,
                "facets": { "query": serde_json::to_string(&definition).unwrap() },
                "reason": "Pin one independently governed Agents relation."
            }),
        )
        .await;
    }
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": AGENTS_WRONG_PRESENCE_QUERY,
            "type": "Collection",
            "kind": "query",
            "name": "Wrong presence relation with matching schema",
            "facets": { "query": serde_json::to_string(&wrong_presence_query).unwrap() },
            "reason": "Exercise semantic relation pinning independently of schema pinning."
        }),
    )
    .await;

    for (id, name, reason) in [
        (
            AGENTS_CLAIMED_RECORD,
            "Visible claimed task",
            "Give the claims port one visible row.",
        ),
        (
            AGENTS_HIDDEN_CLAIMED_RECORD,
            "Hidden claimed task",
            "Prove claim visibility before logical SQL and artifact rendering.",
        ),
    ] {
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id,
                "type": "WorkItem",
                "kind": "task",
                "name": name,
                "reason": reason
            }),
        )
        .await;
    }
    for (run_key, intent) in [
        ("scout-chair-a748b2", "Claim the visible task."),
        ("scout-chair-b748b2", "Remain visible without a claim."),
    ] {
        call(
            &registry,
            &db,
            "set_intent",
            json!({ "intent": intent, "run_key": run_key }),
        )
        .await;
    }
    let claimed_activity_id: String =
        sqlx::query_scalar("SELECT activity_id FROM agent_runs WHERE run_key=?")
            .bind("scout-chair-a748b2")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let idle_activity_id: String =
        sqlx::query_scalar("SELECT activity_id FROM agent_runs WHERE run_key=?")
            .bind("scout-chair-b748b2")
            .fetch_one(db.pool())
            .await
            .unwrap();
    call(
        &registry,
        &db,
        "start_work",
        json!({
            "record_id": AGENTS_CLAIMED_RECORD,
            "action": "claim",
            "run_key": "scout-chair-a748b2"
        }),
    )
    .await;

    let source = include_str!("../fixtures/native-mdx-v2-agents.mdx");
    assert!(source.contains("claim.activity_id === activity.activity_id"));
    assert!(source.contains("{activity.run_key}"));
    assert!(!source.contains("<p>{activity.activity_id}</p>"));
    assert!(!source.contains("claim.record_id ==="));
    assert!(!source.contains("RecordTable"));
    assert!(!source.contains("RecordCard"));
    assert!(!source.contains("FacetControl"));
    assert!(!source.contains("DropTarget"));
    create_artifact(&registry, &db, AGENTS_ARTIFACT, source).await;
    let wrong_relation = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_inputs",
            json!({
                "action": "bind",
                "artifact_id": AGENTS_ARTIFACT,
                "port_name": "presence",
                "collection_id": AGENTS_WRONG_PRESENCE_QUERY
            }),
        )
        .await
        .unwrap_err();
    assert!(
        wrong_relation
            .to_string()
            .contains("exact schema and semantic relation dependencies"),
        "same-schema wrong-relation binding must be rejected: {wrong_relation}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM artifact_inputs WHERE artifact_id=? AND collection_id=?",
        )
        .bind(AGENTS_ARTIFACT)
        .bind(AGENTS_WRONG_PRESENCE_QUERY)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
    for (port_name, collection_id) in [
        ("presence", AGENTS_PRESENCE_QUERY),
        ("claims", AGENTS_CLAIMS_QUERY),
    ] {
        call(
            &registry,
            &db,
            "manage_artifact_inputs",
            json!({
                "action": "bind",
                "artifact_id": AGENTS_ARTIFACT,
                "port_name": port_name,
                "collection_id": collection_id
            }),
        )
        .await;
    }
    let grants = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": AGENTS_ARTIFACT }),
    )
    .await;
    let subject = &grants["subjects"][0];
    for port in ["presence", "claims"] {
        call(
            &registry,
            &db,
            "manage_artifact_module_grants",
            json!({
                "action": "grant",
                "artifact_id": AGENTS_ARTIFACT,
                "subject_kind": "artifact_source",
                "subject_record_id": AGENTS_ARTIFACT,
                "subject_event_id": subject["subject_event_id"],
                "source_sha256": subject["source_sha256"],
                "capability": "input.read",
                "scope": { "artifact_port": port }
            }),
        )
        .await;
    }

    let grants = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": AGENTS_ARTIFACT }),
    )
    .await;
    let granted = grants["grants"]
        .as_array()
        .expect("grant read returns exact grants");
    assert_eq!(granted.len(), 2, "{grants:#}");
    let mut granted_ports = granted
        .iter()
        .map(|grant| {
            assert_eq!(grant["capability"], "input.read", "{grant:#}");
            assert_eq!(grant["subject_kind"], "artifact_source", "{grant:#}");
            grant["scope"]["artifact_port"]
                .as_str()
                .expect("input.read grant names an artifact port")
                .to_owned()
        })
        .collect::<Vec<_>>();
    granted_ports.sort();
    assert_eq!(granted_ports, ["claims", "presence"]);

    for id in [
        AGENTS_ARTIFACT,
        AGENTS_PRESENCE_QUERY,
        AGENTS_CLAIMS_QUERY,
        AGENTS_CLAIMED_RECORD,
    ] {
        replace_explicit_policy(
            &db,
            "test:agents-viewer",
            id,
            vec![AllowEntry::account(AGENTS_VIEWER_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        "test:agents-hidden-claim",
        AGENTS_HIDDEN_CLAIMED_RECORD,
        vec![],
    )
    .await
    .unwrap();
    let hosted_viewer = unsafe {
        Caller::authenticated(AGENTS_VIEWER_ACCOUNT).with_verified_hosted_activity(
            "catalog:agents-viewer",
            "db:agents-artifact",
            vec![
                native_ce::query::principal::ActivityRosterMember::verified_unchecked(
                    "local",
                    "native:workspace-member:local",
                ),
                native_ce::query::principal::ActivityRosterMember::verified_unchecked(
                    AGENTS_VIEWER_ACCOUNT,
                    "native:workspace-member:agents-viewer",
                ),
            ],
        )
    }
    .unwrap();

    let initial = call_as(
        &registry,
        &db,
        hosted_viewer.clone(),
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    assert_eq!(initial["status"], "rendered", "{initial:#}");
    let initial_tree = initial["plan"]["tree"].to_string();
    for expected in [
        "scout-chair-a748b2",
        "scout-chair-b748b2",
        AGENTS_CLAIMED_RECORD,
        "native.semantic.agent_activity",
        "native.semantic.agent_activity_claims",
        AGENTS_PRESENCE_SCHEMA,
        AGENTS_CLAIMS_SCHEMA,
        "Observed",
        "best_effort",
        "within bound",
        "No known degradation in this observation",
        "not proof that a provider is online",
        "Observed recently",
    ] {
        assert!(
            initial_tree.contains(expected),
            "missing {expected}: {initial:#}"
        );
    }
    assert!(!initial_tree.contains(&claimed_activity_id));
    assert!(!initial_tree.contains(&idle_activity_id));
    let presence_port = &initial["plan"]["provenance"]["input_bundle"]["ports"]["presence"];
    let claims_port = &initial["plan"]["provenance"]["input_bundle"]["ports"]["claims"];
    assert_eq!(presence_port["envelope"], "native.relation-envelope.v1");
    assert_eq!(claims_port["envelope"], "native.relation-envelope.v1");
    assert_ne!(presence_port["sha256"], claims_port["sha256"]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM links WHERE relationship='renders' AND (source_id=? OR target_id=?)",
        )
        .bind(AGENTS_ARTIFACT)
        .bind(AGENTS_ARTIFACT)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0,
        "the Agents artifact is standalone and has no Home renders binding"
    );

    call(
        &registry,
        &db,
        "start_work",
        json!({
            "record_id": AGENTS_HIDDEN_CLAIMED_RECORD,
            "action": "claim",
            "run_key": "scout-chair-a748b2"
        }),
    )
    .await;
    let after_hidden_claim = call_as(
        &registry,
        &db,
        hosted_viewer.clone(),
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    assert_eq!(
        after_hidden_claim["status"], "rendered",
        "{after_hidden_claim:#}"
    );
    assert_eq!(
        normalize_agents_observation_metrics(&initial["plan"]["tree"]),
        normalize_agents_observation_metrics(&after_hidden_claim["plan"]["tree"]),
        "a hidden claim must not perturb visible presence rows, safe receipt fields, or rendered structure"
    );
    assert!(
        !after_hidden_claim["plan"]["tree"]
            .to_string()
            .contains(AGENTS_HIDDEN_CLAIMED_RECORD),
        "{after_hidden_claim:#}"
    );

    replace_explicit_policy(
        &db,
        "test:agents-unhide-claim",
        AGENTS_HIDDEN_CLAIMED_RECORD,
        vec![AllowEntry::account(AGENTS_VIEWER_ACCOUNT, Capability::View)],
    )
    .await
    .unwrap();
    let after_unhide = call_as(
        &registry,
        &db,
        hosted_viewer.clone(),
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    let after_unhide_tree = after_unhide["plan"]["tree"].to_string();
    assert_eq!(after_unhide["status"], "rendered", "{after_unhide:#}");
    assert!(after_unhide_tree.contains(AGENTS_HIDDEN_CLAIMED_RECORD));
    assert!(after_unhide_tree.contains(AGENTS_CLAIMED_RECORD));
    assert!(after_unhide_tree.contains("scout-chair-a748b2"));
    assert!(after_unhide_tree.contains("scout-chair-b748b2"));

    replace_explicit_policy(
        &db,
        "test:agents-revoke-claim",
        AGENTS_HIDDEN_CLAIMED_RECORD,
        vec![],
    )
    .await
    .unwrap();
    let after_revoke = call_as(
        &registry,
        &db,
        hosted_viewer.clone(),
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    let after_revoke_tree = after_revoke["plan"]["tree"].to_string();
    assert_eq!(after_revoke["status"], "rendered", "{after_revoke:#}");
    assert!(!after_revoke_tree.contains(AGENTS_HIDDEN_CLAIMED_RECORD));
    assert!(after_revoke_tree.contains(AGENTS_CLAIMED_RECORD));
    assert!(after_revoke_tree.contains("scout-chair-a748b2"));
    assert!(after_revoke_tree.contains("scout-chair-b748b2"));

    let without_activity_authority = call_as(
        &registry,
        &db,
        Caller::authenticated(AGENTS_VIEWER_ACCOUNT),
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    let without_activity_tree = without_activity_authority["plan"]["tree"].to_string();
    assert_eq!(
        without_activity_authority["status"], "rendered",
        "{without_activity_authority:#}"
    );
    assert!(
        without_activity_tree.contains("No agent activity is visible in this bounded observation")
    );
    assert!(!without_activity_tree.contains("scout-chair-a748b2"));
    assert!(!without_activity_tree.contains("scout-chair-b748b2"));
    assert!(!without_activity_tree.contains(AGENTS_CLAIMED_RECORD));
    assert!(!without_activity_tree.contains(AGENTS_HIDDEN_CLAIMED_RECORD));

    // The pane has no timer or refresh control. A host refresh re-executes
    // both governed ports at a new observation time, which is the explicit
    // expiry contract documented in the authored artifact itself.
    // Match the query contract's clock-boundary test fixture: age only the
    // rebuildable projection row through a raw test connection. Production
    // writes remain confined to control-event projection.
    let clock_fixture = rusqlite::Connection::open(&database_path).unwrap();
    clock_fixture
        .execute(
            "UPDATE agent_runs SET started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-25 hours')
              WHERE activity_id=?1",
            rusqlite::params![&idle_activity_id],
        )
        .unwrap();
    clock_fixture
        .execute(
            "UPDATE read_log_calls
                SET started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-25 hours'),
                    ended_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-25 hours')
              WHERE run_key='scout-chair-b748b2'",
            [],
        )
        .unwrap();
    let refreshed = call_as(
        &registry,
        &db,
        hosted_viewer.clone(),
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    assert_eq!(refreshed["status"], "rendered", "{refreshed:#}");
    let refreshed_tree = refreshed["plan"]["tree"].to_string();
    assert!(refreshed_tree.contains("scout-chair-a748b2"));
    assert!(!refreshed_tree.contains("scout-chair-b748b2"));
    assert!(refreshed_tree.contains(AGENTS_CLAIMED_RECORD));
    assert_ne!(
        initial["plan"]["provenance"]["input_bundle"]["ports"]["presence"]["sha256"],
        refreshed["plan"]["provenance"]["input_bundle"]["ports"]["presence"]["sha256"]
    );

    let mut incompatible_presence = presence_query;
    incompatible_presence["relations"]["agent_activity"]["semantic_version"] = json!(1);
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": AGENTS_PRESENCE_QUERY,
            "facets": { "query": serde_json::to_string(&incompatible_presence).unwrap() },
            "reason": "Prove a bound semantic-version drift invalidates the artifact on fresh resolution."
        }),
    )
    .await;
    let incompatible = call_as(
        &registry,
        &db,
        hosted_viewer,
        "render_artifact",
        json!({ "id": AGENTS_ARTIFACT }),
    )
    .await;
    assert_eq!(
        incompatible["diagnostic"]["code"], "named_input_incompatible",
        "{incompatible:#}"
    );
}

#[tokio::test]
async fn root_input_and_record_navigation_require_the_exact_artifact_source_grants() {
    let (db, registry, _guard) = fixture().await;
    let artifact = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } },
    { capability: "navigation.record.user_gesture", scope: {} }
  ]
}

<RecordCard record={native.inputs.orders.records[0]} fields={["name"]} />
"#;
    create_artifact(&registry, &db, ARTIFACT_A, artifact).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ORDERS, "type": "Collection", "kind": "selection", "name": "Orders", "reason": "Root input fixture" }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ORDER_ONE, "type": "WorkItem", "kind": "task", "name": "First order", "reason": "Root navigation fixture" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": ORDER_ONE, "target_id": ORDERS, "relationship": "member_of" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "orders", "collection_id": ORDERS }),
    )
    .await;

    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_capability_denied",
        "{denied:#}"
    );

    let exact = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT_A }),
    )
    .await;
    let subjects = exact["subjects"].as_array().unwrap();
    assert_eq!(subjects.len(), 1, "{exact:#}");
    let subject = &subjects[0];
    assert_eq!(subject["subject_kind"], "artifact_source");
    assert_eq!(subject["subject_record_id"], ARTIFACT_A);
    assert_eq!(subject["requests"].as_array().unwrap().len(), 2);
    let event = subject["subject_event_id"].as_str().unwrap();
    let digest = subject["source_sha256"].as_str().unwrap();

    for invalid in [
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "module_release",
            "subject_record_id": ARTIFACT_A, "subject_event_id": event,
            "source_sha256": digest, "capability": "input.read",
            "scope": { "artifact_port": "orders" }
        }),
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT_A, "subject_event_id": "99999999-9999-4999-8999-999999999999",
            "source_sha256": digest, "capability": "input.read",
            "scope": { "artifact_port": "orders" }
        }),
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT_A, "subject_event_id": event,
            "source_sha256": digest, "capability": "input.read",
            "scope": { "module_port": "orders", "artifact_port": "orders" }
        }),
    ] {
        let error = registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_artifact_module_grants",
                invalid,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("request") || error.contains("subject"),
            "{error}"
        );
    }

    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT_A, "subject_event_id": event,
            "source_sha256": digest, "capability": "input.read",
            "scope": { "artifact_port": "orders" }
        }),
    )
    .await;
    let navigation_denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        navigation_denied["diagnostic"]["code"], "module_capability_denied",
        "{navigation_denied:#}"
    );
    assert_eq!(
        navigation_denied["diagnostic"]["details"]["capability"], "navigation.record.user_gesture",
        "{navigation_denied:#}"
    );

    let wrong_navigation_scope = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
                "subject_record_id": ARTIFACT_A, "subject_event_id": event,
                "source_sha256": digest, "capability": "navigation.record.user_gesture",
                "scope": { "record_id": ORDER_ONE }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        wrong_navigation_scope.contains("request"),
        "{wrong_navigation_scope}"
    );
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT_A, "subject_event_id": event,
            "source_sha256": digest, "capability": "navigation.record.user_gesture", "scope": {}
        }),
    )
    .await;
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert!(rendered["plan"]["tree"].to_string().contains(ORDER_ONE));

    let projected: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT subject_kind,subject_record_id,subject_event_id FROM artifact_module_grants
          WHERE artifact_id=? ORDER BY capability",
    )
    .bind(ARTIFACT_A)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(projected.len(), 2);
    assert!(projected
        .iter()
        .all(|(kind, record, projected_event)| kind == "artifact_source"
            && record == ARTIFACT_A
            && projected_event == event));

    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT_A,
            "body": format!("{artifact}\n"),
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "Create a new exact root source identity"
        }),
    )
    .await;
    assert_eq!(
        updated["artifact_input_continuity"]["status"], "artifact_inputs_carried_forward",
        "{updated:#}"
    );
    let new_source_event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=?
          AND type IN ('record.created','record.updated')
          AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT_A)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let carried_source: String = sqlx::query_scalar(
        "SELECT artifact_source_event_id FROM artifact_inputs WHERE artifact_id=? AND port_name='orders'",
    )
    .bind(ARTIFACT_A)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(carried_source, new_source_event);
    assert_eq!(
        updated["artifact_input_continuity"]["carried_grant_count"], 2,
        "input.read and navigation both carry: {updated:#}"
    );
    assert_eq!(
        updated["artifact_input_continuity"]["dropped_grant_count"], 0,
        "{updated:#}"
    );
    // Every grant repins to the new exact source, so no predecessor row is left
    // behind pointing at the superseded attestation.
    let repinned: Vec<String> = sqlx::query_scalar(
        "SELECT artifact_source_event_id FROM artifact_module_grants WHERE artifact_id=?",
    )
    .bind(ARTIFACT_A)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(repinned.len(), 2);
    assert!(
        repinned.iter().all(|source| source == &new_source_event),
        "{repinned:?}"
    );
    // The body edit needed no re-grant: the next render still succeeds.
    let after_edit = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(after_edit["status"], "rendered", "{after_edit:#}");
    assert!(after_edit["plan"]["tree"].to_string().contains(ORDER_ONE));

    let rebuilt = native_ce::conformance::run_conformance(&db).await;
    assert!(
        rebuilt.ok,
        "root artifact grants must project and rebuild exactly: {rebuilt:?}"
    );
}

/// `fd4faf2`: the manifest spells the port `scope.port` and the grant spells it
/// `scope.artifact_port`. An agent that authored the artifact has only ever been
/// shown the first spelling, so it sends that, and the refusal used to say only
/// that it could not create or broaden a request — which reads as a consent
/// boundary rather than a spelling, and cost a real reader eight days on the wrong
/// hypothesis. The refusal has to name the shape it wanted.
#[tokio::test]
async fn refusing_a_manifest_spelled_grant_scope_names_the_resolved_port_key() {
    let (db, registry, _guard) = fixture().await;
    let artifact = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } },
    { capability: "navigation.record.user_gesture", scope: {} }
  ]
}

<RecordCard record={native.inputs.orders.records[0]} fields={["name"]} />
"#;
    create_artifact(&registry, &db, ARTIFACT_A, artifact).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ORDERS, "type": "Collection", "kind": "selection", "name": "Orders", "reason": "Root input fixture" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "orders", "collection_id": ORDERS }),
    )
    .await;
    let exact = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT_A }),
    )
    .await;
    let subject = &exact["subjects"].as_array().unwrap()[0];
    let event = subject["subject_event_id"].as_str().unwrap();
    let digest = subject["source_sha256"].as_str().unwrap();

    // The manifest's own spelling, copied verbatim into the grant.
    let manifest_spelling = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
                "subject_record_id": ARTIFACT_A, "subject_event_id": event,
                "source_sha256": digest, "capability": "input.read",
                "scope": { "port": "orders" }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        manifest_spelling.contains("artifact_port")
            && manifest_spelling.contains("scope.port")
            && manifest_spelling.contains("orders"),
        "the refusal must name the key it wanted, the spelling it got, and the declared port: \
         {manifest_spelling}"
    );

    // A capability the artifact never asked for is a different refusal, and says so
    // rather than blaming the scope.
    let undeclared = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
                "subject_record_id": ARTIFACT_A, "subject_event_id": event,
                "source_sha256": digest, "capability": "navigation.external.user_gesture", "scope": {}
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        undeclared.contains("declares no navigation.external.user_gesture capability request"),
        "{undeclared}"
    );

    // A scoped grant for a capability declared unscoped is still refused, and quotes
    // the scope the manifest actually declares rather than the port vocabulary.
    let over_scoped = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
                "subject_record_id": ARTIFACT_A, "subject_event_id": event,
                "source_sha256": digest, "capability": "navigation.record.user_gesture",
                "scope": { "artifact_port": "orders" }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        over_scoped.contains("is declared with scope {}") && !over_scoped.contains("scope.port"),
        "{over_scoped}"
    );

    // The corrected spelling is accepted, so the refusal above is a spelling and not
    // a consent boundary: nothing else about the caller or the artifact changed.
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
            "subject_record_id": ARTIFACT_A, "subject_event_id": event,
            "source_sha256": digest, "capability": "input.read",
            "scope": { "artifact_port": "orders" }
        }),
    )
    .await;
}
#[tokio::test]
async fn dropping_a_capability_request_drops_its_carried_grant_and_says_so() {
    let (db, registry, _guard) = fixture().await;
    let with_navigation = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } },
    { capability: "navigation.record.user_gesture", scope: {} }
  ]
}

<RecordCard record={native.inputs.orders.records[0]} fields={["name"]} />
"#;
    create_artifact(&registry, &db, ARTIFACT_A, with_navigation).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ORDERS, "type": "Collection", "kind": "selection", "name": "Orders", "reason": "Dropped-request fixture" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "orders", "collection_id": ORDERS }),
    )
    .await;
    let exact = call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT_A }),
    )
    .await;
    let subject = &exact["subjects"].as_array().unwrap()[0];
    let event = subject["subject_event_id"].as_str().unwrap().to_owned();
    let digest = subject["source_sha256"].as_str().unwrap().to_owned();
    for (capability, scope) in [
        ("input.read", json!({ "artifact_port": "orders" })),
        ("navigation.record.user_gesture", json!({})),
    ] {
        call(
            &registry,
            &db,
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "artifact_source",
                "subject_record_id": ARTIFACT_A, "subject_event_id": event,
                "source_sha256": digest, "capability": capability, "scope": scope
            }),
        )
        .await;
    }

    // The input declarations are untouched, so the surface still matches and the
    // input.read grant carries. The navigation request is gone, so its grant
    // must not survive the edit that withdrew it.
    let without_navigation = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "orders" } }
  ]
}

<Callout>{native.inputs.orders.records.length}</Callout>
"#;
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT_A,
            "body": without_navigation,
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "Withdraw the navigation capability request"
        }),
    )
    .await;
    let continuity = &updated["artifact_input_continuity"];
    assert_eq!(
        continuity["status"], "artifact_inputs_partially_carried",
        "a withdrawn request must be reported, not silently carried: {updated:#}"
    );
    assert_eq!(continuity["carried_grant_count"], 1, "{updated:#}");
    assert_eq!(continuity["dropped_grant_count"], 1, "{updated:#}");
    assert!(
        updated["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| {
                warning["code"] == "artifact_inputs_partially_carried"
                    && warning["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("manage_artifact_module_grants"))
            })),
        "the author is warned at edit time and told how to restore: {updated:#}"
    );
    let write_text = native_ce::mcp::render::render("update_record", &updated).unwrap();
    for (label, field) in [
        (
            "artifact_input_continuity",
            &updated["artifact_input_continuity"],
        ),
        ("warnings", &updated["warnings"]),
    ] {
        let exact = serde_json::to_string(field).unwrap();
        assert!(
            write_text.contains(&format!("{label}: {exact}")),
            "the live handler receipt must survive text rendering exactly: {write_text}"
        );
    }

    let surviving: Vec<String> =
        sqlx::query_scalar("SELECT capability FROM artifact_module_grants WHERE artifact_id=?")
            .bind(ARTIFACT_A)
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(surviving, vec!["input.read".to_owned()]);

    let rebuilt = native_ce::conformance::run_conformance(&db).await;
    assert!(
        rebuilt.ok,
        "a partially carried edit must project and rebuild exactly: {rebuilt:?}"
    );
}

#[tokio::test]
async fn artifact_source_attestations_fail_closed_on_tamper_order_digest_and_bypass() {
    let (db, registry, _guard) = fixture().await;
    let source = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {},
  module_inputs: {},
  capability_requests: []
}

<Callout>attested</Callout>
"#;
    create_artifact(&registry, &db, ARTIFACT_A, source).await;
    let row = sqlx::query(
        "SELECT e.id,e.seq,e.payload,e.created_at,
                json_extract(e.payload,'$.artifact_source.source_event_id') AS source_event_id
           FROM content_events e
          WHERE e.record_id=? AND e.type='artifact.source_attested'
          ORDER BY e.seq DESC LIMIT 1",
    )
    .bind(ARTIFACT_A)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let attestation_event_id: String = row.get("id");
    let source_event_id: String = row.get("source_event_id");
    let source_seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id=?")
        .bind(&source_event_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(row.get::<i64, _>("seq") > source_seq);
    let original: Value = serde_json::from_str(&row.get::<String, _>("payload")).unwrap();

    let mut invalid_hash = original.clone();
    invalid_hash["attestation_sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mut invalid_source_digest = original.clone();
    invalid_source_digest["artifact_source"]["source_sha256"] =
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    invalid_source_digest["attestation_sha256"] =
        json!(canonical_sha256(&invalid_source_digest["artifact_source"]));
    let mut tampered_descriptor = original.clone();
    tampered_descriptor["artifact_source"]["artifact_ports"]["invented"] = json!({
        "envelope": "native.collection-envelope.v1", "required": false
    });

    for (payload, seq) in [
        (invalid_hash, row.get::<i64, _>("seq") + 1),
        (invalid_source_digest, row.get::<i64, _>("seq") + 1),
        (tampered_descriptor, row.get::<i64, _>("seq") + 1),
        (original.clone(), source_seq),
    ] {
        let event = native_ce::events::EventRow {
            local_seq: seq,
            id: attestation_event_id.clone(),
            record_id: ARTIFACT_A.into(),
            event_type: "artifact.source_attested".into(),
            payload: Some(payload.to_string()),
            actor: None,
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
        assert!(
            error.contains("attestation") || error.contains("source") || error.contains("ordering"),
            "{error}"
        );
    }

    let bypass_source = source.replace("attested", "unattested bypass");
    let bypass_payload = json!({ "body": bypass_source, "reason": "internal bypass audit" });
    let bypass_id = "66666666-6666-4666-8666-666666666666";
    let fixture_pool = crate::common::fixture_write_pool(&db).await;
    let bypass_frontier: Vec<String> = sqlx::query_scalar(
        "SELECT event.id
           FROM content_events event
          WHERE NOT EXISTS (
                SELECT 1 FROM content_event_causal_frontier frontier
                 WHERE frontier.parent_event_id=event.id
          )
          ORDER BY event.id",
    )
    .fetch_all(&fixture_pool)
    .await
    .unwrap();
    let bypass_envelope = native_ce::events::CausalEnvelopeV1::complete(
        native_ce::events::CausalFrontierV1::new(bypass_frontier.clone()).unwrap(),
    );
    let inserted = sqlx::query(
        "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
         VALUES(?,?,'record.updated',?,'test','2026-01-01T00:00:00.000Z',1,'complete')",
    )
    .bind(bypass_id)
    .bind(ARTIFACT_A)
    .bind(bypass_payload.to_string())
    .execute(&fixture_pool)
    .await
    .unwrap();
    for parent_event_id in &bypass_frontier {
        sqlx::query(
            "INSERT INTO content_event_causal_frontier(event_id,parent_event_id) VALUES(?,?)",
        )
        .bind(bypass_id)
        .bind(parent_event_id)
        .execute(&fixture_pool)
        .await
        .unwrap();
    }
    let bypass_event = native_ce::events::EventRow {
        local_seq: inserted.last_insert_rowid(),
        id: bypass_id.into(),
        record_id: ARTIFACT_A.into(),
        event_type: "record.updated".into(),
        payload: Some(bypass_payload.to_string()),
        actor: Some("test".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-01-01T00:00:00.000Z".into(),
        causal_envelope: bypass_envelope,
    };
    let mut conn = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    native_ce::projector::project(&mut conn, &bypass_event)
        .await
        .unwrap();
    drop(conn);
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "artifact_source_unattested",
        "{denied:#}"
    );
    let grant_error = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A,
                "subject_kind": "artifact_source", "subject_record_id": ARTIFACT_A,
                "subject_event_id": bypass_id,
                "source_sha256": hex::encode(Sha256::digest(bypass_source.as_bytes())),
                "capability": "navigation.record.user_gesture", "scope": {}
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(grant_error.contains("attestation"), "{grant_error}");
    let rebuilt = native_ce::conformance::run_conformance(&db).await;
    assert!(
        rebuilt.ok,
        "unattested bypass remains replayable but unusable: {rebuilt:?}"
    );
}

#[tokio::test]
async fn transitive_input_grants_attest_the_full_forwarding_path_to_the_root() {
    const LEAF_ID: &str = "22222222-2222-4222-8222-222222222222";
    let (db, registry, _guard) = fixture().await;
    let leaf_source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1",
  inputs: { rows: { envelope: "native.collection-envelope.v1", required: true } },
  exports: { LeafCount: { kind: "component", props: {}, uses_inputs: ["rows"] } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "rows" } }]
}
export function LeafCount(_props, native) { return <Metric label="rows" value={native.inputs.rows.records.length} /> }
"#;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": LEAF_ID, "type": "Program", "kind": "module", "name": "Leaf input",
            "body": leaf_source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Create a transitive input leaf"
        }),
    )
    .await;
    let leaf = publish_module(&registry, &db, LEAF_ID).await;
    let leaf_event = leaf["publication_event_id"].as_str().unwrap();
    let leaf_digest = leaf["source_sha256"].as_str().unwrap();
    let parent_source = format!(
        r#"import {{ LeafCount }} from "native:module/{LEAF_ID}@event-{leaf_event}?sha256={leaf_digest}"
export const nativeModule = {{
  schema: "native.mdx.module.v1",
  inputs: {{ forwarded: {{ envelope: "native.collection-envelope.v1", required: true }} }},
  exports: {{ ParentCount: {{ kind: "component", props: {{}}, uses_inputs: ["forwarded"] }} }},
  module_inputs: {{ LeafCount: {{ publication_event_id: "{leaf_event}", export: "LeafCount", ports: {{ rows: "forwarded" }} }} }},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "forwarded" }} }}]
}}
export function ParentCount() {{ return <LeafCount /> }}
"#
    );
    create_module(&registry, &db, &parent_source).await;
    let parent = publish(&registry, &db).await;
    let parent_event = parent["publication_event_id"].as_str().unwrap();
    let parent_digest = parent["source_sha256"].as_str().unwrap();
    let artifact = format!(
        r#"import {{ ParentCount }} from "native:module/{MODULE_ID}@event-{parent_event}?sha256={parent_digest}"
export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ root_rows: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: false }} }},
  module_inputs: {{ ParentCount: {{ publication_event_id: "{parent_event}", export: "ParentCount", ports: {{ forwarded: "root_rows" }} }} }},
  capability_requests: []
}}

<ParentCount />
"#
    );
    create_artifact(&registry, &db, ARTIFACT_A, &artifact).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ROWS, "type": "Collection", "kind": "selection", "name": "Rows", "reason": "Transitive input fixture" }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ROW_ONE, "type": "WorkItem", "kind": "task", "name": "One", "reason": "Transitive input member" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": ROW_ONE, "target_id": ROWS, "relationship": "member_of" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "root_rows", "collection_id": ROWS }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A,
            "subject_kind": "module_release", "subject_record_id": MODULE_ID,
            "subject_event_id": parent_event, "source_sha256": parent_digest,
            "capability": "input.read",
            "scope": { "module_port": "forwarded", "artifact_port": "root_rows" }
        }),
    )
    .await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_capability_denied",
        "{denied:#}"
    );

    for scope in [
        json!({ "module_port": "rows", "artifact_port": "wrong_root" }),
        json!({ "module_port": "wrong_leaf", "artifact_port": "root_rows" }),
    ] {
        let error = registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_artifact_module_grants",
                json!({
                    "action": "grant", "artifact_id": ARTIFACT_A,
                    "subject_kind": "module_release", "subject_record_id": LEAF_ID,
                    "subject_event_id": leaf_event, "source_sha256": leaf_digest,
                    "capability": "input.read", "scope": scope
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("request") || error.contains("path"),
            "{error}"
        );
    }
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A,
            "subject_kind": "module_release", "subject_record_id": LEAF_ID,
            "subject_event_id": leaf_event, "source_sha256": leaf_digest,
            "capability": "input.read",
            "scope": { "module_port": "rows", "artifact_port": "root_rows" }
        }),
    )
    .await;
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert!(rendered["plan"]["tree"].to_string().contains("\"value\":1"));

    let row = sqlx::query(
        "SELECT id,seq,payload,created_at FROM content_events
          WHERE record_id=? AND type='artifact.module_grant_set' ORDER BY seq DESC LIMIT 1",
    )
    .bind(ARTIFACT_A)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let original_payload: Value = serde_json::from_str(&row.get::<String, _>("payload")).unwrap();
    let mut malicious_payload = original_payload.clone();
    malicious_payload["attestation"]["mapping_path"][1]["resolved_port_map"]["rows"] =
        json!("wrong_root");
    malicious_payload["attestation_sha256"] =
        json!(canonical_sha256(&malicious_payload["attestation"]));
    let malicious = native_ce::events::EventRow {
        local_seq: row.get::<i64, _>("seq") + 1,
        id: "99999999-9999-4999-8999-999999999999".into(),
        record_id: ARTIFACT_A.into(),
        event_type: "artifact.module_grant_set".into(),
        payload: Some(malicious_payload.to_string()),
        actor: None,
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
    let error = native_ce::projector::project(&mut conn, &malicious)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("attestation") || error.contains("request") || error.contains("path"),
        "{error}"
    );
    drop(conn);

    for (id, payload) in [
        (
            "88888888-8888-4888-8888-888888888888",
            original_payload.clone(),
        ),
        (
            "77777777-7777-4777-8777-777777777777",
            original_payload.clone(),
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (id, mut payload))| {
        if index == 0 {
            payload["attestation"]["mapping_path"][0]["import"]["input_map"]["ParentCount"]
                ["ports"]["forwarded"] = json!("invented_root");
        } else {
            let ports = payload["attestation"]["artifact_ports"]
                .as_array_mut()
                .unwrap();
            ports.push(json!("invented"));
            ports.sort_by_key(|port| port.as_str().unwrap().to_owned());
        }
        payload["attestation_sha256"] = json!(canonical_sha256(&payload["attestation"]));
        (id, payload)
    }) {
        let event = native_ce::events::EventRow {
            local_seq: row.get::<i64, _>("seq") + 1,
            id: id.into(),
            record_id: ARTIFACT_A.into(),
            event_type: "artifact.module_grant_set".into(),
            payload: Some(payload.to_string()),
            actor: None,
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
        assert!(
            error.contains("source")
                || error.contains("attestation")
                || error.contains("path")
                || error.contains("request"),
            "{error}"
        );
    }

    let missing_path_artifact = format!(
        r#"import {{ ParentCount }} from "native:module/{MODULE_ID}@event-{parent_event}?sha256={parent_digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: [] }}

<ParentCount />
"#
    );
    create_artifact(&registry, &db, ARTIFACT_B, &missing_path_artifact).await;
    let missing_path = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_B,
                "subject_kind": "module_release", "subject_record_id": LEAF_ID,
                "subject_event_id": leaf_event, "source_sha256": leaf_digest,
                "capability": "input.read",
                "scope": { "module_port": "rows", "artifact_port": "root_rows" }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        missing_path.contains("mapping") || missing_path.contains("path"),
        "{missing_path}"
    );

    let rebuilt = native_ce::conformance::run_conformance(&db).await;
    assert!(
        rebuilt.ok,
        "transitive grant attestation must rebuild exactly: {rebuilt:?}"
    );
}

#[tokio::test]
async fn parent_mapping_cannot_invent_a_hidden_child_input_capability() {
    let (db, registry, _guard) = fixture().await;
    let source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1",
  inputs: { secret: { envelope: "native.collection-envelope.v1", required: true } },
  exports: { Leak: { kind: "component", props: {}, uses_inputs: ["secret"] } },
  module_inputs: {}, capability_requests: []
}
export function Leak(_props, native) { return <Metric label="leak" value={native.inputs.secret.records.length} /> }
"#;
    create_module(&registry, &db, source).await;
    let release = publish(&registry, &db).await;
    let event = release["publication_event_id"].as_str().unwrap();
    let digest = release["source_sha256"].as_str().unwrap();
    let artifact = format!(
        r#"import {{ Leak }} from "native:module/{MODULE_ID}@event-{event}?sha256={digest}"
export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ secret: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: false }} }},
  module_inputs: {{ Leak: {{ publication_event_id: "{event}", export: "Leak", ports: {{ secret: "secret" }} }} }},
  capability_requests: []
}}

<Leak />
"#
    );
    create_artifact(&registry, &db, ARTIFACT_A, &artifact).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": SECRET, "type": "Collection", "kind": "selection", "name": "Secret", "reason": "Exploit fixture" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT_A, "port_name": "secret", "collection_id": SECRET }),
    )
    .await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_capability_denied",
        "{denied:#}"
    );
    let grant_error = registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "module_release",
                "subject_record_id": MODULE_ID, "subject_event_id": event,
                "source_sha256": digest, "capability": "input.read",
                "scope": { "module_port": "secret", "artifact_port": "secret" }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        grant_error.contains("exact subject request"),
        "{grant_error}"
    );
    let undeclared = artifact.replace(
        "ports: { secret: \"secret\" }",
        "ports: { secret: \"secret\", other: \"secret\" }",
    );
    let undeclared_error = registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
            "id": ARTIFACT_A, "body": undeclared,
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "Attempt an undeclared child mapping"
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        undeclared_error.contains("undeclared child input port")
            || undeclared_error.contains("mapping"),
        "{undeclared_error}"
    );
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_capability_denied",
        "{denied:#}"
    );
}

#[tokio::test]
async fn navigation_requires_exact_release_request_and_grant() {
    let (db, registry, _guard) = fixture().await;
    let missing_request = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { Link: { kind: "component", props: {}, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}

export function Link() { return <a href="https://example.com/path">leave</a> }
"#;
    let error = registry
        .call(db.clone(), Caller::local(), "create_record", json!({
            "id": MODULE_ID, "type": "Program", "kind": "module", "name": "Link",
            "body": missing_request, "facets": { "runtime": "native.mdx.v2" }, "reason": "Navigation regression"
        }))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("module_capability_denied"), "{error}");
    let source = missing_request.replace(
        "capability_requests: []",
        "capability_requests: [{ capability: \"navigation.external.user_gesture\", scope: {} }]",
    );
    create_module(&registry, &db, &source).await;
    let release = publish(&registry, &db).await;
    let event = release["publication_event_id"].as_str().unwrap();
    let digest = release["source_sha256"].as_str().unwrap();
    let artifact = format!(
        r#"import {{ Link }} from "native:module/{MODULE_ID}@event-{event}?sha256={digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{ Link: {{ publication_event_id: "{event}", export: "Link", ports: {{}} }} }}, capability_requests: [] }}

<Link />
"#
    );
    create_artifact(&registry, &db, ARTIFACT_A, &artifact).await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_capability_denied",
        "{denied:#}"
    );
    call(
        &registry,
        &db,
        "manage_artifact_module_grants",
        json!({
            "action": "grant", "artifact_id": ARTIFACT_A, "subject_kind": "module_release",
            "subject_record_id": MODULE_ID, "subject_event_id": event, "source_sha256": digest,
            "capability": "navigation.external.user_gesture", "scope": {}
        }),
    )
    .await;
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");
    assert_eq!(
        rendered["plan"]["tree"]["props"]["href"],
        "https://example.com/path"
    );
}

#[tokio::test]
async fn typed_module_boundaries_reject_authority_callbacks_async_and_mutation() {
    let (db, registry, _guard) = fixture().await;
    let source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: {
    Card: { kind: "component", props: { label: { type: "string", required: true } }, uses_inputs: [] },
    echo: { kind: "function", args: [{ type: "string" }], result: { type: "string" }, uses_inputs: [] },
    leak: { kind: "function", args: [], result: { type: "object", properties: { x: { type: "string", required: true } } }, uses_inputs: [] },
    settings: { kind: "constant", result: { type: "object", properties: { currency: { type: "string", required: true } } }, uses_inputs: [] }
  },
  module_inputs: {}, capability_requests: []
}
export function Card({ label }) { return <Callout tone="info" title={label}>{label}</Callout> }
export function echo(value, _native) { return value }
export function leak(native) { return native }
export const settings = { currency: "GBP" }
"#;
    create_module(&registry, &db, source).await;
    let release = publish(&registry, &db).await;
    let event = release["publication_event_id"].as_str().unwrap();
    let digest = release["source_sha256"].as_str().unwrap();
    let prefix = format!(
        r#"import {{ Card, echo, leak, settings }} from "native:module/{MODULE_ID}@event-{event}?sha256={digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: [] }}

"#
    );
    create_artifact(
        &registry,
        &db,
        ARTIFACT_A,
        &format!("{prefix}<Card label={{echo(settings.currency)}} />"),
    )
    .await;
    let rendered = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(rendered["status"], "rendered", "{rendered:#}");

    for (body, expected) in [
        (
            format!("{prefix}<Callout>{{leak().x}}</Callout>"),
            "mdx_capability_denied",
        ),
        (
            format!("{prefix}<Callout>{{echo(() => \"bad\")}}</Callout>"),
            "module_interface_incompatible",
        ),
        (
            format!("{prefix}<Card label={{42}} />"),
            "module_interface_incompatible",
        ),
        (
            format!("{prefix}<Callout>{{settings.currency = \"USD\"}}</Callout>"),
            "mdx_runtime_failed",
        ),
    ] {
        call(
            &registry,
            &db,
            "update_record",
            json!({
                "id": ARTIFACT_A, "body": body,
                "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
                "reason": "Exercise a typed module ABI rejection"
            }),
        )
        .await;
        let denied = call(
            &registry,
            &db,
            "render_artifact",
            json!({ "id": ARTIFACT_A }),
        )
        .await;
        assert_eq!(denied["diagnostic"]["code"], expected, "{denied:#}");
        if expected == "module_interface_incompatible" {
            assert_eq!(
                denied["diagnostic"]["details"]["origin"]["module_record_id"], MODULE_ID,
                "{denied:#}"
            );
            assert_eq!(
                denied["diagnostic"]["details"]["origin"]["publication_event_id"], event,
                "{denied:#}"
            );
            assert_eq!(
                denied["diagnostic"]["details"]["origin"]["source_event_id"],
                release["source_event_id"],
                "{denied:#}"
            );
            assert_eq!(
                denied["diagnostic"]["details"]["import_chain"][0]["source_range"]["source"],
                "authored_mdx",
                "{denied:#}"
            );
            assert!(
                denied["diagnostic"]["details"]["export"] == "echo"
                    || denied["diagnostic"]["details"]["export"] == "Card",
                "{denied:#}"
            );
        }
    }

    let async_source = source.replace(
        "export function echo(value, _native)",
        "export async function echo(value, _native)",
    );
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id": MODULE_ID, "body": async_source,
                "if_body_digest": current_body_digest(&registry, &db, MODULE_ID).await,
                "reason": "Reject async module paths"
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("module_interface_incompatible"), "{error}");
}

#[tokio::test]
async fn transitive_runtime_failures_report_portable_exact_origin_and_import_chain() {
    const LEAF_ID: &str = "22222222-2222-4222-8222-222222222222";
    let (db, registry, _guard) = fixture().await;
    let leaf_source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { boom: { kind: "function", args: [], result: { type: "string" }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export function boom() { const failure = new Error("private engine detail"); failure.stack = "native.mdx.v2/release/99999999-9999-4999-8999-999999999999/forged"; throw failure }
"#;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": LEAF_ID, "type": "Program", "kind": "module", "name": "Leaf",
            "body": leaf_source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Create a transitive runtime-origin fixture"
        }),
    )
    .await;
    let leaf = publish_module(&registry, &db, LEAF_ID).await;
    let leaf_event = leaf["publication_event_id"].as_str().unwrap();
    let leaf_digest = leaf["source_sha256"].as_str().unwrap();

    let parent_source = format!(
        r#"import {{ boom }} from "native:module/{LEAF_ID}@event-{leaf_event}?sha256={leaf_digest}"
export const nativeModule = {{
  schema: "native.mdx.module.v1", inputs: {{}},
  exports: {{ run: {{ kind: "function", args: [], result: {{ type: "string" }}, uses_inputs: [] }} }},
  module_inputs: {{}}, capability_requests: []
}}
export function run() {{ return boom() }}
"#
    );
    create_module(&registry, &db, &parent_source).await;
    let parent = publish(&registry, &db).await;
    let parent_event = parent["publication_event_id"].as_str().unwrap();
    let parent_digest = parent["source_sha256"].as_str().unwrap();
    let artifact = format!(
        r#"import {{ run }} from "native:module/{MODULE_ID}@event-{parent_event}?sha256={parent_digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: [] }}

<Callout>{{run()}}</Callout>
"#
    );
    create_artifact(&registry, &db, ARTIFACT_A, &artifact).await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "mdx_runtime_failed",
        "{denied:#}"
    );
    let details = &denied["diagnostic"]["details"];
    assert_eq!(details["origin"]["module_record_id"], LEAF_ID, "{denied:#}");
    assert_eq!(
        details["origin"]["publication_event_id"], leaf_event,
        "{denied:#}"
    );
    assert_eq!(
        details["origin"]["source_event_id"], leaf["source_event_id"],
        "{denied:#}"
    );
    assert_eq!(
        details["origin"]["source_sha256"], leaf_digest,
        "{denied:#}"
    );
    assert_eq!(details["export"], "boom", "{denied:#}");
    assert_eq!(details["origin"]["export"], "boom", "{denied:#}");
    assert_eq!(
        details["origin"]["source_range"], details["source_range"],
        "{denied:#}"
    );
    assert_eq!(
        details["source_range"]["source"], "authored_mdx",
        "{denied:#}"
    );
    assert_eq!(details["source_range"]["start"]["line"], 6, "{denied:#}");
    assert_eq!(
        details["import_chain"].as_array().unwrap().len(),
        2,
        "{denied:#}"
    );
    assert_eq!(
        details["import_chain"][0]["importer"], "$root",
        "{denied:#}"
    );
    assert_eq!(
        details["import_chain"][1]["publication_event_id"], leaf_event,
        "{denied:#}"
    );
    assert!(details["import_chain"]
        .as_array()
        .unwrap()
        .iter()
        .all(|edge| edge["source_range"]["source"] == "authored_mdx"));
    let public = denied.to_string();
    assert!(!public.contains("native.mdx.v2/release/"), "{public}");
    assert!(!public.contains("private engine detail"), "{public}");
    assert!(!public.to_ascii_lowercase().contains("stack"), "{public}");

    let recovering_parent_source = format!(
        r#"import {{ boom }} from "native:module/{LEAF_ID}@event-{leaf_event}?sha256={leaf_digest}"
export const nativeModule = {{
  schema: "native.mdx.module.v1", inputs: {{}},
  exports: {{ run: {{ kind: "function", args: [], result: {{ type: "string" }}, uses_inputs: [] }} }},
  module_inputs: {{}}, capability_requests: []
}}
export function run() {{ try {{ boom() }} catch (_) {{}} throw new Error("parent failure") }}
"#
    );
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": MODULE_ID, "body": recovering_parent_source,
            "if_body_digest": current_body_digest(&registry, &db, MODULE_ID).await,
            "reason": "Exercise independent failure attribution after a caught leaf error"
        }),
    )
    .await;
    let recovering_parent = publish(&registry, &db).await;
    let recovering_event = recovering_parent["publication_event_id"].as_str().unwrap();
    let recovering_digest = recovering_parent["source_sha256"].as_str().unwrap();
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": ARTIFACT_A,
            "body": format!(
                r#"import {{ run }} from "native:module/{MODULE_ID}@event-{recovering_event}?sha256={recovering_digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: [] }}

<Callout>{{run()}}</Callout>
"#
            ),
            "if_body_digest": current_body_digest(&registry, &db, ARTIFACT_A).await,
            "reason": "Pin the recovering parent release"
        }),
    )
    .await;
    let parent_failure = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        parent_failure["diagnostic"]["details"]["origin"]["module_record_id"], MODULE_ID,
        "{parent_failure:#}"
    );
    assert_eq!(
        parent_failure["diagnostic"]["details"]["origin"]["publication_event_id"], recovering_event,
        "{parent_failure:#}"
    );
    assert_eq!(
        parent_failure["diagnostic"]["details"]["origin"]["export"], "run",
        "{parent_failure:#}"
    );
    assert_eq!(
        parent_failure["diagnostic"]["details"]["import_chain"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{parent_failure:#}"
    );
}

#[tokio::test]
async fn transitive_instruction_limit_keeps_the_deepest_engine_owned_origin() {
    const LEAF_ID: &str = "22222222-2222-4222-8222-222222222222";
    let (db, registry, _guard) = fixture().await;
    let leaf_source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { spin: { kind: "function", args: [], result: { type: "string" }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export function spin() { while (true) {} }
"#;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": LEAF_ID, "type": "Program", "kind": "module", "name": "Loop leaf",
            "body": leaf_source, "facets": { "runtime": "native.mdx.v2" },
            "reason": "Create a transitive engine-limit fixture"
        }),
    )
    .await;
    let leaf = publish_module(&registry, &db, LEAF_ID).await;
    let leaf_event = leaf["publication_event_id"].as_str().unwrap();
    let leaf_digest = leaf["source_sha256"].as_str().unwrap();
    let parent_source = format!(
        r#"import {{ spin }} from "native:module/{LEAF_ID}@event-{leaf_event}?sha256={leaf_digest}"
export const nativeModule = {{
  schema: "native.mdx.module.v1", inputs: {{}},
  exports: {{ run: {{ kind: "function", args: [], result: {{ type: "string" }}, uses_inputs: [] }} }},
  module_inputs: {{}}, capability_requests: []
}}
export function run() {{ return spin() }}
"#
    );
    create_module(&registry, &db, &parent_source).await;
    let parent = publish(&registry, &db).await;
    let parent_event = parent["publication_event_id"].as_str().unwrap();
    let parent_digest = parent["source_sha256"].as_str().unwrap();
    create_artifact(
        &registry,
        &db,
        ARTIFACT_A,
        &format!(
            r#"import {{ run }} from "native:module/{MODULE_ID}@event-{parent_event}?sha256={parent_digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: [] }}

<Callout>{{run()}}</Callout>
"#
        ),
    )
    .await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "mdx_resource_limit_exceeded",
        "{denied:#}"
    );
    let details = &denied["diagnostic"]["details"];
    assert_eq!(details["phase"], "execute", "{denied:#}");
    assert_eq!(details["origin"]["module_record_id"], LEAF_ID, "{denied:#}");
    assert_eq!(
        details["origin"]["publication_event_id"], leaf_event,
        "{denied:#}"
    );
    assert_eq!(details["origin"]["export"], "spin", "{denied:#}");
    assert_eq!(
        details["origin"]["source_range"]["source"], "authored_mdx",
        "{denied:#}"
    );
    assert_eq!(
        details["import_chain"].as_array().unwrap().len(),
        2,
        "{denied:#}"
    );
    assert_eq!(
        details["import_chain"][0]["importer"], "$root",
        "{denied:#}"
    );
    assert_eq!(
        details["import_chain"][1]["publication_event_id"], leaf_event,
        "{denied:#}"
    );
}

#[tokio::test]
async fn top_level_constant_failure_uses_exact_module_export_origin() {
    let (db, registry, _guard) = fixture().await;
    let source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { value: { kind: "constant", result: { type: "string" }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export const value = 42
"#;
    create_module(&registry, &db, source).await;
    let release = publish(&registry, &db).await;
    let event = release["publication_event_id"].as_str().unwrap();
    let digest = release["source_sha256"].as_str().unwrap();
    create_artifact(
        &registry,
        &db,
        ARTIFACT_A,
        &format!(
            r#"import {{ value }} from "native:module/{MODULE_ID}@event-{event}?sha256={digest}"
export const nativeArtifact = {{ schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: [] }}

<Callout>{{value}}</Callout>
"#
        ),
    )
    .await;
    let denied = call(
        &registry,
        &db,
        "render_artifact",
        json!({ "id": ARTIFACT_A }),
    )
    .await;
    assert_eq!(
        denied["diagnostic"]["code"], "module_interface_incompatible",
        "{denied:#}"
    );
    let details = &denied["diagnostic"]["details"];
    assert_eq!(
        details["origin"]["module_record_id"], MODULE_ID,
        "{denied:#}"
    );
    assert_eq!(
        details["origin"]["publication_event_id"], event,
        "{denied:#}"
    );
    assert_eq!(
        details["origin"]["source_event_id"], release["source_event_id"],
        "{denied:#}"
    );
    assert_eq!(details["origin"]["export"], "value", "{denied:#}");
    assert_eq!(
        details["origin"]["source_range"]["source"], "authored_mdx",
        "{denied:#}"
    );
    assert_eq!(
        details["origin"]["source_range"]["start"]["line"], 6,
        "{denied:#}"
    );
    assert_eq!(
        details["import_chain"].as_array().unwrap().len(),
        1,
        "{denied:#}"
    );
}
