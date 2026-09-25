//! End-to-end coverage for the general surface-binding resolver
//! (`manage_surface_bindings`) and the Home binding row it was built for.
//!
//! The resolver's own precedence and skip logic is unit-tested in
//! `native_ce::surface_binding`; these tests exercise the same path through the
//! production MCP registry, storage, and authorization, which is what the
//! acceptance criteria are stated against.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const ARTIFACT_A: &str = "b0d00000-0000-4000-8000-000000000001";
const ARTIFACT_B: &str = "b0d00000-0000-4000-8000-000000000002";
const ARTIFACT_C: &str = "b0d00000-0000-4000-8000-000000000003";
const ARTIFACT_MDX: &str = "b0d00000-0000-4000-8000-000000000006";
const NOTE: &str = "b0d00000-0000-4000-8000-000000000004";
const PERSON: &str = "b0d00000-0000-4000-8000-000000000005";
const BEA: &str = "bea";

const ENVIRONMENT_NOTE: &str = r#"{"v":"native.surface-binding.v1","surface":"home","subject":{"kind":"environment"},"mode":"isolated"}"#;

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry)
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

async fn grant(db: &Db, id: &str, account: &str, capability: Capability) {
    replace_explicit_policy(
        db,
        "test:policy",
        id,
        vec![AllowEntry::account(account, capability)],
    )
    .await
    .unwrap();
}

async fn revoke_all(db: &Db, id: &str) {
    replace_explicit_policy(db, "test:policy", id, vec![])
        .await
        .unwrap();
}

async fn artifact(registry: &ToolRegistry, db: &Db, id: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({
            "id": id,
            "type": "Document",
            "kind": "artifact",
            "name": id,
            "body": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fixture</title></head><body><main><h1>Fixture</h1></main></body></html>",
            "facets": { "runtime": "native.html.v1" },
            "reason": "Fixture artifact for the surface-binding resolver."
        }),
    )
    .await;
}

/// A member record bound to an account, so the caller has a personal scope.
async fn person_bound_to(registry: &ToolRegistry, db: &Db, id: &str, account: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({ "id": id, "type": "Entity", "kind": "person", "name": id, "reason": "Surface-binding fixture member." }),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical) \
         VALUES (?, 'account', ?, 1)",
    )
    .bind(id)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn binding_link_count(db: &Db, source: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id = ? AND relationship = 'surface_binding'",
    )
    .bind(source)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

#[tokio::test]
async fn surface_binding_personal_override_wins_and_reset_restores_workspace_default() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    artifact(&registry, &db, ARTIFACT_B).await;
    person_bound_to(&registry, &db, PERSON, BEA).await;
    grant(&db, PERSON, BEA, Capability::Edit).await;
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    grant(&db, ARTIFACT_B, BEA, Capability::View).await;

    // The workspace default, written through the same resolution path.
    let workspace_set = call(
        &registry,
        &db,
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "workspace",
            "target_id": ARTIFACT_A, "expected_target_id": null
        }),
    )
    .await;
    assert_eq!(workspace_set["status"], "bound", "{workspace_set:#}");
    assert_eq!(workspace_set["resolution"]["source"], "workspace");
    assert_eq!(workspace_set["resolution"]["target_id"], ARTIFACT_A);
    assert_eq!(workspace_set["resolution"]["fallback"], false);

    // A personal override is more specific for this member.
    let personal_set = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_B, "expected_target_id": null
        }),
    )
    .await
    .unwrap();
    assert_eq!(personal_set["status"], "bound", "{personal_set:#}");
    assert_eq!(personal_set["resolution"]["source"], "personal");
    assert_eq!(personal_set["resolution"]["target_id"], ARTIFACT_B);

    let list = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_surface_bindings",
        json!({ "action": "list", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(
        list["bindings"].as_array().map(Vec::len),
        Some(2),
        "{list:#}"
    );

    let effective = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(effective["source"], "personal", "{effective:#}");
    assert_eq!(effective["target_id"], ARTIFACT_B);

    let reset_personal = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_surface_bindings",
        json!({
            "action": "reset", "surface": "home", "scope": "personal",
            "expected_target_id": ARTIFACT_B
        }),
    )
    .await
    .unwrap();
    assert_eq!(reset_personal["status"], "reset", "{reset_personal:#}");
    assert_eq!(reset_personal["resolution"]["source"], "workspace");
    assert_eq!(reset_personal["resolution"]["target_id"], ARTIFACT_A);

    // Resetting the workspace default leaves the app-owned fallback, never
    // nothing.
    let reset_workspace = call(
        &registry,
        &db,
        "manage_surface_bindings",
        json!({
            "action": "reset", "surface": "home", "scope": "workspace",
            "expected_target_id": ARTIFACT_A
        }),
    )
    .await;
    assert_eq!(reset_workspace["status"], "reset", "{reset_workspace:#}");
    assert_eq!(reset_workspace["resolution"]["source"], "app_fallback");
    assert_eq!(reset_workspace["resolution"]["target_id"], Value::Null);
    assert_eq!(reset_workspace["resolution"]["fallback"], true);

    let blank_check = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(blank_check["fallback"], true, "{blank_check:#}");
    assert_eq!(blank_check["target_id"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn surface_binding_refuses_below_threshold_writes_without_adding_links() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    artifact(&registry, &db, ARTIFACT_B).await;
    person_bound_to(&registry, &db, PERSON, BEA).await;
    grant(&db, PERSON, BEA, Capability::Edit).await;
    // View on A only. B is explicitly cut off so no inherited policy applies.
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    revoke_all(&db, ARTIFACT_B).await;

    let bea = Caller::authenticated(BEA);

    // A target bea may not view is refused at bind time, and writes nothing.
    let denied_target = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_B, "expected_target_id": null
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!denied_target.is_empty());
    assert_eq!(binding_link_count(&db, PERSON).await, 0);
    assert_eq!(binding_link_count(&db, "native:root").await, 0);

    // The workspace default changes what everyone sees; bea has no authority
    // there, so it is refused too.
    let denied_scope = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "workspace",
            "target_id": ARTIFACT_A, "expected_target_id": null
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!denied_scope.is_empty());
    assert_eq!(binding_link_count(&db, "native:root").await, 0);

    // A stale compare-and-set is refused rather than silently overwriting.
    let bound = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_A, "expected_target_id": null
        }),
    )
    .await
    .unwrap();
    assert_eq!(bound["status"], "bound", "{bound:#}");
    let stale = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_A, "expected_target_id": null
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(stale.contains("revision"), "{stale}");
    assert_eq!(binding_link_count(&db, PERSON).await, 1);
    db.close().await;
}

#[tokio::test]
async fn surface_binding_degrades_when_bound_target_is_lost_or_unauthorized() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    artifact(&registry, &db, ARTIFACT_C).await;
    person_bound_to(&registry, &db, PERSON, BEA).await;
    grant(&db, PERSON, BEA, Capability::Edit).await;
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    grant(&db, ARTIFACT_C, BEA, Capability::View).await;

    let bea = Caller::authenticated(BEA);

    // Bind, then lose authority on the target. This is the slice's biggest
    // risk: authorized at bind time, unauthorized at render.
    call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_A, "expected_target_id": null
        }),
    )
    .await
    .unwrap();
    revoke_all(&db, ARTIFACT_A).await;
    let unauthorized = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(unauthorized["fallback"], true, "{unauthorized:#}");
    assert_eq!(unauthorized["target_id"], Value::Null);
    let reasons: Vec<&str> = unauthorized["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|skipped| skipped["reason"].as_str())
        .collect();
    assert!(reasons.contains(&"unauthorized"), "{unauthorized:#}");

    // Bind the other artifact, then tombstone it. The binding survives the
    // soft delete and degrades honestly rather than blanking Home.
    call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_C, "expected_target_id": ARTIFACT_A
        }),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": ARTIFACT_C, "reason": "Exercise the missing-target path." }),
    )
    .await;
    let missing = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(missing["fallback"], true, "{missing:#}");
    let reasons: Vec<&str> = missing["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|skipped| skipped["reason"].as_str())
        .collect();
    assert!(reasons.contains(&"missing"), "{missing:#}");
    db.close().await;
}

#[tokio::test]
async fn surface_binding_skips_archived_and_wrong_typed_targets_with_reasons() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    person_bound_to(&registry, &db, PERSON, BEA).await;
    grant(&db, PERSON, BEA, Capability::Edit).await;
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": NOTE, "type": "Document", "kind": "note", "name": "Not an artifact", "reason": "Exercise the wrong-record-type path." }),
    )
    .await;

    let bea = Caller::authenticated(BEA);
    call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "personal",
            "target_id": ARTIFACT_A, "expected_target_id": null
        }),
    )
    .await
    .unwrap();

    // Archive the bound target. The binding must not disappear; it degrades.
    call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": ARTIFACT_A, "archived": true, "reason": "Exercise the archived path." }),
    )
    .await;
    let archived = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(archived["fallback"], true, "{archived:#}");
    let reasons: Vec<&str> = archived["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|skipped| skipped["reason"].as_str())
        .collect();
    assert!(reasons.contains(&"archived"), "{archived:#}");

    // `manage_links` refuses the reserved relationship: the official path
    // requires Manage on `native:root`, which generic link authority does not.
    let forged = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_links",
        json!({
            "action": "add", "source_id": PERSON, "target_id": NOTE,
            "relationship": "surface_binding", "note": ENVIRONMENT_NOTE
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(forged.contains("manage_surface_bindings"), "{forged}");

    // A pre-existing (or hand-written) edge to a non-artifact is still read
    // defensively: it is skipped with the wrong-record-type reason rather than
    // trusted as a binding.
    sqlx::query(
        "INSERT INTO links (id, source_id, target_id, relationship, note) \
         VALUES ('link-forged-wrong-type', ?, ?, 'surface_binding', ?)",
    )
    .bind(PERSON)
    .bind(NOTE)
    .bind(ENVIRONMENT_NOTE)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let wrong_type = call_as(
        &registry,
        &db,
        bea.clone(),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(wrong_type["fallback"], true, "{wrong_type:#}");
    let reasons: Vec<&str> = wrong_type["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|skipped| skipped["reason"].as_str())
        .collect();
    assert!(reasons.contains(&"wrong_record_type"), "{wrong_type:#}");
    db.close().await;
}

/// Criterion 1 has an artifact behind it: the resolver is runtime-agnostic, so
/// a `native.mdx.v2` Home target resolves through the same path as the HTML
/// fixtures. The resolver never inspects the runtime; this pins that.
#[tokio::test]
async fn surface_binding_resolves_a_native_mdx_v2_artifact() {
    let (db, registry) = fixture().await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ARTIFACT_MDX,
            "type": "Document",
            "kind": "artifact",
            "name": "MDX Home",
            "body": "export const nativeArtifact = { schema: \"native.mdx.artifact.v2\", inputs: {}, module_inputs: {}, capability_requests: [] };\n\n# MDX Home",
            "facets": { "runtime": "native.mdx.v2" },
            "reason": "Exercise the native.mdx.v2 Home target."
        }),
    )
    .await;

    let set = call(
        &registry,
        &db,
        "manage_surface_bindings",
        json!({
            "action": "set", "surface": "home", "scope": "workspace",
            "target_id": ARTIFACT_MDX, "expected_target_id": null
        }),
    )
    .await;
    assert_eq!(set["status"], "bound", "{set:#}");
    assert_eq!(set["resolution"]["target_id"], ARTIFACT_MDX);

    let effective = call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_surface_bindings",
        json!({ "action": "get", "surface": "home" }),
    )
    .await
    .unwrap();
    assert_eq!(effective["fallback"], false, "{effective:#}");
    assert_eq!(effective["target_id"], ARTIFACT_MDX);
    assert_eq!(effective["source"], "workspace");
    db.close().await;
}
