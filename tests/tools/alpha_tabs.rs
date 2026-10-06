//! End-to-end coverage for personal alpha tab installs
//! (`manage_alpha_tabs`, task `26ba75a`).
//!
//! These tests exercise the tool through the production MCP registry,
//! storage, and authorization: the install pin/consent rules, the CAS token
//! lifecycle, cross-account isolation, and the honest read-gate verdicts
//! (including the stored-not-enforced digest boundary).

// Registry foundation tests below observe the internal durable hub vector,
// never a public control cursor. Account-scoped SSE remains a separate slice.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

pub(crate) const ARTIFACT_A: &str = "a1d00000-0000-4000-8000-000000000001";
const ARTIFACT_B: &str = "a1d00000-0000-4000-8000-000000000002";
const NOTE: &str = "a1d00000-0000-4000-8000-000000000003";

pub(crate) const ALICE: &str = "alice";
pub(crate) const BEA: &str = "bea";

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn declaration() -> Value {
    json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]})
}

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry)
}

pub(crate) async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), caller, tool, arguments).await
}

pub(crate) async fn grant(db: &Db, id: &str, account: &str, capability: Capability) {
    replace_explicit_policy(
        db,
        "test:policy",
        id,
        vec![AllowEntry::account(account, capability)],
    )
    .await
    .unwrap();
}

pub(crate) async fn revoke_all(db: &Db, id: &str) {
    replace_explicit_policy(db, "test:policy", id, vec![])
        .await
        .unwrap();
}

async fn artifact(registry: &ToolRegistry, db: &Db, id: &str) {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": id,
                "type": "Document",
                "kind": "artifact",
                "name": id,
                "body": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fixture</title></head><body><main><h1>Fixture</h1></main></body></html>",
                "facets": { "runtime": "native.html.v1" },
                "reason": "Fixture artifact for alpha tab installs."
            }),
        )
        .await
        .unwrap();
}

async fn note(registry: &ToolRegistry, db: &Db, id: &str) {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": id, "type": "Document", "kind": "note",
                "name": id, "body": "not an artifact",
                "reason": "Fixture note for the wrong-record-type path."
            }),
        )
        .await
        .unwrap();
}

fn install_args(package: &str, artifact: &str, digest: &str) -> Value {
    json!({
        "action": "install",
        "package": package,
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": artifact,
        "source_revision": "rev-1",
        "declaration": declaration(),
        "reason": "Adopt the attention cockpit preview."
    })
}

#[tokio::test]
async fn install_inspect_list_round_trip_with_stored_pin() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    artifact(&registry, &db, ARTIFACT_B).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    grant(&db, ARTIFACT_B, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);

    let first = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    assert_eq!(first["changed"], true, "{first:#}");
    let token = first["install"]["event_id"].as_str().unwrap().to_string();
    assert_eq!(first["install"]["status"], "installed");
    // Fail closed: the install is target-ready but not executable — the
    // stored digest is unverified at launch, and adoption is caller-asserted.
    assert_eq!(first["install"]["target_resolves"], true, "{first:#}");
    assert_eq!(first["install"]["target_skip_reason"], Value::Null);
    assert_eq!(first["install"]["resolves"], false, "{first:#}");
    assert_eq!(first["install"]["skip_reason"], "digest_unverified");
    assert_eq!(first["install"]["digest_binding"], "stored-not-enforced");
    assert_eq!(first["install"]["digest"], DIGEST_A);
    assert_eq!(first["install"]["adoption"], "caller_asserted");
    // Slice-2 launch verdict: read-only, fail-closed, no ticket. A healthy
    // target-resolving install still refuses on caller-asserted adoption.
    assert_eq!(
        first["install"]["launch_binding"]["digest_version"],
        "alpha-tab-digest.v1"
    );
    assert_eq!(first["install"]["launch_binding"]["verdict"], "refused");
    assert_eq!(
        first["install"]["launch_binding"]["reason"],
        "adoption_unverified"
    );
    assert_eq!(first["install"]["launch_binding"]["receipt"], Value::Null);

    let second = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.team-pulse", ARTIFACT_B, DIGEST_B),
    )
    .await
    .unwrap();
    assert_eq!(second["changed"], true);

    // Two tabs coexist on one viewer.
    let list = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
    assert_eq!(list["installs"].as_array().unwrap().len(), 2, "{list:#}");
    assert_eq!(list["installs"][0]["package"], "agent.attention-cockpit");
    assert_eq!(list["installs"][1]["package"], "agent.team-pulse");
    assert!(
        list["installs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["target_resolves"] == true
                && entry["resolves"] == false
                && entry["skip_reason"] == "digest_unverified"),
        "{list:#}"
    );
    // Every listed entry carries the slice-2 verdict; healthy installs name
    // the adoption boundary, never a stored digest as proof.
    assert!(
        list["installs"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |entry| entry["launch_binding"]["digest_version"] == "alpha-tab-digest.v1"
                    && entry["launch_binding"]["verdict"] == "refused"
                    && entry["launch_binding"]["reason"] == "adoption_unverified"
            ),
        "{list:#}"
    );

    let inspect = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": "agent.attention-cockpit"}),
    )
    .await
    .unwrap();
    assert_eq!(inspect["installed"], true);
    assert_eq!(inspect["install"]["event_id"], token);

    let unknown = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": "agent.unknown-tab"}),
    )
    .await
    .unwrap();
    assert_eq!(unknown["installed"], false);

    // The canonical log carries the install event under the alpha_tab kind.
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT aggregate_kind FROM control_events WHERE type LIKE 'alpha_tab.%'",
    )
    .fetch_all(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(kinds, vec!["alpha_tab".to_string()]);
}

#[tokio::test]
async fn install_refuses_missing_wrong_typed_and_unauthorized_targets() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    note(&registry, &db, NOTE).await;

    // Missing target.
    let missing = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_args(
            "agent.attention-cockpit",
            "00000000-0000-4000-8000-000000000000",
            DIGEST_A,
        ),
    )
    .await;
    assert!(missing.unwrap_err().to_string().contains("missing"));

    // Wrong record type.
    let wrong = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", NOTE, DIGEST_A),
    )
    .await;
    assert!(wrong.unwrap_err().to_string().contains("wrong_record_type"));

    // No View on a live artifact: baseline grants are revoked first, so the
    // bind-time View gate (surface_bindings.rs set precedent) refuses.
    revoke_all(&db, ARTIFACT_A).await;
    let denied = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await;
    assert!(denied.is_err(), "install without View must fail");
}

#[tokio::test]
async fn cas_lifecycle_disable_restore_remove_with_stale_token_refusal() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);

    let installed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    let token = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Stale CAS token fails visibly — no silent last-writer-wins.
    let stale = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.attention-cockpit",
            "expected_install_event_id": "stale-token",
            "reason": "Pause the tab for now."
        }),
    )
    .await;
    assert!(stale
        .unwrap_err()
        .to_string()
        .contains("installation changed"));

    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.attention-cockpit",
            "expected_install_event_id": token,
            "reason": "Pause the tab for now."
        }),
    )
    .await
    .unwrap();
    assert_eq!(disabled["changed"], true);
    assert_eq!(disabled["install"]["status"], "disabled");
    assert_eq!(disabled["install"]["resolves"], false);
    assert_eq!(disabled["install"]["skip_reason"], "disabled");
    assert_eq!(disabled["install"]["launch_binding"]["verdict"], "refused");
    assert_eq!(disabled["install"]["launch_binding"]["reason"], "disabled");
    let disabled_token = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(disabled_token, token);

    // Double disable is a transition error, not a silent no-op.
    let again = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.attention-cockpit",
            "expected_install_event_id": disabled_token,
            "reason": "Pause the tab for now."
        }),
    )
    .await;
    assert!(again.is_err(), "disabling a disabled tab must fail");

    let restored = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "restore", "package": "agent.attention-cockpit",
            "expected_install_event_id": disabled_token,
            "reason": "Resume the tab after review."
        }),
    )
    .await
    .unwrap();
    assert_eq!(restored["install"]["status"], "installed");
    assert_eq!(restored["install"]["target_resolves"], true);
    assert_eq!(restored["install"]["resolves"], false);
    assert_eq!(restored["install"]["skip_reason"], "digest_unverified");
    assert_eq!(
        restored["install"]["launch_binding"]["reason"],
        "adoption_unverified"
    );
    let restored_token = restored["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();

    let removed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.attention-cockpit",
            "expected_install_event_id": restored_token,
            "reason": "Retire the tab permanently."
        }),
    )
    .await
    .unwrap();
    assert_eq!(removed["install"]["status"], "removed");
    assert_eq!(removed["install"]["skip_reason"], "removed");
    assert_eq!(removed["install"]["launch_binding"]["reason"], "removed");
    let removed_token = removed["install"]["event_id"].as_str().unwrap().to_string();

    // Removed is terminal: transitions over it fail, and the tombstone row
    // stays for replay auditability.
    let after = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "restore", "package": "agent.attention-cockpit",
            "expected_install_event_id": removed_token,
            "reason": "Resume the tab after review."
        }),
    )
    .await;
    assert!(after.is_err(), "restore after remove must fail");

    // Stale-token and double remove fail without moving state.
    let stale_remove = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.attention-cockpit",
            "expected_install_event_id": "stale-token",
            "reason": "Retire the tab permanently."
        }),
    )
    .await;
    assert!(stale_remove.is_err(), "stale-token remove must fail");
    let double_remove = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.attention-cockpit",
            "expected_install_event_id": removed_token,
            "reason": "Retire the tab permanently."
        }),
    )
    .await;
    assert!(double_remove.is_err(), "double remove must fail");

    // Re-install after remove chains explicitly over the tombstone token.
    // The default idempotency key names the CAS generation, so the chained
    // reinstall takes a fresh key and succeeds with no caller-supplied key;
    // repeating the original genesis-keyed install converges on the original
    // event (changed: false) and still reports the removed tombstone.
    let fresh = install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A);
    let unchained = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        fresh.clone(),
    )
    .await
    .unwrap();
    assert_eq!(unchained["changed"], false);
    assert_eq!(unchained["install"]["status"], "removed");
    let mut chained = fresh.clone();
    chained["expected_install_event_id"] = Value::String(removed_token.clone());
    let reinstalled = call_as(&registry, &db, alice.clone(), "manage_alpha_tabs", chained)
        .await
        .unwrap();
    assert_eq!(reinstalled["changed"], true);
    assert_eq!(reinstalled["install"]["status"], "installed");
    assert_eq!(reinstalled["install"]["target_resolves"], true);
    assert_eq!(reinstalled["install"]["resolves"], false);
    assert_ne!(
        reinstalled["install"]["event_id"].as_str().unwrap(),
        removed_token
    );
}

#[tokio::test]
async fn accounts_are_isolated_and_authority_loss_degrades_honestly() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();

    call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();

    // Bea sees none of Alice's rows and can install the same package herself.
    let bea_list = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
    assert_eq!(
        bea_list["installs"].as_array().unwrap().len(),
        0,
        "{bea_list:#}"
    );
    call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    let bea_list = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
    assert_eq!(bea_list["installs"].as_array().unwrap().len(), 1);

    // Bea cannot move Alice's install: her CAS token names her own chain,
    // and Alice's token is not hers to spend.
    let alice_token: String = sqlx::query_scalar(
        "SELECT event_id FROM alpha_tab_installs WHERE account_id = ? AND package = ?",
    )
    .bind(ALICE)
    .bind("agent.attention-cockpit")
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let cross = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.attention-cockpit",
            "expected_install_event_id": alice_token,
            "reason": "Pause the tab for now."
        }),
    )
    .await;
    assert!(cross.is_err(), "cross-account CAS must fail");

    // Authority loss degrades to honest-empty, never stale display — and
    // cleanup stays possible: remove works after View is gone.
    revoke_all(&db, ARTIFACT_A).await;
    let alice_list = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
    assert_eq!(alice_list["installs"][0]["target_resolves"], false);
    assert_eq!(
        alice_list["installs"][0]["target_skip_reason"],
        "unauthorized"
    );
    assert_eq!(alice_list["installs"][0]["resolves"], false);
    assert_eq!(alice_list["installs"][0]["skip_reason"], "unauthorized");
    // Launch precedence: the install-intrinsic adoption boundary still names
    // itself first — the verdict never implies authority is the blocker.
    assert_eq!(
        alice_list["installs"][0]["launch_binding"]["reason"],
        "adoption_unverified"
    );
    let viewless_token = alice_list["installs"][0]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let removed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.attention-cockpit",
            "expected_install_event_id": viewless_token,
            "reason": "Retire the tab permanently."
        }),
    )
    .await
    .unwrap();
    assert_eq!(removed["install"]["status"], "removed");
}

#[tokio::test]
async fn remove_survives_a_missing_target_while_restore_refuses_it() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);
    let installed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    let token = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Tombstone the artifact: the install row outlives its target.
    call_as(
        &registry,
        &db,
        Caller::local(),
        "delete_record",
        json!({"id": ARTIFACT_A, "reason": "Retire the fixture artifact."}),
    )
    .await
    .unwrap();
    let missing = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
    assert_eq!(missing["installs"][0]["target_resolves"], false);
    assert_eq!(missing["installs"][0]["target_skip_reason"], "missing");
    // Adoption precedes the missing target in the launch verdict too.
    assert_eq!(
        missing["installs"][0]["launch_binding"]["reason"],
        "adoption_unverified"
    );

    // Remove still cleans up over the missing target.
    let removed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.attention-cockpit",
            "expected_install_event_id": token,
            "reason": "Retire the tab permanently."
        }),
    )
    .await
    .unwrap();
    assert_eq!(removed["install"]["status"], "removed");
}

#[tokio::test]
async fn restore_revalidates_its_target_before_moving_state() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);
    let installed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    let token = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.attention-cockpit",
            "expected_install_event_id": token,
            "reason": "Pause the tab for now."
        }),
    )
    .await
    .unwrap();
    let disabled_token = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Tombstone the artifact while disabled: restore must refuse the
    // missing target with a named reason rather than folding.
    call_as(
        &registry,
        &db,
        Caller::local(),
        "delete_record",
        json!({"id": ARTIFACT_A, "reason": "Retire the fixture artifact."}),
    )
    .await
    .unwrap();
    let restore = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "restore", "package": "agent.attention-cockpit",
            "expected_install_event_id": disabled_token,
            "reason": "Resume the tab after review."
        }),
    )
    .await;
    assert!(
        restore.unwrap_err().to_string().contains("missing"),
        "restore over a missing target must fail"
    );
}

#[tokio::test]
async fn idempotency_key_retries_converge_and_reuse_is_visible() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);

    let mut first = install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A);
    first["idempotency_key"] = Value::String("install-once".into());
    let once = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        first.clone(),
    )
    .await
    .unwrap();
    assert_eq!(once["changed"], true);
    let retry = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        first.clone(),
    )
    .await
    .unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["idempotent_retry"], true);
    assert_eq!(retry["install"]["event_id"], once["install"]["event_id"]);

    // The same key for different intent (another package) fails visibly.
    let mut other = install_args("agent.team-pulse", ARTIFACT_A, DIGEST_A);
    other["idempotency_key"] = Value::String("install-once".into());
    let reuse = call_as(&registry, &db, alice.clone(), "manage_alpha_tabs", other).await;
    assert!(reuse
        .unwrap_err()
        .to_string()
        .contains("idempotency_key was reused"));
}

#[tokio::test]
async fn install_validates_pin_declaration_and_reason() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);

    for (label, args) in [
        (
            "package",
            install_args("not-a-package", ARTIFACT_A, DIGEST_A),
        ),
        ("version", {
            let mut v = install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A);
            v["version"] = Value::String("1.0".into());
            v
        }),
        ("digest", {
            let mut v = install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A);
            v["digest"] = Value::String("sha256:short".into());
            v
        }),
        ("reason", {
            let mut v = install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A);
            v["reason"] = Value::String("   ".into());
            v
        }),
    ] {
        let result = call_as(&registry, &db, alice.clone(), "manage_alpha_tabs", args).await;
        assert!(result.is_err(), "{label} must be refused");
    }

    let mut bad_declaration = install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A);
    bad_declaration["declaration"] = json!({"needs": ["attention.query.v1"]});
    let result = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        bad_declaration,
    )
    .await;
    assert!(
        result.is_err(),
        "declaration without effects must be refused"
    );

    // Nothing folded from the refused writes.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alpha_tab_installs")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn direct_install_stays_caller_asserted_and_launch_stays_fail_closed() {
    // Adopt-confirm slice (task 26ba75a): verified adoption (`shell_adopt.v1`)
    // is producible only through the hosted cookie+Origin adopt confirm
    // against a live server-held receipt — never through install arguments.
    // A direct install stays `caller_asserted` with `resolves: false`,
    // `digest_binding: stored-not-enforced`, and a terminal launch refusal,
    // so no caller-supplied token or field can self-assert a preview or a
    // receipt.
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);

    let installed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    let entry = &installed["install"];
    assert_eq!(entry["adoption"], "caller_asserted", "{installed:#}");
    assert_eq!(entry["resolves"], false, "{installed:#}");
    assert_eq!(
        entry["digest_binding"], "stored-not-enforced",
        "{installed:#}"
    );
    assert_eq!(
        entry["launch_binding"]["verdict"], "refused",
        "{installed:#}"
    );
    assert_eq!(
        entry["launch_binding"]["reason"], "adoption_unverified",
        "{installed:#}"
    );
    assert_eq!(
        entry["launch_binding"]["receipt"],
        Value::Null,
        "{installed:#}"
    );

    // The install schema accepts no adoption field at all: a forged
    // stronger-looking claim is a schema refusal, never a stored upgrade.
    let mut forged = install_args("agent.other-tab", ARTIFACT_A, DIGEST_A);
    forged["adoption"] = Value::String("shell_adopt.v1".into());
    let result = call_as(&registry, &db, alice.clone(), "manage_alpha_tabs", forged).await;
    assert!(
        result.is_err(),
        "forged adoption must be refused, got {result:?}"
    );
}

// --- Sample-only preview producer (task 26ba75a preview slice) ---

const PREVIEW_BODY: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fixture</title></head><body><main><h1>Fixture</h1></main></body></html>";

fn preview_declaration() -> Value {
    json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]})
}

pub(crate) fn configure_preview_launch() {
    // Sample-only launch tickets need the HTML runtime origins; the values
    // are test-local and idempotent across parallel tests in this binary.
    native_ce::artifact_html::configure(
        native_ce::artifact_html::RuntimeConfig::new(
            "http://localhost:8080",
            "http://artifact.localhost:8080",
        )
        .expect("preview test HTML runtime configuration"),
    );
}

async fn preview_source_revision(db: &Db, artifact_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(artifact_id)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

fn preview_digest(body: &str) -> String {
    use native_ce::mcp::tools::alpha_tabs::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    };
    alpha_tab_digest(
        &alpha_tab_bundle_digest(body),
        &alpha_tab_declaration_digest(&preview_declaration()).unwrap(),
        "native.html.v1",
    )
}

fn preview_args(artifact: &str, source_revision: &str, digest: &str) -> Value {
    json!({
        "action": "preview",
        "package": "agent.attention-cockpit",
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": artifact,
        "source_revision": source_revision,
        "declaration": preview_declaration(),
        "reason": "Preview the attention cockpit against sample input."
    })
}

/// Caller carrying the hosted preview attestation for exactly these
/// arguments — the same construction `held/hosting/src/http.rs` performs
/// after cookie-session plus trusted-Origin checks. Tests that exercise the
/// happy path and the pin gates use this; tests for the authority boundary
/// itself use plain (MCP-equivalent) callers.
fn attested_preview_caller(account: &str, args: &Value) -> Caller {
    use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
    let str_field = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
    let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
    Caller::authenticated(account).with_verified_alpha_tab_preview(
        alpha_tab_preview_authority_for(
            account,
            str_field("package"),
            str_field("version"),
            str_field("digest"),
            str_field("artifact_id"),
            str_field("source_revision"),
            &declaration,
        )
        .expect("fixture declaration is well-formed"),
    )
}

/// MCP-router-equivalent caller: same registry, `Channel::Mcp`, and no
/// hosted attestation — exactly what an agent's preview call carries.
fn mcp_preview_caller(account: &str) -> Caller {
    Caller::authenticated(account).with_channel(native_ce::provenance::Channel::Mcp)
}

fn install_exact_args(artifact: &str, source_revision: &str, digest: &str) -> Value {
    json!({
        "action": "install",
        "package": "agent.attention-cockpit",
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": artifact,
        "source_revision": source_revision,
        "declaration": preview_declaration(),
        "reason": "Install the previewed attention cockpit."
    })
}

fn adopt_args(
    artifact: &str,
    source_revision: &str,
    digest: &str,
    receipt_id: &str,
    nonce: &str,
    preview_session: &str,
    expected_event: &str,
) -> Value {
    json!({
        "action": "adopt",
        "package": "agent.attention-cockpit",
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": artifact,
        "source_revision": source_revision,
        "declaration": preview_declaration(),
        "receipt_id": receipt_id,
        "nonce": nonce,
        "preview_session": preview_session,
        "expected_install_event_id": expected_event,
        "reason": "Adopt the previewed attention cockpit."
    })
}

/// Caller carrying the hosted adopt attestation for exactly these
/// arguments — the same construction `held/hosting/src/http.rs` performs
/// for the `adopt` action after cookie-session plus trusted-Origin checks.
/// Tests for the authority boundary itself use plain (MCP-equivalent)
/// callers, which must refuse before any verification work.
fn attested_adopt_caller(account: &str, args: &Value) -> Caller {
    attested_adopt_caller_for(account, account, args)
}

/// Adopt caller whose credential and attestation accounts can differ, for
/// the cross-account borrowing case: presenting another account's
/// attestation must refuse at the authority check even when the pin
/// matches field-for-field.
fn attested_adopt_caller_for(caller: &str, attested: &str, args: &Value) -> Caller {
    use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
    let str_field = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
    let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
    Caller::authenticated(caller).with_verified_alpha_tab_adopt(
        alpha_tab_preview_authority_for(
            attested,
            str_field("package"),
            str_field("version"),
            str_field("digest"),
            str_field("artifact_id"),
            str_field("source_revision"),
            &declaration,
        )
        .expect("fixture declaration is well-formed"),
    )
}

pub(crate) async fn adopt_fixture_artifact(registry: &ToolRegistry, db: &Db) {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT_A, "type": "Document", "kind": "artifact",
                "name": ARTIFACT_A, "body": PREVIEW_BODY,
                "facets": { "runtime": "native.html.v1" },
                "reason": "Fixture artifact for adopt-confirm tests."
            }),
        )
        .await
        .unwrap();
    replace_explicit_policy(
        db,
        "test:policy",
        ARTIFACT_A,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
}

/// Install the exact previewed pin, preview it attested, and return the
/// install event plus the live receipt triple.
async fn installed_and_previewed(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
) -> (String, String, String, String) {
    let source_revision = preview_source_revision(db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_alpha_tabs",
            install_exact_args(ARTIFACT_A, &source_revision, &digest),
        )
        .await
        .unwrap();
    assert_eq!(installed["install"]["adoption"], "caller_asserted");
    let event_id = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let preview_args = preview_args(ARTIFACT_A, &source_revision, &digest);
    let preview = registry
        .call(
            db.clone(),
            attested_preview_caller(account, &preview_args),
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
    let preview_session = preview["receipt"]["preview_session"]
        .as_str()
        .unwrap()
        .to_string();
    (event_id, receipt_id, nonce, preview_session)
}

async fn inspect_adopt_entry(registry: &ToolRegistry, db: &Db, account: &str) -> Value {
    registry
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_alpha_tabs",
            json!({"action": "inspect", "package": "agent.attention-cockpit"}),
        )
        .await
        .unwrap()["install"]
        .clone()
}

fn named_input_preview_body() -> String {
    let declaration = serde_json::to_string(&json!({
        "schema": "native.html.artifact.v1",
        "inputs": {
            "items": {
                "envelope": "native.collection-envelope.v1",
                "required": true,
                "expose_to_root": true
            }
        },
        "capability_requests": [
            { "capability": "input.read", "scope": { "port": "items" } }
        ]
    }))
    .expect("preview named-input declaration serializes");
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Named preview</title><script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script><style>body{{margin:0}}</style></head><body><main><h1>Named preview</h1></main></body></html>"
    )
}

#[tokio::test]
async fn preview_renders_pinned_bytes_against_sample_input_only() {
    // No live governed reads: a named-input artifact with a required port
    // and zero bindings previews fine on sample input alone, and live
    // record content never reaches the frame payload.
    configure_preview_launch();
    let (db, registry) = fixture().await;
    let body = named_input_preview_body();
    let artifact_id = "b1d00000-0000-4000-8000-000000000001";
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": artifact_id, "type": "Document", "kind": "artifact",
                "name": artifact_id, "body": body,
                "facets": { "runtime": "native.html.v1" },
                "reason": "Named-input fixture for sample-only preview."
            }),
        )
        .await
        .unwrap();
    grant(&db, artifact_id, ALICE, Capability::View).await;
    // Live data Alice may view elsewhere: it must not leak into preview.
    let secret = "live-secret-9f31c4-not-for-preview-frames";
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": "c1d00000-0000-4000-8000-000000000001",
                "type": "WorkItem", "kind": "task",
                "name": secret, "body": secret,
                "reason": "Live record that preview must never read."
            }),
        )
        .await
        .unwrap();
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000001",
        ALICE,
        Capability::View,
    )
    .await;

    let source_revision = preview_source_revision(&db, artifact_id).await;
    let digest = preview_digest(&body);
    let args = preview_args(artifact_id, &source_revision, &digest);
    let preview = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &args),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();

    assert_eq!(preview["package"], "agent.attention-cockpit");
    assert_eq!(preview["preview"]["artifact_id"], artifact_id);
    assert_eq!(preview["preview"]["source_event_id"], source_revision);
    assert_eq!(preview["preview"]["digest"], digest);
    assert_eq!(preview["preview"]["digest_version"], "alpha-tab-digest.v1");
    assert_eq!(preview["preview"]["runtime"], "native.html.v1");
    assert_eq!(preview["preview"]["live_reads"], false);
    assert_eq!(preview["preview"]["effects_wired"], false);
    // Sample-only input: host-owned fixture, never live bindings.
    assert_eq!(preview["preview"]["sample_input"]["mode"], "sample");
    assert_eq!(preview["preview"]["sample_input"]["sample_preview"], true);
    assert!(
        !preview["preview"]["sample_input"]
            .to_string()
            .contains("c1d00000"),
        "sample input must not reference live records: {:#}",
        preview["preview"]["sample_input"]
    );
    let serialized = serde_json::to_string(&preview).unwrap();
    assert!(
        !serialized.contains(secret),
        "live record content must never reach the preview payload"
    );
    // Opaque sandbox: no credential-carrying flags, bridge-pinned launch.
    assert_eq!(preview["preview"]["sandbox"]["sandbox"], "allow-scripts");
    assert_eq!(
        preview["preview"]["sandbox"]["referrerPolicy"],
        "no-referrer"
    );
    assert_eq!(preview["preview"]["sandbox"]["allow"], "");
    assert!(
        preview["preview"]["launch"]["url"]
            .as_str()
            .unwrap()
            .contains("/artifact-runtime/v1/launch/"),
        "{preview:#}"
    );
    // Receipt is returned to the shell alongside the preview.
    assert!(preview["receipt"]["receipt_id"].is_string());
    assert!(preview["receipt"]["nonce"].is_string());
    assert!(preview["receipt"]["preview_session"].is_string());
    assert_eq!(preview["receipt"]["account_id"], ALICE);
    assert_eq!(preview["receipt"]["ttl_secs"], 900);
    // Preview changes nothing: no install row, no control event.
    let installs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alpha_tab_installs")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(installs, 0);
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM control_events WHERE type LIKE 'alpha_tab.%'")
            .fetch_one(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
    assert_eq!(events, 0);
}

#[tokio::test]
async fn preview_refuses_pin_mismatch_and_missing_authority() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT_A, "type": "Document", "kind": "artifact",
                "name": ARTIFACT_A, "body": PREVIEW_BODY,
                "facets": { "runtime": "native.html.v1" },
                "reason": "Fixture artifact for preview pin tests."
            }),
        )
        .await
        .unwrap();
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);

    // Wrong digest for the resolved bytes: fail closed, no receipt. The
    // attestation is minted from the request exactly as the hosted adapter
    // mints it, so this exercises the recomputation gate past authority.
    let mut wrong_digest = preview_args(ARTIFACT_A, &source_revision, &digest);
    wrong_digest["digest"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
    );
    let refused = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &wrong_digest),
        "manage_alpha_tabs",
        wrong_digest,
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("digest_mismatch"),
        "pin digest mismatch must fail closed"
    );

    // Unknown source revision: the portable identity resolves nothing.
    let unknown_args = preview_args(ARTIFACT_A, "00000000-0000-4000-8000-000000000000", &digest);
    let unknown = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &unknown_args),
        "manage_alpha_tabs",
        unknown_args,
    )
    .await;
    assert!(
        unknown
            .unwrap_err()
            .to_string()
            .contains("source_revision_unresolved"),
        "unknown source revision must fail closed"
    );

    // No viewer View: the only governed read refuses first.
    let denied_args = preview_args(ARTIFACT_A, &source_revision, &digest);
    let denied = call_as(
        &registry,
        &db,
        attested_preview_caller(BEA, &denied_args),
        "manage_alpha_tabs",
        denied_args,
    )
    .await;
    assert!(
        denied.unwrap_err().to_string().contains("unauthorized"),
        "preview without View must fail"
    );
}

#[tokio::test]
async fn preview_refuses_mcp_and_unattested_callers_at_tool_layer() {
    // The tool-layer default-deny behind the whole preview boundary: the
    // MCP router shares this registry, and Bearer HTTP calls arrive as
    // `Channel::Web`, so neither transport can smuggle authority. Without
    // the hosted attestation the tool refuses before any verification work
    // and mints no receipt — no preview bytes, launch URL, id, or nonce
    // reach the caller.
    configure_preview_launch();
    let (db, registry) = fixture().await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT_A, "type": "Document", "kind": "artifact",
                "name": ARTIFACT_A, "body": PREVIEW_BODY,
                "facets": { "runtime": "native.html.v1" },
                "reason": "Fixture artifact for preview authority tests."
            }),
        )
        .await
        .unwrap();
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let args = preview_args(ARTIFACT_A, &source_revision, &digest);

    for caller in [
        Caller::authenticated(ALICE),
        mcp_preview_caller(ALICE),
        Caller::local(),
    ] {
        let refused = call_as(&registry, &db, caller, "manage_alpha_tabs", args.clone()).await;
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("preview_authority_missing"),
            "unattested preview must fail closed without a response payload"
        );
    }

    // An attestation minted for a different pin authorizes nothing: the
    // field-for-field comparison refuses before any verification work.
    let mut other_args = args.clone();
    other_args["package"] = Value::String("agent.other-tab".into());
    let mismatched = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &other_args),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await;
    assert!(
        mismatched
            .unwrap_err()
            .to_string()
            .contains("preview_pin_mismatch"),
        "cross-pin preview authority must fail closed"
    );
    // An attestation bound to a different account authorizes nothing for
    // this caller: the account binding refuses before any verification work.
    let cross_account = {
        use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
        let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
        let caller = Caller::authenticated(BEA).with_verified_alpha_tab_preview(
            alpha_tab_preview_authority_for(
                ALICE,
                "agent.attention-cockpit",
                "0.1.0",
                args.get("digest")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                ARTIFACT_A,
                args.get("source_revision")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                &declaration,
            )
            .expect("fixture declaration is well-formed"),
        );
        call_as(&registry, &db, caller, "manage_alpha_tabs", args.clone()).await
    };
    assert!(
        cross_account
            .unwrap_err()
            .to_string()
            .contains("preview_pin_mismatch"),
        "cross-account preview authority must fail closed"
    );
}

#[tokio::test]
async fn preview_authority_boundary_is_cookie_plus_origin_only() {
    // The exact rule both layers enforce for preview issuance: Bearer is
    // refused outright and a missing Origin carries no same-origin proof.
    // Cookie plus Origin is the only issuance authority. The hosted adapter
    // (`held/hosting/src/http.rs`) refuses Bearer/missing-Origin before
    // dispatch, and the tool itself requires the attestation only that
    // adapter mints (`preview_refuses_mcp_and_unattested_callers_at_tool_layer`
    // proves the default-deny), so Bearer/MCP callers never receive a
    // preview receipt on any transport.
    use native_ce::mcp::tools::alpha_tabs::alpha_adopt_authority_gate;
    assert_eq!(
        alpha_adopt_authority_gate(true, true),
        Err("bearer_refused")
    );
    assert_eq!(
        alpha_adopt_authority_gate(true, false),
        Err("bearer_refused")
    );
    assert_eq!(
        alpha_adopt_authority_gate(false, false),
        Err("origin_missing")
    );
    assert_eq!(alpha_adopt_authority_gate(false, true), Ok(()));
}

#[tokio::test]
async fn preview_receipt_binds_account_and_full_pin() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": ARTIFACT_A, "type": "Document", "kind": "artifact",
                "name": ARTIFACT_A, "body": PREVIEW_BODY,
                "facets": { "runtime": "native.html.v1" },
                "reason": "Fixture artifact for preview receipt binding."
            }),
        )
        .await
        .unwrap();
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    // `grant` replaces the test policy, so fold both viewers in one write
    // (the same pattern as `accounts_are_isolated_*` below).
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);

    let alice_args = preview_args(ARTIFACT_A, &source_revision, &digest);
    let alice_preview = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &alice_args),
        "manage_alpha_tabs",
        alice_args,
    )
    .await
    .unwrap();
    let receipt_id = alice_preview["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    // The server holds the receipt bound to account plus the full pin plus
    // the sample-preview session: short-lived and single-use.
    use native_ce::mcp::tools::alpha_tabs::{
        alpha_tab_declaration_digest, find_alpha_tab_preview_receipt,
        verify_alpha_tab_adopt_confirm, AlphaTabAdoptConfirm, ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
    };
    let (stored, consumed) =
        find_alpha_tab_preview_receipt(&receipt_id).expect("preview receipt is server-held");
    assert!(!consumed);
    assert_eq!(stored.account_id, ALICE);
    assert_eq!(stored.package, "agent.attention-cockpit");
    assert_eq!(stored.version, "0.1.0");
    assert_eq!(stored.digest, digest);
    assert_eq!(stored.artifact_id, ARTIFACT_A);
    assert_eq!(stored.source_revision, source_revision);
    assert_eq!(
        stored.declaration_digest,
        alpha_tab_declaration_digest(&preview_declaration()).unwrap()
    );
    assert_eq!(stored.needs, vec!["attention.query.v1".to_string()]);
    assert_eq!(stored.effects, vec!["task.triage-set.v1".to_string()]);
    assert_eq!(
        stored.preview_session,
        alice_preview["receipt"]["preview_session"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        stored.expires_at_secs - stored.issued_at_secs,
        ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS
    );
    assert_eq!(
        alice_preview["receipt"]["expires_at_secs"]
            .as_i64()
            .unwrap(),
        stored.expires_at_secs
    );

    // The stored receipt verifies a field-for-field confirm and refuses any
    // pin mismatch without state change.
    let confirm = AlphaTabAdoptConfirm {
        receipt_id: stored.receipt_id.clone(),
        nonce: stored.nonce.clone(),
        account_id: stored.account_id.clone(),
        package: stored.package.clone(),
        version: stored.version.clone(),
        digest: stored.digest.clone(),
        artifact_id: stored.artifact_id.clone(),
        source_revision: stored.source_revision.clone(),
        declaration_digest: stored.declaration_digest.clone(),
        needs: stored.needs.clone(),
        effects: stored.effects.clone(),
        preview_session: stored.preview_session.clone(),
        reason: "Adopt the previewed attention cockpit.".into(),
        expected_install_event_id: "evt_cur".into(),
        current_event_id: "evt_cur".into(),
    };
    assert_eq!(
        verify_alpha_tab_adopt_confirm(
            Some(&stored),
            &confirm,
            stored.issued_at_secs + 60,
            consumed,
            false,
            true
        ),
        Ok(())
    );
    let mut mismatched = confirm.clone();
    mismatched.digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
    assert_eq!(
        verify_alpha_tab_adopt_confirm(
            Some(&stored),
            &mismatched,
            stored.issued_at_secs + 60,
            consumed,
            false,
            true
        ),
        Err("pin_mismatch")
    );

    // A second account previewing the same pin gets its own receipt bound
    // to its own account — receipts never cross accounts.
    let bea_args = preview_args(ARTIFACT_A, &source_revision, &digest);
    let bea_preview = call_as(
        &registry,
        &db,
        attested_preview_caller(BEA, &bea_args),
        "manage_alpha_tabs",
        bea_args,
    )
    .await
    .unwrap();
    let bea_id = bea_preview["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(bea_id, receipt_id);
    let (bea_stored, _) =
        find_alpha_tab_preview_receipt(&bea_id).expect("second account receipt is server-held");
    assert_eq!(bea_stored.account_id, BEA);
    assert_ne!(bea_stored.nonce, stored.nonce);
    assert_ne!(bea_stored.preview_session, stored.preview_session);
}

#[tokio::test]
async fn adopt_flips_install_to_verified_and_stays_fail_closed() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (event_id, receipt_id, nonce, preview_session) =
        installed_and_previewed(&registry, &db, ALICE).await;

    // Direct MCP/Bearer-equivalent calls refuse at the tool layer before
    // any verification work: no attestation, no confirm — on any channel.
    // No caller-supplied token or field can self-assert consent.
    for caller in [
        Caller::authenticated(ALICE),
        mcp_preview_caller(ALICE),
        Caller::local(),
    ] {
        let refused = call_as(
            &registry,
            &db,
            caller,
            "manage_alpha_tabs",
            adopt_args(
                ARTIFACT_A,
                &source_revision,
                &digest,
                &receipt_id,
                &nonce,
                &preview_session,
                &event_id,
            ),
        )
        .await;
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("adopt_authority_missing"),
            "unattested adopt must refuse without state change"
        );
    }

    // A caller-supplied receipt id that the server never held refuses too:
    // the attestation is pin-shaped, so an unknown id passes authority and
    // fails on the server-held lookup.
    let forged = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        "preview_neverminted0001",
        &nonce,
        &preview_session,
        &event_id,
    );
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &forged),
        "manage_alpha_tabs",
        forged,
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("receipt_unknown"),
        "forged receipt id must refuse without state change"
    );

    // The hosted confirm flips adoption to the verified value.
    let args = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &preview_session,
        &event_id,
    );
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();
    assert_eq!(adopted["changed"], true);
    assert_eq!(adopted["package"], "agent.attention-cockpit");
    let entry = &adopted["install"];
    assert_eq!(entry["adoption"], "shell_adopt.v1");
    assert_eq!(entry["status"], "installed");
    assert_ne!(entry["event_id"], event_id);
    // Inspect does not issue a URL; a separate exact-event launch is required.
    assert_eq!(entry["resolves"], false);
    assert_eq!(entry["digest_binding"], "stored-not-enforced");
    assert_eq!(entry["launch_binding"]["verdict"], "refused");
    assert_eq!(entry["launch_binding"]["reason"], "launch_request_required");
    assert_eq!(
        entry["launch_binding"]["digest_version"],
        "alpha-tab-digest.v1"
    );
    // The receipt is spent: single use.
    use native_ce::mcp::tools::alpha_tabs::find_alpha_tab_preview_receipt;
    let (_, consumed) =
        find_alpha_tab_preview_receipt(&receipt_id).expect("adopted receipt is server-held");
    assert!(consumed, "adopt must consume the receipt");
}

#[tokio::test]
async fn launch_binds_verified_install_and_refuses_stale_or_revoked_state() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (installed_event, receipt_id, nonce, session) =
        installed_and_previewed(&registry, &db, ALICE).await;
    let launch_args = |event: &str| {
        json!({
            "action":"launch", "package":"agent.attention-cockpit",
            "expected_install_event_id":event,
        })
    };
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        launch_args(&installed_event),
    )
    .await;
    assert!(refused
        .unwrap_err()
        .to_string()
        .contains("adoption_unverified"));
    let adopt = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &session,
        &installed_event,
    );
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &adopt),
        "manage_alpha_tabs",
        adopt,
    )
    .await
    .unwrap();
    let adopted_event = adopted["install"]["event_id"].as_str().unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        launch_args(&installed_event),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("cas_mismatch"));
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        launch_args(adopted_event),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("missing_install"));
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        launch_args(adopted_event),
    )
    .await
    .unwrap();
    assert_eq!(launch["install_event_id"], adopted_event);
    assert_eq!(launch["pin"]["digest"], digest);
    assert_eq!(launch["pin"]["source_revision"], source_revision);
    assert_eq!(launch["source"]["event_id"], source_revision);
    assert_eq!(
        launch["source"]["bundle_sha256"],
        launch["source"]["body_digest"]
    );
    assert_eq!(launch["source"]["runtime"], "native.html.v1");
    assert_eq!(launch["input"]["mode"], "sample");
    assert_eq!(launch["input"]["sample_preview"], true);
    assert_eq!(launch["live_reads"], false);
    assert_eq!(launch["effects_wired"], false);
    assert_eq!(launch["sandbox"]["sandbox"], "allow-scripts");
    assert!(launch["launch"]["url"]
        .as_str()
        .unwrap()
        .contains("/artifact-runtime/v1/launch/"));
    let inspect = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(inspect["resolves"], false);
    assert_eq!(
        inspect["launch_binding"]["reason"],
        "launch_request_required"
    );
    assert!(inspect["launch_binding"]["receipt"].is_null());
    // A changed runtime after adoption cannot borrow the old digest's
    // permission to launch. Restore the fixture value for the disable check.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("UPDATE facet_values SET value='native.html.artifact.v2' WHERE record_id=? AND key='runtime'")
        .bind(ARTIFACT_A)
        .execute(&pool)
        .await
        .unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        launch_args(adopted_event),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("not_renderable"));
    sqlx::query(
        "UPDATE facet_values SET value='native.html.v1' WHERE record_id=? AND key='runtime'",
    )
    .bind(ARTIFACT_A)
    .execute(&pool)
    .await
    .unwrap();
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action":"disable", "package":"agent.attention-cockpit",
            "expected_install_event_id":adopted_event, "reason":"Pause launch."}),
    )
    .await
    .unwrap();
    assert_eq!(disabled["install"]["status"], "disabled");
    let disabled_event = disabled["install"]["event_id"].as_str().unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        launch_args(disabled_event),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("disabled"));
}

#[tokio::test]
async fn adopt_receipt_is_single_use_and_cas_refuses_before_consume() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (event_id, receipt_id, nonce, preview_session) =
        installed_and_previewed(&registry, &db, ALICE).await;
    let adopt_with = |expected: &str| {
        adopt_args(
            ARTIFACT_A,
            &source_revision,
            &digest,
            &receipt_id,
            &nonce,
            &preview_session,
            expected,
        )
    };

    // A stale CAS generation refuses without spending the receipt, so the
    // caller can re-read the current event and retry with the same live
    // receipt.
    let stale = adopt_with("evt_stale");
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &stale),
        "manage_alpha_tabs",
        stale,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("installation changed"),
        "stale CAS must refuse without state change"
    );
    use native_ce::mcp::tools::alpha_tabs::find_alpha_tab_preview_receipt;
    let (_, consumed) =
        find_alpha_tab_preview_receipt(&receipt_id).expect("receipt survives CAS refusal");
    assert!(!consumed, "CAS refusal must not consume the receipt");

    // The corrected retry adopts.
    let fresh = adopt_with(&event_id);
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &fresh),
        "manage_alpha_tabs",
        fresh,
    )
    .await
    .unwrap();
    let verified_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
    assert_eq!(adopted["install"]["adoption"], "shell_adopt.v1");

    // Replaying the spent receipt with the fresh CAS refuses as consumed —
    // single use is independent of the CAS generation — with no state
    // change.
    let replay = adopt_with(&verified_event);
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &replay),
        "manage_alpha_tabs",
        replay,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("receipt_consumed"),
        "receipt replay must refuse without state change"
    );
    let entry = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(entry["event_id"], verified_event);
    assert_eq!(entry["adoption"], "shell_adopt.v1");
}

#[tokio::test]
async fn adopt_idempotency_key_converges_without_spending_a_second_receipt() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (event_id, receipt_id, nonce, preview_session) =
        installed_and_previewed(&registry, &db, ALICE).await;
    let mut args = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &preview_session,
        &event_id,
    );
    args["idempotency_key"] = Value::String("adopt-confirm-1".into());

    let first = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["changed"], true);
    let verified_event = first["install"]["event_id"].as_str().unwrap().to_string();

    // Same key plus identical intent converges on the first durable event —
    // `changed: false` — even though the receipt is spent and the CAS
    // generation has moved on.
    let retry = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["idempotent_retry"], true);
    assert_eq!(retry["install"]["event_id"], verified_event);
    assert_eq!(retry["install"]["adoption"], "shell_adopt.v1");

    // Same key for different intent fails visibly.
    let mut conflict = args.clone();
    conflict["reason"] = Value::String("A different reason for the same key.".into());
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &conflict),
        "manage_alpha_tabs",
        conflict,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("idempotency_key was reused"),
        "conflicting idempotency reuse must fail visibly"
    );
}

#[tokio::test]
async fn adopt_refuses_cross_pin_attestation_and_install_pin_drift() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (event_id, receipt_id, nonce, preview_session) =
        installed_and_previewed(&registry, &db, ALICE).await;
    let args = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &preview_session,
        &event_id,
    );

    // One preview's authority can never authorize a different pin: an
    // attestation minted for another package refuses at the tool layer.
    let mut other_pin = args.clone();
    other_pin["package"] = Value::String("agent.other-tab".into());
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &other_pin),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("adopt_pin_mismatch"),
        "cross-pin attestation must refuse without state change"
    );

    // Another account's attestation cannot be borrowed: Alice presenting
    // Bea's attestation for the same pin refuses at the authority check.
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller_for(ALICE, BEA, &args),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("adopt_pin_mismatch"),
        "cross-account attestation must refuse without state change"
    );

    // The install still carries the previewed pin here, so adoption would
    // succeed — instead prove the drift arm on a diverged install: Bea
    // installs a well-formed but different digest, previews the real pin,
    // and the adopt refuses across the drift without spending her receipt.
    let drift_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    registry
        .call(
            db.clone(),
            Caller::authenticated(BEA),
            "manage_alpha_tabs",
            install_exact_args(ARTIFACT_A, &source_revision, drift_digest),
        )
        .await
        .unwrap();
    let bea_preview_args = preview_args(ARTIFACT_A, &source_revision, &digest);
    let bea_preview = call_as(
        &registry,
        &db,
        attested_preview_caller(BEA, &bea_preview_args),
        "manage_alpha_tabs",
        bea_preview_args,
    )
    .await
    .unwrap();
    let bea_receipt = bea_preview["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    let bea_event = inspect_adopt_entry(&registry, &db, BEA).await["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let drift = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &bea_receipt,
        bea_preview["receipt"]["nonce"].as_str().unwrap(),
        bea_preview["receipt"]["preview_session"].as_str().unwrap(),
        &bea_event,
    );
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(BEA, &drift),
        "manage_alpha_tabs",
        drift,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("install_pin_mismatch"),
        "adopt across install pin drift must refuse without state change"
    );
    let entry = inspect_adopt_entry(&registry, &db, BEA).await;
    assert_eq!(entry["adoption"], "caller_asserted");
    use native_ce::mcp::tools::alpha_tabs::find_alpha_tab_preview_receipt;
    let (_, consumed) =
        find_alpha_tab_preview_receipt(&bea_receipt).expect("drifted receipt stays live");
    assert!(!consumed, "pin-drift refusal must not consume the receipt");
}

#[tokio::test]
async fn adopt_requires_a_live_install_and_refuses_without_one() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (event_id, receipt_id, nonce, preview_session) =
        installed_and_previewed(&registry, &db, ALICE).await;

    // Bea holds a live receipt for the same pin but never installed: the
    // confirm refuses with no install to bind, spending nothing.
    let bea_preview_args = preview_args(ARTIFACT_A, &source_revision, &digest);
    let bea_preview = call_as(
        &registry,
        &db,
        attested_preview_caller(BEA, &bea_preview_args),
        "manage_alpha_tabs",
        bea_preview_args,
    )
    .await
    .unwrap();
    let bea_args = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        bea_preview["receipt"]["receipt_id"].as_str().unwrap(),
        bea_preview["receipt"]["nonce"].as_str().unwrap(),
        bea_preview["receipt"]["preview_session"].as_str().unwrap(),
        &event_id,
    );
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(BEA, &bea_args),
        "manage_alpha_tabs",
        bea_args,
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("not installed"),
        "adopt without an install must refuse"
    );

    // A disabled install cannot adopt either: restore first.
    registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            json!({
                "action": "disable", "package": "agent.attention-cockpit",
                "expected_install_event_id": event_id,
                "reason": "Pause the tab before adopting."
            }),
        )
        .await
        .unwrap();
    let disabled_event = inspect_adopt_entry(&registry, &db, ALICE).await["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let args = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &preview_session,
        &disabled_event,
    );
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args,
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("cannot adopt"),
        "adopt of a disabled install must refuse"
    );
    let entry = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(entry["status"], "disabled");
    assert_eq!(entry["adoption"], "caller_asserted");
}

#[tokio::test]
async fn two_distinct_packages_install_preview_adopt_launch_independently() {
    // Task `26ba75a` two-package proof (backend lane): two DISTINCT
    // checked-in authored HTML packages — distinct bytes, distinct declarations,
    // distinct digests — install, preview, adopt, and launch through the
    // unchanged host build, with independent pin/disable behavior.
    //
    // Authority note: happy-path calls carry the hosted attestation via the
    // same constructors `held/hosting/src/http.rs` uses after cookie-session
    // plus trusted-Origin checks (see `attested_preview_caller` /
    // `attested_adopt_caller`). That mirrors the existing single-package
    // backend lane; no hosted cookie or browser evidence is claimed here.
    // Fixture records are created through an authenticated MCP-channel caller,
    // the same tool surface an agent can use. This still does not exercise a
    // hosted agent session or browser.
    use native_ce::mcp::tools::alpha_tabs::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    };

    const PKG_A: &str = "agent.attention-cockpit";
    const PKG_B: &str = "agent.team-pulse";
    const BODY_A: &str =
        include_str!("../../experiments/alpha-tab-proof-packages/attention-cockpit.html");
    const BODY_B: &str = include_str!("../../experiments/alpha-tab-proof-packages/team-pulse.html");

    fn decl_a() -> Value {
        json!({"needs": ["attention.query.v1"], "effects": []})
    }
    fn decl_b() -> Value {
        json!({"needs": [], "effects": []})
    }
    fn digest_for(body: &str, decl: &Value) -> String {
        alpha_tab_digest(
            &alpha_tab_bundle_digest(body),
            &alpha_tab_declaration_digest(decl).unwrap(),
            "native.html.v1",
        )
    }
    async fn create_artifact(registry: &ToolRegistry, db: &Db, id: &str, body: &str) {
        registry
            .call(
                db.clone(),
                Caller::authenticated(ALICE).with_channel(native_ce::provenance::Channel::Mcp),
                "create_record",
                json!({
                    "id": id, "type": "Document", "kind": "artifact",
                    "name": id, "body": body,
                    "facets": { "runtime": "native.html.v1" },
                    "reason": "Two-package proof artifact with distinct bytes."
                }),
            )
            .await
            .unwrap();
    }
    fn install_for(package: &str, artifact: &str, rev: &str, digest: &str, decl: &Value) -> Value {
        json!({
            "action": "install", "package": package, "version": "0.1.0",
            "digest": digest, "artifact_id": artifact,
            "source_revision": rev, "declaration": decl,
            "reason": "Install the two-package proof tab."
        })
    }
    fn preview_for(package: &str, artifact: &str, rev: &str, digest: &str, decl: &Value) -> Value {
        json!({
            "action": "preview", "package": package, "version": "0.1.0",
            "digest": digest, "artifact_id": artifact,
            "source_revision": rev, "declaration": decl,
            "reason": "Preview the two-package proof tab against sample input."
        })
    }
    fn adopt_for(
        package: &str,
        artifact: &str,
        rev: &str,
        digest: &str,
        decl: &Value,
        receipt: (&str, &str, &str),
        expected: &str,
    ) -> Value {
        json!({
            "action": "adopt", "package": package, "version": "0.1.0",
            "digest": digest, "artifact_id": artifact,
            "source_revision": rev, "declaration": decl,
            "receipt_id": receipt.0, "nonce": receipt.1,
            "preview_session": receipt.2,
            "expected_install_event_id": expected,
            "reason": "Adopt the previewed two-package proof tab."
        })
    }
    async fn inspect_pkg(registry: &ToolRegistry, db: &Db, package: &str) -> Value {
        registry
            .call(
                db.clone(),
                Caller::authenticated(ALICE),
                "manage_alpha_tabs",
                json!({"action": "inspect", "package": package}),
            )
            .await
            .unwrap()["install"]
            .clone()
    }
    async fn launch_pkg(registry: &ToolRegistry, db: &Db, package: &str, expected: &str) -> Value {
        call_as(
            registry,
            db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            json!({"action": "launch", "package": package,
                "expected_install_event_id": expected}),
        )
        .await
        .unwrap_or_else(|err| panic!("launch {package}@{expected} failed: {err}"))
    }

    configure_preview_launch();
    assert_ne!(BODY_A, BODY_B, "packages must ship distinct bytes");
    assert_ne!(
        decl_a(),
        decl_b(),
        "packages must declare distinct needs/effects"
    );
    let digest_a = digest_for(BODY_A, &decl_a());
    let digest_b = digest_for(BODY_B, &decl_b());
    assert_eq!(
        digest_a, "sha256:cccc7d69fb428cfed6129a52bda468a8c1662e961778270aec6e0651af872680",
        "host digest must match the checked-in Attention install descriptor"
    );
    assert_eq!(
        digest_b, "sha256:37784cc7b79e5c22fe0dad04ec66aee4b0073193b21e173ac6fef87d4e62bed6",
        "host digest must match the checked-in Team Pulse install descriptor"
    );
    assert_ne!(
        digest_a, digest_b,
        "distinct bytes/declaration must pin distinct digests"
    );

    let (db, registry) = fixture().await;
    // A non-local author must have the same portable account→person binding
    // the hosted database supplies. Without it create_record correctly
    // refuses, even when the credential string is authenticated.
    let pool = crate::common::fixture_write_pool(&db).await;
    let creator_person = "test:alpha-proof-author";
    sqlx::query(
        "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence) \
         VALUES (?,'Entity','person','Alpha proof author',?,?,'enduring')",
    )
    .bind(creator_person)
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
    )
    .bind(creator_person)
    .bind(ALICE)
    .execute(&pool)
    .await
    .unwrap();
    create_artifact(&registry, &db, ARTIFACT_A, BODY_A).await;
    create_artifact(&registry, &db, ARTIFACT_B, BODY_B).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    grant(&db, ARTIFACT_B, ALICE, Capability::View).await;
    let rev_a = preview_source_revision(&db, ARTIFACT_A).await;
    let rev_b = preview_source_revision(&db, ARTIFACT_B).await;
    for revision in [&rev_a, &rev_b] {
        let actor: Option<String> =
            sqlx::query_scalar("SELECT actor FROM content_events WHERE id=?")
                .bind(revision)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            actor.as_deref(),
            Some(ALICE),
            "artifact source must carry the authenticated author"
        );
    }
    assert_ne!(
        rev_a, rev_b,
        "distinct artifacts resolve distinct source revisions"
    );

    // Install both pins on the same viewer and host build.
    let installed_a = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_for(PKG_A, ARTIFACT_A, &rev_a, &digest_a, &decl_a()),
    )
    .await
    .unwrap();
    let installed_b = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_for(PKG_B, ARTIFACT_B, &rev_b, &digest_b, &decl_b()),
    )
    .await
    .unwrap();
    let event_a = installed_a["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let event_b = installed_b["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(event_a, event_b);

    let list = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
    assert_eq!(list["installs"].as_array().unwrap().len(), 2, "{list:#}");
    assert_eq!(list["installs"][0]["package"], PKG_A);
    assert_eq!(list["installs"][1]["package"], PKG_B);
    assert_eq!(list["installs"][0]["digest"], digest_a);
    assert_eq!(list["installs"][1]["digest"], digest_b);

    // Preview both exact pins: sample-only, distinct launches.
    let args_a = preview_for(PKG_A, ARTIFACT_A, &rev_a, &digest_a, &decl_a());
    let preview_a = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &args_a),
        "manage_alpha_tabs",
        args_a,
    )
    .await
    .unwrap();
    let args_b = preview_for(PKG_B, ARTIFACT_B, &rev_b, &digest_b, &decl_b());
    let preview_b = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &args_b),
        "manage_alpha_tabs",
        args_b,
    )
    .await
    .unwrap();
    for (preview, artifact, rev, digest) in [
        (&preview_a, ARTIFACT_A, rev_a.as_str(), digest_a.as_str()),
        (&preview_b, ARTIFACT_B, rev_b.as_str(), digest_b.as_str()),
    ] {
        assert_eq!(preview["preview"]["artifact_id"], artifact);
        assert_eq!(preview["preview"]["source_event_id"], rev);
        assert_eq!(preview["preview"]["digest"], digest);
        assert_eq!(preview["preview"]["live_reads"], false);
        assert_eq!(preview["preview"]["effects_wired"], false);
        assert_eq!(preview["preview"]["sample_input"]["mode"], "sample");
    }
    assert_ne!(
        preview_a["preview"]["launch"]["url"], preview_b["preview"]["launch"]["url"],
        "distinct pins must mint distinct one-use launches"
    );
    let receipt_a = (
        preview_a["receipt"]["receipt_id"]
            .as_str()
            .unwrap()
            .to_string(),
        preview_a["receipt"]["nonce"].as_str().unwrap().to_string(),
        preview_a["receipt"]["preview_session"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let receipt_b = (
        preview_b["receipt"]["receipt_id"]
            .as_str()
            .unwrap()
            .to_string(),
        preview_b["receipt"]["nonce"].as_str().unwrap().to_string(),
        preview_b["receipt"]["preview_session"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    assert_ne!(
        receipt_a.0, receipt_b.0,
        "receipts are per-pin server-held values"
    );

    // Adopt both exact pins through the verified confirm.
    let adopt_a = adopt_for(
        PKG_A,
        ARTIFACT_A,
        &rev_a,
        &digest_a,
        &decl_a(),
        (&receipt_a.0, &receipt_a.1, &receipt_a.2),
        &event_a,
    );
    let adopted_a = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &adopt_a),
        "manage_alpha_tabs",
        adopt_a,
    )
    .await
    .unwrap();
    let adopt_b = adopt_for(
        PKG_B,
        ARTIFACT_B,
        &rev_b,
        &digest_b,
        &decl_b(),
        (&receipt_b.0, &receipt_b.1, &receipt_b.2),
        &event_b,
    );
    let adopted_b = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &adopt_b),
        "manage_alpha_tabs",
        adopt_b,
    )
    .await
    .unwrap();
    assert_eq!(adopted_a["install"]["adoption"], "shell_adopt.v1");
    assert_eq!(adopted_b["install"]["adoption"], "shell_adopt.v1");
    let verified_a = adopted_a["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let verified_b = adopted_b["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Launch both verified installs: distinct pins, distinct one-use URLs.
    let launch_a = launch_pkg(&registry, &db, PKG_A, &verified_a).await;
    let launch_b = launch_pkg(&registry, &db, PKG_B, &verified_b).await;
    assert_eq!(launch_a["pin"]["digest"], digest_a);
    assert_eq!(launch_b["pin"]["digest"], digest_b);
    assert_eq!(launch_a["pin"]["artifact_id"], ARTIFACT_A);
    assert_eq!(launch_b["pin"]["artifact_id"], ARTIFACT_B);
    assert_eq!(launch_a["live_reads"], false);
    assert_eq!(launch_b["live_reads"], false);
    assert_ne!(
        launch_a["launch"]["url"], launch_b["launch"]["url"],
        "verified launches must differ per package"
    );

    // Independent disable: pausing A leaves B launchable, then restore A.
    let disabled_a = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "disable", "package": PKG_A,
            "expected_install_event_id": verified_a, "reason": "Pause the cockpit."}),
    )
    .await
    .unwrap();
    assert_eq!(disabled_a["install"]["status"], "disabled");
    let disabled_event_a = disabled_a["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": PKG_A,
            "expected_install_event_id": disabled_event_a}),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("disabled"));
    // B is unaffected by A's disable.
    let still_b = launch_pkg(&registry, &db, PKG_B, &verified_b).await;
    assert_eq!(still_b["pin"]["digest"], digest_b);

    // Restore re-stamps the transition payload as `caller_asserted`
    // (`install_payload` in `src/mcp/tools/alpha_tabs.rs`): a restored tab
    // needs a fresh sample preview plus verified adopt before it launches
    // again. That re-consent is the honest host behavior evidenced here —
    // this test does not change it.
    let restored_a = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "restore", "package": PKG_A,
            "expected_install_event_id": disabled_event_a, "reason": "Restore the cockpit."}),
    )
    .await
    .unwrap();
    assert_eq!(restored_a["install"]["status"], "installed");
    assert_eq!(restored_a["install"]["adoption"], "caller_asserted");
    let restored_event_a = restored_a["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": PKG_A,
            "expected_install_event_id": restored_event_a}),
    )
    .await;
    assert!(refused
        .unwrap_err()
        .to_string()
        .contains("adoption_unverified"));

    // Fresh consent for the restored pin: re-preview, re-adopt, relaunch.
    let fresh_a_args = preview_for(PKG_A, ARTIFACT_A, &rev_a, &digest_a, &decl_a());
    let fresh_a = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &fresh_a_args),
        "manage_alpha_tabs",
        fresh_a_args,
    )
    .await
    .unwrap();
    let readopt_a = adopt_for(
        PKG_A,
        ARTIFACT_A,
        &rev_a,
        &digest_a,
        &decl_a(),
        (
            fresh_a["receipt"]["receipt_id"].as_str().unwrap(),
            fresh_a["receipt"]["nonce"].as_str().unwrap(),
            fresh_a["receipt"]["preview_session"].as_str().unwrap(),
        ),
        &restored_event_a,
    );
    let readopted_a = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &readopt_a),
        "manage_alpha_tabs",
        readopt_a,
    )
    .await
    .unwrap();
    assert_eq!(readopted_a["install"]["adoption"], "shell_adopt.v1");
    let reverified_a = readopted_a["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let again_a = launch_pkg(&registry, &db, PKG_A, &reverified_a).await;
    assert_eq!(again_a["pin"]["digest"], digest_a);

    // Cross-pin binding: a second fresh receipt for A cannot adopt B's pin.
    let cross_a_args = preview_for(PKG_A, ARTIFACT_A, &rev_a, &digest_a, &decl_a());
    let cross_a = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &cross_a_args),
        "manage_alpha_tabs",
        cross_a_args,
    )
    .await
    .unwrap();
    let cross = adopt_for(
        PKG_B,
        ARTIFACT_B,
        &rev_b,
        &digest_b,
        &decl_b(),
        (
            cross_a["receipt"]["receipt_id"].as_str().unwrap(),
            cross_a["receipt"]["nonce"].as_str().unwrap(),
            cross_a["receipt"]["preview_session"].as_str().unwrap(),
        ),
        &verified_b,
    );
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &cross),
        "manage_alpha_tabs",
        cross,
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("pin_mismatch"),
        "a receipt bound to A must not adopt B"
    );

    // Final state: both pins installed and verified, with distinct digests.
    let entry_a = inspect_pkg(&registry, &db, PKG_A).await;
    let entry_b = inspect_pkg(&registry, &db, PKG_B).await;
    assert_eq!(entry_a["adoption"], "shell_adopt.v1");
    assert_eq!(entry_b["adoption"], "shell_adopt.v1");
    assert_ne!(entry_a["digest"], entry_b["digest"]);
}

// --- Governed live read (task 26ba75a backend/data slice) ---
//
// `live_read` is the host-executed `attention.query.v1` read for one adopted
// tab. Launch and preview stay sample-only; this response goes to the tool
// caller (the host), never to the frame. Row semantics v1: live
// WorkItem/task, lifecycle present and not completed/closed, not archived,
// viewer View per row, ordered last_activity_at DESC / id ASC, limit 50.

pub(crate) fn live_read_args(event: &str) -> Value {
    json!({
        "action": "live_read",
        "package": "agent.attention-cockpit",
        "expected_install_event_id": event,
    })
}

pub(crate) async fn live_task(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    name: &str,
    lifecycle: &str,
) {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": id, "type": "WorkItem", "kind": "task",
                "name": name, "body": name, "lifecycle": lifecycle,
                "reason": "Fixture attention row for the governed live read."
            }),
        )
        .await
        .unwrap();
}

pub(crate) async fn adopted_live_fixture(registry: &ToolRegistry, db: &Db) -> (String, String) {
    configure_preview_launch();
    adopt_fixture_artifact(registry, db).await;
    let source_revision = preview_source_revision(db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (installed_event, receipt_id, nonce, session) =
        installed_and_previewed(registry, db, ALICE).await;
    let adopt = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &session,
        &installed_event,
    );
    let adopted = call_as(
        registry,
        db,
        attested_adopt_caller(ALICE, &adopt),
        "manage_alpha_tabs",
        adopt,
    )
    .await
    .unwrap();
    let verified = adopted["install"]["event_id"].as_str().unwrap().to_string();
    (source_revision, verified)
}

#[tokio::test]
async fn live_read_returns_governed_rows_with_revision_and_provenance() {
    let (db, registry) = fixture().await;
    let (source_revision, verified) = adopted_live_fixture(&registry, &db).await;
    let digest = preview_digest(PREVIEW_BODY);
    // Two open rows Alice may view; one completed (terminal, excluded); one
    // open row only Bea may view (authority-filtered, excluded).
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000011",
        "Open alpha one",
        "open",
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000012",
        "Open alpha two",
        "in_progress",
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000013",
        "Done alpha",
        "completed",
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000014",
        "Bea only",
        "open",
    )
    .await;
    for id in [
        "c1d00000-0000-4000-8000-000000000011",
        "c1d00000-0000-4000-8000-000000000012",
        "c1d00000-0000-4000-8000-000000000013",
    ] {
        grant(&db, id, ALICE, Capability::View).await;
    }
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000014",
        BEA,
        Capability::View,
    )
    .await;

    let read = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert_eq!(read["package"], "agent.attention-cockpit");
    assert_eq!(read["install_event_id"], verified);
    assert_eq!(read["need"], "attention.query.v1");
    assert_eq!(read["pin"]["digest"], digest);
    assert_eq!(read["pin"]["source_revision"], source_revision);
    assert_eq!(read["source"]["event_id"], source_revision);
    // Declared (not bound) port: the manifest shape the package must carry
    // for a future bound-port slice. Delivery here is the top-level shim —
    // `inputs` stays empty, so nothing claims a populated named-input port.
    assert_eq!(read["declared_port"]["need"], "attention.query.v1");
    assert_eq!(read["declared_port"]["port"], "items");
    assert_eq!(read["declared_port"]["status"], "declared-not-bound");
    assert_eq!(read["declared_port"]["delivery"], "top-level-records-shim");
    assert_eq!(
        read["declared_port"]["declaration"]["envelope"],
        "native.collection-envelope.v1"
    );
    assert_eq!(read["declared_port"]["declaration"]["required"], true);
    assert_eq!(read["declared_port"]["declaration"]["expose_to_root"], true);
    assert_eq!(
        read["declared_port"]["capability_requests"],
        json!([{ "capability": "input.read", "scope": { "port": "items" } }])
    );
    assert!(read.get("port_mapping").is_none());
    // Exactly the two governed rows, no terminal and no unauthorized row.
    let ids: Vec<String> = read["input"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2, "{read:#}");
    assert!(ids.contains(&"c1d00000-0000-4000-8000-000000000011".to_string()));
    assert!(ids.contains(&"c1d00000-0000-4000-8000-000000000012".to_string()));
    assert_eq!(read["input"]["version"], "native.artifact-input.v1");
    assert_eq!(read["input"]["mode"], "live");
    assert_eq!(read["input"]["sample_preview"], false);
    assert_eq!(read["input"]["inputs"], json!({}));
    // The set digest is canonical over the returned rows and rides both on
    // the input envelope and in the viewer-scoped fence token.
    assert!(!read["rows_sha256"].as_str().unwrap().is_empty());
    assert_eq!(read["input"]["records_sha256"], read["rows_sha256"]);
    assert_eq!(read["revision"]["rows_sha256"], read["rows_sha256"]);
    assert!(!read["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .is_empty());
    // Noninterference shape: no global content-event id/seq, no
    // authorization epoch, no scan counters/completeness anywhere in the
    // caller-visible response. The bounded scan stays internal; the public
    // window marker is static.
    for forbidden in [
        "content_event_id",
        "content_event_seq",
        "authorization_revision",
        "candidates_scanned",
        "scan_cap",
        "complete",
        "input_abi",
        "meta_sha256",
    ] {
        assert!(
            read.get(forbidden).is_none(),
            "top-level {forbidden} must not leak: {read:#}"
        );
        assert!(
            read["revision"].get(forbidden).is_none(),
            "revision.{forbidden} must not leak: {read:#}"
        );
        assert!(
            read["window"].get(forbidden).is_none(),
            "window.{forbidden} must not leak: {read:#}"
        );
    }
    // No ticket TTL is claimed as a display bound (there is no
    // `expires_in_ms` on this response).
    assert!(read.get("expires_in_ms").is_none());
    assert!(!read["input_digest"].as_str().unwrap().is_empty());
    assert_eq!(read["window"], json!({"bounded_window": true}));
    assert_eq!(read["live_reads"], true);
    assert_eq!(read["effects_wired"], false);
    // Launch stays sample-only alongside the live host read: no live row
    // reaches the frame payload.
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action":"launch","package":"agent.attention-cockpit",
            "expected_install_event_id":verified}),
    )
    .await
    .unwrap();
    assert_eq!(launch["live_reads"], false);
    assert_eq!(launch["input"]["mode"], "sample");
    let serialized = serde_json::to_string(&launch).unwrap();
    assert!(!serialized.contains("c1d00000-0000-4000-8000-000000000011"));
}

#[tokio::test]
async fn live_read_scans_past_inaccessible_newer_tasks_to_fill_50_authorized() {
    // The LIMIT-before-View starvation case: 60 Bea-only tasks newer than 55
    // Alice-visible ones. A bare `LIMIT 50` before the authority check would
    // return zero of Alice's rows; the bounded scan must return her newest
    // 50 instead.
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    // Alice's tasks are created first (older); Bea's 60 follow (newer), so
    // the newest 50 attention-shaped candidates are all Bea-only.
    for index in 0..55 {
        let id = format!("d2d00000-0000-4000-8{:03}-000000000000", index);
        live_task(&registry, &db, &id, &format!("Alice older {index}"), "open").await;
        grant(&db, &id, ALICE, Capability::View).await;
    }
    for index in 0..60 {
        let id = format!("d1d00000-0000-4000-8{:03}-000000000000", index);
        live_task(&registry, &db, &id, &format!("Bea newer {index}"), "open").await;
        grant(&db, &id, BEA, Capability::View).await;
    }
    let read = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    let ids: Vec<String> = read["input"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 50, "{read:#}");
    assert!(
        ids.iter().all(|id| id.starts_with("d2d00000")),
        "every returned row must be Alice-visible: {ids:?}"
    );
    // The internal scan reaches past all 60 inaccessible newer tasks to
    // fill the page; the public response discloses nothing about that —
    // only the static bounded-window marker.
    assert_eq!(read["window"], json!({"bounded_window": true}));
}

#[tokio::test]
async fn live_read_revision_follows_visible_row_and_access_changes() {
    // The viewer-scoped token (canonical digest over the returned rows plus
    // the install pin/generation) must move for every delivered-field change
    // and every membership change affecting this viewer. Every record write
    // re-stamps surfaced `last_activity_at`, so even facet/body writes to an
    // included row move the token. L2 limit, stated: rows carry display
    // fields only — no facet prior values and no per-record CAS token — so
    // this token is a staleness fence for re-read comparison, never the
    // observed prior for a triage write.
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    live_task(
        &registry,
        &db,
        "e1d00000-0000-4000-8000-000000000011",
        "Fence one",
        "open",
    )
    .await;
    live_task(
        &registry,
        &db,
        "e1d00000-0000-4000-8000-000000000012",
        "Fence two",
        "open",
    )
    .await;
    for id in [
        "e1d00000-0000-4000-8000-000000000011",
        "e1d00000-0000-4000-8000-000000000012",
    ] {
        grant(&db, id, ALICE, Capability::View).await;
    }
    let live = || async {
        call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            live_read_args(&verified),
        )
        .await
        .unwrap()
    };
    let update = |args: Value| async {
        registry
            .call(db.clone(), Caller::local(), "update_record", args)
            .await
            .unwrap()
    };
    let token_of = |read: &Value| {
        read["revision"]["revision_digest"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let before = live().await;
    let before_token = token_of(&before);
    // Rename: a surfaced field change moves the token.
    update(json!({"id": "e1d00000-0000-4000-8000-000000000011", "name": "Fence one renamed", "reason": "Fence probe."})).await;
    let renamed = live().await;
    assert_ne!(
        token_of(&renamed),
        before_token,
        "rename must move revision_digest"
    );
    // Lifecycle field change: same membership, different row bytes.
    update(json!({"id": "e1d00000-0000-4000-8000-000000000011", "lifecycle": "in_progress", "reason": "Fence probe."})).await;
    let triaged = live().await;
    assert_ne!(
        token_of(&triaged),
        token_of(&renamed),
        "lifecycle change must move revision_digest"
    );
    // Facet write re-stamps surfaced `last_activity_at`, so the token moves.
    update(
        json!({"id": "e1d00000-0000-4000-8000-000000000011", "facets": {"triage_note": "n1"}, "reason": "Fence probe."}),
    )
    .await;
    let faceted = live().await;
    assert_ne!(
        token_of(&faceted),
        token_of(&triaged),
        "facet write must move revision_digest"
    );
    // Body append: same behavior for a non-surfaced content field.
    update(json!({"id": "e1d00000-0000-4000-8000-000000000011", "body_append": " plus", "reason": "Fence probe."})).await;
    let bodied = live().await;
    assert_ne!(
        token_of(&bodied),
        token_of(&faceted),
        "body write must move revision_digest"
    );
    // Terminal lifecycle: membership change moves the token.
    update(json!({"id": "e1d00000-0000-4000-8000-000000000012", "lifecycle": "completed", "reason": "Fence probe."})).await;
    let completed = live().await;
    assert_ne!(
        token_of(&completed),
        token_of(&bodied),
        "terminal transition must move revision_digest"
    );
    // Access revoke: the row drops from this viewer's set.
    revoke_all(&db, "e1d00000-0000-4000-8000-000000000011").await;
    let revoked = live().await;
    assert_ne!(
        token_of(&revoked),
        token_of(&completed),
        "revoke must move revision_digest"
    );
    // Access grant on a new open task: the row appears for this viewer.
    live_task(
        &registry,
        &db,
        "e1d00000-0000-4000-8000-000000000013",
        "Fence three",
        "open",
    )
    .await;
    grant(
        &db,
        "e1d00000-0000-4000-8000-000000000013",
        ALICE,
        Capability::View,
    )
    .await;
    let granted = live().await;
    assert_ne!(
        token_of(&granted),
        token_of(&revoked),
        "grant of a new visible row must move revision_digest"
    );
}

#[tokio::test]
async fn live_read_hides_inaccessible_only_changes() {
    // Noninterference: creating and mutating tasks this viewer may not read
    // must leave every caller-visible byte of her response unchanged — rows,
    // input digest, row digest, and revision token alike. In particular no
    // global head/epoch may smuggle the inaccessible write's existence into
    // her view (the previous `content_event_seq`/`authorization_revision`
    // fields failed exactly this).
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    live_task(
        &registry,
        &db,
        "f1d00000-0000-4000-8000-000000000011",
        "Visible one",
        "open",
    )
    .await;
    grant(
        &db,
        "f1d00000-0000-4000-8000-000000000011",
        ALICE,
        Capability::View,
    )
    .await;
    let live = || async {
        call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            live_read_args(&verified),
        )
        .await
        .unwrap()
    };
    let visible_of = |read: &Value| {
        (
            read["input"]["records"].clone(),
            read["input_digest"].as_str().unwrap().to_string(),
            read["rows_sha256"].as_str().unwrap().to_string(),
            read["revision"]["revision_digest"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    };
    let before = visible_of(&live().await);
    // Inaccessible-only churn: new Bea-only tasks, renames, lifecycle and
    // facet/body writes, terminal transitions, and a grant/revoke cycle —
    // none of it visible to Alice.
    for index in 0..3 {
        let id = format!("f1d00000-0000-4000-8000-00000000002{index}");
        live_task(&registry, &db, &id, &format!("Hidden {index}"), "open").await;
        grant(&db, &id, BEA, Capability::View).await;
    }
    let update_hidden = |args: Value| async {
        registry
            .call(db.clone(), Caller::local(), "update_record", args)
            .await
            .unwrap()
    };
    update_hidden(
        json!({"id": "f1d00000-0000-4000-8000-000000000020", "name": "Hidden renamed", "reason": "Noninterference probe."}),
    )
    .await;
    update_hidden(
        json!({"id": "f1d00000-0000-4000-8000-000000000021", "lifecycle": "in_progress", "reason": "Noninterference probe."}),
    )
    .await;
    update_hidden(
        json!({"id": "f1d00000-0000-4000-8000-000000000021", "facets": {"note": "hidden"}, "reason": "Noninterference probe."}),
    )
    .await;
    update_hidden(
        json!({"id": "f1d00000-0000-4000-8000-000000000022", "lifecycle": "completed", "reason": "Noninterference probe."}),
    )
    .await;
    revoke_all(&db, "f1d00000-0000-4000-8000-000000000020").await;
    grant(
        &db,
        "f1d00000-0000-4000-8000-000000000020",
        BEA,
        Capability::View,
    )
    .await;
    let after = visible_of(&live().await);
    assert_eq!(
        after, before,
        "inaccessible-only changes must not move the reader's visible response"
    );
    // And the hidden ids appear nowhere in her payload.
    let serialized = serde_json::to_string(&live().await).unwrap();
    for fragment in ["Hidden", "000000000020", "000000000021", "000000000022"] {
        assert!(
            !serialized.contains(fragment),
            "inaccessible task data must not leak: found {fragment}"
        );
    }
}

#[tokio::test]
async fn live_read_visible_window_ignores_unreadable_only_push_at_boundary() {
    // Boundary noninterference: with 1 visible + 499 newer unreadable tasks
    // the visible row sits at the edge of the old 500-candidate window; one
    // more unreadable-only write must not move rows or revision_digest.
    // Hidden ids sort below the visible id so timestamp ties still order
    // hidden first (ORDER BY last_activity_at DESC, id ASC).
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    const VISIBLE: &str = "b2d00000-0000-4000-8000-000000000001";
    live_task(&registry, &db, VISIBLE, "Boundary visible", "open").await;
    grant(&db, VISIBLE, ALICE, Capability::View).await;
    for index in 0..499 {
        let id = format!("b1d00000-0000-4000-8{index:03}-000000000000");
        live_task(&registry, &db, &id, &format!("Hidden {index}"), "open").await;
        grant(&db, &id, BEA, Capability::View).await;
    }
    let live = || async {
        call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            live_read_args(&verified),
        )
        .await
        .unwrap()
    };
    let before = live().await;
    let before_ids = before["input"]["records"].clone();
    let before_digest = before["revision"]["revision_digest"].clone();
    assert!(
        before_ids
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == VISIBLE),
        "visible row must be present at the boundary: {before:#}"
    );
    // One more unreadable-only push past the old 500 window.
    live_task(
        &registry,
        &db,
        "b1d00000-0000-4000-8500-000000000000",
        "Hidden push",
        "open",
    )
    .await;
    grant(
        &db,
        "b1d00000-0000-4000-8500-000000000000",
        BEA,
        Capability::View,
    )
    .await;
    let after = live().await;
    assert_eq!(
        after["input"]["records"], before_ids,
        "unreadable-only push must not move visible rows"
    );
    assert_eq!(
        after["revision"]["revision_digest"], before_digest,
        "unreadable-only push must not move revision_digest"
    );
    assert_eq!(after["window"], json!({"bounded_window": true}));
}

#[tokio::test]
async fn live_read_authority_parity_for_guest_members_anchorless_and_derived() {
    // Parity pins: the visible-view join must agree with `can_record_in`
    // (fail-closed `debug_assert` in `do_live_read`, which fires on every
    // admitted row in these reads) for a non-member caller, a members-only
    // grant, a policy-less record, and a derived record resolving through
    // its bearer. The derived suggestion is never attention-shaped and must
    // appear nowhere; the bearer itself stays visible through its own grant.
    const GUEST: &str = "guest-parity";
    const MEMBERS_TASK: &str = "c2d00000-0000-4000-8000-000000000021";
    const GUEST_TASK: &str = "c2d00000-0000-4000-8000-000000000022";
    const ANCHORLESS_TASK: &str = "c2d00000-0000-4000-8000-000000000023";
    const BEARER_TASK: &str = "c2d00000-0000-4000-8000-000000000024";
    const DERIVED_SUGGESTION: &str = "c2d00000-0000-4000-8000-000000000025";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // The fixture artifact grants ALICE+BEA; widen to the guest account so
    // its live-read gates can pass without touching other tests' fixtures.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
            AllowEntry::account(GUEST, Capability::View),
        ],
    )
    .await
    .unwrap();
    let mut verified_for = Vec::new();
    for account in [GUEST, ALICE] {
        let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
        let digest = preview_digest(PREVIEW_BODY);
        let (installed_event, receipt_id, nonce, session) =
            installed_and_previewed(&registry, &db, account).await;
        let adopt = adopt_args(
            ARTIFACT_A,
            &source_revision,
            &digest,
            &receipt_id,
            &nonce,
            &session,
            &installed_event,
        );
        let adopted = call_as(
            &registry,
            &db,
            attested_adopt_caller(account, &adopt),
            "manage_alpha_tabs",
            adopt,
        )
        .await
        .unwrap();
        verified_for.push(adopted["install"]["event_id"].as_str().unwrap().to_string());
    }
    let (guest_verified, alice_verified) = (verified_for[0].clone(), verified_for[1].clone());
    for (id, name) in [
        (MEMBERS_TASK, "Members parity task"),
        (GUEST_TASK, "Guest parity task"),
        (ANCHORLESS_TASK, "Anchorless parity task"),
        (BEARER_TASK, "Bearer parity task"),
    ] {
        live_task(&registry, &db, id, name, "open").await;
    }
    replace_explicit_policy(
        &db,
        "test:policy",
        MEMBERS_TASK,
        vec![AllowEntry::members(Capability::View)],
    )
    .await
    .unwrap();
    grant(&db, GUEST_TASK, GUEST, Capability::View).await;
    revoke_all(&db, ANCHORLESS_TASK).await;
    grant(&db, BEARER_TASK, GUEST, Capability::View).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": DERIVED_SUGGESTION, "type": "Annotation", "kind": "suggestion",
                "name": "Derived parity suggestion", "body": "derived",
                "lifecycle": "open", "facets": { "proposal.precondition": "none" },
                "links": [{ "target_id": BEARER_TASK, "relationship": "part_of" }],
                "reason": "Parity fixture: derived record resolving through its bearer."
            }),
        )
        .await
        .unwrap();
    let ids_of = |read: &Value| {
        let mut ids: Vec<String> = read["input"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    let guest = call_as(
        &registry,
        &db,
        Caller::authenticated(GUEST).with_hosting_member(false),
        "manage_alpha_tabs",
        live_read_args(&guest_verified),
    )
    .await
    .unwrap();
    assert_eq!(ids_of(&guest), vec![GUEST_TASK, BEARER_TASK]);
    let alice = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&alice_verified),
    )
    .await
    .unwrap();
    assert_eq!(ids_of(&alice), vec![MEMBERS_TASK]);
    // Anchorless and derived records surface nowhere, for either viewer.
    for read in [&guest, &alice] {
        let serialized = serde_json::to_string(read).unwrap();
        for fragment in [
            "Anchorless parity",
            "000000000023",
            "Derived parity",
            "000000000025",
        ] {
            assert!(
                !serialized.contains(fragment),
                "parity leak: found {fragment}"
            );
        }
    }
    // The guest (non-member) never sees the members-only row.
    assert!(!serde_json::to_string(&guest)
        .unwrap()
        .contains("Members parity"));
    assert_ne!(
        guest["revision"]["revision_digest"], alice["revision"]["revision_digest"],
        "different visible sets must carry different digests"
    );
}

#[tokio::test]
async fn live_read_refuses_before_adopt() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let (installed_event, _, _, _) = installed_and_previewed(&registry, &db, ALICE).await;
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&installed_event),
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("adoption_unverified"),
        "live rows must stay excluded before verified Adopt"
    );
}

#[tokio::test]
async fn live_read_refuses_on_view_loss() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    revoke_all(&db, ARTIFACT_A).await;
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("unauthorized"),
        "losing View on the package artifact must exclude live rows"
    );
}

#[tokio::test]
async fn live_read_refuses_when_disabled() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action":"disable","package":"agent.attention-cockpit",
            "expected_install_event_id":verified,"reason":"Pause live reads."}),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"].as_str().unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(disabled_event),
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("disabled"),
        "a disabled install must exclude live rows"
    );
}

#[tokio::test]
async fn live_read_refuses_on_digest_mismatch() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    // Drift the stored pin out from under the live source bytes: the
    // recomputed `alpha-tab-digest.v1` no longer matches the pin. The
    // installs projection is test-mutable; the append-only content log is
    // left untouched.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("UPDATE alpha_tab_installs SET digest=? WHERE account_id=? AND package=?")
        .bind("sha256:0000000000000000000000000000000000000000000000000000000000000000")
        .bind(ALICE)
        .bind("agent.attention-cockpit")
        .execute(&pool)
        .await
        .unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("digest_mismatch"),
        "source drift under a pinned digest must exclude live rows"
    );
}

#[tokio::test]
async fn live_read_refuses_on_source_mismatch() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    // Point the pin at a revision that names no body-carrying event: the
    // append-only content log is untouched, the pin simply names no bytes.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "UPDATE alpha_tab_installs SET consented_source_revision=? WHERE account_id=? AND package=?",
    )
    .bind("e1d00000-0000-4000-8000-00000000ffff")
    .bind(ALICE)
    .bind("agent.attention-cockpit")
    .execute(&pool)
    .await
    .unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("source_revision_unresolved"),
        "an unresolvable source revision must exclude live rows"
    );
}

#[tokio::test]
async fn live_read_refuses_by_undeclared_need() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    // A pin whose consented needs omit `attention.query.v1` adopts cleanly
    // but never earns the live read.
    let other = json!({"needs": ["other.need.v1"], "effects": []});
    let digest = {
        use native_ce::mcp::tools::alpha_tabs::{
            alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
        };
        alpha_tab_digest(
            &alpha_tab_bundle_digest(PREVIEW_BODY),
            &alpha_tab_declaration_digest(&other).unwrap(),
            "native.html.v1",
        )
    };
    let install = json!({
        "action": "install", "package": "agent.attention-cockpit",
        "version": "0.1.0", "digest": digest, "artifact_id": ARTIFACT_A,
        "source_revision": source_revision, "declaration": other,
        "reason": "Install a pin without the attention need.",
    });
    let installed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install,
    )
    .await
    .unwrap();
    let event_id = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let preview = json!({
        "action": "preview", "package": "agent.attention-cockpit",
        "version": "0.1.0", "digest": digest, "artifact_id": ARTIFACT_A,
        "source_revision": source_revision, "declaration": other,
        "reason": "Preview a pin without the attention need.",
    });
    let previewed = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &preview),
        "manage_alpha_tabs",
        preview,
    )
    .await
    .unwrap();
    let adopt = json!({
        "action": "adopt", "package": "agent.attention-cockpit",
        "version": "0.1.0", "digest": digest, "artifact_id": ARTIFACT_A,
        "source_revision": source_revision, "declaration": other,
        "receipt_id": previewed["receipt"]["receipt_id"],
        "nonce": previewed["receipt"]["nonce"],
        "preview_session": previewed["receipt"]["preview_session"],
        "expected_install_event_id": event_id,
        "reason": "Adopt a pin without the attention need.",
    });
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &adopt),
        "manage_alpha_tabs",
        adopt,
    )
    .await
    .unwrap();
    assert_eq!(adopted["install"]["adoption"], "shell_adopt.v1");
    let verified = adopted["install"]["event_id"].as_str().unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(verified),
    )
    .await;
    assert!(
        refused.unwrap_err().to_string().contains("undeclared_need"),
        "a need outside the consented declaration must exclude live rows"
    );
}

// On-request declared reads (task `1044bb6`): `records.search.v1` and
// `records.resolve_reference.v1` run through the same gate chain as the
// attention snapshot, then through the ordinary tool handler under the
// viewer, so the frame sees exactly what the viewer's own read would show.

const SEARCH_NEEDS: [&str; 2] = ["records.search.v1", "records.resolve_reference.v1"];

/// Install, preview and adopt the fixture artifact for Alice under an
/// arbitrary consented declaration; returns the verified install event.
/// Callers pass unsorted multi-entry declarations on purpose: install must
/// store the same canonical declaration digest that adopt recomputes.
async fn adopted_with_declaration(registry: &ToolRegistry, db: &Db, declaration: Value) -> String {
    configure_preview_launch();
    adopt_fixture_artifact(registry, db).await;
    let source_revision = preview_source_revision(db, ARTIFACT_A).await;
    let digest = {
        use native_ce::mcp::tools::alpha_tabs::{
            alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
        };
        alpha_tab_digest(
            &alpha_tab_bundle_digest(PREVIEW_BODY),
            &alpha_tab_declaration_digest(&declaration).unwrap(),
            "native.html.v1",
        )
    };
    let pin = json!({
        "package": "agent.search", "version": "0.1.0", "digest": digest,
        "artifact_id": ARTIFACT_A, "source_revision": source_revision,
        "declaration": declaration,
    });
    let with = |action: &str, reason: &str| {
        let mut args = pin.clone();
        args["action"] = json!(action);
        args["reason"] = json!(reason);
        args
    };
    let installed = call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        with("install", "Install a search package pin."),
    )
    .await
    .unwrap();
    let event_id = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let preview = with("preview", "Preview a search package pin.");
    let previewed = call_as(
        registry,
        db,
        attested_preview_caller(ALICE, &preview),
        "manage_alpha_tabs",
        preview,
    )
    .await
    .unwrap();
    let mut adopt = with("adopt", "Adopt a search package pin.");
    adopt["receipt_id"] = previewed["receipt"]["receipt_id"].clone();
    adopt["nonce"] = previewed["receipt"]["nonce"].clone();
    adopt["preview_session"] = previewed["receipt"]["preview_session"].clone();
    adopt["expected_install_event_id"] = json!(event_id);
    let adopted = call_as(
        registry,
        db,
        attested_adopt_caller(ALICE, &adopt),
        "manage_alpha_tabs",
        adopt,
    )
    .await
    .unwrap();
    assert_eq!(adopted["install"]["adoption"], "shell_adopt.v1");
    adopted["install"]["event_id"].as_str().unwrap().to_string()
}

fn declared_read_args(event: &str, need: &str, params: Value) -> Value {
    json!({
        "action": "live_read",
        "package": "agent.search",
        "expected_install_event_id": event,
        "need": need,
        "params": params,
    })
}

async fn declared_read(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    need: &str,
    params: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        declared_read_args(event, need, params),
    )
    .await
}

#[tokio::test]
async fn declared_search_matches_the_viewers_own_search() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000021",
        "Zebra crossing plan",
        "open",
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000022",
        "Zebra hidden from Alice",
        "open",
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000021",
        ALICE,
        Capability::View,
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000022",
        BEA,
        Capability::View,
    )
    .await;

    let read = declared_read(
        &registry,
        &db,
        &verified,
        "records.search.v1",
        json!({"query": "zebra", "limit": 30}),
    )
    .await
    .unwrap();
    let own = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "search",
        json!({"query": "zebra", "limit": 30}),
    )
    .await
    .unwrap();
    // The registry decorates direct tool calls with run context; the search
    // payload itself must be identical.
    let mut own = own;
    own.as_object_mut().unwrap().remove("run_context");
    assert_eq!(
        read["result"], own,
        "declared search must equal the viewer's own search"
    );
    assert_eq!(read["need"], "records.search.v1");
    assert_eq!(read["params"], json!({"query": "zebra", "limit": 30}));
    assert_eq!(read["effects_wired"], false);
    let ids: Vec<&str> = read["result"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|hit| hit["id"].as_str())
        .collect();
    assert!(ids.contains(&"c1d00000-0000-4000-8000-000000000021"));
    assert!(
        !ids.contains(&"c1d00000-0000-4000-8000-000000000022"),
        "a record the viewer cannot see must never reach the frame"
    );
}

#[tokio::test]
async fn declared_search_rechecks_the_install_inside_its_own_read() {
    use native_ce::mcp::tools::alpha_tabs::search_read;
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000021",
        "Zebra crossing plan",
        "open",
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000021",
        ALICE,
        Capability::View,
    )
    .await;
    let alice = Caller::authenticated(ALICE);
    // Called directly, with no outer gate in front of it: the read answers
    // only for the installation that holds in its own snapshot.
    let inner = |event: String| {
        let (db, alice) = (db.clone(), alice.clone());
        async move { search_read(&db, &alice, "agent.search", &event, "zebra", 30).await }
    };
    // The production path serves the same answer through the recheck.
    let public = declared_read(
        &registry,
        &db,
        &verified,
        "records.search.v1",
        json!({"query": "zebra", "limit": 30}),
    )
    .await
    .unwrap();
    assert_eq!(public["result"], inner(verified.clone()).await.unwrap());

    // The viewer loses the tab's artifact: the read refuses on its own.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(BEA, Capability::View)],
    )
    .await
    .unwrap();
    let lost = inner(verified.clone()).await.unwrap_err().to_string();
    assert!(lost.contains("[unauthorized]"), "{lost}");
    adopt_fixture_artifact_policy(&db).await;
    inner(verified.clone()).await.unwrap();

    // The install is replaced by a disable: the generation the read was
    // asked for is gone, and the new one is not live.
    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.search",
            "expected_install_event_id": verified, "reason": "Stop the search tab.",
        }),
    )
    .await
    .unwrap();
    let stale = inner(verified.clone()).await.unwrap_err().to_string();
    assert!(stale.contains("[cas_mismatch]"), "{stale}");
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = inner(disabled_event).await.unwrap_err().to_string();
    assert!(refused.contains("[disabled]"), "{refused}");

    // An install whose consent never named the need cannot read with it.
    let resolve_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        json!({"needs": ["records.resolve_reference.v1"], "effects": []}),
    )
    .await;
    let undeclared = search_read(&db, &alice, "agent.search-only", &resolve_only, "zebra", 30)
        .await
        .unwrap_err()
        .to_string();
    assert!(undeclared.contains("[undeclared_need]"), "{undeclared}");
}

async fn declared_search_parity(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    query: &str,
    limit: i64,
) -> (Value, Value) {
    let params = json!({"query": query, "limit": limit});
    let read = declared_read(registry, db, event, "records.search.v1", params.clone())
        .await
        .unwrap();
    let mut own = call_as(registry, db, Caller::authenticated(ALICE), "search", params)
        .await
        .unwrap();
    own.as_object_mut().unwrap().remove("run_context");
    (read["result"].clone(), own)
}

#[tokio::test]
async fn declared_search_matches_empty_thin_and_capped_results() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    for (id, name) in [
        (
            "c1d00000-0000-4000-8000-000000000021",
            "Zebra crossing plan",
        ),
        (
            "c1d00000-0000-4000-8000-000000000023",
            "Zebra second crossing",
        ),
        (
            "c1d00000-0000-4000-8000-000000000024",
            "Zebra third crossing",
        ),
        (
            "c1d00000-0000-4000-8000-000000000025",
            "Zebra fourth crossing",
        ),
    ] {
        live_task(&registry, &db, id, name, "open").await;
        grant(&db, id, ALICE, Capability::View).await;
    }
    // One visible hit nests under a record Alice cannot see: the parent
    // redacts to null in her search, never to the hidden id.
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000022",
        "Zebra hidden from Alice",
        "open",
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000022",
        BEA,
        Capability::View,
    )
    .await;
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("UPDATE records SET home_id=? WHERE id=?")
        .bind("c1d00000-0000-4000-8000-000000000022")
        .bind("c1d00000-0000-4000-8000-000000000021")
        .execute(&pool)
        .await
        .unwrap();

    // No hits: guidance without matches, identical to her own search.
    let (read, own) =
        declared_search_parity(&registry, &db, &verified, "qqqzzz-no-such-thing", 30).await;
    assert_eq!(read, own);
    assert_eq!(read["hits"].as_array().unwrap().len(), 0);
    assert!(
        read["guidance"].as_str().unwrap().contains("No full-text"),
        "empty results name the miss: {}",
        read["guidance"]
    );

    // Capped: a full page names its cutoff exactly as her own search does.
    let (read, own) = declared_search_parity(&registry, &db, &verified, "zebra", 3).await;
    assert_eq!(read, own);
    assert_eq!(read["limit_reached"], true);
    assert!(read.get("guidance").is_some());

    // Thin: near misses and the hidden parent redact exactly as hers do.
    let (read, own) = declared_search_parity(&registry, &db, &verified, "zebra", 30).await;
    assert_eq!(read, own);
    assert!(read.get("near_misses").is_some());
    let hit = read["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hit| hit["id"] == "c1d00000-0000-4000-8000-000000000021")
        .unwrap();
    assert_eq!(hit["home_id"], Value::Null);
}

#[tokio::test]
async fn declared_reads_refuse_undeclared_unknown_and_out_of_bound_requests() {
    let (db, registry) = fixture().await;
    // Consents to search and to a need the host does not execute on request.
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": ["records.search.v1", "other.need.v1"], "effects": []}),
    )
    .await;
    let refusal = |result: native_ce::Result<Value>| result.unwrap_err().to_string();

    let undeclared = declared_read(
        &registry,
        &db,
        &verified,
        "records.resolve_reference.v1",
        json!({"reference": "abcdef1"}),
    )
    .await;
    assert!(refusal(undeclared).contains("undeclared_need"));
    let attention = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read", "package": "agent.search", "expected_install_event_id": verified,
        }),
    )
    .await;
    assert!(
        refusal(attention).contains("undeclared_need"),
        "search consent is not attention consent"
    );
    let unknown = declared_read(&registry, &db, &verified, "other.need.v1", json!({})).await;
    assert!(refusal(unknown).contains("unknown_need"));
    for params in [
        json!({"query": "zebra", "limit": 31}),
        json!({"query": "zebra", "limit": 0}),
        json!({"query": "   "}),
        json!({"query": "x".repeat(201)}),
        json!({"query": "zebra", "scope": "a1d00000-0000-4000-8000-000000000001"}),
        json!({"query": "zebra", "include_archived": true}),
        json!("zebra"),
    ] {
        let result = declared_read(
            &registry,
            &db,
            &verified,
            "records.search.v1",
            params.clone(),
        )
        .await;
        assert!(
            refusal(result).contains("invalid_params"),
            "{params} must be refused"
        );
    }
    let stale = declared_read(
        &registry,
        &db,
        "stale-event",
        "records.search.v1",
        json!({"query": "zebra"}),
    )
    .await;
    assert!(
        refusal(stale).contains("cas_mismatch"),
        "the shared gate chain still runs first"
    );
}

#[tokio::test]
async fn declared_reference_resolution_returns_display_fields_for_visible_records_only() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000031",
        "Alice can open this",
        "open",
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000032",
        "Only Bea can open this",
        "open",
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000031",
        ALICE,
        Capability::View,
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000032",
        BEA,
        Capability::View,
    )
    .await;

    let found = declared_read(
        &registry,
        &db,
        &verified,
        "records.resolve_reference.v1",
        json!({"reference": "c1d00000-0000-4000-8000-000000000031"}),
    )
    .await
    .unwrap();
    assert_eq!(
        found["result"],
        json!({"status": "found", "record": {
            "id": "c1d00000-0000-4000-8000-000000000031",
            "type": "WorkItem", "kind": "task", "name": "Alice can open this",
        }}),
        "display fields only: no body, children or links"
    );
    let hidden = declared_read(
        &registry,
        &db,
        &verified,
        "records.resolve_reference.v1",
        json!({"reference": "c1d00000-0000-4000-8000-000000000032"}),
    )
    .await
    .unwrap();
    assert_eq!(hidden["result"], json!({"status": "not_found"}));
}

#[tokio::test]
async fn declared_reference_projects_nullable_kind_like_get_record() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    // Historical rows may carry NULL kind, which `create_record` no longer
    // writes. Insert one directly: the declared read must project it exactly
    // as the viewer's own `get_record` does, not error on the NULL.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO records (id,type,kind,name) VALUES (?,'WorkItem',NULL,'Kindless record')",
    )
    .bind("d4d00000-0000-4000-8000-000000000051")
    .execute(&pool)
    .await
    .unwrap();
    grant(
        &db,
        "d4d00000-0000-4000-8000-000000000051",
        ALICE,
        Capability::View,
    )
    .await;

    let own = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "get_record",
        json!({"ids": ["d4d00000-0000-4000-8000-000000000051"], "children_limit": 0, "links_limit": 0}),
    )
    .await
    .unwrap();
    let record = &own["records"][0];
    assert_eq!(record["status"], "found");
    assert_eq!(record["kind"], Value::Null);

    let read = declared_read(
        &registry,
        &db,
        &verified,
        "records.resolve_reference.v1",
        json!({"reference": "d4d00000-0000-4000-8000-000000000051"}),
    )
    .await
    .unwrap();
    assert_eq!(
        read["result"],
        json!({"status": "found", "record": {
            "id": "d4d00000-0000-4000-8000-000000000051",
            "type": "WorkItem", "kind": null, "name": "Kindless record",
        }}),
        "nullable kind must project as null, exactly as get_record shows it"
    );
}

#[tokio::test]
async fn declared_reads_stop_on_disable_remove_and_lost_access() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    let search = json!({"query": "zebra"});

    // Losing View on the artifact refuses the read, and restoring it
    // restores the read: authority is checked per request.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(BEA, Capability::View)],
    )
    .await
    .unwrap();
    let lost = declared_read(
        &registry,
        &db,
        &verified,
        "records.search.v1",
        search.clone(),
    )
    .await;
    assert!(lost.unwrap_err().to_string().contains("[unauthorized]"));
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(ALICE, Capability::View)],
    )
    .await
    .unwrap();
    declared_read(
        &registry,
        &db,
        &verified,
        "records.search.v1",
        search.clone(),
    )
    .await
    .unwrap();

    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.search",
            "expected_install_event_id": verified, "reason": "Stop the search tab.",
        }),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = declared_read(
        &registry,
        &db,
        &disabled_event,
        "records.search.v1",
        search.clone(),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("[disabled]"));

    let removed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.search",
            "expected_install_event_id": disabled_event, "reason": "Remove the search tab.",
        }),
    )
    .await
    .unwrap();
    let removed_event = removed["install"]["event_id"].as_str().unwrap();
    let refused = declared_read(&registry, &db, removed_event, "records.search.v1", search).await;
    assert!(refused.unwrap_err().to_string().contains("[removed]"));
}

/// Tab reads run on the read-only pool (task `9be4011`): with another
/// connection holding SQLite's single writer lock, every read action —
/// snapshot, a SQL need, both search host needs, list and inspect — still
/// answers promptly, where a `BEGIN IMMEDIATE` gate would wait out the
/// writer. Once the writer lets go, the read-pool gates see each committed
/// transition: lost View, a stale token, and a disable.
#[tokio::test]
async fn tab_reads_complete_while_the_writer_is_held() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": [
            "attention.query.v1",
            SEARCH_NEEDS[0],
            SEARCH_NEEDS[1],
            sql_need("lane.count", "Count", "SELECT count(*) AS n FROM records WHERE deleted_at IS NULL"),
        ], "effects": []}),
    )
    .await;
    let prompt = std::time::Duration::from_secs(5);
    let reads = [
        ("records.search.v1", json!({"query": "zebra"})),
        (
            "records.resolve_reference.v1",
            json!({"reference": ARTIFACT_A}),
        ),
        ("lane.count", json!({})),
    ];

    let writer_pool = crate::common::fixture_write_pool(&db).await;
    let mut writer = writer_pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .unwrap();
    let snapshot = tokio::time::timeout(
        prompt,
        sql_snapshot(&registry, &db, ALICE, "agent.search", &verified),
    )
    .await
    .expect("the snapshot read waited on the writer")
    .unwrap();
    assert_eq!(snapshot["install_event_id"], json!(verified));
    for (need, params) in &reads {
        let read = tokio::time::timeout(
            prompt,
            declared_read(&registry, &db, &verified, need, params.clone()),
        )
        .await
        .unwrap_or_else(|_| panic!("{need} waited on the writer"))
        .unwrap();
        assert_eq!(read["need"], json!(need));
        assert_eq!(read["install_event_id"], json!(verified));
    }
    for action in [
        json!({"action": "list"}),
        json!({"action": "inspect", "package": "agent.search"}),
    ] {
        tokio::time::timeout(
            prompt,
            call_as(
                &registry,
                &db,
                Caller::authenticated(ALICE),
                "manage_alpha_tabs",
                action.clone(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{action} waited on the writer"))
        .unwrap();
    }
    sqlx::query("ROLLBACK").execute(&mut *writer).await.unwrap();
    drop(writer);

    let refused = |result: native_ce::Result<Value>, code: &str| {
        let error = result.unwrap_err().to_string();
        assert!(error.contains(&format!("[{code}]")), "{error}");
    };
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    for (need, params) in &reads {
        refused(
            declared_read(&registry, &db, &verified, need, params.clone()).await,
            "unauthorized",
        );
    }
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    for (need, params) in &reads {
        declared_read(&registry, &db, &verified, need, params.clone())
            .await
            .unwrap();
    }
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.search",
            "expected_install_event_id": verified, "reason": "Stop the search tab.",
        }),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"].as_str().unwrap();
    for (need, params) in &reads {
        refused(
            declared_read(&registry, &db, &verified, need, params.clone()).await,
            "cas_mismatch",
        );
        refused(
            declared_read(&registry, &db, disabled_event, need, params.clone()).await,
            "disabled",
        );
    }
}

/// The gate cache (task `9be4011`) keeps only the immutable half of the gate
/// chain, for a SQL need, a host need and the snapshot.
///
/// Warm hits, with the entry held for the event being read: lost View, a
/// runtime change, and undeclared needs (a host name and a SQL-shaped name)
/// still refuse. Cache misses, shown so a cached pass cannot leak: a pin
/// edited in place no longer matches the entry and the full chain refuses;
/// disable and remove write a new install event, so the old token refuses on
/// CAS and the new one on its status.
#[tokio::test]
async fn warm_gate_cache_keeps_per_request_refusals() {
    use native_ce::mcp::tools::alpha_tabs::gate_cache_holds;

    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": [
            "attention.query.v1",
            SEARCH_NEEDS[0],
            sql_need("lane.count", "Count", "SELECT count(*) AS n FROM records WHERE deleted_at IS NULL"),
        ], "effects": []}),
    )
    .await;
    let reads = [
        ("records.search.v1", json!({"query": "zebra"})),
        ("lane.count", json!({})),
    ];
    let refused = |result: native_ce::Result<Value>, code: &str| {
        let error = result.unwrap_err().to_string();
        assert!(error.contains(&format!("[{code}]")), "{error}");
    };
    let all_refuse = |event: String, code: &'static str| {
        let (db, registry) = (db.clone(), &registry);
        let reads = reads.clone();
        async move {
            for (need, params) in reads {
                refused(
                    declared_read(registry, &db, &event, need, params).await,
                    code,
                );
            }
            refused(
                sql_snapshot(registry, &db, ALICE, "agent.search", &event).await,
                code,
            );
        }
    };
    let all_pass = |event: String| {
        let (db, registry) = (db.clone(), &registry);
        let reads = reads.clone();
        async move {
            for (need, params) in reads {
                declared_read(registry, &db, &event, need, params)
                    .await
                    .unwrap();
            }
            sql_snapshot(registry, &db, ALICE, "agent.search", &event)
                .await
                .unwrap();
        }
    };
    let pool = crate::common::fixture_write_pool(&db).await;

    all_pass(verified.clone()).await;
    assert!(gate_cache_holds(&db, ALICE, "agent.search", &verified));

    // Declaration membership is checked after a warm hit: a host need the
    // install did not declare, and a name that is no declared SQL key.
    for (need, params) in [
        (
            "records.resolve_reference.v1",
            json!({"reference": ARTIFACT_A}),
        ),
        ("lane.missing", json!({})),
    ] {
        refused(
            declared_read(&registry, &db, &verified, need, params).await,
            "undeclared_need",
        );
    }
    assert!(gate_cache_holds(&db, ALICE, "agent.search", &verified));

    // Authority is per request: losing View refuses on a warm entry.
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    all_refuse(verified.clone(), "unauthorized").await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    all_pass(verified.clone()).await;

    // The runtime facet changes without a new install event; the warm entry
    // stays, and the runtime is still read every time.
    sqlx::query("UPDATE facet_values SET value='native.html.artifact.v2' WHERE record_id=? AND key='runtime'")
        .bind(ARTIFACT_A)
        .execute(&pool)
        .await
        .unwrap();
    assert!(gate_cache_holds(&db, ALICE, "agent.search", &verified));
    all_refuse(verified.clone(), "not_renderable").await;
    sqlx::query(
        "UPDATE facet_values SET value='native.html.v1' WHERE record_id=? AND key='runtime'",
    )
    .bind(ARTIFACT_A)
    .execute(&pool)
    .await
    .unwrap();
    all_pass(verified.clone()).await;

    // Cache miss: a pin edited in place under the same install event no
    // longer matches the entry, so the full chain runs and refuses.
    let pinned: String = sqlx::query_scalar(
        "SELECT digest FROM alpha_tab_installs WHERE account_id=? AND package=?",
    )
    .bind(ALICE)
    .bind("agent.search")
    .fetch_one(&pool)
    .await
    .unwrap();
    let set_digest = |digest: String| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE alpha_tab_installs SET digest=? WHERE account_id=? AND package=?")
                .bind(digest)
                .bind(ALICE)
                .bind("agent.search")
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    set_digest(format!("sha256:{}", "0".repeat(64))).await;
    all_refuse(verified.clone(), "digest_mismatch").await;
    set_digest(pinned).await;
    all_pass(verified.clone()).await;

    // Cache miss: control transitions write a new install event, so the
    // entry for the old event cannot vouch for it. The old token refuses on
    // CAS before any lookup, and the new event on its status.
    let transition = |action: &'static str, event: String| {
        let (db, registry) = (db.clone(), &registry);
        async move {
            let changed = call_as(
                registry,
                &db,
                Caller::authenticated(ALICE),
                "manage_alpha_tabs",
                json!({
                    "action": action, "package": "agent.search",
                    "expected_install_event_id": event, "reason": "Change the search tab.",
                }),
            )
            .await
            .unwrap();
            changed["install"]["event_id"].as_str().unwrap().to_string()
        }
    };
    let disabled = transition("disable", verified.clone()).await;
    assert!(gate_cache_holds(&db, ALICE, "agent.search", &verified));
    all_refuse(verified.clone(), "cas_mismatch").await;
    all_refuse(disabled.clone(), "disabled").await;
    let removed = transition("remove", disabled.clone()).await;
    all_refuse(disabled, "cas_mismatch").await;
    all_refuse(removed, "removed").await;
}

// Batched on-request reads (task `9be4011`, slice 3): `live_read` with
// `reads: [{need, params?}]`.

fn batch_declaration() -> Value {
    json!({"needs": [
        "attention.query.v1",
        SEARCH_NEEDS[0],
        SEARCH_NEEDS[1],
        "canvas.scene.v1",
        "surface.reveal.v1",
        sql_need("lane.count", "Count", "SELECT count(*) AS n FROM records WHERE deleted_at IS NULL"),
        param_need("lane.by_id", "By id", PARAM_BY_ID_SQL,
            json!([{"name": "record_id", "type": "text", "max_len": 64}])),
        // Valid at install, and fails at execution for exactly one value:
        // `abs` of the smallest 64-bit integer overflows.
        param_need("lane.abs", "Abs", "SELECT abs(?1) AS n",
            json!([{"name": "value", "type": "integer"}])),
    ], "effects": []})
}

async fn batch_read(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    reads: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.search",
            "expected_install_event_id": event,
            "reads": reads,
        }),
    )
    .await
}

/// A single read's answer as a batch item carries it: the registry adds
/// `run_context` to the top level of every tool response, so only the
/// batch's own top level has it.
fn as_item(mut single: Value) -> Value {
    single.as_object_mut().unwrap().remove("run_context");
    single
}

fn batch_items(items: &[(&str, Value)]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|(need, params)| json!({"need": need, "params": params}))
            .collect(),
    )
}

/// Every item of a batch, host and SQL needs mixed, answers in request
/// order with exactly the body its single read returns, and the batch
/// carries the install pin once at the top.
#[tokio::test]
async fn batched_read_answers_each_item_like_its_single_read() {
    let (db, registry) = fixture().await;
    let event = adopted_with_declaration(&registry, &db, batch_declaration()).await;
    scene_fixture(&registry, &db).await;
    let items = [
        ("lane.count", json!({})),
        ("records.search.v1", json!({"query": "zebra"})),
        ("lane.by_id", json!({"record_id": ARTIFACT_A})),
        (
            "records.resolve_reference.v1",
            json!({"reference": ARTIFACT_A}),
        ),
        ("canvas.scene.v1", json!({"canvas_id": SCENE_CANVAS})),
        ("lane.count", json!({})),
    ];
    let batch = batch_read(&registry, &db, &event, batch_items(&items))
        .await
        .unwrap();
    assert_eq!(batch["install_event_id"], json!(event));
    assert_eq!(batch["pin"]["artifact_id"], json!(ARTIFACT_A));
    let results = batch["results"].as_array().unwrap();
    assert_eq!(results.len(), items.len());
    for (result, (need, params)) in results.iter().zip(&items) {
        assert_eq!(result["need"], json!(need));
        let single = declared_read(&registry, &db, &event, need, params.clone())
            .await
            .unwrap();
        assert_eq!(result["ok"], as_item(single), "{need}");
    }

    // The snapshot is an item too, answered as a need-less read answers it.
    let batch = batch_read(
        &registry,
        &db,
        &event,
        json!([{"need": "attention.query.v1"}]),
    )
    .await
    .unwrap();
    let single = sql_snapshot(&registry, &db, ALICE, "agent.search", &event)
        .await
        .unwrap();
    assert_eq!(batch["results"][0]["ok"], as_item(single));
}

/// A refusal or failure of one item is reported against that item, with the
/// code and message its single read would refuse with, beside the others'
/// answers.
#[tokio::test]
async fn batched_read_reports_item_errors_beside_successes() {
    let (db, registry) = fixture().await;
    let event = adopted_with_declaration(&registry, &db, batch_declaration()).await;
    let items = [
        ("lane.count", json!({}), None),
        (
            "records.search.v1",
            json!({"query": ""}),
            Some("invalid_params"),
        ),
        (
            "records.changes.v1",
            json!({"record_id": ARTIFACT_A}),
            Some("undeclared_need"),
        ),
        ("surface.reveal.v1", json!({}), Some("undeclared_need")),
        ("lane.by_id", json!({"nope": 1}), Some("unknown_sql_param")),
        ("lane.missing", json!({}), Some("undeclared_need")),
        (
            "records.resolve_reference.v1",
            json!({"reference": ARTIFACT_A}),
            None,
        ),
    ];
    let reads: Vec<(&str, Value)> = items
        .iter()
        .map(|(need, params, _)| (*need, params.clone()))
        .collect();
    let batch = batch_read(&registry, &db, &event, batch_items(&reads))
        .await
        .unwrap();
    let results = batch["results"].as_array().unwrap();
    assert_eq!(results.len(), items.len());
    for (result, (need, params, code)) in results.iter().zip(&items) {
        assert_eq!(result["need"], json!(need));
        let single = declared_read(&registry, &db, &event, need, params.clone()).await;
        match code {
            None => assert_eq!(result["ok"], as_item(single.unwrap()), "{need}"),
            Some(code) => {
                assert_eq!(result["error"]["code"], json!(code), "{need}: {result}");
                assert_eq!(
                    result["error"]["message"],
                    json!(single.unwrap_err().to_string()),
                    "{need}"
                );
                assert!(result.get("ok").is_none());
            }
        }
    }
    // A snapshot item takes no params, as a need-less read takes none.
    let batch = batch_read(
        &registry,
        &db,
        &event,
        json!([{"need": "attention.query.v1", "params": {}}]),
    )
    .await
    .unwrap();
    assert_eq!(batch["results"][0]["error"]["code"], "invalid_params");
}

/// A SQL item that fails at execution is reported alone. The SQL items after
/// it run on a fresh governed transaction and answer as their single reads.
#[tokio::test]
async fn batched_read_isolates_a_failing_sql_item() {
    let (db, registry) = fixture().await;
    let event = adopted_with_declaration(&registry, &db, batch_declaration()).await;
    let overflow = json!({"value": i64::MIN});
    let single = declared_read(&registry, &db, &event, "lane.abs", overflow.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(single.contains("[sql_need_failed]"), "{single}");
    let items = [
        ("lane.abs", overflow),
        ("lane.count", json!({})),
        ("lane.abs", json!({"value": -5})),
        ("lane.by_id", json!({"record_id": ARTIFACT_A})),
    ];
    let batch = batch_read(&registry, &db, &event, batch_items(&items))
        .await
        .unwrap();
    let results = batch["results"].as_array().unwrap();
    assert_eq!(results[0]["error"]["code"], "sql_need_failed");
    assert_eq!(results[0]["error"]["message"], json!(single));
    for (result, (need, params)) in results.iter().zip(&items).skip(1) {
        let single = declared_read(&registry, &db, &event, need, params.clone())
            .await
            .unwrap();
        assert_eq!(result["ok"], as_item(single), "{need}");
    }
    assert_eq!(results[2]["ok"]["result"]["rows"][0]["n"], 5);
}

/// A gate refusal is about the install, not an item: it fails the whole
/// batch exactly as it fails a single read.
#[tokio::test]
async fn batched_read_gate_refusal_fails_the_whole_call() {
    let (db, registry) = fixture().await;
    let event = adopted_with_declaration(&registry, &db, batch_declaration()).await;
    let reads = batch_items(&[
        ("lane.count", json!({})),
        ("records.search.v1", json!({"query": "zebra"})),
    ]);
    let refused = |result: native_ce::Result<Value>, code: &str| {
        let error = result.unwrap_err().to_string();
        assert!(error.contains(&format!("[{code}]")), "{error}");
    };
    refused(
        batch_read(&registry, &db, "not-the-install-event", reads.clone()).await,
        "cas_mismatch",
    );
    grant(&db, ARTIFACT_A, BEA, Capability::View).await;
    refused(
        batch_read(&registry, &db, &event, reads.clone()).await,
        "unauthorized",
    );
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    batch_read(&registry, &db, &event, reads.clone())
        .await
        .unwrap();
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.search",
            "expected_install_event_id": event, "reason": "Stop the search tab.",
        }),
    )
    .await
    .unwrap();
    let disabled = disabled["install"]["event_id"].as_str().unwrap();
    refused(
        batch_read(&registry, &db, disabled, reads).await,
        "disabled",
    );
}

/// The batch holds 1..=16 items and excludes the single-read fields.
#[tokio::test]
async fn batched_read_refuses_bad_batches_before_the_gate() {
    let (db, registry) = fixture().await;
    let event = adopted_with_declaration(&registry, &db, batch_declaration()).await;
    let item = json!({"need": "lane.count"});
    let full = batch_read(&registry, &db, &event, json!(vec![item.clone(); 16]))
        .await
        .unwrap();
    assert_eq!(full["results"].as_array().unwrap().len(), 16);
    for reads in [json!(vec![item.clone(); 17]), json!([])] {
        let error = batch_read(&registry, &db, &event, reads)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("1..=16"), "{error}");
        assert!(error.contains("[invalid_params]"), "{error}");
    }
    for extra in [
        json!({"need": "lane.count"}),
        json!({"params": {}}),
        json!({"if_revision": "r"}),
        json!({"watch": {"stream": "s", "subscription": "i"}}),
    ] {
        let mut args = json!({
            "action": "live_read", "package": "agent.search",
            "expected_install_event_id": event, "reads": [item.clone()],
        });
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        let error = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            args,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("[invalid_params]"), "{extra}: {error}");
    }
    // The cap is checked before the gate: a stale token still names the cap.
    let error = batch_read(&registry, &db, "stale", json!(vec![item; 17]))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("1..=16"), "{error}");
}

#[tokio::test]
async fn declared_reference_resolution_handles_short_ambiguous_and_absent_references() {
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    for id in [
        "e7e70000-0000-4000-8000-000000000041",
        "e7e70000-0000-4000-8000-000000000042",
    ] {
        live_task(&registry, &db, id, "Shared prefix", "open").await;
        grant(&db, id, ALICE, Capability::View).await;
    }
    live_task(
        &registry,
        &db,
        "e7e71111-0000-4000-8000-000000000043",
        "Unique prefix",
        "open",
    )
    .await;
    grant(
        &db,
        "e7e71111-0000-4000-8000-000000000043",
        ALICE,
        Capability::View,
    )
    .await;

    let resolve = |reference: &str| {
        declared_read(
            &registry,
            &db,
            &verified,
            "records.resolve_reference.v1",
            json!({"reference": reference}),
        )
    };
    let ambiguous = resolve("e7e70000").await.unwrap();
    assert_eq!(ambiguous["result"]["status"], "ambiguous");
    let mut candidates: Vec<String> = ambiguous["result"]["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect();
    candidates.sort();
    assert_eq!(
        candidates,
        vec![
            "e7e70000-0000-4000-8000-000000000041".to_string(),
            "e7e70000-0000-4000-8000-000000000042".to_string(),
        ]
    );
    let short = resolve("e7e711").await.unwrap();
    assert_eq!(short["result"]["status"], "found");
    assert_eq!(
        short["result"]["record"]["id"],
        "e7e71111-0000-4000-8000-000000000043"
    );
    // Records Alpha cannot see are indistinguishable from absent ones, by
    // exact id and by a prefix that matches only them.
    live_task(
        &registry,
        &db,
        "e7e72222-0000-4000-8000-000000000044",
        "Hidden from Alice",
        "open",
    )
    .await;
    grant(
        &db,
        "e7e72222-0000-4000-8000-000000000044",
        BEA,
        Capability::View,
    )
    .await;
    for absent in [
        "e7e7ffff-0000-4000-8000-000000000099",
        "abcdef9",
        "e7e72222-0000-4000-8000-000000000044",
        "e7e722",
    ] {
        let answer = resolve(absent).await.unwrap();
        assert_eq!(
            answer["result"],
            json!({"status": "not_found"}),
            "an absent reference is not_found, not an error: {absent}"
        );
    }
}

#[tokio::test]
async fn declared_reference_rechecks_the_install_inside_its_own_read() {
    use native_ce::mcp::tools::alpha_tabs::resolve_reference_read;
    let (db, registry) = fixture().await;
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-000000000031",
        "Alice can open this",
        "open",
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-000000000031",
        ALICE,
        Capability::View,
    )
    .await;
    let alice = Caller::authenticated(ALICE);
    // Called directly, with no outer gate in front of it: the read answers
    // only for the installation that holds in its own snapshot.
    let inner = |event: String| {
        let (db, alice) = (db.clone(), alice.clone());
        async move {
            resolve_reference_read(
                &db,
                &alice,
                "agent.search",
                &event,
                "c1d00000-0000-4000-8000-000000000031",
            )
            .await
        }
    };
    // The production path serves the same answer through the recheck.
    let public = declared_read(
        &registry,
        &db,
        &verified,
        "records.resolve_reference.v1",
        json!({"reference": "c1d00000-0000-4000-8000-000000000031"}),
    )
    .await
    .unwrap();
    assert_eq!(public["result"], inner(verified.clone()).await.unwrap());

    // The viewer loses the tab's artifact: the read refuses on its own.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(BEA, Capability::View)],
    )
    .await
    .unwrap();
    let lost = inner(verified.clone()).await.unwrap_err().to_string();
    assert!(lost.contains("[unauthorized]"), "{lost}");
    adopt_fixture_artifact_policy(&db).await;
    inner(verified.clone()).await.unwrap();

    // The install is replaced by a disable: the generation the read was
    // asked for is gone, and the new one is not live.
    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.search",
            "expected_install_event_id": verified, "reason": "Stop the search tab.",
        }),
    )
    .await
    .unwrap();
    let stale = inner(verified.clone()).await.unwrap_err().to_string();
    assert!(stale.contains("[cas_mismatch]"), "{stale}");
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = inner(disabled_event).await.unwrap_err().to_string();
    assert!(refused.contains("[disabled]"), "{refused}");

    // An install whose consent never named the need cannot read with it.
    let search_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.resolve-only",
        json!({"needs": ["records.search.v1"], "effects": []}),
    )
    .await;
    let undeclared = resolve_reference_read(
        &db,
        &alice,
        "agent.resolve-only",
        &search_only,
        "c1d00000-0000-4000-8000-000000000031",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(undeclared.contains("[undeclared_need]"), "{undeclared}");
}

// Package-declared fixed SQL snapshot needs (task `421f867`): a `needs[]`
// entry may be `{"need":"sql.snapshot.v1","key","label","sql"}`. The
// snapshot `live_read` runs every declared snapshot need through the
// ordinary `query_sql` handler under the viewer's authority, so parity and
// access hold by construction. The three statements below are the real Ready
// lanes from `experiments/demo-shell/public/lib/projections.js`.

const READY_UNBLOCKED_SQL: &str = "SELECT w.id, w.name, MAX(b.last_activity_at) at, COUNT(*) deps, SUM(b.lifecycle = 'completed') done
  FROM links l
  JOIN records w ON w.id = l.source_id
  JOIN records b ON b.id = l.target_id
  WHERE l.relationship = 'depends_on'
    AND w.deleted_at IS NULL AND b.deleted_at IS NULL
    AND w.lifecycle IN ('open','in_progress','blocked')
  GROUP BY w.id, w.name HAVING deps = done
  ORDER BY at DESC LIMIT 40";

const READY_STALLED_SQL: &str = "SELECT id, name, last_activity_at at FROM records WHERE deleted_at IS NULL AND lifecycle = 'in_progress' AND last_activity_at_ms < now_ms() - 604800000 ORDER BY last_activity_at_ms DESC, id ASC LIMIT 40";

const READY_PROPOSED_SQL: &str = "SELECT id, name, last_activity_at at FROM records
  WHERE deleted_at IS NULL AND maturity = 'proposed' AND lifecycle = 'open'
  ORDER BY last_activity_at DESC LIMIT 40";

pub(crate) fn sql_need(key: &str, label: &str, sql: &str) -> Value {
    json!({"need": "sql.snapshot.v1", "key": key, "label": label, "sql": sql})
}

fn ready_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            sql_need("ready.unblocked", "Unblocked", READY_UNBLOCKED_SQL),
            sql_need("ready.stalled", "Stalled", READY_STALLED_SQL),
            sql_need("ready.proposed", "Proposed", READY_PROPOSED_SQL),
        ],
        "effects": [],
    })
}

// M1 slice 1: a clock-bearing need uses `now_ms()` as a row predicate, not
// as selected output — so its rows are stable across clock ticks while its
// evaluation is genuinely time-dependent. (A need selecting `now_ms()` as a
// column would move its own digest every tick, by construction: the digest
// covers rows.)
pub(crate) const CLOCK_SQL: &str = "SELECT id, name, last_activity_at_ms FROM records WHERE deleted_at IS NULL AND lifecycle = 'in_progress' AND last_activity_at_ms < now_ms() ORDER BY id ASC LIMIT 40";

pub(crate) fn clock_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            sql_need("ready.unblocked", "Unblocked", READY_UNBLOCKED_SQL),
            sql_need("lane.clock", "Clock", CLOCK_SQL),
        ],
        "effects": [],
    })
}

// M1 slice 1 (review repair): a second clock-bearing need over a different
// predicate, so the snapshot stamp is the maximum of two statement clocks.
const CLOCK_SQL_B: &str = "SELECT id, name, created_at_ms FROM records WHERE deleted_at IS NULL AND lifecycle = 'open' AND created_at_ms < now_ms() ORDER BY id ASC LIMIT 40";

fn two_clock_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            sql_need("lane.clock", "Clock", CLOCK_SQL),
            sql_need("lane.clock_b", "Clock B", CLOCK_SQL_B),
        ],
        "effects": [],
    })
}

/// Install, preview and adopt `package` for `account` under `declaration`.
/// The fixture artifact must already exist (call `adopt_fixture_artifact`
/// once); the digest is recomputed the same way the host does, so a SQL
/// declaration binds its statements at adoption.
pub(crate) async fn adopted_with_package(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    package: &str,
    declaration: Value,
) -> String {
    use native_ce::mcp::tools::alpha_tabs::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    };
    let source_revision = preview_source_revision(db, ARTIFACT_A).await;
    let digest = alpha_tab_digest(
        &alpha_tab_bundle_digest(PREVIEW_BODY),
        &alpha_tab_declaration_digest(&declaration).unwrap(),
        "native.html.v1",
    );
    let pin = json!({
        "package": package, "version": "0.1.0", "digest": digest,
        "artifact_id": ARTIFACT_A, "source_revision": source_revision,
        "declaration": declaration,
    });
    let with = |action: &str, reason: &str| {
        let mut args = pin.clone();
        args["action"] = json!(action);
        args["reason"] = json!(reason);
        args
    };
    let installed = call_as(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        with("install", "Install a Ready SQL package."),
    )
    .await
    .unwrap();
    let event_id = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let preview = with("preview", "Preview a Ready SQL package.");
    let previewed = call_as(
        registry,
        db,
        attested_preview_caller(account, &preview),
        "manage_alpha_tabs",
        preview,
    )
    .await
    .unwrap();
    let mut adopt = with("adopt", "Adopt a Ready SQL package.");
    adopt["receipt_id"] = previewed["receipt"]["receipt_id"].clone();
    adopt["nonce"] = previewed["receipt"]["nonce"].clone();
    adopt["preview_session"] = previewed["receipt"]["preview_session"].clone();
    adopt["expected_install_event_id"] = json!(event_id);
    let adopted = call_as(
        registry,
        db,
        attested_adopt_caller(account, &adopt),
        "manage_alpha_tabs",
        adopt,
    )
    .await
    .unwrap();
    assert_eq!(adopted["install"]["adoption"], "shell_adopt.v1");
    adopted["install"]["event_id"].as_str().unwrap().to_string()
}

async fn sql_snapshot(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    package: &str,
    event: &str,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": package,
            "expected_install_event_id": event,
        }),
    )
    .await
}

async fn direct_sql(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    sql: &str,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "query_sql",
        json!({"sql": sql}),
    )
    .await
}

async fn ready_task(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    name: &str,
    lifecycle: &str,
    maturity: Option<&str>,
    links: Option<Value>,
) {
    let mut args = json!({
        "id": id, "type": "WorkItem", "kind": "task",
        "name": name, "body": name, "lifecycle": lifecycle,
        "reason": "Ready snapshot fixture."
    });
    if let Some(maturity) = maturity {
        args["maturity"] = json!(maturity);
    }
    if let Some(links) = links {
        args["links"] = links;
    }
    registry
        .call(db.clone(), Caller::local(), "create_record", args)
        .await
        .unwrap();
}

#[tokio::test]
async fn sql_snapshot_matches_direct_query_sql_for_two_viewers() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // UNBLOCKED lane: open work whose only blocker is completed.
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000b1",
        "Finished blocker",
        "completed",
        None,
        None,
    )
    .await;
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000a1",
        "Newly unblocked",
        "open",
        None,
        Some(json!([{"target_id": "d1d00000-0000-4000-8000-0000000000b1", "relationship": "depends_on"}])),
    )
    .await;
    // STALLED lane: in_progress but untouched for over seven days.
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000a2",
        "Quiet for weeks",
        "in_progress",
        None,
        None,
    )
    .await;
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("UPDATE records SET last_activity_at='2020-01-01T00:00:00Z' WHERE id=?")
        .bind("d1d00000-0000-4000-8000-0000000000a2")
        .execute(&pool)
        .await
        .unwrap();
    // PROPOSED lane, split across viewers: Alice-only, Bea-only, shared.
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000a3",
        "Alice proposal",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000a4",
        "Bea proposal",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000a5",
        "Shared proposal",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    for id in [
        "d1d00000-0000-4000-8000-0000000000b1",
        "d1d00000-0000-4000-8000-0000000000a1",
        "d1d00000-0000-4000-8000-0000000000a2",
        "d1d00000-0000-4000-8000-0000000000a5",
    ] {
        // One policy write naming both viewers: `grant` replaces the
        // record's policy, so two sequential grants would leave only Bea.
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![
                AllowEntry::account(ALICE, Capability::View),
                AllowEntry::account(BEA, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    grant(
        &db,
        "d1d00000-0000-4000-8000-0000000000a3",
        ALICE,
        Capability::View,
    )
    .await;
    grant(
        &db,
        "d1d00000-0000-4000-8000-0000000000a4",
        BEA,
        Capability::View,
    )
    .await;
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.ready", ready_declaration()).await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.ready", ready_declaration()).await;
    for (account, event) in [(ALICE, alice_event.as_str()), (BEA, bea_event.as_str())] {
        let snapshot = sql_snapshot(&registry, &db, account, "agent.ready", event)
            .await
            .unwrap();
        // Attention rows ride alongside the SQL snapshot, unchanged shape.
        assert!(snapshot["input"]["records"].is_array());
        assert!(snapshot["input"]["inputs"].as_object().unwrap().is_empty());
        let sql = &snapshot["input"]["sql"];
        for (key, text) in [
            ("ready.unblocked", READY_UNBLOCKED_SQL),
            ("ready.stalled", READY_STALLED_SQL),
            ("ready.proposed", READY_PROPOSED_SQL),
        ] {
            let direct = direct_sql(&registry, &db, account, text).await.unwrap();
            assert_eq!(
                sql[key]["columns"], direct["columns"],
                "{account} {key} columns"
            );
            assert_eq!(sql[key]["rows"], direct["rows"], "{account} {key} rows");
            assert_eq!(
                sql[key]["row_count"], direct["row_count"],
                "{account} {key} row_count"
            );
            assert_eq!(
                sql[key]["truncated"], direct["truncated"],
                "{account} {key} truncated"
            );
        }
        // The caller-relative `as_of_seq` never leaves the host in this path.
        assert!(sql["ready.proposed"].get("as_of_seq").is_none());
        assert!(snapshot.to_string().find("as_of_seq").is_none());
    }
    // Access splits the viewers: each sees her own proposal plus the shared
    // one, never the other's.
    let alice = sql_snapshot(&registry, &db, ALICE, "agent.ready", &alice_event)
        .await
        .unwrap();
    let bea = sql_snapshot(&registry, &db, BEA, "agent.ready", &bea_event)
        .await
        .unwrap();
    let names = |snapshot: &Value| {
        snapshot["input"]["sql"]["ready.proposed"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let mut alice_names = names(&alice);
    let mut bea_names = names(&bea);
    alice_names.sort();
    bea_names.sort();
    assert_eq!(
        alice_names,
        vec!["Alice proposal".to_string(), "Shared proposal".to_string()]
    );
    assert_eq!(
        bea_names,
        vec!["Bea proposal".to_string(), "Shared proposal".to_string()]
    );
    // The shared lanes agree where access does.
    assert_eq!(
        alice["input"]["sql"]["ready.unblocked"],
        bea["input"]["sql"]["ready.unblocked"]
    );
}

// Bylines for authored tabs (task b1c8a94): the caller-relative `actors`
// relation reaches a tab through an ordinary `sql.snapshot.v1` need, with no
// host-named need. Each viewer's snapshot equals her own direct `query_sql`.
// The directory lists only members who acted where the viewer can see it
// (decision 0052432, Q-b1): a visible person who never acted is absent, an
// actor whose person is hidden from a viewer never appears for her, and a
// viewer with no person binding sees her own row with no identity.
const ACTORS_SQL: &str =
    "SELECT actor, person_id, display_name FROM actors ORDER BY actor LIMIT 200";

#[tokio::test]
async fn sql_snapshot_reads_the_actors_directory_for_two_viewers() {
    const SHARED: &str = "d1d0ac70-0000-4000-8000-000000000000";
    const P_ALICE: &str = "d1d0ac70-0000-4000-8000-000000000001";
    const P_NORA: &str = "d1d0ac70-0000-4000-8000-000000000002";
    const P_HARRIET: &str = "d1d0ac70-0000-4000-8000-000000000003";
    const HARRIET: &str = "account:harriet";
    const NORA: &str = "account:nora";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let pool = crate::common::fixture_write_pool(&db).await;
    // Bea has no person binding: her identity is unknown to everyone.
    for (id, name, account, viewers) in [
        (SHARED, "Shared note", None, vec![ALICE, BEA]),
        (P_ALICE, "Alice Person", Some(ALICE), vec![ALICE, BEA]),
        (P_NORA, "Nora Never", Some(NORA), vec![ALICE, BEA]),
        (P_HARRIET, "Harriet Hidden", Some(HARRIET), vec![ALICE]),
    ] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id, "type": "Entity", "kind": "person",
                    "name": name, "reason": "Actors directory fixture.",
                }),
            )
            .await
            .unwrap();
        if let Some(account) = account {
            sqlx::query(
                "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
            )
            .bind(id)
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            viewers
                .into_iter()
                .map(|viewer| AllowEntry::account(viewer, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
    }
    // Alice, Bea and Harriet act on the shared note. Nora never acts.
    for actor in [ALICE, BEA, HARRIET] {
        sqlx::query(
            "INSERT INTO content_events
                (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
             VALUES ('actors-tab-' || ?, ?, 'record.updated', '{}', ?,
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 'legacy_unknown')",
        )
        .bind(actor)
        .bind(SHARED)
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();
    }
    let declaration = json!({
        "needs": [sql_need("people.actors", "Actors", ACTORS_SQL)],
        "effects": [],
    });
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.actors", declaration.clone()).await;
    let bea_event = adopted_with_package(&registry, &db, BEA, "agent.actors", declaration).await;
    let mut delivered = Vec::new();
    for (account, event) in [(ALICE, alice_event.as_str()), (BEA, bea_event.as_str())] {
        let snapshot = sql_snapshot(&registry, &db, account, "agent.actors", event)
            .await
            .unwrap();
        let rows = snapshot["input"]["sql"]["people.actors"].clone();
        let direct = direct_sql(&registry, &db, account, ACTORS_SQL)
            .await
            .unwrap();
        assert_eq!(rows["columns"], direct["columns"], "{account} columns");
        assert_eq!(rows["rows"], direct["rows"], "{account} rows");
        assert_eq!(rows["truncated"], json!(false), "{account} truncated");
        assert!(snapshot.to_string().find("as_of_seq").is_none());
        delivered.push((account, snapshot, rows["rows"].clone()));
    }
    let names = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["actor"].as_str().unwrap().to_string(),
                    row["person_id"].as_str().map(str::to_string),
                    row["display_name"].as_str().map(str::to_string),
                )
            })
            .collect::<Vec<_>>()
    };
    let named = |actor: &str, person: &str, name: &str| {
        (
            actor.to_string(),
            Some(person.to_string()),
            Some(name.to_string()),
        )
    };
    assert_eq!(
        names(&delivered[0].2),
        [
            named(HARRIET, P_HARRIET, "Harriet Hidden"),
            named(ALICE, P_ALICE, "Alice Person"),
        ]
    );
    assert_eq!(
        names(&delivered[1].2),
        [
            named(ALICE, P_ALICE, "Alice Person"),
            (BEA.to_string(), None, None),
        ]
    );
    // Nora never acted: no frame names her, though both can see her person.
    // Nothing about Harriet reaches Bea's frame, not even her account token.
    for (_, snapshot, _) in &delivered {
        let frame = snapshot.to_string();
        assert!(!frame.contains(NORA), "{frame}");
        assert!(!frame.contains("Nora"), "{frame}");
    }
    let bea_frame = delivered[1].1.to_string();
    assert!(!bea_frame.contains(HARRIET), "{bea_frame}");
    assert!(!bea_frame.contains("Harriet"), "{bea_frame}");
    assert!(!bea_frame.contains(P_HARRIET), "{bea_frame}");
}

// Typed time for authored tabs (task fef3469, D2 slice T2): the
// caller-relative `facet_times` relation reaches a tab through an ordinary
// `sql.snapshot.v1` need. "Events overlapping this week" is a range query on
// the date and millisecond columns alone, since governed SQL has no date
// functions. Each viewer's snapshot equals her own direct `query_sql`, and a
// record hidden from a viewer contributes no row.
//
// The viewer's week is Monday 2026-10-05 to Monday 2026-10-12 in London
// (BST): dates 2026-10-05..2026-10-12 for all-day rows, and
// 2026-10-04T23:00Z..2026-10-11T23:00Z as epoch milliseconds for timed rows.
const WEEK_SQL: &str = "SELECT record_id, key, kind, all_day, start_date, end_date, start_ms, end_ms, tz FROM facet_times WHERE (all_day = 1 AND start_date < '2026-10-12' AND end_date > '2026-10-05') OR (all_day = 0 AND start_ms < 1791759600000 AND (end_ms > 1791154800000 OR start_ms >= 1791154800000)) ORDER BY record_id, key LIMIT 100";

#[tokio::test]
async fn sql_snapshot_reads_facet_times_this_week_for_two_viewers() {
    const STANDUP: &str = "d1d0f000-0000-4000-8000-000000000001";
    const OFFSITE: &str = "d1d0f000-0000-4000-8000-000000000002";
    const ONE_TO_ONE: &str = "d1d0f000-0000-4000-8000-000000000003";
    const NEXT_WEEK: &str = "d1d0f000-0000-4000-8000-000000000004";
    const WEEK_START: &str = "d1d0f000-0000-4000-8000-000000000005";
    const EARLIER: &str = "d1d0f000-0000-4000-8000-000000000006";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_schema_config",
        json!({
            "action": "write",
            "data": { "shapes": { "Document:note": { "facets": {
                "when": { "type": "when" },
                "due": { "type": "date" },
            } } } },
        }),
    )
    .await
    .unwrap();
    let london = |local: &str| json!({ "local": local, "tz": "Europe/London" });
    for (id, name, facets, viewers) in [
        (
            STANDUP,
            "Standup",
            json!({ "when": { "all_day": false, "start": london("2026-10-05T10:00"), "duration": "PT30M" } }),
            vec![ALICE, BEA],
        ),
        (
            OFFSITE,
            "Offsite",
            json!({ "when": { "all_day": true, "start": "2026-10-07", "end": "2026-10-09" } }),
            vec![ALICE, BEA],
        ),
        (
            ONE_TO_ONE,
            "Private one-to-one",
            json!({ "when": { "all_day": false, "start": "2026-10-06T14:00:00Z", "end": "2026-10-06T15:00:00Z" } }),
            vec![ALICE],
        ),
        (
            NEXT_WEEK,
            "Next week's review",
            json!({ "when": { "all_day": false, "start": london("2026-10-13T10:00"), "duration": "PT1H" }, "due": "2026-10-11" }),
            vec![ALICE, BEA],
        ),
        (
            WEEK_START,
            "Midnight marker",
            json!({ "when": { "all_day": false, "start": london("2026-10-05T00:00"), "duration": "PT0S" } }),
            vec![ALICE, BEA],
        ),
        (
            EARLIER,
            "Last week's retro",
            json!({ "when": { "all_day": true, "start": "2026-09-28", "end": "2026-10-05" } }),
            vec![ALICE, BEA],
        ),
    ] {
        call_as(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({
                "id": id, "type": "Document", "kind": "note", "name": name,
                "facets": facets, "reason": "Typed time fixture.",
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            viewers
                .into_iter()
                .map(|viewer| AllowEntry::account(viewer, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
    }
    let declaration = json!({
        "needs": [sql_need("calendar.week", "This week", WEEK_SQL)],
        "effects": [],
    });
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.calendar", declaration.clone()).await;
    let bea_event = adopted_with_package(&registry, &db, BEA, "agent.calendar", declaration).await;
    let mut delivered = Vec::new();
    for (account, event) in [(ALICE, alice_event.as_str()), (BEA, bea_event.as_str())] {
        let snapshot = sql_snapshot(&registry, &db, account, "agent.calendar", event)
            .await
            .unwrap();
        let rows = snapshot["input"]["sql"]["calendar.week"].clone();
        let direct = direct_sql(&registry, &db, account, WEEK_SQL).await.unwrap();
        assert_eq!(rows["columns"], direct["columns"], "{account} columns");
        assert_eq!(rows["rows"], direct["rows"], "{account} rows");
        assert_eq!(rows["truncated"], json!(false), "{account} truncated");
        assert!(snapshot.to_string().find("as_of_seq").is_none());
        delivered.push((snapshot, rows["rows"].clone()));
    }
    let keyed = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["record_id"].as_str().unwrap().to_string(),
                    row["key"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>()
    };
    let row = |id: &str, key: &str| (id.to_string(), key.to_string());
    // The standup (09:00Z), the offsite (all-day), the midnight point on the
    // window's first instant, and next week's review's due date (Sunday)
    // overlap the week. Next week's meeting and last week's retro, which ends
    // exclusively on Monday, do not.
    assert_eq!(
        keyed(&delivered[0].1),
        [
            row(STANDUP, "when"),
            row(OFFSITE, "when"),
            row(ONE_TO_ONE, "when"),
            row(NEXT_WEEK, "due"),
            row(WEEK_START, "when"),
        ]
    );
    assert_eq!(
        keyed(&delivered[1].1),
        [
            row(STANDUP, "when"),
            row(OFFSITE, "when"),
            row(NEXT_WEEK, "due"),
            row(WEEK_START, "when"),
        ]
    );
    let standup = &delivered[1].1[0];
    assert_eq!(standup["all_day"], json!(0));
    assert_eq!(standup["start_ms"], json!(1_791_190_800_000_i64));
    assert_eq!(standup["end_ms"], json!(1_791_192_600_000_i64));
    assert_eq!(standup["tz"], json!("Europe/London"));
    assert!(standup["start_date"].is_null());
    let offsite = &delivered[1].1[1];
    assert_eq!(offsite["all_day"], json!(1));
    assert_eq!(offsite["start_date"], json!("2026-10-07"));
    assert_eq!(offsite["end_date"], json!("2026-10-09"));
    assert!(offsite["start_ms"].is_null());
    // Nothing about the hidden one-to-one reaches Bea's frame.
    let bea_frame = delivered[1].0.to_string();
    assert!(!bea_frame.contains(ONE_TO_ONE), "{bea_frame}");
    // The relation carries no sequence column.
    assert!(!delivered[0].0["input"]["sql"]["calendar.week"]["columns"]
        .to_string()
        .contains("seq"));
}

// Historical run attribution for authored tabs (task 6867ce6): `runs` and
// `run_intents` reach a tab through an ordinary `sql.snapshot.v1` need. Each
// viewer's snapshot equals her own direct `query_sql`. A run is listed when
// `get_history` would disclose its owner (decision 0052432, Q-6867): Harriet's
// person is visible to Alice only, so Bea's frame carries nothing of her run.
// Alice's first run is backdated to January, far outside the activity window,
// and her intents are the real `set_intent` declarations, captured by the
// read log and listed in order.
const RUNS_SQL: &str = "SELECT r.run_key, r.principal_person_id, r.started_at_ms, \
     r.reported_model, r.model_assurance, i.ordinal, i.intent \
     FROM runs r LEFT JOIN run_intents i USING (run_key) \
     ORDER BY r.started_at_ms, r.run_key, i.ordinal LIMIT 200";

#[tokio::test]
async fn sql_snapshot_reads_historical_runs_and_intents_for_two_viewers() {
    const P_ALICE: &str = "6867ce61-0000-4000-8000-000000000001";
    const P_HARRIET: &str = "6867ce61-0000-4000-8000-000000000002";
    const HARRIET: &str = "account:harriet";
    const ALICE_OLD_RUN: &str = "heron-archery-a11ce0";
    const ALICE_NEW_RUN: &str = "heron-archery-a11ce1";
    const HARRIET_RUN: &str = "heron-archery-4a8810";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let pool = crate::common::fixture_write_pool(&db).await;
    for (id, name, account, viewers) in [
        (P_ALICE, "Alice Person", ALICE, vec![ALICE, BEA]),
        (P_HARRIET, "Harriet Hidden", HARRIET, vec![ALICE]),
    ] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id, "type": "Entity", "kind": "person",
                    "name": name, "reason": "Runs fixture.",
                }),
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
        )
        .bind(id)
        .bind(account)
        .execute(&pool)
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            viewers
                .into_iter()
                .map(|viewer| AllowEntry::account(viewer, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
    }
    for (account, run_key, intent, model) in [
        (
            ALICE,
            ALICE_OLD_RUN,
            "Draft the January plan",
            Some("claude-opus-5-5"),
        ),
        (ALICE, ALICE_OLD_RUN, "Narrow it to the budget", None),
        (ALICE, ALICE_NEW_RUN, "Pick the plan back up", None),
        (HARRIET, HARRIET_RUN, "Harriet private plan", None),
    ] {
        let mut arguments = json!({"intent": intent, "run_key": run_key});
        if let Some(model) = model {
            arguments["model"] = json!(model);
        }
        registry
            .call(
                db.clone(),
                Caller::authenticated(account),
                "set_intent",
                arguments,
            )
            .await
            .unwrap();
        db.drain_captures_for_tests().await;
    }
    sqlx::query("UPDATE agent_runs SET started_at='2026-01-05T09:00:00.000Z' WHERE run_key=?")
        .bind(ALICE_OLD_RUN)
        .execute(&pool)
        .await
        .unwrap();

    let declaration = json!({
        "needs": [sql_need("people.runs", "Runs", RUNS_SQL)],
        "effects": [],
    });
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.runs", declaration.clone()).await;
    let bea_event = adopted_with_package(&registry, &db, BEA, "agent.runs", declaration).await;
    let mut delivered = Vec::new();
    for (account, event) in [(ALICE, alice_event.as_str()), (BEA, bea_event.as_str())] {
        let snapshot = sql_snapshot(&registry, &db, account, "agent.runs", event)
            .await
            .unwrap();
        let rows = snapshot["input"]["sql"]["people.runs"].clone();
        let direct = direct_sql(&registry, &db, account, RUNS_SQL).await.unwrap();
        assert_eq!(rows["columns"], direct["columns"], "{account} columns");
        assert_eq!(rows["rows"], direct["rows"], "{account} rows");
        assert_eq!(rows["truncated"], json!(false), "{account} truncated");
        delivered.push((account, snapshot, rows["rows"].clone()));
    }
    let listed = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["run_key"].as_str().unwrap().to_string(),
                    row["principal_person_id"].as_str().map(str::to_string),
                    row["ordinal"].as_i64(),
                    row["intent"].as_str().map(str::to_string),
                )
            })
            .collect::<Vec<_>>()
    };
    let row = |run: &str, person: &str, ordinal: i64, intent: &str| {
        (
            run.to_string(),
            Some(person.to_string()),
            Some(ordinal),
            Some(intent.to_string()),
        )
    };
    let alice_runs = [
        row(ALICE_OLD_RUN, P_ALICE, 1, "Draft the January plan"),
        row(ALICE_OLD_RUN, P_ALICE, 2, "Narrow it to the budget"),
    ];
    // Alice sees her own runs and Harriet's. The January run leads.
    let alice_rows = listed(&delivered[0].2);
    assert_eq!(&alice_rows[..2], &alice_runs);
    let mut alice_rest = alice_rows[2..].to_vec();
    alice_rest.sort();
    let mut expected_rest = vec![
        row(ALICE_NEW_RUN, P_ALICE, 1, "Pick the plan back up"),
        row(HARRIET_RUN, P_HARRIET, 1, "Harriet private plan"),
    ];
    expected_rest.sort();
    assert_eq!(alice_rest, expected_rest);
    // Bea sees Alice's runs only.
    assert_eq!(
        listed(&delivered[1].2),
        [
            alice_runs[0].clone(),
            alice_runs[1].clone(),
            row(ALICE_NEW_RUN, P_ALICE, 1, "Pick the plan back up"),
        ]
    );
    let first = &delivered[1].2[0];
    assert_eq!(first["started_at_ms"], json!(1_767_603_600_000_i64));
    assert_eq!(first["reported_model"], json!("claude-opus-5-5"));
    assert_eq!(first["model_assurance"], json!("self_declared"));
    for (_, snapshot, _) in &delivered {
        let frame = snapshot.to_string();
        assert!(frame.find("as_of_seq").is_none(), "{frame}");
        assert!(!frame.contains(&format!("\"{ALICE}\"")), "{frame}");
    }
    // Nothing about Harriet reaches Bea's frame.
    let bea_frame = delivered[1].1.to_string();
    for hidden in [HARRIET, HARRIET_RUN, P_HARRIET, "Harriet"] {
        assert!(!bea_frame.contains(hidden), "{hidden}: {bea_frame}");
    }
}

// Per-viewer message state for apps and tabs (task b2583dc, design D6):
// `my_message_state` and `my_mentions` reach a tab
// through ordinary `sql.snapshot.v1` needs, with no host need and no consent
// step of their own. Each viewer's snapshot equals her own direct
// `query_sql`. Bea opening and muting a Message moves Bea's frame and leaves
// Alice's rows and revision digest exactly as they were: read state is
// private to each viewer (decision 0052432), and no frame carries a
// sequence or an account.
const MESSAGE_STATE_SQL: &str = "SELECT message_id, stage, unread, is_own, mentioned, muted \
     FROM my_message_state ORDER BY message_id LIMIT 200";
const MENTIONS_SQL: &str =
    "SELECT source_id, via, seen FROM my_mentions ORDER BY mentioned_at_ms DESC, source_id LIMIT 200";

#[tokio::test]
async fn sql_snapshot_reads_private_message_state_for_two_viewers() {
    const P_ALICE: &str = "b2583dc1-0000-4000-8000-000000000001";
    const P_BEA: &str = "b2583dc1-0000-4000-8000-000000000002";
    const M_SHARED: &str = "b2583dc1-0000-4000-8000-00000000000a";
    const M_BEA_ONLY: &str = "b2583dc1-0000-4000-8000-00000000000b";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let pool = crate::common::fixture_write_pool(&db).await;
    for (id, name, account, record_type, kind, viewers, owner) in [
        (
            P_ALICE,
            "Alice Person",
            Some(ALICE),
            "Entity",
            Some("person"),
            vec![ALICE, BEA],
            None,
        ),
        (
            P_BEA,
            "Bea Person",
            Some(BEA),
            "Entity",
            Some("person"),
            vec![ALICE, BEA],
            None,
        ),
        (
            M_SHARED,
            "Standup at ten",
            None,
            "Message",
            None,
            vec![ALICE, BEA],
            Some(P_BEA),
        ),
        (
            M_BEA_ONLY,
            "Bea's note to self",
            None,
            "Message",
            None,
            vec![BEA],
            Some(P_BEA),
        ),
    ] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id, "type": "Document", "kind": "note",
                    "name": name, "reason": "Message state fixture.",
                }),
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE records SET type = ?, kind = ?, owner_id = COALESCE(?, owner_id) WHERE id = ?",
        )
        .bind(record_type)
        .bind(kind)
        .bind(owner)
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        if let Some(account) = account {
            sqlx::query(
                "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
            )
            .bind(id)
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            viewers
                .into_iter()
                .map(|viewer| AllowEntry::account(viewer, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
    }
    for message in [M_SHARED, M_BEA_ONLY] {
        sqlx::query(
            "INSERT INTO message_mentions
               (message_id, mention_id, target_kind, target_binding, target_record_id,
                span_start, span_end, authored_label, source_event_seq, effective)
             VALUES (?, 'mention-alice', 'principal', 'native-principal:alice', ?, 0, 6, '@Alice',
                     (SELECT max(seq) FROM content_events WHERE record_id = ?), 1)",
        )
        .bind(message)
        .bind(P_ALICE)
        .bind(message)
        .execute(&pool)
        .await
        .unwrap();
    }
    let declaration = json!({
        "needs": [
            sql_need("inbox.state", "Read state", MESSAGE_STATE_SQL),
            sql_need("inbox.mentions", "Mentions", MENTIONS_SQL),
        ],
        "effects": [],
    });
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.inbox", declaration.clone()).await;
    let bea_event = adopted_with_package(&registry, &db, BEA, "agent.inbox", declaration).await;
    let snapshots = |label: &'static str| {
        let registry = &registry;
        let db = &db;
        let alice_event = alice_event.clone();
        let bea_event = bea_event.clone();
        async move {
            let mut delivered = Vec::new();
            for (account, event) in [(ALICE, alice_event.as_str()), (BEA, bea_event.as_str())] {
                let snapshot = sql_snapshot(registry, db, account, "agent.inbox", event)
                    .await
                    .unwrap();
                for (key, sql) in [
                    ("inbox.state", MESSAGE_STATE_SQL),
                    ("inbox.mentions", MENTIONS_SQL),
                ] {
                    let rows = &snapshot["input"]["sql"][key];
                    let direct = direct_sql(registry, db, account, sql).await.unwrap();
                    assert_eq!(rows["rows"], direct["rows"], "{label} {account} {key}");
                    assert_eq!(rows["truncated"], json!(false), "{label} {account} {key}");
                }
                let frame = snapshot.to_string();
                assert!(frame.find("as_of_seq").is_none(), "{frame}");
                for account_token in [ALICE, BEA] {
                    assert!(
                        !frame.contains(&format!("\"{account_token}\"")),
                        "{account_token}: {frame}"
                    );
                }
                delivered.push(snapshot);
            }
            delivered
        }
    };
    let before = snapshots("before").await;
    let alice_state = &before[0]["input"]["sql"]["inbox.state"]["rows"];
    assert_eq!(
        alice_state,
        &json!([{
            "message_id": M_SHARED, "stage": "unsurfaced", "unread": 1,
            "is_own": 0, "mentioned": 1, "muted": 0
        }])
    );
    assert_eq!(
        before[0]["input"]["sql"]["inbox.mentions"]["rows"],
        json!([{"source_id": M_SHARED, "via": "principal", "seen": 0}])
    );
    let bea_state = before[1]["input"]["sql"]["inbox.state"]["rows"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(bea_state.len(), 2);
    assert!(bea_state
        .iter()
        .all(|row| row["is_own"] == 1 && row["unread"] == 0));
    assert_eq!(
        before[1]["input"]["sql"]["inbox.mentions"]["rows"],
        json!([])
    );

    // Bea opens and mutes the shared Message through the real awareness
    // writers.
    let mut tx = pool.begin().await.unwrap();
    let mut act_alloc = native_ce::act::ActAllocation::new();
    native_ce::awareness::advance_human(
        &mut tx,
        BEA,
        M_SHARED,
        native_ce::awareness::HumanStage::Opened,
        0,
        "bea-opens-standup",
        &native_ce::awareness::VerifiedHumanInteraction {
            nonce: "bea-opens-standup".into(),
            executor_ref: "trusted-ui".into(),
        },
        "opened in the channel",
        &mut act_alloc,
    )
    .await
    .unwrap();
    native_ce::awareness::set_preference(
        &mut tx,
        BEA,
        M_SHARED,
        native_ce::awareness::PreferenceAction::Mute,
        None,
        0,
        "bea-mutes-standup",
        "too noisy",
        &mut act_alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let after = snapshots("after").await;
    for key in ["inbox.state", "inbox.mentions"] {
        assert_eq!(
            before[0]["input"]["sql"][key], after[0]["input"]["sql"][key],
            "{key}: Bea's read moved Alice's rows"
        );
    }
    assert_eq!(
        before[0]["revision"]["revision_digest"], after[0]["revision"]["revision_digest"],
        "Bea's read moved Alice's digest"
    );
    let bea_shared = after[1]["input"]["sql"]["inbox.state"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["message_id"] == M_SHARED)
        .unwrap()
        .clone();
    assert_eq!(bea_shared["stage"], "opened");
    assert_eq!(bea_shared["muted"], 1);
    assert_ne!(
        before[1]["revision"]["revision_digest"], after[1]["revision"]["revision_digest"],
        "Bea's own frame reflects her read"
    );
}

// Two-viewer narrowing for bounded snapshot + keyed reads (task 79da157).
//
// Generic shape, folders-flavoured: one param-less snapshot need (roots)
// plus one keyed on-request need (children by folder id). Both viewers
// install the same declaration; narrowing one listed record for Bea must
// exclude it from both her paths, move her viewer-scoped snapshot digest,
// leave Alice byte-identical, leak nothing, and restore on re-grant. Only
// delivered rows, digests and absence are compared — never hidden write
// counts (see task a5804e8). Activity, Graph and Tasks can clone this
// shape with their own needs: the reusable core is install-both,
// baseline-compare, narrow-one, compare-again, restore.
const NARROW_ROOTS_SQL: &str = "SELECT id, name FROM records WHERE deleted_at IS NULL AND home_id IS NULL AND type NOT IN ('Message', 'Annotation') ORDER BY name ASC, id ASC LIMIT 200";
const NARROW_CHILDREN_SQL: &str = "SELECT id, name FROM records WHERE home_id = ?1 AND deleted_at IS NULL AND type NOT IN ('Message', 'Annotation') ORDER BY name ASC, id ASC LIMIT 200";

fn narrow_declaration() -> Value {
    json!({
        "needs": [
            sql_need("narrow.roots", "Roots", NARROW_ROOTS_SQL),
            param_need("narrow.children", "Children", NARROW_CHILDREN_SQL,
                json!([{"name": "folder_id", "type": "text", "max_len": 128}])),
        ],
        "effects": [],
    })
}

/// A true top-level record: `create_record` files homeless records under
/// the workspace root, so roots are inserted directly with NULL home
/// (same INSERT shape as the account-binding precedent below).
async fn narrow_root(db: &Db, id: &str, name: &str) {
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query(
        "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence) \
         VALUES (?,'Collection','folder',?,NULL,?,'enduring')",
    )
    .bind(id)
    .bind(name)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&pool)
    .await
    .unwrap();
}

async fn narrow_record(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    name: &str,
    folder: bool,
    home: Option<&str>,
) {
    let mut args = json!({
        "id": id,
        "type": if folder { "Collection" } else { "Document" },
        "kind": if folder { "folder" } else { "note" },
        "name": name, "body": name,
        "reason": "Two-viewer narrowing fixture.",
    });
    if let Some(home_id) = home {
        args["home_id"] = json!(home_id);
    }
    registry
        .call(db.clone(), Caller::local(), "create_record", args)
        .await
        .unwrap();
}

async fn narrow_snap(registry: &ToolRegistry, db: &Db, account: &str, event: &str) -> Value {
    sql_snapshot(registry, db, account, "agent.narrow-probe", event)
        .await
        .unwrap()
}

async fn narrow_kids(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    event: &str,
    folder: &str,
) -> Value {
    sql_param_read(
        registry,
        db,
        account,
        "agent.narrow-probe",
        event,
        "narrow.children",
        json!({"folder_id": folder}),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn two_viewer_narrowing_moves_snapshot_and_keyed_reads() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    const ROOT_A: &str = "f1d00000-0000-4000-8000-000000000031";
    const ROOT_B: &str = "f1d00000-0000-4000-8000-000000000032";
    const KID_ONE: &str = "f1d00000-0000-4000-8000-000000000033";
    const KID_TWO: &str = "f1d00000-0000-4000-8000-000000000034";
    narrow_root(&db, ROOT_A, "North Root").await;
    narrow_root(&db, ROOT_B, "South Root").await;
    narrow_record(&registry, &db, KID_ONE, "Kid one", false, Some(ROOT_A)).await;
    narrow_record(&registry, &db, KID_TWO, "Kid two", false, Some(ROOT_A)).await;
    for id in [ROOT_A, ROOT_B, KID_ONE, KID_TWO] {
        // One policy write naming both viewers: `grant` replaces the
        // record's policy, so two sequential grants would leave only Bea.
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![
                AllowEntry::account(ALICE, Capability::View),
                AllowEntry::account(BEA, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    // The bootstrapped workspace root is ambiently visible and therefore
    // part of every roots read; narrowing legs compare the fixture rows
    // around it rather than pretending the lane holds only them.
    const NATIVE_ROOT: &str = "native:root";
    let alice_event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.narrow-probe",
        narrow_declaration(),
    )
    .await;
    let bea_event = adopted_with_package(
        &registry,
        &db,
        BEA,
        "agent.narrow-probe",
        narrow_declaration(),
    )
    .await;
    let digest_of = |read: &Value| {
        read["revision"]["revision_digest"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let root_ids = |read: &Value| {
        read["input"]["sql"]["narrow.roots"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    // Baseline: identical delivered rows for both viewers on both paths.
    // (Digests are NOT compared across viewers: the pin carries each
    // install's own event id, so equal rows still digest differently.)
    let alice_snap = narrow_snap(&registry, &db, ALICE, &alice_event).await;
    let bea_snap = narrow_snap(&registry, &db, BEA, &bea_event).await;
    let own_roots = |read: &Value| {
        root_ids(read)
            .into_iter()
            .filter(|id| id != NATIVE_ROOT)
            .collect::<Vec<_>>()
    };
    assert!(root_ids(&alice_snap).contains(&NATIVE_ROOT.to_string()));
    assert_eq!(own_roots(&alice_snap), vec![ROOT_A, ROOT_B]);
    assert_eq!(root_ids(&bea_snap), root_ids(&alice_snap));
    assert_eq!(alice_snap["input"]["sql"]["narrow.roots"]["row_count"], 3);
    assert_eq!(
        alice_snap["input"]["sql"]["narrow.roots"]["truncated"],
        false
    );
    let alice_kids = narrow_kids(&registry, &db, ALICE, &alice_event, ROOT_A).await;
    let bea_kids = narrow_kids(&registry, &db, BEA, &bea_event, ROOT_A).await;
    let kid_ids = |read: &Value| {
        read["result"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(kid_ids(&alice_kids), vec![KID_ONE, KID_TWO]);
    assert_eq!(kid_ids(&bea_kids), kid_ids(&alice_kids));
    assert_eq!(alice_kids["result"]["row_count"], 2);
    let alice_snap_digest = digest_of(&alice_snap);
    let bea_snap_digest = digest_of(&bea_snap);
    // Narrow one snapshot row and one keyed row for Bea only.
    for (id, account) in [(ROOT_B, ALICE), (KID_TWO, ALICE)] {
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account(account, Capability::View)],
        )
        .await
        .unwrap();
    }
    let alice_snap_after = narrow_snap(&registry, &db, ALICE, &alice_event).await;
    let bea_snap_after = narrow_snap(&registry, &db, BEA, &bea_event).await;
    assert_eq!(own_roots(&alice_snap_after), vec![ROOT_A, ROOT_B]);
    assert_eq!(digest_of(&alice_snap_after), alice_snap_digest);
    assert_eq!(own_roots(&bea_snap_after), vec![ROOT_A]);
    assert_eq!(
        bea_snap_after["input"]["sql"]["narrow.roots"]["row_count"],
        2
    );
    assert_ne!(digest_of(&bea_snap_after), bea_snap_digest);
    let alice_kids_after = narrow_kids(&registry, &db, ALICE, &alice_event, ROOT_A).await;
    let bea_kids_after = narrow_kids(&registry, &db, BEA, &bea_event, ROOT_A).await;
    assert_eq!(kid_ids(&alice_kids_after), vec![KID_ONE, KID_TWO]);
    assert_eq!(alice_kids_after["result"], alice_kids["result"]);
    assert_eq!(kid_ids(&bea_kids_after), vec![KID_ONE]);
    assert_eq!(bea_kids_after["result"]["row_count"], 1);
    assert_eq!(bea_kids_after["result"]["truncated"], false);
    // Nothing narrowed may appear anywhere in Bea's answers.
    for read in [&bea_snap_after, &bea_kids_after] {
        let text = read.to_string();
        for secret in [ROOT_B, KID_TWO, "South Root", "Kid two"] {
            assert!(
                !text.contains(secret),
                "narrowed record leaks into Bea's read: {secret}"
            );
        }
    }
    // An unknown folder is an empty row set, not a refusal, for Bea too.
    let missing = narrow_kids(&registry, &db, BEA, &bea_event, "no-such-folder").await;
    assert_eq!(missing["result"]["rows"].as_array().unwrap().len(), 0);
    // Re-grant restores Bea to Alice's rows and her baseline digest shape.
    for id in [ROOT_B, KID_TWO] {
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![
                AllowEntry::account(ALICE, Capability::View),
                AllowEntry::account(BEA, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    let bea_restored = narrow_snap(&registry, &db, BEA, &bea_event).await;
    assert_eq!(own_roots(&bea_restored), vec![ROOT_A, ROOT_B]);
    assert_eq!(digest_of(&bea_restored), bea_snap_digest);
    let bea_kids_restored = narrow_kids(&registry, &db, BEA, &bea_event, ROOT_A).await;
    assert_eq!(kid_ids(&bea_kids_restored), vec![KID_ONE, KID_TWO]);
}

#[tokio::test]
async fn sql_snapshot_reports_server_detected_time_dependence_and_stamp() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // Ready's stalled lane uses the server clock, while its two other
    // statements remain clock-free.
    let ready_event =
        adopted_with_package(&registry, &db, ALICE, "agent.ready", ready_declaration()).await;
    let ready = sql_snapshot(&registry, &db, ALICE, "agent.ready", &ready_event)
        .await
        .unwrap();
    assert_eq!(ready["time_dependent"], true);
    assert_eq!(
        ready["input"]["sql"]["ready.stalled"]["now_ms_ms"],
        ready["as_of_ms"]
    );
    assert_eq!(
        ready["input"]["sql"]["ready.stalled"]["time_dependent"],
        true
    );
    for key in ["ready.unblocked", "ready.proposed"] {
        assert_eq!(ready["input"]["sql"][key]["time_dependent"], false);
        assert!(ready["input"]["sql"][key]["now_ms_ms"].is_null());
    }
    // Clock-bearing declaration: the engine detects `now_ms()`, stamps the
    // evaluation, and the snapshot reports both.
    let clock_event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let first = sql_snapshot(&registry, &db, ALICE, "agent.clock", &clock_event)
        .await
        .unwrap();
    assert_eq!(first["time_dependent"], true);
    let stamp = first["as_of_ms"]
        .as_i64()
        .expect("clock snapshot carries an evaluation stamp");
    assert_eq!(first["input"]["sql"]["lane.clock"]["time_dependent"], true);
    // A single time-dependent need: the snapshot stamp is its exact
    // statement-fixed clock, and the clock-free need stays unstamped.
    assert_eq!(
        first["input"]["sql"]["lane.clock"]["now_ms_ms"].as_i64(),
        Some(stamp)
    );
    assert_eq!(
        first["input"]["sql"]["ready.unblocked"]["time_dependent"],
        false
    );
    assert!(first["input"]["sql"]["ready.unblocked"]["now_ms_ms"].is_null());
    // Clock-only reevaluation keeps the row-based digest: run until the wall
    // clock advances past the first stamp, then compare digests.
    let first_digest = first["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let mut second = first.clone();
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        second = sql_snapshot(&registry, &db, ALICE, "agent.clock", &clock_event)
            .await
            .unwrap();
        if second["as_of_ms"].as_i64() != Some(stamp) {
            break;
        }
    }
    assert_eq!(
        second["revision"]["revision_digest"].as_str().unwrap(),
        first_digest,
        "a stamp-only change must not move the revision digest"
    );
    assert!(second["as_of_ms"].as_i64().unwrap() >= stamp);
}

#[tokio::test]
async fn sql_snapshot_stamp_is_the_max_of_two_statement_clocks() {
    // M1 slice 1 (review repair): with two `now_ms()` needs, the snapshot
    // stamp is the maximum of the per-need statement-fixed clocks — an
    // upper bound no statement clock exceeds, not any one need's clock.
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.clock2",
        two_clock_declaration(),
    )
    .await;
    let snapshot = sql_snapshot(&registry, &db, ALICE, "agent.clock2", &event)
        .await
        .unwrap();
    assert_eq!(snapshot["time_dependent"], true);
    let clock_a = snapshot["input"]["sql"]["lane.clock"]["now_ms_ms"]
        .as_i64()
        .expect("first clock need is stamped");
    let clock_b = snapshot["input"]["sql"]["lane.clock_b"]["now_ms_ms"]
        .as_i64()
        .expect("second clock need is stamped");
    assert_eq!(snapshot["as_of_ms"].as_i64(), Some(clock_a.max(clock_b)));
}

#[tokio::test]
async fn sql_snapshot_holds_digest_for_inaccessible_writes() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    ready_task(
        &registry,
        &db,
        "d2d00000-0000-4000-8000-0000000000a1",
        "Visible proposal",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    ready_task(
        &registry,
        &db,
        "d2d00000-0000-4000-8000-0000000000a2",
        "Hidden proposal",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    grant(
        &db,
        "d2d00000-0000-4000-8000-0000000000a1",
        ALICE,
        Capability::View,
    )
    .await;
    grant(
        &db,
        "d2d00000-0000-4000-8000-0000000000a2",
        BEA,
        Capability::View,
    )
    .await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.ready", ready_declaration()).await;
    let before = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    // A record hidden from the viewer never appears in the rows ...
    let serialized = before.to_string();
    assert!(!serialized.contains("d2d00000-0000-4000-8000-0000000000a2"));
    assert!(serialized.contains("d2d00000-0000-4000-8000-0000000000a1"));
    // ... and writing to it does not move the digest.
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id": "d2d00000-0000-4000-8000-0000000000a2",
                "name": "Hidden proposal renamed",
                "reason": "Noninterference probe on a record Alice cannot see.",
            }),
        )
        .await
        .unwrap();
    let after = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    assert_eq!(
        after["revision"]["revision_digest"],
        before["revision"]["revision_digest"]
    );
    assert!(!after
        .to_string()
        .contains("d2d00000-0000-4000-8000-0000000000a2"));
}

#[tokio::test]
async fn sql_snapshot_holds_digest_for_hidden_creates_and_completions() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // An aggregate need: a hidden create or completion would move this count
    // for a viewer who could see the row, so a held digest locks
    // noninterference for writes the viewer cannot see.
    let count_sql =
        "SELECT COUNT(*) AS open_tasks FROM records WHERE deleted_at IS NULL AND lifecycle = 'open'";
    let declaration = json!({
        "needs": ["attention.query.v1", sql_need("lane.count", "Open count", count_sql)],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.count", declaration).await;
    ready_task(
        &registry,
        &db,
        "d6d00000-0000-4000-8000-0000000000a1",
        "Visible",
        "open",
        None,
        None,
    )
    .await;
    ready_task(
        &registry,
        &db,
        "d6d00000-0000-4000-8000-0000000000a2",
        "Hidden",
        "open",
        None,
        None,
    )
    .await;
    grant(
        &db,
        "d6d00000-0000-4000-8000-0000000000a1",
        ALICE,
        Capability::View,
    )
    .await;
    grant(
        &db,
        "d6d00000-0000-4000-8000-0000000000a2",
        BEA,
        Capability::View,
    )
    .await;
    let digest_of = |snapshot: &Value| {
        snapshot["revision"]["revision_digest"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let before = sql_snapshot(&registry, &db, ALICE, "agent.count", &event)
        .await
        .unwrap();
    // Hidden create: a new open row Alice cannot see.
    ready_task(
        &registry,
        &db,
        "d6d00000-0000-4000-8000-0000000000a3",
        "Hidden newborn",
        "open",
        None,
        None,
    )
    .await;
    grant(
        &db,
        "d6d00000-0000-4000-8000-0000000000a3",
        BEA,
        Capability::View,
    )
    .await;
    let after_create = sql_snapshot(&registry, &db, ALICE, "agent.count", &event)
        .await
        .unwrap();
    assert_eq!(digest_of(&after_create), digest_of(&before));
    // Hidden completion: a lifecycle change the COUNT would see if visible.
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id": "d6d00000-0000-4000-8000-0000000000a2",
                "lifecycle": "completed",
                "reason": "Complete a record Alice cannot see.",
            }),
        )
        .await
        .unwrap();
    let after_complete = sql_snapshot(&registry, &db, ALICE, "agent.count", &event)
        .await
        .unwrap();
    assert_eq!(digest_of(&after_complete), digest_of(&before));
    let serialized = after_complete.to_string();
    assert!(!serialized.contains("d6d00000-0000-4000-8000-0000000000a2"));
    assert!(!serialized.contains("d6d00000-0000-4000-8000-0000000000a3"));
    assert!(serialized.contains("d6d00000-0000-4000-8000-0000000000a1"));
}

#[tokio::test]
async fn sql_snapshot_digest_moves_on_visible_change_and_holds_when_idle() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    ready_task(
        &registry,
        &db,
        "d3d00000-0000-4000-8000-0000000000a1",
        "Visible proposal",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    grant(
        &db,
        "d3d00000-0000-4000-8000-0000000000a1",
        ALICE,
        Capability::View,
    )
    .await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.ready", ready_declaration()).await;
    let first = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    let idle = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    assert_eq!(
        idle["revision"]["revision_digest"], first["revision"]["revision_digest"],
        "nothing visible changed, the digest must hold"
    );
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id": "d3d00000-0000-4000-8000-0000000000a1",
                "name": "Visible proposal renamed",
                "reason": "A visible row changes, the digest must move.",
            }),
        )
        .await
        .unwrap();
    let moved = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    assert_ne!(
        moved["revision"]["revision_digest"],
        first["revision"]["revision_digest"]
    );
    assert!(moved.to_string().contains("Visible proposal renamed"));
}

#[tokio::test]
async fn sql_snapshot_install_refuses_out_of_bound_declarations() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let install = |declaration: Value| {
        call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            json!({
                "action": "install",
                "package": "agent.ready",
                "version": "0.1.0",
                "digest": DIGEST_A,
                "artifact_id": ARTIFACT_A,
                "source_revision": source_revision,
                "declaration": declaration,
                "reason": "Probe SQL declaration bounds.",
            }),
        )
    };
    let oversize_sql = format!("SELECT '{}'", "x".repeat(4096));
    let wide_sql: String = format!(
        "SELECT {}",
        (0..65)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut nine = Vec::new();
    for index in 0..9 {
        nine.push(sql_need(
            &format!("lane.{index}"),
            "Lane",
            "SELECT id FROM records",
        ));
    }
    let dup_sql = sql_need("lane.dup", "Dup", "SELECT id FROM records");
    for declaration in [
        json!({"needs": nine, "effects": []}),
        json!({"needs": [sql_need("Bad", "Label", "SELECT id FROM records")], "effects": []}),
        json!({"needs": [sql_need("1lane", "Label", "SELECT id FROM records")], "effects": []}),
        json!({"needs": [sql_need(&"k".repeat(41), "Label", "SELECT id FROM records")], "effects": []}),
        json!({"needs": [dup_sql.clone(), dup_sql.clone()], "effects": []}),
        json!({"needs": [sql_need("lane.big", "Label", &oversize_sql)], "effects": []}),
        json!({"needs": [sql_need("lane.wide", "Too wide", &wide_sql)], "effects": []}),
        json!({"needs": [sql_need("lane.write", "Write", "DELETE FROM records WHERE id = 'x'")], "effects": []}),
        json!({"needs": [sql_need("lane.param", "Param", "SELECT id FROM records WHERE id = ?1")], "effects": []}),
        json!({"needs": [sql_need("lane.lost", "Lost", "SELECT id FROM nope_not_a_relation")], "effects": []}),
        json!({"needs": [sql_need("lane.clock", "Clock", "SELECT id, name FROM records WHERE last_activity_at < datetime('now','-7 days')")], "effects": []}),
        json!({"needs": [sql_need("lane.empty", "", "SELECT id FROM records")], "effects": []}),
        json!({"needs": [sql_need("attention.query.v1", "Host", "SELECT id FROM records")], "effects": []}),
        json!({"needs": [sql_need("records.search.v1", "Host", "SELECT id FROM records")], "effects": []}),
        json!({"needs": [sql_need("records.resolve_reference.v1", "Host", "SELECT id FROM records")], "effects": []}),
        json!({"needs": ["lane.x", sql_need("lane.x", "X", "SELECT id FROM records")], "effects": []}),
    ] {
        let error = install(declaration).await.unwrap_err().to_string();
        assert!(
            error.contains("invalid_sql_need"),
            "out-of-bound SQL declarations refuse with invalid_sql_need: {error}"
        );
    }
}

#[tokio::test]
async fn sql_snapshot_execution_failure_is_a_named_refusal() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // A two-character ESCAPE prepares cleanly (LIKE over plain columns) but
    // raises on every execution: admitted at install, failing at every read.
    let text = "SELECT id FROM records WHERE name LIKE 'x' ESCAPE 'xy'";
    let declaration = json!({
        "needs": [sql_need("lane.broken", "Broken", text)],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.broken", declaration).await;
    let direct = direct_sql(&registry, &db, ALICE, text).await;
    assert!(
        direct.is_err(),
        "the broken statement must fail direct query_sql too"
    );
    let refused = sql_snapshot(&registry, &db, ALICE, "agent.broken", &event).await;
    let error = refused.unwrap_err().to_string();
    assert!(
        error.contains("sql_need_failed"),
        "a failing SQL need refuses the whole snapshot, never a partial input: {error}"
    );
    assert!(error.contains("lane.broken"));
    assert!(
        !error.contains("as_of_seq"),
        "no seq-like field leaks through the refusal text: {error}"
    );
}

#[tokio::test]
async fn sql_snapshot_refuses_a_corrupt_stored_declaration() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let declaration = json!({
        "needs": [sql_need("lane.one", "One", "SELECT id FROM records")],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.dup", declaration).await;
    // Corrupt the stored consent out from under the install: the same entry
    // twice under one key. The corruption is self-consistent (the stored
    // declaration digest and the package digest are both recomputed over the
    // corrupt body), so every digest gate passes and the execution layer
    // must refuse instead of collapsing last-wins.
    let dup = sql_need("lane.one", "One", "SELECT id FROM records");
    let corrupt = json!({"needs": [dup.clone(), dup], "effects": []});
    let (digest, package_digest) = {
        use native_ce::mcp::tools::alpha_tabs::{
            alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
        };
        let declaration_digest = alpha_tab_declaration_digest(&corrupt).unwrap();
        let package_digest = alpha_tab_digest(
            &alpha_tab_bundle_digest(PREVIEW_BODY),
            &declaration_digest,
            "native.html.v1",
        );
        (declaration_digest, package_digest)
    };
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("UPDATE alpha_tab_installs SET consented_declaration=?, declaration_digest=?, digest=? WHERE account_id=? AND package=?")
        .bind(serde_json::to_string(&corrupt).unwrap())
        .bind(digest)
        .bind(package_digest)
        .bind(ALICE)
        .bind("agent.dup")
        .execute(&pool)
        .await
        .unwrap();
    let refused = sql_snapshot(&registry, &db, ALICE, "agent.dup", &event).await;
    let error = refused.unwrap_err().to_string();
    assert!(
        error.contains("sql_need_failed"),
        "duplicate stored keys refuse instead of collapsing: {error}"
    );
    assert!(error.contains("lane.one"));
}

#[tokio::test]
async fn malformed_declarations_refuse_on_inspect_and_preview() {
    let (db, registry) = fixture().await;
    // A verified install, so the gate chain reaches the digest recomputation
    // instead of refusing earlier on adoption.
    let (source_revision, _) = adopted_live_fixture(&registry, &db).await;
    let digest = preview_digest(PREVIEW_BODY);
    // Launch/inspect path: corrupt the stored consent with a malformed SQL
    // entry while keeping the stored digest, so the recomputation itself —
    // not a comparison against a default — is what refuses.
    let malformed = json!({"need": "sql.snapshot.v1", "key": "Bad", "label": "L", "sql": "SELECT id FROM records"});
    let corrupt = json!({
        "needs": ["attention.query.v1", malformed],
        "effects": ["task.triage-set.v1"],
    });
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "UPDATE alpha_tab_installs SET consented_declaration=? WHERE account_id=? AND package=?",
    )
    .bind(serde_json::to_string(&corrupt).unwrap())
    .bind(ALICE)
    .bind("agent.attention-cockpit")
    .execute(&pool)
    .await
    .unwrap();
    let entry = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(entry["launch_binding"]["verdict"], "refused");
    assert_eq!(entry["launch_binding"]["reason"], "digest_mismatch");
    // Preview path: the same malformed declaration as a caller-supplied pin
    // refuses at admission, before any authority or digest comparison. A
    // plain caller suffices: no attestation can be minted for it anyway.
    let mut preview = preview_args(ARTIFACT_A, &source_revision, &digest);
    preview["declaration"] = corrupt;
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        preview,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("invalid_sql_need"),
        "a malformed preview declaration refuses at admission"
    );
}

#[tokio::test]
async fn string_only_snapshot_keeps_its_shape_and_digest() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let read = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    // No SQL needs declared: no `sql` member appears in the input object.
    assert!(read["input"].get("sql").is_none());
    let entry = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(
        entry["declaration_digest"],
        "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15",
        "string-only declarations digest exactly as before the SQL slice"
    );
}

#[tokio::test]
async fn sql_snapshot_truncates_each_need_at_two_hundred_rows() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    for index in 0..205 {
        let id = format!("d4d00000-0000-4000-8000-{index:012}");
        ready_task(
            &registry,
            &db,
            &id,
            &format!("Bulk {index}"),
            "open",
            None,
            None,
        )
        .await;
        grant(&db, &id, ALICE, Capability::View).await;
    }
    let text = "SELECT id, name FROM records ORDER BY id";
    let declaration = json!({
        "needs": [sql_need("lane.bulk", "Bulk", text)],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.bulk", declaration).await;
    let snapshot = sql_snapshot(&registry, &db, ALICE, "agent.bulk", &event)
        .await
        .unwrap();
    let lane = &snapshot["input"]["sql"]["lane.bulk"];
    let direct = direct_sql(&registry, &db, ALICE, text).await.unwrap();
    let full_len = direct["rows"].as_array().unwrap().len();
    assert!(full_len > 200);
    // Delivered rows stop at the cap while `row_count` reports the full
    // "200 of N", so a package can show the tail it did not receive.
    assert_eq!(lane["rows"].as_array().unwrap().len(), 200);
    assert_eq!(lane["row_count"], json!(full_len));
    assert_eq!(lane["truncated"], true);
    assert!(lane["truncation_hint"].is_string());
    // Truncation drops the tail, never reorders or reshapes.
    assert_eq!(
        lane["rows"],
        json!(direct["rows"].as_array().unwrap()[..200])
    );
}

#[tokio::test]
async fn sql_snapshot_digest_moves_on_tail_growth_past_the_cap() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // SQL-only install: the digest fences the SQL rows alone, so this locks
    // that tail growth past the 200-row cap moves the digest while the
    // delivered 200-row prefix is byte-identical.
    let text = "SELECT id FROM records ORDER BY id";
    let declaration = json!({
        "needs": [sql_need("lane.tail", "Tail", text)],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.tail", declaration).await;
    for index in 0..201 {
        let id = format!("e5d00000-0000-4000-8000-{index:012}");
        ready_task(
            &registry,
            &db,
            &id,
            &format!("Tail {index}"),
            "open",
            None,
            None,
        )
        .await;
        grant(&db, &id, ALICE, Capability::View).await;
    }
    let before = sql_snapshot(&registry, &db, ALICE, "agent.tail", &event)
        .await
        .unwrap();
    assert_eq!(
        before["input"]["sql"]["lane.tail"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        200
    );
    let before_count = before["input"]["sql"]["lane.tail"]["row_count"]
        .as_u64()
        .unwrap();
    let grown_id = "e5d00000-0000-4000-8000-000000000201";
    ready_task(&registry, &db, grown_id, "Tail 201", "open", None, None).await;
    grant(&db, grown_id, ALICE, Capability::View).await;
    let after = sql_snapshot(&registry, &db, ALICE, "agent.tail", &event)
        .await
        .unwrap();
    assert_eq!(
        after["input"]["sql"]["lane.tail"]["rows"], before["input"]["sql"]["lane.tail"]["rows"],
        "the delivered 200-row prefix is unchanged"
    );
    assert_eq!(
        after["input"]["sql"]["lane.tail"]["row_count"],
        json!(before_count + 1)
    );
    assert_ne!(
        after["revision"]["revision_digest"], before["revision"]["revision_digest"],
        "one more row past the cap still moves the digest"
    );
}

// Parameterised SQL needs: one authored tab serves many values. Values bind
// positionally through the ordinary `query_sql` handler under the viewer's
// authority, so a parameter can never widen what the viewer sees.

const PARAM_BY_LIFECYCLE_SQL: &str =
    "SELECT id, name FROM records WHERE deleted_at IS NULL AND lifecycle = ?1 ORDER BY id ASC";
const PARAM_BY_ID_SQL: &str = "SELECT id, name FROM records WHERE id = ?1";
const PARAM_SINCE_SQL: &str =
    "SELECT id FROM records WHERE deleted_at IS NULL AND created_at_ms > ?1 ORDER BY id ASC";

fn param_need(key: &str, label: &str, sql: &str, params: Value) -> Value {
    json!({"need": "sql.snapshot.v1", "key": key, "label": label, "sql": sql, "params": params})
}

fn param_declaration() -> Value {
    json!({
        "needs": [
            "attention.query.v1",
            sql_need("lane.fixed", "Fixed", "SELECT count(*) AS n FROM records WHERE deleted_at IS NULL"),
            param_need("lane.by_lifecycle", "By lifecycle", PARAM_BY_LIFECYCLE_SQL,
                json!([{"name": "lifecycle", "type": "text", "max_len": 32}])),
            param_need("lane.by_id", "By id", PARAM_BY_ID_SQL,
                json!([{"name": "record_id", "type": "text", "max_len": 64}])),
            param_need("lane.since", "Since", PARAM_SINCE_SQL,
                json!([{"name": "since_ms", "type": "timestamp_ms"}])),
        ],
        "effects": [],
    })
}

async fn sql_param_read(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    package: &str,
    event: &str,
    key: &str,
    params: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": package,
            "expected_install_event_id": event,
            "need": key,
            "params": params,
        }),
    )
    .await
}

async fn direct_param_sql(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    sql: &str,
    parameters: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "query_sql",
        json!({"sql": sql, "parameters": parameters}),
    )
    .await
}

async fn param_fixture(registry: &ToolRegistry, db: &Db) -> (String, String) {
    configure_preview_launch();
    adopt_fixture_artifact(registry, db).await;
    ready_task(
        registry,
        db,
        "e2e00000-0000-4000-8000-0000000000a1",
        "Alice only",
        "open",
        None,
        None,
    )
    .await;
    ready_task(
        registry,
        db,
        "e2e00000-0000-4000-8000-0000000000a2",
        "Shared",
        "open",
        None,
        None,
    )
    .await;
    grant(
        db,
        "e2e00000-0000-4000-8000-0000000000a1",
        ALICE,
        Capability::View,
    )
    .await;
    replace_explicit_policy(
        db,
        "test:policy",
        "e2e00000-0000-4000-8000-0000000000a2",
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let declaration = param_declaration();
    let alice = adopted_with_package(registry, db, ALICE, "agent.param", declaration.clone()).await;
    let bea = adopted_with_package(registry, db, BEA, "agent.param", declaration).await;
    (alice, bea)
}

#[tokio::test]
async fn sql_param_read_matches_direct_query_sql_for_two_viewers() {
    let (db, registry) = fixture().await;
    let (alice_event, bea_event) = param_fixture(&registry, &db).await;
    for (account, event) in [(ALICE, alice_event.as_str()), (BEA, bea_event.as_str())] {
        let read = sql_param_read(
            &registry,
            &db,
            account,
            "agent.param",
            event,
            "lane.by_lifecycle",
            json!({"lifecycle": "open"}),
        )
        .await
        .unwrap();
        let direct = direct_param_sql(
            &registry,
            &db,
            account,
            PARAM_BY_LIFECYCLE_SQL,
            json!([{"type": "text", "value": "open"}]),
        )
        .await
        .unwrap();
        let result = &read["result"];
        assert_eq!(result["columns"], direct["columns"], "{account} columns");
        assert_eq!(result["rows"], direct["rows"], "{account} rows");
        assert_eq!(
            result["row_count"], direct["row_count"],
            "{account} row_count"
        );
        assert_eq!(
            result["truncated"], direct["truncated"],
            "{account} truncated"
        );
        assert_eq!(read["need"], json!("lane.by_lifecycle"));
        assert!(read.to_string().find("as_of_seq").is_none());
    }
    // Access splits the viewers: Bea never sees the Alice-only row.
    let names = |read: &Value| {
        read["result"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let alice = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.by_lifecycle",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap();
    let bea = sql_param_read(
        &registry,
        &db,
        BEA,
        "agent.param",
        &bea_event,
        "lane.by_lifecycle",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap();
    assert_eq!(
        names(&alice),
        vec!["Alice only".to_string(), "Shared".to_string()]
    );
    assert_eq!(names(&bea), vec!["Shared".to_string()]);
}

#[tokio::test]
async fn sql_param_cannot_widen_visibility() {
    let (db, registry) = fixture().await;
    let (alice_event, bea_event) = param_fixture(&registry, &db).await;
    let hidden = "e2e00000-0000-4000-8000-0000000000a1";
    // Bea names the Alice-only record directly: the parameter binds as data
    // under her own authority, so it returns nothing.
    let bea = sql_param_read(
        &registry,
        &db,
        BEA,
        "agent.param",
        &bea_event,
        "lane.by_id",
        json!({"record_id": hidden}),
    )
    .await
    .unwrap();
    assert_eq!(bea["result"]["rows"], json!([]));
    assert_eq!(bea["result"]["row_count"], json!(0));
    let direct = direct_param_sql(
        &registry,
        &db,
        BEA,
        PARAM_BY_ID_SQL,
        json!([{"type": "text", "value": hidden}]),
    )
    .await
    .unwrap();
    assert_eq!(bea["result"]["rows"], direct["rows"]);
    // Alice names the same record and sees it: the value, not the
    // statement, decides, and her authority covers it.
    let alice = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.by_id",
        json!({"record_id": hidden}),
    )
    .await
    .unwrap();
    assert_eq!(alice["result"]["rows"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn sql_param_refusals_name_all_three_codes() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    let read = |params: Value| {
        sql_param_read(
            &registry,
            &db,
            ALICE,
            "agent.param",
            &alice_event,
            "lane.by_lifecycle",
            params,
        )
    };
    let error = read(json!({"lifecycle": "open", "other": "x"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown_sql_param"), "{error}");
    let error = read(json!({})).await.unwrap_err().to_string();
    assert!(error.contains("missing_sql_param"), "{error}");
    for bad in [
        json!({"lifecycle": 7}),
        json!({"lifecycle": "x".repeat(33)}),
        json!({"lifecycle": ["open"]}),
    ] {
        let error = read(bad.clone()).await.unwrap_err().to_string();
        assert!(error.contains("invalid_sql_param"), "{bad}: {error}");
    }
    // A key no declaration holds is not an on-request need at all.
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.missing",
        json!({}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("undeclared_need"), "{error}");
}

#[tokio::test]
async fn sql_param_injection_shaped_text_is_data() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    let probe = "' OR '1'='1";
    let read = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.by_lifecycle",
        json!({"lifecycle": probe}),
    )
    .await
    .unwrap();
    // Bound as a text parameter, the probe matches no lifecycle value and
    // widens nothing: zero rows, same as a direct parameterised call.
    assert_eq!(read["result"]["rows"], json!([]));
    let direct = direct_param_sql(
        &registry,
        &db,
        ALICE,
        PARAM_BY_LIFECYCLE_SQL,
        json!([{"type": "text", "value": probe}]),
    )
    .await
    .unwrap();
    assert_eq!(read["result"]["rows"], direct["rows"]);
}

#[tokio::test]
async fn sql_param_timestamp_binds_and_matches_direct_call() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    let read = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.since",
        json!({"since_ms": 0}),
    )
    .await
    .unwrap();
    let direct = direct_param_sql(
        &registry,
        &db,
        ALICE,
        PARAM_SINCE_SQL,
        json!([{"type": "integer", "value": "0"}]),
    )
    .await
    .unwrap();
    assert_eq!(read["result"]["rows"], direct["rows"]);
    assert!(!read["result"]["rows"].as_array().unwrap().is_empty());
    // A non-integer timestamp value is a type refusal, not a silent cast.
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.since",
        json!({"since_ms": "long ago"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("invalid_sql_param"), "{error}");
}

#[tokio::test]
async fn sql_snapshot_skips_parameterised_needs_and_keeps_mixed_declarations() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    let snapshot = sql_snapshot(&registry, &db, ALICE, "agent.param", &alice_event)
        .await
        .unwrap();
    let sql = &snapshot["input"]["sql"];
    // The param-less need runs in the snapshot unchanged.
    assert_eq!(
        sql["lane.fixed"]["row_count"],
        direct_sql(
            &registry,
            &db,
            ALICE,
            "SELECT count(*) AS n FROM records WHERE deleted_at IS NULL"
        )
        .await
        .unwrap()["row_count"]
    );
    // Parameterised needs carry no values here, so the snapshot skips them.
    for key in ["lane.by_lifecycle", "lane.by_id", "lane.since"] {
        assert!(sql.get(key).is_none(), "snapshot must skip {key}");
    }
    // And the on-request path still serves a skipped key afterwards.
    let read = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.by_lifecycle",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap();
    assert_eq!(read["result"]["rows"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn sql_param_less_need_reads_on_request_like_its_snapshot() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    let snapshot = sql_snapshot(&registry, &db, ALICE, "agent.param", &alice_event)
        .await
        .unwrap();
    let snap = snapshot["input"]["sql"]["lane.fixed"].clone();
    // Omitted params and an explicit empty object take the same path: a
    // param-less need binds nothing and runs the same statement.
    let omitted = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.param",
            "expected_install_event_id": alice_event,
            "need": "lane.fixed",
        }),
    )
    .await
    .unwrap();
    let empty = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.fixed",
        json!({}),
    )
    .await
    .unwrap();
    for read in [&omitted, &empty] {
        assert_eq!(read["need"], json!("lane.fixed"));
        assert_eq!(read["result"], snap, "on-request matches the snapshot need");
        assert_eq!(read["result"]["truncated"], json!(false));
        assert!(read["result"]["row_count"].as_u64().is_some());
        assert!(read.to_string().find("as_of_seq").is_none());
    }
    // A param-less need declares no names, so any supplied param is unknown.
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.fixed",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown_sql_param"), "{error}");
}

// ---- Completeness and keyset paging past query_sql's own cap (232e8f5) ----
//
// `row_count` is the count `query_sql` returned, and `query_sql` stops at
// 1,000 rows. `row_count_complete` says whether that count is the true
// total, so a tab can never print a false "of N". Paging past 200 (and past
// 1,000) is the canonical keyset pattern: an `after_key` text param, a
// predicate on a unique key and `ORDER BY` that key, `LIMIT` at the cap.

const KEYSET_PAGE_SQL: &str = "SELECT id, name FROM records WHERE deleted_at IS NULL AND type = 'WorkItem' AND id > ?1 ORDER BY id ASC LIMIT 200";

fn bulk_id(prefix: &str, index: usize) -> String {
    format!("{prefix}-0000-4000-8000-{index:012}")
}

/// `count` open tasks, created out of order so only `ORDER BY` can order
/// them. Every index `≡ 3 (mod 7)` is filed in a folder whose explicit
/// policy grants BEA only, so ALICE never sees it; the rest are filed in a
/// folder granting ALICE. Returns ALICE's ids, sorted.
///
/// Setup cost matters at this scale, so the tasks inherit their folder's
/// policy boundary (two policy writes, not one per task) and are appended
/// through the engine's own record path in batched write transactions
/// (`store::append_batch`) rather than one MCP tool call each. What the tests
/// read, and the between-page revocation, still go through the production
/// tool and authorisation paths.
async fn bulk_visible_tasks(db: &Db, prefix: &str, count: usize) -> Vec<String> {
    use native_ce::store::{append_batch, create_record as create_raw_record, AppendSpec};
    let alice_folder = format!("{prefix}-0000-4000-8000-a11ce0000000");
    let bea_folder = format!("{prefix}-0000-4000-8000-bea000000000");
    for (folder, account) in [(&alice_folder, ALICE), (&bea_folder, BEA)] {
        create_raw_record(
            db,
            json!({"id": folder, "type": "Collection", "kind": "folder", "name": format!("Bulk for {account}")}),
        )
        .await
        .unwrap();
        grant(db, folder, account, Capability::View).await;
    }
    let order: Vec<usize> = (0..count).map(|step| (step * 7919) % count).collect();
    for chunk in order.chunks(250) {
        let specs = chunk
            .iter()
            .map(|index| AppendSpec {
                record_id: bulk_id(prefix, *index),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "WorkItem", "kind": "task", "name": format!("Bulk {index}"),
                    "body": "Bulk", "lifecycle": "open",
                    "home_id": if index % 7 == 3 { &bea_folder } else { &alice_folder },
                }),
                actor: None,
            })
            .collect();
        append_batch(db, specs).await.unwrap();
    }
    let mut visible: Vec<String> = order
        .into_iter()
        .filter(|index| index % 7 != 3)
        .map(|index| bulk_id(prefix, index))
        .collect();
    visible.sort();
    visible
}

fn result_ids(result: &Value) -> Vec<String> {
    result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn sql_row_count_complete_is_false_exactly_past_query_sqls_own_cap() {
    use native_ce::mcp::tools::alpha_tabs::SQL_NEED_RESULT_FIELDS;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // 1,167 tasks leave exactly 1,000 visible to ALICE.
    let mut visible = bulk_visible_tasks(&db, "c0c00000", 1_167).await;
    assert_eq!(visible.len(), 1_000);
    let all = "SELECT id FROM records WHERE type = 'WorkItem' ORDER BY id";
    let some = "SELECT id FROM records WHERE type = 'WorkItem' AND id < ?1 ORDER BY id";
    let few = "SELECT id FROM records WHERE type = 'WorkItem' ORDER BY id LIMIT 150";
    let declaration = json!({
        "needs": [
            sql_need("lane.all", "All", all),
            sql_need("lane.few", "Few", few),
            param_need("lane.some", "Below a key", some,
                json!([{"name": "below", "type": "text", "max_len": 64}])),
        ],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.complete", declaration).await;

    // Exactly 1,000 visible rows: query_sql did not truncate, so the count
    // is the total even though delivery stops at 200.
    let before = sql_snapshot(&registry, &db, ALICE, "agent.complete", &event)
        .await
        .unwrap();
    let lane = &before["input"]["sql"]["lane.all"];
    assert_eq!(lane["row_count"], json!(1_000));
    assert_eq!(lane["row_count_complete"], true);
    assert_eq!(lane["truncated"], true);
    let mut fields: Vec<&str> = lane
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    let mut expected: Vec<&str> = SQL_NEED_RESULT_FIELDS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        fields, expected,
        "the result carries exactly SQL_NEED_RESULT_FIELDS"
    );

    // One more visible task, sorting last: query_sql now truncates. The
    // rows it returns are unchanged, so only completeness can move the
    // digest, and it must.
    let extra = bulk_id("c0c00000", 999_999);
    ready_task(&registry, &db, &extra, "Bulk extra", "open", None, None).await;
    grant(&db, &extra, ALICE, Capability::View).await;
    visible.push(extra);
    let after = sql_snapshot(&registry, &db, ALICE, "agent.complete", &event)
        .await
        .unwrap();
    let lane = &after["input"]["sql"]["lane.all"];
    let direct = direct_sql(&registry, &db, ALICE, all).await.unwrap();
    assert_eq!(direct["truncated"], true, "query_sql itself truncated");
    assert_eq!(
        lane["row_count"],
        json!(1_000),
        "a floor, not the 1,001 total"
    );
    assert_eq!(lane["row_count_complete"], false);
    assert_eq!(lane["truncated"], true);
    assert_eq!(lane["rows"].as_array().unwrap().len(), 200);
    assert_eq!(lane["rows"], before["input"]["sql"]["lane.all"]["rows"]);
    assert_ne!(
        after["revision"]["revision_digest"], before["revision"]["revision_digest"],
        "crossing query_sql's own cap moves the digest"
    );

    // Below 200: nothing is capped and the count is the total.
    let small = &after["input"]["sql"]["lane.few"];
    assert_eq!(small["row_count"], json!(150));
    assert_eq!(small["row_count_complete"], true);
    assert_eq!(small["truncated"], false);

    // On request, between 200 and 1,000: the delivery cap truncates, but
    // query_sql did not, so "200 of N" is honest.
    let read = |below: String| {
        let (registry, db, event) = (&registry, &db, &event);
        async move {
            sql_param_read(
                registry,
                db,
                ALICE,
                "agent.complete",
                event,
                "lane.some",
                json!({"below": below}),
            )
            .await
            .unwrap()
        }
    };
    let between = read(visible[700].clone()).await;
    assert_eq!(between["result"]["row_count"], json!(700));
    assert_eq!(between["result"]["row_count_complete"], true);
    assert_eq!(between["result"]["truncated"], true);
    // On request, past 1,000: the floor again.
    let past = read(format!("{}~", visible.last().unwrap())).await;
    assert_eq!(past["result"]["row_count"], json!(1_000));
    assert_eq!(past["result"]["row_count_complete"], false);
    assert!(past.to_string().find("as_of_seq").is_none());
}

/// Page `lane.page` from `""` until a short page, calling `between` after
/// each page with the 1-based page number. Asserts every page is whole.
async fn keyset_pages<F, Fut>(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    event: &str,
    mut between: F,
) -> Vec<Vec<String>>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut pages = Vec::new();
    let mut after = String::new();
    loop {
        let read = sql_param_read(
            registry,
            db,
            account,
            "agent.keyset",
            event,
            "lane.page",
            json!({"after_key": after}),
        )
        .await
        .unwrap();
        let result = &read["result"];
        assert_eq!(
            result["truncated"], false,
            "a page at the cap is delivered whole"
        );
        assert_eq!(result["row_count_complete"], true);
        let ids = result_ids(result);
        assert_eq!(result["row_count"], json!(ids.len()));
        let short = ids.len() < 200;
        if let Some(last) = ids.last() {
            assert!(*last > after, "the cursor advances");
            after = last.clone();
        }
        pages.push(ids);
        between(pages.len()).await;
        if short {
            return pages;
        }
        assert!(pages.len() < 20, "paging terminates");
    }
}

#[tokio::test]
async fn sql_keyset_paging_is_deterministic_and_never_duplicates_or_reveals() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // 1,225 tasks: 1,050 visible to ALICE, 175 to BEA only.
    let visible = bulk_visible_tasks(&db, "c2c00000", 1_225).await;
    assert_eq!(visible.len(), 1_050);
    let declaration = json!({
        "needs": [param_need("lane.page", "Every visible task, in pages of 200", KEYSET_PAGE_SQL,
            json!([{"name": "after_key", "type": "text", "max_len": 128}]))],
        "effects": [],
    });
    let alice =
        adopted_with_package(&registry, &db, ALICE, "agent.keyset", declaration.clone()).await;
    let bea = adopted_with_package(&registry, &db, BEA, "agent.keyset", declaration).await;

    // More than 1,000 rows, in whole pages, in id order, with no gaps.
    let pages = keyset_pages(&registry, &db, ALICE, &alice, |_| async {}).await;
    assert_eq!(pages.len(), 6);
    let flat: Vec<String> = pages.concat();
    assert_eq!(
        flat, visible,
        "every visible task once, in id order, no gaps"
    );
    let again: Vec<String> = keyset_pages(&registry, &db, ALICE, &alice, |_| async {})
        .await
        .concat();
    assert_eq!(again, flat, "the same state pages identically");
    // Each page is exactly the viewer's own query_sql for that cursor, so
    // paging never widens authority.
    let mut after = String::new();
    for page in &pages {
        let direct = direct_param_sql(
            &registry,
            &db,
            ALICE,
            KEYSET_PAGE_SQL,
            json!([{"type": "text", "value": after}]),
        )
        .await
        .unwrap();
        assert_eq!(&result_ids(&direct), page);
        after = page.last().cloned().unwrap_or_default();
    }
    // BEA sees only her own tasks through the same package.
    let bea_rows: Vec<String> = keyset_pages(&registry, &db, BEA, &bea, |_| async {})
        .await
        .concat();
    assert_eq!(bea_rows.len(), 175);
    assert!(bea_rows.iter().all(|id| visible.binary_search(id).is_err()));

    // Access changes between pages. After page 2, hide one task already
    // delivered on page 1 and one the cursor has not reached (page 4).
    let seen_then_hidden = visible[150].clone();
    let hidden_ahead = visible[700].clone();
    let pages = keyset_pages(&registry, &db, ALICE, &alice, |page| {
        let db = db.clone();
        let (seen, ahead) = (seen_then_hidden.clone(), hidden_ahead.clone());
        async move {
            if page == 2 {
                revoke_all(&db, &seen).await;
                revoke_all(&db, &ahead).await;
            }
        }
    })
    .await;
    let flat: Vec<String> = pages.concat();
    assert!(
        flat.windows(2).all(|pair| pair[0] < pair[1]),
        "strict id order, so no record appears twice"
    );
    assert!(
        !flat.contains(&hidden_ahead),
        "a record hidden before its page is read is never revealed"
    );
    assert_eq!(
        flat.iter().filter(|id| **id == seen_then_hidden).count(),
        1,
        "a record hidden after its page was read appears exactly once"
    );
    let expected: Vec<String> = visible
        .iter()
        .filter(|id| **id != hidden_ahead)
        .cloned()
        .collect();
    assert_eq!(
        flat, expected,
        "no gaps: everything visible when its page was read"
    );
    // A fresh read after the change sees neither hidden task.
    let fresh: Vec<String> = keyset_pages(&registry, &db, ALICE, &alice, |_| async {})
        .await
        .concat();
    assert!(!fresh.contains(&seen_then_hidden) && !fresh.contains(&hidden_ahead));
    assert_eq!(fresh.len(), visible.len() - 2);
}
// Declared-SQL reads re-check tab consent inside their own governed data
// transaction (task `7fee345`): gate and parameter refusals keep their own
// codes in gates->declaration->params order, and only execution failures
// carry `sql_need_failed`.

#[tokio::test]
async fn sql_inner_gate_refusals_stay_unwrapped_and_ordered() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    // Live install: gates pass, so parameter refusals keep their own codes.
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.by_lifecycle",
        json!({}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("missing_sql_param"), "{error}");
    assert!(!error.contains("sql_need_failed"), "{error}");
    // Unknown SQL key: undeclared_need, never the execution wrapper.
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.missing",
        json!({}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("undeclared_need"), "{error}");
    assert!(!error.contains("sql_need_failed"), "{error}");
    // Stale generation token: cas_mismatch, still unwrapped.
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        "stale-event-id",
        "lane.by_lifecycle",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("cas_mismatch"), "{error}");
    assert!(!error.contains("sql_need_failed"), "{error}");
    // Disabled install: the gate refusal names the state, not execution.
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action":"disable","package":"agent.param",
            "expected_install_event_id":alice_event,"reason":"Pause SQL reads."}),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"].as_str().unwrap();
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        disabled_event,
        "lane.by_lifecycle",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("disabled"), "{error}");
    assert!(!error.contains("sql_need_failed"), "{error}");
}

#[tokio::test]
async fn sql_inner_gate_refuses_view_loss_unwrapped() {
    let (db, registry) = fixture().await;
    let (alice_event, _) = param_fixture(&registry, &db).await;
    revoke_all(&db, ARTIFACT_A).await;
    let error = sql_param_read(
        &registry,
        &db,
        ALICE,
        "agent.param",
        &alice_event,
        "lane.by_lifecycle",
        json!({"lifecycle": "open"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unauthorized"), "{error}");
    assert!(!error.contains("sql_need_failed"), "{error}");
}

#[tokio::test]
async fn sql_snapshot_warm_governed_reuse_is_deterministic() {
    // Warm reuse across sequential snapshots on the shared governed pool.
    // The hard same-connection proof (physical identity, unqualified
    // gate-style reads after prior SQL) lives at lib level, where the pool
    // is directly drivable; no process-global state is touched here.
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.ready", ready_declaration()).await;
    let first = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    let second = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    // Per-need statement clocks tick by design, so compare everything but
    // `now_ms_ms`: rows, counts, flags, and the digest over them.
    for key in ["ready.unblocked", "ready.stalled", "ready.proposed"] {
        for field in [
            "columns",
            "rows",
            "row_count",
            "truncated",
            "time_dependent",
        ] {
            assert_eq!(
                first["input"]["sql"][key][field], second["input"]["sql"][key][field],
                "{key}.{field}"
            );
        }
    }
    assert_eq!(
        first["revision"]["revision_digest"],
        second["revision"]["revision_digest"]
    );
    assert!(first.to_string().find("as_of_seq").is_none());
}

#[tokio::test]
async fn sql_snapshot_hidden_writes_leave_alice_digest_unchanged() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.ready", ready_declaration()).await;
    let before = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    // A Bea-only row is invisible to Alice: her SQL digest must not move.
    ready_task(
        &registry,
        &db,
        "d1d00000-0000-4000-8000-0000000000b9",
        "Bea only",
        "open",
        Some("proposed"),
        None,
    )
    .await;
    grant(
        &db,
        "d1d00000-0000-4000-8000-0000000000b9",
        BEA,
        Capability::View,
    )
    .await;
    let after = sql_snapshot(&registry, &db, ALICE, "agent.ready", &event)
        .await
        .unwrap();
    assert_eq!(
        before["revision"]["revision_digest"], after["revision"]["revision_digest"],
        "hidden writes must not move a viewer SQL digest"
    );
}

#[tokio::test]
async fn sql_clock_need_rows_match_direct_and_digest_holds() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let snapshot = sql_snapshot(&registry, &db, ALICE, "agent.clock", &event)
        .await
        .unwrap();
    let direct = direct_sql(&registry, &db, ALICE, CLOCK_SQL).await.unwrap();
    assert_eq!(
        snapshot["input"]["sql"]["lane.clock"]["rows"], direct["rows"],
        "clock-need rows match the viewer's own query"
    );
    assert_eq!(
        snapshot["input"]["sql"]["lane.clock"]["row_count"],
        direct["row_count"]
    );
    assert_eq!(
        snapshot["input"]["sql"]["lane.clock"]["time_dependent"],
        json!(true)
    );
    let again = sql_snapshot(&registry, &db, ALICE, "agent.clock", &event)
        .await
        .unwrap();
    assert_eq!(
        snapshot["revision"]["revision_digest"], again["revision"]["revision_digest"],
        "a clock-only tick moves no digest"
    );
}

// ---- P1a plugin import end-to-end (task 1bf0e85, S3b) ----
//
// read_folder(team-pulse/) → import_candidate → import_revision_into_alpha
// → manage_alpha_tabs install (bridge outcome values) → attested preview →
// attested adopt → launch, reusing this file's harness. The checked-in
// folder stays untouched: folder-independence copies it to a tempdir.

fn team_pulse_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("experiments/alpha-tab-proof-packages/team-pulse")
}

fn team_pulse_provenance(origin: &str) -> native_ce::plugins::import::ProvenanceInput {
    native_ce::plugins::import::ProvenanceInput {
        adapter: "local_folder".into(),
        origin: json!({"path": origin}),
        requested_ref: None,
        fetched_by: native_ce::plugins::import::FetchedBy::Host,
        importer: ALICE.into(),
        run_key: "p1a-team-pulse".into(),
        at: "2026-09-26T00:00:00Z".into(),
    }
}

async fn plugin_home(db: &Db) -> String {
    native_ce::store::create_record(
        db,
        json!({
            "type": "Collection", "kind": "folder", "name": "Plugin home",
            "persistence": "enduring",
        }),
    )
    .await
    .unwrap()
}

fn bridge_pin_args(outcome: &native_ce::plugins::bridge_alpha::AlphaBridgeOutcome) -> Value {
    json!({
        "package": outcome.package, "version": outcome.version,
        "digest": outcome.alpha_digest, "artifact_id": outcome.artifact_id,
        "source_revision": outcome.source_revision,
        "declaration": outcome.declaration,
    })
}

/// Full P1a flow for the folder at `dir`: import, bridge, install, attested
/// preview, attested adopt. Returns the bridge outcome, the adopted install
/// event, and the revision digest.
async fn import_adopt_team_pulse(
    registry: &ToolRegistry,
    db: &Db,
    dir: &std::path::Path,
    origin: &str,
) -> (
    native_ce::plugins::bridge_alpha::AlphaBridgeOutcome,
    String,
    String,
) {
    let read = native_ce::plugins::source_local::read_folder(dir).unwrap();
    let revision = native_ce::plugins::import::import_candidate(
        &read.candidate,
        &team_pulse_provenance(origin),
    )
    .unwrap();
    let digest = revision.digest.clone();
    let home_id = plugin_home(db).await;
    let outcome = native_ce::plugins::bridge_alpha::import_revision_into_alpha(
        db,
        &Caller::local(),
        &revision,
        &home_id,
        "Bridge the imported team pulse revision.",
    )
    .await
    .unwrap();
    assert!(outcome.created);
    assert_eq!(outcome.package, "agent.team-pulse");
    assert_eq!(outcome.version, "0.1.0");
    let (_, adopted_event) = adopt_pinned_tab(registry, db, &outcome).await;
    (outcome, adopted_event, digest)
}

/// Install a bridged outcome, attested-preview it, attest-adopt it: the
/// shared tail of every P1a end-to-end test. Returns the install event and
/// the adopted event.
async fn adopt_pinned_tab(
    registry: &ToolRegistry,
    db: &Db,
    outcome: &native_ce::plugins::bridge_alpha::AlphaBridgeOutcome,
) -> (String, String) {
    let installed_event = install_pinned_tab(registry, db, outcome, None).await;
    let adopted_event = preview_adopt_pinned_tab(registry, db, outcome, &installed_event).await;
    (installed_event, adopted_event)
}

async fn install_pinned_tab(
    registry: &ToolRegistry,
    db: &Db,
    outcome: &native_ce::plugins::bridge_alpha::AlphaBridgeOutcome,
    expected_install_event_id: Option<&str>,
) -> String {
    grant(db, &outcome.artifact_id, ALICE, Capability::View).await;
    let mut install = bridge_pin_args(outcome);
    install["action"] = json!("install");
    install["reason"] = json!("Install the imported team pulse.");
    if let Some(expected) = expected_install_event_id {
        install["expected_install_event_id"] = json!(expected);
    }
    let installed = call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install,
    )
    .await
    .unwrap();
    let event_id = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    event_id
}

async fn preview_adopt_pinned_tab(
    registry: &ToolRegistry,
    db: &Db,
    outcome: &native_ce::plugins::bridge_alpha::AlphaBridgeOutcome,
    event_id: &str,
) -> String {
    let mut preview = bridge_pin_args(outcome);
    preview["action"] = json!("preview");
    preview["reason"] = json!("Preview the imported team pulse against sample input.");
    let previewed = call_as(
        registry,
        db,
        attested_preview_caller(ALICE, &preview),
        "manage_alpha_tabs",
        preview,
    )
    .await
    .unwrap();
    let receipt = &previewed["receipt"];
    let mut adopt = bridge_pin_args(outcome);
    adopt["action"] = json!("adopt");
    adopt["receipt_id"] = receipt["receipt_id"].clone();
    adopt["nonce"] = receipt["nonce"].clone();
    adopt["preview_session"] = receipt["preview_session"].clone();
    adopt["expected_install_event_id"] = json!(event_id);
    adopt["reason"] = json!("Adopt the previewed team pulse.");
    let adopted = call_as(
        registry,
        db,
        attested_adopt_caller(ALICE, &adopt),
        "manage_alpha_tabs",
        adopt,
    )
    .await
    .unwrap();
    let adopted_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
    adopted_event
}

#[tokio::test]
async fn plugin_imported_tab_previews_adopts_and_launches() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    let dir = team_pulse_dir();
    let (outcome, adopted_event, digest) =
        import_adopt_team_pulse(&registry, &db, &dir, "/checked/in").await;
    // The artifact's package_digest facet equals the revision digest.
    let pool = crate::common::fixture_write_pool(&db).await;
    let facet: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'package_digest'",
    )
    .bind(&outcome.artifact_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(facet, digest);
    // Launch passes the pin check over the retained bytes.
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.team-pulse",
            "expected_install_event_id": adopted_event}),
    )
    .await
    .unwrap();
    assert_eq!(launch["pin"]["digest"], outcome.alpha_digest);
    assert_eq!(launch["pin"]["source_revision"], outcome.source_revision);
    assert_eq!(launch["source"]["event_id"], outcome.source_revision);
    assert_eq!(launch["source"]["runtime"], "native.html.v1");
}

#[tokio::test]
async fn imported_tab_survives_folder_deletion_and_disable() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    // Copy the checked-in folder to a tempdir and import from the copy.
    let src = team_pulse_dir();
    let tmp = tempfile::tempdir().unwrap();
    let copy = tmp.path().join("team-pulse");
    std::fs::create_dir_all(copy.join("dist")).unwrap();
    std::fs::write(
        copy.join("native-package.json"),
        std::fs::read(src.join("native-package.json")).unwrap(),
    )
    .unwrap();
    std::fs::write(
        copy.join("dist/team-pulse.html"),
        std::fs::read(src.join("dist/team-pulse.html")).unwrap(),
    )
    .unwrap();
    // Plugin-created data before disable: an ordinary note record.
    note(&registry, &db, NOTE).await;
    let (outcome, adopted_event, _) =
        import_adopt_team_pulse(&registry, &db, &copy, "/tmp/copy").await;
    // Delete the source folder: the adopted tab still launches.
    std::fs::remove_dir_all(&copy).unwrap();
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.team-pulse",
            "expected_install_event_id": adopted_event}),
    )
    .await
    .unwrap();
    assert_eq!(launch["pin"]["digest"], outcome.alpha_digest);
    // Disable: launch refuses with the fallback reason.
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "disable", "package": "agent.team-pulse",
            "expected_install_event_id": adopted_event, "reason": "Pause the pulse."}),
    )
    .await
    .unwrap();
    assert_eq!(disabled["install"]["status"], "disabled");
    let disabled_event = disabled["install"]["event_id"].as_str().unwrap();
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.team-pulse",
            "expected_install_event_id": disabled_event}),
    )
    .await;
    assert!(refused.unwrap_err().to_string().contains("disabled"));
    // The data it created remains readable.
    let pool = crate::common::fixture_write_pool(&db).await;
    let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
        .bind(NOTE)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(body, "not an artifact");
}

#[tokio::test]
async fn plugin_attention_cockpit_golden_digest_and_launch() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("experiments/alpha-tab-proof-packages/attention-cockpit");
    let read = native_ce::plugins::source_local::read_folder(&dir).unwrap();
    let revision = native_ce::plugins::import::import_candidate(
        &read.candidate,
        &team_pulse_provenance("/checked/in"),
    )
    .unwrap();
    // The non-empty declaration survives the mapping end to end.
    assert_eq!(
        revision.manifest.declared.reads,
        vec!["attention.query.v1".to_string()]
    );
    let home_id = plugin_home(&db).await;
    let outcome = native_ce::plugins::bridge_alpha::import_revision_into_alpha(
        &db,
        &Caller::local(),
        &revision,
        &home_id,
        "Bridge the imported attention cockpit revision.",
    )
    .await
    .unwrap();
    // Golden: the bridge digest equals install-descriptors.json's
    // alpha-tab-digest.v1 over the same bytes and declaration.
    assert_eq!(
        outcome.alpha_digest,
        "sha256:cccc7d69fb428cfed6129a52bda468a8c1662e961778270aec6e0651af872680"
    );
    assert_eq!(
        outcome.declaration,
        json!({"needs": ["attention.query.v1"], "effects": []})
    );
    let (_, adopted_event) = adopt_pinned_tab(&registry, &db, &outcome).await;
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.attention-cockpit",
            "expected_install_event_id": adopted_event}),
    )
    .await
    .unwrap();
    assert_eq!(launch["pin"]["digest"], outcome.alpha_digest);
    assert_eq!(launch["source"]["event_id"], outcome.source_revision);
}

#[tokio::test]
async fn foreign_import_preserves_alpha_installs_but_requires_fresh_adoption() {
    // Native task c5b9159, acceptance 6: slice 3 closes the missing alpha
    // projection rebuild gap. Foreign import now retains the pin and appends
    // a sealed consent reset, so imported code needs fresh Preview -> Adopt.
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let (event_id, receipt_id, nonce, preview_session) =
        installed_and_previewed(&registry, &db, ALICE).await;
    let args = adopt_args(
        ARTIFACT_A,
        &source_revision,
        &digest,
        &receipt_id,
        &nonce,
        &preview_session,
        &event_id,
    );
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();
    let bytes = native_ce::interchange::export_canonical_interchange(&db)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let imported = native_ce::interchange::import_canonical_interchange(
        &bytes,
        &tmp.path().join("imported.db"),
        native_ce::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let inspected = call_as(
        &registry,
        &imported,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": "agent.attention-cockpit"}),
    )
    .await
    .unwrap();
    assert_eq!(inspected["installed"], true);
    let install = &inspected["install"];
    for field in [
        "package",
        "version",
        "digest",
        "artifact_id",
        "consented_source_revision",
        "declaration_digest",
        "consented_declaration",
        "request",
        "status",
    ] {
        assert_eq!(
            install[field], adopted["install"][field],
            "pin field {field}"
        );
    }
    assert_eq!(install["adoption"], "caller_asserted");
    assert_eq!(install["adoption_basis"], "requires_adoption");
    assert!(install["adoption_provenance"].is_null());
    assert_ne!(install["event_id"], adopted["install"]["event_id"]);
    let refused = call_as(
        &registry,
        &imported,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.attention-cockpit",
            "expected_install_event_id": install["event_id"]}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(refused.contains("adoption_unverified"), "{refused}");
    let pool = crate::common::fixture_write_pool(&imported).await;
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM control_events WHERE id=? AND type='alpha_tab.import_reset'",
    )
    .bind(install["event_id"].as_str().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    let reset: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(reset["pin"]["account_id"], ALICE);
    assert_eq!(reset["pin"]["package"], "agent.attention-cockpit");
    assert_eq!(
        reset["pin"]["previous_event_id"],
        adopted["install"]["event_id"]
    );
    assert_eq!(reset["pin"]["adoption"], "caller_asserted");
    assert!(reset["adoption_provenance"].is_null());
    assert!(
        native_ce::conformance::rebuild_and_diff_control(&imported)
            .await
            .unwrap()
            .equal
    );
    imported.close().await;
    db.close().await;
}

#[tokio::test]
async fn new_revision_digest_needs_fresh_preview_and_adopt() {
    use sha2::Digest;
    configure_preview_launch();
    let (db, registry) = fixture().await;
    let dir = team_pulse_dir();
    let (outcome_v1, adopted_v1, _) =
        import_adopt_team_pulse(&registry, &db, &dir, "/checked/in").await;
    // Changed revision: one byte changed, version bumped to 0.1.1.
    let tmp = tempfile::tempdir().unwrap();
    let copy = tmp.path().join("team-pulse");
    std::fs::create_dir_all(copy.join("dist")).unwrap();
    let mut bundle = std::fs::read(dir.join("dist/team-pulse.html")).unwrap();
    bundle.extend_from_slice(b"<!-- 0.1.1 -->");
    std::fs::write(copy.join("dist/team-pulse.html"), &bundle).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("native-package.json")).unwrap()).unwrap();
    manifest["version"] = json!("0.1.1");
    manifest["files"][0]["sha256"] = json!(format!("{:x}", sha2::Sha256::digest(&bundle)));
    manifest["files"][0]["bytes_len"] = json!(bundle.len());
    std::fs::write(
        copy.join("native-package.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let read = native_ce::plugins::source_local::read_folder(&copy).unwrap();
    let revision = native_ce::plugins::import::import_candidate(
        &read.candidate,
        &team_pulse_provenance("/tmp/v2"),
    )
    .unwrap();
    let home_id = plugin_home(&db).await;
    let outcome = native_ce::plugins::bridge_alpha::import_revision_into_alpha(
        &db,
        &Caller::local(),
        &revision,
        &home_id,
        "Bridge team pulse 0.1.1.",
    )
    .await
    .unwrap();
    assert!(outcome.created);
    assert_eq!(outcome.version, "0.1.1");
    assert_ne!(outcome.alpha_digest, outcome_v1.alpha_digest);
    assert_ne!(outcome.artifact_id, outcome_v1.artifact_id);
    // Installed but not yet approved: launch refuses. The normal alpha
    // update path removes the old install first, then chains the new one.
    let removed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "remove", "package": "agent.team-pulse",
            "expected_install_event_id": adopted_v1,
            "reason": "Replace with the new revision."}),
    )
    .await
    .unwrap();
    let removed_event = removed["install"]["event_id"].as_str().unwrap().to_string();
    let installed_event = install_pinned_tab(&registry, &db, &outcome, Some(&removed_event)).await;
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.team-pulse",
            "expected_install_event_id": installed_event}),
    )
    .await;
    assert!(refused
        .unwrap_err()
        .to_string()
        .contains("adoption_unverified"));
    // Fresh attested preview + adopt, then launch passes.
    let adopted_event = preview_adopt_pinned_tab(&registry, &db, &outcome, &installed_event).await;
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": "agent.team-pulse",
            "expected_install_event_id": adopted_event}),
    )
    .await
    .unwrap();
    assert_eq!(launch["pin"]["digest"], outcome.alpha_digest);
}

/// Section cell text by column name (`{"type":"text","value":...}`).
fn section_cell(row: &Value, columns: &[String], name: &str) -> Option<String> {
    let index = columns.iter().position(|column| column == name)?;
    match row.get(index)?.get("value") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn find_section<'a>(bundle: &'a Value, name: &str) -> &'a Value {
    bundle["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["name"] == name)
        .unwrap_or_else(|| panic!("interchange section {name} missing"))
}

#[tokio::test]
async fn imported_revision_bytes_survive_export_import_and_fresh_adoption() {
    // Native task c5b9159, acceptance 6: slice 3 makes the exported alpha pin
    // reconstructible. Foreign import resets consent; prove the retained bytes
    // launch after a new browser Preview -> Adopt, rather than carrying consent.
    configure_preview_launch();
    let (db, registry) = fixture().await;
    let dir = team_pulse_dir();
    let (outcome, _adopted_event, digest) =
        import_adopt_team_pulse(&registry, &db, &dir, "/checked/in").await;
    let bytes = native_ce::interchange::export_canonical_interchange(&db)
        .await
        .unwrap();
    let bundle: Value = serde_json::from_slice(&bytes).unwrap();
    let columns_of = |section: &Value| {
        section["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|column| column["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    // The artifact record and its live facets travelled.
    let facet_values = find_section(&bundle, "facet_values");
    let facet_columns = columns_of(facet_values);
    let mut saw_digest = false;
    let mut saw_manifest = false;
    for row in facet_values["rows"].as_array().unwrap() {
        if section_cell(row, &facet_columns, "record_id").as_deref()
            != Some(outcome.artifact_id.as_str())
        {
            continue;
        }
        match section_cell(row, &facet_columns, "key").as_deref() {
            Some("package_digest") => {
                assert_eq!(
                    section_cell(row, &facet_columns, "value").as_deref(),
                    Some(digest.as_str())
                );
                saw_digest = true;
            }
            Some("package_manifest") => {
                assert!(section_cell(row, &facet_columns, "value")
                    .unwrap()
                    .contains("native.package-manifest@2"));
                saw_manifest = true;
            }
            _ => {}
        }
    }
    assert!(
        saw_digest && saw_manifest,
        "package facets must be exported"
    );
    // The receipt observations travelled.
    let observations = find_section(&bundle, "facet_observations");
    let observation_columns = columns_of(observations);
    let receipts = observations["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            section_cell(row, &observation_columns, "record_id").as_deref()
                == Some(outcome.artifact_id.as_str())
                && section_cell(row, &observation_columns, "key").as_deref()
                    == Some("package_receipt")
        })
        .count();
    assert!(receipts >= 1, "receipt observations must be exported");
    // The alpha install/adopt events travelled.
    let control = find_section(&bundle, "control_events");
    let control_columns = columns_of(control);
    let mut saw_install = false;
    let mut saw_adopt = false;
    for row in control["rows"].as_array().unwrap() {
        let payload = section_cell(row, &control_columns, "payload").unwrap_or_default();
        if !payload.contains("agent.team-pulse") {
            continue;
        }
        match section_cell(row, &control_columns, "type").as_deref() {
            Some("alpha_tab.installed") => saw_install = true,
            Some("alpha_tab.adopted") => saw_adopt = true,
            _ => {}
        }
    }
    assert!(
        saw_install && saw_adopt,
        "alpha install events must be exported"
    );
    // The alpha pin recomputes from the exported body bytes alone.
    let events = find_section(&bundle, "content_events");
    let event_columns = columns_of(events);
    let mut exported_body = None;
    for row in events["rows"].as_array().unwrap() {
        if section_cell(row, &event_columns, "record_id").as_deref()
            != Some(outcome.artifact_id.as_str())
        {
            continue;
        }
        let payload: Value =
            serde_json::from_str(&section_cell(row, &event_columns, "payload").unwrap_or_default())
                .unwrap_or(Value::Null);
        if let Some(body) = payload.get("body").and_then(Value::as_str) {
            exported_body = Some(body.to_string());
        }
    }
    let exported_body = exported_body.expect("exported artifact body missing");
    let recomputed = {
        use native_ce::mcp::tools::alpha_tabs::{
            alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
        };
        alpha_tab_digest(
            &alpha_tab_bundle_digest(&exported_body),
            &alpha_tab_declaration_digest(&outcome.declaration).unwrap(),
            "native.html.v1",
        )
    };
    assert_eq!(recomputed, outcome.alpha_digest);
    let tmp = tempfile::tempdir().unwrap();
    let imported = native_ce::interchange::import_canonical_interchange(
        &bytes,
        &tmp.path().join("imported-bytes.db"),
        native_ce::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let pool = crate::common::fixture_write_pool(&imported).await;
    let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&outcome.artifact_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(body, exported_body);
    let inspected = call_as(
        &registry,
        &imported,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": outcome.package}),
    )
    .await
    .unwrap();
    assert_eq!(inspected["install"]["adoption_basis"], "requires_adoption");
    let imported_event = inspected["install"]["event_id"].as_str().unwrap();
    let refused = call_as(
        &registry,
        &imported,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": outcome.package,
            "expected_install_event_id": imported_event}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(refused.contains("adoption_unverified"), "{refused}");
    let adopted_event =
        preview_adopt_pinned_tab(&registry, &imported, &outcome, imported_event).await;
    let launched = call_as(
        &registry,
        &imported,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "launch", "package": outcome.package,
            "expected_install_event_id": adopted_event}),
    )
    .await
    .unwrap();
    assert_eq!(launched["pin"]["digest"], outcome.alpha_digest);
    assert_eq!(launched["pin"]["source_revision"], outcome.source_revision);
    assert_eq!(launched["source"]["event_id"], outcome.source_revision);
    assert_eq!(
        launched["source"]["bundle_sha256"],
        native_ce::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&exported_body)
    );
    imported.close().await;
    db.close().await;
}

// Task c5d3820: per-account tab order through `manage_alpha_tabs`.
//
// The shell built-ins keep their default strip order until the viewer (or an
// agent) stores an order with `reorder`; installs interleave freely once
// stored. `list`/`inspect` always report the effective order.

async fn tab_order_of(registry: &ToolRegistry, db: &Db, caller: Caller) -> Value {
    call_as(
        registry,
        db,
        caller,
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap()["tab_order"]
        .clone()
}

async fn order_fixture() -> (Db, ToolRegistry) {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    artifact(&registry, &db, ARTIFACT_B).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    grant(&db, ARTIFACT_B, ALICE, Capability::View).await;
    let alice = Caller::authenticated(ALICE);
    call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.attention-cockpit", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        install_args("agent.team-pulse", ARTIFACT_B, DIGEST_B),
    )
    .await
    .unwrap();
    (db, registry)
}

#[tokio::test]
async fn reorder_stores_interleaved_order_and_list_reports_it() {
    let (db, registry) = order_fixture().await;
    let alice = Caller::authenticated(ALICE);
    assert_eq!(
        tab_order_of(&registry, &db, alice.clone()).await,
        json!([
            "agents",
            "folders",
            "tasks",
            "graph",
            "pending:agent.attention-cockpit",
            "pending:agent.team-pulse",
        ]),
    );
    let wanted = json!([
        "agents",
        "pending:agent.team-pulse",
        "tasks",
        "folders",
        "graph",
        "pending:agent.attention-cockpit",
    ]);
    let reordered = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": wanted, "reason": "Demo wants Task Invaders second."}),
    )
    .await
    .unwrap();
    assert_eq!(reordered["changed"], true, "{reordered:#}");
    assert_eq!(reordered["tab_order"], wanted, "{reordered:#}");
    assert_eq!(tab_order_of(&registry, &db, alice.clone()).await, wanted);
    let inspect = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": "agent.team-pulse"}),
    )
    .await
    .unwrap();
    assert_eq!(inspect["tab_order"], wanted, "{inspect:#}");
}

#[tokio::test]
async fn reorder_refuses_unknown_duplicate_and_uninstalled_tabs() {
    let (db, registry) = order_fixture().await;
    let alice = Caller::authenticated(ALICE);
    for (order, fragment) in [
        (json!(["agents", "nope"]), "unknown tab"),
        (
            json!([
                "agents",
                "agents",
                "folders",
                "tasks",
                "graph",
                "pending:agent.attention-cockpit",
                "pending:agent.team-pulse"
            ]),
            "twice",
        ),
        (
            json!([
                "agents",
                "folders",
                "tasks",
                "graph",
                "pending:agent.never-installed"
            ]),
            "no installed package",
        ),
        // Tabs are arranged, never hidden: all four built-ins required.
        (
            json!([
                "agents",
                "folders",
                "tasks",
                "pending:agent.attention-cockpit",
                "pending:agent.team-pulse"
            ]),
            "omits built-in tab",
        ),
    ] {
        let refused = call_as(
            &registry,
            &db,
            alice.clone(),
            "manage_alpha_tabs",
            json!({"action": "reorder", "tab_order": order, "reason": "Probe refusal."}),
        )
        .await;
        assert!(
            refused.unwrap_err().to_string().contains(fragment),
            "order {order} must fail naming {fragment}"
        );
    }
    // Refusals store nothing: the default still stands.
    assert_eq!(
        tab_order_of(&registry, &db, alice.clone()).await,
        json!([
            "agents",
            "folders",
            "tasks",
            "graph",
            "pending:agent.attention-cockpit",
            "pending:agent.team-pulse",
        ]),
    );
}

#[tokio::test]
async fn reorder_empty_resets_to_default() {
    let (db, registry) = order_fixture().await;
    let alice = Caller::authenticated(ALICE);
    call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder",
               "tab_order": ["graph", "agents", "folders", "tasks",
                             "pending:agent.team-pulse", "pending:agent.attention-cockpit"],
               "reason": "Custom order for the demo."}),
    )
    .await
    .unwrap();
    let reset = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": [], "reason": "Back to default."}),
    )
    .await
    .unwrap();
    assert_eq!(reset["changed"], true, "{reset:#}");
    assert_eq!(
        reset["tab_order"],
        json!([
            "agents",
            "folders",
            "tasks",
            "graph",
            "pending:agent.attention-cockpit",
            "pending:agent.team-pulse",
        ]),
        "{reset:#}"
    );
}

#[tokio::test]
async fn reorder_removed_tab_hides_and_reinstall_restores_position() {
    let (db, registry) = order_fixture().await;
    let alice = Caller::authenticated(ALICE);
    // Park team-pulse second, then remove it: the tab hides but its stored
    // position survives, so a reinstall slots back where it was.
    let wanted = json!([
        "agents",
        "pending:agent.team-pulse",
        "folders",
        "tasks",
        "graph",
        "pending:agent.attention-cockpit",
    ]);
    call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": wanted, "reason": "Park team-pulse second."}),
    )
    .await
    .unwrap();
    let inspect = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": "agent.team-pulse"}),
    )
    .await
    .unwrap();
    let token = inspect["install"]["event_id"].as_str().unwrap().to_string();
    let removed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "remove", "package": "agent.team-pulse",
               "expected_install_event_id": token, "reason": "Drop the tab."}),
    )
    .await
    .unwrap();
    assert_eq!(removed["install"]["status"], "removed");
    assert_eq!(
        tab_order_of(&registry, &db, alice.clone()).await,
        json!([
            "agents",
            "folders",
            "tasks",
            "graph",
            "pending:agent.attention-cockpit",
        ]),
    );
    // A reorder while removed cannot name the tab (no live slot).
    let renamed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": wanted, "reason": "Stale retry."}),
    )
    .await;
    assert!(renamed
        .unwrap_err()
        .to_string()
        .contains("no installed package"));
    // Reinstall slots back into its remembered position.
    let removed_token = removed["install"]["event_id"].as_str().unwrap().to_string();
    let mut reinstall = install_args("agent.team-pulse", ARTIFACT_B, DIGEST_B);
    reinstall["expected_install_event_id"] = json!(removed_token);
    call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        reinstall,
    )
    .await
    .unwrap();
    assert_eq!(tab_order_of(&registry, &db, alice.clone()).await, wanted);
}

#[tokio::test]
async fn reorder_is_per_account_and_idempotent_retry_converges() {
    let (db, registry) = order_fixture().await;
    let alice = Caller::authenticated(ALICE);
    let bea = Caller::authenticated(BEA);
    let wanted = json!([
        "graph",
        "agents",
        "folders",
        "tasks",
        "pending:agent.team-pulse",
        "pending:agent.attention-cockpit",
    ]);
    let first = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": wanted,
               "reason": "Alice demo order.", "idempotency_key": "alice-order-1"}),
    )
    .await
    .unwrap();
    assert_eq!(first["changed"], true, "{first:#}");
    let retry = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": wanted,
               "reason": "Alice demo order.", "idempotency_key": "alice-order-1"}),
    )
    .await
    .unwrap();
    assert_eq!(retry["changed"], false, "{retry:#}");
    assert_eq!(retry["idempotent_retry"], true, "{retry:#}");
    assert_eq!(retry["tab_order"], wanted, "{retry:#}");
    // Bea never reordered: her default still stands.
    assert_eq!(
        tab_order_of(&registry, &db, bea.clone()).await,
        json!(["agents", "folders", "tasks", "graph"]),
    );
}

#[tokio::test]
async fn reorder_returning_to_earlier_order_reapplies_it() {
    // Regression: default keys used to be SHA(tab_order), so A→B→A with the
    // same reason reused A's first event — reporting convergence while B
    // stayed projected (or erroring on a different reason). Keyless calls
    // now mint fresh keys, so returning to A really stores A.
    let (db, registry) = order_fixture().await;
    let alice = Caller::authenticated(ALICE);
    let order_a = json!([
        "agents",
        "pending:agent.team-pulse",
        "folders",
        "tasks",
        "graph",
        "pending:agent.attention-cockpit",
    ]);
    let order_b = json!([
        "graph",
        "agents",
        "folders",
        "tasks",
        "pending:agent.team-pulse",
        "pending:agent.attention-cockpit",
    ]);
    for order in [&order_a, &order_b, &order_a] {
        let applied = call_as(
            &registry,
            &db,
            alice.clone(),
            "manage_alpha_tabs",
            json!({"action": "reorder", "tab_order": order, "reason": "Demo shuffle."}),
        )
        .await
        .unwrap();
        assert_eq!(applied["changed"], true, "{applied:#}");
        assert_eq!(applied["tab_order"], *order, "{applied:#}");
    }
    assert_eq!(tab_order_of(&registry, &db, alice.clone()).await, order_a);
    // Reordering to the already-stored order is a no-op that appends
    // nothing: changed false, and no idempotent-retry marker (no key was
    // involved).
    let noop = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({"action": "reorder", "tab_order": order_a, "reason": "Demo shuffle."}),
    )
    .await
    .unwrap();
    assert_eq!(noop["changed"], false, "{noop:#}");
    assert_eq!(noop.get("idempotent_retry"), None, "{noop:#}");
    assert_eq!(noop["tab_order"], order_a, "{noop:#}");
}

// `canvas.scene.v1` (task `ab9463e`, design `638bc12` slice 1): a declared,
// read-only page of an existing Canvas v1 scene, read through the ordinary
// `get_scene` path under the viewer, so redaction and refusal are the
// viewer's own by construction. Every revision the tab sees is sealed: no
// database-wide content sequence reaches it (task `a5804e8`).

const SCENE_CANVAS: &str = "c5d00000-0000-4000-8000-000000000001";
const SCENE_SHARED: &str = "c5d00000-0000-4000-8000-000000000002";
const SCENE_PRIVATE: &str = "c5d00000-0000-4000-8000-000000000003";
const SCENE_ELSEWHERE: &str = "c5d00000-0000-4000-8000-000000000004";

fn scene_declaration() -> Value {
    json!({"needs": ["canvas.scene.v1"], "effects": []})
}

/// A canvas holding a frame with a note inside it, one card on a record
/// both viewers may see, one card on a record only Alice may see, and an
/// asserted (semantic) connector between the two cards. In `(z, id)` order
/// the connector comes last, so a two-object page never carries it with
/// either of its cards. Alice alone holds View on the canvas.
async fn scene_fixture(registry: &ToolRegistry, db: &Db) {
    for (id, record_type, kind, name) in [
        (SCENE_CANVAS, "Document", "canvas", "Board"),
        (SCENE_SHARED, "WorkItem", "task", "Ship the board"),
        (SCENE_PRIVATE, "Document", "note", "Salary bands"),
    ] {
        create_scene_record(registry, db, id, record_type, kind, name).await;
    }
    grant(db, SCENE_CANVAS, ALICE, Capability::View).await;
    replace_explicit_policy(
        db,
        "test:policy",
        SCENE_SHARED,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    grant(db, SCENE_PRIVATE, ALICE, Capability::View).await;
    let committed = commit_scene(
        registry,
        db,
        "scene-1",
        json!([
            { "op": "create", "object": { "id": "f1", "kind": "frame", "x": 0, "y": 0, "w": 800, "h": 600, "z": "a0", "props": { "title": "Now", "color": "grey" } } },
            { "op": "create", "object": { "id": "n1", "kind": "note", "x": 20, "y": 40, "w": 200, "h": 120, "z": "a1", "parent": "f1", "props": { "text": "Inside the frame", "color": "yellow" } } },
            { "op": "create", "object": { "id": "c-shared", "kind": "record_card", "x": 300, "y": 40, "w": 240, "h": 120, "z": "a2", "props": { "record_id": SCENE_SHARED } } },
            { "op": "create", "object": { "id": "c-private", "kind": "record_card", "x": 300, "y": 240, "w": 240, "h": 120, "z": "a3", "props": { "record_id": SCENE_PRIVATE } } },
            { "op": "create", "object": { "id": "k1", "kind": "connector", "x": 0, "y": 0, "w": 0, "h": 0, "z": "a4", "props": { "from": { "object": "c-shared" }, "to": { "object": "c-private" }, "style": "arrow" } } }
        ]),
    )
    .await;
    assert_eq!(committed["outcome"], "committed", "{committed:#}");
    let asserted = call_as(
        registry,
        db,
        Caller::local(),
        "manage_canvas",
        json!({
            "action": "assert_connector", "canvas_id": SCENE_CANVAS,
            "object_id": "k1", "relationship": "relates_to",
        }),
    )
    .await
    .unwrap();
    assert_eq!(asserted["outcome"], "committed", "{asserted:#}");
}

async fn create_scene_record(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    record_type: &str,
    kind: &str,
    name: &str,
) {
    call_as(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({
            "id": id, "type": record_type, "kind": kind, "name": name,
            "reason": "Fixture for the canvas scene need.",
        }),
    )
    .await
    .unwrap();
}

async fn commit_scene(registry: &ToolRegistry, db: &Db, batch_id: &str, ops: Value) -> Value {
    call_as(
        registry,
        db,
        Caller::local(),
        "manage_canvas",
        json!({
            "action": "commit_batch",
            "batch": {
                "version": "native.canvas-batch.v1",
                "canvas_id": SCENE_CANVAS,
                "batch_id": batch_id,
                "origin": { "kind": "agent" },
                "ops": ops,
            }
        }),
    )
    .await
    .unwrap()
}

async fn scene_read(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    package: &str,
    event: &str,
    params: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": package,
            "expected_install_event_id": event,
            "need": "canvas.scene.v1",
            "params": params,
        }),
    )
    .await
}

async fn own_scene(registry: &ToolRegistry, db: &Db, account: &str) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "read_canvas",
        json!({"action": "get_scene", "canvas_id": SCENE_CANVAS}),
    )
    .await
    .map(|mut scene| {
        scene.as_object_mut().unwrap().remove("run_context");
        scene
    })
}

/// Objects with every revision removed, so a tab page and the viewer's own
/// `get_scene` compare on everything else: geometry, kind, parent, props,
/// redaction, connector semantics and record faces.
fn unsealed(objects: &Value) -> Value {
    let mut objects = objects.clone();
    for object in objects.as_array_mut().unwrap() {
        let object = object.as_object_mut().unwrap();
        object.remove("versions");
        if let Some(record) = object.get_mut("record").and_then(Value::as_object_mut) {
            record.remove("version");
        }
    }
    objects
}

fn scene_object<'a>(scene: &'a Value, id: &str) -> &'a Value {
    scene["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == id)
        .unwrap_or_else(|| panic!("object {id} in {scene:#}"))
}

fn scene_ids(scene: &Value) -> Vec<String> {
    scene["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|object| object["id"].as_str().unwrap().to_string())
        .collect()
}

async fn content_events(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

async fn both_view_canvas(db: &Db) {
    replace_explicit_policy(
        db,
        "test:policy",
        SCENE_CANVAS,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn declared_canvas_scene_reads_as_the_viewer_and_follows_their_view() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    scene_fixture(&registry, &db).await;
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.board", scene_declaration()).await;
    let params = json!({"canvas_id": SCENE_CANVAS});
    let events_before = content_events(&db).await;

    // Alice's page is her own get_scene, object for object, revisions aside.
    let read = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &alice_event,
        params.clone(),
    )
    .await
    .unwrap();
    let own = own_scene(&registry, &db, ALICE).await.unwrap();
    let scene = &read["result"];
    assert_eq!(
        unsealed(&scene["objects"]),
        unsealed(&own["objects"]),
        "{read:#}"
    );
    assert_eq!(scene["version"], "canvas.scene.v1");
    assert_eq!(scene["canvas_id"], SCENE_CANVAS);
    assert_eq!(scene["live_objects"], 5);
    assert_eq!(scene["truncated"], false);
    assert_eq!(scene["next_cursor"], Value::Null);
    assert_eq!(scene["limit"], 500);
    assert_eq!(read["need"], "canvas.scene.v1");
    assert_eq!(
        read["params"],
        json!({"canvas_id": SCENE_CANVAS, "limit": 500, "cursor": null})
    );
    assert_eq!(read["effects_wired"], false);
    // Geometry, z, parent/frame and kind all reach the frame.
    let note = scene_object(scene, "n1");
    assert_eq!(note["kind"], "note");
    assert_eq!(note["parent"], "f1");
    assert_eq!(note["z"], "a1");
    assert_eq!(
        (note["x"].clone(), note["w"].clone()),
        (json!(20.0), json!(200.0))
    );
    assert_eq!(scene_object(scene, "f1")["kind"], "frame");
    assert_eq!(
        scene_object(scene, "c-private")["record"]["name"],
        "Salary bands"
    );
    assert_eq!(
        scene_object(scene, "c-shared")["record"]["id"],
        SCENE_SHARED
    );
    // Ids are stable: a second read names the same objects in the same order.
    let again = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &alice_event,
        params.clone(),
    )
    .await
    .unwrap();
    assert_eq!(scene_ids(&again["result"]), scene_ids(scene));
    assert_eq!(
        scene_ids(scene),
        ["f1", "n1", "c-shared", "c-private", "k1"]
    );

    // Bea holds no View on the canvas: the need refuses exactly as her own
    // get_scene does, without disclosing that the canvas exists.
    let refused = scene_read(
        &registry,
        &db,
        BEA,
        "agent.board",
        &bea_event,
        params.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    let own_refusal = own_scene(&registry, &db, BEA)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(refused, own_refusal);
    assert!(refused.contains("does not exist"), "{refused}");

    // Given View on the canvas, Bea sees the card on the private record as
    // `withheld`, with its geometry, while Alice's still resolves.
    both_view_canvas(&db).await;
    let as_bea = scene_read(
        &registry,
        &db,
        BEA,
        "agent.board",
        &bea_event,
        params.clone(),
    )
    .await
    .unwrap();
    let bea_own = own_scene(&registry, &db, BEA).await.unwrap();
    assert_eq!(
        unsealed(&as_bea["result"]["objects"]),
        unsealed(&bea_own["objects"])
    );
    let hidden = scene_object(&as_bea["result"], "c-private");
    assert_eq!(hidden["props"]["record_id"], "withheld");
    assert!(hidden.get("record").is_none(), "{hidden:#}");
    assert_eq!(hidden["y"], 240.0);
    assert_eq!(
        scene_object(&as_bea["result"], "c-shared")["record"]["name"],
        "Ship the board"
    );
    assert!(!as_bea.to_string().contains(SCENE_PRIVATE));
    assert!(!as_bea.to_string().contains("Salary bands"));
    let as_alice = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &alice_event,
        params.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        scene_object(&as_alice["result"], "c-private")["props"]["record_id"],
        SCENE_PRIVATE
    );
    // Tokens are bound to the install, so two viewers cannot compare them.
    assert_ne!(
        scene_object(&as_bea["result"], "n1")["versions"]["geometry"],
        scene_object(&as_alice["result"], "n1")["versions"]["geometry"]
    );
    assert_ne!(
        as_bea["result"]["scene_token"],
        as_alice["result"]["scene_token"]
    );

    // Revoking Bea's View refuses her very next read.
    grant(&db, SCENE_CANVAS, ALICE, Capability::View).await;
    let revoked = scene_read(&registry, &db, BEA, "agent.board", &bea_event, params)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(revoked, own_refusal);

    // No read wrote anything: no content event, and the scene is unmoved.
    assert_eq!(content_events(&db).await, events_before);
    assert_eq!(
        own_scene(&registry, &db, ALICE).await.unwrap()["canvas_version"],
        own["canvas_version"]
    );
}

/// Every number in `value`, with the key it sits under, and every string.
fn walk_scene(value: &Value, key: &str, numbers: &mut Vec<String>, strings: &mut Vec<String>) {
    match value {
        Value::Number(_) => numbers.push(key.to_string()),
        Value::String(text) => strings.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                walk_scene(item, key, numbers, strings);
            }
        }
        Value::Object(map) => {
            for (child_key, child) in map {
                walk_scene(child, child_key, numbers, strings);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn declared_canvas_scene_carries_no_sequence_and_tokens_move_only_with_the_object() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    scene_fixture(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    let params = json!({"canvas_id": SCENE_CANVAS});
    let read = || scene_read(&registry, &db, ALICE, "agent.board", &event, params.clone());

    // Walk the whole response: the only numbers are geometry and the two
    // counts, and no string is a `canvas:N` or `rec:N` revision.
    let first = read().await.unwrap();
    let (mut numbers, mut strings) = (Vec::new(), Vec::new());
    walk_scene(&first, "", &mut numbers, &mut strings);
    for key in &numbers {
        assert!(
            ["x", "y", "w", "h", "live_objects", "limit"].contains(&key.as_str()),
            "a number under '{key}' reached the tab: {first:#}"
        );
    }
    for text in &strings {
        let revision = text
            .strip_prefix("canvas:")
            .or_else(|| text.strip_prefix("rec:"));
        assert!(
            !revision.is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit())),
            "a sequence revision '{text}' reached the tab"
        );
    }
    let scene = &first["result"];
    let tokens: Vec<&Value> = std::iter::once(&scene["scene_token"])
        .chain(
            scene["objects"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|object| {
                    [
                        &object["versions"]["geometry"],
                        &object["versions"]["content"],
                    ]
                }),
        )
        .chain(std::iter::once(
            &scene_object(scene, "c-shared")["record"]["version"],
        ))
        .collect();
    for token in &tokens {
        let token = token.as_str().unwrap();
        assert!(
            token.starts_with("t:") && token.len() == 34,
            "opaque token, got {token}"
        );
    }

    // No change: every token is stable.
    assert_eq!(read().await.unwrap()["result"], *scene);

    // Writes the viewer cannot see, including to another canvas, move no
    // token she sees.
    create_scene_record(
        &registry,
        &db,
        SCENE_ELSEWHERE,
        "Document",
        "canvas",
        "Hidden board",
    )
    .await;
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_canvas",
        json!({
            "action": "commit_batch",
            "batch": {
                "version": "native.canvas-batch.v1", "canvas_id": SCENE_ELSEWHERE,
                "batch_id": "elsewhere-1", "origin": { "kind": "agent" },
                "ops": [{ "op": "create", "object": { "id": "h1", "kind": "note", "x": 0, "y": 0, "w": 10, "h": 10, "z": "a0", "props": { "text": "hidden" } } }],
            }
        }),
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id": SCENE_ELSEWHERE, "name": "Hidden board, renamed", "reason": "Invisible write."}),
    )
    .await
    .unwrap();
    assert_eq!(read().await.unwrap()["result"], *scene);

    // Moving one object moves its geometry token and the scene token, and
    // nothing else.
    let n1_geometry = scene_object(scene, "n1")["versions"]["geometry"].clone();
    let own = own_scene(&registry, &db, ALICE).await.unwrap();
    let moved = commit_scene(
        &registry,
        &db,
        "scene-move",
        json!([{ "op": "patch", "id": "n1", "expected": { "geometry": scene_object(&own, "n1")["versions"]["geometry"] }, "set": { "x": 60 } }]),
    )
    .await;
    assert_eq!(moved["outcome"], "committed", "{moved:#}");
    let after = read().await.unwrap();
    let after = &after["result"];
    assert_ne!(after["scene_token"], scene["scene_token"]);
    let n1 = scene_object(after, "n1");
    assert_ne!(n1["versions"]["geometry"], n1_geometry);
    assert_eq!(
        n1["versions"]["content"],
        scene_object(scene, "n1")["versions"]["content"]
    );
    for id in ["f1", "c-shared", "c-private", "k1"] {
        assert_eq!(
            scene_object(after, id)["versions"],
            scene_object(scene, id)["versions"],
            "{id} did not change"
        );
    }
    assert_eq!(
        scene_object(after, "c-shared")["record"]["version"],
        scene_object(scene, "c-shared")["record"]["version"]
    );
}

#[tokio::test]
async fn declared_canvas_scene_pages_honestly_and_withholds_a_connector_across_pages() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    scene_fixture(&registry, &db).await;
    both_view_canvas(&db).await;

    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.board", scene_declaration()).await;
    for (account, event) in [(ALICE, &alice_event), (BEA, &bea_event)] {
        let whole = own_scene(&registry, &db, account).await.unwrap();
        let mut cursor = Value::Null;
        let mut pages: Vec<Value> = Vec::new();
        loop {
            let read = scene_read(
                &registry,
                &db,
                account,
                "agent.board",
                event,
                json!({"canvas_id": SCENE_CANVAS, "limit": 2, "cursor": cursor}),
            )
            .await
            .unwrap();
            let page = read["result"].clone();
            // Every page counts the whole scene, not just itself.
            assert_eq!(page["live_objects"], 5);
            assert!(page["objects"].as_array().unwrap().len() <= 2);
            pages.push(page.clone());
            if page["truncated"] == true {
                assert!(page["next_cursor"].is_string(), "{page:#}");
                cursor = page["next_cursor"].clone();
            } else {
                assert_eq!(page["next_cursor"], Value::Null);
                break;
            }
        }
        assert_eq!(pages.len(), 3);
        // Nothing moved between pages, so the scene token held throughout.
        assert!(pages
            .iter()
            .all(|page| page["scene_token"] == pages[0]["scene_token"]));
        // The pages are the whole scene, in order, each object redacted and
        // resolved exactly as the unwindowed read resolves it.
        let paged: Vec<Value> = pages
            .iter()
            .flat_map(|page| page["objects"].as_array().unwrap().clone())
            .collect();
        assert_eq!(unsealed(&Value::Array(paged)), unsealed(&whole["objects"]));
        // The connector sits alone on the last page; both of its cards are
        // on the page before. Its semantics still resolve for the viewer
        // who sees both records and are withheld whole from the one who
        // does not.
        assert_eq!(scene_ids(&pages[2]), ["k1"]);
        assert_eq!(scene_ids(&pages[1]), ["c-shared", "c-private"]);
        let semantic = &scene_object(&pages[2], "k1")["props"]["semantic"];
        if account == ALICE {
            assert_eq!(semantic["relationship"], "relates_to", "{semantic:#}");
            assert_eq!(semantic["status"], "asserted");
            assert!(semantic["link_id"].is_string());
        } else {
            assert_eq!(*semantic, json!("withheld"));
            assert!(!pages[2].to_string().contains("relates_to"));
        }
    }

    let event = alice_event;
    // A limit that covers the scene exactly is not truncated.
    let exact = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &event,
        json!({"canvas_id": SCENE_CANVAS, "limit": 5}),
    )
    .await
    .unwrap();
    assert_eq!(exact["result"]["truncated"], false);
    let short = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &event,
        json!({"canvas_id": SCENE_CANVAS, "limit": 4}),
    )
    .await
    .unwrap();
    assert_eq!(short["result"]["truncated"], true);
    assert_eq!(scene_ids(&short["result"]).len(), 4);
}

#[tokio::test]
async fn declared_canvas_scene_stops_a_page_before_the_bridge_answer_cap() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    scene_fixture(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    // 120 notes of 8,000 characters: about 1 MiB of text, far under the
    // 500-object limit but over the page byte budget.
    let text = "x".repeat(8000);
    for batch in 0..4 {
        let ops: Vec<Value> = (0..30)
            .map(|index| {
                let id = format!("big-{:03}", batch * 30 + index);
                json!({ "op": "create", "object": {
                    "id": id, "kind": "note", "x": 0, "y": 0, "w": 100, "h": 100,
                    "z": format!("b{id}"), "props": { "text": text }
                }})
            })
            .collect();
        let committed = commit_scene(&registry, &db, &format!("big-{batch}"), json!(ops)).await;
        assert_eq!(committed["outcome"], "committed", "{committed:#}");
    }

    let mut cursor = Value::Null;
    let mut ids: Vec<String> = Vec::new();
    let mut pages = 0;
    loop {
        let read = scene_read(
            &registry,
            &db,
            ALICE,
            "agent.board",
            &event,
            json!({"canvas_id": SCENE_CANVAS, "cursor": cursor}),
        )
        .await
        .unwrap();
        pages += 1;
        // What the bridge measures: the whole answer, serialised.
        let answer = serde_json::to_string(&json!({
            "status": "ok", "code": null, "need": "canvas.scene.v1", "result": read["result"],
        }))
        .unwrap();
        assert!(answer.len() < 1024 * 1024, "page of {} bytes", answer.len());
        let objects = serde_json::to_vec(&read["result"]["objects"]).unwrap();
        assert!(
            objects.len() <= 768 * 1024,
            "objects of {} bytes",
            objects.len()
        );
        ids.extend(scene_ids(&read["result"]));
        if read["result"]["truncated"] == true {
            assert!(read["result"]["objects"].as_array().unwrap().len() < 500);
            cursor = read["result"]["next_cursor"].clone();
        } else {
            break;
        }
    }
    assert!(pages >= 2, "the budget must have cut at least one page");
    let whole = own_scene(&registry, &db, ALICE).await.unwrap();
    assert_eq!(ids, scene_ids(&whole), "no object skipped or repeated");
    assert_eq!(ids.len(), 125);
}

#[tokio::test]
async fn declared_canvas_scene_rechecks_the_install_inside_its_own_read() {
    use native_ce::mcp::tools::alpha_tabs::canvas_scene_read;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    scene_fixture(&registry, &db).await;
    let alice = Caller::authenticated(ALICE);
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    // Called directly, with no outer gate in front of it.
    let inner = |event: String| {
        let (db, alice) = (db.clone(), alice.clone());
        async move {
            canvas_scene_read(&db, &alice, "agent.board", &event, SCENE_CANVAS, 500, None).await
        }
    };
    let page = inner(event.clone()).await.unwrap();
    assert_eq!(page["live_objects"], 5);

    // The viewer loses the tab's artifact: the read refuses on its own.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(BEA, Capability::View)],
    )
    .await
    .unwrap();
    let lost = inner(event.clone()).await.unwrap_err().to_string();
    assert!(lost.contains("[unauthorized]"), "{lost}");
    adopt_fixture_artifact_policy(&db).await;
    inner(event.clone()).await.unwrap();

    // The install is replaced by a disable: the generation the read was
    // asked for is gone, and the new one is not live.
    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.board",
            "expected_install_event_id": event, "reason": "Stop the board tab.",
        }),
    )
    .await
    .unwrap();
    let stale = inner(event.clone()).await.unwrap_err().to_string();
    assert!(stale.contains("[cas_mismatch]"), "{stale}");
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = inner(disabled_event).await.unwrap_err().to_string();
    assert!(refused.contains("[disabled]"), "{refused}");

    // An install whose consent never named the need cannot read with it.
    let search_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        json!({"needs": ["records.search.v1"], "effects": []}),
    )
    .await;
    let undeclared = canvas_scene_read(
        &db,
        &alice,
        "agent.search-only",
        &search_only,
        SCENE_CANVAS,
        500,
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(undeclared.contains("[undeclared_need]"), "{undeclared}");
}

async fn adopt_fixture_artifact_policy(db: &Db) {
    replace_explicit_policy(
        db,
        "test:policy",
        ARTIFACT_A,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn declared_canvas_scene_refuses_undeclared_and_out_of_bound_requests() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    scene_fixture(&registry, &db).await;
    let refusal = |result: native_ce::Result<Value>| result.unwrap_err().to_string();

    // A package that never declared the need cannot read a scene with it.
    let search_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        json!({"needs": ["records.search.v1"], "effects": []}),
    )
    .await;
    let undeclared = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        &search_only,
        json!({"canvas_id": SCENE_CANVAS}),
    )
    .await;
    assert!(refusal(undeclared).contains("undeclared_need"));

    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    for params in [
        json!({}),
        json!({"canvas_id": ""}),
        json!({"canvas_id": SCENE_CANVAS, "limit": 0}),
        json!({"canvas_id": SCENE_CANVAS, "limit": 501}),
        json!({"canvas_id": SCENE_CANVAS, "cursor": "zz"}),
        json!({"canvas_id": SCENE_CANVAS, "include_deleted": true}),
        json!({"canvas_id": SCENE_CANVAS, "presence": true}),
        // There is no write path through a read need.
        json!({"canvas_id": SCENE_CANVAS, "ops": [{"op": "delete", "id": "n1"}]}),
    ] {
        let refused =
            scene_read(&registry, &db, ALICE, "agent.board", &event, params.clone()).await;
        assert!(refusal(refused).contains("[invalid_params]"), "{params}");
    }
    // A record that is not a canvas refuses as get_scene would.
    let not_canvas = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &event,
        json!({"canvas_id": SCENE_PRIVATE}),
    )
    .await;
    assert!(refusal(not_canvas).contains("is not a Document kind:canvas"));
}

#[tokio::test]
async fn declared_canvas_scene_bounds_an_oversized_first_object_and_pages_past_it() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    create_scene_record(&registry, &db, SCENE_CANVAS, "Document", "canvas", "Board").await;
    create_scene_record(
        &registry,
        &db,
        SCENE_SHARED,
        "Document",
        "note",
        "Long read",
    )
    .await;
    grant(&db, SCENE_CANVAS, ALICE, Capability::View).await;
    grant(&db, SCENE_SHARED, ALICE, Capability::View).await;
    // A record summary no field bound limits: 1,100,000 characters, over the
    // bridge's whole 1 MiB answer cap on its own.
    sqlx::query("UPDATE records SET summary=? WHERE id=?")
        .bind("s".repeat(1_100_000))
        .bind(SCENE_SHARED)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let committed = commit_scene(
        &registry,
        &db,
        "oversized-1",
        json!([
            { "op": "create", "object": { "id": "big-card", "kind": "record_card", "x": 0, "y": 0, "w": 240, "h": 120, "z": "a0", "props": { "record_id": SCENE_SHARED } } },
            { "op": "create", "object": { "id": "after", "kind": "note", "x": 300, "y": 0, "w": 200, "h": 120, "z": "a1", "props": { "text": "Next in line" } } }
        ]),
    )
    .await;
    assert_eq!(committed["outcome"], "committed", "{committed:#}");
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;
    // What the bridge measures: the whole answer, serialised.
    let answer_len = |read: &Value| {
        serde_json::to_string(&json!({
            "status": "ok", "code": null, "need": "canvas.scene.v1", "result": read["result"],
        }))
        .unwrap()
        .len()
    };

    let first = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &event,
        json!({"canvas_id": SCENE_CANVAS, "limit": 1}),
    )
    .await
    .unwrap();
    assert!(
        answer_len(&first) < 1024 * 1024,
        "{} bytes",
        answer_len(&first)
    );
    let page = &first["result"];
    assert_eq!(scene_ids(page), ["big-card"]);
    let card = scene_object(page, "big-card");
    assert_eq!(card["truncated_fields"], json!(["record.summary"]));
    assert_eq!(card["record"]["summary"].as_str().unwrap().len(), 8 * 1024);
    assert_eq!(card["record"]["name"], "Long read");
    assert_eq!(card["props"]["record_id"], SCENE_SHARED);
    assert_eq!(page["truncated"], true);

    let second = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &event,
        json!({"canvas_id": SCENE_CANVAS, "limit": 1, "cursor": page["next_cursor"]}),
    )
    .await
    .unwrap();
    assert!(answer_len(&second) < 1024 * 1024);
    assert_eq!(scene_ids(&second["result"]), ["after"]);
    assert_eq!(second["result"]["truncated"], false);
    assert!(scene_object(&second["result"], "after")
        .get("truncated_fields")
        .is_none());

    // Unwindowed, both fit one page, still under the cap.
    let whole = scene_read(
        &registry,
        &db,
        ALICE,
        "agent.board",
        &event,
        json!({"canvas_id": SCENE_CANVAS}),
    )
    .await
    .unwrap();
    assert!(answer_len(&whole) < 1024 * 1024);
    assert_eq!(scene_ids(&whole["result"]), ["big-card", "after"]);
    assert_eq!(whole["result"]["truncated"], false);
}

/// `JSON.stringify(answer).length` for the answer the frame bridge sizes:
/// the host's `{status, need, result}` around the page. RFC 8785 formats
/// numbers and escapes strings as ECMAScript does, and reorders keys only.
fn bridge_answer_chars(result: &Value) -> usize {
    let answer = json!({"status": "ok", "need": "canvas.scene.v1", "result": result});
    String::from_utf8(serde_jcs::to_vec(&answer).unwrap())
        .unwrap()
        .encode_utf16()
        .count()
}

/// The same length from a real ECMAScript engine, when Node is installed:
/// it parses the page as the host does and stringifies it as the bridge
/// does. `None` when Node is absent.
fn node_answer_chars(result: &Value) -> Option<usize> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("node")
        .args([
            "-e",
            "let s='';process.stdin.on('data',c=>s+=c).on('end',()=>{const result=JSON.parse(s);process.stdout.write(String(JSON.stringify({status:'ok',need:'canvas.scene.v1',result}).length))})",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(result).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "node failed");
    Some(String::from_utf8(output.stdout).unwrap().parse().unwrap())
}

#[tokio::test]
async fn declared_canvas_scene_measures_pages_as_the_bridge_does() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    create_scene_record(&registry, &db, SCENE_CANVAS, "Document", "canvas", "Board").await;
    grant(&db, SCENE_CANVAS, ALICE, Capability::View).await;
    // Twelve strokes of 2,000 `[1e20, 1e20]` points, one batch each.
    // serde_json writes each point in 13 characters (`[1e+20,1e+20]`);
    // ECMAScript expands `1e20` and writes 45, so the scene is about 1.1
    // million characters to the bridge while serde_json measures about a
    // third of that.
    let points = vec![json!([1e20, 1e20]); 2000];
    for index in 0..12 {
        let committed = commit_scene(
            &registry,
            &db,
            &format!("stroke-{index}"),
            json!([{ "op": "create", "object": {
                "id": format!("s{index:02}"), "kind": "stroke", "x": 0, "y": 0, "w": 10, "h": 10,
                "z": format!("a{index:02}"), "props": { "points": points, "width": 2 }
            }}]),
        )
        .await;
        assert_eq!(committed["outcome"], "committed", "{committed:#}");
    }
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.board", scene_declaration()).await;

    let mut cursor = Value::Null;
    let mut ids: Vec<String> = Vec::new();
    let mut pages = 0;
    let mut node_checked = false;
    loop {
        let read = scene_read(
            &registry,
            &db,
            ALICE,
            "agent.board",
            &event,
            json!({"canvas_id": SCENE_CANVAS, "cursor": cursor}),
        )
        .await
        .unwrap();
        let page = &read["result"];
        pages += 1;
        let chars = bridge_answer_chars(page);
        assert!(chars < 1_048_576, "page {pages} is {chars} characters");
        if let Some(node) = node_answer_chars(page) {
            assert_eq!(node, chars, "RFC 8785 and JSON.stringify disagree");
            node_checked = true;
        }
        // Whole strokes, not placeholders: each fits a page on its own.
        for object in page["objects"].as_array().unwrap() {
            assert!(object.get("oversized").is_none());
            assert_eq!(object["props"]["points"].as_array().unwrap().len(), 2000);
        }
        ids.extend(scene_ids(page));
        if page["truncated"] == true {
            cursor = page["next_cursor"].clone();
        } else {
            break;
        }
    }
    assert!(pages >= 2, "the ECMAScript measure must have cut a page");
    let expected: Vec<String> = (0..12).map(|index| format!("s{index:02}")).collect();
    assert_eq!(ids, expected, "no stroke skipped or repeated");
    if !node_checked {
        eprintln!("node not found: checked the RFC 8785 length only");
    }
}

// --- shell_auto.v1 authored adoption (plan 100d273 E1, task f1d80b0) ---

fn adopt_authored_args(
    artifact: &str,
    source_revision: &str,
    digest: &str,
    expected_event: &str,
) -> Value {
    json!({
        "action": "adopt_authored",
        "package": "agent.attention-cockpit",
        "version": "0.1.0",
        "digest": digest,
        "artifact_id": artifact,
        "source_revision": source_revision,
        "declaration": preview_declaration(),
        "expected_install_event_id": expected_event,
        "reason": "Adopt the pane-authored revision.",
    })
}

/// Caller carrying the hosted authored-adopt attestation for exactly these
/// arguments — the same construction `held/hosting/src/http.rs` performs
/// for the `adopt_authored` action after cookie-session plus trusted-Origin
/// checks. Tests for the authority boundary itself use plain
/// (MCP-equivalent) callers.
fn attested_adopt_authored_caller(account: &str, args: &Value) -> Caller {
    use native_ce::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for;
    let str_field = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
    let declaration = args.get("declaration").cloned().unwrap_or(Value::Null);
    Caller::authenticated(account).with_verified_alpha_tab_adopt_authored(
        alpha_tab_preview_authority_for(
            account,
            str_field("package"),
            str_field("version"),
            str_field("digest"),
            str_field("artifact_id"),
            str_field("source_revision"),
            &declaration,
        )
        .expect("fixture declaration is well-formed"),
    )
}

#[tokio::test]
async fn adopt_authored_refuses_without_hosted_authority() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            install_exact_args(ARTIFACT_A, &source_revision, &digest),
        )
        .await
        .unwrap();
    let event_id = installed["install"]["event_id"].as_str().unwrap();

    // Direct MCP/Bearer-equivalent calls refuse at the tool layer: no
    // attestation, no adopt — on any channel.
    for caller in [
        Caller::authenticated(ALICE),
        mcp_preview_caller(ALICE),
        Caller::local(),
    ] {
        let refused = call_as(
            &registry,
            &db,
            caller,
            "manage_alpha_tabs",
            adopt_authored_args(ARTIFACT_A, &source_revision, &digest, event_id),
        )
        .await;
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("adopt_authored_authority_missing"),
            "unattested adopt_authored must refuse without state change"
        );
    }
    // A preview attestation is never an authored-adopt authority, and an
    // adopt attestation is never one either: each action carries its own
    // field.
    let preview = preview_args(ARTIFACT_A, &source_revision, &digest);
    let refused = call_as(
        &registry,
        &db,
        attested_preview_caller(ALICE, &preview),
        "manage_alpha_tabs",
        adopt_authored_args(ARTIFACT_A, &source_revision, &digest, event_id),
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("adopt_authored_authority_missing"),
        "preview authority must not authorize adopt_authored"
    );
}

#[tokio::test]
async fn adopt_authored_rejects_pin_mismatch_and_stale_cas() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            install_exact_args(ARTIFACT_A, &source_revision, &digest),
        )
        .await
        .unwrap();
    let event_id = installed["install"]["event_id"].as_str().unwrap();

    // Cross-pin attestation refuses before any state change: the
    // attestation names digest B while the request names the install pin.
    let wrong = adopt_authored_args(ARTIFACT_A, &source_revision, DIGEST_B, event_id);
    let right = adopt_authored_args(ARTIFACT_A, &source_revision, &digest, event_id);
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_authored_caller(ALICE, &wrong),
        "manage_alpha_tabs",
        right,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("adopt_authored_pin_mismatch"),
        "cross-pin attestation must refuse"
    );

    // Stale CAS refuses without adopting: the attestation matches the pin,
    // but the token names no live generation.
    let stale = adopt_authored_args(ARTIFACT_A, &source_revision, &digest, "evt_stale");
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_authored_caller(ALICE, &stale),
        "manage_alpha_tabs",
        stale,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("installation changed"),
        "stale CAS must refuse"
    );

    // Requested pin drifted from the install refuses with a pin error.
    let drifted = adopt_authored_args(ARTIFACT_A, "rev-unknown", &digest, event_id);
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_authored_caller(ALICE, &drifted),
        "manage_alpha_tabs",
        drifted,
    )
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("install_pin_mismatch"),
        "adopt across pins must refuse"
    );

    // Nothing above moved the row: still caller-asserted over the install.
    let entry = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(entry["adoption"], "caller_asserted");
    assert_eq!(entry["event_id"], event_id);
}

#[tokio::test]
async fn adopt_authored_refuses_over_long_asserted_provenance() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            install_exact_args(ARTIFACT_A, &source_revision, &digest),
        )
        .await
        .unwrap();
    let event_id = installed["install"]["event_id"].as_str().unwrap();

    // Client-asserted provenance is bounded at 256 characters per field.
    for field in ["launch_id", "authored_run_key"] {
        let mut args = adopt_authored_args(ARTIFACT_A, &source_revision, &digest, event_id);
        args[field] = json!("x".repeat(257));
        let refused = call_as(
            &registry,
            &db,
            attested_adopt_authored_caller(ALICE, &args),
            "manage_alpha_tabs",
            args,
        )
        .await;
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains(&format!("{field}_too_long")),
            "over-long {field} must refuse with a named reason"
        );
    }

    // Nothing above moved the row.
    let entry = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(entry["adoption"], "caller_asserted");
    assert_eq!(entry["event_id"], event_id);
}

#[tokio::test]
async fn adopt_authored_flips_to_shell_auto_echoes_request_and_launches() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);

    // Install with request text: inspect surfaces it verbatim.
    let mut install = install_exact_args(ARTIFACT_A, &source_revision, &digest);
    install["request"] = json!("make it blue");
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            install,
        )
        .await
        .unwrap();
    assert_eq!(installed["install"]["adoption"], "caller_asserted");
    assert_eq!(installed["install"]["request"], "make it blue");
    let event_id = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();

    // The hosted authored adopt flips adoption with no receipt, echoing the
    // install's request and recording the asserted launch provenance.
    let mut args = adopt_authored_args(ARTIFACT_A, &source_revision, &digest, &event_id);
    args["launch_id"] = json!("launch-1");
    args["authored_run_key"] = json!("pane-run-1");
    args["idempotency_key"] = json!("authored-retry-1");
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_authored_caller(ALICE, &args),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(adopted["changed"], true);
    let entry = &adopted["install"];
    assert_eq!(entry["adoption"], "shell_auto.v1");
    assert_eq!(entry["status"], "installed");
    assert_eq!(entry["request"], "make it blue");
    assert_ne!(entry["event_id"], event_id);

    // shell_auto.v1 is verified: launch binds the adopted pin.
    let adopted_event = entry["event_id"].as_str().unwrap().to_string();
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "launch",
            "package": "agent.attention-cockpit",
            "expected_install_event_id": adopted_event,
        }),
    )
    .await
    .unwrap();
    assert_eq!(launch["install_event_id"], adopted_event);
    assert_eq!(launch["pin"]["digest"], digest);

    // Same-key retry converges without a second event.
    let second = call_as(
        &registry,
        &db,
        attested_adopt_authored_caller(ALICE, &args),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();
    assert_eq!(second["changed"], false);
    assert_eq!(second["install"]["adoption"], "shell_auto.v1");
}

#[tokio::test]
async fn install_request_is_optional_bounded_and_display_only() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);

    // Absent request surfaces as null.
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            install_exact_args(ARTIFACT_A, &source_revision, &digest),
        )
        .await
        .unwrap();
    assert!(installed["install"]["request"].is_null());

    // Over-long request refuses with a named reason and moves nothing.
    let mut too_long = install_exact_args(ARTIFACT_A, &source_revision, &digest);
    too_long["request"] = json!("x".repeat(501));
    let refused = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            too_long,
        )
        .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("request_too_long"),
        "over-long request must refuse"
    );

    // Blank request normalizes to absent (fresh package: a second install
    // over a live row would refuse as already-installed).
    let mut blank = install_exact_args(ARTIFACT_A, &source_revision, &digest);
    blank["package"] = json!("agent.second-cockpit");
    blank["request"] = json!("   ");
    let installed = registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            blank,
        )
        .await
        .unwrap();
    assert!(installed["install"]["request"].is_null());
}

// `records.changes.v1` (task `68b48e5`, slice A): a declared, read-only page
// of one record's changes, newest first, read as the viewer's own
// `get_history {detail: metadata}` would read it, with bounded scalar
// before/after values and body sizes added. No payload and no content
// sequence reaches the tab (task `a5804e8`).

const CHANGES_RECORD: &str = "cd000000-0000-4000-8000-000000000001";
const CHANGES_OTHER: &str = "cd000000-0000-4000-8000-000000000002";

fn changes_declaration() -> Value {
    json!({"needs": ["records.changes.v1"], "effects": []})
}

/// A task Alice may edit and Bea may only view, created by the local
/// principal, then changed by Alice: its title, lifecycle, a facet set and
/// unset, and its body. Bea may not see who Alice is.
async fn changes_fixture(registry: &ToolRegistry, db: &Db) {
    for id in [CHANGES_RECORD, CHANGES_OTHER] {
        call_as(
            registry,
            db,
            Caller::local(),
            "create_record",
            json!({
                "id": id, "type": "WorkItem", "kind": "task", "name": "Draft plan",
                "lifecycle": "open", "body": "First body.",
                "reason": "Fixture for the record changes need.",
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            "test:policy",
            id,
            vec![
                AllowEntry::account(ALICE, Capability::Edit),
                AllowEntry::account(BEA, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    for update in [
        json!({"name": "Final plan", "reason": "Retitle the plan."}),
        json!({"lifecycle": "in_progress"}),
        json!({"facets": {"effort": "small"}}),
        json!({"facets": {"effort": "large"}}),
        json!({"facets": {"effort": null}}),
        json!({"body": "Second body, a little longer."}),
    ] {
        change_record(registry, db, ALICE, CHANGES_RECORD, update).await;
    }
}

async fn change_record(registry: &ToolRegistry, db: &Db, account: &str, id: &str, update: Value) {
    let mut args = update;
    args["id"] = json!(id);
    if args.get("reason").is_none() {
        args["reason"] = json!("Fixture change.");
    }
    if args.get("body").is_some() {
        let current = call_as(
            registry,
            db,
            Caller::authenticated(account),
            "get_record",
            json!({"ids": [id]}),
        )
        .await
        .unwrap();
        args["if_body_digest"] = current["records"][0]["body_digest"].clone();
    }
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "update_record",
        args,
    )
    .await
    .unwrap();
}

async fn changes_read(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    event: &str,
    params: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.history",
            "expected_install_event_id": event,
            "need": "records.changes.v1",
            "params": params,
        }),
    )
    .await
}

/// The viewer's own metadata history of `id`, newest first.
async fn own_history(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    id: &str,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "get_history",
        json!({"record_id": id, "detail": "metadata", "order": "newest_first", "limit": 1000}),
    )
    .await
}

fn change<'a>(event: &'a Value, field: &str) -> &'a Value {
    event["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["field"] == field)
        .unwrap_or_else(|| panic!("change to {field} in {event:#}"))
}

/// The first event, newest first, whose `changed_fields` name `field`.
fn event_changing<'a>(page: &'a Value, field: &str) -> &'a Value {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| {
            event["changed_fields"]
                .as_array()
                .unwrap()
                .contains(&json!(field))
        })
        .unwrap_or_else(|| panic!("an event changing {field} in {page:#}"))
}

/// Assert that nothing positional reaches the tab: the only numbers are the
/// page limit and byte sizes, and no key names a sequence.
fn assert_no_sequence(response: &Value) {
    fn walk(value: &Value, key: &str) {
        match value {
            Value::Number(_) => assert!(
                ["limit", "payload_bytes", "bytes"].contains(&key),
                "a number under '{key}' reached the tab"
            ),
            Value::Array(items) => items.iter().for_each(|item| walk(item, key)),
            Value::Object(map) => {
                for (child_key, child) in map {
                    assert!(
                        !child_key.contains("seq") && child_key != "version_seq",
                        "a sequence-shaped key '{child_key}' reached the tab"
                    );
                    walk(child, child_key);
                }
            }
            _ => {}
        }
    }
    walk(response, "");
}

/// Every page of the record's changes, following `next_cursor`.
async fn all_change_pages(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    event: &str,
    id: &str,
    limit: i64,
) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut cursor = Value::Null;
    loop {
        let read = changes_read(
            registry,
            db,
            account,
            event,
            json!({"record_id": id, "limit": limit, "cursor": cursor}),
        )
        .await
        .unwrap();
        let page = read["result"].clone();
        assert!(page["events"].as_array().unwrap().len() <= limit as usize);
        cursor = page["next_cursor"].clone();
        assert_eq!(page["complete"], cursor.is_null(), "{page:#}");
        pages.push(page);
        if cursor.is_null() {
            return pages;
        }
        assert!(pages.len() < 100, "paging must end");
    }
}

#[tokio::test]
async fn declared_record_changes_match_each_viewers_history() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let alice_event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.history", changes_declaration()).await;
    let params = json!({"record_id": CHANGES_RECORD});
    let events_before = content_events(&db).await;

    for (account, event) in [(ALICE, &alice_event), (BEA, &bea_event)] {
        let read = changes_read(&registry, &db, account, event, params.clone())
            .await
            .unwrap();
        assert_no_sequence(&read);
        let page = &read["result"];
        assert_eq!(page["version"], "records.changes.v1");
        assert_eq!(page["record_id"], CHANGES_RECORD);
        assert_eq!(page["order"], "newest_first");
        assert_eq!(page["complete"], true);
        assert_eq!(page["next_cursor"], Value::Null);
        assert_eq!(page["limit"], 50);
        assert_eq!(
            read["params"],
            json!({"record_id": CHANGES_RECORD, "limit": 50, "cursor": null})
        );

        // Event for event, the viewer's own metadata history: the same
        // events, the same actor rule, the same changed fields.
        let own = own_history(&registry, &db, account, CHANGES_RECORD)
            .await
            .unwrap();
        // The need leaves out occurrence bindings, which change no field.
        let own_events: Vec<&Value> = own["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["type"] != "occurrence.bound.v1")
            .collect();
        let events = page["events"].as_array().unwrap();
        assert_eq!(events.len(), own_events.len(), "{page:#}");
        assert_eq!(events.len(), 7);
        for (tab, own) in events.iter().zip(own_events) {
            assert_eq!(tab["event_id"], own["id"]);
            assert_eq!(tab["type"], own["type"]);
            assert_eq!(tab["created_at"], own["created_at"]);
            assert_eq!(tab["actor"], own["actor"]);
            assert_eq!(tab["run_key"], own["run_key"]);
            assert_eq!(tab["changed_fields"], own["changed_fields"]);
            assert_eq!(tab["payload_bytes"], own["payload_json_utf8_bytes"]);
            assert_eq!(
                tab["reason"],
                own.get("reason").cloned().unwrap_or(Value::Null)
            );
            assert!(tab.get("payload").is_none(), "{tab:#}");
        }

        // Title, lifecycle, facet set/change/unset and body.
        let title = change(event_changing(page, "name"), "name");
        assert_eq!(
            (&title["before"], &title["after"]),
            (&json!("Draft plan"), &json!("Final plan"))
        );
        assert_eq!(title["before_known"], true);
        assert_eq!(event_changing(page, "name")["reason"], "Retitle the plan.");
        let lifecycle_event = page["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| {
                let fields = event["changed_fields"].as_array().unwrap();
                event["type"] != "record.created"
                    && (fields.contains(&json!("lifecycle"))
                        || fields.contains(&json!("facet:lifecycle")))
            })
            .unwrap();
        let lifecycle = &lifecycle_event["changes"][0];
        assert_eq!(
            (&lifecycle["before"], &lifecycle["after"]),
            (&json!("open"), &json!("in_progress")),
            "{lifecycle_event:#}"
        );
        let efforts: Vec<(Value, Value)> = events
            .iter()
            .rev()
            .filter(|event| {
                event["changed_fields"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("facet:effort"))
            })
            .map(|event| {
                let effort = change(event, "facet:effort");
                assert_eq!(effort["before_known"], true);
                (effort["before"].clone(), effort["after"].clone())
            })
            .collect();
        assert_eq!(
            efforts,
            [
                (Value::Null, json!("small")),
                (json!("small"), json!("large")),
                (json!("large"), Value::Null)
            ]
        );
        let body = change(event_changing(page, "body"), "body");
        assert_eq!(
            body,
            &json!({"field": "body", "changed": true, "bytes": "Second body, a little longer.".len()})
        );
        assert!(!read.to_string().contains("Second body"));
        let created = events.last().unwrap();
        assert_eq!(created["type"], "record.created");
        assert_eq!(change(created, "name")["before"], Value::Null);
        assert_eq!(change(created, "name")["before_known"], true);
        assert_eq!(change(created, "name")["after"], "Draft plan");
        assert_eq!(
            change(created, "body"),
            &json!({"field": "body", "changed": true, "bytes": 11})
        );

        // Alice sees herself act; Bea may not see who Alice is, so the
        // actor and run are null for her, and the event still shows.
        let retitle = event_changing(page, "name");
        if account == ALICE {
            assert_eq!(retitle["actor"], ALICE);
        } else {
            assert_eq!(retitle["actor"], Value::Null);
            assert_eq!(retitle["run_key"], Value::Null);
            assert!(!read.to_string().contains(ALICE), "{read:#}");
        }
    }

    // A record Bea cannot see refuses exactly as her own history does, and
    // losing View refuses her very next read.
    revoke_all(&db, CHANGES_OTHER).await;
    grant(&db, CHANGES_OTHER, ALICE, Capability::View).await;
    let hidden = json!({"record_id": CHANGES_OTHER});
    let refused = changes_read(&registry, &db, BEA, &bea_event, hidden)
        .await
        .unwrap_err()
        .to_string();
    let own_refusal = own_history(&registry, &db, BEA, CHANGES_OTHER)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(refused, own_refusal);
    assert!(refused.contains("does not exist"), "{refused}");
    grant(&db, CHANGES_RECORD, ALICE, Capability::Edit).await;
    let revoked = changes_read(&registry, &db, BEA, &bea_event, params)
        .await
        .unwrap_err()
        .to_string();
    assert!(revoked.contains("does not exist"), "{revoked}");

    // No read wrote anything.
    assert_eq!(content_events(&db).await, events_before);
}

#[tokio::test]
async fn declared_record_changes_page_without_gaps_or_duplicates() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    // Enough further changes that pages cut through runs of one field, so
    // a page must look back past itself for its before-values.
    for round in 0..8 {
        change_record(
            &registry,
            &db,
            ALICE,
            CHANGES_RECORD,
            json!({"name": format!("Plan {round}")}),
        )
        .await;
        change_record(
            &registry,
            &db,
            ALICE,
            CHANGES_RECORD,
            json!({"facets": {"effort": format!("e{round}")}}),
        )
        .await;
        change_record(
            &registry,
            &db,
            ALICE,
            CHANGES_OTHER,
            json!({"name": format!("Other {round}")}),
        )
        .await;
    }
    let event =
        adopted_with_package(&registry, &db, BEA, "agent.history", changes_declaration()).await;
    let whole = all_change_pages(&registry, &db, BEA, &event, CHANGES_RECORD, 50).await;
    assert_eq!(whole.len(), 1);
    let whole_events = whole[0]["events"].as_array().unwrap().clone();
    assert_eq!(whole_events.len(), 23);

    for limit in [1, 3, 7] {
        let pages = all_change_pages(&registry, &db, BEA, &event, CHANGES_RECORD, limit).await;
        let paged: Vec<Value> = pages
            .iter()
            .flat_map(|page| page["events"].as_array().unwrap().clone())
            .collect();
        // Same events, same order, same before/after values: no gap, no
        // repeat, and a page's look-back agrees with the single page.
        assert_eq!(paged, whole_events, "limit {limit}");
        for page in &pages {
            assert_no_sequence(page);
            // The cursor is sealed: no event id reaches the tab in it.
            if let Some(cursor) = page["next_cursor"].as_str() {
                for event in &whole_events {
                    let id = event["event_id"].as_str().unwrap();
                    assert!(!cursor.contains(id) && !cursor.contains(&hex::encode(id)));
                }
            }
        }
    }

    // A cursor resumes only the record it came from.
    let first = changes_read(
        &registry,
        &db,
        BEA,
        &event,
        json!({"record_id": CHANGES_RECORD, "limit": 2}),
    )
    .await
    .unwrap();
    let cursor = first["result"]["next_cursor"].clone();
    let elsewhere = changes_read(
        &registry,
        &db,
        BEA,
        &event,
        json!({"record_id": CHANGES_OTHER, "cursor": cursor}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        elsewhere,
        "manage_alpha_tabs: live read refused [invalid_params]"
    );
    // Access revoked between two pages refuses the next page.
    revoke_all(&db, CHANGES_RECORD).await;
    grant(&db, CHANGES_RECORD, ALICE, Capability::Edit).await;
    let revoked = changes_read(
        &registry,
        &db,
        BEA,
        &event,
        json!({"record_id": CHANGES_RECORD, "limit": 2, "cursor": cursor}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(revoked.contains("does not exist"), "{revoked}");
    assert!(!revoked.contains("rc1"), "{revoked}");
}

#[tokio::test]
async fn declared_record_changes_cap_values_and_survive_oversized_payloads() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let long_name = "N".repeat(300);
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"name": long_name, "reason": "R".repeat(1500)}),
    )
    .await;
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"name": "Short"}),
    )
    .await;
    // Larger than query_sql's caller ceiling on one value (the class of
    // `73e5b92`): the read still answers, with the size and not the text.
    let oversized = "x".repeat(256 * 1024 + 1024);
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"body": oversized}),
    )
    .await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let read = changes_read(
        &registry,
        &db,
        ALICE,
        &event,
        json!({"record_id": CHANGES_RECORD}),
    )
    .await
    .unwrap();
    assert_no_sequence(&read);
    assert!(read.to_string().len() < 64 * 1024, "the page stays small");
    let events = read["result"]["events"].as_array().unwrap();

    let body_event = &events[0];
    assert_eq!(
        change(body_event, "body"),
        &json!({"field": "body", "changed": true, "bytes": oversized.len()})
    );
    assert!(body_event["payload_bytes"].as_u64().unwrap() > oversized.len() as u64);

    let short = change(&events[1], "name");
    assert_eq!(short["before"], "N".repeat(256));
    assert_eq!(short["before_truncated"], true);
    assert_eq!(short["after"], "Short");
    assert_eq!(short["after_truncated"], false);
    let long = &events[2];
    assert_eq!(change(long, "name")["after"], "N".repeat(256));
    assert_eq!(change(long, "name")["after_truncated"], true);
    assert_eq!(change(long, "name")["before"], "Final plan");
    assert_eq!(long["reason"], "R".repeat(1024));
    assert_eq!(long["reason_truncated"], true);
    assert_eq!(events[1]["reason_truncated"], false);
}

#[tokio::test]
async fn declared_record_changes_recheck_the_install_inside_their_own_read() {
    use native_ce::mcp::tools::alpha_tabs::record_changes_read;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let alice = Caller::authenticated(ALICE);
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    // Called directly, with no outer gate in front of it.
    let inner = |event: String| {
        let (db, alice) = (db.clone(), alice.clone());
        async move {
            record_changes_read(
                &db,
                &alice,
                "agent.history",
                &event,
                CHANGES_RECORD,
                50,
                None,
            )
            .await
        }
    };
    let page = inner(event.clone()).await.unwrap();
    assert_eq!(page["events"].as_array().unwrap().len(), 7);

    // The viewer loses the tab's artifact: the read refuses on its own.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(BEA, Capability::View)],
    )
    .await
    .unwrap();
    let lost = inner(event.clone()).await.unwrap_err().to_string();
    assert!(lost.contains("[unauthorized]"), "{lost}");
    adopt_fixture_artifact_policy(&db).await;
    inner(event.clone()).await.unwrap();

    // The install is disabled and then removed after the gate the host ran:
    // the generation the read was asked for is gone.
    let disabled = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.history",
            "expected_install_event_id": event, "reason": "Stop the history tab.",
        }),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let removed = call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.history",
            "expected_install_event_id": disabled_event, "reason": "Remove the history tab.",
        }),
    )
    .await
    .unwrap();
    let stale = inner(event.clone()).await.unwrap_err().to_string();
    assert!(stale.contains("[cas_mismatch]"), "{stale}");
    let removed_event = removed["install"]["event_id"].as_str().unwrap().to_string();
    let refused = inner(removed_event).await.unwrap_err().to_string();
    assert!(refused.contains("[removed]"), "{refused}");

    // An install whose consent never named the need cannot read with it.
    let search_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        json!({"needs": ["records.search.v1"], "effects": []}),
    )
    .await;
    let undeclared = record_changes_read(
        &db,
        &alice,
        "agent.search-only",
        &search_only,
        CHANGES_RECORD,
        50,
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(undeclared.contains("[undeclared_need]"), "{undeclared}");
}

#[tokio::test]
async fn declared_record_changes_refuse_undeclared_and_out_of_bound_requests() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let refusal = |result: native_ce::Result<Value>| result.unwrap_err().to_string();

    // A package that never declared the need cannot read with it.
    let search_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        json!({"needs": ["records.search.v1"], "effects": []}),
    )
    .await;
    let undeclared = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read", "package": "agent.search-only",
            "expected_install_event_id": search_only,
            "need": "records.changes.v1", "params": {"record_id": CHANGES_RECORD},
        }),
    )
    .await;
    assert!(refusal(undeclared).contains("[undeclared_need]"));

    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    for params in [
        json!({}),
        json!({"record_id": ""}),
        json!({"record_id": CHANGES_RECORD, "limit": 0}),
        json!({"record_id": CHANGES_RECORD, "limit": 51}),
        json!({"record_id": CHANGES_RECORD, "cursor": "zz"}),
        json!({"record_id": CHANGES_RECORD, "after_local_seq": 1}),
        json!({"record_id": CHANGES_RECORD, "detail": "full"}),
    ] {
        let refused = changes_read(&registry, &db, ALICE, &event, params.clone()).await;
        assert_eq!(
            refusal(refused),
            "manage_alpha_tabs: live read refused [invalid_params]",
            "{params}"
        );
    }
}

async fn append_raw(db: &Db, record_id: &str, event_type: &str, payload: Value) -> String {
    native_ce::store::append(
        db,
        native_ce::store::AppendSpec {
            record_id: record_id.to_string(),
            event_type: event_type.to_string(),
            payload,
            actor: None,
        },
    )
    .await
    .unwrap()
    .id
}

async fn latest_event_id(db: &Db, record_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

/// Every page of a record's changes read directly with `budget`, following
/// `next_cursor`.
async fn all_budgeted_pages(
    db: &Db,
    account: &str,
    event: &str,
    id: &str,
    limit: i64,
    budget: native_ce::mcp::tools::history::TabChangeBudget,
) -> Vec<Value> {
    use native_ce::mcp::tools::alpha_tabs::record_changes_read_with_budget;
    let caller = Caller::authenticated(account);
    let mut pages: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = record_changes_read_with_budget(
            db,
            &caller,
            "agent.history",
            event,
            id,
            limit,
            cursor.as_deref(),
            budget,
        )
        .await
        .unwrap();
        cursor = page["next_cursor"].as_str().map(str::to_string);
        assert_eq!(page["complete"], cursor.is_none(), "{page:#}");
        pages.push(page);
        if cursor.is_none() {
            return pages;
        }
        assert!(pages.len() < 200, "paging must end");
    }
}

fn page_events(pages: &[Value]) -> Vec<Value> {
    pages
        .iter()
        .flat_map(|page| page["events"].as_array().unwrap().clone())
        .collect()
}

#[tokio::test]
async fn declared_record_changes_refuse_every_unsealed_cursor_alike() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let alice_event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.history", changes_declaration()).await;
    let bea_page = changes_read(
        &registry,
        &db,
        BEA,
        &bea_event,
        json!({"record_id": CHANGES_RECORD, "limit": 2}),
    )
    .await
    .unwrap();
    let genuine = bea_page["result"]["next_cursor"]
        .as_str()
        .unwrap()
        .to_string();
    // Cursors shaped like a sealed one, naming in clear: an id that does
    // not exist, another record's event, and one of this record's own.
    // A nonce, the id in clear, and a tag: the shape of a sealed cursor.
    let forge = |id: &str| format!("{}{}{}", "00".repeat(24), hex::encode(id), "00".repeat(16));
    let foreign = latest_event_id(&db, CHANGES_OTHER).await;
    let own = latest_event_id(&db, CHANGES_RECORD).await;
    let forged = [
        forge("0f0f0f0f-0000-4000-8000-000000000000"),
        forge(&foreign),
        forge(&own),
    ];
    let read = |account: &'static str, event: String, cursor: Option<String>| {
        let (registry, db) = (&registry, &db);
        async move {
            changes_read(
                registry,
                db,
                account,
                &event,
                json!({"record_id": CHANGES_RECORD, "cursor": cursor}),
            )
            .await
            .unwrap_err()
            .to_string()
        }
    };

    // With View, every cursor this install did not seal for this record is
    // one identical refusal: forgeries, and Bea's genuine cursor in Alice's
    // install.
    let mut refusals = Vec::new();
    for cursor in forged.iter().cloned().chain([genuine.clone()]) {
        refusals.push(read(ALICE, alice_event.clone(), Some(cursor)).await);
    }
    // Bea's genuine cursor on another record, in her own install.
    let elsewhere = changes_read(
        &registry,
        &db,
        BEA,
        &bea_event,
        json!({"record_id": CHANGES_OTHER, "cursor": genuine}),
    )
    .await
    .unwrap_err()
    .to_string();
    refusals.push(elsewhere);
    for refusal in &refusals {
        assert_eq!(
            refusal,
            "manage_alpha_tabs: live read refused [invalid_params]"
        );
    }

    // Without View, the record refusal comes first and is the same for every
    // cursor, genuine or forged, and for none at all.
    revoke_all(&db, CHANGES_RECORD).await;
    grant(&db, CHANGES_RECORD, ALICE, Capability::Edit).await;
    let own_refusal = own_history(&registry, &db, BEA, CHANGES_RECORD)
        .await
        .unwrap_err()
        .to_string();
    for cursor in forged
        .iter()
        .cloned()
        .map(Some)
        .chain([Some(genuine.clone()), None])
    {
        assert_eq!(read(BEA, bea_event.clone(), cursor).await, own_refusal);
    }
}

#[tokio::test]
async fn declared_record_changes_redact_look_back_values_as_the_page_does() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    // A historical structured name carrying identity-shaped keys, then a
    // rename: the rename's before-value must be the redacted structure
    // whether the page holds the earlier event or looks back for it.
    append_raw(
        &db,
        CHANGES_RECORD,
        "record.updated",
        json!({"name": {"label": "Plan", "owner_id": "acct_hidden", "email": "hidden@example.com"}}),
    )
    .await;
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"name": "Plain"}),
    )
    .await;
    let event =
        adopted_with_package(&registry, &db, BEA, "agent.history", changes_declaration()).await;
    let whole =
        page_events(&all_change_pages(&registry, &db, BEA, &event, CHANGES_RECORD, 50).await);
    for limit in [1, 2] {
        let paged = page_events(
            &all_change_pages(&registry, &db, BEA, &event, CHANGES_RECORD, limit).await,
        );
        assert_eq!(paged, whole, "limit {limit}");
    }
    let rename = change(&whole[0], "name");
    assert_eq!(rename["after"], "Plain");
    assert_eq!(rename["before_known"], true);
    let before = rename["before"].as_str().unwrap();
    assert!(before.contains("Plan"), "{before}");
    assert!(
        !before.contains("hidden@example.com") && !before.contains("acct_hidden"),
        "{before}"
    );
}

#[tokio::test]
async fn declared_record_changes_seed_the_projectors_creation_defaults() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let unnamed = "cd000000-0000-4000-8000-000000000003";
    // Created with no name, which the projector stores as empty text.
    append_raw(
        &db,
        unnamed,
        "record.created",
        json!({"type": "WorkItem", "kind": "task", "persistence": "enduring"}),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        unnamed,
        vec![AllowEntry::account(ALICE, Capability::Edit)],
    )
    .await
    .unwrap();
    change_record(
        &registry,
        &db,
        ALICE,
        unnamed,
        json!({"facets": {"effort": "small"}}),
    )
    .await;
    change_record(&registry, &db, ALICE, unnamed, json!({"name": "Named"})).await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    for limit in [1, 50] {
        let read = changes_read(
            &registry,
            &db,
            ALICE,
            &event,
            json!({"record_id": unnamed, "limit": limit}),
        )
        .await
        .unwrap();
        let rename = change(&read["result"]["events"][0], "name");
        assert_eq!(
            (&rename["before"], &rename["before_known"], &rename["after"]),
            (&json!(""), &json!(true), &json!("Named")),
            "limit {limit}: {read:#}"
        );
    }
}

#[tokio::test]
async fn declared_record_changes_look_back_stops_at_its_row_budget() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let budget = native_ce::mcp::tools::history::TabChangeBudget::DEFAULT.lookback_rows;
    assert_eq!(budget, 256);
    let within = "cd000000-0000-4000-8000-000000000004";
    let beyond = "cd000000-0000-4000-8000-000000000005";
    // The rename's look-back must pass `noise` rows before the creation
    // that set the name: the budget minus one of them leaves room for the
    // creation, the budget itself does not.
    for (id, noise) in [(within, budget - 1), (beyond, budget)] {
        call_as(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({
                "id": id, "type": "WorkItem", "kind": "task", "name": "Original",
                "reason": "Fixture for the look-back budget.",
            }),
        )
        .await
        .unwrap();
        grant(&db, id, ALICE, Capability::View).await;
        for index in 0..noise {
            append_raw(
                &db,
                id,
                "facet.set",
                json!({"key": "noise", "value": format!("n{index}")}),
            )
            .await;
        }
        append_raw(&db, id, "record.updated", json!({"name": "Renamed"})).await;
    }
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let rename = |id: &'static str| {
        let (registry, db, event) = (&registry, &db, event.clone());
        async move {
            let read = changes_read(
                registry,
                db,
                ALICE,
                &event,
                json!({"record_id": id, "limit": 1}),
            )
            .await
            .unwrap();
            change(&read["result"]["events"][0], "name").clone()
        }
    };
    let found = rename(within).await;
    assert_eq!(
        (&found["before"], &found["before_known"]),
        (&json!("Original"), &json!(true))
    );
    let unknown = rename(beyond).await;
    assert_eq!(
        (
            &unknown["before"],
            &unknown["before_known"],
            &unknown["after"]
        ),
        (&Value::Null, &json!(false), &json!("Renamed"))
    );
}

#[tokio::test]
async fn declared_record_changes_page_walk_stops_at_its_scan_budget_and_deadline() {
    use native_ce::mcp::tools::history::TabChangeBudget;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    for round in 0..20 {
        change_record(
            &registry,
            &db,
            ALICE,
            CHANGES_RECORD,
            json!({"name": format!("Plan {round}")}),
        )
        .await;
    }
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let whole = page_events(
        &all_budgeted_pages(
            &db,
            ALICE,
            &event,
            CHANGES_RECORD,
            50,
            TabChangeBudget::DEFAULT,
        )
        .await,
    );
    assert_eq!(whole.len(), 27);

    // Three rows a page: each page stops early, honestly, and paging still
    // covers every event exactly once with the same values.
    let tight = TabChangeBudget {
        scan_rows: 3,
        ..TabChangeBudget::DEFAULT
    };
    let pages = all_budgeted_pages(&db, ALICE, &event, CHANGES_RECORD, 50, tight).await;
    assert!(pages.len() >= 9, "{}", pages.len());
    assert!(pages
        .iter()
        .all(|page| page["events"].as_array().unwrap().len() <= 3));
    assert_eq!(pages[0]["complete"], false);
    assert_eq!(page_events(&pages), whole);

    // A spent deadline still examines one window per page, so paging
    // progresses; the look-back it cannot afford leaves values unknown.
    let spent = TabChangeBudget {
        deadline: std::time::Duration::ZERO,
        ..TabChangeBudget::DEFAULT
    };
    let pages = all_budgeted_pages(&db, ALICE, &event, CHANGES_RECORD, 50, spent).await;
    // Only each page's guaranteed first row fits a spent deadline, and the
    // walk learns the log has ended from one last, empty, complete page.
    assert_eq!(pages.len(), whole.len() + 1);
    assert!(pages.last().unwrap()["events"]
        .as_array()
        .unwrap()
        .is_empty());
    let ids = |events: &[Value]| -> Vec<Value> {
        events
            .iter()
            .map(|event| event["event_id"].clone())
            .collect()
    };
    let hurried = page_events(&pages);
    assert_eq!(ids(&hurried), ids(&whole));
    assert!(hurried
        .iter()
        .flat_map(|event| event["changes"].as_array().unwrap().clone())
        .any(|change| change["before_known"] == false));
}

#[tokio::test]
async fn declared_record_changes_bound_field_names_and_oversized_events() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    // A 600 KiB facet key names itself in changed_fields and changes[].field.
    let key = "k".repeat(600 * 1024);
    append_raw(
        &db,
        CHANGES_RECORD,
        "facet.set",
        json!({"key": key, "value": "v"}),
    )
    .await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let read = changes_read(
        &registry,
        &db,
        ALICE,
        &event,
        json!({"record_id": CHANGES_RECORD}),
    )
    .await
    .unwrap();
    let page = &read["result"];
    let length = serde_json::to_string(page).unwrap().encode_utf16().count();
    assert!(length < 64 * 1024, "{length}");
    assert_eq!(page["complete"], true);
    assert_eq!(page["events"].as_array().unwrap().len(), 8);
    let facet = &page["events"][0];
    assert_eq!(facet["fields_truncated"], true);
    let field = facet["changed_fields"][0].as_str().unwrap();
    assert_eq!(field.chars().count(), 256);
    assert!(field.starts_with("facet:kkk"));
    assert_eq!(facet["changes"][0]["field"], field);
    assert_eq!(facet["changes"][0]["after"], "v");
    assert_eq!(page["events"][1]["fields_truncated"], false);
}

/// Insert `count` rows the field-change read never shows (the always-hidden
/// history types and occurrence bindings) straight into `record_id`'s log,
/// as a workspace carrying them would hold them.
async fn insert_hidden_rows(db: &Db, record_id: &str, count: usize) {
    let pool = crate::common::fixture_write_pool(db).await;
    let types = [
        "reconciliation.recorded.v1",
        "unit.superseded.v1",
        "receipt.dependency_audited.v1",
        "occurrence.bound.v1",
    ];
    for index in 0..count {
        sqlx::query(
            "INSERT INTO content_events
               (id, record_id, type, payload, actor, causal_envelope_version, causal_status)
             VALUES ('hidden-' || lower(hex(randomblob(16))), ?, ?, '{}', 'acct_hidden', 1,
                     'legacy_unknown')",
        )
        .bind(record_id)
        .bind(types[index % types.len()])
        .execute(&pool)
        .await
        .unwrap();
    }
}

/// Pages as a tab observes them, less the cursor's random nonce: whether a
/// cursor was offered stays, its bytes go.
fn observable(pages: &[Value]) -> Vec<Value> {
    pages
        .iter()
        .map(|page| {
            let mut page = page.clone();
            page["next_cursor"] = json!(page["next_cursor"].is_string());
            page
        })
        .collect()
}

#[tokio::test]
async fn declared_record_changes_pagination_ignores_hidden_rows_entirely() {
    use native_ce::mcp::tools::history::TabChangeBudget;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let tight = TabChangeBudget {
        scan_rows: 3,
        lookback_rows: 4,
        ..TabChangeBudget::DEFAULT
    };
    let budgets = [TabChangeBudget::DEFAULT, tight];
    let read_all = || async {
        let mut all = Vec::new();
        for limit in [1, 3, 50] {
            for budget in budgets {
                all.push(observable(
                    &all_budgeted_pages(&db, ALICE, &event, CHANGES_RECORD, limit, budget).await,
                ));
            }
        }
        all
    };
    let before = read_all().await;
    // More hidden rows than the whole scan budget, all newer than every
    // visible event: the first thing a newest-first walk meets.
    insert_hidden_rows(
        &db,
        CHANGES_RECORD,
        2 * TabChangeBudget::DEFAULT.scan_rows + 100,
    )
    .await;
    let after = read_all().await;
    assert_eq!(after, before, "hidden rows changed what the tab observes");
    // The same number of reads to reach the end, and the viewer's own
    // history agrees that nothing it may see changed.
    for (before, after) in before.iter().zip(&after) {
        assert_eq!(before.len(), after.len());
    }
}

#[tokio::test]
async fn declared_record_changes_pages_alike_with_hidden_rows_interleaved() {
    use native_ce::mcp::tools::history::TabChangeBudget;
    // Two workspaces with the same visible history, one with hidden rows
    // between every visible event. Ids and times differ between the two, so
    // those are set aside; everything else a tab sees must be equal.
    let mut observed = Vec::new();
    for hidden in [0usize, 37] {
        let (db, registry) = fixture().await;
        configure_preview_launch();
        adopt_fixture_artifact(&registry, &db).await;
        changes_fixture(&registry, &db).await;
        for round in 0..6 {
            insert_hidden_rows(&db, CHANGES_RECORD, hidden).await;
            change_record(
                &registry,
                &db,
                ALICE,
                CHANGES_RECORD,
                json!({"name": format!("Plan {round}")}),
            )
            .await;
        }
        insert_hidden_rows(&db, CHANGES_RECORD, hidden).await;
        let event = adopted_with_package(
            &registry,
            &db,
            ALICE,
            "agent.history",
            changes_declaration(),
        )
        .await;
        let tight = TabChangeBudget {
            scan_rows: 2,
            lookback_rows: 3,
            ..TabChangeBudget::DEFAULT
        };
        let mut runs = Vec::new();
        for limit in [1, 4, 50] {
            for budget in [TabChangeBudget::DEFAULT, tight] {
                let pages = observable(
                    &all_budgeted_pages(&db, ALICE, &event, CHANGES_RECORD, limit, budget).await,
                );
                let pages: Vec<Value> = pages
                    .into_iter()
                    .map(|mut page| {
                        for event in page["events"].as_array_mut().unwrap() {
                            event["event_id"] = json!("-");
                            event["created_at"] = json!("-");
                        }
                        page
                    })
                    .collect();
                runs.push(pages);
            }
        }
        observed.push(runs);
    }
    assert_eq!(observed[0], observed[1]);
}

#[tokio::test]
async fn declared_record_changes_leave_an_over_bound_event_unprocessed_within_the_deadline() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    // One event naming 20,000 records: redacting it would mean 20,000
    // authorization queries.
    let references: Vec<Value> = (0..20_000)
        .map(|index| json!({"id": format!("00000000-0000-4000-8000-{index:012}")}))
        .collect();
    let heavy = append_raw(
        &db,
        CHANGES_RECORD,
        "record.updated",
        json!({"name": "Heavy", "references": references}),
    )
    .await;
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"name": "After"}),
    )
    .await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let started = std::time::Instant::now();
    let pages = all_change_pages(&registry, &db, ALICE, &event, CHANGES_RECORD, 50).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < native_ce::mcp::tools::history::TabChangeBudget::DEFAULT.deadline,
        "{elapsed:?}"
    );
    let events = page_events(&pages);
    assert_eq!(events.len(), 9, "paging moved past the heavy event");
    let placeholder = events
        .iter()
        .find(|event| event["event_id"] == heavy)
        .unwrap();
    assert_eq!(placeholder["unprocessed"], true);
    assert_eq!(placeholder["type"], "record.updated");
    assert!(placeholder.get("changes").is_none() && placeholder.get("actor").is_none());
    // The heavy event wrote the name, so the rename after it cannot know
    // what it replaced; the rename before it still can.
    let after = change(&events[0], "name");
    assert_eq!(
        (&after["before"], &after["before_known"], &after["after"]),
        (&Value::Null, &json!(false), &json!("After"))
    );
    let retitle = change(event_changing(&pages[0], "name"), "name");
    assert_eq!(retitle["before_known"], false);
    let earlier = events
        .iter()
        .find(|event| event.get("changes").is_some() && event["reason"] == "Retitle the plan.")
        .unwrap();
    assert_eq!(change(earlier, "name")["before"], "Draft plan");
}

#[tokio::test]
async fn declared_record_changes_leave_an_oversized_payload_unread() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let max = native_ce::mcp::tools::history::TAB_CHANGE_MAX_PAYLOAD_BYTES as usize;
    let huge = append_raw(
        &db,
        CHANGES_RECORD,
        "record.updated",
        json!({"body": "x".repeat(max + 1)}),
    )
    .await;
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"facets": {"effort": "tiny"}}),
    )
    .await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let read = changes_read(
        &registry,
        &db,
        ALICE,
        &event,
        json!({"record_id": CHANGES_RECORD}),
    )
    .await
    .unwrap();
    assert!(read.to_string().len() < 64 * 1024);
    let events = read["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 9);
    assert_eq!(events[1]["event_id"], huge);
    assert_eq!(events[1]["unprocessed"], true);
    // Its time is stored after the payload, so it is not read either.
    assert_eq!(events[1]["created_at"], Value::Null);
    assert_eq!(events[1]["type"], "record.updated");
    // What an unread event wrote is not known, so nothing after it can say
    // what it replaced.
    let effort = change(&events[0], "facet:effort");
    assert_eq!(
        (&effort["before_known"], &effort["after"]),
        (&json!(false), &json!("tiny"))
    );
}

#[tokio::test]
async fn declared_record_changes_count_claim_nested_references_the_actor_would_check() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    // Redaction walks a claim key only when the viewer is the actor: for
    // Alice, reading her own event, these 100,000 references would each be
    // an authorization query.
    let references: Vec<Value> = (0..100_000)
        .map(|index| json!({"id": format!("00000000-0000-4000-8000-{index:012}")}))
        .collect();
    let claimed = native_ce::store::append(
        &db,
        native_ce::store::AppendSpec {
            record_id: CHANGES_RECORD.to_string(),
            event_type: "record.updated".to_string(),
            payload: json!({"name": {"claimed_run_key": {"references": references}}}),
            actor: Some(ALICE.to_string()),
        },
    )
    .await
    .unwrap()
    .id;
    let alice_event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.history", changes_declaration()).await;
    for (account, event) in [(ALICE, &alice_event), (BEA, &bea_event)] {
        let started = std::time::Instant::now();
        let read = changes_read(
            &registry,
            &db,
            account,
            event,
            json!({"record_id": CHANGES_RECORD}),
        )
        .await
        .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < native_ce::mcp::tools::history::TabChangeBudget::DEFAULT.deadline,
            "{account}: {elapsed:?}"
        );
        let first = &read["result"]["events"][0];
        assert_eq!(first["event_id"], claimed, "{account}");
        if account == ALICE {
            assert_eq!(first["unprocessed"], true, "{first:#}");
            assert!(first.get("changes").is_none());
        } else {
            // Bea's redaction erases the claim unread, so it costs her no
            // checks and the event is processed as her history shows it.
            assert!(first.get("unprocessed").is_none(), "{first:#}");
            assert_eq!(
                change(first, "name")["after"],
                r#"{"claimed_run_key":null}"#
            );
        }
    }
}

#[tokio::test]
async fn declared_record_changes_never_report_a_failed_read_as_the_end_of_history() {
    use native_ce::mcp::tools::alpha_tabs::record_changes_read_with_budget;
    use native_ce::mcp::tools::history::TabChangeBudget;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    // Without the index the read's first statement cannot run at all.
    sqlx::query("DROP INDEX idx_content_events_record_changes")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let alice = Caller::authenticated(ALICE);
    for budget in [
        TabChangeBudget::DEFAULT,
        TabChangeBudget {
            deadline: std::time::Duration::ZERO,
            ..TabChangeBudget::DEFAULT
        },
        TabChangeBudget {
            scan_rows: 1,
            lookback_rows: 1,
            deadline: std::time::Duration::ZERO,
        },
    ] {
        let result = record_changes_read_with_budget(
            &db,
            &alice,
            "agent.history",
            &event,
            CHANGES_RECORD,
            50,
            None,
            budget,
        )
        .await;
        let error = result
            .expect_err("a failed read must be an error, never an empty complete page")
            .to_string();
        assert!(error.contains("no such index"), "{budget:?}: {error}");
    }
    let hosted = changes_read(
        &registry,
        &db,
        ALICE,
        &event,
        json!({"record_id": CHANGES_RECORD}),
    )
    .await;
    assert!(hosted.is_err(), "{hosted:?}");
}

/// One workspace whose task carries, from Alice, a rename whose name hides
/// `references` record references under a claim key, then a later rename.
async fn erased_claim_fixture(references: usize) -> (Db, ToolRegistry, String, String) {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    changes_fixture(&registry, &db).await;
    let references: Vec<Value> = (0..references)
        .map(|index| json!({"id": format!("00000000-0000-4000-8000-{index:012}")}))
        .collect();
    native_ce::store::append(
        &db,
        native_ce::store::AppendSpec {
            record_id: CHANGES_RECORD.to_string(),
            event_type: "record.updated".to_string(),
            payload: json!({"name": {"claimed_run_key": {"references": references}}}),
            actor: Some(ALICE.to_string()),
        },
    )
    .await
    .unwrap();
    change_record(
        &registry,
        &db,
        ALICE,
        CHANGES_RECORD,
        json!({"name": "Plain"}),
    )
    .await;
    let alice = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.history",
        changes_declaration(),
    )
    .await;
    let bea =
        adopted_with_package(&registry, &db, BEA, "agent.history", changes_declaration()).await;
    (db, registry, alice, bea)
}

/// A page with what differs between two workspaces set aside: ids, times
/// and the cursor's bytes.
fn comparable(read: &Value) -> Value {
    let mut page = read["result"].clone();
    page["next_cursor"] = json!(page["next_cursor"].is_string());
    for event in page["events"].as_array_mut().unwrap() {
        event["event_id"] = json!("-");
        event["created_at"] = json!("-");
    }
    page
}

#[tokio::test]
async fn declared_record_changes_reveal_nothing_about_an_erased_claim() {
    let mut bea_pages = Vec::new();
    for references in [0usize, 257] {
        let (db, registry, alice, bea) = erased_claim_fixture(references).await;
        let params = json!({"record_id": CHANGES_RECORD});
        let as_bea = changes_read(&registry, &db, BEA, &bea, params.clone())
            .await
            .unwrap();
        // Everything Bea sees derives from her own history, which shows the
        // claim as null whatever it held.
        let own = own_history(&registry, &db, BEA, CHANGES_RECORD)
            .await
            .unwrap();
        let claim_event = &as_bea["result"]["events"][1];
        let own_claim = &own["events"][1];
        assert_eq!(claim_event["event_id"], own_claim["id"]);
        assert!(claim_event.get("unprocessed").is_none(), "{claim_event:#}");
        assert_eq!(
            claim_event["payload_bytes"],
            own_claim["payload_json_utf8_bytes"]
        );
        assert_eq!(claim_event["payload_bytes"], 33);
        let full = call_as(
            &registry,
            &db,
            Caller::authenticated(BEA),
            "get_history",
            json!({"record_id": CHANGES_RECORD, "detail": "full", "order": "newest_first"}),
        )
        .await
        .unwrap();
        assert_eq!(
            full["events"][1]["payload"],
            json!({"name": {"claimed_run_key": null}})
        );
        bea_pages.push(comparable(&as_bea));

        // Alice holds the claim: her redaction would walk it, so at 257
        // references her event is left unprocessed, and at 0 it is not.
        let as_alice = changes_read(&registry, &db, ALICE, &alice, params)
            .await
            .unwrap();
        let alice_claim = &as_alice["result"]["events"][1];
        assert_eq!(
            alice_claim.get("unprocessed") == Some(&json!(true)),
            references == 257,
            "{references}: {alice_claim:#}"
        );
    }
    assert_eq!(
        bea_pages[0], bea_pages[1],
        "the erased claim showed through"
    );
}

// Inbound reveal admission (task `fb8564c`, design `e839b03`): the
// `admit_reveal_target` action admits one exact already-visible record id
// to a consented `surface.reveal.v1` install, and `surface.reveal.v1` is
// push-only — never readable via `live_read`.

const REVEAL_NEED: &str = "surface.reveal.v1";
const REVEAL_PACKAGE: &str = "agent.reveal";
const REVEAL_TARGET: &str = "e1d00000-0000-4000-8000-0000000000a1";

fn reveal_declaration() -> Value {
    json!({"needs": ["attention.query.v1", REVEAL_NEED], "effects": []})
}

fn reveal_args(event: &str, record_id: &str) -> Value {
    json!({
        "action": "admit_reveal_target",
        "package": REVEAL_PACKAGE,
        "expected_install_event_id": event,
        "record_id": record_id,
    })
}

async fn reveal_call(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    record_id: &str,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        reveal_args(event, record_id),
    )
    .await
}

async fn adopted_reveal_fixture(registry: &ToolRegistry, db: &Db) -> String {
    configure_preview_launch();
    adopt_fixture_artifact(registry, db).await;
    adopted_with_package(registry, db, ALICE, REVEAL_PACKAGE, reveal_declaration()).await
}

async fn reveal_target_note(registry: &ToolRegistry, db: &Db, id: &str, name: &str) {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id": id, "type": "Document", "kind": "note",
                "name": name, "body": name,
                "reason": "Fixture reveal target."
            }),
        )
        .await
        .unwrap();
    grant(db, id, ALICE, Capability::View).await;
}

#[tokio::test]
async fn reveal_admits_exact_visible_id_with_minimal_receipt() {
    let (db, registry) = fixture().await;
    let verified = adopted_reveal_fixture(&registry, &db).await;
    reveal_target_note(&registry, &db, REVEAL_TARGET, "Reveal me").await;
    let receipt = reveal_call(&registry, &db, &verified, REVEAL_TARGET)
        .await
        .unwrap();
    assert_eq!(receipt["package"], REVEAL_PACKAGE);
    assert_eq!(receipt["install_event_id"], verified);
    assert_eq!(receipt["pin"]["package"], REVEAL_PACKAGE);
    assert_eq!(receipt["pin"]["artifact_id"], ARTIFACT_A);
    assert!(receipt["pin"]["digest"].as_str().is_some());
    assert!(receipt["pin"]["source_revision"].as_str().is_some());
    assert!(receipt["pin"]["declaration_digest"].as_str().is_some());
    assert_eq!(receipt["target"]["record_id"], REVEAL_TARGET);
    // Minimal: no names, bodies, rows, ancestors or sequences leave.
    for key in ["records", "rows", "result", "name", "body"] {
        assert!(receipt.get(key).is_none(), "receipt must not carry {key}");
    }
    assert!(
        !receipt.to_string().contains("Reveal me"),
        "receipt must not leak the target name"
    );
    // Exact reserved ids are admitted, not resolved: the seeded workspace
    // root passes once the viewer may view it.
    grant(&db, "native:root", ALICE, Capability::View).await;
    let reserved = reveal_call(&registry, &db, &verified, "native:root")
        .await
        .unwrap();
    assert_eq!(reserved["target"]["record_id"], "native:root");
    assert_eq!(reserved["install_event_id"], verified);
}

#[tokio::test]
async fn reveal_prefixes_refuse_uniformly_without_leak() {
    const SIBLING_TARGET: &str = "e1d00000-0000-4000-8000-0000000000b1";
    let (db, registry) = fixture().await;
    let verified = adopted_reveal_fixture(&registry, &db).await;
    reveal_target_note(&registry, &db, REVEAL_TARGET, "Reveal me").await;
    reveal_target_note(&registry, &db, SIBLING_TARGET, "Reveal me too").await;
    // The exact-target exemption skips pre-handler prefix resolution for
    // this action, so every non-exact input reaches the exact-row check and
    // refuses uniformly: a unique prefix, a genuinely ambiguous prefix, a
    // well-formed absent id and a truncated reserved id all share one
    // not_visible refusal with no echo and no candidate enumeration.
    let unique = &REVEAL_TARGET[..REVEAL_TARGET.len() - 1];
    for input in [
        unique,
        &REVEAL_TARGET[..7],
        "e1d00000-0000-4000-8000-0000000000ff",
        "native:roo",
    ] {
        let refused = reveal_call(&registry, &db, &verified, input).await;
        let message = refused.unwrap_err().to_string();
        assert!(
            message.contains("reveal refused [not_visible]"),
            "{input:?} must refuse uniformly: {message}"
        );
        assert!(!message.contains(REVEAL_TARGET), "no echo of {input:?}");
        assert!(
            !message.contains(SIBLING_TARGET),
            "no sibling echo for {input:?}"
        );
        assert!(
            !message.contains("ambiguous") && !message.contains("candidates"),
            "no resolver runs for {input:?}"
        );
    }
}

#[tokio::test]
async fn reveal_exemption_keeps_other_alpha_tabs_resolution() {
    // Registry pre-handler variant: another action of the same tool still
    // resolves. Installing by `artifact_id` prefix expands to the fixture
    // artifact, so the install target resolves. (`adopted_with_declaration`
    // below creates the fixture artifact; the install reuses it.)
    let (db, registry) = fixture().await;
    configure_preview_launch();
    let verified = adopted_with_declaration(
        &registry,
        &db,
        json!({"needs": SEARCH_NEEDS, "effects": []}),
    )
    .await;
    let source_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let digest = preview_digest(PREVIEW_BODY);
    let installed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "install",
            "package": "agent.attention-cockpit",
            "version": "0.1.0",
            "digest": digest,
            "artifact_id": &ARTIFACT_A[..8],
            "source_revision": source_revision,
            "declaration": preview_declaration(),
            "reason": "Install by artifact prefix.",
        }),
    )
    .await
    .unwrap();
    assert_eq!(installed["install"]["target_resolves"], true);
    // Snapshot-scoped variant (`resolve_record_ids_in`): the declared
    // reference read still resolves a unique prefix for a consented need.
    live_task(
        &registry,
        &db,
        "e7e71111-0000-4000-8000-000000000043",
        "Unique prefix",
        "open",
    )
    .await;
    grant(
        &db,
        "e7e71111-0000-4000-8000-000000000043",
        ALICE,
        Capability::View,
    )
    .await;
    let short = declared_read(
        &registry,
        &db,
        &verified,
        "records.resolve_reference.v1",
        json!({"reference": "e7e711"}),
    )
    .await
    .unwrap();
    assert_eq!(short["result"]["status"], "found");
    assert_eq!(
        short["result"]["record"]["id"],
        "e7e71111-0000-4000-8000-000000000043"
    );
}

#[tokio::test]
async fn reveal_hidden_and_missing_share_not_visible() {
    let (db, registry) = fixture().await;
    let verified = adopted_reveal_fixture(&registry, &db).await;
    reveal_target_note(&registry, &db, REVEAL_TARGET, "Reveal me").await;
    revoke_all(&db, REVEAL_TARGET).await;
    let hidden = reveal_call(&registry, &db, &verified, REVEAL_TARGET)
        .await
        .unwrap_err()
        .to_string();
    assert!(hidden.contains("reveal refused [not_visible]"));
    let missing = reveal_call(
        &registry,
        &db,
        &verified,
        "e1d00000-0000-4000-8000-0000000000ff",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(missing.contains("reveal refused [not_visible]"));
    assert!(
        !missing.contains("0000000000ff"),
        "missing-id refusal must not echo the id"
    );
}

#[tokio::test]
async fn reveal_refusal_precedence_gate_declaration_params_target() {
    let (db, registry) = fixture().await;
    let verified = adopted_reveal_fixture(&registry, &db).await;
    reveal_target_note(&registry, &db, REVEAL_TARGET, "Reveal me").await;
    // Gate first: a stale generation beats even a malformed target, and
    // beats a well-shaped prefix too — no target analysis runs before it.
    let stale = reveal_call(&registry, &db, "stale-event-token", "bad id!!")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        stale.contains("cas_mismatch"),
        "gate precedes params: {stale}"
    );
    let stale_prefix = reveal_call(&registry, &db, "stale-event-token", &REVEAL_TARGET[..7])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        stale_prefix.contains("cas_mismatch"),
        "gate precedes prefix: {stale_prefix}"
    );
    // Declaration before target params: an install without the reveal need
    // refuses undeclared_need even for a malformed id.
    configure_preview_launch();
    let undeclared_event =
        adopted_with_package(&registry, &db, ALICE, "agent.plain", declaration()).await;
    let undeclared = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "admit_reveal_target",
            "package": "agent.plain",
            "expected_install_event_id": &undeclared_event,
            "record_id": "bad id!!",
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        undeclared.contains("undeclared_need"),
        "declaration precedes params: {undeclared}"
    );
    let undeclared_prefix = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "admit_reveal_target",
            "package": "agent.plain",
            "expected_install_event_id": &undeclared_event,
            "record_id": &REVEAL_TARGET[..7],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        undeclared_prefix.contains("undeclared_need"),
        "declaration precedes prefix: {undeclared_prefix}"
    );
    // Target params: malformed ids refuse invalid_params after gate and
    // declaration have passed.
    let long = "a".repeat(129);
    for malformed in ["bad id!!".to_string(), String::new(), long] {
        let refused = reveal_call(&registry, &db, &verified, &malformed)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("invalid_params"),
            "{malformed:?} must refuse: {refused}"
        );
    }
    // Withdrawn install: disabling beats a well-formed visible target.
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable",
            "package": REVEAL_PACKAGE,
            "expected_install_event_id": verified,
            "reason": "Withdraw the reveal install.",
        }),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"].as_str().unwrap();
    let withdrawn = reveal_call(&registry, &db, disabled_event, REVEAL_TARGET)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        withdrawn.contains("disabled"),
        "withdrawal precedes target: {withdrawn}"
    );
    let withdrawn_prefix = reveal_call(&registry, &db, disabled_event, &REVEAL_TARGET[..7])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        withdrawn_prefix.contains("disabled"),
        "withdrawal precedes prefix: {withdrawn_prefix}"
    );
}

#[tokio::test]
async fn reveal_direct_entry_rechecks_stale_and_withdrawn_install() {
    use native_ce::mcp::tools::alpha_tabs::admit_reveal_target;
    let (db, registry) = fixture().await;
    let verified = adopted_reveal_fixture(&registry, &db).await;
    reveal_target_note(&registry, &db, REVEAL_TARGET, "Reveal me").await;
    let caller = Caller::authenticated(ALICE);
    let stale =
        admit_reveal_target(&db, &caller, REVEAL_PACKAGE, "stale-event", REVEAL_TARGET).await;
    assert!(
        stale.unwrap_err().to_string().contains("cas_mismatch"),
        "direct entry must recheck the generation"
    );
    let disabled = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable",
            "package": REVEAL_PACKAGE,
            "expected_install_event_id": verified,
            "reason": "Withdraw the reveal install.",
        }),
    )
    .await
    .unwrap();
    let disabled_event = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let withdrawn =
        admit_reveal_target(&db, &caller, REVEAL_PACKAGE, &disabled_event, REVEAL_TARGET).await;
    assert!(
        withdrawn.unwrap_err().to_string().contains("disabled"),
        "direct entry must recheck withdrawal"
    );
}

#[tokio::test]
async fn reveal_need_is_push_only_and_snapshot_stays_whole() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // A receipt-carrying package also holding a SQL snapshot need: the
    // default open still reads the same snapshot output shape.
    let declaration = json!({
        "needs": [
            "attention.query.v1",
            REVEAL_NEED,
            sql_need("probe.rows", "Probe",
                "SELECT id, name FROM records WHERE deleted_at IS NULL AND lifecycle = 'open' ORDER BY id ASC LIMIT 40"),
        ],
        "effects": [],
    });
    let verified = adopted_with_package(&registry, &db, ALICE, REVEAL_PACKAGE, declaration).await;
    let snapshot = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": REVEAL_PACKAGE,
            "expected_install_event_id": verified,
        }),
    )
    .await
    .unwrap();
    assert!(snapshot["input"]["records"].is_array());
    assert!(snapshot["input"]["inputs"].as_object().unwrap().is_empty());
    assert!(snapshot["input"]["sql"]["probe.rows"]["rows"].is_array());
    assert!(snapshot["input"]["sql"].get(REVEAL_NEED).is_none());
    // The push-only string is never readable: consented or not, with valid
    // or invalid parameters, the refusal stays undeclared_need.
    for params in [
        json!({}),
        json!({"query": "x"}),
        json!({"reference": REVEAL_TARGET}),
    ] {
        let refused = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            json!({
                "action": "live_read",
                "package": REVEAL_PACKAGE,
                "expected_install_event_id": verified,
                "need": REVEAL_NEED,
                "params": params,
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            refused.contains("undeclared_need"),
            "push-only read must refuse {params}: {refused}"
        );
    }
    // Other needs keep their semantics: an undeclared string need still
    // refuses undeclared_need through the same path.
    let other = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": REVEAL_PACKAGE,
            "expected_install_event_id": verified,
            "need": "records.search.v1",
            "params": {"query": "reveal", "limit": 5},
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        other.contains("undeclared_need"),
        "other needs unchanged: {other}"
    );
    // And the consented reveal action itself succeeds on this same install.
    reveal_target_note(&registry, &db, REVEAL_TARGET, "Reveal me").await;
    let receipt = reveal_call(&registry, &db, &verified, REVEAL_TARGET)
        .await
        .unwrap();
    assert_eq!(receipt["target"]["record_id"], REVEAL_TARGET);
}

// Old-pin delivery compatibility (task fb8564c bridge increment). What this
// oracle proves: the CURRENT install/adopt pin for the long-standing fixture
// equals the FIXED c851-baseline pin below, and launch plus governed reads
// retain it after the bootstrap bytes change. What it does NOT prove: HTML
// rendering or ticket redemption over HTTP (no render claim is made here),
// an already-LOADED old frame passing the future host fence (later host
// stage), or hosted redemption (held fixtures own that proof).

/// Golden pre-bridge (c851) bootstrap evidence: the exact bytes hashed to
/// this before the onReveal increment.
const GOLDEN_PREBRIDGE_BOOTSTRAP_SHA: &str =
    "6b509627de3d87d594ea5670b115d3de1df987ac54ff701e9bedb0d36c29ba34";
/// Golden onReveal-increment delivery evidence, retained as a historical
/// control independently of the current delivery bytes.
const GOLDEN_REVEAL_INCREMENT_BOOTSTRAP_SHA: &str =
    "0f8b6ecf4b68028210412cd488c61c44565a957bc7cd26ffd0165b446c9295da";
/// Golden current Body-attempt delivery evidence: independently measured
/// as 67704 bytes, hardcoded so a silent bytes change fails the test.
const GOLDEN_NEW_BOOTSTRAP_SHA: &str =
    "f4a0cfb3da85ea40b076914c776a2d73aca65428c1d28f8e9a492487ebc8d4aa";
/// Fixed c851-baseline install pin digest for the fixture below.
/// Provenance, two independent derivations that agree:
/// - Rust: executing the pin formula (`alpha_tab_digest` over
///   bundle_sha256, declaration_digest and runtime) on PREVIEW_BODY,
///   preview_declaration and native.html.v1. The formula, fixture body,
///   declaration and runtime are byte-identical between 7db8dfb46 and
///   this head (empty git diff on those regions), so that execution IS
///   the c851 pin.
/// - Python: hashlib SHA-256 over the COMMITTED c851 file bytes
///   (`git show c8518036a:tests/tools/alpha_tabs.rs`): 204-byte PREVIEW_BODY
///   yields bundle 44a905b57d7957f3d8411ac4ce8fcedd5dcd202454cfbed87ec84cfda75efda0;
///   ASCII sorted compact canonical declaration
///   {"effects":["task.triage-set.v1"],"needs":["attention.query.v1"]}
///   yields 9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15;
///   pin input JCS yields the digest below. This matches root's independent
///   read-only baseline evidence exactly.
///
/// The test compares the PUBLIC actual install/adopt/launch pin against this
/// literal constant — never a runtime recomputation. Any formula, fixture or
/// canonicalization drift fails it.
const GOLDEN_C851_PIN_DIGEST: &str =
    "sha256:abd4e377416d6cecec1afff72b4281ee5ffde53d8649b6a7b9530a94dc3b0f40";

const VENDORED_BRIDGE: &str =
    include_str!("../../packages/alpha-tab-kit/src/fake-host/bridge-bootstrap.js");

#[tokio::test]
async fn reveal_old_pin_survives_new_bootstrap_delivery() {
    use native_ce::artifact_html::{bootstrap_digest, descriptor};
    use sha2::{Digest, Sha256};
    // Delivery truth: the current bytes digest is the new SHA, truthfully
    // different from the pre-bridge golden SHA — no historical rewrite.
    assert_eq!(bootstrap_digest(), GOLDEN_NEW_BOOTSTRAP_SHA);
    assert_ne!(bootstrap_digest(), GOLDEN_PREBRIDGE_BOOTSTRAP_SHA);
    assert_ne!(bootstrap_digest(), GOLDEN_REVEAL_INCREMENT_BOOTSTRAP_SHA);
    assert_eq!(
        descriptor()["delivery_transform"]["digest"],
        GOLDEN_NEW_BOOTSTRAP_SHA
    );
    // The bytes the kit serves are exactly those current bytes.
    assert_eq!(
        hex::encode(Sha256::digest(VENDORED_BRIDGE.as_bytes())),
        GOLDEN_NEW_BOOTSTRAP_SHA
    );
    let (db, registry) = fixture().await;
    let (source_revision, verified) = adopted_live_fixture(&registry, &db).await;
    // The adopted install pin equals the fixed c851 baseline pin: nothing
    // about the bridge increments moved it.
    let adopted = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(adopted["event_id"], verified);
    assert_eq!(adopted["digest"], GOLDEN_C851_PIN_DIGEST);
    assert_eq!(adopted["artifact_id"], ARTIFACT_A);
    assert_eq!(adopted["adoption"], "shell_adopt.v1");
    let launch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "launch",
            "package": "agent.attention-cockpit",
            "expected_install_event_id": verified,
        }),
    )
    .await
    .unwrap();
    assert_eq!(launch["install_event_id"], verified);
    assert_eq!(launch["pin"]["digest"], GOLDEN_C851_PIN_DIGEST);
    assert_eq!(launch["pin"]["source_revision"], source_revision);
    assert!(launch["launch"]["url"]
        .as_str()
        .unwrap()
        .contains("/artifact-runtime/v1/launch/"));
    live_task(
        &registry,
        &db,
        "c1d00000-0000-4000-8000-0000000000b1",
        "Open old-pin row",
        "open",
    )
    .await;
    grant(
        &db,
        "c1d00000-0000-4000-8000-0000000000b1",
        ALICE,
        Capability::View,
    )
    .await;
    let read = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert!(read["input"]["records"].is_array());
    // Same install event throughout: no reinstall or migration moved it.
    let inspect = inspect_adopt_entry(&registry, &db, ALICE).await;
    assert_eq!(inspect["event_id"], verified);
}

// Guarded in-place updates (Native design 18fcacc, slice 4).
fn update_pin(
    package: &str,
    event: &str,
    artifact: &str,
    revision: &str,
    body: &str,
    declaration: Value,
) -> Value {
    use native_ce::mcp::tools::alpha_tabs::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    };
    json!({"action": "update", "package": package, "version": "1.2.3",
        "digest": alpha_tab_digest(&alpha_tab_bundle_digest(body), &alpha_tab_declaration_digest(&declaration).unwrap(), "native.html.v1"),
        "artifact_id": artifact, "source_revision": revision, "declaration": declaration,
        "expected_install_event_id": event, "reason": "Update the exact validated pin."})
}

async fn update_call(registry: &ToolRegistry, db: &Db, args: Value) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        args,
    )
    .await
}

async fn update_new_source(registry: &ToolRegistry, db: &Db) -> (String, String) {
    let body = PREVIEW_BODY.replace("Fixture", "Updated source");
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
        "id": ARTIFACT_B, "type": "Document", "kind": "artifact", "name": "Update source",
        "body": body, "facets": {"runtime": "native.html.v1"}, "reason": "Stage update bytes."}),
        )
        .await
        .unwrap();
    grant(db, ARTIFACT_B, ALICE, Capability::View).await;
    (preview_source_revision(db, ARTIFACT_B).await, body)
}

async fn update_fresh_adopt(
    registry: &ToolRegistry,
    db: &Db,
    update: &Value,
    event: &str,
) -> Value {
    let mut pin = json!({"action": "preview", "reason": "Preview updated generation."});
    for field in [
        "package",
        "version",
        "digest",
        "artifact_id",
        "source_revision",
        "declaration",
    ] {
        pin[field] = update[field].clone();
    }
    let preview = call_as(
        registry,
        db,
        attested_preview_caller(ALICE, &pin),
        "manage_alpha_tabs",
        pin.clone(),
    )
    .await
    .unwrap();
    pin["action"] = json!("adopt");
    pin["expected_install_event_id"] = json!(event);
    for field in ["receipt_id", "nonce", "preview_session"] {
        pin[field] = preview["receipt"][field].clone();
    }
    call_as(
        registry,
        db,
        attested_adopt_caller(ALICE, &pin),
        "manage_alpha_tabs",
        pin,
    )
    .await
    .unwrap()
}

async fn update_launch(
    registry: &ToolRegistry,
    db: &Db,
    package: &str,
    event: &str,
) -> native_ce::Result<Value> {
    update_call(
        registry,
        db,
        json!({"action": "launch", "package": package, "expected_install_event_id": event}),
    )
    .await
}

async fn update_counts(db: &Db) -> (i64, i64) {
    let pool = crate::common::fixture_write_pool(db).await;
    (
        sqlx::query_scalar("SELECT count(*) FROM control_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(&pool)
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn update_carries_canonical_permutations_and_launches_new_bytes_with_original_review() {
    let (db, registry) = fixture().await;
    let declaration =
        json!({"needs": ["records.search.v1", "records.resolve_reference.v1"], "effects": []});
    let root = adopted_with_declaration(&registry, &db, declaration).await;
    let original = update_call(
        &registry,
        &db,
        json!({"action": "inspect", "package": "agent.search"}),
    )
    .await
    .unwrap();
    let original_revision = preview_source_revision(&db, ARTIFACT_A).await;
    let (revision, body) = update_new_source(&registry, &db).await;
    let mut args = update_pin(
        "agent.search",
        &root,
        ARTIFACT_B,
        &revision,
        &body,
        json!({"effects": [], "needs": ["records.resolve_reference.v1", "records.search.v1"]}),
    );
    args["idempotency_key"] = json!("update:carry");
    let updated = update_call(&registry, &db, args.clone()).await.unwrap();
    assert_eq!(updated["adoption_carried"], true);
    assert_eq!(updated["adoption_required"], false);
    assert_eq!(
        updated["install"]["adoption_provenance"]["original_adoption_event_id"],
        root
    );
    assert_eq!(
        updated["install"]["adoption_provenance"]["reviewed_source_revision"],
        original_revision
    );
    assert_eq!(
        updated["install"]["adoption_provenance"]["reviewed_bundle_digest"],
        original["install"]["digest"]
    );
    assert_ne!(
        updated["install"]["adoption_provenance"]["reviewed_bundle_digest"],
        updated["install"]["digest"]
    );
    assert_ne!(
        updated["install"]["adoption_provenance"]["reviewed_source_revision"],
        revision
    );
    let event = updated["update_event_id"].as_str().unwrap();
    let launched = update_launch(&registry, &db, "agent.search", event)
        .await
        .unwrap();
    assert_eq!(launched["source"]["event_id"], revision);
    assert_eq!(launched["pin"]["artifact_id"], ARTIFACT_B);
    assert_eq!(
        launched["source"]["bundle_sha256"],
        native_ce::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&body)
    );
    assert!(update_launch(&registry, &db, "agent.search", &root)
        .await
        .unwrap_err()
        .to_string()
        .contains("cas_mismatch"));
    let stale = update_call(&registry, &db, json!({"action": "live_read", "package": "agent.search",
        "expected_install_event_id": root, "need": "records.search.v1", "params": {"query": "test"}})).await.unwrap_err().to_string();
    assert!(stale.contains("cas_mismatch"), "{stale}");
    let mut rollback = args.clone();
    rollback["expected_install_event_id"] = json!(event);
    rollback["version"] = json!("0.0.0");
    rollback["idempotency_key"] = json!("update:rollback");
    let later = update_call(&registry, &db, rollback).await.unwrap();
    assert_eq!(later["adoption_carried"], true);
    assert_eq!(
        later["install"]["adoption_provenance"]["carried_from_event_id"],
        event
    );
    let before = update_counts(&db).await;
    let retry = update_call(&registry, &db, args).await.unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["idempotent_retry"], true);
    assert_eq!(retry["update_event_id"], event);
    assert_eq!(retry["install"], updated["install"]);
    assert_eq!(
        retry["current_install"]["event_id"],
        later["update_event_id"]
    );
    assert_eq!(before, update_counts(&db).await);
}

#[tokio::test]
async fn update_each_declaration_dimension_requires_fresh_adoption_and_pending_breaks_chain() {
    let baseline = json!({"needs": ["attention.query.v1", param_need("n1", "Rows", "SELECT id FROM records WHERE id=?1",
        json!([{"name": "record_id", "type": "text", "max_len": 64}]))],
        "effects": [{"effect": "records.facet-set.v1", "key": "priority", "values": ["low", "high"], "target": {"need": "n1"}}],
        "sessions": [{"session": "session.body.v1", "key": "doc", "scope": {"type": "Document", "kind": "note"}, "mode": "view", "presence": false}]});
    let mut variants = Vec::new();
    let mut changed = baseline.clone();
    changed["needs"].as_array_mut().unwrap().remove(0);
    variants.push(("needs", changed));
    let mut changed = baseline.clone();
    changed["effects"][0]["values"] = json!(["low"]);
    variants.push(("effect bounds", changed));
    let mut changed = baseline.clone();
    changed["needs"][1]["sql"] = json!("SELECT id FROM records WHERE id=?1 AND deleted_at IS NULL");
    variants.push(("SQL", changed));
    let mut changed = baseline.clone();
    changed["needs"][1]["params"][0]["max_len"] = json!(32);
    variants.push(("params", changed));
    let mut changed = baseline.clone();
    changed["sessions"][0]["mode"] = json!("edit");
    variants.push(("sessions", changed));
    for (dimension, declaration) in variants {
        let (db, registry) = fixture().await;
        let root = adopted_with_declaration(&registry, &db, baseline.clone()).await;
        let revision = preview_source_revision(&db, ARTIFACT_A).await;
        let mut args = update_pin(
            "agent.search",
            &root,
            ARTIFACT_A,
            &revision,
            PREVIEW_BODY,
            declaration,
        );
        let updated = update_call(&registry, &db, args.clone()).await.unwrap();
        assert_eq!(updated["adoption_required"], true, "{dimension}");
        assert_eq!(updated["install"]["adoption"], "caller_asserted");
        assert!(updated["install"]["adoption_provenance"].is_null());
        let event = updated["update_event_id"].as_str().unwrap();
        assert!(update_launch(&registry, &db, "agent.search", event)
            .await
            .unwrap_err()
            .to_string()
            .contains("adoption_unverified"));
        args["expected_install_event_id"] = json!(event);
        let identical_pending = update_call(&registry, &db, args.clone()).await.unwrap();
        assert_eq!(identical_pending["adoption_carried"], false);
        let returned = update_call(
            &registry,
            &db,
            update_pin(
                "agent.search",
                identical_pending["update_event_id"].as_str().unwrap(),
                ARTIFACT_A,
                &revision,
                PREVIEW_BODY,
                baseline.clone(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            returned["adoption_carried"], false,
            "return to original must not revive {dimension}"
        );
        args["expected_install_event_id"] = returned["update_event_id"].clone();
        let pending = update_call(&registry, &db, args.clone()).await.unwrap();
        let adopted = update_fresh_adopt(
            &registry,
            &db,
            &args,
            pending["update_event_id"].as_str().unwrap(),
        )
        .await;
        update_launch(
            &registry,
            &db,
            "agent.search",
            adopted["install"]["event_id"].as_str().unwrap(),
        )
        .await
        .unwrap();
        assert!(
            native_ce::conformance::rebuild_and_diff_control(&db)
                .await
                .unwrap()
                .equal
        );
    }
}

#[tokio::test]
async fn update_shell_auto_carries_honest_origin_and_disabled_status() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let revision = preview_source_revision(&db, ARTIFACT_A).await;
    let mut install = install_exact_args(ARTIFACT_A, &revision, &preview_digest(PREVIEW_BODY));
    install["request"] = json!("Keep this request display text.");
    let installed = update_call(&registry, &db, install).await.unwrap();
    let args = adopt_authored_args(
        ARTIFACT_A,
        &revision,
        &preview_digest(PREVIEW_BODY),
        installed["install"]["event_id"].as_str().unwrap(),
    );
    let adopted = call_as(
        &registry,
        &db,
        attested_adopt_authored_caller(ALICE, &args),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();
    let disabled = update_call(&registry, &db, json!({"action": "disable", "package": "agent.attention-cockpit",
        "expected_install_event_id": adopted["install"]["event_id"], "reason": "Disable before updating."})).await.unwrap();
    let (revision, body) = update_new_source(&registry, &db).await;
    let updated = update_call(
        &registry,
        &db,
        update_pin(
            "agent.attention-cockpit",
            disabled["install"]["event_id"].as_str().unwrap(),
            ARTIFACT_B,
            &revision,
            &body,
            preview_declaration(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(updated["adoption_carried"], true);
    assert_eq!(updated["install"]["status"], "disabled");
    assert_eq!(
        updated["install"]["request"],
        "Keep this request display text."
    );
    assert_eq!(updated["install"]["adoption"], "shell_auto.v1");
    assert_eq!(
        updated["install"]["adoption_provenance"]["original_adoption_method"],
        "shell_auto.v1"
    );
    assert!(updated["install"]["adoption_provenance"]["reviewed_source_revision"].is_null());
    assert!(updated["install"]["adoption_provenance"]["reviewed_bundle_digest"].is_null());
    assert!(update_launch(
        &registry,
        &db,
        "agent.attention-cockpit",
        updated["update_event_id"].as_str().unwrap()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("disabled"));
}

#[tokio::test]
async fn update_after_restore_requires_fresh_adoption_for_same_declaration() {
    let (db, registry) = fixture().await;
    let root = adopted_with_declaration(&registry, &db, preview_declaration()).await;
    let disabled = update_call(
        &registry,
        &db,
        json!({"action": "disable", "package": "agent.search",
        "expected_install_event_id": root, "reason": "Disable the adopted tab."}),
    )
    .await
    .unwrap();
    let restored = update_call(&registry, &db, json!({"action": "restore", "package": "agent.search",
        "expected_install_event_id": disabled["install"]["event_id"], "reason": "Restore pending fresh consent."})).await.unwrap();
    assert_eq!(restored["install"]["adoption"], "caller_asserted");
    let (revision, body) = update_new_source(&registry, &db).await;
    let updated = update_call(
        &registry,
        &db,
        update_pin(
            "agent.search",
            restored["install"]["event_id"].as_str().unwrap(),
            ARTIFACT_B,
            &revision,
            &body,
            preview_declaration(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(updated["adoption_required"], true);
    assert_eq!(updated["adoption_carried"], false);
    assert_eq!(updated["install"]["adoption_basis"], "requires_adoption");
    assert!(updated["install"]["adoption_provenance"].is_null());
    assert!(update_launch(
        &registry,
        &db,
        "agent.search",
        updated["update_event_id"].as_str().unwrap()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("adoption_unverified"));
}

#[tokio::test]
async fn update_refusals_and_key_reuse_leave_every_write_count_unchanged() {
    let (db, registry) = fixture().await;
    let root = adopted_with_declaration(&registry, &db, preview_declaration()).await;
    let (revision, body) = update_new_source(&registry, &db).await;
    let args = update_pin(
        "agent.search",
        &root,
        ARTIFACT_B,
        &revision,
        &body,
        preview_declaration(),
    );
    let mut cases = Vec::new();
    for (field, value) in [
        ("expected_install_event_id", json!("stale")),
        ("package", json!("agent.missing")),
        ("digest", json!(DIGEST_A)),
        ("source_revision", json!(root)),
        ("artifact_id", json!(ARTIFACT_A)),
        ("request", json!("Changed request")),
        ("version", json!("1.2")),
        ("version", json!("1.2.3-beta")),
        ("version", json!("123456789.0.0")),
        ("version", json!("1.2.3\u{202e}")),
    ] {
        let mut malformed = args.clone();
        malformed[field] = value;
        cases.push(malformed);
    }
    let mut reads = args.clone();
    reads["declaration"]["reads"] = json!({"relations": {"records": ["id"]}});
    cases.push(reads);
    let mut unknown = args.clone();
    unknown["declaration"]["unknown_key"] = json!(true);
    cases.push(unknown);
    let mut forged = args.clone();
    forged["adoption"] = json!("shell_adopt.v1");
    cases.push(forged);
    let mut missing_token = args.clone();
    missing_token
        .as_object_mut()
        .unwrap()
        .remove("expected_install_event_id");
    cases.push(missing_token);
    for invalid in cases {
        let before = update_counts(&db).await;
        assert!(update_call(&registry, &db, invalid).await.is_err());
        assert_eq!(update_counts(&db).await, before);
    }
    revoke_all(&db, ARTIFACT_B).await;
    let before = update_counts(&db).await;
    assert!(update_call(&registry, &db, args.clone()).await.is_err());
    assert_eq!(update_counts(&db).await, before);
    grant(&db, ARTIFACT_B, ALICE, Capability::View).await;
    let mut keyed = args.clone();
    keyed["idempotency_key"] = json!("update:shared-key");
    let updated = update_call(&registry, &db, keyed.clone()).await.unwrap();
    for (field, value) in [
        ("reason", json!("Different reason.")),
        (
            "expected_install_event_id",
            updated["update_event_id"].clone(),
        ),
        ("version", json!("2.0.0")),
        ("package", json!("agent.other")),
        ("request", json!("different request")),
    ] {
        let mut changed = keyed.clone();
        changed[field] = value;
        let before = update_counts(&db).await;
        assert!(update_call(&registry, &db, changed)
            .await
            .unwrap_err()
            .to_string()
            .contains("different intent"));
        assert_eq!(update_counts(&db).await, before);
    }
    let before = update_counts(&db).await;
    assert!(call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        keyed.clone()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("different intent"));
    assert_eq!(before, update_counts(&db).await);
    let removed = update_call(&registry, &db, json!({"action": "remove", "package": "agent.search", "expected_install_event_id": updated["update_event_id"], "reason": "Remove updated tab."})).await.unwrap();
    let before = update_counts(&db).await;
    let retry = update_call(&registry, &db, keyed).await.unwrap();
    assert_eq!(retry["current_install"]["status"], "removed");
    assert_eq!(retry["update_event_id"], updated["update_event_id"]);
    let mut after_remove = args;
    after_remove["expected_install_event_id"] = removed["install"]["event_id"].clone();
    assert!(update_call(&registry, &db, after_remove).await.is_err());
    assert_eq!(before, update_counts(&db).await);
}

#[tokio::test]
async fn update_race_matrix_has_one_winner_and_no_loser_writes() {
    for action in ["update", "remove", "adopt", "disable"] {
        configure_preview_launch();
        let (db, registry) = fixture().await;
        adopt_fixture_artifact(&registry, &db).await;
        let (event, receipt, nonce, session) = installed_and_previewed(&registry, &db, ALICE).await;
        let revision = preview_source_revision(&db, ARTIFACT_A).await;
        let (new_revision, body) = update_new_source(&registry, &db).await;
        let left = update_pin(
            "agent.attention-cockpit",
            &event,
            ARTIFACT_B,
            &new_revision,
            &body,
            preview_declaration(),
        );
        let mut right = match action {
            "update" => {
                let mut other = left.clone();
                other["version"] = json!("other update");
                other
            }
            "adopt" => adopt_args(
                ARTIFACT_A,
                &revision,
                &preview_digest(PREVIEW_BODY),
                &receipt,
                &nonce,
                &session,
                &event,
            ),
            _ => {
                json!({"action": action, "package": "agent.attention-cockpit", "expected_install_event_id": event, "reason": "Race control mutation."})
            }
        };
        right["idempotency_key"] = json!(format!("race:{action}"));
        let caller = if action == "adopt" {
            attested_adopt_caller(ALICE, &right)
        } else {
            Caller::authenticated(ALICE)
        };
        let before = update_counts(&db).await;
        let (a, b) = tokio::join!(
            update_call(&registry, &db, left),
            call_as(&registry, &db, caller, "manage_alpha_tabs", right)
        );
        assert_eq!(
            usize::from(a.is_ok()) + usize::from(b.is_ok()),
            1,
            "{action}: {a:?} {b:?}"
        );
        let after = update_counts(&db).await;
        assert_eq!(after, (before.0 + 1, before.1 + 1), "{action}");
        assert!(
            native_ce::conformance::rebuild_and_diff_control(&db)
                .await
                .unwrap()
                .equal
        );
    }
}

#[tokio::test]
async fn update_old_preview_receipt_cannot_adopt_the_new_generation() {
    configure_preview_launch();
    let (db, registry) = fixture().await;
    adopt_fixture_artifact(&registry, &db).await;
    let (event, receipt, nonce, session) = installed_and_previewed(&registry, &db, ALICE).await;
    let revision = preview_source_revision(&db, ARTIFACT_A).await;
    let mut cosmetic = update_pin(
        "agent.attention-cockpit",
        &event,
        ARTIFACT_A,
        &revision,
        PREVIEW_BODY,
        preview_declaration(),
    );
    cosmetic["version"] = json!("0.1.0");
    let updated = update_call(&registry, &db, cosmetic).await.unwrap();
    assert_eq!(
        updated["adoption_required"], true,
        "pending equality grants nothing"
    );
    let args = adopt_args(
        ARTIFACT_A,
        &revision,
        &preview_digest(PREVIEW_BODY),
        &receipt,
        &nonce,
        &session,
        &event,
    );
    let before = update_counts(&db).await;
    assert!(call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args
    )
    .await
    .is_err());
    let fresh_token_old_receipt = adopt_args(
        ARTIFACT_A,
        &revision,
        &preview_digest(PREVIEW_BODY),
        &receipt,
        &nonce,
        &session,
        updated["update_event_id"].as_str().unwrap(),
    );
    let refused = call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &fresh_token_old_receipt),
        "manage_alpha_tabs",
        fresh_token_old_receipt,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(refused.contains("receipt_generation_changed"), "{refused}");
    assert_eq!(before, update_counts(&db).await);
    let (new_revision, body) = update_new_source(&registry, &db).await;
    let update = update_pin(
        "agent.attention-cockpit",
        updated["update_event_id"].as_str().unwrap(),
        ARTIFACT_B,
        &new_revision,
        &body,
        preview_declaration(),
    );
    let new = update_call(&registry, &db, update.clone()).await.unwrap();
    let args = adopt_args(
        ARTIFACT_B,
        &new_revision,
        update["digest"].as_str().unwrap(),
        &receipt,
        &nonce,
        &session,
        new["update_event_id"].as_str().unwrap(),
    );
    let after_update = update_counts(&db).await;
    assert!(call_as(
        &registry,
        &db,
        attested_adopt_caller(ALICE, &args),
        "manage_alpha_tabs",
        args
    )
    .await
    .is_err());
    assert_eq!(after_update, update_counts(&db).await);
    assert_eq!(after_update.0, before.0 + 1);
    // Staging and its policy grant also allocate acts; refusal allocates none.
}

#[tokio::test]
async fn personal_alpha_registry_committed_lifecycle_wakes_without_content_cursor() {
    use native_ce::realtime::RealtimeHub;
    use std::time::Duration;
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let (db, hub) = RealtimeHub::attach(db, None).await.unwrap();
    let mut vectors = hub.subscribe_inbox();
    let mut content = hub.subscribe();
    let mut args = install_args("app.registry", ARTIFACT_A, DIGEST_A);
    args["idempotency_key"] = json!("registry-install");
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap();
    let installed = tokio::time::timeout(Duration::from_secs(5), vectors.recv())
        .await
        .unwrap()
        .unwrap();
    let original_content = installed.content;
    let mut prior_control = installed.control;
    assert!(content.try_recv().is_err());
    let retry = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();
    assert_eq!(retry["changed"], false);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), vectors.recv())
            .await
            .is_err()
    );
    let mut token = first["install"]["event_id"].as_str().unwrap().to_owned();
    for action in ["disable", "restore"] {
        let result = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            json!({
                "action":action, "package":"app.registry", "expected_install_event_id":token,
                "reason":"Registry lifecycle test."
            }),
        )
        .await
        .unwrap();
        token = result["install"]["event_id"].as_str().unwrap().to_owned();
        let next = tokio::time::timeout(Duration::from_secs(5), vectors.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(next.control > prior_control);
        assert_eq!(next.content, original_content);
        prior_control = next.control;
        assert!(content.try_recv().is_err());
    }
    call_as(&registry, &db, Caller::authenticated(ALICE), "manage_alpha_tabs", json!({
        "action":"reorder", "tab_order":["graph","agents","folders","tasks","pending:app.registry"], "reason":"Registry order test."
    })).await.unwrap();
    let order = tokio::time::timeout(Duration::from_secs(5), vectors.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(order.control > prior_control);
    assert_eq!(order.content, original_content);
    assert!(content.try_recv().is_err());
    let removed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action":"remove", "package":"app.registry",
            "expected_install_event_id":token, "reason":"Registry removal test."}),
    )
    .await
    .unwrap();
    let removal = tokio::time::timeout(Duration::from_secs(5), vectors.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(removal.control > order.control);
    assert_eq!(removal.content, original_content);
    // Restore is the existing disabled -> installed transition. Removal
    // still refuses restore; completion must not invent new lifecycle rules.
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action":"restore", "package":"app.registry",
            "expected_install_event_id":removed["install"]["event_id"],
            "reason":"Removed restore must refuse."}),
    )
    .await;
    assert!(refused.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), vectors.recv())
            .await
            .is_err()
    );
    assert!(content.try_recv().is_err());
    // The actual production content tool still uses its existing provenance
    // completion path and publishes content; control completion replaces none
    // of that path's bookkeeping.
    note(&registry, &db, NOTE).await;
    let updated = tokio::time::timeout(Duration::from_secs(5), content.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(updated.local_seq > original_content);
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_real_fold_failure_rolls_back_without_wake() {
    use native_ce::realtime::RealtimeHub;
    use std::time::Duration;
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let pool = crate::common::fixture_write_pool(&db).await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER registry_fold_fault AFTER INSERT ON alpha_tab_installs BEGIN SELECT RAISE(FAIL,'registry fold fault'); END").execute(&pool).await.unwrap();
    let (db, hub) = RealtimeHub::attach(db, None).await.unwrap();
    let mut vectors = hub.subscribe_inbox();
    let mut content = hub.subscribe();
    let result = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_args("app.registry", ARTIFACT_A, DIGEST_A),
    )
    .await;
    assert!(result.is_err());
    // Taking the write lane after the error also drains SQLx's rollback.
    let mut tx = pool.begin().await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alpha_tab_installs")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(rows, 0);
    tx.rollback().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), vectors.recv())
            .await
            .is_err()
    );
    assert!(content.try_recv().is_err());
    sqlx::query("DROP TRIGGER registry_fold_fault")
        .execute(&pool)
        .await
        .unwrap();
    let recovered = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        install_args("app.registry", ARTIFACT_A, DIGEST_A),
    )
    .await
    .unwrap();
    assert_eq!(recovered["changed"], true);
    tokio::time::timeout(Duration::from_secs(5), vectors.recv())
        .await
        .unwrap()
        .unwrap();
    db.close().await;
}

// --- Performance baseline: alpha-tab declared read cost ---
//
// Branch `perf/tab-read-baseline`. This is a measurement, not a correctness
// test. It installs one app with exactly two consented needs — a host/string
// need (`records.search.v1`, handled by the string branch of
// `do_declared_read`) and a fixed SQL need (`bench.open`, handled by the
// governed-pool branch) — warms the pools, then:
//
//   1. times N sequential declared reads of each need, printing mean/p50/p95;
//   2. runs K concurrent readers of each need while one background task loops
//      ordinary `create_record` writes, to expose write-lock contention.
//
// It is `#[ignore]`d so the ordinary suite never pays for it. Run it with:
//
//   cargo test --test tools tab_read_cost_baseline -- --ignored --nocapture
//
// N defaults to 200 (env `TAB_READ_BENCH_N`), the per-reader concurrency
// count to 50 (env `TAB_READ_BENCH_CONC_N`), and K to 8 (env
// `TAB_READ_BENCH_K`). Numbers are recorded in
// `docs/perf/tab-read-baseline.md`.
//
// Transaction counting is deliberately absent. The one existing acquisition
// counter (`src/db.rs::with_write_pool_acquisition_counter`) and the
// `write_contention::observed` sampling seam are both `#[cfg(test)]
// pub(crate)`, so the `tests/tools` integration binary cannot reach them, and
// there is no governed-pool counter at all. Instrumenting production code for
// a benchmark is out of scope by instruction, so this reports wall time only.

const BENCH_PACKAGE: &str = "agent.bench";
const BENCH_SQL: &str = "SELECT id, name FROM records WHERE deleted_at IS NULL AND lifecycle = 'open' ORDER BY id ASC LIMIT 40";

fn bench_declaration() -> Value {
    json!({
        "needs": [
            "records.search.v1",
            sql_need("bench.open", "Open", BENCH_SQL),
        ],
        "effects": [],
    })
}

const BENCH_DOCS_PACKAGE: &str = "agent.bench-docs";

/// A Docs-like page: three host needs and five SQL needs.
fn bench_docs_declaration() -> Value {
    json!({
        "needs": [
            "records.search.v1",
            "records.resolve_reference.v1",
            "records.changes.v1",
            sql_need("docs.open", "Open", BENCH_SQL),
            sql_need("docs.count", "Count", "SELECT count(*) AS n FROM records WHERE deleted_at IS NULL"),
            sql_need("docs.recent", "Recent", "SELECT id, name FROM records WHERE deleted_at IS NULL ORDER BY created_at DESC, id ASC LIMIT 20"),
            param_need("docs.by_id", "By id", PARAM_BY_ID_SQL,
                json!([{"name": "record_id", "type": "text", "max_len": 64}])),
            param_need("docs.by_lifecycle", "By lifecycle", PARAM_BY_LIFECYCLE_SQL,
                json!([{"name": "lifecycle", "type": "text", "max_len": 32}])),
        ],
        "effects": [],
    })
}

fn bench_docs_reads() -> Vec<(&'static str, Value)> {
    let page = "be0c0000-0000-4000-8000-000000000000";
    vec![
        ("records.search.v1", bench_search_params()),
        ("records.resolve_reference.v1", json!({"reference": page})),
        ("records.changes.v1", json!({"record_id": page})),
        ("docs.open", json!({})),
        ("docs.count", json!({})),
        ("docs.recent", json!({})),
        ("docs.by_id", json!({"record_id": page})),
        ("docs.by_lifecycle", json!({"lifecycle": "open"})),
    ]
}

fn bench_search_params() -> Value {
    json!({"query": "bench", "limit": 30})
}

async fn bench_declared_read(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    need: &str,
    params: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": BENCH_PACKAGE,
            "expected_install_event_id": event,
            "need": need,
            "params": params,
        }),
    )
    .await
}

/// Install the bench app with its two needs over a database seeded with
/// searchable, Alice-viewable tasks.
async fn bench_fixture() -> (Db, ToolRegistry, String) {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    for i in 0..25u32 {
        let id = format!("be0c0000-0000-4000-8000-{i:012}");
        live_task(&registry, &db, &id, &format!("Bench row {i}"), "open").await;
        grant(&db, &id, ALICE, Capability::View).await;
    }
    let event =
        adopted_with_package(&registry, &db, ALICE, BENCH_PACKAGE, bench_declaration()).await;
    (db, registry, event)
}

fn bench_percentile(samples: &[std::time::Duration], fraction: f64) -> std::time::Duration {
    if samples.is_empty() {
        return std::time::Duration::ZERO;
    }
    let last = samples.len() - 1;
    let index = ((last as f64 * fraction).round() as usize).min(last);
    samples[index]
}

fn bench_print_latency(label: &str, samples: &[std::time::Duration]) {
    if samples.is_empty() {
        println!("{label}: no samples");
        return;
    }
    let mut sorted = samples.to_vec();
    sorted.sort();
    let n = sorted.len();
    let total: std::time::Duration = sorted.iter().sum();
    let mean = total / (n as u32);
    let p50 = bench_percentile(&sorted, 0.50);
    let p95 = bench_percentile(&sorted, 0.95);
    let p99 = bench_percentile(&sorted, 0.99);
    let max = *sorted.last().unwrap();
    let millis = |value: std::time::Duration| value.as_secs_f64() * 1000.0;
    println!(
        "{label}: n={n} mean={:.3}ms p50={:.3}ms p95={:.3}ms p99={:.3}ms max={:.3}ms",
        millis(mean),
        millis(p50),
        millis(p95),
        millis(p99),
        millis(max),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "performance baseline; run with --ignored --nocapture"]
async fn tab_read_cost_baseline() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let n: usize = std::env::var("TAB_READ_BENCH_N")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(200);
    let conc_n: usize = std::env::var("TAB_READ_BENCH_CONC_N")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    let k: usize = std::env::var("TAB_READ_BENCH_K")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8);

    let (db, registry, event) = bench_fixture().await;
    let registry = Arc::new(registry);

    // Warm-up discards pool creation, prepared-statement/plan caching, and the
    // first SQLite page reads. Reads are asserted later, not here.
    for _ in 0..10 {
        bench_declared_read(
            &registry,
            &db,
            &event,
            "records.search.v1",
            bench_search_params(),
        )
        .await
        .unwrap();
        bench_declared_read(&registry, &db, &event, "bench.open", json!({}))
            .await
            .unwrap();
    }

    println!("\n=== tab_read_cost_baseline ===");
    println!(
        "sequential: n={n} reads per need; database is the ephemeral file behind create_database(\":memory:\")"
    );
    println!("transaction counting: omitted (no integration-test-visible pool/transaction hook)");

    let mut host_sequential = Vec::with_capacity(n);
    for _ in 0..n {
        let started = Instant::now();
        let result = bench_declared_read(
            &registry,
            &db,
            &event,
            "records.search.v1",
            bench_search_params(),
        )
        .await;
        let elapsed = started.elapsed();
        result.expect("host/string declared read must succeed");
        host_sequential.push(elapsed);
    }
    bench_print_latency(
        "sequential host/string need (records.search.v1)",
        &host_sequential,
    );

    let mut sql_sequential = Vec::with_capacity(n);
    for _ in 0..n {
        let started = Instant::now();
        let result = bench_declared_read(&registry, &db, &event, "bench.open", json!({})).await;
        let elapsed = started.elapsed();
        result.expect("sql declared read must succeed");
        sql_sequential.push(elapsed);
    }
    bench_print_latency("sequential sql need (bench.open)", &sql_sequential);

    // Scenario 2: K concurrent readers while one task loops ordinary writes.
    println!("\n--- contention: {k} concurrent readers vs 1 background writer ---");
    println!("per reader: conc_n={conc_n} reads per need");

    let stop = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let writer = {
        let registry = Arc::clone(&registry);
        let db = db.clone();
        let stop = Arc::clone(&stop);
        let writes = Arc::clone(&writes);
        tokio::spawn(async move {
            let mut i: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                let id = format!("be0c1000-0000-4000-8000-{i:012}");
                let result = registry
                    .call(
                        db.clone(),
                        Caller::local(),
                        "create_record",
                        json!({
                            "id": id,
                            "type": "Document",
                            "kind": "note",
                            "name": format!("bench writer {i}"),
                            "body": "background write for the tab-read cost baseline",
                            "reason": "Background write loop for the tab-read cost baseline.",
                        }),
                    )
                    .await;
                if result.is_ok() {
                    writes.fetch_add(1, Ordering::Relaxed);
                }
                i += 1;
                tokio::task::yield_now().await;
            }
        })
    };

    let mut readers = Vec::with_capacity(k);
    for _ in 0..k {
        let registry = Arc::clone(&registry);
        let db = db.clone();
        let event = event.clone();
        readers.push(tokio::spawn(async move {
            let mut host = Vec::with_capacity(conc_n);
            let mut sql = Vec::with_capacity(conc_n);
            for _ in 0..conc_n {
                let started = Instant::now();
                let result = bench_declared_read(
                    &registry,
                    &db,
                    &event,
                    "records.search.v1",
                    bench_search_params(),
                )
                .await;
                let elapsed = started.elapsed();
                result.expect("concurrent host/string declared read must succeed");
                host.push(elapsed);

                let started = Instant::now();
                let result =
                    bench_declared_read(&registry, &db, &event, "bench.open", json!({})).await;
                let elapsed = started.elapsed();
                result.expect("concurrent sql declared read must succeed");
                sql.push(elapsed);
            }
            (host, sql)
        }));
    }

    let mut host_concurrent = Vec::with_capacity(k * conc_n);
    let mut sql_concurrent = Vec::with_capacity(k * conc_n);
    for reader in readers {
        let (host, sql) = reader.await.expect("reader task must not panic");
        host_concurrent.extend(host);
        sql_concurrent.extend(sql);
    }
    stop.store(true, Ordering::Relaxed);
    writer.await.expect("background writer must not panic");
    let write_count = writes.load(Ordering::Relaxed);

    bench_print_latency(
        &format!("contended host/string need ({k} readers)"),
        &host_concurrent,
    );
    bench_print_latency(
        &format!("contended sql need ({k} readers)"),
        &sql_concurrent,
    );
    println!("background writes completed during the contention window: {write_count}");

    // Scenario 3 (slice 3): opening a Docs-like page that needs eight
    // declared reads, three host and five SQL, uncontended.
    let docs_n: usize = std::env::var("TAB_READ_BENCH_DOCS_N")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    let docs_event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        BENCH_DOCS_PACKAGE,
        bench_docs_declaration(),
    )
    .await;
    let docs_reads = bench_docs_reads();
    let one = |need: &'static str, params: Value| {
        let (registry, db, event) = (Arc::clone(&registry), db.clone(), docs_event.clone());
        async move {
            call_as(
                &registry,
                &db,
                Caller::authenticated(ALICE),
                "manage_alpha_tabs",
                json!({
                    "action": "live_read", "package": BENCH_DOCS_PACKAGE,
                    "expected_install_event_id": event, "need": need, "params": params,
                }),
            )
            .await
            .expect("docs single read must succeed")
        }
    };
    let batch = || {
        let (registry, db, event) = (Arc::clone(&registry), db.clone(), docs_event.clone());
        let reads: Vec<Value> = docs_reads
            .iter()
            .map(|(need, params)| json!({"need": need, "params": params}))
            .collect();
        async move {
            let answer = call_as(
                &registry,
                &db,
                Caller::authenticated(ALICE),
                "manage_alpha_tabs",
                json!({
                    "action": "live_read", "package": BENCH_DOCS_PACKAGE,
                    "expected_install_event_id": event, "reads": reads,
                }),
            )
            .await
            .expect("docs batch read must succeed");
            for result in answer["results"].as_array().unwrap() {
                assert!(result.get("ok").is_some(), "{result}");
            }
        }
    };
    for _ in 0..5 {
        batch().await;
    }
    println!(
        "\n--- docs open: {} needs per page, uncontended, n={docs_n} pages ---",
        docs_reads.len()
    );
    let mut docs_sequential = Vec::with_capacity(docs_n);
    let mut docs_parallel = Vec::with_capacity(docs_n);
    let mut docs_batch = Vec::with_capacity(docs_n);
    for _ in 0..docs_n {
        let started = Instant::now();
        for (need, params) in &docs_reads {
            one(need, params.clone()).await;
        }
        docs_sequential.push(started.elapsed());

        let started = Instant::now();
        futures::future::join_all(
            docs_reads
                .iter()
                .map(|(need, params)| one(need, params.clone())),
        )
        .await;
        docs_parallel.push(started.elapsed());

        let started = Instant::now();
        batch().await;
        docs_batch.push(started.elapsed());
    }
    bench_print_latency("docs open, one call per need, sequential", &docs_sequential);
    bench_print_latency(
        "docs open, one call per need, all in flight",
        &docs_parallel,
    );
    bench_print_latency("docs open, one batched call", &docs_batch);
    println!("=== end tab_read_cost_baseline ===\n");

    db.close().await;
}

// `artifact.render.v1` (task `51e8571`, slice A): a declared, read-only
// live render of one MDX artifact as the viewer, projected display-only.
// The tree is the viewer's own `render_artifact` tree by construction, so
// the artifact's bound records follow the viewer's visibility, not the
// tab's or the author's.

const RENDER_FOLDER: &str = "ae000000-0000-4000-8000-000000000001";
const RENDER_SHARED_TASK: &str = "ae000000-0000-4000-8000-000000000002";
const RENDER_PRIVATE_TASK: &str = "ae000000-0000-4000-8000-000000000003";
const RENDER_BOUND_V1: &str = "ae000000-0000-4000-8000-000000000004";
const RENDER_STANDALONE_V2: &str = "ae000000-0000-4000-8000-000000000005";
const RENDER_ALICE_ONLY_V2: &str = "ae000000-0000-4000-8000-000000000006";
const RENDER_MISSING: &str = "ae000000-0000-4000-8000-0000000000ff";

const RENDER_BOUND_V1_BODY: &str =
    "# Delivery\n\n<RecordTable records={props.input.records} columns={['name', 'lifecycle']} />\n";
const RENDER_V2_BODY: &str = "export const nativeArtifact = { schema: \"native.mdx.artifact.v2\", inputs: {}, module_inputs: {}, capability_requests: [] };\n\n# Plain page\n\nSome *ordinary* text.\n";

fn render_declaration() -> Value {
    json!({"needs": ["artifact.render.v1"], "effects": []})
}

async fn both_view(db: &Db, id: &str) {
    replace_explicit_policy(
        db,
        "test:policy",
        id,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
}

async fn create_local(registry: &ToolRegistry, db: &Db, args: Value) {
    let mut args = args;
    args["reason"] = json!("Fixture for the artifact render need.");
    call_as(registry, db, Caller::local(), "create_record", args)
        .await
        .unwrap();
}

/// A folder both viewers see, holding one task both see and one only Alice
/// sees; a v1 artifact bound to the folder that tables every record it is
/// given; a standalone v2 page both see; and a v2 page only Alice sees.
async fn render_fixture(registry: &ToolRegistry, db: &Db) {
    create_local(
        registry,
        db,
        json!({"id": RENDER_FOLDER, "type": "Collection", "kind": "folder", "name": "Launch"}),
    )
    .await;
    for (id, name) in [
        (RENDER_SHARED_TASK, "Ship the page"),
        (RENDER_PRIVATE_TASK, "Salary review"),
    ] {
        create_local(
            registry,
            db,
            json!({
                "id": id, "type": "WorkItem", "kind": "task", "name": name,
                "home_id": RENDER_FOLDER, "lifecycle": "open",
            }),
        )
        .await;
    }
    create_local(
        registry,
        db,
        json!({
            "id": RENDER_BOUND_V1, "type": "Document", "kind": "artifact", "name": "Delivery",
            "body": RENDER_BOUND_V1_BODY, "facets": {"runtime": "native.mdx.v1"},
        }),
    )
    .await;
    call_as(
        registry,
        db,
        Caller::local(),
        "manage_renderer_binding",
        json!({"action": "bind", "artifact_id": RENDER_BOUND_V1, "collection_id": RENDER_FOLDER}),
    )
    .await
    .unwrap();
    for id in [RENDER_STANDALONE_V2, RENDER_ALICE_ONLY_V2] {
        create_local(
            registry,
            db,
            json!({
                "id": id, "type": "Document", "kind": "artifact", "name": "Plain page",
                "body": RENDER_V2_BODY, "facets": {"runtime": "native.mdx.v2"},
            }),
        )
        .await;
    }
    for id in [
        RENDER_FOLDER,
        RENDER_SHARED_TASK,
        RENDER_BOUND_V1,
        RENDER_STANDALONE_V2,
    ] {
        both_view(db, id).await;
    }
    for id in [RENDER_PRIVATE_TASK, RENDER_ALICE_ONLY_V2] {
        grant(db, id, ALICE, Capability::View).await;
    }
}

async fn render_read(
    registry: &ToolRegistry,
    db: &Db,
    account: &str,
    package: &str,
    event: &str,
    params: Value,
) -> native_ce::Result<Value> {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": package,
            "expected_install_event_id": event,
            "need": "artifact.render.v1",
            "params": params,
        }),
    )
    .await
}

async fn own_render(registry: &ToolRegistry, db: &Db, account: &str, id: &str) -> Value {
    call_as(
        registry,
        db,
        Caller::authenticated(account),
        "render_artifact",
        json!({"id": id}),
    )
    .await
    .unwrap()
}

fn table_names(tree: &Value) -> Vec<String> {
    let table = tree["children"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["type"] == "RecordTable")
        .unwrap_or_else(|| panic!("RecordTable in {tree:#}"));
    let mut names: Vec<String> = table["props"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn declared_artifact_render_is_the_viewers_own_render_display_only() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    render_fixture(&registry, &db).await;
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.docs", render_declaration()).await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.docs", render_declaration()).await;
    let events_before = content_events(&db).await;

    // The bound v1 artifact: each viewer's tab tree is exactly their own
    // render's tree, so Alice's table holds the task only she can see and
    // Bea's does not.
    let alice = render_read(
        &registry,
        &db,
        ALICE,
        "agent.docs",
        &alice_event,
        json!({"artifact_id": RENDER_BOUND_V1}),
    )
    .await
    .unwrap();
    assert_eq!(alice["need"], "artifact.render.v1");
    assert_eq!(alice["params"], json!({"artifact_id": RENDER_BOUND_V1}));
    assert_eq!(alice["effects_wired"], false);
    let answer = &alice["result"];
    assert_eq!(answer["version"], "artifact.render.v1", "{alice:#}");
    assert_eq!(answer["status"], "rendered", "{alice:#}");
    assert_eq!(answer["artifact_id"], RENDER_BOUND_V1);
    assert_eq!(answer["runtime"], json!({"id": "native.mdx.v1"}));
    assert_eq!(answer["plan"]["kind"], "safe_tree");
    let alice_own = own_render(&registry, &db, ALICE, RENDER_BOUND_V1).await;
    assert_eq!(answer["plan"]["tree"], alice_own["plan"]["tree"]);
    assert_eq!(
        table_names(&answer["plan"]["tree"]),
        ["Salary review", "Ship the page"]
    );
    assert_eq!(
        answer["plan"]["provenance"]["body_sha256"],
        alice_own["plan"]["provenance"]["body_sha256"]
    );
    assert_eq!(answer["plan"]["provenance"]["record_id"], RENDER_BOUND_V1);

    let bea = render_read(
        &registry,
        &db,
        BEA,
        "agent.docs",
        &bea_event,
        json!({"artifact_id": RENDER_BOUND_V1}),
    )
    .await
    .unwrap();
    let bea_own = own_render(&registry, &db, BEA, RENDER_BOUND_V1).await;
    assert_eq!(bea["result"]["plan"]["tree"], bea_own["plan"]["tree"]);
    assert_eq!(
        table_names(&bea["result"]["plan"]["tree"]),
        ["Ship the page"]
    );

    // A standalone v2 page: the same, and nothing that identifies the viewer
    // or would let the frame act crosses.
    let v2 = render_read(
        &registry,
        &db,
        BEA,
        "agent.docs",
        &bea_event,
        json!({"artifact_id": RENDER_STANDALONE_V2}),
    )
    .await
    .unwrap();
    let answer = &v2["result"];
    assert_eq!(answer["status"], "rendered", "{v2:#}");
    assert_eq!(answer["runtime"], json!({"id": "native.mdx.v2"}));
    let v2_own = own_render(&registry, &db, BEA, RENDER_STANDALONE_V2).await;
    assert_eq!(answer["plan"]["tree"], v2_own["plan"]["tree"]);
    assert_eq!(
        answer["plan"]["provenance"]["render_sha256"],
        v2_own["plan"]["provenance"]["render_sha256"]
    );
    let keys = |value: &Value| {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(
        keys(answer),
        ["artifact_id", "plan", "runtime", "status", "version"]
    );
    assert_eq!(
        keys(&answer["plan"]),
        ["kind", "provenance", "tree", "version"]
    );
    let text = answer.to_string();
    for withheld in [
        "caller_sha256",
        "revalidation",
        "input_bundle",
        "interaction_availability",
        "observed",
        "cache",
    ] {
        assert!(!text.contains(withheld), "{withheld} crossed: {answer:#}");
    }

    // Reads write nothing.
    assert_eq!(content_events(&db).await, events_before);
}

#[tokio::test]
async fn declared_artifact_render_refuses_hidden_missing_and_non_mdx_records_alike() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    render_fixture(&registry, &db).await;
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.docs", render_declaration()).await;
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.docs", render_declaration()).await;
    let (registry_ref, db_ref) = (&registry, &db);
    let read = |account: &'static str, event: String, id: &'static str| async move {
        render_read(
            registry_ref,
            db_ref,
            account,
            "agent.docs",
            &event,
            json!({"artifact_id": id}),
        )
        .await
    };
    // Refusals are ordinary refused reads; the host relays the bracketed
    // code to the frame and nothing else.
    let refused = |result: native_ce::Result<Value>| {
        let message = result.unwrap_err().to_string();
        assert!(
            message.starts_with("manage_alpha_tabs: live read refused ["),
            "{message}"
        );
        message
    };
    let refusal = |code: &str| format!("manage_alpha_tabs: live read refused [{code}]");

    // A page Bea cannot see refuses exactly as one that does not exist.
    assert_eq!(
        refused(read(BEA, bea_event.clone(), RENDER_ALICE_ONLY_V2).await),
        refusal("not_found")
    );
    assert_eq!(
        refused(read(BEA, bea_event.clone(), RENDER_MISSING).await),
        refusal("not_found")
    );
    // Alice sees it and gets the render.
    assert_eq!(
        read(ALICE, alice_event.clone(), RENDER_ALICE_ONLY_V2)
            .await
            .unwrap()["result"]["status"],
        "rendered"
    );
    // A visible HTML tab package, a folder and a task are not MDX artifacts.
    for id in [ARTIFACT_A, RENDER_FOLDER, RENDER_SHARED_TASK] {
        let id: &'static str = id;
        assert_eq!(
            refused(read(BEA, bea_event.clone(), id).await),
            refusal("not_mdx_artifact"),
            "{id}"
        );
    }
    // The viewer loses View on the folder: the bound render then fails as
    // the viewer's own render does, rather than rendering with the tab's
    // or the author's reach.
    replace_explicit_policy(
        &db,
        "test:policy",
        RENDER_FOLDER,
        vec![AllowEntry::account(ALICE, Capability::View)],
    )
    .await
    .unwrap();
    let own = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "render_artifact",
        json!({"id": RENDER_BOUND_V1}),
    )
    .await;
    assert!(
        own.as_ref().map_or(true, |own| own["status"] != "rendered"),
        "{own:?}"
    );
    let lost = read(BEA, bea_event.clone(), RENDER_BOUND_V1).await;
    if own.is_ok() {
        assert_eq!(refused(lost), refusal("render_failed"));
    } else {
        assert!(lost.is_err());
    }

    // Parameters are bounded before anything is read. A short prefix is
    // refused, not resolved: no target lookup runs ahead of the tab's gates,
    // even one that would match records Bea can see.
    for params in [
        json!({}),
        json!({"artifact_id": "ae00000"}),
        json!({"artifact_id": &RENDER_STANDALONE_V2[..8]}),
        json!({"artifact_id": RENDER_STANDALONE_V2.to_uppercase()}),
        json!({"artifact_id": RENDER_STANDALONE_V2, "as_of": {"event_id": "e1"}}),
    ] {
        let refused = render_read(
            &registry,
            &db,
            BEA,
            "agent.docs",
            &bea_event,
            params.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(refused.contains("[invalid_params]"), "{params}: {refused}");
    }
}

#[tokio::test]
async fn declared_artifact_render_rechecks_consent_and_the_install_on_its_own() {
    use native_ce::mcp::tools::alpha_tabs::artifact_render_read;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    render_fixture(&registry, &db).await;
    let alice = Caller::authenticated(ALICE);
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.docs", render_declaration()).await;
    let inner = |package: &'static str, event: String| {
        let (db, alice) = (db.clone(), alice.clone());
        async move { artifact_render_read(&db, &alice, package, &event, RENDER_STANDALONE_V2).await }
    };
    assert_eq!(
        inner("agent.docs", event.clone()).await.unwrap()["status"],
        "rendered"
    );

    // A package whose consent never named the need cannot read with it,
    // through the host or called directly.
    let search_only = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        json!({"needs": ["records.search.v1"], "effects": []}),
    )
    .await;
    let undeclared = inner("agent.search-only", search_only.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(undeclared.contains("[undeclared_need]"), "{undeclared}");
    let undeclared = render_read(
        &registry,
        &db,
        ALICE,
        "agent.search-only",
        &search_only,
        json!({"artifact_id": RENDER_STANDALONE_V2}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(undeclared.contains("[undeclared_need]"), "{undeclared}");

    // The viewer loses the tab's own artifact: the read refuses on its own.
    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![AllowEntry::account(BEA, Capability::View)],
    )
    .await
    .unwrap();
    let lost = inner("agent.docs", event.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(lost.contains("[unauthorized]"), "{lost}");
    adopt_fixture_artifact_policy(&db).await;

    // The install is disabled: the generation asked for is gone.
    call_as(
        &registry,
        &db,
        alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.docs",
            "expected_install_event_id": event, "reason": "Stop the docs tab.",
        }),
    )
    .await
    .unwrap();
    let stale = inner("agent.docs", event.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("[cas_mismatch]"), "{stale}");
}

/// The window between admission and render: the artifact is revoked or
/// deleted after the read admitted it. Whatever the render then fails
/// with, the frame gets the same bare `not_found` it would have got had
/// the artifact been hidden or missing from the start: no record id, no
/// tool name, no render error text.
#[tokio::test]
async fn declared_artifact_render_settles_a_mid_read_loss_as_not_found() {
    use native_ce::mcp::tools::alpha_tabs::artifact_render_read_with;
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    render_fixture(&registry, &db).await;
    let bea = Caller::authenticated(BEA);
    let alice = Caller::authenticated(ALICE);
    let bea_event =
        adopted_with_package(&registry, &db, BEA, "agent.docs", render_declaration()).await;
    let alice_event =
        adopted_with_package(&registry, &db, ALICE, "agent.docs", render_declaration()).await;
    let exact = "manage_alpha_tabs: live read refused [not_found]";

    // Bea loses View on the page after admission.
    let revoked = artifact_render_read_with(
        &db,
        &bea,
        "agent.docs",
        &bea_event,
        RENDER_STANDALONE_V2,
        || async {
            grant(&db, RENDER_STANDALONE_V2, ALICE, Capability::View).await;
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(revoked, exact);

    // Alice's page is deleted after admission.
    let deleted = artifact_render_read_with(
        &db,
        &alice,
        "agent.docs",
        &alice_event,
        RENDER_ALICE_ONLY_V2,
        || async {
            call_as(
                &registry,
                &db,
                Caller::local(),
                "delete_record",
                json!({"id": RENDER_ALICE_ONLY_V2, "reason": "Delete mid-read."}),
            )
            .await
            .unwrap();
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(deleted, exact);

    for message in [&revoked, &deleted] {
        assert!(!message.contains("ae000000"), "{message}");
        assert!(!message.contains("render_artifact"), "{message}");
    }
    // Both match what an up-front hidden or missing read answers.
    let missing = artifact_render_read_with(
        &db,
        &alice,
        "agent.docs",
        &alice_event,
        RENDER_ALICE_ONLY_V2,
        || async {},
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(missing, exact);
}

/// `artifact.render.v1` gates itself on its own transaction, as record
/// changes do, so a batched read routes it onto that single read path. Each
/// item, a missing artifact included, answers exactly as its single read.
#[tokio::test]
async fn batched_read_answers_artifact_render_like_its_single_read() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    render_fixture(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.docs", render_declaration()).await;

    let artifacts = [RENDER_BOUND_V1, RENDER_STANDALONE_V2, RENDER_MISSING];
    let batch = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.docs",
            "expected_install_event_id": event,
            "reads": artifacts
                .iter()
                .map(|id| json!({"need": "artifact.render.v1", "params": {"artifact_id": id}}))
                .collect::<Vec<_>>(),
        }),
    )
    .await
    .unwrap();
    let results = batch["results"].as_array().unwrap();
    assert_eq!(results.len(), artifacts.len(), "{batch:#}");
    for (result, id) in results.iter().zip(artifacts) {
        assert_eq!(result["need"], "artifact.render.v1");
        let single = render_read(
            &registry,
            &db,
            ALICE,
            "agent.docs",
            &event,
            json!({"artifact_id": id}),
        )
        .await;
        if id == RENDER_MISSING {
            // A missing artifact refuses rather than reporting a status; the
            // batch item carries exactly that refusal.
            let message = single.unwrap_err().to_string();
            assert!(message.ends_with("[not_found]"), "{message}");
            assert_eq!(
                result["error"],
                json!({"code": "not_found", "message": message}),
                "{result:#}"
            );
        } else {
            assert_eq!(result["ok"], as_item(single.unwrap()), "{id}");
        }
    }
}
