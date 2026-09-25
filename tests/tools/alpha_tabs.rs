//! End-to-end coverage for personal alpha tab installs
//! (`manage_alpha_tabs`, task `26ba75a`).
//!
//! These tests exercise the tool through the production MCP registry,
//! storage, and authorization: the install pin/consent rules, the CAS token
//! lifecycle, cross-account isolation, and the honest read-gate verdicts
//! (including the stored-not-enforced digest boundary).

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const ARTIFACT_A: &str = "a1d00000-0000-4000-8000-000000000001";
const ARTIFACT_B: &str = "a1d00000-0000-4000-8000-000000000002";
const NOTE: &str = "a1d00000-0000-4000-8000-000000000003";

const ALICE: &str = "alice";
const BEA: &str = "bea";

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

fn configure_preview_launch() {
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
        &alpha_tab_declaration_digest(&preview_declaration()),
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
    Caller::authenticated(account).with_verified_alpha_tab_preview(alpha_tab_preview_authority_for(
        account,
        str_field("package"),
        str_field("version"),
        str_field("digest"),
        str_field("artifact_id"),
        str_field("source_revision"),
        &declaration,
    ))
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
    Caller::authenticated(caller).with_verified_alpha_tab_adopt(alpha_tab_preview_authority_for(
        attested,
        str_field("package"),
        str_field("version"),
        str_field("digest"),
        str_field("artifact_id"),
        str_field("source_revision"),
        &declaration,
    ))
}

async fn adopt_fixture_artifact(registry: &ToolRegistry, db: &Db) {
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
            ),
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
        alpha_tab_declaration_digest(&preview_declaration())
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
            &alpha_tab_declaration_digest(decl),
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

fn live_read_args(event: &str) -> Value {
    json!({
        "action": "live_read",
        "package": "agent.attention-cockpit",
        "expected_install_event_id": event,
    })
}

async fn live_task(registry: &ToolRegistry, db: &Db, id: &str, name: &str, lifecycle: &str) {
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

async fn adopted_live_fixture(registry: &ToolRegistry, db: &Db) -> (String, String) {
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
            &alpha_tab_declaration_digest(&other),
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
            &alpha_tab_declaration_digest(&declaration),
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
