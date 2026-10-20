//! Saved sessions S4 — engine placement, inherited access and atomic share/stop.
//!
//! Design f38936b §§5.1, 7.1–7.4; verification plan Access changes 8–12
//! (plan row cites 7–11; actual numbering is 8–12 — intent over stale labels).
//! Real engine policy evaluation through the narrow `tools` harness only:
//! `register_surface_tools` + in-memory engine, canonical onboarded
//! principals, no node `session_writer`, no migration, no Slack client logic.
//! Slack clearing/transition recovery/ABA pending-card logic and UI are S6.

use native_ce::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use serde_json::{json, Value};

// Pinned v4 UUID fixtures. Hardcoded, never generated.
const SAVED_ROOT: &str = "a5a50000-0000-4000-8000-000000000001";
const SESSION_FOLDER: &str = "a5a50000-0000-4000-8000-000000000002";
const SESSION_RECORD: &str = "a5a50000-0000-4000-8000-000000000003";
const STEP_ONE: &str = "a5a50000-0000-4000-8000-000000000004";
const STEP_TWO: &str = "a5a50000-0000-4000-8000-000000000005";
const CHANNEL: &str = "a5a50000-0000-4000-8000-000000000006";
const SHARE_CARD: &str = "a5a50000-0000-4000-8000-000000000007";
const NON_OWNER_NOTE: &str = "a5a50000-0000-4000-8000-000000000008";
const CHANNEL_POST: &str = "a5a50000-0000-4000-8000-000000000009";

struct Fixture {
    db: native_ce::Db,
    owner: String,
    member: String,
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn onboard(db: &native_ce::Db, email: &str, role: HostedMembershipRole) -> String {
    let arrival = HostedMembershipArrival::new(
        role,
        HostedMembershipSource::Direct,
        "2026-10-09T00:00:00Z".into(),
    )
    .unwrap();
    reconcile_hosted_identity(db, email, "s4-catalog", &arrival, None)
        .await
        .unwrap()
}

/// Owner + member principals, Saved sessions root (owner-only explicit
/// policy), inheriting session folder/record/steps, and a members-View
/// channel folder. Mirrors §5.1 placement with `note` kinds standing in
/// for the S2 `agent-session` kinds (no kind proposal here).
async fn fixture(registry: &ToolRegistry) -> Fixture {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let owner = onboard(&db, "s4-owner@example.test", HostedMembershipRole::Owner).await;
    let member = onboard(&db, "s4-member@example.test", HostedMembershipRole::Member).await;
    // Saved sessions root: explicit owner-only policy, atomically installed.
    call(
        registry,
        &db,
        Caller::authenticated(&owner),
        "create_record",
        json!({"id": SAVED_ROOT, "type": "Collection", "kind": "folder",
            "name": "Saved sessions", "access_policy": "account_only"}),
    )
    .await
    .unwrap();
    // Channel folder: a real members boundary. The seeded root baseline is
    // members-Edit, so a members grant can never widen it. The channel
    // narrows the members baseline to View (read-only channel), which
    // changes state and creates the boundary moves re-anchor to.
    call(
        registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"id": CHANNEL, "type": "Collection", "kind": "folder",
            "name": "#channel"}),
    )
    .await
    .unwrap();
    call(
        registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "set_members_baseline", "record_id": CHANNEL,
            "capability": "view",
            "reason": "S4 read-only channel audience fixture."}),
    )
    .await
    .unwrap();
    // The owner posts in the channel: a direct account grant, so share/stop
    // moves (which need Edit on the destination) succeed as the owner while
    // members keep View. Per-subject deltas always change state.
    call(
        registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "grant", "record_id": CHANNEL,
            "subject": {"kind": "account", "account_id": owner},
            "capability": "edit",
            "reason": "S4 owner posting-rights fixture."}),
    )
    .await
    .unwrap();
    // Session subtree: no access_policy anywhere below the root.
    for (id, ty, kind, name, home) in [
        (
            SESSION_FOLDER,
            "Collection",
            "folder",
            "hike plan",
            SAVED_ROOT,
        ),
        (
            SESSION_RECORD,
            "Document",
            "note",
            "hike plan",
            SESSION_FOLDER,
        ),
        (STEP_ONE, "Document", "note", "step 000001", SESSION_FOLDER),
        (STEP_TWO, "Document", "note", "step 000002", SESSION_FOLDER),
    ] {
        call(
            registry,
            &db,
            Caller::authenticated(&owner),
            "create_record",
            json!({"id": id, "type": ty, "kind": kind, "name": name,
                "home_id": home,
                "facets": {"native.session.folder": "1"}}),
        )
        .await
        .unwrap();
    }
    Fixture { db, owner, member }
}

async fn anchor_of(db: &native_ce::Db, id: &str) -> String {
    sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn is_not_found(view: &Value) -> bool {
    view["records"][0]["status"] == json!("not_found")
}

/// Plan 8: inherit-only subtree under an owner-only root excludes members.
#[tokio::test]
async fn saved_root_is_owner_only_and_subtree_inherits() {
    let registry = registry();
    let Fixture { db, owner, member } = fixture(&registry).await;
    // Root names exactly the owner with Manage; nothing below is explicit.
    let policy = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "manage_record_policy",
        json!({"action": "list", "record_id": SAVED_ROOT}),
    )
    .await
    .unwrap();
    let entries = policy["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{policy}");
    assert_eq!(entries[0]["capability"], "manage");
    for id in [SESSION_FOLDER, SESSION_RECORD, STEP_ONE, STEP_TWO] {
        assert_eq!(anchor_of(&db, id).await, SAVED_ROOT, "{id}");
        let listed = call(
            &registry,
            &db,
            Caller::authenticated(&owner),
            "manage_record_policy",
            json!({"action": "list", "record_id": id}),
        )
        .await
        .unwrap();
        // `list` resolves the effective policy: inherit mode with the root
        // anchor proves no explicit boundary of its own.
        assert_eq!(listed["mode"], "inherit", "{id} {listed}");
        assert_eq!(listed["anchor_id"], SAVED_ROOT, "{id} {listed}");
    }
    // Member sees none of the subtree; owner reads all of it.
    for id in [
        SAVED_ROOT,
        SESSION_FOLDER,
        SESSION_RECORD,
        STEP_ONE,
        STEP_TWO,
    ] {
        let denied = call(
            &registry,
            &db,
            Caller::authenticated(&member),
            "get_record",
            json!({"ids": [id]}),
        )
        .await
        .unwrap();
        assert!(is_not_found(&denied).await, "{id} {denied}");
        let allowed = call(
            &registry,
            &db,
            Caller::authenticated(&owner),
            "get_record",
            json!({"ids": [id]}),
        )
        .await
        .unwrap();
        assert_eq!(allowed["records"][0]["status"], "found", "{id} {allowed}");
    }
    db.close().await;
}

/// Plan 9: moving the folder into the channel grants members subtree read;
/// moving it back revokes it. Real policy recompute, same transaction.
#[tokio::test]
async fn channel_move_grants_and_private_move_revokes_subtree() {
    let registry = registry();
    let Fixture { db, owner, member } = fixture(&registry).await;
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "update_record",
        json!({"id": SESSION_FOLDER, "home_id": CHANNEL}),
    )
    .await
    .unwrap();
    assert_eq!(anchor_of(&db, SESSION_FOLDER).await, CHANNEL);
    assert_eq!(anchor_of(&db, STEP_ONE).await, CHANNEL);
    for id in [SESSION_FOLDER, SESSION_RECORD, STEP_ONE, STEP_TWO] {
        let view = call(
            &registry,
            &db,
            Caller::authenticated(&member),
            "get_record",
            json!({"ids": [id]}),
        )
        .await
        .unwrap();
        assert_eq!(view["records"][0]["status"], "found", "{id} {view}");
    }
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "update_record",
        json!({"id": SESSION_FOLDER, "home_id": SAVED_ROOT}),
    )
    .await
    .unwrap();
    assert_eq!(anchor_of(&db, SESSION_FOLDER).await, SAVED_ROOT);
    for id in [SESSION_FOLDER, SESSION_RECORD, STEP_ONE, STEP_TWO] {
        let revoked = call(
            &registry,
            &db,
            Caller::authenticated(&member),
            "get_record",
            json!({"ids": [id]}),
        )
        .await
        .unwrap();
        assert!(is_not_found(&revoked).await, "{id} {revoked}");
    }
    db.close().await;
}

async fn facet_of(db: &native_ce::Db, id: &str, key: &str) -> Option<String> {
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
        .bind(id)
        .bind(key)
        .fetch_optional(&pool)
        .await
        .unwrap()
}

async fn home_of(db: &native_ce::Db, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Plan 10a: Share batch moves folder + pending card together; a stale
/// guard rolls both back with nothing written.
#[tokio::test]
async fn share_batch_is_atomic_and_stale_guard_rolls_back_both() {
    let registry = registry();
    let Fixture { db, owner, member } = fixture(&registry).await;
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "create_record",
        json!({"id": SHARE_CARD, "type": "Document", "kind": "note",
            "name": "share hike plan", "home_id": SAVED_ROOT,
            "facets": {"native.share.state": "pending"}}),
    )
    .await
    .unwrap();
    let stale = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "batch_write",
        json!({"reason": "S4 stale share guard.",
        "idempotency_key": "s4-share-stale",
        "items": [
            {"op": "update", "id": SESSION_FOLDER, "home_id": CHANNEL,
             "facets": {"native.session.access_version": "99"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.session.access_version": "7"}},
            {"op": "update", "id": SHARE_CARD, "home_id": CHANNEL,
             "facets": {"native.share.state": "shared"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.share.state": "pending"}}
        ]}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(stale.contains("nothing was written"), "{stale}");
    assert_eq!(
        home_of(&db, SESSION_FOLDER).await.as_deref(),
        Some(SAVED_ROOT)
    );
    assert_eq!(home_of(&db, SHARE_CARD).await.as_deref(), Some(SAVED_ROOT));
    let shared = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "batch_write",
        json!({"reason": "S4 share session.",
        "idempotency_key": "s4-share-t1",
        "items": [
            {"op": "update", "id": SESSION_FOLDER, "home_id": CHANNEL,
             "facets": {"native.session.access_version": "1"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.session.access_version": null}},
            {"op": "update", "id": SHARE_CARD, "home_id": CHANNEL,
             "facets": {"native.share.state": "shared"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.share.state": "pending"}}
        ]}),
    )
    .await
    .unwrap();
    assert_eq!(shared["changed"], 2, "{shared}");
    let view = call(
        &registry,
        &db,
        Caller::authenticated(&member),
        "get_record",
        json!({"ids": [STEP_ONE]}),
    )
    .await
    .unwrap();
    assert_eq!(view["records"][0]["status"], "found", "{view}");
    db.close().await;
}

/// Plan 10b: Stop is atomic + fenced; a new share attempt frozen at the
/// superseded `access_version` fails its guards and both records stay put.
/// Same-key T1 replay (S6 card recovery: replay-before-CAS returning the old
/// receipt) is pinned below with byte-identical args; older-transition
/// recovery races (T1 vs T2) remain owed to S6.
#[tokio::test]
async fn stop_is_atomic_and_stale_share_guards_refuse() {
    let registry = registry();
    let Fixture { db, owner, member } = fixture(&registry).await;
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "create_record",
        json!({"id": SHARE_CARD, "type": "Document", "kind": "note",
            "name": "share hike plan", "home_id": SAVED_ROOT,
            "facets": {"native.share.state": "pending"}}),
    )
    .await
    .unwrap();
    // Share T1: version 0 -> 1, folder + card into the channel.
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "batch_write",
        json!({"reason": "S4 share T1.",
        "idempotency_key": "s4-stop-share-t1",
        "items": [
            {"op": "update", "id": SESSION_FOLDER, "home_id": CHANNEL,
             "facets": {"native.session.access_version": "1"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.session.access_version": null}},
            {"op": "update", "id": SHARE_CARD, "home_id": CHANNEL,
             "facets": {"native.share.state": "shared"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.share.state": "pending"}}
        ]}),
    )
    .await
    .unwrap();
    // Stop T1: folder back, card to stopped; card stays in the channel.
    let stopped = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "batch_write",
        json!({"reason": "S4 stop T1.",
        "idempotency_key": "s4-stop-t1",
        "items": [
            {"op": "update", "id": SESSION_FOLDER, "home_id": SAVED_ROOT,
             "facets": {"native.session.access_version": "2"},
             "if_home_id": CHANNEL,
             "if_facets": {"native.session.access_version": "1"}},
            {"op": "update", "id": SHARE_CARD,
             "facets": {"native.share.state": "stopped"},
             "if_facets": {"native.share.state": "shared"}}
        ]}),
    )
    .await
    .unwrap();
    assert_eq!(stopped["changed"], 2, "{stopped}");
    // A new share attempt frozen at the superseded version (v0/null) fails
    // its guards; both records stay put.
    let stale = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "batch_write",
        json!({"reason": "S4 stale new share attempt after Stop.",
        "idempotency_key": "s4-stop-stale-share",
        "items": [
            {"op": "update", "id": SESSION_FOLDER, "home_id": CHANNEL,
             "facets": {"native.session.access_version": "1"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.session.access_version": null}},
            {"op": "update", "id": SHARE_CARD, "home_id": CHANNEL,
             "facets": {"native.share.state": "shared"},
             "if_facets": {"native.share.state": "stopped"}}
        ]}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(stale.contains("nothing was written"), "{stale}");
    assert_eq!(
        home_of(&db, SESSION_FOLDER).await.as_deref(),
        Some(SAVED_ROOT)
    );
    assert_eq!(
        facet_of(&db, SESSION_FOLDER, "native.session.access_version")
            .await
            .as_deref(),
        Some("2")
    );
    assert_eq!(
        facet_of(&db, SHARE_CARD, "native.share.state")
            .await
            .as_deref(),
        Some("stopped")
    );
    // Same-key replay of the committed T1 share (byte-identical args)
    // returns the old receipt without removing the private placement.
    let replayed = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "batch_write",
        json!({"reason": "S4 share T1.",
        "idempotency_key": "s4-stop-share-t1",
        "items": [
            {"op": "update", "id": SESSION_FOLDER, "home_id": CHANNEL,
             "facets": {"native.session.access_version": "1"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.session.access_version": null}},
            {"op": "update", "id": SHARE_CARD, "home_id": CHANNEL,
             "facets": {"native.share.state": "shared"},
             "if_home_id": SAVED_ROOT,
             "if_facets": {"native.share.state": "pending"}}
        ]}),
    )
    .await
    .unwrap();
    assert_eq!(replayed["changed"], 2, "{replayed}");
    assert_eq!(
        home_of(&db, SESSION_FOLDER).await.as_deref(),
        Some(SAVED_ROOT)
    );
    assert_eq!(
        facet_of(&db, SESSION_FOLDER, "native.session.access_version")
            .await
            .as_deref(),
        Some("2")
    );
    assert_eq!(
        facet_of(&db, SHARE_CARD, "native.share.state")
            .await
            .as_deref(),
        Some("stopped")
    );
    let revoked = call(
        &registry,
        &db,
        Caller::authenticated(&member),
        "get_record",
        json!({"ids": [STEP_TWO]}),
    )
    .await
    .unwrap();
    assert!(is_not_found(&revoked).await, "{revoked}");
    db.close().await;
}

async fn person_for_account(db: &native_ce::Db, account: &str) -> String {
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query_scalar("SELECT record_id FROM bindings WHERE identifier = ?")
        .bind(account)
        .fetch_one(&pool)
        .await
        .unwrap()
}

/// Plan 11: owner Stop/move-private succeeds despite a non-owner descendant
/// and an explicit-policy anomaly. The anomaly stays inspectable (reportable
/// in S6); the non-owner record stays owner-floored to its owner (reportable
/// fact). Member revocation on owner steps is
/// the engine precondition that closes live views with `access_lost` —
/// proven by the existing bounded harness
/// (`scheduler_closes_on_access_loss_without_the_value`,
/// `scheduler_closes_when_hook_reports_loss_despite_stale_flag`,
/// `revoke_between_rerun_and_emit_gate_closes_without_value`,
/// `slow_consumer_stale_then_reread_misses_nothing`); no app cache logic here.
#[tokio::test]
async fn owner_stop_succeeds_with_non_owner_and_explicit_policy_anomalies() {
    let registry = registry();
    let Fixture { db, owner, member } = fixture(&registry).await;
    // Filing rights while shared: the read-only channel alone would not let
    // the member file. A direct account grant on the channel does that.
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "grant", "record_id": CHANNEL,
            "subject": {"kind": "account", "account_id": member},
            "capability": "edit",
            "reason": "S4 shared-period filing fixture."}),
    )
    .await
    .unwrap();
    // Explicit-policy anomaly on one step, planted while private (a leftover
    // direct grant, e.g. from an earlier share): against the owner-only
    // effective policy this delta changes state, so it creates a real
    // boundary that later moves must carry along, never block on.
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "grant", "record_id": STEP_ONE,
            "subject": {"kind": "account", "account_id": member},
            "capability": "edit",
            "reason": "S4 explicit-policy anomaly fixture."}),
    )
    .await
    .unwrap();
    let planted = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "manage_record_policy",
        json!({"action": "list", "record_id": STEP_ONE}),
    )
    .await
    .unwrap();
    assert_eq!(planted["mode"], "explicit", "{planted}");
    assert_eq!(planted["anchor_id"], STEP_ONE, "{planted}");
    // Share: folder into the channel (version 0 -> 1).
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "update_record",
        json!({"id": SESSION_FOLDER, "home_id": CHANNEL,
            "facets": {"native.session.access_version": "1"}}),
    )
    .await
    .unwrap();
    // Non-owner descendant: member files her own note in the shared folder.
    call(
        &registry,
        &db,
        Caller::authenticated(&member),
        "create_record",
        json!({"id": NON_OWNER_NOTE, "type": "Document", "kind": "note",
            "name": "member scratch", "home_id": SESSION_FOLDER}),
    )
    .await
    .unwrap();
    // The anomaly boundary survived both moves (S6 reports it); Stop was
    // not blocked on leftover access.
    let anomaly = call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "manage_record_policy",
        json!({"action": "list", "record_id": STEP_ONE}),
    )
    .await
    .unwrap();
    assert_eq!(anomaly["mode"], "explicit", "{anomaly}");
    assert_eq!(anomaly["anchor_id"], STEP_ONE, "{anomaly}");
    // Owner Stop succeeds despite both anomalies.
    call(
        &registry,
        &db,
        Caller::authenticated(&owner),
        "update_record",
        json!({"id": SESSION_FOLDER, "home_id": SAVED_ROOT,
            "facets": {"native.session.access_version": "2"}}),
    )
    .await
    .unwrap();
    assert_eq!(
        home_of(&db, SESSION_FOLDER).await.as_deref(),
        Some(SAVED_ROOT)
    );
    // Owner steps revoked for the member (live-view close precondition);
    // the explicit-policy step keeps its separate audience (S6 reports it).
    for id in [SESSION_RECORD, STEP_TWO] {
        let revoked = call(
            &registry,
            &db,
            Caller::authenticated(&member),
            "get_record",
            json!({"ids": [id]}),
        )
        .await
        .unwrap();
        assert!(is_not_found(&revoked).await, "{id} {revoked}");
    }
    let separate = call(
        &registry,
        &db,
        Caller::authenticated(&member),
        "get_record",
        json!({"ids": [STEP_ONE]}),
    )
    .await
    .unwrap();
    assert_eq!(separate["records"][0]["status"], "found", "{separate}");
    // Non-owner record: owner floor keeps it with its owner (reportable
    // fact for S6; view filtering itself is S6's read contract).
    let own = call(
        &registry,
        &db,
        Caller::authenticated(&member),
        "get_record",
        json!({"ids": [NON_OWNER_NOTE]}),
    )
    .await
    .unwrap();
    assert_eq!(own["records"][0]["status"], "found", "{own}");
    let owner_person = person_for_account(&db, &owner).await;
    let member_person = person_for_account(&db, &member).await;
    assert_ne!(owner_person, member_person);
    let pool = crate::common::fixture_write_pool(&db).await;
    let owner_steps: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE home_id = ? AND owner_id = ?")
            .bind(SESSION_FOLDER)
            .bind(&owner_person)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(owner_steps >= 3, "{owner_steps}");
    // Reportable facts for S6, not a view filter: the member note is still
    // owned by the member (owner floor), and STEP_ONE still carries its
    // explicit members-View boundary (asserted above via policy list).
    // Session-view filtering (owner + policy filter in a supported read
    // query) is S6's read contract; the engine proves Stop was not blocked
    // and the facts S6 must report are inspectable.
    let note_owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM records WHERE id = ?")
            .bind(NON_OWNER_NOTE)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(note_owner.as_deref(), Some(member_person.as_str()));
    db.close().await;
}

/// Plan 12 (storage precondition): the saved subtree holds no Message rows.
/// S6's Slack channel discovery treats channels as Message-homed
/// Collections; this pins the layout fact it relies on (saved folders never
/// qualify), not the Slack query contract itself, which is S6.
#[tokio::test]
async fn saved_subtree_holds_no_message_rows() {
    let registry = registry();
    let Fixture { db, owner, .. } = fixture(&registry).await;
    // Channel post Message via the store seam (delivery plane is S6).
    let post = native_ce::store::create_record(
        &db,
        json!({"id": CHANNEL_POST, "type": "Message", "kind": "message",
            "name": "shared hike plan", "body": "shared",
            "home_id": CHANNEL, "owner_id": person_for_account(&db, &owner).await}),
    )
    .await
    .unwrap();
    assert_eq!(post, CHANNEL_POST);
    let pool = crate::common::fixture_write_pool(&db).await;
    // No Message under the saved subtree.
    let saved_messages: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE type = 'Message' AND id IN (?, ?, ?, ?, ?)",
    )
    .bind(SAVED_ROOT)
    .bind(SESSION_FOLDER)
    .bind(SESSION_RECORD)
    .bind(STEP_ONE)
    .bind(STEP_TWO)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(saved_messages, 0);
    // Layout consequence: no Message is homed in the saved subtree, so a
    // Message-homed channel listing cannot pick up saved folders. The
    // channel itself does hold the post Message.
    let homes: Vec<Option<String>> =
        sqlx::query_scalar("SELECT DISTINCT home_id FROM records WHERE type = 'Message'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        homes.iter().any(|h| h.as_deref() == Some(CHANNEL)),
        "{homes:?}"
    );
    assert!(
        !homes.iter().any(|h| h.as_deref() == Some(SAVED_ROOT)),
        "{homes:?}"
    );
    assert!(
        !homes.iter().any(|h| h.as_deref() == Some(SESSION_FOLDER)),
        "{homes:?}"
    );
    db.close().await;
}
