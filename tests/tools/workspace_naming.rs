//! Naming and renaming the workspace.
//!
//! There is no separate workspace entity in native-ce: the workspace IS the
//! canonical root record `native:root`, so "the workspace name" is that
//! record's `name`. Three things are contracted here.
//!
//! 1. Genesis installs a neutral default. Nothing about the engine's own
//!    branding belongs in a user's workspace label.
//! 2. That name is mutable for life, while the root's structural facts
//!    (`kind`, `home_id`, `persistence`) are not. The name is display-only —
//!    no handle, slug, or URL is derived from it — so a rename is a pure
//!    presentation change and every surface reporting it follows immediately.
//! 3. Performing the rename is host-owner administration, not ordinary
//!    editing, even though genesis grants members `edit` on the root so that
//!    filing works.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::schema::{DEFAULT_WORKSPACE_NAME, ROOT_RECORD_ID};
use native_ce::{create_database, create_database_named, Db};
use serde_json::{json, Value};

const REASON: &str = "Exercise the workspace naming contract.";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn root_name(db: &Db) -> String {
    sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
        .bind(ROOT_RECORD_ID)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), caller, tool, arguments).await
}

/// Pinned person record ids: canonical v4 UUIDs, since a record id can no
/// longer be a readable slug. Both are load-bearing text — the refusal test
/// asserts neither string appears in the refusal, and `enrol` also uses the id
/// as the person's display name so that assertion still covers both the id and
/// the name it would leak.
const OWNER_PERSON_ID: &str = "5e4b1c00-0000-4000-8000-000000000001";
const MEMBER_PERSON_ID: &str = "5e4b1c00-0000-4000-8000-000000000002";

/// A hosted caller who is a member of this database but not its host owner.
fn member(account: &str) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context(format!("host:{account}"), "db:workspace-naming")
        .with_hosting_owner(false)
}

/// A hosted caller who IS the host owner of this database.
fn host_owner(account: &str) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context(format!("host:{account}"), "db:workspace-naming")
        .with_hosting_owner(true)
}

/// Give `account` a verified person record so the root's `members -> edit`
/// grant actually reaches it. Without this the rename tests would be vacuous:
/// the caller would be refused for want of membership rather than by the
/// owner gate.
async fn enrol(registry: &ToolRegistry, db: &Db, person_id: &str, account: &str) {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({
            "id": person_id,
            "type": "Entity",
            "kind": "person",
            "name": person_id,
            "reason": REASON
        }),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person_id)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

#[tokio::test]
async fn fresh_genesis_names_the_workspace_neutrally() {
    let db = create_database(":memory:").await.unwrap();
    assert_eq!(root_name(&db).await, DEFAULT_WORKSPACE_NAME);
    assert_eq!(root_name(&db).await, "Workspace");
}

#[tokio::test]
async fn a_resolved_name_is_written_by_genesis_rather_than_renamed_afterwards() {
    let db = create_database_named(":memory:", "Richard Ng's workspace")
        .await
        .unwrap();
    assert_eq!(root_name(&db).await, "Richard Ng's workspace");
    // One creation event by the seed actor, and no rename: there is no window
    // in which the database was named something else, and the history records
    // no write that nobody performed.
    let events: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT type, actor FROM content_events WHERE record_id = ? ORDER BY seq")
            .bind(ROOT_RECORD_ID)
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        events,
        vec![(
            "record.created".to_string(),
            Some("engine:seed".to_string())
        )]
    );
}

#[tokio::test]
async fn the_workspace_name_is_mutable_while_its_structural_facts_are_not() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    // Mutable, deliberately and for life.
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": ROOT_RECORD_ID, "name": "Acme Research", "reason": REASON }),
    )
    .await
    .unwrap();
    assert_eq!(root_name(&db).await, "Acme Research");

    // Immutable, equally deliberately: the engine relies on these. Asserted
    // against the projector rather than the tool, because the projector is
    // where the guarantee lives — a `record.updated` reaching it by any route
    // is refused. (The tool inherits that, and adds its own earlier guards:
    // rehoming the root would also be caught as a containment cycle, since the
    // root is the ancestor of everything.)
    let folder = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type": "Collection",
            "kind": "folder",
            "name": "Elsewhere",
            "persistence": "enduring",
            "reason": REASON
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (field, value) in [
        ("kind", json!("selection")),
        ("home_id", json!(folder)),
        ("persistence", json!("occurrent")),
    ] {
        let refusal = native_ce::store::update_record(
            &db,
            ROOT_RECORD_ID,
            json!({ field: value, "reason": REASON }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains(&format!("immutable {field}")),
            "{field}: {refusal}"
        );
    }

    // And the name still went through, by the same route the guard rejects
    // the others on.
    native_ce::store::update_record(
        &db,
        ROOT_RECORD_ID,
        json!({ "name": "Acme Research Group", "reason": REASON }),
    )
    .await
    .unwrap();
    assert_eq!(root_name(&db).await, "Acme Research Group");
}

#[tokio::test]
async fn the_host_owner_renames_the_workspace_and_every_surface_follows() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    enrol(&registry, &db, OWNER_PERSON_ID, "acct:owner").await;

    let before = call(
        &registry,
        &db,
        host_owner("acct:owner"),
        "bootstrap",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        before["workspace"]["primary_workspace"]["name"],
        DEFAULT_WORKSPACE_NAME
    );

    let renamed = call(
        &registry,
        &db,
        host_owner("acct:owner"),
        "update_record",
        json!({ "id": ROOT_RECORD_ID, "name": "Acme Research", "reason": REASON }),
    )
    .await
    .unwrap();
    assert_eq!(renamed["name"], "Acme Research");

    let after = call(
        &registry,
        &db,
        host_owner("acct:owner"),
        "bootstrap",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        after["workspace"]["primary_workspace"]["id"],
        ROOT_RECORD_ID
    );
    assert_eq!(
        after["workspace"]["primary_workspace"]["name"],
        "Acme Research"
    );
}

#[tokio::test]
async fn a_member_who_is_not_the_host_owner_is_refused_the_rename_without_leaking() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    enrol(&registry, &db, MEMBER_PERSON_ID, "acct:member").await;
    enrol(&registry, &db, OWNER_PERSON_ID, "acct:owner").await;

    let refusal = call(
        &registry,
        &db,
        member("acct:member"),
        "update_record",
        json!({ "id": ROOT_RECORD_ID, "name": "Member's takeover", "reason": REASON }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refusal.contains("reserved to the host owner"),
        "the refusal must name the rule: {refusal}"
    );
    // Non-leaky: it discloses no roster and no policy detail — not who the
    // owner is, not who else is a member, not what the entries say.
    for leak in [
        "acct:owner",
        OWNER_PERSON_ID,
        MEMBER_PERSON_ID,
        "members",
        "policy",
        "capability",
    ] {
        assert!(!refusal.contains(leak), "refusal leaked {leak}: {refusal}");
    }
    assert_eq!(root_name(&db).await, DEFAULT_WORKSPACE_NAME);

    // The gate is about the workspace root specifically, not about this
    // caller's editing rights: the same member edits an ordinary record fine.
    let note = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Notes", "reason": REASON }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let edited = call(
        &registry,
        &db,
        member("acct:member"),
        "update_record",
        json!({ "id": note, "name": "Renamed notes", "reason": REASON }),
    )
    .await
    .unwrap();
    assert_eq!(edited["name"], "Renamed notes");
}

#[tokio::test]
async fn workspace_renames_require_a_trimmed_name_of_at_most_eighty_unicode_characters() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    for invalid in [
        "".to_string(),
        "   ".to_string(),
        " leading".to_string(),
        "trailing ".to_string(),
        "界".repeat(81),
    ] {
        let refusal = call(
            &registry,
            &db,
            Caller::local(),
            "update_record",
            json!({ "id": ROOT_RECORD_ID, "name": invalid, "reason": REASON }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("workspace name must be 1-80 trimmed characters"),
            "unexpected refusal: {refusal}"
        );
        assert_eq!(root_name(&db).await, DEFAULT_WORKSPACE_NAME);
    }

    let eighty_unicode_scalars = "界".repeat(80);
    let renamed = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "id": ROOT_RECORD_ID,
            "name": eighty_unicode_scalars,
            "reason": REASON
        }),
    )
    .await
    .unwrap();
    assert_eq!(renamed["name"].as_str().unwrap().chars().count(), 80);

    // The stricter contract belongs only to the canonical workspace root.
    // Ordinary records retain the general record API's empty-name behavior.
    let ordinary = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Note", "reason": REASON }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let cleared = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": ordinary, "name": "", "reason": REASON }),
    )
    .await
    .unwrap();
    assert_eq!(cleared["name"], "");
}
