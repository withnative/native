//! Gated S2b package adoption/disable tests: scope authority, exact install
//! verification, caller-asserted acknowledgment, family pin fan-out with
//! shared-pin protection, stale-disable refusal, fail-closed displacement,
//! and replay equivalence. No v1 schema, events, or tools touched.

use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_definition_as, adopt_package_at, create_principal, create_v2_database, describe_world_as,
    install_definition_as, install_package_as, read_package_selection_in,
    require_package_active_in,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor, BEHAVIOUR_KIND,
    SURFACE_KIND,
};

fn def_bytes(family: &str, version: u32, kinds: &str) -> String {
    format!(r#"{{"family":"{family}","version":{version},"kinds":{kinds}}}"#)
}

fn entry(family: &str, kinds: &str) -> DefinitionEntry {
    entry_v(family, 1, kinds)
}

fn entry_v(family: &str, version: u32, kinds: &str) -> DefinitionEntry {
    let bytes = def_bytes(family, version, kinds);
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: bytes,
        digest,
    }
}

fn manifest(namespace: &str, name: &str, entries: Vec<DefinitionEntry>) -> PackageManifest {
    PackageManifest {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version: 1,
        definitions: entries,
        behaviour: Some(BehaviourDescriptor {
            kind: BEHAVIOUR_KIND.to_string(),
            reads: vec!["linked_record:view".to_string()],
            effects: vec![],
        }),
        surface: Some(SurfaceDescriptor {
            kind: SURFACE_KIND.to_string(),
            view: "pack.view".to_string(),
            fallback: "pack.unavailable".to_string(),
        }),
        declared_reads: vec!["linked_record:view".to_string()],
    }
}

fn ack(m: &PackageManifest) -> Vec<String> {
    m.declared_reads.clone()
}

async fn admin_db() -> (crate::db::Db, String) {
    create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap()
}

async fn install(
    db: &crate::db::Db,
    admin: &str,
    m: &PackageManifest,
) -> crate::package_manifest::ManifestIdentity {
    install_package_as(db, admin, m).await.unwrap()
}

async fn content_count(db: &crate::db::Db, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type = ?")
        .bind(event_type)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

async fn family_pin(
    db: &crate::db::Db,
    scope: &str,
    family: &str,
) -> (Option<i64>, Option<String>) {
    sqlx::query_as("SELECT selected_version, selected_digest FROM kernel_adoptions WHERE scope_home = ? AND family = ?")
        .bind(scope)
        .bind(family)
        .fetch_optional(db.write_pool())
        .await
        .unwrap()
        .unwrap_or((None, None))
}

#[tokio::test]
async fn adopt_selects_package_and_pins_definitions() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    let receipt = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    assert_eq!(receipt.namespace, "acme");
    assert_eq!(receipt.ack_actor, admin);
    assert_eq!(receipt.acknowledged_reads, ack(&m));
    assert!(receipt.selected.is_some() && receipt.event_seq >= 1);
    assert_eq!(content_count(&db, "kernel.package_adopted.v1").await, 1);
    assert_eq!(content_count(&db, "kernel.definition_adopted.v1").await, 1);
    let (ver, dig) = family_pin(&db, KERNEL_ROOT_ID, "demo.notes").await;
    assert_eq!(ver, Some(1));
    assert_eq!(dig, Some(m.definitions[0].digest.clone()));
    let mut conn = db.write_pool().acquire().await.unwrap();
    let (stored, active_manifest) =
        require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "notes")
            .await
            .unwrap();
    assert_eq!(stored.selected.as_ref().unwrap().digest, id.digest);
    assert_eq!(active_manifest.package_digest().unwrap(), id.digest);
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn adopt_exact_retry_appends_nothing() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    let first = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let second = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    assert_eq!(first, second);
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    db.close().await;
}

#[tokio::test]
async fn widened_reads_refuse_without_fresh_ack() {
    let (db, admin) = admin_db().await;
    let v1 = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id1 = install(&db, &admin, &v1).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v1, Some(&id1), &ack(&v1))
        .await
        .unwrap();
    let mut v2 = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    v2.version = 2;
    v2.declared_reads.push("resolution:view".to_string());
    v2.behaviour
        .as_mut()
        .unwrap()
        .reads
        .push("resolution:view".to_string());
    let id2 = install(&db, &admin, &v2).await;
    let before = content_count(&db, "kernel.package_adopted.v1").await;
    let err = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v2, Some(&id2), &ack(&v1))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("fresh acknowledgment"), "{err}");
    assert_eq!(
        content_count(&db, "kernel.package_adopted.v1").await,
        before
    );
    let receipt = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v2, Some(&id2), &ack(&v2))
        .await
        .unwrap();
    assert_eq!(receipt.selected.as_ref().unwrap().version, 2);
    db.close().await;
}

#[tokio::test]
async fn disable_tombstones_and_keeps_history() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    let receipt = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, None, &[])
        .await
        .unwrap();
    assert!(receipt.selected.is_none());
    let mut conn = db.write_pool().acquire().await.unwrap();
    let stored = read_package_selection_in(&mut conn, KERNEL_ROOT_ID, "acme", "notes")
        .await
        .unwrap()
        .expect("tombstone row reads back");
    assert!(stored.selected.is_none());
    drop(conn);
    let (ver, _) = family_pin(&db, KERNEL_ROOT_ID, "demo.notes").await;
    assert_eq!(ver, None);
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "notes")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("disabled"), "{err}");
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn stale_disable_cannot_clobber_newer_selection() {
    let (db, admin) = admin_db().await;
    let v1 = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id1 = install(&db, &admin, &v1).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v1, Some(&id1), &ack(&v1))
        .await
        .unwrap();
    let mut v2 = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    v2.version = 2;
    let id2 = install(&db, &admin, &v2).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v2, Some(&id2), &ack(&v2))
        .await
        .unwrap();
    let err = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v1, None, &[])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("stale package disable"), "{err}");
    let mut conn = db.write_pool().acquire().await.unwrap();
    let stored = read_package_selection_in(&mut conn, KERNEL_ROOT_ID, "acme", "notes")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.selected.as_ref().unwrap().version, 2);
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn root_adoption_inherited_by_children() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    let child = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let sibling = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    require_package_active_in(&mut conn, &child, "acme", "notes")
        .await
        .unwrap();
    require_package_active_in(&mut conn, &sibling, "acme", "notes")
        .await
        .unwrap();
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn child_tombstone_suppresses_only_its_subtree() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    let child = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let sibling = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    // No exact child row exists: the tombstone lands on the inherited live
    // selection, creating a child-local suppression.
    let receipt = adopt_package_at(&db, &admin, &child, &m, None, &[])
        .await
        .unwrap();
    assert!(receipt.selected.is_none());
    assert_eq!(receipt.scope_home, child);
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = require_package_active_in(&mut conn, &child, "acme", "notes")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("disabled"), "{err}");
    require_package_active_in(&mut conn, &sibling, "acme", "notes")
        .await
        .unwrap();
    require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "notes")
        .await
        .unwrap();
    drop(conn);
    // Exact-scope rows: the child carries a tombstone, the sibling carries
    // no row and keeps inheriting the root pin.
    let child_tombs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_adoptions WHERE scope_home = ? AND family = 'demo.notes' AND selected_version IS NULL",
    )
    .bind(&child)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(child_tombs, 1);
    let sibling_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_adoptions WHERE scope_home = ? AND family = 'demo.notes'",
    )
    .bind(&sibling)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(sibling_rows, 0);
    db.close().await;
}

#[tokio::test]
async fn stale_child_disable_against_moved_ancestor_refused() {
    let (db, admin) = admin_db().await;
    let v1 = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id1 = install(&db, &admin, &v1).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v1, Some(&id1), &ack(&v1))
        .await
        .unwrap();
    let mut v2 = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    v2.version = 2;
    let id2 = install(&db, &admin, &v2).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &v2, Some(&id2), &ack(&v2))
        .await
        .unwrap();
    let child = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let err = adopt_package_at(&db, &admin, &child, &v1, None, &[])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("stale package disable"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn shared_pin_survives_sibling_disable() {
    let (db, admin) = admin_db().await;
    let shared = entry("demo.shared", r#"["s"]"#);
    let a = manifest("acme", "aaa", vec![shared.clone()]);
    let b = manifest("acme", "bbb", vec![shared]);
    let ida = install(&db, &admin, &a).await;
    let idb = install(&db, &admin, &b).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &a, Some(&ida), &ack(&a))
        .await
        .unwrap();
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &b, Some(&idb), &ack(&b))
        .await
        .unwrap();
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &b, None, &[])
        .await
        .unwrap();
    let (ver, dig) = family_pin(&db, KERNEL_ROOT_ID, "demo.shared").await;
    assert_eq!(ver, Some(1));
    assert_eq!(dig, Some(a.definitions[0].digest.clone()));
    let mut conn = db.write_pool().acquire().await.unwrap();
    require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "aaa")
        .await
        .unwrap();
    let err = require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "bbb")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("disabled"), "{err}");
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn conflicting_pin_refuses_before_legacy_conditional_disable() {
    let (db, admin) = admin_db().await;
    let a = manifest("acme", "aaa", vec![entry_v("demo.shared", 1, r#"["a"]"#)]);
    let b = manifest("acme", "bbb", vec![entry_v("demo.shared", 2, r#"["b"]"#)]);
    let ida = install(&db, &admin, &a).await;
    let idb = install(&db, &admin, &b).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &a, Some(&ida), &ack(&a))
        .await
        .unwrap();
    let before = crate::dependency_authority_tests::snapshot(&db).await;
    assert!(
        adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &b, Some(&idb), &ack(&b))
            .await
            .is_err()
    );
    assert_eq!(
        crate::dependency_authority_tests::snapshot(&db).await,
        before
    );
    // Preserve conditional-disable coverage for canonical pre-enforcement
    // displacement; the supported adoption path now refuses to create it.
    crate::dependency_tests::legacy_override(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &crate::meta::definition_artifact::RevisionIdentity {
            family: b.definitions[0].family.clone(),
            version: b.definitions[0].version,
            digest: b.definitions[0].digest.clone(),
        },
    )
    .await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &b, Some(&idb), &ack(&b))
        .await
        .unwrap();
    let (ver, dig) = family_pin(&db, KERNEL_ROOT_ID, "demo.shared").await;
    assert_eq!(ver, Some(2));
    assert_eq!(dig, Some(b.definitions[0].digest.clone()));
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &b, None, &[])
        .await
        .unwrap();
    let (ver, _) = family_pin(&db, KERNEL_ROOT_ID, "demo.shared").await;
    assert_eq!(ver, None);
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &a, None, &[])
        .await
        .unwrap();
    let (ver, _) = family_pin(&db, KERNEL_ROOT_ID, "demo.shared").await;
    assert_eq!(ver, None);
    db.close().await;
}

#[tokio::test]
async fn scope_authorization_and_missing_scope() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let err = adopt_package_at(&db, &stranger, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap_err();
    assert!(!err.to_string().is_empty());
    let err = adopt_package_at(&db, &admin, "no-such-home", &m, Some(&id), &ack(&m))
        .await
        .unwrap_err();
    assert!(!err.to_string().is_empty());
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    db.close().await;
}

#[tokio::test]
async fn second_actor_ack_gets_own_event_not_prior_receipt() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let home = crate::kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (stranger.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let first = adopt_package_at(&db, &admin, &home, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    assert_eq!(first.ack_actor, admin);
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let second = adopt_package_at(&db, &stranger, &home, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    assert_eq!(second.ack_actor, stranger);
    assert_ne!(first.event_seq, second.event_seq);
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(after, before + 2);
    let third = adopt_package_at(&db, &stranger, &home, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    assert_eq!(second, third);
    let final_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(final_count, after);
    db.close().await;
}

async fn poison_content(db: &crate::db::Db, scope: &str, payload: serde_json::Value) {
    // Raw content-log insert bypassing the folding write path (which would
    // already refuse these at append); replay must then fail instead of
    // projecting the forgery.
    sqlx::query(
        "INSERT INTO content_events (id, record_id, type, payload, actor, causal_envelope_version, causal_status, created_at)
          VALUES (?, ?, 'kernel.package_adopted.v1', ?, ?, 1, 'complete', ?)",
    )
    .bind(format!("evt-forged-{scope}-{}", payload.to_string().len()))
    .bind(scope)
    .bind(serde_json::to_string(&payload).unwrap())
    .bind("test:forger")
    .bind("2026-09-26T00:00:00.000Z")
    .execute(db.write_pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn adopt_missing_install_appends_nothing() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "ghost", vec![entry("demo.ghost", r#"["g"]"#)]);
    let digest = m.package_digest().unwrap();
    let id = crate::package_manifest::ManifestIdentity {
        namespace: "acme".to_string(),
        name: "ghost".to_string(),
        version: 1,
        digest,
    };
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let err = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("missing package revision"),
        "{err}"
    );
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    db.close().await;
}

#[tokio::test]
async fn forged_adoption_replays_fail() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    // Bad pin: uninstalled revision with an otherwise exact ack.
    poison_content(
        &db,
        KERNEL_ROOT_ID,
        serde_json::json!({
            "scope_home": KERNEL_ROOT_ID,
            "namespace": "acme", "name": "notes",
            "selected": {"version": 9, "digest": "f".repeat(64)},
            "acknowledged_reads": ["linked_record:view"],
        }),
    )
    .await;
    let err = crate::kernel::replay_all_projections(&db)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("missing package revision"),
        "{err}"
    );
    db.close().await;
}

fn two_read_manifest() -> (PackageManifest, crate::package_manifest::ManifestIdentity) {
    // Declared reads need two scopes for the unsorted replay case; the
    // digest is computed purely (no DB).
    let mut m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    m.declared_reads.push("resolution:view".to_string());
    m.behaviour
        .as_mut()
        .unwrap()
        .reads
        .push("resolution:view".to_string());
    let id = m.identity().unwrap();
    (m, id)
}

#[tokio::test]
async fn forged_adoption_bad_ack_fails_replay() {
    let (db, admin) = admin_db().await;
    let (m, id) = two_read_manifest();
    install(&db, &admin, &m).await;
    poison_content(
        &db,
        KERNEL_ROOT_ID,
        serde_json::json!({
            "scope_home": KERNEL_ROOT_ID,
            "namespace": "acme", "name": "notes",
            "selected": {"version": 1, "digest": id.digest.clone()},
            "acknowledged_reads": [],
        }),
    )
    .await;
    let err = crate::kernel::replay_all_projections(&db)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exactly cover"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn forged_adoption_unsorted_ack_fails_replay() {
    let (db, admin) = admin_db().await;
    let (m, id) = two_read_manifest();
    install(&db, &admin, &m).await;
    poison_content(
        &db,
        KERNEL_ROOT_ID,
        serde_json::json!({
            "scope_home": KERNEL_ROOT_ID,
            "namespace": "acme", "name": "notes",
            "selected": {"version": 1, "digest": id.digest.clone()},
            "acknowledged_reads": ["resolution:view", "linked_record:view"],
        }),
    )
    .await;
    let err = crate::kernel::replay_all_projections(&db)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("sorted and unique"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn second_actor_disable_appends_own_tombstone() {
    // Attribution rule applied to the disabled no-op: a different Manage
    // principal disabling an already-disabled package records their own
    // attributed tombstone rather than borrowing the prior receipt.
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let home = crate::kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (stranger.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &admin, &home, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    adopt_package_at(&db, &admin, &home, &m, None, &[])
        .await
        .unwrap();
    let before = content_count(&db, "kernel.package_adopted.v1").await;
    let receipt = adopt_package_at(&db, &stranger, &home, &m, None, &[])
        .await
        .unwrap();
    assert!(receipt.selected.is_none());
    assert_eq!(receipt.ack_actor, stranger);
    assert_eq!(
        content_count(&db, "kernel.package_adopted.v1").await,
        before + 1
    );
    db.close().await;
}

#[tokio::test]
async fn displaced_pin_fails_closed() {
    let (db, admin) = admin_db().await;
    let a = manifest("acme", "aaa", vec![entry_v("demo.shared", 1, r#"["a"]"#)]);
    let b = manifest("acme", "bbb", vec![entry_v("demo.shared", 2, r#"["b"]"#)]);
    let ida = install(&db, &admin, &a).await;
    let idb = install(&db, &admin, &b).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &a, Some(&ida), &ack(&a))
        .await
        .unwrap();
    // A real legacy adoption event retains runtime fallback coverage
    // without asking the enforcing API to introduce new displacement.
    crate::dependency_tests::legacy_override(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &crate::meta::definition_artifact::RevisionIdentity {
            family: b.definitions[0].family.clone(),
            version: b.definitions[0].version,
            digest: b.definitions[0].digest.clone(),
        },
    )
    .await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &b, Some(&idb), &ack(&b))
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "aaa")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("displaced"), "{err}");
    require_package_active_in(&mut conn, KERNEL_ROOT_ID, "acme", "bbb")
        .await
        .unwrap();
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn replay_reconstructs_selections_and_tamper_fails_read() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, None, &[])
        .await
        .unwrap();
    let before = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    crate::kernel::replay_all_projections(&db).await.unwrap();
    let after = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(after.packages.len(), 1);
    assert!(after.packages[0].3.is_none());
    sqlx::query(
        "UPDATE kernel_package_selections SET ack_actor = 'test:impostor' WHERE namespace = 'acme'",
    )
    .execute(db.write_pool())
    .await
    .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = read_package_selection_in(&mut conn, KERNEL_ROOT_ID, "acme", "notes")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("disagrees"), "{err}");
    drop(conn);
    db.close().await;
}

/// K6/K8 provenance: `describe` names the supplying package for a definition
/// it embeds, and says local (JSON null) for a directly installed one.
#[tokio::test]
async fn describe_reports_supplying_package_or_local() {
    let (db, admin) = admin_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let id = install(&db, &admin, &m).await;
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &ack(&m))
        .await
        .unwrap();
    // A directly installed and adopted family has no package supplier.
    let local_bytes = def_bytes("local.thing", 1, r#"["note"]"#);
    install_definition_as(&db, &admin, "local.thing", 1, local_bytes.as_bytes())
        .await
        .unwrap();
    let local_digest =
        crate::meta::definition_artifact::digest_artifact_bytes(local_bytes.as_bytes());
    let local_pin = crate::meta::definition_artifact::RevisionIdentity {
        family: "local.thing".to_string(),
        version: 1,
        digest: local_digest,
    };
    adopt_definition_as(&db, &admin, "local.thing", Some(&local_pin))
        .await
        .unwrap();

    let out = describe_world_as(&db, &admin).await.unwrap();
    let defs = out["definitions"].as_array().unwrap();
    let pkg_entry = defs
        .iter()
        .find(|e| e["family"] == "demo.notes")
        .expect("package definition present");
    assert_eq!(pkg_entry["package"]["namespace"], "acme");
    assert_eq!(pkg_entry["package"]["name"], "notes");
    assert_eq!(pkg_entry["package"]["version"], 1);
    assert_eq!(pkg_entry["package"]["digest"], id.digest);
    let local_entry = defs
        .iter()
        .find(|e| e["family"] == "local.thing")
        .expect("local definition present");
    assert_eq!(local_entry["package"], serde_json::Value::Null);
    db.close().await;
}
