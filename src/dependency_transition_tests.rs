//! Package/definition transition tests for task e2bfaf5 (source-only).
//! Owns five cases the core writer's canonical suite does not cover:
//! empty upgrade with replay equivalence, visible outside-subtree retained
//! rows (changed pin plus dropped family), child-package blocks on direct
//! definition seams plus a global-pin consumer block, shared-pin survival
//! across a single-package disable, and root scoped/global normalization.
//! Reuses the authority-test fixtures; arbitrary legacy forgery stays with
//! the core suite.
//!
//! NOTE for integration: register with `#[cfg(test)] mod
//! dependency_transition_tests;` in `src/lib.rs` (owned by the core writer).

use crate::dependency::{
    preview_definition_change, preview_package_adopt, register_consumer_at, DEPENDENCY_REFUSAL,
};
use crate::dependency_authority_tests::{
    admin_db, auth_entry, auth_manifest, snapshot, title_fields,
};
use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_definition_as, adopt_definition_at, adopt_package_at, create_as, create_home,
    install_definition_as, install_package_as, replay_all_projections, resolve_effective_adoption,
    ScopedAdoption,
};
use crate::meta::definition_artifact::RevisionIdentity;

async fn effective_pin(db: &crate::db::Db, family: &str, home: &str) -> Option<ScopedAdoption> {
    let mut conn = db.write_pool().acquire().await.unwrap();
    resolve_effective_adoption(&mut conn, family, home)
        .await
        .unwrap()
}

async fn record_pin(db: &crate::db::Db, id: &str) -> (String, i64, String) {
    sqlx::query_as("SELECT pin_family, pin_version, pin_digest FROM kernel_records WHERE id = ?")
        .bind(id)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

async fn global_choice(
    db: &crate::db::Db,
    family: &str,
) -> Option<crate::meta::adoption::AdoptionChoice> {
    let mut conn = db.write_pool().acquire().await.unwrap();
    crate::meta::adoption::read_definition_adoption_on(&mut conn, family)
        .await
        .unwrap()
}

#[tokio::test]
async fn empty_package_upgrade_keeps_definitions_and_replays_exact() {
    let (db, admin) = admin_db().await;
    let v1 = auth_manifest("auth", "up", 1, vec![auth_entry("auth.up", 1, "up v1")]);
    let v2 = auth_manifest("auth", "up", 2, vec![auth_entry("auth.up", 2, "up v2")]);
    let id1 = install_package_as(&db, &admin, &v1).await.unwrap();
    let id2 = install_package_as(&db, &admin, &v2).await.unwrap();
    let target = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &admin, &target, &v1, Some(&id1), &v1.declared_reads)
        .await
        .unwrap();
    // Empty upgrade succeeds: the selected pin moves to 2 ...
    adopt_package_at(&db, &admin, &target, &v2, Some(&id2), &v2.declared_reads)
        .await
        .unwrap();
    let d2 = v2.definitions[0].digest.clone();
    assert!(matches!(
        effective_pin(&db, "auth.up", &target).await,
        Some(ScopedAdoption::Adopted(pin)) if pin.version == 2 && pin.digest == d2
    ));
    // ... and both definition revisions stay installed.
    let (_, _, dump) = snapshot(&db).await;
    let flat = format!("{:?}", dump.artifacts);
    assert!(flat.contains(&v1.definitions[0].digest), "{flat}");
    assert!(flat.contains(&d2), "{flat}");

    // A consumer on pin 2 plus a full replay reproduces both logs and dump.
    let entry = &v2.definitions[0];
    register_consumer_at(
        &db,
        &admin,
        &target,
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        entry.version,
        &entry.digest,
        None,
    )
    .await
    .unwrap();
    let before = snapshot(&db).await;
    replay_all_projections(&db).await.unwrap();
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn visible_outside_rows_block_replacement_with_retained_data() {
    let (db, admin) = admin_db().await;
    // Admin owns and Views every home here, so refusal proves row coverage.
    let target = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let outside = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let v1 = auth_manifest("auth", "cov", 1, vec![auth_entry("auth.cov", 1, "cov v1")]);
    let id1 = install_package_as(&db, &admin, &v1).await.unwrap();
    adopt_package_at(&db, &admin, &target, &v1, Some(&id1), &v1.declared_reads)
        .await
        .unwrap();
    adopt_package_at(&db, &admin, &outside, &v1, Some(&id1), &v1.declared_reads)
        .await
        .unwrap();
    // OLD-pinned populated row in the visible home outside the target subtree.
    let row = create_as(
        &db,
        &admin,
        "auth.cov",
        "AuthNote",
        &title_fields("Elsewhere"),
        &outside,
    )
    .await
    .unwrap();
    assert_eq!(record_pin(&db, &row).await.1, 1);

    // Changed pin: preview names retained-data breakage, execute refuses.
    let v2 = auth_manifest("auth", "cov", 2, vec![auth_entry("auth.cov", 2, "cov v2")]);
    let id2 = install_package_as(&db, &admin, &v2).await.unwrap();
    let pre_preview = snapshot(&db).await;
    let impact = preview_package_adopt(&db, &admin, &target, &v2)
        .await
        .unwrap();
    assert_eq!(impact.broken.len(), 1);
    assert_eq!(impact.broken[0].consumer_kind, "retained-data");
    assert_eq!(snapshot(&db).await, pre_preview);
    let before = snapshot(&db).await;
    let err = adopt_package_at(&db, &admin, &target, &v2, Some(&id2), &v2.declared_reads)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before);

    // Dropped family in a fresh fixture refuses the same stranded rows.
    let v3 = auth_manifest(
        "auth",
        "cov",
        3,
        vec![auth_entry("auth.other", 1, "other v1")],
    );
    let id3 = install_package_as(&db, &admin, &v3).await.unwrap();
    let before3 = snapshot(&db).await;
    let impact3 = preview_package_adopt(&db, &admin, &target, &v3)
        .await
        .unwrap();
    assert_eq!(impact3.broken.len(), 1);
    assert_eq!(impact3.broken[0].consumer_kind, "retained-data");
    assert_eq!(snapshot(&db).await, before3);
    let err3 = adopt_package_at(&db, &admin, &target, &v3, Some(&id3), &v3.declared_reads)
        .await
        .unwrap_err();
    assert_eq!(err3.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before3);
    db.close().await;
}

#[tokio::test]
async fn child_package_blocks_direct_definition_seams() {
    let (db, admin) = admin_db().await;
    let child = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let m = auth_manifest("auth", "dir", 1, vec![auth_entry("auth.dir", 1, "dir v1")]);
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    adopt_package_at(&db, &admin, &child, &m, Some(&id), &m.declared_reads)
        .await
        .unwrap();
    // The incompatible pin is installed, so refusal proves impact, not absence.
    let e2 = auth_entry("auth.dir", 2, "dir v2");
    install_definition_as(
        &db,
        &admin,
        &e2.family,
        e2.version,
        e2.artifact_bytes.as_bytes(),
    )
    .await
    .unwrap();
    let pin2 = RevisionIdentity {
        family: e2.family.clone(),
        version: e2.version,
        digest: e2.digest.clone(),
    };
    let before = snapshot(&db).await;
    let adopt_err = adopt_definition_at(&db, &admin, "auth.dir", Some(&pin2), &child)
        .await
        .unwrap_err();
    assert_eq!(adopt_err.to_string(), DEPENDENCY_REFUSAL);
    let disable_err = adopt_definition_at(&db, &admin, "auth.dir", None, &child)
        .await
        .unwrap_err();
    assert_eq!(disable_err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before);

    // A generic root consumer against the GLOBAL pin blocks the global seam
    // with no root-scoped package anywhere near the family.
    let g1 = auth_entry("auth.glob", 1, "glob v1");
    let g2 = auth_entry("auth.glob", 2, "glob v2");
    for e in [&g1, &g2] {
        install_definition_as(
            &db,
            &admin,
            &e.family,
            e.version,
            e.artifact_bytes.as_bytes(),
        )
        .await
        .unwrap();
    }
    let global1 = RevisionIdentity {
        family: g1.family.clone(),
        version: g1.version,
        digest: g1.digest.clone(),
    };
    adopt_definition_as(&db, &admin, "auth.glob", Some(&global1))
        .await
        .unwrap();
    register_consumer_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "saved-query",
        "auth",
        "watcher",
        &g1.family,
        g1.version,
        &g1.digest,
        None,
    )
    .await
    .unwrap();
    let before_global = snapshot(&db).await;
    let pin2g = RevisionIdentity {
        family: g2.family.clone(),
        version: g2.version,
        digest: g2.digest.clone(),
    };
    let global_err = adopt_definition_as(&db, &admin, "auth.glob", Some(&pin2g))
        .await
        .unwrap_err();
    assert_eq!(global_err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before_global);
    db.close().await;
}

#[tokio::test]
async fn shared_pin_survives_single_package_disable_at_child() {
    let (db, admin) = admin_db().await;
    // Two packages over the SAME definition pin.
    let entry = auth_entry("auth.shared", 1, "shared v1");
    let ma = auth_manifest("auth", "a", 1, vec![entry.clone()]);
    let mb = auth_manifest("auth", "b", 1, vec![entry.clone()]);
    let ida = install_package_as(&db, &admin, &ma).await.unwrap();
    let idb = install_package_as(&db, &admin, &mb).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &ma,
        Some(&ida),
        &ma.declared_reads,
    )
    .await
    .unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &mb,
        Some(&idb),
        &mb.declared_reads,
    )
    .await
    .unwrap();
    let child = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();

    // Disabling A at the child succeeds: B still covers the family pin.
    adopt_package_at(&db, &admin, &child, &ma, None, &[])
        .await
        .unwrap();
    // No family tombstone: the effective pin is still the shared revision.
    assert!(matches!(
        effective_pin(&db, "auth.shared", &child).await,
        Some(ScopedAdoption::Adopted(pin)) if pin.version == 1 && pin.digest == entry.digest
    ));
    // A fresh child record still pins revision 1 ...
    let row = create_as(
        &db,
        &admin,
        "auth.shared",
        "AuthNote",
        &title_fields("Kept"),
        &child,
    )
    .await
    .unwrap();
    assert_eq!(
        record_pin(&db, &row).await,
        ("auth.shared".to_string(), 1, entry.digest.clone())
    );
    // ... and the root A selection is unaffected.
    let sel: (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT selected_version, selected_digest FROM kernel_package_selections
          WHERE scope_home = ? AND namespace = ? AND name = ?",
    )
    .bind(KERNEL_ROOT_ID)
    .bind("auth")
    .bind("a")
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(sel, (Some(1), Some(ida.digest.clone())));
    db.close().await;
}

#[tokio::test]
async fn root_scope_preview_normalizes_global_disable() {
    let (db, admin) = admin_db().await;
    let e1 = auth_entry("auth.rn", 1, "rn v1");
    let m = auth_manifest("auth", "rnpack", 1, vec![e1.clone()]);
    install_definition_as(
        &db,
        &admin,
        &e1.family,
        e1.version,
        e1.artifact_bytes.as_bytes(),
    )
    .await
    .unwrap();
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    // Global fallback pin plus the root-scoped package over the same revision.
    let global = RevisionIdentity {
        family: e1.family.clone(),
        version: e1.version,
        digest: e1.digest.clone(),
    };
    adopt_definition_as(&db, &admin, "auth.rn", Some(&global))
        .await
        .unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &m,
        Some(&id),
        &m.declared_reads,
    )
    .await
    .unwrap();

    // The scoped root change previews clean ...
    let impact = preview_definition_change(&db, &admin, Some(KERNEL_ROOT_ID), "auth.rn", None)
        .await
        .unwrap();
    assert!(!impact.refuses());
    // ... then the root-normalized disable clears the GLOBAL fallback while
    // the SCOPED package pin survives.
    adopt_definition_at(&db, &admin, "auth.rn", None, KERNEL_ROOT_ID)
        .await
        .unwrap();
    // Stored global choice is now the disable tombstone ...
    let stored = global_choice(&db, "auth.rn").await;
    assert!(stored.is_some_and(|c| c.selected.is_none()));
    // ... while the effective scoped pin is still revision 1.
    assert!(matches!(
        effective_pin(&db, "auth.rn", KERNEL_ROOT_ID).await,
        Some(ScopedAdoption::Adopted(pin)) if pin.version == 1 && pin.digest == e1.digest
    ));
    let row = create_as(
        &db,
        &admin,
        "auth.rn",
        "AuthNote",
        &title_fields("StillOne"),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    assert_eq!(
        record_pin(&db, &row).await,
        ("auth.rn".to_string(), 1, e1.digest.clone())
    );
    db.close().await;
}
