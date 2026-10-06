//! Gated dependency-safety tests (task e2bfaf5, Increment 2+): canonical
//! B-a/B-b/B-d blockers, shared inheritance, direct-definition bypass,
//! populated replacement, and replay. Authority/oracle/redaction cases live
//! in `dependency_authority_tests` (harness-owned); this module covers the
//! canonical enforcement paths. No production schema or tools touched.

use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_definition_as, adopt_definition_at, adopt_package_at, create_home, create_v2_database,
    install_package_as, read_scoped_adoption_verified,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor, BEHAVIOUR_KIND,
    SURFACE_KIND,
};

const FAMILY: &str = "example.records";
const NS: &str = "acme";
const NAME: &str = "notes";
const DEFINITION_ADOPTED: &str = "kernel.definition_adopted.v1";

async fn admin_db() -> (crate::db::Db, String) {
    create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap()
}

async fn child_home(db: &crate::db::Db, admin: &str) -> String {
    create_home(db, KERNEL_ROOT_ID, None, admin).await.unwrap()
}

fn def_bytes(family: &str, version: u32) -> String {
    format!(r#"{{"family":"{family}","version":{version},"kinds":["note"]}}"#)
}

fn entry_v(family: &str, version: u32) -> DefinitionEntry {
    let bytes = def_bytes(family, version);
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: bytes,
        digest,
    }
}

fn manifest_v(version: u32, entry_version: u32) -> PackageManifest {
    PackageManifest {
        namespace: NS.to_string(),
        name: NAME.to_string(),
        version,
        definitions: vec![entry_v(FAMILY, entry_version)],
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

/// A definitions-only (K5) revision of the same package triple: definitions
/// only, no behaviour, no surface, empty declared reads.
fn definitions_only_manifest_v(version: u32, entry_version: u32) -> PackageManifest {
    PackageManifest {
        namespace: NS.to_string(),
        name: NAME.to_string(),
        version,
        definitions: vec![entry_v(FAMILY, entry_version)],
        behaviour: None,
        surface: None,
        declared_reads: vec![],
    }
}

fn pin_v(entry_version: u32) -> crate::meta::definition_artifact::RevisionIdentity {
    let e = entry_v(FAMILY, entry_version);
    crate::meta::definition_artifact::RevisionIdentity {
        family: FAMILY.to_string(),
        version: e.version,
        digest: e.digest,
    }
}

async fn install(
    db: &crate::db::Db,
    admin: &str,
    m: &PackageManifest,
) -> crate::package_manifest::ManifestIdentity {
    install_package_as(db, admin, m).await.unwrap()
}

async fn adopt(
    db: &crate::db::Db,
    admin: &str,
    scope: &str,
    m: &PackageManifest,
    id: &crate::package_manifest::ManifestIdentity,
) {
    adopt_package_at(db, admin, scope, m, Some(id), &m.declared_reads)
        .await
        .unwrap();
}

/// Exact log plus projection footprint: both event-log counts and the full
/// kernel table dump. Every refusal below must leave all three unchanged,
/// proving exact state rather than mere per-type counts.
async fn snapshot(db: &crate::db::Db) -> (i64, i64, crate::kernel::KernelTableDump) {
    let meta: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let content: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let dump = crate::kernel::dump_all_kernel_tables(db).await.unwrap();
    (meta, content, dump)
}

/// Canonical legacy-override fixture: a real `kernel.definition_adopted.v1`
/// event through the content seam, which folds (append-event-then-project)
/// inside the same tx. This is how genuinely displaced (pre-enforcement)
/// state is represented — a real event with a real projection — rather
/// than raw-SQL tampering or an invalid event. Test-only: production paths
/// always pass preflight.
pub(crate) async fn legacy_override(
    db: &crate::db::Db,
    admin: &str,
    home: &str,
    pin: &crate::meta::definition_artifact::RevisionIdentity,
) {
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    crate::store::append_in(
        db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: home.to_string(),
            event_type: DEFINITION_ADOPTED.to_string(),
            payload: serde_json::json!({
                "family": pin.family,
                "selected": {
                    "family": pin.family,
                    "version": pin.version,
                    "digest": pin.digest,
                },
                "scope_home": home,
            }),
            actor: Some(admin.to_string()),
        },
        &mut alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Half-null tombstone falsifier (B-b): SQLite CHECK does not reliably
/// prevent a mixed (version, digest) pair, and collapsing it to `None`
/// would bless corruption against a tombstone event. Both halves refuse.
#[tokio::test]
async fn half_null_tombstone_row_fails_closed() {
    let (db, admin) = admin_db().await;
    // Full-length halves: the UPDATE itself must pass the DDL CHECK so the
    // read guard (not the constraint) is what refuses.
    let halves = [
        (
            "UPDATE kernel_adoptions SET selected_version = 1 WHERE scope_home = ? AND family = ?",
            "version half",
        ),
        (
            "UPDATE kernel_adoptions SET selected_digest = ? WHERE scope_home = ? AND family = ?",
            "digest half",
        ),
    ];
    for (tamper, label) in halves {
        let home = child_home(&db, &admin).await;
        adopt_definition_at(&db, &admin, FAMILY, None, &home)
            .await
            .unwrap();
        if label == "digest half" {
            sqlx::query(tamper)
                .bind("e".repeat(64))
                .bind(&home)
                .bind(FAMILY)
                .execute(db.write_pool())
                .await
                .unwrap();
        } else {
            sqlx::query(tamper)
                .bind(&home)
                .bind(FAMILY)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let mut conn = db.write_pool().acquire().await.unwrap();
        assert!(
            read_scoped_adoption_verified(&mut conn, &home, FAMILY)
                .await
                .is_err(),
            "half-null row must refuse: {label}"
        );
    }
    db.close().await;
}

/// B-a: a package with adoption events but no projection row fails closed.
/// Deleting the selection row must make disable (and its preview) refuse
/// with zero new events — never read as absent.
#[tokio::test]
async fn missing_package_projection_with_log_refuses() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let id1 = install(&db, &admin, &m1).await;
    adopt(&db, &admin, KERNEL_ROOT_ID, &m1, &id1).await;
    let child = child_home(&db, &admin).await;
    sqlx::query("DELETE FROM kernel_package_selections")
        .execute(db.write_pool())
        .await
        .unwrap();
    // Same-package paths: the target verified read catches the missing row.
    let before = snapshot(&db).await;
    let preview =
        crate::dependency::preview_package_disable(&db, &admin, KERNEL_ROOT_ID, &m1).await;
    assert!(preview.is_err());
    let exec = adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m1, None, &[]).await;
    assert!(exec.is_err());
    assert_eq!(snapshot(&db).await, before);
    // Union-enumeration paths: a direct-definition change at the child names
    // no package at all, so only the projection-UNION-log candidate scan can
    // catch the missing row (zero projection keys, live log subjects on the
    // ancestor chain). Both preview and execute must refuse with exact state.
    let before = snapshot(&db).await;
    let preview =
        crate::dependency::preview_definition_change(&db, &admin, Some(&child), FAMILY, None).await;
    assert!(preview.is_err());
    assert!(adopt_definition_at(&db, &admin, FAMILY, None, &child)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

/// B-b (scoped): a tampered PRIOR scoped pin fails the preflight baseline
/// read with zero consumers watching. Both a replacement adoption and a
/// disable must refuse with zero new events — never overwrite the row.
#[tokio::test]
async fn corrupt_prior_scoped_pin_blocks_with_zero_consumers() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install(&db, &admin, &m1).await;
    install(&db, &admin, &m2).await;
    let home = child_home(&db, &admin).await;
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE kernel_adoptions SET selected_digest = ? WHERE scope_home = ? AND family = ?",
    )
    .bind("f".repeat(64))
    .bind(&home)
    .bind(FAMILY)
    .execute(db.write_pool())
    .await
    .unwrap();
    let before = snapshot(&db).await;
    let p2 = pin_v(2);
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .is_err());
    assert!(adopt_definition_at(&db, &admin, FAMILY, None, &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

/// B-b (global): a missing workspace-wide projection with surviving log
/// events refuses a global mutation — even when a root scoped override
/// exists, which the effective resolver would otherwise return first. The
/// explicit global read must not be skipped.
#[tokio::test]
async fn missing_global_projection_with_log_refuses_despite_root_override() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    install(&db, &admin, &m1).await;
    let p1 = pin_v(1);
    adopt_definition_as(&db, &admin, FAMILY, Some(&p1))
        .await
        .unwrap();
    // Root scoped override via a root package adoption (scoped rows at root).
    let id1 = install(&db, &admin, &m1).await;
    adopt(&db, &admin, KERNEL_ROOT_ID, &m1, &id1).await;
    sqlx::query("DELETE FROM definition_adoptions")
        .execute(db.write_pool())
        .await
        .unwrap();
    // P2 must be installed for the write path to reach preflight; install
    // it through a second package revision without adopting it.
    let m2 = manifest_v(2, 2);
    install(&db, &admin, &m2).await;
    let before = snapshot(&db).await;
    let p2 = pin_v(2);
    assert!(adopt_definition_as(&db, &admin, FAMILY, Some(&p2))
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

/// B-d (refuse): root replaces A v1 with v2 while a child scoped override
/// still pins the family to v1. The child's newly-effective v2 surface
/// requirement is unsatisfied-after against a satisfied-before counterpart,
/// so the replacement refuses with zero new events.
#[tokio::test]
async fn child_override_makes_replacement_refuse() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install(&db, &admin, &m1).await;
    let id2 = install(&db, &admin, &m2).await;
    let id1 = install(&db, &admin, &m1).await;
    adopt(&db, &admin, KERNEL_ROOT_ID, &m1, &id1).await;
    let child = child_home(&db, &admin).await;
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &child)
        .await
        .unwrap();
    let before = snapshot(&db).await;
    let preview = crate::dependency::preview_package_adopt(&db, &admin, KERNEL_ROOT_ID, &m2).await;
    let impact = preview.expect("preview itself must succeed");
    assert!(
        !impact.broken.is_empty(),
        "expected a broken newly-effective child requirement"
    );
    assert!(adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &m2,
        Some(&id2),
        &m2.declared_reads
    )
    .await
    .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

/// B-d (legacy allow): the child's override pins a revision the package
/// never satisfied (legacy displacement). Replacing the root package still
/// succeeds; the preview reports the stale requirement explicitly instead
/// of freezing the change.
#[tokio::test]
async fn legacy_displaced_child_does_not_freeze_replacement() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install(&db, &admin, &m1).await;
    let id2 = install(&db, &admin, &m2).await;
    let id1 = install(&db, &admin, &m1).await;
    adopt(&db, &admin, KERNEL_ROOT_ID, &m1, &id1).await;
    let child = child_home(&db, &admin).await;
    // Override to an unrelated installed revision through the canonical
    // event seam (the enforcing API would refuse this displacement, so the
    // legacy state it represents is built as a real event, not a call).
    let m9 = manifest_v(9, 9);
    install(&db, &admin, &m9).await;
    let p9 = pin_v(9);
    legacy_override(&db, &admin, &child, &p9).await;
    let impact = crate::dependency::preview_package_adopt(&db, &admin, KERNEL_ROOT_ID, &m2)
        .await
        .expect("preview itself must succeed");
    assert!(impact.broken.is_empty());
    assert!(
        !impact.already_unsatisfied.is_empty(),
        "expected the legacy requirement reported explicitly"
    );
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &m2,
        Some(&id2),
        &m2.declared_reads,
    )
    .await
    .expect("legacy displacement must not freeze the replacement");
    db.close().await;
}

/// K6a review amendment: the derived `package-surface` consumer derives
/// nothing for a definitions-only package, and a surface requirement dropped
/// by a replacement cannot linger as a stale pin that blocks.
#[tokio::test]
async fn definitions_only_package_derives_no_surface_requirement() {
    let (db, admin) = admin_db().await;
    let surface_v1 = manifest_v(1, 1);
    let defs_v2 = definitions_only_manifest_v(2, 2);
    let id1 = install(&db, &admin, &surface_v1).await;
    let id2 = install(&db, &admin, &defs_v2).await;
    let home = child_home(&db, &admin).await;
    adopt(&db, &admin, &home, &surface_v1, &id1).await;

    // While the surface revision is selected, the derived package-surface
    // requirement still blocks a definition move: surface packages remain
    // protected exactly as before.
    let impact =
        crate::dependency::preview_definition_change(&db, &admin, Some(&home), FAMILY, None)
            .await
            .unwrap();
    assert!(impact.refuses());
    assert!(impact
        .broken
        .iter()
        .any(|e| e.consumer_kind == "package-surface"));

    // Replace it with the definitions-only revision: the removed surface
    // requirement is recomputed from the live manifest and cannot linger.
    crate::kernel::adopt_package_at(&db, &admin, &home, &defs_v2, Some(&id2), &[])
        .await
        .expect("definitions-only replacement must not be blocked by a stale surface pin");

    // The definitions-only revision derives nothing, so disabling the family
    // is no longer blocked and no package-surface requirement is reported.
    let impact =
        crate::dependency::preview_definition_change(&db, &admin, Some(&home), FAMILY, None)
            .await
            .unwrap();
    assert!(!impact.refuses(), "{impact:?}");
    assert!(impact
        .broken
        .iter()
        .all(|e| e.consumer_kind != "package-surface"));

    // Disabling the definitions-only package is likewise unblocked by any
    // surface requirement it does not have.
    let impact = crate::dependency::preview_package_disable(&db, &admin, &home, &defs_v2)
        .await
        .unwrap();
    assert!(!impact.refuses(), "{impact:?}");
    db.close().await;
}
