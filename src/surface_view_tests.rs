//! Gated S4 surface-model tests: one unchanged host render path serves two
//! distinct manifests, disable/fallback semantics, bounded rows, and replay
//! retention. No markup, scripts, frames, effects, or v1 changes.

use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_package_at, create_v2_database, install_package_as, render_package_surface_as,
    SurfaceViewModel, SURFACE_FALLBACK_VIEW,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor, BEHAVIOUR_KIND,
    SURFACE_KIND,
};

const READ: &str = "linked_record:view";
const FAMILY: &str = "demo.shared";
const KIND: &str = "note";

fn shared_entry() -> DefinitionEntry {
    let bytes = serde_json::json!({
        "family": FAMILY, "version": 1,
        "interpreter": "native.defn/2", "primary_type": "note",
        "kinds": [{"token": KIND,
            "fields": [{"name": "title", "type": "text", "required": true}],
            "identity": {"field": "title"},
            "links": [{"predicate": "relates_to",
                "target": {"primary_type": "note", "kind": "note"},
                "direction": "either"}],
            "maturity": "current", "description": "Shared note."}],
    })
    .to_string();
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: FAMILY.to_string(),
        version: 1,
        artifact_bytes: bytes,
        digest,
    }
}

fn manifest(name: &str, view: &str, fallback: &str) -> PackageManifest {
    PackageManifest {
        namespace: "acme".to_string(),
        name: name.to_string(),
        version: 1,
        definitions: vec![shared_entry()],
        behaviour: Some(BehaviourDescriptor {
            kind: BEHAVIOUR_KIND.to_string(),
            reads: vec![READ.to_string()],
            effects: vec![],
        }),
        surface: Some(SurfaceDescriptor {
            kind: SURFACE_KIND.to_string(),
            view: view.to_string(),
            fallback: fallback.to_string(),
        }),
        declared_reads: vec![READ.to_string()],
    }
}

fn fields(title: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "title".to_string(),
        serde_json::Value::String(title.to_string()),
    );
    map
}

fn linked_to(target: &str) -> Option<(&str, &str, &str)> {
    Some(("relates_to", target, "out"))
}

async fn render(
    db: &crate::db::Db,
    viewer: &str,
    name: &str,
    target: &str,
    limit: usize,
) -> SurfaceViewModel {
    render_package_surface_as(
        db,
        viewer,
        KERNEL_ROOT_ID,
        "acme",
        name,
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(target),
        limit,
        None,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn two_manifests_one_host_fn_shared_pin_disable_keeps_b_live() {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let b = manifest("bbb", "notes.b", "pack.bgone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    let idb = install_package_as(&db, &admin, &b).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &b,
        Some(&idb),
        &b.declared_reads,
    )
    .await
    .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    let s1 = crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("S1"), KERNEL_ROOT_ID)
        .await
        .unwrap();
    crate::kernel::link_records_as(&db, &admin, &s1, &target)
        .await
        .unwrap();
    match render(&db, &admin, "aaa", &target, 10).await {
        SurfaceViewModel::List {
            title,
            rows,
            receipt,
            introspection,
            ..
        } => {
            assert_eq!(title, "notes.a");
            assert_eq!(rows.len(), 1);
            assert_eq!(introspection.digest, ida.digest);
            assert_eq!(introspection.definition_pins.len(), 1);
            assert_eq!(introspection.declared_reads, vec![READ.to_string()]);
            // The full freshness receipt rides the model for stale-paint
            // fencing: pin plus ack seq, never a snapshot claim.
            assert_eq!(receipt.package_digest, ida.digest);
            assert_eq!(receipt.ack_event_seq, introspection.ack_event_seq);
            assert!(receipt.served_content_seq >= receipt.ack_event_seq);
        }
        SurfaceViewModel::Notice { notice } => panic!("expected list, got {notice}"),
    }
    match render(&db, &admin, "bbb", &target, 10).await {
        SurfaceViewModel::List { title, rows, .. } => {
            assert_eq!(title, "notes.b");
            assert_eq!(rows.len(), 1);
        }
        SurfaceViewModel::Notice { notice } => panic!("expected list, got {notice}"),
    }
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &a, None, &[])
        .await
        .unwrap();
    assert_eq!(
        render(&db, &admin, "aaa", &target, 10).await,
        SurfaceViewModel::Notice {
            notice: "pack.agone".to_string()
        }
    );
    match render(&db, &admin, "bbb", &target, 10).await {
        SurfaceViewModel::List { rows, .. } => assert_eq!(rows.len(), 1),
        SurfaceViewModel::Notice { notice } => panic!("B must stay live, got {notice}"),
    }
    db.close().await;
}

#[tokio::test]
async fn fallback_missing_package_answers_generic() {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    // Missing package: generic fallback.
    assert_eq!(
        render(&db, &admin, "ghost", &target, 10).await,
        SurfaceViewModel::Notice {
            notice: SURFACE_FALLBACK_VIEW.to_string()
        }
    );
    db.close().await;
}

#[tokio::test]
async fn render_refuses_displaced_pins_with_named_notice() {
    // Deterministic displacement path: adopting a second package moves the
    // shared family's effective pin, so the first package's render must hit
    // the activation gate (not stale pins) and name its own fallback.
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    let mut b = manifest("bbb", "notes.b", "pack.bgone");
    b.definitions = vec![{
        let bytes = serde_json::json!({
            "family": FAMILY, "version": 2,
            "interpreter": "native.defn/2", "primary_type": "note",
            "kinds": [{"token": KIND,
                "fields": [{"name": "title", "type": "text", "required": true}],
                "identity": {"field": "title"},
                "links": [{"predicate": "relates_to",
                    "target": {"primary_type": "note", "kind": "note"},
                    "direction": "either"}],
                "maturity": "current", "description": "V2 note."}],
        })
        .to_string();
        let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
        crate::package_manifest::DefinitionEntry {
            family: FAMILY.to_string(),
            version: 2,
            artifact_bytes: bytes,
            digest,
        }
    }];
    let idb = install_package_as(&db, &admin, &b).await.unwrap();
    // Preserve named-notice handling of canonical legacy displacement;
    // modern adoption refuses to break A's previously satisfied pin.
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
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &b,
        Some(&idb),
        &b.declared_reads,
    )
    .await
    .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    assert_eq!(
        render(&db, &admin, "aaa", &target, 10).await,
        SurfaceViewModel::Notice {
            notice: "pack.agone".to_string()
        }
    );
    db.close().await;
}

#[tokio::test]
async fn poisoned_parent_cycle_answers_generic() {
    // Poisoned kernel_roots parent chain (A→B→A): every ancestor walk caps
    // at MAX_HOME_DEPTH, so the render terminates on the generic notice.
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    // home_a carries its own policy (capability anchors immediately, no
    // walk), so the poisoned cycle below exercises the fallback ancestor
    // walk's own depth cap rather than the capability evaluator's.
    let home_a = crate::kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let home_b = crate::kernel::create_home(&db, &home_a, None, &admin)
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_roots SET parent_id = ? WHERE root_id = ?")
        .bind(&home_b)
        .bind(&home_a)
        .execute(db.write_pool())
        .await
        .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    let out = render_package_surface_as(
        &db,
        &admin,
        &home_a,
        "acme",
        "aaa",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceViewModel::Notice {
            notice: SURFACE_FALLBACK_VIEW.to_string()
        }
    );
    db.close().await;
}

#[tokio::test]
async fn renders_inherited_root_selection_in_child() {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    let child = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    let src = crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Src"), KERNEL_ROOT_ID)
        .await
        .unwrap();
    crate::kernel::link_records_as(&db, &admin, &src, &target)
        .await
        .unwrap();
    let model = render_package_surface_as(
        &db,
        &admin,
        &child,
        "acme",
        "aaa",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    match model {
        SurfaceViewModel::List {
            title,
            rows,
            introspection,
            ..
        } => {
            assert_eq!(title, "notes.a");
            assert_eq!(rows.len(), 1);
            assert_eq!(introspection.digest, ida.digest);
        }
        SurfaceViewModel::Notice { notice } => panic!("expected inherited list, got {notice}"),
    }
    db.close().await;
}

#[tokio::test]
async fn list_rows_bounded_by_limit() {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    for title in ["R1", "R2", "R3"] {
        let id =
            crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields(title), KERNEL_ROOT_ID)
                .await
                .unwrap();
        crate::kernel::link_records_as(&db, &admin, &id, &target)
            .await
            .unwrap();
    }
    match render(&db, &admin, "aaa", &target, 2).await {
        SurfaceViewModel::List { rows, cursor, .. } => {
            assert_eq!(rows.len(), 2);
            assert!(cursor.is_some());
        }
        SurfaceViewModel::Notice { notice } => panic!("expected list, got {notice}"),
    }
    db.close().await;
}

#[tokio::test]
async fn replay_retains_rendered_model() {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let a = manifest("aaa", "notes.a", "pack.agone");
    let ida = install_package_as(&db, &admin, &a).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &a,
        Some(&ida),
        &a.declared_reads,
    )
    .await
    .unwrap();
    let target =
        crate::kernel::create_as(&db, &admin, FAMILY, KIND, &fields("Target"), KERNEL_ROOT_ID)
            .await
            .unwrap();
    let before_model = render(&db, &admin, "aaa", &target, 10).await;
    let before_dump = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    crate::kernel::replay_all_projections(&db).await.unwrap();
    let after_dump = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before_dump, after_dump);
    let after_model = render(&db, &admin, "aaa", &target, 10).await;
    assert_eq!(before_model, after_model);
    db.close().await;
}
