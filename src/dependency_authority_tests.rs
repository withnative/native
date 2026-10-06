//! Independent authority/privacy tests for the public dependency APIs
//! (task e2bfaf5). Source-only: hidden-scope traversal refusal, global
//! replacement coverage, list redaction, capability/existence gates, and
//! stale-retire preconditions. The canonical tamper, shared-inheritance,
//! direct-bypass, populated-data, and replay cases live with the core
//! writer's generic dependency tests and are not duplicated here.
//!
//! NOTE for integration: register with `#[cfg(test)] mod
//! dependency_authority_tests;` in `src/lib.rs` (owned by the core writer).

use crate::dependency::{
    list_consumers_as, preview_package_adopt, preview_package_disable, register_consumer_at,
    retire_consumer_at, DEPENDENCY_REFUSAL,
};
use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_package_at, create_as, create_home, create_principal, create_v2_database,
    dump_all_kernel_tables, install_package_as, replace_home_policy, KernelTableDump,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor, BEHAVIOUR_KIND,
    SURFACE_KIND,
};

const READ: &str = "linked_record:view";

pub(crate) fn auth_entry(family: &str, version: u32, marker: &str) -> DefinitionEntry {
    let bytes = serde_json::json!({
        "family": family, "version": version,
        "interpreter": "native.defn/2", "primary_type": "authnote",
        "kinds": [{"token": "AuthNote",
            "fields": [{"name": "title", "type": "text", "required": true}],
            "identity": {"field": "title"},
            "links": [{"predicate": "relates_to",
                "target": {"primary_type": "authnote", "kind": "AuthNote"},
                "direction": "either"}],
            "maturity": "current", "description": marker}],
    })
    .to_string();
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: bytes,
        digest,
    }
}

pub(crate) fn auth_manifest(
    namespace: &str,
    name: &str,
    version: u32,
    entries: Vec<DefinitionEntry>,
) -> PackageManifest {
    PackageManifest {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version,
        definitions: entries,
        behaviour: Some(BehaviourDescriptor {
            kind: BEHAVIOUR_KIND.to_string(),
            reads: vec![READ.to_string()],
            effects: vec![],
        }),
        surface: Some(SurfaceDescriptor {
            kind: SURFACE_KIND.to_string(),
            view: "auth.view".to_string(),
            fallback: "auth.unavailable".to_string(),
        }),
        declared_reads: vec![READ.to_string()],
    }
}

pub(crate) async fn admin_db() -> (crate::db::Db, String) {
    create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap()
}

pub(crate) fn title_fields(title: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "title".to_string(),
        serde_json::Value::String(title.to_string()),
    );
    map
}

/// Exact log plus projection footprint: both event logs and the full
/// kernel table dump. Every refusal below must leave all three unchanged,
/// proving exact projection state rather than mere row counts.
pub(crate) async fn snapshot(db: &crate::db::Db) -> (i64, i64, KernelTableDump) {
    let meta: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let content: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let dump = dump_all_kernel_tables(db).await.unwrap();
    (meta, content, dump)
}

#[tokio::test]
async fn hidden_descendant_refuses_preview_and_execute_identically() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let m = auth_manifest(
        "auth",
        "keep",
        1,
        vec![auth_entry("auth.keep", 1, "keep v1")],
    );
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    let target = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &op, &target, &m, Some(&id), &m.declared_reads)
        .await
        .unwrap();
    // Hidden descendant of the caller's Manage scope: op sees nothing there.
    let hidden = create_home(&db, &target, Some(&[(admin.as_str(), "manage")]), &admin)
        .await
        .unwrap();

    // No consumer anywhere hidden: preview and execute refuse uniformly.
    let before = snapshot(&db).await;
    let preview_err = preview_package_disable(&db, &op, &target, &m)
        .await
        .unwrap_err();
    let exec_err = adopt_package_at(&db, &op, &target, &m, None, &[])
        .await
        .unwrap_err();
    assert_eq!(preview_err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(exec_err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before);

    // A live consumer inside the hidden child: byte-identical refusal.
    let entry = &m.definitions[0];
    register_consumer_at(
        &db,
        &admin,
        &hidden,
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
    let after_setup = snapshot(&db).await;
    let preview_err2 = preview_package_disable(&db, &op, &target, &m)
        .await
        .unwrap_err();
    let exec_err2 = adopt_package_at(&db, &op, &target, &m, None, &[])
        .await
        .unwrap_err();
    assert_eq!(preview_err2.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(exec_err2.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(preview_err2.to_string(), preview_err.to_string());
    assert_eq!(exec_err2.to_string(), exec_err.to_string());
    assert_eq!(snapshot(&db).await, after_setup);
    db.close().await;
}

#[tokio::test]
async fn outside_subtree_hidden_home_blocks_replacement_not_data_only_disable() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let v1 = auth_manifest(
        "auth",
        "shift",
        1,
        vec![auth_entry("auth.shift", 1, "shift v1")],
    );
    let v2 = auth_manifest(
        "auth",
        "shift",
        2,
        vec![auth_entry("auth.shift", 2, "shift v2")],
    );
    install_package_as(&db, &admin, &v1).await.unwrap();
    install_package_as(&db, &admin, &v2).await.unwrap();
    let id2 = v2.identity().unwrap();
    let target = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let id1 = v1.identity().unwrap();
    adopt_package_at(&db, &op, &target, &v1, Some(&id1), &v1.declared_reads)
        .await
        .unwrap();
    // Op holds View on the workspace root (admin keeps Manage), so the
    // whole traversal domain is visible before the hidden home exists.
    replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(admin.as_str(), "manage"), (op.as_str(), "view")],
    )
    .await
    .unwrap();
    // Positive control: the candidate replacement previews clean here.
    let control = preview_package_adopt(&db, &op, &target, &v2).await.unwrap();
    assert!(!control.refuses());
    assert!(control.broken.is_empty());
    // Hidden home outside the target subtree: op cannot prove global coverage.
    let outside = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (stranger.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();

    // An exact retry excludes no old pins, so unrelated hidden homes do
    // not impose global data-coverage authority or create an oracle.
    let retry_before = snapshot(&db).await;
    assert!(!preview_package_adopt(&db, &op, &target, &v1)
        .await
        .unwrap()
        .refuses());
    adopt_package_at(&db, &op, &target, &v1, Some(&id1), &v1.declared_reads)
        .await
        .unwrap();
    assert_eq!(snapshot(&db).await, retry_before);

    // Replacement refuses identically with no unseen rows anywhere.
    let before = snapshot(&db).await;
    let preview1 = preview_package_adopt(&db, &op, &target, &v2)
        .await
        .unwrap_err();
    let exec1 = adopt_package_at(&db, &op, &target, &v2, Some(&id2), &v2.declared_reads)
        .await
        .unwrap_err();
    assert_eq!(preview1.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(exec1.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before);

    // Old-pinned rows inside the hidden home: the same refusal, no oracle.
    adopt_package_at(
        &db,
        &stranger,
        &outside,
        &v1,
        Some(&id1),
        &v1.declared_reads,
    )
    .await
    .unwrap();
    create_as(
        &db,
        &stranger,
        "auth.shift",
        "AuthNote",
        &title_fields("Elsewhere"),
        &outside,
    )
    .await
    .unwrap();
    let after_setup = snapshot(&db).await;
    let preview2 = preview_package_adopt(&db, &op, &target, &v2)
        .await
        .unwrap_err();
    let exec2 = adopt_package_at(&db, &op, &target, &v2, Some(&id2), &v2.declared_reads)
        .await
        .unwrap_err();
    assert_eq!(preview2.to_string(), preview1.to_string());
    assert_eq!(exec2.to_string(), exec1.to_string());
    assert_eq!(snapshot(&db).await, after_setup);

    // Ordinary disable with only retained rows still succeeds.
    create_as(
        &db,
        &op,
        "auth.shift",
        "AuthNote",
        &title_fields("Local"),
        &target,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &op, &target, &v1, None, &[])
        .await
        .unwrap();
    db.close().await;
}

#[tokio::test]
async fn list_redacts_actor_without_root_view() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let viewer = create_principal(&db, "account", "Viewer", "test:viewer", &admin)
        .await
        .unwrap();
    let m = auth_manifest(
        "auth",
        "notes",
        1,
        vec![auth_entry("auth.notes", 1, "notes v1")],
    );
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    let scope = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[
            (admin.as_str(), "manage"),
            (op.as_str(), "manage"),
            (viewer.as_str(), "view"),
        ]),
        &admin,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &op, &scope, &m, Some(&id), &m.declared_reads)
        .await
        .unwrap();
    let entry = &m.definitions[0];
    register_consumer_at(
        &db,
        &op,
        &scope,
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

    // Scope-View without root-View: requirement visible, actor redacted,
    // and no principal id leaks anywhere in the disclosed view.
    let as_viewer = list_consumers_as(&db, &viewer, &scope).await.unwrap();
    assert_eq!(as_viewer.len(), 1);
    assert_eq!(as_viewer[0].actor, None);
    let flat = format!("{:?}", as_viewer);
    assert!(
        !flat.contains(op.as_str()) && !flat.contains(admin.as_str()),
        "{flat}"
    );

    // The attributing principal sees its own actor value.
    let as_self = list_consumers_as(&db, &op, &scope).await.unwrap();
    assert_eq!(as_self[0].actor.as_deref(), Some(op.as_str()));
    db.close().await;
}

#[tokio::test]
async fn unchanged_child_package_keeps_redacted_ack_actor_in_preview() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let target = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let child = create_home(
        &db,
        &target,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "view")]),
        &admin,
    )
    .await
    .unwrap();
    let entry = auth_entry("auth.actor", 1, "actor v1");
    let parent_manifest = auth_manifest("auth", "actor", 1, vec![entry.clone()]);
    let child_manifest = auth_manifest("auth", "actor", 2, vec![entry]);
    let parent_pin = install_package_as(&db, &admin, &parent_manifest)
        .await
        .unwrap();
    let child_pin = install_package_as(&db, &admin, &child_manifest)
        .await
        .unwrap();
    adopt_package_at(
        &db,
        &admin,
        &target,
        &parent_manifest,
        Some(&parent_pin),
        &parent_manifest.declared_reads,
    )
    .await
    .unwrap();
    adopt_package_at(
        &db,
        &admin,
        &child,
        &child_manifest,
        Some(&child_pin),
        &child_manifest.declared_reads,
    )
    .await
    .unwrap();
    // A canonical pre-enforcement displacement leaves the child's surface
    // already unsatisfied. Its selection and original acknowledger stay put.
    let legacy = auth_entry("auth.actor", 9, "actor v9");
    let legacy_manifest = auth_manifest("auth", "actor", 9, vec![legacy.clone()]);
    install_package_as(&db, &admin, &legacy_manifest)
        .await
        .unwrap();
    crate::dependency_tests::legacy_override(
        &db,
        &admin,
        &child,
        &crate::meta::definition_artifact::RevisionIdentity {
            family: legacy.family,
            version: legacy.version,
            digest: legacy.digest,
        },
    )
    .await;
    let before = snapshot(&db).await;
    let impact = preview_package_disable(&db, &op, &target, &parent_manifest)
        .await
        .unwrap();
    assert!(!impact.refuses());
    assert!(!impact.already_unsatisfied.is_empty());
    assert!(
        impact
            .already_unsatisfied
            .iter()
            .all(|requirement| { requirement.scope_home == child && requirement.actor.is_none() }),
        "{impact:?}"
    );
    // Root-View sees the real acknowledger, never a package/definition-pin
    // comparison that attributes an unchanged child to the preview caller.
    let disclosed = preview_package_disable(&db, &admin, &target, &parent_manifest)
        .await
        .unwrap();
    assert!(
        disclosed
            .already_unsatisfied
            .iter()
            .all(|requirement| { requirement.actor.as_deref() == Some(admin.as_str()) }),
        "{disclosed:?}"
    );
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn capability_and_existence_gates_are_uniform() {
    let (db, admin) = admin_db().await;
    let editor = create_principal(&db, "account", "Editor", "test:editor", &admin)
        .await
        .unwrap();
    let outsider = create_principal(&db, "account", "Outsider", "test:outsider", &admin)
        .await
        .unwrap();
    let m = auth_manifest(
        "auth",
        "gated",
        1,
        vec![auth_entry("auth.gated", 1, "gated v1")],
    );
    install_package_as(&db, &admin, &m).await.unwrap();
    let scope = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (editor.as_str(), "edit")]),
        &admin,
    )
    .await
    .unwrap();
    let hidden = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let entry = &m.definitions[0];

    // Edit is not Manage for writes; missing, hidden, and ghost-principal
    // inputs all read the same uniform answer; nothing appends.
    let before = snapshot(&db).await;
    let edit_err = register_consumer_at(
        &db,
        &editor,
        &scope,
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        entry.version,
        &entry.digest,
        None,
    )
    .await
    .unwrap_err();
    let missing_err = register_consumer_at(
        &db,
        &admin,
        "no-such-home",
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        entry.version,
        &entry.digest,
        None,
    )
    .await
    .unwrap_err();
    let hidden_err = register_consumer_at(
        &db,
        &outsider,
        &hidden,
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        entry.version,
        &entry.digest,
        None,
    )
    .await
    .unwrap_err();
    let ghost_err = register_consumer_at(
        &db,
        "no-such-principal",
        &scope,
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        entry.version,
        &entry.digest,
        None,
    )
    .await
    .unwrap_err();
    assert!(!edit_err.to_string().is_empty());
    assert_eq!(missing_err.to_string(), hidden_err.to_string());
    assert_eq!(hidden_err.to_string(), ghost_err.to_string());
    assert_eq!(edit_err.to_string(), missing_err.to_string());
    let list_err = list_consumers_as(&db, &outsider, &scope).await.unwrap_err();
    assert_eq!(list_err.to_string(), missing_err.to_string());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn stale_retire_after_reregistration_refuses_and_retains_pin() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let m = auth_manifest(
        "auth",
        "stale",
        1,
        vec![auth_entry("auth.stale", 1, "stale v1")],
    );
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    let scope = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &admin, &scope, &m, Some(&id), &m.declared_reads)
        .await
        .unwrap();
    let entry = &m.definitions[0];
    let first = register_consumer_at(
        &db,
        &admin,
        &scope,
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
    // Deterministic interleaving, no sleep: a second attributor's exact
    // retry moves the event seq while the pin stays put.
    let second = register_consumer_at(
        &db,
        &op,
        &scope,
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        entry.version,
        &entry.digest,
        Some(first.event_seq),
    )
    .await
    .unwrap();
    assert!(second.event_seq > first.event_seq);

    // The stale retire refuses and retains the live pin untouched.
    let before = snapshot(&db).await;
    let stale_err = retire_consumer_at(
        &db,
        &admin,
        &scope,
        "saved-query",
        "auth",
        "watcher",
        &entry.family,
        Some(first.event_seq),
    )
    .await
    .unwrap_err();
    assert!(
        stale_err.to_string().contains("stale consumer retirement"),
        "{stale_err}"
    );
    let live = list_consumers_as(&db, &admin, &scope).await.unwrap();
    assert_eq!(live.len(), 1);
    assert!(live[0].active);
    assert_eq!(live[0].digest, entry.digest);
    assert_eq!(live[0].event_seq, second.event_seq);
    assert_eq!(live[0].actor.as_deref(), Some(op.as_str()));
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}
