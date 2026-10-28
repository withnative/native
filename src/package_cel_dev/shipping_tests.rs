//! Exercise real feature-off code. Fixture seeding uses private storage/log
//! seams to represent an already retained development package, never a
//! cfg(test) switch that enables a live runtime.
use super::*;
use crate::events::KERNEL_ROOT_ID;
use crate::kernel as k;
use crate::package_manifest::PackageManifest;
use crate::package_operations::{call_package_operation_as, describe_package_operations_as};
use serde_json::json;

fn package() -> PackageManifest {
    let value = serde_json::from_str(include_str!(
        "../../examples/packages/cel-scalar-dev/quote.package.json"
    ))
    .unwrap();
    PackageManifest::from_canonical_value(&value).unwrap()
}

#[tokio::test]
async fn shipping_build_refuses_runtime_but_reads_and_replays_retained_package_data() {
    const { assert!(!cfg!(feature = "package-cel-dev")) };
    #[cfg(feature = "v2-kernel-probe")]
    {
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        assert!(registry.get("describe_package_operations").is_none());
        assert!(registry.get("call_package_operation").is_none());
    }
    let manifest = package();
    let identity = manifest.identity().unwrap();
    let canonical = manifest.canonical_value().unwrap();
    assert_eq!(
        PackageManifest::from_canonical_value(&canonical).unwrap(),
        manifest
    );
    assert!(!manifest.operations[0].available_in_build());
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let refused = k::install_package_as(&db, &admin, &manifest)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("package-cel-dev"), "{refused}");
    assert!(admit(&manifest).await.is_err());
    assert!(run(
        manifest.operations[0].executable.clone().unwrap(),
        "{}".into()
    )
    .await
    .is_err());

    // Historical fixture: immutable bytes and attributed events are valid even
    // when this binary cannot run their provider. No public admission bypass.
    let mut tx = db.write_pool().begin().await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    crate::meta::package::install_package_in(&mut tx, &manifest, Some(&admin), &mut acts)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let definition = &manifest.definitions[0];
    let pin = crate::meta::definition_artifact::RevisionIdentity {
        family: definition.family.clone(),
        version: definition.version,
        digest: definition.digest.clone(),
    };
    k::adopt_definition_as(&db, &admin, &definition.family, Some(&pin))
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    crate::store::append_in(
        &db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: k::KERNEL_PACKAGE_ADOPTED_EVENT.into(),
            payload: json!({
                "scope_home":KERNEL_ROOT_ID,"namespace":manifest.namespace,"name":manifest.name,
                "selected":{"version":identity.version,"digest":identity.digest},
                "acknowledged_reads":manifest.declared_reads,
            }),
            actor: Some(admin.clone()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let id = k::create_as(
        &db,
        &admin,
        &definition.family,
        "quote",
        json!({"inputs_json":"{\"subtotal\":1000,\"discount_pct\":10}"})
            .as_object()
            .unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let before = k::read_record_as(&db, &admin, &id).await.unwrap().unwrap();
    let history = k::history_as(&db, &admin, &id).await.unwrap();
    assert!(!history.is_empty());
    let selection = k::adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &manifest,
        Some(&identity),
        &manifest.declared_reads,
    )
    .await
    .unwrap_err();
    assert!(
        selection.to_string().contains("package-cel-dev"),
        "{selection}"
    );
    let refused = call_package_operation_as(
        &db,
        &admin,
        &manifest.namespace,
        &manifest.name,
        "compute",
        &id,
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("package-cel-dev"), "{refused}");
    assert!(describe_package_operations_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &manifest.namespace,
        &manifest.name
    )
    .await
    .is_err());
    let world = k::describe_world_as(&db, &admin).await.unwrap();
    assert!(world.get("package_operations").is_none());
    assert!(!world["definitions"].as_array().unwrap().is_empty());

    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        k::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .fields,
        before.fields
    );
    assert_eq!(
        k::history_as(&db, &admin, &id).await.unwrap().len(),
        history.len()
    );
    let mut read = db.pool().begin().await.unwrap();
    let stored = crate::meta::package::read_package_in(
        &mut read,
        &manifest.namespace,
        &manifest.name,
        identity.version,
        &identity.digest,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stored.manifest.canonical_value().unwrap(), canonical);
    read.rollback().await.unwrap();
    // A shipping build can disable retained development metadata without
    // needing an evaluator, and ordinary data/history remain readable.
    k::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, None, &[])
        .await
        .unwrap();
    assert!(k::read_record_as(&db, &admin, &id).await.unwrap().is_some());
    assert_eq!(
        k::history_as(&db, &admin, &id).await.unwrap().len(),
        history.len()
    );
    db.close().await;
}
