//! Disposable falsifying probe for Native task 5ce292f.
//!
//! A genuinely new primary type `Specimen` is installed and adopted through
//! the *generic* internal registry + adoption seams, then a fresh in-process
//! [`ToolRegistry`] client attempts discovery, authoring, and public package
//! install. The test pins the exact closed-spine refusals the current engine
//! produces. `#[cfg(test)]` only: no production seam, no allowlist entry, no
//! `Document` disguise, no frozen-contract change.
//!
//! Working identity criterion (ungoverned by the current parser): a discrete
//! physical sample with an immutable accession code unique within its issuing
//! lab. Candidate kinds: `field-sample`, `lab-aliquot`.

use crate::db::begin_write;
use crate::definition_registry::{install_definition_artifact_in, read_definition_artifact};
use crate::mcp::{Caller, ToolRegistry};
use crate::meta::adoption::append_definition_adoption_in;

const SPECIMEN_FAMILY: &str = "native.specimen";
const SPECIMEN_VERSION: u32 = 1;

fn specimen_artifact_bytes() -> Vec<u8> {
    serde_json::json!({
        "family": SPECIMEN_FAMILY,
        "version": SPECIMEN_VERSION,
        "kinds": [{"token": "field-sample"}, {"token": "lab-aliquot"}],
    })
    .to_string()
    .into_bytes()
}

fn surface_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    registry
}

#[tokio::test]
async fn specimen_installs_generically_but_spine_refuses_authoring() {
    // E2a re-fixture: R's optional-resolution genesis (Resolution absent,
    // nine types) and its `ontology:type-availability` vocabulary do not
    // exist on main, so this runs on the ordinary genesis. The probe's real
    // assertions — generic install/adoption succeed, the closed spine still
    // refuses authoring — are genesis-independent.
    let db = crate::create_database(":memory:").await.unwrap();
    // E2a delta from S: E1 keeps the registry tables out of frozen DDL,
    // so gated tests apply E1 REGISTRY_DDL explicitly.
    crate::definition_registry::ensure_registry_tables(&db)
        .await
        .unwrap();

    // Genesis seeds engine-owned root folders as Collection records.
    let roots: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, type FROM records WHERE id IN ('native:root', 'native:unfiled')",
    )
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(roots.len(), 2, "genesis roots {roots:?}");
    assert!(roots.iter().all(|(_, t)| t == "Collection"), "{roots:?}");

    // Control: capture both refusals BEFORE any install/adoption.
    let registry_before = surface_registry();
    let preview_before = registry_before
        .call(
            db.clone(),
            Caller::local(),
            "preview_record_shape",
            serde_json::json!({"type": "Specimen"}),
        )
        .await
        .unwrap_err()
        .to_string();
    let create_before = registry_before
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            serde_json::json!({
                "type": "Specimen",
                "kind": "field-sample",
                "reason": "Specimen probe control before install.",
            }),
        )
        .await
        .unwrap_err()
        .to_string();

    // Generic internal install + adoption of native.specimen@1 succeed.
    let bytes = specimen_artifact_bytes();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let installed = install_definition_artifact_in(
        &mut tx,
        SPECIMEN_FAMILY,
        SPECIMEN_VERSION,
        &bytes,
        &mut acts,
    )
    .await
    .unwrap();
    assert_eq!(installed.identity.family, SPECIMEN_FAMILY);
    let choice = append_definition_adoption_in(
        &mut tx,
        SPECIMEN_FAMILY,
        Some(&installed.identity),
        &mut acts,
    )
    .await
    .unwrap();
    assert_eq!(
        choice.selected.as_ref().unwrap().digest,
        installed.identity.digest
    );
    tx.commit().await.unwrap();
    let stored = read_definition_artifact(
        &db,
        SPECIMEN_FAMILY,
        SPECIMEN_VERSION,
        &installed.identity.digest,
    )
    .await
    .unwrap()
    .expect("retained specimen bytes");
    assert_eq!(stored.bytes.as_bytes(), bytes.as_slice());

    // No public installer side effects from the internal path.
    let public_side_effects: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vocabularies WHERE name IN ('ontology:package-revision', 'kind:Specimen')",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(public_side_effects, 0);

    // A newly constructed client after install/adoption sees the same refusal.
    let registry_after = surface_registry();
    let preview = registry_after
        .call(
            db.clone(),
            Caller::local(),
            "preview_record_shape",
            serde_json::json!({"type": "Specimen"}),
        )
        .await
        .unwrap_err();
    assert!(
        preview
            .to_string()
            .contains("unknown closed spine type 'Specimen'"),
        "{preview}"
    );
    assert_eq!(
        preview.to_string(),
        preview_before,
        "refusal predates install"
    );
    // Fresh client: authoring refuses the unknown primary type.
    let create = registry_after
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            serde_json::json!({
                "type": "Specimen",
                "kind": "field-sample",
                "reason": "Specimen probe observes the authoring refusal.",
            }),
        )
        .await
        .unwrap_err();
    assert!(
        create
            .to_string()
            .contains("type 'Specimen' is not a spine type"),
        "{create}"
    );
    assert_eq!(
        create.to_string(),
        create_before,
        "refusal predates install"
    );

    // R-only availability promotion dropped (no `ontology_availability`
    // on main): retry on a fresh client still sees the same refusals,
    // because install/adoption never touch the closed spine gate.
    let registry_promoted = surface_registry();
    let preview_retry = registry_promoted
        .call(
            db.clone(),
            Caller::local(),
            "preview_record_shape",
            serde_json::json!({"type": "Specimen"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        preview_retry, preview_before,
        "admission cannot cross spine"
    );
    let create_retry = registry_promoted
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            serde_json::json!({
                "type": "Specimen",
                "kind": "field-sample",
                "reason": "Specimen probe retry after availability promote.",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(create_retry, create_before, "admission cannot cross spine");

    // Positive control: an admitted spine type still authors fine.
    registry_promoted
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            serde_json::json!({
                "type": "Outcome",
                "kind": "target",
                "reason": "Positive control: admitted types author.",
            }),
        )
        .await
        .unwrap();

    // Nothing was stored under the new primary type.
    let specimens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type = 'Specimen'")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(specimens, 0);
    db.close().await;
}
