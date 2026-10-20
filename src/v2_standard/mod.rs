//! The `native.standard` definitions-only packages (PR3).
//!
//! Gated like the rest of the v2 kernel probe surface. Two packages ship the
//! first default record types as ordinary checked-in definition bytes:
//! `native.standard/document@2` (`Document:note`) and
//! `native.standard/outcome@1` (`Outcome:impact`). Both are definitions-only
//! (K5): no behaviour, no surface, no declared reads.
//!
//! The bytes live in exact, checked-in files beside this module: whitespace
//! counts toward each definition digest, and the package digest is the JCS
//! digest of the built manifest. Nothing here touches the default build.

pub(crate) mod claims_retained;
pub mod claims_v1;
pub mod foci;
pub mod foci_consumer;
pub mod foci_consumer_fixtures;
pub mod foci_wire;
pub mod relates_to;
pub(crate) mod relates_to_retained;
pub mod relates_to_v1;
pub mod v1_compat;
// Preserve the frozen version, including its superseded discovery helpers.
#[allow(dead_code)]
pub(crate) mod relates_to_v2;
pub(crate) mod relates_to_v3;

use crate::package_manifest::{DefinitionEntry, PackageManifest};

/// Namespace shared by both first standard packages.
pub const STANDARD_NAMESPACE: &str = "native.standard";
/// Family of the Document definition.
pub const DOCUMENT_FAMILY: &str = "native.standard.document";
/// Family of the Outcome definition.
pub const OUTCOME_FAMILY: &str = "native.standard.outcome";

/// Exact `Document:note` definition bytes (whitespace significant).
pub const DOCUMENT_DEFINITION: &str = include_str!("document.defn.json");
/// Exact `Outcome:impact` definition bytes (whitespace significant).
pub const OUTCOME_DEFINITION: &str = include_str!("outcome.defn.json");

fn definition_entry(family: &str, version: u32, artifact_bytes: &str) -> DefinitionEntry {
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: artifact_bytes.to_string(),
        digest: crate::meta::definition_artifact::digest_artifact_bytes(artifact_bytes.as_bytes()),
    }
}

/// The `native.standard/document@2` definitions-only package.
///
/// Version 2 loosens the note per D7 (task 9d70658): `title` is optional so
/// every v1 note fits directly, with no invented titles. `relates_to` still
/// declares only note→note: `native.defn/3` has no wildcard link target
/// (link targets must name one of the envelope's own kinds), so links to any
/// record type cannot be expressed without a language change.
///
/// Adoption path from @1 (K6a dependency safety): an existing workspace must
/// `package-disable` the @1 document package and then `package-adopt` @2.
/// A direct replacement adopt is refused by the retained-data guard while
/// @1-pinned records exist — that refusal is by design, not a migration to
/// work around. Records created under @1 stay pinned to @1 permanently:
/// they keep validating, reading and replaying under the strict revision.
/// Between the disable and the @2 adopt, note creates fail (nothing adopted).
/// Importers must omit empty v1 names rather than writing `""`: an explicit
/// null stores as absent, but an empty string stores as given.
pub fn document_package() -> PackageManifest {
    PackageManifest {
        operations: vec![],
        namespace: STANDARD_NAMESPACE.to_string(),
        name: "document".to_string(),
        version: 2,
        definitions: vec![definition_entry(DOCUMENT_FAMILY, 2, DOCUMENT_DEFINITION)],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// The `native.standard/outcome@1` definitions-only package.
pub fn outcome_package() -> PackageManifest {
    PackageManifest {
        operations: vec![],
        namespace: STANDARD_NAMESPACE.to_string(),
        name: "outcome".to_string(),
        version: 1,
        definitions: vec![definition_entry(OUTCOME_FAMILY, 1, OUTCOME_DEFINITION)],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// Optional-title note with governed any-record relationships. @2 remains immutable.
pub fn document3_package() -> PackageManifest {
    let mut manifest = document_package();
    manifest.version = 3;
    manifest.definitions = vec![definition_entry(
        DOCUMENT_FAMILY,
        3,
        include_str!("document3.defn.json"),
    )];
    manifest
}

/// Successor to @3: optional summary and lifecycle; prior revisions stay immutable.
pub fn document4_package() -> PackageManifest {
    let mut manifest = document3_package();
    manifest.version = 4;
    manifest.definitions = vec![definition_entry(
        DOCUMENT_FAMILY,
        4,
        include_str!("document4.defn.json"),
    )];
    manifest
}

/// Both first standard packages, in a stable order.
pub fn standard_packages() -> Vec<PackageManifest> {
    vec![document_package(), outcome_package()]
}

fn compiled_packages() -> Vec<PackageManifest> {
    let mut packages = standard_packages();
    packages.extend([
        document3_package(),
        document4_package(),
        relates_to::package(),
        claims_v1::package(),
        foci::package(),
        v1_compat::package(),
    ]);
    packages
}

/// Gated admission policy, deliberately separate from historical validation.
pub(crate) fn is_reserved_namespace(name: &str) -> bool {
    name.split('.')
        .next()
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("native"))
}

pub(crate) fn require_publishable_package(manifest: &PackageManifest) -> crate::error::Result<()> {
    let reserved = is_reserved_namespace(&manifest.namespace)
        || manifest
            .definitions
            .iter()
            .any(|entry| is_reserved_namespace(&entry.family));
    if reserved
        && !compiled_packages()
            .iter()
            .any(|built_in| built_in == manifest)
    {
        return Err(crate::error::Error::engine(
            "reserved namespace: native and native.* names (ignoring ASCII case) are reserved for the exact first-party packages compiled into this binary. Use your own package namespace and definition families. Packages already installed stay readable and adoptable, but cannot be reinstalled unless their exact revision is compiled into this binary.",
        ));
    }
    Ok(())
}

pub(crate) fn namespace_policy() -> serde_json::Value {
    serde_json::json!({
        "reserved": ["native", "native.*"],
        "case_matching": "ASCII case-insensitive",
        "applies_to": ["package_namespace", "definition_family"],
        "publication": "exact_compiled_first_party_package",
        "existing_packages": "Packages already installed stay readable, adoptable and replayable. Reinstall requires the exact revision to be compiled into this binary. Retrying an older compiled revision after a binary upgrade is refused if that revision is no longer included."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::KERNEL_ROOT_ID;
    use crate::kernel;

    #[test]
    fn definitions_validate_and_are_definitions_only() {
        for manifest in standard_packages() {
            manifest.validate().expect("standard package validates");
            assert!(manifest.behaviour.is_none());
            assert!(manifest.surface.is_none());
            assert!(manifest.declared_reads.is_empty());
            assert!(!manifest.declares_surface());
        }

        let document = document_package();
        assert_eq!(document.namespace, STANDARD_NAMESPACE);
        assert_eq!(document.name, "document");
        assert_eq!(document.version, 2);
        assert_eq!(document.definitions.len(), 1);
        assert_eq!(document.definitions[0].family, DOCUMENT_FAMILY);
        assert!(document.definitions[0].declares_kind("note"));

        let outcome = outcome_package();
        assert_eq!(outcome.namespace, STANDARD_NAMESPACE);
        assert_eq!(outcome.name, "outcome");
        assert_eq!(outcome.version, 1);
        assert_eq!(outcome.definitions[0].family, OUTCOME_FAMILY);
        assert!(outcome.definitions[0].declares_kind("impact"));
    }

    fn own_package(namespace: &str, family: &str) -> PackageManifest {
        let mut manifest = document_package();
        manifest.namespace = namespace.to_string();
        manifest.name = "x".to_string();
        let bytes = DOCUMENT_DEFINITION.replace(DOCUMENT_FAMILY, family);
        manifest.definitions = vec![definition_entry(
            family,
            manifest.definitions[0].version,
            &bytes,
        )];
        manifest
    }

    #[tokio::test]
    async fn reserved_namespace_refusals_are_atomic_and_own_names_work() {
        let dir = tempfile::tempdir().unwrap();
        let url = dir
            .path()
            .join("namespace.db")
            .to_str()
            .unwrap()
            .to_string();
        let (db, admin) = kernel::create_v2_database(&url, "account", "Admin", "acct:admin")
            .await
            .unwrap();
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        let mut changed_bytes = document_package();
        changed_bytes.definitions[0].artifact_bytes.push('\n');
        changed_bytes.definitions[0].digest =
            crate::meta::definition_artifact::digest_artifact_bytes(
                changed_bytes.definitions[0].artifact_bytes.as_bytes(),
            );
        let mut changed_version = document_package();
        changed_version.version += 1;
        let mut changed_reads = document_package();
        changed_reads.behaviour = Some(crate::package_manifest::BehaviourDescriptor {
            kind: crate::package_manifest::BEHAVIOUR_KIND.to_string(),
            reads: vec!["record:view".to_string()],
            effects: vec![],
        });
        changed_reads.declared_reads = vec!["record:view".to_string()];
        changed_reads.surface = Some(crate::package_manifest::SurfaceDescriptor {
            kind: crate::package_manifest::SURFACE_KIND.to_string(),
            view: "view".to_string(),
            fallback: "fallback".to_string(),
        });
        for manifest in [
            own_package("native.standard", "native.standard.x"),
            own_package("acme", "native.standard.x"),
            own_package("native", "acme.x"),
            own_package("native.other", "acme.x"),
            own_package("acme", "native"),
            own_package("acme", "native.other.x"),
            own_package("NATIVE", "acme.x"),
            own_package("Native.standard", "acme.x"),
            own_package("nAtIvE.other", "acme.x"),
            own_package("acme", "NATIVE"),
            own_package("acme", "Native.standard.document"),
            own_package("acme", "nAtIvE.other.x"),
            changed_bytes,
            changed_version,
            changed_reads,
        ] {
            manifest.validate().unwrap();
            let err = kernel::install_package_as(&db, &admin, &manifest)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("reserved namespace"), "{err}");
            assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        }
        let err = kernel::install_definition_as(
            &db,
            &admin,
            DOCUMENT_FAMILY,
            document_package().definitions[0].version,
            DOCUMENT_DEFINITION.as_bytes(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("reserved namespace"), "{err}");
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        let mixed_case = own_package("acme", "Native.standard.document");
        let entry = &mixed_case.definitions[0];
        let err = kernel::install_definition_as(
            &db,
            &admin,
            &entry.family,
            entry.version,
            entry.artifact_bytes.as_bytes(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("reserved namespace"), "{err}");
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        for namespace in [
            "acme",
            "nativeish",
            "native-other",
            "native_other",
            "NATIVEish",
        ] {
            let manifest = own_package(namespace, &format!("{namespace}.x"));
            let identity = kernel::install_package_as(&db, &admin, &manifest)
                .await
                .unwrap();
            kernel::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, Some(&identity), &[])
                .await
                .unwrap();
        }
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }

    /// Install and adopt both packages into a blank v2 database, then compare
    /// `describe` with the checked-in snapshot. Adopting at the workspace root
    /// keeps every home id deterministic (`kernel:root`), so the snapshot is
    /// byte-stable apart from the digests, which are content-addressed.
    #[tokio::test]
    async fn golden_describe_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let url = dir
            .path()
            .join("v2-standard-golden.db")
            .to_str()
            .unwrap()
            .to_string();
        let (db, admin) = kernel::create_v2_database(&url, "account", "Admin", "acct:admin")
            .await
            .unwrap();
        for manifest in standard_packages() {
            let identity = manifest.identity().unwrap();
            kernel::install_package_as(&db, &admin, &manifest)
                .await
                .unwrap();
            kernel::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, Some(&identity), &[])
                .await
                .unwrap();
        }
        let described = kernel::describe_world_as(&db, &admin).await.unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("describe_snapshot.json")).unwrap();
        assert_eq!(
            described,
            expected,
            "golden describe snapshot mismatch; actual:\n{}",
            serde_json::to_string_pretty(&described).unwrap()
        );
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        for manifest in standard_packages() {
            kernel::install_package_as(&db, &admin, &manifest)
                .await
                .unwrap();
        }
        assert_eq!(
            before,
            kernel::dump_all_kernel_tables(&db).await.unwrap(),
            "compiled retries append nothing"
        );
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        assert_eq!(
            described,
            kernel::describe_world_as(&db, &admin).await.unwrap()
        );
        db.close().await;
    }

    /// Openness guard: the v2 modules must never reach back into v1's closed
    /// type list. The forbidden needles are assembled from pieces so this
    /// guard's own source does not contain them contiguously.
    #[test]
    fn openness_guard_v2_modules_avoid_the_closed_type_list() {
        const V2_MODULES: &[(&str, &str)] = &[
            ("src/kernel.rs", include_str!("../kernel.rs")),
            (
                "src/definition_registry.rs",
                include_str!("../definition_registry.rs"),
            ),
            (
                "src/package_manifest.rs",
                include_str!("../package_manifest.rs"),
            ),
            ("src/dependency.rs", include_str!("../dependency.rs")),
            ("src/rule_registry.rs", include_str!("../rule_registry.rs")),
            ("src/meta/adoption.rs", include_str!("../meta/adoption.rs")),
            ("src/meta/consumer.rs", include_str!("../meta/consumer.rs")),
            (
                "src/meta/definition_artifact.rs",
                include_str!("../meta/definition_artifact.rs"),
            ),
            ("src/meta/package.rs", include_str!("../meta/package.rs")),
            (
                "src/meta/rule_installation.rs",
                include_str!("../meta/rule_installation.rs"),
            ),
            (
                "src/v2_slice1_probe.rs",
                include_str!("../v2_slice1_probe.rs"),
            ),
            (
                "src/v2_slice2_probe.rs",
                include_str!("../v2_slice2_probe.rs"),
            ),
            ("src/v2_standard/mod.rs", include_str!("mod.rs")),
            ("src/v2_standard/v1_compat.rs", include_str!("v1_compat.rs")),
        ];
        let needles = [
            ["SPINE", "_TYPES"].concat(),
            ["Core", "Kind"].concat(),
            ["generated", "::kinds"].concat(),
        ];
        for (path, source) in V2_MODULES {
            for needle in &needles {
                assert!(
                    !source.contains(needle.as_str()),
                    "v2 module {path} references the closed v1 type list via '{needle}'"
                );
            }
        }
    }
}
