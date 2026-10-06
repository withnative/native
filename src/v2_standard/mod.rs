//! The `native.standard` definitions-only packages (PR3).
//!
//! Gated like the rest of the v2 kernel probe surface. Two packages ship the
//! first default record types as ordinary checked-in definition bytes:
//! `native.standard/document@1` (`Document:note`) and
//! `native.standard/outcome@1` (`Outcome:impact`). Both are definitions-only
//! (K5): no behaviour, no surface, no declared reads.
//!
//! The bytes live in exact, checked-in files beside this module: whitespace
//! counts toward each definition digest, and the package digest is the JCS
//! digest of the built manifest. Nothing here touches the default build.

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

/// The `native.standard/document@1` definitions-only package.
pub fn document_package() -> PackageManifest {
    PackageManifest {
        namespace: STANDARD_NAMESPACE.to_string(),
        name: "document".to_string(),
        version: 1,
        definitions: vec![definition_entry(DOCUMENT_FAMILY, 1, DOCUMENT_DEFINITION)],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// The `native.standard/outcome@1` definitions-only package.
pub fn outcome_package() -> PackageManifest {
    PackageManifest {
        namespace: STANDARD_NAMESPACE.to_string(),
        name: "outcome".to_string(),
        version: 1,
        definitions: vec![definition_entry(OUTCOME_FAMILY, 1, OUTCOME_DEFINITION)],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// Both first standard packages, in a stable order.
pub fn standard_packages() -> Vec<PackageManifest> {
    vec![document_package(), outcome_package()]
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
        assert_eq!(document.version, 1);
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
