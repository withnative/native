//! The `native/v1@1` compatibility carrier (HQ cutover S2).
//!
//! One permissive `native.defn/5` definition family, `native.v1.record`
//! (`record`), carries every v1 (type, kind) pair with no first-class v2
//! definition — everything except `Document:note`, which rides
//! `native.standard/document@4`. Writing one definition per v1 kind (117
//! pairs) is not practical, and the definition language cannot parameterise
//! a kind by arbitrary type/kind: kinds are fixed tokens in the envelope.
//! So the carrier is a single generic kind with the v1 pair preserved
//! verbatim in required text fields `v1_type` / `v1_kind`, plus optional
//! `title`, `summary` (HQ max 2.6 KB, inside the `/5` text budget) and
//! free-text `lifecycle`. The record body is not a field: `/5` caps text
//! values at 4096 bytes and a record's fields at 64 KiB, while real HQ
//! bodies reach 1.3 MB, so bodies live in the kernel-owned body lane,
//! outside the field budget.
//!
//! The bytes live in the exact, checked-in file beside this module:
//! whitespace counts toward the definition digest, and the package digest is
//! the JCS digest of the built manifest. Definitions-only (K5): no
//! behaviour, no surface, no declared reads, no operations.
//!
//! Links mirror `document@4`: one governed `relates_to.v1` declaration with
//! an `any_record` target, so a carried record relates to any record through
//! the relates-to provider commit port. The package is registered in
//! `compiled_packages()`, so the reserved-namespace admission check accepts
//! this exact revision; it adds no behaviour to the default build.

use crate::package_manifest::{DefinitionEntry, PackageManifest};

/// Namespace of the compatibility carrier package.
pub const NAMESPACE: &str = "native";
/// Package name of the compatibility carrier package.
pub const PACKAGE: &str = "v1";
/// Family of the carrier definition.
pub const FAMILY: &str = "native.v1.record";
/// The single carrier kind: every non-note v1 pair rides this kind.
pub const KIND: &str = "record";

/// Caller-facing type/kind for get/query and S7's SQL projection.
/// `native/v1@1` carries its records in the reserved definition pin
/// `native.v1.record@1` (PR #2447). Match that immutable binding, not just
/// field names: unrelated records may legitimately hold v1_type/v1_kind.
pub fn v1_type_and_kind<'a>(
    family: Option<&str>,
    version: Option<u32>,
    primary_type: Option<&'a str>,
    kind: Option<&'a str>,
    fields: &'a serde_json::Map<String, serde_json::Value>,
) -> (Option<&'a str>, Option<&'a str>) {
    if family == Some(crate::v2_standard::v1_compat::FAMILY) && version == Some(1) {
        (
            fields.get("v1_type").and_then(serde_json::Value::as_str),
            fields.get("v1_kind").and_then(serde_json::Value::as_str),
        )
    } else {
        (primary_type, kind)
    }
}

/// Preserve authorship for both imported and native Message records. Only the
/// reserved compatibility pin may override the native envelope's type.
pub fn preserves_message_authorship(
    family: Option<&str>,
    version: Option<u32>,
    primary_type: Option<&str>,
    kind: Option<&str>,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    v1_type_and_kind(family, version, primary_type, kind, fields).0 == Some("Message")
}

/// Exact carrier definition bytes (whitespace significant).
pub const DEFINITION: &str = include_str!("v1_compat.defn.json");

fn definition_entry(family: &str, version: u32, artifact_bytes: &str) -> DefinitionEntry {
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: artifact_bytes.to_string(),
        digest: crate::meta::definition_artifact::digest_artifact_bytes(artifact_bytes.as_bytes()),
    }
}

/// The `native/v1@1` definitions-only package.
pub fn package() -> PackageManifest {
    PackageManifest {
        operations: vec![],
        namespace: NAMESPACE.to_string(),
        name: PACKAGE.to_string(),
        version: 1,
        definitions: vec![definition_entry(FAMILY, 1, DEFINITION)],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// Exact compiled first-party package admission check.
pub fn known_package(manifest: &PackageManifest) -> bool {
    *manifest == package()
}

/// Where a v1 (type, kind) pair is carried in v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1Carrier {
    /// `Document:note` rides the first-class note kind.
    DocumentNote,
    /// Every other v1 pair rides the compat carrier kind.
    Compat,
}

impl V1Carrier {
    /// Namespace of the carrying package.
    pub fn package_namespace(self) -> &'static str {
        match self {
            Self::DocumentNote => super::STANDARD_NAMESPACE,
            Self::Compat => NAMESPACE,
        }
    }

    /// Name of the carrying package.
    pub fn package_name(self) -> &'static str {
        match self {
            Self::DocumentNote => "document",
            Self::Compat => PACKAGE,
        }
    }

    /// Version of the carrying package.
    pub fn package_version(self) -> u32 {
        match self {
            Self::DocumentNote => 4,
            Self::Compat => 1,
        }
    }

    /// Family of the carrying definition.
    pub fn family(self) -> &'static str {
        match self {
            Self::DocumentNote => super::DOCUMENT_FAMILY,
            Self::Compat => FAMILY,
        }
    }

    /// Kind token to create under the carrying definition.
    pub fn kind(self) -> &'static str {
        match self {
            Self::DocumentNote => "note",
            Self::Compat => KIND,
        }
    }
}

/// Route a v1 (type, kind) pair to its v2 carrier. Pure: no I/O, no globals.
/// `Document`/`note` rides `document@4`; everything else rides `native/v1@1`.
pub fn v1_carrier_for(v1_type: &str, v1_kind: &str) -> V1Carrier {
    if v1_type == "Document" && v1_kind == "note" {
        V1Carrier::DocumentNote
    } else {
        V1Carrier::Compat
    }
}

/// Build the compat-kind field map for a carried v1 record. `v1_type` and
/// `v1_kind` are preserved verbatim; `title` is omitted when `None` or the
/// truly empty string — no title is ever invented. Whitespace-only titles
/// are kept verbatim: only `""` counts as empty. The remaining `Option`s
/// are stored verbatim when `Some`, omitted when `None`. The record body is
/// never a field: bodies live in the kernel body lane.
pub fn compat_fields(
    v1_type: &str,
    v1_kind: &str,
    title: Option<&str>,
    summary: Option<&str>,
    lifecycle: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("v1_type".to_string(), v1_type.into());
    fields.insert("v1_kind".to_string(), v1_kind.into());
    if let Some(title) = title.filter(|t| !t.is_empty()) {
        fields.insert("title".to_string(), title.into());
    }
    if let Some(summary) = summary {
        fields.insert("summary".to_string(), summary.into());
    }
    if let Some(lifecycle) = lifecycle {
        fields.insert("lifecycle".to_string(), lifecycle.into());
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::KERNEL_ROOT_ID;
    use crate::kernel;

    #[test]
    fn manifest_validates_and_is_definitions_only() {
        let manifest = package();
        manifest.validate().expect("v1 compat package validates");
        assert!(manifest.behaviour.is_none());
        assert!(manifest.surface.is_none());
        assert!(manifest.declared_reads.is_empty());
        assert!(!manifest.declares_surface());
        assert!(manifest.operations.is_empty());
        assert_eq!(manifest.namespace, NAMESPACE);
        assert_eq!(manifest.name, PACKAGE);
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.definitions.len(), 1);
        assert_eq!(manifest.definitions[0].family, FAMILY);
        assert!(manifest.definitions[0].declares_kind(KIND));
        assert!(known_package(&manifest));
    }

    #[test]
    fn helper_routes_document_note_and_everything_else() {
        let fields = compat_fields("Message", "message", None, None, None);
        assert!(preserves_message_authorship(
            Some(FAMILY),
            Some(1),
            Some("V1"),
            Some(KIND),
            &fields
        ));
        assert!(preserves_message_authorship(
            None,
            None,
            Some("Message"),
            None,
            &serde_json::Map::new()
        ));
        assert!(!preserves_message_authorship(
            Some("unrelated"),
            Some(1),
            Some("Document"),
            None,
            &fields
        ));
        let note = v1_carrier_for("Document", "note");
        assert_eq!(note, V1Carrier::DocumentNote);
        assert_eq!(
            note.package_namespace(),
            crate::v2_standard::STANDARD_NAMESPACE
        );
        assert_eq!(note.package_name(), "document");
        assert_eq!(note.package_version(), 4);
        assert_eq!(note.family(), crate::v2_standard::DOCUMENT_FAMILY);
        assert_eq!(note.kind(), "note");
        for (v1_type, v1_kind) in [
            ("WorkItem", "task"),
            ("WorkItem", "epic"),
            ("WorkItem", "attention"),
            ("Collection", "folder"),
            ("Resolution", "decision"),
            ("Entity", "person"),
            ("Document", "attachment"),
            ("Document", "NOTE"),
            ("document", "note"),
            ("Outcome", "impact"),
            ("", ""),
        ] {
            let carrier = v1_carrier_for(v1_type, v1_kind);
            assert_eq!(carrier, V1Carrier::Compat, "{v1_type}/{v1_kind}");
            assert_eq!(carrier.package_namespace(), NAMESPACE);
            assert_eq!(carrier.package_name(), PACKAGE);
            assert_eq!(carrier.package_version(), 1);
            assert_eq!(carrier.family(), FAMILY);
            assert_eq!(carrier.kind(), KIND);
        }
    }

    #[test]
    fn compat_fields_omits_empty_title_and_absent_options() {
        let fields = compat_fields("WorkItem", "task", Some("T"), None, Some("open"));
        assert_eq!(fields["v1_type"], "WorkItem");
        assert_eq!(fields["v1_kind"], "task");
        assert_eq!(fields["title"], "T");
        assert_eq!(fields["lifecycle"], "open");
        assert!(!fields.contains_key("summary"));
        for title in [None, Some("")] {
            let fields = compat_fields("Collection", "folder", title, None, None);
            assert_eq!(fields["v1_type"], "Collection");
            assert_eq!(fields["v1_kind"], "folder");
            assert!(!fields.contains_key("title"), "{title:?}");
        }
        // Whitespace-only titles are kept verbatim: only "" counts as empty.
        let fields = compat_fields("Collection", "folder", Some("  "), None, None);
        assert_eq!(fields["title"], "  ");
    }

    async fn world(
        with_relationship_provider: bool,
        with_document3: bool,
    ) -> (tempfile::TempDir, crate::db::Db, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1-compat.db");
        let (db, admin) =
            kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
                .await
                .unwrap();
        let mut manifests = vec![package()];
        if with_relationship_provider {
            manifests.push(crate::v2_standard::relates_to::package());
        }
        if with_document3 {
            manifests.push(crate::v2_standard::document3_package());
        }
        for manifest in &manifests {
            let identity = manifest.identity().unwrap();
            kernel::install_package_as(&db, &admin, manifest)
                .await
                .unwrap();
            kernel::adopt_package_at(
                &db,
                &admin,
                KERNEL_ROOT_ID,
                manifest,
                Some(&identity),
                &manifest.declared_reads,
            )
            .await
            .unwrap();
        }
        (dir, db, admin)
    }

    async fn create(
        db: &crate::db::Db,
        actor: &str,
        fields: &serde_json::Map<String, serde_json::Value>,
    ) -> crate::Result<String> {
        kernel::create_json_as(
            db,
            actor,
            FAMILY,
            KIND,
            &serde_json::to_string(fields).unwrap(),
            KERNEL_ROOT_ID,
        )
        .await
    }

    #[tokio::test]
    async fn install_adopt_create_read_round_trip() {
        let (_dir, db, admin) = world(false, false).await;
        let task = compat_fields(
            "WorkItem",
            "task",
            Some("Ship S2"),
            Some("Compat carrier"),
            Some("in_progress"),
        );
        let folder = compat_fields("Collection", "folder", None, None, None);
        let decision = compat_fields(
            "Resolution",
            "decision",
            Some("Use a carrier"),
            Some("One definition carries all v1 kinds."),
            Some("done"),
        );
        for expected in [&task, &folder, &decision] {
            let id = create(&db, &admin, expected).await.unwrap();
            let read = kernel::read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&read.fields, expected);
        }
        // The untitled folder stores no title at all: nothing was invented.
        assert!(!folder.contains_key("title"));
        db.close().await;
    }

    #[tokio::test]
    async fn governed_any_record_link_between_carried_records() {
        use crate::v2_standard::relates_to::Command;
        let (_dir, db, admin) = world(true, false).await;
        let task = create(
            &db,
            &admin,
            &compat_fields("WorkItem", "task", Some("Ship S2"), None, Some("open")),
        )
        .await
        .unwrap();
        let decision = create(
            &db,
            &admin,
            &compat_fields("Resolution", "decision", Some("Use a carrier"), None, None),
        )
        .await
        .unwrap();
        let request = kernel::prepare_provider_as(
            &db,
            &admin,
            &task,
            &decision,
            "s2-carrier-link",
            Command::Assert { sources: vec![] },
        )
        .await
        .unwrap();
        kernel::commit_provider_as(&db, &admin, &request)
            .await
            .unwrap();
        let relations = kernel::relations_as(&db, &admin, &task).await.unwrap();
        assert!(
            serde_json::to_string(&relations)
                .unwrap()
                .contains(&decision),
            "governed relations for {task} mention {decision}: {relations:?}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn carrier_and_note_link_in_both_directions() {
        use crate::v2_standard::relates_to::Command;
        let (_dir, db, admin) = world(true, true).await;
        let task = create(
            &db,
            &admin,
            &compat_fields("WorkItem", "task", Some("Ship S2"), None, Some("open")),
        )
        .await
        .unwrap();
        let note = kernel::create_json_as(
            &db,
            &admin,
            crate::v2_standard::DOCUMENT_FAMILY,
            "note",
            r#"{"title":"A note"}"#,
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        for (anchor, counterpart, key) in [
            (&task, &note, "s2-carrier-anchors-note"),
            (&note, &task, "s2-note-anchors-carrier"),
        ] {
            let request = kernel::prepare_provider_as(
                &db,
                &admin,
                anchor,
                counterpart,
                key,
                Command::Assert { sources: vec![] },
            )
            .await
            .unwrap();
            kernel::commit_provider_as(&db, &admin, &request)
                .await
                .unwrap();
        }
        for id in [&task, &note] {
            let relations = kernel::relations_as(&db, &admin, id).await.unwrap();
            let other = if id == &task { &note } else { &task };
            assert!(
                serde_json::to_string(&relations).unwrap().contains(other),
                "governed relations for {id} mention {other}: {relations:?}"
            );
        }
        db.close().await;
    }
}
