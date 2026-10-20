//! The `native.foci/foci@1` definitions-only package.
//!
//! Three `native.defn/5` definition families with no behaviour, no surface,
//! no operations and no declared reads: `native.foci.focus` (`focus`),
//! `native.foci.saved_view` (`record_view`, `query_view`) and
//! `native.foci.preferences` (`focus_preferences`).
//!
//! The bytes live in exact, checked-in files beside this module: whitespace
//! counts toward each definition digest, and the package digest is the JCS
//! digest of the built manifest. Nothing here touches the default build.

use crate::package_manifest::{DefinitionEntry, PackageManifest};

/// Namespace of the Foci package.
pub const NAMESPACE: &str = "native.foci";
/// Package name.
pub const PACKAGE: &str = "foci";
/// Family of the Focus definition.
pub const FOCUS_FAMILY: &str = "native.foci.focus";
/// Family of the saved-view definition.
pub const SAVED_VIEW_FAMILY: &str = "native.foci.saved_view";
/// Family of the preferences definition.
pub const PREFERENCES_FAMILY: &str = "native.foci.preferences";

/// Exact `focus` definition bytes (whitespace significant).
pub const FOCUS_DEFINITION: &str = include_str!("foci_focus.defn.json");
/// Exact saved-view definition bytes (whitespace significant).
pub const SAVED_VIEW_DEFINITION: &str = include_str!("foci_saved_view.defn.json");
/// Exact preferences definition bytes (whitespace significant).
pub const PREFERENCES_DEFINITION: &str = include_str!("foci_preferences.defn.json");

fn definition_entry(family: &str, version: u32, artifact_bytes: &str) -> DefinitionEntry {
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: artifact_bytes.to_string(),
        digest: crate::meta::definition_artifact::digest_artifact_bytes(artifact_bytes.as_bytes()),
    }
}

/// The `native.foci/foci@1` definitions-only package.
pub fn package() -> PackageManifest {
    PackageManifest {
        operations: vec![],
        namespace: NAMESPACE.to_string(),
        name: PACKAGE.to_string(),
        version: 1,
        definitions: vec![
            definition_entry(FOCUS_FAMILY, 1, FOCUS_DEFINITION),
            definition_entry(SAVED_VIEW_FAMILY, 1, SAVED_VIEW_DEFINITION),
            definition_entry(PREFERENCES_FAMILY, 1, PREFERENCES_DEFINITION),
        ],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// Exact compiled first-party package admission check.
pub fn known_package(manifest: &PackageManifest) -> bool {
    *manifest == package()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::KERNEL_ROOT_ID;
    use crate::kernel;
    use serde_json::{json, Value};

    fn map(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    async fn world() -> (tempfile::TempDir, crate::db::Db, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foci.db");
        let (db, admin) =
            kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
                .await
                .unwrap();
        let manifest = package();
        let identity = manifest.identity().unwrap();
        kernel::install_package_as(&db, &admin, &manifest)
            .await
            .unwrap();
        kernel::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, Some(&identity), &[])
            .await
            .unwrap();
        (dir, db, admin)
    }

    async fn create(
        db: &crate::db::Db,
        actor: &str,
        family: &str,
        kind: &str,
        fields: &serde_json::Map<String, Value>,
    ) -> crate::Result<String> {
        kernel::create_json_as(
            db,
            actor,
            family,
            kind,
            &serde_json::to_string(fields)?,
            KERNEL_ROOT_ID,
        )
        .await
    }

    async fn events(db: &crate::db::Db) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    fn focus_fields() -> Value {
        json!({"name": "Now", "colour": "#112233", "view_order": []})
    }

    fn record_view_fields() -> Value {
        json!({"name": "Plan", "definition": {"app": "fixture.docs", "target": {"record_id": "some-record"}}})
    }

    fn maximal_query_view_fields() -> Value {
        let terms: Vec<Value> = (0..16)
            .map(|i| json!({"field": format!("field{i}"), "op": "eq", "value": "open"}))
            .collect();
        let sorts: Vec<Value> = (0..8)
            .map(|i| json!({"field": format!("field{i}"), "direction": "asc"}))
            .collect();
        json!({"name": "Work", "definition": {
            "app": "fixture.tracker",
            "format": "tracker-start/1",
            "text": "urgent",
            "filter": {"combine": "all", "terms": terms},
            "sort": sorts,
            "group_by": "status",
        }})
    }

    fn preferences_fields() -> Value {
        json!({"foci": [
            {"focus_id": "focus-now", "tier": "now", "hidden": false},
            {"focus_id": "focus-later", "tier": "background", "hidden": true},
        ]})
    }

    fn minimal_query_view_fields() -> Value {
        json!({"name": "Bare", "definition": {
            "app": "fixture.tracker",
            "format": "tracker-start/1",
            "filter": {"combine": "all", "terms": []},
            "sort": [],
        }})
    }

    fn assert_engine(result: crate::Result<String>, expected: &str) {
        match result.unwrap_err() {
            crate::Error::Engine(message) => assert_eq!(message, expected),
            other => panic!("expected Engine({expected:?}), got {other:?}"),
        }
    }

    #[test]
    fn manifest_validates_and_is_definitions_only() {
        let manifest = package();
        manifest.validate().expect("foci package validates");
        assert!(manifest.behaviour.is_none());
        assert!(manifest.surface.is_none());
        assert!(manifest.declared_reads.is_empty());
        assert!(!manifest.declares_surface());
        assert!(manifest.operations.is_empty());
        assert_eq!(manifest.namespace, NAMESPACE);
        assert_eq!(manifest.name, PACKAGE);
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.definitions.len(), 3);
        assert_eq!(manifest.definitions[0].family, FOCUS_FAMILY);
        assert!(manifest.definitions[0].declares_kind("focus"));
        assert_eq!(manifest.definitions[1].family, SAVED_VIEW_FAMILY);
        assert!(manifest.definitions[1].declares_kind("record_view"));
        assert!(manifest.definitions[1].declares_kind("query_view"));
        assert_eq!(manifest.definitions[2].family, PREFERENCES_FAMILY);
        assert!(manifest.definitions[2].declares_kind("focus_preferences"));
        assert!(known_package(&manifest));
    }

    #[tokio::test]
    async fn install_adopt_describe() {
        let (_dir, db, admin) = world().await;
        let described = kernel::describe_world_as(&db, &admin).await.unwrap();
        let entries = described["definitions"].as_array().unwrap();
        let manifest = package();
        for (family, kind) in [
            (FOCUS_FAMILY, "focus"),
            (SAVED_VIEW_FAMILY, "record_view"),
            (SAVED_VIEW_FAMILY, "query_view"),
            (PREFERENCES_FAMILY, "focus_preferences"),
        ] {
            let entry = entries
                .iter()
                .find(|e| e["family"] == family && e["kind"] == kind)
                .unwrap_or_else(|| panic!("missing describe entry for {family}/{kind}"));
            assert_eq!(entry["interpreter"], "native.defn/5");
            assert_eq!(entry["package"]["namespace"], NAMESPACE);
            assert_eq!(entry["package"]["name"], PACKAGE);
            assert_eq!(entry["adoption"]["state"], "adopted");
            let pin = manifest
                .definitions
                .iter()
                .find(|d| d.family == family)
                .unwrap();
            assert_eq!(entry["version"], pin.version);
            assert_eq!(entry["digest"], pin.digest);
            assert_eq!(entry["adoption"]["pin"]["digest"], pin.digest);
        }
        db.close().await;
    }

    #[tokio::test]
    async fn create_and_read_all_kinds_round_trip() {
        let (_dir, db, admin) = world().await;
        let mut bare_focus = focus_fields();
        bare_focus.as_object_mut().unwrap().remove("colour");
        for (family, kind, fields) in [
            (FOCUS_FAMILY, "focus", focus_fields()),
            (FOCUS_FAMILY, "focus", bare_focus),
            (SAVED_VIEW_FAMILY, "record_view", record_view_fields()),
            (SAVED_VIEW_FAMILY, "query_view", maximal_query_view_fields()),
            (SAVED_VIEW_FAMILY, "query_view", minimal_query_view_fields()),
            (
                PREFERENCES_FAMILY,
                "focus_preferences",
                preferences_fields(),
            ),
        ] {
            let id = create(&db, &admin, family, kind, &map(fields.clone()))
                .await
                .unwrap();
            let read = kernel::read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(Value::Object(read.fields.clone()), fields);
        }
        db.close().await;
    }

    #[tokio::test]
    async fn guarded_revise_accepts_fresh_and_refuses_stale() {
        let (_dir, db, admin) = world().await;
        let id = create(&db, &admin, FOCUS_FAMILY, "focus", &map(focus_fields()))
            .await
            .unwrap();
        let first = kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap();
        let mut revised = focus_fields();
        revised["name"] = json!("Later");
        kernel::revise_json_as_expected(
            &db,
            &admin,
            &id,
            &serde_json::to_string(&map(revised.clone())).unwrap(),
            Some(first.revision),
        )
        .await
        .unwrap();
        let current = kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(current.fields.clone()), revised);
        let before = events(&db).await;
        let stale = kernel::revise_json_as_expected(
            &db,
            &admin,
            &id,
            &serde_json::to_string(&map(focus_fields())).unwrap(),
            Some(first.revision),
        )
        .await;
        match stale.unwrap_err() {
            crate::Error::Conflict(message) => assert_eq!(
                message,
                format!(
                    "record revision mismatch: expected {}, found {}",
                    first.revision, current.revision
                )
            ),
            other => panic!("expected stale-revision Conflict, got {other:?}"),
        }
        assert_eq!(events(&db).await, before);
        assert_eq!(
            kernel::read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap(),
            current
        );
        db.close().await;
    }

    #[tokio::test]
    async fn structural_refusals_are_event_free() {
        let (_dir, db, admin) = world().await;
        let many_views: Vec<Value> = (0..129).map(|i| json!(format!("view{i}"))).collect();
        let many_terms: Vec<Value> = (0..17)
            .map(|_| json!({"field": "status", "op": "eq", "value": "open"}))
            .collect();
        let many_sorts: Vec<Value> = (0..9)
            .map(|_| json!({"field": "title", "direction": "asc"}))
            .collect();
        let many_foci: Vec<Value> = (0..129)
            .map(|i| json!({"focus_id": format!("focus{i}"), "tier": "now", "hidden": false}))
            .collect();
        let mut null_member = record_view_fields();
        null_member["definition"]["target"]["record_id"] = Value::Null;
        let mut unknown = focus_fields();
        unknown["bogus"] = json!("x");
        let mut missing = focus_fields();
        missing.as_object_mut().unwrap().remove("name");
        let mut bad_choice = maximal_query_view_fields();
        bad_choice["definition"]["sort"][0]["direction"] = json!("down");
        let mut over_views = focus_fields();
        over_views["view_order"] = Value::Array(many_views);
        let mut over_terms = maximal_query_view_fields();
        over_terms["definition"]["filter"]["terms"] = Value::Array(many_terms);
        let mut over_sorts = maximal_query_view_fields();
        over_sorts["definition"]["sort"] = Value::Array(many_sorts);
        let mut over_foci = preferences_fields();
        over_foci["foci"] = Value::Array(many_foci);
        let mut bad_tier = preferences_fields();
        bad_tier["foci"][0]["tier"] = json!("later");
        for (family, kind, fields, expected) in [
            (FOCUS_FAMILY, "focus", unknown, "unknown_member at /bogus"),
            (FOCUS_FAMILY, "focus", missing, "required_missing at /name"),
            (
                FOCUS_FAMILY,
                "focus",
                over_views,
                "limit_exceeded at /view_order",
            ),
            (
                SAVED_VIEW_FAMILY,
                "record_view",
                null_member,
                "null_not_supported at /definition/target/record_id",
            ),
            (
                SAVED_VIEW_FAMILY,
                "query_view",
                bad_choice,
                "wrong_type at /definition/sort/0/direction",
            ),
            (
                SAVED_VIEW_FAMILY,
                "query_view",
                over_terms,
                "limit_exceeded at /definition/filter/terms",
            ),
            (
                SAVED_VIEW_FAMILY,
                "query_view",
                over_sorts,
                "limit_exceeded at /definition/sort",
            ),
            (
                PREFERENCES_FAMILY,
                "focus_preferences",
                over_foci,
                "limit_exceeded at /foci",
            ),
            (
                PREFERENCES_FAMILY,
                "focus_preferences",
                bad_tier,
                "wrong_type at /foci/0/tier",
            ),
        ] {
            let before = events(&db).await;
            assert_engine(
                create(&db, &admin, family, kind, &map(fields)).await,
                expected,
            );
            assert_eq!(events(&db).await, before);
        }
        db.close().await;
    }

    #[tokio::test]
    async fn identical_record_views_have_distinct_ids() {
        let (_dir, db, admin) = world().await;
        let one = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(record_view_fields()),
        )
        .await
        .unwrap();
        let two = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(record_view_fields()),
        )
        .await
        .unwrap();
        assert_ne!(one, two);
        db.close().await;
    }

    #[tokio::test]
    async fn link4_member_of_and_parent() {
        // The two links below are separate, non-atomic calls: each commits on
        // its own, so a crash between them leaves the first link in place.
        let (_dir, db, admin) = world().await;
        let parent = create(&db, &admin, FOCUS_FAMILY, "focus", &map(focus_fields()))
            .await
            .unwrap();
        let mut child = focus_fields();
        child["name"] = json!("Child");
        let child = create(&db, &admin, FOCUS_FAMILY, "focus", &map(child))
            .await
            .unwrap();
        let view = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(record_view_fields()),
        )
        .await
        .unwrap();
        let query = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "query_view",
            &map(minimal_query_view_fields()),
        )
        .await
        .unwrap();
        kernel::link_as(&db, &admin, &child, "parent", &parent)
            .await
            .unwrap();
        kernel::link_as(&db, &admin, &view, "member_of", &child)
            .await
            .unwrap();
        kernel::link_as(&db, &admin, &query, "member_of", &child)
            .await
            .unwrap();
        for (source, predicate, target) in [
            (&child, "parent", &parent),
            (&view, "member_of", &child),
            (&query, "member_of", &child),
        ] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM kernel_link4_edges WHERE source_id = ? AND predicate = ? AND target_id = ?",
            )
            .bind(source)
            .bind(predicate)
            .bind(target)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(count, 1);
        }
        db.close().await;
    }
}
