use super::*;
use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
use crate::events::{LinkAddedPayload, LinkRemovedPayload};
use crate::query::QueryPrincipal;
use crate::store::{add_link, archive_record, create_record_as, remove_link, update_record};
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn fixture_id(label: &str) -> String {
    if uuid::Uuid::parse_str(label).is_ok() {
        return label.to_owned();
    }
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(format!("vault-fixture:{label}").as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    uuid::Uuid::from_bytes(bytes).to_string()
}
async fn db() -> crate::Db {
    crate::create_database(":memory:").await.unwrap()
}
async fn record(
    db: &crate::Db,
    id: &str,
    title: &str,
    ty: &str,
    kind: &str,
    home: &str,
    body: &str,
) {
    let id = fixture_id(id);
    let home = if home.starts_with("native:") {
        home.to_owned()
    } else {
        fixture_id(home)
    };
    create_record_as(
        db,
        json!({"id":id,"type":ty,"kind":kind,"name":title,"home_id":home,"body":body}),
        Some("alice"),
    )
    .await
    .unwrap();
}
async fn link(db: &crate::Db, source: &str, target: &str, rel: &str) {
    add_link(
        db,
        LinkAddedPayload {
            id: None,
            source_id: source.into(),
            target_id: target.into(),
            relationship: rel.into(),
            note: Some("link note".into()),
        },
    )
    .await
    .unwrap();
}
async fn policy(db: &crate::Db, id: &str, account: &str) {
    replace_explicit_policy(
        db,
        "fixture",
        id,
        vec![AllowEntry::account(account, Capability::View)],
    )
    .await
    .unwrap();
}
async fn source(db: &crate::Db, account: &str) -> SourceSnapshot {
    crate::query::sql::projection_snapshot(db, QueryPrincipal::authenticated(account, true))
        .await
        .unwrap()
}
fn rendered(s: &SourceSnapshot) -> Rendered {
    render::render(s, &BTreeMap::new()).unwrap()
}
fn path_for(rendered: &Rendered, id: &str) -> String {
    rendered
        .files
        .iter()
        .find(|(_, o)| String::from_utf8_lossy(&o.bytes).contains(&format!("\"id\": \"{id}\"")))
        .unwrap()
        .0
        .clone()
}
fn edit(path: &Path, text: &str) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(path, text).unwrap();
}
fn disk(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                visit(root, &p, out);
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(path, path, &mut out);
    out
}

#[tokio::test]
async fn production_depends_on_is_rendered_updated_and_authorized() {
    let db = db().await;
    let a = fixture_id("dependency-source");
    let b = fixture_id("dependency-target");
    record(
        &db,
        &a,
        "Source task",
        "WorkItem",
        "task",
        "native:root",
        "source",
    )
    .await;
    record(
        &db,
        &b,
        "Target task",
        "WorkItem",
        "task",
        "native:root",
        "target",
    )
    .await;
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    registry
        .call(
            db.clone(),
            crate::mcp::Caller::local(),
            "manage_links",
            json!({
                "action":"add", "source_id":a, "target_id":b,
                "relationship":"depends_on", "note":"production dependency"
            }),
        )
        .await
        .unwrap();
    let first = source(&db, "alice").await;
    assert!(first
        .links
        .iter()
        .any(|l| l.source_id == a && l.target_id == b && l.relationship == "depends_on"));
    let initial = rendered(&first);
    let note = String::from_utf8_lossy(&initial.files[&path_for(&initial, &a)].bytes);
    assert!(note.contains("\"depends_on\""));
    assert!(note.contains("Target task"));
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut publisher = Publisher::open(&root).unwrap();
    publisher.cycle(&first).unwrap();
    update_record(&db, &b, json!({"name":"Renamed target"}))
        .await
        .unwrap();
    let next = source(&db, "alice").await;
    let fresh = render::render(&next, &initial.allocations).unwrap();
    publisher.cycle(&next).unwrap();
    let actual = disk(&root);
    for (path, output) in &fresh.files {
        assert_eq!(actual[path], output.bytes);
    }
    assert!(String::from_utf8_lossy(&actual[&path_for(&fresh, &a)]).contains("Renamed target"));
    policy(&db, &b, "bea").await;
    let revoked = source(&db, "alice").await;
    assert!(!revoked
        .links
        .iter()
        .any(|l| l.source_id == a && l.target_id == b));
    publisher.cycle(&revoked).unwrap();
    assert!(disk(&root)
        .values()
        .all(|bytes| !String::from_utf8_lossy(bytes).contains("Renamed target")));
}

#[tokio::test]
async fn authorized_snapshot_is_complete_large_and_pool_principal_safe() {
    let db = db().await;
    record(
        &db,
        "41329f31-d27c-4c34-8988-6777ee0b162a",
        "Alice visible",
        "Document",
        "note",
        "native:root",
        "alice",
    )
    .await;
    record(
        &db,
        "8c20c466-dd55-49e4-8359-f5cfa0a8d060",
        "BEA SECRET",
        "Entity",
        "person",
        "native:root",
        "secret",
    )
    .await;
    policy(&db, "41329f31-d27c-4c34-8988-6777ee0b162a", "alice").await;
    policy(&db, "8c20c466-dd55-49e4-8359-f5cfa0a8d060", "bea").await;
    link(
        &db,
        "41329f31-d27c-4c34-8988-6777ee0b162a",
        "8c20c466-dd55-49e4-8359-f5cfa0a8d060",
        "derived_from",
    )
    .await;
    let large = "\"\\\n".repeat(110_000); // raw >256 KiB, serialized escaping much larger.
    record(
        &db,
        "22c63d57-df7a-4f99-bb9e-0f85163b0a6f",
        "Large document",
        "Document",
        "note",
        "native:root",
        &large,
    )
    .await;
    // Synthetic volume exceeds BOTH public row and encoded-result caps.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1100) INSERT INTO records(id,type,kind,name,body,home_id,policy_anchor_id) SELECT printf('99000000-0000-4000-8000-%012x',x),'Document','note',printf('Volume %04d',x),?1,'native:root','native:root' FROM n").bind("x".repeat(5000)).execute(db.write_pool()).await.unwrap();
    for account in ["alice", "bea", "alice", "bea"] {
        let s = source(&db, account).await;
        assert_eq!(
            s.records["22c63d57-df7a-4f99-bb9e-0f85163b0a6f"]
                .body
                .as_deref(),
            Some(large.as_str())
        );
        assert_eq!(
            s.records
                .keys()
                .filter(|id| id.starts_with("99000000-"))
                .count(),
            1100
        );
        assert_eq!(
            s.records
                .contains_key("41329f31-d27c-4c34-8988-6777ee0b162a"),
            account == "alice"
        );
        assert_eq!(
            s.records
                .contains_key("8c20c466-dd55-49e4-8359-f5cfa0a8d060"),
            account == "bea"
        );
        assert!(s
            .links
            .iter()
            .all(|l| l.source_id != "41329f31-d27c-4c34-8988-6777ee0b162a"
                || l.target_id != "8c20c466-dd55-49e4-8359-f5cfa0a8d060"));
    }
    policy(&db, "41329f31-d27c-4c34-8988-6777ee0b162a", "bea").await;
    let s = source(&db, "alice").await;
    assert!(!s
        .records
        .contains_key("41329f31-d27c-4c34-8988-6777ee0b162a"));
    assert!(!s
        .records
        .contains_key("8c20c466-dd55-49e4-8359-f5cfa0a8d060"));
    let r = rendered(&s);
    for output in r.files.values() {
        let text = String::from_utf8_lossy(&output.bytes);
        assert!(!text.contains("BEA SECRET"));
        assert!(!text.contains("8c20c466-dd55-49e4-8359-f5cfa0a8d060"));
    }
    // A new projection connection and a public governed query agree on ids.
    let expected =
        crate::query::sql::workspace_visible_set(&db, QueryPrincipal::authenticated("alice", true))
            .await
            .unwrap();
    assert_eq!(
        s.records.keys().cloned().collect::<BTreeSet<_>>(),
        expected.ids.iter().cloned().collect()
    );
}

#[tokio::test]
async fn layout_mutations_fresh_equivalence_and_artifacts() {
    let db = db().await;
    record(
        &db,
        "04ee2b51-11d0-4a0d-bd5a-48e924340470",
        "Folder",
        "Collection",
        "folder",
        "native:root",
        "Folder body",
    )
    .await;
    record(
        &db,
        "108e2284-aaf4-422f-87b6-9b8a3bf6ae51",
        "Empty",
        "Collection",
        "folder",
        "native:root",
        "",
    )
    .await;
    record(
        &db,
        "4faa49c9-b5fc-4005-9b17-b17f5ef2a73b",
        "Folder",
        "Document",
        "note",
        "04ee2b51-11d0-4a0d-bd5a-48e924340470",
        "first",
    )
    .await;
    record(
        &db,
        "2ba92c86-9a36-43d6-8656-ffe48ca731e4",
        "folder",
        "Document",
        "note",
        "04ee2b51-11d0-4a0d-bd5a-48e924340470",
        "second",
    )
    .await;
    record(
        &db,
        "6dda7b6a-0d7a-45c5-a9bd-3e25678ad535",
        "Artifact",
        "Document",
        "artifact",
        "04ee2b51-11d0-4a0d-bd5a-48e924340470",
        "<html>unchanged</html>",
    )
    .await;
    crate::store::set_facet(
        &db,
        "6dda7b6a-0d7a-45c5-a9bd-3e25678ad535",
        serde_json::from_value(json!({"key":"runtime","value":"native.html.v1"})).unwrap(),
    )
    .await
    .unwrap();
    link(
        &db,
        "4faa49c9-b5fc-4005-9b17-b17f5ef2a73b",
        "6dda7b6a-0d7a-45c5-a9bd-3e25678ad535",
        "derived_from",
    )
    .await;
    let s = source(&db, "alice").await;
    let first = rendered(&s);
    let artifact_note = String::from_utf8_lossy(
        &first.files[&path_for(&first, "6dda7b6a-0d7a-45c5-a9bd-3e25678ad535")].bytes,
    );
    assert!(artifact_note.contains("\"facet.runtime\": \"native.html.v1\""));
    assert!(artifact_note.contains("\"native_projection_renderer\": \"native.markdown-vault.v1\""));
    assert!(!artifact_note.contains("\"facets\": {"));
    assert!(first.files.keys().any(|p| p.ends_with("Artifact.html")));
    assert!(first.directories.keys().any(|p| p.ends_with("/Empty")));
    assert!(!first.files.keys().any(|p| p.ends_with("Empty.md")));
    assert_ne!(
        path_for(&first, "4faa49c9-b5fc-4005-9b17-b17f5ef2a73b"),
        path_for(&first, "04ee2b51-11d0-4a0d-bd5a-48e924340470")
    );
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    for output in first.files.keys() {
        assert_eq!(
            std::fs::metadata(root.join(output))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
    }
    update_record(
        &db,
        "6dda7b6a-0d7a-45c5-a9bd-3e25678ad535",
        json!({"name":"Renamed artifact","home_id":"native:root"}),
    )
    .await
    .unwrap();
    for id in [
        "4faa49c9-b5fc-4005-9b17-b17f5ef2a73b",
        "2ba92c86-9a36-43d6-8656-ffe48ca731e4",
    ] {
        update_record(&db, id, json!({"home_id":"native:root"}))
            .await
            .unwrap();
    }
    archive_record(&db, "04ee2b51-11d0-4a0d-bd5a-48e924340470")
        .await
        .unwrap();
    // Production now forbids populated-folder archival. Seed a historical
    // projection anomaly after valid moves/archive to exercise read fallback.
    sqlx::query("UPDATE records SET home_id='04ee2b51-11d0-4a0d-bd5a-48e924340470' WHERE id='4faa49c9-b5fc-4005-9b17-b17f5ef2a73b'").execute(db.write_pool()).await.unwrap();
    let next = source(&db, "alice").await;
    let fresh = render::render(&next, &first.allocations).unwrap();
    p.cycle(&next).unwrap();
    let actual = disk(&root);
    for (path, output) in fresh.files {
        assert_eq!(actual[&path], output.bytes);
    }
    assert!(!root
        .join(path_for(&first, "6dda7b6a-0d7a-45c5-a9bd-3e25678ad535"))
        .exists());
    assert!(String::from_utf8_lossy(
        &actual[&path_for(
            &render::render(&next, &first.allocations).unwrap(),
            "4faa49c9-b5fc-4005-9b17-b17f5ef2a73b"
        )]
    )
    .contains("Renamed artifact"));
    let mut idle = next.clone();
    idle.act += 1;
    let idle_render = render::render(&idle, &first.allocations).unwrap();
    let next_render = render::render(&next, &first.allocations).unwrap();
    for (path, output) in idle_render.files {
        assert_eq!(next_render.files[&path].bytes, output.bytes);
    }
}

#[tokio::test]
async fn revocation_purges_edited_aggregates_companions_paths_and_state() {
    let db = db().await;
    record(
        &db,
        "9c10797d-45c3-471e-8255-6daf435669f8",
        "SENSITIVE FOLDER",
        "Collection",
        "folder",
        "native:root",
        "",
    )
    .await;
    record(
        &db,
        "9fc16585-83d0-4272-8929-0a9edb88f505",
        "SENSITIVE TARGET",
        "Document",
        "artifact",
        "9c10797d-45c3-471e-8255-6daf435669f8",
        "<html>secret bytes</html>",
    )
    .await;
    crate::store::set_facet(
        &db,
        "9fc16585-83d0-4272-8929-0a9edb88f505",
        serde_json::from_value(json!({"key":"runtime","value":"native.html.v1"})).unwrap(),
    )
    .await
    .unwrap();
    record(
        &db,
        "aa9fae65-ef25-4ac8-9a9a-c3c4ff0dc457",
        "Public",
        "Document",
        "note",
        "native:root",
        "safe body",
    )
    .await;
    record(
        &db,
        "1bce2987-6ae7-424a-a70e-7326a5daea00",
        "",
        "Annotation",
        "comment",
        "native:root",
        "SENSITIVE COMMENT",
    )
    .await;
    link(
        &db,
        "1bce2987-6ae7-424a-a70e-7326a5daea00",
        "aa9fae65-ef25-4ac8-9a9a-c3c4ff0dc457",
        "part_of",
    )
    .await;
    link(
        &db,
        "aa9fae65-ef25-4ac8-9a9a-c3c4ff0dc457",
        "9fc16585-83d0-4272-8929-0a9edb88f505",
        "derived_from",
    )
    .await;
    record(
        &db,
        "ee92129a-8a32-4397-878c-986edb6c765b",
        "",
        "Message",
        "note",
        "native:root",
        "SENSITIVE MESSAGE",
    )
    .await;
    let s = source(&db, "alice").await;
    let first = rendered(&s);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    let public = path_for(&first, "aa9fae65-ef25-4ac8-9a9a-c3c4ff0dc457");
    edit(&root.join(&public), "SENSITIVE TARGET locally edited");
    let artifact = first.files.keys().find(|p| p.ends_with(".html")).unwrap();
    edit(&root.join(artifact), "SENSITIVE ARTIFACT EDIT");
    for id in [
        "9c10797d-45c3-471e-8255-6daf435669f8",
        "ee92129a-8a32-4397-878c-986edb6c765b",
    ] {
        policy(&db, id, "bea").await;
    }
    // Comment authorization follows its bearer, not its own policy. Removing
    // its sole bearer edge revokes that derived record without hiding Public.
    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: "1bce2987-6ae7-424a-a70e-7326a5daea00".into(),
            target_id: "aa9fae65-ef25-4ac8-9a9a-c3c4ff0dc457".into(),
            relationship: "part_of".into(),
        },
    )
    .await
    .unwrap();
    let next = source(&db, "alice").await;
    assert!(!next
        .records
        .contains_key("9fc16585-83d0-4272-8929-0a9edb88f505"));
    assert!(!next
        .records
        .contains_key("1bce2987-6ae7-424a-a70e-7326a5daea00"));
    p.cycle(&next).unwrap();
    for (path, bytes) in disk(&root) {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!path.contains("SENSITIVE"), "{path}");
        assert!(!text.contains("SENSITIVE"), "{path}");
        for id in [
            "9c10797d-45c3-471e-8255-6daf435669f8",
            "9fc16585-83d0-4272-8929-0a9edb88f505",
            "1bce2987-6ae7-424a-a70e-7326a5daea00",
            "ee92129a-8a32-4397-878c-986edb6c765b",
        ] {
            assert!(!text.contains(id), "{path}: {id}");
        }
    }
    assert!(!std::fs::read_to_string(root.join(public))
        .unwrap()
        .contains("locally edited"));
}

#[tokio::test]
async fn durable_plan_keeps_old_contributors_across_crash_then_revocation() {
    let db = db().await;
    record(
        &db,
        "bcfbc252-4f6c-4138-82eb-be83199134b4",
        "Source",
        "Document",
        "note",
        "native:root",
        "body",
    )
    .await;
    record(
        &db,
        "3af828ab-55e3-43b2-b9f4-b52e3d8878c3",
        "Sensitive linked title",
        "Document",
        "note",
        "native:root",
        "target",
    )
    .await;
    link(
        &db,
        "bcfbc252-4f6c-4138-82eb-be83199134b4",
        "3af828ab-55e3-43b2-b9f4-b52e3d8878c3",
        "derived_from",
    )
    .await;
    let s = source(&db, "alice").await;
    let path = path_for(&rendered(&s), "bcfbc252-4f6c-4138-82eb-be83199134b4");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: "bcfbc252-4f6c-4138-82eb-be83199134b4".into(),
            target_id: "3af828ab-55e3-43b2-b9f4-b52e3d8878c3".into(),
            relationship: "derived_from".into(),
        },
    )
    .await
    .unwrap();
    let next = source(&db, "alice").await;
    publisher::FAIL_AFTER_PLAN.with(|f| f.set(true));
    assert!(p.cycle(&next).is_err());
    drop(p);
    assert!(std::fs::read_to_string(root.join(&path))
        .unwrap()
        .contains("Sensitive linked title"));
    policy(&db, "3af828ab-55e3-43b2-b9f4-b52e3d8878c3", "bea").await;
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&source(&db, "alice").await).unwrap();
    for (_, bytes) in disk(&root) {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("Sensitive linked title"));
        assert!(!text.contains("3af828ab-55e3-43b2-b9f4-b52e3d8878c3"));
    }
}

#[tokio::test]
async fn local_conflicts_foreign_files_and_symlink_revocation_obstructions() {
    let db = db().await;
    record(
        &db,
        "483a9e49-c514-4ba4-9067-9f30ba9e0819",
        "Note",
        "Document",
        "note",
        "native:root",
        "original",
    )
    .await;
    let s = source(&db, "alice").await;
    let r = rendered(&s);
    let path = path_for(&r, "483a9e49-c514-4ba4-9067-9f30ba9e0819");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    edit(&root.join(&path), "my edit");
    update_record(
        &db,
        "483a9e49-c514-4ba4-9067-9f30ba9e0819",
        json!({"body":"updated"}),
    )
    .await
    .unwrap();
    assert!(p
        .cycle(&source(&db, "alice").await)
        .unwrap()
        .contains(&path));
    assert_eq!(
        std::fs::read_to_string(root.join(&path)).unwrap(),
        "my edit"
    );
    edit(&root.join("README.md"), "user readme");
    assert!(p
        .cycle(&source(&db, "alice").await)
        .unwrap()
        .contains(&"README.md".into()));
    let parent = root.join(&path).parent().unwrap().to_path_buf();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_file(root.join(&path)).unwrap();
    let external = dir.path().join("outside");
    std::fs::write(&external, "outside untouched").unwrap();
    symlink(&external, root.join(&path)).unwrap();
    policy(&db, "483a9e49-c514-4ba4-9067-9f30ba9e0819", "bea").await;
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    assert_eq!(
        std::fs::read_to_string(external).unwrap(),
        "outside untouched"
    );
    let foreign = dir.path().join("foreign");
    std::fs::create_dir(&foreign).unwrap();
    std::fs::write(foreign.join("mine"), "mine").unwrap();
    assert!(Publisher::open(&foreign).is_err());
}

#[tokio::test]
async fn unicode_byte_limits_and_unsafe_titles_never_escape_root() {
    let db = db().await;
    for (id, title) in [
        (
            "9a56a8df-8316-414f-a624-a1d6b39a0683",
            "../../escape".to_owned(),
        ),
        (
            "a4975ebe-2cb0-4be5-aed9-9d4fd8561566",
            "/absolute\\x:*?\"<>|".into(),
        ),
        ("fe23d9e1-a5d9-4e3f-93bc-898b90ecd190", "界".repeat(150)),
        ("5de591c4-d1f9-4c35-925c-30f357a5971b", "界".repeat(80)),
        (
            "502abf81-27e6-4cbe-bc13-3e94d21ab3d9",
            "100%% reserved".into(),
        ),
        ("1727e041-cc0c-4f3a-833a-d704cd0e8ce0", "e\u{301}".into()),
        ("371efabf-2dcd-496a-8470-69ff628feea4", "É".into()),
        ("752402d6-d945-4488-83c8-ebe8ec307571", "Straße".into()),
        ("43467b13-3217-4a1b-9a79-263607401436", "STRASSE".into()),
    ] {
        record(&db, id, &title, "Document", "note", "native:root", "body").await;
    }
    let s = source(&db, "alice").await;
    let r = rendered(&s);
    for path in r.files.keys() {
        for part in path.split('/') {
            assert!(part.len() <= 255);
            assert!(!matches!(part, "." | ".."));
            assert!(!part.starts_with('.'));
        }
    }
    assert_ne!(
        unicase::UniCase::new(path_for(&r, "752402d6-d945-4488-83c8-ebe8ec307571")),
        unicase::UniCase::new(path_for(&r, "43467b13-3217-4a1b-9a79-263607401436"))
    );
    assert!(path_for(&r, "5de591c4-d1f9-4c35-925c-30f357a5971b")
        .ends_with(&format!("{}.md", "界".repeat(80))));
    assert!(!path_for(&r, "502abf81-27e6-4cbe-bc13-3e94d21ab3d9").contains("%%"));
    let a = path_for(&r, "1727e041-cc0c-4f3a-833a-d704cd0e8ce0");
    let b = path_for(&r, "371efabf-2dcd-496a-8470-69ff628feea4");
    assert_ne!(a.to_lowercase(), b.to_lowercase());
}

#[tokio::test]
async fn creator_author_is_disclosed_independently_of_owner_and_pool_history() {
    let db = db().await;
    record(
        &db,
        "a6595e3b-6e5f-4287-91c2-42b3cadb993e",
        "Alice creator",
        "Entity",
        "person",
        "native:root",
        "",
    )
    .await;
    record(
        &db,
        "0d4488c9-5b97-4c7f-8dd7-1a1d5f8b17a5",
        "BEA HIDDEN IDENTITY",
        "Entity",
        "person",
        "native:root",
        "",
    )
    .await;
    policy(&db, "0d4488c9-5b97-4c7f-8dd7-1a1d5f8b17a5", "bea").await;
    for (account, id) in [
        ("alice", "a6595e3b-6e5f-4287-91c2-42b3cadb993e"),
        ("bea", "0d4488c9-5b97-4c7f-8dd7-1a1d5f8b17a5"),
    ] {
        sqlx::query("INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?1,'account',?2,1)").bind(id).bind(account).execute(db.write_pool()).await.unwrap();
    }
    record(
        &db,
        "e0227bcb-752b-4ed8-bd18-4aae31e4263c",
        "Target",
        "Document",
        "note",
        "native:root",
        "body",
    )
    .await;
    record(
        &db,
        "849fe4ac-0e33-40e9-97d3-19a7215ebe02",
        "",
        "Annotation",
        "comment",
        "native:root",
        "Alice comment",
    )
    .await;
    create_record_as(&db,json!({"id":"1f25ae0e-00b5-43fd-a765-dfc09f94e3cb","type":"Annotation","kind":"comment","body":"Bea comment","home_id":"native:root"}),Some("bea")).await.unwrap();
    for id in [
        "849fe4ac-0e33-40e9-97d3-19a7215ebe02",
        "1f25ae0e-00b5-43fd-a765-dfc09f94e3cb",
    ] {
        link(&db, id, "e0227bcb-752b-4ed8-bd18-4aae31e4263c", "part_of").await;
    }
    update_record(
        &db,
        "849fe4ac-0e33-40e9-97d3-19a7215ebe02",
        json!({"owner_id":"0d4488c9-5b97-4c7f-8dd7-1a1d5f8b17a5"}),
    )
    .await
    .unwrap();
    let bea = source(&db, "bea").await;
    assert_eq!(
        bea.records["1f25ae0e-00b5-43fd-a765-dfc09f94e3cb"].metadata["author"],
        "0d4488c9-5b97-4c7f-8dd7-1a1d5f8b17a5"
    );
    let alice = source(&db, "alice").await;
    assert_eq!(
        alice.records["849fe4ac-0e33-40e9-97d3-19a7215ebe02"].metadata["author"],
        "a6595e3b-6e5f-4287-91c2-42b3cadb993e"
    );
    assert!(!alice.records["1f25ae0e-00b5-43fd-a765-dfc09f94e3cb"]
        .metadata
        .contains_key("author"));
    assert!(!alice.records["849fe4ac-0e33-40e9-97d3-19a7215ebe02"]
        .metadata
        .contains_key("owner"));
    let r = rendered(&alice);
    let body = String::from_utf8_lossy(
        &r.files[&path_for(&r, "e0227bcb-752b-4ed8-bd18-4aae31e4263c")].bytes,
    );
    assert!(body.contains("Alice creator"));
    assert!(!body.contains("BEA HIDDEN IDENTITY"));
    assert!(!body.contains("0d4488c9-5b97-4c7f-8dd7-1a1d5f8b17a5"));
}

#[tokio::test]
async fn revoked_directory_with_foreign_note_fails_visibly_and_freshness_ticks() {
    let db = db().await;
    record(
        &db,
        "89b26a50-18f3-4857-a28a-73784521e403",
        "Private folder title",
        "Collection",
        "folder",
        "native:root",
        "",
    )
    .await;
    let mut s = source(&db, "alice").await;
    let r = rendered(&s);
    let folder = r
        .directories
        .keys()
        .find(|p| p.ends_with("Private folder title"))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    let before = std::fs::read(root.join(".native/STATUS.md")).unwrap();
    s.freshness = json!({"freshness":{"age_seconds":301,"beyond_rpo":true}});
    p.status(&s, &[]).unwrap();
    let status = std::fs::read(root.join(".native/STATUS.md")).unwrap();
    assert_ne!(before, status);
    let before_text = String::from_utf8_lossy(&before);
    let after_text = String::from_utf8_lossy(&status);
    assert_eq!(
        before_text.lines().find(|l| l.starts_with("Rendered at:")),
        after_text.lines().find(|l| l.starts_with("Rendered at:"))
    );
    p.unavailable("fixture failure").unwrap();
    let failed = std::fs::read_to_string(root.join(".native/STATUS.md")).unwrap();
    assert!(failed.contains("unavailable / current cycle failed"));
    assert_eq!(
        before_text
            .lines()
            .find(|l| l.starts_with("Last successful content act:")),
        failed
            .lines()
            .find(|l| l.starts_with("Last successful content act:"))
    );

    assert!(String::from_utf8_lossy(&status).contains("beyond_rpo\":true"));
    std::fs::set_permissions(root.join(folder), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join(folder).join("mine.md"), "user note").unwrap();
    policy(&db, "89b26a50-18f3-4857-a28a-73784521e403", "bea").await;
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    assert_eq!(
        std::fs::read_to_string(root.join(folder).join("mine.md")).unwrap(),
        "user note"
    );
}

#[tokio::test]
async fn interrupted_initial_and_nested_folder_plans_recover_and_clean_temps() {
    let db = db().await;
    record(
        &db,
        "900ad220-c096-4dea-b9c5-3ba17256b6c3",
        "Initial",
        "Document",
        "note",
        "native:root",
        "body",
    )
    .await;
    let s = source(&db, "alice").await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    publisher::FAIL_AFTER_PLAN.with(|f| f.set(true));
    assert!(p.cycle(&s).is_err());
    drop(p);
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    record(
        &db,
        "b2cba3e5-44d1-443e-8451-062a4de15071",
        "New parent",
        "Collection",
        "folder",
        "native:root",
        "",
    )
    .await;
    record(
        &db,
        "1515c271-26a0-439f-8725-b30e774648c9",
        "New nested",
        "Collection",
        "folder",
        "b2cba3e5-44d1-443e-8451-062a4de15071",
        "",
    )
    .await;
    update_record(
        &db,
        "900ad220-c096-4dea-b9c5-3ba17256b6c3",
        json!({"home_id":"1515c271-26a0-439f-8725-b30e774648c9"}),
    )
    .await
    .unwrap();
    let next = source(&db, "alice").await;
    publisher::FAIL_AFTER_PLAN.with(|f| f.set(true));
    assert!(p.cycle(&next).is_err());
    drop(p);
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&next).unwrap();
    drop(p);
    let r = rendered(&next);
    let nested = root
        .join(path_for(&r, "900ad220-c096-4dea-b9c5-3ba17256b6c3"))
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join(".native-vault-tmp-root"), "stray").unwrap();
    std::fs::write(nested.join(".native-vault-tmp-nested"), "stray").unwrap();
    let _p = Publisher::open(&root).unwrap();
    assert!(!root.join(".native-vault-tmp-root").exists());
    assert!(!nested.join(".native-vault-tmp-nested").exists());
}

#[tokio::test]
async fn canonical_owner_binding_and_other_members_private_home_are_not_bypassed() {
    let db = db().await;
    for (person, account, name) in [
        (
            "734bb1e8-3d69-470c-ae39-8b8335042299",
            "alice",
            "Workspace owner",
        ),
        (
            "97aaa36c-3fba-4e8a-ae12-2bfd7e36f42e",
            "bea",
            "Other member",
        ),
    ] {
        record(&db, person, name, "Entity", "person", "native:root", "").await;
        sqlx::query("INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?1,'account',?2,1)").bind(person).bind(account).execute(db.write_pool()).await.unwrap();
    }
    for (home, person, title) in [
        (
            "33cbad0d-402f-49c6-bc31-22bdbbe268e3",
            "734bb1e8-3d69-470c-ae39-8b8335042299",
            "Owner private context",
        ),
        (
            "0f584132-2dbc-45ed-8ab3-21a757ce284a",
            "97aaa36c-3fba-4e8a-ae12-2bfd7e36f42e",
            "Other member private context",
        ),
    ] {
        record(&db, home, title, "Collection", "folder", "native:root", "").await;
        update_record(&db, home, json!({"owner_id":person}))
            .await
            .unwrap();
        replace_explicit_policy(&db, "fixture", home, vec![])
            .await
            .unwrap();
        let note = fixture_id(&format!("{home}-note"));
        record(
            &db,
            &note,
            &format!("{title} note"),
            "Document",
            "note",
            home,
            "private body",
        )
        .await;
        update_record(&db, &note, json!({"owner_id":person}))
            .await
            .unwrap();
    }
    // Local-owner marker carries no trusted-local read bypass.
    let owner: QueryPrincipal = (&crate::mcp::Caller::local_owner("alice")).into();
    let member: QueryPrincipal = (&crate::mcp::Caller::authenticated("bea")).into();
    for (principal, own, hidden) in [
        (
            owner,
            "33cbad0d-402f-49c6-bc31-22bdbbe268e3",
            "0f584132-2dbc-45ed-8ab3-21a757ce284a",
        ),
        (
            member,
            "0f584132-2dbc-45ed-8ab3-21a757ce284a",
            "33cbad0d-402f-49c6-bc31-22bdbbe268e3",
        ),
    ] {
        let snapshot = crate::query::sql::projection_snapshot(&db, principal)
            .await
            .unwrap();
        assert!(snapshot.records.contains_key(own));
        assert!(snapshot
            .records
            .contains_key(&fixture_id(&format!("{own}-note"))));
        assert!(!snapshot.records.contains_key(hidden));
        assert!(!snapshot
            .records
            .contains_key(&fixture_id(&format!("{hidden}-note"))));
    }
}

#[tokio::test]
async fn quoted_threaded_comments_and_monthly_message_collisions() {
    let db = db().await;
    record(
        &db,
        "989e00d6-2fd1-469c-9a06-13e40601b54c",
        "Target",
        "Document",
        "note",
        "native:root",
        "Quoted passage",
    )
    .await;
    record(
        &db,
        "0c6af9fd-a3f8-48fa-9cac-2fdd1a1d2906",
        "",
        "Annotation",
        "comment",
        "native:root",
        "root comment",
    )
    .await;
    link(
        &db,
        "0c6af9fd-a3f8-48fa-9cac-2fdd1a1d2906",
        "989e00d6-2fd1-469c-9a06-13e40601b54c",
        "part_of",
    )
    .await;
    record(
        &db,
        "1743371c-5001-40d7-ba6b-20bdbe26cc25",
        "",
        "Annotation",
        "comment",
        "native:root",
        "nested reply",
    )
    .await;
    link(
        &db,
        "1743371c-5001-40d7-ba6b-20bdbe26cc25",
        "0c6af9fd-a3f8-48fa-9cac-2fdd1a1d2906",
        "part_of",
    )
    .await;
    sqlx::query("INSERT INTO annotation_targets(annotation_id,target_record_id,source_slot,source_event_seq,source_sha256,selectors,created_at,updated_at) VALUES ('0c6af9fd-a3f8-48fa-9cac-2fdd1a1d2906','989e00d6-2fd1-469c-9a06-13e40601b54c','body',1,?1,?2,'2026-01-01','2026-01-01')").bind("0".repeat(64)).bind(json!([{"type":"text_quote","exact":"Quoted passage"},{"type":"data_position","start":0,"end":14}]).to_string()).execute(db.write_pool()).await.unwrap();
    for (home, title) in [
        ("58588319-41be-4e4b-bbb6-99b6eca9caa5", "Conversation"),
        ("44a1cc4e-3096-4c6c-896d-569337ef7826", "conversation"),
        (
            "147827fa-198d-4dd3-83d1-7a9b5dd95b36",
            "conversation (message-1)",
        ),
    ] {
        record(&db, home, title, "Collection", "folder", "native:root", "").await;
    }
    for n in 0..6 {
        let id = fixture_id(&format!("monthly-message-{n}"));
        record(
            &db,
            &id,
            "",
            "Message",
            "note",
            "58588319-41be-4e4b-bbb6-99b6eca9caa5",
            &"m".repeat(200_000),
        )
        .await;
        // Fixture clock mutation only; collector must preserve source order.
        sqlx::query("UPDATE records SET created_at=? WHERE id=?")
            .bind(if n < 3 {
                "2026-01-15T12:00:00Z"
            } else {
                "2026-02-15T12:00:00Z"
            })
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    for home in [
        "44a1cc4e-3096-4c6c-896d-569337ef7826",
        "147827fa-198d-4dd3-83d1-7a9b5dd95b36",
    ] {
        record(
            &db,
            &format!("{home}-message"),
            "",
            "Message",
            "note",
            home,
            "small message",
        )
        .await;
    }
    let s = source(&db, "alice").await;
    let r = rendered(&s);
    let target = String::from_utf8_lossy(
        &r.files[&path_for(&r, "989e00d6-2fd1-469c-9a06-13e40601b54c")].bytes,
    );
    assert!(target.contains("> Quoted passage"));
    assert!(target.contains("  - Unknown author"));
    assert!(target.contains("    nested reply"));
    assert!(!target.contains("data_position"));
    let message_paths: Vec<_> = r
        .files
        .keys()
        .filter(|p| p.starts_with("Messages/"))
        .collect();
    assert_eq!(message_paths.len(), 4);
    assert!(message_paths.iter().any(|p| p.contains("2026-01")));
    assert!(message_paths.iter().any(|p| p.contains("2026-02")));
    let folded: BTreeSet<_> = message_paths.iter().map(|p| p.to_lowercase()).collect();
    assert_eq!(folded.len(), message_paths.len());
}

#[test]
fn audit_tick_is_bounded_and_status_copy_has_no_content() {
    use std::time::Duration;
    let mut source = SourceSnapshot {
        act: 7,
        generation: "g".into(),
        ..Default::default()
    };
    source.records.insert(
        "body".into(),
        SourceRecord {
            body: Some("large".repeat(100_000)),
            ..Default::default()
        },
    );
    let status = source.status_only();
    assert!(status.records.is_empty());
    assert!(!needs_projection(
        Some(&status),
        7,
        "g",
        Duration::from_secs(299)
    ));
    assert!(needs_projection(
        Some(&status),
        7,
        "g",
        Duration::from_secs(300)
    ));
    assert!(needs_projection(Some(&status), 8, "g", Duration::ZERO));
    assert!(needs_projection(
        Some(&status),
        7,
        "new-generation",
        Duration::ZERO
    ));
    assert_eq!(short("native:root"), "native:root");
}

#[tokio::test]
async fn renamed_folder_note_and_artifact_extensions_disambiguate_emitted_names() {
    let db = db().await;
    record(
        &db,
        "29dedc52-90c5-4bd1-a9ec-30902d5c41c4",
        "Old folder",
        "Collection",
        "folder",
        "native:root",
        "folder body",
    )
    .await;
    record(
        &db,
        "394ca536-3878-4be7-ad8d-c3193a97084b",
        "New title",
        "Document",
        "note",
        "29dedc52-90c5-4bd1-a9ec-30902d5c41c4",
        "child body",
    )
    .await;
    record(
        &db,
        "5bdcd09c-445a-45fb-8465-54472c23b49a",
        "A",
        "Document",
        "artifact",
        "native:root",
        "html",
    )
    .await;
    crate::store::set_facet(
        &db,
        "5bdcd09c-445a-45fb-8465-54472c23b49a",
        serde_json::from_value(json!({"key":"runtime","value":"native.html.v1"})).unwrap(),
    )
    .await
    .unwrap();
    record(
        &db,
        "90000000-0000-4000-8000-000000000001",
        "A.md",
        "Document",
        "artifact",
        "native:root",
        "second html",
    )
    .await;
    crate::store::set_facet(
        &db,
        "90000000-0000-4000-8000-000000000001",
        serde_json::from_value(json!({"key":"runtime","value":"native.html.v1"})).unwrap(),
    )
    .await
    .unwrap();
    let first = rendered(&source(&db, "alice").await);
    update_record(
        &db,
        "29dedc52-90c5-4bd1-a9ec-30902d5c41c4",
        json!({"name":"New title"}),
    )
    .await
    .unwrap();
    record(
        &db,
        "f64b91d8-9c91-40db-a0ae-5ebe5f1d9587",
        "A.html",
        "Collection",
        "folder",
        "native:root",
        "",
    )
    .await;
    let next = source(&db, "alice").await;
    let r = render::render(&next, &first.allocations).unwrap();
    assert_ne!(
        path_for(&r, "29dedc52-90c5-4bd1-a9ec-30902d5c41c4"),
        path_for(&r, "394ca536-3878-4be7-ad8d-c3193a97084b")
    );
    assert_eq!(
        r.files
            .iter()
            .filter(|(path, _)| path.ends_with(".html"))
            .count(),
        2
    );
    assert!(r
        .files
        .iter()
        .any(|(path, out)| path.ends_with("/A.html") && out.bytes == b"html"));
    assert!(r
        .files
        .iter()
        .any(|(path, out)| path.ends_with("/A.md.html") && out.bytes == b"second html"));
    for file in r.files.keys() {
        assert!(!r.directories.contains_key(file));
    }
    let dir = tempfile::tempdir().unwrap();
    let mut p = Publisher::open(&dir.path().join("vault")).unwrap();
    p.cycle(&next).unwrap();
}

#[tokio::test]
async fn symlink_ancestors_and_edited_control_state_refuse_publication() {
    let db = db().await;
    record(
        &db,
        "7cae492c-4210-49ad-a94e-8c2370502509",
        "Note",
        "Document",
        "note",
        "native:root",
        "body",
    )
    .await;
    let s = source(&db, "alice").await;
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let alias = dir.path().join("alias");
    symlink(&outside, &alias).unwrap();
    assert!(Publisher::open(&alias.join("vault")).is_err());
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    let state = root.join(".native/state.json");
    std::fs::write(&state, "local state edit").unwrap();
    assert!(p.cycle(&s).is_err());
    assert_eq!(std::fs::read_to_string(&state).unwrap(), "local state edit");
    drop(p);
    assert!(Publisher::open(&root).is_err());
}

#[tokio::test]
async fn initial_open_is_durably_owned_before_any_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    drop(Publisher::open(&root).unwrap());
    assert!(root.join(".native/state.json").is_file());
    let mut p = Publisher::open(&root).unwrap();
    let db = db().await;
    p.cycle(&source(&db, "alice").await).unwrap();
    let foreign = dir.path().join("foreign");
    std::fs::create_dir_all(foreign.join(".native")).unwrap();
    assert!(Publisher::open(&foreign).is_err());
    assert!(!foreign.join(".native/state.json").exists());
}

#[tokio::test]
async fn repeated_interrupted_plans_keep_every_possible_content_digest() {
    let db = db().await;
    record(
        &db,
        "67e29680-149b-46d6-8327-22a97116b663",
        "Note",
        "Document",
        "note",
        "native:root",
        "D0",
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    let s = source(&db, "alice").await;
    let path = path_for(&rendered(&s), "67e29680-149b-46d6-8327-22a97116b663");
    p.cycle(&s).unwrap();
    update_record(
        &db,
        "67e29680-149b-46d6-8327-22a97116b663",
        json!({"body":"D1"}),
    )
    .await
    .unwrap();
    publisher::FAIL_AFTER_WRITES.with(|f| f.set(true));
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    drop(p);
    assert!(std::fs::read_to_string(root.join(&path))
        .unwrap()
        .contains("D1"));
    update_record(
        &db,
        "67e29680-149b-46d6-8327-22a97116b663",
        json!({"body":"D2"}),
    )
    .await
    .unwrap();
    let mut p = Publisher::open(&root).unwrap();
    publisher::FAIL_AFTER_PLAN.with(|f| f.set(true));
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    drop(p);
    let mut p = Publisher::open(&root).unwrap();
    let conflicts = p.cycle(&source(&db, "alice").await).unwrap();
    assert!(conflicts.is_empty(), "{conflicts:?}");
    assert!(std::fs::read_to_string(root.join(path))
        .unwrap()
        .contains("D2"));
}

#[tokio::test]
async fn directory_sync_failure_and_failure_status_keep_revocable_prior_bytes() {
    let db = db().await;
    record(
        &db,
        "cc1e55a0-defe-4c46-91fb-56c9239baa51",
        "Source",
        "Document",
        "note",
        "native:root",
        "safe",
    )
    .await;
    record(
        &db,
        "7ab17b4d-63a5-4148-a0f7-0080ca4064d2",
        "Sensitive pre-sync endpoint",
        "Document",
        "note",
        "native:root",
        "target",
    )
    .await;
    link(
        &db,
        "cc1e55a0-defe-4c46-91fb-56c9239baa51",
        "7ab17b4d-63a5-4148-a0f7-0080ca4064d2",
        "derived_from",
    )
    .await;
    let s = source(&db, "alice").await;
    let r = rendered(&s);
    let path = path_for(&r, "cc1e55a0-defe-4c46-91fb-56c9239baa51");
    let prior = r.files[&path].bytes.clone();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&s).unwrap();
    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: "cc1e55a0-defe-4c46-91fb-56c9239baa51".into(),
            target_id: "7ab17b4d-63a5-4148-a0f7-0080ca4064d2".into(),
            relationship: "derived_from".into(),
        },
    )
    .await
    .unwrap();
    publisher::FAIL_AFTER_WRITES.with(|f| f.set(true));
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    p.unavailable("directory sync failed").unwrap();
    let attempts = publisher::DIRECTORY_SYNC_ATTEMPTS.with(|count| count.get());
    let unchanged = std::fs::read(root.join(&path)).unwrap();
    publisher::FAIL_NEXT_DIRECTORY_SYNC.with(|flag| flag.set(true));
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    assert!(publisher::DIRECTORY_SYNC_ATTEMPTS.with(|count| count.get()) > attempts);
    assert_eq!(std::fs::read(root.join(&path)).unwrap(), unchanged);
    p.unavailable("unchanged retry sync failed").unwrap();
    let journal: Value =
        serde_json::from_slice(&std::fs::read(root.join(".native/state.json")).unwrap()).unwrap();
    assert!(journal["dirty_directories"]
        .as_array()
        .is_some_and(|dirs| !dirs.is_empty()));
    assert!(journal["files"][&path]["contributors"]
        .as_array()
        .unwrap()
        .contains(&json!("7ab17b4d-63a5-4148-a0f7-0080ca4064d2")));
    drop(p);
    // Simulate a power loss resurrecting the old directory entry, rather than
    // treating an ordinary digest conflict as evidence it is safe to preserve.
    std::fs::set_permissions(root.join(&path), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(root.join(&path), prior).unwrap();
    policy(&db, "7ab17b4d-63a5-4148-a0f7-0080ca4064d2", "bea").await;
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&source(&db, "alice").await).unwrap();
    for (_, bytes) in disk(&root) {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("Sensitive pre-sync endpoint"));
        assert!(!text.contains("7ab17b4d-63a5-4148-a0f7-0080ca4064d2"));
    }
}

#[tokio::test]
async fn missing_unlink_retry_flushes_parent_before_forgetting_revoked_metadata() {
    let db = db().await;
    let id = "91000000-0000-4000-8000-000000000001";
    record(
        &db,
        id,
        "Revoked",
        "Document",
        "note",
        "native:root",
        "private bytes",
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut p = Publisher::open(&root).unwrap();
    p.cycle(&source(&db, "alice").await).unwrap();
    policy(&db, id, "bea").await;
    publisher::FAIL_NEXT_DIRECTORY_SYNC.with(|flag| flag.set(true));
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    // STATUS sorts first in the revocation set and its unlink happened, but
    // its parent was not synced and its contributor ledger must remain.
    assert!(!root.join(".native/STATUS.md").exists());
    drop(p);
    let mut p = Publisher::open(&root).unwrap();
    let attempts = publisher::DIRECTORY_SYNC_ATTEMPTS.with(|count| count.get());
    publisher::FAIL_NEXT_DIRECTORY_SYNC.with(|flag| flag.set(true));
    assert!(p.cycle(&source(&db, "alice").await).is_err());
    assert!(publisher::DIRECTORY_SYNC_ATTEMPTS.with(|count| count.get()) > attempts);
    p.cycle(&source(&db, "alice").await).unwrap();
    for (_, bytes) in disk(&root) {
        assert!(!String::from_utf8_lossy(&bytes).contains(id));
    }
}

#[tokio::test]
async fn generated_readme_names_the_off_switch() {
    let db = db().await;
    record(
        &db,
        "readme-fixture",
        "Fixture",
        "Document",
        "note",
        "native:root",
        "body",
    )
    .await;
    let first = rendered(&source(&db, "alice").await);
    let readme = String::from_utf8_lossy(&first.files["README.md"].bytes);
    assert!(
        readme.contains(r#""markdown_folder": false"#),
        "generated README must name the off switch: {readme}"
    );
}

#[test]
fn diagnostic_fields_stay_single_line_and_bounded() {
    assert_eq!(diag_field(&"/tmp/node/vault", 80), "/tmp/node/vault");
    assert_eq!(
        diag_field(&"a\nb\rc\td\x01e\x7f", 80),
        "a\\nb\\rc\\td\\u0001e\\u007f"
    );
    assert_eq!(diag_field(&"café", 80), "caf\\u00e9");
    assert_eq!(diag_field(&"x".repeat(100), 10), "x".repeat(10));
    assert!(diag_field(&"/vault", 0).is_empty());
}
