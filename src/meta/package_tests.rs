//! Gated S2a package-install tests: one-transaction install, exact retry,
//! collision refusal, atomicity, verified reads, and replay equivalence.
//! Nothing here touches production DDL, migrations, events, or tools.

use crate::db::{begin_write, create_database, Db};
use crate::definition_registry::ensure_registry_tables;
use crate::meta::package::{
    ensure_package_tables, install_package_in, package_subject, read_package_in,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor,
};

type PackageArtifactRow = (String, String, String, i64, String, String, i64, String);

fn def_bytes(family: &str, version: u32, kinds: &str) -> String {
    format!(r#"{{"family":"{family}","version":{version},"kinds":{kinds}}}"#)
}

fn entry(family: &str, kinds: &str) -> DefinitionEntry {
    let bytes = def_bytes(family, 1, kinds);
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: family.to_string(),
        version: 1,
        artifact_bytes: bytes,
        digest,
    }
}

fn manifest(namespace: &str, name: &str, entries: Vec<DefinitionEntry>) -> PackageManifest {
    PackageManifest {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version: 1,
        definitions: entries,
        behaviour: Some(BehaviourDescriptor {
            kind: crate::package_manifest::BEHAVIOUR_KIND.to_string(),
            reads: vec!["linked_record:view".to_string()],
            effects: vec![],
        }),
        surface: Some(SurfaceDescriptor {
            kind: crate::package_manifest::SURFACE_KIND.to_string(),
            view: "pack.view".to_string(),
            fallback: "pack.unavailable".to_string(),
        }),
        declared_reads: vec!["linked_record:view".to_string()],
    }
}

async fn test_db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    ensure_registry_tables(&db).await.unwrap();
    ensure_package_tables(&db).await.unwrap();
    db
}

async fn install(
    db: &Db,
    manifest: &PackageManifest,
) -> Result<crate::package_manifest::ManifestIdentity, crate::error::Error> {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let outcome =
        install_package_in(&mut tx, manifest, Some("test:installer"), &mut allocation).await;
    match outcome {
        Ok(outcome) => {
            tx.commit().await.unwrap();
            Ok(outcome.identity)
        }
        Err(e) => {
            tx.rollback().await.unwrap();
            Err(e)
        }
    }
}

async fn meta_count(db: &Db, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM meta_events WHERE type = ?")
        .bind(event_type)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

async fn table_count(db: &Db, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

/// Insert a forged meta event row directly, bypassing the folding write path
/// (which would already refuse it at append). Replay of the poisoned log must
/// then fail instead of projecting a lying row.
async fn poison_log(db: &Db, subject: &str, event_type: &str, payload: serde_json::Value) {
    sqlx::query(
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at)
          VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(format!("evt-forged-{subject}"))
    .bind(subject)
    .bind(event_type)
    .bind(serde_json::to_string(&payload).unwrap())
    .bind("test:forger")
    .bind("2026-09-26T00:00:00.000Z")
    .execute(db.write_pool())
    .await
    .unwrap();
}

/// Pristine replay target: DDL only, no seeds, so replayed seed events cannot
/// collide with pre-seeded rows (unlike `create_database`).
async fn pristine_db() -> Db {
    let fresh = crate::db::open_database(":memory:").await.unwrap();
    crate::db::apply_schema(&fresh).await.unwrap();
    ensure_registry_tables(&fresh).await.unwrap();
    ensure_package_tables(&fresh).await.unwrap();
    fresh
}

#[tokio::test]
async fn exact_retry_appends_nothing() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let first = install(&db, &m).await.unwrap();
    assert_eq!(meta_count(&db, "package_artifact.installed.v1").await, 1);
    assert_eq!(meta_count(&db, "definition_artifact.installed").await, 1);
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut allocation = crate::act::ActAllocation::new();
    let outcome = install_package_in(&mut tx, &m, Some("test:installer"), &mut allocation)
        .await
        .unwrap();
    assert_eq!(outcome.identity, first);
    tx.commit().await.unwrap();
    assert_eq!(meta_count(&db, "package_artifact.installed.v1").await, 1);
    assert_eq!(meta_count(&db, "definition_artifact.installed").await, 1);
    assert_eq!(table_count(&db, "package_artifacts").await, 1);
    db.close().await;
}

#[tokio::test]
async fn same_triple_different_digest_refuses_before_append() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    install(&db, &m).await.unwrap();
    let before_package = meta_count(&db, "package_artifact.installed.v1").await;
    let before_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let mut rival = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    rival.surface.as_mut().unwrap().fallback = "pack.empty".to_string();
    let err = install(&db, &rival).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("already installed with a different digest"),
        "{err}"
    );
    assert_eq!(
        meta_count(&db, "package_artifact.installed.v1").await,
        before_package
    );
    let after_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(before_total, after_total);
    db.close().await;
}

#[tokio::test]
async fn missing_projection_with_prior_event_refuses_reinstall() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    install(&db, &m).await.unwrap();
    sqlx::query("DELETE FROM package_artifacts WHERE namespace = 'acme'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let err = install(&db, &m).await.unwrap_err();
    assert!(
        err.to_string().contains("projection/log disagreement"),
        "{err}"
    );
    assert_eq!(meta_count(&db, "package_artifact.installed.v1").await, 1);
    db.close().await;
}

#[tokio::test]
async fn two_packages_share_one_definition_event() {
    let db = test_db().await;
    let shared = entry("demo.shared", r#"["s"]"#);
    let a = manifest("acme", "aaa", vec![shared.clone()]);
    let b = manifest("acme", "bbb", vec![shared]);
    install(&db, &a).await.unwrap();
    install(&db, &b).await.unwrap();
    assert_eq!(meta_count(&db, "package_artifact.installed.v1").await, 2);
    assert_eq!(meta_count(&db, "definition_artifact.installed").await, 1);
    assert_eq!(table_count(&db, "package_artifacts").await, 2);
    assert_eq!(table_count(&db, "definition_artifacts").await, 1);
    db.close().await;
}

#[tokio::test]
async fn invalid_member_leaves_no_partial_state() {
    let db = test_db().await;
    let mut bad = entry("demo.broken", r#"["b"]"#);
    bad.digest = "0".repeat(64);
    let m = manifest(
        "acme",
        "notes",
        vec![entry("demo.notes", r#"["note"]"#), bad],
    );
    let err = install(&db, &m).await.unwrap_err();
    assert!(err.to_string().contains("digest must equal"), "{err}");
    assert_eq!(table_count(&db, "package_artifacts").await, 0);
    assert_eq!(table_count(&db, "definition_artifacts").await, 0);
    assert_eq!(meta_count(&db, "package_artifact.installed.v1").await, 0);
    assert_eq!(meta_count(&db, "definition_artifact.installed").await, 0);
    db.close().await;
}

#[tokio::test]
async fn cross_package_byte_conflict_is_atomic() {
    let db = test_db().await;
    let a = manifest("acme", "aaa", vec![entry("demo.shared", r#"["a"]"#)]);
    install(&db, &a).await.unwrap();
    let rival_entry = entry("demo.shared", r#"["b"]"#);
    let b = manifest("acme", "bbb", vec![rival_entry]);
    let err = install(&db, &b).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("already installed with different bytes"),
        "{err}"
    );
    assert_eq!(table_count(&db, "package_artifacts").await, 1);
    assert_eq!(meta_count(&db, "package_artifact.installed.v1").await, 1);
    let stored: String = sqlx::query_scalar(
        "SELECT artifact_bytes FROM definition_artifacts WHERE family = 'demo.shared'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(stored, def_bytes("demo.shared", 1, r#"["a"]"#));
    db.close().await;
}

fn defn2_bytes() -> String {
    serde_json::json!({
        "family": "demo.thing", "version": 1,
        "interpreter": "native.defn/2", "primary_type": "thing",
        "kinds": [{"token": "note",
            "fields": [{"name": "title", "type": "text", "required": true}],
            "identity": {"field": "title"}, "links": [],
            "maturity": "current", "description": "A note."}],
    })
    .to_string()
}

fn defn2_entry() -> DefinitionEntry {
    let bytes = defn2_bytes();
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: "demo.thing".to_string(),
        version: 1,
        artifact_bytes: bytes,
        digest,
    }
}

#[tokio::test]
async fn unknown_interpreter_refused_and_valid_defn2_passes() {
    let db = test_db().await;
    let evil_bytes = def_bytes("demo.evil", 1, r#"["e"]"#).replace(
        r#"{"family":"demo.evil""#,
        r#"{"interpreter":"native.evil/9","family":"demo.evil""#,
    );
    let evil_digest =
        crate::meta::definition_artifact::digest_artifact_bytes(evil_bytes.as_bytes());
    let evil = DefinitionEntry {
        family: "demo.evil".to_string(),
        version: 1,
        artifact_bytes: evil_bytes,
        digest: evil_digest,
    };
    let err = install(&db, &manifest("acme", "evil", vec![evil]))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("unknown definition interpreter"),
        "{err}"
    );
    assert_eq!(table_count(&db, "package_artifacts").await, 0);
    let identity = install(&db, &manifest("acme", "good", vec![defn2_entry()]))
        .await
        .unwrap();
    assert_eq!(identity.name, "good");
    assert_eq!(table_count(&db, "package_artifacts").await, 1);
    db.close().await;
}

#[tokio::test]
async fn verified_read_asserts_projection_log_agreement() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let identity = install(&db, &m).await.unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let stored = read_package_in(&mut conn, "acme", "notes", 1, &identity.digest)
        .await
        .unwrap()
        .expect("installed package reads back");
    assert_eq!(stored.identity, identity);
    assert_eq!(stored.manifest.package_digest().unwrap(), identity.digest);
    assert!(stored.event_seq >= 1);
    assert!(
        read_package_in(&mut conn, "acme", "missing", 1, &identity.digest)
            .await
            .unwrap()
            .is_none()
    );
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn forged_same_triple_collision_fails_replay() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    install(&db, &m).await.unwrap();
    let mut rival = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    rival.surface.as_mut().unwrap().fallback = "pack.forged".to_string();
    let digest = rival.package_digest().unwrap();
    let canonical = rival.canonical_value().unwrap();
    let manifest_bytes =
        String::from_utf8(crate::canonical_json::canonical_json(&canonical)).unwrap();
    poison_log(
        &db,
        &package_subject("acme", "notes", 1, &digest),
        "package_artifact.installed.v1",
        serde_json::to_value(crate::meta::events::PackageArtifactInstalledV1Payload {
            namespace: "acme".to_string(),
            name: "notes".to_string(),
            version: 1,
            digest: digest.clone(),
            manifest_bytes,
        })
        .unwrap(),
    )
    .await;
    let fresh = pristine_db().await;
    let mut live_conn = db.write_pool().acquire().await.unwrap();
    let events = crate::meta::read_all_meta_events(&mut live_conn)
        .await
        .unwrap();
    drop(live_conn);
    let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
    let err = crate::projector::meta::replay_meta(&mut fresh_conn, &events)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("already installed with a different digest"),
        "{err}"
    );
    drop(fresh_conn);
    db.close().await;
    fresh.close().await;
}

#[tokio::test]
async fn replay_rebuild_matches_live_dump() {
    let db = test_db().await;
    let m = manifest(
        "acme",
        "notes",
        vec![
            entry("demo.notes", r#"["note"]"#),
            entry("demo.tags", r#"["tag"]"#),
        ],
    );
    install(&db, &m).await.unwrap();
    assert!(
        crate::definition_registry::rebuild_and_diff_kernel_tables(&db)
            .await
            .unwrap()
    );
    let mut live_conn = db.write_pool().acquire().await.unwrap();
    let live: Vec<PackageArtifactRow> = sqlx::query_as(
        "SELECT id, namespace, name, version, digest, manifest_bytes, event_seq, created_at
           FROM package_artifacts ORDER BY id",
    )
    .fetch_all(&mut *live_conn)
    .await
    .unwrap();
    assert_eq!(live.len(), 1);
    let events = crate::meta::read_all_meta_events(&mut live_conn)
        .await
        .unwrap();
    drop(live_conn);
    let fresh = pristine_db().await;
    let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
    crate::projector::meta::replay_meta(&mut fresh_conn, &events)
        .await
        .unwrap();
    let rebuilt: Vec<PackageArtifactRow> = sqlx::query_as(
        "SELECT id, namespace, name, version, digest, manifest_bytes, event_seq, created_at
           FROM package_artifacts ORDER BY id",
    )
    .fetch_all(&mut *fresh_conn)
    .await
    .unwrap();
    assert_eq!(live, rebuilt);
    drop(fresh_conn);
    db.close().await;
    fresh.close().await;
}

#[tokio::test]
async fn forged_effects_payload_fails_replay() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    install(&db, &m).await.unwrap();
    let mut forged_value = m.canonical_value().unwrap();
    forged_value["behaviour"]["effects"] = serde_json::json!(["write:record"]);
    let digest = crate::canonical_json::digest_json(&forged_value);
    let manifest_bytes =
        String::from_utf8(crate::canonical_json::canonical_json(&forged_value)).unwrap();
    poison_log(
        &db,
        &package_subject("acme", "forged", 1, &digest),
        "package_artifact.installed.v1",
        serde_json::to_value(crate::meta::events::PackageArtifactInstalledV1Payload {
            namespace: "acme".to_string(),
            name: "forged".to_string(),
            version: 1,
            digest,
            manifest_bytes,
        })
        .unwrap(),
    )
    .await;
    let fresh = pristine_db().await;
    let mut live_conn = db.write_pool().acquire().await.unwrap();
    let events = crate::meta::read_all_meta_events(&mut live_conn)
        .await
        .unwrap();
    drop(live_conn);
    let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
    let err = crate::projector::meta::replay_meta(&mut fresh_conn, &events)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("effects must stay empty"), "{err}");
    drop(fresh_conn);
    db.close().await;
    fresh.close().await;
}

#[tokio::test]
async fn noncanonical_bytes_refused_on_replay() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let digest = m.package_digest().unwrap();
    let pretty = serde_json::to_string_pretty(&m.canonical_value().unwrap()).unwrap();
    poison_log(
        &db,
        &package_subject("acme", "pretty", 1, &digest),
        "package_artifact.installed.v1",
        serde_json::to_value(crate::meta::events::PackageArtifactInstalledV1Payload {
            namespace: "acme".to_string(),
            name: "pretty".to_string(),
            version: 1,
            digest,
            manifest_bytes: pretty,
        })
        .unwrap(),
    )
    .await;
    let mut live_conn = db.write_pool().acquire().await.unwrap();
    let events = crate::meta::read_all_meta_events(&mut live_conn)
        .await
        .unwrap();
    drop(live_conn);
    let fresh = pristine_db().await;
    let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
    let err = crate::projector::meta::replay_meta(&mut fresh_conn, &events)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not canonical"), "{err}");
    drop(fresh_conn);
    db.close().await;
    fresh.close().await;
}

#[tokio::test]
async fn tampered_projection_breaks_read_and_retry() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let identity = install(&db, &m).await.unwrap();
    sqlx::query(
        "UPDATE package_artifacts SET event_seq = event_seq + 100 WHERE namespace = 'acme'",
    )
    .execute(db.write_pool())
    .await
    .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = read_package_in(&mut conn, "acme", "notes", 1, &identity.digest)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("disagrees"), "{err}");
    drop(conn);
    let err = install(&db, &m).await.unwrap_err();
    assert!(err.to_string().contains("disagrees"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn forged_duplicate_same_digest_fails_replay_and_read() {
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let identity = install(&db, &m).await.unwrap();
    let digest = m.package_digest().unwrap();
    let canonical = m.canonical_value().unwrap();
    let manifest_bytes =
        String::from_utf8(crate::canonical_json::canonical_json(&canonical)).unwrap();
    poison_log(
        &db,
        &package_subject("acme", "notes", 1, &digest),
        "package_artifact.installed.v1",
        serde_json::to_value(crate::meta::events::PackageArtifactInstalledV1Payload {
            namespace: "acme".to_string(),
            name: "notes".to_string(),
            version: 1,
            digest: digest.clone(),
            manifest_bytes,
        })
        .unwrap(),
    )
    .await;
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = read_package_in(&mut conn, "acme", "notes", 1, &identity.digest)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("expected exactly one"), "{err}");
    drop(conn);
    let mut live_conn = db.write_pool().acquire().await.unwrap();
    let events = crate::meta::read_all_meta_events(&mut live_conn)
        .await
        .unwrap();
    drop(live_conn);
    let fresh = pristine_db().await;
    let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
    let err = crate::projector::meta::replay_meta(&mut fresh_conn, &events)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("duplicate on replay"), "{err}");
    drop(fresh_conn);
    db.close().await;
    fresh.close().await;
}

#[tokio::test]
async fn underscore_triple_prefix_does_not_overmatch() {
    // `a_c` as a LIKE pattern would match sibling triple `abc`; the verified
    // read must use a literal prefix comparison so each triple counts only
    // its own install event.
    let db = test_db().await;
    let first = manifest("a_c", "my_pack", vec![entry("demo.first", r#"["f"]"#)]);
    let second = manifest("abc", "my_pack", vec![entry("demo.second", r#"["s"]"#)]);
    let first_id = install(&db, &first).await.unwrap();
    let second_id = install(&db, &second).await.unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let stored = read_package_in(&mut conn, "a_c", "my_pack", 1, &first_id.digest)
        .await
        .unwrap()
        .expect("underscore triple reads back exactly its own event");
    assert_eq!(stored.identity, first_id);
    let stored = read_package_in(&mut conn, "abc", "my_pack", 1, &second_id.digest)
        .await
        .unwrap()
        .expect("sibling triple reads back exactly its own event");
    assert_eq!(stored.identity, second_id);
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn joint_event_projection_tamper_breaks_read_and_retry() {
    // Event payload and projection row rewritten together with reworded
    // canonical bytes while the claimed digest stays original: agreement
    // holds, but the recomputed digest no longer matches the claim.
    let db = test_db().await;
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let identity = install(&db, &m).await.unwrap();
    let mut forged_value = m.canonical_value().unwrap();
    forged_value["surface"]["fallback"] = serde_json::Value::String("pack.forged".to_string());
    let forged_bytes =
        String::from_utf8(crate::canonical_json::canonical_json(&forged_value)).unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let (payload_text,): (String,) = sqlx::query_as(
        "SELECT payload FROM meta_events WHERE type = 'package_artifact.installed.v1'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let mut payload: serde_json::Value = serde_json::from_str(&payload_text).unwrap();
    payload["manifest_bytes"] = serde_json::Value::String(forged_bytes.clone());
    let payload_text = serde_json::to_string(&payload).unwrap();
    drop(conn);
    sqlx::query("UPDATE meta_events SET payload = ? WHERE type = 'package_artifact.installed.v1'")
        .bind(&payload_text)
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE package_artifacts SET manifest_bytes = ? WHERE namespace = 'acme'")
        .bind(&forged_bytes)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let err = read_package_in(&mut conn, "acme", "notes", 1, &identity.digest)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match canonical manifest bytes"),
        "{err}"
    );
    drop(conn);
    let err = install(&db, &m).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match canonical manifest bytes"),
        "{err}"
    );
    db.close().await;
}

#[tokio::test]
async fn install_requires_manage_on_kernel_root() {
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Admin", "test:admin")
            .await
            .unwrap();
    let m = manifest("acme", "notes", vec![entry("demo.notes", r#"["note"]"#)]);
    let identity = crate::kernel::install_package_as(&db, &admin, &m)
        .await
        .unwrap();
    assert_eq!(identity.name, "notes");
    let stranger =
        crate::kernel::create_principal(&db, "account", "Stranger", "test:stranger", &admin)
            .await
            .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let err = crate::kernel::install_package_as(&db, &stranger, &m)
        .await
        .unwrap_err();
    assert!(!err.to_string().is_empty());
    assert_eq!(table_count(&db, "package_artifacts").await, 1);
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    db.close().await;
}
