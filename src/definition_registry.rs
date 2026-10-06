//! Gated v2 definition-artifact registry prototype (E1, test-only).
//!
//! Compiled only under `cfg(test)` (see the
//! gated `mod` declaration in `crate` root). Nothing here affects the default
//! build: no v1 schema change, no migration, no additions to
//! `crate::schema::DDL_STATEMENTS`.
//!
//! Increment 1 skeleton: the registry DDL const plus the family-neutral
//! kind-membership helper. Install/read/verify move over in later increments.
//! (Increment 3 adds the verifying transaction-scoped read the gated fold
//! needs; install paths and tests land in Increment 4.)

use crate::db::{begin_write, Db};
use crate::error::{Error, Result};
use crate::meta::definition_artifact::{
    append_definition_artifact_installed_in, digest_artifact_bytes, parse_artifact_envelope,
    validate_family_version, RevisionIdentity, ARTIFACT_VOCABULARY_ID,
};
use crate::meta::events::DefinitionArtifactInstalledPayload;
use sqlx::{Sqlite, SqliteConnection, Transaction};

/// Registry DDL, byte-identical to the general engine-65 statements on the
/// reference branch (`definition_artifacts` + its family index +
/// `definition_adoptions`). Resolution tables are deliberately excluded, and
/// these statements are NOT part of the frozen `crate::schema::DDL_STATEMENTS`:
/// gated setup code executes them explicitly.
pub const REGISTRY_DDL: [&str; 3] = [
    r#"CREATE TABLE definition_artifacts (
     id             TEXT PRIMARY KEY,
     family         TEXT NOT NULL,
     version        INTEGER NOT NULL CHECK (version >= 0),
     digest         TEXT NOT NULL CHECK (length(digest) = 64),
     artifact_bytes TEXT NOT NULL CHECK (length(artifact_bytes) > 0),
     kinds          TEXT NOT NULL CHECK (json_valid(kinds)),
     created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
     UNIQUE (family, version)
   )"#,
    r#"CREATE INDEX idx_definition_artifacts_family
        ON definition_artifacts(family, version)"#,
    r#"CREATE TABLE definition_adoptions (
     family         TEXT NOT NULL PRIMARY KEY CHECK (length(family) > 0),
     selected_version INTEGER CHECK (selected_version >= 0),
     selected_digest TEXT CHECK (length(selected_digest) = 64 AND selected_digest NOT GLOB '*[^0-9a-f]*'),
     event_seq      INTEGER NOT NULL CHECK (event_seq >= 1),
     CHECK ((selected_version IS NULL) = (selected_digest IS NULL))
   )"#,
];

/// Install one immutable definition revision, or return the existing one on
/// an exact retry. `artifact` must be valid UTF-8 carrying the JSON envelope
/// `{"family", "version", "kinds"}` (or the equivalent `package_ref` of the
/// form `family@version` plus `kinds`); the envelope's own declarations must
/// equal the `family`/`version` arguments. Kind meaning is derived by parsing
/// the hashed bytes; there is no out-of-band kinds argument.
pub async fn install_definition_artifact(
    db: &Db,
    family: &str,
    version: u32,
    artifact: &[u8],
) -> Result<RevisionIdentity> {
    // Keep the public install's validation-before-BEGIN behaviour.
    let _ = validated_install_identity(family, version, artifact)?;
    let mut tx = begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let outcome =
        install_definition_artifact_in(&mut tx, family, version, artifact, &mut act_alloc).await?;
    if outcome.installed {
        tx.commit().await?;
    } else {
        // Preserve the existing public exact-retry rollback path.
        tx.rollback().await?;
    }
    Ok(outcome.identity)
}

pub(crate) struct InstallOutcome {
    pub identity: RevisionIdentity,
    pub installed: bool,
}

fn validated_install_identity(
    family: &str,
    version: u32,
    artifact: &[u8],
) -> Result<RevisionIdentity> {
    let bytes = std::str::from_utf8(artifact)
        .map_err(|_| Error::engine("definition artifact bytes must be valid UTF-8"))?;
    validate_family_version(family, version)?;
    let parsed = parse_artifact_envelope(bytes)?;
    if parsed.family != family || parsed.version != version {
        return Err(Error::engine(
            "definition artifact declaration mismatch: envelope family/version differ from the install arguments",
        ));
    }
    Ok(RevisionIdentity {
        family: family.to_string(),
        version,
        digest: digest_artifact_bytes(artifact),
    })
}

/// Install inside the caller's existing `BEGIN IMMEDIATE` transaction. The
/// caller commits or rolls back both this event and its subsequent work.
pub(crate) async fn install_definition_artifact_in(
    tx: &mut Transaction<'static, Sqlite>,
    family: &str,
    version: u32,
    artifact: &[u8],
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<InstallOutcome> {
    install_definition_artifact_as_in(tx, family, version, artifact, None, act_alloc).await
}

pub(crate) async fn install_definition_artifact_as_in(
    tx: &mut Transaction<'static, Sqlite>,
    family: &str,
    version: u32,
    artifact: &[u8],
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<InstallOutcome> {
    let identity = validated_install_identity(family, version, artifact)?;
    let bytes = std::str::from_utf8(artifact).expect("validated UTF-8");
    let digest = &identity.digest;

    // The dedicated table is the only revision projection this installer
    // consults. No vocabulary row is created: the event subject keeps the
    // pre-60 `vv:` shape as an opaque identity (verified on append and on
    // replay), and generic vocabulary verbs address `vocabulary_values`
    // rows this code never reads — they cannot affect revision semantics.
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT digest, artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ?",
    )
    .bind(family)
    .bind(version as i64)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((existing_digest, stored_bytes)) = existing {
        if existing_digest != *digest {
            return Err(Error::engine(format!(
                "definition artifact conflict: {family}@{version} is already installed with different bytes"
            )));
        }
        if stored_bytes != bytes {
            return Err(Error::engine(
                "definition artifact conflict: same revision digest with different stored bytes",
            ));
        }
        return Ok(InstallOutcome {
            identity,
            installed: false,
        });
    }
    append_definition_artifact_installed_in(
        tx,
        DefinitionArtifactInstalledPayload {
            vocabulary_id: ARTIFACT_VOCABULARY_ID.to_string(),
            value: identity.value_string(),
            family: family.to_string(),
            version,
            digest: digest.clone(),
            artifact_bytes: bytes.to_string(),
        },
        actor,
        act_alloc,
    )
    .await?;
    Ok(InstallOutcome {
        identity,
        installed: true,
    })
}

/// One retained definition revision as read back from the projection.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredArtifact {
    pub identity: RevisionIdentity,
    /// The exact bytes supplied at install, byte-for-byte.
    pub bytes: String,
    /// The kind descriptors derived from the exact bytes at install.
    pub kinds: serde_json::Value,
}

/// Transaction-scoped verified read. A missing revision is `Ok(None)`;
/// present-but-unverifiable bytes (projection tamper, envelope drift) are an
/// error — reads never fall back to another revision.
pub(crate) async fn read_definition_artifact_on(
    conn: &mut SqliteConnection,
    family: &str,
    version: u32,
    digest: &str,
) -> Result<Option<StoredArtifact>> {
    validate_family_version(family, version)?;
    let identity = RevisionIdentity {
        family: family.to_string(),
        version,
        digest: digest.to_string(),
    };
    let row: Option<(String, i64, String, String, String)> = sqlx::query_as(
        "SELECT family, version, digest, artifact_bytes, kinds
           FROM definition_artifacts WHERE id = ?",
    )
    .bind(identity.value_id())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((stored_family, stored_version, stored_digest, stored_bytes, stored_kinds)) = row
    else {
        return Ok(None);
    };
    if stored_family != identity.family
        || stored_version != identity.version as i64
        || stored_digest != identity.digest
    {
        return Err(Error::engine(
            "definition artifact projection id/value mismatch",
        ));
    }
    parse_stored_projection(&identity, &stored_bytes, &stored_kinds).map(Some)
}

/// Read one revision back by exact identity. A missing revision is `Ok(None)`;
/// present-but-unverifiable bytes are an error — reads never fall back to
/// another revision.
pub async fn read_definition_artifact(
    db: &Db,
    family: &str,
    version: u32,
    digest: &str,
) -> Result<Option<StoredArtifact>> {
    validate_family_version(family, version)?;
    let mut conn = db.write_pool().acquire().await?;
    read_definition_artifact_on(&mut conn, family, version, digest).await
}

/// List every installed revision of one family, ordered by version then
/// digest. The dedicated table holds only revisions, so there is nothing to
/// skip and a poisoned generic row cannot pollute the result.
pub async fn list_family_revisions(db: &Db, family: &str) -> Result<Vec<RevisionIdentity>> {
    validate_family_version(family, 0)?;
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version, digest FROM definition_artifacts WHERE family = ?
          ORDER BY version, digest",
    )
    .bind(family)
    .fetch_all(db.write_pool())
    .await?;
    Ok(rows
        .into_iter()
        .map(|(version, digest)| RevisionIdentity {
            family: family.to_string(),
            version: version as u32,
            digest,
        })
        .collect())
}

/// Exact-token membership of a requested kind in a retained artifact's
/// `kinds` array. Bare strings match by equality; object entries match by
/// their `token` field, ignoring any `type` field. Family-neutral by design:
/// the reference branch type-scoped object entries to `"Resolution"`, which
/// would bake one family into shared kernel code.
pub(crate) fn artifact_contains_kind(kinds: &serde_json::Value, target_kind: &str) -> bool {
    let Some(entries) = kinds.as_array() else {
        return false;
    };
    for entry in entries {
        if let Some(token) = entry.as_str() {
            if token == target_kind {
                return true;
            }
            continue;
        }
        if let Some(obj) = entry.as_object() {
            if obj
                .get("token")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|token| token == target_kind)
            {
                return true;
            }
        }
    }
    false
}

/// Verify a dedicated-table projection row against its claimed identity and
/// unpack it. `kinds` are re-derived from the stored bytes on every read and
/// must equal the stored copy: a bytes rewrite is caught by the digest check;
/// a kinds-copy-only rewrite is caught by the drift check.
fn parse_stored_projection(
    identity: &RevisionIdentity,
    stored_bytes: &str,
    stored_kinds_json: &str,
) -> Result<StoredArtifact> {
    if digest_artifact_bytes(stored_bytes.as_bytes()) != identity.digest {
        return Err(Error::engine(
            "definition artifact projection digest mismatch: stored bytes do not hash to the revision digest",
        ));
    }
    let stored_kinds: serde_json::Value = serde_json::from_str(stored_kinds_json)
        .map_err(|_| Error::engine("definition artifact projection carries unreadable kinds"))?;
    let reparsed = parse_artifact_envelope(stored_bytes)?;
    if reparsed.family != identity.family
        || reparsed.version != identity.version
        || reparsed.kinds != stored_kinds
    {
        return Err(Error::engine(
            "definition artifact projection kinds drift: stored kinds differ from what the retained bytes declare",
        ));
    }
    Ok(StoredArtifact {
        identity: identity.clone(),
        bytes: stored_bytes.to_string(),
        kinds: stored_kinds,
    })
}

/// Test setup: the frozen DDL deliberately has no registry tables, so every
/// gated test applies `REGISTRY_DDL` explicitly after `create_database`.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) async fn ensure_registry_tables(db: &Db) -> Result<()> {
    for statement in REGISTRY_DDL {
        sqlx::query(statement).execute(db.write_pool()).await?;
    }
    Ok(())
}

/// Test-only kernel rebuild-and-diff. Production `rebuild_and_diff_meta` is
/// untouched per D-c (its fresh database has no registry tables), so gated
/// tests replay the live meta log into a bare-schema database plus
/// `REGISTRY_DDL` and compare the two kernel tables row-for-row.
#[cfg(test)]
type PackageArtifactRow = (String, String, String, i64, String, String, i64, String);

#[cfg(test)]
pub(crate) async fn rebuild_and_diff_kernel_tables(db: &Db) -> Result<bool> {
    let fresh = crate::db::open_database(":memory:").await?;
    crate::db::apply_schema(&fresh).await?;
    ensure_registry_tables(&fresh).await?;
    crate::meta::package::ensure_package_tables(&fresh).await?;
    let mut live_conn = db.write_pool().acquire().await?;
    let events = crate::meta::read_all_meta_events(&mut live_conn).await?;
    let live_artifacts: Vec<(String, String, i64, String, String, String, String)> =
        sqlx::query_as(
            "SELECT id, family, version, digest, artifact_bytes, kinds, created_at
           FROM definition_artifacts ORDER BY id",
        )
        .fetch_all(&mut *live_conn)
        .await?;
    let live_adoptions: Vec<(String, Option<i64>, Option<String>, i64)> = sqlx::query_as(
        "SELECT family, selected_version, selected_digest, event_seq
            FROM definition_adoptions ORDER BY family",
    )
    .fetch_all(&mut *live_conn)
    .await?;
    let live_packages: Vec<PackageArtifactRow> = sqlx::query_as(
        "SELECT id, namespace, name, version, digest, manifest_bytes, event_seq, created_at
               FROM package_artifacts ORDER BY id",
    )
    .fetch_all(&mut *live_conn)
    .await?;
    drop(live_conn);
    let mut fresh_conn = fresh.write_pool().acquire().await?;
    crate::projector::meta::replay_meta(&mut fresh_conn, &events).await?;
    let rebuilt_artifacts: Vec<(String, String, i64, String, String, String, String)> =
        sqlx::query_as(
            "SELECT id, family, version, digest, artifact_bytes, kinds, created_at
               FROM definition_artifacts ORDER BY id",
        )
        .fetch_all(&mut *fresh_conn)
        .await?;
    let rebuilt_adoptions: Vec<(String, Option<i64>, Option<String>, i64)> = sqlx::query_as(
        "SELECT family, selected_version, selected_digest, event_seq
            FROM definition_adoptions ORDER BY family",
    )
    .fetch_all(&mut *fresh_conn)
    .await?;
    let rebuilt_packages: Vec<PackageArtifactRow> = sqlx::query_as(
        "SELECT id, namespace, name, version, digest, manifest_bytes, event_seq, created_at
               FROM package_artifacts ORDER BY id",
    )
    .fetch_all(&mut *fresh_conn)
    .await?;
    Ok(live_artifacts == rebuilt_artifacts
        && live_adoptions == rebuilt_adoptions
        && live_packages == rebuilt_packages)
}

#[cfg(test)]
mod registry_slice_tests {
    //! Raw-log and raw-projection tests: `Db::write_pool` is crate-private
    //! by design, so poisoning and tampering are exercised inside the crate.

    use super::*;
    use crate::db::create_database;

    fn kinds_a() -> serde_json::Value {
        serde_json::json!([{"token": "decision", "gloss": "first meaning"}])
    }

    fn kinds_b() -> serde_json::Value {
        serde_json::json!([
            {"token": "decision", "gloss": "revised meaning"},
            {"token": "rule", "gloss": "new kind"},
        ])
    }

    fn envelope(family: &str, version: u32, kinds: &serde_json::Value) -> Vec<u8> {
        serde_json::json!({"family": family, "version": version, "kinds": kinds})
            .to_string()
            .into_bytes()
    }

    async fn test_db() -> Db {
        let db = create_database(":memory:").await.unwrap();
        ensure_registry_tables(&db).await.unwrap();
        crate::meta::package::ensure_package_tables(&db)
            .await
            .unwrap();
        db
    }

    async fn write_projection_bytes(db: &Db, id: &str, bytes: &str) {
        sqlx::query("UPDATE definition_artifacts SET artifact_bytes = ? WHERE id = ?")
            .bind(bytes)
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
    }

    async fn write_projection_kinds(db: &Db, id: &str, kinds: &serde_json::Value) {
        sqlx::query("UPDATE definition_artifacts SET kinds = ? WHERE id = ?")
            .bind(kinds.to_string())
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn attributed_install_carries_actor() {
        let db = test_db().await;
        let kinds = kinds_a();
        let bytes = envelope("test.actor", 1, &kinds);
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        let outcome = install_definition_artifact_as_in(
            &mut tx,
            "test.actor",
            1,
            &bytes,
            Some("test:actor"),
            &mut acts,
        )
        .await
        .unwrap();
        assert!(outcome.installed);
        tx.commit().await.unwrap();
        let actor: Option<String> = sqlx::query_scalar(
            "SELECT actor FROM meta_events WHERE type = 'definition_artifact.installed' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(actor.as_deref(), Some("test:actor"));
    }

    #[tokio::test]
    async fn tampered_projection_bytes_fail_reads() {
        let db = test_db().await;
        let bytes = envelope("test.def", 1, &kinds_a());
        let id = install_definition_artifact(&db, "test.def", 1, &bytes)
            .await
            .unwrap();
        write_projection_bytes(
            &db,
            &id.value_id(),
            &String::from_utf8(envelope("test.def", 1, &kinds_b())).unwrap(),
        )
        .await;
        let err = read_definition_artifact(&db, "test.def", 1, &id.digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest mismatch"), "got: {err}");
    }

    #[tokio::test]
    async fn tampered_projection_kinds_fail_reads() {
        let db = test_db().await;
        let bytes = envelope("test.def", 1, &kinds_a());
        let id = install_definition_artifact(&db, "test.def", 1, &bytes)
            .await
            .unwrap();
        write_projection_kinds(&db, &id.value_id(), &kinds_b()).await;
        let err = read_definition_artifact(&db, "test.def", 1, &id.digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("kinds drift"), "got: {err}");
    }

    #[tokio::test]
    async fn poisoned_event_breaks_kernel_rebuild() {
        let db = test_db().await;
        install_definition_artifact(&db, "test.def", 1, &envelope("test.def", 1, &kinds_a()))
            .await
            .unwrap();
        assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
        let poison_payload = serde_json::json!({
            "vocabulary_id": "voc:ontology:definition-artifact",
            "value": "test.def@9#0000000000000000000000000000000000000000000000000000000000000000",
            "family": "test.def",
            "version": 9,
            "digest": "0000000000000000000000000000000000000000000000000000000000000000",
            "artifact_bytes": serde_json::json!({"family": "test.def", "version": 9, "kinds": []}).to_string(),
        });
        sqlx::query(
            "INSERT INTO meta_events (id, subject_id, type, payload) VALUES (?, ?, ?, ?)",
        )
        .bind("poison-1")
        .bind("vv:voc:ontology:definition-artifact:test.def@9#0000000000000000000000000000000000000000000000000000000000000000")
        .bind("definition_artifact.installed")
        .bind(poison_payload.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
        let fresh = crate::db::open_database(":memory:").await.unwrap();
        crate::db::apply_schema(&fresh).await.unwrap();
        ensure_registry_tables(&fresh).await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        let events = crate::meta::read_all_meta_events(&mut conn).await.unwrap();
        drop(conn);
        let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
        let err = crate::projector::meta::replay_meta(&mut fresh_conn, &events)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest mismatch"), "got: {err}");
    }

    #[tokio::test]
    async fn forged_second_valid_event_breaks_kernel_rebuild() {
        let db = test_db().await;
        install_definition_artifact(&db, "test.def", 1, &envelope("test.def", 1, &kinds_a()))
            .await
            .unwrap();
        let bytes2 = envelope("test.def", 1, &kinds_b());
        install_definition_artifact(&db, "test.def", 1, &bytes2)
            .await
            .unwrap_err();
        let digest2 = digest_artifact_bytes(&bytes2);
        let forged_value = format!("test.def@1#{digest2}");
        let forged_payload = serde_json::json!({
            "vocabulary_id": "voc:ontology:definition-artifact",
            "value": forged_value,
            "family": "test.def",
            "version": 1,
            "digest": digest2,
            "artifact_bytes": String::from_utf8(bytes2).unwrap(),
        });
        sqlx::query("INSERT INTO meta_events (id, subject_id, type, payload) VALUES (?, ?, ?, ?)")
            .bind("forged-2")
            .bind(format!(
                "vv:voc:ontology:definition-artifact:{forged_value}"
            ))
            .bind("definition_artifact.installed")
            .bind(forged_payload.to_string())
            .execute(db.write_pool())
            .await
            .unwrap();
        let fresh = crate::db::open_database(":memory:").await.unwrap();
        crate::db::apply_schema(&fresh).await.unwrap();
        ensure_registry_tables(&fresh).await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        let events = crate::meta::read_all_meta_events(&mut conn).await.unwrap();
        drop(conn);
        let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
        let err = crate::projector::meta::replay_meta(&mut fresh_conn, &events)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("conflict on replay"), "got: {err}");
    }

    #[tokio::test]
    async fn import_shaped_staging_with_empty_projection_fails_kernel_diff() {
        // The import-loss path, proven fail-closed: bulk import copies the
        // `meta_events` log without folding, so a staging database would hold
        // the installed event with an empty `definition_artifacts` table. The
        // kernel rebuild diff rejects that drift loudly instead of serving
        // reads with a silently missing revision.
        let db = test_db().await;
        let bytes = envelope("test.def", 1, &kinds_a());
        let digest = digest_artifact_bytes(&bytes);
        let value = format!("test.def@1#{digest}");
        let payload = serde_json::json!({
            "vocabulary_id": "voc:ontology:definition-artifact",
            "value": value,
            "family": "test.def",
            "version": 1,
            "digest": digest,
            "artifact_bytes": String::from_utf8(bytes).unwrap(),
        });
        sqlx::query("INSERT INTO meta_events (id, subject_id, type, payload) VALUES (?, ?, ?, ?)")
            .bind("import-copy-1")
            .bind(format!("vv:voc:ontology:definition-artifact:{value}"))
            .bind("definition_artifact.installed")
            .bind(payload.to_string())
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(
            !rebuild_and_diff_kernel_tables(&db).await.unwrap(),
            "an unfolded log copy must fail the kernel rebuild diff"
        );
    }

    #[tokio::test]
    async fn wiped_projection_rebuilds_from_log() {
        // Destructive rebuild: the dedicated table is pure log projection,
        // so wiping it and replaying the authoritative log restores reads
        // and the kernel rebuild diff passes again.
        let db = test_db().await;
        let v1 =
            install_definition_artifact(&db, "test.def", 1, &envelope("test.def", 1, &kinds_a()))
                .await
                .unwrap();
        let v2 =
            install_definition_artifact(&db, "test.def", 2, &envelope("test.def", 2, &kinds_b()))
                .await
                .unwrap();
        sqlx::query("DELETE FROM definition_artifacts")
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(
            read_definition_artifact(&db, "test.def", 1, &v1.digest)
                .await
                .unwrap()
                .is_none(),
            "wiped projection must read as missing"
        );
        let mut conn = db.write_pool().acquire().await.unwrap();
        let events = crate::meta::read_all_meta_events(&mut conn).await.unwrap();
        // Re-fold only this registry's own installed events: the wiped table
        // is purely their projection, and replaying the whole meta log into
        // a live database would re-insert seed rows it already holds.
        for event in events
            .iter()
            .filter(|e| e.event_type == "definition_artifact.installed")
        {
            crate::projector::meta::project_meta(&mut conn, event)
                .await
                .unwrap();
        }
        drop(conn);
        let stored = read_definition_artifact(&db, "test.def", 1, &v1.digest)
            .await
            .unwrap()
            .expect("replay must restore v1");
        assert_eq!(stored.identity, v1);
        assert_eq!(
            list_family_revisions(&db, "test.def").await.unwrap(),
            vec![v1, v2]
        );
        assert!(rebuild_and_diff_kernel_tables(&db).await.unwrap());
    }

    #[tokio::test]
    async fn package_ref_envelope_installs_and_mismatch_refuses_without_event() {
        // The `package_ref` declaration form carries no explicit
        // family/version fields; the install arguments supply them.
        let db = test_db().await;
        let bytes = serde_json::json!({"package_ref": "example.widget@1", "kinds": []})
            .to_string()
            .into_bytes();
        let identity = install_definition_artifact(&db, "example.widget", 1, &bytes)
            .await
            .unwrap();
        assert_eq!(identity.family, "example.widget");
        assert_eq!(identity.version, 1);
        let stored = read_definition_artifact(&db, "example.widget", 1, &identity.digest)
            .await
            .unwrap()
            .expect("package_ref install must read back");
        assert_eq!(stored.bytes.as_bytes(), bytes.as_slice());
        assert_eq!(stored.identity, identity);
        // A `package_ref` that disagrees with the install arguments is
        // refused before any event is appended.
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let bad = serde_json::json!({"package_ref": "example.widget@2", "kinds": []})
            .to_string()
            .into_bytes();
        let err = install_definition_artifact(&db, "example.widget", 1, &bad)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mismatch"), "got: {err}");
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn artifact_membership_ignores_type_field() {
        use serde_json::json;
        // Bare-string equality holds; non-arrays never match. Object entries
        // match by token regardless of any `type` field: unlike the reference
        // branch (which type-scoped to one family), this helper is neutral.
        assert!(artifact_contains_kind(&json!(["decision"]), "decision"));
        assert!(!artifact_contains_kind(&json!("decision"), "decision"));
        assert!(!artifact_contains_kind(&json!(null), "decision"));
        assert!(artifact_contains_kind(
            &json!([{"type": "example.widget", "token": "decision"}]),
            "decision"
        ));
        assert!(artifact_contains_kind(
            &json!([{"type": "other", "token": "decision"}]),
            "decision"
        ));
        assert!(artifact_contains_kind(
            &json!([{"token": "decision"}]),
            "decision"
        ));
        assert!(!artifact_contains_kind(
            &json!([{"type": "example.widget", "token": "rule"}]),
            "decision"
        ));
    }
}
