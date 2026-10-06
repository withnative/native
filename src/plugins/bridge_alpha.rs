//! v1 bridge persistence (task `1bf0e85`, P1a slice S3a).
//!
//! [`import_revision_into_alpha`] persists an [`ImportedRevision`] as one
//! alpha artifact record — bundle bytes as the record body, canonical
//! manifest / package digest / identity as live facets, each import's
//! provenance as an append-only facet observation — and returns exactly the
//! values the alpha-tab `install` action needs. It does NOT call install
//! itself; S3b drives install → preview → adopt → launch from here.
//!
//! One artifact record per package digest *per importing principal*: lookup
//! and create share a single write transaction (SQLite serializes writers
//! on the pool, so the check-then-create cannot interleave with another
//! import). Authority runs before lookups leak anything: creating needs
//! `Edit` on the home; digest reuse considers only live artifacts the caller
//! can `Edit` (otherwise they get their own record); triple collision
//! considers only records the caller can `View`, and refusals never name
//! record ids — invisible records neither satisfy reuse nor trigger
//! collision (namespaces are locally asserted in P1a).
//!
//! Authority mirrors the tools: creating needs `Edit` on the home folder
//! (the same rule `create_record` enforces), appending a receipt needs
//! `Edit` on the artifact record (the `manage_facet_observations` rule).
//! Writes use the `store::append_in` event seam — the same admission and
//! projection kernel the tools compose over — never the blob tier.

use sqlx::Row;

use sha2::Digest;

use super::import::{single_html_surface, ImportRefusal, ImportedRevision};
use super::manifest_v2::join_package_id;
use crate::authorization::Capability;
use crate::error::{Error, Result};

const TOOL: &str = "plugin_bridge_alpha";
const ALPHA_RUNTIME: &str = "native.html.v1";

/// Live facets naming one imported revision on its artifact record.
pub const FACET_PACKAGE_DIGEST: &str = "package_digest";
pub const FACET_PACKAGE_NAMESPACE: &str = "package_namespace";
pub const FACET_PACKAGE_NAME: &str = "package_name";
pub const FACET_PACKAGE_VERSION: &str = "package_version";
pub const FACET_PACKAGE_MANIFEST: &str = "package_manifest";
/// Append-only receipt observations (one per import, never overwritten).
pub const FACET_PACKAGE_RECEIPT: &str = "package_receipt";

/// Exactly what the alpha-tab `install` action needs, plus whether this
/// call created the artifact record.
#[derive(Debug)]
pub struct AlphaBridgeOutcome {
    pub artifact_id: String,
    pub source_revision: String,
    pub alpha_digest: String,
    pub package: String,
    pub version: String,
    pub declaration: serde_json::Value,
    pub created: bool,
}

/// The pure pin computation: surface/html/version/package checks plus the
/// alpha digest over alpha's own canonical functions (never reimplemented).
struct BridgePin {
    package: String,
    declaration: serde_json::Value,
    alpha_digest: String,
    bundle: String,
    /// Claimed sha256 of the surface-bundle file, re-proven on reuse (R1).
    bundle_sha256: String,
}

fn bridge_inputs(revision: &ImportedRevision) -> std::result::Result<BridgePin, ImportRefusal> {
    let (_contribution, file) = single_html_surface(&revision.manifest)?;
    let version = revision.manifest.version.clone();
    crate::mcp::tools::alpha_tabs::require_version(&version).map_err(|_| {
        ImportRefusal::refused(
            "version_not_alpha_compatible",
            format!("version '{version}' is not plain numeric X.Y.Z"),
        )
    })?;
    let package = join_package_id(&revision.manifest.namespace, &revision.manifest.name);
    crate::mcp::tools::alpha_tabs::require_package(&package).map_err(|_| {
        ImportRefusal::refused(
            "package_not_alpha_compatible",
            format!("package id '{package}' is not a reverse-DNS id"),
        )
    })?;
    let mut needs = revision.manifest.declared.reads.clone();
    needs.sort();
    let raw = serde_json::json!({"needs": needs, "effects": []});
    let declaration = crate::mcp::tools::alpha_tabs::alpha_tab_canonical_declaration(&raw)
        .map_err(|e| ImportRefusal::refused("bridge_declaration_invalid", e.to_string()))?;
    let bytes = revision
        .files
        .iter()
        .find(|f| f.path == file.path)
        .map(|f| f.bytes.as_slice())
        .ok_or_else(|| {
            ImportRefusal::refused(
                "surface_bytes_missing",
                format!("surface file '{}' has no retained bytes", file.path),
            )
        })?;
    let bundle = std::str::from_utf8(bytes)
        .map_err(|_| {
            ImportRefusal::refused(
                "bundle_not_utf8",
                format!("surface file '{}' is not UTF-8", file.path),
            )
        })?
        .to_string();
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration)
            .map_err(|e| ImportRefusal::refused("bridge_declaration_invalid", e.to_string()))?;
    let alpha_digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
        &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&bundle),
        &declaration_digest,
        ALPHA_RUNTIME,
    );
    Ok(BridgePin {
        package,
        declaration,
        alpha_digest,
        bundle,
        bundle_sha256: file.sha256.clone(),
    })
}
type Tx = sqlx::Transaction<'static, sqlx::Sqlite>;

async fn is_live_artifact(tx: &mut Tx, record_id: &str) -> Result<bool> {
    let row = sqlx::query(
        "SELECT r.type, r.kind, r.deleted_at,
                EXISTS (SELECT 1 FROM facet_values a
                         WHERE a.record_id = r.id AND a.key = 'archived') AS archived
           FROM records r WHERE r.id = ?",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(false) };
    Ok(row.try_get::<String, _>("type")? == "Document"
        && row.try_get::<Option<String>, _>("kind")?.as_deref() == Some("artifact")
        && row.try_get::<Option<String>, _>("deleted_at")?.is_none()
        && row.try_get::<i64, _>("archived")? == 0)
}

/// Candidate live artifact records carrying this package digest, in stable
/// order. Authority filtering happens in the caller: only records the
/// caller can edit satisfy reuse; the rest are skipped, never refused.
async fn digest_candidate_ids(tx: &mut Tx, digest: &str) -> Result<Vec<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT record_id FROM facet_values WHERE key = ? AND value = ? ORDER BY record_id",
    )
    .bind(FACET_PACKAGE_DIGEST)
    .bind(digest)
    .fetch_all(&mut **tx)
    .await?;
    Ok(ids)
}

/// A live artifact with the same triple but a different digest refuses —
/// but only among records the caller can View. Records invisible to the
/// caller never cause a refusal (namespaces are locally asserted in P1a),
/// and the refusal never names record ids.
async fn visible_triple_collision_in(
    tx: &mut Tx,
    caller: &crate::mcp::registry::Caller,
    revision: &ImportedRevision,
) -> Result<bool> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT n.record_id FROM facet_values n
           JOIN facet_values m ON m.record_id = n.record_id
           JOIN facet_values v ON v.record_id = n.record_id
          WHERE n.key = ? AND n.value = ?
            AND m.key = ? AND m.value = ?
            AND v.key = ? AND v.value = ?
          ORDER BY n.record_id",
    )
    .bind(FACET_PACKAGE_NAMESPACE)
    .bind(&revision.manifest.namespace)
    .bind(FACET_PACKAGE_NAME)
    .bind(&revision.manifest.name)
    .bind(FACET_PACKAGE_VERSION)
    .bind(&revision.manifest.version)
    .fetch_all(&mut **tx)
    .await?;
    for id in ids {
        if !is_live_artifact(tx, &id).await? {
            continue;
        }
        if crate::mcp::tools::require_record_in(tx, caller, TOOL, &id, Capability::View)
            .await
            .is_err()
        {
            continue;
        }
        let digest: Option<String> =
            sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
                .bind(&id)
                .bind(FACET_PACKAGE_DIGEST)
                .fetch_optional(&mut **tx)
                .await?
                .flatten();
        if digest.as_deref() != Some(revision.digest.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Newest body-carrying content event for an artifact record.
async fn newest_body_event(tx: &mut Tx, artifact_id: &str) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        "SELECT id, json_extract(payload, '$.body') AS body FROM content_events
          WHERE record_id = ? AND json_type(payload, '$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(artifact_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok((
            row.try_get::<String, _>("id")?,
            row.try_get::<String, _>("body")?,
        ))
    })
    .transpose()
}

/// R1: the `package_digest` facet is a claim, not proof — artifact records
/// are editable. On reuse, prove the record still holds the revision: its
/// current body must hash to the surface-bundle sha256, and its
/// `package_manifest` facet must equal the canonical manifest bytes.
/// Anything else refuses `revision_record_modified` — naming no record ids —
/// instead of returning a stale or foreign source_revision.
async fn reverify_reused_record(
    tx: &mut Tx,
    artifact_id: &str,
    revision: &ImportedRevision,
    bundle_sha256: &str,
) -> Result<String> {
    let refused = |detail: String| {
        Error::engine(format!(
            "plugin import refused [revision_record_modified]: {detail}"
        ))
    };
    let Some((source_revision, current_body)) = newest_body_event(tx, artifact_id).await? else {
        return Err(refused("holds no body event".to_string()));
    };
    let current_sha = hex::encode(sha2::Sha256::digest(current_body.as_bytes()));
    if current_sha != bundle_sha256 {
        return Err(refused(
            "current body does not hash to the revision's surface bundle".to_string(),
        ));
    }
    let stored_manifest: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
            .bind(artifact_id)
            .bind(FACET_PACKAGE_MANIFEST)
            .fetch_optional(&mut **tx)
            .await?;
    let expected =
        String::from_utf8(revision.canonical_manifest_bytes.clone()).expect("JCS bytes are UTF-8");
    if stored_manifest.as_deref() != Some(expected.as_str()) {
        return Err(refused(
            "package_manifest facet does not match the revision".to_string(),
        ));
    }
    Ok(source_revision)
}
/// Next `as_of` for a receipt observation: strictly after both now and
/// the newest existing observation for this key. Observation rows upsert
/// on `(record_id, key, as_of)`, so monotonicity is what keeps receipts
/// append-only — two imports in the same millisecond must never share one.
/// Only parseable RFC3339 rows count toward the max (compared
/// chronologically, not as strings); malformed rows are ignored rather than
/// erroring, and a far-future max simply yields max + 1ms.
fn next_receipt_as_of(existing: &[String]) -> String {
    next_receipt_as_of_at(existing, chrono::Utc::now())
}

/// Both sides are compared at the millisecond precision the value is stored
/// in: comparing a full-precision `now` against a millisecond max would let
/// `now` win and then truncate back onto the max, upserting over it.
fn next_receipt_as_of_at(existing: &[String], now: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::SubsecRound;
    let now = now.trunc_subsecs(3);
    let mut max: Option<chrono::DateTime<chrono::Utc>> = None;
    for raw in existing {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(raw) {
            let moment = parsed.with_timezone(&chrono::Utc).trunc_subsecs(3);
            if max.is_none_or(|current| moment > current) {
                max = Some(moment);
            }
        }
    }
    let next = match max {
        Some(moment) if moment >= now => moment + chrono::Duration::milliseconds(1),
        _ => now,
    };
    next.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn append_receipt_observation(
    db: &crate::db::Db,
    tx: &mut Tx,
    act_alloc: &mut crate::act::ActAllocation,
    record_id: &str,
    receipt_json: &str,
    actor: Option<String>,
) -> Result<()> {
    let existing: Vec<String> =
        sqlx::query_scalar("SELECT as_of FROM facet_observations WHERE record_id = ? AND key = ?")
            .bind(record_id)
            .bind(FACET_PACKAGE_RECEIPT)
            .fetch_all(&mut **tx)
            .await?;
    let payload = serde_json::json!({
        "key": FACET_PACKAGE_RECEIPT,
        "value": receipt_json,
        "as_of": next_receipt_as_of(&existing),
        "observation_only": true,
    });
    crate::store::append_in(
        db,
        tx,
        crate::store::AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.set".into(),
            payload,
            actor,
        },
        act_alloc,
    )
    .await?;
    Ok(())
}
/// Persist an imported revision as an alpha artifact record (or attach to
/// the existing record for the same digest) and return the install values.
/// Lookup, create and receipt append share one write transaction.
pub async fn import_revision_into_alpha(
    db: &crate::db::Db,
    caller: &crate::mcp::registry::Caller,
    revision: &ImportedRevision,
    home_id: &str,
    reason: &str,
) -> Result<AlphaBridgeOutcome> {
    let pin = bridge_inputs(revision).map_err(Error::from)?;
    if reason.trim().is_empty() {
        return Err(Error::engine(format!("{TOOL}: reason must not be blank")));
    }
    let actor = Some(caller.actor().to_string());
    let receipt_json = serde_json::to_string(&revision.receipt.canonical_value())
        .expect("a receipt value always serializes");
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    // Authority first: creating needs Edit on the home, so no lookup below
    // can leak records the caller could never file alongside.
    crate::mcp::tools::lifecycle::assert_home_target_in(&mut tx, TOOL, home_id).await?;
    crate::mcp::tools::require_record_in(&mut tx, caller, TOOL, home_id, Capability::Edit).await?;
    // Digest reuse among live artifacts the caller can Edit only; the rest
    // are skipped, never refused. No editable record → own new record below.
    for candidate in digest_candidate_ids(&mut tx, &revision.digest).await? {
        if !is_live_artifact(&mut tx, &candidate).await? {
            continue;
        }
        if crate::mcp::tools::require_record_in(&mut tx, caller, TOOL, &candidate, Capability::Edit)
            .await
            .is_err()
        {
            continue;
        }
        let source_revision =
            reverify_reused_record(&mut tx, &candidate, revision, &pin.bundle_sha256).await?;
        append_receipt_observation(
            db,
            &mut tx,
            &mut act_alloc,
            &candidate,
            &receipt_json,
            actor,
        )
        .await?;
        db.commit_content(tx).await?;
        return Ok(AlphaBridgeOutcome {
            artifact_id: candidate,
            source_revision,
            alpha_digest: pin.alpha_digest,
            package: pin.package,
            version: revision.manifest.version.clone(),
            declaration: pin.declaration,
            created: false,
        });
    }
    // Triple collision among records the caller can View only; invisible
    // records never collide, and the refusal names no record ids.
    if visible_triple_collision_in(&mut tx, caller, revision).await? {
        return Err(Error::engine(format!(
            "plugin import refused [version_collision]: triple {} {} {} already imported as a different digest",
            revision.manifest.namespace, revision.manifest.name, revision.manifest.version,
        )));
    }
    let artifact_id = crate::domain_transaction::record_id_for_create(None)?;
    let created_event = crate::store::append_in(
        db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: artifact_id.clone(),
            event_type: "record.created".into(),
            payload: serde_json::json!({
                "type": "Document",
                "kind": "artifact",
                "name": pin.package,
                "body": pin.bundle,
                "home_id": home_id,
            }),
            actor: actor.clone(),
        },
        &mut act_alloc,
    )
    .await?;
    let manifest_json =
        String::from_utf8(revision.canonical_manifest_bytes.clone()).expect("JCS bytes are UTF-8");
    for (key, value) in [
        ("runtime", ALPHA_RUNTIME.to_string()),
        (FACET_PACKAGE_DIGEST, revision.digest.clone()),
        (FACET_PACKAGE_NAMESPACE, revision.manifest.namespace.clone()),
        (FACET_PACKAGE_NAME, revision.manifest.name.clone()),
        (FACET_PACKAGE_VERSION, revision.manifest.version.clone()),
        (FACET_PACKAGE_MANIFEST, manifest_json),
    ] {
        crate::store::append_in(
            db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: artifact_id.clone(),
                event_type: "facet.set".into(),
                payload: serde_json::json!({"key": key, "value": value}),
                actor: actor.clone(),
            },
            &mut act_alloc,
        )
        .await?;
    }
    append_receipt_observation(
        db,
        &mut tx,
        &mut act_alloc,
        &artifact_id,
        &receipt_json,
        actor,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(AlphaBridgeOutcome {
        artifact_id,
        source_revision: created_event.id,
        alpha_digest: pin.alpha_digest,
        package: pin.package,
        version: revision.manifest.version.clone(),
        declaration: pin.declaration,
        created: true,
    })
}
#[cfg(test)]
mod tests {
    use super::super::import::{import_candidate, FetchedBy, ImportCandidate, ProvenanceInput};
    use super::*;
    use sha2::Digest;
    use std::collections::BTreeMap;

    const BODY: &[u8] = b"<!doctype html><html><body><h1>Pulse</h1></body></html>";

    #[test]
    fn receipt_as_of_never_repeats_within_one_millisecond() {
        let at = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        // The second import lands later in the same millisecond as the first.
        let first = next_receipt_as_of_at(&[], at("2026-09-27T00:00:00.123400Z"));
        assert_eq!(first, "2026-09-27T00:00:00.123Z");
        let second = next_receipt_as_of_at(
            std::slice::from_ref(&first),
            at("2026-09-27T00:00:00.123900Z"),
        );
        assert_eq!(second, "2026-09-27T00:00:00.124Z");
        let third =
            next_receipt_as_of_at(&[first, second.clone()], at("2026-09-27T00:00:00.123950Z"));
        assert_eq!(third, "2026-09-27T00:00:00.125Z");
        // A later clock still wins once it passes the max.
        let later = next_receipt_as_of_at(&[second], at("2026-09-27T00:00:01.000Z"));
        assert_eq!(later, "2026-09-27T00:00:01.000Z");
    }

    fn sha(bytes: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(bytes))
    }

    fn manifest_value(
        namespace: &str,
        version: &str,
        files: &[(&str, &[u8], &str, &str)],
        surfaces: &[(&str, &str)],
    ) -> serde_json::Value {
        let items: Vec<serde_json::Value> = files
            .iter()
            .map(|(path, bytes, media, role)| {
                serde_json::json!({
                    "path": path, "sha256": sha(bytes),
                    "bytes_len": bytes.len(), "media_type": media, "role": role,
                })
            })
            .collect();
        let surface_refs: Vec<serde_json::Value> = surfaces
            .iter()
            .map(|(name, file)| serde_json::json!({"name": name, "file": file}))
            .collect();
        serde_json::json!({
            "format": "native.package-manifest@2",
            "namespace": namespace, "name": "team-pulse", "version": version,
            "files": items,
            "contributions": {"surfaces": surface_refs},
            "declared_reads": [], "declared_effects": [], "requires": [],
        })
    }

    fn revision_for(version: &str, body: &[u8]) -> ImportedRevision {
        let value = manifest_value(
            "agent",
            version,
            &[("team-pulse.html", body, "text/html", "surface_bundle")],
            &[("team-pulse", "team-pulse.html")],
        );
        let candidate = ImportCandidate {
            manifest_bytes: serde_json::to_vec(&value).unwrap(),
            files: BTreeMap::from([("team-pulse.html".to_string(), body.to_vec())]),
        };
        import_candidate(
            &candidate,
            &ProvenanceInput {
                adapter: "local_folder".into(),
                origin: serde_json::json!({"path": "/tmp/team-pulse"}),
                requested_ref: None,
                fetched_by: FetchedBy::Host,
                importer: "alice".into(),
                run_key: "rk-1".into(),
                at: "2026-09-26T00:00:00Z".into(),
            },
        )
        .unwrap()
    }

    async fn home(db: &crate::db::Db) -> String {
        crate::store::create_record(
            db,
            serde_json::json!({
                "type": "Collection", "kind": "folder", "name": "Plugin home",
                "persistence": "enduring",
            }),
        )
        .await
        .unwrap()
    }

    fn local_caller() -> crate::mcp::registry::Caller {
        crate::mcp::registry::Caller::local()
    }

    #[tokio::test]
    async fn create_returns_install_values() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let revision = revision_for("0.1.0", BODY);
        let outcome = import_revision_into_alpha(
            &db,
            &local_caller(),
            &revision,
            &home_id,
            "Bridge the team pulse revision.",
        )
        .await
        .unwrap();
        assert!(outcome.created);
        assert_eq!(outcome.package, "agent.team-pulse");
        assert_eq!(outcome.version, "0.1.0");
        assert_eq!(
            outcome.declaration,
            serde_json::json!({"needs": [], "effects": []})
        );
        // The digest equals what alpha recomputes from the stored body.
        let body: String = sqlx::query_scalar(
            "SELECT json_extract(payload, '$.body') FROM content_events
              WHERE record_id = ? AND id = ?",
        )
        .bind(&outcome.artifact_id)
        .bind(&outcome.source_revision)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
            &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&body),
            &crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&outcome.declaration)
                .unwrap(),
            "native.html.v1",
        );
        assert_eq!(digest, outcome.alpha_digest);
        let stored: String = sqlx::query_scalar(
            "SELECT value FROM facet_values WHERE record_id = ? AND key = 'package_digest'",
        )
        .bind(&outcome.artifact_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(stored, revision.digest);
    }
    #[tokio::test]
    async fn reimport_appends_second_receipt_without_new_record() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let revision = revision_for("0.1.0", BODY);
        let first =
            import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "First import.")
                .await
                .unwrap();
        let second =
            import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Second import.")
                .await
                .unwrap();
        assert!(!second.created);
        assert_eq!(second.artifact_id, first.artifact_id);
        assert_eq!(second.source_revision, first.source_revision);
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_observations WHERE record_id = ? AND key = 'package_receipt'",
        )
        .bind(&first.artifact_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(receipts, 2);
        let distinct: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT as_of) FROM facet_observations
              WHERE record_id = ? AND key = 'package_receipt'",
        )
        .bind(&first.artifact_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(distinct, 2, "receipts must never share an as_of");
    }

    #[tokio::test]
    async fn same_triple_different_bytes_is_version_collision() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        import_revision_into_alpha(
            &db,
            &local_caller(),
            &revision_for("0.1.0", BODY),
            &home_id,
            "First.",
        )
        .await
        .unwrap();
        let other = revision_for(
            "0.1.0",
            b"<!doctype html><html><body><h1>Changed</h1></body></html>",
        );
        let err = import_revision_into_alpha(&db, &local_caller(), &other, &home_id, "Second.")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("version_collision"), "{err}");
    }

    #[tokio::test]
    async fn alpha_incompatible_versions_and_surfaces_refused() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let prerelease = revision_for("1.0.0-rc.1", BODY);
        let err = import_revision_into_alpha(&db, &local_caller(), &prerelease, &home_id, "Why.")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("version_not_alpha_compatible"),
            "{err}"
        );
        let upper = manifest_value(
            "Agent",
            "0.1.0",
            &[("team-pulse.html", BODY, "text/html", "surface_bundle")],
            &[("team-pulse", "team-pulse.html")],
        );
        let candidate = ImportCandidate {
            manifest_bytes: serde_json::to_vec(&upper).unwrap(),
            files: BTreeMap::from([("team-pulse.html".to_string(), BODY.to_vec())]),
        };
        // Uppercase namespace is S1-valid but not alpha-compatible.
        let provenance = ProvenanceInput {
            adapter: "local_folder".into(),
            origin: serde_json::json!({}),
            requested_ref: None,
            fetched_by: FetchedBy::Host,
            importer: "a".into(),
            run_key: "r".into(),
            at: "2026-09-26T00:00:00Z".into(),
        };
        let revision = import_candidate(&candidate, &provenance).unwrap();
        let err = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Why.")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("package_not_alpha_compatible"),
            "{err}"
        );
        let bytes = &[0xff, 0xfe, 0x00];
        let broken = manifest_value(
            "agent",
            "0.1.0",
            &[("team-pulse.html", bytes, "text/html", "surface_bundle")],
            &[("team-pulse", "team-pulse.html")],
        );
        let candidate = ImportCandidate {
            manifest_bytes: serde_json::to_vec(&broken).unwrap(),
            files: BTreeMap::from([("team-pulse.html".to_string(), bytes.to_vec())]),
        };
        let provenance = ProvenanceInput {
            adapter: "local_folder".into(),
            origin: serde_json::json!({}),
            requested_ref: None,
            fetched_by: FetchedBy::Host,
            importer: "a".into(),
            run_key: "r".into(),
            at: "2026-09-26T00:00:00Z".into(),
        };
        let revision = import_candidate(&candidate, &provenance).unwrap();
        let err = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Why.")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bundle_not_utf8"), "{err}");
    }

    #[tokio::test]
    async fn caller_without_home_authority_refused() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        // Fresh databases default-allow; pin an explicit policy with no
        // entry for bob before asserting the refusal.
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            &home_id,
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        let revision = revision_for("0.1.0", BODY);
        let bob = crate::mcp::registry::Caller::authenticated("bob");
        let err = import_revision_into_alpha(&db, &bob, &revision, &home_id, "Why.")
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn edited_body_refuses_reuse() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let revision = revision_for("0.1.0", BODY);
        let first = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "First.")
            .await
            .unwrap();
        crate::store::update_record(
            &db,
            &first.artifact_id,
            serde_json::json!({"body": "<!doctype html><html><body><h1>Edited</h1></body></html>"}),
        )
        .await
        .unwrap();
        let err = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Second.")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("revision_record_modified"), "{message}");
        assert!(!message.contains(&first.artifact_id), "{message}");
    }

    #[tokio::test]
    async fn hand_set_digest_facet_is_not_reused() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let revision = revision_for("0.1.0", BODY);
        let unrelated = crate::store::create_record(
            &db,
            serde_json::json!({
                "type": "Document", "kind": "artifact", "name": "unrelated",
                "body": "<!doctype html><html><body><h1>Other</h1></body></html>",
                "home_id": home_id,
            }),
        )
        .await
        .unwrap();
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: unrelated.clone(),
                event_type: "facet.set".into(),
                payload: serde_json::json!({"key": "package_digest", "value": revision.digest}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let err = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Import.")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("revision_record_modified"), "{message}");
        assert!(!message.contains(&unrelated), "{message}");
        let pool = db.write_pool();
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_observations WHERE record_id = ? AND key = 'package_receipt'",
        )
        .bind(&unrelated)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(receipts, 0, "refusal must precede any receipt append");
    }

    #[tokio::test]
    async fn invisible_triple_record_does_not_collide() {
        use crate::authorization::{AllowEntry, Capability};
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let alice = import_revision_into_alpha(
            &db,
            &local_caller(),
            &revision_for("0.1.0", BODY),
            &home_id,
            "Alice imports.",
        )
        .await
        .unwrap();
        // Bob can file into the home but cannot see Alice's record.
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            &alice.artifact_id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let changed = b"<!doctype html><html><body><h1>Changed</h1></body></html>";
        let bob = crate::mcp::registry::Caller::authenticated("bob");
        let outcome = import_revision_into_alpha(
            &db,
            &bob,
            &revision_for("0.1.0", changed),
            &home_id,
            "Bob.",
        )
        .await
        .unwrap();
        assert!(outcome.created);
        assert_ne!(outcome.artifact_id, alice.artifact_id);
    }

    #[tokio::test]
    async fn view_without_edit_gets_own_record() {
        use crate::authorization::{AllowEntry, Capability};
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let revision = revision_for("0.1.0", BODY);
        let alice = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Alice.")
            .await
            .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            &alice.artifact_id,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bob", Capability::View),
            ],
        )
        .await
        .unwrap();
        let bob = crate::mcp::registry::Caller::authenticated("bob");
        let outcome = import_revision_into_alpha(&db, &bob, &revision, &home_id, "Bob.")
            .await
            .unwrap();
        assert!(outcome.created);
        assert_ne!(outcome.artifact_id, alice.artifact_id);
        let pool = db.write_pool();
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_observations WHERE record_id = ? AND key = 'package_receipt'",
        )
        .bind(&alice.artifact_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            receipts, 1,
            "no receipt may attach to the uneditable record"
        );
    }

    #[tokio::test]
    async fn collision_refusal_names_no_records() {
        use crate::authorization::{AllowEntry, Capability};
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let alice = import_revision_into_alpha(
            &db,
            &local_caller(),
            &revision_for("0.1.0", BODY),
            &home_id,
            "Alice.",
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            &alice.artifact_id,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bob", Capability::View),
            ],
        )
        .await
        .unwrap();
        let changed = b"<!doctype html><html><body><h1>Changed</h1></body></html>";
        let bob = crate::mcp::registry::Caller::authenticated("bob");
        let err = import_revision_into_alpha(
            &db,
            &bob,
            &revision_for("0.1.0", changed),
            &home_id,
            "Bob.",
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("version_collision"), "{message}");
        assert!(!message.contains(&alice.artifact_id), "{message}");
    }

    #[tokio::test]
    async fn malformed_and_future_observations_do_not_block_receipts() {
        let db = crate::create_database(":memory:").await.unwrap();
        let home_id = home(&db).await;
        let revision = revision_for("0.1.0", BODY);
        let first = import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "First.")
            .await
            .unwrap();
        // Hand-written observations bypassing tool validation: one garbage
        // as_of, one far in the future.
        for as_of in ["not-a-timestamp", "2999-06-01T12:00:00Z"] {
            crate::store::append(
                &db,
                crate::store::AppendSpec {
                    record_id: first.artifact_id.clone(),
                    event_type: "facet.set".into(),
                    payload: serde_json::json!({
                        "key": "package_receipt",
                        "value": "{}",
                        "as_of": as_of,
                        "observation_only": true,
                    }),
                    actor: None,
                },
            )
            .await
            .unwrap();
        }
        let second =
            import_revision_into_alpha(&db, &local_caller(), &revision, &home_id, "Second.")
                .await
                .unwrap();
        assert!(!second.created);
        let pool = db.write_pool();
        let distinct: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT as_of) FROM facet_observations
              WHERE record_id = ? AND key = 'package_receipt'",
        )
        .bind(&first.artifact_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(distinct, 4, "each receipt keeps its own as_of");
    }
}
