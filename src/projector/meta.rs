//! The meta-tier projector — the `meta_events` -> meta-projection fold
//! (decision ba9f97e). The exact analogue of `super::project` for the system tier.
//!
//! `project_meta()` applies ONE meta event to `vocabularies`,
//! `vocabulary_values`, `vocabulary_value_json_nodes`, `schema_config` and
//! `workspace_rule_installations` and `schema_config_json_nodes`.
//! It is the ONLY writer of those
//! tables: every meta mutation is append-event-then-project (see
//! `crate::meta::log`), and the meta rebuild-and-diff
//! (`crate::conformance::rebuild_and_diff_meta`) folds the same events through
//! this same function into a fresh database.
//!
//! Contract, identical to the content projector: DETERMINISTIC, EXACTLY-ONCE,
//! IN-ORDER replay. Timestamps come from the event (`event.created_at`), never
//! from a SQL `DEFAULT`, so two replays of the same log produce byte-identical
//! rows. It is NOT idempotent — the harness replays each event exactly once from
//! an empty database.
//!
//! DELIBERATELY GUARD-FREE. The lifecycle guards (no hard delete of a seeded or
//! referenced value, no alias chains, no cross-vocabulary alias, pack rows are
//! seed-only) live at the WRITE path in `crate::meta`, not here — the same split
//! the content tier already makes. A guard here would re-run at replay against a
//! half-built database and fail rebuilds that the live write legitimately
//! allowed: `delete_value`'s referenced-by-`facet_values` check, for instance,
//! reads a content-tier table that the meta rebuild's fresh database does not
//! populate at all. Guards decide whether an event may be APPENDED; the fold's
//! only job is to reproduce what was appended.

use sqlx::SqliteConnection;

use crate::error::{Error, Result};
#[cfg(any(test, feature = "v2-kernel-probe"))]
use crate::meta::events::{
    ConsumerRequiredV1Payload, ConsumerRetiredV1Payload, DefinitionAdoptionSetV1Payload,
    DefinitionArtifactInstalledPayload, PackageArtifactInstalledV1Payload,
};
use crate::meta::events::{
    MetaEventRow, SchemaConfigSetPayload, VocabValueAliasedPayload, VocabValueGlossSetPayload,
    VocabValueMetadataSetPayload, VocabValueProposedPayload, VocabValueReorderedPayload,
    VocabularyCreatedPayload,
};

fn parse_payload<T: serde::de::DeserializeOwned>(event: &MetaEventRow) -> Result<T> {
    let Some(payload) = event.payload.as_deref() else {
        return Err(Error::engine(format!(
            "meta event {} ({}) has no payload",
            event.id, event.event_type
        )));
    };
    Ok(serde_json::from_str(payload)?)
}

/// Apply ONE meta event to the meta projections.
pub async fn project_meta(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    match event.event_type.as_str() {
        "vocabulary.created" => vocabulary_created(conn, event).await,
        "vocabulary.deleted" => vocabulary_deleted(conn, event).await,
        "vocab_value.proposed" => vocab_value_proposed(conn, event).await,
        "vocab_value.promoted" => vocab_value_status(conn, event, "active", true).await,
        "vocab_value.deprecated" => vocab_value_status(conn, event, "deprecated", false).await,
        "vocab_value.aliased" => vocab_value_aliased(conn, event).await,
        "vocab_value.reordered" => vocab_value_reordered(conn, event).await,
        "vocab_value.gloss_set" => vocab_value_gloss_set(conn, event).await,
        "vocab_value.metadata_set" => vocab_value_metadata_set(conn, event).await,
        "vocab_value.deleted" => vocab_value_deleted(conn, event).await,
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        "definition_artifact.installed" => definition_artifact_installed(conn, event).await,
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        "definition_adoption.set.v1" => definition_adoption_set_v1(conn, event).await,
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        "package_artifact.installed.v1" => package_artifact_installed_v1(conn, event).await,
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        "consumer_required.v1" => consumer_required_v1(conn, event).await,
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        "consumer_retired.v1" => consumer_retired_v1(conn, event).await,
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        "rule_installation.set.v1" => {
            crate::meta::rule_installation::fold_installation_set_v1(conn, event).await
        }
        "workspace_rule_installation.set.v1" => {
            crate::meta::workspace_rule_installation::fold(conn, event).await
        }
        "schema_config.set" => schema_config_set(conn, event).await,
        other => Err(Error::engine(format!("unknown meta event type: {other}"))),
    }
}

/// Fold a whole meta log into a (fresh) database, in order.
pub async fn replay_meta(conn: &mut SqliteConnection, events: &[MetaEventRow]) -> Result<()> {
    for event in events {
        project_meta(conn, event).await?;
    }
    Ok(())
}

async fn vocabulary_created(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabularyCreatedPayload = parse_payload(event)?;
    sqlx::query("INSERT INTO vocabularies (id, name, created_at) VALUES (?, ?, ?)")
        .bind(&event.subject_id)
        .bind(&p.name)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `vocabulary_values` cascade-delete off their parent vocabulary in the frozen
/// DDL, and `crate::db` enables `PRAGMA foreign_keys` per connection — so the
/// values go with it here exactly as they do on the live path, without the fold
/// enumerating them. That equivalence is what keeps the rebuild honest: a fold
/// that deleted values explicitly would diverge from a live delete the moment the
/// cascade and the enumeration disagreed.
async fn vocabulary_deleted(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let res = sqlx::query("DELETE FROM vocabularies WHERE id = ?")
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_proposed(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueProposedPayload = parse_payload(event)?;
    let metadata = serde_json::to_string(&p.metadata)?;
    sqlx::query(
        "INSERT INTO vocabulary_values
            (id, vocabulary_id, value, gloss, status, ordinal, terminality, metadata)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.subject_id)
    .bind(&p.vocabulary_id)
    .bind(&p.value)
    .bind(&p.gloss)
    .bind(&p.status)
    .bind(p.ordinal)
    .bind(&p.terminality)
    .bind(&metadata)
    .execute(&mut *conn)
    .await?;
    crate::json_nodes_projection::replace_sqlite(conn, &event.subject_id, &metadata).await?;
    Ok(())
}

async fn vocab_value_metadata_set(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueMetadataSetPayload = parse_payload(event)?;
    let metadata = serde_json::to_string(&p.metadata)?;
    let res = sqlx::query("UPDATE vocabulary_values SET metadata = ? WHERE id = ?")
        .bind(&metadata)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)?;
    crate::json_nodes_projection::replace_sqlite(conn, &event.subject_id, &metadata).await
}

async fn vocab_value_reordered(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueReorderedPayload = parse_payload(event)?;
    let res = sqlx::query("UPDATE vocabulary_values SET ordinal = ? WHERE id = ?")
        .bind(p.ordinal)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_gloss_set(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueGlossSetPayload = parse_payload(event)?;
    let res = sqlx::query("UPDATE vocabulary_values SET gloss = ? WHERE id = ?")
        .bind(p.gloss)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

/// Promote and deprecate differ only in the status they write and in whether
/// they clear `alias_of`: promotion makes a value canonical, so it cannot remain
/// an alias of something else; deprecation leaves any alias in place.
async fn vocab_value_status(
    conn: &mut SqliteConnection,
    event: &MetaEventRow,
    status: &str,
    clear_alias: bool,
) -> Result<()> {
    let sql = if clear_alias {
        "UPDATE vocabulary_values SET status = ?, alias_of = NULL WHERE id = ?"
    } else {
        "UPDATE vocabulary_values SET status = ? WHERE id = ?"
    };
    let res = sqlx::query(sql)
        .bind(status)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_aliased(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueAliasedPayload = parse_payload(event)?;
    let res = sqlx::query(
        "UPDATE vocabulary_values SET alias_of = ?, status = 'deprecated' WHERE id = ?",
    )
    .bind(&p.alias_of)
    .bind(&event.subject_id)
    .execute(&mut *conn)
    .await?;
    assert_hit(&res, event)
}

async fn vocab_value_deleted(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let res = sqlx::query("DELETE FROM vocabulary_values WHERE id = ?")
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn schema_config_set(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: SchemaConfigSetPayload = parse_payload(event)?;
    let nodes = crate::schema_config_json_nodes::prepare(&p.data)?;
    // Unconditional upsert — see SchemaConfigSetPayload: both the user-layer
    // upsert and the pack-layer seed only append when the write landed, so the
    // layer guard belongs at the write path and replaying is a plain apply.
    sqlx::query(
        "INSERT INTO schema_config (id, layer, name, data, applies_to_collection_id, version_lineage, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT (id) DO UPDATE SET layer           = excluded.layer,
                                         name            = excluded.name,
                                         data            = excluded.data,
                                         applies_to_collection_id = excluded.applies_to_collection_id,
                                         version_lineage = excluded.version_lineage",
    )
    .bind(&event.subject_id)
    .bind(&p.layer)
    .bind(&p.name)
    .bind(&p.data)
    .bind(&p.applies_to_collection_id)
    .bind(&p.version_lineage)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    crate::schema_config_json_nodes::replace_prepared(conn, &event.subject_id, nodes).await
}

/// An update/delete that matched no row means the log describes a mutation of
/// something that is not there — a phantom event. On the content tier the
/// equivalent is `assert_record_live`; here the check is after the fact because
/// the subject's absence is the only failure mode. Erroring rolls back the
/// append transaction on the live path, and fails the rebuild on the replay path
/// — which is the point: the log is the law, so a log that cannot be folded is a
/// failing test rather than a silent no-op.
fn assert_hit(res: &sqlx::sqlite::SqliteQueryResult, event: &MetaEventRow) -> Result<()> {
    if res.rows_affected() == 0 {
        return Err(Error::engine(format!(
            "meta event {} ({}) matched no row: subject {} does not exist",
            event.id, event.event_type, event.subject_id
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gated v2 kernel fold (E1 test-only prototype). These arms match
// exactly `META_KERNEL_EVENT_TYPES`; production `META_EVENT_TYPES` and
// `META_PROJECTION_TABLES` remain separate from the kernel additions, and the pre-60
// `vocab_value_deleted` compatibility rule from the reference branch is
// deliberately NOT ported (no such history exists on this branch).

/// Fold one `definition_artifact.installed` event: verify, then project into
/// the dedicated `definition_artifacts` table.
///
/// The tier's one deliberate replay-time verification: artifact bytes are
/// self-verifying, so the fold recomputes SHA-256 from the event-carried
/// bytes and fails on any mismatch instead of projecting a lying revision.
/// The fold never consults `vocabulary_values`.
#[cfg(any(test, feature = "v2-kernel-probe"))]
async fn definition_artifact_installed(
    conn: &mut SqliteConnection,
    event: &MetaEventRow,
) -> Result<()> {
    let p: DefinitionArtifactInstalledPayload = parse_payload(event)?;
    let identity =
        crate::meta::definition_artifact::verify_installed_payload(&event.subject_id, &p)?;
    // Same-tier replay conflict detection: the write path rejects a second
    // family/version with different bytes before append, but a forged log can
    // carry two individually valid installs. The fold re-enforces the rule
    // against what it has already built. This reads only the table being
    // built (no cross-tier access), so it stays deterministic and
    // replay-safe.
    let existing: Vec<(String,)> =
        sqlx::query_as("SELECT digest FROM definition_artifacts WHERE family = ? AND version = ?")
            .bind(&identity.family)
            .bind(identity.version as i64)
            .fetch_all(&mut *conn)
            .await?;
    for (digest,) in existing {
        if digest != identity.digest {
            return Err(Error::engine(format!(
                "definition artifact conflict on replay: {}@{} is already installed with different bytes",
                identity.family, identity.version
            )));
        }
    }
    let envelope = crate::meta::definition_artifact::envelope_from_payload(&p);
    let kinds = envelope
        .get("kinds")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    sqlx::query(
        "INSERT INTO definition_artifacts
            (id, family, version, digest, artifact_bytes, kinds, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.subject_id)
    .bind(&identity.family)
    .bind(identity.version as i64)
    .bind(&identity.digest)
    .bind(&p.artifact_bytes)
    .bind(serde_json::to_string(&kinds)?)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Fold one `definition_adoption.set.v1` event: verify the payload, the
/// reserved `definition-adoption:{family}` subject, and the selected revision
/// against the installed projection, then upsert `definition_adoptions`.
#[cfg(any(test, feature = "v2-kernel-probe"))]
async fn definition_adoption_set_v1(
    conn: &mut SqliteConnection,
    event: &MetaEventRow,
) -> Result<()> {
    let raw: serde_json::Value = parse_payload(event)?;
    if raw.get("selected").is_none() {
        return Err(Error::engine(
            "definition adoption payload must explicitly carry selected or null",
        ));
    }
    let p: DefinitionAdoptionSetV1Payload = serde_json::from_value(raw)?;
    crate::meta::definition_artifact::validate_family_version(&p.family, 0)?;
    if let Some(key) = &p.request_key {
        crate::meta::adoption::validate_request_key(key)?;
    }
    if event.subject_id != format!("definition-adoption:{}", p.family) {
        return Err(Error::engine(
            "definition adoption subject does not match reserved family identity",
        ));
    }
    if event.seq < 1 {
        return Err(Error::engine(
            "definition adoption event has invalid sequence",
        ));
    }
    if let Some(selected) = &p.selected {
        if selected.family != p.family
            || selected.digest.len() != 64
            || !selected
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::engine(
                "definition adoption selected revision identity is invalid",
            ));
        }
        let installed = crate::definition_registry::read_definition_artifact_on(
            conn,
            &selected.family,
            selected.version,
            &selected.digest,
        )
        .await?;
        if installed.is_none() {
            return Err(Error::engine(
                "definition adoption selected revision has not been installed",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO definition_adoptions (family, selected_version, selected_digest, event_seq)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(family) DO UPDATE SET
           selected_version=excluded.selected_version,
           selected_digest=excluded.selected_digest,
           event_seq=excluded.event_seq",
    )
    .bind(&p.family)
    .bind(p.selected.as_ref().map(|s| s.version as i64))
    .bind(p.selected.as_ref().map(|s| &s.digest))
    .bind(event.seq)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Fold one `package_artifact.installed.v1` event: verify the payload and
/// subject, re-validate the manifest, recompute its digest, verify every
/// embedded definition revision against the installed projection, refuse a
/// forged same-triple collision, then insert the package row.
///
/// The fold never trusts the projection it is building beyond the
/// same-triple check: definition bytes come from the already-folded
/// `definition_artifacts` table, which the log order guarantees precedes the
/// package event on the honest write path.
#[cfg(any(test, feature = "v2-kernel-probe"))]
async fn package_artifact_installed_v1(
    conn: &mut SqliteConnection,
    event: &MetaEventRow,
) -> Result<()> {
    let p: PackageArtifactInstalledV1Payload = parse_payload(event)?;
    let identity = crate::meta::package::verify_package_payload(&event.subject_id, &p)?;
    if event.seq < 1 {
        return Err(Error::engine("package artifact event has invalid sequence"));
    }
    let existing: Vec<(String,)> = sqlx::query_as(
        "SELECT digest FROM package_artifacts WHERE namespace = ? AND name = ? AND version = ?",
    )
    .bind(&identity.namespace)
    .bind(&identity.name)
    .bind(identity.version as i64)
    .fetch_all(&mut *conn)
    .await?;
    if let Some((digest,)) = existing.into_iter().next() {
        // The live write path appends nothing on exact retry, so any second
        // install event for a triple is corruption — even with the same
        // digest. Accepting it would silently legitimize a forged duplicate.
        if digest != identity.digest {
            return Err(Error::engine(format!(
                "package artifact conflict on replay: {}/{}@{} is already installed with a different digest",
                identity.namespace, identity.name, identity.version
            )));
        }
        return Err(Error::engine(format!(
            "package artifact duplicate on replay: {}/{}@{} already has an install event",
            identity.namespace, identity.name, identity.version
        )));
    }
    let value: serde_json::Value = serde_json::from_str(&p.manifest_bytes)
        .map_err(|_| Error::engine("package manifest bytes must be canonical JSON"))?;
    let manifest = crate::package_manifest::PackageManifest::from_canonical_value(&value)?;
    for entry in &manifest.definitions {
        let stored: Option<(String, String)> = sqlx::query_as(
            "SELECT digest, artifact_bytes FROM definition_artifacts
              WHERE family = ? AND version = ?",
        )
        .bind(&entry.family)
        .bind(entry.version as i64)
        .fetch_optional(&mut *conn)
        .await?;
        match stored {
            Some((digest, bytes)) if digest == entry.digest && bytes == entry.artifact_bytes => {}
            _ => {
                return Err(Error::engine(format!(
                    "package definition '{}@{}' has not been installed with the pinned bytes",
                    entry.family, entry.version
                )));
            }
        }
    }
    sqlx::query(
        "INSERT INTO package_artifacts
            (id, namespace, name, version, digest, manifest_bytes, event_seq, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.subject_id)
    .bind(&identity.namespace)
    .bind(&identity.name)
    .bind(identity.version as i64)
    .bind(&identity.digest)
    .bind(&p.manifest_bytes)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Fold one `consumer_required.v1` event: verify the payload against its
/// subject, validate the key and pin, verify the pinned revision is
/// installed with exact bytes, then upsert the requirement row active.
/// The fold never invents a pin: an uninstalled revision breaks the rebuild.
#[cfg(any(test, feature = "v2-kernel-probe"))]
async fn consumer_required_v1(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: ConsumerRequiredV1Payload = parse_payload(event)?;
    crate::meta::consumer::verify_required_payload(&event.subject_id, &p)?;
    if event.seq < 1 {
        return Err(Error::engine(
            "consumer requirement event has invalid sequence",
        ));
    }
    let installed = crate::definition_registry::read_definition_artifact_on(
        conn, &p.family, p.version, &p.digest,
    )
    .await?;
    if installed.is_none() {
        return Err(Error::engine(
            "consumer requirement selects a definition revision that is not installed",
        ));
    }
    sqlx::query(
        "INSERT INTO consumer_requirements
            (scope_home, consumer_kind, consumer_namespace, consumer_name,
             family, version, digest, active, event_seq, actor, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
          ON CONFLICT(scope_home, consumer_kind, consumer_namespace, consumer_name, family)
          DO UPDATE SET version=excluded.version, digest=excluded.digest,
            active=1, event_seq=excluded.event_seq, actor=excluded.actor,
            created_at=excluded.created_at",
    )
    .bind(&p.scope_home)
    .bind(&p.consumer_kind)
    .bind(&p.consumer_namespace)
    .bind(&p.consumer_name)
    .bind(&p.family)
    .bind(p.version as i64)
    .bind(&p.digest)
    .bind(event.seq)
    .bind(event.actor.clone().unwrap_or_default())
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Fold one `consumer_retired.v1` event: verify the key, require a prior
/// row (a forged retire-alone breaks the rebuild), keep the pin and mark
/// the row retired.
#[cfg(any(test, feature = "v2-kernel-probe"))]
async fn consumer_retired_v1(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: ConsumerRetiredV1Payload = parse_payload(event)?;
    crate::meta::consumer::verify_retired_payload(&event.subject_id, &p)?;
    if event.seq < 1 {
        return Err(Error::engine(
            "consumer retirement event has invalid sequence",
        ));
    }
    // The retirement must name the live row's exact pin: a forged retire for
    // a different pin breaks the rebuild instead of clearing a row it never
    // verified.
    let live: Option<(i64, String)> = sqlx::query_as(
        "SELECT version, digest FROM consumer_requirements
          WHERE scope_home=? AND consumer_kind=? AND consumer_namespace=?
            AND consumer_name=? AND family=?",
    )
    .bind(&p.scope_home)
    .bind(&p.consumer_kind)
    .bind(&p.consumer_namespace)
    .bind(&p.consumer_name)
    .bind(&p.family)
    .fetch_optional(&mut *conn)
    .await?;
    match live {
        Some((version, digest)) if version == p.version as i64 && digest == p.digest => {}
        _ => {
            return Err(Error::engine(
                "consumer retirement names a pin the live row does not hold",
            ));
        }
    }
    let res = sqlx::query(
        "UPDATE consumer_requirements SET active=0, event_seq=?, actor=?
          WHERE scope_home=? AND consumer_kind=? AND consumer_namespace=?
            AND consumer_name=? AND family=?",
    )
    .bind(event.seq)
    .bind(event.actor.clone().unwrap_or_default())
    .bind(&p.scope_home)
    .bind(&p.consumer_kind)
    .bind(&p.consumer_namespace)
    .bind(&p.consumer_name)
    .bind(&p.family)
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() == 0 {
        return Err(Error::engine(
            "consumer retirement matched no row: no prior requirement for this key",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod kernel_fold_consistency_tests {
    use crate::meta::events::META_KERNEL_EVENT_TYPES;

    /// The gated arms above must match exactly the gated event-type list:
    /// string literals cannot name the list in patterns, so this pins them
    /// together instead.
    #[test]
    fn kernel_event_list_matches_fold_arms() {
        assert_eq!(
            META_KERNEL_EVENT_TYPES,
            [
                "definition_artifact.installed",
                "definition_adoption.set.v1",
                "package_artifact.installed.v1",
                "consumer_required.v1",
                "consumer_retired.v1",
                "rule_installation.set.v1"
            ]
        );
    }
}
