//! Trusted generated admission preparation. No request-provided evidence is a
//! source of authority: compare the entire closed candidate with a fresh host
//! resolution before carrying its owned source proof into the workspace writer.
use super::{facet_resolver, source_proof, v2, Revision};
use crate::{db::Db, Error, Result};
use serde_json::Value;
use std::{collections::BTreeSet, time::Instant};

pub(crate) struct Prepared {
    candidate: facet_resolver::Prepared,
}
impl Prepared {
    pub(crate) fn revision(&self) -> &Revision {
        &self.candidate.revision
    }
    pub(crate) fn name(&self) -> &str {
        &self.candidate.name
    }
    pub(crate) async fn recheck(
        &self,
        db: &Db,
        writer: &mut source_proof::Writer,
        actor: &str,
    ) -> Result<()> {
        self.candidate.proof.recheck_on(db, writer, actor).await?;
        Ok(())
    }
}

/// The workspace is the host kernel's immutable identity, never a manifest
/// field supplied by the client or an ingress role/membership assertion.
pub(crate) async fn prepare(
    db: &Db,
    actor: &str,
    bearer: &str,
    requested: &Value,
    deadline: Instant,
) -> Result<Prepared> {
    let definition: v2::Definition = serde_json::from_value(requested.clone())?;
    if serde_json::to_value(&definition)? != *requested {
        return Err(Error::engine("generated candidate must be canonical"));
    }
    definition.validate()?;
    let workspace = {
        let mut conn = db.pool().acquire().await?;
        workspace_on(&mut conn).await?
    };
    let manifest = &definition.generated;
    let selection = match &manifest.selection {
        v2::Selection::Keys { keys } => crate::query::generated_facets::Selection::Keys(
            keys.iter().cloned().collect::<BTreeSet<_>>(),
        ),
        v2::Selection::All => crate::query::generated_facets::Selection::All,
    };
    let candidate = facet_resolver::prepare(
        db,
        actor,
        &workspace,
        bearer,
        facet_resolver::Request {
            record_type: manifest.context.r#type.clone(),
            kind: manifest.context.kind.clone(),
            home: manifest.context.logical_home_id.clone(),
            selection,
        },
        deadline,
    )
    .await?;
    // Includes query/profile/output/meanings, origin/selector, every retained
    // fragment/reference/absence/governance/value, and the deterministic name.
    // Comparing a digest or caller-selected evidence subset is insufficient.
    if candidate.revision.definition != *requested {
        return Err(Error::conflict(
            "view_source_changed: generated candidate differs from trusted resolution; propose again",
        ));
    }
    candidate.validate(deadline).await?;
    Ok(Prepared { candidate })
}

/// Kernel coordinates already certify this immutable UUID at rowid 1. Do not
/// use v1's absent database_identity singleton, a pathname, caller assertions,
/// or standby's history-scanning discovery of preserved v1 import origins.
pub(crate) async fn workspace_on(conn: &mut sqlx::SqliteConnection) -> Result<String> {
    let id: Option<String> = sqlx::query_scalar(
        "SELECT CASE WHEN octet_length(id)=36 THEN id ELSE '' END FROM main.content_events WHERE seq=1 AND type=? AND record_id=?",
    ).bind(crate::events::KERNEL_GENESIS_EVENT).bind(crate::events::KERNEL_ROOT_ID)
        .fetch_optional(conn).await?;
    let id = id
        .and_then(|id| uuid::Uuid::parse_str(&id).ok())
        .ok_or_else(|| {
            Error::engine("view_profile_unsupported: invalid kernel workspace identity")
        })?;
    Ok(format!("kernel:{id}"))
}
pub(crate) async fn is_writer(conn: &mut sqlx::SqliteConnection) -> Result<bool> {
    let mut handle = conn.lock_handle().await?;
    Ok(unsafe {
        libsqlite3_sys::sqlite3_txn_state(handle.as_raw_handle().as_ptr(), c"main".as_ptr())
            == libsqlite3_sys::SQLITE_TXN_WRITE
    })
}

/// Current View only, including archived bearers. This authorizes immutable
/// receipt/metadata retrieval; it does not certify executable sources or SQL.
pub(crate) async fn authorize_metadata_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    definition: &v2::Definition,
    deadline: Instant,
) -> Result<()> {
    let mut checked = BTreeSet::new();
    for id in std::iter::once(definition.generated.context.logical_home_id.as_str()).chain(
        definition
            .generated
            .sources
            .iter()
            .filter_map(|s| s.anchor.as_deref()),
    ) {
        super::storage::check_deadline(deadline)?;
        super::source_proof::require_visible_anchor_on(conn, actor, id, &mut checked).await?;
    }
    Ok(())
}

// This request-local scope is established only after immutable certificates
// and the owned source proof pass on the enrolled writer. It grants no role;
// all existing current bearer/owner/closure checks remain in the source path.
// Canonical replay never consults it.
tokio::task_local! { static CERTIFIED: BTreeSet<String>; }
pub(crate) fn require_certified(revision: &Revision) -> Result<()> {
    if CERTIFIED
        .try_with(|set| set.contains(&revision.definition_sha256))
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(Error::conflict(
            "view_validation_changed: generated preflight missing; prepare again",
        ))
    }
}
pub(crate) async fn certified<T>(
    digests: BTreeSet<String>,
    work: impl std::future::Future<Output = T>,
) -> T {
    CERTIFIED.scope(digests, work).await
}

pub(crate) struct Referenced {
    proof: source_proof::Proof,
    pub(crate) digests: BTreeSet<String>,
}
impl Referenced {
    pub(crate) async fn recheck(
        &self,
        db: &Db,
        writer: &mut source_proof::Writer,
        actor: &str,
    ) -> Result<()> {
        self.proof.recheck_on(db, writer, actor).await?;
        Ok(())
    }
}
/// Outside both guards. Exact referenced bodies were SQL-certified by closure
/// preflight; this later S snapshot binds mandatory current sources/context and
/// catches every relevant import in (S,T] before effect, including new aliases.
pub(crate) async fn prepare_referenced(
    db: &Db,
    actor: &str,
    ids: &[String],
    deadline: Instant,
) -> Result<Option<Referenced>> {
    let mut conn = db.pool().begin().await?;
    let mut revisions = Vec::new();
    let mut bytes = 0usize;
    for id in ids {
        super::storage::check_deadline(deadline)?;
        let len: i64 = sqlx::query_scalar(
            "SELECT octet_length(payload) FROM main.content_events WHERE id=? AND type=?",
        )
        .bind(id)
        .bind(super::REVISION)
        .fetch_one(&mut *conn)
        .await?;
        let len = usize::try_from(len).map_err(|_| Error::engine("view_revision_unavailable"))?;
        if len > super::MAX_CARRIER_BYTES
            || len > (512 * 1024usize).saturating_sub(bytes)
            || revisions.len() >= 16
        {
            return Err(Error::engine("view_budget_exceeded: generated closure"));
        }
        bytes += len;
        let event = super::read_event(&mut conn, id, i64::MAX).await?;
        let revision: Revision = super::decode(&event, super::MAX_CARRIER_BYTES)?;
        revision.validate_retained(&event)?;
        if revision.v == 2 {
            revisions.push(revision);
        }
    }
    conn.rollback().await?;
    if revisions.is_empty() {
        return Ok(None);
    }
    let workspace = {
        let mut conn = db.pool().acquire().await?;
        workspace_on(&mut conn).await?
    };
    let mut definitions = Vec::new();
    let mut digests = BTreeSet::new();
    for revision in revisions {
        let definition: v2::Definition = serde_json::from_value(revision.definition)?;
        let bearer = revision
            .view_id
            .strip_prefix("native.named-view:")
            .ok_or_else(|| Error::engine(super::MISSING))?
            .to_owned();
        definitions.push((bearer, definition));
        digests.insert(revision.definition_sha256);
    }
    let proof =
        source_proof::prepare_retained(db, actor, &workspace, &definitions, deadline).await?;
    Ok(Some(Referenced { proof, digests }))
}

/// Admission-only deduplication, outside guards. The lifecycle cap bounds this
/// search to 256 revision carriers. SQL extracts only the digest; it does not
/// certify historical bodies or execute their SQL. Only the matching immutable
/// body is fetched, closed-validated and compared in full with the trusted
/// candidate. Commit compares the bearer's indexed revision head and event
/// certificate, rather than repeating this search under its writer.
pub(crate) async fn identical_on(
    conn: &mut sqlx::SqliteConnection,
    ids: &[String],
    candidate: &Revision,
    deadline: Instant,
) -> Result<Option<super::Pin>> {
    if ids.len() > 128 {
        return Err(Error::engine(
            "view_budget_exceeded: bearer revision history",
        ));
    }
    let mut matched = None;
    for id in ids {
        super::storage::check_deadline(deadline)?;
        // Indexed point lookup, never a scan of unrelated bearer events. The
        // canonical lifetime cap permits at most 128 carriers for this bearer.
        // SQLite parses only a bounded carrier, returning no historical body.
        #[cfg(test)]
        super::record_revision_access(id); // SQLite JSON extraction is body work too.
        let (bytes, matches): (i64, bool) = sqlx::query_as(
            "SELECT octet_length(payload),CASE WHEN octet_length(payload)<=? THEN json_extract(payload,'$.definition_sha256')=? ELSE 0 END FROM main.content_events WHERE id=? AND type=?",
        ).bind(super::MAX_CARRIER_BYTES as i64).bind(&candidate.definition_sha256)
            .bind(id).bind(super::REVISION).fetch_one(&mut *conn).await?;
        if !(0..=super::MAX_CARRIER_BYTES as i64).contains(&bytes) {
            return Err(Error::engine("view_revision_unavailable"));
        }
        super::storage::check_deadline(deadline)?;
        if matches {
            matched = Some(id.clone());
            break;
        }
    }
    let Some(id) = matched else {
        return Ok(None);
    };
    let event = super::read_event(conn, &id, i64::MAX).await?;
    let revision: Revision = super::decode(&event, super::MAX_CARRIER_BYTES)?;
    let common = revision.validate_retained(&event)?;
    if revision.v != candidate.v
        || revision.view_id != candidate.view_id
        || revision.definition != candidate.definition
    {
        return Err(Error::conflict(
            "view_revision_unavailable: generated deduplication mismatch",
        ));
    }
    Ok(Some(super::Pin {
        view_id: revision.view_id,
        revision_id: id,
        definition_sha256: revision.definition_sha256,
        schema_sha256: common.query.output.schema_sha256,
    }))
}
