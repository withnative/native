//! Kernel-native session foundation. No session creation, scheduling or hosted
//! ingress: single-writer ownership and lifecycle qualification must precede it.
use super::live::{base_proof, BaseVersion, BodyEvent, CutProof, LoadedBody, SessionMode};
use super::{PeerKind, VersionSnapshot};
use crate::authorization::Capability;
use crate::kernel::{self, hq};
use crate::{db::Db, mcp::Caller, Error, Result};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

fn digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

/// The supplied Caller must already be H2/H3 reconciled by the host. Re-resolve
/// its binding, current roster and exact app claim on this actual snapshot.
async fn principal_on(conn: &mut SqliteConnection, caller: &Caller) -> Result<String> {
    let principal: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    if !kernel::hosted_identity::admitted(conn, &principal).await? {
        return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
    }
    if let Some(app) = caller.host_asserted_app() {
        kernel::app_installs::admit_app_on(conn, &principal, app).await?;
    }
    Ok(principal)
}

/// Mint a registry contributor from an already host-reconciled caller. The
/// principal is a kernel principal id, never a v1 account credential.
pub(crate) async fn contributor_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
) -> Result<super::AcknowledgedContributor> {
    let principal = principal_on(conn, caller).await?;
    Ok(contributor_for(principal, caller))
}

fn contributor_for(principal: String, caller: &Caller) -> super::AcknowledgedContributor {
    let (executor_kind, _, _) = crate::provenance::verified_executor_attribution(caller);
    let channel = caller.channel();
    super::AcknowledgedContributor {
        principal,
        executor_kind,
        run_key: caller
            .run_key()
            .filter(|s| !s.is_empty() && *s != "new")
            .map(str::to_owned),
        app: caller.host_asserted_app().map(|app| super::AppAttribution {
            package: app.package.clone(),
            version: app.version.clone(),
            install_event_id: app.install_event_id.clone(),
        }),
        channel: (channel != crate::provenance::Channel::Unknown)
            .then(|| channel.as_str().to_owned()),
    }
}

async fn validate_contributor_on(
    conn: &mut SqliteConnection,
    fact: &super::AcknowledgedContributor,
    current: bool,
) -> Result<()> {
    let bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND kind='account' AND auth_binding IS NOT NULL AND auth_binding!='')")
        .bind(&fact.principal).fetch_one(&mut *conn).await?;
    if !bound || (current && !kernel::hosted_identity::admitted(conn, &fact.principal).await?) {
        return Err(Error::engine("kernel contributor binding unavailable"));
    }
    if current {
        if let Some(app) = &fact.app {
            let claim = crate::mcp::app_attribution::AppAttribution::new(
                &app.package,
                &app.version,
                &app.install_event_id,
            )?;
            kernel::app_installs::admit_app_on(conn, &fact.principal, &claim).await?;
        }
    }
    Ok(())
}

/// Read the sealed catalogue directly and feed the existing pure kind
/// reducer. No v1 database, vocabulary tables or schema shim is constructed.
async fn supported_on(
    conn: &mut SqliteConnection,
    typ: &str,
    kind: Option<&str>,
    runtime: bool,
) -> Result<bool> {
    if runtime || !matches!(typ, "Document" | "WorkItem") {
        return Ok(false);
    }
    let Some(kind) = kind else {
        return Ok(typ == "Document");
    };
    let vocabulary = kernel::v1_state::rows_on(conn, "vocabularies")
        .await?
        .into_iter()
        .find(|row| row["name"] == format!("kind:{typ}"));
    let values = kernel::v1_state::rows_on(conn, "vocabulary_values").await?;
    let value = vocabulary.as_ref().and_then(|vocabulary| {
        values
            .iter()
            .find(|row| row["vocabulary_id"] == vocabulary["id"] && row["value"] == kind)
    });
    let mut joined = None;
    if let Some(value) = value {
        use crate::portable_sql::{NormalizedRow, NormalizedValue};
        let canonical = value["alias_of"]
            .as_str()
            .and_then(|id| values.iter().find(|row| row["id"] == id));
        let mut row = NormalizedRow::new();
        for name in ["id", "status", "metadata", "alias_of"] {
            row.insert(
                name.into(),
                value[name]
                    .as_str()
                    .map(|s| NormalizedValue::Text(s.into()))
                    .unwrap_or(NormalizedValue::Null),
            );
        }
        for (name, column) in [
            ("canonical_id", "id"),
            ("canonical_value", "value"),
            ("canonical_status", "status"),
            ("canonical_metadata", "metadata"),
        ] {
            row.insert(
                name.into(),
                canonical
                    .and_then(|row| row[column].as_str())
                    .map(|s| NormalizedValue::Text(s.into()))
                    .unwrap_or(NormalizedValue::Null),
            );
        }
        joined = Some(row);
    }
    let resolved = crate::meta::kind::resolve_identity_row(typ, kind, joined.as_ref())?;
    Ok(super::eligibility::markdown_kind_supported(
        typ, kind, &resolved,
    ))
}

/// Ordinary View and live-scope validation, without author/contributor minting.
/// Only an existing-room current-read join calls this; NoRoom is unrestricted.
pub(crate) async fn require_live_scope_on(
    conn: &mut SqliteConnection,
    actor: &str,
    view: &kernel::KernelRecordView,
) -> Result<()> {
    kernel::kernel_require(conn, actor, &view.id, Capability::View).await?;
    if hq::tombstoned_on(conn, &view.id).await? {
        return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
    }
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(&view.id)
            .fetch_one(&mut *conn)
            .await?;
    let (typ, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        view.family.as_deref(),
        view.pin.as_ref().map(|p| p.version),
        primary.as_deref(),
        view.kind.as_deref(),
        &view.fields,
    );
    let runtime: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_facets WHERE record_id=? AND key='runtime')",
    )
    .bind(&view.id)
    .fetch_one(&mut *conn)
    .await?;
    if !supported_on(conn, typ.unwrap_or_default(), kind, runtime).await? {
        return Err(Error::engine(
            "current body read: room scope is no longer live Markdown",
        ));
    }
    Ok(())
}

/// Actual target metadata after View. This is not a body view or an operation
/// permit; only the reserved, complete compatibility pin can override type/kind.
struct LiveScopeMetadata {
    primary_type: Option<String>,
    kind: Option<String>,
    family: Option<String>,
    version: Option<u32>,
    fields: serde_json::Map<String, serde_json::Value>,
    runtime: bool,
}

async fn admitted_scope_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    mode: SessionMode,
) -> Result<(String, LiveScopeMetadata)> {
    let principal = principal_on(conn, caller).await?;
    // Coedit admission resolves the caller itself, without a provenance
    // app claim for the kernel gates to consult: enforce the grant here.
    if let Some(app) = caller.host_asserted_app() {
        let scope = kernel::app_installs::scope::scope_on(conn, &principal, &app.package).await?;
        if scope.is_scoped() && !kernel::app_scope_allows_target_on(conn, record, &scope).await? {
            return Err(Error::engine(kernel::OUTSIDE_APP_SCOPE));
        }
    }
    kernel::kernel_require(conn, &principal, record, Capability::View).await?;
    if mode == PeerKind::Edit {
        kernel::kernel_require(conn, &principal, record, Capability::Edit).await?;
    }
    if hq::tombstoned_on(conn, record).await? {
        return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
    }
    type Header = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        bool,
    );
    let (primary_type, kind, family, version, digest_present): Header = sqlx::query_as(
        "SELECT primary_type,kind,pin_family,pin_version,pin_digest IS NOT NULL FROM main.kernel_records WHERE id=?",
    )
    .bind(record)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    // Match read_record_unchecked_on: incomplete pins expose neither family
    // nor version; out-of-range versions become0, never compatibility@1.
    let (family, version) = match (family, version, digest_present) {
        (Some(family), Some(version), true) => {
            (Some(family), Some(u32::try_from(version).unwrap_or(0)))
        }
        _ => (None, None),
    };
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name,value_json FROM main.kernel_record_fields WHERE record_id=? AND name IN ('v1_type','v1_kind') ORDER BY name",
    )
    .bind(record)
    .fetch_all(&mut *conn)
    .await?;
    let mut fields = serde_json::Map::new();
    for (name, value) in rows {
        fields.insert(name, serde_json::from_str(&value)?);
    }
    let runtime = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.kernel_facets WHERE record_id=? AND key='runtime')",
    )
    .bind(record)
    .fetch_one(&mut *conn)
    .await?;
    let scope = LiveScopeMetadata {
        primary_type,
        kind,
        family,
        version,
        fields,
        runtime,
    };
    let (typ, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        scope.family.as_deref(),
        scope.version,
        scope.primary_type.as_deref(),
        scope.kind.as_deref(),
        &scope.fields,
    );
    if !supported_on(conn, typ.unwrap_or_default(), kind, scope.runtime).await? {
        return Err(Error::engine(
            "kernel record body is not live-editable Markdown",
        ));
    }
    Ok((principal, scope))
}

/// Snapshot data only; never an operation or enqueue permit.
#[allow(dead_code)] // Consumed only by the inactive private peer-read unit.
pub(super) struct NativePeerFacts {
    contributor: super::AcknowledgedContributor,
}
#[allow(dead_code)]
impl NativePeerFacts {
    pub(super) fn principal(&self) -> &str {
        &self.contributor.principal
    }
    pub(super) fn contributor(&self) -> &super::AcknowledgedContributor {
        &self.contributor
    }
    pub(super) fn into_contributor(self) -> super::AcknowledgedContributor {
        self.contributor
    }
}

/// Scope and actual Caller provenance on ONE connection/snapshot, without
/// target-body hydration or a detached author/source admission.
#[allow(dead_code)]
pub(super) async fn peer_facts_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    mode: SessionMode,
) -> Result<NativePeerFacts> {
    let (principal, _) = admitted_scope_on(conn, caller, record, mode).await?;
    Ok(NativePeerFacts {
        contributor: contributor_for(principal, caller),
    })
}

/// Scope/authority only on this actual snapshot. No target body, projection,
/// event payload, digest, CAS or read-birth proof is loaded or manufactured.
pub(crate) async fn revalidate_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    mode: SessionMode,
) -> Result<()> {
    admitted_scope_on(conn, caller, record, mode)
        .await
        .map(|_| ())
}

pub(crate) async fn revalidate(
    db: &Db,
    caller: &Caller,
    record: &str,
    mode: SessionMode,
) -> Result<()> {
    let mut tx = db.pool().begin().await?;
    let checked = revalidate_on(&mut tx, caller, record, mode).await;
    // Settle even an ordinary refusal before exposing it. Rollback failure is
    // storage unavailability, never a positive capability or saved refusal.
    tx.rollback().await?;
    checked
}

/// Optimization for confirmed UTF-8 files ONLY, on an already View/mode/scope
/// admitted connection. Other admitted encodings retain full-load validation
/// and the final Rust UTF-8 byte limit; no universal hydration bound is claimed.
async fn seed_size_preflight_on(conn: &mut SqliteConnection, record: &str) -> Result<()> {
    #[cfg(test)]
    observe_body_work(record, BodyWorkStage::Encoding)?;
    let encoding: String = sqlx::query_scalar("PRAGMA encoding")
        .fetch_one(&mut *conn)
        .await?;
    if encoding == "UTF-8" {
        #[cfg(test)]
        observe_body_work(record, BodyWorkStage::Size)?;
        let bytes: Option<i64> = sqlx::query_scalar(
            "SELECT octet_length(body) FROM main.kernel_record_bodies WHERE record_id=?",
        )
        .bind(record)
        .fetch_optional(&mut *conn)
        .await?;
        if bytes.is_some_and(|bytes| bytes > super::registry::MAX_BODY_BYTES as i64) {
            return Err(Error::engine("kernel live body exceeds session budget"));
        }
    }
    Ok(())
}

pub(crate) async fn load_committed_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    mode: SessionMode,
) -> Result<LoadedBody> {
    let (principal, _) = admitted_scope_on(conn, caller, record, mode).await?;
    seed_size_preflight_on(conn, record).await?;
    #[cfg(test)]
    observe_body_work(record, BodyWorkStage::Hydrate)?;
    let view = kernel::read_record_on(conn, &principal, record)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    if hq::tombstoned_on(conn, record).await? {
        return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
    }
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(record)
            .fetch_one(&mut *conn)
            .await?;
    let (typ, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        view.family.as_deref(),
        view.pin.as_ref().map(|p| p.version),
        primary.as_deref(),
        view.kind.as_deref(),
        &view.fields,
    );
    let runtime: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_facets WHERE record_id=? AND key='runtime')",
    )
    .bind(record)
    .fetch_one(&mut *conn)
    .await?;
    if !supported_on(conn, typ.unwrap_or_default(), kind, runtime).await? {
        return Err(Error::engine(
            "kernel record body is not live-editable Markdown",
        ));
    }
    // Projection identity, not MAX(body-like event). Imported snapshots and
    // native body facts use their actual body-carrying event. Missing evidence
    // is an error, never an invented empty event or a swallowed SQL failure.
    let projection = kernel::body_evidence::projection_on(conn, record).await?;
    let body = projection.body.unwrap_or_default();
    let event = projection.event.map(|event| BodyEvent {
        id: event.id,
        seq: event.seq,
    });
    if view.body.as_deref().unwrap_or_default() != body {
        return Err(Error::engine(
            "kernel body snapshot disagrees with projection",
        ));
    }
    if body.len() > super::registry::MAX_BODY_BYTES {
        return Err(Error::engine("kernel live body exceeds session budget"));
    }
    #[cfg(test)]
    observe_body_work(record, BodyWorkStage::Hash)?;
    Ok(LoadedBody {
        base: BaseVersion {
            version: format!("rec:{}", view.revision),
            body_sha256: digest(&body),
            proof: CutProof {
                body_event_id: event.as_ref().map(|e| e.id.clone()),
                body_event_seq: event.as_ref().map(|e| e.seq),
                snapshot: None,
            },
        },
        body,
        admitted_as_document: typ == Some("Document"),
    })
}

pub(crate) async fn load_committed(
    db: &Db,
    caller: &Caller,
    record: &str,
    mode: SessionMode,
) -> Result<LoadedBody> {
    let mut tx = db.pool().begin().await?;
    let loaded = load_committed_on(&mut tx, caller, record, mode).await;
    // A typed preflight refusal must not escape ahead of this read snapshot's
    // rollback ACK either. A settlement error supersedes the saved outcome.
    tx.rollback().await?;
    loaded
}

/// Read-only native version content. This is payload input, never an ownership
/// witness or an installed CRDT snapshot proof. Routed callers derive it under
/// their writer guard and supply the separate opaque append permit.
pub(crate) struct NativeCandidateView<'a> {
    pub(crate) body: &'a str,
    pub(crate) contributors: &'a [super::AcknowledgedContributor],
    pub(crate) span_map: &'a super::span_map::SpanMap,
    pub(crate) session: &'a super::SessionId,
}

impl<'a> NativeCandidateView<'a> {
    fn installed(snapshot: &'a VersionSnapshot) -> Self {
        Self {
            body: snapshot.body(),
            contributors: snapshot.contributors(),
            span_map: snapshot.span_map(),
            session: snapshot.session_id(),
        }
    }
}

/// Exact append/readback identity, PROVISIONAL until the owner's known commit.
/// Metadata appended later in the same act must not replace this body identity.
pub(crate) struct NativeBodyCommit {
    pub(crate) body_event_id: String,
    pub(crate) body_event_seq: i64,
    pub(crate) body_sha256: String,
    pub(crate) record_version: String,
}

/// Standalone foundation use without a room. The common store backstop refuses
/// this unowned append against every reserved/live/grace room, including tests.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_in(
    db: &Db,
    tx: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    expected_body_event_seq: Option<i64>,
    snapshot: &VersionSnapshot,
    acts: &mut crate::act::ActAllocation,
) -> Result<BaseVersion> {
    cut_installed_in(
        db,
        tx,
        caller,
        record,
        expected_body_event_seq,
        snapshot,
        acts,
        None,
    )
    .await
}

/// Installed cuts retain the foundation's uniform current-app accounting.
/// Ownership and commit/install/drain remain with the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_installed_in(
    db: &Db,
    tx: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    expected_body_event_seq: Option<i64>,
    snapshot: &VersionSnapshot,
    acts: &mut crate::act::ActAllocation,
    permit: Option<super::live::kernel_writes::KernelAppendPermit>,
) -> Result<BaseVersion> {
    let committed = append_version_in(
        db,
        tx,
        caller,
        record,
        expected_body_event_seq,
        NativeCandidateView::installed(snapshot),
        None,
        None,
        acts,
        permit,
        true,
    )
    .await?;
    let event = BodyEvent {
        id: committed.body_event_id,
        seq: committed.body_event_seq,
    };
    Ok(BaseVersion {
        version: committed.record_version,
        proof: base_proof(snapshot, &committed.body_sha256, Some(&event)),
        body_sha256: committed.body_sha256,
    })
}

/// A routed update's outer transaction owns its app action. Never start a
/// second action here, and never fabricate an installed snapshot proof.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_routed_in(
    db: &Db,
    tx: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    expected_body_event_seq: Option<i64>,
    candidate: NativeCandidateView<'_>,
    origin: Option<serde_json::Value>,
    basis: Option<serde_json::Value>,
    acts: &mut crate::act::ActAllocation,
    permit: super::live::kernel_writes::KernelAppendPermit,
) -> Result<NativeBodyCommit> {
    append_version_in(
        db,
        tx,
        caller,
        record,
        expected_body_event_seq,
        candidate,
        origin,
        basis,
        acts,
        Some(permit),
        false,
    )
    .await
}

pub(crate) fn candidate_payload(
    candidate: &NativeCandidateView<'_>,
    origin: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    candidate_payload_with_basis(candidate, origin, None)
}

pub(crate) fn candidate_payload_with_basis(
    candidate: &NativeCandidateView<'_>,
    origin: Option<serde_json::Value>,
    basis: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let metadata = super::version_metadata::kernel_metadata_view(
        candidate.body,
        candidate.contributors,
        candidate.span_map,
        candidate.session,
    )?;
    Ok(serde_json::to_value(hq::KernelBodyPayload {
        body: candidate.body.into(),
        origin,
        basis,
        coedit: Some(metadata),
    })?)
}

/// Authority is evaluated on the actual append transaction independently of
/// payload assembly, ownership capability and app-action accounting.
async fn validate_candidate_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    expected_body_event_seq: Option<i64>,
    candidate: &NativeCandidateView<'_>,
) -> Result<String> {
    let loaded = load_committed_on(conn, caller, record, PeerKind::Edit).await?;
    if loaded.base.proof.body_event_seq != expected_body_event_seq {
        return Err(Error::conflict("kernel session body revision changed"));
    }
    let principal = principal_on(conn, caller).await?;
    for fact in candidate.contributors {
        validate_contributor_on(conn, fact, true).await?;
    }
    for owner in &candidate.span_map.authors {
        match owner {
            super::span_map::Owner::Contributor(fact) => {
                validate_contributor_on(conn, fact, false).await?
            }
            super::span_map::Owner::PriorVersion => {}
            super::span_map::Owner::Unattributed => {
                return Err(Error::engine("native cut requires attributed updates"))
            }
        }
    }
    Ok(principal)
}

/// Inactive explicit requester only. The consumed input is the original W0
/// parts loan; legacy automatic/foundation and routed entries stay unchanged.
pub(super) async fn cut_explicit_in(
    input: super::live::kernel_writes::ExplicitAppend<'_, '_>,
) -> Result<BaseVersion> {
    let (db, tx, acts, request, snapshot, expected_body_seq, permit) = input.into_parts();
    request.require_same_dispatch()?;
    let caller = request.caller();
    let record = request.record();
    let candidate = NativeCandidateView::installed(snapshot);
    let principal =
        validate_candidate_on(tx, caller, record, expected_body_seq, &candidate).await?;
    let ambient = kernel::app_installs::admit_dispatched_on(tx, &principal).await?;
    if ambient.is_some() && caller.host_asserted_app().is_none() {
        return Err(Error::auth("explicit native app absence disagreement"));
    }
    let payload = candidate_payload(&candidate, None)?;
    let pending = if let Some(app) = caller.host_asserted_app() {
        let admitted = kernel::app_installs::admit_app_on(tx, &principal, app).await?;
        kernel::app_installs::start_declared_app_action_in(
            db,
            tx,
            &principal,
            admitted,
            "update_record",
            digest(&serde_json::to_string(&payload)?),
            Some("Explicit native collaborative body version".into()),
            acts,
        )
        .await?
    } else {
        None
    };
    let event = crate::store::append_owned_kernel_body_in(
        db,
        tx,
        crate::store::AppendSpec {
            record_id: record.into(),
            event_type: "kernel.body_set.v1".into(),
            payload,
            actor: Some(principal.clone()),
        },
        acts,
        permit,
    )
    .await?;
    let readback = load_committed_on(tx, caller, record, PeerKind::Edit).await?;
    if readback.body != candidate.body
        || readback.base.proof.body_event_id.as_deref() != Some(event.id.as_str())
        || readback.base.proof.body_event_seq != Some(event.local_seq)
    {
        return Err(Error::engine("explicit cut readback evidence disagrees"));
    }
    // This body event, not the app-accounting tail, supplies the proof.
    let body_event = BodyEvent {
        id: event.id,
        seq: event.local_seq,
    };
    let base = BaseVersion {
        version: readback.base.version,
        body_sha256: readback.base.body_sha256.clone(),
        proof: base_proof(snapshot, &readback.base.body_sha256, Some(&body_event)),
    };
    kernel::app_installs::finish_app_action_in(db, tx, &principal, pending, acts).await?;
    Ok(base)
}

#[allow(clippy::too_many_arguments)]
async fn append_version_in(
    db: &Db,
    tx: &mut SqliteConnection,
    caller: &Caller,
    record: &str,
    expected_body_event_seq: Option<i64>,
    candidate: NativeCandidateView<'_>,
    origin: Option<serde_json::Value>,
    basis: Option<serde_json::Value>,
    acts: &mut crate::act::ActAllocation,
    permit: Option<super::live::kernel_writes::KernelAppendPermit>,
    standalone_action: bool,
) -> Result<NativeBodyCommit> {
    let principal =
        validate_candidate_on(tx, caller, record, expected_body_event_seq, &candidate).await?;
    let payload = candidate_payload_with_basis(&candidate, origin, basis)?;
    let uniform_app = caller.host_asserted_app().filter(|app| {
        standalone_action
            && !candidate.contributors.is_empty()
            && candidate.contributors.iter().all(|fact| {
                fact.principal == principal
                    && fact.app.as_ref().is_some_and(|claimed| {
                        claimed.package == app.package
                            && claimed.version == app.version
                            && claimed.install_event_id == app.install_event_id
                    })
            })
    });
    let pending = if let Some(app) = uniform_app {
        let admitted = kernel::app_installs::admit_app_on(tx, &principal, app).await?;
        kernel::app_installs::start_declared_app_action_in(
            db,
            tx,
            &principal,
            admitted,
            "update_record",
            digest(&serde_json::to_string(&payload)?),
            Some("Cut a native collaborative body version".into()),
            acts,
        )
        .await?
    } else {
        None
    };
    let spec = crate::store::AppendSpec {
        record_id: record.into(),
        event_type: "kernel.body_set.v1".into(),
        payload,
        actor: Some(principal.clone()),
    };
    let event = match permit {
        Some(permit) => {
            crate::store::append_owned_kernel_body_in(db, tx, spec, acts, permit).await?
        }
        None => crate::store::append_on(db, tx, spec, acts).await?,
    };
    let readback = load_committed_on(tx, caller, record, PeerKind::Edit).await?;
    if readback.body != candidate.body
        || readback.base.proof.body_event_id.as_deref() != Some(event.id.as_str())
        || readback.base.proof.body_event_seq != Some(event.local_seq)
    {
        return Err(Error::engine("native cut readback evidence disagrees"));
    }
    // Capture exact native body identity before any action-tail event. The
    // routed owner refreshes the final record revision independently afterward.
    if standalone_action {
        kernel::app_installs::finish_app_action_in(db, tx, &principal, pending, acts).await?;
    }
    Ok(NativeBodyCommit {
        body_event_id: event.id,
        body_event_seq: event.local_seq,
        body_sha256: readback.base.body_sha256,
        record_version: readback.base.version,
    })
}

// Target-scoped observation of the actual full-load boundary. These test-only
// counters are diagnostics, never admission, principal or publication authority.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BodyWorkStage {
    Encoding,
    Size,
    Hydrate,
    Hash,
}
#[cfg(test)]
#[derive(Default)]
struct BodyWork {
    stages: std::sync::Mutex<Vec<BodyWorkStage>>,
    deny_hydration: bool,
}
#[cfg(test)]
type BodyWorkMap = std::collections::HashMap<String, std::sync::Arc<BodyWork>>;
#[cfg(test)]
static BODY_WORK: std::sync::LazyLock<std::sync::Mutex<BodyWorkMap>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
pub(super) struct BodyWorkObservation {
    record: String,
    work: std::sync::Arc<BodyWork>,
}
#[cfg(test)]
impl BodyWorkObservation {
    pub(super) fn stages(&self) -> Vec<BodyWorkStage> {
        self.work.stages.lock().unwrap().clone()
    }
}
#[cfg(test)]
impl Drop for BodyWorkObservation {
    fn drop(&mut self) {
        let mut work = BODY_WORK.lock().unwrap();
        if work
            .get(&self.record)
            .is_some_and(|w| std::sync::Arc::ptr_eq(w, &self.work))
        {
            work.remove(&self.record);
        }
    }
}
#[cfg(test)]
pub(super) fn observe_body(record: &str, deny_hydration: bool) -> BodyWorkObservation {
    let work = std::sync::Arc::new(BodyWork {
        stages: std::sync::Mutex::new(Vec::new()),
        deny_hydration,
    });
    // Tests use genuine newly created record IDs, not a global on/off switch.
    let mut observations = BODY_WORK.lock().unwrap();
    assert!(observations.len() < 64, "bounded N1 observations exceeded");
    assert!(
        !observations.contains_key(record),
        "one observer per actual target"
    );
    observations.insert(record.to_owned(), work.clone());
    BodyWorkObservation {
        record: record.to_owned(),
        work,
    }
}
#[cfg(test)]
fn observe_body_work(record: &str, stage: BodyWorkStage) -> Result<()> {
    let observation = BODY_WORK.lock().unwrap().get(record).cloned();
    if let Some(work) = observation {
        let mut stages = work.stages.lock().unwrap();
        assert!(stages.len() < 128, "bounded N1 observation exceeded");
        stages.push(stage);
        drop(stages);
        if stage == BodyWorkStage::Hydrate && work.deny_hydration {
            return Err(Error::engine(
                "test observation refused actual target-body hydration",
            ));
        }
    }
    Ok(())
}
