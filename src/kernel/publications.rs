//! Internal publication authority. A publication grants only current committed
//! Markdown title/body, never an authenticated principal or arbitrary blob access.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) const EVENT: &str = "kernel.publication_changed.v1";
pub(crate) const DDL: &str = "CREATE TABLE kernel_publications (
 public_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, database_birth TEXT NOT NULL,
 record_birth TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), event_seq INTEGER NOT NULL)";
pub(crate) const INDEX: &str =
    "CREATE INDEX idx_kernel_publications_record ON kernel_publications(record_id,event_seq)";
pub(crate) const RECEIPTS: &str = "CREATE TABLE kernel_publication_receipts (
 principal TEXT NOT NULL, operation_key TEXT NOT NULL, request TEXT NOT NULL,
 receipt TEXT NOT NULL, PRIMARY KEY(principal,operation_key))";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationAction {
    Publish,
    Revoke { public_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRequest {
    pub record_id: String,
    pub action: PublicationAction,
    /// Entire record CAS, observed by authenticated inspection/read.
    pub expected_revision: i64,
    /// Latest publication transition (including lifecycle invalidation), or None.
    pub expected_publication_version: Option<i64>,
    pub operation_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct PublicationState {
    pub public_id: String,
    /// Internal routing/reconciliation binding; never visitor metadata.
    pub database_birth: String,
    pub record_birth: String,
    pub active: bool,
    pub version: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub state: PublicationState,
    pub event_id: String,
    pub event_seq: i64,
    pub act: Option<i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Changed {
    request: PublicationRequest,
    public_id: String,
    database_birth: String,
    record_birth: String,
}

/// A deliberately constructed visitor projection: no private IDs or metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicDocument {
    pub title: String,
    pub body: String,
    pub format: &'static str,
    pub version: String,
    pub body_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicRead {
    Available(PublicDocument),
    Unavailable,
}

const TITLE_MAX_BYTES: usize = 4096;
const BODY_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Authenticated preparation for both management transports. The source and
/// publication revisions must be carried into the subsequent guarded change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicationPreview {
    pub record_revision: i64,
    pub publication: Option<PublicationState>,
    pub title: String,
    pub body: String,
    pub body_sha256: String,
    #[serde(skip)]
    pub(crate) binding: PublicationBinding,
}

/// Private binding to the canonical database and record creation events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicationBinding {
    pub database_birth: String,
    pub record_birth: String,
}

struct Representation {
    title: String,
    body: String,
}

impl Representation {
    fn within_limits(&self) -> bool {
        self.title.len() <= TITLE_MAX_BYTES && self.body.len() <= BODY_MAX_BYTES
    }
}

/// Read the existing committed source projection, never live peer text. Used
/// by preparation, mutation and anonymous reads to keep their limits aligned.
async fn representation_on(conn: &mut SqliteConnection, record: &str) -> Result<Representation> {
    let title: Option<String> = sqlx::query_scalar(
        "SELECT value_json FROM kernel_record_fields WHERE record_id=? AND name='title'",
    )
    .bind(record)
    .fetch_optional(&mut *conn)
    .await?;
    let title = title
        .map(|value| serde_json::from_str::<String>(&value))
        .transpose()?
        .unwrap_or_default();
    let body = match hq::body_on(conn, record).await? {
        Some(body) => body,
        None => {
            let field: Option<String> = sqlx::query_scalar(
                "SELECT value_json FROM kernel_record_fields WHERE record_id=? AND name='body'",
            )
            .bind(record)
            .fetch_optional(&mut *conn)
            .await?;
            field
                .map(|value| serde_json::from_str::<String>(&value))
                .transpose()?
                .unwrap_or_default()
        }
    };
    Ok(Representation { title, body })
}

fn representation_limit_error() -> Error {
    Error::engine("record exceeds public reader limits: title 4096 UTF-8 bytes; body 4 MiB")
}

/// This previews current canonical disclosure, rather than recorded state on
/// a member/standby copy. It writes nothing and grants no public access.
pub async fn prepare_as(db: &Db, principal: &str, record: &str) -> Result<PublicationPreview> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "publication preparation requires canonical database",
        ));
    }
    let mut tx = db.pool().begin().await?;
    require_ready_on(&mut tx).await?;
    manage_on(&mut tx, principal, record).await?;
    if !readable_on(&mut tx, record).await? {
        return Err(Error::engine("record cannot be published"));
    }
    let representation = representation_on(&mut tx, record).await?;
    if !representation.within_limits() {
        return Err(representation_limit_error());
    }
    let (database_birth, record_birth) = births_on(&mut tx, record).await?;
    Ok(PublicationPreview {
        record_revision: revision_on(&mut tx, record).await?,
        publication: state_on(&mut tx, record).await?,
        body_sha256: format!("{:x}", Sha256::digest(representation.body.as_bytes())),
        title: representation.title,
        body: representation.body,
        binding: PublicationBinding {
            database_birth,
            record_birth,
        },
    })
}

async fn births_on(conn: &mut SqliteConnection, record: &str) -> Result<(String, String)> {
    let database: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE type='kernel.root_created.v1' ORDER BY seq LIMIT 1",
    )
    .fetch_one(&mut *conn)
    .await?;
    let birth: String = sqlx::query_scalar("SELECT e.id FROM kernel_records r JOIN content_events e ON e.seq=r.created_seq WHERE r.id=?").bind(record).fetch_one(conn).await?;
    Ok((database, birth))
}
async fn state_on(conn: &mut SqliteConnection, record: &str) -> Result<Option<PublicationState>> {
    Ok(sqlx::query_as("SELECT public_id,database_birth,record_birth,active,event_seq AS version FROM kernel_publications WHERE record_id=? ORDER BY event_seq DESC LIMIT 1").bind(record).fetch_optional(conn).await?)
}
async fn revision_on(conn: &mut SqliteConnection, record: &str) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=?")
            .bind(record)
            .fetch_one(conn)
            .await?,
    )
}
async fn manage_on(conn: &mut SqliteConnection, principal: &str, record: &str) -> Result<()> {
    kernel_require(conn, principal, record, Capability::Manage).await
}

/// Supported initial surface: bare text records and ordinary imported records.
/// Executable/derived/root/package/structured families fail closed. No renderer,
/// reference resolver, attachment reader or asset map is invoked here.
async fn supported_on(conn: &mut SqliteConnection, record: &str) -> Result<bool> {
    type FormatRow = (Option<String>, Option<String>, Option<String>, Option<i64>);
    let row: Option<FormatRow> = sqlx::query_as(
        "SELECT primary_type,kind,pin_family,pin_version FROM kernel_records WHERE id=?",
    )
    .bind(record)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((typ, kind, family, pin_version)) = row else {
        return Ok(false);
    };
    if family.is_none() {
        return Ok(true);
    }
    if family.as_deref() == Some("native.standard.document") {
        return Ok(typ.as_deref() == Some("Document")
            && kind.as_deref() == Some("note")
            && matches!(pin_version, Some(2..=4)));
    }
    if pin_version != Some(1) || family.as_deref() != Some("native.v1.record") {
        return Ok(false);
    }
    let fields: Vec<(String,String)> = sqlx::query_as("SELECT name,value_json FROM kernel_record_fields WHERE record_id=? AND name IN ('v1_type','v1_kind')").bind(record).fetch_all(conn).await?;
    let field = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| serde_json::from_str::<String>(v).ok())
    };
    let typ = field("v1_type").or(typ);
    let kind = field("v1_kind").or(kind);
    Ok(matches!(
        (typ.as_deref(), kind.as_deref()),
        (Some("Document"), Some("note"))
            | (Some("WorkItem"), Some("task"))
            | (Some("Resolution"), Some("decision"))
    ))
}
async fn readable_on(conn: &mut SqliteConnection, record: &str) -> Result<bool> {
    Ok(!hq::tombstoned_on(conn, record).await?
        && !hq::archived_on(conn, record).await?
        && supported_on(conn, record).await?)
}

pub async fn inspect_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<Option<PublicationState>> {
    Ok(inspect_revision_as(db, principal, record).await?.1)
}

/// Look up the original receipt for an exact retry request under current
/// canonical Manage authority. This is historical evidence, not current
/// publication eligibility.
pub async fn receipt_for_request_as(
    db: &Db,
    principal: &str,
    request: &PublicationRequest,
) -> Result<Option<PublicationReceipt>> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "publication receipt requires canonical read-write mode",
        ));
    }
    let mut tx = db.pool().begin().await?;
    require_ready_on(&mut tx).await?;
    manage_on(&mut tx, principal, &request.record_id).await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT request,receipt FROM kernel_publication_receipts WHERE principal=? AND operation_key=?",
    )
    .bind(principal)
    .bind(&request.operation_key)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((stored, receipt)) = row else {
        return Ok(None);
    };
    let stored: PublicationRequest = serde_json::from_str(&stored)?;
    if &stored != request {
        return Err(Error::conflict("publication retry intent collision"));
    }
    Ok(Some(serde_json::from_str(&receipt)?))
}

/// A guarded receipt lookup distinguishes an authority refusal or absent /
/// conflicting receipt from a failure to observe canonical state.
pub enum PublicationReceiptLookup {
    Found(PublicationReceipt),
    Missing,
    Conflict,
    Denied,
}

pub async fn checked_receipt_for_request_as(
    db: &Db,
    principal: &str,
    request: &PublicationRequest,
) -> Result<PublicationReceiptLookup> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "publication receipt requires canonical read-write mode",
        ));
    }
    let mut tx = db.pool().begin().await?;
    require_ready_on(&mut tx).await?;
    let capability =
        super::kernel_effective_capability_on(&mut tx, principal, &request.record_id).await?;
    if !capability.allows(Capability::Manage) {
        return Ok(PublicationReceiptLookup::Denied);
    }
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT request,receipt FROM kernel_publication_receipts WHERE principal=? AND operation_key=?",
    ).bind(principal).bind(&request.operation_key).fetch_optional(&mut *tx).await?;
    let Some((stored, receipt)) = row else {
        return Ok(PublicationReceiptLookup::Missing);
    };
    let stored: PublicationRequest = serde_json::from_str(&stored)?;
    if &stored != request {
        return Ok(PublicationReceiptLookup::Conflict);
    }
    Ok(PublicationReceiptLookup::Found(serde_json::from_str(
        &receipt,
    )?))
}

/// Management state and its record CAS from one authorized snapshot. Unlike
/// prepare_as this does not require a currently publishable representation.
/// On a copy these remain recorded facts, not current canonical eligibility.
pub async fn inspect_revision_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<(i64, Option<PublicationState>)> {
    let mut tx = db.pool().begin().await?;
    require_ready_on(&mut tx).await?;
    manage_on(&mut tx, principal, record).await?;
    Ok((
        revision_on(&mut tx, record).await?,
        state_on(&mut tx, record).await?,
    ))
}

/// Canonical Manage-only inspection with birth identities from the same snapshot.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn inspect_bound_revision_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<(i64, Option<PublicationState>, PublicationBinding)> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "publication inspection requires canonical database",
        ));
    }
    let mut tx = db.pool().begin().await?;
    require_ready_on(&mut tx).await?;
    manage_on(&mut tx, principal, record).await?;
    let (database_birth, record_birth) = births_on(&mut tx, record).await?;
    Ok((
        revision_on(&mut tx, record).await?,
        state_on(&mut tx, record).await?,
        PublicationBinding {
            database_birth,
            record_birth,
        },
    ))
}

/// Retry identity is actor + operation key + exact typed request. A retry
/// returns the historical receipt, not a claim that its URL is still active.
pub async fn change_as(
    db: &Db,
    principal: &str,
    request: PublicationRequest,
) -> Result<PublicationReceipt> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "publication writes require canonical read-write mode",
        ));
    }
    if request.operation_key.trim().is_empty() || request.operation_key.len() > 256 {
        return Err(Error::engine("invalid publication operation key"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_ready_on(&mut tx).await?;
    manage_on(&mut tx, principal, &request.record_id).await?;
    let raw = serde_json::to_string(&request)?;
    let old: Option<(String,String)>=sqlx::query_as("SELECT request,receipt FROM kernel_publication_receipts WHERE principal=? AND operation_key=?").bind(principal).bind(&request.operation_key).fetch_optional(&mut *tx).await?;
    if let Some((prior, receipt)) = old {
        if prior != raw {
            return Err(Error::conflict("publication retry intent collision"));
        }
        return Ok(serde_json::from_str(&receipt)?);
    }
    if revision_on(&mut tx, &request.record_id).await? != request.expected_revision
        || state_on(&mut tx, &request.record_id)
            .await?
            .map(|s| s.version)
            != request.expected_publication_version
    {
        return Err(Error::conflict("publication version conflict"));
    }
    let public_id = match &request.action {
        PublicationAction::Publish => {
            if !readable_on(&mut tx, &request.record_id).await? {
                return Err(Error::engine("record cannot be published"));
            }
            if !representation_on(&mut tx, &request.record_id)
                .await?
                .within_limits()
            {
                return Err(representation_limit_error());
            }
            if state_on(&mut tx, &request.record_id)
                .await?
                .is_some_and(|s| s.active)
            {
                return Err(Error::conflict("record already published"));
            }
            Uuid::new_v4().simple().to_string()
        }
        PublicationAction::Revoke { public_id } => {
            if !state_on(&mut tx, &request.record_id)
                .await?
                .is_some_and(|s| s.active && s.public_id == *public_id)
            {
                return Err(Error::conflict("publication version conflict"));
            }
            public_id.clone()
        }
    };
    let (database_birth, record_birth) = births_on(&mut tx, &request.record_id).await?;
    let payload = Changed {
        request,
        public_id,
        database_birth,
        record_birth,
    };
    let mut acts = crate::act::ActAllocation::new();
    let event = crate::store::append_kernel_publication_in(
        db,
        &mut tx,
        &Seal { _private: () },
        AppendSpec {
            record_id: payload.request.record_id.clone(),
            event_type: EVENT.into(),
            payload: serde_json::to_value(&payload)?,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    let receipt = receipt(&payload, &event);
    tx.commit().await?;
    Ok(receipt)
}
pub(crate) struct Seal {
    _private: (),
}
fn receipt(p: &Changed, event: &EventRow) -> PublicationReceipt {
    PublicationReceipt {
        state: PublicationState {
            public_id: p.public_id.clone(),
            database_birth: p.database_birth.clone(),
            record_birth: p.record_birth.clone(),
            active: matches!(p.request.action, PublicationAction::Publish),
            version: event.local_seq,
        },
        event_id: event.id.clone(),
        event_seq: event.local_seq,
        act: event.act,
    }
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Changed = event_payload(event)?;
    if p.request.record_id != event.record_id
        || births_on(conn, &event.record_id).await?
            != (p.database_birth.clone(), p.record_birth.clone())
    {
        return Err(Error::engine("publication identity mismatch"));
    }
    let prior: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=? AND seq<?",
    )
    .bind(&event.record_id)
    .bind(event.local_seq)
    .fetch_one(&mut *conn)
    .await?;
    if prior != p.request.expected_revision {
        return Err(Error::conflict("publication fold record revision mismatch"));
    }
    if let PublicationAction::Revoke { public_id } = &p.request.action {
        if public_id != &p.public_id {
            return Err(Error::engine("publication revocation identity mismatch"));
        }
    }
    // Replay uses recorded authority, not the publisher's present membership.
    if state_on(conn, &event.record_id).await?.map(|s| s.version)
        != p.request.expected_publication_version
    {
        return Err(Error::conflict("publication fold version mismatch"));
    }
    let active = matches!(p.request.action, PublicationAction::Publish);
    if active {
        if state_on(conn, &event.record_id)
            .await?
            .is_some_and(|s| s.active)
        {
            return Err(Error::conflict("record already published"));
        }
        if p.public_id.len() != 32
            || !p.public_id.bytes().all(|b| b.is_ascii_hexdigit())
            || !readable_on(conn, &event.record_id).await?
        {
            return Err(Error::engine("invalid publication"));
        }
        sqlx::query("INSERT INTO kernel_publications VALUES(?,?,?,?,1,?)")
            .bind(&p.public_id)
            .bind(&event.record_id)
            .bind(&p.database_birth)
            .bind(&p.record_birth)
            .bind(event.local_seq)
            .execute(&mut *conn)
            .await?;
    } else {
        let changed=sqlx::query("UPDATE kernel_publications SET active=0,event_seq=? WHERE public_id=? AND record_id=? AND active=1").bind(event.local_seq).bind(&p.public_id).bind(&event.record_id).execute(&mut *conn).await?;
        if changed.rows_affected() != 1 {
            return Err(Error::engine("invalid publication revocation"));
        }
    }
    sqlx::query("INSERT INTO kernel_publication_receipts VALUES(?,?,?,?)")
        .bind(
            event
                .actor
                .as_deref()
                .ok_or_else(|| Error::engine("publication actor missing"))?,
        )
        .bind(&p.request.operation_key)
        .bind(serde_json::to_string(&p.request)?)
        .bind(serde_json::to_string(&receipt(&p, event))?)
        .execute(conn)
        .await?;
    Ok(())
}

/// Existing canonical lifecycle evidence permanently invalidates each active
/// ID at that transition. Restore never clears these tombstones.
pub(crate) async fn invalidate_on(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if !matches!(
        event.event_type.as_str(),
        "kernel.archive_changed.v1"
            | "kernel.record_deleted.v1"
            | "kernel.import_state.v1"
            | "kernel.import_state_delta.v1"
            | "kernel.import_removed.v1"
    ) {
        return Ok(());
    }
    if hq::tombstoned_on(conn, &event.record_id).await?
        || hq::archived_on(conn, &event.record_id).await?
    {
        sqlx::query(
            "UPDATE kernel_publications SET active=0,event_seq=? WHERE record_id=? AND active=1",
        )
        .bind(event.local_seq)
        .bind(&event.record_id)
        .execute(conn)
        .await?;
    }
    Ok(())
}
pub(crate) async fn require_ready_on(conn: &mut SqliteConnection) -> Result<()> {
    let unknown: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type GLOB 'kernel.publication_*' AND type!=?)").bind(EVENT).fetch_one(conn).await?;
    if unknown {
        return Err(Error::engine("unsupported publication event version"));
    }
    Ok(())
}
pub(crate) async fn ensure_schema_on(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [DDL, RECEIPTS, INDEX] {
        let ddl = ddl
            .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
            .replacen("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1);
        sqlx::query(&ddl).execute(&mut *conn).await?;
    }
    Ok(())
}
pub(crate) async fn prepare_on(conn: &mut SqliteConnection) -> Result<()> {
    let missing: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM sqlite_master WHERE name='kernel_publications') OR NOT EXISTS(SELECT 1 FROM sqlite_master WHERE name='kernel_publication_receipts')").fetch_one(&mut *conn).await?;
    ensure_schema_on(conn).await?;
    require_ready_on(conn).await?;
    if !missing {
        return Ok(());
    }
    let has_events: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type=?)")
            .bind(EVENT)
            .fetch_one(&mut *conn)
            .await?;
    if !has_events {
        return Ok(());
    }
    sqlx::query("DELETE FROM kernel_publication_receipts")
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM kernel_publications")
        .execute(&mut *conn)
        .await?;
    // Preparation may see final record state. Use full replay for authority:
    // event-time archive/delete/restore evidence must fold in canonical order.
    super::replay_all_projections_on(conn).await
}

/// Admission is a read transaction on canonical state. Storage/readiness errors
/// remain Err (retryable at the transport); all nonpublic IDs have no data.
pub async fn read_public(db: &Db, public_id: &str) -> Result<PublicRead> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "public admission requires canonical database",
        ));
    }
    if public_id.len() != 32 || !public_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(PublicRead::Unavailable);
    }
    let mut tx = db.pool().begin().await?;
    require_ready_on(&mut tx).await?;
    let row: Option<(String,String,String)>=sqlx::query_as("SELECT record_id,database_birth,record_birth FROM kernel_publications WHERE public_id=? AND active=1").bind(public_id).fetch_optional(&mut *tx).await?;
    let Some((record, database, birth)) = row else {
        return Ok(PublicRead::Unavailable);
    };
    if births_on(&mut tx, &record).await? != (database, birth)
        || !readable_on(&mut tx, &record).await?
    {
        return Ok(PublicRead::Unavailable);
    }
    let representation = representation_on(&mut tx, &record).await?;
    if !representation.within_limits() {
        return Ok(PublicRead::Unavailable);
    }
    let Representation { title, body } = representation;
    // Hash an unguessable canonical source event identity rather than a small
    // numeric sequence, so an opaque visitor basis is not a count oracle.
    let revision: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&record)
    .fetch_one(&mut *tx)
    .await?;
    let body_sha256 = format!("{:x}", Sha256::digest(body.as_bytes()));
    let version = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            public_id,
            revision,
            &title,
            &body_sha256
        ))?)
    );
    Ok(PublicRead::Available(PublicDocument {
        title,
        body,
        format: "markdown",
        version,
        body_sha256,
    }))
}

#[cfg(test)]
mod tests;
