//! Connection-scoped imported-source proofs for gated generated admission.
//! Preparation owns a read snapshot; recheck requires the same Db's existing
//! BEGIN IMMEDIATE transaction. Neither helper compiles SQL or grants access.
use crate::{db::Db, events::KERNEL_ROOT_ID, kernel, Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};
use std::{collections::BTreeSet, time::Instant};

const SECTIONS: [&str; 3] = ["schema_config", "vocabularies", "vocabulary_values"];
const PAGE: i64 = 32;
const PREPARE_ROWS: usize = 65_536;
const PREPARE_BYTES: usize = 8 * 1024 * 1024;
const WINDOW_ROWS: usize = 512;
const WINDOW_BYTES: usize = 1024 * 1024;
const STATE_BYTES: &str = "coalesce(octet_length(section),0)+coalesce(octet_length(source_id),0)+coalesce(octet_length(origin),0)+coalesce(octet_length(payload),0)+coalesce(octet_length(account_principal),0)+coalesce(octet_length(record_id),0)+coalesce(octet_length(observed_at),0)+8";
const EVENT_BYTES: &str = "coalesce(octet_length(id),0)+coalesce(octet_length(record_id),0)+coalesce(octet_length(type),0)+coalesce(octet_length(payload),0)+coalesce(octet_length(actor),0)+coalesce(octet_length(run_key),0)+coalesce(octet_length(parent_key),0)+coalesce(octet_length(intent),0)+coalesce(octet_length(created_at),0)+coalesce(octet_length(causal_status),0)+24";
// Context lookup inspects only the indexed record/seq and type (before the
// payload column); actor/run/intent and payload are neither fetched nor parsed.
const CONTEXT_HEADER_BYTES: &str =
    "coalesce(octet_length(record_id),0)+coalesce(octet_length(type),0)+8";
fn context_page_sql() -> String {
    format!("SELECT seq,{CONTEXT_HEADER_BYTES} FROM main.content_events INDEXED BY idx_content_events_record WHERE record_id=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?")
}
const EVENT_PAGE: &str =
    "SELECT seq FROM main.content_events NOT INDEXED WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?";

fn state_page_sql(after: bool) -> String {
    format!("SELECT rowid,event_seq,{STATE_BYTES} FROM main.kernel_v1_state WHERE section=? {} ORDER BY source_id LIMIT ?", if after { "AND source_id>?" } else { "" })
}

fn conflict(why: &str) -> Error {
    Error::conflict(format!("view_source_changed: {why}; prepare again"))
}
fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(conflict("source proof deadline exceeded"));
    }
    Ok(())
}
#[derive(Default, Clone, Copy, Debug)]
pub(super) struct Work {
    pub rows: usize,
    pub bytes: usize,
}
impl Work {
    fn charge(&mut self, bytes: i64, rows: usize, limit: usize) -> Result<()> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| conflict("row bound"))?;
        self.bytes = self
            .bytes
            .checked_add(usize::try_from(bytes).map_err(|_| conflict("invalid byte length"))?)
            .ok_or_else(|| conflict("byte bound"))?;
        if self.rows > rows || self.bytes > limit {
            return Err(conflict("source scan budget exceeded"));
        }
        Ok(())
    }
}
// Only advisory current-catalog comparison may recover from Incomplete.
// Preparation unwraps the original error and remains strict. SQL/IO, deadline
// and authority errors are always Refuse; no message-based classification.
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ComparisonReason {
    Budget,
    Unsupported,
    Integrity,
}
pub(super) enum ComparisonFailure {
    Incomplete(Error, ComparisonReason),
    Refuse(Error),
}
impl ComparisonFailure {
    pub(super) fn budget(e: Error) -> Self {
        Self::Incomplete(e, ComparisonReason::Budget)
    }
    pub(super) fn unsupported(e: Error) -> Self {
        Self::Incomplete(e, ComparisonReason::Unsupported)
    }
    pub(super) fn integrity(e: Error) -> Self {
        Self::Incomplete(e, ComparisonReason::Integrity)
    }
    pub(super) fn into_error(self) -> Error {
        match self {
            Self::Incomplete(e, _) | Self::Refuse(e) => e,
        }
    }
}
impl From<Error> for ComparisonFailure {
    fn from(e: Error) -> Self {
        Self::Refuse(e)
    }
}
impl From<sqlx::Error> for ComparisonFailure {
    fn from(e: sqlx::Error) -> Self {
        Self::Refuse(e.into())
    }
}
impl From<serde_json::Error> for ComparisonFailure {
    fn from(e: serde_json::Error) -> Self {
        Self::unsupported(e.into())
    }
}
pub(super) type ComparisonResult<T> = std::result::Result<T, ComparisonFailure>;
#[derive(Clone, Copy)]
pub(super) struct ScanLimits {
    pub rows: usize,
    pub bytes: usize,
}
impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            rows: PREPARE_ROWS,
            bytes: PREPARE_BYTES,
        }
    }
}
#[derive(Debug)]
pub(super) struct Source {
    pub section: String,
    pub source_id: String,
    pub origin: String,
    pub payload: String,
    pub event_id: String,
    pub event_sha256: String,
    event_seq: i64,
}
#[derive(Clone)]
struct Anchor {
    id: String,
    home: String,
    // Conservatively detects logical rehomes as well as physical placement.
    // Interpreting logical records.home_id belongs to the later resolver.
    moved: i64,
    root_record: bool,
    record: bool,
    folder: bool,
}
#[derive(Clone)]
struct Reference {
    section: String,
    source_id: String,
    origin: String,
    event_seq: i64,
    event_id: String,
}
#[allow(dead_code)] // B is deliberately not wired to a generated producer.
pub(super) struct Snapshot {
    conn: SqliteConnection,
    db: Db,
    head: (i64, String),
    deadline: Instant,
    sources: Vec<Source>,
    work: Work,
    database_file: String,
}
#[allow(dead_code)] // Only internal preparation uses this; no producer consumes it.
pub(super) struct Proof {
    db: Db,
    actor: String,
    head: (i64, String),
    deadline: Instant,
    refs: Vec<Reference>,
    anchors: Vec<Anchor>,
    database_file: String,
}

/// Private enrollment at the existing writer seam. No conversion from an
/// arbitrary/read SQLx connection or transaction is exposed.
#[allow(dead_code)] // No producer consumes this internal writer yet.
pub(crate) struct Writer {
    owner: Db,
    tx: sqlx::Transaction<'static, sqlx::Sqlite>,
}
#[allow(dead_code)] // Proof-only tests use this; producer wiring is deferred.
impl Writer {
    pub(crate) async fn begin(db: &Db, deadline: Instant) -> Result<Self> {
        check(deadline)?;
        let tx = crate::db::begin_write_with_deadline(
            db.write_pool(),
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
        Ok(Self {
            owner: db.clone(),
            tx,
        })
    }
    pub(crate) fn transaction(&mut self) -> &mut sqlx::Transaction<'static, sqlx::Sqlite> {
        &mut self.tx
    }
    pub(crate) fn into_transaction(self) -> sqlx::Transaction<'static, sqlx::Sqlite> {
        self.tx
    }
    pub(super) async fn rollback(self) -> Result<()> {
        self.tx.rollback().await.map_err(Error::from)
    }
    pub(super) async fn commit(self) -> Result<()> {
        self.tx.commit().await.map_err(Error::from)
    }
}

async fn head_on(conn: &mut SqliteConnection) -> Result<(i64, String)> {
    sqlx::query_as("SELECT seq,id FROM main.content_events ORDER BY seq DESC LIMIT 1")
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| conflict("missing source snapshot anchor"))
}
async fn anchor_on(conn: &mut SqliteConnection, actor: &str, id: &str) -> Result<Anchor> {
    let structural_alias = id == "native:root"
        && !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root')",
        )
        .fetch_one(&mut *conn)
        .await?;
    let id = if structural_alias { KERNEL_ROOT_ID } else { id };
    let home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if home {
        if !kernel::kernel_effective_capability_on(conn, actor, id)
            .await?
            .allows(crate::authorization::Capability::View)
        {
            return Err(Error::engine(super::MISSING));
        }
        let root_record = id == KERNEL_ROOT_ID
            && sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root')",
            )
            .fetch_one(&mut *conn)
            .await?;
        if root_record {
            super::closure::require_accessible_bearer_on(
                conn,
                actor,
                "native:root",
                &mut BTreeSet::new(),
                true,
            )
            .await?;
        }
        return Ok(Anchor {
            id: id.into(),
            home: id.into(),
            moved: 0,
            root_record,
            record: false,
            folder: false,
        });
    }
    record_anchor_on(conn, actor, id).await
}
/// Metadata authorization has no source executability requirement. Native root
/// is a logical alias; schema/catalog rows never acquire an invented ACL.
pub(super) async fn require_visible_anchor_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    checked: &mut BTreeSet<String>,
) -> Result<()> {
    let id = if id == "native:root"
        && !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root')",
        )
        .fetch_one(&mut *conn)
        .await?
    {
        KERNEL_ROOT_ID
    } else {
        id
    };
    let home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_roots WHERE root_id=?)")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if home {
        if !kernel::kernel_effective_capability_on(conn, actor, id)
            .await?
            .allows(crate::authorization::Capability::View)
        {
            return Err(Error::engine(super::MISSING));
        }
        Ok(())
    } else {
        super::closure::require_accessible_bearer_on(conn, actor, id, checked, false).await
    }
}
async fn record_anchor_on(conn: &mut SqliteConnection, actor: &str, id: &str) -> Result<Anchor> {
    let mut seen = BTreeSet::new();
    super::closure::require_accessible_bearer_on(conn, actor, id, &mut seen, true).await?;
    let (home, moved, folder): (String, i64, bool) = sqlx::query_as("SELECT home_id,coalesce((SELECT max(seq) FROM main.content_events INDEXED BY idx_kernel_record_moves WHERE record_id=? AND type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')),0),EXISTS(SELECT 1 FROM main.kernel_record_fields t JOIN main.kernel_record_fields k ON k.record_id=t.record_id WHERE t.record_id=r.id AND t.name='v1_type' AND CASE WHEN octet_length(t.value_json)=12 THEN t.value_json='\"Collection\"' ELSE 0 END AND k.name='v1_kind' AND CASE WHEN octet_length(k.value_json)=8 THEN k.value_json='\"folder\"' ELSE 0 END) FROM main.kernel_records r WHERE id=?")
        .bind(id).bind(id).fetch_one(conn).await?;
    Ok(Anchor {
        id: id.into(),
        home,
        moved,
        root_record: false,
        record: true,
        folder,
    })
}

#[allow(dead_code)] // Closed proof-only entrypoint, not an admission API.
pub(super) async fn prepare(db: &Db, deadline: Instant) -> Result<Snapshot> {
    prepare_inner(db, deadline)
        .await
        .map_err(|error| deadline_error(error, deadline))
}
pub(super) fn deadline_error(error: Error, deadline: Instant) -> Error {
    if Instant::now() >= deadline
        && matches!(&error, Error::Sqlx(sqlx::Error::Database(db)) if db.code().as_deref() == Some("9"))
    {
        conflict("source proof deadline exceeded")
    } else {
        error
    }
}
async fn prepare_inner(db: &Db, deadline: Instant) -> Result<Snapshot> {
    let mut snapshot = open_snapshot(db, deadline).await?;
    snapshot.sources = sources_on(
        &mut snapshot.conn,
        snapshot.head.0,
        &mut snapshot.work,
        deadline,
    )
    .await?;
    Ok(snapshot)
}
// Only constructors in this module can observe an unscanned snapshot. A draft
// receives a complete owned snapshot after its context is authorized; a frozen
// activation receives an interval/anchor Proof, never a claimed source set.
async fn open_snapshot(db: &Db, deadline: Instant) -> Result<Snapshot> {
    check(deadline)?;
    // A detached, owned read-only connection cannot return a progress callback
    // or an open snapshot to a serving borrower, including on cancellation.
    let mut conn = tokio::time::timeout_at(deadline.into(), db.pool().acquire())
        .await
        .map_err(|_| conflict("source snapshot queue deadline"))??
        .detach();
    conn.lock_handle()
        .await?
        .set_progress_handler(100, move || Instant::now() < deadline);
    sqlx::query("BEGIN").execute(&mut conn).await?;
    let database_file: String =
        sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name='main'")
            .fetch_one(&mut conn)
            .await?;
    if database_file.is_empty() {
        return Err(conflict("source database identity unavailable"));
    }
    let head = head_on(&mut conn).await?; // Establish S before any source read.
    Ok(Snapshot {
        conn,
        db: db.clone(),
        head,
        deadline,
        sources: Vec::new(),
        work: Work::default(),
        database_file,
    })
}

/// Authorize the requested bearer and actual governing home in S before any
/// section scan can disclose a source count/byte/parse failure. Same S/work cap.
pub(super) async fn prepare_context(
    db: &Db,
    actor: &str,
    bearer: &str,
    home: &str,
    deadline: Instant,
) -> Result<(Snapshot, String, String)> {
    let result = async {
        let mut snapshot = open_snapshot(db, deadline).await?;
        snapshot.require_bearer(actor, bearer).await?;
        let (home, anchor) = snapshot.logical_home(actor, home).await?;
        snapshot.sources = sources_on(
            &mut snapshot.conn,
            snapshot.head.0,
            &mut snapshot.work,
            deadline,
        )
        .await?;
        Ok((snapshot, home, anchor))
    }
    .await;
    result.map_err(|error| deadline_error(error, deadline))
}
/// A frozen activation needs current required presence and anchor/context View,
/// not a complete current advisory interpretation. No source section scan or
/// compiler is required: the owned proof catches all relevant imports after S.
pub(super) async fn prepare_retained(
    db: &Db,
    actor: &str,
    workspace: &str,
    definitions: &[(String, super::v2::Definition)],
    deadline: Instant,
) -> Result<Proof> {
    let result = async {
        let mut snapshot = open_snapshot(db, deadline).await?;
        let mut anchors = BTreeSet::new();
        for (bearer, definition) in definitions {
            snapshot
                .check_retained(actor, workspace, bearer, definition)
                .await?;
            anchors.insert(bearer.clone());
            anchors.insert(definition.generated.context.logical_home_id.clone());
            anchors.extend(
                definition
                    .generated
                    .sources
                    .iter()
                    .filter_map(|s| s.anchor.clone()),
            );
        }
        snapshot
            .seal(actor, &[], &anchors.into_iter().collect::<Vec<_>>())
            .await
    }
    .await;
    result.map_err(|error| deadline_error(error, deadline))
}

/// Complete bounded imported-source scan on an already established caller
/// snapshot. Does not begin a transaction or replace its progress handler.
pub(super) async fn sources_on(
    conn: &mut SqliteConnection,
    head: i64,
    work: &mut Work,
    deadline: Instant,
) -> Result<Vec<Source>> {
    comparison_sources_on(conn, head, work, deadline, ScanLimits::default())
        .await
        .map_err(ComparisonFailure::into_error)
}

pub(super) async fn comparison_sources_on(
    conn: &mut SqliteConnection,
    head: i64,
    work: &mut Work,
    deadline: Instant,
    limits: ScanLimits,
) -> ComparisonResult<Vec<Source>> {
    let mut sources = Vec::new();
    for section in SECTIONS {
        let mut after = String::new();
        let mut first = true;
        loop {
            check(deadline)?;
            // Direct column octet_length uses SQLite's BYTELEN Column flag:
            // numeric metadata only, no CAST, JSON filter or oversized cells.
            let sql = state_page_sql(!first);
            let mut query = sqlx::query_as::<_, (i64, i64, i64)>(&sql).bind(section);
            if !first {
                query = query.bind(&after);
            }
            // Reserve one sealed-wrapper row for every returned state row.
            // Refuse before another page when completeness cannot fit: do not
            // fetch a sentinel page outside the shared inspected-row cap.
            let limit = ((limits.rows.saturating_sub(work.rows)) / 2).min(PAGE as usize);
            if limit == 0 {
                return Err(ComparisonFailure::budget(conflict(
                    "source scan budget exceeded",
                )));
            }
            let rows = query.bind(limit as i64).fetch_all(&mut *conn).await?;
            if rows.is_empty() {
                break;
            }
            // Charge the complete inspected metadata page before fetching cells.
            for (_, _, bytes) in &rows {
                work.charge(*bytes, limits.rows, limits.bytes)
                    .map_err(ComparisonFailure::budget)?;
            }
            for (rowid, seq, _) in rows {
                check(deadline)?;
                trace(Trace::StateFetch);
                let row = sqlx::query("SELECT source_id,origin,payload,account_principal,record_id,observed_at FROM main.kernel_v1_state WHERE rowid=?")
                    .bind(rowid).fetch_one(&mut *conn).await?;
                after = row.try_get("source_id")?;
                let event = sealed_on(&mut *conn, seq, head, work, deadline, limits).await?;
                let wrapper = decode_wrapper(&event.kind, &event.payload)
                    .map_err(ComparisonFailure::integrity)?;
                if event.record != KERNEL_ROOT_ID
                    || wrapper.section != section
                    || wrapper.source_id != after
                    || wrapper.origin != row.try_get::<String, _>("origin")?
                    || wrapper.value_json.as_deref() != Some(row.try_get::<&str, _>("payload")?)
                    || wrapper.account_principal
                        != row.try_get::<Option<String>, _>("account_principal")?
                    || wrapper.record_id != row.try_get::<Option<String>, _>("record_id")?
                    || wrapper.observed_at != row.try_get::<String, _>("observed_at")?
                {
                    return Err(ComparisonFailure::integrity(conflict(
                        "state differs from sealed import",
                    )));
                }
                let value = serde_json::from_str::<crate::record_body::budgeted::UniqueJson>(
                    wrapper.value_json.as_deref().unwrap(),
                )?
                .0;
                if !value.is_object()
                    || value["id"].as_str().is_none()
                    || serde_json::to_string(&[value["id"].as_str().unwrap()])? != after
                {
                    return Err(ComparisonFailure::integrity(conflict(
                        "source row identity differs",
                    )));
                }
                sources.push(Source {
                    section: section.into(),
                    source_id: after.clone(),
                    origin: wrapper.origin,
                    payload: wrapper.value_json.unwrap(),
                    event_id: event.id,
                    event_seq: seq,
                    event_sha256: event.digest,
                });
            }
            first = false;
        }
    }
    check(deadline)?;
    Ok(sources)
}

struct Sealed {
    id: String,
    record: String,
    kind: String,
    payload: String,
    digest: String,
}
async fn sealed_on(
    conn: &mut SqliteConnection,
    seq: i64,
    head: i64,
    work: &mut Work,
    deadline: Instant,
    limits: ScanLimits,
) -> ComparisonResult<Sealed> {
    check(deadline)?;
    if seq <= 0 || seq > head {
        return Err(ComparisonFailure::integrity(conflict(
            "source event outside snapshot",
        )));
    }
    let size: i64 = sqlx::query_scalar(&format!(
        "SELECT {EVENT_BYTES} FROM main.content_events WHERE seq=?"
    ))
    .bind(seq)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| ComparisonFailure::integrity(conflict("source event missing")))?;
    work.charge(size, limits.rows, limits.bytes)
        .map_err(ComparisonFailure::budget)?;
    trace(Trace::EventFetch);
    let (id, record, kind, payload): (String, String, String, String) =
        sqlx::query_as("SELECT id,record_id,type,payload FROM main.content_events WHERE seq=?")
            .bind(seq)
            .fetch_one(conn)
            .await?;
    let parsed: crate::record_body::budgeted::UniqueJson = serde_json::from_str(&payload)
        .map_err(|error| ComparisonFailure::integrity(error.into()))?;
    let digest = format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &serde_json::json!([kind, record, parsed.0])
        ))
    );
    Ok(Sealed {
        id,
        record,
        kind,
        payload,
        digest,
    })
}
fn decode_wrapper(kind: &str, raw: &str) -> Result<kernel::v1_state::ImportedState> {
    trace(Trace::Parse);
    if kind != kernel::v1_state::EVENT {
        return Err(conflict("unsupported import version"));
    }
    // Reject duplicates before the closed typed envelope erases them. The
    // snapshot value is bounded provenance, never an admission authority.
    let _: crate::record_body::budgeted::UniqueJson = serde_json::from_str(raw)?;
    let row: kernel::v1_state::ImportedState = serde_json::from_str(raw)?;
    if !kernel::v1_state::is_section(&row.section)
        || row.source_id.is_empty()
        || row.origin.is_empty()
        || !row.snapshot.is_object()
        || chrono::DateTime::parse_from_rfc3339(&row.observed_at).is_err()
    {
        return Err(conflict("malformed import wrapper"));
    }
    Ok(row)
}

struct HomeContext<'a> {
    conn: &'a mut SqliteConnection,
    work: &'a mut Work,
    head: i64,
    deadline: Instant,
    retained: bool,
}
impl HomeContext<'_> {
    async fn logical_home_inner(
        &mut self,
        actor: &str,
        requested: &str,
    ) -> Result<(String, String)> {
        check(self.deadline)?;
        let physical = if requested == "native:root" {
            KERNEL_ROOT_ID
        } else {
            requested
        };
        let real_root: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root')",
        )
        .fetch_one(&mut *self.conn)
        .await?;
        if physical == KERNEL_ROOT_ID && !real_root {
            anchor_on(&mut *self.conn, actor, KERNEL_ROOT_ID).await?;
        }
        let is_home: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                .bind(physical)
                .fetch_one(&mut *self.conn)
                .await?;
        // A record/folder cannot have a home-birth event. Physical home birth
        // lookup uses counted unfiltered header pages, not a filtered LIMIT.
        let birth = if physical == KERNEL_ROOT_ID || !is_home {
            None
        } else {
            match self.context_event(physical, false).await {
                Ok(Some(seq)) => {
                    let bytes: i64 = sqlx::query_scalar(&format!(
                        "SELECT {EVENT_BYTES} FROM main.content_events WHERE seq=?"
                    ))
                    .bind(seq)
                    .fetch_one(&mut *self.conn)
                    .await?;
                    Some((seq, bytes))
                }
                Ok(None) => return Err(Error::engine(super::MISSING)),
                Err(Error::Conflict(_)) if !self.retained && Instant::now() < self.deadline => {
                    return Err(Error::engine(super::MISSING))
                }
                Err(other) => return Err(other),
            }
        };
        let bound = if let Some((seq, bytes)) = birth {
            self.work
                .charge(bytes, PREPARE_ROWS, PREPARE_BYTES)
                .map_err(|e| {
                    if self.retained {
                        e
                    } else {
                        Error::engine(super::MISSING)
                    }
                })?;
            check(self.deadline)?;
            trace(Trace::EventFetch);
            let raw: String =
                sqlx::query_scalar("SELECT payload FROM main.content_events WHERE seq=?")
                    .bind(seq)
                    .fetch_one(&mut *self.conn)
                    .await?;
            trace(Trace::Parse);
            let value = serde_json::from_str::<crate::record_body::budgeted::UniqueJson>(&raw)?.0;
            match value.get("source_record_id") {
                None | Some(Value::Null) => None,
                Some(Value::String(id))
                    if !id.is_empty() && id.len() <= 128 && !id.contains('\0') =>
                {
                    Some(id.clone())
                }
                _ => return Err(Error::engine(super::MISSING)),
            }
        } else {
            None
        };
        let logical = if physical == KERNEL_ROOT_ID {
            self.root_logical().await?
        } else {
            bound.unwrap_or_else(|| requested.into())
        };
        let structural_root = logical == "native:root"
            && !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root')",
            )
            .fetch_one(&mut *self.conn)
            .await?;
        let anchor = if structural_root {
            KERNEL_ROOT_ID
        } else {
            logical.as_str()
        };
        anchor_on(&mut *self.conn, actor, anchor).await?;
        let is_home: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                .bind(anchor)
                .fetch_one(&mut *self.conn)
                .await?;
        if !is_home {
            let folder: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_record_fields t JOIN kernel_record_fields k ON k.record_id=t.record_id WHERE t.record_id=? AND t.name='v1_type' AND CASE WHEN octet_length(t.value_json)=12 THEN t.value_json='\"Collection\"' ELSE 0 END AND k.name='v1_kind' AND CASE WHEN octet_length(k.value_json)=8 THEN k.value_json='\"folder\"' ELSE 0 END)").bind(anchor).fetch_one(&mut *self.conn).await?;
            if !folder {
                return Err(Error::engine(super::MISSING));
            }
        }
        Ok((logical.clone(), anchor.to_owned()))
    }
    // No required (record_id,type) index exists. Header absence/presence is
    // certified in bounded source snapshots (preparation or retained reads).
    // Canonical births/witnesses cannot disappear; new root witnesses in (S,T]
    // conflict below. The writer never repeats these historical scans.
    async fn root_logical(&mut self) -> Result<String> {
        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root')",
        )
        .fetch_one(&mut *self.conn)
        .await?
            || self.context_event(KERNEL_ROOT_ID, true).await?.is_some()
        {
            Ok("native:root".into())
        } else {
            Ok(KERNEL_ROOT_ID.into())
        }
    }
    async fn context_event(&mut self, record: &str, root: bool) -> Result<Option<i64>> {
        let mut after = 0;
        loop {
            check(self.deadline)?;
            let limit = (PREPARE_ROWS - self.work.rows).min(PAGE as usize);
            if limit == 0 {
                return Err(conflict(
                    "home context header budget exceeded; choose a logical folder context",
                ));
            }
            let rows: Vec<(i64, i64)> = sqlx::query_as(&context_page_sql())
                .bind(record)
                .bind(after)
                .bind(self.head)
                .bind(limit as i64)
                .fetch_all(&mut *self.conn)
                .await?;
            if rows.is_empty() {
                return Ok(None);
            }
            for (_, bytes) in &rows {
                self.work.charge(*bytes, PREPARE_ROWS, PREPARE_BYTES)?;
            }
            for (seq, _) in rows {
                check(self.deadline)?;
                let kind: String =
                    sqlx::query_scalar("SELECT type FROM main.content_events WHERE seq=?")
                        .bind(seq)
                        .fetch_one(&mut *self.conn)
                        .await?;
                if root {
                    trace(Trace::RootHeader);
                }
                if (root && kind == "kernel.import_home_policy.v1")
                    || (!root
                        && matches!(
                            kind.as_str(),
                            "kernel.import_home.v1" | "kernel.home_created.v1"
                        ))
                {
                    return Ok(Some(seq));
                }
                if (root && kind.starts_with("kernel.import_home_policy."))
                    || (!root
                        && (kind.starts_with("kernel.import_home.")
                            || kind.starts_with("kernel.home_created.")))
                {
                    return Err(conflict("unsupported home context import version"));
                }
                after = seq;
            }
        }
    }
}

/// Visibility is checked before historical context or catalog scan budgets.
/// Anchors are derived from the validated retained manifest, never caller indices.
pub(super) async fn retained_context_on(
    conn: &mut SqliteConnection,
    actor: &str,
    bearer: &str,
    manifest: &super::v2::Manifest,
    deadline: Instant,
) -> Result<(i64, Work)> {
    check(deadline)?;
    record_anchor_on(conn, actor, bearer).await?;
    let mut anchors = BTreeSet::from([manifest.context.logical_home_id.as_str()]);
    anchors.extend(manifest.sources.iter().filter_map(|s| s.anchor.as_deref()));
    for id in anchors {
        check(deadline)?;
        anchor_on(conn, actor, id).await?;
    }
    let head = head_on(conn).await?.0;
    let mut work = Work::default();
    let (logical, _) = HomeContext {
        conn,
        work: &mut work,
        head,
        deadline,
        retained: true,
    }
    .logical_home_inner(actor, &manifest.context.logical_home_id)
    .await?;
    if logical != manifest.context.logical_home_id {
        return Err(Error::conflict(
            "view_source_invalidated: logical home context changed",
        ));
    }
    Ok((head, work))
}

#[allow(dead_code)] // Internal resolver selects evidence only from this owned S snapshot.
impl Snapshot {
    pub(super) async fn check_retained(
        &mut self,
        actor: &str,
        workspace: &str,
        bearer: &str,
        definition: &super::v2::Definition,
    ) -> Result<()> {
        let (_, work) = super::retained_facets::mandatory_on(
            &mut self.conn,
            actor,
            workspace,
            bearer,
            definition,
            self.deadline,
        )
        .await?;
        self.work.rows = self
            .work
            .rows
            .checked_add(work.rows)
            .ok_or_else(|| conflict("row bound"))?;
        self.work.bytes = self
            .work
            .bytes
            .checked_add(work.bytes)
            .ok_or_else(|| conflict("byte bound"))?;
        if self.work.rows > PREPARE_ROWS || self.work.bytes > PREPARE_BYTES {
            return Err(conflict("source scan budget exceeded"));
        }
        Ok(())
    }
    pub(super) fn sources(&self) -> &[Source] {
        &self.sources
    }
    pub(super) fn work(&self) -> Work {
        self.work
    }

    /// Normalize only real logical-home aliases witnessed by the same S snapshot.
    /// A schema row has no independent ACL; its home bearer supplies visibility.
    pub(super) async fn logical_home(
        &mut self,
        actor: &str,
        requested: &str,
    ) -> Result<(String, String)> {
        HomeContext {
            conn: &mut self.conn,
            work: &mut self.work,
            head: self.head.0,
            deadline: self.deadline,
            retained: false,
        }
        .logical_home_inner(actor, requested)
        .await
        .map_err(|error| deadline_error(error, self.deadline))
    }
    pub(super) async fn require_bearer(&mut self, actor: &str, id: &str) -> Result<()> {
        check(self.deadline)?;
        record_anchor_on(&mut self.conn, actor, id)
            .await
            .map(|_| ())
            .map_err(|error| deadline_error(error, self.deadline))
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) async fn seal(
        self,
        actor: &str,
        selected: &[usize],
        anchors: &[String],
    ) -> Result<Proof> {
        let deadline = self.deadline;
        self.seal_inner(actor, selected, anchors, None)
            .await
            .map_err(|error| deadline_error(error, deadline))
    }
    pub(super) async fn seal_generated(
        self,
        actor: &str,
        selected: &[usize],
        anchors: &[String],
        bearer: &str,
    ) -> Result<Proof> {
        let deadline = self.deadline;
        self.seal_inner(actor, selected, anchors, Some(bearer))
            .await
            .map_err(|error| deadline_error(error, deadline))
    }
    async fn seal_inner(
        mut self,
        actor: &str,
        selected: &[usize],
        anchors: &[String],
        bearer: Option<&str>,
    ) -> Result<Proof> {
        check(self.deadline)?;
        if selected.len() > 288 || anchors.is_empty() || anchors.len() > 33 {
            return Err(conflict("retained source/anchor bound"));
        }
        let mut refs = Vec::new();
        let mut ids = BTreeSet::new();
        let mut catalog = 0;
        let mut values = std::collections::BTreeMap::<String, usize>::new();
        for index in selected {
            check(self.deadline)?;
            if !ids.insert(index) {
                return Err(conflict("duplicate selected source"));
            }
            let source = self
                .sources
                .get(*index)
                .ok_or_else(|| conflict("unknown selected source"))?;
            if source.section == "vocabulary_values" {
                let value: Value = serde_json::from_str(&source.payload)?;
                let vocab = value["vocabulary_id"]
                    .as_str()
                    .ok_or_else(|| conflict("missing vocabulary identity"))?;
                *values.entry(vocab.into()).or_default() += 1;
            } else {
                catalog += 1;
            }
            refs.push(Reference {
                section: source.section.clone(),
                source_id: source.source_id.clone(),
                origin: source.origin.clone(),
                event_seq: source.event_seq,
                event_id: source.event_id.clone(),
            });
        }
        if catalog > 32 || values.values().sum::<usize>() > 256 || values.values().any(|n| *n > 64)
        {
            return Err(conflict("retained source category bound"));
        }
        let mut checked = Vec::new();
        let mut seen = BTreeSet::new();
        for id in anchors {
            check(self.deadline)?;
            if !seen.insert(id) {
                return Err(conflict("duplicate anchor"));
            }
            checked.push(if bearer == Some(id.as_str()) {
                record_anchor_on(&mut self.conn, actor, id).await?
            } else {
                anchor_on(&mut self.conn, actor, id).await?
            });
        }
        check(self.deadline)?;
        sqlx::query("ROLLBACK").execute(&mut self.conn).await?;
        Ok(Proof {
            db: self.db,
            actor: actor.into(),
            head: self.head,
            deadline: self.deadline,
            refs,
            anchors: checked,
            database_file: self.database_file,
        })
    }
}

#[allow(dead_code)] // No authored write or receipt path calls this helper.
impl Proof {
    /// Point checks only, on the caller's read snapshot. Does not relax the
    /// strict admission proof or certify any public generated serving path.
    pub(super) async fn inspect_frozen_on(
        &self,
        db: &Db,
        conn: &mut SqliteConnection,
        actor: &str,
        required: &BTreeSet<usize>,
        deadline: Instant,
    ) -> Result<bool> {
        check(deadline)?;
        if !self.db.same_handle(db) || self.actor != actor {
            return Err(Error::engine(super::MISSING));
        }
        let file: String =
            sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name='main'")
                .fetch_one(&mut *conn)
                .await?;
        if file != self.database_file {
            return Err(Error::engine(super::MISSING));
        }
        // Authorize the entire anchor set before inspecting catalog presence.
        for expected in &self.anchors {
            check(deadline)?;
            let actual = if expected.record {
                record_anchor_on(conn, actor, &expected.id).await?
            } else {
                anchor_on(conn, actor, &expected.id).await?
            };
            if actual.home != expected.home
                || actual.moved != expected.moved
                || actual.root_record != expected.root_record
                || actual.record != expected.record
                || actual.folder != expected.folder
            {
                return Err(conflict("anchor placement changed"));
            }
        }
        if required.iter().any(|i| *i >= self.refs.len()) {
            return Err(conflict("required source index"));
        }
        let mut drift = false;
        for (i, r) in self.refs.iter().enumerate() {
            check(deadline)?;
            let current: Option<(i64, String, bool)> = sqlx::query_as("SELECT s.event_seq,e.id,CASE WHEN octet_length(s.origin)=? THEN s.origin=? ELSE 0 END FROM main.kernel_v1_state s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.section=? AND s.source_id=?")
                .bind(r.origin.len() as i64).bind(&r.origin).bind(&r.section).bind(&r.source_id).fetch_optional(&mut *conn).await?;
            if current.is_none() && required.contains(&i) {
                return Err(Error::engine(super::MISSING));
            }
            drift |= current != Some((r.event_seq, r.event_id.clone(), true));
        }
        check(deadline)?;
        Ok(drift)
    }
    pub(super) async fn recheck_on(
        &self,
        db: &Db,
        writer: &mut Writer,
        actor: &str,
    ) -> Result<Work> {
        if !self.db.same_handle(db) || actor != self.actor {
            return Err(conflict("source proof owner differs"));
        }
        if !self.db.same_handle(&writer.owner) {
            return Err(conflict(
                "source proof requires same database writer transaction",
            ));
        }
        self.recheck_inner(db, &mut writer.tx, actor)
            .await
            .map_err(|error| deadline_error(error, self.deadline))
    }
    async fn recheck_inner(
        &self,
        db: &Db,
        tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
        actor: &str,
    ) -> Result<Work> {
        let conn = &mut **tx;
        check(self.deadline)?;
        if !self.db.same_handle(db) || actor != self.actor {
            return Err(conflict("source proof owner differs"));
        }
        // Actual physical connection, not merely the caller's Db parameter.
        // Transaction type excludes bare connections; SQLite WRITE state excludes
        // deferred/read transactions. BEGIN IMMEDIATE is the existing writer seam.
        let file: String =
            sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name='main'")
                .fetch_one(&mut *conn)
                .await?;
        let write = {
            let mut handle = conn.lock_handle().await?;
            unsafe {
                libsqlite3_sys::sqlite3_txn_state(handle.as_raw_handle().as_ptr(), c"main".as_ptr())
                    == 2
            }
        };
        if file != self.database_file || !write {
            return Err(conflict(
                "source proof requires same database writer transaction",
            ));
        }
        let current = head_on(conn).await?;
        let id: Option<String> =
            sqlx::query_scalar("SELECT id FROM main.content_events WHERE seq=?")
                .bind(self.head.0)
                .fetch_optional(&mut *conn)
                .await?;
        if current.0 < self.head.0 || id.as_deref() != Some(&self.head.1) {
            return Err(conflict("source snapshot anchor changed"));
        }
        // Current authorization is never certified by the interval. Check it
        // before reporting conflicts which might describe hidden source work.
        for expected in &self.anchors {
            check(self.deadline)?;
            let actual = if expected.record {
                record_anchor_on(conn, actor, &expected.id).await?
            } else {
                anchor_on(conn, actor, &expected.id).await?
            };
            if actual.home != expected.home
                || actual.moved != expected.moved
                || actual.root_record != expected.root_record
                || actual.record != expected.record
                || actual.folder != expected.folder
            {
                return Err(conflict("anchor placement changed"));
            }
        }
        for r in &self.refs {
            check(self.deadline)?;
            // Do not transport a replacement origin before noticing a stale
            // reference. CASE is lazy and direct octet_length uses metadata;
            // any compared string is at most the already charged S length.
            let actual: Option<(i64,String,bool)> = sqlx::query_as("SELECT s.event_seq,e.id,CASE WHEN octet_length(s.origin)=? THEN s.origin=? ELSE 0 END FROM main.kernel_v1_state s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.section=? AND s.source_id=?")
                .bind(r.origin.len() as i64).bind(&r.origin).bind(&r.section).bind(&r.source_id).fetch_optional(&mut *conn).await?;
            if actual != Some((r.event_seq, r.event_id.clone(), true)) {
                return Err(conflict("source reference changed"));
            }
        }
        let mut work = Work::default();
        let mut after = self.head.0;
        while after < current.0 {
            check(self.deadline)?;
            // Every event in (S,T], never a type-filtered LIMIT.
            let limit = (WINDOW_ROWS - work.rows).min(PAGE as usize);
            if limit == 0 {
                return Err(conflict("source scan budget exceeded"));
            }
            let seqs: Vec<i64> = sqlx::query_scalar(EVENT_PAGE)
                .bind(after)
                .bind(current.0)
                .bind(limit as i64)
                .fetch_all(&mut *conn)
                .await?;
            if seqs.is_empty() {
                return Err(conflict("event interval incomplete"));
            }
            for _ in &seqs {
                trace(Trace::WindowRow);
            }
            let mut metadata = Vec::new();
            for seq in seqs {
                check(self.deadline)?;
                let bytes: i64 = sqlx::query_scalar(&format!(
                    "SELECT {EVENT_BYTES} FROM main.content_events WHERE seq=?"
                ))
                .bind(seq)
                .fetch_one(&mut *conn)
                .await?;
                work.charge(bytes, WINDOW_ROWS, WINDOW_BYTES)?;
                metadata.push(seq);
            }
            for seq in metadata {
                check(self.deadline)?;
                let kind: String =
                    sqlx::query_scalar("SELECT type FROM main.content_events WHERE seq=?")
                        .bind(seq)
                        .fetch_one(&mut *conn)
                        .await?;
                if kind.starts_with("kernel.import_home_policy.") {
                    let record: String =
                        sqlx::query_scalar("SELECT record_id FROM main.content_events WHERE seq=?")
                            .bind(seq)
                            .fetch_one(&mut *conn)
                            .await?;
                    if record == KERNEL_ROOT_ID {
                        return Err(conflict("root context import since preparation"));
                    }
                }
                if kind.starts_with("kernel.v1_state_imported.") {
                    trace(Trace::EventFetch);
                    let (record, raw): (String, String) = sqlx::query_as(
                        "SELECT record_id,payload FROM main.content_events WHERE seq=?",
                    )
                    .bind(seq)
                    .fetch_one(&mut *conn)
                    .await?;
                    let wrapper = decode_wrapper(&kind, &raw)?;
                    if record != KERNEL_ROOT_ID {
                        return Err(conflict("malformed import anchor"));
                    }
                    if SECTIONS.contains(&wrapper.section.as_str()) {
                        return Err(conflict("catalog import since preparation"));
                    }
                }
                after = seq;
            }
        }
        check(self.deadline)?;
        Ok(work)
    }
}

#[derive(Clone, Copy)]
enum Trace {
    StateFetch,
    EventFetch,
    Parse,
    WindowRow,
    RootHeader,
}
fn trace(_event: Trace) {
    #[cfg(test)]
    if matches!(_event, Trace::RootHeader) {
        let _ = ROOT_HEADERS.try_with(|n| n.set(n.get() + 1));
    }
    #[cfg(test)]
    let _ = TRACE.try_with(|n| {
        let mut v = n.get();
        if (_event as usize) < v.len() {
            v[_event as usize] += 1;
        }
        n.set(v);
    });
    #[cfg(test)]
    if matches!(_event, Trace::StateFetch) {
        // Deterministically expire the caller deadline inside the shared scan,
        // after mandatory checks. This task-local fixture never affects serving.
        let _ = SCAN_EXPIRES.try_with(|until| {
            if let Some(until) = until.take() {
                std::thread::sleep(
                    until.saturating_duration_since(Instant::now())
                        + std::time::Duration::from_millis(1),
                );
            }
        });
    }
}
#[cfg(test)]
tokio::task_local! { static TRACE: std::cell::Cell<[usize;4]>;
static ROOT_HEADERS: std::cell::Cell<usize>;
static SCAN_EXPIRES: std::cell::Cell<Option<Instant>>; }
#[cfg(test)]
mod tests;
