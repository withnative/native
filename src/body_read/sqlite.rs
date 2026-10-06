//! Private owned S2 executor and Hosted broker. No public offering or route.
//! Dispatcher-selected resolvers borrow this owner's snapshot and ledger.
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use futures::{future::BoxFuture, FutureExt, TryStreamExt};
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions, Connection, Row, Sqlite, SqliteConnection, Transaction};
use tokio::{sync::OwnedSemaphorePermit, task::JoinHandle};

use super::{BindingContext, Codec, Refusal, Request, Snapshot};
use crate::{db::Db, mcp::registry::Caller, portable_sql::*};

const BODY: u64 = 16 * 1024 * 1024;
const PROVENANCE: u64 = 32 * 1024 * 1024;
const EVENTS: usize = 128;
const TRUSTED_INPUT_BYTES: usize = 256;
const VM: u64 = 2_000_000;
const TIMEOUT: Duration = Duration::from_secs(5);

pub(super) mod alpha_install;
pub(super) mod owned_jobs;

#[cfg(test)]
use super::Page;
#[cfg(test)]
use crate::db::DatabaseOpenMode;
#[cfg(test)]
use std::sync::OnceLock;
#[cfg(test)]
use tokio::sync::Semaphore;

// Fixed call graph: policy1 + Alpha proof5 + HTML1 OR body1/canonical1.
// Eight is the largest production path; one private phase barrier makes nine.
const CPU_STAGES: usize = 9;
#[derive(Default)]
struct CpuSlot {
    handles: Vec<JoinHandle<()>>,
}
#[derive(Debug)]
enum CpuOutput {
    #[cfg(test)]
    Phase,
    Admission(crate::storage_profile::OperationAdmission),
    Body(Option<String>, String),
    Json(serde_json::Value),
    Declaration(serde_json::Value, bool),
    Marker(
        Box<(
            crate::control::ControlEventRow,
            crate::control::AlphaTabAdoptV2Payload,
        )>,
    ),
    AlphaBody(String, String),
    HtmlPrepared(crate::artifact_html::PreparedLaunch),
    Canonical(super::hosted::CanonicalBytes),
}

// Only the engine dispatcher selects this closed lookup; no app binding facts.
enum SourceLocator {
    AlphaInstall {
        package: String,
        #[cfg(test)]
        after_source: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
    },
    #[cfg(test)]
    Qualification { locator: String, resolver: Resolver },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    InvalidParams,
    InvalidCursor,
    CursorExpired,
    ResultBudget,
    UnsupportedProfile,
    UnsupportedCapability,
    SourceIntegrity,
    UndeclaredRead,
    AdoptionRequired,
    RecordUnavailable,
    AccessLost,
    ScopeDenied,
    RevisionChanged,
    TooLarge,
    ProcessBusy,
    SourceWork,
    ProvenanceWork,
    VmWork,
    Timeout,
    Engine,
}
impl Failure {
    fn code_reason(self) -> (&'static str, &'static str) {
        match self {
            Self::InvalidParams => ("invalid_params", "request"),
            Self::InvalidCursor => ("invalid_cursor", "cursor"),
            Self::CursorExpired => ("cursor_expired", "cursor"),
            Self::ResultBudget => ("resource_exhausted", "result_budget"),
            Self::UnsupportedProfile => ("unsupported_profile", "primary_sqlite_required"),
            Self::UnsupportedCapability => ("unsupported_capability", "portability_policy"),
            Self::SourceIntegrity => ("source_integrity", "source"),
            Self::UndeclaredRead => ("undeclared_read", "descriptor"),
            Self::AdoptionRequired => ("adoption_required", "source"),
            Self::RecordUnavailable => ("record_unavailable", "target"),
            Self::AccessLost => ("access_lost", "target"),
            Self::ScopeDenied => ("scope_denied", "scope"),
            Self::RevisionChanged => ("revision_changed", "incarnation"),
            Self::TooLarge => ("too_large", "body_read_work_limit"),
            Self::ProcessBusy => ("resource_exhausted", "process_busy"),
            Self::SourceWork => ("resource_exhausted", "source_work_limit"),
            Self::ProvenanceWork => ("resource_exhausted", "provenance_work_limit"),
            Self::VmWork => ("resource_exhausted", "vm_work_limit"),
            Self::Timeout => ("timeout", "request"),
            Self::Engine => ("engine", "integrity_or_execution"),
        }
    }
}
type Result<T> = std::result::Result<T, Failure>;

impl From<Refusal> for Failure {
    fn from(value: Refusal) -> Self {
        match value {
            Refusal::RevisionChanged => Self::RevisionChanged,
            Refusal::Engine => Self::Engine,
            Refusal::InvalidParams => Self::InvalidParams,
            Refusal::InvalidCursor => Self::InvalidCursor,
            Refusal::CursorExpired => Self::CursorExpired,
            Refusal::ResourceExhausted => Self::ResultBudget,
        }
    }
}

struct Budget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    steps: Arc<AtomicU64>,
    source: u64,
    provenance: u64,
    events: usize,
}
impl Budget {
    #[cfg(test)]
    fn new() -> Self {
        Self::from_ingress(Instant::now()).expect("monotonic clock")
    }
    fn from_ingress(started: Instant) -> Result<Self> {
        Ok(Self {
            deadline: started.checked_add(TIMEOUT).ok_or(Failure::Timeout)?,
            cancelled: Arc::new(AtomicBool::new(false)),
            steps: Arc::new(AtomicU64::new(0)),
            source: 0,
            provenance: 0,
            events: 0,
        })
    }
    fn stop(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) || Instant::now() >= self.deadline {
            return Err(Failure::Timeout);
        }
        if self.steps.load(Ordering::SeqCst) >= VM {
            return Err(Failure::VmWork);
        }
        if self.source > BODY {
            return Err(Failure::SourceWork);
        }
        if self.provenance > PROVENANCE {
            return Err(Failure::ProvenanceWork);
        }
        Ok(())
    }
    fn sql(&self) -> Result<()> {
        // Reserve an interval for this statement's unreported callback tail.
        self.steps.fetch_add(1000, Ordering::SeqCst);
        self.stop()
    }
    fn event(&mut self) -> Result<()> {
        self.stop()?;
        self.events = self.events.checked_add(1).ok_or(Failure::ProvenanceWork)?;
        if self.events > EVENTS {
            return Err(Failure::ProvenanceWork);
        }
        Ok(())
    }
    fn charge(&mut self, bytes: i64, provenance: bool) -> Result<()> {
        self.stop()?;
        let bytes = u64::try_from(bytes).map_err(|_| Failure::Engine)?;
        let (counter, limit, failure) = if provenance {
            (&mut self.provenance, PROVENANCE, Failure::ProvenanceWork)
        } else {
            (&mut self.source, BODY, Failure::SourceWork)
        };
        *counter = counter.checked_add(bytes).ok_or(failure)?;
        if *counter > limit {
            return Err(failure);
        }
        Ok(())
    }
}

/// Explicit release only. Ordinary unwinding must never return capacity.
struct Slot(Option<OwnedSemaphorePermit>);
impl Slot {
    fn acknowledge(&mut self) {
        drop(self.0.take());
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            p.forget();
        }
    }
}

struct PhysicalAck(Arc<()>);
struct Resources {
    ack_owner: Arc<()>,
    physical_finished: bool,
    slot: Slot,
    registry: Arc<owned_jobs::Registry>,
    db: Option<Db>,
    deployment: Option<crate::mcp::DeploymentAdmission>,
    pending: Option<crate::storage_profile::PendingBodyPolicy>,
    admitted: Option<crate::storage_profile::OperationAdmission>,
    budget: Option<Budget>,
    ticket: Option<crate::db::enrolled::BodyJobTicket>,
    connection: Option<SqliteConnection>,
    acquiring: Option<BoxFuture<'static, std::result::Result<SqliteConnection, sqlx::Error>>>,
    startup_polled: bool,
    startup_terminal: bool,
    unknown: bool,
    closing: Option<BoxFuture<'static, bool>>,
    cpu: CpuSlot,
}
impl Resources {
    fn new(
        db: &Db,
        permit: OwnedSemaphorePermit,
        budget: Budget,
        pending: crate::storage_profile::PendingBodyPolicy,
        deployment: Option<crate::mcp::DeploymentAdmission>,
        registry: Arc<owned_jobs::Registry>,
    ) -> Result<Self> {
        // Gate and process permit already owned; atomic handle registration
        // precedes constructing/submitting this ORIGINAL unpolled startup.
        let ticket = db.register_body_job().map_err(|_| Failure::Engine)?;
        let options = db.body_connection_options();
        Ok(Self {
            ack_owner: Arc::new(()),
            physical_finished: false,
            slot: Slot(Some(permit)),
            registry,
            db: Some(db.clone()),
            deployment,
            pending: Some(pending),
            admitted: None,
            budget: Some(budget),
            ticket: Some(ticket),
            connection: None,
            acquiring: Some(async move { options.connect().await }.boxed()),
            startup_polled: false,
            startup_terminal: false,
            unknown: false,
            closing: None,
            cpu: CpuSlot::default(),
        })
    }
    async fn start(&mut self) -> Result<()> {
        if self.startup_terminal {
            return if self.connection.is_some() && !self.unknown {
                Ok(())
            } else {
                Err(Failure::Engine)
            };
        }
        if !self.startup_polled {
            self.ticket
                .as_ref()
                .ok_or(Failure::Engine)?
                .physical_started()
                .map_err(|_| Failure::Engine)?;
            self.startup_polled = true;
        }
        // Never race/drop the inner acquisition: original future is retained
        // before polling, including its terminal Err/panic without a handle.
        let result = std::panic::AssertUnwindSafe(self.acquiring.as_mut().ok_or(Failure::Engine)?)
            .catch_unwind()
            .await;
        self.startup_terminal = true;
        match result {
            Ok(Ok(connection)) => {
                self.connection = Some(connection); // BEFORE any setup await
                Ok(())
            }
            _ => {
                self.unknown = true;
                // No raw handle was returned. Publish the armed ticket's
                // existing Unknown disposition without releasing any custody.
                drop(self.ticket.take());
                Err(Failure::Engine)
            }
        }
    }
    async fn finish_physical(&mut self) -> Result<PhysicalAck> {
        if self.physical_finished {
            return Err(Failure::Engine);
        }
        if !self.startup_polled && self.connection.is_none() && self.cpu.handles.is_empty() {
            // Actual pre-first-poll disposition, never called driver ACK.
            self.ticket
                .take()
                .ok_or(Failure::Engine)?
                .no_physical_started()
                .map_err(|_| Failure::Engine)?;
            self.acquiring = None;
            self.physical_finished = true;
            return Ok(PhysicalAck(self.ack_owner.clone()));
        }
        if !self.startup_terminal && self.connection.is_none() {
            self.start().await?;
        }
        if self.unknown {
            return Err(Failure::Engine);
        }
        if self.closing.is_none() {
            let ticket = self.ticket.take().ok_or(Failure::Engine)?;
            let connection = self.connection.take().ok_or(Failure::Engine)?;
            let handles = std::mem::take(&mut self.cpu.handles);
            self.closing = Some(ticket.finish_physical(connection, handles));
        }
        if !self.closing.as_mut().ok_or(Failure::Engine)?.await {
            self.unknown = true;
            return Err(Failure::Engine);
        }
        self.physical_finished = true;
        self.acquiring = None;
        Ok(PhysicalAck(self.ack_owner.clone()))
    }
    fn release_terminal(&mut self, ack: PhysicalAck) {
        if self.physical_finished && Arc::ptr_eq(&self.ack_owner, &ack.0) {
            // Prune terminal custody BEFORE returning its existing permit;
            // no replacement can transiently create a third retained entry.
            self.registry.complete(&ack);
            self.admitted = None;
            self.pending = None;
            self.deployment = None;
            self.slot.acknowledge();
        }
    }
    async fn finish(&mut self) -> Result<()> {
        let ack = self.finish_physical().await?;
        self.release_terminal(ack);
        Ok(())
    }
}
impl Drop for Resources {
    fn drop(&mut self) {
        if self.slot.0.is_none() {
            return;
        }
        // Emergency fixture/holder loss transfers WHOLE custody to the same
        // registry; production jobs already have a retained outer Arc holder.
        let registry = self.registry.clone();
        let finalizer = Self {
            ack_owner: self.ack_owner.clone(),
            physical_finished: self.physical_finished,
            slot: Slot(self.slot.0.take()),
            registry: registry.clone(),
            db: self.db.take(),
            deployment: self.deployment.take(),
            pending: self.pending.take(),
            admitted: self.admitted.take(),
            budget: self.budget.take(),
            ticket: self.ticket.take(),
            connection: self.connection.take(),
            acquiring: self.acquiring.take(),
            startup_polled: self.startup_polled,
            startup_terminal: self.startup_terminal,
            unknown: self.unknown,
            closing: self.closing.take(),
            cpu: std::mem::take(&mut self.cpu),
        };
        let job = registry.retain(finalizer);
        let holder = job.resources();
        registry.start(
            job,
            async move {
                let mut resources = holder.lock().await;
                if resources.physical_finished {
                    let ack = PhysicalAck(resources.ack_owner.clone());
                    resources.release_terminal(ack);
                    true
                } else {
                    matches!(
                        std::panic::AssertUnwindSafe(resources.finish())
                            .catch_unwind()
                            .await,
                        Ok(Ok(()))
                    )
                }
            }
            .boxed(),
        );
    }
}

struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// This type has no app constructor. Its fields are built by engine-owned
/// resolver implementations; tests supply explicit fixtures, not issuers.
pub(super) struct ResolvedSource {
    pub(super) source: String,
    pub(super) generation: String,
    pub(super) runtime: String,
    pub(super) declaration: String,
    pub(super) record_type: Option<String>,
}
impl ResolvedSource {
    /// Validate raw trusted correlation facts before constructing a codec binding.
    /// This preserves S1's exact byte policy; it does not normalize identities.
    fn checked(self, handle: &str) -> Result<Self> {
        if [
            &self.source,
            &self.generation,
            &self.runtime,
            &self.declaration,
        ]
        .iter()
        .any(|s| s.is_empty() || s.len() > TRUSTED_INPUT_BYTES)
            || !super::digest(&self.declaration)
            || self
                .generation
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_add(handle.len()))
                .is_none_or(|n| n > TRUSTED_INPUT_BYTES)
            || self.record_type.as_ref().is_some_and(|s| !trusted_input(s))
        {
            return Err(Failure::SourceIntegrity);
        }
        Ok(self)
    }
}

pub(super) fn trusted_input(value: &str) -> bool {
    value.len() <= TRUSTED_INPUT_BYTES && !value.trim().is_empty()
}
#[cfg(test)]
type Resolver =
    for<'a, 'tx> fn(&'a mut ReadSnapshot<'tx>, &'a str) -> BoxFuture<'a, Result<ResolvedSource>>;

struct ReadSnapshot<'a> {
    transaction: Transaction<'a, Sqlite>,
    budget: &'a mut Budget,
    viewer: String,
    member: bool,
}
impl ReadSnapshot<'_> {
    fn map_sql(&self, _: sqlx::Error) -> Failure {
        self.budget.stop().err().unwrap_or(Failure::Engine)
    }
    async fn text_columns(
        &mut self,
        table: &str,
        key: &str,
        id: &str,
        columns: &[&str],
    ) -> Result<Option<sqlx::sqlite::SqliteRow>> {
        // Only engine static identifiers reach this private helper.
        let sizes = columns
            .iter()
            .map(|c| format!("octet_length({c})"))
            .collect::<Vec<_>>()
            .join(",");
        self.budget.sql()?;
        let sql = format!("SELECT {sizes} FROM {table} WHERE {key}=?");
        let metadata = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&mut *self.transaction)
            .await
            .map_err(|e| self.map_sql(e))?;
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        for index in 0..columns.len() {
            let size: Option<i64> = metadata.try_get(index).map_err(|_| Failure::Engine)?;
            self.budget.charge(size.unwrap_or(0), false)?;
        }
        self.budget.sql()?;
        let sql = format!("SELECT {} FROM {table} WHERE {key}=?", columns.join(","));
        sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&mut *self.transaction)
            .await
            .map_err(|e| self.map_sql(e))
    }
    async fn kind(
        &mut self,
        record_type: &str,
        kind: Option<&str>,
    ) -> Result<Option<crate::meta::kind::KindResolution>> {
        match kind {
            None => Ok(None),
            Some(kind) => crate::meta::kind::resolve_with(self, record_type, kind)
                .await
                .map(Some)
                .map_err(|_| self.budget.stop().err().unwrap_or(Failure::Engine)),
        }
    }
    async fn bearer(&mut self, id: &str) -> Result<Option<String>> {
        self.budget.sql()?;
        let rows: Vec<String> = sqlx::query_scalar("SELECT CASE WHEN octet_length(target_id)<=128 THEN target_id END FROM links WHERE source_id=? AND relationship='part_of' ORDER BY target_id LIMIT 2")
            .bind(id).fetch_all(&mut *self.transaction).await.map_err(|e| self.map_sql(e))?;
        for row in &rows {
            self.budget.charge(row.len() as i64, false)?;
        }
        Ok((rows.len() == 1).then(|| rows[0].clone()))
    }
    async fn target_shape(
        &mut self,
        id: &str,
        position: crate::comments::Position,
        bearer: &str,
    ) -> Result<bool> {
        let row = self
            .text_columns(
                "annotation_targets",
                "annotation_id",
                id,
                &["target_record_id", "source_slot"],
            )
            .await?;
        let target = row
            .as_ref()
            .map(|r| Ok::<_, Failure>((text(r, "target_record_id")?, text(r, "source_slot")?)))
            .transpose()?;
        Ok(crate::comments::check_target_shape(
            position,
            bearer,
            target.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
        )
        .is_ok())
    }
    async fn eligible(&mut self, id: &str) -> Result<bool> {
        use crate::{comments::Position, generated::kinds::CoreKind};
        let Some(row) = self
            .text_columns("records", "id", id, &["type", "kind", "deleted_at"])
            .await?
        else {
            return Ok(false);
        };
        let record_type = text(&row, "type")?;
        let kind: Option<String> = row.try_get("kind").map_err(|_| Failure::Engine)?;
        let Some(resolution) = self.kind(&record_type, kind.as_deref()).await? else {
            return Ok(true);
        };
        if CoreKind::AnnotationAttribution.matches(&resolution) {
            return Ok(false);
        }
        if !CoreKind::AnnotationComment.matches(&resolution) {
            return Ok(true);
        }
        if optional(&row, "deleted_at")?.is_some() {
            return Ok(false);
        }
        let Some(bearer) = self.bearer(id).await? else {
            return Ok(false);
        };
        let Some(bearer_row) = self
            .text_columns("records", "id", &bearer, &["type", "kind", "deleted_at"])
            .await?
        else {
            return Ok(false);
        };
        if optional(&bearer_row, "deleted_at")?.is_some() {
            return Ok(false);
        }
        let bearer_kind = self
            .kind(
                &text(&bearer_row, "type")?,
                optional(&bearer_row, "kind")?.as_deref(),
            )
            .await?;
        let mut position = Position::Root;
        if bearer_kind
            .as_ref()
            .is_some_and(|r| CoreKind::AnnotationComment.matches(r))
        {
            let fields = self
                .text_columns("records", "id", &bearer, &["body", "lifecycle", "summary"])
                .await?
                .ok_or(Failure::Engine)?;
            if !prospective(&fields, Position::Root)? {
                return Ok(false);
            }
            let Some(root_bearer) = self.bearer(&bearer).await? else {
                return Ok(false);
            };
            let Some(root) = self
                .text_columns(
                    "records",
                    "id",
                    &root_bearer,
                    &["type", "kind", "deleted_at"],
                )
                .await?
            else {
                return Ok(false);
            };
            if optional(&root, "deleted_at")?.is_some() {
                return Ok(false);
            }
            if self
                .kind(&text(&root, "type")?, optional(&root, "kind")?.as_deref())
                .await?
                .as_ref()
                .is_some_and(|r| CoreKind::AnnotationComment.matches(r))
            {
                return Ok(false);
            }
            if !self
                .target_shape(&bearer, Position::Root, &root_bearer)
                .await?
            {
                return Ok(false);
            }
            position = Position::Reply;
        }
        if !self.target_shape(id, position, &bearer).await? {
            return Ok(false);
        }
        let fields = self
            .text_columns("records", "id", id, &["body", "lifecycle", "summary"])
            .await?
            .ok_or(Failure::Engine)?;
        prospective(&fields, position)
    }
}
fn text(row: &sqlx::sqlite::SqliteRow, name: &str) -> Result<String> {
    row.try_get(name).map_err(|_| Failure::Engine)
}
fn optional(row: &sqlx::sqlite::SqliteRow, name: &str) -> Result<Option<String>> {
    row.try_get(name).map_err(|_| Failure::Engine)
}
fn prospective(row: &sqlx::sqlite::SqliteRow, position: crate::comments::Position) -> Result<bool> {
    let body = optional(row, "body")?;
    let lifecycle = optional(row, "lifecycle")?;
    let summary = optional(row, "summary")?;
    Ok(crate::comments::check_prospective(
        position,
        body.as_deref(),
        lifecycle.as_deref(),
        summary.as_deref(),
    )
    .is_ok())
}

impl DomainStatementExecutor for ReadSnapshot<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            if statement.kind() != StatementKind::Select {
                return Err(SqlError::contract("reader requires SELECT"));
            }
            let render = statement.render(Dialect::Sqlite)?;
            validate_bindings(&render, bindings)?;
            // Metadata for exactly this source-reviewed SELECT precedes any
            // field hydration. Both passes share the same immutable snapshot.
            let sizes = columns
                .iter()
                .map(|c| {
                    Dialect::Sqlite
                        .quote_identifier(&c.name)
                        .map(|q| format!("octet_length({q})"))
                })
                .collect::<SqlResult<Vec<_>>>()?
                .join(",");
            self.budget
                .sql()
                .map_err(|_| SqlError::contract("reader budget"))?;
            let metadata_sql = format!("SELECT {sizes} FROM ({})", render.sql);
            let mut metadata =
                bind_sqlite(sqlx::query(&metadata_sql), bindings)?.fetch(&mut *self.transaction);
            while let Some(row) = metadata
                .try_next()
                .await
                .map_err(|_| SqlError::contract("reader storage"))?
            {
                for index in 0..columns.len() {
                    let size: Option<i64> = row
                        .try_get(index)
                        .map_err(|_| SqlError::contract("reader metadata"))?;
                    self.budget
                        .charge(size.unwrap_or(0), false)
                        .map_err(|_| SqlError::contract("reader budget"))?;
                }
            }
            drop(metadata);
            self.budget
                .sql()
                .map_err(|_| SqlError::contract("reader budget"))?;
            let rows = bind_sqlite(sqlx::query(&render.sql), bindings)?
                .fetch_all(&mut *self.transaction)
                .await
                .map_err(|_| SqlError::contract("reader storage"))?;
            rows.iter()
                .map(|row| normalize_sqlite_row(row, columns))
                .collect()
        })
    }
}

#[cfg(test)]
async fn execute(
    db: Db,
    caller: Caller,
    locator: String,
    raw: Vec<u8>,
    resolver: Resolver,
) -> Result<Page> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    execute_on(
        SLOTS.get_or_init(|| Arc::new(Semaphore::new(2))).clone(),
        db,
        caller,
        locator,
        raw,
        resolver,
    )
    .await
}

#[cfg(test)]
async fn execute_on(
    slots: Arc<Semaphore>,
    db: Db,
    caller: Caller,
    locator: String,
    raw: Vec<u8>,
    resolver: Resolver,
) -> Result<Page> {
    execute_owned(
        slots,
        db,
        caller,
        SourceLocator::Qualification { locator, resolver },
        raw,
        Instant::now(),
    )
    .await
}

#[cfg(test)]
async fn execute_alpha_on(
    slots: Arc<Semaphore>,
    db: Db,
    caller: Caller,
    package: String,
    raw: Vec<u8>,
    started: Instant,
) -> Result<Page> {
    execute_owned(
        slots,
        db,
        caller,
        SourceLocator::AlphaInstall {
            package,
            after_source: None,
        },
        raw,
        started,
    )
    .await
}

#[cfg(test)]
async fn execute_owned(
    slots: Arc<Semaphore>,
    db: Db,
    caller: Caller,
    locator: SourceLocator,
    raw: Vec<u8>,
    started: Instant,
) -> Result<Page> {
    let budget = Budget::from_ingress(started)?;
    let deadline = budget.deadline;
    let request = Request::parse(&raw)?;
    budget.stop()?;
    if db.open_mode() != DatabaseOpenMode::ReadWrite || caller.is_member_copy() {
        return Err(Failure::UnsupportedProfile);
    }
    let locator_valid = match &locator {
        SourceLocator::Qualification { locator, .. } => trusted_input(locator),
        SourceLocator::AlphaInstall { package, .. } => alpha_install::package_valid(package),
    };
    if caller.is_trusted_local() || !trusted_input(caller.credential()) || !locator_valid {
        return Err(Failure::SourceIntegrity);
    }
    let pending = crate::storage_profile::PendingBodyPolicy::acquire(&db, started)
        .await
        .map_err(|e| budget.stop().err().unwrap_or_else(|| policy_failure(e)))?;
    budget.stop()?;
    let permit = slots
        .try_acquire_owned()
        .map_err(|_| Failure::ProcessBusy)?;
    let cancel = budget.cancelled.clone();
    let _cancel_on_drop = CancelOnDrop(cancel.clone());
    let registry = Arc::new(owned_jobs::Registry::default()); // isolated test owner
    let resources = Resources::new(&db, permit, budget, pending, None, registry.clone())?;
    let job = registry.retain(resources);
    let holder = job.resources();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    registry.start(
        job,
        async move {
            let mut resources = holder.lock().await;
            let operation = std::panic::AssertUnwindSafe(async {
                resources.budget.as_ref().ok_or(Failure::Engine)?.stop()?;
                resources.start().await?;
                resources.budget.as_ref().ok_or(Failure::Engine)?.stop()?;
                let future = inner_job(
                    &db,
                    &caller,
                    &locator,
                    Some(request),
                    &cancel,
                    &mut resources,
                    None,
                );
                match tokio::time::timeout_at(deadline.into(), future)
                    .await
                    .map_err(|_| Failure::Timeout)??
                {
                    JobOutput::Page(page) => Ok(*page),
                    _ => Err(Failure::Engine),
                }
            })
            .catch_unwind()
            .await;
            let result = operation.unwrap_or(Err(Failure::Engine));
            let ack = match std::panic::AssertUnwindSafe(resources.finish_physical())
                .catch_unwind()
                .await
            {
                Ok(Ok(ack)) => Some(ack),
                _ => None,
            };
            let result = if ack.is_some() {
                result
            } else {
                Err(Failure::Engine)
            };
            let terminal = if let Some(ack) = ack {
                resources.release_terminal(ack);
                true
            } else {
                false
            }; // registry retains WHOLE original custody
            if !cancel.load(Ordering::SeqCst) && Instant::now() < deadline {
                let _ = sender.send(result);
            }
            terminal
        }
        .boxed(),
    );

    let result = tokio::time::timeout_at(deadline.into(), receiver)
        .await
        .map_err(|_| Failure::Timeout)?;
    if Instant::now() >= deadline {
        return Err(Failure::Timeout);
    }
    result.map_err(|_| Failure::Engine)?
}

enum JobOutput {
    #[cfg(test)]
    Page(Box<Page>),
    Canonical(super::hosted::CanonicalBytes),
    Issued,
    Retired,
}

#[cfg(test)]
async fn inner(
    db: &Db,
    caller: &Caller,
    locator: &SourceLocator,
    request: Request,
    budget: Budget,
    cancel: &Arc<AtomicBool>,
    resources: &mut Resources,
) -> Result<Page> {
    resources.budget = Some(budget);
    match inner_job(db, caller, locator, Some(request), cancel, resources, None).await? {
        JobOutput::Page(page) => Ok(*page),
        _ => Err(Failure::Engine),
    }
}

async fn inner_job(
    db: &Db,
    caller: &Caller,
    locator: &SourceLocator,
    request: Option<Request>,
    cancel: &Arc<AtomicBool>,
    resources: &mut Resources,
    mut broker: Option<&mut BrokerContext>,
) -> Result<JobOutput> {
    let Resources {
        connection,
        budget,
        cpu,
        pending,
        admitted,
        ..
    } = resources;
    let connection = connection.as_mut().ok_or(Failure::Engine)?;
    let budget = budget.as_mut().ok_or(Failure::Engine)?;
    let pending = pending.as_ref().ok_or(Failure::Engine)?.clone();
    let progress = budget.steps.clone();
    let handler_steps = progress.clone();
    let handler_cancel = cancel.clone();
    let deadline = budget.deadline;
    {
        let mut raw = connection
            .lock_handle()
            .await
            .map_err(|_| Failure::Engine)?;
        raw.remove_progress_handler();
        raw.set_progress_handler(1000, move || {
            let steps = handler_steps.fetch_add(1000, Ordering::SeqCst) + 1000;
            !handler_cancel.load(Ordering::SeqCst) && Instant::now() < deadline && steps < VM
        });
        // Explicit close means exact original options never re-enter a pool.
        // This defensive row/value ceiling is not the body read-work cap.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                raw.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                (PROVENANCE + 65536) as i32,
            );
        }
        let open =
            unsafe { libsqlite3_sys::sqlite3_get_autocommit(raw.as_raw_handle().as_ptr()) == 0 };
        if open {
            return Err(Failure::Engine);
        }
    }
    budget.stop()?;
    match db.install_body_owned_guard(connection).await {
        Ok(crate::db::BodyHostAvailability::AvailableUnmanaged) => (),
        Ok(crate::db::BodyHostAvailability::KnownUnavailable) => {
            budget.stop()?;
            if let Some(context) = broker.as_deref_mut() {
                context.refusal = Some(super::hosted::HostRefusal::MountUnavailable);
            }
            return Err(Failure::Engine);
        }
        Err(_) => return Err(budget.stop().err().unwrap_or(Failure::Engine)),
    }
    budget.stop()?;
    if connection.is_in_transaction() {
        return Err(Failure::Engine);
    }
    budget.sql()?;
    let temp: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema)")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| budget.stop().err().unwrap_or(Failure::Engine))?;
    if temp {
        return Err(Failure::Engine);
    }
    budget.sql()?;
    sqlx::query("PRAGMA query_only=ON")
        .execute(&mut *connection)
        .await
        .map_err(|_| budget.stop().err().unwrap_or(Failure::Engine))?;
    budget.sql()?;
    let transaction = connection
        .begin()
        .await
        .map_err(|_| budget.stop().err().unwrap_or(Failure::Engine))?;
    let mut snapshot = ReadSnapshot {
        transaction,
        budget,
        viewer: caller.credential().into(),
        member: caller.is_host_member(),
    };
    snapshot.budget.sql()?;
    let encoding: String = sqlx::query_scalar("PRAGMA encoding")
        .fetch_one(&mut *snapshot.transaction)
        .await
        .map_err(|e| snapshot.map_sql(e))?;
    if encoding != "UTF-8" {
        return Err(Failure::UnsupportedProfile);
    }
    snapshot.budget.sql()?;
    snapshot.budget.sql()?;
    let database = crate::identity::database_id_on(db, &mut snapshot.transaction)
        .await
        .map_err(|_| snapshot.budget.stop().err().unwrap_or(Failure::Engine))?;
    let columns = policy_columns(&mut snapshot).await?;
    let policy_db = db.clone();
    let CpuOutput::Admission(admission) = alpha_install::cpu(cpu, snapshot.budget, move || {
        pending
            .admit_snapshot(&policy_db, columns)
            .map(CpuOutput::Admission)
            .map_err(policy_failure)
    })
    .await?
    else {
        return Err(Failure::Engine);
    };
    *admitted = Some(admission.clone());
    admission
        .scope(async {
            if let Some(context) = broker.as_deref_mut() {
                if context.retire {
                    let mount = context.opened.as_ref().ok_or(Failure::Engine)?;
                    if !mount.database_matches(context.owner, &database) {
                        context.refusal = Some(super::hosted::HostRefusal::MountUnavailable);
                        return Err(Failure::Engine);
                    }
                    snapshot.budget.sql()?;
                    snapshot
                        .transaction
                        .rollback()
                        .await
                        .map_err(|_| Failure::Engine)?;
                    if progress.load(Ordering::SeqCst) >= VM {
                        return Err(Failure::VmWork);
                    }
                    if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
                        return Err(Failure::Timeout);
                    }
                    return Ok(JobOutput::Retired);
                }
            }
            let handle = db.handle_id().to_string();
            let (source, generation_bound, retained) = match locator {
                #[cfg(test)]
                SourceLocator::Qualification { locator, resolver } => {
                    (resolver(&mut snapshot, locator).await?, false, None)
                }
                SourceLocator::AlphaInstall { package, .. } => {
                    let proof = if broker.as_ref().is_some_and(|c| c.mixed) {
                        alpha_install::resolve_current_mixed(&mut snapshot, package, &handle, cpu)
                            .await?
                    } else {
                        alpha_install::resolve_current(&mut snapshot, package, &handle, cpu).await?
                    };
                    if let Some(binding) = proof.mixed_binding {
                        let context = broker.as_deref_mut().ok_or(Failure::Engine)?;
                        // Reserve both the retained reply buffer and potential
                        // Vec->Box shrink/copy BEFORE allocation/finalization.
                        snapshot.budget.charge(2 * MIXED_REPLY_BYTES as i64, true)?;
                        let mut bytes = Vec::new();
                        bytes
                            .try_reserve_exact(MIXED_REPLY_BYTES)
                            .map_err(|_| Failure::Engine)?;
                        context.mixed_reply = Some(bytes);
                        context.mixed_binding = Some(binding);
                    }
                    (proof.binding, true, Some((proof.body, proof.bundle)))
                }
            };
            let source = source.checked(&handle)?;
            #[cfg(test)]
            if let SourceLocator::AlphaInstall {
                after_source: Some((entered, release)),
                ..
            } = locator
            {
                entered.wait().await;
                release.wait().await;
                snapshot.budget.stop()?;
            }
            if let Some(context) = broker.as_deref_mut() {
                if let Some(mount) = &context.opened {
                    if !mount.database_matches(context.owner, &database)
                        || !mount.source_matches(context.owner, &source)
                    {
                        context.refusal = Some(super::hosted::HostRefusal::MountUnavailable);
                        return Err(Failure::Engine);
                    }
                } else {
                    let package = match locator {
                        SourceLocator::AlphaInstall { package, .. } => package,
                        #[cfg(test)]
                        _ => return Err(Failure::Engine),
                    };
                    let (body, bundle) = retained.ok_or(Failure::Engine)?;
                    if body.len() > crate::artifact_html::BODY_LIMIT {
                        context.refusal = Some(super::hosted::HostRefusal::HtmlUnavailable);
                        return Err(Failure::Engine);
                    }
                    snapshot.budget.charge(2 * 1024 * 1024, true)?;
                    let html_context = context
                        .delivery
                        .body_context(&context.origin)
                        .map_err(|e| context.fail(e))?;
                    let expected: [u8; 32] = hex::decode(bundle)
                        .map_err(|_| Failure::Engine)?
                        .try_into()
                        .map_err(|_| Failure::Engine)?;
                    #[cfg(test)]
                    let html_probe = context.probe.clone();
                    let prepared = alpha_install::cpu(cpu, snapshot.budget, move || {
                        #[cfg(test)]
                        if let Some(p) = html_probe.filter(|p| p.phase == ProbePhase::Html) {
                            let wait = p.html_wait.lock().unwrap().take().unwrap();
                            p.entered.add_permits(1);
                            wait.recv().unwrap(); // actual registered blocking HTML job
                        }
                        html_context
                            .prepare(body, expected)
                            .map(CpuOutput::HtmlPrepared)
                            .map_err(|_| Failure::Engine)
                    })
                    .await;
                    let CpuOutput::HtmlPrepared(prepared) = prepared.inspect_err(|e| {
                        if *e == Failure::Engine {
                            context.refusal = Some(super::hosted::HostRefusal::HtmlUnavailable);
                        }
                    })?
                    else {
                        return Err(Failure::Engine);
                    };
                    let (token, opened) = context
                        .owner
                        .mint(
                            &database,
                            caller.credential(),
                            package,
                            &source,
                            super::hosted::HostHeaders {
                                cookie: &context.cookie,
                                origin: &context.origin,
                            },
                            context.started,
                        )
                        .map_err(|e| {
                            context.refusal = Some(e);
                            Failure::Engine
                        })?;
                    let meta = opened.metadata(context.owner, &token).map_err(|e| {
                        context.refusal = Some(e);
                        Failure::Engine
                    })?;
                    // Millisecond wire times round down: use the same conservative
                    // instant, never renew the original start + 30s cleanup window.
                    let ticket_deadline = opened
                        .ticket_deadline(context.owner)
                        .map_err(|_| Failure::Timeout)?;
                    context.reservation = Some(
                        context
                            .delivery
                            .reserve_body_pair(prepared, meta, ticket_deadline)
                            .map_err(|e| context.fail(e))?,
                    );
                    #[cfg(test)]
                    if let Some(p) = &context.probe {
                        p.reserved.store(true, Ordering::SeqCst);
                    }
                    context.token = token;
                    snapshot.budget.sql()?;
                    snapshot
                        .transaction
                        .rollback()
                        .await
                        .map_err(|_| Failure::Engine)?;
                    if progress.load(Ordering::SeqCst) >= VM {
                        return Err(Failure::VmWork);
                    }
                    if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
                        return Err(Failure::Timeout);
                    }
                    return Ok(JobOutput::Issued);
                }
            }
            drop(retained);
            let request = request.ok_or(Failure::Engine)?;
            let binding = BindingContext {
                database,
                viewer: caller.credential().into(),
                declaring_source: source.source,
                adoption_generation: if generation_bound {
                    source.generation
                } else {
                    format!("{}:{}", source.generation, handle)
                },
                source_runtime_pin: source.runtime,
                declaration_digest: source.declaration,
                record_id: request.record_id.clone(),
            };
            let continued = request.cursor.is_some();
            let codec = broker
                .as_ref()
                .map(|c| c.owner.codec)
                .unwrap_or_else(Codec::process);
            let prepared = codec.prepare(&binding, request)?;
            let unavailable = if continued {
                Failure::AccessLost
            } else {
                Failure::RecordUnavailable
            };
            match snapshot.eligible(&binding.record_id).await {
                Ok(true) => (),
                Ok(false) | Err(Failure::SourceWork | Failure::VmWork) => return Err(unavailable),
                Err(e) => return Err(e),
            }
            snapshot.budget.sql()?;
            let deleted: bool =
                sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM records WHERE id=?")
                    .bind(&binding.record_id)
                    .fetch_one(&mut *snapshot.transaction)
                    .await
                    .map_err(|e| snapshot.map_sql(e))?;
            if deleted {
                return Err(unavailable);
            }
            let actual = crate::authorization::effective_capability_with(
                &mut snapshot,
                crate::mcp::tools::principal(caller),
                &binding.record_id,
                false,
            )
            .await
            .map_err(|_| snapshot.budget.stop().err().unwrap_or(Failure::Engine))?;
            if !actual.allows(crate::authorization::Capability::View) {
                return Err(unavailable);
            }
            if let Some(record_type) = source.record_type {
                let row = snapshot
                    .text_columns("records", "id", &binding.record_id, &["type"])
                    .await?
                    .ok_or(unavailable)?;
                if text(&row, "type")? != record_type {
                    return Err(Failure::ScopeDenied);
                }
            }
            let event = event(&mut snapshot, &binding.record_id).await?;
            if prepared
                .continuation
                .as_ref()
                .is_some_and(|c| c.event != event)
            {
                return Err(Failure::RevisionChanged);
            }
            snapshot.budget.sql()?;
            let (kind, bytes): (String, Option<i64>) =
                sqlx::query_as("SELECT typeof(body),octet_length(body) FROM records WHERE id=?")
                    .bind(&binding.record_id)
                    .fetch_one(&mut *snapshot.transaction)
                    .await
                    .map_err(|e| snapshot.map_sql(e))?;
            if !matches!(kind.as_str(), "null" | "text") {
                return Err(Failure::Engine);
            }
            if prepared.continuation.as_ref().is_some_and(|cursor| {
                cursor.total != bytes.unwrap_or(0) as u64 || cursor.body_present != (kind == "text")
            }) {
                return Err(Failure::Engine);
            }
            if bytes.is_some_and(|n| n < 0 || n as u64 > BODY) {
                return Err(Failure::TooLarge);
            }
            snapshot.budget.sql()?;
            let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
                .bind(&binding.record_id)
                .fetch_one(&mut *snapshot.transaction)
                .await
                .map_err(|e| snapshot.map_sql(e))?;
            if body.as_ref().map(|b| b.len() as i64) != bytes {
                return Err(Failure::Engine);
            }
            let hash_cancel = cancel.clone();
            let hashed = alpha_install::cpu(cpu, snapshot.budget, move || {
                let mut hash = Sha256::new();
                for chunk in body.as_deref().unwrap_or("").as_bytes().chunks(65536) {
                    if hash_cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
                        return Err(Failure::Timeout);
                    }
                    hash.update(chunk);
                }
                Ok(CpuOutput::Body(body, hex::encode(hash.finalize())))
            })
            .await;
            let CpuOutput::Body(body, digest) = hashed? else {
                return Err(Failure::Engine);
            };
            snapshot.budget.stop()?;
            let mut page = prepared.page(Snapshot {
                body: body.as_deref(),
                event_id: &event,
                body_digest: &digest,
            })?;
            page.limits.max_body_bytes = Some(BODY);
            page.limits.max_source_bytes = Some(BODY);
            page.limits.max_provenance_payload_bytes = Some(PROVENANCE);
            page.limits.max_provenance_events = Some(EVENTS);
            page.limits.request_timeout_ms = Some(TIMEOUT.as_millis() as u64);
            super::check_response_size(&page, super::MAX_RESPONSE_BYTES)?;
            let output = if broker.is_some() {
                snapshot
                    .budget
                    .charge(super::MAX_RESPONSE_BYTES as i64, true)?;
                let CpuOutput::Canonical(bytes) =
                    alpha_install::cpu(cpu, snapshot.budget, move || {
                        let bytes = serde_json::to_vec(&page).map_err(|_| Failure::Engine)?;
                        if bytes.len() > super::MAX_RESPONSE_BYTES {
                            return Err(Failure::ResultBudget);
                        }
                        Ok(CpuOutput::Canonical(super::hosted::CanonicalBytes(
                            bytes.into_boxed_slice(),
                        )))
                    })
                    .await?
                else {
                    return Err(Failure::Engine);
                };
                JobOutput::Canonical(bytes)
            } else {
                #[cfg(test)]
                {
                    JobOutput::Page(Box::new(page))
                }
                #[cfg(not(test))]
                {
                    return Err(Failure::Engine);
                }
            };
            snapshot.budget.sql()?;
            snapshot
                .transaction
                .rollback()
                .await
                .map_err(|_| Failure::Engine)?;
            if progress.load(Ordering::SeqCst) >= VM {
                return Err(Failure::VmWork);
            }
            if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return Err(Failure::Timeout);
            }
            Ok(output)
        })
        .await
}

fn policy_failure(error: crate::storage_profile::BodyPolicyFailure) -> Failure {
    use crate::storage_profile::BodyPolicyFailure::*;
    match error {
        Deadline => Failure::Timeout,
        HandleMismatch | State(_) => Failure::Engine,
        Admission(_) => Failure::UnsupportedCapability,
    }
}

async fn policy_columns(
    snapshot: &mut ReadSnapshot<'_>,
) -> Result<Option<crate::storage_profile::PortabilityPolicyColumns>> {
    const TEXT: [&str; 7] = [
        "enforcement",
        "source_profile_id",
        "source_mode",
        "targets",
        "revision_floors",
        "allow_conversions",
        "catalog_sha256",
    ];
    snapshot.budget.sql()?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='storage_portability_policy')")
        .fetch_one(&mut *snapshot.transaction).await.map_err(|e| snapshot.map_sql(e))?;
    if !exists {
        return Ok(None);
    }
    // ALL identifiers come from this fixed engine list. INTEGER revisions and
    // seven TEXT/octet metadata precede any policy string hydration.
    let fields = TEXT
        .iter()
        .map(|c| format!("typeof({c}),octet_length({c})"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT typeof(policy_revision),typeof(source_profile_revision),{fields} FROM storage_portability_policy WHERE singleton=1 LIMIT 2");
    snapshot.budget.sql()?;
    let metadata = sqlx::query(&sql)
        .fetch_all(&mut *snapshot.transaction)
        .await
        .map_err(|e| snapshot.map_sql(e))?;
    if metadata.len() > 1 {
        return Err(Failure::Engine);
    }
    let Some(row) = metadata.first() else {
        return Ok(None);
    };
    for index in 0..2 {
        if row
            .try_get::<String, _>(index)
            .map_err(|_| Failure::Engine)?
            != "integer"
        {
            return Err(Failure::Engine);
        }
    }
    snapshot.budget.charge(16, true)?;
    for index in 0..TEXT.len() {
        if row
            .try_get::<String, _>(2 + index * 2)
            .map_err(|_| Failure::Engine)?
            != "text"
        {
            return Err(Failure::Engine);
        }
        let bytes: i64 = row.try_get(3 + index * 2).map_err(|_| Failure::Engine)?;
        // SQLite row hydration, owned column extraction and bounded decoder
        // input custody share the ORIGINAL cumulative provenance ledger.
        snapshot
            .budget
            .charge(bytes.checked_mul(3).ok_or(Failure::ProvenanceWork)?, true)?;
    }
    snapshot.budget.sql()?;
    let row = sqlx::query("SELECT policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256 FROM storage_portability_policy WHERE singleton=1")
        .fetch_one(&mut *snapshot.transaction).await.map_err(|e| snapshot.map_sql(e))?;
    Ok(Some(crate::storage_profile::PortabilityPolicyColumns {
        policy_revision: row
            .try_get("policy_revision")
            .map_err(|_| Failure::Engine)?,
        enforcement: row.try_get("enforcement").map_err(|_| Failure::Engine)?,
        source_profile_id: row
            .try_get("source_profile_id")
            .map_err(|_| Failure::Engine)?,
        source_profile_revision: row
            .try_get("source_profile_revision")
            .map_err(|_| Failure::Engine)?,
        source_mode: row.try_get("source_mode").map_err(|_| Failure::Engine)?,
        targets: row.try_get("targets").map_err(|_| Failure::Engine)?,
        revision_floors: row
            .try_get("revision_floors")
            .map_err(|_| Failure::Engine)?,
        allow_conversions: row
            .try_get("allow_conversions")
            .map_err(|_| Failure::Engine)?,
        catalog_sha256: row.try_get("catalog_sha256").map_err(|_| Failure::Engine)?,
    }))
}

async fn event(snapshot: &mut ReadSnapshot<'_>, id: &str) -> Result<String> {
    snapshot.budget.sql()?;
    let metadata = sqlx::query("SELECT CASE WHEN octet_length(id)<=128 THEN id END AS id,type,octet_length(payload) AS bytes FROM content_events WHERE record_id=? AND type IN ('record.created','record.updated','receipt.committed.v1','unit.revision.recorded.v1') ORDER BY seq DESC LIMIT 129")
        .bind(id).fetch_all(&mut *snapshot.transaction).await.map_err(|e| snapshot.map_sql(e))?;
    let mut creation = None;
    for (index, row) in metadata.iter().enumerate() {
        if index >= EVENTS {
            return Err(Failure::ProvenanceWork);
        }
        snapshot.budget.event()?;
        snapshot
            .budget
            .charge(row.try_get("bytes").map_err(|_| Failure::Engine)?, true)?;
        let event_id = text(row, "id")?;
        // Same predicate as S1, before carrier selection, fallback or revision comparison.
        if !super::identity(&event_id) {
            return Err(Failure::Engine);
        }
        if text(row, "type")? == "record.created" {
            creation = Some(event_id.clone());
        }
        snapshot.budget.sql()?;
        let sql = format!(
            "SELECT CASE WHEN typeof(payload)='text' AND octet_length(payload)<=? THEN CASE WHEN json_valid(payload) THEN CASE WHEN json_type(payload)='object' THEN ({}) ELSE NULL END ELSE NULL END ELSE NULL END FROM content_events WHERE id=?",
            crate::record_body::BODY_CARRYING_EVENT_SQL
        );
        let carrier: Option<bool> = sqlx::query_scalar(&sql)
            .bind(PROVENANCE as i64)
            .bind(&event_id)
            .fetch_one(&mut *snapshot.transaction)
            .await
            .map_err(|e| snapshot.map_sql(e))?;
        if carrier.ok_or(Failure::Engine)? {
            return Ok(event_id);
        }
    }
    snapshot.budget.sql()?;
    let absent: bool = sqlx::query_scalar("SELECT body IS NULL FROM records WHERE id=?")
        .bind(id)
        .fetch_one(&mut *snapshot.transaction)
        .await
        .map_err(|e| snapshot.map_sql(e))?;
    if absent {
        creation.ok_or(Failure::Engine)
    } else {
        Err(Failure::Engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sqlx::TransactionManager;

    fn fixture_resolver<'a, 'tx>(
        snapshot: &'a mut ReadSnapshot<'tx>,
        locator: &'a str,
    ) -> BoxFuture<'a, Result<ResolvedSource>> {
        Box::pin(async move {
            // Explicit qualification fixture; this is NOT an AlphaInstall or
            // AppPackage marker verifier and is not a production authority.
            let row = snapshot
                .text_columns("records", "id", locator, &["body", "deleted_at"])
                .await?
                .ok_or(Failure::SourceIntegrity)?;
            if optional(&row, "deleted_at")?.is_some() {
                return Err(Failure::SourceIntegrity);
            }
            let fixture: Value =
                serde_json::from_str(&text(&row, "body")?).map_err(|_| Failure::SourceIntegrity)?;
            if fixture["descriptor"] != true {
                return Err(Failure::UndeclaredRead);
            }
            if fixture["adopted"] != true {
                return Err(Failure::AdoptionRequired);
            }
            if !fixture["viewers"]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(&snapshot.viewer)))
            {
                return Err(Failure::SourceIntegrity);
            }
            let field = |name: &str| {
                fixture[name]
                    .as_str()
                    .filter(|s| s.len() <= 128 && !s.is_empty())
                    .map(str::to_owned)
                    .ok_or(Failure::SourceIntegrity)
            };
            Ok(ResolvedSource {
                source: locator.into(),
                generation: field("generation")?,
                runtime: field("runtime")?,
                declaration: field("declaration")?,
                record_type: fixture["record_type"].as_str().map(str::to_owned),
            })
        })
    }
    fn fixture() -> Value {
        json!({"descriptor":true,"adopted":true,"viewers":["acct_alice","acct_bea"],"generation":"generation-one","runtime":"retained-runtime","declaration":"a".repeat(64)})
    }
    async fn setup() -> (tempfile::TempDir, Db, String, String) {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(directory.path().join("reader.db").to_str().unwrap())
            .await
            .unwrap();
        let source = crate::store::create_record(&db,json!({"type":"Document","kind":"note","name":"Resolver qualification fixture","home_id":crate::schema::ROOT_RECORD_ID,"body":fixture().to_string()})).await.unwrap();
        let target = crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Body","home_id":crate::schema::ROOT_RECORD_ID}),
        )
        .await
        .unwrap();
        for (name, token) in [("Alice", "acct_alice"), ("Bea", "acct_bea")] {
            let person = crate::store::create_record(&db,json!({"type":"Entity","kind":"person","name":name,"home_id":crate::schema::ROOT_RECORD_ID})).await.unwrap();
            sqlx::query("INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,'account',?,1)").bind(person).bind(token).execute(db.write_pool()).await.unwrap();
        }
        (directory, db, source, target)
    }
    fn caller(account: &str) -> Caller {
        Caller::authenticated(account).with_hosting_member(true)
    }
    async fn read(db: &Db, source: &str, request: Value) -> Result<Page> {
        execute(
            db.clone(),
            caller("acct_alice"),
            source.into(),
            serde_json::to_vec(&request).unwrap(),
            fixture_resolver,
        )
        .await
    }
    fn next(page: &Page) -> Value {
        json!({"record_id":page.record_id,"revision":page.revision,"cursor":page.next_cursor})
    }

    // Isolated admission permits keep these new conformance fixtures independent
    // of the process-global executor used by earlier qualification tests.
    async fn correction_read(db: &Db, source: &str, request: Value) -> Result<Page> {
        execute_on(
            Arc::new(Semaphore::new(2)),
            db.clone(),
            caller("acct_alice"),
            source.into(),
            serde_json::to_vec(&request).unwrap(),
            fixture_resolver,
        )
        .await
    }

    #[tokio::test]
    async fn malformed_event_identity_precedes_first_and_continuation_revision_checks() {
        let (_directory, db, source, target) = setup().await;
        crate::store::update_record(&db, &target, json!({"body":"abcdefgh"}))
            .await
            .unwrap();
        let first = correction_read(&db, &source, json!({"record_id":target,"page_bytes":4}))
            .await
            .unwrap();
        assert!(!first.complete);
        let continuation = next(&first);
        // Explicit isolated storage corruption, not an ordinary writer path.
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(db.write_pool())
            .await
            .unwrap();
        // Event IDs have foreign-key dependents. This isolated fault injection
        // must bypass them on ONE held connection, never a pooled ordinary write.
        let mut fault_connection = db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *fault_connection)
            .await
            .unwrap();
        let (seq, original): (i64, String) = sqlx::query_as(
            "SELECT seq,id FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq DESC LIMIT 1")
            .bind(&target).fetch_one(&mut *fault_connection).await.unwrap();
        for invalid in [
            "".to_owned(),
            "bad id".into(),
            "bad\tid".into(),
            "é".into(),
            "x".repeat(129),
        ] {
            sqlx::query("UPDATE content_events SET id=? WHERE seq=?")
                .bind(&invalid)
                .bind(seq)
                .execute(&mut *fault_connection)
                .await
                .unwrap();
            for request in [json!({"record_id":target}), continuation.clone()] {
                assert_eq!(
                    correction_read(&db, &source, request).await.unwrap_err(),
                    Failure::Engine
                );
            }
        }
        // An invalid selected identity does not bypass codec/viewer gates.
        for (viewer, request, expected) in [
            (
                caller("acct_bea"),
                continuation.clone(),
                Failure::InvalidCursor,
            ),
            (
                Caller::authenticated("acct_alice").with_hosting_member(false),
                continuation.clone(),
                Failure::AccessLost,
            ),
            (
                Caller::authenticated("acct_alice").with_hosting_member(false),
                json!({"record_id":target}),
                Failure::RecordUnavailable,
            ),
        ] {
            assert_eq!(
                execute_on(
                    Arc::new(Semaphore::new(2)),
                    db.clone(),
                    viewer,
                    source.clone(),
                    serde_json::to_vec(&request).unwrap(),
                    fixture_resolver
                )
                .await
                .unwrap_err(),
                expected
            );
        }
        sqlx::query("UPDATE content_events SET id=? WHERE seq=?")
            .bind(original)
            .bind(seq)
            .execute(&mut *fault_connection)
            .await
            .unwrap();
        assert!(correction_read(&db, &source, continuation.clone())
            .await
            .is_ok());
        for payload in ["[]", "null", "{"] {
            sqlx::query("UPDATE content_events SET payload=? WHERE seq=?")
                .bind(payload)
                .bind(seq)
                .execute(&mut *fault_connection)
                .await
                .unwrap();
            assert_eq!(
                correction_read(&db, &source, continuation.clone())
                    .await
                    .unwrap_err(),
                Failure::Engine
            );
        }
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *fault_connection)
            .await
            .unwrap();
        fault_connection.close().await.unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn event_payload_requires_object_but_preserves_absent_and_all_null_carriers() {
        let (_directory, db, source, target) = setup().await;
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(db.write_pool())
            .await
            .unwrap();
        let seq: i64 = sqlx::query_scalar(
            "SELECT seq FROM content_events WHERE record_id=? AND type='record.created'",
        )
        .bind(&target)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        // Only a valid object with absent body may use the null-body creation fallback.
        for payload in ["{}", "{\"unrelated\":true}"] {
            sqlx::query("UPDATE content_events SET payload=? WHERE seq=?")
                .bind(payload)
                .bind(seq)
                .execute(db.write_pool())
                .await
                .unwrap();
            let page = correction_read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap();
            assert!(!page.body_present && page.complete && page.total_bytes == 0);
        }
        for payload in ["null", "false", "42", "\"scalar\"", "[]", "[{}]", "{"] {
            sqlx::query("UPDATE content_events SET payload=? WHERE seq=?")
                .bind(payload)
                .bind(seq)
                .execute(db.write_pool())
                .await
                .unwrap();
            assert_eq!(
                correction_read(&db, &source, json!({"record_id":target}))
                    .await
                    .unwrap_err(),
                Failure::Engine
            );
        }
        // SQL NULL and BLOB storage are malformed payloads even if the bytes spell an object.
        for sql in [
            "UPDATE content_events SET payload=NULL WHERE seq=?",
            "UPDATE content_events SET payload=CAST('{}' AS BLOB) WHERE seq=?",
        ] {
            sqlx::query(sql)
                .bind(seq)
                .execute(db.write_pool())
                .await
                .unwrap();
            assert_eq!(
                correction_read(&db, &source, json!({"record_id":target}))
                    .await
                    .unwrap_err(),
                Failure::Engine
            );
        }
        for (kind, payload) in [
            ("record.created", "{\"body\":null}"),
            ("record.updated", "{\"body\":null}"),
            ("receipt.committed.v1", "{\"body\":null}"),
            (
                "unit.revision.recorded.v1",
                "{\"content\":{\"content\":null}}",
            ),
        ] {
            sqlx::query("UPDATE content_events SET type=?,payload=? WHERE seq=?")
                .bind(kind)
                .bind(payload)
                .bind(seq)
                .execute(db.write_pool())
                .await
                .unwrap();
            let page = correction_read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap();
            assert!(!page.body_present && page.complete);
        }
        // Target diagnostics remain after source, codec and current scope gates.
        sqlx::query("UPDATE content_events SET payload='[]' WHERE seq=?")
            .bind(seq)
            .execute(db.write_pool())
            .await
            .unwrap();
        let mut configured = fixture();
        configured["descriptor"] = json!(false);
        crate::store::update_record(&db, &source, json!({"body":configured.to_string()}))
            .await
            .unwrap();
        assert_eq!(
            correction_read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap_err(),
            Failure::UndeclaredRead
        );
        configured["descriptor"] = json!(true);
        configured["record_type"] = json!("Entity");
        crate::store::update_record(&db, &source, json!({"body":configured.to_string()}))
            .await
            .unwrap();
        assert_eq!(
            correction_read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap_err(),
            Failure::ScopeDenied
        );
        db.close().await;
    }

    #[tokio::test]
    async fn trusted_lookup_and_account_refuse_before_permit_checkout_or_resolver() {
        fn never_entered<'a, 'tx>(
            _: &'a mut ReadSnapshot<'tx>,
            _: &'a str,
        ) -> BoxFuture<'a, Result<ResolvedSource>> {
            panic!("invalid trusted input reached resolver")
        }
        let (_directory, db, source, target) = setup().await;
        let size = db.governed_pool().size();
        let idle = db.governed_pool().num_idle();
        for invalid in [
            String::new(),
            " \t\n".into(),
            "x".repeat(257),
            "é".repeat(129),
        ] {
            for (locator, account) in [
                (invalid.clone(), "acct_alice".to_owned()),
                (source.clone(), invalid),
            ] {
                // Zero slots makes any attempted admission fail ProcessBusy. SourceIntegrity
                // proves refusal before permit acquisition, spawn and pool checkout.
                let slots = Arc::new(Semaphore::new(0));
                assert_eq!(
                    execute_on(
                        slots.clone(),
                        db.clone(),
                        caller(&account),
                        locator,
                        serde_json::to_vec(&json!({"record_id":target})).unwrap(),
                        never_entered
                    )
                    .await
                    .unwrap_err(),
                    Failure::SourceIntegrity
                );
                assert_eq!(slots.available_permits(), 0);
                assert_eq!(db.governed_pool().size(), size);
                assert_eq!(db.governed_pool().num_idle(), idle);
            }
        }
        assert!(trusted_input(&"é".repeat(128)));
        assert!(trusted_input(" acct_exact ")); // validation, not stripping/aliasing
        db.close().await;
    }

    #[test]
    fn trusted_resolved_source_checks_exact_binding_bounds_and_digest_shape() {
        fn facts() -> ResolvedSource {
            ResolvedSource {
                source: "source".into(),
                generation: "generation".into(),
                runtime: "runtime".into(),
                declaration: "a".repeat(64),
                record_type: None,
            }
        }
        let handle = "00000000-0000-0000-0000-000000000000";
        for field in 0..5 {
            for invalid in [String::new(), "é".repeat(129)] {
                let mut source = facts();
                match field {
                    0 => source.source = invalid,
                    1 => source.generation = invalid,
                    2 => source.runtime = invalid,
                    3 => source.declaration = invalid,
                    _ => source.record_type = Some(invalid),
                }
                assert!(matches!(
                    source.checked(handle),
                    Err(Failure::SourceIntegrity)
                ));
            }
        }
        for declaration in ["A".repeat(64), "z".repeat(64), "a".repeat(63)] {
            let mut source = facts();
            source.declaration = declaration;
            assert!(matches!(
                source.checked(handle),
                Err(Failure::SourceIntegrity)
            ));
        }
        let mut source = facts();
        source.generation = "x".repeat(220);
        assert!(matches!(
            source.checked(handle),
            Err(Failure::SourceIntegrity)
        ));
        let mut source = facts();
        source.generation = "x".repeat(219);
        source.source = "é".repeat(128);
        source.runtime = " exact runtime ".into();
        let checked = source.checked(handle).unwrap();
        assert_eq!(checked.source, "é".repeat(128));
        assert_eq!(checked.runtime, " exact runtime ");
    }

    #[tokio::test]
    async fn owned_reconstructs_large_utf8_with_fresh_checkouts_and_engine_guard() {
        let (_directory, db, source, target) = setup().await;
        assert_eq!(
            db.body_connection_options().get_filename(),
            db.governed_pool().connect_options().get_filename()
        );
        let body = "é😀\n\tA".repeat(50000);
        assert!(body.len() > 262144 && body.chars().count() > 120000);
        crate::store::update_record(&db, &target, json!({"body":body}))
            .await
            .unwrap();
        let mut request = json!({"record_id":target});
        let mut assembled = String::new();
        let mut revision = None;
        loop {
            let page = read(&db, &source, request).await.unwrap();
            assert_eq!(page.start_byte as usize, assembled.len());
            assert_eq!(
                page.body_digest,
                crate::mcp::tools::lifecycle::body_digest(Some(&body))
            );
            assert_eq!(page.limits.max_body_bytes, Some(BODY));
            assert!(serde_json::to_vec(&page).unwrap().len() <= super::super::MAX_RESPONSE_BYTES);
            if let Some(prior) = &revision {
                assert_eq!(prior, &page.revision);
            } else {
                revision = Some(page.revision.clone());
            }
            assembled.push_str(&page.text);
            if page.complete {
                break;
            }
            request = next(&page);
        }
        assert_eq!(assembled, body);
        db.close().await;
    }

    #[tokio::test]
    async fn viewer_scope_revocation_source_generation_and_aba_refusals() {
        let (_directory, db, source, target) = setup().await;
        crate::store::update_record(&db, &target, json!({"body":"abcdefgh"}))
            .await
            .unwrap();
        let first = read(&db, &source, json!({"record_id":target,"page_bytes":4}))
            .await
            .unwrap();
        let pair = next(&first);
        assert_eq!(
            execute(
                db.clone(),
                caller("acct_bea"),
                source.clone(),
                serde_json::to_vec(&pair).unwrap(),
                fixture_resolver
            )
            .await
            .unwrap_err(),
            Failure::InvalidCursor
        );
        let second_viewer = execute(
            db.clone(),
            caller("acct_bea"),
            source.clone(),
            serde_json::to_vec(&json!({"record_id":target})).unwrap(),
            fixture_resolver,
        )
        .await
        .unwrap();
        assert_ne!(first.revision, second_viewer.revision);
        let denied = Caller::authenticated("acct_alice").with_hosting_member(false);
        assert_eq!(
            execute(
                db.clone(),
                denied,
                source.clone(),
                serde_json::to_vec(&pair).unwrap(),
                fixture_resolver
            )
            .await
            .unwrap_err(),
            Failure::AccessLost
        );
        let mut changed = fixture();
        changed["record_type"] = json!("Entity");
        crate::store::update_record(&db, &source, json!({"body":changed.to_string()}))
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, pair.clone()).await.unwrap_err(),
            Failure::ScopeDenied
        );
        changed = fixture();
        changed["generation"] = json!("generation-two");
        crate::store::update_record(&db, &source, json!({"body":changed.to_string()}))
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, pair.clone()).await.unwrap_err(),
            Failure::InvalidCursor
        );
        crate::store::update_record(&db, &source, json!({"body":fixture().to_string()}))
            .await
            .unwrap();
        crate::store::update_record(&db, &target, json!({"body":"changed"}))
            .await
            .unwrap();
        crate::store::update_record(&db, &target, json!({"body":"abcdefgh"}))
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, pair).await.unwrap_err(),
            Failure::RevisionChanged
        );
        crate::store::delete_record(&db, &target).await.unwrap();
        assert_eq!(
            read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap_err(),
            Failure::RecordUnavailable
        );
        assert_eq!(
            execute(
                db.clone(),
                Caller::local(),
                source.clone(),
                b"{}".to_vec(),
                fixture_resolver
            )
            .await
            .unwrap_err(),
            Failure::InvalidParams
        );
        db.close().await;
    }

    #[tokio::test]
    async fn null_empty_incarnation_and_closed_error_categories() {
        let (_directory, db, source, target) = setup().await;
        let null = read(&db, &source, json!({"record_id":target}))
            .await
            .unwrap();
        assert!(!null.body_present);
        assert!(null.complete);
        assert_eq!(null.total_bytes, 0);
        crate::store::update_record(&db, &target, json!({"body":""}))
            .await
            .unwrap();
        let empty = read(&db, &source, json!({"record_id":target}))
            .await
            .unwrap();
        assert!(empty.body_present);
        assert_eq!(empty.body_digest, null.body_digest);
        assert_ne!(empty.revision, null.revision);
        let mut source_fixture = fixture();
        source_fixture["descriptor"] = json!(false);
        crate::store::update_record(&db, &source, json!({"body":source_fixture.to_string()}))
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap_err(),
            Failure::UndeclaredRead
        );
        source_fixture["descriptor"] = json!(true);
        source_fixture["adopted"] = json!(false);
        crate::store::update_record(&db, &source, json!({"body":source_fixture.to_string()}))
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap_err(),
            Failure::AdoptionRequired
        );
        for failure in [
            Failure::InvalidParams,
            Failure::InvalidCursor,
            Failure::CursorExpired,
            Failure::ResultBudget,
            Failure::UnsupportedProfile,
            Failure::UnsupportedCapability,
            Failure::SourceIntegrity,
            Failure::UndeclaredRead,
            Failure::AdoptionRequired,
            Failure::RecordUnavailable,
            Failure::AccessLost,
            Failure::ScopeDenied,
            Failure::RevisionChanged,
            Failure::TooLarge,
            Failure::ProcessBusy,
            Failure::SourceWork,
            Failure::ProvenanceWork,
            Failure::VmWork,
            Failure::Timeout,
            Failure::Engine,
        ] {
            let (code, reason) = failure.code_reason();
            assert!(code.is_ascii() && reason.is_ascii());
            assert!(!reason.contains(&target));
        }
        db.close().await;
    }

    #[tokio::test]
    async fn holder_drop_and_unwind_hold_slots_until_cpu_and_sqlite_ack() {
        let (_directory, db, _source, _target) = setup().await;
        let slots = Arc::new(Semaphore::new(2));
        let (release_cpu, wait_cpu) = std::sync::mpsc::channel();
        let mut holder = fixture_resources(&db, &slots).await;
        holder
            .cpu
            .handles
            .push(tokio::task::spawn_blocking(move || {
                wait_cpu.recv().unwrap();
            }));
        let second = Slot(Some(slots.clone().try_acquire_owned().unwrap()));
        drop(holder);
        for _ in 0..16 {
            tokio::task::yield_now().await;
            assert!(slots.clone().try_acquire_owned().is_err());
        }
        release_cpu.send(()).unwrap();
        let available = tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(available);
        drop(second); // second intentionally withholds its slot
        assert_eq!(slots.available_permits(), 1);
        // Inner unwind borrows resources, leaving ownership outside catch.
        let mut resources = fixture_resources(&db, &slots).await;
        let unwind = std::panic::AssertUnwindSafe(async {
            panic!("qualified inner unwind");
        })
        .catch_unwind()
        .await;
        assert!(unwind.is_err());
        assert_eq!(slots.available_permits(), 0);
        resources.finish().await.unwrap();
        assert_eq!(slots.available_permits(), 1);
        db.close().await;
    }

    #[tokio::test]
    async fn source_body_and_provenance_work_caps_are_not_writer_caps() {
        let (_directory, db, source, target) = setup().await;
        let body = "x".repeat(BODY as usize);
        crate::store::update_record(&db, &target, json!({"body":body}))
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap()
                .total_bytes,
            BODY
        );
        // This ordinary writer currently runs body_blocks extraction and
        // rejects this size. Do not call that a universal storage/read cap.
        assert!(matches!(
            crate::store::update_record(&db, &target, json!({"body":"x".repeat(BODY as usize+1)}))
                .await,
            Err(crate::error::Error::Engine(_))
        ));
        // Storage fault fixture ONLY: qualify metadata-before-hydration and
        // the reader refusal without claiming a healthy projected write.
        sqlx::query("UPDATE records SET body=? WHERE id=?")
            .bind("x".repeat(BODY as usize + 1))
            .bind(&target)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            read(&db, &source, json!({"record_id":target}))
                .await
                .unwrap_err(),
            Failure::TooLarge
        );
        let mut budget = Budget::new();
        assert_eq!(budget.charge(BODY as i64, false), Ok(()));
        assert_eq!(budget.charge(1, false), Err(Failure::SourceWork));
        let mut budget = Budget::new();
        assert_eq!(budget.charge(PROVENANCE as i64, true), Ok(()));
        assert_eq!(budget.charge(1, true), Err(Failure::ProvenanceWork));
        db.close().await;
    }

    #[tokio::test]
    async fn returned_raw_cpu_caller_drop_retains_original_cleanup() {
        let (_directory, db, source, target) = setup().await;
        let slots = Arc::new(Semaphore::new(2));
        let (receiver, entered, release, cancelled) = fixture_cpu_job(&db, &slots).await;
        entered.await.unwrap();
        let waiting_caller = tokio::spawn(async move {
            let _lifetime = CancelOnDrop(cancelled);
            receiver.await
        });
        tokio::task::yield_now().await;
        waiting_caller.abort();
        assert!(waiting_caller.await.unwrap_err().is_cancelled());
        let second = Slot(Some(slots.clone().try_acquire_owned().unwrap()));
        assert_eq!(
            execute_on(
                slots.clone(),
                db.clone(),
                caller("acct_alice"),
                source.clone(),
                serde_json::to_vec(&json!({"record_id":target})).unwrap(),
                fixture_resolver
            )
            .await
            .unwrap_err(),
            Failure::ProcessBusy
        );
        for _ in 0..32 {
            tokio::task::yield_now().await;
            assert_eq!(slots.available_permits(), 0);
        }
        release.send(()).unwrap();
        let released = tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(released);
        drop(second); // this separate intentional unknown slot remains withheld
        assert_eq!(slots.available_permits(), 1);
        assert!(correction_read(&db, &source, json!({"record_id":target}))
            .await
            .is_ok());
        db.close().await;
    }

    fn acquisition_forbidden_resolver<'a, 'tx>(
        _: &'a mut ReadSnapshot<'tx>,
        _: &'a str,
    ) -> BoxFuture<'a, Result<ResolvedSource>> {
        panic!("quarantined or failed acquisition entered resolver")
    }

    #[tokio::test]
    async fn owned_temp_quarantine_keeps_meter_and_closes_without_sql_repair() {
        let (_directory, db, source, target) = setup().await;
        let slots = Arc::new(Semaphore::new(1));
        let mut resources = fixture_resources(&db, &slots).await;
        // Inject only on this genuinely returned, registered raw connection.
        sqlx::query("CREATE TEMP TABLE stale_viewer_secret(value TEXT)")
            .execute(resources.connection.as_mut().unwrap())
            .await
            .unwrap();
        let budget = Budget::new();
        let steps = budget.steps.clone();
        let cancel = budget.cancelled.clone();
        assert_eq!(
            inner(
                &db,
                &caller("acct_alice"),
                &SourceLocator::Qualification {
                    locator: source.clone(),
                    resolver: acquisition_forbidden_resolver
                },
                Request::parse(&serde_json::to_vec(&json!({"record_id":target})).unwrap()).unwrap(),
                budget,
                &cancel,
                &mut resources
            )
            .await
            .unwrap_err(),
            Failure::Engine
        );
        assert_eq!(
            steps.load(Ordering::SeqCst),
            1000,
            "owned sentinel reserves original VM tail"
        );
        assert_eq!(slots.available_permits(), 0);
        // Fixture-only observations, not executor repair SQL or new cleanup grace.
        let connection = resources.connection.as_mut().unwrap();
        let still_present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE name='stale_viewer_secret')",
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert!(still_present);
        assert_eq!(query_only, 0, "quarantine precedes subsequent setup");
        // Seed the remaining test budget and cross it with actual SQLite VM work:
        // the original installed handler remains active after quarantine.
        steps.store(VM - 1000, Ordering::SeqCst);
        assert!(matches!(sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT sum(x) FROM n")
            .execute(&mut *connection).await, Err(sqlx::Error::Database(_))));
        assert!(steps.load(Ordering::SeqCst) >= VM);
        let before_close = steps.load(Ordering::SeqCst);
        resources.finish().await.unwrap(); // actual driver shutdown ACK
        assert_eq!(
            steps.load(Ordering::SeqCst),
            before_close,
            "no close optimization/repair VM work"
        );
        assert_eq!(slots.available_permits(), 1);
        let fresh = correction_read(&db, &source, json!({"record_id":target}))
            .await
            .unwrap();
        assert!(!fresh.body_present);
        db.close().await;
    }

    #[tokio::test]
    async fn owned_physical_and_driver_transaction_quarantine_precedes_sql() {
        let (_directory, db, source, target) = setup().await;
        for driver_only in [false, true] {
            let slots = Arc::new(Semaphore::new(1));
            let mut resources = fixture_resources(&db, &slots).await;
            let connection = resources.connection.as_mut().unwrap();
            if driver_only {
                // Public TransactionManager API creates genuine driver bookkeeping;
                // raw rollback deliberately leaves depth inconsistent with SQLite.
                <Sqlite as sqlx::Database>::TransactionManager::begin(&mut *connection, None)
                    .await
                    .unwrap();
                sqlx::query("ROLLBACK")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            } else {
                sqlx::query("BEGIN")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            assert_eq!(connection.is_in_transaction(), driver_only);
            let physical = {
                let mut handle = connection.lock_handle().await.unwrap();
                unsafe {
                    libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) == 0
                }
            };
            assert_eq!(physical, !driver_only);
            let budget = Budget::new();
            let steps = budget.steps.clone();
            let cancel = budget.cancelled.clone();
            assert_eq!(
                inner(
                    &db,
                    &caller("acct_alice"),
                    &SourceLocator::Qualification {
                        locator: source.clone(),
                        resolver: acquisition_forbidden_resolver
                    },
                    Request::parse(&serde_json::to_vec(&json!({"record_id":target})).unwrap())
                        .unwrap(),
                    budget,
                    &cancel,
                    &mut resources
                )
                .await
                .unwrap_err(),
                Failure::Engine
            );
            assert_eq!(
                steps.load(Ordering::SeqCst),
                0,
                "quarantine before first owned SQL"
            );
            assert_eq!(slots.available_permits(), 0);
            // State remains unrepaired until physical shutdown, without new SQL grace.
            assert_eq!(
                resources.connection.as_ref().unwrap().is_in_transaction(),
                driver_only
            );
            resources.finish().await.unwrap();
            assert_eq!(steps.load(Ordering::SeqCst), 0);
            assert_eq!(slots.available_permits(), 1);
        }
        assert!(correction_read(&db, &source, json!({"record_id":target}))
            .await
            .is_ok());
        db.close().await;
    }

    #[tokio::test]
    async fn real_fresh_sqlite_open_failure_withholds_slot_and_replacements_read_pages() {
        let (directory, db, source, target) = setup().await;
        crate::store::update_record(&db, &target, json!({"body":"abcdefgh"}))
            .await
            .unwrap();
        assert_eq!(
            db.body_connection_options().get_filename(),
            db.governed_pool().connect_options().get_filename()
        );
        // Drain all ordinary governed connections with actual acknowledged close.
        let mut held = Vec::new();
        for _ in 0..db.governed_pool().options().get_max_connections() {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        for connection in held {
            connection.close().await.unwrap();
        }
        assert_eq!(db.governed_pool().size(), 0);
        let path = directory.path().join("reader.db");
        assert_eq!(db.body_connection_options().get_filename(), path);
        let retained = directory.path().join("reader.retained");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::create_dir(&path).unwrap();
        // Genuine selected raw SQLite fresh-connect fault, NOT a synthetic future.
        match db.body_connection_options().connect().await {
            Err(sqlx::Error::Database(error)) => assert_eq!(error.code().as_deref(), Some("14")),
            other => panic!("expected SQLite CANTOPEN, got {other:?}"),
        }
        let slots = Arc::new(Semaphore::new(2));
        assert_eq!(
            execute_on(
                slots.clone(),
                db.clone(),
                caller("acct_alice"),
                source.clone(),
                serde_json::to_vec(&json!({"record_id":target})).unwrap(),
                acquisition_forbidden_resolver
            )
            .await
            .unwrap_err(),
            Failure::Engine
        );
        assert_eq!(
            slots.available_permits(),
            1,
            "terminal acquisition is not a close ACK"
        );
        assert_eq!(db.governed_pool().size(), 0);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&retained, &path).unwrap();
        let mut request = json!({"record_id":target,"page_bytes":4});
        let mut assembled = String::new();
        let mut revision = None;
        loop {
            let page = execute_on(
                slots.clone(),
                db.clone(),
                caller("acct_alice"),
                source.clone(),
                serde_json::to_vec(&request).unwrap(),
                fixture_resolver,
            )
            .await
            .unwrap();
            if let Some(prior) = &revision {
                assert_eq!(prior, &page.revision);
            } else {
                revision = Some(page.revision.clone());
            }
            assembled.push_str(&page.text);
            assert_eq!(
                slots.available_permits(),
                1,
                "only successful physical close releases its slot"
            );
            if page.complete {
                break;
            }
            request = next(&page);
        }
        assert_eq!(assembled, "abcdefgh");
        db.close().await;
    }

    #[tokio::test]
    async fn original_deadline_retains_returned_raw_cpu_until_real_close() {
        let (_directory, db, source, target) = setup().await;
        let slots = Arc::new(Semaphore::new(1));
        let started = Instant::now();
        let (receiver, entered, release, cancelled) = fixture_cpu_job(&db, &slots).await;
        entered.await.unwrap();
        let _lifetime = CancelOnDrop(cancelled);
        assert!(
            tokio::time::timeout_at((started + TIMEOUT).into(), receiver)
                .await
                .is_err()
        );
        assert!(started.elapsed() >= TIMEOUT);
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(
            execute_on(
                slots.clone(),
                db.clone(),
                caller("acct_alice"),
                source.clone(),
                serde_json::to_vec(&json!({"record_id":target})).unwrap(),
                acquisition_forbidden_resolver
            )
            .await
            .unwrap_err(),
            Failure::ProcessBusy
        );
        release.send(()).unwrap();
        let acknowledged =
            tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned())
                .await
                .unwrap()
                .unwrap();
        drop(acknowledged);
        assert_eq!(slots.available_permits(), 1);
        assert!(correction_read(&db, &source, json!({"record_id":target}))
            .await
            .is_ok());
        db.close().await;
    }

    // Synthetic terminal startup only: retained object/drop observations do not
    // establish SQLx's internal discard or physical shutdown acknowledgement.
    struct ControlledStartup {
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        release: tokio::sync::oneshot::Receiver<()>,
        panic: bool,
        polls: Arc<std::sync::atomic::AtomicUsize>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl std::future::Future for ControlledStartup {
        type Output = std::result::Result<SqliteConnection, sqlx::Error>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(entered) = this.entered.take() {
                entered.send(()).unwrap();
            }
            match std::future::Future::poll(std::pin::Pin::new(&mut this.release), cx) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(result) => {
                    result.unwrap();
                    if this.panic {
                        panic!("qualification startup unwind");
                    }
                    std::task::Poll::Ready(Err(sqlx::Error::PoolClosed))
                }
            }
        }
    }
    impl Drop for ControlledStartup {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct DrainWake(std::sync::atomic::AtomicUsize);
    impl futures::task::ArcWake for DrainWake {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct StartupObservation {
        entered: tokio::sync::oneshot::Receiver<()>,
        release: tokio::sync::oneshot::Sender<()>,
        polls: Arc<std::sync::atomic::AtomicUsize>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }
    fn controlled_startup(
        panic: bool,
    ) -> (
        BoxFuture<'static, std::result::Result<SqliteConnection, sqlx::Error>>,
        StartupObservation,
    ) {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, waiting) = tokio::sync::oneshot::channel();
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            ControlledStartup {
                entered: Some(entered),
                release: waiting,
                panic,
                polls: polls.clone(),
                drops: drops.clone(),
            }
            .boxed(),
            StartupObservation {
                entered: observed,
                release,
                polls,
                drops,
            },
        )
    }
    fn startup_address(resources: &Resources) -> usize {
        resources.acquiring.as_ref().unwrap().as_ref().get_ref() as *const _ as *const () as usize
    }
    fn assert_retained_no_handle(resources: &Resources, db: &Db, original: usize) {
        assert!(resources.startup_polled);
        assert!(resources.startup_terminal);
        assert!(resources.unknown);
        assert!(!resources.physical_finished);
        assert!(resources.ticket.is_none());
        assert!(resources.connection.is_none());
        assert!(resources.closing.is_none());
        assert_eq!(startup_address(resources), original);
        assert_eq!(resources.db.as_ref().unwrap().handle_id(), db.handle_id());
        assert!(resources.pending.is_some());
        assert!(resources.admitted.is_none()); // No setup or admission was reached.
        assert!(resources.deployment.is_none()); // This fixture has no deployment.
        assert!(resources.budget.is_some());
        assert!(resources.cpu.handles.is_empty()); // Startup precedes registered CPU.
        assert!(resources.slot.0.is_some());
    }

    #[tokio::test]
    async fn finalizer_fault_and_panic_withhold_capacity() {
        for panic in [false, true] {
            let (_directory, db, _source, _target) = setup().await;
            let slots = Arc::new(Semaphore::new(1));
            let mut resources = fixture_unstarted_resources(&db, &slots).await;
            let gate = db.owned_portability_policy_gate();
            let (startup, observed) = controlled_startup(panic);
            resources.acquiring = Some(startup);
            let original = startup_address(&resources);
            observed.release.send(()).unwrap();
            assert_eq!(resources.start().await, Err(Failure::Engine));
            observed.entered.await.unwrap();
            assert_retained_no_handle(&resources, &db, original);
            let polls = observed.polls.load(Ordering::SeqCst);
            assert_eq!(polls, 1);
            assert_eq!(resources.start().await, Err(Failure::Engine));
            assert_eq!(resources.finish().await, Err(Failure::Engine));
            assert_eq!(observed.polls.load(Ordering::SeqCst), polls);
            assert_retained_no_handle(&resources, &db, original);
            assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
            assert!(gate.try_write().is_err());
            let witness = db.fence_body_retirement();
            assert!(!witness.body_complete());
            assert!(
                !tokio::time::timeout(Duration::from_secs(2), witness.drain())
                    .await
                    .unwrap()
            );
            drop(resources);
            for _ in 0..32 {
                tokio::task::yield_now().await;
                assert_eq!(slots.available_permits(), 0);
                assert!(gate.try_write().is_err());
                assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
            }
            assert!(!tokio::time::timeout(
                Duration::from_secs(2),
                db.fence_body_retirement().drain()
            )
            .await
            .unwrap());
            assert!(!witness.body_complete());
            assert_eq!(observed.polls.load(Ordering::SeqCst), polls);
        }
    }

    #[tokio::test]
    async fn terminal_no_handle_notifies_existing_drain_and_retains_original_custody() {
        for panic in [false, true] {
            let (_directory, db, _source, _target) = setup().await;
            let slots = Arc::new(Semaphore::new(1));
            let mut resources = fixture_unstarted_resources(&db, &slots).await;
            let gate = db.owned_portability_policy_gate();
            let deadline = resources.budget.as_ref().unwrap().deadline;
            let cancelled = resources.budget.as_ref().unwrap().cancelled.clone();
            let steps = resources.budget.as_ref().unwrap().steps.clone();
            let (startup, observed) = controlled_startup(panic);
            resources.acquiring = Some(startup);
            let original = startup_address(&resources);
            let witness = {
                let started = resources.start();
                tokio::pin!(started);
                assert!(futures::poll!(&mut started).is_pending());
                observed.entered.await.unwrap(); // Actual first poll/physical_started.
                assert!(gate.try_write().is_err());
                assert_eq!(slots.available_permits(), 0);
                let witness = db.fence_body_retirement();
                let draining = witness.drain();
                tokio::pin!(draining);
                let wake = Arc::new(DrainWake(std::sync::atomic::AtomicUsize::new(0)));
                let waker = futures::task::waker_ref(&wake);
                let mut context = std::task::Context::from_waker(&waker);
                assert!(std::future::Future::poll(draining.as_mut(), &mut context).is_pending());
                assert_eq!(wake.0.load(Ordering::SeqCst), 0);
                observed.release.send(()).unwrap();
                assert_eq!(started.await, Err(Failure::Engine));
                assert!(wake.0.load(Ordering::SeqCst) > 0);
                // Poll the SAME already-enabled waiter; only ticket Drop notifies it.
                assert!(!tokio::time::timeout(Duration::from_secs(2), &mut draining)
                    .await
                    .unwrap());
                witness.clone()
            };
            assert!(!witness.body_complete());
            assert_retained_no_handle(&resources, &db, original);
            let polls = observed.polls.load(Ordering::SeqCst);
            assert_eq!(resources.start().await, Err(Failure::Engine));
            assert_eq!(resources.finish().await, Err(Failure::Engine));
            assert_eq!(observed.polls.load(Ordering::SeqCst), polls);

            // Normal retained outer-holder path, with a Weak observation only.
            // A refused finish is NOT close ACK and must leave the registry entry.
            let registry = resources.registry.clone();
            let job = registry.retain(resources);
            let holder = job.resources();
            let retained = Arc::downgrade(&holder);
            let (finished, completion) = tokio::sync::oneshot::channel();
            registry.start(
                job,
                async move {
                    let result = holder.lock().await.finish().await;
                    let terminal = result.is_ok();
                    let _ = finished.send(result);
                    terminal
                }
                .boxed(),
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), completion)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(Failure::Engine)
            );
            {
                let holder = retained
                    .upgrade()
                    .expect("registry retains unresolved custody");
                let mut resources = holder.lock().await;
                assert_retained_no_handle(&resources, &db, original);
                let budget = resources.budget.as_ref().unwrap();
                assert_eq!(budget.deadline, deadline);
                assert!(Arc::ptr_eq(&budget.cancelled, &cancelled));
                assert!(Arc::ptr_eq(&budget.steps, &steps));
                assert_eq!(resources.start().await, Err(Failure::Engine));
                assert_eq!(resources.finish().await, Err(Failure::Engine));
            }
            assert_eq!(observed.polls.load(Ordering::SeqCst), polls);
            assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
            assert_eq!(slots.available_permits(), 0);
            assert!(gate.try_write().is_err());
            assert!(
                !tokio::time::timeout(Duration::from_secs(2), witness.drain())
                    .await
                    .unwrap()
            );
            assert!(!witness.body_complete());
            // Caller registry-owner loss also cannot discharge an unknown job.
            drop(registry);
            for _ in 0..32 {
                tokio::task::yield_now().await;
                assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
                assert_eq!(slots.available_permits(), 0);
                assert!(gate.try_write().is_err());
                assert!(retained.upgrade().is_some());
            }
        }
    }

    #[tokio::test]
    async fn queued_sqlite_worker_blocks_close_ack_and_third_job() {
        let (_directory, db, _source, _target) = setup().await;
        let slots = Arc::new(Semaphore::new(2));
        let mut resources = fixture_resources(&db, &slots).await;
        let connection = resources.connection.as_mut().unwrap();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, waiting) = std::sync::mpsc::channel();
        let mut entered = Some(entered);
        {
            let mut handle = connection.lock_handle().await.unwrap();
            handle.set_progress_handler(1, move || {
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                    waiting.recv().unwrap();
                }
                true
            });
        }
        {
            let pending = sqlx::query("SELECT 1").execute(&mut *connection);
            tokio::pin!(pending);
            tokio::select! { result = &mut pending => panic!("barrier SQL unexpectedly ended {result:?}"), result = observed => result.unwrap() }
            // Drop the SQL awaiter while the physical worker is in its callback.
        }
        let second = Slot(Some(slots.clone().try_acquire_owned().unwrap()));
        drop(resources);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            slots.available_permits(),
            0,
            "diagnostic grace cannot release physical ownership"
        );
        release.send(()).unwrap();
        let acknowledged =
            tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned())
                .await
                .unwrap()
                .unwrap();
        drop(acknowledged);
        drop(second);
        db.close().await;
    }

    #[tokio::test]
    async fn bounded_comment_parity_and_typed_budget_exhaustion() {
        let (_directory, db, _source, target) = setup().await;
        sqlx::query("UPDATE records SET type='Annotation',kind='comment' WHERE id=?")
            .bind(&target)
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO links(id,source_id,target_id,relationship) VALUES(?,?,?,'part_of')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&target)
        .bind(crate::schema::ROOT_RECORD_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        for (body, lifecycle, summary) in [
            ("visible", None, None),
            ("\u{2003}", None, None),
            ("reply", Some("open"), None),
            ("resolved", Some("resolved"), Some("done")),
            ("broken", Some("resolved"), None),
        ] {
            sqlx::query("UPDATE records SET body=?,lifecycle=?,summary=? WHERE id=?")
                .bind(body)
                .bind(lifecycle)
                .bind(summary)
                .bind(&target)
                .execute(db.write_pool())
                .await
                .unwrap();
            let mut connection = db.governed_pool().acquire().await.unwrap();
            connection.close_on_drop();
            {
                let transaction = connection.begin().await.unwrap();
                let mut budget = Budget::new();
                let mut snapshot = ReadSnapshot {
                    transaction,
                    budget: &mut budget,
                    viewer: "acct_alice".into(),
                    member: true,
                };
                let ordinary = crate::query::read::ordinary_record_read_eligible_live_in(
                    &mut snapshot.transaction,
                    &target,
                )
                .await
                .unwrap();
                assert_eq!(snapshot.eligible(&target).await.unwrap(), ordinary);
                snapshot.budget.steps.store(VM, Ordering::SeqCst);
                assert_eq!(
                    snapshot.eligible(&target).await.unwrap_err(),
                    Failure::VmWork
                );
                snapshot.transaction.rollback().await.unwrap();
            }
            connection.close().await.unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn owned_identity_metadata_overflow_and_clone_cache() {
        let (_directory, db, _source, target) = setup().await;
        let mut connection = db.governed_pool().acquire().await.unwrap();
        connection.close_on_drop();
        let mut transaction = connection.begin().await.unwrap();
        let identity = crate::identity::database_id_on(&db, &mut transaction)
            .await
            .unwrap();
        assert!(crate::identity::is_database_id(&identity));
        assert_eq!(
            crate::identity::database_id_on(&db.clone(), &mut transaction)
                .await
                .unwrap(),
            identity
        );
        transaction.rollback().await.unwrap();
        crate::store::update_record(&db, &target, json!({"body":"x".repeat(2*1024*1024)}))
            .await
            .unwrap();
        {
            let mut raw = connection.lock_handle().await.unwrap();
            unsafe {
                libsqlite3_sys::sqlite3_limit(
                    raw.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                    1024,
                );
            }
        }
        let bytes: i64 = sqlx::query_scalar("SELECT octet_length(body) FROM records WHERE id=?")
            .bind(&target)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert_eq!(bytes, 2 * 1024 * 1024);
        let explanation = sqlx::query("EXPLAIN SELECT octet_length(body) FROM records WHERE id=?")
            .bind(&target)
            .fetch_all(&mut *connection)
            .await
            .unwrap();
        assert!(explanation
            .iter()
            .any(|r| r.get::<String, _>("opcode") == "Column" && r.get::<i64, _>("p5") & 64 != 0));
        assert!(
            sqlx::query_scalar::<_, String>("SELECT body FROM records WHERE id=?")
                .bind(&target)
                .fetch_one(&mut *connection)
                .await
                .is_err()
        );
        connection.close().await.unwrap();
        db.close().await;
    }
}

// Per-owned-job qualification only: never compiled into the Hosted dependency.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ProbePhase {
    RawCpu,
    Html,
    BeforeAck,
}
#[cfg(test)]
pub(super) struct BrokerProbe {
    pub(super) phase: ProbePhase,
    pub(super) entered: Semaphore,
    pub(super) release: tokio::sync::Notify,
    pub(super) html_wait: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    pub(super) acknowledged: AtomicBool,
    pub(super) reserved: AtomicBool,
    pub(super) cleaned: AtomicBool,
}
const MIXED_REPLY_BYTES: usize = 16384;
struct MixedReplyWriter<'a> {
    bytes: &'a mut Vec<u8>,
    budget: &'a Budget,
}
impl std::io::Write for MixedReplyWriter<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.budget
            .stop()
            .map_err(|_| std::io::Error::other("mixed reply stopped"))?;
        if input.len() > MIXED_REPLY_BYTES.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("mixed reply bound"));
        }
        // Pre-reserved capacity; this append cannot allocate beyond the cap.
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[derive(serde::Serialize)]
struct MixedLaunch<'a> {
    url: &'a str,
    expires_in_ms: u128,
    bridge_version: &'static str,
}
#[derive(serde::Serialize)]
struct MixedMountReply<'a> {
    contract: &'static str,
    mount_token: &'a str,
    launch: MixedLaunch<'a>,
    source_binding: &'a alpha_install::MixedSourceBinding,
}
struct BrokerContext {
    owner: &'static super::hosted::Process,
    delivery: crate::artifact_html::LaunchDelivery,
    cookie: String,
    origin: String,
    started: Instant,
    opened: Option<super::hosted::OpenedMount>,
    token: String,
    reservation: Option<crate::artifact_html::BodyReservation>,
    refusal: Option<super::hosted::HostRefusal>,
    retire: bool,
    mixed: bool,
    mixed_binding: Option<alpha_install::MixedSourceBinding>,
    mixed_reply: Option<Vec<u8>>,
    #[cfg(test)]
    probe: Option<Arc<BrokerProbe>>,
}
impl BrokerContext {
    fn fail(&mut self, error: crate::artifact_html::BodyDeliveryFailure) -> Failure {
        self.refusal = Some(super::hosted::delivery_error(error));
        Failure::Engine
    }
}
fn closed_body_failure(failure: Failure) -> super::hosted::Reply {
    let (code, reason) = failure.code_reason();
    let bytes=serde_json::to_vec(&serde_json::json!({"contract":"records.body.read.v1","error":{"code":code,"reason":reason}})).expect("fixed refusal object");
    super::hosted::Reply::Body(super::hosted::CanonicalBytes(bytes.into_boxed_slice()))
}
pub(super) async fn execute_hosted(work: super::hosted::Work) -> super::hosted::Reply {
    use super::hosted::{CanonicalBytes, HostRefusal, OwnedRequest, Reply};
    let budget = match Budget::from_ingress(work.started) {
        Ok(b) => b,
        Err(e) => return closed_body_failure(e),
    };
    if let Err(e) = budget.stop() {
        return closed_body_failure(e);
    }
    let request = match &work.request {
        OwnedRequest::Page(_, raw) => match Request::parse(raw) {
            Ok(r) => Some(r),
            Err(e) => return closed_body_failure(e.into()),
        },
        _ => None,
    };
    // Reject malformed/unredeemed transport correlation before assigning any
    // physical job. These bounded checks grant no current SQL source authority.
    let opened = match &work.request {
        OwnedRequest::Issue(_) | OwnedRequest::IssueMixed(_) => None,
        OwnedRequest::Page(token, _) | OwnedRequest::Retire(token) => {
            let mount =
                match work
                    .owner
                    .open(token, work.caller.credential(), &work.cookie, &work.origin)
                {
                    Ok(m) => m,
                    Err(e) => return Reply::HostRefused(e),
                };
            if matches!(work.request, OwnedRequest::Page(_, _)) {
                let meta = match mount.metadata(work.owner, token) {
                    Ok(m) => m,
                    Err(e) => return Reply::HostRefused(e),
                };
                match work.delivery.body_mount_is_redeemed(&meta) {
                    Ok(true) => (),
                    Ok(false) => return Reply::HostRefused(HostRefusal::MountUnavailable),
                    Err(e) => return Reply::HostRefused(super::hosted::delivery_error(e)),
                }
            }
            Some(mount)
        }
    };
    if let Err(e) = budget.stop() {
        return closed_body_failure(e);
    }
    let availability = work.db.body_host_availability();
    if let Err(e) = budget.stop() {
        return closed_body_failure(e);
    }
    match availability {
        Ok(crate::db::BodyHostAvailability::AvailableUnmanaged) => (),
        Ok(crate::db::BodyHostAvailability::KnownUnavailable) => {
            return Reply::HostRefused(HostRefusal::MountUnavailable)
        }
        Err(_) => return closed_body_failure(Failure::Engine),
    }
    let pending = match crate::storage_profile::PendingBodyPolicy::acquire(&work.db, work.started)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            return closed_body_failure(budget.stop().err().unwrap_or_else(|| policy_failure(e)))
        }
    };
    if let Err(e) = budget.stop() {
        return closed_body_failure(e);
    }
    let permit = match work.owner.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return closed_body_failure(Failure::ProcessBusy),
    };
    let deadline = budget.deadline;
    let cancel = budget.cancelled.clone();
    let _cancel_on_drop = CancelOnDrop(cancel.clone());
    let registry = work.owner.jobs.clone();
    let resources = match Resources::new(
        &work.db,
        permit,
        budget,
        pending,
        Some(work.admission),
        registry.clone(),
    ) {
        Ok(r) => r,
        Err(e) => return closed_body_failure(e),
    };
    let job = registry.retain(resources);
    let holder = job.resources();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    registry.start(job, async move {
        let mut resources = holder.lock().await;
        let mut context = BrokerContext {
            owner: work.owner,
            delivery: work.delivery,
            cookie: work.cookie,
            origin: work.origin,
            started: work.started,
            opened,
            token: String::new(),
            reservation: None,
            refusal: None,
            retire: matches!(work.request, OwnedRequest::Retire(_)),
            mixed: matches!(work.request, OwnedRequest::IssueMixed(_)),
            mixed_binding: None,
            mixed_reply: None,
            #[cfg(test)]
            probe: work.probe,
        };
        let operation = std::panic::AssertUnwindSafe(async {
            let package = match work.request {
                OwnedRequest::Issue(package) | OwnedRequest::IssueMixed(package) => package,
                OwnedRequest::Page(token, _) | OwnedRequest::Retire(token) => {
                    let package = context
                        .opened
                        .as_ref()
                        .ok_or(Failure::Engine)?
                        .package
                        .clone();
                    context.token = token;
                    package
                }
            };
            resources.budget.as_ref().ok_or(Failure::Engine)?.stop()?;
            resources.start().await?;
            #[cfg(test)]
            if let Some(p) = context.probe.as_ref().filter(|p| p.phase == ProbePhase::RawCpu).cloned() {
                // Raw connection has RETURNED and is retained. This is an
                // actual registered CPU/setup barrier, NOT SQLx startup proof.
                let Resources { cpu, budget, .. } = &mut *resources;
                let budget = budget.as_ref().ok_or(Failure::Engine)?;
                alpha_install::cpu(cpu, budget, move || {
                    let wait = p.html_wait.lock().unwrap().take().unwrap();
                    p.entered.add_permits(1);
                    wait.recv().unwrap();
                    Ok(CpuOutput::Phase)
                }).await?;
            }
            resources.budget.as_ref().ok_or(Failure::Engine)?.stop()?;
            let locator = SourceLocator::AlphaInstall {
                package,
                #[cfg(test)]
                after_source: None,
            };
            tokio::time::timeout_at(
                deadline.into(),
                inner_job(
                    &work.db,
                    &work.caller,
                    &locator,
                    request,
                    &cancel,
                    &mut resources,
                    Some(&mut context),
                ),
            )
            .await
            .map_err(|_| Failure::Timeout)?
        })
        .catch_unwind()
        .await;
        let result = operation.unwrap_or(Err(Failure::Engine));
        #[cfg(test)]
        if matches!(&result, Ok(JobOutput::Issued)) {
            if let Some(p) = context
                .probe
                .as_ref()
                .filter(|p| p.phase == ProbePhase::BeforeAck)
            {
                p.entered.add_permits(1);
                p.release.notified().await;
            }
        }
        let finalization = std::panic::AssertUnwindSafe(resources.finish_physical())
            .catch_unwind()
            .await;
        let ack = match finalization {
            Ok(Ok(ack)) => {
                #[cfg(test)]
                if let Some(p) = &context.probe {
                    p.acknowledged.store(true, Ordering::SeqCst);
                }
                Some(ack)
            }
            _ => None, // registry keeps Db/admissions/ticket/slot/physical work
        };
        let reply = (|| {
            if ack.is_none() {
                return Reply::HostRefused(HostRefusal::Engine);
            }
            if !super::hosted::still_live(&cancel, deadline) {
                return Reply::HostRefused(HostRefusal::Deadline);
            }
            match result {
                Err(e) => {
                    if let Some(cause) = context.refusal {
                        Reply::HostRefused(cause)
                    } else {
                        closed_body_failure(e)
                    }
                }
                Ok(JobOutput::Canonical(bytes)) => {
                    let Some(opened) = &context.opened else {
                        return Reply::HostRefused(HostRefusal::Engine);
                    };
                    let meta = match opened.metadata(context.owner, &context.token) {
                        Ok(m) => m,
                        Err(e) => return Reply::HostRefused(e),
                    };
                    match context.delivery.body_mount_is_redeemed(&meta) {
                        Ok(true) if super::hosted::still_live(&cancel, deadline) => {
                            Reply::Body(bytes)
                        }
                        Err(e) => Reply::HostRefused(super::hosted::delivery_error(e)),
                        _ => Reply::HostRefused(HostRefusal::MountUnavailable),
                    }
                }
                Ok(JobOutput::Issued) => {
                    let Some(reservation) = context.reservation.as_ref() else {
                        return Reply::HostRefused(HostRefusal::Engine);
                    };
                    let descriptor = reservation.descriptor();
                    let remaining = match descriptor
                        .ticket_deadline()
                        .checked_duration_since(Instant::now())
                    {
                        Some(n) => n.as_millis(),
                        None => return Reply::HostRefused(HostRefusal::Deadline),
                    };
                    let bytes = if context.mixed {
                        let (Some(binding), Some(mut bytes), Some(budget)) = (
                            context.mixed_binding.as_ref(), context.mixed_reply.take(), resources.budget.as_ref()
                        ) else { return Reply::HostRefused(HostRefusal::Engine); };
                        if remaining == 0 || remaining > 30000 {
                            return Reply::HostRefused(HostRefusal::Deadline);
                        }
                        let reply = MixedMountReply {
                            contract: "records.body.mount.mixed.v1", mount_token: &context.token,
                            launch: MixedLaunch { url: descriptor.url(), expires_in_ms: remaining,
                                bridge_version: crate::artifact_html::BRIDGE_VERSION },
                            source_binding: binding,
                        };
                        let serialized = serde_json::to_writer(
                            MixedReplyWriter { bytes: &mut bytes, budget }, &reply);
                        // Original ingress clock/cancellation has precedence,
                        // including expiry during synchronous serialization.
                        if !super::hosted::still_live(&cancel, deadline) {
                            return Reply::HostRefused(HostRefusal::Deadline);
                        }
                        if serialized.is_err() || budget.stop().is_err() {
                            return Reply::HostRefused(HostRefusal::Engine);
                        }
                        bytes
                    } else {
                    let bytes = match serde_json::to_vec(
                        &serde_json::json!({"contract":"records.body.mount.v1","mount_token":context.token,"launch":{"url":descriptor.url(),"expires_in_ms":remaining,"bridge_version":crate::artifact_html::BRIDGE_VERSION}}),
                    ) {
                        Ok(b) if b.len() <= 16384 => b,
                        _ => return Reply::HostRefused(HostRefusal::Engine),
                    };
                        bytes
                    };
                    let Some(reservation) = context.reservation.take() else {
                        return Reply::HostRefused(HostRefusal::Engine);
                    };
                    let bytes = CanonicalBytes(bytes.into_boxed_slice());
                    match reservation.publish(&cancel, deadline) {
                        Ok(()) => Reply::Issued(bytes),
                        Err(e) => Reply::HostRefused(super::hosted::delivery_error(e)),
                    }
                }
                Ok(JobOutput::Retired) => {
                    let Some(opened) = &context.opened else {
                        return Reply::HostRefused(HostRefusal::Engine);
                    };
                    let meta = match opened.metadata(context.owner, &context.token) {
                        Ok(m) => m,
                        Err(e) => return Reply::HostRefused(e),
                    };
                    match context
                        .delivery
                        .retire_body_mount_checked(&meta, &cancel, deadline)
                    {
                        Ok(()) => Reply::Retired,
                        Err(e) => Reply::HostRefused(super::hosted::delivery_error(e)),
                    }
                }
                #[cfg(test)]
                Ok(JobOutput::Page(_)) => Reply::HostRefused(HostRefusal::Engine),
            }
        })();
        // Cleanup only this new reservation before returning its physical slot.
        let fresh_reservation = context.reservation.take();
        #[cfg(test)]
        let cleaning = fresh_reservation.is_some();
        drop(fresh_reservation);
        #[cfg(test)]
        if cleaning {
            if let Some(p) = &context.probe {
                p.cleaned.store(true, Ordering::SeqCst);
            }
        }
        let terminal = if let Some(ack) = ack {
            resources.release_terminal(ack);
            true
        } else { false };
        // No await after publication; lost receiver leaves only new TTL state.
        if !cancel.load(Ordering::SeqCst) && Instant::now() < deadline {
            let _ = sender.send(reply);
        }
        terminal
    }.boxed());
    match tokio::time::timeout_at(deadline.into(), receiver).await {
        Ok(Ok(reply)) if Instant::now() < deadline => reply,
        Ok(Err(_)) => Reply::HostRefused(HostRefusal::Engine),
        _ => Reply::HostRefused(HostRefusal::Deadline),
    }
}

#[cfg(test)]
async fn fixture_unstarted_resources(db: &Db, slots: &Arc<Semaphore>) -> Resources {
    let started = Instant::now();
    let budget = Budget::from_ingress(started).unwrap();
    let pending = crate::storage_profile::PendingBodyPolicy::acquire(db, started)
        .await
        .unwrap();
    Resources::new(
        db,
        slots.clone().try_acquire_owned().unwrap(),
        budget,
        pending,
        None,
        Arc::new(owned_jobs::Registry::default()),
    )
    .unwrap()
}
#[cfg(test)]
async fn fixture_resources(db: &Db, slots: &Arc<Semaphore>) -> Resources {
    let mut resources = fixture_unstarted_resources(db, slots).await;
    resources.start().await.unwrap();
    resources
}

#[cfg(test)]
async fn fixture_cpu_job(
    db: &Db,
    slots: &Arc<Semaphore>,
) -> (
    tokio::sync::oneshot::Receiver<Result<()>>,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    Arc<AtomicBool>,
) {
    let resources = fixture_unstarted_resources(db, slots).await;
    let cancelled = resources.budget.as_ref().unwrap().cancelled.clone();
    let deadline = resources.budget.as_ref().unwrap().deadline;
    let registry = resources.registry.clone();
    let job = registry.retain(resources);
    let holder = job.resources();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    registry.start(
        job,
        async move {
            let mut resources = holder.lock().await;
            let result = async {
                resources.start().await?;
                // Actual registered CPU, strictly AFTER returned raw startup.
                let Resources { cpu, budget, .. } = &mut *resources;
                let output = alpha_install::cpu(cpu, budget.as_ref().unwrap(), move || {
                    let _ = entered.send(());
                    wait.recv().unwrap();
                    Ok(CpuOutput::Phase)
                });
                tokio::time::timeout_at(deadline.into(), output)
                    .await
                    .map_err(|_| Failure::Timeout)??;
                Ok(())
            }
            .await;
            let terminal = resources.finish().await.is_ok();
            let _ = sender.send(result);
            terminal
        }
        .boxed(),
    );
    (receiver, observed, release, cancelled)
}

#[cfg(test)]
mod broker_tests {
    use super::*;
    #[tokio::test]
    async fn acknowledged_shutdown_keeps_slot_through_terminal_publication_phase() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(directory.path().join("broker-ack.db").to_str().unwrap())
            .await
            .unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let mut resources = fixture_resources(&db, &slots).await;
        let ack = resources.finish_physical().await.unwrap();
        assert!(resources.physical_finished);
        assert_eq!(slots.available_permits(), 0);
        assert!(slots.clone().try_acquire_owned().is_err());
        resources.release_terminal(ack);
        assert_eq!(slots.available_permits(), 1);
        db.close().await;
    }

    #[tokio::test]
    async fn unpolled_startup_disposition_releases_gate_without_driver_ack() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(root.path().join("unpolled.db").to_str().unwrap())
            .await
            .unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let mut resources = fixture_unstarted_resources(&db, &slots).await;
        resources.acquiring = Some(async { panic!("unpolled startup was submitted") }.boxed());
        let gate = db.owned_portability_policy_gate();
        assert!(gate.try_write().is_err());
        assert!(!resources.startup_polled);
        resources.finish().await.unwrap();
        assert!(
            !resources.startup_polled,
            "no-start is distinct from close ACK"
        );
        assert_eq!(slots.available_permits(), 1);
        assert!(gate.try_write().is_ok());
        assert!(db.fence_body_retirement().drain().await);
    }

    #[tokio::test]
    async fn actual_cpu_panic_closes_raw_but_keeps_unknown_gate_and_slot() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(root.path().join("cpu-panic.db").to_str().unwrap())
            .await
            .unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let mut resources = fixture_resources(&db, &slots).await;
        let Resources { cpu, budget, .. } = &mut resources;
        assert!(matches!(
            alpha_install::cpu(cpu, budget.as_ref().unwrap(), || {
                panic!("qualification actual CPU panic")
            })
            .await,
            Err(Failure::Engine)
        ));
        assert_eq!(resources.cpu.handles.len(), 1);
        assert!(resources.finish().await.is_err());
        assert!(resources.unknown);
        assert_eq!(slots.available_permits(), 0);
        assert!(db.owned_portability_policy_gate().try_write().is_err());
        let registry = resources.registry.clone();
        drop(resources);
        let observed = registry.observe_terminal();
        assert_eq!(observed.len(), 1);
        assert!(
            !tokio::time::timeout(Duration::from_secs(3), observed.wait())
                .await
                .unwrap()
        );
        assert!(!db.fence_body_retirement().drain().await);
        assert!(db.owned_portability_policy_gate().try_write().is_err());
    }

    #[tokio::test]
    async fn policy_metadata_checks_all_nine_types_and_cumulative_utf8_copies() {
        // Isolated storage-fault projection fixture, not a granted resolver.
        let mut raw = SqliteConnection::connect(":memory:").await.unwrap();
        {
            let mut budget = Budget::new();
            let transaction = raw.begin().await.unwrap();
            let mut snapshot = ReadSnapshot {
                transaction,
                budget: &mut budget,
                viewer: "acct_alice".into(),
                member: true,
            };
            assert!(policy_columns(&mut snapshot).await.unwrap().is_none());
            snapshot.transaction.rollback().await.unwrap();
        }
        sqlx::query("CREATE TABLE storage_portability_policy(singleton,policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256)")
            .execute(&mut raw).await.unwrap();
        sqlx::query("INSERT INTO storage_portability_policy VALUES(1,1,'off','sqlite-local',2,'embedded','[]','[]','[]',?)")
            .bind("0".repeat(64)).execute(&mut raw).await.unwrap();
        for field in [
            "policy_revision",
            "source_profile_revision",
            "enforcement",
            "source_profile_id",
            "source_mode",
            "targets",
            "revision_floors",
            "allow_conversions",
            "catalog_sha256",
        ] {
            // NULL remains NULL without affinity coercion in this fault table.
            let mut budget = Budget::new();
            let transaction = raw.begin().await.unwrap();
            let mut snapshot = ReadSnapshot {
                transaction,
                budget: &mut budget,
                viewer: "acct_alice".into(),
                member: true,
            };
            sqlx::query(&format!(
                "UPDATE storage_portability_policy SET {field}=NULL"
            ))
            .execute(&mut *snapshot.transaction)
            .await
            .unwrap();
            assert!(matches!(
                policy_columns(&mut snapshot).await,
                Err(Failure::Engine)
            ));
            snapshot.transaction.rollback().await.unwrap();
        }
        {
            let mut budget = Budget::new();
            budget.charge(100, true).unwrap();
            let transaction = raw.begin().await.unwrap();
            let mut snapshot = ReadSnapshot {
                transaction,
                budget: &mut budget,
                viewer: "acct_alice".into(),
                member: true,
            };
            let columns = policy_columns(&mut snapshot).await.unwrap().unwrap();
            let octets = [
                &columns.enforcement,
                &columns.source_profile_id,
                &columns.source_mode,
                &columns.targets,
                &columns.revision_floors,
                &columns.allow_conversions,
                &columns.catalog_sha256,
            ]
            .iter()
            .map(|v| v.len() as u64)
            .sum::<u64>();
            assert_eq!(snapshot.budget.provenance, 100 + 16 + 3 * octets);
            assert_eq!(snapshot.budget.source, 0);
            snapshot.transaction.rollback().await.unwrap();
        }
        sqlx::query("UPDATE storage_portability_policy SET source_mode=?")
            .bind("文".repeat((PROVENANCE / 9 + 1) as usize))
            .execute(&mut raw)
            .await
            .unwrap();
        {
            let mut budget = Budget::new();
            let transaction = raw.begin().await.unwrap();
            let mut snapshot = ReadSnapshot {
                transaction,
                budget: &mut budget,
                viewer: "acct_alice".into(),
                member: true,
            };
            assert!(matches!(
                policy_columns(&mut snapshot).await,
                Err(Failure::ProvenanceWork)
            ));
            assert_eq!(snapshot.budget.source, 0);
            assert_eq!(
                snapshot.budget.steps.load(Ordering::SeqCst),
                2000,
                "metadata refuses before the hydration statement"
            );
            snapshot.transaction.rollback().await.unwrap();
        }
        raw.close().await.unwrap();
    }

    #[test]
    fn policy_origin_mapping_preserves_existing_closed_pairs() {
        use crate::storage_profile::BodyPolicyFailure;
        assert_eq!(
            policy_failure(BodyPolicyFailure::Deadline),
            Failure::Timeout
        );
        assert_eq!(
            policy_failure(BodyPolicyFailure::HandleMismatch),
            Failure::Engine
        );
        assert_eq!(
            policy_failure(BodyPolicyFailure::State(crate::Error::engine(
                "fixed fixture"
            ))),
            Failure::Engine
        );
        assert_eq!(
            policy_failure(BodyPolicyFailure::Admission(crate::Error::engine(
                "fixed fixture"
            ))),
            Failure::UnsupportedCapability
        );
    }

    #[test]
    fn every_engine_refusal_matches_shared_client_golden() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../packages/alpha-tab-kit/fixtures/body-read-v1.json"
        ))
        .unwrap();
        let failures = [
            Failure::InvalidParams,
            Failure::InvalidCursor,
            Failure::CursorExpired,
            Failure::ResultBudget,
            Failure::UnsupportedProfile,
            Failure::UnsupportedCapability,
            Failure::SourceIntegrity,
            Failure::UndeclaredRead,
            Failure::AdoptionRequired,
            Failure::RecordUnavailable,
            Failure::AccessLost,
            Failure::ScopeDenied,
            Failure::RevisionChanged,
            Failure::TooLarge,
            Failure::ProcessBusy,
            Failure::SourceWork,
            Failure::ProvenanceWork,
            Failure::VmWork,
            Failure::Timeout,
            Failure::Engine,
        ];
        let actual: Vec<serde_json::Value> = failures
            .into_iter()
            .map(|f| match closed_body_failure(f) {
                super::super::hosted::Reply::Body(b) => {
                    serde_json::from_slice(b.as_bytes()).unwrap()
                }
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(serde_json::Value::Array(actual), expected);
    }
}
