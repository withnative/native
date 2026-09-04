//! Portable relational SQL for Native-owned statements.
//!
//! This is deliberately smaller than a storage API. It renders a reviewed SQL
//! template, binds logical values, normalizes returned cells, and gives driver
//! failures stable categories. Domain operations, tables, and physical
//! behavior do not live here.
//!
//! In particular, the following remain named backend adapters and may not be
//! smuggled into a portable statement: write-conflict/concurrency policy,
//! event-cursor allocation, recursive logical queries, search, caller-provided
//! raw SQL, physical schema and migrations, backup/restore, and topology.
//! SQLite write admission and `BEGIN IMMEDIATE` therefore remain in
//! [`crate::db::begin_write`]; [`SqliteTransaction`] only accepts an already
//! admitted transaction.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::sqlite::{SqliteArguments, SqliteQueryResult, SqliteRow};
#[cfg(feature = "postgres")]
use sqlx::{
    postgres::{PgArguments, PgQueryResult, PgRow},
    Postgres,
};
use sqlx::{query::Query, Row, Sqlite, SqliteConnection, Transaction};
use tokio::sync::Notify;
use tokio::time::Instant;

/// The deliberately maintained Native SQL subset.
///
/// This is documentation that tests can inspect, not a claim that arbitrary
/// text can be proved portable by parsing it. [`StatementTemplate`] is the
/// admission boundary for reviewed Native-owned statements.
pub const MAINTAINED_SQL_SUBSET: SqlSubset = SqlSubset {
    statements: &["select", "insert", "update", "delete"],
    joins: &["inner", "left"],
    predicates: &["ordinary", "exists"],
    aggregates: true,
    grouping: true,
    explicit_ordering: true,
    non_recursive_ctes: "only after every target driver proves the statement",
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SqlSubset {
    pub statements: &'static [&'static str],
    pub joins: &'static [&'static str],
    pub predicates: &'static [&'static str],
    pub aggregates: bool,
    pub grouping: bool,
    pub explicit_ordering: bool,
    pub non_recursive_ctes: &'static str,
}

/// Physical or security behavior that must remain in a named adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterBoundary {
    WriteConflict,
    EventCursor,
    LogicalQuery,
    Search,
    RawSql,
    PhysicalSchema,
    BackupRestore,
    Topology,
}

impl AdapterBoundary {
    pub const ALL: [Self; 8] = [
        Self::WriteConflict,
        Self::EventCursor,
        Self::LogicalQuery,
        Self::Search,
        Self::RawSql,
        Self::PhysicalSchema,
        Self::BackupRestore,
        Self::Topology,
    ];

    pub const fn adapter_name(self) -> &'static str {
        match self {
            Self::WriteConflict => "write-conflict",
            Self::EventCursor => "event-cursor",
            Self::LogicalQuery => "logical-query-primitives",
            Self::Search => "search",
            Self::RawSql => "raw-sql-security",
            Self::PhysicalSchema => "physical-schema",
            Self::BackupRestore => "backup-restore",
            Self::Topology => "topology",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Sqlite,
    Postgres,
    Turso,
}

impl Backend {
    pub const fn dialect(self) -> Dialect {
        match self {
            Self::Sqlite => Dialect::Sqlite,
            Self::Postgres => Dialect::Postgres,
            Self::Turso => Dialect::TursoSqlite,
        }
    }
}

/// SQL frontend identity. Turso is intentionally distinct from SQLite even
/// though the maintained placeholders and identifier syntax currently match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dialect {
    Sqlite,
    Postgres,
    TursoSqlite,
}

impl Dialect {
    pub fn placeholder(self, one_based_index: usize) -> SqlResult<String> {
        if one_based_index == 0 {
            return Err(SqlError::contract("placeholder indexes are one-based"));
        }
        Ok(match self {
            Self::Postgres => format!("${one_based_index}"),
            Self::Sqlite | Self::TursoSqlite => format!("?{one_based_index}"),
        })
    }

    /// Quote one generated identifier. Values never enter this function.
    pub fn quote_identifier(self, identifier: &str) -> SqlResult<String> {
        let mut bytes = identifier.bytes();
        let Some(first) = bytes.next() else {
            return Err(SqlError::contract("SQL identifier must not be empty"));
        };
        if !(first.is_ascii_lowercase() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(SqlError::contract(
                "SQL identifier must be generated lowercase ASCII",
            ));
        }
        Ok(format!("\"{identifier}\""))
    }

    /// Render an optional physical schema without leaking it into handlers.
    /// SQLite/Turso callers normally pass `None`; Postgres passes the logical
    /// database's generated schema.
    pub fn qualify_relation(self, schema: Option<&str>, relation: &str) -> SqlResult<String> {
        let relation = self.quote_identifier(relation)?;
        match schema {
            Some(schema) => Ok(format!("{}.{}", self.quote_identifier(schema)?, relation)),
            None => Ok(relation),
        }
    }

    /// Render the few approved expressions whose spellings are physical.
    pub fn fragment(self, fragment: DialectFragment) -> &'static str {
        match (self, fragment) {
            (Self::Postgres, DialectFragment::TransactionTimestamp) => "transaction_timestamp()",
            (Self::Sqlite | Self::TursoSqlite, DialectFragment::TransactionTimestamp) => {
                "strftime('%Y-%m-%dT%H:%M:%fZ','now')"
            }
            (_, DialectFragment::UpsertDoNothing) => "ON CONFLICT DO NOTHING",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialectFragment {
    TransactionTimestamp,
    UpsertDoNothing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StatementKind {
    Select,
    Insert,
    Update,
    Delete,
}

/// A reviewed, source-static Native statement split at bind positions.
///
/// For `WHERE id = ? AND kind = ?`, supply three fragments. Callers cannot
/// supply placeholder spellings, comments, multiple statements, DDL, PRAGMAs,
/// recursive CTEs, or engine catalogs through this path. Construction is
/// crate-private and accepts only `'static` source fragments. The token checks
/// are defense in depth for reviewed code, not a SQL parser or runtime
/// admission mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementTemplate {
    kind: StatementKind,
    relation: &'static str,
    fragments: &'static [&'static str],
}

impl StatementTemplate {
    // Kept crate-private so runtime SQL cannot self-admit. The first shared
    // handler migration will consume this; feature probes exercise it today.
    #[allow(dead_code)]
    pub(crate) fn new(
        kind: StatementKind,
        relation: &'static str,
        fragments: &'static [&'static str],
    ) -> SqlResult<Self> {
        if fragments.is_empty() {
            return Err(SqlError::contract(
                "portable SQL template needs at least one fragment",
            ));
        }
        Dialect::Sqlite.quote_identifier(relation)?;
        validate_template(kind, relation, fragments)?;
        Ok(Self {
            kind,
            relation,
            fragments,
        })
    }

    pub const fn kind(&self) -> StatementKind {
        self.kind
    }

    pub(crate) const fn relation(&self) -> &'static str {
        self.relation
    }

    pub fn parameter_count(&self) -> usize {
        self.fragments.len() - 1
    }

    pub fn render(&self, dialect: Dialect) -> SqlResult<RenderedStatement> {
        self.render_in(dialect, None)
    }

    pub fn render_in(
        &self,
        dialect: Dialect,
        schema: Option<&str>,
    ) -> SqlResult<RenderedStatement> {
        let relation = dialect.qualify_relation(schema, self.relation)?;
        let mut sql = self.fragments[0].replace("{{relation}}", &relation);
        for (index, fragment) in self.fragments.iter().enumerate().skip(1) {
            sql.push_str(&dialect.placeholder(index)?);
            sql.push_str(&fragment.replace("{{relation}}", &relation));
        }
        Ok(RenderedStatement {
            kind: self.kind,
            sql,
            parameter_count: self.parameter_count(),
        })
    }
}

#[allow(dead_code)] // Reached only through the deliberately crate-private constructor above.
fn validate_template(kind: StatementKind, relation: &str, fragments: &[&str]) -> SqlResult<()> {
    let joined = fragments.join(" ");
    if !joined.contains("{{relation}}") || joined.replace("{{relation}}", "").contains("{{") {
        return Err(SqlError::contract(format!(
            "portable SQL template for {relation} must use only its reviewed relation slot"
        )));
    }
    let normalized = joined.to_ascii_lowercase();
    if joined.contains(';')
        || joined.contains("--")
        || joined.contains("/*")
        || joined.contains("*/")
        || joined.contains('?')
        || joined.contains('$')
    {
        return Err(SqlError::contract(
            "portable SQL templates cannot contain delimiters, comments, or placeholders",
        ));
    }
    let padded = format!(" {normalized} ");
    for forbidden in [
        " pragma ",
        " attach ",
        " detach ",
        " vacuum ",
        " recursive ",
        " sqlite_",
        " pg_catalog",
        " information_schema",
        " create ",
        " alter ",
        " drop ",
    ] {
        if padded.contains(forbidden) {
            return Err(SqlError::contract(format!(
                "portable SQL template requires a named adapter for {forbidden:?}"
            )));
        }
    }
    let first = normalized.split_whitespace().next().unwrap_or_default();
    let expected = match kind {
        StatementKind::Select => "select",
        StatementKind::Insert => "insert",
        StatementKind::Update => "update",
        StatementKind::Delete => "delete",
    };
    if first != expected && !(kind == StatementKind::Select && first == "with") {
        return Err(SqlError::contract(format!(
            "portable SQL kind {kind:?} does not match leading keyword {first:?}"
        )));
    }
    if kind == StatementKind::Select && normalized.contains("select *") {
        return Err(SqlError::contract(
            "portable SELECT statements must name columns explicitly",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedStatement {
    pub kind: StatementKind,
    pub sql: String,
    pub parameter_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BindValue {
    Null(LogicalType),
    Bool(bool),
    Integer(i64),
    Real(f64),
    Text(String),
    Bytes(Vec<u8>),
    Json(Value),
    Timestamp(DateTime<Utc>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalType {
    Bool,
    Integer,
    Real,
    Text,
    Bytes,
    Json,
    Timestamp,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum NormalizedValue {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    Text(String),
    Bytes(Vec<u8>),
    Json(Value),
    Timestamp(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnSpec {
    pub name: String,
    pub logical_type: LogicalType,
    pub nullable: bool,
}

impl ColumnSpec {
    pub fn required(name: impl Into<String>, logical_type: LogicalType) -> Self {
        Self {
            name: name.into(),
            logical_type,
            nullable: false,
        }
    }

    pub fn nullable(name: impl Into<String>, logical_type: LogicalType) -> Self {
        Self {
            name: name.into(),
            logical_type,
            nullable: true,
        }
    }
}

pub type NormalizedRow = BTreeMap<String, NormalizedValue>;

/// Transaction-scoped execution of source-reviewed Native statements. The
/// executor cannot accept caller SQL; [`StatementTemplate`] remains the only
/// admission path. Shared domain folds use this seam for ordinary relational
/// reads while named adapters retain recursive and physical operations.
pub(crate) trait DomainStatementExecutor {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>>;
}

/// Borrowed SQLite executor for an already caller-owned transaction/snapshot.
pub(crate) struct BorrowedSqliteStatementExecutor<'a> {
    connection: &'a mut SqliteConnection,
}

impl<'a> BorrowedSqliteStatementExecutor<'a> {
    pub(crate) fn new(connection: &'a mut SqliteConnection) -> Self {
        Self { connection }
    }
}

impl DomainStatementExecutor for BorrowedSqliteStatementExecutor<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            if statement.kind() != StatementKind::Select {
                return Err(SqlError::contract("fetch_all requires a SELECT template"));
            }
            let rendered = statement.render(Dialect::Sqlite)?;
            validate_bindings(&rendered, bindings)?;
            let query = bind_sqlite(sqlx::query(&rendered.sql), bindings)?;
            let rows = query
                .fetch_all(&mut *self.connection)
                .await
                .map_err(|error| {
                    normalize_sqlx_error(Backend::Sqlite, ExecutionPhase::Statement, &error)
                })?;
            rows.iter()
                .map(|row| normalize_sqlite_row(row, columns))
                .collect()
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Cancelled,
    DeadlineExceeded,
    UniqueViolation,
    ForeignKeyViolation,
    ConstraintViolation,
    Busy,
    Conflict,
    ConnectionUnavailable,
    OutcomeUnknown,
    InvalidData,
    Unsupported,
    Storage,
    Contract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionPhase {
    Begin,
    Statement,
    Commit,
    Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{category:?} during {phase:?}")]
pub struct SqlError {
    pub category: ErrorCategory,
    pub phase: ExecutionPhase,
    pub retryable: bool,
    pub backend: Option<Backend>,
    pub backend_code: Option<String>,
    detail: Option<String>,
}

impl SqlError {
    pub(crate) fn contract(detail: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Contract,
            phase: ExecutionPhase::Statement,
            retryable: false,
            backend: None,
            backend_code: None,
            detail: Some(detail.into()),
        }
    }

    fn control(category: ErrorCategory, phase: ExecutionPhase) -> Self {
        Self {
            category,
            phase,
            retryable: false,
            backend: None,
            backend_code: None,
            detail: None,
        }
    }

    /// Construct a lifecycle error for the backend-neutral domain owner.
    /// Driver details are deliberately absent from control-flow failures.
    pub(crate) fn control_for_domain(category: ErrorCategory, phase: ExecutionPhase) -> Self {
        Self::control(category, phase)
    }

    pub fn stable_message(&self) -> &'static str {
        match self.category {
            ErrorCategory::Cancelled => "storage operation cancelled",
            ErrorCategory::DeadlineExceeded => "storage deadline exceeded",
            ErrorCategory::UniqueViolation => "uniqueness conflict",
            ErrorCategory::ForeignKeyViolation | ErrorCategory::ConstraintViolation => {
                "storage constraint violated"
            }
            ErrorCategory::Busy | ErrorCategory::Conflict => "storage conflict",
            ErrorCategory::ConnectionUnavailable => "storage unavailable",
            ErrorCategory::OutcomeUnknown => "storage commit outcome unknown",
            ErrorCategory::InvalidData => "invalid storage value",
            ErrorCategory::Unsupported => "storage operation unsupported",
            ErrorCategory::Storage => "storage operation failed",
            ErrorCategory::Contract => "invalid portable SQL contract",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

pub type SqlResult<T> = std::result::Result<T, SqlError>;

/// Cooperative cancellation and an optional absolute deadline.
#[derive(Clone, Debug, Default)]
pub struct ExecutionControl {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
    deadline: Option<Instant>,
}

impl ExecutionControl {
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + timeout),
            ..Self::default()
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    #[cfg(feature = "turso-local")]
    pub(crate) fn deadline_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    #[cfg(feature = "turso-local")]
    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    async fn cancellation(&self) {
        while !self.is_cancelled() {
            self.notify.notified().await;
        }
    }

    async fn run<F, T>(&self, phase: ExecutionPhase, future: F) -> SqlResult<T>
    where
        F: Future<Output = SqlResult<T>>,
    {
        let interrupted = if phase == ExecutionPhase::Commit {
            ErrorCategory::OutcomeUnknown
        } else {
            ErrorCategory::Cancelled
        };
        if self.is_cancelled() {
            return Err(SqlError::control(interrupted, phase));
        }
        match self.deadline {
            Some(deadline) => tokio::select! {
                biased;
                _ = self.cancellation() => Err(SqlError::control(interrupted, phase)),
                _ = tokio::time::sleep_until(deadline) => Err(SqlError::control(
                    if phase == ExecutionPhase::Commit { ErrorCategory::OutcomeUnknown } else { ErrorCategory::DeadlineExceeded },
                    phase,
                )),
                result = future => result,
            },
            None => tokio::select! {
                biased;
                _ = self.cancellation() => Err(SqlError::control(interrupted, phase)),
                result = future => result,
            },
        }
    }

    /// Run one backend-owned domain port under the same cancellation/deadline
    /// semantics as a reviewed statement.  Kept crate-private: lifecycle
    /// owners, not MCP handlers, choose the execution phase.
    pub(crate) async fn run_domain<F, T>(&self, phase: ExecutionPhase, future: F) -> SqlResult<T>
    where
        F: Future<Output = SqlResult<T>>,
    {
        self.run(phase, future).await
    }
}

/// SQLite execution inside a transaction already admitted by the backend.
///
/// The constructor is crate-private on purpose: shared handlers cannot acquire
/// a write connection through this seam and bypass strict-portability policy,
/// `BEGIN IMMEDIATE`, write gating, or realtime commit handling.
pub struct SqliteTransaction {
    transaction: Option<Transaction<'static, Sqlite>>,
}

impl SqliteTransaction {
    // SQLite routing is intentionally unchanged in this extraction. Dependent
    // handler work will wrap begin_write results through this constructor.
    #[allow(dead_code)]
    pub(crate) fn from_admitted(transaction: Transaction<'static, Sqlite>) -> Self {
        Self {
            transaction: Some(transaction),
        }
    }

    pub async fn execute(
        &mut self,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        control: &ExecutionControl,
    ) -> SqlResult<u64> {
        let rendered = statement.render(Dialect::Sqlite)?;
        validate_bindings(&rendered, bindings)?;
        let result = {
            let transaction = self.active()?;
            control
                .run(ExecutionPhase::Statement, async move {
                    let query = bind_sqlite(sqlx::query(&rendered.sql), bindings)?;
                    let result: SqliteQueryResult =
                        query.execute(&mut **transaction).await.map_err(|error| {
                            normalize_sqlx_error(Backend::Sqlite, ExecutionPhase::Statement, &error)
                        })?;
                    Ok(result.rows_affected())
                })
                .await
        };
        self.poison_if_interrupted(&result);
        result
    }

    pub async fn fetch_all(
        &mut self,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        columns: &[ColumnSpec],
        control: &ExecutionControl,
    ) -> SqlResult<Vec<NormalizedRow>> {
        if statement.kind() != StatementKind::Select {
            return Err(SqlError::contract("fetch_all requires a SELECT template"));
        }
        let rendered = statement.render(Dialect::Sqlite)?;
        validate_bindings(&rendered, bindings)?;
        let result = {
            let transaction = self.active()?;
            control
                .run(ExecutionPhase::Statement, async move {
                    let query = bind_sqlite(sqlx::query(&rendered.sql), bindings)?;
                    let rows = query.fetch_all(&mut **transaction).await.map_err(|error| {
                        normalize_sqlx_error(Backend::Sqlite, ExecutionPhase::Statement, &error)
                    })?;
                    rows.iter()
                        .map(|row| normalize_sqlite_row(row, columns))
                        .collect()
                })
                .await
        };
        self.poison_if_interrupted(&result);
        result
    }

    /// Return a healthy transaction to the backend-owned lifecycle. Only that
    /// owner may commit or roll back, preserving SQLite's post-durability
    /// realtime wake and any operation-specific completion behavior.
    #[allow(dead_code)]
    pub(crate) fn into_admitted(mut self) -> SqlResult<Transaction<'static, Sqlite>> {
        self.transaction
            .take()
            .ok_or_else(|| SqlError::contract("portable transaction is poisoned"))
    }

    fn active(&mut self) -> SqlResult<&mut Transaction<'static, Sqlite>> {
        self.transaction
            .as_mut()
            .ok_or_else(|| SqlError::contract("portable transaction is no longer active"))
    }

    fn poison_if_interrupted<T>(&mut self, result: &SqlResult<T>) {
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.category,
                ErrorCategory::Cancelled
                    | ErrorCategory::DeadlineExceeded
                    | ErrorCategory::OutcomeUnknown
            )
        }) {
            // Dropping SQLx's transaction schedules a rollback before the
            // pooled connection can be reused. The wrapper becomes terminal,
            // so no caller can commit after cancellation raced the worker.
            self.transaction.take();
        }
    }
}

/// Postgres execution owning a backend-admitted transaction.
///
/// Acquisition, isolation, locks, retry, event allocation, and completion all
/// remain with the Postgres adapter. An interrupted executor is terminal and
/// [`into_admitted`](Self::into_admitted) returns it only while healthy.
#[cfg(feature = "postgres")]
pub struct PostgresTransaction<'connection> {
    transaction: Option<Transaction<'connection, Postgres>>,
    schema: String,
    poisoned: bool,
}

#[cfg(feature = "postgres")]
impl<'connection> PostgresTransaction<'connection> {
    pub fn from_admitted(
        transaction: Transaction<'connection, Postgres>,
        schema: impl Into<String>,
    ) -> SqlResult<Self> {
        let schema = schema.into();
        Dialect::Postgres.quote_identifier(&schema)?;
        Ok(Self {
            transaction: Some(transaction),
            schema,
            poisoned: false,
        })
    }

    pub async fn execute(
        &mut self,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        control: &ExecutionControl,
    ) -> SqlResult<u64> {
        let rendered = statement.render_in(Dialect::Postgres, Some(&self.schema))?;
        validate_bindings(&rendered, bindings)?;
        let result = {
            let transaction = self.active()?;
            control
                .run(ExecutionPhase::Statement, async {
                    let query = bind_postgres(sqlx::query(&rendered.sql), bindings)?;
                    let result: PgQueryResult =
                        query.execute(&mut **transaction).await.map_err(|error| {
                            normalize_sqlx_error(
                                Backend::Postgres,
                                ExecutionPhase::Statement,
                                &error,
                            )
                        })?;
                    Ok(result.rows_affected())
                })
                .await
        };
        if result.is_err() {
            self.poisoned = true;
            self.transaction.take();
        }
        result
    }

    pub async fn fetch_all(
        &mut self,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        columns: &[ColumnSpec],
        control: &ExecutionControl,
    ) -> SqlResult<Vec<NormalizedRow>> {
        if statement.kind() != StatementKind::Select {
            return Err(SqlError::contract("fetch_all requires a SELECT template"));
        }
        let rendered = statement.render_in(Dialect::Postgres, Some(&self.schema))?;
        validate_bindings(&rendered, bindings)?;
        let result = {
            let transaction = self.active()?;
            control
                .run(ExecutionPhase::Statement, async {
                    let query = bind_postgres(sqlx::query(&rendered.sql), bindings)?;
                    let rows = query.fetch_all(&mut **transaction).await.map_err(|error| {
                        normalize_sqlx_error(Backend::Postgres, ExecutionPhase::Statement, &error)
                    })?;
                    rows.iter()
                        .map(|row| normalize_postgres_row(row, columns))
                        .collect()
                })
                .await
        };
        if result.is_err() {
            self.poisoned = true;
            self.transaction.take();
        }
        result
    }

    pub fn into_admitted(mut self) -> SqlResult<Transaction<'connection, Postgres>> {
        if self.poisoned {
            Err(SqlError::contract(
                "failed Postgres transaction was rolled back",
            ))
        } else {
            self.transaction
                .take()
                .ok_or_else(|| SqlError::contract("Postgres transaction is no longer active"))
        }
    }

    /// Borrow the healthy admitted transaction for a backend-owned physical
    /// operation (blob bytes, event append/projection). Lifecycle ownership is
    /// unchanged: only [`into_admitted`](Self::into_admitted) releases it.
    pub(crate) fn admitted_mut(&mut self) -> SqlResult<&mut Transaction<'connection, Postgres>> {
        if self.poisoned {
            return Err(SqlError::contract(
                "failed Postgres transaction was rolled back",
            ));
        }
        self.active()
    }

    fn active(&mut self) -> SqlResult<&mut Transaction<'connection, Postgres>> {
        self.transaction
            .as_mut()
            .ok_or_else(|| SqlError::contract("Postgres transaction is no longer active"))
    }
}

/// Turso execution owning a backend-admitted transaction.
///
/// This adapter deliberately does not issue `BEGIN`, `COMMIT`, sync, or
/// topology calls. It forces rollback-on-drop and returns the transaction only
/// while healthy.
#[cfg(feature = "turso-local")]
pub struct TursoTransaction<'connection> {
    transaction: Option<turso::transaction::Transaction<'connection>>,
    poisoned: bool,
}

#[cfg(feature = "turso-local")]
impl<'connection> TursoTransaction<'connection> {
    pub fn from_admitted(mut transaction: turso::transaction::Transaction<'connection>) -> Self {
        transaction.set_drop_behavior(turso::transaction::DropBehavior::Rollback);
        debug_assert_eq!(
            transaction.drop_behavior(),
            turso::transaction::DropBehavior::Rollback
        );
        Self {
            transaction: Some(transaction),
            poisoned: false,
        }
    }

    /// Narrow escape hatch for the named Turso search adapter. Search is an
    /// explicit [`AdapterBoundary::Search`], so its backend-native `MATCH`
    /// statements cannot be represented as portable SQL templates. Keeping
    /// this crate-private and search-named prevents arbitrary domain handlers
    /// from turning the portable executor into a raw-SQL seam.
    pub(crate) fn native_search_transaction(
        &mut self,
    ) -> SqlResult<&turso::transaction::Transaction<'connection>> {
        self.active()
    }

    pub async fn execute(
        &mut self,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        control: &ExecutionControl,
    ) -> SqlResult<u64> {
        let rendered = statement.render(Dialect::TursoSqlite)?;
        validate_bindings(&rendered, bindings)?;
        let params = bind_turso(bindings)?;
        let result = {
            let transaction = self.active()?;
            control
                .run(ExecutionPhase::Statement, async {
                    transaction
                        .execute(&rendered.sql, params)
                        .await
                        .map_err(|error| normalize_turso_error(ExecutionPhase::Statement, &error))
                })
                .await
        };
        if result.is_err() {
            self.poisoned = true;
            self.transaction.take();
        }
        result
    }

    pub async fn fetch_all(
        &mut self,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        columns: &[ColumnSpec],
        control: &ExecutionControl,
    ) -> SqlResult<Vec<NormalizedRow>> {
        if statement.kind() != StatementKind::Select {
            return Err(SqlError::contract("fetch_all requires a SELECT template"));
        }
        let rendered = statement.render(Dialect::TursoSqlite)?;
        validate_bindings(&rendered, bindings)?;
        let params = bind_turso(bindings)?;
        let result =
            {
                let transaction = self.active()?;
                control
                    .run(ExecutionPhase::Statement, async {
                        let mut rows =
                            transaction
                                .query(&rendered.sql, params)
                                .await
                                .map_err(|error| {
                                    normalize_turso_error(ExecutionPhase::Statement, &error)
                                })?;
                        let indexes = columns
                            .iter()
                            .map(|column| {
                                rows.column_index(&column.name).map_err(|error| {
                                    normalize_turso_error(ExecutionPhase::Statement, &error)
                                })
                            })
                            .collect::<SqlResult<Vec<_>>>()?;
                        let mut normalized = Vec::new();
                        while let Some(row) = rows.next().await.map_err(|error| {
                            normalize_turso_error(ExecutionPhase::Statement, &error)
                        })? {
                            normalized.push(normalize_turso_row(&row, columns, &indexes)?);
                        }
                        Ok(normalized)
                    })
                    .await
            };
        if result.is_err() {
            self.poisoned = true;
            self.transaction.take();
        }
        result
    }

    pub fn into_admitted(mut self) -> SqlResult<turso::transaction::Transaction<'connection>> {
        if self.poisoned {
            Err(SqlError::contract(
                "failed Turso transaction was rolled back",
            ))
        } else {
            self.transaction
                .take()
                .ok_or_else(|| SqlError::contract("Turso transaction is no longer active"))
        }
    }

    fn active(&mut self) -> SqlResult<&turso::transaction::Transaction<'connection>> {
        self.transaction
            .as_ref()
            .ok_or_else(|| SqlError::contract("Turso transaction is no longer active"))
    }
}

fn validate_bindings(statement: &RenderedStatement, bindings: &[BindValue]) -> SqlResult<()> {
    if statement.parameter_count != bindings.len() {
        return Err(SqlError::contract(format!(
            "portable SQL expected {} bindings, received {}",
            statement.parameter_count,
            bindings.len()
        )));
    }
    if bindings
        .iter()
        .any(|value| matches!(value, BindValue::Real(value) if !value.is_finite()))
    {
        return Err(SqlError::contract(
            "portable SQL does not admit non-finite real values",
        ));
    }
    Ok(())
}

fn bind_sqlite<'q>(
    mut query: Query<'q, Sqlite, SqliteArguments<'q>>,
    bindings: &[BindValue],
) -> SqlResult<Query<'q, Sqlite, SqliteArguments<'q>>> {
    for binding in bindings {
        query = match binding {
            BindValue::Null(LogicalType::Bool) => query.bind(Option::<bool>::None),
            BindValue::Null(LogicalType::Integer) => query.bind(Option::<i64>::None),
            BindValue::Null(LogicalType::Real) => query.bind(Option::<f64>::None),
            BindValue::Null(LogicalType::Text | LogicalType::Json | LogicalType::Timestamp) => {
                query.bind(Option::<String>::None)
            }
            BindValue::Null(LogicalType::Bytes) => query.bind(Option::<Vec<u8>>::None),
            BindValue::Bool(value) => query.bind(*value),
            BindValue::Integer(value) => query.bind(*value),
            BindValue::Real(value) => query.bind(*value),
            BindValue::Text(value) => query.bind(value.clone()),
            BindValue::Bytes(value) => query.bind(value.clone()),
            BindValue::Json(value) => {
                query.bind(serde_json::to_string(value).map_err(|error| {
                    let mut mapped =
                        SqlError::contract("portable JSON binding could not be encoded");
                    mapped.detail = Some(error.to_string());
                    mapped
                })?)
            }
            BindValue::Timestamp(value) => {
                query.bind(value.to_rfc3339_opts(SecondsFormat::Millis, true))
            }
        };
    }
    Ok(query)
}

#[cfg(feature = "postgres")]
fn bind_postgres<'q>(
    mut query: Query<'q, Postgres, PgArguments>,
    bindings: &[BindValue],
) -> SqlResult<Query<'q, Postgres, PgArguments>> {
    for binding in bindings {
        query = match binding {
            BindValue::Null(LogicalType::Bool) => query.bind(Option::<bool>::None),
            BindValue::Null(LogicalType::Integer) => query.bind(Option::<i64>::None),
            BindValue::Null(LogicalType::Real) => query.bind(Option::<f64>::None),
            BindValue::Null(LogicalType::Text) => query.bind(Option::<String>::None),
            BindValue::Null(LogicalType::Json) => {
                query.bind(Option::<sqlx::types::Json<Value>>::None)
            }
            BindValue::Null(LogicalType::Timestamp) => query.bind(Option::<DateTime<Utc>>::None),
            BindValue::Null(LogicalType::Bytes) => query.bind(Option::<Vec<u8>>::None),
            BindValue::Bool(value) => query.bind(*value),
            BindValue::Integer(value) => query.bind(*value),
            BindValue::Real(value) => query.bind(*value),
            BindValue::Text(value) => query.bind(value.clone()),
            BindValue::Bytes(value) => query.bind(value.clone()),
            BindValue::Json(value) => query.bind(sqlx::types::Json(value.clone())),
            BindValue::Timestamp(value) => query.bind(*value),
        };
    }
    Ok(query)
}

#[cfg(feature = "turso-local")]
fn bind_turso(bindings: &[BindValue]) -> SqlResult<Vec<turso::Value>> {
    bindings
        .iter()
        .map(|binding| {
            Ok(match binding {
                BindValue::Null(_) => turso::Value::Null,
                BindValue::Bool(value) => turso::Value::Integer(i64::from(*value)),
                BindValue::Integer(value) => turso::Value::Integer(*value),
                BindValue::Real(value) => turso::Value::Real(*value),
                BindValue::Text(value) => turso::Value::Text(value.clone()),
                BindValue::Bytes(value) => turso::Value::Blob(value.clone()),
                BindValue::Json(value) => {
                    turso::Value::Text(serde_json::to_string(value).map_err(|error| {
                        let mut mapped =
                            SqlError::contract("portable JSON binding could not be encoded");
                        mapped.detail = Some(error.to_string());
                        mapped
                    })?)
                }
                BindValue::Timestamp(value) => {
                    turso::Value::Text(value.to_rfc3339_opts(SecondsFormat::Millis, true))
                }
            })
        })
        .collect()
}

fn normalize_sqlite_row(row: &SqliteRow, columns: &[ColumnSpec]) -> SqlResult<NormalizedRow> {
    let mut normalized = BTreeMap::new();
    for column in columns {
        let value = match column.logical_type {
            LogicalType::Bool => {
                optional(row, column, |name| row.try_get::<Option<bool>, _>(name))?
                    .map(NormalizedValue::Bool)
            }
            LogicalType::Integer => {
                optional(row, column, |name| row.try_get::<Option<i64>, _>(name))?
                    .map(NormalizedValue::Integer)
            }
            LogicalType::Real => {
                let value = optional(row, column, |name| row.try_get::<Option<f64>, _>(name))?;
                if value.is_some_and(|value| !value.is_finite()) {
                    return Err(invalid_column(column, "non-finite real"));
                }
                value.map(NormalizedValue::Real)
            }
            LogicalType::Text => {
                optional(row, column, |name| row.try_get::<Option<String>, _>(name))?
                    .map(NormalizedValue::Text)
            }
            LogicalType::Bytes => {
                optional(row, column, |name| row.try_get::<Option<Vec<u8>>, _>(name))?
                    .map(NormalizedValue::Bytes)
            }
            LogicalType::Json => {
                let value = optional(row, column, |name| row.try_get::<Option<String>, _>(name))?;
                value
                    .map(|value| {
                        serde_json::from_str(&value)
                            .map(NormalizedValue::Json)
                            .map_err(|_| invalid_column(column, "invalid JSON"))
                    })
                    .transpose()?
            }
            LogicalType::Timestamp => {
                let value = optional(row, column, |name| row.try_get::<Option<String>, _>(name))?;
                value
                    .map(|value| normalize_timestamp(column, &value))
                    .transpose()?
                    .map(NormalizedValue::Timestamp)
            }
        }
        .unwrap_or(NormalizedValue::Null);
        normalized.insert(column.name.clone(), value);
    }
    Ok(normalized)
}

#[cfg(feature = "postgres")]
fn normalize_postgres_row(row: &PgRow, columns: &[ColumnSpec]) -> SqlResult<NormalizedRow> {
    let mut normalized = BTreeMap::new();
    for column in columns {
        let value = match column.logical_type {
            LogicalType::Bool => {
                pg_optional(row, column, |name| row.try_get::<Option<bool>, _>(name))?
                    .map(NormalizedValue::Bool)
            }
            LogicalType::Integer => {
                pg_optional(row, column, |name| row.try_get::<Option<i64>, _>(name))?
                    .map(NormalizedValue::Integer)
            }
            LogicalType::Real => {
                let value = pg_optional(row, column, |name| row.try_get::<Option<f64>, _>(name))?;
                if value.is_some_and(|value| !value.is_finite()) {
                    return Err(invalid_backend_column(
                        Backend::Postgres,
                        column,
                        "non-finite real",
                    ));
                }
                value.map(NormalizedValue::Real)
            }
            LogicalType::Text => {
                pg_optional(row, column, |name| row.try_get::<Option<String>, _>(name))?
                    .map(NormalizedValue::Text)
            }
            LogicalType::Bytes => {
                pg_optional(row, column, |name| row.try_get::<Option<Vec<u8>>, _>(name))?
                    .map(NormalizedValue::Bytes)
            }
            LogicalType::Json => pg_optional(row, column, |name| {
                row.try_get::<Option<sqlx::types::Json<Value>>, _>(name)
            })?
            .map(|value| NormalizedValue::Json(value.0)),
            LogicalType::Timestamp => pg_optional(row, column, |name| {
                row.try_get::<Option<DateTime<Utc>>, _>(name)
            })?
            .map(|value| {
                NormalizedValue::Timestamp(value.to_rfc3339_opts(SecondsFormat::Millis, true))
            }),
        }
        .unwrap_or(NormalizedValue::Null);
        normalized.insert(column.name.clone(), value);
    }
    Ok(normalized)
}

#[cfg(feature = "postgres")]
fn pg_optional<T, F>(row: &PgRow, column: &ColumnSpec, decode: F) -> SqlResult<Option<T>>
where
    F: FnOnce(&str) -> std::result::Result<Option<T>, sqlx::Error>,
{
    let value = decode(&column.name).map_err(|error| {
        normalize_sqlx_error(Backend::Postgres, ExecutionPhase::Statement, &error)
    })?;
    if value.is_none() && !column.nullable {
        return Err(invalid_backend_column(
            Backend::Postgres,
            column,
            "unexpected NULL",
        ));
    }
    let _ = row;
    Ok(value)
}

#[cfg(feature = "turso-local")]
fn normalize_turso_row(
    row: &turso::Row,
    columns: &[ColumnSpec],
    indexes: &[usize],
) -> SqlResult<NormalizedRow> {
    if row.column_count() < columns.len() {
        return Err(SqlError {
            category: ErrorCategory::InvalidData,
            phase: ExecutionPhase::Statement,
            retryable: false,
            backend: Some(Backend::Turso),
            backend_code: None,
            detail: Some("Turso row has fewer columns than its portable specification".into()),
        });
    }
    let mut normalized = BTreeMap::new();
    for (column, index) in columns.iter().zip(indexes.iter().copied()) {
        let raw = row
            .get_value(index)
            .map_err(|error| normalize_turso_error(ExecutionPhase::Statement, &error))?;
        let value = normalize_turso_value(raw, column)?;
        normalized.insert(column.name.clone(), value);
    }
    Ok(normalized)
}

#[cfg(feature = "turso-local")]
fn normalize_turso_value(value: turso::Value, column: &ColumnSpec) -> SqlResult<NormalizedValue> {
    use turso::Value as TursoValue;
    if matches!(value, TursoValue::Null) {
        return if column.nullable {
            Ok(NormalizedValue::Null)
        } else {
            Err(invalid_backend_column(
                Backend::Turso,
                column,
                "unexpected NULL",
            ))
        };
    }
    match (column.logical_type, value) {
        (LogicalType::Bool, TursoValue::Integer(0)) => Ok(NormalizedValue::Bool(false)),
        (LogicalType::Bool, TursoValue::Integer(1)) => Ok(NormalizedValue::Bool(true)),
        (LogicalType::Integer, TursoValue::Integer(value)) => Ok(NormalizedValue::Integer(value)),
        (LogicalType::Real, TursoValue::Real(value)) if value.is_finite() => {
            Ok(NormalizedValue::Real(value))
        }
        (LogicalType::Text, TursoValue::Text(value)) => Ok(NormalizedValue::Text(value)),
        (LogicalType::Bytes, TursoValue::Blob(value)) => Ok(NormalizedValue::Bytes(value)),
        (LogicalType::Json, TursoValue::Text(value)) => serde_json::from_str(&value)
            .map(NormalizedValue::Json)
            .map_err(|_| invalid_backend_column(Backend::Turso, column, "invalid JSON")),
        (LogicalType::Timestamp, TursoValue::Text(value)) => {
            normalize_backend_timestamp(Backend::Turso, column, &value)
                .map(NormalizedValue::Timestamp)
        }
        _ => Err(invalid_backend_column(
            Backend::Turso,
            column,
            "unexpected physical type",
        )),
    }
}

fn optional<T, F>(row: &SqliteRow, column: &ColumnSpec, decode: F) -> SqlResult<Option<T>>
where
    F: FnOnce(&str) -> std::result::Result<Option<T>, sqlx::Error>,
{
    let value = decode(&column.name).map_err(|error| {
        normalize_sqlx_error(Backend::Sqlite, ExecutionPhase::Statement, &error)
    })?;
    if value.is_none() && !column.nullable {
        return Err(invalid_column(column, "unexpected NULL"));
    }
    let _ = row;
    Ok(value)
}

fn normalize_timestamp(column: &ColumnSpec, value: &str) -> SqlResult<String> {
    normalize_backend_timestamp(Backend::Sqlite, column, value)
}

fn normalize_backend_timestamp(
    backend: Backend,
    column: &ColumnSpec,
    value: &str,
) -> SqlResult<String> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid_backend_column(backend, column, "invalid RFC3339 timestamp"))?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn invalid_column(column: &ColumnSpec, detail: &str) -> SqlError {
    invalid_backend_column(Backend::Sqlite, column, detail)
}

fn invalid_backend_column(backend: Backend, column: &ColumnSpec, detail: &str) -> SqlError {
    SqlError {
        category: ErrorCategory::InvalidData,
        phase: ExecutionPhase::Statement,
        retryable: false,
        backend: Some(backend),
        backend_code: None,
        detail: Some(format!("{}: {detail}", column.name)),
    }
}

pub fn normalize_sqlx_error(
    backend: Backend,
    phase: ExecutionPhase,
    error: &sqlx::Error,
) -> SqlError {
    let code = match error {
        sqlx::Error::Database(database) => database.code().map(|code| code.into_owned()),
        _ => None,
    };
    let category = match (backend, code.as_deref()) {
        (Backend::Sqlite | Backend::Turso, Some("5" | "6")) => ErrorCategory::Busy,
        (Backend::Sqlite | Backend::Turso, Some("2067" | "1555")) => ErrorCategory::UniqueViolation,
        (Backend::Sqlite | Backend::Turso, Some("787")) => ErrorCategory::ForeignKeyViolation,
        (Backend::Sqlite | Backend::Turso, Some("19" | "275")) => {
            ErrorCategory::ConstraintViolation
        }
        (Backend::Sqlite | Backend::Turso, Some("9")) => ErrorCategory::Cancelled,
        (Backend::Postgres, Some("23505")) => ErrorCategory::UniqueViolation,
        (Backend::Postgres, Some("23503")) => ErrorCategory::ForeignKeyViolation,
        (Backend::Postgres, Some("23514")) => ErrorCategory::ConstraintViolation,
        (Backend::Postgres, Some("40001" | "40P01" | "55P03")) => ErrorCategory::Conflict,
        (Backend::Postgres, Some("57014")) => ErrorCategory::Cancelled,
        (Backend::Postgres, Some(code)) if code.starts_with("08") => {
            if phase == ExecutionPhase::Commit {
                ErrorCategory::OutcomeUnknown
            } else {
                ErrorCategory::ConnectionUnavailable
            }
        }
        _ if matches!(error, sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed) => {
            ErrorCategory::ConnectionUnavailable
        }
        _ => ErrorCategory::Storage,
    };
    let retryable = matches!(
        category,
        ErrorCategory::Busy | ErrorCategory::Conflict | ErrorCategory::ConnectionUnavailable
    ) && phase != ExecutionPhase::Commit;
    SqlError {
        category,
        phase,
        retryable,
        backend: Some(backend),
        backend_code: code,
        detail: None,
    }
}

/// Whether a SQLite-dialect constraint message names a uniqueness violation.
///
/// Message matching is the only signal this driver exposes; the wording is
/// SQLite's long-standing text that Turso reproduces. A wording change degrades
/// to the generic constraint category rather than misreporting, and the
/// canonical duplicate-create test fails loudly if that happens.
#[cfg(feature = "turso-local")]
fn is_unique_violation_message(message: &str) -> bool {
    let message = message.to_ascii_uppercase();
    message.contains("UNIQUE CONSTRAINT FAILED")
        || message.contains("PRIMARY KEY CONSTRAINT FAILED")
}

#[cfg(feature = "turso-local")]
pub fn normalize_turso_error(phase: ExecutionPhase, error: &turso::Error) -> SqlError {
    let category = match error {
        turso::Error::Busy(_) | turso::Error::BusySnapshot(_) => ErrorCategory::Busy,
        turso::Error::Interrupt(_) => ErrorCategory::Cancelled,
        // The driver reports every constraint failure through one variant, so
        // the specific violation is only in its message. A duplicate key is a
        // uniqueness conflict, and reporting it as a generic constraint failure
        // gave the same logical fault a different stable category here than on
        // SQLite (extended codes 2067/1555) and Postgres (SQLSTATE 23505).
        turso::Error::Constraint(message) => {
            if is_unique_violation_message(message) {
                ErrorCategory::UniqueViolation
            } else {
                ErrorCategory::ConstraintViolation
            }
        }
        turso::Error::IoError(_, _) => {
            if phase == ExecutionPhase::Commit {
                ErrorCategory::OutcomeUnknown
            } else {
                ErrorCategory::ConnectionUnavailable
            }
        }
        turso::Error::Readonly(_) => ErrorCategory::Unsupported,
        turso::Error::ConversionFailure(_) | turso::Error::ToSqlConversionFailure(_) => {
            ErrorCategory::InvalidData
        }
        _ => ErrorCategory::Storage,
    };
    SqlError {
        category,
        phase,
        retryable: matches!(
            category,
            ErrorCategory::Busy | ErrorCategory::ConnectionUnavailable
        ) && phase != ExecutionPhase::Commit,
        backend: Some(Backend::Turso),
        backend_code: None,
        detail: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn select_template() -> StatementTemplate {
        StatementTemplate::new(
            StatementKind::Select,
            "portable_values",
            &[
                "SELECT id, enabled, score, payload, created_at FROM {{relation}} WHERE id = ",
                " ORDER BY id",
            ],
        )
        .unwrap()
    }

    fn insert_template() -> StatementTemplate {
        StatementTemplate::new(
            StatementKind::Insert,
            "portable_values",
            &[
                "INSERT INTO {{relation}} (id, enabled, score, payload, created_at) VALUES (",
                ", ",
                ", ",
                ", ",
                ", ",
                ")",
            ],
        )
        .unwrap()
    }

    fn probe_bindings() -> Vec<BindValue> {
        let timestamp = DateTime::parse_from_rfc3339("2026-08-05T12:34:56.123456+01:00")
            .unwrap()
            .with_timezone(&Utc);
        vec![
            BindValue::Text("portable:row".into()),
            BindValue::Bool(false),
            BindValue::Real(1.5),
            BindValue::Json(serde_json::json!({"number": 1})),
            BindValue::Timestamp(timestamp),
        ]
    }

    fn probe_columns() -> Vec<ColumnSpec> {
        vec![
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::required("enabled", LogicalType::Bool),
            ColumnSpec::required("score", LogicalType::Real),
            ColumnSpec::required("payload", LogicalType::Json),
            ColumnSpec::required("created_at", LogicalType::Timestamp),
        ]
    }

    fn assert_probe_row(rows: &[NormalizedRow]) {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], NormalizedValue::Text("portable:row".into()));
        assert_eq!(rows[0]["enabled"], NormalizedValue::Bool(false));
        assert_eq!(rows[0]["score"], NormalizedValue::Real(1.5));
        assert_eq!(
            rows[0]["payload"],
            NormalizedValue::Json(serde_json::json!({"number": 1}))
        );
        assert_eq!(
            rows[0]["created_at"],
            NormalizedValue::Timestamp("2026-08-05T11:34:56.123Z".into())
        );
    }

    #[test]
    fn renders_dialects_without_collapsing_engine_identity() {
        let template = select_template();
        assert_eq!(
            template.render(Dialect::Sqlite).unwrap().sql,
            "SELECT id, enabled, score, payload, created_at FROM \"portable_values\" WHERE id = ?1 ORDER BY id"
        );
        assert_eq!(
            template.render(Dialect::Postgres).unwrap().sql,
            "SELECT id, enabled, score, payload, created_at FROM \"portable_values\" WHERE id = $1 ORDER BY id"
        );
        assert_eq!(
            template.render(Dialect::TursoSqlite).unwrap().sql,
            template.render(Dialect::Sqlite).unwrap().sql
        );
        assert_ne!(Backend::Sqlite, Backend::Turso);
    }

    #[test]
    fn validates_schema_qualification_and_escape_hatches() {
        assert_eq!(
            Dialect::Postgres
                .qualify_relation(Some("native_contract_1"), "records")
                .unwrap(),
            "\"native_contract_1\".\"records\""
        );
        assert!(Dialect::Postgres
            .qualify_relation(Some("public; DROP SCHEMA public"), "records")
            .is_err());
        assert_eq!(
            select_template()
                .render_in(Dialect::Postgres, Some("native_contract_1"))
                .unwrap()
                .sql,
            "SELECT id, enabled, score, payload, created_at FROM \"native_contract_1\".\"portable_values\" WHERE id = $1 ORDER BY id"
        );
        assert_eq!(
            AdapterBoundary::ALL
                .iter()
                .map(|boundary| boundary.adapter_name())
                .collect::<Vec<_>>(),
            [
                "write-conflict",
                "event-cursor",
                "logical-query-primitives",
                "search",
                "raw-sql-security",
                "physical-schema",
                "backup-restore",
                "topology",
            ]
        );
    }

    #[test]
    fn rejects_sql_outside_the_native_owned_subset() {
        for sql in [
            "SELECT * FROM records",
            "PRAGMA user_version",
            "WITH RECURSIVE tree AS (SELECT id FROM records) SELECT id FROM tree",
            "SELECT id FROM sqlite_schema",
            "SELECT id FROM records; DELETE FROM records",
        ] {
            assert!(validate_template(StatementKind::Select, "records", &[sql]).is_err());
        }
        assert!(StatementTemplate::new(
            StatementKind::Select,
            "records",
            &["DELETE FROM {{relation}} WHERE id = ", ""]
        )
        .is_err());
    }

    #[tokio::test]
    async fn cancellation_and_commit_deadlines_have_stable_categories() {
        let cancelled = ExecutionControl::default();
        cancelled.cancel();
        let error = cancelled
            .run(ExecutionPhase::Statement, async { Ok::<_, SqlError>(()) })
            .await
            .unwrap_err();
        assert_eq!(error.category, ErrorCategory::Cancelled);

        let commit = ExecutionControl::with_timeout(Duration::ZERO);
        let error = commit
            .run(
                ExecutionPhase::Commit,
                std::future::pending::<SqlResult<()>>(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.category, ErrorCategory::OutcomeUnknown);
        assert!(!error.retryable);
    }

    #[tokio::test]
    async fn interrupted_sqlite_statement_poisoned_the_admitted_transaction() {
        let database = crate::create_database(":memory:").await.unwrap();
        let admitted = db::begin_write(database.write_pool()).await.unwrap();
        let mut transaction = SqliteTransaction::from_admitted(admitted);
        let control = ExecutionControl::default();
        control.cancel();
        let error = transaction
            .fetch_all(
                &select_template(),
                &[BindValue::Text("missing".into())],
                &[],
                &control,
            )
            .await
            .unwrap_err();
        assert_eq!(error.category, ErrorCategory::Cancelled);
        assert!(transaction.into_admitted().is_err());

        // SQLx's dropped transaction rollback is drained before pool reuse.
        sqlx::query("SELECT 1")
            .execute(database.pool())
            .await
            .unwrap();
        database.close().await;
    }

    #[tokio::test]
    async fn sqlite_adapter_executes_inside_admitted_transaction_and_normalizes_rows() {
        let database = crate::create_database(":memory:").await.unwrap();
        let mut transaction = db::begin_write(database.write_pool()).await.unwrap();
        // Physical setup is intentionally outside the portable executor.
        sqlx::query(
            "CREATE TABLE portable_values(\
             id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, score REAL NOT NULL,\
             payload TEXT NOT NULL, created_at TEXT NOT NULL)",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let mut transaction = SqliteTransaction::from_admitted(transaction);
        let control = ExecutionControl::default();
        transaction
            .execute(&insert_template(), &probe_bindings(), &control)
            .await
            .unwrap();
        let rows = transaction
            .fetch_all(
                &select_template(),
                &[BindValue::Text("portable:row".into())],
                &probe_columns(),
                &control,
            )
            .await
            .unwrap();
        assert_probe_row(&rows);
        transaction
            .into_admitted()
            .unwrap()
            .rollback()
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name = ?")
            .bind("portable_values")
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
        database.close().await;
    }

    #[cfg(feature = "turso-local")]
    #[tokio::test]
    async fn turso_adapter_executes_the_shared_statement_and_normalizes_rows() {
        let database = turso::Builder::new_local(":memory:").build().await.unwrap();
        let mut connection = database.connect().unwrap();
        connection
            .execute(
                "CREATE TABLE portable_values(\
                 id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, score REAL NOT NULL,\
                 payload TEXT NOT NULL, created_at TEXT NOT NULL)",
                (),
            )
            .await
            .unwrap();
        let admitted = connection
            .transaction_with_behavior(turso::transaction::TransactionBehavior::Immediate)
            .await
            .unwrap();
        let control = ExecutionControl::default();
        let mut transaction = TursoTransaction::from_admitted(admitted);
        transaction
            .execute(&insert_template(), &probe_bindings(), &control)
            .await
            .unwrap();
        let rows = transaction
            .fetch_all(
                &select_template(),
                &[BindValue::Text("portable:row".into())],
                &probe_columns(),
                &control,
            )
            .await
            .unwrap();
        assert_probe_row(&rows);
        transaction
            .into_admitted()
            .unwrap()
            .rollback()
            .await
            .unwrap();

        let admitted = connection
            .transaction_with_behavior(turso::transaction::TransactionBehavior::Immediate)
            .await
            .unwrap();
        let mut transaction = TursoTransaction::from_admitted(admitted);
        let cancelled = ExecutionControl::default();
        cancelled.cancel();
        let error = transaction
            .execute(&insert_template(), &probe_bindings(), &cancelled)
            .await
            .unwrap_err();
        assert_eq!(error.category, ErrorCategory::Cancelled);
        assert!(transaction.into_admitted().is_err());
        assert_eq!(
            connection
                .query("SELECT COUNT(*) FROM portable_values", ())
                .await
                .unwrap()
                .next()
                .await
                .unwrap()
                .unwrap()
                .get::<i64>(0)
                .unwrap(),
            0
        );
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn postgres_adapter_executes_the_shared_statement_and_normalizes_rows() {
        use sqlx::postgres::PgPoolOptions;

        let Ok(url) = std::env::var("NATIVE_CE_POSTGRES_TEST_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("portable_sql_{}", uuid::Uuid::new_v4().simple());
        let relation = Dialect::Postgres
            .qualify_relation(Some(&schema), "portable_values")
            .unwrap();
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(&format!(
            "CREATE TABLE {relation}(\
             id TEXT PRIMARY KEY, enabled BOOLEAN NOT NULL, score DOUBLE PRECISION NOT NULL,\
             payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let admitted = pool.begin().await.unwrap();
        let control = ExecutionControl::default();
        let mut transaction = PostgresTransaction::from_admitted(admitted, &schema).unwrap();
        transaction
            .execute(&insert_template(), &probe_bindings(), &control)
            .await
            .unwrap();
        let rows = transaction
            .fetch_all(
                &select_template(),
                &[BindValue::Text("portable:row".into())],
                &probe_columns(),
                &control,
            )
            .await
            .unwrap();
        assert_probe_row(&rows);
        transaction
            .into_admitted()
            .unwrap()
            .rollback()
            .await
            .unwrap();

        let admitted = pool.begin().await.unwrap();
        let mut transaction = PostgresTransaction::from_admitted(admitted, &schema).unwrap();
        transaction
            .execute(&insert_template(), &probe_bindings(), &control)
            .await
            .unwrap();
        let error = transaction
            .execute(&insert_template(), &probe_bindings(), &control)
            .await
            .unwrap_err();
        assert_eq!(error.category, ErrorCategory::UniqueViolation);
        assert!(transaction.into_admitted().is_err());
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {relation}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "failed Postgres transaction was not rolled back");

        let admitted = pool.begin().await.unwrap();
        let mut transaction = PostgresTransaction::from_admitted(admitted, &schema).unwrap();
        let cancelled = ExecutionControl::default();
        cancelled.cancel();
        let error = transaction
            .execute(&insert_template(), &probe_bindings(), &cancelled)
            .await
            .unwrap_err();
        assert_eq!(error.category, ErrorCategory::Cancelled);
        assert!(transaction.into_admitted().is_err());

        sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
}
