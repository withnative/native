//! Local-Turso `query_sql` safety provider over an isolated core projection.
//!
//! Caller SQL is never prepared against the authoritative Turso file. The
//! backend first materializes caller-visible logical rows into this bounded
//! in-memory database, enables core query-only mode, then validates and runs a
//! single SELECT under core progress, deadline, interrupt, row, and byte caps.

use std::collections::{BTreeMap, HashSet};
use std::num::NonZero;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Map, Number, Value};

use super::sql_contract::{
    self, QuerySqlErrorCategory, QuerySqlParameter, QuerySqlRequest, QuerySqlResult,
};
use crate::portable_sql::ExecutionControl;
use crate::portable_sql::{NormalizedRow, NormalizedValue};
use crate::{Error, Result};

use super::error::contract_violation;

pub(crate) const MAX_PROJECTION_ROWS: usize = 20_000;
pub(crate) const MAX_PROJECTION_ENCODED_BYTES: usize = 16 * 1024 * 1024;
const PROGRESS_OPS: u64 = 1_000;

fn turso_logical_relations() -> impl Iterator<Item = &'static sql_contract::QuerySqlRelationContract>
{
    let profile = sql_contract::QuerySqlProfile::TursoLocal.contract().id;
    sql_contract::LOGICAL_RELATIONS
        .iter()
        .filter(move |relation| relation.profiles.contains(&profile))
}

#[cfg(test)]
pub(crate) struct CoreWorkerProbe {
    started: Option<tokio::sync::oneshot::Sender<()>>,
    stopped: Option<tokio::sync::oneshot::Sender<bool>>,
    entry_release: Option<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
pub(crate) struct CoreWorkerControl {
    started: Option<tokio::sync::oneshot::Receiver<()>>,
    stopped: Option<tokio::sync::oneshot::Receiver<bool>>,
    entry_release: Option<std::sync::mpsc::Sender<()>>,
}

#[cfg(test)]
impl CoreWorkerProbe {
    pub(crate) fn new() -> (Self, CoreWorkerControl) {
        Self::with_entry_gate(None)
    }

    fn paused_at_entry() -> (Self, CoreWorkerControl) {
        let (release, wait_for_release) = std::sync::mpsc::channel();
        Self::with_entry_gate(Some((wait_for_release, release)))
    }

    fn with_entry_gate(
        entry_gate: Option<(std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>)>,
    ) -> (Self, CoreWorkerControl) {
        let (started, observe_started) = tokio::sync::oneshot::channel();
        let (stopped, observe_stopped) = tokio::sync::oneshot::channel();
        let (entry_release, release_entry) = entry_gate.unzip();
        (
            Self {
                started: Some(started),
                stopped: Some(stopped),
                entry_release,
            },
            CoreWorkerControl {
                started: Some(observe_started),
                stopped: Some(observe_stopped),
                entry_release: release_entry,
            },
        )
    }

    fn worker_started(&mut self) {
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.entry_release.take() {
            let _ = release.recv();
        }
    }

    fn worker_stopped(&mut self, observed_cancellation: bool) {
        if let Some(stopped) = self.stopped.take() {
            let _ = stopped.send(observed_cancellation);
        }
    }
}

#[cfg(test)]
impl CoreWorkerControl {
    pub(crate) async fn wait_started(&mut self) {
        self.started
            .as_mut()
            .expect("worker start may be observed only once")
            .await
            .expect("worker dropped before reporting its start");
        self.started = None;
    }

    pub(crate) async fn wait_stopped(&mut self) -> bool {
        let observed_cancellation = self
            .stopped
            .as_mut()
            .expect("worker stop may be observed only once")
            .await
            .expect("worker dropped without reporting its stop");
        self.stopped = None;
        observed_cancellation
    }

    fn try_stopped(&mut self) -> Option<bool> {
        self.stopped.as_mut()?.try_recv().ok()
    }

    fn release(&mut self) {
        if let Some(release) = self.entry_release.take() {
            let _ = release.send(());
        }
    }
}

#[cfg(test)]
impl Drop for CoreWorkerControl {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
struct ObservedCoreWorker {
    control: ExecutionControl,
    probe: CoreWorkerProbe,
}

#[cfg(test)]
impl ObservedCoreWorker {
    fn enter(control: ExecutionControl, probe: CoreWorkerProbe) -> Self {
        let mut worker = Self { control, probe };
        worker.probe.worker_started();
        worker
    }
}

#[cfg(test)]
impl Drop for ObservedCoreWorker {
    fn drop(&mut self) {
        self.probe.worker_stopped(self.control.is_cancelled());
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct IsolatedProjection {
    relations: BTreeMap<&'static str, Vec<NormalizedRow>>,
    row_count: usize,
    encoded_bytes: usize,
    /// Workspace content sequence observed inside the same backend snapshot
    /// the projection rows were materialized from (E1 M1 slice A). Carried
    /// through to every `QuerySqlResult` executed over this projection so
    /// rows and stamp share one snapshot.
    pub(crate) as_of_seq: i64,
}

impl IsolatedProjection {
    /// Remaining encoded projection space for a derived relation that must
    /// materialize rows outside the isolated core before insertion.
    pub(crate) fn remaining_encoded_bytes(&self) -> usize {
        MAX_PROJECTION_ENCODED_BYTES.saturating_sub(self.encoded_bytes)
    }

    pub(crate) fn insert(
        &mut self,
        relation: &'static str,
        rows: Vec<NormalizedRow>,
    ) -> Result<()> {
        let contract = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|candidate| candidate.name == relation)
            .ok_or_else(|| {
                contract_violation(format!("unknown query_sql projection '{relation}'"))
            })?;
        if self.relations.contains_key(relation) {
            return Err(contract_violation(format!(
                "duplicate query_sql projection '{relation}'"
            )));
        }
        for row in &rows {
            let actual = row.keys().map(String::as_str).collect::<HashSet<_>>();
            let expected = contract.columns.iter().copied().collect::<HashSet<_>>();
            if actual != expected {
                return Err(contract_violation(format!(
                    "query_sql projection '{relation}' column contract drift"
                )));
            }
        }
        // Lifecycle rows are a bounded, one-to-one interpretation of the
        // already counted visible records. Charging both copies against the
        // aggregate row ceiling would halve Turso's useful record capacity
        // for this relation. Encoded bytes still count in full below.
        if relation == "record_lifecycle_interpretations" && rows.len() > MAX_PROJECTION_ROWS {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::ResultTooLarge,
                format!("lifecycle projection exceeds the {MAX_PROJECTION_ROWS}-row limit"),
            ));
        }
        if relation != "record_lifecycle_interpretations" {
            self.row_count = self.row_count.saturating_add(rows.len());
        }
        if self.row_count > MAX_PROJECTION_ROWS {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::ResultTooLarge,
                format!("caller-visible projection exceeds the {MAX_PROJECTION_ROWS}-row limit"),
            ));
        }
        self.encoded_bytes = self
            .encoded_bytes
            .saturating_add(serde_json::to_vec(&rows)?.len());
        if self.encoded_bytes > MAX_PROJECTION_ENCODED_BYTES {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::ResultTooLarge,
                format!(
                    "caller-visible projection exceeds the {MAX_PROJECTION_ENCODED_BYTES}-byte encoded limit"
                ),
            ));
        }
        self.relations.insert(relation, rows);
        Ok(())
    }

    fn complete(&self) -> Result<()> {
        if let Some(missing) =
            turso_logical_relations().find(|relation| !self.relations.contains_key(relation.name))
        {
            return Err(contract_violation(format!(
                "query_sql projection omitted logical relation '{}'",
                missing.name
            )));
        }
        Ok(())
    }
}

struct CoreProjection {
    connection: Arc<turso::core::Connection>,
    control: ExecutionControl,
    as_of_seq: i64,
}

impl CoreProjection {
    fn build(projection: IsolatedProjection, control: ExecutionControl) -> Result<Self> {
        projection.complete()?;
        let io: Arc<dyn turso::core::IO> = Arc::new(turso::core::MemoryIO::new());
        let database = turso::core::Database::open(
            io,
            ":memory:",
            turso::core::OpenOptions::new(Arc::new(turso::core::SqliteDialect))
                .flags(turso::core::OpenFlags::Create)
                .db_opts(
                    turso::core::DatabaseOpts::new()
                        .with_attach(false)
                        .with_views(false)
                        .with_vacuum(false),
                ),
        )
        .map_err(|error| contract_violation(format!("open isolated Turso projection: {error}")))?;
        let connection = database.connect().map_err(|error| {
            contract_violation(format!("connect isolated Turso projection: {error}"))
        })?;
        if control.is_cancelled() || control.deadline_expired() {
            return Err(control_error(&control));
        }
        connection.set_query_timeout(
            control
                .remaining()
                .unwrap_or(Duration::from_millis(sql_contract::QUERY_DEADLINE_MS)),
        );
        let observed = control.clone();
        connection.set_progress_handler(
            PROGRESS_OPS,
            Some(Box::new(move || {
                observed.is_cancelled() || observed.deadline_expired()
            })),
        );
        connection
            .execute(super::sql::STRICT_LOGICAL_SCHEMA)
            .map_err(core_step_error)?;
        for relation in turso_logical_relations() {
            if control.is_cancelled() || control.deadline_expired() {
                return Err(control_error(&control));
            }
            let rows = projection
                .relations
                .get(relation.name)
                .expect("complete projection checked");
            let placeholders = (1..=relation.columns.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "INSERT INTO {} ({}) VALUES ({placeholders})",
                relation.name,
                relation.columns.join(",")
            );
            for row in rows {
                if control.is_cancelled() || control.deadline_expired() {
                    return Err(control_error(&control));
                }
                let mut statement = connection.prepare(&sql).map_err(|error| {
                    contract_violation(format!("prepare isolated Turso projection row: {error}"))
                })?;
                for (index, column) in relation.columns.iter().enumerate() {
                    statement
                        .bind_at(
                            NonZero::new(index + 1).expect("one-based parameter"),
                            core_value(row.get(*column).expect("projection columns checked"))?,
                        )
                        .map_err(|error| {
                            contract_violation(format!(
                                "bind isolated Turso projection row: {error}"
                            ))
                        })?;
                }
                drain(&database, &mut statement).map_err(core_step_error)?;
            }
        }
        connection.set_query_only(true);
        Ok(Self {
            connection,
            control,
            as_of_seq: projection.as_of_seq,
        })
    }

    fn execute(
        &self,
        request: QuerySqlRequest,
        apply_default_order: bool,
    ) -> Result<QuerySqlResult> {
        if self.control.is_cancelled() || self.control.deadline_expired() {
            return Err(control_error(&self.control));
        }
        request.validate()?;
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::TursoLocal,
            &request.sql,
        )?;
        // E2 ad-hoc default ORDER BY: enabled only when the caller passes
        // `apply_default_order` (the ad-hoc `query_sql` entry does; probes
        // and any future non-ad-hoc caller leave it off). Splice before
        // validation so the validator below runs once, on the final text.
        let (statement, assumed_order) = if apply_default_order {
            self.splice_default_order(&statement)?
        } else {
            (statement, None)
        };
        super::turso_validate::validate(&statement)?;
        // I1 review: the `?N` set has to be exactly
        // `1..=parameters.len()`; positional binding would otherwise
        // shift gapped numbers silently.
        sql_contract::check_positional_arguments(
            sql_contract::QuerySqlProfile::TursoLocal,
            &statement,
            request.parameters.len(),
        )?;
        // E1 M3: bound `?N` regexp patterns meet the same subset and cap
        // as literals before the isolated projection evaluates them.
        sql_contract::validate_regexp_bound_patterns(
            sql_contract::QuerySqlProfile::TursoLocal,
            &statement,
            &request.parameters,
        )?;
        // Native e25665c: bound `?N` label arguments meet the integer
        // contract before the isolated projection evaluates them.
        sql_contract::validate_utc_date_label_bound_args(
            sql_contract::QuerySqlProfile::TursoLocal,
            &statement,
            &request.parameters,
        )?;
        // E1 M3: every `now_ms()` becomes one hidden positional
        // (`?{parameters.len() + 1}`), shared by every use in the
        // statement. The exact-set check above already refused any caller
        // use of that index, so the hidden value is unspoofable. Captured
        // once per statement here at admission: the projection's
        // `as_of_seq` was fixed at snapshot build, and this is the
        // statement's own admission moment.
        let hidden_index = request.parameters.len() + 1;
        let (statement, now_ms_uses) = sql_contract::rewrite_now_ms_calls(
            sql_contract::QuerySqlProfile::TursoLocal,
            &statement,
            &format!("?{hidden_index}"),
        )?;
        // Native e25665c: lower `utc_date_label(ms)` to the Turso
        // `strftime(..., 'unixepoch')` expression (same spelling as SQLite;
        // Turso core 0.7.2 implements the same date primitives). Runs after
        // validation, introduces no placeholder, exposes no engine clock.
        let (statement, _) = sql_contract::rewrite_utc_date_label_calls(
            sql_contract::QuerySqlProfile::TursoLocal,
            &statement,
            sql_contract::UtcDateLabelEngine::Sqlite,
        )?;
        let time_dependent = now_ms_uses > 0;
        let now_ms_ms: Option<i64> = time_dependent.then(|| chrono::Utc::now().timestamp_millis());
        let mut effective_parameters = request.parameters.clone();
        if let Some(now_ms) = now_ms_ms {
            effective_parameters.push(QuerySqlParameter::Integer {
                value: Some(now_ms.to_string()),
            });
        }
        // Defensive: the rewritten placeholders must be exactly
        // `1..=effective.len()`, or the rewrite disagreed with the bind.
        sql_contract::check_positional_arguments(
            sql_contract::QuerySqlProfile::TursoLocal,
            &statement,
            effective_parameters.len(),
        )?;
        // NOTE: this wraps every classified statement as a subquery operand.
        // The Turso validator admits SELECT only today, so this is total. If
        // that parser ever admits EXPLAIN QUERY PLAN, a canonical
        // "EXPLAIN QUERY PLAN ..." statement must bypass this wrapper (as
        // src/query/sql.rs::cap_statement does for sqlite-local); wrapping it
        // here would produce invalid SQL.
        let capped = format!(
            "SELECT * FROM ({statement}) LIMIT {}",
            sql_contract::MAX_ROWS + 1
        );
        let mut statement = self.connection.prepare(&capped).map_err(|error| {
            let detail = error.to_string();
            // E1 M2 I6: name the valid columns when a known logical relation
            // is read with an unknown column. Rewords an already-rejected
            // prepare; the shared contract repair keeps the message identical
            // on every engine by construction.
            if let Some(column) = sql_contract::unknown_column_in_detail(&detail) {
                let scope = sql_contract::statement_scope(&request.sql);
                let relations: Vec<&str> =
                    sql_contract::resolve_column_scope(column.as_str(), &scope);
                if let Some(repair) = sql_contract::unknown_column_repair(
                    column.as_str(),
                    &relations,
                    sql_contract::QuerySqlProfile::TursoLocal,
                ) {
                    return sql_contract::categorized_error(
                        QuerySqlErrorCategory::SyntaxOrType,
                        sql_contract::join_detail_repair(&detail, &repair),
                    );
                }
            }
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, detail)
        })?;
        if self.control.is_cancelled() || self.control.deadline_expired() {
            return Err(control_error(&self.control));
        }
        if !statement.get_program().is_readonly() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "Turso core compiled a non-read-only program",
            ));
        }
        if statement.tail_offset() < capped.len()
            && !capped[statement.tail_offset()..].trim().is_empty()
        {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "a single statement only",
            ));
        }
        if statement.parameters_count() != effective_parameters.len() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::InvalidArguments,
                format!(
                    "statement expects {} parameters, received {}",
                    statement.parameters_count(),
                    effective_parameters.len()
                ),
            ));
        }
        for (index, parameter) in effective_parameters.iter().enumerate() {
            statement
                .bind_at(
                    NonZero::new(index + 1).expect("one-based parameter"),
                    parameter_value(parameter)?,
                )
                .map_err(|error| {
                    sql_contract::categorized_error(
                        QuerySqlErrorCategory::InvalidArguments,
                        error.to_string(),
                    )
                })?;
        }

        let columns = (0..statement.num_columns())
            .map(|index| statement.get_column_name(index).into_owned())
            .collect::<Vec<_>>();
        if columns.len() > sql_contract::MAX_COLUMNS {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::ResultTooLarge,
                format!(
                    "result exceeds the {}-column limit",
                    sql_contract::MAX_COLUMNS
                ),
            ));
        }
        let mut unique = HashSet::new();
        if let Some(duplicate) = columns
            .iter()
            .find(|column| !unique.insert(column.as_str()))
        {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::DuplicateColumns,
                format!("duplicate output column label '{duplicate}'"),
            ));
        }

        collect_rows(
            &mut statement,
            &columns,
            self.as_of_seq,
            now_ms_ms,
            time_dependent,
            assumed_order,
        )
    }

    /// E2 ad-hoc default ORDER BY: when the top-level statement carries LIMIT
    /// with no ORDER BY, splice `ORDER BY 1, .., n` (labels from a
    /// describe-only prepare, which also expands `SELECT *`) and report the
    /// assumption for disclosure. A prepare failure falls through to the
    /// validator's precise refusal below; nested unordered LIMITs keep their
    /// refusal in `validate()`, which runs on the rewritten text.
    fn splice_default_order(
        &self,
        statement: &str,
    ) -> Result<(String, Option<sql_contract::AssumedOrder>)> {
        if !super::turso_ast_rules::top_level_unordered_limit(statement) {
            return Ok((statement.to_owned(), None));
        }
        let probe = match self.connection.prepare(statement) {
            Ok(prepared) => prepared,
            Err(_) => return Ok((statement.to_owned(), None)),
        };
        let labels = (0..probe.num_columns())
            .map(|index| probe.get_column_name(index).into_owned())
            .collect::<Vec<_>>();
        match sql_contract::apply_default_order(
            sql_contract::QuerySqlProfile::TursoLocal,
            statement,
            &labels,
        ) {
            Some((rewritten, assumed)) => Ok((rewritten, Some(assumed))),
            None => Ok((statement.to_owned(), None)),
        }
    }
}

pub(crate) fn execute(
    projection: IsolatedProjection,
    request: QuerySqlRequest,
    control: ExecutionControl,
    apply_default_order: bool,
) -> Result<QuerySqlResult> {
    CoreProjection::build(projection, control)?.execute(request, apply_default_order)
}

#[cfg(test)]
pub(crate) fn execute_with_probe(
    projection: IsolatedProjection,
    request: QuerySqlRequest,
    control: ExecutionControl,
    probe: CoreWorkerProbe,
    apply_default_order: bool,
) -> Result<QuerySqlResult> {
    let _worker = ObservedCoreWorker::enter(control.clone(), probe);
    execute(projection, request, control, apply_default_order)
}

pub(crate) fn control_error(control: &ExecutionControl) -> Error {
    sql_contract::categorized_error(
        QuerySqlErrorCategory::Timeout,
        if control.is_cancelled() {
            String::from("Turso query_sql was cancelled")
        } else {
            sql_contract::deadline_hint()
        },
    )
}

fn collect_rows(
    statement: &mut turso::core::Statement,
    columns: &[String],
    as_of_seq: i64,
    now_ms_ms: Option<i64>,
    time_dependent: bool,
    assumed_order: Option<sql_contract::AssumedOrder>,
) -> Result<QuerySqlResult> {
    let mut rows = Vec::new();
    let mut encoded_bytes = serde_json::to_vec(columns)?.len().saturating_add(2);
    loop {
        match statement.step().map_err(core_step_error)? {
            turso::core::StepResult::Row => {
                if rows.len() == sql_contract::MAX_ROWS {
                    return Ok(QuerySqlResult {
                        columns: columns.to_vec(),
                        row_count: rows.len(),
                        rows,
                        truncated: true,
                        truncation_hint: Some(sql_contract::truncation_hint()),
                        as_of_seq,
                        now_ms_ms,
                        time_dependent,
                        assumed_order: assumed_order.clone(),
                    });
                }
                let row = statement
                    .row()
                    .ok_or_else(|| contract_violation("Turso returned Row without row data"))?;
                let mut object = Map::new();
                for (column, value) in columns.iter().zip(row.get_values()) {
                    object.insert(column.clone(), json_value(value)?);
                }
                let value = Value::Object(object);
                encoded_bytes = encoded_bytes
                    .saturating_add(serde_json::to_vec(&value)?.len())
                    .saturating_add(1);
                if encoded_bytes > sql_contract::MAX_RESULT_ENCODED_BYTES {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::ResultTooLarge,
                        format!(
                            "encoded result exceeds the {}-byte limit",
                            sql_contract::MAX_RESULT_ENCODED_BYTES
                        ),
                    ));
                }
                rows.push(value);
            }
            // Upstream canonical-loop behavior: drive the event loop and step
            // again, never sleep. No busy handler is installed in this
            // isolated configuration, so Sleep is unreachable; the arm keeps
            // the match exhaustive against future engine variants.
            turso::core::StepResult::IO
            | turso::core::StepResult::Yield
            | turso::core::StepResult::Sleep { .. } => statement
                ._io()
                .step()
                .map_err(|error| contract_violation(format!("step isolated Turso I/O: {error}")))?,
            turso::core::StepResult::Done => {
                return Ok(QuerySqlResult {
                    columns: columns.to_vec(),
                    row_count: rows.len(),
                    rows,
                    truncated: false,
                    truncation_hint: None,
                    as_of_seq,
                    now_ms_ms,
                    time_dependent,
                    assumed_order,
                })
            }
            turso::core::StepResult::Interrupt => {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::Timeout,
                    sql_contract::deadline_hint(),
                ))
            }
            turso::core::StepResult::Busy => {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::Timeout,
                    "Turso storage is busy holding a conflicting lock; retry the read",
                ))
            }
        }
    }
}

fn drain(
    database: &turso::core::Database,
    statement: &mut turso::core::Statement,
) -> turso::core::Result<()> {
    loop {
        match statement.step()? {
            // Same upstream canonical-loop behavior as above: no busy handler
            // installed, so Sleep is unreachable; the arm stays exhaustive.
            turso::core::StepResult::IO
            | turso::core::StepResult::Yield
            | turso::core::StepResult::Sleep { .. } => {
                let _ = database;
                statement._io().step()?
            }
            turso::core::StepResult::Row => {}
            turso::core::StepResult::Done => return Ok(()),
            turso::core::StepResult::Interrupt | turso::core::StepResult::Busy => {
                return Err(turso::core::LimboError::Busy)
            }
        }
    }
}

fn core_value(value: &NormalizedValue) -> Result<turso::core::Value> {
    Ok(match value {
        NormalizedValue::Null => turso::core::Value::Null,
        NormalizedValue::Bool(value) => turso::core::Value::from_i64(i64::from(*value)),
        NormalizedValue::Integer(value) => turso::core::Value::from_i64(*value),
        NormalizedValue::Real(value) if value.is_finite() => turso::core::Value::from_f64(*value),
        NormalizedValue::Real(_) => {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::SyntaxOrType,
                "projection contains a non-finite real value",
            ))
        }
        NormalizedValue::Text(value) | NormalizedValue::Timestamp(value) => {
            turso::core::Value::build_text(value.clone())
        }
        NormalizedValue::Bytes(value) => turso::core::Value::Blob(value.clone()),
        NormalizedValue::Json(value) => {
            turso::core::Value::build_text(serde_json::to_string(value)?)
        }
    })
}

fn parameter_value(parameter: &QuerySqlParameter) -> Result<turso::core::Value> {
    Ok(match parameter {
        QuerySqlParameter::Boolean { value } => value
            .map(|value| turso::core::Value::from_i64(i64::from(value)))
            .unwrap_or(turso::core::Value::Null),
        QuerySqlParameter::Integer { value } => value
            .as_deref()
            .map(str::parse::<i64>)
            .transpose()
            .map_err(|_| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "integer parameter must be a signed 64-bit decimal string",
                )
            })?
            .map(turso::core::Value::from_i64)
            .unwrap_or(turso::core::Value::Null),
        QuerySqlParameter::Real { value } => value
            .map(turso::core::Value::from_f64)
            .unwrap_or(turso::core::Value::Null),
        QuerySqlParameter::Text { value }
        | QuerySqlParameter::Json { value }
        | QuerySqlParameter::Timestamp { value } => value
            .as_ref()
            .map(|value| turso::core::Value::build_text(value.clone()))
            .unwrap_or(turso::core::Value::Null),
        QuerySqlParameter::Bytes { value } => value
            .as_deref()
            .map(|value| base64::engine::general_purpose::STANDARD.decode(value))
            .transpose()
            .map_err(|_| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "bytes parameter must be canonical base64",
                )
            })?
            .map(turso::core::Value::Blob)
            .unwrap_or(turso::core::Value::Null),
    })
}

fn json_value(value: &turso::core::Value) -> Result<Value> {
    let value = match value {
        turso::core::Value::Null => Value::Null,
        turso::core::Value::Numeric(turso::core::Numeric::Integer(value)) => {
            Value::Number((*value).into())
        }
        turso::core::Value::Numeric(turso::core::Numeric::Float(value)) => {
            let value: f64 = (*value).into();
            Value::Number(Number::from_f64(value).ok_or_else(|| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "Turso returned a non-finite real value",
                )
            })?)
        }
        turso::core::Value::Text(value) => Value::String(value.as_str().to_string()),
        turso::core::Value::Blob(value) => {
            Value::String(base64::engine::general_purpose::STANDARD.encode(value))
        }
    };
    if serde_json::to_vec(&value)?.len() > sql_contract::MAX_CELL_ENCODED_BYTES {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            format!(
                "a cell exceeds the {}-byte encoded limit.{}",
                sql_contract::MAX_CELL_ENCODED_BYTES,
                sql_contract::projection_cell_cap_repair()
            ),
        ));
    }
    Ok(value)
}

fn core_step_error(error: turso::core::LimboError) -> Error {
    let detail = error.to_string();
    let category = if detail.to_ascii_lowercase().contains("interrupt")
        || detail.to_ascii_lowercase().contains("busy")
    {
        QuerySqlErrorCategory::Timeout
    } else {
        QuerySqlErrorCategory::SyntaxOrType
    };
    sql_contract::categorized_error(category, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection_with_records(records: Vec<NormalizedRow>) -> IsolatedProjection {
        let mut projection = IsolatedProjection::default();
        for relation in turso_logical_relations() {
            projection
                .insert(
                    relation.name,
                    if relation.name == "records" {
                        records.clone()
                    } else {
                        Vec::new()
                    },
                )
                .unwrap();
        }
        projection
    }

    fn record(id: &str, body: &str) -> NormalizedRow {
        let relation = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "records")
            .unwrap();
        let mut row = relation
            .columns
            .iter()
            .map(|column| ((*column).to_string(), NormalizedValue::Null))
            .collect::<NormalizedRow>();
        row.insert("id".into(), NormalizedValue::Text(id.into()));
        row.insert("type".into(), NormalizedValue::Text("Document".into()));
        row.insert("body".into(), NormalizedValue::Text(body.into()));
        row
    }

    fn request(sql: impl Into<String>) -> QuerySqlRequest {
        QuerySqlRequest {
            sql: sql.into(),
            parameters: Vec::new(),
        }
    }

    #[test]
    fn isolated_projection_executes_typed_read_and_parameters() {
        let result = execute(
            projection_with_records(vec![record("visible", "hello")]),
            QuerySqlRequest {
                sql: "SELECT id, body FROM records WHERE id=?1".into(),
                parameters: vec![QuerySqlParameter::Text {
                    value: Some("visible".into()),
                }],
            },
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap();
        assert_eq!(result.columns, ["id", "body"]);
        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0]["id"], "visible");
        assert!(!result.truncated);
        assert_eq!(result.truncation_hint, None);
    }

    #[test]
    fn isolated_now_ms_two_uses_agree_and_stamp_matches() {
        // E1 M3 cross-engine twin of the SQLite agreement test: one
        // statement-fixed value per statement, stamped beside `as_of_seq`.
        let result = execute(
            projection_with_records(vec![record("visible", "hello")]),
            request("SELECT now_ms() AS a, now_ms() AS b"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap();
        assert!(result.time_dependent);
        let stamp = result.now_ms_ms.expect("now_ms() must stamp the result");
        assert_eq!(result.rows[0]["a"].as_i64().unwrap(), stamp);
        assert_eq!(result.rows[0]["b"].as_i64().unwrap(), stamp);
        let skewed = (chrono::Utc::now().timestamp_millis() - stamp).abs();
        assert!(skewed < 60_000, "stamp {stamp} is too far from now");
        // Clock-free statements carry no stamp, exactly as before.
        let plain = execute(
            projection_with_records(vec![record("visible", "hello")]),
            request("SELECT id FROM records"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap();
        assert!(!plain.time_dependent);
        assert_eq!(plain.now_ms_ms, None);
    }

    #[test]
    fn isolated_now_ms_refuses_spoofed_and_keyword_clocks() {
        // E1 M3: the hidden index is unspoofable and keyword clocks fail
        // with the portable repair on this engine too.
        for (sql, parameters) in [
            (
                "SELECT ?2, now_ms()",
                vec![QuerySqlParameter::Text {
                    value: Some("visible".into()),
                }],
            ),
            (
                "SELECT now_ms()",
                vec![QuerySqlParameter::Text {
                    value: Some("visible".into()),
                }],
            ),
        ] {
            let error = execute(
                projection_with_records(Vec::new()),
                QuerySqlRequest {
                    sql: sql.into(),
                    parameters,
                },
                ExecutionControl::with_timeout(Duration::from_secs(2)),
                false,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("must match exactly"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        for sql in [
            "SELECT CURRENT_TIMESTAMP AS t",
            "SELECT current_date AS t FROM records",
        ] {
            let error = execute(
                projection_with_records(Vec::new()),
                request(sql),
                ExecutionControl::with_timeout(Duration::from_secs(2)),
                false,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("now_ms()"), "{sql}: {error}");
        }
    }

    #[test]
    fn truncated_results_carry_the_keyset_hint() {
        let rows = (0..1001)
            .map(|index| record(&format!("bulk:{index:04}"), "body"))
            .collect::<Vec<_>>();
        let result = execute(
            projection_with_records(rows),
            request("SELECT id FROM records ORDER BY id"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap();
        assert!(result.truncated);
        assert_eq!(result.row_count, sql_contract::MAX_ROWS);
        assert_eq!(
            result.truncation_hint,
            Some(sql_contract::truncation_hint())
        );
    }

    #[test]
    fn isolated_projection_enforces_output_contract() {
        let duplicate = execute(
            projection_with_records(Vec::new()),
            request("SELECT 1 AS duplicate, 2 AS duplicate"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("duplicate_columns"));

        let columns = (0..=sql_contract::MAX_COLUMNS)
            .map(|index| format!("{index} AS c{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let too_many = execute(
            projection_with_records(Vec::new()),
            request(format!("SELECT {columns}")),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(too_many.contains("result_too_large"));

        let oversized = execute(
            projection_with_records(vec![record(
                "visible",
                &"x".repeat(sql_contract::MAX_CELL_ENCODED_BYTES + 1),
            )]),
            request("SELECT body FROM records"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(oversized.contains("result_too_large"));
    }

    #[test]
    fn unknown_column_names_that_relations_columns() {
        let error = execute(
            projection_with_records(vec![record("visible", "hello")]),
            request("SELECT titel FROM records"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "query_sql [syntax_or_type]: Parse error: no such column: titel. \
             Hint: valid columns of records are id, type, kind, name, body, home_id, lifecycle, \
             persistence, maturity, summary, is_current, successor_count … (21 total). \
             Full list: SELECT column_name FROM catalog_columns \
             WHERE relation_name = 'records' ORDER BY column_position."
        );

        let joined = execute(
            projection_with_records(vec![record("visible", "hello")]),
            request("SELECT titel FROM records JOIN links ON links.target_id = records.id"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            joined.contains("is not a column of any relation in scope"),
            "{joined}"
        );
        assert!(joined.contains("Valid columns of records are "), "{joined}");
        assert!(joined.contains("valid columns of links are "), "{joined}");
        assert!(
            joined.contains("WHERE relation_name IN ('records', 'links')"),
            "{joined}"
        );
    }

    #[test]
    fn projection_caps_are_atomic() {
        let mut projection = IsolatedProjection::default();
        let rows = (0..=MAX_PROJECTION_ROWS)
            .map(|index| record(&format!("r{index}"), ""))
            .collect();
        let error = projection.insert("records", rows).unwrap_err().to_string();
        assert!(error.contains("result_too_large"));
        assert!(!projection.relations.contains_key("records"));
    }

    #[test]
    fn lifecycle_rows_do_not_double_charge_visible_record_count() {
        let mut projection = IsolatedProjection::default();
        projection
            .insert("records", vec![record("r1", "")])
            .unwrap();
        let relation = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "record_lifecycle_interpretations")
            .unwrap();
        let mut lifecycle = relation
            .columns
            .iter()
            .map(|column| ((*column).to_string(), NormalizedValue::Null))
            .collect::<NormalizedRow>();
        lifecycle.insert("record_id".into(), NormalizedValue::Text("r1".into()));
        lifecycle.insert("status".into(), NormalizedValue::Text("absent".into()));
        projection
            .insert("record_lifecycle_interpretations", vec![lifecycle])
            .unwrap();
        assert_eq!(projection.row_count, 1);
        assert!(projection.encoded_bytes > 0);
    }

    #[test]
    fn cancellation_stops_projection_construction_within_bound() {
        let records = (0..MAX_PROJECTION_ROWS)
            .map(|index| record(&format!("cancel-{index}"), "payload"))
            .collect();
        let projection = projection_with_records(records);
        let control = ExecutionControl::default();
        let cancellation = control.clone();
        let (probe, mut observation) = CoreWorkerProbe::new();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancellation.cancel();
        });
        let started = std::time::Instant::now();
        let error = execute_with_probe(
            projection,
            request("SELECT count(*) AS n FROM records"),
            control,
            probe,
            false,
        )
        .unwrap_err()
        .to_string();
        canceller.join().unwrap();
        assert!(error.contains("timeout"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(observation.try_stopped(), Some(true));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_entry_control_before_worker_arrives_never_blocks() {
        let (probe, control) = CoreWorkerProbe::paused_at_entry();
        let mut drop_control = tokio::task::spawn_blocking(move || drop(control));
        let released_before_worker =
            match tokio::time::timeout(Duration::from_secs(1), &mut drop_control).await {
                Ok(result) => {
                    result.unwrap();
                    true
                }
                Err(_) => false,
            };

        let worker = tokio::task::spawn_blocking(move || {
            execute_with_probe(
                projection_with_records(Vec::new()),
                request("SELECT count(*) AS n FROM records"),
                ExecutionControl::default(),
                probe,
                false,
            )
        });
        let result = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("worker consumed the pre-sent entry release")
            .unwrap();
        if !released_before_worker {
            drop_control.await.unwrap();
        }
        assert!(
            released_before_worker,
            "dropping a test control must not rendezvous with a worker that has not started"
        );
        result.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn per_invocation_probe_ignores_unrelated_worker_before_own_start() {
        let (unrelated_probe, mut unrelated) = CoreWorkerProbe::paused_at_entry();
        let unrelated_control = ExecutionControl::default();
        let unrelated_worker = tokio::task::spawn_blocking(move || {
            execute_with_probe(
                projection_with_records(Vec::new()),
                request("SELECT count(*) AS n FROM records"),
                unrelated_control,
                unrelated_probe,
                false,
            )
        });
        tokio::time::timeout(Duration::from_secs(1), unrelated.wait_started())
            .await
            .expect("unrelated worker reached its deterministic entry gate");

        let (target_probe, mut target) = CoreWorkerProbe::paused_at_entry();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), target.wait_started())
                .await
                .is_err(),
            "an unrelated active worker must not satisfy the target invocation's probe"
        );
        let target_control = ExecutionControl::default();
        let target_cancellation = target_control.clone();
        let target_worker = tokio::task::spawn_blocking(move || {
            execute_with_probe(
                projection_with_records(Vec::new()),
                request("SELECT count(*) AS n FROM records"),
                target_control,
                target_probe,
                false,
            )
        });
        tokio::time::timeout(Duration::from_secs(1), target.wait_started())
            .await
            .expect("target invocation reached its own worker");
        target_cancellation.cancel();
        target.release();
        let target_error = target_worker.await.unwrap().unwrap_err().to_string();
        assert!(target_error.contains("timeout"), "{target_error}");
        let observed_cancellation =
            tokio::time::timeout(Duration::from_secs(1), target.wait_stopped())
                .await
                .expect("target worker reported its own stop");
        assert!(observed_cancellation);
        assert!(
            unrelated.try_stopped().is_none(),
            "the target proof must not depend on the unrelated worker stopping"
        );

        unrelated.release();
        unrelated_worker.await.unwrap().unwrap();
    }

    #[test]
    fn isolated_projection_utc_date_label_matches_contract_vectors() {
        // Native e25665c Turso spike + parity: the isolated core projection
        // evaluates the `strftime(..., 'unixepoch')` lowering with the same
        // vectors as SQLite (epoch, negatives, boundaries, leap, NULL, and
        // both supported-range bounds). Turso core 0.7.2 implements the
        // SQLite date primitives (`functions/datetime.rs`); this test pins
        // the agreement inside the supported UTC years 0000–9999.
        for (ms, expected) in [
            ("0", "Thu 1 Jan"),
            ("-1", "Wed 31 Dec"),
            ("-86400000", "Wed 31 Dec"),
            ("1790294400000", "Fri 25 Sep"),
            ("1790294399999", "Thu 24 Sep"),
            ("1709164800000", "Thu 29 Feb"),
            ("1790380799999", "Fri 25 Sep"),
            ("1790380800000", "Sat 26 Sep"),
            ("-62167219200000", "Sat 1 Jan"),
            ("253402300799999", "Fri 31 Dec"),
        ] {
            let result = execute(
                projection_with_records(vec![record("visible", "hello")]),
                QuerySqlRequest {
                    sql: "SELECT utc_date_label(?1) AS label".into(),
                    parameters: vec![QuerySqlParameter::Integer {
                        value: Some(ms.into()),
                    }],
                },
                ExecutionControl::with_timeout(Duration::from_secs(2)),
                false,
            )
            .unwrap();
            assert_eq!(
                result.rows[0]["label"],
                Value::String(expected.into()),
                "ms={ms}"
            );
        }
        let null = execute(
            projection_with_records(vec![record("visible", "hello")]),
            request("SELECT utc_date_label(NULL) AS label"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap();
        assert_eq!(null.rows[0]["label"], Value::Null);
        for sql in [
            "SELECT utc_date_label() AS label",
            "SELECT utc_date_label(1, 2) AS label",
        ] {
            let error = execute(
                projection_with_records(vec![record("visible", "hello")]),
                request(sql),
                ExecutionControl::with_timeout(Duration::from_secs(2)),
                false,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("exactly one argument"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        // Text inputs are refused with the integer repair, mirroring
        // SQLite: no per-engine coercion fork.
        let error = execute(
            projection_with_records(vec![record("visible", "hello")]),
            request("SELECT utc_date_label('abc') AS label"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("integer epoch milliseconds"),
            "unexpected refusal: {error}"
        );
        let error = execute(
            projection_with_records(vec![record("visible", "hello")]),
            QuerySqlRequest {
                sql: "SELECT utc_date_label(?1) AS label".into(),
                parameters: vec![QuerySqlParameter::Text {
                    value: Some("abc".into()),
                }],
            },
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("integer epoch milliseconds"),
            "unexpected refusal: {error}"
        );
        // Out-of-range extremes are outside the portable contract and no
        // behavior is pinned here by design: past 9999 Turso keeps
        // labelling (measured `Sat 1 Jan` for 10000-01-01) while SQLite
        // yields NULL and Postgres raises. The supported UTC years are
        // 0000–9999; the bounds themselves are pinned in the vector loop
        // above.
    }

    #[test]
    fn isolated_projection_regexp_matches_and_rejects() {
        // E1 M3: the Turso builtin needs no registration. Literal patterns
        // take the validator subset path; bound `?N` patterns are validated
        // against the same rules at execution, before the projection runs —
        // an invalid bound pattern is rejected with the repair instead of
        // reaching the engine (which would yield NULL).
        let result = execute(
            projection_with_records(vec![record("visible", "hello world")]),
            request(
                "SELECT regexp('hello', body) AS hit, regexp('zzz', body) AS miss FROM records WHERE id='visible'",
            ),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
            false,
        )
        .unwrap();
        assert_eq!(result.rows[0]["hit"], 1);
        assert_eq!(result.rows[0]["miss"], 0);
        for (pattern, repair) in [
            (
                QuerySqlParameter::Text {
                    value: Some("(?=".into()),
                },
                "outside the portable subset",
            ),
            (
                QuerySqlParameter::Integer {
                    value: Some("3".into()),
                },
                "must be text",
            ),
        ] {
            let error = execute(
                projection_with_records(vec![record("visible", "hello world")]),
                QuerySqlRequest {
                    sql: "SELECT regexp(?1, body) AS hit FROM records WHERE id='visible'".into(),
                    parameters: vec![pattern],
                },
                ExecutionControl::with_timeout(Duration::from_secs(2)),
                false,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(repair), "unexpected refusal: {error}");
        }
    }
}
