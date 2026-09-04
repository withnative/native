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
}

impl IsolatedProjection {
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
        self.row_count = self.row_count.saturating_add(rows.len());
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
}

impl CoreProjection {
    fn build(projection: IsolatedProjection, control: ExecutionControl) -> Result<Self> {
        projection.complete()?;
        let io: Arc<dyn turso::core::IO> = Arc::new(turso::core::MemoryIO::new());
        let database = turso::core::Database::open_file_with_flags(
            io,
            ":memory:",
            turso::core::OpenFlags::Create,
            turso::core::DatabaseOpts::new()
                .with_attach(false)
                .with_views(false)
                .with_vacuum(false),
            None,
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
        })
    }

    fn execute(&self, request: QuerySqlRequest) -> Result<QuerySqlResult> {
        if self.control.is_cancelled() || self.control.deadline_expired() {
            return Err(control_error(&self.control));
        }
        request.validate()?;
        super::turso_validate::validate(&request.sql)?;
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::TursoLocal,
            &request.sql,
        )?;
        let capped = format!(
            "SELECT * FROM ({statement}) LIMIT {}",
            sql_contract::MAX_ROWS + 1
        );
        let mut statement = self.connection.prepare(&capped).map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
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
        if statement.parameters_count() != request.parameters.len() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::InvalidArguments,
                format!(
                    "statement expects {} parameters, received {}",
                    statement.parameters_count(),
                    request.parameters.len()
                ),
            ));
        }
        for (index, parameter) in request.parameters.iter().enumerate() {
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

        collect_rows(&mut statement, &columns)
    }
}

pub(crate) fn execute(
    projection: IsolatedProjection,
    request: QuerySqlRequest,
    control: ExecutionControl,
) -> Result<QuerySqlResult> {
    CoreProjection::build(projection, control)?.execute(request)
}

#[cfg(test)]
pub(crate) fn execute_with_probe(
    projection: IsolatedProjection,
    request: QuerySqlRequest,
    control: ExecutionControl,
    probe: CoreWorkerProbe,
) -> Result<QuerySqlResult> {
    let _worker = ObservedCoreWorker::enter(control.clone(), probe);
    execute(projection, request, control)
}

fn control_error(control: &ExecutionControl) -> Error {
    sql_contract::categorized_error(
        QuerySqlErrorCategory::Timeout,
        if control.is_cancelled() {
            "Turso query_sql was cancelled"
        } else {
            "Turso query_sql exceeded its absolute deadline"
        },
    )
}

fn collect_rows(
    statement: &mut turso::core::Statement,
    columns: &[String],
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
            turso::core::StepResult::IO | turso::core::StepResult::Yield => statement
                ._io()
                .step()
                .map_err(|error| contract_violation(format!("step isolated Turso I/O: {error}")))?,
            turso::core::StepResult::Done => {
                return Ok(QuerySqlResult {
                    columns: columns.to_vec(),
                    row_count: rows.len(),
                    rows,
                    truncated: false,
                })
            }
            turso::core::StepResult::Interrupt | turso::core::StepResult::Busy => {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::Timeout,
                    "Turso core interrupted the query at its mandatory deadline",
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
            turso::core::StepResult::IO | turso::core::StepResult::Yield => {
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
                "a cell exceeds the {}-byte encoded limit",
                sql_contract::MAX_CELL_ENCODED_BYTES
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
        )
        .unwrap();
        assert_eq!(result.columns, ["id", "body"]);
        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0]["id"], "visible");
        assert!(!result.truncated);
    }

    #[test]
    fn isolated_projection_enforces_output_contract() {
        let duplicate = execute(
            projection_with_records(Vec::new()),
            request("SELECT 1 AS duplicate, 2 AS duplicate"),
            ExecutionControl::with_timeout(Duration::from_secs(2)),
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
        )
        .unwrap_err()
        .to_string();
        assert!(oversized.contains("result_too_large"));
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
}
