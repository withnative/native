use futures::future::BoxFuture;
use serde_json::{json, Value};

use crate::authorization::{Capability, Principal};
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, LogicalType, NormalizedRow, NormalizedValue,
    StatementKind, StatementTemplate,
};
use crate::schema::{ROOT_RECORD_ID, UNFILED_RECORD_ID};
use crate::store::AppendSpec;
use crate::{Error, Result};

/// Backend-owned mechanics needed by the portable record tombstone fold.
/// Lock ordering is record first, then the content cursor, matching the other
/// record mutations and keeping the CAS check adjacent to the append.
pub(crate) trait RecordLifecyclePhysicalPort {
    fn lock_live_record<'a>(&'a mut self, record_id: &'a str) -> BoxFuture<'a, Result<()>>;
    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>>;
    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<String>>;
}

fn statement(
    operation: &'static str,
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments)
        .map_err(|error| super::stable_storage_error(operation, &error))
}

async fn fetch<E: DomainStatementExecutor>(
    executor: &mut E,
    operation: &'static str,
    statement: &StatementTemplate,
    bindings: &[BindValue],
    columns: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    executor
        .fetch_all(statement, bindings, columns)
        .await
        .map_err(|error| super::stable_storage_error(operation, &error))
}

fn text(row: &NormalizedRow, column: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "delete_record state column '{column}' is invalid"
        ))),
    }
}

fn optional_text(row: &NormalizedRow, column: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "delete_record state column '{column}' is invalid"
        ))),
    }
}

fn optional_integer(row: &NormalizedRow, column: &str) -> Result<Option<i64>> {
    match row.get(column) {
        Some(NormalizedValue::Integer(value)) => Ok(Some(*value)),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "delete_record state column '{column}' is invalid"
        ))),
    }
}

async fn record_state<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<(String, Option<String>, Option<String>)> {
    let query = statement(
        "delete_record",
        "records",
        &[
            "SELECT type, kind, deleted_at FROM {{relation}} WHERE id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "delete_record",
        &query,
        &[BindValue::Text(record_id.into())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
        ],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Err(Error::engine(format!(
            "delete_record: record {record_id} does not exist"
        )));
    };
    Ok((
        text(row, "type")?,
        optional_text(row, "kind")?,
        optional_text(row, "deleted_at")?,
    ))
}

async fn previous_seq<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<Option<i64>> {
    let query = statement(
        "delete_record",
        "content_events",
        &[
            "SELECT MAX(seq) AS previous_seq FROM {{relation}} WHERE record_id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "delete_record",
        &query,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::nullable("previous_seq", LogicalType::Integer)],
    )
    .await?;
    rows.first()
        .map(|row| optional_integer(row, "previous_seq"))
        .transpose()
        .map(Option::flatten)
}

async fn assert_no_live_children<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<()> {
    let query = statement(
        "delete_record",
        "records",
        &[
            "SELECT id FROM {{relation}} WHERE home_id = ",
            " AND deleted_at IS NULL ORDER BY id LIMIT 1",
        ],
    )?;
    let rows = fetch(
        executor,
        "delete_record",
        &query,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::required("id", LogicalType::Text)],
    )
    .await?;
    if let Some(row) = rows.first() {
        return Err(Error::engine(format!(
            "cannot apply record.deleted: folder {record_id} still has live homed members (including {}); rehome its members atomically first",
            text(row, "id")?
        )));
    }
    Ok(())
}

/// Apply the portable soft-delete contract inside one backend-owned
/// transaction. Missing, unauthorized and malformed authorization shapes are
/// deliberately indistinguishable to hosted callers.
pub(crate) async fn delete_record<P>(
    port: &mut P,
    principal: Principal<'_>,
    record_id: &str,
    reason: &str,
    actor: &str,
    if_content_seq: Option<i64>,
) -> Result<Value>
where
    P: DomainStatementExecutor
        + RecordLifecyclePhysicalPort
        + crate::awareness::CandidateWithdrawalPhysicalPort,
{
    if reason.trim().is_empty() {
        return Err(Error::engine("delete_record: 'reason' must not be blank"));
    }

    port.lock_live_record(record_id).await?;
    port.lock_content_log().await?;
    if crate::authorization::is_attribution_record_with(port, record_id).await? {
        return Err(Error::engine(format!(
            "delete_record: record {record_id} does not exist"
        )));
    }
    if !crate::authorization::allows_record_with(port, principal, record_id, Capability::Manage)
        .await?
    {
        return Err(Error::engine(format!(
            "delete_record: record {record_id} does not exist"
        )));
    }
    crate::instructions::assert_source_deletable_with(port, "delete_record", record_id).await?;

    let (record_type, _kind, deleted_at) = record_state(port, record_id).await?;
    if deleted_at.is_some() {
        return Err(Error::engine(format!(
            "cannot apply record.deleted: record {record_id} is deleted (tombstoned)"
        )));
    }
    if matches!(record_id, ROOT_RECORD_ID | UNFILED_RECORD_ID) {
        return Err(Error::engine(format!(
            "cannot apply record.deleted: engine filing record {record_id} cannot be removed"
        )));
    }
    assert_no_live_children(port, record_id).await?;

    let previous_seq = previous_seq(port, record_id).await?;
    if if_content_seq.is_some_and(|expected| previous_seq != Some(expected)) {
        return Err(Error::engine(
            "delete_record: content revision conflict; get the record and prepare again",
        ));
    }
    let deletion_event_id = port
        .append_content(AppendSpec {
            record_id: record_id.into(),
            event_type: "record.deleted".into(),
            payload: json!({ "reason": reason }),
            actor: Some(actor.into()),
        })
        .await?;
    if record_type == "Message" {
        crate::awareness::withdraw_message_candidates_with(
            port,
            record_id,
            "record.deleted",
            &deletion_event_id,
        )
        .await?;
    }
    let (_, _, deleted_at) = record_state(port, record_id).await?;
    Ok(json!({
        "id": record_id,
        "deleted": true,
        "deleted_at": deleted_at,
        "previous_seq": previous_seq,
    }))
}
