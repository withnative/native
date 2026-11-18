//! Adapter for reviewed, engine-owned portable read templates. This carries no
//! Db or write capability; it lets existing deterministic schema folds read
//! the admitted file directly.
use super::*;
use crate::portable_sql::*;
use futures::future::BoxFuture;

pub(crate) struct NativeStatementExecutor<'a>(pub(crate) &'a AdmittedMemberFile);
impl<'a> NativeStatementExecutor<'a> {
    pub(crate) fn attachment_reader(file: &'a AdmittedMemberFile) -> crate::Result<Self> {
        file_fence::verify_on(&file.connection, &file.expected)
            .map_err(|_| crate::Error::copy_unavailable())?;
        super::query::ensure_blobs_view(file)?;
        Ok(Self(file))
    }
}

impl DomainStatementExecutor for NativeStatementExecutor<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        template: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        // Evaluate synchronously before constructing the ready future; SQLite
        // connection references never cross an async suspension.
        let result = (|| {
            let refused = || SqlError::contract("native member template refused");
            if template.kind() != StatementKind::Select
                || (!RELATIONS.contains(&template.relation()) && template.relation() != "blobs")
            {
                return Err(refused());
            }
            file_fence::verify_on(&self.0.connection, &self.0.expected).map_err(|_| refused())?;
            if template.relation() == "blobs" {
                super::query::ensure_blobs_view(self.0).map_err(|_| refused())?;
            }
            let rendered = template.render(Dialect::Sqlite)?;
            if bindings.len() != rendered.parameter_count {
                return Err(refused());
            }
            let values = bindings
                .iter()
                .map(|b| {
                    Ok(match b {
                        BindValue::Null(_) => Value::Null,
                        BindValue::Bool(b) => Value::Integer(i64::from(*b)),
                        BindValue::Integer(n) => Value::Integer(*n),
                        BindValue::Real(n) => Value::Real(*n),
                        BindValue::Text(s) => Value::Text(s.clone()),
                        BindValue::Bytes(b) => Value::Blob(b.clone()),
                        BindValue::Json(v) => {
                            Value::Text(serde_json::to_string(v).map_err(|_| refused())?)
                        }
                        BindValue::Timestamp(v) => Value::Text(v.to_rfc3339()),
                    })
                })
                .collect::<SqlResult<Vec<_>>>()?;
            let mut statement = self
                .0
                .connection
                .prepare(&rendered.sql)
                .map_err(|_| refused())?;
            if !statement.readonly() {
                return Err(refused());
            }
            let mut cursor = statement
                .query(rusqlite::params_from_iter(values))
                .map_err(|_| refused())?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().map_err(|_| refused())? {
                let mut out = NormalizedRow::new();
                for column in columns {
                    let cell: Value = row.get(column.name.as_str()).map_err(|_| refused())?;
                    let value = match (cell, column.logical_type) {
                        (Value::Null, _) if column.nullable => NormalizedValue::Null,
                        (Value::Integer(n), LogicalType::Bool) => NormalizedValue::Bool(n != 0),
                        (Value::Integer(n), LogicalType::Integer) => NormalizedValue::Integer(n),
                        (Value::Real(n), LogicalType::Real) => NormalizedValue::Real(n),
                        (Value::Integer(n), LogicalType::Real) => NormalizedValue::Real(n as f64),
                        (Value::Text(s), LogicalType::Text) => NormalizedValue::Text(s),
                        (Value::Text(s), LogicalType::Timestamp) => NormalizedValue::Timestamp(s),
                        (Value::Text(s), LogicalType::Json) => {
                            NormalizedValue::Json(serde_json::from_str(&s).map_err(|_| refused())?)
                        }
                        (Value::Blob(b), LogicalType::Bytes) => NormalizedValue::Bytes(b),
                        _ => return Err(refused()),
                    };
                    out.insert(column.name.clone(), value);
                }
                rows.push(out);
            }
            Ok(rows)
        })();
        Box::pin(futures::future::ready(result))
    }
}

impl crate::domain_transaction::AttachmentPhysicalPort for NativeStatementExecutor<'_> {
    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, crate::Result<()>> {
        Box::pin(futures::future::ready(Err(
            crate::Error::standby_read_only(),
        )))
    }
    fn insert_blob<'a>(
        &'a mut self,
        _bytes: &'a [u8],
        _mime: Option<&'a str>,
        _filename: Option<&'a str>,
    ) -> BoxFuture<'a, crate::Result<crate::blob::BlobMeta>> {
        Box::pin(futures::future::ready(Err(
            crate::Error::standby_read_only(),
        )))
    }
    fn append_content<'a>(
        &'a mut self,
        _spec: crate::store::AppendSpec,
    ) -> BoxFuture<'a, crate::Result<()>> {
        Box::pin(futures::future::ready(Err(
            crate::Error::standby_read_only(),
        )))
    }
    fn read_blob_range<'a>(
        &'a mut self,
        blob_id: &'a str,
        offset: u64,
        length: u64,
    ) -> BoxFuture<'a, crate::Result<Option<crate::blob::BlobSlice>>> {
        use rusqlite::OptionalExtension;
        let result = (|| {
            let failed = || crate::Error::engine("native member attachment range refused");
            file_fence::verify_on(&self.0.connection, &self.0.expected).map_err(|_| failed())?;
            let start =
                i64::try_from(offset.checked_add(1).ok_or_else(failed)?).map_err(|_| failed())?;
            let count = i64::try_from(length).map_err(|_| failed())?;
            let row:Option<(Vec<u8>,u64)>=self.0.connection.query_row("SELECT substr(bytes,?2,?3),length(bytes) FROM main.member_attachments WHERE json_extract(metadata,'$.id')=?1",rusqlite::params![blob_id,start,count],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|failed())?;
            Ok(row.map(|(bytes, total_size)| crate::blob::BlobSlice {
                eof: offset.saturating_add(bytes.len() as u64) >= total_size,
                bytes,
                offset,
                total_size,
            }))
        })();
        Box::pin(futures::future::ready(result))
    }
}
