use super::*;

const SOURCE_LIMIT: usize = crate::query::turso_sql::MAX_PROJECTION_ROWS + 1;
const MAX_SOURCE_CELL_BYTES: usize = crate::query::sql_contract::MAX_CELL_ENCODED_BYTES;

#[derive(Default)]
struct SourceBudget {
    rows: usize,
    encoded_upper_bytes: usize,
}

impl SourceBudget {
    fn reserve(&mut self, relation: &str, rows: usize, encoded_upper_bytes: usize) -> Result<()> {
        if rows >= SOURCE_LIMIT {
            return Err(projection_too_large(format!(
                "source relation '{relation}' exceeds the {}-row projection candidate limit",
                crate::query::turso_sql::MAX_PROJECTION_ROWS
            )));
        }
        self.rows = self.rows.saturating_add(rows);
        if self.rows > crate::query::turso_sql::MAX_PROJECTION_ROWS {
            return Err(projection_too_large(format!(
                "source projection candidates exceed the {}-row aggregate limit",
                crate::query::turso_sql::MAX_PROJECTION_ROWS
            )));
        }
        self.encoded_upper_bytes = self.encoded_upper_bytes.saturating_add(encoded_upper_bytes);
        if self.encoded_upper_bytes > crate::query::turso_sql::MAX_PROJECTION_ENCODED_BYTES {
            return Err(projection_too_large(format!(
                "source projection candidates exceed the {}-byte aggregate limit",
                crate::query::turso_sql::MAX_PROJECTION_ENCODED_BYTES
            )));
        }
        Ok(())
    }
}

fn text_json_encoded_upper(raw_bytes: usize) -> usize {
    // A single input byte can become a six-byte `\u00xx` escape. The static
    // SQL preflight already includes per-row structural overhead, so charging
    // that entire physical estimate at 6x also covers quotes, keys and commas.
    raw_bytes.saturating_mul(6)
}

fn blob_json_encoded_upper(raw_bytes: usize, cells: usize) -> usize {
    // Base64 is four bytes per three input bytes. Four bytes per cell also
    // conservatively cover JSON quotes and NULL (which is four bytes).
    (raw_bytes.saturating_add(cells.saturating_mul(2)) / 3)
        .saturating_mul(4)
        .saturating_add(cells.saturating_mul(4))
}

fn projection_too_large(detail: impl AsRef<str>) -> Error {
    crate::query::sql_contract::categorized_error(
        crate::query::sql_contract::QuerySqlErrorCategory::ResultTooLarge,
        detail,
    )
}

/// A lifecycle row is serialized before it joins the growing vector. The
/// surrounding JSON array costs two brackets and a comma between rows, so
/// this exactly matches the isolated core's eventual encoded-size charge.
pub(super) fn reserve_lifecycle_encoded_bytes(
    used: usize,
    limit: usize,
    row: &NormalizedRow,
    needs_comma: bool,
) -> Result<usize> {
    let row_bytes = serde_json::to_vec(row)?.len();
    let next = used
        .saturating_add(usize::from(needs_comma))
        .saturating_add(row_bytes);
    if next > limit {
        return Err(projection_too_large(format!(
            "record_lifecycle_interpretations exceeds the {}-byte encoded projection limit",
            crate::query::turso_sql::MAX_PROJECTION_ENCODED_BYTES
        )));
    }
    Ok(next)
}

fn columns(relation: &str) -> Vec<ColumnSpec> {
    if relation == "semantic_units" {
        return vec![ColumnSpec::nullable("unit_id", LogicalType::Text)];
    }
    crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .find(|candidate| candidate.name == relation)
        .expect("known query_sql logical relation")
        .columns
        .iter()
        // `*_ms` companions are computed in Rust by `with_millis`, never
        // read from the backend: the physical tables have no such columns.
        .filter(|column| !column.ends_with("_ms"))
        .map(|column| {
            let logical_type = match (relation, *column) {
                ("content_events", "local_seq")
                | ("facet_observations", "event_seq")
                | ("blobs", "size_bytes")
                | ("records", "is_current")
                | ("records", "successor_count")
                | ("records", "archived")
                | (
                    "body_task_items",
                    "item_index" | "checked" | "in_quote" | "start_offset" | "end_offset",
                ) => LogicalType::Integer,
                ("bindings", "is_canonical") => LogicalType::Bool,
                ("facet_values", "value_num") | ("vocabulary_values", "ordinal") => {
                    LogicalType::Real
                }
                ("blobs", "bytes") => LogicalType::Bytes,
                // These are TEXT in the public SQLite contract. Parsing and
                // reserializing them would change caller-visible whitespace
                // and object-key ordering on the Turso projection path.
                ("vocabulary_values", "metadata") | ("schema_config", "data") => LogicalType::Text,
                (_, column)
                    if column.ends_with("_at") || matches!(column, "as_of" | "last_seen_at") =>
                {
                    LogicalType::Timestamp
                }
                _ => LogicalType::Text,
            };
            ColumnSpec::nullable(*column, logical_type)
        })
        .collect()
}

async fn source_rows(
    transaction: &mut TursoDomainTransaction<'_>,
    budget: &mut SourceBudget,
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<Vec<NormalizedRow>> {
    source_rows_extra(transaction, budget, relation, fragments, &[]).await
}

/// [`source_rows`] plus transient helper columns that never reach the
/// projection: the fetch fragment must project them and they are stripped
/// by the caller before `IsolatedProjection::insert`, whose column contract
/// is exact. Their bytes ride in the source budget slack (a 6x text
/// multiplier over the measured cells against a 16 MiB cap).
async fn source_rows_extra(
    transaction: &mut TursoDomainTransaction<'_>,
    budget: &mut SourceBudget,
    relation: &'static str,
    fragments: &'static [&'static str],
    extra: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    source_rows_bound(
        transaction,
        budget,
        relation,
        source_preflight(relation),
        fragments,
        &[],
        extra,
    )
    .await
}

async fn source_rows_bound(
    transaction: &mut TursoDomainTransaction<'_>,
    budget: &mut SourceBudget,
    relation: &'static str,
    preflight_fragments: &'static [&'static str],
    fragments: &'static [&'static str],
    bindings: &[BindValue],
    extra: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    let preflight = statement(StatementKind::Select, relation, preflight_fragments)
        .map_err(|error| stable("query_sql projection preflight", error))?;
    let preflight = transaction
        .rows(
            "query_sql projection preflight",
            &preflight,
            bindings,
            &[
                ColumnSpec::required("candidate_count", LogicalType::Integer),
                ColumnSpec::nullable("max_cell_bytes", LogicalType::Integer),
                ColumnSpec::nullable("candidate_bytes", LogicalType::Integer),
            ],
        )
        .await?;
    let row = preflight
        .first()
        .ok_or_else(|| Error::engine("query_sql projection preflight returned no row"))?;
    let integer = |column: &str| match row.get(column) {
        Some(NormalizedValue::Integer(value)) => usize::try_from(*value)
            .map_err(|_| Error::engine("query_sql projection preflight overflow")),
        Some(NormalizedValue::Null) => Ok(0),
        _ => Err(Error::engine(format!(
            "query_sql projection preflight column '{column}' is invalid"
        ))),
    };
    let candidate_count = integer("candidate_count")?;
    let max_cell_bytes = integer("max_cell_bytes")?;
    let candidate_bytes = integer("candidate_bytes")?;
    if max_cell_bytes > MAX_SOURCE_CELL_BYTES {
        return Err(projection_too_large(format!(
            "source relation '{relation}' contains a cell above the {MAX_SOURCE_CELL_BYTES}-byte limit"
        )));
    }
    // Reserve before fetching: a later relation cannot cause several already
    // materialized vectors plus one unbounded fetch to exceed the source cap.
    budget.reserve(
        relation,
        candidate_count,
        text_json_encoded_upper(candidate_bytes),
    )?;
    let statement = statement(StatementKind::Select, relation, fragments)
        .map_err(|error| stable("query_sql projection", error))?;
    let mut specs = columns(relation);
    specs.extend(extra.iter().cloned());
    let rows = transaction
        .rows("query_sql projection", &statement, bindings, &specs)
        .await?;
    if rows.len() != candidate_count {
        return Err(Error::engine(format!(
            "source relation '{relation}' changed inside the query_sql snapshot"
        )));
    }
    Ok(rows)
}

// Every expression is source-static. `CAST(... AS BLOB)` makes `length`
// count bytes rather than Unicode code points. The aggregate result is tiny,
// so no physical value is copied into Rust until both per-cell and cumulative
// candidate bounds have been admitted.
fn source_preflight(relation: &str) -> &'static [&'static str] {
    match relation {
        "records" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(type AS BLOB)),0),coalesce(length(CAST(kind AS BLOB)),0),coalesce(length(CAST(name AS BLOB)),0),coalesce(length(CAST(body AS BLOB)),0),coalesce(length(CAST(home_id AS BLOB)),0),coalesce(length(CAST(lifecycle AS BLOB)),0),coalesce(length(CAST(persistence AS BLOB)),0),coalesce(length(CAST(maturity AS BLOB)),0),coalesce(length(CAST(summary AS BLOB)),0),coalesce(length(CAST(is_current AS BLOB)),0),coalesce(length(CAST(successor_count AS BLOB)),0),coalesce(length(CAST(archived AS BLOB)),0),coalesce(length(CAST(last_activity_at AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0),coalesce(length(CAST(updated_at AS BLOB)),0),coalesce(length(CAST(deleted_at AS BLOB)),0))) AS max_cell_bytes,sum(152+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(type AS BLOB)),0)+coalesce(length(CAST(kind AS BLOB)),0)+coalesce(length(CAST(name AS BLOB)),0)+coalesce(length(CAST(body AS BLOB)),0)+coalesce(length(CAST(home_id AS BLOB)),0)+coalesce(length(CAST(lifecycle AS BLOB)),0)+coalesce(length(CAST(persistence AS BLOB)),0)+coalesce(length(CAST(maturity AS BLOB)),0)+coalesce(length(CAST(summary AS BLOB)),0)+coalesce(length(CAST(is_current AS BLOB)),0)+coalesce(length(CAST(successor_count AS BLOB)),0)+coalesce(length(CAST(archived AS BLOB)),0)+coalesce(length(CAST(last_activity_at AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)+coalesce(length(CAST(updated_at AS BLOB)),0)+coalesce(length(CAST(deleted_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,type,kind,name,body,home_id,lifecycle,persistence,maturity,summary,is_current,successor_count,last_activity_at,created_at,updated_at,deleted_at,archived FROM {{relation}} WHERE deleted_at IS NULL LIMIT 20001)"],
        "semantic_units" => &["SELECT count(*) AS candidate_count,max(coalesce(length(CAST(unit_id AS BLOB)),0)) AS max_cell_bytes,sum(32+coalesce(length(CAST(unit_id AS BLOB)),0)) AS candidate_bytes FROM (SELECT unit_id FROM {{relation}} LIMIT 20001)"],
        "content_events" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(local_seq AS BLOB)),0),coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(type AS BLOB)),0),coalesce(length(CAST(actor AS BLOB)),0),coalesce(length(CAST(run_key AS BLOB)),0),coalesce(length(CAST(parent_key AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(local_seq AS BLOB)),0)+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(type AS BLOB)),0)+coalesce(length(CAST(actor AS BLOB)),0)+coalesce(length(CAST(run_key AS BLOB)),0)+coalesce(length(CAST(parent_key AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT seq AS local_seq,id,record_id,type,actor,run_key,parent_key,created_at FROM {{relation}} LIMIT 20001)"],
        "links" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(source_id AS BLOB)),0),coalesce(length(CAST(target_id AS BLOB)),0),coalesce(length(CAST(relationship AS BLOB)),0),coalesce(length(CAST(note AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(source_id AS BLOB)),0)+coalesce(length(CAST(target_id AS BLOB)),0)+coalesce(length(CAST(relationship AS BLOB)),0)+coalesce(length(CAST(note AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} LIMIT 20001)"],
        "facet_values" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(key AS BLOB)),0),coalesce(length(CAST(value AS BLOB)),0),coalesce(length(CAST(value_num AS BLOB)),0),coalesce(length(CAST(vocab_ref AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(key AS BLOB)),0)+coalesce(length(CAST(value AS BLOB)),0)+coalesce(length(CAST(value_num AS BLOB)),0)+coalesce(length(CAST(vocab_ref AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,record_id,key,value,value_num,vocab_ref,created_at FROM {{relation}} LIMIT 20001)"],
        "facet_observations" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(key AS BLOB)),0),coalesce(length(CAST(value AS BLOB)),0),coalesce(length(CAST(op AS BLOB)),0),coalesce(length(CAST(vocab_ref AS BLOB)),0),coalesce(length(CAST(as_of AS BLOB)),0),coalesce(length(CAST(observed_at AS BLOB)),0),coalesce(length(CAST(event_seq AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(key AS BLOB)),0)+coalesce(length(CAST(value AS BLOB)),0)+coalesce(length(CAST(op AS BLOB)),0)+coalesce(length(CAST(vocab_ref AS BLOB)),0)+coalesce(length(CAST(as_of AS BLOB)),0)+coalesce(length(CAST(observed_at AS BLOB)),0)+coalesce(length(CAST(event_seq AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq FROM {{relation}} LIMIT 20001)"],
        "bindings" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(system AS BLOB)),0),coalesce(length(CAST(identifier AS BLOB)),0),coalesce(length(CAST(is_canonical AS BLOB)),0),coalesce(length(CAST(url AS BLOB)),0),coalesce(length(CAST(etag AS BLOB)),0),coalesce(length(CAST(last_seen_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(system AS BLOB)),0)+coalesce(length(CAST(identifier AS BLOB)),0)+coalesce(length(CAST(is_canonical AS BLOB)),0)+coalesce(length(CAST(url AS BLOB)),0)+coalesce(length(CAST(etag AS BLOB)),0)+coalesce(length(CAST(last_seen_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at FROM {{relation}} LIMIT 20001)"],
        "blobs" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(bytes AS BLOB)),0),coalesce(length(CAST(mime AS BLOB)),0),coalesce(length(CAST(size_bytes AS BLOB)),0),coalesce(length(CAST(sha256 AS BLOB)),0),coalesce(length(CAST(original_filename AS BLOB)),0),coalesce(length(CAST(storage_tier AS BLOB)),0),coalesce(length(CAST(external_ref AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(bytes AS BLOB)),0)+coalesce(length(CAST(mime AS BLOB)),0)+coalesce(length(CAST(size_bytes AS BLOB)),0)+coalesce(length(CAST(sha256 AS BLOB)),0)+coalesce(length(CAST(original_filename AS BLOB)),0)+coalesce(length(CAST(storage_tier AS BLOB)),0)+coalesce(length(CAST(external_ref AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref,created_at FROM {{relation}} LIMIT 20001)"],
        "vocabularies" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(name AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(32+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(name AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,name,created_at FROM {{relation}} LIMIT 20001)"],
        "vocabulary_values" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(vocabulary_id AS BLOB)),0),coalesce(length(CAST(value AS BLOB)),0),coalesce(length(CAST(gloss AS BLOB)),0),coalesce(length(CAST(status AS BLOB)),0),coalesce(length(CAST(ordinal AS BLOB)),0),coalesce(length(CAST(terminality AS BLOB)),0),coalesce(length(CAST(metadata AS BLOB)),0),coalesce(length(CAST(alias_of AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(vocabulary_id AS BLOB)),0)+coalesce(length(CAST(value AS BLOB)),0)+coalesce(length(CAST(gloss AS BLOB)),0)+coalesce(length(CAST(status AS BLOB)),0)+coalesce(length(CAST(ordinal AS BLOB)),0)+coalesce(length(CAST(terminality AS BLOB)),0)+coalesce(length(CAST(metadata AS BLOB)),0)+coalesce(length(CAST(alias_of AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of FROM {{relation}} LIMIT 20001)"],
        "schema_config" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(layer AS BLOB)),0),coalesce(length(CAST(name AS BLOB)),0),coalesce(length(CAST(data AS BLOB)),0),coalesce(length(CAST(applies_to_collection_id AS BLOB)),0),coalesce(length(CAST(version_lineage AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(layer AS BLOB)),0)+coalesce(length(CAST(name AS BLOB)),0)+coalesce(length(CAST(data AS BLOB)),0)+coalesce(length(CAST(applies_to_collection_id AS BLOB)),0)+coalesce(length(CAST(version_lineage AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,layer,name,data,applies_to_collection_id,version_lineage,created_at FROM {{relation}} LIMIT 20001)"],
        "body_task_items" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(item_index AS BLOB)),0),coalesce(length(CAST(marker AS BLOB)),0),coalesce(length(CAST(checked AS BLOB)),0),coalesce(length(CAST(in_quote AS BLOB)),0),coalesce(length(CAST(start_offset AS BLOB)),0),coalesce(length(CAST(end_offset AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(item_index AS BLOB)),0)+coalesce(length(CAST(marker AS BLOB)),0)+coalesce(length(CAST(checked AS BLOB)),0)+coalesce(length(CAST(in_quote AS BLOB)),0)+coalesce(length(CAST(start_offset AS BLOB)),0)+coalesce(length(CAST(end_offset AS BLOB)),0)) AS candidate_bytes FROM (SELECT record_id,item_index,marker,checked,in_quote,start_offset,end_offset FROM {{relation}} WHERE record_id IN (SELECT value FROM json_each(", ")) LIMIT 20001)"],
        _ => unreachable!("known query_sql source relation"),
    }
}

fn value_text<'a>(row: &'a NormalizedRow, column: &str) -> Option<&'a str> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) | Some(NormalizedValue::Timestamp(value)) => Some(value),
        _ => None,
    }
}

fn value_bool(row: &NormalizedRow, column: &str) -> bool {
    matches!(row.get(column), Some(NormalizedValue::Bool(true)))
        || matches!(row.get(column), Some(NormalizedValue::Integer(1)))
}

async fn source_blob_rows(
    transaction: &mut TursoDomainTransaction<'_>,
    budget: &mut SourceBudget,
    visible_blob_ids: &BTreeSet<String>,
) -> Result<Vec<NormalizedRow>> {
    let mut blobs = Vec::new();
    for id in visible_blob_ids {
        let bindings = [BindValue::Text(id.clone())];
        let preflight = statement(
            StatementKind::Select,
            "blobs",
            &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(bytes AS BLOB)),0),coalesce(length(CAST(mime AS BLOB)),0),coalesce(length(CAST(size_bytes AS BLOB)),0),coalesce(length(CAST(sha256 AS BLOB)),0),coalesce(length(CAST(original_filename AS BLOB)),0),coalesce(length(CAST(storage_tier AS BLOB)),0),coalesce(length(CAST(external_ref AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(bytes AS BLOB)),0)+coalesce(length(CAST(mime AS BLOB)),0)+coalesce(length(CAST(size_bytes AS BLOB)),0)+coalesce(length(CAST(sha256 AS BLOB)),0)+coalesce(length(CAST(original_filename AS BLOB)),0)+coalesce(length(CAST(storage_tier AS BLOB)),0)+coalesce(length(CAST(external_ref AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes,sum(coalesce(length(CAST(bytes AS BLOB)),0)) AS blob_bytes FROM (SELECT id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref,created_at FROM {{relation}} WHERE id = ", " LIMIT 2)"],
        )
        .map_err(|error| stable("query_sql blob preflight", error))?;
        let preflight = transaction
            .rows(
                "query_sql blob preflight",
                &preflight,
                &bindings,
                &[
                    ColumnSpec::required("candidate_count", LogicalType::Integer),
                    ColumnSpec::nullable("max_cell_bytes", LogicalType::Integer),
                    ColumnSpec::nullable("candidate_bytes", LogicalType::Integer),
                    ColumnSpec::nullable("blob_bytes", LogicalType::Integer),
                ],
            )
            .await?;
        let row = preflight
            .first()
            .ok_or_else(|| Error::engine("query_sql blob preflight returned no row"))?;
        let integer = |column: &str| match row.get(column) {
            Some(NormalizedValue::Integer(value)) => usize::try_from(*value)
                .map_err(|_| Error::engine("query_sql blob preflight overflow")),
            Some(NormalizedValue::Null) => Ok(0),
            _ => Err(Error::engine(format!(
                "query_sql blob preflight column '{column}' is invalid"
            ))),
        };
        let candidate_count = integer("candidate_count")?;
        let max_cell_bytes = integer("max_cell_bytes")?;
        let candidate_bytes = integer("candidate_bytes")?;
        let blob_bytes = integer("blob_bytes")?;
        if max_cell_bytes > MAX_SOURCE_CELL_BYTES {
            return Err(projection_too_large(format!(
                "source relation 'blobs' contains a cell above the {MAX_SOURCE_CELL_BYTES}-byte limit"
            )));
        }
        let non_blob_bytes = candidate_bytes.saturating_sub(blob_bytes);
        let encoded_upper_bytes = text_json_encoded_upper(non_blob_bytes)
            .saturating_add(blob_json_encoded_upper(blob_bytes, candidate_count));
        budget.reserve("blobs", candidate_count, encoded_upper_bytes)?;
        let select = statement(
            StatementKind::Select,
            "blobs",
            &["SELECT id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref,created_at FROM {{relation}} WHERE id = ", " LIMIT 2"],
        )
        .map_err(|error| stable("query_sql blob projection", error))?;
        let rows = transaction
            .rows(
                "query_sql blob projection",
                &select,
                &bindings,
                &columns("blobs"),
            )
            .await?;
        if rows.len() != candidate_count {
            return Err(Error::engine(
                "source relation 'blobs' changed inside the query_sql snapshot",
            ));
        }
        blobs.extend(rows);
    }
    Ok(blobs)
}

async fn source_task_item_rows(
    transaction: &mut TursoDomainTransaction<'_>,
    budget: &mut SourceBudget,
    visible: &BTreeSet<String>,
) -> Result<Vec<NormalizedRow>> {
    if visible.is_empty() {
        return Ok(Vec::new());
    }
    // Admission and fetch use the same visible-id predicate inside this
    // snapshot. Hidden task rows never consume the caller's source budget.
    let bindings = [BindValue::Text(
        serde_json::to_string(visible).expect("string set serializes to JSON"),
    )];
    source_rows_bound(
        transaction,
        budget,
        "body_task_items",
        source_preflight("body_task_items"),
        &["SELECT record_id,item_index,marker,checked,in_quote,start_offset,end_offset FROM {{relation}} WHERE record_id IN (SELECT value FROM json_each(", ")) LIMIT 20001"],
        &bindings,
        &[],
    )
    .await
}

/// Workspace content head inside the current backend snapshot. Unfiltered
/// on purpose: hidden writes advance the stamp exactly as they do on the
/// SQLite path.
async fn snapshot_head_seq(transaction: &mut TursoDomainTransaction<'_>) -> Result<i64> {
    let select = statement(
        StatementKind::Select,
        "content_events",
        &["SELECT COALESCE(MAX(seq),0) AS head FROM {{relation}}"],
    )
    .map_err(|error| stable("query_sql snapshot head", error))?;
    let rows = transaction
        .rows(
            "query_sql snapshot head",
            &select,
            &[],
            &[ColumnSpec::required("head", LogicalType::Integer)],
        )
        .await?;
    rows.first()
        .map(|row| integer(row, "head", "query_sql snapshot"))
        .transpose()?
        .ok_or_else(|| Error::engine("query_sql snapshot head returned no row"))
}

/// Served catalog rows, generated from LOGICAL_RELATIONS so Turso returns
/// the same catalog every other engine serves from `catalog_view_statements`.
fn catalog_relation_rows() -> Vec<NormalizedRow> {
    crate::query::sql_contract::catalog_relation_rows()
        .into_iter()
        .map(
            |(name, identity, version, caller_relative, completeness, profiles, comment)| {
                NormalizedRow::from([
                    (
                        "relation_name".to_string(),
                        NormalizedValue::Text(name.into()),
                    ),
                    (
                        "identity".to_string(),
                        NormalizedValue::Text(identity.into()),
                    ),
                    (
                        "semantic_version".to_string(),
                        NormalizedValue::Integer(i64::from(version)),
                    ),
                    (
                        "caller_relative".to_string(),
                        NormalizedValue::Integer(caller_relative),
                    ),
                    (
                        "completeness".to_string(),
                        NormalizedValue::Text(completeness.into()),
                    ),
                    ("profiles".to_string(), NormalizedValue::Text(profiles)),
                    ("comment".to_string(), NormalizedValue::Text(comment.into())),
                ])
            },
        )
        .collect()
}

fn catalog_column_rows() -> Vec<NormalizedRow> {
    crate::query::sql_contract::catalog_column_rows()
        .into_iter()
        .map(|(relation, column, position)| {
            NormalizedRow::from([
                (
                    "relation_name".to_string(),
                    NormalizedValue::Text(relation.into()),
                ),
                (
                    "column_name".to_string(),
                    NormalizedValue::Text(column.into()),
                ),
                (
                    "column_position".to_string(),
                    NormalizedValue::Integer(position as i64),
                ),
            ])
        })
        .collect()
}

/// Portable value-model companions (E1 M1 slice B). For each
/// engine-managed timestamp column, parse the backend text once and project
/// both the fixed UTC-millis text and the integer epoch-millis companion,
/// so date maths is portable integer arithmetic. NULL or unparseable text
/// NULLs both cells, matching the SQLite views' `strftime` behaviour.
/// `as_of` is free-form valid-time input and is never touched.
fn with_millis(mut rows: Vec<NormalizedRow>, columns: &[&str]) -> Vec<NormalizedRow> {
    for row in &mut rows {
        for column in columns {
            let is_timestamp = matches!(row.get(*column), Some(NormalizedValue::Timestamp(_)));
            let (text, ms) = match row.get(*column) {
                Some(NormalizedValue::Text(value)) | Some(NormalizedValue::Timestamp(value)) => {
                    match chrono::DateTime::parse_from_rfc3339(value) {
                        Ok(parsed) => (
                            Some(parsed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                            Some(parsed.timestamp_millis()),
                        ),
                        Err(_) => (None, None),
                    }
                }
                _ => (None, None),
            };
            let text_value = text.map(|text| {
                if is_timestamp {
                    NormalizedValue::Timestamp(text)
                } else {
                    NormalizedValue::Text(text)
                }
            });
            row.insert(
                (*column).into(),
                text_value.unwrap_or(NormalizedValue::Null),
            );
            row.insert(
                format!("{column}_ms"),
                ms.map(NormalizedValue::Integer)
                    .unwrap_or(NormalizedValue::Null),
            );
        }
    }
    rows
}

async fn build_projection(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    include_task_items: bool,
    include_lifecycle: bool,
) -> Result<crate::query::turso_sql::IsolatedProjection> {
    // Freshness stamp (E1 M1 slice A): the workspace content sequence
    // observed inside this same backend snapshot, before any projection row
    // is read, so rows and stamp share one snapshot.
    let as_of_seq = snapshot_head_seq(transaction).await?;
    let mut budget = SourceBudget::default();
    let mut records = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "records",
            &["SELECT id,type,kind,name,body,home_id,lifecycle,persistence,maturity,summary,is_current,successor_count,last_activity_at,created_at,updated_at,deleted_at,archived FROM {{relation}} WHERE deleted_at IS NULL LIMIT 20001"],
        )
        .await?,
        &[
            "last_activity_at",
            "created_at",
            "updated_at",
            "deleted_at",
        ],
    );
    let semantic_rows = {
        source_rows(
            transaction,
            &mut budget,
            "semantic_units",
            &["SELECT unit_id FROM {{relation}} LIMIT 20001"],
        )
        .await?
    };
    let semantic_ids = semantic_rows
        .iter()
        .filter_map(|row| value_text(row, "unit_id"))
        .collect::<BTreeSet<_>>();
    let mut visible = BTreeSet::new();
    // One memo for the whole projection. Every record is resolved through the
    // same derived-artifact bearer walk, and the walk is issued as SQL per
    // edge, so without sharing the resolved suffixes a chain of D edges costs
    // O(D^2) statements per pass and two passes per record (subject
    // resolution, then the capability fold). The qualification fixtures
    // contain a deliberate MAX_DERIVED_BEARER_DEPTH-long chain, which is what
    // pushed this projection to the edge of QUERY_DEADLINE_MS. The memo is
    // scoped to this one snapshot transaction and is discarded with it.
    let mut bearer_memo = crate::authorization::BearerTargetMemo::default();
    for row in &records {
        let id = value_text(row, "id")
            .ok_or_else(|| Error::engine("query_sql record candidate has invalid id"))?;
        // Governed attribution is dedicated-reader state. Its bearer is used
        // only to authorize that exact read and must never upgrade the hidden
        // annotation into either query_sql provider's generic projection.
        if value_text(row, "type") == Some("Annotation")
            && value_text(row, "kind") == Some("attribution")
        {
            continue;
        }
        if value_text(row, "type") == Some("Entity")
            && value_text(row, "kind") == Some("semantic-unit")
        {
            continue;
        }
        let subject = match crate::authorization::query_sql_authorization_subject_memoized(
            transaction,
            &mut bearer_memo,
            id,
        )
        .await
        {
            Ok(subject) => subject,
            Err(_) => continue,
        };
        if semantic_ids.contains(subject.as_str()) {
            continue;
        }
        if crate::authorization::allows_record_memoized(
            transaction,
            &mut bearer_memo,
            principal(caller),
            id,
            crate::authorization::Capability::View,
        )
        .await?
        {
            visible.insert(id.to_string());
        }
    }
    records.retain(|row| value_text(row, "id").is_some_and(|id| visible.contains(id)));
    // Preserve the physical bearer for interpretation before the public
    // records projection withholds a hidden home_id. It never enters SQL.
    let lifecycle_contexts = include_lifecycle.then(|| {
        records
            .iter()
            .map(|row| {
                (
                    value_text(row, "id").unwrap_or_default().to_owned(),
                    value_text(row, "type").unwrap_or_default().to_owned(),
                    value_text(row, "kind").map(str::to_owned),
                    value_text(row, "home_id").map(str::to_owned),
                    value_text(row, "lifecycle").map(str::to_owned),
                )
            })
            .collect::<Vec<_>>()
    });
    for row in &mut records {
        if value_text(row, "home_id").is_some_and(|home| !visible.contains(home)) {
            row.insert("home_id".into(), NormalizedValue::Null);
        }
    }

    // The claim-shaped flag is computed backend-side so payload bytes never
    // cross the projection boundary; it is stripped before serving and only
    // decides run_key/parent_key withholding below. The `->` operator (not
    // `->>`) preserves an explicit-null claim key as JSON text, so key
    // presence matches the history rule exactly; it also keeps `$` out of
    // the portable template, which forbids placeholders.
    // Transport follows SQLite's output/event precedence and invalidation
    // rule, then the actor disclosure gate below. The shared channel CHECK
    // bounds this label to seven bytes, covered by the preflight row slack.
    let fetched = with_millis(
        source_rows_extra(
            transaction,
            &mut budget,
            "content_events",
            &["SELECT e.seq AS local_seq,e.id,e.record_id,e.type,e.actor,e.run_key,e.parent_key,e.created_at,((e.payload->'claimed_by_account') IS NOT NULL OR (e.payload->'claimed_run_key') IS NOT NULL OR (e.payload->'released_from_run_key') IS NOT NULL) AS claim_shaped,
                COALESCE((SELECT CASE WHEN EXISTS (
                    SELECT 1 FROM provenance_attestation_validity_events AS v
                    WHERE v.attestation_id=first_att.attestation_id AND v.status='invalidated'
                      AND v.ordinal=(SELECT MAX(v2.ordinal) FROM provenance_attestation_validity_events AS v2 WHERE v2.attestation_id=v.attestation_id))
                    THEN 'unknown' ELSE first_att.channel END
                  FROM (SELECT a.channel AS channel,a.id AS attestation_id,0 AS src
                        FROM provenance_action_outputs AS o
                        JOIN provenance_action_attestations AS a ON a.id=o.action_attestation_id
                        WHERE o.output_domain='content' AND o.output_event_id=e.id
                        UNION ALL
                        SELECT a.channel,a.id,1 AS src
                        FROM provenance_action_events AS ev
                        JOIN provenance_action_attestations AS a ON a.id=ev.action_attestation_id
                        WHERE ev.output_event_id=e.id ORDER BY 3 LIMIT 1) AS first_att),'unknown') AS channel_kind
                FROM {{relation}} AS e LIMIT 20001"],
            &[ColumnSpec::nullable("claim_shaped", LogicalType::Integer)],
        )
        .await?,
        &["created_at"],
    );
    // Attribution follows the single shared rule (`authorization`), resolved
    // once per distinct actor: a projection holds many events but few actors.
    // Trusted-local callers bypass redaction wholesale, exactly as history
    // does; a NULL actor discloses nothing.
    let credential = caller.credential().to_string();
    let bypass = caller.is_trusted_local();
    let mut disclosable = std::collections::HashMap::new();
    if !bypass {
        let mut actors: Vec<String> = fetched
            .iter()
            .filter_map(|row| value_text(row, "actor").map(str::to_owned))
            .collect();
        actors.sort();
        actors.dedup();
        for actor in actors {
            let visible = actor == credential
                || crate::authorization::actor_disclosable_with(
                    transaction,
                    principal(caller),
                    &actor,
                )
                .await?;
            disclosable.insert(actor, visible);
        }
    }
    let events = fetched
        .into_iter()
        .filter_map(|mut row| {
            let visible_hit = value_text(&row, "record_id").is_some_and(|id| visible.contains(id));
            let event_type = value_text(&row, "type").map(str::to_owned)?;
            let actor = value_text(&row, "actor").map(str::to_owned);
            let claim_shaped = matches!(
                row.get("claim_shaped"),
                Some(NormalizedValue::Integer(1)) | Some(NormalizedValue::Bool(true))
            );
            if !visible_hit
                || matches!(
                    event_type.as_str(),
                    "reconciliation.recorded.v1"
                        | "unit.superseded.v1"
                        | "receipt.dependency_audited.v1"
                )
            {
                return None;
            }
            let disclosed = bypass
                || actor
                    .as_deref()
                    .is_some_and(|actor| disclosable.get(actor).copied().unwrap_or(false));
            let holder = actor.as_deref() == Some(credential.as_str());
            row.remove("claim_shaped");
            if !disclosed {
                row.insert("actor".into(), NormalizedValue::Null);
                row.insert("run_key".into(), NormalizedValue::Null);
                row.insert("parent_key".into(), NormalizedValue::Null);
                row.insert("channel_kind".into(), NormalizedValue::Null);
            } else if claim_shaped && !bypass && !holder {
                row.insert("run_key".into(), NormalizedValue::Null);
                row.insert("parent_key".into(), NormalizedValue::Null);
            }
            if event_type == "receipt.committed.v1" {
                row.insert(
                    "type".into(),
                    NormalizedValue::Text("record.updated".into()),
                );
            }
            Some(row)
        })
        .collect();
    let links = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "links",
            &["SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} LIMIT 20001"],
        )
        .await?,
        &["created_at"],
    );
    let attachment_ids = records
        .iter()
        .filter(|row| {
            value_text(row, "type") == Some("Document")
                && value_text(row, "kind") == Some("attachment")
        })
        .filter_map(|row| value_text(row, "id"))
        .collect::<BTreeSet<_>>();
    let eligible_attachments = links
        .iter()
        .filter_map(|row| {
            let source = value_text(row, "source_id")?;
            let target = value_text(row, "target_id")?;
            (value_text(row, "relationship") == Some("part_of")
                && attachment_ids.contains(source)
                && visible.contains(target))
            .then_some(source.to_owned())
        })
        .collect::<BTreeSet<_>>();
    let projected_links = links
        .into_iter()
        .filter(|row| {
            value_text(row, "source_id").is_some_and(|id| visible.contains(id))
                && value_text(row, "target_id").is_some_and(|id| visible.contains(id))
        })
        .collect();
    let facets = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "facet_values",
            &["SELECT id,record_id,key,value,value_num,vocab_ref,created_at FROM {{relation}} LIMIT 20001"],
        )
        .await?,
        &["created_at"],
    );
    let visible_blob_ids = facets
        .iter()
        .filter(|row| {
            value_text(row, "key") == Some("blob_ref")
                && value_text(row, "record_id").is_some_and(|id| eligible_attachments.contains(id))
        })
        .filter_map(|row| value_text(row, "value").map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let projected_facets = facets
        .into_iter()
        .filter(|row| value_text(row, "record_id").is_some_and(|id| visible.contains(id)))
        .collect();
    let observations = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "facet_observations",
            &["SELECT id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq FROM {{relation}} LIMIT 20001"],
        )
        .await?,
        &["observed_at"],
    )
    .into_iter()
    .filter(|row| value_text(row, "record_id").is_some_and(|id| visible.contains(id)))
    .collect();
    let bindings = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "bindings",
            &["SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at FROM {{relation}} LIMIT 20001"],
        )
        .await?,
        &["last_seen_at"],
    );
    let owned = bindings
        .iter()
        .filter(|row| {
            value_text(row, "system") == Some("account")
                && value_text(row, "identifier") == Some(caller.credential())
                && value_bool(row, "is_canonical")
        })
        .filter_map(|row| value_text(row, "record_id").map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let projected_bindings = bindings
        .into_iter()
        .filter(|row| {
            value_text(row, "record_id")
                .is_some_and(|id| visible.contains(id) && owned.contains(id))
                && matches!(value_text(row, "system"), Some("account" | "email"))
        })
        .collect();
    // Blob payloads are the largest physical cells. Do not fetch them while
    // discovering visibility: only exact ids already proven reachable from a
    // visible attachment and its visible bearer cross this boundary.
    let blobs = with_millis(
        source_blob_rows(transaction, &mut budget, &visible_blob_ids).await?,
        &["created_at"],
    );
    let vocabularies = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "vocabularies",
            &["SELECT id,name,created_at FROM {{relation}} LIMIT 20001"],
        )
        .await?,
        &["created_at"],
    );
    let vocabulary_values = source_rows(
        transaction,
        &mut budget,
        "vocabulary_values",
        &["SELECT id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of FROM {{relation}} LIMIT 20001"],
    )
    .await?;
    let schema_config = with_millis(
        source_rows(
            transaction,
            &mut budget,
            "schema_config",
            &["SELECT id,layer,name,data,applies_to_collection_id,version_lineage,created_at FROM {{relation}} LIMIT 20001"],
        )
        .await?,
        &["created_at"],
    )
    .into_iter()
    .filter(|row| match row.get("applies_to_collection_id") {
        Some(NormalizedValue::Null) => true,
        _ => value_text(row, "applies_to_collection_id").is_some_and(|id| visible.contains(id)),
    })
    .collect();
    let task_items = if include_task_items {
        source_task_item_rows(transaction, &mut budget, &visible).await?
    } else {
        Vec::new()
    };

    let mut projection = crate::query::turso_sql::IsolatedProjection::default();
    projection.as_of_seq = as_of_seq;
    projection.insert("records", records)?;
    projection.insert("content_events", events)?;
    projection.insert("links", projected_links)?;
    projection.insert("facet_values", projected_facets)?;
    projection.insert("facet_observations", observations)?;
    projection.insert("bindings", projected_bindings)?;
    projection.insert("blobs", blobs)?;
    projection.insert("vocabularies", vocabularies)?;
    projection.insert("vocabulary_values", vocabulary_values)?;
    projection.insert("schema_config", schema_config)?;
    projection.insert("body_task_items", task_items)?;
    // Served catalog rows are generated from LOGICAL_RELATIONS (E2 I-2),
    // so Turso returns the same catalog as every other engine.
    projection.insert("catalog_relations", catalog_relation_rows())?;
    projection.insert("catalog_columns", catalog_column_rows())?;
    // The isolated core owns one closed logical catalog across profiles. Turso
    // rejects unavailable relations before building this projection, but the
    // core still requires their sealed table shapes to be present. Materialize
    // them empty so an unavailable profile relation can never acquire rows by
    // accident while ordinary Turso reads retain catalog-shape parity.
    for relation in crate::query::sql_contract::LOGICAL_RELATIONS {
        if !relation.profiles.contains(
            &crate::query::sql_contract::QuerySqlProfile::TursoLocal
                .contract()
                .id,
        ) {
            projection.insert(relation.name, Vec::new())?;
        }
    }
    let lifecycle_rows = if let Some(contexts) = lifecycle_contexts {
        use crate::query::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};
        if contexts.len() > 20_000 {
            return Err(projection_too_large(
                "record_lifecycle_interpretations exceeds the 20000 visible-record limit",
            ));
        }
        // The same snapshot and visible bearer set govern schema rows and
        // record rows. Loading through a second connection would mix epochs.
        let schema_rows = crate::query::cascade::schema_config_rows_with(transaction)
            .await?
            .into_iter()
            .filter(|row| {
                row.applies_to_collection_id
                    .as_deref()
                    .is_none_or(|id| visible.contains(id))
            })
            .collect();
        let interpreter =
            LifecycleInterpreter::load_from_rows_with(transaction, schema_rows).await?;
        let mut rows = Vec::with_capacity(contexts.len());
        let remaining = projection.remaining_encoded_bytes();
        let mut encoded_bytes = 2usize; // JSON array brackets
        if encoded_bytes > remaining {
            return Err(projection_too_large(
                "lifecycle projection has no encoded-byte budget",
            ));
        }
        for (index, (record_id, record_type, kind, home_id, raw)) in
            contexts.into_iter().enumerate()
        {
            if index % 64 == 0
                && (transaction.control.is_cancelled() || transaction.control.deadline_expired())
            {
                return Err(crate::query::turso_sql::control_error(&transaction.control));
            }
            let mut row = NormalizedRow::new();
            row.insert("record_id".into(), NormalizedValue::Text(record_id));
            for column in [
                "status",
                "raw",
                "axis_key",
                "axis_label",
                "vocabulary_id",
                "vocabulary_name",
                "value_id",
                "canonical",
                "terminality",
                "reason",
            ] {
                row.insert(column.into(), NormalizedValue::Null);
            }
            let mut put = |column: &str, value: String| {
                row.insert(column.into(), NormalizedValue::Text(value));
            };
            match interpreter.interpret(
                &record_type,
                kind.as_deref(),
                home_id.as_deref(),
                raw.as_deref(),
            ) {
                LifecycleInterpretation::Governed(value) => {
                    put("status", "governed".into());
                    put("raw", value.value.raw);
                    put("axis_key", value.axis.key);
                    put("axis_label", value.axis.label);
                    put("vocabulary_id", value.vocabulary.id);
                    put("vocabulary_name", value.vocabulary.name);
                    put("value_id", value.value.id);
                    put("canonical", value.value.canonical);
                    put("terminality", value.terminality);
                }
                LifecycleInterpretation::Absent(value) => {
                    put("status", "absent".into());
                    if let Some(axis) = value.axis {
                        put("axis_key", axis.key);
                        put("axis_label", axis.label);
                    }
                    if let Some(vocabulary) = value.vocabulary {
                        put("vocabulary_id", vocabulary.id);
                        put("vocabulary_name", vocabulary.name);
                    }
                }
                LifecycleInterpretation::Unclassified(value) => {
                    put("status", "unclassified".into());
                    put("raw", value.raw);
                    put("reason", value.reason.into());
                }
            }
            encoded_bytes =
                reserve_lifecycle_encoded_bytes(encoded_bytes, remaining, &row, index != 0)?;
            rows.push(row);
        }
        rows
    } else {
        Vec::new()
    };
    projection.insert("record_lifecycle_interpretations", lifecycle_rows)?;
    Ok(projection)
}

pub(super) async fn query_sql(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    query_sql_inner(db, caller, arguments, None).await
}

#[cfg(test)]
pub(super) async fn query_sql_with_worker_probe(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
    worker_probe: crate::query::turso_sql::CoreWorkerProbe,
) -> Result<Value> {
    query_sql_inner(db, caller, arguments, Some(worker_probe)).await
}

async fn query_sql_inner(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
    #[cfg(test)] worker_probe: Option<crate::query::turso_sql::CoreWorkerProbe>,
    #[cfg(not(test))] _worker_probe: Option<()>,
) -> Result<Value> {
    crate::query::sql_contract::require_available(
        crate::query::sql_contract::QuerySqlProfile::TursoLocal,
    )?;
    let request: crate::query::sql_contract::QuerySqlRequest =
        parse_arguments("query_sql", arguments)?;
    request.validate()?;
    // E2 ad-hoc default ORDER BY: an unordered top-level LIMIT is spliced
    // inside execute() (which owns a connection for label discovery), so the
    // determinism pre-check below would refuse it first — skip exactly that
    // case. execute() runs the full validation on the rewritten text, and
    // every other statement validates here unchanged.
    if !crate::query::turso_ast_rules::top_level_unordered_limit(&request.sql) {
        crate::query::turso_validate::validate(&request.sql)?;
    }
    let dependencies = crate::query::sql::validated_relation_dependencies(&request.sql)?;
    if let Some(relation) = crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .find(|relation| {
            dependencies.contains(relation.name)
                && !relation.profiles.contains(
                    &crate::query::sql_contract::QuerySqlProfile::TursoLocal
                        .contract()
                        .id,
                )
        })
    {
        return Err(crate::query::sql_contract::categorized_error(
            crate::query::sql_contract::QuerySqlErrorCategory::UnauthorizedRelation,
            format!(
                "query_sql relation '{}' is unavailable in profile turso-local",
                relation.name
            ),
        ));
    }
    crate::query::sql_contract::classify_single_read_statement(
        crate::query::sql_contract::QuerySqlProfile::TursoLocal,
        &request.sql,
    )?;
    let control = ExecutionControl::with_timeout(std::time::Duration::from_millis(
        crate::query::sql_contract::QUERY_DEADLINE_MS,
    ));
    let mut cancel_on_drop = CancelOnDrop(Some(control.clone()));
    let caller = caller.clone();
    let include_task_items = dependencies.contains("body_task_items");
    let include_lifecycle = dependencies.contains("record_lifecycle_interpretations");
    let projection = run_db_snapshot(db, &control, move |transaction| {
        Box::pin(async move {
            build_projection(transaction, &caller, include_task_items, include_lifecycle).await
        })
    })
    .await?;
    let worker_control = control.clone();
    let result = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some(probe) = worker_probe {
            return crate::query::turso_sql::execute_with_probe(
                projection,
                request,
                worker_control,
                probe,
                false,
            );
        }
        // E2 ad-hoc default ORDER BY is enabled: this is the ad-hoc
        // `query_sql` entry, the only Turso caller that may assume an order.
        crate::query::turso_sql::execute(projection, request, worker_control, true)
    })
    .await
    .map_err(|error| Error::engine(format!("query_sql core worker failed: {error}")))?;
    cancel_on_drop.0 = None;
    let result = result?;
    serde_json::to_value(result).map_err(Into::into)
}

struct CancelOnDrop(Option<ExecutionControl>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(control) = &self.0 {
            control.cancel();
        }
    }
}
