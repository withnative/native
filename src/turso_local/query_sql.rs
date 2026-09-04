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
        .map(|column| {
            let logical_type = match (relation, *column) {
                ("content_events", "local_seq")
                | ("facet_observations", "event_seq")
                | ("blobs", "size_bytes") => LogicalType::Integer,
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
    let preflight = statement(StatementKind::Select, relation, source_preflight(relation))
        .map_err(|error| stable("query_sql projection preflight", error))?;
    let preflight = transaction
        .rows(
            "query_sql projection preflight",
            &preflight,
            &[],
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
    let rows = transaction
        .rows("query_sql projection", &statement, &[], &columns(relation))
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
        "records" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(type AS BLOB)),0),coalesce(length(CAST(kind AS BLOB)),0),coalesce(length(CAST(name AS BLOB)),0),coalesce(length(CAST(body AS BLOB)),0),coalesce(length(CAST(home_id AS BLOB)),0),coalesce(length(CAST(lifecycle AS BLOB)),0),coalesce(length(CAST(persistence AS BLOB)),0),coalesce(length(CAST(maturity AS BLOB)),0),coalesce(length(CAST(summary AS BLOB)),0),coalesce(length(CAST(last_activity_at AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0),coalesce(length(CAST(updated_at AS BLOB)),0),coalesce(length(CAST(deleted_at AS BLOB)),0))) AS max_cell_bytes,sum(128+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(type AS BLOB)),0)+coalesce(length(CAST(kind AS BLOB)),0)+coalesce(length(CAST(name AS BLOB)),0)+coalesce(length(CAST(body AS BLOB)),0)+coalesce(length(CAST(home_id AS BLOB)),0)+coalesce(length(CAST(lifecycle AS BLOB)),0)+coalesce(length(CAST(persistence AS BLOB)),0)+coalesce(length(CAST(maturity AS BLOB)),0)+coalesce(length(CAST(summary AS BLOB)),0)+coalesce(length(CAST(last_activity_at AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)+coalesce(length(CAST(updated_at AS BLOB)),0)+coalesce(length(CAST(deleted_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,type,kind,name,body,home_id,lifecycle,persistence,maturity,summary,last_activity_at,created_at,updated_at,deleted_at FROM {{relation}} WHERE deleted_at IS NULL LIMIT 20001)"],
        "semantic_units" => &["SELECT count(*) AS candidate_count,max(coalesce(length(CAST(unit_id AS BLOB)),0)) AS max_cell_bytes,sum(32+coalesce(length(CAST(unit_id AS BLOB)),0)) AS candidate_bytes FROM (SELECT unit_id FROM {{relation}} LIMIT 20001)"],
        "content_events" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(local_seq AS BLOB)),0),coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(type AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(local_seq AS BLOB)),0)+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(type AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT seq AS local_seq,id,record_id,type,created_at FROM {{relation}} LIMIT 20001)"],
        "links" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(source_id AS BLOB)),0),coalesce(length(CAST(target_id AS BLOB)),0),coalesce(length(CAST(relationship AS BLOB)),0),coalesce(length(CAST(note AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(source_id AS BLOB)),0)+coalesce(length(CAST(target_id AS BLOB)),0)+coalesce(length(CAST(relationship AS BLOB)),0)+coalesce(length(CAST(note AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} LIMIT 20001)"],
        "facet_values" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(key AS BLOB)),0),coalesce(length(CAST(value AS BLOB)),0),coalesce(length(CAST(value_num AS BLOB)),0),coalesce(length(CAST(vocab_ref AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(key AS BLOB)),0)+coalesce(length(CAST(value AS BLOB)),0)+coalesce(length(CAST(value_num AS BLOB)),0)+coalesce(length(CAST(vocab_ref AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,record_id,key,value,value_num,vocab_ref,created_at FROM {{relation}} LIMIT 20001)"],
        "facet_observations" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(key AS BLOB)),0),coalesce(length(CAST(value AS BLOB)),0),coalesce(length(CAST(op AS BLOB)),0),coalesce(length(CAST(vocab_ref AS BLOB)),0),coalesce(length(CAST(as_of AS BLOB)),0),coalesce(length(CAST(observed_at AS BLOB)),0),coalesce(length(CAST(event_seq AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(key AS BLOB)),0)+coalesce(length(CAST(value AS BLOB)),0)+coalesce(length(CAST(op AS BLOB)),0)+coalesce(length(CAST(vocab_ref AS BLOB)),0)+coalesce(length(CAST(as_of AS BLOB)),0)+coalesce(length(CAST(observed_at AS BLOB)),0)+coalesce(length(CAST(event_seq AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq FROM {{relation}} LIMIT 20001)"],
        "bindings" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(record_id AS BLOB)),0),coalesce(length(CAST(system AS BLOB)),0),coalesce(length(CAST(identifier AS BLOB)),0),coalesce(length(CAST(is_canonical AS BLOB)),0),coalesce(length(CAST(url AS BLOB)),0),coalesce(length(CAST(etag AS BLOB)),0),coalesce(length(CAST(last_seen_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(record_id AS BLOB)),0)+coalesce(length(CAST(system AS BLOB)),0)+coalesce(length(CAST(identifier AS BLOB)),0)+coalesce(length(CAST(is_canonical AS BLOB)),0)+coalesce(length(CAST(url AS BLOB)),0)+coalesce(length(CAST(etag AS BLOB)),0)+coalesce(length(CAST(last_seen_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at FROM {{relation}} LIMIT 20001)"],
        "blobs" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(bytes AS BLOB)),0),coalesce(length(CAST(mime AS BLOB)),0),coalesce(length(CAST(size_bytes AS BLOB)),0),coalesce(length(CAST(sha256 AS BLOB)),0),coalesce(length(CAST(original_filename AS BLOB)),0),coalesce(length(CAST(storage_tier AS BLOB)),0),coalesce(length(CAST(external_ref AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(bytes AS BLOB)),0)+coalesce(length(CAST(mime AS BLOB)),0)+coalesce(length(CAST(size_bytes AS BLOB)),0)+coalesce(length(CAST(sha256 AS BLOB)),0)+coalesce(length(CAST(original_filename AS BLOB)),0)+coalesce(length(CAST(storage_tier AS BLOB)),0)+coalesce(length(CAST(external_ref AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref,created_at FROM {{relation}} LIMIT 20001)"],
        "vocabularies" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(name AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(32+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(name AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,name,created_at FROM {{relation}} LIMIT 20001)"],
        "vocabulary_values" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(vocabulary_id AS BLOB)),0),coalesce(length(CAST(value AS BLOB)),0),coalesce(length(CAST(gloss AS BLOB)),0),coalesce(length(CAST(status AS BLOB)),0),coalesce(length(CAST(ordinal AS BLOB)),0),coalesce(length(CAST(terminality AS BLOB)),0),coalesce(length(CAST(metadata AS BLOB)),0),coalesce(length(CAST(alias_of AS BLOB)),0))) AS max_cell_bytes,sum(96+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(vocabulary_id AS BLOB)),0)+coalesce(length(CAST(value AS BLOB)),0)+coalesce(length(CAST(gloss AS BLOB)),0)+coalesce(length(CAST(status AS BLOB)),0)+coalesce(length(CAST(ordinal AS BLOB)),0)+coalesce(length(CAST(terminality AS BLOB)),0)+coalesce(length(CAST(metadata AS BLOB)),0)+coalesce(length(CAST(alias_of AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of FROM {{relation}} LIMIT 20001)"],
        "schema_config" => &["SELECT count(*) AS candidate_count,max(max(coalesce(length(CAST(id AS BLOB)),0),coalesce(length(CAST(layer AS BLOB)),0),coalesce(length(CAST(name AS BLOB)),0),coalesce(length(CAST(data AS BLOB)),0),coalesce(length(CAST(applies_to_collection_id AS BLOB)),0),coalesce(length(CAST(version_lineage AS BLOB)),0),coalesce(length(CAST(created_at AS BLOB)),0))) AS max_cell_bytes,sum(64+coalesce(length(CAST(id AS BLOB)),0)+coalesce(length(CAST(layer AS BLOB)),0)+coalesce(length(CAST(name AS BLOB)),0)+coalesce(length(CAST(data AS BLOB)),0)+coalesce(length(CAST(applies_to_collection_id AS BLOB)),0)+coalesce(length(CAST(version_lineage AS BLOB)),0)+coalesce(length(CAST(created_at AS BLOB)),0)) AS candidate_bytes FROM (SELECT id,layer,name,data,applies_to_collection_id,version_lineage,created_at FROM {{relation}} LIMIT 20001)"],
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

async fn build_projection(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
) -> Result<crate::query::turso_sql::IsolatedProjection> {
    let mut budget = SourceBudget::default();
    let mut records = source_rows(
        transaction,
        &mut budget,
        "records",
        &["SELECT id,type,kind,name,body,home_id,lifecycle,persistence,maturity,summary,last_activity_at,created_at,updated_at,deleted_at FROM {{relation}} WHERE deleted_at IS NULL LIMIT 20001"],
    )
    .await?;
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
    for row in &mut records {
        if value_text(row, "home_id").is_some_and(|home| !visible.contains(home)) {
            row.insert("home_id".into(), NormalizedValue::Null);
        }
    }

    let events = source_rows(
        transaction,
        &mut budget,
        "content_events",
        &["SELECT seq AS local_seq,id,record_id,type,created_at FROM {{relation}} LIMIT 20001"],
    )
    .await?
    .into_iter()
    .filter_map(|mut row| {
        let record_id = value_text(&row, "record_id")?;
        let event_type = value_text(&row, "type")?;
        if !visible.contains(record_id)
            || matches!(
                event_type,
                "reconciliation.recorded.v1"
                    | "unit.superseded.v1"
                    | "receipt.dependency_audited.v1"
            )
        {
            return None;
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
    let links = source_rows(
        transaction,
        &mut budget,
        "links",
        &["SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} LIMIT 20001"],
    )
    .await?;
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
    let facets = source_rows(
        transaction,
        &mut budget,
        "facet_values",
        &["SELECT id,record_id,key,value,value_num,vocab_ref,created_at FROM {{relation}} LIMIT 20001"],
    )
    .await?;
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
    let observations = source_rows(
        transaction,
        &mut budget,
        "facet_observations",
        &["SELECT id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq FROM {{relation}} LIMIT 20001"],
    )
    .await?
    .into_iter()
    .filter(|row| value_text(row, "record_id").is_some_and(|id| visible.contains(id)))
    .collect();
    let bindings = source_rows(
        transaction,
        &mut budget,
        "bindings",
        &["SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at FROM {{relation}} LIMIT 20001"],
    )
    .await?;
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
    let blobs = source_blob_rows(transaction, &mut budget, &visible_blob_ids).await?;
    let vocabularies = source_rows(
        transaction,
        &mut budget,
        "vocabularies",
        &["SELECT id,name,created_at FROM {{relation}} LIMIT 20001"],
    )
    .await?;
    let vocabulary_values = source_rows(
        transaction,
        &mut budget,
        "vocabulary_values",
        &["SELECT id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of FROM {{relation}} LIMIT 20001"],
    )
    .await?;
    let schema_config = source_rows(
        transaction,
        &mut budget,
        "schema_config",
        &["SELECT id,layer,name,data,applies_to_collection_id,version_lineage,created_at FROM {{relation}} LIMIT 20001"],
    )
    .await?
    .into_iter()
    .filter(|row| match row.get("applies_to_collection_id") {
        Some(NormalizedValue::Null) => true,
        _ => value_text(row, "applies_to_collection_id").is_some_and(|id| visible.contains(id)),
    })
    .collect();

    let mut projection = crate::query::turso_sql::IsolatedProjection::default();
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
    crate::query::turso_validate::validate(&request.sql)?;
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
    let projection = run_db_snapshot(db, &control, move |transaction| {
        Box::pin(async move { build_projection(transaction, &caller).await })
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
            );
        }
        crate::query::turso_sql::execute(projection, request, worker_control)
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
