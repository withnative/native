//! Durable targets and deterministic resolution for target-bearing Annotations.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::blob::BLOB_REF_FACET_KEY;
use crate::db::{apply_schema, open_database, Db};
use crate::error::{Error, Result};
use crate::events::AnnotationTargetSetPayload;
use crate::query::events;
use crate::query::lens::{LiveBlobRead, ReadLens};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnotationTargetInput {
    pub target_record_id: String,
    pub source_slot: SourceSlot,
    pub selectors: Vec<SelectorInput>,
    pub purpose: Option<String>,
}

/// Backward-compatible name retained for the citation-specific management
/// tool. The storage and validation contract is shared by target-bearing
/// Annotations, including anchored comment roots.
pub type CitationTargetInput = AnnotationTargetInput;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceSlot {
    Body,
    Blob,
}

impl SourceSlot {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Blob => "blob",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelectorInput {
    TextQuote {
        exact: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suffix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        position_hint: Option<u64>,
    },
    DataPosition {
        start: u64,
        end: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_sha256: Option<String>,
    },
    Fragment {
        conforms_to: String,
        value: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotationTargetView {
    pub annotation_id: String,
    pub target_record_id: String,
    pub source_slot: String,
    pub source_state: Value,
    pub selectors: Value,
    pub purpose: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub validation: ValidationSummary,
    pub anchored: Value,
    pub current: Value,
    pub display: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationSummary {
    pub status: ValidationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Current,
    Relocated,
    Stale,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone)]
struct TargetRow {
    annotation_id: String,
    target_record_id: String,
    source_slot: String,
    source_event_seq: Option<i64>,
    blob_id: Option<String>,
    source_sha256: String,
    selectors: Value,
    purpose: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct Representation {
    bytes: Vec<u8>,
    sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn body_at(
    content_log: &sqlx::SqlitePool,
    record_id: &str,
    seq: i64,
) -> Result<Option<Representation>> {
    let prefix = events::log_prefix_in_pool(content_log, seq).await?;
    let scratch = open_database(":memory:").await?;
    apply_schema(&scratch).await?;
    let outcome = async {
        // One transaction for the same reason `lens::replay_projection` takes
        // one: a bare connection autocommits every projector statement, and a
        // scratch database is a real WAL file at `synchronous=FULL`, so the
        // fold pays a flush several times per event. Reconstructing one body
        // anchor should not cost a commit per event in the workspace.
        let mut tx = scratch.write_pool().begin().await?;
        // Blob citation events earlier in the prefix need FK identities only;
        // never hydrate their potentially large bytes while reconstructing an
        // unrelated body anchor.
        crate::projector::replay_with_blob_placeholders(&mut tx, &prefix).await?;
        let body: Option<Option<String>> =
            sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                .bind(record_id)
                .fetch_optional(&mut *tx)
                .await?;
        // The anchor has been read from inside the fold, and the scratch is
        // closed below, so there is nothing to publish to another connection.
        // Rolling back explicitly says that, and skips the commit's flush.
        tx.rollback().await?;
        Ok::<_, crate::Error>(body.map(|body| {
            let bytes = body.unwrap_or_default().into_bytes();
            Representation {
                sha256: digest(&bytes),
                bytes,
            }
        }))
    }
    .await;
    scratch.close().await;
    outcome
}

async fn blob_bytes(blobs: LiveBlobRead<'_>, blob_id: &str) -> Result<Option<Representation>> {
    let row = sqlx::query("SELECT bytes, storage_tier FROM blobs WHERE id = ?")
        .bind(blob_id)
        .fetch_optional(blobs.shared_pool())
        .await?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<String, _>("storage_tier")? != "inline" {
        return Ok(None);
    }
    let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>("bytes")? else {
        return Ok(None);
    };
    Ok(Some(Representation {
        sha256: digest(&bytes),
        bytes,
    }))
}

async fn current_representation(
    lens: &ReadLens<'_>,
    target: &TargetRow,
) -> Result<Option<Representation>> {
    let db = lens.projection().snapshot_pool();
    let live: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM records WHERE id = ? AND deleted_at IS NULL")
            .bind(&target.target_record_id)
            .fetch_optional(db)
            .await?;
    if live.is_none() {
        return Ok(None);
    }
    match target.source_slot.as_str() {
        "body" => {
            let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                .bind(&target.target_record_id)
                .fetch_one(db)
                .await?;
            let bytes = body.unwrap_or_default().into_bytes();
            Ok(Some(Representation {
                sha256: digest(&bytes),
                bytes,
            }))
        }
        "blob" => {
            let current_blob: Option<String> = sqlx::query_scalar(
                "SELECT value FROM facet_values WHERE record_id = ? AND key = ?",
            )
            .bind(&target.target_record_id)
            .bind(BLOB_REF_FACET_KEY)
            .fetch_optional(db)
            .await?;
            match current_blob {
                Some(id) => blob_bytes(lens.blobs(), &id).await,
                None => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

async fn current_representation_on(
    conn: &mut SqliteConnection,
    target: &TargetRow,
) -> Result<Option<Representation>> {
    let live: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM records WHERE id = ? AND deleted_at IS NULL")
            .bind(&target.target_record_id)
            .fetch_optional(&mut *conn)
            .await?;
    if live.is_none() {
        return Ok(None);
    }
    match target.source_slot.as_str() {
        "body" => {
            let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                .bind(&target.target_record_id)
                .fetch_one(&mut *conn)
                .await?;
            let bytes = body.unwrap_or_default().into_bytes();
            Ok(Some(Representation {
                sha256: digest(&bytes),
                bytes,
            }))
        }
        "blob" => {
            let current_blob: Option<String> = sqlx::query_scalar(
                "SELECT value FROM facet_values WHERE record_id = ? AND key = ?",
            )
            .bind(&target.target_record_id)
            .bind(BLOB_REF_FACET_KEY)
            .fetch_optional(&mut *conn)
            .await?;
            let Some(blob_id) = current_blob else {
                return Ok(None);
            };
            let row = sqlx::query("SELECT bytes, storage_tier FROM blobs WHERE id = ?")
                .bind(blob_id)
                .fetch_optional(conn)
                .await?;
            let Some(row) = row else { return Ok(None) };
            if row.try_get::<String, _>("storage_tier")? != "inline" {
                return Ok(None);
            }
            let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>("bytes")? else {
                return Ok(None);
            };
            Ok(Some(Representation {
                sha256: digest(&bytes),
                bytes,
            }))
        }
        _ => Ok(None),
    }
}

async fn anchored_representation(
    lens: &ReadLens<'_>,
    target: &TargetRow,
) -> Result<Option<Representation>> {
    match target.source_slot.as_str() {
        "body" => {
            body_at(
                lens.content_log().snapshot_pool(),
                &target.target_record_id,
                target.source_event_seq.unwrap_or_default(),
            )
            .await
        }
        "blob" => match target.blob_id.as_deref() {
            Some(id) => blob_bytes(lens.blobs(), id).await,
            None => Ok(None),
        },
        _ => Ok(None),
    }
}

fn quote_matches(
    bytes: &[u8],
    exact: &str,
    prefix: Option<&str>,
    suffix: Option<&str>,
) -> Vec<(usize, usize)> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    text.match_indices(exact)
        .filter_map(|(start, matched)| {
            let end = start + matched.len();
            let prefix_ok = prefix.is_none_or(|p| text[..start].ends_with(p));
            let suffix_ok = suffix.is_none_or(|s| text[end..].starts_with(s));
            (prefix_ok && suffix_ok).then_some((start, end))
        })
        .collect()
}

fn exact_matches(bytes: &[u8], needle: &[u8]) -> Vec<(usize, usize)> {
    if needle.is_empty() || needle.len() > bytes.len() {
        return Vec::new();
    }

    // KMP keeps relocation linear in source + selection size. The previous
    // implementation re-hashed every same-length window, multiplying the two
    // sizes for large finance attachments.
    let mut prefix = vec![0usize; needle.len()];
    for i in 1..needle.len() {
        let mut matched = prefix[i - 1];
        while matched > 0 && needle[i] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if needle[i] == needle[matched] {
            matched += 1;
        }
        prefix[i] = matched;
    }

    let mut ranges = Vec::new();
    let mut matched = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        while matched > 0 && *byte != needle[matched] {
            matched = prefix[matched - 1];
        }
        if *byte == needle[matched] {
            matched += 1;
        }
        if matched == needle.len() {
            let end = index + 1;
            ranges.push((end - needle.len(), end));
            matched = prefix[matched - 1];
        }
    }
    ranges
}

const RFC_7111: &str = "https://www.rfc-editor.org/rfc/rfc7111";

#[derive(Debug, Clone, Copy)]
enum CsvCoordinate {
    Row(usize),
    Cell { row: usize, column: usize },
}

#[derive(Debug)]
struct CsvRow {
    range: (usize, usize),
    cells: Vec<(usize, usize)>,
}

fn positive_coordinate(value: &str, label: &str) -> Result<usize> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::engine(format!(
            "RFC 7111 {label} must be a positive base-10 integer without leading zeroes"
        )));
    }
    value
        .parse::<usize>()
        .map_err(|_| Error::engine(format!("RFC 7111 {label} is too large")))
}

fn parse_csv_coordinate(conforms_to: &str, value: &str) -> Result<CsvCoordinate> {
    if conforms_to != RFC_7111 {
        return Err(Error::engine(format!(
            "unsupported fragment conformance {conforms_to:?}; citation fragments support only {RFC_7111}"
        )));
    }
    if let Some(row) = value.strip_prefix("row=") {
        if row.contains([',', '-', ';', '*']) {
            return Err(Error::engine(
                "citation RFC 7111 v1 supports one row coordinate only: row=N",
            ));
        }
        return Ok(CsvCoordinate::Row(positive_coordinate(row, "row")?));
    }
    if let Some(cell) = value.strip_prefix("cell=") {
        if cell.contains(['-', ';', '*']) {
            return Err(Error::engine(
                "citation RFC 7111 v1 supports one cell coordinate only: cell=ROW,COLUMN",
            ));
        }
        let mut parts = cell.split(',');
        let row = parts.next().unwrap_or_default();
        let column = parts.next().unwrap_or_default();
        if parts.next().is_some() {
            return Err(Error::engine(
                "citation RFC 7111 cell coordinate must be cell=ROW,COLUMN",
            ));
        }
        return Ok(CsvCoordinate::Cell {
            row: positive_coordinate(row, "cell row")?,
            column: positive_coordinate(column, "cell column")?,
        });
    }
    Err(Error::engine(
        "citation RFC 7111 v1 supports only row=N or cell=ROW,COLUMN",
    ))
}

fn csv_rows(bytes: &[u8]) -> Result<Vec<CsvRow>> {
    let mut rows = Vec::new();
    let mut cells = Vec::new();
    let mut row_start = 0usize;
    let mut field_start = 0usize;
    let mut in_quotes = false;
    let mut quote_closed = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_quotes {
            if byte == b'"' {
                if bytes.get(index + 1) == Some(&b'"') {
                    index += 2;
                } else {
                    in_quotes = false;
                    quote_closed = true;
                    index += 1;
                }
            } else {
                index += 1;
            }
            continue;
        }

        match byte {
            b'"' if index == field_start && !quote_closed => {
                in_quotes = true;
                index += 1;
            }
            b'"' => {
                return Err(Error::engine(
                    "malformed CSV: quote must open at the start of a field",
                ));
            }
            b',' => {
                cells.push((field_start, index));
                index += 1;
                field_start = index;
                quote_closed = false;
            }
            b'\n' => {
                cells.push((field_start, index));
                rows.push(CsvRow {
                    range: (row_start, index),
                    cells: std::mem::take(&mut cells),
                });
                index += 1;
                row_start = index;
                field_start = index;
                quote_closed = false;
            }
            b'\r' => {
                if bytes.get(index + 1) != Some(&b'\n') {
                    return Err(Error::engine(
                        "malformed CSV: bare carriage return outside a quoted field",
                    ));
                }
                cells.push((field_start, index));
                rows.push(CsvRow {
                    range: (row_start, index),
                    cells: std::mem::take(&mut cells),
                });
                index += 2;
                row_start = index;
                field_start = index;
                quote_closed = false;
            }
            _ if quote_closed => {
                return Err(Error::engine(
                    "malformed CSV: characters follow a closing quote before the delimiter",
                ));
            }
            _ => index += 1,
        }
    }
    if in_quotes {
        return Err(Error::engine("malformed CSV: unterminated quoted field"));
    }
    if row_start < bytes.len() {
        cells.push((field_start, bytes.len()));
        rows.push(CsvRow {
            range: (row_start, bytes.len()),
            cells,
        });
    }
    Ok(rows)
}

fn fragment_range(conforms_to: &str, value: &str, bytes: &[u8]) -> Result<(usize, usize)> {
    let coordinate = parse_csv_coordinate(conforms_to, value)?;
    let rows = csv_rows(bytes)?;
    match coordinate {
        CsvCoordinate::Row(row) => rows
            .get(row - 1)
            .map(|row| row.range)
            .ok_or_else(|| Error::engine(format!("RFC 7111 row {row} is outside the CSV"))),
        CsvCoordinate::Cell { row, column } => rows
            .get(row - 1)
            .ok_or_else(|| Error::engine(format!("RFC 7111 row {row} is outside the CSV")))?
            .cells
            .get(column - 1)
            .copied()
            .ok_or_else(|| {
                Error::engine(format!("RFC 7111 cell {row},{column} is outside the CSV"))
            }),
    }
}

/// Validate and canonicalize selectors against the exact captured bytes.
/// Citation creation and semantic Occurrence binding share this one integrity
/// contract so neither path can admit a weaker coordinate-only anchor.
pub(crate) fn canonicalize_selectors(
    mut selectors: Vec<SelectorInput>,
    bytes: &[u8],
) -> Result<Vec<SelectorInput>> {
    if selectors.is_empty() {
        return Err(Error::engine("target requires at least one selector"));
    }
    let has_fragment = selectors
        .iter()
        .any(|selector| matches!(selector, SelectorInput::Fragment { .. }));
    let has_position = selectors
        .iter()
        .any(|selector| matches!(selector, SelectorInput::DataPosition { .. }));
    if has_fragment && !has_position {
        return Err(Error::engine(
            "fragment selectors require a paired data_position integrity selector",
        ));
    }
    // Canonicalize positional integrity first. A caller may pair an ambiguous
    // quote with one exact byte position to identify the captured occurrence;
    // the stored position hint is never trusted for later relocation.
    for selector in &mut selectors {
        match selector {
            SelectorInput::TextQuote { .. } => {}
            SelectorInput::DataPosition {
                start,
                end,
                selected_sha256,
            } => {
                let start_usize = usize::try_from(*start)
                    .map_err(|_| Error::engine("data_position start is too large"))?;
                let end_usize = usize::try_from(*end)
                    .map_err(|_| Error::engine("data_position end is too large"))?;
                if start_usize >= end_usize || end_usize > bytes.len() {
                    return Err(Error::engine(format!(
                        "data_position [{start},{end}) is outside source length {}",
                        bytes.len()
                    )));
                }
                if std::str::from_utf8(bytes).is_ok()
                    && (std::str::from_utf8(&bytes[..start_usize]).is_err()
                        || std::str::from_utf8(&bytes[..end_usize]).is_err())
                {
                    return Err(Error::engine(
                        "data_position boundaries split a UTF-8 code point",
                    ));
                }
                let computed = digest(&bytes[start_usize..end_usize]);
                if selected_sha256
                    .as_deref()
                    .is_some_and(|provided| provided != computed)
                {
                    return Err(Error::engine(
                        "data_position selected_sha256 does not match source bytes",
                    ));
                }
                *selected_sha256 = Some(computed);
            }
            SelectorInput::Fragment { conforms_to, value } => {
                fragment_range(conforms_to, value, bytes)?;
            }
        }
    }
    let position_range = selectors.iter().find_map(|selector| match selector {
        SelectorInput::DataPosition { start, end, .. } => {
            usize::try_from(*start).ok().zip(usize::try_from(*end).ok())
        }
        _ => None,
    });
    for selector in &mut selectors {
        let SelectorInput::TextQuote {
            exact,
            prefix,
            suffix,
            position_hint,
        } = selector
        else {
            continue;
        };
        if exact.is_empty() {
            return Err(Error::engine("text_quote exact must not be empty"));
        }
        let matches = quote_matches(bytes, exact, prefix.as_deref(), suffix.as_deref());
        let selected = if matches.len() == 1 {
            matches[0]
        } else if let Some(position) = position_range.filter(|position| matches.contains(position))
        {
            position
        } else {
            return Err(Error::engine(format!(
                "text_quote must identify exactly one anchored segment, or agree with data_position; found {}",
                matches.len()
            )));
        };
        *position_hint = Some(selected.0 as u64);
    }
    selector_ranges(&selectors, bytes, None)?;
    Ok(selectors)
}

pub(crate) fn selector_ranges(
    selectors: &[SelectorInput],
    bytes: &[u8],
    relocation_evidence: Option<&[u8]>,
) -> Result<Vec<(usize, usize)>> {
    let mut ranges = Vec::new();
    for selector in selectors {
        let matches = match selector {
            SelectorInput::TextQuote {
                exact,
                prefix,
                suffix,
                position_hint,
            } => {
                // Prefix/suffix and the captured position disambiguate the
                // original representation only. Once the source changes they
                // are expected to drift: relocation is based on the exact
                // selected bytes, and succeeds only when those bytes occur
                // once. Repeated evidence therefore remains a conflict rather
                // than being steered by stale surrounding context.
                let matches = if relocation_evidence.is_some() {
                    exact_matches(bytes, exact.as_bytes())
                } else {
                    quote_matches(bytes, exact, prefix.as_deref(), suffix.as_deref())
                };
                if relocation_evidence.is_none() && matches.len() > 1 {
                    position_hint
                        .and_then(|hint| usize::try_from(hint).ok())
                        .and_then(|hint| matches.iter().copied().find(|range| range.0 == hint))
                        .into_iter()
                        .collect()
                } else {
                    matches
                }
            }
            SelectorInput::DataPosition {
                start,
                end,
                selected_sha256,
            } => {
                let start = usize::try_from(*start)
                    .map_err(|_| Error::engine("citation byte start is too large"))?;
                let end = usize::try_from(*end)
                    .map_err(|_| Error::engine("citation byte end is too large"))?;
                let expected = selected_sha256.as_deref().ok_or_else(|| {
                    Error::engine("citation data_position is missing selected_sha256")
                })?;
                if let Some(evidence) = relocation_evidence {
                    if digest(evidence) != expected {
                        return Err(Error::engine(
                            "anchored evidence does not match data_position digest",
                        ));
                    }
                    exact_matches(bytes, evidence)
                } else if start < end
                    && end <= bytes.len()
                    && digest(&bytes[start..end]) == expected
                {
                    vec![(start, end)]
                } else {
                    Vec::new()
                }
            }
            SelectorInput::Fragment { conforms_to, value } => {
                vec![fragment_range(conforms_to, value, bytes)?]
            }
        };
        if matches.len() > 1 {
            return Err(Error::engine("selector has multiple exact matches"));
        }
        let Some(one) = matches.first().copied() else {
            return Err(Error::engine("selector has no exact match"));
        };
        ranges.push(one);
    }
    if ranges.is_empty() {
        return Err(Error::engine("citation has no integrity selector"));
    }
    if ranges.iter().any(|range| *range != ranges[0]) {
        return Err(Error::engine(
            "citation selectors disagree about the selected segment",
        ));
    }
    Ok(ranges)
}

fn evidence(bytes: &[u8], range: (usize, usize)) -> Value {
    let selected = &bytes[range.0..range.1];
    match std::str::from_utf8(selected) {
        Ok(text) => json!({ "start": range.0, "end": range.1, "text": text }),
        Err(_) => json!({
            "start": range.0,
            "end": range.1,
            "base64": base64::engine::general_purpose::STANDARD.encode(selected)
        }),
    }
}

async fn target_row_in_pool(
    pool: &sqlx::SqlitePool,
    annotation_id: &str,
) -> Result<Option<TargetRow>> {
    let mut conn = pool.acquire().await?;
    target_row_on(&mut conn, annotation_id).await
}

async fn target_row(db: &Db, annotation_id: &str) -> Result<Option<TargetRow>> {
    let mut conn = db.write_pool().acquire().await?;
    target_row_on(&mut conn, annotation_id).await
}

async fn target_row_on(
    conn: &mut SqliteConnection,
    annotation_id: &str,
) -> Result<Option<TargetRow>> {
    let row = sqlx::query(
        "SELECT annotation_id, target_record_id, source_slot, source_event_seq, blob_id,
                source_sha256, selectors, purpose, created_at, updated_at
           FROM annotation_targets WHERE annotation_id = ?",
    )
    .bind(annotation_id)
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(TargetRow {
            annotation_id: row.try_get("annotation_id")?,
            target_record_id: row.try_get("target_record_id")?,
            source_slot: row.try_get("source_slot")?,
            source_event_seq: row.try_get("source_event_seq")?,
            blob_id: row.try_get("blob_id")?,
            source_sha256: row.try_get("source_sha256")?,
            selectors: serde_json::from_str(&row.try_get::<String, _>("selectors")?)?,
            purpose: row.try_get("purpose")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    })
    .transpose()
}

fn parsed_selectors(target: &TargetRow) -> Result<Vec<SelectorInput>> {
    serde_json::from_value(target.selectors.clone()).map_err(Into::into)
}

fn validation_from(
    target: &TargetRow,
    selectors: &[SelectorInput],
    anchored: Option<&Representation>,
    current: Option<&Representation>,
) -> ValidationSummary {
    let Some(anchored) = anchored else {
        return ValidationSummary {
            status: ValidationStatus::Unavailable,
            detail: Some("anchored source representation is unavailable".into()),
        };
    };
    if anchored.sha256 != target.source_sha256 {
        return ValidationSummary {
            status: ValidationStatus::Unavailable,
            detail: Some("anchored source digest no longer verifies".into()),
        };
    }
    let anchored_ranges = match selector_ranges(selectors, &anchored.bytes, None) {
        Ok(ranges) => ranges,
        Err(error) => {
            return ValidationSummary {
                status: ValidationStatus::Conflict,
                detail: Some(error.to_string()),
            };
        }
    };
    let anchored_evidence = &anchored.bytes[anchored_ranges[0].0..anchored_ranges[0].1];
    let Some(current) = current else {
        return ValidationSummary {
            status: ValidationStatus::Stale,
            detail: Some(
                "anchored evidence is verified, but the current source representation is unavailable"
                    .into(),
            ),
        };
    };
    if current.sha256 == target.source_sha256 {
        return ValidationSummary {
            status: ValidationStatus::Current,
            detail: None,
        };
    }
    match selector_ranges(selectors, &current.bytes, Some(anchored_evidence)) {
        Ok(_) => ValidationSummary {
            status: ValidationStatus::Relocated,
            detail: Some("the exact evidence exists exactly once in the current source".into()),
        },
        Err(error)
            if error.to_string().contains("multiple") || error.to_string().contains("disagree") =>
        {
            ValidationSummary {
                status: ValidationStatus::Conflict,
                detail: Some(error.to_string()),
            }
        }
        Err(error) => ValidationSummary {
            status: ValidationStatus::Stale,
            detail: Some(error.to_string()),
        },
    }
}

async fn resolved_values(
    lens: &ReadLens<'_>,
    target: &TargetRow,
) -> Result<(ValidationSummary, Value, Value)> {
    let selectors = parsed_selectors(target)?;
    let anchored = anchored_representation(lens, target).await?;
    let current = current_representation(lens, target).await?;
    let (anchored_value, anchored_evidence) = match anchored.as_ref() {
        Some(rep) if rep.sha256 == target.source_sha256 => {
            match selector_ranges(&selectors, &rep.bytes, None) {
                Ok(ranges) => (
                    json!({ "available": true, "source_sha256": rep.sha256, "excerpt": evidence(&rep.bytes, ranges[0]) }),
                    Some(rep.bytes[ranges[0].0..ranges[0].1].to_vec()),
                ),
                Err(error) => (
                    json!({ "available": true, "source_sha256": rep.sha256, "conflict": error.to_string() }),
                    None,
                ),
            }
        }
        _ => (json!({ "available": false }), None),
    };
    let validation = validation_from(target, &selectors, anchored.as_ref(), current.as_ref());
    let current_value = match current.as_ref() {
        Some(rep) => {
            let relocation_evidence = (rep.sha256 != target.source_sha256)
                .then_some(anchored_evidence.as_deref())
                .flatten();
            match selector_ranges(&selectors, &rep.bytes, relocation_evidence) {
                Ok(ranges) => {
                    json!({ "source_sha256": rep.sha256, "excerpt": evidence(&rep.bytes, ranges[0]) })
                }
                Err(error) => json!({ "source_sha256": rep.sha256, "detail": error.to_string() }),
            }
        }
        None => Value::Null,
    };
    Ok((validation, anchored_value, current_value))
}

pub async fn read_target_view(
    db: &Db,
    annotation_id: &str,
) -> Result<Option<AnnotationTargetView>> {
    read_target_view_with_lens(&ReadLens::live(db), annotation_id).await
}

pub async fn read_target_view_with_lens(
    lens: &ReadLens<'_>,
    annotation_id: &str,
) -> Result<Option<AnnotationTargetView>> {
    let Some(target) = target_row_in_pool(lens.projection().snapshot_pool(), annotation_id).await?
    else {
        return Ok(None);
    };
    let (validation, anchored, current) = resolved_values(lens, &target).await?;
    Ok(Some(target_view(target, validation, anchored, current)))
}

fn target_view(
    target: TargetRow,
    validation: ValidationSummary,
    anchored: Value,
    current: Value,
) -> AnnotationTargetView {
    let source_state = if target.source_slot == "body" {
        json!({ "kind": "record_body", "event_seq": target.source_event_seq, "sha256": target.source_sha256 })
    } else {
        json!({ "kind": "blob", "blob_id": target.blob_id, "sha256": target.source_sha256 })
    };
    let display = format!(
        "{} annotation target to {} {} ({:?})",
        target.purpose.as_deref().unwrap_or("passage"),
        target.target_record_id,
        target.source_slot,
        validation.status
    );
    AnnotationTargetView {
        annotation_id: target.annotation_id,
        target_record_id: target.target_record_id,
        source_slot: target.source_slot,
        source_state,
        selectors: target.selectors,
        purpose: target.purpose,
        created_at: target.created_at,
        updated_at: target.updated_at,
        validation,
        anchored,
        current,
        display,
    }
}

pub(crate) async fn read_target_view_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    lens: &ReadLens<'_>,
    annotation_id: &str,
) -> Result<Option<AnnotationTargetView>> {
    let Some(target) = target_row_on(tx, annotation_id).await? else {
        return Ok(None);
    };
    // The target row controlling identity and disclosure is pinned to the
    // caller's snapshot. Anchored event/blob representations are immutable;
    // current record content is read below from that same snapshot.
    let selectors = parsed_selectors(&target)?;
    let anchored = anchored_representation(lens, &target).await?;
    let current = current_representation_on(tx, &target).await?;
    let validation = validation_from(&target, &selectors, anchored.as_ref(), current.as_ref());
    let (anchored_value, anchored_evidence) = match anchored.as_ref() {
        Some(rep) if rep.sha256 == target.source_sha256 => {
            match selector_ranges(&selectors, &rep.bytes, None) {
                Ok(ranges) => (
                    json!({ "available": true, "source_sha256": rep.sha256, "excerpt": evidence(&rep.bytes, ranges[0]) }),
                    Some(rep.bytes[ranges[0].0..ranges[0].1].to_vec()),
                ),
                Err(error) => (
                    json!({ "available": true, "source_sha256": rep.sha256, "conflict": error.to_string() }),
                    None,
                ),
            }
        }
        _ => (json!({ "available": false }), None),
    };
    let current_value = match current.as_ref() {
        Some(rep) => {
            let relocation_evidence = (rep.sha256 != target.source_sha256)
                .then_some(anchored_evidence.as_deref())
                .flatten();
            match selector_ranges(&selectors, &rep.bytes, relocation_evidence) {
                Ok(ranges) => {
                    json!({ "source_sha256": rep.sha256, "excerpt": evidence(&rep.bytes, ranges[0]) })
                }
                Err(error) => json!({ "source_sha256": rep.sha256, "detail": error.to_string() }),
            }
        }
        None => Value::Null,
    };
    Ok(Some(target_view(
        target,
        validation,
        anchored_value,
        current_value,
    )))
}

pub async fn resolve(db: &Db, annotation_id: &str) -> Result<Value> {
    let lens = ReadLens::live(db);
    let citation = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(annotation_id)
        .fetch_optional(db.write_pool())
        .await?;
    let Some(citation) = citation else {
        return Err(Error::engine(format!(
            "Annotation {annotation_id} does not exist"
        )));
    };
    let record_type: String = citation.try_get("type")?;
    let kind: Option<String> = citation.try_get("kind")?;
    let deleted_at: Option<String> = citation.try_get("deleted_at")?;
    let bearer_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(annotation_id)
    .fetch_one(db.write_pool())
    .await?;
    if deleted_at.is_some()
        || record_type != "Annotation"
        || kind.as_deref() != Some("citation")
        || bearer_count != 1
    {
        return Err(Error::engine(format!(
            "Annotation {annotation_id} is not a live citation with a bearer"
        )));
    }
    let target = target_row(db, annotation_id)
        .await?
        .ok_or_else(|| Error::engine(format!("Annotation {annotation_id} has no target")))?;
    let selectors = parsed_selectors(&target)?;
    let anchored = anchored_representation(&lens, &target).await?;
    let current = current_representation(&lens, &target).await?;
    let (anchored_value, anchored_evidence) = match anchored.as_ref() {
        Some(rep) if rep.sha256 == target.source_sha256 => {
            match selector_ranges(&selectors, &rep.bytes, None) {
                Ok(ranges) => (
                    json!({ "available": true, "source_sha256": rep.sha256, "excerpt": evidence(&rep.bytes, ranges[0]) }),
                    Some(rep.bytes[ranges[0].0..ranges[0].1].to_vec()),
                ),
                Err(error) => (
                    json!({ "available": true, "source_sha256": rep.sha256, "conflict": error.to_string() }),
                    None,
                ),
            }
        }
        _ => (json!({ "available": false }), None),
    };
    let status = validation_from(&target, &selectors, anchored.as_ref(), current.as_ref());
    let current_value = match current.as_ref() {
        Some(rep) => {
            let relocation_evidence = (rep.sha256 != target.source_sha256)
                .then_some(anchored_evidence.as_deref())
                .flatten();
            match selector_ranges(&selectors, &rep.bytes, relocation_evidence) {
                Ok(ranges) => {
                    json!({ "source_sha256": rep.sha256, "excerpt": evidence(&rep.bytes, ranges[0]) })
                }
                Err(error) => json!({ "source_sha256": rep.sha256, "detail": error.to_string() }),
            }
        }
        None => Value::Null,
    };
    Ok(json!({
        "annotation_id": annotation_id,
        "target_record_id": target.target_record_id,
        "anchored": anchored_value,
        "current": current_value,
        "validation": status,
        "selectors": target.selectors,
        "read_only": true
    }))
}

pub async fn capture_target_in(
    tx: &mut Transaction<'static, Sqlite>,
    input: AnnotationTargetInput,
) -> Result<AnnotationTargetSetPayload> {
    if input.selectors.is_empty() {
        return Err(Error::engine(
            "annotation target requires at least one selector",
        ));
    }
    if input
        .purpose
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(Error::engine("annotation target purpose must not be blank"));
    }
    let target = sqlx::query("SELECT type, kind, body, deleted_at FROM records WHERE id = ?")
        .bind(&input.target_record_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "annotation target record {} does not exist",
                input.target_record_id
            ))
        })?;
    if target.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "annotation target record {} is deleted",
            input.target_record_id
        )));
    }

    let (bytes, source_event_seq, blob_id, source_sha256) = match input.source_slot {
        SourceSlot::Body => {
            let body = target
                .try_get::<Option<String>, _>("body")?
                .unwrap_or_default();
            let seq: i64 =
                sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
                    .bind(&input.target_record_id)
                    .fetch_one(&mut **tx)
                    .await?;
            let bytes = body.into_bytes();
            let sha = digest(&bytes);
            (bytes, Some(seq), None, sha)
        }
        SourceSlot::Blob => {
            if target.try_get::<String, _>("type")? != "Document"
                || target.try_get::<Option<String>, _>("kind")?.as_deref() != Some("attachment")
            {
                return Err(Error::engine(
                    "blob citation targets must name a Document kind:attachment record",
                ));
            }
            let blob_id: String = sqlx::query_scalar(
                "SELECT value FROM facet_values WHERE record_id = ? AND key = ?",
            )
            .bind(&input.target_record_id)
            .bind(BLOB_REF_FACET_KEY)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| Error::engine("attachment citation target has no blob_ref"))?;
            let blob = sqlx::query("SELECT bytes, storage_tier FROM blobs WHERE id = ?")
                .bind(&blob_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| Error::engine("attachment citation blob does not exist"))?;
            if blob.try_get::<String, _>("storage_tier")? != "inline" {
                return Err(Error::engine("external blobs cannot be cited in v1"));
            }
            let bytes = blob
                .try_get::<Option<Vec<u8>>, _>("bytes")?
                .ok_or_else(|| Error::engine("attachment citation blob has no bytes"))?;
            let sha = digest(&bytes);
            (bytes, None, Some(blob_id), sha)
        }
    };

    let selectors = canonicalize_selectors(input.selectors, &bytes)?;
    Ok(AnnotationTargetSetPayload {
        target_record_id: input.target_record_id,
        source_slot: input.source_slot.as_str().into(),
        source_event_seq,
        blob_id,
        source_sha256,
        selectors: serde_json::to_value(selectors)?,
        purpose: input.purpose,
    })
}
