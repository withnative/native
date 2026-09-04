//! Governed record kinds. `kind:<Type>` vocabularies are the runtime authority;
//! schema shapes describe facets but do not create kind identity.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedRow, NormalizedValue, StatementKind, StatementTemplate,
};
use crate::schema::SPINE_TYPES;

pub const KIND_METADATA_SCHEMA_VERSION: u64 = 1;
pub const CORE_KIND_MANIFEST_JSON: &str = include_str!("core_kinds.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KindDedupMode {
    ExternalBinding,
    FacetTuple,
    RecordId,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindDedupV1 {
    pub mode: KindDedupMode,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindIdentityV1 {
    pub criterion: String,
    pub dedup: KindDedupV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindMetadataV1 {
    pub schema_version: u64,
    pub provenance_ref: String,
    pub definition: String,
    pub identity: KindIdentityV1,
    pub declared_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_unattested: bool,
}

impl KindMetadataV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != KIND_METADATA_SCHEMA_VERSION {
            return Err(Error::engine(format!(
                "kind metadata schema_version must be {KIND_METADATA_SCHEMA_VERSION}"
            )));
        }
        if !self.provenance_ref.starts_with("rec:")
            || self
                .provenance_ref
                .trim_start_matches("rec:")
                .trim()
                .is_empty()
        {
            return Err(Error::engine(
                "kind metadata provenance_ref must be a non-empty rec:<id> citation",
            ));
        }
        if self.definition.trim().is_empty() {
            return Err(Error::engine("kind metadata definition must not be blank"));
        }
        if self.identity.criterion.trim().is_empty() {
            return Err(Error::engine(
                "kind metadata identity.criterion must not be blank",
            ));
        }
        if self.identity.dedup.mode == KindDedupMode::FacetTuple
            && (self.identity.dedup.keys.is_empty()
                || self
                    .identity
                    .dedup
                    .keys
                    .iter()
                    .any(|key| key.trim().is_empty()))
        {
            return Err(Error::engine(
                "kind metadata identity.dedup.keys must be non-empty for facet_tuple",
            ));
        }
        if self.identity.dedup.mode != KindDedupMode::FacetTuple
            && !self.identity.dedup.keys.is_empty()
        {
            return Err(Error::engine(
                "kind metadata identity.dedup.keys is only valid for facet_tuple",
            ));
        }
        if self
            .declared_capabilities
            .iter()
            .any(|capability| capability.trim().is_empty())
        {
            return Err(Error::engine(
                "kind metadata declared_capabilities must not contain blank values",
            ));
        }
        Ok(())
    }

    pub fn legacy(record_type: &str, token: &str) -> Self {
        Self {
            schema_version: KIND_METADATA_SCHEMA_VERSION,
            provenance_ref: "rec:8c2eea0".into(),
            definition: format!(
                "Legacy {record_type} kind '{token}'; canonical definition not yet attested."
            ),
            identity: KindIdentityV1 {
                criterion: "Legacy identity criterion not yet attested; manual review required."
                    .into(),
                dedup: KindDedupV1 {
                    mode: KindDedupMode::Manual,
                    keys: Vec::new(),
                },
            },
            declared_capabilities: Vec::new(),
            legacy_unattested: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreKindSeed {
    #[serde(rename = "type")]
    pub record_type: String,
    pub token: String,
    pub value_id: String,
    pub metadata: KindMetadataV1,
    /// Optional admission gloss written into `vocabulary_values.gloss` on first
    /// seed and when adopting an exact-identity proposed value. Active and
    /// deprecated rows are not re-checked against this on reopen — `set_gloss`
    /// remains the supported correction path after admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gloss: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreKindManifest {
    pub schema_version: u64,
    pub kinds: Vec<CoreKindSeed>,
}

pub fn core_kind_manifest() -> Result<CoreKindManifest> {
    let manifest: CoreKindManifest = serde_json::from_str(CORE_KIND_MANIFEST_JSON)?;
    if manifest.schema_version != KIND_METADATA_SCHEMA_VERSION {
        return Err(Error::engine(format!(
            "core kind manifest schema_version must be {KIND_METADATA_SCHEMA_VERSION}"
        )));
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut value_ids = std::collections::BTreeSet::new();
    for kind in &manifest.kinds {
        if !SPINE_TYPES.contains(&kind.record_type.as_str()) {
            return Err(Error::engine(format!(
                "core kind manifest names unknown spine type '{}'",
                kind.record_type
            )));
        }
        if kind.token.trim().is_empty() {
            return Err(Error::engine("core kind manifest token must not be blank"));
        }
        // Program:module deliberately retains the already-shipped value id.
        // The id is a stable governed identity, not a reparsed type token; the
        // The pre-baseline schema-23 conversion moved it between kind
        // vocabularies without minting a replacement identity.
        let expected_value_id = if kind.record_type == "Program" && kind.token == "module" {
            "vv:voc:kind:Document:module".to_string()
        } else {
            format!(
                "vv:{}:{}",
                kind_vocabulary_id(&kind.record_type),
                kind.token
            )
        };
        if kind.value_id != expected_value_id {
            return Err(Error::engine(format!(
                "core kind {}:{} uses value id '{}', expected stable id '{expected_value_id}'",
                kind.record_type, kind.token, kind.value_id
            )));
        }
        kind.metadata.validate()?;
        if let Some(gloss) = &kind.gloss {
            if gloss.trim().is_empty() {
                return Err(Error::engine(format!(
                    "core kind {}:{} gloss must not be blank when present",
                    kind.record_type, kind.token
                )));
            }
        }
        if kind.record_type == "Document" && kind.token == "handoff" && kind.gloss.is_none() {
            return Err(Error::engine(
                "core kind Document:handoff requires an admission gloss",
            ));
        }
        if !identities.insert((kind.record_type.clone(), kind.token.clone())) {
            return Err(Error::engine(format!(
                "duplicate core kind {}:{}",
                kind.record_type, kind.token
            )));
        }
        if !value_ids.insert(kind.value_id.clone()) {
            return Err(Error::engine(format!(
                "duplicate core kind value id {}",
                kind.value_id
            )));
        }
    }
    Ok(manifest)
}

pub fn core_kind_manifest_digest() -> String {
    hex::encode(Sha256::digest(CORE_KIND_MANIFEST_JSON.as_bytes()))
}

pub fn kind_vocabulary_name(record_type: &str) -> String {
    format!("kind:{record_type}")
}

pub fn kind_vocabulary_id(record_type: &str) -> String {
    format!("voc:kind:{record_type}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KindClassification {
    ActiveCanonical,
    DeprecatedAlias,
    DeprecatedNonAlias,
    Proposed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindDefinition {
    #[serde(rename = "type")]
    pub record_type: String,
    pub token: String,
    pub value_id: String,
    pub metadata: KindMetadataV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindResolution {
    #[serde(rename = "type")]
    pub record_type: String,
    pub raw_kind: String,
    pub classification: KindClassification,
    pub canonical_kind: Option<String>,
    pub canonical_value_id: Option<String>,
    pub lifecycle_status: Option<String>,
    pub metadata: Option<KindMetadataV1>,
    pub quarantined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// One spine type under which an exact raw token currently resolves to an
/// active canonical kind. This is a diagnostic projection of governed state:
/// it does not make the token valid for any other record type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct GovernedKindMatch {
    #[serde(rename = "type")]
    pub record_type: String,
    pub matched_token: String,
    pub classification: KindClassification,
    pub canonical_kind: String,
    pub canonical_value_id: String,
    pub lifecycle_status: String,
}

impl KindResolution {
    /// The governed token that is safe to persist for dispatch. A quarantined
    /// alias may still expose its historical target for diagnostics, but that
    /// target is not an authorised write canonicalisation.
    pub fn canonical_kind_for_write(&self) -> Option<&str> {
        (!self.quarantined)
            .then_some(self.canonical_kind.as_deref())
            .flatten()
    }
}

fn parse_metadata(raw: &str, context: &str) -> Result<KindMetadataV1> {
    let metadata: KindMetadataV1 = serde_json::from_str(raw)
        .map_err(|err| Error::engine(format!("{context} carries invalid KindMetadataV1: {err}")))?;
    metadata.validate()?;
    Ok(metadata)
}

pub async fn list_active_on(
    conn: &mut SqliteConnection,
    record_type: &str,
) -> Result<Vec<KindDefinition>> {
    let mut executor = BorrowedSqliteStatementExecutor::new(conn);
    list_active_with(&mut executor, record_type).await
}

/// Read the active canonical kind registry through one admitted portable
/// snapshot. Schema discovery uses this on every qualified backend so it never
/// substitutes a compile-time kind list for the database's governed state.
pub(crate) async fn list_active_with<E: DomainStatementExecutor>(
    executor: &mut E,
    record_type: &str,
) -> Result<Vec<KindDefinition>> {
    let statement = StatementTemplate::new(
        StatementKind::Select,
        "vocabularies",
        &[
            "SELECT vv.id, vv.value, vv.metadata FROM {{relation}} v JOIN vocabulary_values vv ON vv.vocabulary_id = v.id WHERE v.name = ",
            " AND vv.status = 'active' AND vv.alias_of IS NULL ORDER BY vv.value, vv.id",
        ],
    )
    .map_err(|error| crate::domain_transaction::stable_storage_error("list active kinds", &error))?;
    let rows = executor
        .fetch_all(
            &statement,
            &[BindValue::Text(kind_vocabulary_name(record_type))],
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("value", LogicalType::Text),
                ColumnSpec::required("metadata", LogicalType::Text),
            ],
        )
        .await
        .map_err(|error| {
            crate::domain_transaction::stable_storage_error("list active kinds", &error)
        })?;
    rows.into_iter()
        .map(|row| {
            let value_id = kind_row_text(&row, "id")?;
            let token = kind_row_text(&row, "value")?;
            let raw = kind_row_text(&row, "metadata")?;
            Ok(KindDefinition {
                record_type: record_type.to_string(),
                token,
                metadata: parse_metadata(&raw, &format!("kind value {value_id}"))?,
                value_id,
            })
        })
        .collect()
}

pub async fn list_active(db: &Db, record_type: &str) -> Result<Vec<KindDefinition>> {
    let mut conn = db.write_pool().acquire().await?;
    list_active_on(&mut conn, record_type).await
}

/// Find spine types for which `raw_kind` currently resolves to an admitted
/// canonical kind. This is deliberately backed by the runtime registry rather
/// than the compiled core manifest: user-promoted kinds and active aliases are
/// part of the same governed surface.
pub(crate) async fn governed_matches_for_token_with<E: DomainStatementExecutor>(
    executor: &mut E,
    raw_kind: &str,
) -> Result<Vec<GovernedKindMatch>> {
    let statement = StatementTemplate::new(
        StatementKind::Select,
        "vocabularies",
        &[
            "SELECT v.name AS vocabulary_name, vv.status AS matched_status, vv.alias_of, canonical.id AS canonical_id, canonical.value AS canonical_value FROM {{relation}} v JOIN vocabulary_values vv ON vv.vocabulary_id = v.id JOIN vocabulary_values canonical ON canonical.id = COALESCE(vv.alias_of, vv.id) AND canonical.vocabulary_id = vv.vocabulary_id WHERE vv.value = ",
            " AND canonical.status = 'active' AND canonical.alias_of IS NULL",
        ],
    )
    .map_err(|error| {
        crate::domain_transaction::stable_storage_error("find governed kind types", &error)
    })?;
    let rows = executor
        .fetch_all(
            &statement,
            &[BindValue::Text(raw_kind.into())],
            &[
                ColumnSpec::required("vocabulary_name", LogicalType::Text),
                ColumnSpec::required("matched_status", LogicalType::Text),
                ColumnSpec::nullable("alias_of", LogicalType::Text),
                ColumnSpec::required("canonical_id", LogicalType::Text),
                ColumnSpec::required("canonical_value", LogicalType::Text),
            ],
        )
        .await
        .map_err(|error| {
            crate::domain_transaction::stable_storage_error("find governed kind types", &error)
        })?;
    let mut matches = Vec::new();
    for row in rows {
        let vocabulary_name = kind_row_text(&row, "vocabulary_name")?;
        let Some(record_type) = vocabulary_name.strip_prefix("kind:") else {
            continue;
        };
        if !SPINE_TYPES.contains(&record_type) {
            continue;
        }
        let alias_of = kind_row_optional_text(&row, "alias_of")?;
        matches.push(GovernedKindMatch {
            record_type: record_type.to_string(),
            matched_token: raw_kind.to_string(),
            classification: if alias_of.is_some() {
                KindClassification::DeprecatedAlias
            } else {
                KindClassification::ActiveCanonical
            },
            canonical_kind: kind_row_text(&row, "canonical_value")?,
            canonical_value_id: kind_row_text(&row, "canonical_id")?,
            lifecycle_status: kind_row_text(&row, "matched_status")?,
        });
    }
    matches.sort_by(|left, right| {
        left.record_type
            .as_bytes()
            .cmp(right.record_type.as_bytes())
            .then_with(|| {
                left.canonical_kind
                    .as_bytes()
                    .cmp(right.canonical_kind.as_bytes())
            })
            .then_with(|| {
                left.canonical_value_id
                    .as_bytes()
                    .cmp(right.canonical_value_id.as_bytes())
            })
    });
    matches.dedup();
    Ok(matches)
}

async fn governed_types_for_token_with<E: DomainStatementExecutor>(
    executor: &mut E,
    raw_kind: &str,
) -> Result<Vec<String>> {
    Ok(governed_matches_for_token_with(executor, raw_kind)
        .await?
        .into_iter()
        .map(|kind_match| kind_match.record_type)
        .collect())
}

fn unknown_kind_warning(record_type: &str, raw_kind: &str, governed_types: &[String]) -> String {
    let rejected = format!("kind '{raw_kind}' is not governed by kind:{record_type}");
    let consequence = "stored for interoperability but quarantined from governed dispatch";
    match governed_types {
        [] => format!("{rejected}; {consequence}"),
        [governed_type] => format!(
            "{rejected}. It is governed under type {governed_type} (kind:{governed_type}); did you mean that type? The record was {consequence}"
        ),
        governed_types => {
            let candidates = governed_types
                .iter()
                .map(|candidate| format!("{candidate} (kind:{candidate})"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{rejected}. It is governed under multiple types: {candidates}; choose the intended type. The record was {consequence}"
            )
        }
    }
}

pub async fn resolve_on(
    conn: &mut SqliteConnection,
    record_type: &str,
    raw_kind: &str,
) -> Result<KindResolution> {
    let mut executor = BorrowedSqliteStatementExecutor::new(conn);
    resolve_with(&mut executor, record_type, raw_kind).await
}

fn kind_row_text(row: &NormalizedRow, column: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "kind resolution state column '{column}' is invalid"
        ))),
    }
}

fn kind_row_optional_text(row: &NormalizedRow, column: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "kind resolution state column '{column}' is invalid"
        ))),
    }
}

pub(crate) async fn resolve_with<E: DomainStatementExecutor>(
    executor: &mut E,
    record_type: &str,
    raw_kind: &str,
) -> Result<KindResolution> {
    if raw_kind.is_empty() {
        return Err(Error::engine("kind must not be empty"));
    }
    let statement = StatementTemplate::new(
        StatementKind::Select,
        "vocabularies",
        &[
            "SELECT vv.id, vv.status, vv.metadata, vv.alias_of, canonical.id AS canonical_id, canonical.value AS canonical_value, canonical.status AS canonical_status, canonical.metadata AS canonical_metadata FROM {{relation}} v JOIN vocabulary_values vv ON vv.vocabulary_id = v.id LEFT JOIN vocabulary_values canonical ON canonical.id = vv.alias_of WHERE v.name = ",
            " AND vv.value = ",
            "",
        ],
    )
    .map_err(|error| crate::domain_transaction::stable_storage_error("resolve kind", &error))?;
    let rows = executor
        .fetch_all(
            &statement,
            &[
                BindValue::Text(kind_vocabulary_name(record_type)),
                BindValue::Text(raw_kind.into()),
            ],
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("status", LogicalType::Text),
                ColumnSpec::required("metadata", LogicalType::Text),
                ColumnSpec::nullable("alias_of", LogicalType::Text),
                ColumnSpec::nullable("canonical_id", LogicalType::Text),
                ColumnSpec::nullable("canonical_value", LogicalType::Text),
                ColumnSpec::nullable("canonical_status", LogicalType::Text),
                ColumnSpec::nullable("canonical_metadata", LogicalType::Text),
            ],
        )
        .await
        .map_err(|error| crate::domain_transaction::stable_storage_error("resolve kind", &error))?;

    let Some(row) = rows.first() else {
        let governed_types = governed_types_for_token_with(executor, raw_kind).await?;
        return Ok(KindResolution {
            record_type: record_type.into(),
            raw_kind: raw_kind.into(),
            classification: KindClassification::Unknown,
            canonical_kind: None,
            canonical_value_id: None,
            lifecycle_status: None,
            metadata: None,
            quarantined: true,
            warning: Some(unknown_kind_warning(record_type, raw_kind, &governed_types)),
        });
    };

    let id = kind_row_text(row, "id")?;
    let status = kind_row_text(row, "status")?;
    let alias_of = kind_row_optional_text(row, "alias_of")?;
    let (classification, canonical_kind, canonical_value_id, metadata, quarantined) =
        if alias_of.is_some() {
            let canonical_status = kind_row_optional_text(row, "canonical_status")?;
            let canonical_kind = kind_row_optional_text(row, "canonical_value")?;
            let canonical_id = kind_row_optional_text(row, "canonical_id")?;
            let metadata = kind_row_optional_text(row, "canonical_metadata")?
                .map(|raw| parse_metadata(&raw, &format!("canonical kind value {id}")))
                .transpose()?;
            let allowed = canonical_status.as_deref() == Some("active")
                && canonical_kind.is_some()
                && canonical_id.is_some();
            (
                KindClassification::DeprecatedAlias,
                canonical_kind,
                canonical_id,
                metadata,
                !allowed,
            )
        } else {
            let classification = match status.as_str() {
                "active" => KindClassification::ActiveCanonical,
                "proposed" => KindClassification::Proposed,
                _ => KindClassification::DeprecatedNonAlias,
            };
            let metadata = if status == "active" {
                let raw = kind_row_text(row, "metadata")?;
                Some(parse_metadata(&raw, &format!("kind value {id}"))?)
            } else {
                None
            };
            (
                classification,
                (status == "active").then(|| raw_kind.to_string()),
                (status == "active").then_some(id.clone()),
                metadata,
                status != "active",
            )
        };
    let warning = quarantined.then(|| {
        format!(
            "kind '{raw_kind}' is {classification:?}; stored for interoperability but quarantined from governed dispatch"
        )
    });
    Ok(KindResolution {
        record_type: record_type.into(),
        raw_kind: raw_kind.into(),
        classification,
        canonical_kind,
        canonical_value_id,
        lifecycle_status: Some(status),
        metadata,
        quarantined,
        warning,
    })
}

pub(crate) async fn resolve_in_pool(
    pool: &sqlx::SqlitePool,
    record_type: &str,
    raw_kind: &str,
) -> Result<KindResolution> {
    let mut conn = pool.acquire().await?;
    resolve_on(&mut conn, record_type, raw_kind).await
}

pub async fn resolve(db: &Db, record_type: &str, raw_kind: &str) -> Result<KindResolution> {
    let mut conn = db.write_pool().acquire().await?;
    resolve_on(&mut conn, record_type, raw_kind).await
}

pub fn matches_identity(
    resolution: &KindResolution,
    expected_type: &str,
    expected_value_id: &str,
) -> bool {
    !resolution.quarantined
        && resolution.record_type == expected_type
        && resolution.canonical_value_id.as_deref() == Some(expected_value_id)
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// SQL predicate for a record alias whose stored kind resolves to one active
/// canonical identity. This is deliberately generated from immutable value
/// ids rather than token spelling: historical alias-valued records keep
/// participating while aliases whose target later leaves service stop doing
/// so without rewriting content history.
pub fn sql_matches_identity(
    record_alias: &str,
    expected_type: &str,
    expected_value_id: &str,
) -> String {
    assert!(
        !record_alias.is_empty()
            && record_alias
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "record SQL alias must be an identifier"
    );
    let vocabulary = sql_literal(&kind_vocabulary_name(expected_type));
    let expected_type = sql_literal(expected_type);
    let expected_value_id = sql_literal(expected_value_id);
    format!(
        "({record_alias}.type = {expected_type} AND EXISTS (
            SELECT 1
              FROM vocabularies kind_vocabulary
              JOIN vocabulary_values stored_kind
                ON stored_kind.vocabulary_id = kind_vocabulary.id
               AND stored_kind.value = {record_alias}.kind
              JOIN vocabulary_values canonical_kind
                ON canonical_kind.id = COALESCE(stored_kind.alias_of, stored_kind.id)
               AND canonical_kind.vocabulary_id = kind_vocabulary.id
             WHERE kind_vocabulary.name = {vocabulary}
               AND canonical_kind.id = {expected_value_id}
               AND canonical_kind.status = 'active'
               AND canonical_kind.alias_of IS NULL
        ))"
    )
}

/// Every raw token currently authorised to resolve to an active identity.
/// Used when an explicit token filter must retrieve both canonical and
/// historical alias-valued rows.
pub(crate) async fn active_identity_tokens_in_pool(
    pool: &sqlx::SqlitePool,
    expected_type: &str,
    expected_value_id: &str,
) -> Result<Vec<String>> {
    let mut conn = pool.acquire().await?;
    active_identity_tokens_on(&mut conn, expected_type, expected_value_id).await
}

pub async fn active_identity_tokens(
    db: &Db,
    expected_type: &str,
    expected_value_id: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query_scalar(
        "SELECT stored_kind.value
           FROM vocabularies kind_vocabulary
           JOIN vocabulary_values stored_kind
             ON stored_kind.vocabulary_id = kind_vocabulary.id
           JOIN vocabulary_values canonical_kind
             ON canonical_kind.id = COALESCE(stored_kind.alias_of, stored_kind.id)
            AND canonical_kind.vocabulary_id = kind_vocabulary.id
          WHERE kind_vocabulary.name = ?
            AND canonical_kind.id = ?
            AND canonical_kind.status = 'active'
            AND canonical_kind.alias_of IS NULL
          ORDER BY stored_kind.value",
    )
    .bind(kind_vocabulary_name(expected_type))
    .bind(expected_value_id)
    .fetch_all(db.write_pool())
    .await?;
    Ok(rows)
}

pub(crate) async fn active_identity_tokens_on(
    conn: &mut SqliteConnection,
    expected_type: &str,
    expected_value_id: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query_scalar(
        "SELECT stored_kind.value
           FROM vocabularies kind_vocabulary
           JOIN vocabulary_values stored_kind
             ON stored_kind.vocabulary_id = kind_vocabulary.id
           JOIN vocabulary_values canonical_kind
             ON canonical_kind.id = COALESCE(stored_kind.alias_of, stored_kind.id)
            AND canonical_kind.vocabulary_id = kind_vocabulary.id
          WHERE kind_vocabulary.name = ?
            AND canonical_kind.id = ?
            AND canonical_kind.status = 'active'
            AND canonical_kind.alias_of IS NULL
          ORDER BY stored_kind.value",
    )
    .bind(kind_vocabulary_name(expected_type))
    .bind(expected_value_id)
    .fetch_all(conn)
    .await?;
    Ok(rows)
}
