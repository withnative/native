//! Engine-neutral contract for caller-supplied, read-only SQL.
//!
//! This module owns the public request, result, limits, discovery metadata and
//! defence-in-depth statement classifier. Backend adapters remain responsible
//! for authoritative parsing, authorization and read-only execution. It is
//! deliberately separate from `portable_sql`, which accepts only Native-owned
//! reviewed statements.

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

use crate::{QueryError, Result};

pub const GUIDE_TOPIC: &str = "query-sql";
pub const MAX_SQL_BYTES: usize = 64 * 1024;
pub const MAX_PARAMETERS: usize = 256;
pub const MAX_PARAMETER_ENCODED_BYTES: usize = 256 * 1024;
pub const MAX_ROWS: usize = 1_000;
pub const MAX_COLUMNS: usize = 64;
pub const MAX_CELL_ENCODED_BYTES: usize = 256 * 1024;
pub const MAX_RESULT_ENCODED_BYTES: usize = 4 * 1024 * 1024;
pub const QUERY_DEADLINE_MS: u64 = 2_000;
/// Breaking semantic revision of catalog-wide SQL behavior. Saved governed SQL
/// pins this independently from an engine/dialect profile. Additive relations
/// and relation-local changes do not bump this revision: each dependency's
/// name/profile/semantic-version pin is its compatibility gate. Change this
/// only when compatibility changes beyond one relation's declared contract.
pub const LOGICAL_CATALOG_REVISION: u32 = 3;
pub const LOGICAL_RELATION_VERSION: u32 = 1;
pub const CONTENT_EVENTS_RELATION_VERSION: u32 = 2;
pub const AGENT_ACTIVITY_RELATION_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlRelationContract {
    /// Stable semantic identity; unlike a physical table name, this may be
    /// pinned by durable saved queries across storage migrations.
    pub identity: &'static str,
    pub name: &'static str,
    pub semantic_version: u32,
    pub caller_relative: bool,
    /// `complete` or `best_effort`; execution receipts conservatively fold
    /// the completeness of every dependency.
    pub completeness: &'static str,
    pub profiles: &'static [&'static str],
    pub columns: &'static [&'static str],
}

const ALL_PROFILES: &[&str] = &["sqlite-local", "postgres-server", "turso-local"];
const SQLITE_PROFILE: &[&str] = &["sqlite-local"];

pub const LOGICAL_RELATIONS: &[QuerySqlRelationContract] = &[
    QuerySqlRelationContract {
        identity: "native.query-sql.records",
        name: "records",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "type",
            "kind",
            "name",
            "body",
            "home_id",
            "lifecycle",
            "persistence",
            "maturity",
            "summary",
            "last_activity_at",
            "created_at",
            "updated_at",
            "deleted_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.content-events",
        name: "content_events",
        semantic_version: CONTENT_EVENTS_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &["local_seq", "id", "record_id", "type", "created_at"],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.links",
        name: "links",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "source_id",
            "target_id",
            "relationship",
            "note",
            "created_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.facet-values",
        name: "facet_values",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "record_id",
            "key",
            "value",
            "value_num",
            "vocab_ref",
            "created_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.facet-observations",
        name: "facet_observations",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "record_id",
            "key",
            "value",
            "op",
            "vocab_ref",
            "as_of",
            "observed_at",
            "event_seq",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.bindings",
        name: "bindings",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "record_id",
            "system",
            "identifier",
            "is_canonical",
            "url",
            "etag",
            "last_seen_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.blobs",
        name: "blobs",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "bytes",
            "mime",
            "size_bytes",
            "sha256",
            "original_filename",
            "storage_tier",
            "external_ref",
            "created_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.vocabularies",
        name: "vocabularies",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: false,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &["id", "name", "created_at"],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.vocabulary-values",
        name: "vocabulary_values",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: false,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "vocabulary_id",
            "value",
            "gloss",
            "status",
            "ordinal",
            "terminality",
            "metadata",
            "alias_of",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.schema-config",
        name: "schema_config",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "id",
            "layer",
            "name",
            "data",
            "applies_to_collection_id",
            "version_lineage",
            "created_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.effective-relationships",
        name: "effective_relationships",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "relationship_origin_db_id",
            "relationship_id",
            "relationship_type",
            "type_definition_id",
            "endpoint_semantics",
            "endpoints",
            "effective_state",
            "epistemic_state",
            "support_count",
            "contest_count",
            "recomputed_at",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.semantic.agent_activity",
        name: "agent_activity",
        semantic_version: AGENT_ACTIVITY_RELATION_VERSION,
        caller_relative: true,
        completeness: "best_effort",
        profiles: SQLITE_PROFILE,
        columns: &[
            "activity_id",
            "run_key",
            "principal_ref",
            "principal_display_name",
            "started_at",
            "ended_at",
            "last_observed_activity_at",
            "active_until",
            "appears_active",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.semantic.agent_activity_claims",
        name: "agent_activity_claims",
        semantic_version: 1,
        caller_relative: true,
        completeness: "best_effort",
        profiles: SQLITE_PROFILE,
        columns: &[
            "claim_id",
            "activity_id",
            "record_id",
            "claimed_at",
            "released_at",
            "is_current",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.messages-awaiting-reply",
        name: "messages_awaiting_reply",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &["message_id"],
    },
];

pub fn is_logical_relation(name: &str) -> bool {
    LOGICAL_RELATIONS
        .iter()
        .any(|relation| relation.name == name)
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlLimits {
    pub sql_bytes: usize,
    pub parameter_count: usize,
    pub parameter_encoded_bytes: usize,
    pub rows: usize,
    pub columns: usize,
    pub cell_encoded_bytes: usize,
    pub result_encoded_bytes: usize,
    pub deadline_ms: u64,
}

pub const LIMITS: QuerySqlLimits = QuerySqlLimits {
    sql_bytes: MAX_SQL_BYTES,
    parameter_count: MAX_PARAMETERS,
    parameter_encoded_bytes: MAX_PARAMETER_ENCODED_BYTES,
    rows: MAX_ROWS,
    columns: MAX_COLUMNS,
    cell_encoded_bytes: MAX_CELL_ENCODED_BYTES,
    result_encoded_bytes: MAX_RESULT_ENCODED_BYTES,
    deadline_ms: QUERY_DEADLINE_MS,
};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlParameterTypeContract {
    pub tag: &'static str,
    pub non_null_encoding: &'static str,
}

pub const PARAMETER_TYPES: &[QuerySqlParameterTypeContract] = &[
    QuerySqlParameterTypeContract {
        tag: "boolean",
        non_null_encoding: "json-boolean",
    },
    QuerySqlParameterTypeContract {
        tag: "integer",
        non_null_encoding: "signed-i64-decimal-string",
    },
    QuerySqlParameterTypeContract {
        tag: "real",
        non_null_encoding: "finite-json-number",
    },
    QuerySqlParameterTypeContract {
        tag: "text",
        non_null_encoding: "json-string",
    },
    QuerySqlParameterTypeContract {
        tag: "bytes",
        non_null_encoding: "base64-string",
    },
    QuerySqlParameterTypeContract {
        tag: "json",
        non_null_encoding: "json-text-string",
    },
    QuerySqlParameterTypeContract {
        tag: "timestamp",
        non_null_encoding: "rfc3339-string",
    },
];

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlValueEncoding {
    pub logical_type: &'static str,
    pub json_encoding: &'static str,
    pub qualification: &'static str,
}

pub const RESULT_VALUE_ENCODINGS: &[QuerySqlValueEncoding] = &[
    QuerySqlValueEncoding {
        logical_type: "null",
        json_encoding: "null",
        qualification: "all engines",
    },
    QuerySqlValueEncoding {
        logical_type: "boolean",
        json_encoding: "boolean",
        qualification: "when the engine exposes a distinct boolean type; SQLite integer expressions remain signed_i64",
    },
    QuerySqlValueEncoding {
        logical_type: "signed_i64",
        json_encoding: "integer",
        qualification: "exact signed 64-bit range",
    },
    QuerySqlValueEncoding {
        logical_type: "finite_real",
        json_encoding: "number",
        qualification: "finite IEEE-754 value",
    },
    QuerySqlValueEncoding {
        logical_type: "arbitrary_numeric",
        json_encoding: "decimal-string",
        qualification: "lossless canonical decimal text for values outside signed_i64 or finite_real",
    },
    QuerySqlValueEncoding {
        logical_type: "text",
        json_encoding: "string",
        qualification: "UTF-8 text",
    },
    QuerySqlValueEncoding {
        logical_type: "bytes",
        json_encoding: "base64-string",
        qualification: "RFC 4648 standard alphabet",
    },
    QuerySqlValueEncoding {
        logical_type: "json",
        json_encoding: "native-json",
        qualification: "when losslessly representable by JSON; otherwise canonical JSON text",
    },
    QuerySqlValueEncoding {
        logical_type: "timestamp",
        json_encoding: "rfc3339-string",
        qualification: "preserve engine precision and offset when representable",
    },
];

/// Exhaustive backend type decisions for adapters that expose typed values.
/// The first matching rule wins, so SQL NULL is handled before its declared
/// engine type. A backend adapter must not add an implicit stringification
/// path outside these rules.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlEngineTypeRule {
    pub profile: &'static str,
    pub engine_types: &'static [&'static str],
    pub condition: &'static str,
    pub outcome: &'static str,
    pub json_encoding: Option<&'static str>,
    pub error_category: Option<&'static str>,
}

pub const ENGINE_TYPE_RULES: &[QuerySqlEngineTypeRule] = &[
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["*"],
        condition: "value is SQL NULL",
        outcome: "encode",
        json_encoding: Some("null"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["bool"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("boolean"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["int2", "int4", "int8"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("signed-json-integer"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["float4", "float8"],
        condition: "finite",
        outcome: "encode",
        json_encoding: Some("json-number"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["float4", "float8"],
        condition: "NaN, +Infinity, or -Infinity",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["numeric"],
        condition: "finite",
        outcome: "encode",
        json_encoding: Some("lossless-canonical-decimal-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["numeric"],
        condition: "NaN, +Infinity, or -Infinity",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["text", "varchar", "bpchar", "char", "name"],
        condition: "non-null UTF-8 text",
        outcome: "encode",
        json_encoding: Some("string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["bytea"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("base64-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["json", "jsonb"],
        condition: "non-null; preserve the engine's canonical JSON text without decoding through serde_json::Value",
        outcome: "encode",
        json_encoding: Some("canonical-json-text-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["timestamptz"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("rfc3339-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["timestamp"],
        condition: "non-null value has no UTC offset",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@5",
        engine_types: &["array types (*[])"],
        condition: "unless a later contract revision explicitly supports the exact array type",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
];

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlUnsupportedTypePolicy {
    pub outcome: &'static str,
    pub error_category: &'static str,
    pub rule: &'static str,
}

pub const UNSUPPORTED_TYPE_POLICY: QuerySqlUnsupportedTypePolicy =
    QuerySqlUnsupportedTypePolicy {
        outcome: "reject",
        error_category: "syntax_or_type",
        rule: "Reject every engine type or value form not matched by an explicit rule, including domains, enums, composites, ranges, multiranges, geometric, network, bit, vector, extension, and unknown types; never coerce or stringify implicitly.",
    };

pub const RESULT_FIELDS: &[&str] = &["columns", "rows", "row_count", "truncated"];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuerySqlErrorCategory {
    InvalidArguments,
    UnsafeStatement,
    UnauthorizedRelation,
    SyntaxOrType,
    Timeout,
    ResultTooLarge,
    DuplicateColumns,
    UnsupportedProfile,
    Engine,
}

pub const ERROR_CATEGORIES: &[QuerySqlErrorCategory] = &[
    QuerySqlErrorCategory::InvalidArguments,
    QuerySqlErrorCategory::UnsafeStatement,
    QuerySqlErrorCategory::UnauthorizedRelation,
    QuerySqlErrorCategory::SyntaxOrType,
    QuerySqlErrorCategory::Timeout,
    QuerySqlErrorCategory::ResultTooLarge,
    QuerySqlErrorCategory::DuplicateColumns,
    QuerySqlErrorCategory::UnsupportedProfile,
    QuerySqlErrorCategory::Engine,
];

impl QuerySqlErrorCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::UnsafeStatement => "unsafe_statement",
            Self::UnauthorizedRelation => "unauthorized_relation",
            Self::SyntaxOrType => "syntax_or_type",
            Self::Timeout => "timeout",
            Self::ResultTooLarge => "result_too_large",
            Self::DuplicateColumns => "duplicate_columns",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::Engine => "engine",
        }
    }
}

fn categorized_error(category: QuerySqlErrorCategory, detail: impl AsRef<str>) -> QueryError {
    QueryError::Sql {
        category,
        detail: detail.as_ref().to_string(),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySqlRequest {
    pub sql: String,
    #[serde(default)]
    pub parameters: Vec<QuerySqlParameter>,
}

impl QuerySqlRequest {
    pub fn validate(&self) -> Result<()> {
        if self.parameters.len() > MAX_PARAMETERS {
            return Err(categorized_error(
                QuerySqlErrorCategory::InvalidArguments,
                format!("parameters exceed the {MAX_PARAMETERS}-item limit"),
            ));
        }
        let bytes = serde_json::to_vec(&self.parameters)?.len();
        if bytes > MAX_PARAMETER_ENCODED_BYTES {
            return Err(categorized_error(
                QuerySqlErrorCategory::InvalidArguments,
                format!("parameters exceed the {MAX_PARAMETER_ENCODED_BYTES}-byte encoded limit"),
            ));
        }
        for parameter in &self.parameters {
            parameter.validate()?;
        }
        Ok(())
    }
}

/// Ordered positional parameter. `value: null` is a typed SQL NULL. Integer
/// values use decimal strings and bytes use base64 so JSON never loses data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuerySqlParameter {
    Boolean {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    Integer {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<String>,
    },
    Real {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<f64>,
    },
    Text {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<String>,
    },
    Bytes {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<String>,
    },
    Json {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<String>,
    },
    Timestamp {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<String>,
    },
}

/// `Option<T>` normally treats an omitted field like an explicit JSON null.
/// Applying a custom field deserializer keeps null valid but makes omission a
/// Serde `missing field` error, which the MCP boundary categorizes exactly.
fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl QuerySqlParameter {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Integer { value: Some(value) } => {
                value.parse::<i64>().map_err(|_| {
                    categorized_error(
                        QuerySqlErrorCategory::InvalidArguments,
                        "integer parameter must be a signed 64-bit decimal string",
                    )
                })?;
            }
            Self::Bytes { value: Some(value) } => {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| {
                        categorized_error(
                            QuerySqlErrorCategory::InvalidArguments,
                            "bytes parameter must be canonical base64",
                        )
                    })?;
            }
            Self::Timestamp { value: Some(value) } => {
                chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
                    categorized_error(
                        QuerySqlErrorCategory::InvalidArguments,
                        "timestamp parameter must be RFC 3339",
                    )
                })?;
            }
            Self::Json { value: Some(value) } => {
                serde_json::from_str::<Value>(value).map_err(|_| {
                    categorized_error(
                        QuerySqlErrorCategory::InvalidArguments,
                        "json parameter must be valid JSON text",
                    )
                })?;
            }
            Self::Real { value: Some(value) } if !value.is_finite() => {
                return Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "real parameter must be finite",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct QuerySqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<Value>,
    pub row_count: usize,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuerySqlProfile {
    SqliteLocal,
    PostgresServer,
    TursoLocal,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlUnavailableReason {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlDialectContract {
    pub name: &'static str,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlProfileContract {
    pub id: &'static str,
    pub revision: u32,
    pub mode: &'static str,
    pub dialect: QuerySqlDialectContract,
    pub placeholder: &'static str,
    pub available: bool,
    pub unavailable_reason: Option<QuerySqlUnavailableReason>,
}

impl QuerySqlProfile {
    pub fn contract(self) -> QuerySqlProfileContract {
        match self {
            Self::SqliteLocal => QuerySqlProfileContract {
                id: "sqlite-local",
                revision: 1,
                mode: "embedded",
                dialect: QuerySqlDialectContract {
                    name: "sqlite",
                    // The root crate pins libsqlite3-sys 0.30's bundled
                    // amalgamation. Keeping the value here avoids a storage
                    // dependency in this pure contract member; a root
                    // compatibility test asserts it still matches the linked
                    // runtime whenever that pin changes.
                    version: "3.46.0".to_owned(),
                },
                placeholder: "?1",
                available: true,
                unavailable_reason: None,
            },
            Self::PostgresServer => QuerySqlProfileContract {
                id: "postgres-server",
                revision: 5,
                mode: "network",
                dialect: QuerySqlDialectContract {
                    name: "postgresql",
                    version: "16+".to_owned(),
                },
                placeholder: "$1",
                available: true,
                unavailable_reason: None,
            },
            Self::TursoLocal => QuerySqlProfileContract {
                id: "turso-local",
                revision: 4,
                mode: "embedded",
                dialect: QuerySqlDialectContract {
                    name: "turso-sqlite",
                    version: "Turso 0.7.2".to_owned(),
                },
                placeholder: "?1",
                available: true,
                unavailable_reason: None,
            },
        }
    }
}

pub const PROFILES: &[QuerySqlProfile] = &[
    QuerySqlProfile::SqliteLocal,
    QuerySqlProfile::PostgresServer,
    QuerySqlProfile::TursoLocal,
];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlParameterContract {
    pub style: &'static str,
    pub placeholder: &'static str,
    pub null_encoding: &'static str,
    pub types: &'static [QuerySqlParameterTypeContract],
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlResultContract {
    pub response_fields: &'static [&'static str],
    pub row_shape: &'static str,
    pub unique_column_labels: bool,
    pub values: &'static [QuerySqlValueEncoding],
    pub engine_type_rules: &'static [QuerySqlEngineTypeRule],
    pub unsupported_type_policy: QuerySqlUnsupportedTypePolicy,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlCapability {
    pub format: &'static str,
    pub available: bool,
    pub unavailable_reason: Option<QuerySqlUnavailableReason>,
    pub profile: QuerySqlProfileContract,
    pub dialect: QuerySqlDialectContract,
    pub parameters: QuerySqlParameterContract,
    pub limits: QuerySqlLimits,
    pub guide_topic: &'static str,
    pub logical_catalog: &'static [QuerySqlRelationContract],
    pub result_encoding: QuerySqlResultContract,
    pub error_categories: Vec<&'static str>,
    pub known_profiles: Vec<QuerySqlProfileContract>,
}

pub fn capability_contract(profile: QuerySqlProfile) -> QuerySqlCapability {
    let active = profile.contract();
    QuerySqlCapability {
        format: "native.query-sql-capability.v2",
        available: active.available,
        unavailable_reason: active.unavailable_reason.clone(),
        parameters: QuerySqlParameterContract {
            style: "ordered-positional-tagged",
            placeholder: active.placeholder,
            null_encoding: "explicit-json-null-value",
            types: PARAMETER_TYPES,
        },
        dialect: active.dialect.clone(),
        profile: active,
        limits: LIMITS,
        guide_topic: GUIDE_TOPIC,
        logical_catalog: LOGICAL_RELATIONS,
        result_encoding: QuerySqlResultContract {
            response_fields: RESULT_FIELDS,
            row_shape: "object-keyed-by-unique-column-label",
            unique_column_labels: true,
            values: RESULT_VALUE_ENCODINGS,
            engine_type_rules: ENGINE_TYPE_RULES,
            unsupported_type_policy: UNSUPPORTED_TYPE_POLICY,
        },
        error_categories: ERROR_CATEGORIES
            .iter()
            .map(|category| category.as_str())
            .collect(),
        known_profiles: PROFILES.iter().map(|profile| profile.contract()).collect(),
    }
}

pub fn capability(profile: QuerySqlProfile) -> Value {
    serde_json::to_value(capability_contract(profile)).expect("query_sql capability serializes")
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuerySqlGuideContract {
    pub format: &'static str,
    pub guide_topic: &'static str,
    pub limits: QuerySqlLimits,
    pub parameter_types: &'static [QuerySqlParameterTypeContract],
    pub parameter_null_encoding: &'static str,
    pub logical_catalog: &'static [QuerySqlRelationContract],
    pub result_encoding: QuerySqlResultContract,
    pub error_categories: Vec<&'static str>,
    pub profiles: Vec<QuerySqlProfileContract>,
}

pub fn guide_contract() -> QuerySqlGuideContract {
    QuerySqlGuideContract {
        format: "native.query-sql-guide-contract.v1",
        guide_topic: GUIDE_TOPIC,
        limits: LIMITS,
        parameter_types: PARAMETER_TYPES,
        parameter_null_encoding: "explicit-json-null-value",
        logical_catalog: LOGICAL_RELATIONS,
        result_encoding: QuerySqlResultContract {
            response_fields: RESULT_FIELDS,
            row_shape: "object-keyed-by-unique-column-label",
            unique_column_labels: true,
            values: RESULT_VALUE_ENCODINGS,
            engine_type_rules: ENGINE_TYPE_RULES,
            unsupported_type_policy: UNSUPPORTED_TYPE_POLICY,
        },
        error_categories: ERROR_CATEGORIES
            .iter()
            .map(|category| category.as_str())
            .collect(),
        profiles: PROFILES.iter().map(|profile| profile.contract()).collect(),
    }
}

pub fn render_guide_contract_markdown() -> String {
    let contract = guide_contract();
    let json =
        serde_json::to_string_pretty(&contract).expect("query_sql guide contract serializes");
    format!(
        "## Generated contract reference\n\nThis exhaustive reference is generated from the same typed metadata used by `engine_info` and runtime admission. The `profiles` entries define availability, immutable profile revision, dialect/version, and placeholder syntax. `logical_catalog`, `limits`, `parameter_types`, `result_encoding`, and `error_categories` are normative; adapters may report a safe engine-specific error detail but must not invent a different result shape.\n\n```json\n{json}\n```"
    )
}

/// MCP request schema derived from the canonical parameter tag inventory.
pub fn request_schema() -> Value {
    let one_of = PARAMETER_TYPES
        .iter()
        .map(|parameter| {
            let value_schema = match parameter.tag {
                "boolean" => json!({ "type": ["boolean", "null"] }),
                "integer" => {
                    json!({ "type": ["string", "null"], "pattern": "^-?[0-9]+$" })
                }
                "real" => json!({ "type": ["number", "null"] }),
                "text" => json!({ "type": ["string", "null"] }),
                "bytes" => {
                    json!({ "type": ["string", "null"], "contentEncoding": "base64" })
                }
                "json" => json!({
                    "type": ["string", "null"],
                    "description": "Valid JSON text; use the string 'null' for JSON null and an explicit null value for SQL NULL."
                }),
                "timestamp" => {
                    json!({ "type": ["string", "null"], "format": "date-time" })
                }
                unexpected => unreachable!("unknown query_sql parameter tag {unexpected}"),
            };
            json!({
                "type": "object",
                "properties": {
                    "type": { "const": parameter.tag },
                    "value": value_schema
                },
                "required": ["type", "value"],
                "additionalProperties": false
            })
        })
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "properties": {
            "sql": { "type": "string", "description": "One engine-native SELECT/WITH statement." },
            "parameters": {
                "type": "array",
                "maxItems": LIMITS.parameter_count,
                "description": "Ordered tagged positional parameters. Read engine_info.query_sql.parameters.placeholder for the active profile.",
                "items": { "oneOf": one_of }
            }
        },
        "required": ["sql"],
        "additionalProperties": false
    })
}

/// Admission reads the same descriptor exposed by `engine_info`; a profile
/// cannot be executed while discovery says it is unavailable.
pub fn require_available(profile: QuerySqlProfile) -> Result<()> {
    let descriptor = capability_contract(profile);
    if descriptor.available {
        return Ok(());
    }
    let reason = descriptor
        .unavailable_reason
        .map(|reason| reason.code)
        .unwrap_or("unsupported_profile");
    Err(categorized_error(
        QuerySqlErrorCategory::UnsupportedProfile,
        reason,
    ))
}

/// Defence-in-depth classifier. The backend parser and authorization provider
/// remain authoritative. This scanner only establishes one SELECT/WITH-shaped
/// statement and rejects obvious write/session/control tokens outside quoted
/// and commented text.
pub fn classify_single_read_statement(profile: QuerySqlProfile, sql: &str) -> Result<String> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(categorized_error(
            QuerySqlErrorCategory::InvalidArguments,
            format!("SQL input exceeds the {MAX_SQL_BYTES}-byte limit"),
        ));
    }
    let tokens = scan_tokens(profile, sql)?;
    let mut words = Vec::new();
    let mut semicolons = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => words.push(word),
            Token::Semicolon(offset) => semicolons.push(offset),
        }
    }
    let Some(first) = words.first() else {
        return Err(categorized_error(
            QuerySqlErrorCategory::InvalidArguments,
            "empty query",
        ));
    };
    if !matches!(first.as_str(), "select" | "with") {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("read-only statement must start with SELECT or WITH, got '{first}'"),
        ));
    }
    const FORBIDDEN: [&str; 23] = [
        "insert",
        "update",
        "delete",
        "merge",
        "create",
        "alter",
        "drop",
        "truncate",
        "grant",
        "revoke",
        "copy",
        "call",
        "do",
        "pragma",
        "attach",
        "detach",
        "vacuum",
        "reindex",
        "begin",
        "commit",
        "rollback",
        "savepoint",
        "release",
    ];
    if let Some(word) = words.iter().find(|word| FORBIDDEN.contains(&word.as_str())) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("read-only statement contains prohibited token '{word}'"),
        ));
    }
    if semicolons.len() > 1
        || semicolons
            .first()
            .is_some_and(|offset| !only_space_or_comments(profile, &sql[offset + 1..]))
    {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "a single statement only",
        ));
    }
    let statement = semicolons.first().map_or(sql, |offset| &sql[..*offset]);
    Ok(statement.trim().to_owned())
}

enum Token {
    Word(String),
    Semicolon(usize),
}

fn scan_tokens(profile: QuerySqlProfile, sql: &str) -> Result<Vec<Token>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = block_comment_end(bytes, i, profile == QuerySqlProfile::PostgresServer)?;
            }
            b'e' | b'E'
                if profile == QuerySqlProfile::PostgresServer
                    && bytes.get(i + 1) == Some(&b'\'') =>
            {
                i = quoted_end(bytes, i + 1, b'\'', true)?;
            }
            b'\'' | b'"' => {
                let quote = bytes[i];
                i = quoted_end(bytes, i, quote, false)?;
            }
            b'`' if profile != QuerySqlProfile::PostgresServer => {
                i = quoted_end(bytes, i, b'`', false)?;
            }
            b'[' if profile != QuerySqlProfile::PostgresServer => {
                i = bracket_identifier_end(bytes, i)?;
            }
            b'$' if profile == QuerySqlProfile::PostgresServer => {
                if let Some((delimiter, after)) = dollar_delimiter(sql, i) {
                    let rest = &sql[after..];
                    let Some(end) = rest.find(&delimiter) else {
                        return syntax_error("unterminated dollar-quoted string");
                    };
                    i = after + end + delimiter.len();
                } else {
                    i += 1;
                }
            }
            b';' => {
                tokens.push(Token::Semicolon(i));
                i += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                tokens.push(Token::Word(sql[start..i].to_ascii_lowercase()));
            }
            _ => i += 1,
        }
    }
    Ok(tokens)
}

fn quoted_end(bytes: &[u8], start: usize, quote: u8, backslash_escapes: bool) -> Result<usize> {
    let mut i = start + 1;
    loop {
        if i >= bytes.len() {
            return syntax_error("unterminated quoted value or identifier");
        }
        if backslash_escapes && bytes[i] == b'\\' {
            if i + 1 >= bytes.len() {
                return syntax_error("unterminated PostgreSQL escape string");
            }
            i += 2;
        } else if bytes[i] == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return Ok(i + 1);
            }
        } else {
            i += 1;
        }
    }
}

fn bracket_identifier_end(bytes: &[u8], start: usize) -> Result<usize> {
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != b']' {
        i += 1;
    }
    if i >= bytes.len() {
        return syntax_error("unterminated bracket identifier");
    }
    Ok(i + 1)
}

fn block_comment_end(bytes: &[u8], start: usize, nested: bool) -> Result<usize> {
    let mut depth = 1_usize;
    let mut i = start + 2;
    while i + 1 < bytes.len() {
        if nested && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            i += 2;
        } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Ok(i);
            }
        } else {
            i += 1;
        }
    }
    syntax_error("unterminated block comment")
}

fn dollar_delimiter(sql: &str, offset: usize) -> Option<(String, usize)> {
    let bytes = sql.as_bytes();
    let mut i = offset + 1;
    if bytes.get(i) == Some(&b'$') {
        return Some(("$$".to_owned(), i + 1));
    }
    if !bytes
        .get(i)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    (bytes.get(i) == Some(&b'$')).then(|| (sql[offset..=i].to_owned(), i + 1))
}

fn only_space_or_comments(profile: QuerySqlProfile, sql: &str) -> bool {
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            byte if byte.is_ascii_whitespace() => i += 1,
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let Ok(end) =
                    block_comment_end(bytes, i, profile == QuerySqlProfile::PostgresServer)
                else {
                    return false;
                };
                i = end;
            }
            _ => return false,
        }
    }
    true
}

fn syntax_error<T>(detail: &str) -> Result<T> {
    Err(categorized_error(
        QuerySqlErrorCategory::SyntaxOrType,
        detail,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_classifier_understands_sqlite_quoting_and_parameters() {
        for sql in [
            "-- lead\nSELECT ';' AS value",
            "SELECT \"delete;\" FROM records",
            "SELECT `update;` FROM records",
            "SELECT [drop;] FROM records",
            "SELECT $name AS value",
        ] {
            assert!(
                classify_single_read_statement(QuerySqlProfile::SqliteLocal, sql).is_ok(),
                "{sql}"
            );
        }
        assert!(classify_single_read_statement(
            QuerySqlProfile::SqliteLocal,
            "SELECT $tag$DELETE; DROP$tag$ AS body"
        )
        .is_err());
    }

    #[test]
    fn postgres_classifier_understands_native_lexical_forms() {
        for sql in [
            "SELECT \"delete;drop\" FROM records",
            "SELECT $$DELETE; DROP$$ AS body",
            "SELECT $tag$DELETE; DROP$tag$ AS body; -- tail",
            r"SELECT E'escaped\'; DELETE' AS body",
            "SELECT /* outer DELETE /* inner ; */ DROP */ 1",
        ] {
            assert!(
                classify_single_read_statement(QuerySqlProfile::PostgresServer, sql).is_ok(),
                "{sql}"
            );
        }
    }

    #[test]
    fn classifier_rejects_multiple_and_data_modifying_ctes() {
        for sql in [
            "SELECT 1; SELECT 2",
            "WITH changed AS (DELETE FROM records RETURNING id) SELECT * FROM changed",
            "COPY records TO PROGRAM 'cat'",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_err(),
                    "{profile:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn every_parameter_tag_requires_an_explicit_nullable_value() {
        for parameter in PARAMETER_TYPES {
            let error = serde_json::from_value::<QuerySqlRequest>(json!({
                "sql": "SELECT ?1",
                "parameters": [{ "type": parameter.tag }]
            }))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("missing field `value`"),
                "{}: {error}",
                parameter.tag
            );
        }
    }

    #[test]
    fn capability_is_truthful_per_profile() {
        assert_eq!(capability(QuerySqlProfile::SqliteLocal)["available"], true);
        assert_eq!(
            capability(QuerySqlProfile::PostgresServer)["available"],
            true
        );
        assert_eq!(capability(QuerySqlProfile::TursoLocal)["available"], true);
    }

    #[test]
    fn activity_relations_have_ratified_identities_and_sqlite_only_profiles() {
        let relation = |name| {
            LOGICAL_RELATIONS
                .iter()
                .find(|relation| relation.name == name)
                .unwrap()
        };
        assert_eq!(
            relation("agent_activity").identity,
            "native.semantic.agent_activity"
        );
        assert_eq!(
            relation("agent_activity_claims").identity,
            "native.semantic.agent_activity_claims"
        );
        for name in ["agent_activity", "agent_activity_claims"] {
            assert_eq!(relation(name).profiles, &["sqlite-local"]);
            assert_eq!(relation(name).completeness, "best_effort");
        }
        assert_eq!(
            relation("agent_activity").semantic_version,
            AGENT_ACTIVITY_RELATION_VERSION
        );
        assert_eq!(relation("agent_activity").semantic_version, 2);
        assert_eq!(
            &relation("agent_activity").columns[..2],
            &["activity_id", "run_key"]
        );
        assert_eq!(relation("agent_activity_claims").semantic_version, 1);
    }

    #[test]
    fn content_events_alone_advances_for_the_honest_local_cursor_name() {
        let content = LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "content_events")
            .unwrap();
        assert_eq!(LOGICAL_CATALOG_REVISION, 3);
        assert_eq!(content.semantic_version, CONTENT_EVENTS_RELATION_VERSION);
        assert_eq!(content.semantic_version, 2);
        assert_eq!(
            content.columns,
            &["local_seq", "id", "record_id", "type", "created_at"]
        );
        assert!(LOGICAL_RELATIONS
            .iter()
            .filter(|relation| { !matches!(relation.name, "content_events" | "agent_activity") })
            .all(|relation| relation.semantic_version == LOGICAL_RELATION_VERSION));
    }

    #[test]
    fn postgres_reports_the_qualified_server_profile() {
        let contract = QuerySqlProfile::PostgresServer.contract();
        assert!(contract.available);
        assert_eq!(contract.revision, 5);
        assert_eq!(contract.unavailable_reason, None);
    }

    #[test]
    fn turso_reports_completed_isolated_core_qualification() {
        let contract = QuerySqlProfile::TursoLocal.contract();
        assert!(contract.available);
        assert_eq!(contract.revision, 4);
        assert_eq!(contract.unavailable_reason, None);
        assert_eq!(
            capability(QuerySqlProfile::TursoLocal)["unavailable_reason"],
            Value::Null
        );
    }

    #[test]
    fn postgres_result_type_rules_are_total_and_lossless() {
        let find = |types: &[&str], condition: &str| {
            ENGINE_TYPE_RULES
                .iter()
                .find(|rule| rule.engine_types == types && rule.condition == condition)
                .unwrap_or_else(|| panic!("missing rule for {types:?} when {condition}"))
        };
        let encoded = |types: &[&str], condition: &str, encoding: &str| {
            let rule = find(types, condition);
            assert_eq!(rule.profile, "postgres-server@5");
            assert_eq!(rule.outcome, "encode");
            assert_eq!(rule.json_encoding, Some(encoding));
            assert_eq!(rule.error_category, None);
        };
        let rejected = |types: &[&str], condition: &str| {
            let rule = find(types, condition);
            assert_eq!(rule.profile, "postgres-server@5");
            assert_eq!(rule.outcome, "reject");
            assert_eq!(rule.json_encoding, None);
            assert_eq!(rule.error_category, Some("syntax_or_type"));
        };

        assert_eq!(ENGINE_TYPE_RULES.len(), 13);
        encoded(&["*"], "value is SQL NULL", "null");
        encoded(&["bool"], "non-null", "boolean");
        encoded(&["int2", "int4", "int8"], "non-null", "signed-json-integer");
        encoded(&["float4", "float8"], "finite", "json-number");
        rejected(&["float4", "float8"], "NaN, +Infinity, or -Infinity");
        encoded(&["numeric"], "finite", "lossless-canonical-decimal-string");
        rejected(&["numeric"], "NaN, +Infinity, or -Infinity");
        encoded(
            &["text", "varchar", "bpchar", "char", "name"],
            "non-null UTF-8 text",
            "string",
        );
        encoded(&["bytea"], "non-null", "base64-string");
        encoded(
            &["json", "jsonb"],
            "non-null; preserve the engine's canonical JSON text without decoding through serde_json::Value",
            "canonical-json-text-string",
        );
        encoded(&["timestamptz"], "non-null", "rfc3339-string");
        rejected(&["timestamp"], "non-null value has no UTC offset");
        rejected(
            &["array types (*[])"],
            "unless a later contract revision explicitly supports the exact array type",
        );
        assert_eq!(
            UNSUPPORTED_TYPE_POLICY,
            QuerySqlUnsupportedTypePolicy {
                outcome: "reject",
                error_category: "syntax_or_type",
                rule: "Reject every engine type or value form not matched by an explicit rule, including domains, enums, composites, ranges, multiranges, geometric, network, bit, vector, extension, and unknown types; never coerce or stringify implicitly.",
            }
        );
    }

    #[test]
    fn json_text_distinguishes_json_null_from_sql_null() {
        let json_null: QuerySqlRequest = serde_json::from_value(json!({
            "sql": "SELECT ?1",
            "parameters": [{ "type": "json", "value": "null" }]
        }))
        .unwrap();
        let sql_null: QuerySqlRequest = serde_json::from_value(json!({
            "sql": "SELECT ?1",
            "parameters": [{ "type": "json", "value": null }]
        }))
        .unwrap();
        assert!(json_null.validate().is_ok());
        assert!(sql_null.validate().is_ok());
        assert!(matches!(
            &json_null.parameters[0],
            QuerySqlParameter::Json { value: Some(value) } if value == "null"
        ));
        assert!(matches!(
            &sql_null.parameters[0],
            QuerySqlParameter::Json { value: None }
        ));
    }
}
