//! Engine-neutral contract for caller-supplied, read-only SQL.
//!
//! This module owns the public request, result, limits, discovery metadata and
//! defence-in-depth statement classifier. Backend adapters remain responsible
//! for authoritative parsing, authorization and read-only execution. It is
//! deliberately separate from `portable_sql`, which accepts only Native-owned
//! reviewed statements.

use std::collections::{BTreeSet, HashMap, HashSet};

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
pub const LOGICAL_CATALOG_REVISION: u32 = 4;
pub const LOGICAL_RELATION_VERSION: u32 = 1;
pub const CONTENT_EVENTS_RELATION_VERSION: u32 = 2;
pub const AGENT_ACTIVITY_RELATION_VERSION: u32 = 3;

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
            "last_activity_at_ms",
            "created_at",
            "created_at_ms",
            "updated_at",
            "updated_at_ms",
            "deleted_at",
            "deleted_at_ms",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.content-events",
        name: "content_events",
        semantic_version: CONTENT_EVENTS_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "local_seq",
            "id",
            "record_id",
            "type",
            "created_at",
            "created_at_ms",
        ],
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
            "created_at_ms",
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
            "created_at_ms",
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
            "observed_at_ms",
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
            "last_seen_at_ms",
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
            "created_at_ms",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.vocabularies",
        name: "vocabularies",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: false,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &["id", "name", "created_at", "created_at_ms"],
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
            "created_at_ms",
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
            "recomputed_at_ms",
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
            "started_at_ms",
            "ended_at",
            "ended_at_ms",
            "last_observed_activity_at",
            "last_observed_activity_at_ms",
            "active_until",
            "active_until_ms",
            "appears_active",
            "declared_intent",
            "declared_intent_state",
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
            "claimed_at_ms",
            "released_at",
            "released_at_ms",
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
    QuerySqlRelationContract {
        identity: "native.query-sql.catalog-relations",
        name: "catalog_relations",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: false,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "relation_name",
            "identity",
            "semantic_version",
            "caller_relative",
            "completeness",
            "profiles",
            "comment",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.catalog-columns",
        name: "catalog_columns",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: false,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &["relation_name", "column_name", "column_position"],
    },
];

pub fn is_logical_relation(name: &str) -> bool {
    LOGICAL_RELATIONS
        .iter()
        .any(|relation| relation.name == name)
}

/// Machine-readable keyset repair attached to truncated results, identical
/// on every engine. Names the bound and the repair, not the statement.
pub fn truncation_hint() -> String {
    format!(
        "result truncated at {} rows: add ORDER BY over a unique key and \
         page with a keyset predicate (WHERE key > ?N) rather than raising LIMIT",
        MAX_ROWS
    )
}

/// Physical tables agents probe for, with the logical relation to use.
/// A probed table absent here gets the full relation list instead.
const PHYSICAL_TO_LOGICAL: &[(&str, &str)] = &[
    ("relationships", "effective_relationships"),
    ("relationship_endpoints", "effective_relationships"),
    ("relationship_assertion_heads", "effective_relationships"),
];

fn is_catalog_probe(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "sqlite_master"
        || lower == "sqlite_schema"
        || lower == "information_schema"
        || lower == "pg_catalog"
        || lower.contains("sqlite_master")
        || lower.contains("information_schema")
        || lower.contains("pg_catalog")
        || lower.starts_with("pragma_")
        || lower.starts_with("sqlite_")
        || lower.starts_with("pg_")
}

/// Repair suffix for a blocked catalog probe or physical table, shared by
/// every engine so the wording cannot drift per backend. The relation list
/// and the physical→logical map are filtered by the active profile, so a
/// caller is never pointed at a relation their engine cannot query.
/// Returns `None` when the name is a logical relation (or empty): the
/// engine detail stands alone and no repair is appended.
pub fn blocked_relation_repair(name: &str, profile: QuerySqlProfile) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || is_logical_relation(&trimmed.to_ascii_lowercase()) {
        return None;
    }
    if is_catalog_probe(trimmed) {
        return Some(format!(
            "'{trimmed}' is catalog introspection, not a queryable relation. \
             List relations and columns with SELECT relation_name, column_name, \
             column_position FROM catalog_columns ORDER BY relation_name, \
             column_position, and read relation notes in catalog_relations."
        ));
    }
    let profile_id = profile.contract().id;
    if let Some((_, logical)) = PHYSICAL_TO_LOGICAL.iter().find(|(physical, logical)| {
        physical.eq_ignore_ascii_case(trimmed)
            && LOGICAL_RELATIONS.iter().any(|relation| {
                relation.name == *logical && relation.profiles.contains(&profile_id)
            })
    }) {
        return Some(format!(
            "'{trimmed}' is a physical table, not a queryable relation. \
             Use logical relation '{logical}' instead."
        ));
    }
    let names = LOGICAL_RELATIONS
        .iter()
        .filter(|relation| relation.profiles.contains(&profile_id))
        .map(|relation| relation.name)
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "'{trimmed}' is not a queryable logical relation. \
         Queryable relations on {profile_id}: {names}."
    ))
}

/// One-line relation notes for `catalog_relations`, carrying the join keys
/// agents otherwise guess. Descriptive only; the drift tests pin structure,
/// not prose. No apostrophes: values render inside single-quoted SQL.
const RELATION_COMMENTS: &[(&str, &str)] = &[
    ("records", "one row per visible record - join links.source_id/target_id, facet_values.record_id and content_events.record_id to records.id - home_id is NULL when the home is not visible"),
    ("content_events", "append-only history - join record_id to records.id - local_seq orders it"),
    ("links", "edges - join source_id and target_id to records.id - both endpoints must be visible or the edge is absent"),
    ("facet_values", "current facet per (record_id, key) - join record_id to records.id"),
    ("facet_observations", "facet history with as_of/observed_at/event_seq - join record_id to records.id"),
    ("bindings", "caller-owned account/email bindings - join record_id to records.id"),
    ("blobs", "attachment payloads reachable through facet_values key blob_ref on a Document attachment"),
    ("vocabularies", "caller-independent - join vocabulary_values.vocabulary_id to vocabularies.id"),
    ("vocabulary_values", "join vocabulary_id to vocabularies.id"),
    ("schema_config", "workspace configuration rows"),
    ("effective_relationships", "governed relationships - endpoints is a JSON array with record_id per endpoint"),
    ("agent_activity", "best-effort run presence over the last 24 hours - declared_intent is caller disclosure, not verified fact"),
    ("agent_activity_claims", "durable claim events - join activity_id to agent_activity, record_id to records.id"),
    ("messages_awaiting_reply", "single-column queue of message ids awaiting reply"),
    ("catalog_relations", "this catalog - one row per declared relation, filter profiles for queryability"),
    ("catalog_columns", "one row per (relation, column) - order by relation_name, column_position"),
];

/// Rows of `catalog_relations`, generated from `LOGICAL_RELATIONS`:
/// (name, identity, version, caller_relative 0/1, completeness,
/// comma-joined profiles, comment).
pub fn catalog_relation_rows() -> Vec<(
    &'static str,
    &'static str,
    u32,
    i64,
    &'static str,
    String,
    &'static str,
)> {
    LOGICAL_RELATIONS
        .iter()
        .map(|relation| {
            let comment = RELATION_COMMENTS
                .iter()
                .find(|(name, _)| *name == relation.name)
                .map(|(_, comment)| *comment)
                .unwrap_or("");
            (
                relation.name,
                relation.identity,
                relation.semantic_version,
                i64::from(relation.caller_relative),
                relation.completeness,
                relation.profiles.join(","),
                comment,
            )
        })
        .collect()
}

/// Rows of `catalog_columns`, generated from `LOGICAL_RELATIONS`:
/// (relation, column, zero-based position).
pub fn catalog_column_rows() -> Vec<(&'static str, &'static str, usize)> {
    let mut rows = Vec::new();
    for relation in LOGICAL_RELATIONS {
        for (position, column) in relation.columns.iter().enumerate() {
            rows.push((relation.name, *column, position));
        }
    }
    rows
}

fn sql_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// `CREATE VIEW` statements for the two catalog relations, generated from
/// `LOGICAL_RELATIONS` so the served catalog cannot drift from the
/// admission catalog. Every engine executes these verbatim (SQLite/Turso
/// as TEMP views, Postgres with its own prefix); row content is identical.
/// Postgres has no `CREATE VIEW IF NOT EXISTS`, so it passes `false`.
pub fn catalog_view_statements(if_not_exists: bool) -> Vec<String> {
    // Postgres has no CREATE VIEW IF NOT EXISTS, so it passes false.
    let guard = if if_not_exists { "IF NOT EXISTS " } else { "" };
    let mut relations = format!("CREATE TEMP VIEW {guard}catalog_relations AS ");
    for (index, (name, identity, version, caller_relative, completeness, profiles, comment)) in
        catalog_relation_rows().iter().enumerate()
    {
        if index > 0 {
            relations.push_str(" UNION ALL ");
        }
        relations.push_str(&format!(
            "SELECT {name} AS relation_name, {identity} AS identity, \
             {version} AS semantic_version, {caller_relative} AS caller_relative, \
             {completeness} AS completeness, {profiles} AS profiles, {comment} AS comment",
            name = sql_quote(name),
            identity = sql_quote(identity),
            profiles = sql_quote(profiles),
            completeness = sql_quote(completeness),
            comment = sql_quote(comment),
        ));
    }
    let mut columns = format!("CREATE TEMP VIEW {guard}catalog_columns AS ");
    for (index, (relation, column, position)) in catalog_column_rows().iter().enumerate() {
        if index > 0 {
            columns.push_str(" UNION ALL ");
        }
        columns.push_str(&format!(
            "SELECT {relation} AS relation_name, {column} AS column_name, \
             {position} AS column_position",
            relation = sql_quote(relation),
            column = sql_quote(column),
        ));
    }
    vec![relations, columns]
}

/// Join-key notes for the `sql_read` catalog card, one per relation.
/// Relation names and columns render from `LOGICAL_RELATIONS` itself, so
/// only this prose can drift; the card test pins both directions.
const CARD_NOTES: &[(&str, &str)] = &[
    ("records", "containment parent is home_id (NULL when the home is not visible); join links.source_id/target_id, facet_values.record_id and content_events.record_id to id"),
    ("content_events", "append-only history; record_id to records.id; local_seq orders it"),
    ("links", "edges; part_of runs source (part) -> target (whole); both endpoints must be visible"),
    ("facet_values", "current value per (record_id, key); record_id to records.id"),
    ("facet_observations", "history; record_id to records.id"),
    ("bindings", "caller-owned account/email bindings only; record_id to records.id"),
    ("blobs", "attachment payloads via facet_values key blob_ref on a Document attachment"),
    ("vocabularies", "caller-independent; join vocabulary_values.vocabulary_id to id"),
    ("vocabulary_values", "vocabulary_id to vocabularies.id"),
    ("schema_config", "workspace configuration rows"),
    ("effective_relationships", "governed relationships; endpoints is a JSON array with record_id per endpoint"),
    ("agent_activity", "best-effort run presence over the last 24 hours"),
    ("agent_activity_claims", "activity_id to agent_activity, record_id to records.id"),
    ("messages_awaiting_reply", "single-column queue of message ids awaiting reply"),
    ("catalog_relations", "this catalog; one row per declared relation - filter profiles for queryability"),
    ("catalog_columns", "one row per (relation, column); order by relation_name, column_position"),
];

/// Worked statements shipped in the card. Each runs verbatim (plus a seed
/// scope predicate) as a conformance case in `sql_conformance::corpus()`
/// and in the Postgres parity loop, so a card example can never fail.
/// Placeholders are spelled `?N` here to match the SQLite/Turso convention
/// callers write; the validator rules themselves belong to E1 M2, so
/// review placeholder-behavior changes there, not in this text.
pub const CARD_WORKED_STATEMENTS: &[(&str, &str)] = &[
    ("Current work", "SELECT id, type, name, lifecycle FROM records WHERE type = 'WorkItem' AND lifecycle IN ('open', 'in_progress', 'blocked') ORDER BY last_activity_at DESC, id LIMIT 20"),
    ("Direct children of a folder or record", "SELECT id, type, name FROM records WHERE home_id = ?1 ORDER BY name, id"),
    ("Parts of a record (semantic part_of links run child source -> parent target)", "SELECT l.source_id, r.name FROM links l JOIN records r ON r.id = l.source_id WHERE l.target_id = ?1 AND l.relationship = 'part_of' ORDER BY r.name, l.source_id"),
    ("Recent history of one record", "SELECT local_seq, type, created_at FROM content_events WHERE record_id = ?1 ORDER BY local_seq DESC LIMIT 10"),
];

/// Budget for the served card (bytes).
pub const SQL_READ_CARD_MAX_BYTES: usize = 6 * 1024;
/// Budget for the whole served `sql_read` descriptor (bytes).
pub const SQL_READ_DESCRIPTOR_MAX_BYTES: usize = 8 * 1024;

/// Compact catalog card for the `sql_read` descriptor, generated from
/// `LOGICAL_RELATIONS` (names, columns, profile scope) with hand-written
/// join notes and worked statements. It renders inside descriptor prose,
/// never inside a SQL batch, so its notes may use semicolons freely.
pub fn sql_read_catalog_card() -> String {
    let mut card = String::from(
        "Queryable relations (caller-visible). Full column list: \
         SELECT relation_name, column_name, column_position FROM catalog_columns \
         ORDER BY relation_name, column_position. \
         Relation notes: SELECT * FROM catalog_relations ORDER BY relation_name.",
    );
    for relation in LOGICAL_RELATIONS {
        let note = CARD_NOTES
            .iter()
            .find(|(name, _)| *name == relation.name)
            .map(|(_, note)| *note)
            .unwrap_or("");
        card.push_str(&format!(
            "\n{}({}): {}",
            relation.name,
            relation.columns.join(","),
            note,
        ));
        if relation.profiles != ALL_PROFILES {
            card.push_str(&format!(" [only: {}]", relation.profiles.join(",")));
        }
    }
    card.push_str(
        "\nValues: timestamps as UTC-millis text with integer *_ms companions; \
         booleans as 0/1; binary ordering for stored text; SQL NULL as JSON null. \
         Parameters: positional ?N (1-based, contiguous). \
         Text matching via LIKE is literal text/wildcard only (not line- or \
         word-aware): e.g. \
         LIKE '%- [ ]%' also matches records that merely quote the checklist \
         syntax, so check matched text before relying on a count. \
         Physical tables, sqlite_master, pragma_* and information_schema are \
         not queryable; the errors name the fix.",
    );
    for (intent, sql) in CARD_WORKED_STATEMENTS {
        card.push_str(&format!("\n{intent}: {sql}"));
    }
    card
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
        qualification: "computed boolean expressions on postgres-server only; every catalog boolean column presents 0/1 as signed_i64 on every engine",
    },
    QuerySqlValueEncoding {
        logical_type: "signed_i64",
        json_encoding: "integer",
        qualification: "exact signed 64-bit range",
    },
    QuerySqlValueEncoding {
        logical_type: "finite_real",
        json_encoding: "number",
        qualification: "finite IEEE-754 value for non-integral postgres-server numerics within the double range; integer-valued numerics encode as signed-json-integer",
    },
    QuerySqlValueEncoding {
        logical_type: "arbitrary_numeric",
        json_encoding: "decimal-string",
        qualification: "reserved: no current profile emits decimal strings; integer-valued numerics outside i64 and values outside the double range reject instead of encoding as text",
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
        qualification: "fixed UTC millisecond precision with Z suffix on every engine, plus integer epoch-millis *_ms companions for engine-managed timestamps",
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
        profile: "postgres-server@6",
        engine_types: &["*"],
        condition: "value is SQL NULL",
        outcome: "encode",
        json_encoding: Some("null"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["bool"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("boolean"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["int2", "int4", "int8"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("signed-json-integer"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["float4", "float8"],
        condition: "finite",
        outcome: "encode",
        json_encoding: Some("json-number"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["float4", "float8"],
        condition: "NaN, +Infinity, or -Infinity",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["numeric"],
        condition: "integer-valued and fits in i64",
        outcome: "encode",
        json_encoding: Some("signed-json-integer"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["numeric"],
        condition: "integer-valued but outside the i64 range",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["numeric"],
        condition: "non-integral, finite, and within the IEEE-754 double range",
        outcome: "encode",
        json_encoding: Some("json-number"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["numeric"],
        condition: "NaN, +Infinity, -Infinity, or magnitude beyond the double range",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["text", "varchar", "bpchar", "char", "name"],
        condition: "non-null UTF-8 text",
        outcome: "encode",
        json_encoding: Some("string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["bytea"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("base64-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["json", "jsonb"],
        condition: "non-null; preserve the engine's canonical JSON text without decoding through serde_json::Value",
        outcome: "encode",
        json_encoding: Some("canonical-json-text-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["timestamptz"],
        condition: "non-null",
        outcome: "encode",
        json_encoding: Some("rfc3339-string"),
        error_category: None,
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
        engine_types: &["timestamp"],
        condition: "non-null value has no UTC offset",
        outcome: "reject",
        json_encoding: None,
        error_category: Some("syntax_or_type"),
    },
    QuerySqlEngineTypeRule {
        profile: "postgres-server@6",
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

pub const RESULT_FIELDS: &[&str] = &[
    "columns",
    "rows",
    "row_count",
    "truncated",
    "truncation_hint",
    "as_of_seq",
];

/// `Some(hint)` exactly when a result was truncated, else `None`.
pub fn truncation_hint_for(truncated: bool) -> Option<String> {
    truncated.then(truncation_hint)
}

/// Exclusion repair for oversized stored values, identical wherever an
/// engine can name them. Offenders are `(relation, id)` pairs because ids
/// are per relation: each relation gets its own qualified clause
/// (`records.id NOT IN (...) AND links.id NOT IN (...)`), so the repair
/// stays unambiguous in joined statements. Shows at most 10 ids with the
/// total count; `None` when no id is known (engines that cap at projection
/// without row identity keep their existing message). Ids are single-quoted
/// with `'` doubled, so the clause is portable SQL the validator admits.
pub fn oversized_exclusion_hint(ids_by_relation: &[(&str, &str)]) -> Option<String> {
    if ids_by_relation.is_empty() {
        return None;
    }
    // Dedupe ids per relation, preserving first-seen relation order.
    let mut grouped: Vec<(&str, Vec<&str>)> = Vec::new();
    for (relation, id) in ids_by_relation {
        match grouped.iter_mut().find(|(known, _)| *known == *relation) {
            Some((_, ids)) => {
                if !ids.contains(id) {
                    ids.push(*id);
                }
            }
            None => grouped.push((relation, vec![*id])),
        }
    }
    let total: usize = grouped.iter().map(|(_, ids)| ids.len()).sum();
    // At most 10 ids overall; the probe names up to 12, so the count below
    // is reachable through the wired path.
    let mut remaining = 10;
    let mut clauses = Vec::new();
    for (relation, ids) in &grouped {
        let shown = ids
            .iter()
            .take(remaining)
            .map(|id| format!("'{}'", id.replace('\'', "''")))
            .collect::<Vec<_>>();
        if shown.is_empty() {
            break;
        }
        remaining -= shown.len();
        clauses.push(format!("{relation}.id NOT IN ({})", shown.join(", ")));
    }
    let mut hint = format!(
        "Exclude these oversized rows and retry with WHERE {}",
        clauses.join(" AND ")
    );
    if total > 10 {
        hint.push_str(&format!(" (first 10 of {total} oversized rows)"));
    }
    hint.push_str(
        ". If the statement aliases a relation, qualify with its alias instead \
         of the relation name (for example r.id when the statement reads records r).",
    );
    Some(hint)
}

/// Scan-versus-probe cause plus the repair, identical on every engine.
pub fn deadline_hint() -> String {
    format!(
        "query exceeded the governed SQL deadline of {}ms. \
         Scanning a caller-relative relation (records, links) rather than \
         probing it by id usually causes this: the visibility join turns a \
         scan into a whole-workspace authorization walk. Add a selective \
         WHERE on an indexed key, or LIMIT with ORDER BY.",
        QUERY_DEADLINE_MS
    )
}

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
    /// Keyset repair, present only when `truncated` is true. Rows are
    /// untouched; this is the only shape change. Additive: no catalog or
    /// revision bump (same rule as additive relations). Serialized on
    /// every engine whether null or set, so the field is always present.
    pub truncation_hint: Option<String>,
    /// Workspace content sequence (`COALESCE(MAX(seq), 0)` over
    /// `content_events`) observed inside the same read transaction or
    /// snapshot as the statement itself, never before or after it.
    pub as_of_seq: i64,
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
                // Revision 6: caller placeholders are `?N` on every
                // profile (I1); the Postgres path rewrites to `$N`
                // after the classifier (I1b).
                revision: 6,
                mode: "network",
                dialect: QuerySqlDialectContract {
                    name: "postgresql",
                    version: "16+".to_owned(),
                },
                placeholder: "?1",
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
            "sql": { "type": "string", "description": "One engine-native SELECT/WITH statement, optionally prefixed with EXPLAIN QUERY PLAN to inspect its plan." },
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
///
/// `EXPLAIN QUERY PLAN <statement>` is admitted when the explained statement
/// is itself admissible: it returns only the plan (never record data), so it
/// lets an author see a visibility-relation scan without widening the data
/// surface. Bare `EXPLAIN` and any other explained statement stay rejected.
pub fn classify_single_read_statement(profile: QuerySqlProfile, sql: &str) -> Result<String> {
    classify_single_read_statement_impl(profile, sql, true, FunctionAllowance::Portable)
}

/// Richard 25 Sep (Native e25665c): the I2 portable-function rules
/// (dropped functions + two-argument `round`) apply to NEW SQL only — ad-hoc
/// `query_sql` and SQL being saved. Inspection and execution of already-stored
/// governed SQL use this entry point instead: every other check is identical
/// (safety, single statement, relations, I1 placeholders, catalog pin), only
/// the portable-call scan is skipped and the legacy allowance (pre-I2
/// allowlist ∪ the portable subset) applies at the engine allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionAllowance {
    /// Ad-hoc `query_sql` and SQL being saved: the I2 portable subset.
    Portable,
    /// Native e25665c: already-stored governed SQL keeps working
    /// under the legacy allowance (pre-I2 allowlist ∪ portable subset).
    LegacySavedSql,
}

/// Inspection/execution of already-stored governed SQL. See
/// [`FunctionAllowance::LegacySavedSql`].
pub fn classify_stored_saved_sql(profile: QuerySqlProfile, sql: &str) -> Result<String> {
    classify_single_read_statement_impl(profile, sql, true, FunctionAllowance::LegacySavedSql)
}

fn classify_single_read_statement_impl(
    profile: QuerySqlProfile,
    sql: &str,
    allow_explain: bool,
    allowance: FunctionAllowance,
) -> Result<String> {
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
            Token::Word { text, end } => words.push((text, end)),
            Token::Semicolon(offset) => semicolons.push(offset),
            Token::Placeholder { .. } => {}
        }
    }
    let Some((first, _)) = words.first() else {
        return Err(categorized_error(
            QuerySqlErrorCategory::InvalidArguments,
            "empty query",
        ));
    };
    if allow_explain && first == "explain" {
        return classify_explain_query_plan(profile, sql, &words, &semicolons, allowance);
    }
    if !matches!(first.as_str(), "select" | "with") {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("read-only statement must start with SELECT or WITH, got '{first}'"),
        ));
    }
    // `replace` is absent on purpose: it is both the `REPLACE INTO` write
    // and the portable `replace()` string function. The write is rejected
    // by `reject_bare_replace` below; the call form is admitted by the
    // portable function check.
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
    if let Some((word, _)) = words
        .iter()
        .find(|(word, _)| FORBIDDEN.contains(&word.as_str()))
    {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("read-only statement contains prohibited token '{word}'"),
        ));
    }
    reject_bare_replace(profile, sql, &words)?;
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
    let statement = statement.trim();
    if allowance == FunctionAllowance::Portable {
        validate_portable_calls(profile, statement)?;
    }
    Ok(statement.to_owned())
}

/// Admit `EXPLAIN QUERY PLAN <statement>` only. The explained statement is
/// re-classified without `EXPLAIN` so nesting (`EXPLAIN QUERY PLAN EXPLAIN
/// ...`) and non-read explained statements stay rejected exactly as if they
/// had been submitted alone.
fn classify_explain_query_plan(
    profile: QuerySqlProfile,
    sql: &str,
    words: &[(String, usize)],
    semicolons: &[usize],
    allowance: FunctionAllowance,
) -> Result<String> {
    let is_query_plan = words.get(1).is_some_and(|(word, _)| word == "query")
        && words.get(2).is_some_and(|(word, _)| word == "plan");
    if !is_query_plan {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "EXPLAIN without QUERY PLAN is not admitted; use EXPLAIN QUERY PLAN over a SELECT or WITH statement",
        ));
    }
    let plan_end = words[2].1;
    if semicolons.iter().any(|offset| *offset < plan_end) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "a single statement only",
        ));
    }
    let inner = classify_single_read_statement_impl(profile, &sql[plan_end..], false, allowance)?;
    Ok(format!("EXPLAIN QUERY PLAN {inner}"))
}

enum Token {
    Word {
        text: String,
        end: usize,
    },
    Semicolon(usize),
    /// An admitted `?N` placeholder: byte span of the `?` plus its digits.
    Placeholder {
        start: usize,
        end: usize,
    },
}

/// I1b (E1 M2): rewrite caller `?N` placeholders to Postgres `$N`.
///
/// `statement` must already be classified (notably under
/// `QuerySqlProfile::PostgresServer` for Postgres callers), so every `?`
/// in code is an admitted `?N`. The spans come from `scan_tokens`, the same
/// scanner that admitted the statement, so `?N` inside string literals,
/// comments, quoted identifiers and dollar-quoted strings is untouched by
/// construction. Run this before `pg_query` parse; the exact-`$n`-set check
/// then runs on the rewritten text.
///
/// The classify-first precondition is asserted in debug builds: production
/// always classifies before rewriting, and an unclassified input (e.g. a
/// bare comment) must surface there, not here.
pub fn rewrite_placeholders_for_postgres(
    profile: QuerySqlProfile,
    statement: &str,
) -> Result<String> {
    debug_assert!(
        classify_single_read_statement(profile, statement).is_ok(),
        "rewrite_placeholders_for_postgres expects a classified statement"
    );
    let mut rewritten = String::with_capacity(statement.len());
    let mut cursor = 0;
    for token in scan_tokens(profile, statement)? {
        if let Token::Placeholder { start, end } = token {
            rewritten.push_str(&statement[cursor..start]);
            rewritten.push('$');
            rewritten.push_str(&statement[start + 1..end]);
            cursor = end;
        }
    }
    rewritten.push_str(&statement[cursor..]);
    Ok(rewritten)
}

/// I1 review: the exact-set check every engine applies once the parameter
/// count is visible. The classifier admits `?N` without a count; the
/// executor requires the `?N` set to be exactly `1..=parameters.len()`, so
/// `?2` with one parameter fails here instead of binding a silent NULL
/// (SQLite) or a positionally shifted value (Turso). Postgres enforces the
/// equivalent rule on the rewritten `$n` set with its own message.
pub fn check_positional_arguments(
    profile: QuerySqlProfile,
    statement: &str,
    parameters_len: usize,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for token in scan_tokens(profile, statement)? {
        if let Token::Placeholder { start, end } = token {
            seen.insert(
                statement[start + 1..end]
                    .parse::<usize>()
                    .unwrap_or(usize::MAX),
            );
        }
    }
    let expected: BTreeSet<usize> = (1..=parameters_len).collect();
    if seen != expected {
        return Err(categorized_error(
            QuerySqlErrorCategory::InvalidArguments,
            "ordered parameters and `?N` placeholders must match exactly",
        ));
    }
    Ok(())
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
                // I1 review: `$` continues a Postgres identifier
                // (`a$tag$`), so it opens a dollar-quoted string only
                // when the preceding byte cannot be part of one.
                // Otherwise a phantom string could hide statement
                // structure (e.g. the `;` in `a$tag$; DELETE …`).
                let ident_prev = i > 0
                    && matches!(
                        bytes[i - 1],
                        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$'
                    );
                if !ident_prev {
                    if let Some((delimiter, after)) = dollar_delimiter(sql, i) {
                        let rest = &sql[after..];
                        let Some(end) = rest.find(&delimiter) else {
                            return syntax_error("unterminated dollar-quoted string");
                        };
                        i = after + end + delimiter.len();
                        continue;
                    }
                }
                i = placeholder_end(bytes, i)?;
            }
            b'?' => {
                let start = i;
                i = placeholder_end(bytes, i)?;
                tokens.push(Token::Placeholder { start, end: i });
            }
            b':' | b'@' | b'$' => {
                i = placeholder_end(bytes, i)?;
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
                tokens.push(Token::Word {
                    text: sql[start..i].to_ascii_lowercase(),
                    end: i,
                });
            }
            _ => i += 1,
        }
    }
    Ok(tokens)
}

/// I1 (E1 M2 portability validator): one placeholder syntax (`?N`) across
/// engines. `scan_tokens` routes every `?`, `:`, `@` and `$` that is not
/// inside a string literal, comment, quoted identifier or (on Postgres)
/// dollar-quoted string here. `?N` with N >= 1 is admitted; `$N`, bare `?`
/// (including `?0`), `:name`, `@name` and `$name` are rejected with the
/// portable repair. `::` is the cast operator, not a placeholder, and `[1:2]`
/// slice colons are left for the engine parsers. Contiguity against the
/// parameter count stays with the engines, which see the count.
fn placeholder_end(bytes: &[u8], start: usize) -> Result<usize> {
    const REPAIR: &str = "use positional `?N` placeholders (1-based, contiguous); Postgres `$n` is not accepted from callers";
    let found = |end: usize| {
        let end = end.min(start + 16);
        String::from_utf8_lossy(&bytes[start..end]).into_owned()
    };
    let reject = |end: usize| {
        Err(categorized_error(
            QuerySqlErrorCategory::InvalidArguments,
            format!("non-portable placeholder `{}` — {REPAIR}", found(end)),
        ))
    };
    let is_ident_start =
        |byte: Option<&u8>| byte.is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_');
    let mut end = start + 1;
    match bytes[start] {
        b'?' => {
            while bytes.get(end).is_some_and(|byte| byte.is_ascii_digit()) {
                end += 1;
            }
            if end == start + 1 {
                // I1 review: a bare `?` is not a placeholder claim —
                // Postgres `?`/`?|`/`?&` are jsonb operators, and none
                // of them are in the portable profile.
                return Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "`?` is not admitted: placeholders are positional `?N`, and Postgres `?`/`?|`/`?&` operators are not in the portable profile.",
                ));
            }
            if bytes[start + 1] == b'0' {
                return reject(end);
            }
            // I1 review: bound N even though the classifier cannot see
            // the parameter count; `?4294967297` truncated to int32
            // downstream. Equal-length digit strings compare numerically.
            let max = MAX_PARAMETERS.to_string();
            let digits = String::from_utf8_lossy(&bytes[start + 1..end]);
            if digits.len() > max.len()
                || (digits.len() == max.len() && digits.as_ref() > max.as_str())
            {
                return Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    format!(
                        "non-portable placeholder `{}` — placeholder numbers must not exceed {MAX_PARAMETERS}",
                        found(end)
                    ),
                ));
            }
            Ok(end)
        }
        b':' => {
            if bytes.get(start + 1) == Some(&b':') {
                return Ok(start + 2);
            }
            if is_ident_start(bytes.get(start + 1)) {
                end += 1;
                while bytes
                    .get(end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    end += 1;
                }
                return reject(end);
            }
            Ok(start + 1)
        }
        b'@' => {
            if bytes
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                while bytes
                    .get(end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    end += 1;
                }
                return reject(end);
            }
            Ok(start + 1)
        }
        b'$' => {
            if bytes.get(end).is_some_and(|byte| byte.is_ascii_digit()) {
                while bytes.get(end).is_some_and(|byte| byte.is_ascii_digit()) {
                    end += 1;
                }
                return reject(end);
            }
            if is_ident_start(bytes.get(end)) {
                end += 1;
                while bytes
                    .get(end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    end += 1;
                }
                return reject(end);
            }
            Ok(start + 1)
        }
        _ => Ok(start + 1),
    }
}

/// I2 (E1 M2 portability validator): the portable function subset. One
/// table feeds every engine, so a rejection names the same replacement on
/// SQLite, Turso and Postgres. `like` is intentionally absent: it is an
/// operator on Postgres (`~~`) and a function-form entry at the engines'
/// own call sites. `round` is admitted with one argument only; two or more
/// arguments are rejected by the arity check in `validate_portable_calls`.
pub const PORTABLE_FUNCTIONS: &[&str] = &[
    "abs",
    "avg",
    "coalesce",
    "count",
    "cume_dist",
    "dense_rank",
    "length",
    "lower",
    "max",
    "min",
    "ntile",
    "nullif",
    "percent_rank",
    "rank",
    "replace",
    "round",
    "row_number",
    "substr",
    "sum",
    "trim",
    "upper",
];

/// True for the intersection every engine executes. The SQLite and Turso
/// call sites additionally admit `like`, whose Postgres spelling is the
/// `~~` operator family rather than a function call.
pub fn is_portable_function(name: &str) -> bool {
    PORTABLE_FUNCTIONS
        .iter()
        .any(|safe| name.eq_ignore_ascii_case(safe))
}

const M1_TIMESTAMP_REPAIR: &str =
    "use the M1 timestamp columns (e.g. created_at and created_at_ms)";
const JSON_REPAIR: &str = "use the owned relations (e.g. facet_values, facet_observations)";
const FLOOR_CEIL_REPAIR: &str = "unavailable on the portable profile — use CAST(x AS INTEGER) for truncation toward zero (it truncates rather than floors negatives) or compute client-side";

/// I2: dropped functions and their portable replacements. `json_*` is
/// covered by the prefix rule in `portable_function_repair`, so only the
/// named forms that deserve a distinct mention are listed.
const DROPPED_FUNCTION_REPAIRS: &[(&str, &str)] = &[
    // I4 will add the case-insensitivity claim when it is true on
    // Postgres; until then the repair names no semantics.
    ("instr", "use substr() or LIKE"),
    ("glob", "use LIKE"),
    ("date", M1_TIMESTAMP_REPAIR),
    ("datetime", M1_TIMESTAMP_REPAIR),
    ("julianday", M1_TIMESTAMP_REPAIR),
    ("strftime", M1_TIMESTAMP_REPAIR),
    ("time", M1_TIMESTAMP_REPAIR),
    ("unixepoch", M1_TIMESTAMP_REPAIR),
    ("json_array_length", JSON_REPAIR),
    ("json_type", JSON_REPAIR),
    ("json_valid", JSON_REPAIR),
    ("json_group_array", JSON_REPAIR),
    // N2 residual (re-review): bare `json()` is SQLite's JSON parse, not
    // covered by the `json_` prefix rule, so it names the repair directly.
    ("json", JSON_REPAIR),
    ("typeof", "use the catalog column types"),
    (
        "group_concat",
        "aggregate client-side instead of GROUP_CONCAT",
    ),
    ("total", "use sum (note: sum returns NULL on empty input where total returns 0.0 — use coalesce(sum(x), 0))"),
    // substr(x, 1, 1) returns a character, not a code point, so it
    // would be a misleading replacement.
    ("unicode", "no portable equivalent — compute client-side"),
    ("substring", "use substr"),
    ("floor", FLOOR_CEIL_REPAIR),
    ("ceil", FLOOR_CEIL_REPAIR),
    ("ceiling", FLOOR_CEIL_REPAIR),
    ("char_length", "use length"),
    ("character_length", "use length"),
    (
        "octet_length",
        "use length() for character length; byte length has no portable equivalent",
    ),
    ("greatest", "use a CASE expression"),
    ("least", "use a CASE expression"),
];

/// The portable repair for a lowercased function name, if the function is
/// dropped from the portable profile. Any other `json_*` spelling falls
/// under the same repair via the prefix rule.
pub fn portable_function_repair(lower_name: &str) -> Option<&'static str> {
    DROPPED_FUNCTION_REPAIRS
        .iter()
        .find(|(dropped, _)| *dropped == lower_name)
        .map(|(_, repair)| *repair)
        .or_else(|| lower_name.starts_with("json_").then_some(JSON_REPAIR))
}

/// The identical rejection detail every engine reports for a dropped
/// function: `function '<name>' is unavailable — <repair>`, with the name
/// lowercased so caller casing cannot fork the message. Engines wrap it
/// with `QuerySqlErrorCategory::UnsafeStatement`, matching the classifier.
pub fn unavailable_function_detail(found_name: &str) -> Option<String> {
    let lower = found_name.to_ascii_lowercase();
    portable_function_repair(&lower)
        .map(|repair| format!("function '{lower}' is unavailable — {repair}"))
}

/// I2: enforce the portable function subset on a classified statement.
/// Every `word(` outside strings, comments and quoted identifiers is a
/// call: dropped names are rejected with their portable replacement, and
/// `round` with two or more arguments is rejected with the numeric repair.
/// Anything else (admitted names, unknown names, keywords like `CAST (`)
/// is left for the engines, which keep their own allowlists as defence in
/// depth. `::` casts and `[1:2]`-style colons never reach here as calls.
fn validate_portable_calls(profile: QuerySqlProfile, statement: &str) -> Result<()> {
    let bytes = statement.as_bytes();
    let nested = profile == QuerySqlProfile::PostgresServer;
    // N1 (re-review): one linear paren pre-pass. Per-call rescans here were
    // quadratic on nested input; every exemption/arity check below is now an
    // O(1) index lookup, keeping the whole classifier linear.
    let index = build_paren_index(statement, bytes, nested)?;
    let mut i = 0;
    // N2 (re-review): whether the previous significant token is the word
    // `AS`, so `AS name(` (a table-alias column list) is exempt like a CTE
    // definition. Comments and whitespace leave it; every other token sets
    // it. A genuine call is never directly preceded by `AS`.
    let mut prev_is_as = false;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = block_comment_end(bytes, i, nested)?;
            }
            b'e' | b'E' if nested && bytes.get(i + 1) == Some(&b'\'') => {
                prev_is_as = false;
                i = quoted_end(bytes, i + 1, b'\'', true)?;
            }
            b'\'' => {
                prev_is_as = false;
                i = quoted_end(bytes, i, b'\'', false)?;
            }
            // I2 review: a quoted/bracketed identifier immediately followed
            // by `(` is a call too (`SELECT "round"(1.5, 2)`), so the
            // dropped-name and round-arity checks run on it. A bare CTE
            // definition (`WITH instr(a) AS (...)`, quoted or not) is not
            // a call and stays admitted.
            b'"' => {
                let end = quoted_end(bytes, i, b'"', false)?;
                let j = skip_ws_and_comments(bytes, end, nested)?;
                if bytes.get(j) == Some(&b'(')
                    && !prev_is_as
                    && !is_cte_column_list(bytes, j, nested, &index)?
                {
                    check_call(&unquote_doubled(&statement[i + 1..end - 1], '"'), j, &index)?;
                }
                prev_is_as = false;
                i = end;
            }
            b'`' if !nested => {
                let end = quoted_end(bytes, i, b'`', false)?;
                let j = skip_ws_and_comments(bytes, end, nested)?;
                if bytes.get(j) == Some(&b'(')
                    && !prev_is_as
                    && !is_cte_column_list(bytes, j, nested, &index)?
                {
                    check_call(&unquote_doubled(&statement[i + 1..end - 1], '`'), j, &index)?;
                }
                prev_is_as = false;
                i = end;
            }
            b'[' if !nested => {
                let end = bracket_identifier_end(bytes, i)?;
                let j = skip_ws_and_comments(bytes, end, nested)?;
                if bytes.get(j) == Some(&b'(')
                    && !prev_is_as
                    && !is_cte_column_list(bytes, j, nested, &index)?
                {
                    check_call(&statement[i + 1..end - 1], j, &index)?;
                }
                prev_is_as = false;
                i = end;
            }
            b'$' if nested => {
                prev_is_as = false;
                if let Some((delimiter, after)) = dollar_delimiter(statement, i) {
                    let rest = &statement[after..];
                    let Some(end) = rest.find(&delimiter) else {
                        return syntax_error("unterminated dollar-quoted string");
                    };
                    i = after + end + delimiter.len();
                } else {
                    i += 1;
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = &statement[start..i];
                let j = skip_ws_and_comments(bytes, i, nested)?;
                if bytes.get(j) == Some(&b'(')
                    && !prev_is_as
                    && !is_cte_column_list(bytes, j, nested, &index)?
                {
                    check_call(name, j, &index)?;
                }
                prev_is_as = name.eq_ignore_ascii_case("as");
            }
            _ => {
                // Whitespace leaves `prev_is_as` (`AS "instr"(` is still
                // an alias); any other single byte ends the adjacency.
                if !bytes[i].is_ascii_whitespace() {
                    prev_is_as = false;
                }
                i += 1;
            }
        }
    }
    Ok(())
}

fn skip_ws_and_comments(bytes: &[u8], mut j: usize, nested: bool) -> Result<usize> {
    loop {
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if bytes.get(j) == Some(&b'-') && bytes.get(j + 1) == Some(&b'-') {
            j += 2;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
        } else if bytes.get(j) == Some(&b'/') && bytes.get(j + 1) == Some(&b'*') {
            j = block_comment_end(bytes, j, nested)?;
        } else {
            return Ok(j);
        }
    }
}

/// Check one `name(` call found in code. Dropped names report their
/// portable replacement; `round` with a top-level comma takes the numeric
/// repair; everything else belongs to the engines.
fn check_call(name: &str, paren: usize, index: &ParenIndex) -> Result<()> {
    let lower = name.to_ascii_lowercase();
    if lower == "round" {
        return check_round_arity(paren, index);
    }
    if let Some(detail) = unavailable_function_detail(name) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            detail,
        ));
    }
    Ok(())
}

/// `name(` is a CTE column list rather than a call when the parenthesised
/// group is followed by `AS (` (optionally via `MATERIALIZED` / `NOT
/// MATERIALIZED`): `WITH instr(a) AS (SELECT ...)`. A genuine call alias
/// (`SELECT instr(x) AS y`) never has a parenthesised target, so skipping
/// exactly this shape cannot hide a call.
fn is_cte_column_list(
    bytes: &[u8],
    paren: usize,
    nested: bool,
    index: &ParenIndex,
) -> Result<bool> {
    let Some(close) = index.close.get(&paren) else {
        // Unbalanced tail: left for the engines to syntax-error.
        return Ok(false);
    };
    let mut j = skip_ws_and_comments(bytes, close + 1, nested)?;
    let (word, end) = read_word(bytes, j);
    if word != "as" {
        return Ok(false);
    }
    j = skip_ws_and_comments(bytes, end, nested)?;
    let (word, end) = read_word(bytes, j);
    j = if word == "materialized" {
        skip_ws_and_comments(bytes, end, nested)?
    } else if word == "not" {
        let k = skip_ws_and_comments(bytes, end, nested)?;
        let (next, next_end) = read_word(bytes, k);
        if next != "materialized" {
            return Ok(false);
        }
        skip_ws_and_comments(bytes, next_end, nested)?
    } else {
        j
    };
    Ok(bytes.get(j) == Some(&b'('))
}

/// Paren-match index from one linear pre-pass over a statement: every
/// `(` in code maps to its matching `)`, and every `(` whose level
/// directly contains a top-level comma is flagged. Exemption and arity
/// checks consult it in O(1), keeping `validate_portable_calls` linear.
/// Unbalanced parens map to nothing; the engines syntax-error those.
struct ParenIndex {
    close: HashMap<usize, usize>,
    top_comma: HashSet<usize>,
}

/// One linear scan with the same literal/comment skipping as the
/// classifiers (Postgres nesting, dollar quotes and `E''` when `nested`).
fn build_paren_index(statement: &str, bytes: &[u8], nested: bool) -> Result<ParenIndex> {
    let mut index = ParenIndex {
        close: HashMap::new(),
        top_comma: HashSet::new(),
    };
    let mut open: Vec<usize> = Vec::new();
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
                i = block_comment_end(bytes, i, nested)?;
            }
            b'e' | b'E' if nested && bytes.get(i + 1) == Some(&b'\'') => {
                i = quoted_end(bytes, i + 1, b'\'', true)?;
            }
            b'\'' | b'"' => {
                i = quoted_end(bytes, i, bytes[i], false)?;
            }
            b'`' if !nested => {
                i = quoted_end(bytes, i, b'`', false)?;
            }
            b'[' if !nested => {
                i = bracket_identifier_end(bytes, i)?;
            }
            b'$' if nested => {
                if let Some((delimiter, after)) = dollar_delimiter(statement, i) {
                    let rest = &statement[after..];
                    let Some(end) = rest.find(&delimiter) else {
                        return syntax_error("unterminated dollar-quoted string");
                    };
                    i = after + end + delimiter.len();
                } else {
                    i += 1;
                }
            }
            b'(' => {
                open.push(i);
                i += 1;
            }
            b')' => {
                if let Some(start) = open.pop() {
                    index.close.insert(start, i);
                }
                i += 1;
            }
            b',' => {
                if let Some(top) = open.last() {
                    index.top_comma.insert(*top);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(index)
}

/// Lowercased word (`[A-Za-z_][A-Za-z0-9_]*`) at `j`, or empty when `j` is
/// not at a word. The second element is the byte offset past the word.
fn read_word(bytes: &[u8], j: usize) -> (String, usize) {
    if !bytes
        .get(j)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return (String::new(), j);
    }
    let mut end = j + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    (
        String::from_utf8_lossy(&bytes[j..end]).to_ascii_lowercase(),
        end,
    )
}

/// Undo `""`-style doubling inside a quoted identifier (`"a""b"` names
/// `a"b`). Only exact names reach the checks, so anything exotic stays
/// admitted here and fails closed at the engines.
fn unquote_doubled(inner: &str, quote: char) -> String {
    let doubled: String = [quote, quote].iter().collect();
    inner.replace(&doubled, &quote.to_string())
}

/// `round` admits one argument; two or more name the numeric repair. The
/// answer comes from the linear pre-pass index: a top-level comma flag on
/// the call's own level. An unbalanced tail (no index entry) is left for
/// the engines to syntax-error.
fn check_round_arity(paren: usize, index: &ParenIndex) -> Result<()> {
    const REPAIR: &str =
        "two-argument round is not portable — CAST the value to the catalog numeric type first";
    if !index.close.contains_key(&paren) {
        return Ok(());
    }
    if index.top_comma.contains(&paren) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            REPAIR,
        ));
    }
    Ok(())
}

/// I2: `REPLACE` is both the `REPLACE INTO` / `INSERT OR REPLACE` write
/// and the portable `replace()` string function. Only the write positions
/// are rejected: a leading `REPLACE` (never reached — the statement must
/// start with SELECT or WITH), `REPLACE INTO`, and `INSERT OR REPLACE`.
/// Anywhere else (`SELECT 1 AS replace`, a column named `replace`) the
/// word is data, and the call form `replace(` is admitted by the portable
/// function check.
fn reject_bare_replace(
    profile: QuerySqlProfile,
    sql: &str,
    words: &[(String, usize)],
) -> Result<()> {
    let bytes = sql.as_bytes();
    let nested = profile == QuerySqlProfile::PostgresServer;
    for (index, (word, end)) in words.iter().enumerate() {
        if word != "replace" {
            continue;
        }
        let after = skip_ws_and_comments(bytes, *end, nested)?;
        if bytes.get(after) == Some(&b'(') {
            continue;
        }
        let prev = index.checked_sub(1).and_then(|i| words.get(i));
        let prev_prev = index.checked_sub(2).and_then(|i| words.get(i));
        let next = words.get(index + 1);
        let is_write = index == 0
            || next.is_some_and(|(next, _)| next == "into")
            || (prev.is_some_and(|(prev, _)| prev == "or")
                && prev_prev.is_some_and(|(prev_prev, _)| prev_prev == "insert"));
        if is_write {
            return Err(categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "read-only statement contains prohibited token 'replace'",
            ));
        }
    }
    Ok(())
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
            // I1: `$name` is no longer admitted (see
            // `placeholders_use_positional_syntax_only`).
            "SELECT id FROM records WHERE id = ?1",
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
    fn oversized_exclusion_hint_bounds_the_id_list() {
        assert!(oversized_exclusion_hint(&[]).is_none());
        let hint = oversized_exclusion_hint(&[("records", "abc123")]).expect("hint with ids");
        assert!(
            hint.contains("WHERE records.id NOT IN ('abc123')"),
            "{hint}"
        );
        assert!(!hint.contains("first 10"), "{hint}");
        assert!(hint.contains("alias"), "{hint}");
        // One clause per relation, qualified so a join stays unambiguous.
        let mixed = oversized_exclusion_hint(&[
            ("records", "r1"),
            ("links", "l1"),
            ("records", "r1"),
            ("links", "l2"),
        ])
        .expect("grouped hint");
        assert!(
            mixed.contains("records.id NOT IN ('r1') AND links.id NOT IN ('l1', 'l2')"),
            "{mixed}"
        );
        assert!(!mixed.contains("WHERE id NOT IN"), "{mixed}");
        let ids: Vec<String> = (0..12).map(|index| format!("id{index:02}")).collect();
        let refs: Vec<(&str, &str)> = ids.iter().map(|id| ("records", id.as_str())).collect();
        let bounded = oversized_exclusion_hint(&refs).expect("bounded hint");
        assert!(
            bounded.contains("first 10 of 12 oversized rows"),
            "{bounded}"
        );
        assert!(!bounded.contains("id11"), "{bounded}");
        let quoted = oversized_exclusion_hint(&[("records", "o'brien")]).expect("quoted hint");
        assert!(quoted.contains("'o''brien'"), "{quoted}");
    }

    #[test]
    fn deadline_hint_names_the_cause_and_the_repair() {
        let hint = deadline_hint();
        assert!(hint.contains("2000ms"), "{hint}");
        assert!(hint.contains("probing it by id"), "{hint}");
        assert!(hint.contains("LIMIT with ORDER BY"), "{hint}");
    }

    #[test]
    fn truncation_hint_names_the_bound_and_the_keyset_repair() {
        assert!(truncation_hint_for(false).is_none());
        let hint = truncation_hint_for(true).expect("hint when truncated");
        assert!(hint.contains("1000"), "{hint}");
        assert!(hint.contains("ORDER BY"), "{hint}");
        assert!(hint.contains("keyset"), "{hint}");
        assert!(hint.contains("WHERE key > ?N"), "{hint}");
    }

    #[test]
    fn blocked_relation_repair_names_the_fix() {
        use QuerySqlProfile::{PostgresServer, SqliteLocal};
        let probe = blocked_relation_repair("sqlite_master", SqliteLocal).expect("probe repair");
        assert!(probe.contains("catalog introspection"), "{probe}");
        assert!(probe.contains("FROM catalog_columns"), "{probe}");
        let pragma =
            blocked_relation_repair("pragma_table_info", SqliteLocal).expect("pragma repair");
        assert!(pragma.contains("catalog introspection"), "{pragma}");
        let mapped = blocked_relation_repair("relationships", SqliteLocal).expect("mapped repair");
        assert!(mapped.contains("effective_relationships"), "{mapped}");
        let unmapped =
            blocked_relation_repair("member_contexts", SqliteLocal).expect("list repair");
        assert!(
            unmapped.contains("records, content_events, links"),
            "{unmapped}"
        );
        // Profile filtering: Postgres cannot query the sqlite-only
        // relations, so the map falls through to the filtered list.
        let pg_mapped =
            blocked_relation_repair("relationships", PostgresServer).expect("pg fallback repair");
        assert!(
            !pg_mapped.contains("effective_relationships"),
            "{pg_mapped}"
        );
        assert!(pg_mapped.contains("on postgres-server"), "{pg_mapped}");
        let pg_list =
            blocked_relation_repair("member_contexts", PostgresServer).expect("pg list repair");
        assert!(!pg_list.contains("agent_activity"), "{pg_list}");
        assert!(pg_list.contains("catalog_columns"), "{pg_list}");
        assert!(blocked_relation_repair("records", SqliteLocal).is_none());
        assert!(blocked_relation_repair("RECORDS", SqliteLocal).is_none());
        assert!(blocked_relation_repair("", SqliteLocal).is_none());
    }

    #[test]
    fn catalog_views_cover_every_relation_and_column() {
        for relation in LOGICAL_RELATIONS {
            assert!(
                RELATION_COMMENTS
                    .iter()
                    .any(|(name, _)| *name == relation.name),
                "no catalog comment for {}",
                relation.name
            );
        }
        for (name, _) in RELATION_COMMENTS {
            assert!(
                LOGICAL_RELATIONS
                    .iter()
                    .any(|relation| relation.name == *name),
                "stale catalog comment for removed relation {name}"
            );
        }
        let relation_rows = catalog_relation_rows();
        assert_eq!(relation_rows.len(), LOGICAL_RELATIONS.len());
        let column_rows = catalog_column_rows();
        let expected: usize = LOGICAL_RELATIONS.iter().map(|r| r.columns.len()).sum();
        assert_eq!(column_rows.len(), expected);
        // Zero-based, dense positions per relation.
        let mut seen = std::collections::BTreeMap::new();
        for (relation, _, position) in &column_rows {
            assert_eq!(
                *position,
                seen.get(relation).copied().unwrap_or(0),
                "{relation}"
            );
            seen.insert(*relation, position + 1);
        }
        let statements = catalog_view_statements(true);
        assert_eq!(statements.len(), 2);
        for statement in &statements {
            // Installers split the contract batch on semicolons, so a
            // semicolon inside a comment would corrupt every statement
            // after it.
            assert!(!statement.contains(';'), "{statement}");
            assert!(statement.contains("IF NOT EXISTS"), "{statement}");
        }
        let bare = catalog_view_statements(false);
        assert_eq!(bare.len(), 2);
        for statement in &bare {
            assert!(!statement.contains("IF NOT EXISTS"), "{statement}");
        }
        assert_eq!(
            statements[0].matches("UNION ALL").count(),
            relation_rows.len() - 1
        );
        assert_eq!(
            statements[1].matches("UNION ALL").count(),
            column_rows.len() - 1
        );
    }

    #[test]
    fn catalog_card_names_every_relation_and_column() {
        let card = sql_read_catalog_card();
        assert!(
            card.len() <= SQL_READ_CARD_MAX_BYTES,
            "card is {} bytes over the {} budget",
            card.len(),
            SQL_READ_CARD_MAX_BYTES
        );
        // The card renders in descriptor prose, never in a SQL batch,
        // so its notes may use semicolons freely.
        for relation in LOGICAL_RELATIONS {
            let header = format!("{}({})", relation.name, relation.columns.join(","));
            assert!(card.contains(&header), "card omits {}", relation.name);
            assert!(
                CARD_NOTES.iter().any(|(name, _)| *name == relation.name),
                "no card note for {}",
                relation.name
            );
        }
        for (name, _) in CARD_NOTES {
            assert!(
                LOGICAL_RELATIONS
                    .iter()
                    .any(|relation| relation.name == *name),
                "stale card note for removed relation {name}"
            );
        }
        // Profile scope travels with the relation line.
        assert!(card.contains("[only: sqlite-local]"), "{card}");
        for (_, sql) in CARD_WORKED_STATEMENTS {
            assert!(card.contains(sql), "card omits a worked statement");
        }
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
    fn placeholders_use_positional_syntax_only() {
        // I1 (E1 M2): `?N` (1-based) is the only admitted spelling, on
        // every profile. Contiguity against the parameter count stays with
        // the engines, which see the count.
        for sql in [
            "SELECT id FROM records WHERE id = ?1",
            "SELECT id FROM records WHERE id = ?1 AND name = ?2",
            "SELECT id FROM records WHERE id = ?12",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
        // Every other spelling is rejected with the portable repair.
        for sql in [
            "SELECT id FROM records WHERE id = $1",
            "SELECT id FROM records WHERE id = ?0",
            "SELECT id FROM records WHERE id = :name",
            "SELECT id FROM records WHERE id = @name",
            "SELECT id FROM records WHERE id = $name",
            "SELECT id FROM records WHERE id = @1",
        ] {
            for profile in PROFILES {
                let error = classify_single_read_statement(*profile, sql).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("use positional `?N` placeholders"),
                    "{profile:?}: {sql}: missing repair: {error}"
                );
            }
        }
        // Placeholder numbers are bounded even without a parameter
        // count in view: `?4294967297` would truncate to int32
        // downstream.
        for profile in PROFILES {
            let error = classify_single_read_statement(
                *profile,
                "SELECT id FROM records WHERE id = ?4294967297",
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("must not exceed"),
                "{profile:?}: {error}"
            );
        }
        // A bare `?` is not a placeholder claim: it names the jsonb
        // operators as out of profile instead.
        for profile in PROFILES {
            let error =
                classify_single_read_statement(*profile, "SELECT id FROM records WHERE id = ?")
                    .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Postgres `?`/`?|`/`?&` operators"),
                "{profile:?}: {error}"
            );
        }
        // The same spellings inside literals, comments and quoted
        // identifiers are data, not placeholders, and stay admitted.
        for sql in [
            "SELECT '$1' AS value",
            "SELECT ':x' AS value",
            "SELECT id FROM records WHERE name = '$1' AND id = ?1",
            "-- filter $1\nSELECT id FROM records",
            "SELECT /* :name */ id FROM records",
            "SELECT \"$1\" FROM records",
            "SELECT 1::int FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn postgres_rewrite_turns_positional_placeholders_into_dollar_forms() {
        // I1b: `?N` in code becomes `$N`; the same scanner spans that the
        // classifier walked decide what is code, so literals, comments,
        // quoted identifiers and dollar-quotes are untouched. `?10` is one
        // placeholder (number ten), not `?1` followed by `0`.
        for (statement, expected) in [
            (
                "SELECT id FROM records WHERE id = ?1",
                "SELECT id FROM records WHERE id = $1",
            ),
            (
                "SELECT id FROM records WHERE a = ?1 AND b = ?10",
                "SELECT id FROM records WHERE a = $1 AND b = $10",
            ),
            (
                "SELECT id FROM records WHERE name = '?1' AND id = ?1",
                "SELECT id FROM records WHERE name = '?1' AND id = $1",
            ),
            ("SELECT '?1' AS value", "SELECT '?1' AS value"),
            (
                "-- filter ?1\nSELECT id FROM records WHERE id = ?2",
                "-- filter ?1\nSELECT id FROM records WHERE id = $2",
            ),
            (
                "SELECT /* ?1 */ id FROM records WHERE id = ?1",
                "SELECT /* ?1 */ id FROM records WHERE id = $1",
            ),
            (
                "SELECT \"?1\" FROM records WHERE id = ?1",
                "SELECT \"?1\" FROM records WHERE id = $1",
            ),
            (
                "SELECT $tag$?1$tag$ AS body FROM records WHERE id = ?1",
                "SELECT $tag$?1$tag$ AS body FROM records WHERE id = $1",
            ),
            (
                "SELECT 1::int FROM records WHERE id = ?1",
                "SELECT 1::int FROM records WHERE id = $1",
            ),
        ] {
            assert_eq!(
                rewrite_placeholders_for_postgres(QuerySqlProfile::PostgresServer, statement)
                    .unwrap(),
                expected,
                "{statement}"
            );
        }
    }

    #[test]
    fn positional_arguments_require_the_exact_set() {
        // I1 review: once the count is visible, `?N` must be exactly
        // `1..=len` — on every profile, since the helper takes one.
        for profile in PROFILES {
            check_positional_arguments(*profile, "SELECT 1", 0).unwrap();
            check_positional_arguments(*profile, "SELECT id FROM records WHERE id = ?1", 1)
                .unwrap();
            check_positional_arguments(
                *profile,
                "SELECT id FROM records WHERE a = ?1 AND b = ?2",
                2,
            )
            .unwrap();
            for (sql, len) in [
                ("SELECT id FROM records WHERE id = ?2", 1),
                ("SELECT id FROM records WHERE a = ?1 AND b = ?3", 2),
                ("SELECT id FROM records WHERE id = ?1", 0),
                ("SELECT id FROM records WHERE id = ?1", 2),
            ] {
                let error = check_positional_arguments(*profile, sql, len).unwrap_err();
                assert!(
                    error.to_string().contains("must match exactly"),
                    "{profile:?}: {sql}/{len}: {error}"
                );
            }
        }
    }

    #[test]
    fn dollar_quotes_do_not_open_inside_identifiers() {
        // I1 review: on Postgres `$` continues an identifier, so
        // `a$tag$` must not open a dollar-quoted string that hides a
        // `?1` from the rewrite or a `;` from the single-statement
        // check. Every profile rejects both inputs.
        for sql in [
            "SELECT a$tag$?1 xyz$tag$ FROM records",
            "SELECT 1 a$tag$; DELETE FROM records$tag$",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_err(),
                    "{profile:?}: unexpectedly admitted {sql}"
                );
            }
        }
    }

    #[test]
    fn every_profile_advertises_positional_placeholders() {
        // I1 review: callers send `?N` on every profile; the Postgres
        // `$N` form is the execution rewrite, never caller syntax.
        for profile in PROFILES {
            assert_eq!(profile.contract().placeholder, "?1", "{profile:?}");
        }
    }

    #[test]
    fn dropped_functions_name_their_portable_replacement() {
        // I2: every profile rejects the same way with the same message.
        for (sql, repair) in [
            (
                "SELECT instr(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
            ("SELECT glob('*', name) FROM records", "use LIKE"),
            (
                "SELECT date(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT datetime(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT julianday(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT strftime('%Y', created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT time(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT unixepoch(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT json_type(body) FROM records",
                "facet_values, facet_observations",
            ),
            (
                "SELECT json_extract(body, '$.a') FROM records",
                "facet_values, facet_observations",
            ),
            (
                "SELECT json_group_array(name) FROM records",
                "facet_values, facet_observations",
            ),
            (
                "SELECT json(body) FROM records",
                "facet_values, facet_observations",
            ),
            ("SELECT typeof(name) FROM records", "catalog column types"),
            (
                "SELECT group_concat(name) FROM records",
                "aggregate client-side",
            ),
            ("SELECT total(id) FROM records", "use sum"),
            (
                "SELECT unicode(name) FROM records",
                "no portable equivalent",
            ),
            ("SELECT substring(name, 1, 2) FROM records", "use substr"),
            ("SELECT floor(value) FROM records", "CAST(x AS INTEGER)"),
            ("SELECT ceil(value) FROM records", "CAST(x AS INTEGER)"),
            ("SELECT ceiling(value) FROM records", "CAST(x AS INTEGER)"),
            ("SELECT char_length(name) FROM records", "use length"),
            ("SELECT character_length(name) FROM records", "use length"),
            ("SELECT octet_length(name) FROM records", "character length"),
            ("SELECT greatest(a, b) FROM records", "CASE"),
            ("SELECT least(a, b) FROM records", "CASE"),
            (
                "SELECT round(avg(value), 2) FROM records",
                "catalog numeric type",
            ),
        ] {
            for profile in PROFILES {
                let error = classify_single_read_statement(*profile, sql).unwrap_err();
                let rendered = error.to_string();
                assert!(
                    rendered.contains(repair),
                    "{profile:?}: {sql}: missing repair: {rendered}"
                );
            }
        }
        // Case-insensitive names report the lowercased repair, and calls
        // hidden in literals, comments and quoted identifiers stay admitted.
        for profile in PROFILES {
            let error =
                classify_single_read_statement(*profile, "SELECT INSTR(body, 'x') FROM records")
                    .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("function 'instr' is unavailable"),
                "{profile:?}: {error}"
            );
            for sql in [
                "SELECT 'instr(' AS value FROM records",
                "SELECT /* glob(*) */ id FROM records",
                "-- typeof(name)\nSELECT id FROM records",
                "SELECT \"instr\" FROM records",
            ] {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn widened_functions_are_admitted_on_every_profile() {
        // I2 intersection: scalar/string, aggregates, window, plus 1-arg
        // round. CASE/CAST coverage lives with the engine suites.
        for sql in [
            "SELECT lower(name), upper(name) FROM records",
            "SELECT trim(name), replace(name, 'a', 'b') FROM records",
            "SELECT substr(name, 1, 2) FROM records",
            "SELECT coalesce(name, 'z'), nullif(name, 'z') FROM records",
            "SELECT abs(id), length(name), round(1.5) FROM records",
            "SELECT avg(id), count(*), sum(id), min(id), max(id) FROM records",
            "SELECT rank() OVER (ORDER BY id) FROM records",
            "SELECT row_number() OVER (ORDER BY id) FROM records",
            "SELECT dense_rank() OVER (ORDER BY id) FROM records",
            "SELECT id FROM records WHERE name LIKE 'conf:%'",
            "SELECT CASE WHEN id = 1 THEN 'one' ELSE 'other' END FROM records",
            "SELECT CAST(id AS TEXT) FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn quoted_calls_face_the_same_dropped_name_and_arity_checks() {
        // I2 review: quoting the name (`"round"`, `` `round` ``,
        // `[round]`) must not bypass the dropped-name or round-arity
        // checks. Whitespace and comments between the name and `(` still
        // form a call.
        for sql in [
            "SELECT \"round\"(1.5, 2) FROM records",
            "SELECT \"round\" /* c */ (1.5, 2) FROM records",
            "SELECT round(\"round\"(a, 2)) FROM records",
            "SELECT \"instr\"(x, y) FROM records",
            "SELECT \"ROUND\"(1.5, 2) FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_err(),
                    "{profile:?}: unexpectedly admitted {sql}"
                );
            }
        }
        let error = classify_single_read_statement(
            QuerySqlProfile::SqliteLocal,
            "SELECT \"instr\"(x, y) FROM records",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("use substr() or LIKE"), "{error}");
        let error = classify_single_read_statement(
            QuerySqlProfile::SqliteLocal,
            "SELECT \"round\"(1.5, 2) FROM records",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("catalog numeric type"), "{error}");
        // Backtick and bracket spellings are not identifiers on Postgres
        // (they fail closed at the pg parser instead), so they are only
        // checked on the SQLite-family profiles.
        for sql in [
            "SELECT `round`(1.5, 2) FROM records",
            "SELECT [round](1.5, 2) FROM records",
            "SELECT `instr`(x, y) FROM records",
            "SELECT [instr](x, y) FROM records",
        ] {
            for profile in [QuerySqlProfile::SqliteLocal, QuerySqlProfile::TursoLocal] {
                assert!(
                    classify_single_read_statement(profile, sql).is_err(),
                    "{profile:?}: unexpectedly admitted {sql}"
                );
            }
        }
        // Quoted names without a call stay admitted, as do one-argument
        // quoted `round` and the widened quoted spellings.
        for sql in [
            "SELECT \"round\"(1.5) FROM records",
            "SELECT \"lower\"(name) FROM records",
            "SELECT \"instr\" FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}: unexpectedly rejected"
                );
            }
        }
    }

    #[test]
    fn deeply_nested_calls_classify_in_linear_time() {
        // N1 (re-review): per-call paren rescans were quadratic (2.2–2.6 s
        // at the 64 KiB cap; the linear pre-pass measures 51–65 ms there).
        // The 1 s bound catches the regression without flaking on a loaded
        // CI runner.
        use std::time::Instant;
        let depth = 20_000;
        let mut sql = String::from("SELECT ");
        for _ in 0..depth {
            sql.push_str("a(");
        }
        sql.push('1');
        for _ in 0..depth {
            sql.push(')');
        }
        sql.push_str(" FROM records");
        assert!(sql.len() < MAX_SQL_BYTES, "{}", sql.len());
        for profile in PROFILES {
            let start = Instant::now();
            let outcome = classify_single_read_statement(*profile, &sql);
            let elapsed = start.elapsed();
            assert!(outcome.is_ok(), "{profile:?}: {outcome:?}");
            assert!(
                elapsed.as_secs() < 1,
                "{profile:?}: took {elapsed:?} for {} bytes",
                sql.len()
            );
        }
    }

    #[test]
    fn cte_column_lists_are_not_calls() {
        // I2 review nit: a CTE name with an explicit column list is a
        // definition, not a call — even when the name matches a dropped
        // function. The `AS (` shape (optionally via MATERIALIZED)
        // distinguishes it from a call alias (`SELECT f(x) AS y`).
        for sql in [
            "WITH instr(a) AS (SELECT 1) SELECT a FROM instr",
            "WITH \"instr\"(a) AS (SELECT 1) SELECT a FROM \"instr\"",
            "WITH t(a, b) AS (SELECT 1, 2) SELECT * FROM t",
            "WITH round(a) AS MATERIALIZED (SELECT 1) SELECT a FROM round",
            // N2 (re-review): a derived-table alias with a column list is
            // not a call either (`AS name(`/`, quoted or not). Engines
            // without alias column lists still fail closed at parse.
            "SELECT * FROM (SELECT 1 AS q) AS \"instr\"(y)",
            "SELECT * FROM (SELECT 1 AS q) AS instr(y)",
            "SELECT * FROM (VALUES (1)) AS \"instr\"(x)",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}: unexpectedly rejected"
                );
            }
        }
        // A genuine dropped call with an alias is still a call.
        for profile in PROFILES {
            let error = classify_single_read_statement(
                *profile,
                "SELECT instr(x, y) AS found FROM records",
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("use substr() or LIKE"),
                "{profile:?}: {error}"
            );
        }
    }

    #[test]
    fn replace_as_an_alias_is_not_the_write() {
        // I2 review nit: only the write positions (`REPLACE INTO`,
        // `INSERT OR REPLACE`) are rejected; `replace` elsewhere is data
        // and the `replace()` call form stays admitted.
        for sql in [
            "SELECT 1 AS replace FROM records",
            "SELECT 'a' AS replace, replace(name, 'b', 'c') FROM records",
            "SELECT replace FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}: unexpectedly rejected"
                );
            }
        }
        for sql in [
            "WITH x AS (SELECT 1) REPLACE INTO records VALUES(1,'z')",
            "WITH changed AS (INSERT OR REPLACE INTO records VALUES(1,'z')) SELECT * FROM changed",
            "REPLACE INTO records VALUES(1,'z')",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_err(),
                    "{profile:?}: unexpectedly admitted {sql}"
                );
            }
        }
    }

    #[test]
    fn classifier_rejects_multiple_and_data_modifying_ctes() {
        for sql in [
            "SELECT 1; SELECT 2",
            "WITH changed AS (DELETE FROM records RETURNING id) SELECT * FROM changed",
            "WITH x AS (SELECT 1) REPLACE INTO records VALUES(1,'z')",
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
    fn explain_query_plan_admits_only_a_plan_over_an_admissible_statement() {
        for profile in PROFILES {
            for sql in [
                "EXPLAIN QUERY PLAN SELECT id FROM records",
                "explain query plan select id from records where id = 'x'",
                "EXPLAIN QUERY PLAN WITH visible AS (SELECT id FROM records) SELECT count(*) FROM visible",
                "-- lead\nEXPLAIN /* mid */ QUERY PLAN SELECT 1; -- tail",
            ] {
                let classified =
                    classify_single_read_statement(*profile, sql).unwrap_or_else(|error| {
                        panic!("{profile:?}: {sql}: {error}")
                    });
                assert!(
                    classified.starts_with("EXPLAIN QUERY PLAN "),
                    "{profile:?}: {sql}: {classified}"
                );
                assert!(!classified.contains(';'), "{profile:?}: {sql}: {classified}");
            }
            // Bare EXPLAIN (without QUERY PLAN) stays rejected.
            for sql in [
                "EXPLAIN SELECT id FROM records",
                "EXPLAIN QUERY SELECT id FROM records",
                "EXPLAIN PLAN SELECT id FROM records",
                "EXPLAIN",
            ] {
                assert!(
                    classify_single_read_statement(*profile, sql).is_err(),
                    "{profile:?}: unexpectedly admitted {sql}"
                );
            }
            // An explained statement that is not itself admissible stays
            // rejected exactly as if submitted alone.
            for sql in [
                "EXPLAIN QUERY PLAN DELETE FROM records",
                "EXPLAIN QUERY PLAN WITH changed AS (DELETE FROM records RETURNING id) SELECT * FROM changed",
                "EXPLAIN QUERY PLAN WITH x AS (SELECT 1) REPLACE INTO records VALUES(1,'z')",
                "EXPLAIN QUERY PLAN SELECT 1; SELECT 2",
                "EXPLAIN QUERY PLAN EXPLAIN QUERY PLAN SELECT 1",
                "EXPLAIN QUERY PLAN",
                "EXPLAIN; QUERY PLAN SELECT 1",
            ] {
                assert!(
                    classify_single_read_statement(*profile, sql).is_err(),
                    "{profile:?}: unexpectedly admitted {sql}"
                );
            }
        }
        assert_eq!(
            classify_single_read_statement(
                QuerySqlProfile::SqliteLocal,
                "explain query plan select 1;"
            )
            .unwrap(),
            "EXPLAIN QUERY PLAN select 1"
        );
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
        assert_eq!(relation("agent_activity").semantic_version, 3);
        assert_eq!(
            &relation("agent_activity").columns[..2],
            &["activity_id", "run_key"]
        );
        assert_eq!(
            &relation("agent_activity").columns[12..],
            &["appears_active", "declared_intent", "declared_intent_state"]
        );
        assert_eq!(relation("agent_activity_claims").semantic_version, 1);
    }

    #[test]
    fn content_events_alone_advances_for_the_honest_local_cursor_name() {
        let content = LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "content_events")
            .unwrap();
        assert_eq!(LOGICAL_CATALOG_REVISION, 4);
        assert_eq!(content.semantic_version, CONTENT_EVENTS_RELATION_VERSION);
        assert_eq!(content.semantic_version, 2);
        assert_eq!(
            content.columns,
            &[
                "local_seq",
                "id",
                "record_id",
                "type",
                "created_at",
                "created_at_ms"
            ]
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
        assert_eq!(contract.revision, 6);
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
    fn postgres_result_type_rules_are_total() {
        let find = |types: &[&str], condition: &str| {
            ENGINE_TYPE_RULES
                .iter()
                .find(|rule| rule.engine_types == types && rule.condition == condition)
                .unwrap_or_else(|| panic!("missing rule for {types:?} when {condition}"))
        };
        let encoded = |types: &[&str], condition: &str, encoding: &str| {
            let rule = find(types, condition);
            assert_eq!(rule.profile, "postgres-server@6");
            assert_eq!(rule.outcome, "encode");
            assert_eq!(rule.json_encoding, Some(encoding));
            assert_eq!(rule.error_category, None);
        };
        let rejected = |types: &[&str], condition: &str| {
            let rule = find(types, condition);
            assert_eq!(rule.profile, "postgres-server@6");
            assert_eq!(rule.outcome, "reject");
            assert_eq!(rule.json_encoding, None);
            assert_eq!(rule.error_category, Some("syntax_or_type"));
        };

        assert_eq!(ENGINE_TYPE_RULES.len(), 15);
        encoded(&["*"], "value is SQL NULL", "null");
        encoded(&["bool"], "non-null", "boolean");
        encoded(&["int2", "int4", "int8"], "non-null", "signed-json-integer");
        encoded(&["float4", "float8"], "finite", "json-number");
        rejected(&["float4", "float8"], "NaN, +Infinity, or -Infinity");
        encoded(
            &["numeric"],
            "integer-valued and fits in i64",
            "signed-json-integer",
        );
        rejected(&["numeric"], "integer-valued but outside the i64 range");
        encoded(
            &["numeric"],
            "non-integral, finite, and within the IEEE-754 double range",
            "json-number",
        );
        rejected(
            &["numeric"],
            "NaN, +Infinity, -Infinity, or magnitude beyond the double range",
        );
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
