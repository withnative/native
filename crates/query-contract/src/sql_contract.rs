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
/// Shared repair hint for projection-time cell caps (Turso/PG): the stored
/// value was readable, only the projected cell is too large. Callers can
/// shrink the projection instead of excluding rows.
pub fn projection_cell_cap_repair() -> &'static str {
    " Repair: select fewer/smaller columns (e.g. substr(col, 1, 200) or LENGTH(col) instead of the full value) and page by the relation's stable catalog key (records: id; agent_activity: activity_id; agent_activity_claims: claim_id; messages_awaiting_reply: message_id) with ORDER BY <key> LIMIT 1000."
}
/// Breaking semantic revision of catalog-wide SQL behavior. Saved governed SQL
/// pins this independently from an engine/dialect profile. Additive relations
/// and relation-local changes do not bump this revision: each dependency's
/// name/profile/semantic-version pin is its compatibility gate. Change this
/// only when compatibility changes beyond one relation's declared contract.
pub const LOGICAL_CATALOG_REVISION: u32 = 4;
pub const LOGICAL_RELATION_VERSION: u32 = 1;
pub const CONTENT_EVENTS_RELATION_VERSION: u32 = 4;
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
            "is_current",
            "successor_count",
            "last_activity_at",
            "last_activity_at_ms",
            "created_at",
            "created_at_ms",
            "updated_at",
            "updated_at_ms",
            "deleted_at",
            "deleted_at_ms",
            "archived",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.record-lifecycle-interpretations",
        name: "record_lifecycle_interpretations",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "record_id",
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
            "actor",
            "run_key",
            "parent_key",
            "channel_kind",
            "created_at",
            "created_at_ms",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.body-blocks",
        name: "body_blocks",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "record_id",
            "block_index",
            "chunk_index",
            "chunk_count",
            "heading_path",
            "block_kind",
            "text",
            "start_offset",
            "end_offset",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.body-block-headings",
        name: "body_block_headings",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "record_id",
            "block_index",
            "chunk_index",
            "heading_index",
            "depth",
            "title",
            "title_truncated",
            "heading_block_index",
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
        identity: "native.query-sql.vocabulary-value-json-nodes",
        name: "vocabulary_value_json_nodes",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: false,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "value_id",
            "ordinal",
            "path",
            "parent_path",
            "parent_ordinal",
            "member_key",
            "array_index",
            "depth",
            "node_type",
            "text_value",
            "number_text",
            "bool_value",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.schema-config-json-nodes",
        name: "schema_config_json_nodes",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "config_id",
            "ordinal",
            "path",
            "parent_path",
            "parent_ordinal",
            "member_key",
            "array_index",
            "depth",
            "node_type",
            "text_value",
            "number_text",
            "bool_value",
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
        identity: "native.query-sql.effective-relationship-endpoints",
        name: "effective_relationship_endpoints",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "relationship_origin_db_id",
            "relationship_id",
            "ordinal",
            "role",
            "portable_ref",
            "record_type",
            "record_kind",
            "record_id",
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
        identity: "native.query-sql.actors",
        name: "actors",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &["actor", "person_id", "display_name"],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.runs",
        name: "runs",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "run_key",
            "principal_person_id",
            "started_at_ms",
            "ended_at_ms",
            "reported_model",
            "reported_client",
            "model_assurance",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.run-intents",
        name: "run_intents",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        // Declarations live in the read log, which a standby export strips.
        completeness: "best_effort",
        profiles: SQLITE_PROFILE,
        columns: &["run_key", "ordinal", "intent", "declared_at_ms"],
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
    // Design D6 (task b2583dc): per-viewer message state and mentions. Both
    // hold only the caller's own private state and have no account column,
    // so no join or aggregate can reach another viewer's. Neither carries a
    // sequence, version or head. Additive: no existing relation changes
    // shape. `message_reactions` follows separately on its own projection.
    QuerySqlRelationContract {
        identity: "native.query-sql.my-message-state",
        name: "my_message_state",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "message_id",
            "stage",
            "unread",
            "is_own",
            "mentioned",
            "flagged",
            "muted",
            "archived",
            "snoozed_until",
            "snoozed_until_ms",
            "reactable",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.my-mentions",
        name: "my_mentions",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "source_id",
            "source_kind",
            "via",
            "own_source",
            "mentioned_at",
            "mentioned_at_ms",
            "seen",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.facet-times",
        name: "facet_times",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: SQLITE_PROFILE,
        columns: &[
            "record_id",
            "key",
            "kind",
            "all_day",
            "start_date",
            "end_date",
            "start_ms",
            "end_ms",
            "tz",
            "tzdb_version",
        ],
    },
    QuerySqlRelationContract {
        identity: "native.query-sql.body-task-items",
        name: "body_task_items",
        semantic_version: LOGICAL_RELATION_VERSION,
        caller_relative: true,
        completeness: "complete",
        profiles: ALL_PROFILES,
        columns: &[
            "record_id",
            "item_index",
            "marker",
            "checked",
            "in_quote",
            "start_offset",
            "end_offset",
        ],
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

/// Cap on the columns named per relation in the unknown-column repair; the
/// total is always named so the message stays bounded on wide relations.
pub const UNKNOWN_COLUMN_LIST_CAP: usize = 12;
/// Cap on the in-scope relations named in the unknown-column repair; beyond
/// it the message falls back to the `catalog_columns` pointer.
pub const UNKNOWN_COLUMN_RELATION_CAP: usize = 4;

/// Columns of one logical relation on one profile, or `None` when the
/// relation is unknown or unavailable on that profile. Profile-aware so a
/// caller is never pointed at columns their engine cannot query.
pub fn logical_columns(
    relation: &str,
    profile: QuerySqlProfile,
) -> Option<&'static [&'static str]> {
    let profile_id = profile.contract().id;
    LOGICAL_RELATIONS
        .iter()
        .find(|candidate| {
            candidate.name.eq_ignore_ascii_case(relation)
                && candidate.profiles.contains(&profile_id)
        })
        .map(|relation| relation.columns)
}

/// Extract the unknown-column spelling from an engine failure detail.
/// Understands SQLite/Turso (`no such column: titel`, qualifier included)
/// and Postgres (`column "titel" does not exist`, quoted dotted parts
/// included). Returns the display spelling with quotes stripped
/// (`r.nme`), ready for [`unknown_column_repair`].
pub fn unknown_column_in_detail(detail: &str) -> Option<String> {
    if let Some(tail) = detail
        .find("no such column")
        .map(|index| &detail[index + "no such column".len()..])
    {
        let raw: String = tail
            .trim_start_matches([':', ' ', '\t'])
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '"')
            .collect();
        return clean_column_parts(&raw);
    }
    if let Some(start) = detail.find("column ") {
        let tail = &detail[start + "column ".len()..];
        if let Some(end) = tail.find(" does not exist") {
            return clean_column_parts(&tail[..end]);
        }
    }
    None
}

/// Strip per-part quoting from a dotted column spelling (`"r"."nme"` →
/// `r.nme`) and reject anything that is not a plain column reference.
fn clean_column_parts(raw: &str) -> Option<String> {
    let column: String = raw
        .split('.')
        .map(|part| part.trim().trim_matches('"').trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if column.is_empty()
        || !column
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return None;
    }
    Some(column)
}

/// Join an engine failure detail to the shared unknown-column repair as two
/// sentences: `. ` normally, a bare space when the detail already ends a
/// sentence (so no `..` appears), `; ` when it ends in other punctuation.
pub fn join_detail_repair(detail: &str, repair: &str) -> String {
    match detail.chars().last() {
        Some('.') | Some('?') | Some('!') => format!("{detail} {repair}"),
        Some(c) if c.is_ascii_punctuation() => format!("{detail}; {repair}"),
        _ => format!("{detail}. {repair}"),
    }
}

/// Repair remedy for an unknown column on known logical relation(s), shared
/// by every engine so the wording cannot drift per backend. States only the
/// remedy, prefixed `Hint:` — engines join it to their own failure detail
/// with [`join_detail_repair`], so the repair never restates the engine's
/// "no such column". `column` is the engine's display spelling (qualifier
/// included); `scope_relations` are the statement's in-scope logical
/// relation names in FROM order (see [`statement_scope`]). Relations unknown
/// on `profile` are dropped; an empty or over-wide scope falls back to the
/// `catalog_columns` pointer. Returns `None` when there is nothing to name
/// (empty column with an empty scope).
pub fn unknown_column_repair(
    column: &str,
    scope_relations: &[&str],
    profile: QuerySqlProfile,
) -> Option<String> {
    let column = column.trim().trim_matches('"').trim();
    let mut relations: Vec<(&'static str, &'static [&'static str])> = Vec::new();
    for name in scope_relations {
        if relations
            .iter()
            .any(|(seen, _)| seen.eq_ignore_ascii_case(name))
        {
            continue;
        }
        if let Some(columns) = logical_columns(name, profile) {
            let canonical = LOGICAL_RELATIONS
                .iter()
                .find(|candidate| candidate.name.eq_ignore_ascii_case(name))
                .expect("logical_columns returned columns")
                .name;
            relations.push((canonical, columns));
        }
    }
    if relations.is_empty() || relations.len() > UNKNOWN_COLUMN_RELATION_CAP {
        if column.is_empty() && relations.is_empty() {
            return None;
        }
        return Some(
            "Hint: list valid columns with SELECT relation_name, column_name \
             FROM catalog_columns ORDER BY relation_name, column_position."
                .to_owned(),
        );
    }
    let mut parts = Vec::new();
    for (name, columns) in &relations {
        let shown = columns
            .iter()
            .take(UNKNOWN_COLUMN_LIST_CAP)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if columns.len() > UNKNOWN_COLUMN_LIST_CAP {
            parts.push(format!(
                "valid columns of {name} are {shown} … ({} total)",
                columns.len()
            ));
        } else {
            parts.push(format!("valid columns of {name} are {shown}"));
        }
    }
    if relations.len() == 1 {
        return Some(format!(
            "Hint: {}. Full list: SELECT column_name FROM catalog_columns \
             WHERE relation_name = '{}' ORDER BY column_position.",
            parts[0], relations[0].0,
        ));
    }
    let mut listed = parts.join("; ");
    if let Some(first) = listed.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    Some(format!(
        "Hint: '{column}' is not a column of any relation in scope. {listed}. \
         Full list: SELECT relation_name, column_name FROM catalog_columns \
         WHERE relation_name IN ({}) ORDER BY relation_name, column_position.",
        relations
            .iter()
            .map(|(name, _)| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

/// Best-effort FROM/JOIN scope of a SELECT statement: `(relation, alias)`
/// pairs in first-seen order, restricted to logical relations. The statement
/// is lexed first — string literals and comments contribute no tokens, and
/// quoted identifiers never act as keywords — then scanned at paren depth
/// zero only. Conservative by design: a `WITH` clause or any parenthesised
/// subquery (`FROM (SELECT …)`, `IN (SELECT …)`) yields an empty scope, so
/// the repair falls back to the generic `catalog_columns` pointer. A wrong
/// relation is worse than the fallback. Repair-text input only, never
/// authorization. Table qualifiers (`main.`/`temp.`) are stripped; a bare
/// `AS` alias is recorded, as is an implicit `<table> <alias>` alias.
pub fn statement_scope(statement: &str) -> Vec<(String, Option<String>)> {
    const KEYWORD: &[&str] = &[
        "where",
        "group",
        "order",
        "limit",
        "having",
        "window",
        "select",
        "with",
        "union",
        "except",
        "intersect",
        "values",
        "returning",
        "left",
        "right",
        "inner",
        "outer",
        "cross",
        "full",
        "natural",
        "join",
        "from",
        "on",
        "using",
        "as",
    ];
    let tokens = scope_tokens(statement);
    let mut scope: Vec<(String, Option<String>)> = Vec::new();
    let mut depth = 0usize;
    let mut need_table = false;
    let mut from_active = false;
    let mut in_on = false;
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        match token.kind {
            ScopeKind::LParen => {
                if need_table {
                    // `FROM (` is a derived table or parenthesised join:
                    // conservative fallback, never a misattributed scope.
                    return Vec::new();
                }
                if peek_word(&tokens, i + 1).is_some_and(|word| {
                    word.eq_ignore_ascii_case("select")
                        || word.eq_ignore_ascii_case("with")
                        || word.eq_ignore_ascii_case("values")
                }) {
                    return Vec::new();
                }
                depth += 1;
                i += 1;
                continue;
            }
            ScopeKind::RParen => {
                depth = depth.saturating_sub(1);
                i += 1;
                continue;
            }
            ScopeKind::Comma => {
                if need_table {
                    i += 1;
                    continue;
                }
                if from_active && !in_on && depth == 0 {
                    need_table = true;
                }
                i += 1;
                continue;
            }
            ScopeKind::Quoted => {
                if need_table && depth == 0 {
                    need_table = false;
                    if is_logical_relation(&token.text.to_ascii_lowercase()) {
                        let canonical = LOGICAL_RELATIONS
                            .iter()
                            .find(|candidate| candidate.name.eq_ignore_ascii_case(token.text))
                            .expect("is_logical_relation matched")
                            .name
                            .to_owned();
                        let (alias, next) = scope_alias(&tokens, i + 1, KEYWORD);
                        scope.push((canonical, alias));
                        i = next;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            ScopeKind::Word => {}
        }
        let word = token.text;
        if word.eq_ignore_ascii_case("with") {
            return Vec::new();
        }
        if depth != 0 {
            i += 1;
            continue;
        }
        if word.eq_ignore_ascii_case("from") || word.eq_ignore_ascii_case("join") {
            need_table = true;
            from_active = true;
            in_on = false;
            i += 1;
            continue;
        }
        if word.eq_ignore_ascii_case("on") || word.eq_ignore_ascii_case("using") {
            need_table = false;
            in_on = true;
            i += 1;
            continue;
        }
        if KEYWORD.iter().any(|key| word.eq_ignore_ascii_case(key)) {
            need_table = false;
            from_active = false;
            in_on = false;
            i += 1;
            continue;
        }
        if need_table {
            need_table = false;
            let short = word.rsplit('.').next().unwrap_or(word);
            if is_logical_relation(&short.to_ascii_lowercase()) {
                let canonical = LOGICAL_RELATIONS
                    .iter()
                    .find(|candidate| candidate.name.eq_ignore_ascii_case(short))
                    .expect("is_logical_relation matched")
                    .name
                    .to_owned();
                let (alias, next) = scope_alias(&tokens, i + 1, KEYWORD);
                scope.push((canonical, alias));
                i = next;
                continue;
            }
            // Non-logical target (unknown name, physical table): keep the
            // FROM list active so a later comma still re-arms.
        }
        i += 1;
    }
    scope
}

/// Next significant (non-paren) token at or after `i`, used to spot
/// parenthesised subqueries without descending into them.
fn peek_word<'a>(tokens: &[ScopeToken<'a>], i: usize) -> Option<&'a str> {
    tokens[i..].iter().find_map(|token| match token.kind {
        ScopeKind::Word | ScopeKind::Quoted => Some(token.text),
        ScopeKind::LParen | ScopeKind::RParen | ScopeKind::Comma => None,
    })
}

/// Alias after a FROM target: `AS name` or a bare `name` that is not a
/// keyword, comma or paren. Returns the alias and the next index.
fn scope_alias(
    tokens: &[ScopeToken<'_>],
    mut next: usize,
    keyword: &[&str],
) -> (Option<String>, usize) {
    let is_keyword = |text: &str| keyword.iter().any(|key| text.eq_ignore_ascii_case(key));
    if tokens
        .get(next)
        .is_some_and(|token| token.kind == ScopeKind::Word && token.text.eq_ignore_ascii_case("as"))
    {
        next += 1;
        return match tokens.get(next) {
            Some(token) if token.kind == ScopeKind::Word || token.kind == ScopeKind::Quoted => {
                (Some(token.text.to_owned()), next + 1)
            }
            _ => (None, next),
        };
    }
    match tokens.get(next) {
        Some(token)
            if (token.kind == ScopeKind::Word && !is_keyword(token.text))
                || token.kind == ScopeKind::Quoted =>
        {
            (Some(token.text.to_owned()), next + 1)
        }
        _ => (None, next),
    }
}

/// One lexical token of a caller statement for [`statement_scope`]. String
/// literals and comments produce nothing; quoted identifiers (`"…"`,
/// `` `…` ``, `[…]`) are identifiers that never act as keywords.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ScopeKind {
    Word,
    Quoted,
    Comma,
    LParen,
    RParen,
}

#[derive(Clone, Copy, Debug)]
struct ScopeToken<'a> {
    kind: ScopeKind,
    text: &'a str,
}

fn scope_tokens(statement: &str) -> Vec<ScopeToken<'_>> {
    let bytes = statement.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' | 0x0C => {
                i += 1;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                // Nested block comments (Postgres) need depth tracking.
                let mut depth = 1;
                i += 2;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\'' {
                        if bytes.get(i + 1) == Some(&b'\'') {
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' | b'`' => {
                let quote = byte;
                let start = i + 1;
                i += 1;
                let mut text_end = start;
                while i < bytes.len() {
                    if bytes[i] == quote {
                        if bytes.get(i + 1) == Some(&quote) {
                            i += 2;
                            text_end = i - 1;
                        } else {
                            break;
                        }
                    } else {
                        i += 1;
                        text_end = i;
                    }
                }
                // Unterminated quotes swallow the rest; still an identifier,
                // never a keyword.
                tokens.push(ScopeToken {
                    kind: ScopeKind::Quoted,
                    text: &statement[start..text_end.min(statement.len())],
                });
                i += 1;
            }
            b'[' => {
                let start = i + 1;
                i += 1;
                while i < bytes.len() && bytes[i] != b']' {
                    i += 1;
                }
                tokens.push(ScopeToken {
                    kind: ScopeKind::Quoted,
                    text: &statement[start..i.min(statement.len())],
                });
                i += 1;
            }
            b'$' => {
                // Dollar-quoted strings (`$tag$…$tag$`): skip to the closer.
                // `$1` parameters cannot appear here — callers send `?N` —
                // so a `$` always opens a quote or a stray separator.
                let mut tag_end = i + 1;
                while tag_end < bytes.len()
                    && (bytes[tag_end].is_ascii_alphanumeric() || bytes[tag_end] == b'_')
                {
                    tag_end += 1;
                }
                if tag_end < bytes.len() && bytes[tag_end] == b'$' && tag_end > i + 1 {
                    let tag = &statement[i..=tag_end];
                    if let Some(close) = statement[tag_end + 1..].find(tag) {
                        i = tag_end + 1 + close + tag.len();
                    } else {
                        i = bytes.len();
                    }
                } else {
                    i += 1;
                }
            }
            b',' => {
                tokens.push(ScopeToken {
                    kind: ScopeKind::Comma,
                    text: ",",
                });
                i += 1;
            }
            b'(' => {
                tokens.push(ScopeToken {
                    kind: ScopeKind::LParen,
                    text: "(",
                });
                i += 1;
            }
            b')' => {
                tokens.push(ScopeToken {
                    kind: ScopeKind::RParen,
                    text: ")",
                });
                i += 1;
            }
            _ if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.' || byte >= 0x80 => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric()
                        || bytes[i] == b'_'
                        || bytes[i] == b'.'
                        || bytes[i] >= 0x80)
                {
                    i += 1;
                }
                tokens.push(ScopeToken {
                    kind: ScopeKind::Word,
                    text: &statement[start..i],
                });
            }
            _ => {
                i += 1;
            }
        }
    }
    tokens
}

/// Resolve which in-scope relations an unknown column could belong to.
/// `column` is the engine's display spelling (`titel`, `r.nme`,
/// `"records"."actor"`). A qualifier matching a relation or alias narrows to
/// that relation; anything else (bare column, unknown qualifier) returns the
/// whole scope so the repair lists every candidate.
pub fn resolve_column_scope<'a>(
    column: &str,
    scope: &'a [(String, Option<String>)],
) -> Vec<&'a str> {
    let parts: Vec<&str> = column
        .split('.')
        .map(|part| part.trim().trim_matches('"').trim())
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() < 2 {
        return scope
            .iter()
            .map(|(relation, _)| relation.as_str())
            .collect();
    }
    let qualifier = parts[0];
    if let Some(hit) = scope
        .iter()
        .find(|(relation, _)| relation.eq_ignore_ascii_case(qualifier))
    {
        return vec![hit.0.as_str()];
    }
    if let Some(hit) = scope.iter().find(|(_, alias)| {
        alias
            .as_ref()
            .is_some_and(|alias| alias.eq_ignore_ascii_case(qualifier))
    }) {
        return vec![hit.0.as_str()];
    }
    scope
        .iter()
        .map(|(relation, _)| relation.as_str())
        .collect()
}

/// One-line relation notes for `catalog_relations`, carrying the join keys
/// agents otherwise guess. Descriptive only; the drift tests pin structure,
/// not prose. No apostrophes: values render inside single-quoted SQL.
const RELATION_COMMENTS: &[(&str, &str)] = &[
    ("records", "one row per visible record - join links.source_id/target_id, facet_values.record_id and content_events.record_id to records.id - home_id is NULL when the home is not visible - archived is 0 or 1 and does not filter rows or certify currency"),
    ("record_lifecycle_interpretations", "caller-relative live lifecycle meaning for each visible record - join record_id to records.id - derived from the same query snapshot, with no public governance basis token"),
    ("content_events", "append-only history - join record_id to records.id - local_seq orders it - actor, run_key and parent_key are redacted by the get_history disclosure rule - channel_kind travels only where the actor is disclosed"),
    ("body_blocks", "visible record body chunks - join record_id to records.id - page by record_id, block_index, chunk_index with ORDER BY - reassemble text in that order - heading_path is a JSON array of ancestor/self heading objects"),
    ("body_block_headings", "ancestor/self heading per visible body chunk - key record_id,block_index,chunk_index,heading_index - heading_index is zero-based path position - heading_block_index identifies heading within current body revision - title is <=120-character display excerpt, title_truncated 0/1 - empty/opaque paths have no rows - online SQLite only, member/offline unavailable"),
    ("links", "edges - join source_id and target_id to records.id - both endpoints must be visible or the edge is absent"),
    ("facet_values", "current facet per (record_id, key) - join record_id to records.id"),
    ("facet_observations", "facet history with as_of/observed_at/event_seq - join record_id to records.id"),
    ("bindings", "caller-owned account/email bindings - join record_id to records.id"),
    ("blobs", "attachment payloads reachable through facet_values key blob_ref on a Document attachment"),
    ("vocabularies", "caller-independent - join vocabulary_values.vocabulary_id to vocabularies.id"),
    ("vocabulary_values", "join vocabulary_id to vocabularies.id"),
    ("vocabulary_value_json_nodes", "caller-independent stored metadata occurrences - value_id joins vocabulary_values.id - unique key value_id, ordinal (zero-based preorder) - parent_ordinal identifies the parent occurrence - paths are escaped JSON Pointers, not unique - roots and empty containers are rows - number_text preserves the token, bool_value is 0/1/NULL"),
    ("schema_config_json_nodes", "complete stored object-root config occurrences - config_id joins caller-filtered schema_config.id - key config_id, ordinal - parent_ordinal disambiguates duplicate parents - escaped JSON Pointer paths repeat - numeric tokens are exact - online SQLite only - member/offline unavailable"),
    ("schema_config", "workspace configuration rows"),
    ("effective_relationships", "governed relationships - endpoints is a JSON array with record_id per endpoint"),
    ("effective_relationship_endpoints", "one row per endpoint of a relationship present in effective_relationships - join both relationship_origin_db_id and relationship_id - ordinal is the endpoint order - a relationship with any hidden endpoint yields no rows - online SQLite only, member/offline unavailable"),
    ("agent_activity", "best-effort run presence over the last 24 hours - declared_intent is caller disclosure, not verified fact"),
    ("agent_activity_claims", "durable claim events - join activity_id to agent_activity, record_id to records.id"),
    ("actors", "actors disclosed in the caller's own history under the get_history rule, never members who have not acted there - join content_events.actor to actor, person_id to records.id - display_name is the visible person's name, NULL when there is none"),
    ("runs", "durable agent runs of every age whose owner the get_history rule discloses - principal_person_id is the visible person, NULL when there is none - reported_model and reported_client are self-declared, never verified - page by started_at_ms, run_key"),
    ("run_intents", "ordered set_intent declarations of each run in runs - join run_key to runs.run_key - ordinal counts from 1 within a run - empty when the workspace keeps no read log"),
    ("messages_awaiting_reply", "single-column queue of message ids awaiting reply"),
    ("my_message_state", "the caller's own read state and preferences for each visible Message, private to the caller - join message_id to records.id - stage is unsurfaced, presented, opened or acknowledged - unread is 1 until the caller opens a Message they did not write"),
    ("my_mentions", "sources that mention the caller, private to the caller - join source_id to records.id - via principal is an addressed @-mention on a Message, via reference is a record reference that resolves to the caller - seen is NULL where Native does not track it"),
    ("facet_times", "typed time facets (declared date, instant, zoned, when) on the timeline - join record_id to records.id - all_day rows use start_date/end_date, timed rows start_ms/end_ms, end exclusive"),
    ("body_task_items", "GFM task-list items in visible records' current bodies - byte offsets in body, document order by item_index - checked and quoted rows remain present, source event sequence is withheld"),
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

/// Relations whose columns are inlined on the card; every other relation
/// prints only by name because the card budget cannot fit every column list,
/// and `catalog_columns` (taught in the card header) carries the rest.
const CARD_COLUMN_RELATIONS: &[&str] = &["records", "links", "content_events", "facet_values"];

/// Join-key notes for the `sql_read` catalog card, one per relation.
/// Relation names render from `LOGICAL_RELATIONS` itself, so only this
/// prose can drift; the card test pins both directions.
const CARD_NOTES: &[(&str, &str)] = &[
    ("records", "home_id parent (hidden=NULL); links.source_id/target_id=id"),
    ("record_lifecycle_interpretations", "governed/absent/unclassified"),
    ("content_events", "append-only; order local_seq"),
    ("body_blocks", "chunks; page by record_id, block_index, chunk_index to join text"),
    ("body_block_headings", "chunk key+heading_index; heading_block_index revision ordinal; title excerpt"),
    ("links", "part_of source part->target whole; both visible"),

    ("facet_values", "current (record_id,key)"),
    ("facet_observations", "history"),
    ("bindings", "caller account/email"),
    ("blobs", "Document attachment via blob_ref"),
    ("vocabularies", "vocabulary_values.vocabulary_id=id"),
    ("vocabulary_values", "vocabulary_id=vocabularies.id"),
    ("vocabulary_value_json_nodes", "value_id=vocabulary_values.id; key value_id,ordinal; parent_ordinal occurrence; number_text literals"),
    ("schema_config", "global or visible config"),
    ("schema_config_json_nodes", "config_id=schema_config.id; key config_id,ordinal; parent_ordinal occurrence; paths repeat; scalar literals; member/offline unavailable"),
    ("effective_relationships", "governed; endpoints JSON record_id array"),
    ("effective_relationship_endpoints", "join on both ids; ordinal order"),
    ("agent_activity", "best-effort run presence, 24h"),
    ("agent_activity_claims", "activity_id=agent_activity"),
    ("actors", "content_events.actor=actor; person_id=records.id; hidden display_name NULL"),
    ("runs", "principal_person_id=records.id; model self-declared; order started_at_ms,run_key"),
    ("run_intents", "run_key=runs.run_key; order ordinal"),
    ("messages_awaiting_reply", "IDs awaiting reply"),
    ("my_message_state", "private; message_id=records.id; unread by records.home_id"),
    ("my_mentions", "private; source_id=records.id; order mentioned_at_ms"),
    ("facet_times", "all_day dates; timed millis; end exclusive"),
    ("body_task_items", "GFM tasks; item_index order; checked/in_quote"),
    ("catalog_relations", "filter by profiles"),
    ("catalog_columns", "order relation_name,column_position"),

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
        "Unordered top-level LIMIT sorts all outputs (assumed_order). \
         Saved SQL, nested/CTE LIMITs, OFFSET and FETCH require ORDER BY. \
         Unique tie-breakers. record_id=records.id. Queryable relations: \
         SELECT * FROM catalog_relations ORDER BY relation_name. \
         Columns: SELECT * FROM catalog_columns ORDER BY relation_name,column_position.",
    );
    for relation in LOGICAL_RELATIONS {
        let note = CARD_NOTES
            .iter()
            .find(|(name, _)| *name == relation.name)
            .map(|(_, note)| *note)
            .unwrap_or("");
        card.push_str(&format!("\n{}", relation.name));
        if CARD_COLUMN_RELATIONS.contains(&relation.name) {
            card.push_str(&format!("({})", relation.columns.join(",")));
        }
        card.push_str(&format!(": {}", note));
        if relation.profiles != ALL_PROFILES {
            card.push_str(&format!(" [only: {}]", relation.profiles.join(",")));
        }
    }
    card.push_str(
        "\nValues: UTC-millis timestamp text + integer *_ms; bool 0/1; \
         binary text order; SQL NULL=JSON null. ?N contiguous from 1. \
         LIKE wildcards, not words; '%- [ ]%' includes quoted checklists. \
         Physical tables/sqlite_master/pragma_*/information_schema \
         blocked; errors give fixes.",
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

/// Whether a parameter type tag is in the shared registry (rule typed params
/// validate their declarations against this; the registry stays canonical).
pub fn parameter_type_known(tag: &str) -> bool {
    PARAMETER_TYPES.iter().any(|known| known.tag == tag)
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
    "now_ms_ms",
    "time_dependent",
    "assumed_order",
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

pub(crate) fn categorized_error(
    category: QuerySqlErrorCategory,
    detail: impl AsRef<str>,
) -> QueryError {
    QueryError::Sql {
        category,
        detail: detail.as_ref().to_string(),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySqlRequest {
    pub sql: String,
    #[serde(default, deserialize_with = "deserialize_parameters")]
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

/// Schema-failure repair for the executor operation-contract surface (Native
/// b0b7419). The widened `parameters` schema otherwise renders as an opaque
/// anyOf/oneOf union; name the expected shape and the first offending index
/// instead. Returns `None` when every entry is admissible (or `parameters`
/// is not an array), in which case the caller keeps the generic error.
pub fn parameters_shape_diagnostic(parameters: &Value) -> Option<String> {
    let items = parameters.as_array()?;
    for (index, entry) in items.iter().enumerate() {
        if parameter_from_json(entry).is_ok() {
            continue;
        }
        let found = if entry.is_array() {
            "an array".to_owned()
        } else if let Some(object) = entry.as_object() {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            let listed = keys
                .iter()
                .map(|key| format!("\"{key}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!("an object with keys [{listed}]")
        } else {
            "a value of an unsupported shape".to_owned()
        };
        return Some(format!(
            "parameters[{index}]: expected {EXPECTED_PARAMETER_SHAPE}; found {found}"
        ));
    }
    None
}

/// Ordered positional parameter. `value: null` is a typed SQL NULL. Integer
/// values use decimal strings and bytes use base64 so JSON never loses data.
///
/// Deserialization additionally accepts bare JSON scalars and infers the tag
/// (Native b0b7419): string maps to text, integer to integer, fractional
/// number to real, boolean to boolean, and null to SQL NULL. Bytes, json and
/// timestamp stay typed-only: a bare string is always text. Bare integers
/// must fit the signed 64-bit range, and clients that cannot carry integers
/// beyond 2^53 exactly should prefer the typed decimal-string form.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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

/// Typed-object form of [`QuerySqlParameter`], kept as the canonical shape.
/// The public enum deserializes through [`parameter_from_json`], which
/// delegates objects here so malformed typed entries keep serde's exact
/// field errors (e.g. `missing field 'value'`).
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TypedQuerySqlParameter {
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

impl From<TypedQuerySqlParameter> for QuerySqlParameter {
    fn from(typed: TypedQuerySqlParameter) -> Self {
        match typed {
            TypedQuerySqlParameter::Boolean { value } => Self::Boolean { value },
            TypedQuerySqlParameter::Integer { value } => Self::Integer { value },
            TypedQuerySqlParameter::Real { value } => Self::Real { value },
            TypedQuerySqlParameter::Text { value } => Self::Text { value },
            TypedQuerySqlParameter::Bytes { value } => Self::Bytes { value },
            TypedQuerySqlParameter::Json { value } => Self::Json { value },
            TypedQuerySqlParameter::Timestamp { value } => Self::Timestamp { value },
        }
    }
}

/// Expected-shape repair shared by scalar inference and both error surfaces
/// (serde deserialization and the executor operation-contract check).
pub const EXPECTED_PARAMETER_SHAPE: &str = "each parameter must be a typed object {\"type\", \"value\"} or a bare JSON scalar (string->text, integer->integer, number->real, boolean->boolean, null->SQL NULL); bytes, json and timestamp stay typed-only";
/// Infer a [`QuerySqlParameter`] from one raw JSON entry. Objects take the
/// typed form; bare scalars infer their tag; anything else is a shape error.
fn parameter_from_json(entry: &Value) -> std::result::Result<QuerySqlParameter, String> {
    match entry {
        Value::Null => Ok(QuerySqlParameter::Text { value: None }),
        Value::Bool(flag) => Ok(QuerySqlParameter::Boolean { value: Some(*flag) }),
        Value::String(text) => Ok(QuerySqlParameter::Text {
            value: Some(text.clone()),
        }),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                // serde_json preserves i64 exactly; the decimal string keeps
                // it exact through validation and binding.
                Ok(QuerySqlParameter::Integer {
                    value: Some(integer.to_string()),
                })
            } else if let Some(unsigned) = number.as_u64() {
                Err(format!(
                    "bare integer parameter {unsigned} is outside the signed 64-bit range, which no query_sql encoding carries; {EXPECTED_PARAMETER_SHAPE}"
                ))
            } else if let Some(real) = number.as_f64() {
                if real.is_finite() {
                    Ok(QuerySqlParameter::Real { value: Some(real) })
                } else {
                    Err(format!(
                        "bare real parameter must be finite; {EXPECTED_PARAMETER_SHAPE}"
                    ))
                }
            } else {
                Err(format!(
                    "bare number parameter is not a supported integer or real; {EXPECTED_PARAMETER_SHAPE}"
                ))
            }
        }
        Value::Array(_) => Err(format!("got an array; {EXPECTED_PARAMETER_SHAPE}")),
        Value::Object(_) => serde_json::from_value::<TypedQuerySqlParameter>(entry.clone())
            .map(QuerySqlParameter::from)
            .map_err(|error| format!("invalid typed entry: {error}; {EXPECTED_PARAMETER_SHAPE}")),
    }
}

impl<'de> Deserialize<'de> for QuerySqlParameter {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entry = Value::deserialize(deserializer)?;
        parameter_from_json(&entry).map_err(serde::de::Error::custom)
    }
}

/// Element-wise parameters decoding so failures name the offending index
/// (Native b0b7419): `parameters[2]: ...` instead of a bare serde error.
fn deserialize_parameters<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<QuerySqlParameter>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<Value>::deserialize(deserializer)?;
    raw.iter()
        .enumerate()
        .map(|(index, entry)| {
            parameter_from_json(entry).map_err(|message| {
                serde::de::Error::custom(format!("parameters[{index}]: {message}"))
            })
        })
        .collect()
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
    /// Statement-fixed clock (E1 M3): the single Native-supplied
    /// milliseconds-since-Unix-epoch value bound for every `now_ms()` use
    /// in this statement, captured once per statement at admission beside
    /// `as_of_seq`. `None` when the statement uses no `now_ms()`. A run is
    /// reproducible given its stamp; the digest covers rows, never this.
    pub now_ms_ms: Option<i64>,
    /// True exactly when the statement used `now_ms()` (equivalently,
    /// `now_ms_ms` is `Some`). Time-dependent consumers (live tabs, caches)
    /// re-run on a clock tick as well as on data change when this is set.
    pub time_dependent: bool,
    /// Server-assumed ordering (E2 ad-hoc default): `Some` exactly when the
    /// outermost statement carried `LIMIT` with no `ORDER BY` and the server
    /// ordered by every output column in projection order instead of
    /// refusing. Serialized always (null when the caller ordered or no
    /// LIMIT applied), so the field is always present.
    pub assumed_order: Option<AssumedOrder>,
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
                revision: 5,
                mode: "embedded",
                dialect: QuerySqlDialectContract {
                    name: "turso-sqlite",
                    version: "Turso 0.8.0".to_owned(),
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

/// MCP request schema derived from the canonical parameter tag inventory,
/// plus the bare JSON scalars the deserializer infers (Native b0b7419).
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
                "description": "Positional parameters: typed {\"type\", \"value\"} entries or inferred bare scalars (bytes/json/timestamp stay typed-only). See read_guide(query-sql) for the mapping.",
                "items": { "anyOf": [
                    { "oneOf": one_of },
                    { "type": "string" },
                    { "type": "integer" },
                    { "type": "number" },
                    { "type": "boolean" },
                    { "type": "null" }
                ] }
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
/// (dropped functions + two-argument `round` + multi-argument `max`/`min`)
/// apply to NEW SQL only — ad-hoc `query_sql` and SQL being saved.
/// Inspection and execution of already-stored
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
    // E1 M3: engine keyword clocks are hidden non-determinism — each engine
    // would read its own clock at its own moment. Runs under both
    // allowances: a stored definition using one fails legibly and migrates
    // to `now_ms()`. Quoted forms (`"current_date"`, `'...'` strings) are
    // `Quoted` tokens, never `Word`, so identifiers and literals are safe.
    reject_clock_keywords(&words)?;
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
    validate_portable_calls(profile, statement, allowance)?;
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

/// Rule-input parameter slots: the exact `?N` set of a classified statement,
/// required contiguous `1..=N` (empty when the statement takes no parameters).
/// The extractor pins the returned slots; registration compares them. Fails
/// closed on any gap: `?1, ?3` can never become slots `[1, 3]`.
pub fn placeholder_slots(profile: QuerySqlProfile, statement: &str) -> Result<Vec<usize>> {
    let mut slots = BTreeSet::new();
    for token in scan_tokens(profile, statement)? {
        if let Token::Placeholder { start, end } = token {
            slots.insert(
                statement[start + 1..end]
                    .parse::<usize>()
                    .unwrap_or(usize::MAX),
            );
        }
    }
    let expected: Vec<usize> = (1..=slots.len()).collect();
    let found: Vec<usize> = slots.into_iter().collect();
    if found != expected {
        return Err(categorized_error(
            QuerySqlErrorCategory::InvalidArguments,
            "rule input `?N` placeholders must be exactly ?1..=?N with no gaps",
        ));
    }
    Ok(found)
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

/// E1 M3 function registry: one declaration per Native function, shared by
/// every engine. The validator admits a function only when it is registered
/// here, so a rejection names the same replacement on SQLite, Turso and
/// Postgres; the per-engine `engines` capability is what E5's router will read
/// rather than maintaining its own allowlist. `like` is intentionally
/// absent: it is an operator on Postgres (`~~`) and a function-form entry
/// at the engines' own call sites. `round` is admitted with one argument
/// only; two or more arguments are rejected by the arity check in
/// `validate_portable_calls`. `regexp` is admitted with exactly two
/// arguments (`pattern`, `haystack`); literal patterns are additionally
/// checked against the portable subset by `check_regexp_call` (arity,
/// length cap, ASCII, shared constructs). `now_ms` is admitted with zero
/// arguments only: the engines never execute it by name — each execution
/// path captures one Native-supplied millisecond value per statement and
/// binds it as a hidden parameter — so the arity check in `check_call`
/// runs under both allowances. `utc_date_label` is admitted with exactly
/// one argument (Native e25665c): an integer millisecond-since-Unix-epoch
/// value rendered as English `DDD D MMM` in UTC (Sunday weekday zero, no
/// year, no leading day zero, NULL in NULL out); the engines never execute
/// it by name — each execution path lowers it to engine-native date
/// primitives — so its arity check also runs under both allowances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionKind {
    /// Pure deterministic computation executed by the engine itself.
    Scalar,
    /// Server-supplied value bound as a hidden parameter, never executed by
    /// the engine under its own name. A future `current_principal()` is a
    /// second member of this class, not a special case.
    ContextInput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionDecl {
    /// Lowercase canonical name, matched case-insensitively.
    pub name: &'static str,
    pub kind: FunctionKind,
    /// Engine profiles implementing this function.
    pub engines: &'static [QuerySqlProfile],
    /// True when the result depends on something other than stored data, so
    /// consumers (live tabs, caches) must re-run on a clock tick as well as
    /// on data change. Carried on the result beside the stamp.
    pub time_dependent: bool,
}

/// Default capability: engines declared to execute the function — proven
/// where runtime evidence exists, otherwise explicitly tracked as owed
/// below. A new row narrows this whenever an engine genuinely lacks the
/// function — never mark an engine supported without runtime proof or an
/// explicit owed-proof note.
const ALL_ENGINE_PROFILES: &[QuerySqlProfile] = &[
    QuerySqlProfile::SqliteLocal,
    QuerySqlProfile::PostgresServer,
    QuerySqlProfile::TursoLocal,
];

/// Window-function capability, honestly scoped. Exact-0.8.0 evidence
/// (task 3333335 parity probe): the engine resolves all six names but
/// compiles every window program as non-read-only, refused by the isolated
/// query-only projection — so TursoLocal is excluded here, and the Turso
/// gate (`src/query/turso_validate.rs`) refuses the six names with that
/// precise repair. SQLite executes window functions, but the tie-safe
/// corpus case proving identical answers is still owed to M4; Postgres
/// implements them, but end-to-end execution proof is owed to M4
/// follow-on #2 (full PG corpus). `is_portable_function` stays true for
/// all 24 names on every profile; per-engine routing consults
/// `function_supported_on`.
const SQLITE_AND_POSTGRES: &[QuerySqlProfile] = &[
    QuerySqlProfile::SqliteLocal,
    QuerySqlProfile::PostgresServer,
];

/// The registry itself: exactly the portable subset, one row per function.
pub const FUNCTION_REGISTRY: &[FunctionDecl] = &[
    FunctionDecl {
        name: "abs",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "avg",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "coalesce",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "count",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "cume_dist",
        kind: FunctionKind::Scalar,
        engines: SQLITE_AND_POSTGRES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "dense_rank",
        kind: FunctionKind::Scalar,
        engines: SQLITE_AND_POSTGRES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "length",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "lower",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "max",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "min",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "now_ms",
        kind: FunctionKind::ContextInput,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: true,
    },
    FunctionDecl {
        name: "ntile",
        kind: FunctionKind::Scalar,
        engines: SQLITE_AND_POSTGRES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "nullif",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "percent_rank",
        kind: FunctionKind::Scalar,
        engines: SQLITE_AND_POSTGRES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "rank",
        kind: FunctionKind::Scalar,
        engines: SQLITE_AND_POSTGRES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "regexp",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "replace",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "round",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "row_number",
        kind: FunctionKind::Scalar,
        engines: SQLITE_AND_POSTGRES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "substr",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "sum",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "trim",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "upper",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
    FunctionDecl {
        name: "utc_date_label",
        kind: FunctionKind::Scalar,
        engines: ALL_ENGINE_PROFILES,
        time_dependent: false,
    },
];

const PORTABLE_FUNCTION_NAMES: [&str; 24] = {
    let mut names = [""; 24];
    let mut i = 0;
    while i < FUNCTION_REGISTRY.len() {
        names[i] = FUNCTION_REGISTRY[i].name;
        i += 1;
    }
    names
};

// Fail closed at compile time if the registry grows or shrinks: shrinkage
// would otherwise leave trailing `""` phantoms in the derived list.
const _: [(); 24] = [(); FUNCTION_REGISTRY.len()];

/// I2 (E1 M2 portability validator): the portable function names, derived
/// from [`FUNCTION_REGISTRY`] so the two can never drift apart.
pub const PORTABLE_FUNCTIONS: &[&str] = &PORTABLE_FUNCTION_NAMES;

/// Look up one registered function by name (case-insensitive), for future
/// E5 routing and context-input handling. `None` for unregistered names.
pub fn function_decl(name: &str) -> Option<&'static FunctionDecl> {
    FUNCTION_REGISTRY
        .iter()
        .find(|decl| decl.name.eq_ignore_ascii_case(name))
}

/// True when `name` is registered for `profile`. The Turso validator uses
/// this scope, and E5's router needs no table of its own. Note the
/// six window rows exclude Turso (exact 0.8.0 resolves the names but
/// compiles every window program as non-read-only, refused by the isolated
/// query-only projection); the Turso validator gate consumes this scoping
/// and refuses the six names with the query-only repair.
pub fn function_supported_on(name: &str, profile: QuerySqlProfile) -> bool {
    function_decl(name).is_some_and(|decl| decl.engines.contains(&profile))
}

/// True for registry membership (admission parity across profiles in this
/// slice). Per-engine execution support differs — see
/// [`function_supported_on`]: the six window functions exclude TursoLocal
/// (exact 0.8.0 compiles them non-read-only, refused query-only) even
/// though the shared classifier still accepts them; the Turso validator
/// refuses them with the repair.
/// The SQLite and Turso call sites additionally admit `like`, whose
/// Postgres spelling is the `~~` operator family rather than a function
/// call.
pub fn is_portable_function(name: &str) -> bool {
    function_decl(name).is_some()
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
/// call: dropped names are rejected with their portable replacement,
/// `round` with two or more arguments is rejected with the numeric repair,
/// and `max`/`min` with two or more arguments are rejected with the CASE
/// repair. Anything else (admitted names, unknown names, keywords like
/// `CAST (`)
/// is left for the engines, which keep their own allowlists as defence in
/// depth. `::` casts and `[1:2]`-style colons never reach here as calls.
/// Walk every `name(` call in code (outside strings, comments and quoted
/// identifiers, modulo the CTE/alias exemptions) and invoke `on_call` with
/// the name, the byte offset where the call starts (the opening quote for
/// a quoted/bracketed spelling, else the name itself) and its paren
/// offset. The single discovery site for the portable-call scan, the
/// regexp runtime check, the `now_ms()` hidden-parameter rewrite and the
/// `utc_date_label()` per-engine lowering, so the four can never disagree
/// about where the calls are.
type CallVisitor<'visitor> =
    &'visitor mut dyn FnMut(&str, usize, usize, &ParenIndex, &str, &[u8]) -> Result<()>;

fn scan_calls(statement: &str, profile: QuerySqlProfile, on_call: CallVisitor<'_>) -> Result<()> {
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
                    on_call(
                        &unquote_doubled(&statement[i + 1..end - 1], '"'),
                        i,
                        j,
                        &index,
                        statement,
                        bytes,
                    )?;
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
                    on_call(
                        &unquote_doubled(&statement[i + 1..end - 1], '`'),
                        i,
                        j,
                        &index,
                        statement,
                        bytes,
                    )?;
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
                    on_call(&statement[i + 1..end - 1], i, j, &index, statement, bytes)?;
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
                    on_call(name, start, j, &index, statement, bytes)?;
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

/// Enforce the portable function subset on a classified statement (see
/// `PORTABLE_FUNCTIONS`). The `regexp` shape rule and the `now_ms` /
/// `utc_date_label` arity rules run under both allowances — a stored
/// definition predating the registry must still carry a portable shape —
/// while the dropped-name, `round`-arity and `max`/`min`-arity rejections
/// stay new-SQL-only.
fn validate_portable_calls(
    profile: QuerySqlProfile,
    statement: &str,
    allowance: FunctionAllowance,
) -> Result<()> {
    scan_calls(
        statement,
        profile,
        &mut |name, _name_start, paren, index, statement, bytes| {
            check_call(name, paren, index, statement, bytes, allowance)
        },
    )
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
/// repair; `max`/`min` with a top-level comma take the CASE repair;
/// `regexp` takes the arity plus pattern-shape check, and `now_ms`
/// / `utc_date_label` take their arity checks, all of which run under both
/// allowances; everything else belongs to the engines.
fn check_call(
    name: &str,
    paren: usize,
    index: &ParenIndex,
    statement: &str,
    bytes: &[u8],
    allowance: FunctionAllowance,
) -> Result<()> {
    let lower = name.to_ascii_lowercase();
    if lower == "regexp" {
        return check_regexp_call(paren, index, statement, bytes);
    }
    // E1 M3: `now_ms()` takes no arguments. Runs under both allowances (a
    // stored definition predating the registry must still carry the
    // zero-argument shape); the engines never see the name — execution
    // binds one hidden parameter per statement (see
    // `rewrite_now_ms_calls`).
    if lower == "now_ms" {
        return check_now_ms_arity(paren, index, statement);
    }
    // Native e25665c: `utc_date_label(ms)` takes exactly one argument.
    // Runs under both allowances like `now_ms`/`regexp`; the engines never
    // see the name — execution lowers it per engine (see
    // `rewrite_utc_date_label_calls`).
    if lower == "utc_date_label" {
        check_utc_date_label_arity(paren, index, statement)?;
        return check_utc_date_label_arg_shape(paren, index, statement);
    }
    if allowance == FunctionAllowance::LegacySavedSql {
        return Ok(());
    }
    if lower == "round" {
        return check_round_arity(paren, index);
    }
    if lower == "max" || lower == "min" {
        return check_max_min_arity(&lower, paren, index);
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
    /// Top-level comma byte offsets per open paren, so arity checks can
    /// count arguments and locate the first one without rescanning.
    top_commas: HashMap<usize, Vec<usize>>,
}

/// One linear scan with the same literal/comment skipping as the
/// classifiers (Postgres nesting, dollar quotes and `E''` when `nested`).
fn build_paren_index(statement: &str, bytes: &[u8], nested: bool) -> Result<ParenIndex> {
    let mut index = ParenIndex {
        close: HashMap::new(),
        top_comma: HashSet::new(),
        top_commas: HashMap::new(),
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
                    index.top_commas.entry(*top).or_default().push(i);
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

/// `max`/`min` with one argument stay aggregates. Two or more arguments
/// are SQLite's scalar form (Postgres `max`/`min` are aggregate-only), so
/// the portable repair names a CASE expression with explicit NULL handling:
/// SQLite scalar `max` returns NULL if any argument is NULL, while Postgres
/// `greatest` skips NULLs. Runs new-SQL-only like `round`, before the GROUP
/// BY check, so the caller is sent to CASE rather than GROUP BY.
fn check_max_min_arity(lower: &str, paren: usize, index: &ParenIndex) -> Result<()> {
    if !index.close.contains_key(&paren) {
        return Ok(());
    }
    if index.top_comma.contains(&paren) {
        let example = if lower == "max" {
            "CASE WHEN a IS NULL OR b IS NULL THEN NULL WHEN a > b THEN a ELSE b END"
        } else {
            "CASE WHEN a IS NULL OR b IS NULL THEN NULL WHEN a < b THEN a ELSE b END"
        };
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "multi-argument {lower} is not portable — use a CASE expression with explicit NULL handling, e.g. {example} (SQLite scalar {lower} returns NULL if any argument is NULL)"
            ),
        ));
    }
    Ok(())
}

/// E1 M3: the shared arity repair for `now_ms`, used by the classifier and
/// mirrored by the execution-time rewrite so every profile names the same
/// canonical form.
pub const NOW_MS_ARITY_REPAIR: &str =
    "now_ms() takes no arguments — use now_ms() with empty parentheses";

/// `now_ms` admits zero arguments only. A top-level comma, or anything but
/// ASCII whitespace between the parens (a comment there is rejected too —
/// write the bare call), takes the arity repair. An unbalanced tail (no
/// index entry) is left for the engines to syntax-error.
fn check_now_ms_arity(paren: usize, index: &ParenIndex, statement: &str) -> Result<()> {
    let Some(close) = index.close.get(&paren) else {
        return Ok(());
    };
    if index.top_comma.contains(&paren) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            NOW_MS_ARITY_REPAIR,
        ));
    }
    if !statement[paren + 1..*close]
        .bytes()
        .all(|byte| byte.is_ascii_whitespace())
    {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            NOW_MS_ARITY_REPAIR,
        ));
    }
    Ok(())
}

/// E1 M3: count the balanced `now_ms()` calls in a statement (any profile).
/// Discovery is the shared `scan_calls` site, so this can never disagree
/// with the classifier about where the calls are. Arity is enforced here
/// too, so a miscount is impossible: unbalanced tails are left for the
/// engines, anything else with arguments fails with the arity repair.
/// Saved-SQL gates and tabs derive time dependence from this without
/// rewriting or binding anything.
pub fn count_now_ms_calls(profile: QuerySqlProfile, statement: &str) -> Result<usize> {
    let mut count = 0;
    scan_calls(
        statement,
        profile,
        &mut |name, _name_start, paren, index, statement, _bytes| {
            if !name.eq_ignore_ascii_case("now_ms") {
                return Ok(());
            }
            check_now_ms_arity(paren, index, statement)?;
            if index.close.contains_key(&paren) {
                count += 1;
            }
            Ok(())
        },
    )?;
    Ok(count)
}

/// E1 M3: true when a statement uses `now_ms()` and is therefore time
/// dependent — its result changes with the clock as well as with data, so
/// tabs and caches re-run it on a tick, not only on data change.
pub fn statement_uses_now_ms(profile: QuerySqlProfile, statement: &str) -> Result<bool> {
    Ok(count_now_ms_calls(profile, statement)? > 0)
}

/// E1 M3: rewrite every `now_ms()` call to one hidden positional
/// placeholder (e.g. `?7`), returning the rewritten statement and the call
/// count. Every use in one statement shares the same placeholder, so every
/// use sees the single statement-fixed value the execution path binds.
///
/// Discovery is the shared `scan_calls` site and the arity rule is the
/// shared `check_now_ms_arity`, so classifier and rewrite agree by
/// construction. The caller guarantees `hidden_placeholder` is fresh —
/// `?{parameters.len() + 1}` after the exact-set positional check — which
/// is what makes the value unspoofable: no caller text can name it and
/// still pass that check. A post-rewrite rescan fails closed if any
/// balanced `now_ms()` call survived.
pub fn rewrite_now_ms_calls(
    profile: QuerySqlProfile,
    statement: &str,
    hidden_placeholder: &str,
) -> Result<(String, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    scan_calls(
        statement,
        profile,
        &mut |name, name_start, paren, index, statement, _bytes| {
            if !name.eq_ignore_ascii_case("now_ms") {
                return Ok(());
            }
            check_now_ms_arity(paren, index, statement)?;
            if let Some(close) = index.close.get(&paren) {
                spans.push((name_start, close + 1));
            }
            Ok(())
        },
    )?;
    if spans.is_empty() {
        return Ok((statement.to_owned(), 0));
    }
    let mut rewritten = String::with_capacity(statement.len() + spans.len() * 4);
    let mut cursor = 0;
    for (start, end) in &spans {
        rewritten.push_str(&statement[cursor..*start]);
        rewritten.push_str(hidden_placeholder);
        cursor = *end;
    }
    rewritten.push_str(&statement[cursor..]);
    // Fail closed: no balanced `now_ms()` call may survive the rewrite.
    // (Unbalanced tails stay for the engines to syntax-error, as everywhere
    // else in this classifier.)
    let mut survivors = 0;
    scan_calls(
        &rewritten,
        profile,
        &mut |name, _name_start, paren, index, _statement, _bytes| {
            if name.eq_ignore_ascii_case("now_ms") && index.close.contains_key(&paren) {
                survivors += 1;
            }
            Ok(())
        },
    )?;
    if survivors > 0 {
        return Err(categorized_error(
            QuerySqlErrorCategory::Engine,
            "now_ms() rewrite left a call behind — refusing to run",
        ));
    }
    Ok((rewritten, spans.len()))
}

/// Native e25665c: the shared arity repair for `utc_date_label`, used by
/// the classifier and mirrored by the Postgres AST walk so every profile
/// names the same canonical form.
pub const UTC_DATE_LABEL_ARITY_REPAIR: &str =
    "utc_date_label takes exactly one argument: utc_date_label(ms)";

/// Native e25665c: the shared input-type repair for `utc_date_label`. The
/// contract is integer epoch milliseconds: an `*_ms` column, an integer
/// literal, NULL, or a `?N` integer parameter. A single-quoted text literal
/// is rejected here and a `Text`-typed bound placeholder is rejected at
/// execution (`validate_utc_date_label_bound_args`), because the engines
/// fork on text — SQLite coerces `'abc'` to 0 (`Thu 1 Jan`) while Postgres
/// type-errors — so admitting it would claim a parity the engines do not
/// have. Columns, expressions and non-canonical spellings cannot be checked
/// uniformly and stay admitted; passing them non-integer data is outside
/// the portable contract, as is every input outside the supported UTC year
/// range below.
pub const UTC_DATE_LABEL_TYPE_REPAIR: &str =
    "utc_date_label takes integer epoch milliseconds — use an *_ms column, an integer literal, NULL, or a ?N integer parameter";

/// Supported UTC range for `utc_date_label`: 0000-01-01T00:00:00Z through
/// 9999-12-31T23:59:59.999Z, in epoch milliseconds. Inside it every engine
/// labels identically; outside it they diverge — SQLite yields NULL past
/// 9999, Turso keeps labelling (measured `Sat 1 Jan` for 10000-01-01),
/// Postgres raises — so extremes stay out of the shared corpus and out of
/// any parity claim by design.
pub const UTC_DATE_LABEL_MIN_MS: i64 = -62_167_219_200_000;
pub const UTC_DATE_LABEL_MAX_MS: i64 = 253_402_300_799_999;

/// `utc_date_label` admits exactly one argument: a millisecond-since-epoch
/// value. A top-level comma (two or more arguments) or an empty/whitespace
/// argument list (zero arguments) takes the arity repair. An unbalanced
/// tail (no index entry) is left for the engines to syntax-error.
fn check_utc_date_label_arity(paren: usize, index: &ParenIndex, statement: &str) -> Result<()> {
    let Some(close) = index.close.get(&paren) else {
        return Ok(());
    };
    if index.top_comma.contains(&paren) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            UTC_DATE_LABEL_ARITY_REPAIR,
        ));
    }
    if statement[paren + 1..*close]
        .bytes()
        .all(|byte| byte.is_ascii_whitespace())
    {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            UTC_DATE_LABEL_ARITY_REPAIR,
        ));
    }
    Ok(())
}

/// The trimmed single-argument span of a balanced call, or `None` for an
/// unbalanced tail (left for the engines to syntax-error, as everywhere).
fn single_call_argument<'statement>(
    paren: usize,
    index: &ParenIndex,
    statement: &'statement str,
) -> Option<&'statement str> {
    let close = index.close.get(&paren)?;
    Some(statement[paren + 1..*close].trim())
}

/// `utc_date_label` rejects an obvious text literal up front: the engines
/// fork on text (SQLite coerces, Postgres errors), so the repair names the
/// integer contract instead of letting one engine guess. Anything that is
/// not one single-quoted literal — integers, NULL, placeholders, columns,
/// expressions — is left for the engines (and, for `?N`, for
/// `validate_utc_date_label_bound_args`).
fn check_utc_date_label_arg_shape(paren: usize, index: &ParenIndex, statement: &str) -> Result<()> {
    let Some(argument) = single_call_argument(paren, index, statement) else {
        return Ok(());
    };
    if single_quoted_literal(argument).is_some() {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            UTC_DATE_LABEL_TYPE_REPAIR,
        ));
    }
    Ok(())
}

/// Validate bound `?N` arguments to `utc_date_label` against the integer
/// contract, on the values actually bound. Every execution path calls this
/// after the classifier (which admits only non-literal shapes besides the
/// literal it already rejected) and after the positional-argument check (so
/// every `?N` resolves): a `Text`-typed bound value is rejected with the
/// type repair — it is the execution-time twin of the literal check above
/// (`check_utc_date_label_arg_shape`) — while `NULL` in any binding and
/// every non-text binding are admitted. Anything the classifier should
/// have rejected fails closed here too. Call after classification, never
/// instead of it.
pub fn validate_utc_date_label_bound_args(
    profile: QuerySqlProfile,
    statement: &str,
    parameters: &[QuerySqlParameter],
) -> Result<()> {
    scan_calls(
        statement,
        profile,
        &mut |name, _name_start, paren, index, statement, _bytes| {
            if !name.eq_ignore_ascii_case("utc_date_label") {
                return Ok(());
            }
            check_utc_date_label_arity(paren, index, statement)?;
            let Some(argument) = single_call_argument(paren, index, statement) else {
                return Ok(());
            };
            if single_quoted_literal(argument).is_some() {
                return Err(categorized_error(
                    QuerySqlErrorCategory::UnsafeStatement,
                    UTC_DATE_LABEL_TYPE_REPAIR,
                ));
            }
            let Some(digits) = argument.strip_prefix('?') else {
                return Ok(());
            };
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Ok(());
            }
            let position: usize = digits.parse().map_err(|_| {
                categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "utc_date_label placeholder is not a valid parameter index",
                )
            })?;
            let Some(parameter) = position.checked_sub(1).and_then(|at| parameters.get(at)) else {
                return Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "ordered parameters and `?N` placeholders must match exactly",
                ));
            };
            match parameter {
                QuerySqlParameter::Text { value: Some(_) } => Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    UTC_DATE_LABEL_TYPE_REPAIR,
                )),
                _ => Ok(()),
            }
        },
    )
}

/// Which engine family a `utc_date_label` lowering targets. SQLite and
/// Turso share the `strftime(..., 'unixepoch')` spelling (Turso core 0.7.2
/// implements the same date primitives — spiked from its `datetime.rs`);
/// Postgres uses `to_timestamp` + `EXTRACT` with an explicit `AT TIME ZONE
/// 'UTC'` so the session timezone can never fork the label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtcDateLabelEngine {
    Sqlite,
    Postgres,
}

/// Native e25665c: lower every `utc_date_label(arg)` call to an engine
/// expression rendering English `DDD D MMM` in UTC (Sunday weekday zero,
/// no year, no leading day zero, NULL in NULL out).
///
/// Discovery is the shared `scan_calls` site and the arity rule is the
/// shared `check_utc_date_label_arity`, so classifier and rewrite agree by
/// construction. The argument text is embedded verbatim (parenthesised),
/// so `?N`/`$N` placeholders, columns and expressions survive; no new
/// placeholder is introduced, so the caller's exact-set placeholder check
/// still holds after the rewrite. A post-rewrite rescan fails closed if
/// any balanced call survived.
pub fn rewrite_utc_date_label_calls(
    profile: QuerySqlProfile,
    statement: &str,
    engine: UtcDateLabelEngine,
) -> Result<(String, usize)> {
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    scan_calls(
        statement,
        profile,
        &mut |name, name_start, paren, index, statement, _bytes| {
            if !name.eq_ignore_ascii_case("utc_date_label") {
                return Ok(());
            }
            check_utc_date_label_arity(paren, index, statement)?;
            if let Some(close) = index.close.get(&paren) {
                let arg = statement[paren + 1..*close].trim().to_owned();
                spans.push((name_start, close + 1, arg));
            }
            Ok(())
        },
    )?;
    if spans.is_empty() {
        return Ok((statement.to_owned(), 0));
    }
    let mut rewritten = String::with_capacity(statement.len() + spans.len() * 128);
    let mut cursor = 0;
    for (start, end, arg) in &spans {
        rewritten.push_str(&statement[cursor..*start]);
        match engine {
            UtcDateLabelEngine::Sqlite => {
                rewritten.push_str(&sqlite_date_label_expr(arg));
            }
            UtcDateLabelEngine::Postgres => {
                rewritten.push_str(&postgres_date_label_expr(arg));
            }
        }
        cursor = *end;
    }
    rewritten.push_str(&statement[cursor..]);
    let mut survivors = 0;
    scan_calls(
        &rewritten,
        profile,
        &mut |name, _name_start, paren, index, _statement, _bytes| {
            if name.eq_ignore_ascii_case("utc_date_label") && index.close.contains_key(&paren) {
                survivors += 1;
            }
            Ok(())
        },
    )?;
    if survivors > 0 {
        return Err(categorized_error(
            QuerySqlErrorCategory::Engine,
            "utc_date_label() rewrite left a call behind — refusing to run",
        ));
    }
    Ok((rewritten, spans.len()))
}

/// Server default ORDER BY for an unordered top-level LIMIT (ad-hoc `query_sql`).
///
/// When the outermost statement carries `LIMIT` with no top-level `ORDER BY`,
/// the server orders by every output column in projection order instead of
/// refusing. Nested unordered LIMITs (subquery, CTE body, compound arm) keep
/// their refusal; bare `OFFSET` without `LIMIT` and `FETCH` without a `LIMIT`
/// word never trigger this path.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AssumedOrder {
    /// Engine-assigned output labels, in projection order.
    pub columns: Vec<String>,
    /// The injected clause, e.g. `ORDER BY 1, 2`. Ordinals (never aliases),
    /// so duplicate or unnamed output columns cannot mis-resolve.
    pub order_by: String,
    /// Why the default was applied. Always `limit_without_order_by` here.
    pub reason: &'static str,
}

/// Reason carried on every server-assumed ordering in this slice.
pub const ASSUMED_ORDER_REASON: &str = "limit_without_order_by";

/// Depth-0 clause words relevant to the default: whether an `ORDER BY` pair
/// is present, and the byte offset of the last plausible `LIMIT` clause word.
struct TopLevelClauses {
    ordered: bool,
    limit_at: Option<usize>,
}

/// Words that can follow a `LIMIT` word only when that word is a bare
/// identifier rather than the clause (a clause LIMIT is followed by a count
/// expression, `ALL`, a placeholder, or `OFFSET`). `offset` is deliberately
/// absent: `LIMIT n OFFSET m` is the canonical clause shape.
const NON_CLAUSE_FOLLOWERS: [&str; 19] = [
    "from",
    "where",
    "group",
    "having",
    "order",
    "limit",
    "union",
    "intersect",
    "except",
    "join",
    "inner",
    "left",
    "right",
    "full",
    "cross",
    "natural",
    "window",
    "fetch",
    "for",
];

/// Lexically scan depth-0 clause words, skipping string literals, comments
/// and quoted identifiers with the same discipline as `scan_tokens`, and
/// tracking parenthesis depth. Words inside any nesting level (subqueries,
/// CTE bodies, function arguments, window definitions) never decide.
/// Returns `None` when the text does not scan cleanly, so callers fall
/// through to the existing path unchanged.
fn scan_top_level_clauses(profile: QuerySqlProfile, sql: &str) -> Option<TopLevelClauses> {
    let bytes = sql.as_bytes();
    let mut clauses = TopLevelClauses {
        ordered: false,
        limit_at: None,
    };
    let mut depth = 0usize;
    let mut previous_word: Option<String> = None;
    // Pending `LIMIT` candidate: confirmed only once the following depth-0
    // word proves it is the clause rather than a bare identifier.
    let mut pending_limit: Option<usize> = None;
    // Settle a pending candidate against the next depth-0 word (`None` at
    // end of input, where a trailing clause LIMIT is valid).
    let flush_pending =
        |clauses: &mut TopLevelClauses, pending: &mut Option<usize>, next_word: Option<&str>| {
            if let Some(offset) = pending.take() {
                let followed_by_clause =
                    next_word.is_some_and(|word| NON_CLAUSE_FOLLOWERS.contains(&word));
                if !followed_by_clause {
                    clauses.limit_at = Some(offset);
                }
            }
        };
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
                i = block_comment_end(bytes, i, profile == QuerySqlProfile::PostgresServer).ok()?;
            }
            b'e' | b'E'
                if profile == QuerySqlProfile::PostgresServer
                    && bytes.get(i + 1) == Some(&b'\'') =>
            {
                i = quoted_end(bytes, i + 1, b'\'', true).ok()?;
            }
            b'\'' | b'"' => {
                let quote = bytes[i];
                i = quoted_end(bytes, i, quote, false).ok()?;
            }
            b'`' if profile != QuerySqlProfile::PostgresServer => {
                i = quoted_end(bytes, i, b'`', false).ok()?;
            }
            b'[' if profile != QuerySqlProfile::PostgresServer => {
                i = bracket_identifier_end(bytes, i).ok()?;
            }
            b'$' if profile == QuerySqlProfile::PostgresServer => {
                let ident_prev = i > 0
                    && matches!(
                        bytes[i - 1],
                        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$'
                    );
                if !ident_prev {
                    if let Some((delimiter, after)) = dollar_delimiter(sql, i) {
                        let rest = &sql[after..];
                        let end = rest.find(&delimiter)?;
                        i = after + end + delimiter.len();
                        continue;
                    }
                }
                i = placeholder_end(bytes, i).ok()?;
            }
            b'?' | b':' | b'@' | b'$' => {
                i = placeholder_end(bytes, i).ok()?;
            }
            b'(' => {
                depth += 1;
                previous_word = None;
                i += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                previous_word = None;
                i += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if depth == 0 {
                    let word = sql[start..i].to_ascii_lowercase();
                    if word == "order" {
                        // A pending LIMIT before ORDER cannot be the clause:
                        // the clause LIMIT sorts after ORDER BY, never before.
                        pending_limit = None;
                    } else {
                        flush_pending(&mut clauses, &mut pending_limit, Some(word.as_str()));
                    }
                    if word == "by" && previous_word.as_deref() == Some("order") {
                        clauses.ordered = true;
                    }
                    if word == "limit" {
                        pending_limit = Some(start);
                    }
                    previous_word = Some(word);
                } else {
                    previous_word = None;
                }
            }
            _ => i += 1,
        }
    }
    flush_pending(&mut clauses, &mut pending_limit, None);
    Some(clauses)
}

/// True when the text carries a plausible depth-0 `LIMIT` clause word and no
/// depth-0 `ORDER BY`. FETCH-only and bare-OFFSET spellings return false, as
/// do nested-only and already-ordered ones. Lexical counterpart to the
/// engine AST gates; [`apply_default_order`] reuses the same scan, so a
/// true here with usable labels always splices.
pub fn has_top_level_limit(profile: QuerySqlProfile, statement: &str) -> bool {
    scan_top_level_clauses(profile, statement)
        .is_some_and(|scan| !scan.ordered && scan.limit_at.is_some())
}

/// Detect a top-level `LIMIT` without a top-level `ORDER BY` and splice
/// `ORDER BY 1, .., n` (n = `columns.len()`) before the LIMIT word.
///
/// Purely lexical (see `scan_top_level_clauses`). The caller supplies the
/// output labels from the engine's prepare-without-execution seam (which
/// also expands `SELECT *`), and confirms the top-level shape on its own
/// AST before splicing, so keyword-as-identifier and `EXPLAIN` shapes cannot
/// misfire. Returns `None` — fall through to the existing path — when a
/// depth-0 `ORDER BY` is present, no plausible depth-0 `LIMIT` word exists,
/// `columns` is empty, or the text does not scan cleanly.
pub fn apply_default_order(
    profile: QuerySqlProfile,
    statement: &str,
    columns: &[String],
) -> Option<(String, AssumedOrder)> {
    if columns.is_empty() {
        return None;
    }
    let scan = scan_top_level_clauses(profile, statement)?;
    if scan.ordered {
        return None;
    }
    let limit_at = scan.limit_at?;
    let positions = (1..=columns.len())
        .map(|position| position.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let order_by = format!("ORDER BY {positions}");
    let mut rewritten = String::with_capacity(statement.len() + order_by.len() + 1);
    // Trim only spaces and tabs: a trailing newline may close a `--` line
    // comment, and removing it would pull the injected clause inside the
    // comment (commenting out the LIMIT itself).
    rewritten.push_str(statement[..limit_at].trim_end_matches([' ', '\t']));
    rewritten.push(' ');
    rewritten.push_str(&order_by);
    rewritten.push(' ');
    rewritten.push_str(&statement[limit_at..]);
    Some((
        rewritten,
        AssumedOrder {
            columns: columns.to_vec(),
            order_by,
            reason: ASSUMED_ORDER_REASON,
        },
    ))
}

/// SQLite/Turso lowering: `strftime` with the `unixepoch` modifier (UTC by
/// construction) extracts weekday/month/day numbers; `CASE` maps them to
/// fixed English names so locale can never fork the label. Day uses
/// `CAST(... AS INTEGER)` to strip the leading zero. No `ELSE` arm: a NULL
/// argument yields NULL extractions, no `WHEN` matches, and `||` with NULL
/// yields NULL — STRICT NULL in NULL out on every engine. Seconds are
/// `(arg)/1000.0` (REAL division) so negative epochs floor correctly
/// (integer `/` truncates toward zero and would misdate pre-1970 times).
fn sqlite_date_label_expr(arg: &str) -> String {
    let secs = format!("(({arg})/1000.0)");
    format!(
        "(CASE strftime('%w', {secs}, 'unixepoch') WHEN '0' THEN 'Sun' WHEN '1' THEN 'Mon' WHEN '2' THEN 'Tue' WHEN '3' THEN 'Wed' WHEN '4' THEN 'Thu' WHEN '5' THEN 'Fri' WHEN '6' THEN 'Sat' END || ' ' || CAST(strftime('%d', {secs}, 'unixepoch') AS INTEGER) || ' ' || CASE strftime('%m', {secs}, 'unixepoch') WHEN '01' THEN 'Jan' WHEN '02' THEN 'Feb' WHEN '03' THEN 'Mar' WHEN '04' THEN 'Apr' WHEN '05' THEN 'May' WHEN '06' THEN 'Jun' WHEN '07' THEN 'Jul' WHEN '08' THEN 'Aug' WHEN '09' THEN 'Sep' WHEN '10' THEN 'Oct' WHEN '11' THEN 'Nov' WHEN '12' THEN 'Dec' END)"
    )
}

/// Postgres lowering: `to_timestamp` + `EXTRACT` with an explicit
/// `AT TIME ZONE 'UTC'` (a bare `EXTRACT(DOW FROM timestamptz)` would use
/// the session timezone and fork the label). `DOW` is Sunday-zero like
/// `strftime('%w')`; `DAY` needs no zero-strip (numeric); month/day names
/// come from the same fixed-English `CASE` map as SQLite. No `ELSE` arm,
/// so NULL stays NULL through `||` exactly as on SQLite/Turso.
fn postgres_date_label_expr(arg: &str) -> String {
    let ts = format!("(to_timestamp((({arg})/1000.0)) AT TIME ZONE 'UTC')");
    format!(
        "(CASE CAST(EXTRACT(DOW FROM {ts}) AS INTEGER) WHEN 0 THEN 'Sun' WHEN 1 THEN 'Mon' WHEN 2 THEN 'Tue' WHEN 3 THEN 'Wed' WHEN 4 THEN 'Thu' WHEN 5 THEN 'Fri' WHEN 6 THEN 'Sat' END || ' ' || CAST(EXTRACT(DAY FROM {ts}) AS INTEGER) || ' ' || CASE CAST(EXTRACT(MONTH FROM {ts}) AS INTEGER) WHEN 1 THEN 'Jan' WHEN 2 THEN 'Feb' WHEN 3 THEN 'Mar' WHEN 4 THEN 'Apr' WHEN 5 THEN 'May' WHEN 6 THEN 'Jun' WHEN 7 THEN 'Jul' WHEN 8 THEN 'Aug' WHEN 9 THEN 'Sep' WHEN 10 THEN 'Oct' WHEN 11 THEN 'Nov' WHEN 12 THEN 'Dec' END)"
    )
}

/// E1 M3: the portable regexp subset. One table, three engines: SQLite and
/// Turso evaluate with the same `regex` implementation (unified version in
/// the lockfile), Postgres evaluates POSIX ARE via `regexp_like`. Patterns
/// are ASCII-only and combine literals, `.`, `*`, `+`, `?`, `^`, `$`, `\A`,
/// `|`, `(...)`, `(?:...)`, explicit ASCII ranges like `[0-9]`, and `{m,n}`.
/// Excluded: `(?flags)`, named groups, `\p`/`\P` and the Unicode-aware
/// `\d \w \s` (ARE matches ASCII only), `\b` (a backspace in ARE),
/// `\z \Z \m \M` (split support), backreferences, lookaround, and POSIX
/// `[[:...:]]` (locale-dependent on Postgres).
pub const MAX_REGEXP_PATTERN_BYTES: usize = 1024;

/// Shared arity repair for `regexp`, used by the classifier and mirrored by
/// the Postgres AST walk so every profile names the same canonical form.
pub const REGEXP_ARITY_REPAIR: &str =
    "regexp takes exactly two arguments: regexp(pattern, haystack)";

fn regexp_subset_error(detail: impl AsRef<str>) -> crate::QueryError {
    categorized_error(
        QuerySqlErrorCategory::UnsafeStatement,
        format!(
            "regexp pattern is outside the portable subset ({}) — {}",
            "ASCII-only literals, `. * + ? ^ $ \\A | ( ) (?: ) [0-9] {m,n}`",
            detail.as_ref()
        ),
    )
}

/// One portable function shape: the pattern is a single-quoted text
/// literal, a bare `NULL` (NULL in, NULL out on every engine), or a `?N`
/// text parameter. Columns, expressions and non-canonical literal
/// spellings (`E''`, dollar quotes, quoted identifiers, numbers) cannot be
/// checked uniformly, so they are rejected with the repair instead of
/// being silently admitted to diverge per engine.
pub const REGEXP_SHAPE_REPAIR: &str =
    "regexp pattern must be a single-quoted text literal, NULL, or a ?N text parameter — columns, expressions and E''/dollar-quoted spellings are not portable";

/// `regexp` admits exactly two arguments. A single-quoted literal pattern
/// is checked against the portable subset now, with the repair; a `?N`
/// placeholder is admitted for the execution-time value check
/// (`validate_regexp_bound_patterns`); anything else is rejected above.
fn check_regexp_call(
    paren: usize,
    index: &ParenIndex,
    statement: &str,
    bytes: &[u8],
) -> Result<()> {
    let commas = index.top_commas.get(&paren);
    if commas.map(Vec::len) != Some(1) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            REGEXP_ARITY_REPAIR,
        ));
    }
    let Some(argument) = first_call_argument(paren, index, statement, bytes) else {
        // Unbalanced tail: left for the engines to syntax-error.
        return Ok(());
    };
    if let Some(pattern) = single_quoted_literal(argument) {
        check_regexp_pattern(&pattern)?;
        return Ok(());
    }
    if argument.eq_ignore_ascii_case("null") || is_positional_placeholder(argument) {
        return Ok(());
    }
    Err(categorized_error(
        QuerySqlErrorCategory::UnsafeStatement,
        REGEXP_SHAPE_REPAIR,
    ))
}

/// A single `'...'` literal with `''` unescaped, or `None` for anything
/// else — including `'a' || 'b'`, which starts and ends with a quote but is
/// an expression, not one literal. Quote-finding is byte-safe under UTF-8.
fn single_quoted_literal(argument: &str) -> Option<String> {
    let bytes = argument.as_bytes();
    if bytes.first() != Some(&b'\'') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            if i + 1 == bytes.len() {
                return Some(argument[1..i].replace("''", "'"));
            }
            return None;
        }
        i += 1;
    }
    None
}

/// The trimmed first-argument span of a call, or `None` when the parens
/// are unbalanced (the engines syntax-error those).
fn first_call_argument<'statement>(
    paren: usize,
    index: &ParenIndex,
    statement: &'statement str,
    bytes: &[u8],
) -> Option<&'statement str> {
    let first_comma = *index.top_commas.get(&paren)?.first()?;
    let mut start = paren + 1;
    while start < first_comma && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = first_comma;
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    Some(&statement[start..end])
}

/// A bare `?N` positional placeholder (the only non-literal pattern shape).
/// The number itself is range-checked against the bound parameters by the
/// existing positional-argument check and again defensively at execution.
fn is_positional_placeholder(argument: &str) -> bool {
    let digits = argument.strip_prefix('?').unwrap_or_default();
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Validate bound `?N` regexp patterns against the same subset and cap as
/// literals, on the values actually bound. Every execution path calls this
/// after the classifier (which admits only literals and `?N`) and after the
/// positional-argument check (so every `?N` resolves): literals are already
/// checked and skipped here; a non-text binding or an out-of-subset text is
/// rejected with the repair; anything the classifier should have rejected
/// fails closed here too. Call after classification, never instead of it.
pub fn validate_regexp_bound_patterns(
    profile: QuerySqlProfile,
    statement: &str,
    parameters: &[QuerySqlParameter],
) -> Result<()> {
    scan_calls(
        statement,
        profile,
        &mut |name, _name_start, paren, index, statement, bytes| {
            if !name.eq_ignore_ascii_case("regexp") {
                return Ok(());
            }
            let commas = index.top_commas.get(&paren);
            if commas.map(Vec::len) != Some(1) {
                return Err(categorized_error(
                    QuerySqlErrorCategory::UnsafeStatement,
                    REGEXP_ARITY_REPAIR,
                ));
            }
            let Some(argument) = first_call_argument(paren, index, statement, bytes) else {
                return Ok(());
            };
            if single_quoted_literal(argument).is_some() || argument.eq_ignore_ascii_case("null") {
                return Ok(());
            }
            let digits = argument.strip_prefix('?').unwrap_or_default();
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(categorized_error(
                    QuerySqlErrorCategory::UnsafeStatement,
                    REGEXP_SHAPE_REPAIR,
                ));
            }
            let position: usize = digits.parse().map_err(|_| {
                categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "regexp pattern placeholder is not a valid parameter index",
                )
            })?;
            let Some(parameter) = position.checked_sub(1).and_then(|at| parameters.get(at)) else {
                return Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "ordered parameters and `?N` placeholders must match exactly",
                ));
            };
            match parameter {
                QuerySqlParameter::Text { value: None } => Ok(()),
                QuerySqlParameter::Text { value: Some(text) } => check_regexp_pattern(text),
                _ => Err(categorized_error(
                    QuerySqlErrorCategory::InvalidArguments,
                    "regexp pattern parameter must be text (or NULL)",
                )),
            }
        },
    )
}

/// Check one literal pattern against the portable subset.
fn check_regexp_pattern(pattern: &str) -> Result<()> {
    if pattern.len() > MAX_REGEXP_PATTERN_BYTES {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "regexp pattern exceeds the {MAX_REGEXP_PATTERN_BYTES}-byte portable cap — shorten the pattern or compute client-side"
            ),
        ));
    }
    if !pattern.is_ascii() {
        return Err(regexp_subset_error(
            "patterns must be ASCII-only so every engine matches the same bytes",
        ));
    }
    // Flag, named-group, POSIX-class and split-support escape syntax,
    // skipped over escapes so a literal backslash (`\\(`) cannot hide or
    // fake a group opening. The escaped character itself is inspected:
    // `\z \Z \m \M` mean different things (or nothing) across engines.
    let raw = pattern.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            match raw.get(i + 1) {
                Some(b'z' | b'Z' | b'm' | b'M') => {
                    return Err(regexp_subset_error(
                        "only ^, $ and \\A are portable anchors; \\z \\Z \\m \\M are split across engines",
                    ));
                }
                Some(_) => {
                    i += 2;
                    continue;
                }
                None => {
                    i += 1;
                    continue;
                }
            }
        }
        if raw[i] == b'(' && raw.get(i + 1) == Some(&b'?') && raw.get(i + 2) != Some(&b':') {
            return Err(regexp_subset_error(
                "only (?:...) non-capturing groups are portable; (?flags) and (?P<name>) differ on Postgres",
            ));
        }
        if raw[i] == b'[' && raw.get(i + 1) == Some(&b'[') && raw.get(i + 2) == Some(&b':') {
            return Err(regexp_subset_error(
                "POSIX [[:...:]] classes are locale-dependent on Postgres; spell out the ranges instead",
            ));
        }
        i += 1;
    }
    let ast = regex_syntax::ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|error| regexp_subset_error(error.to_string()))?;
    check_regexp_ast(&ast)
}

/// Walk one bracketed class set: flat unions of ASCII literals and ranges
/// only. Negation (`[^...]`) is fine — both engines complement the same
/// ASCII set — but nesting, POSIX/Unicode/Perl classes and set operations
/// are rejected. The catch-all keeps future syntax failing closed.
fn check_regexp_class_set(set: &regex_syntax::ast::ClassSet) -> Result<()> {
    use regex_syntax::ast::{ClassSet, ClassSetItem};
    match set {
        ClassSet::Item(item) => match item {
            ClassSetItem::Empty(_)
            | ClassSetItem::Literal(_)
            | ClassSetItem::Range(_) => Ok(()),
            ClassSetItem::Union(union) => union
                .items
                .iter()
                .try_for_each(check_regexp_class_item),
            _ => Err(regexp_subset_error(
                "nested or POSIX classes inside [...] are not portable; spell out ASCII literals and ranges",
            )),
        },
        ClassSet::BinaryOp(_) => Err(regexp_subset_error(
            "set operations (&&, --, ~~) inside [...] are not portable; spell out ASCII literals and ranges",
        )),
    }
}

/// One member of a class union (see `check_regexp_class_set`).
fn check_regexp_class_item(item: &regex_syntax::ast::ClassSetItem) -> Result<()> {
    use regex_syntax::ast::ClassSetItem;
    match item {
        ClassSetItem::Empty(_)
        | ClassSetItem::Literal(_)
        | ClassSetItem::Range(_) => Ok(()),
        ClassSetItem::Union(union) => union
            .items
            .iter()
            .try_for_each(check_regexp_class_item),
        _ => Err(regexp_subset_error(
            "nested or POSIX classes inside [...] are not portable; spell out ASCII literals and ranges",
        )),
    }
}
/// Walk one parsed pattern at the AST level (concrete syntax, so `.` stays
/// `.` instead of desugaring into a non-ASCII class). Rejects what Postgres
/// ARE cannot match the same way: Perl classes (`\d \w \s`, Unicode-aware
/// here but ASCII-only in ARE), `\p` classes, word boundaries (`\b` is a
/// backspace in ARE), named or flag-bearing groups, and huge repetitions.
/// Parse-level rejects (backreferences, bad escapes) already failed above
/// with their message.
fn check_regexp_ast(ast: &regex_syntax::ast::Ast) -> Result<()> {
    use regex_syntax::ast::{AssertionKind, Ast, GroupKind};
    match ast {
        Ast::Empty(_) | Ast::Dot(_) | Ast::Literal(_) => Ok(()),
        Ast::Flags(_) => Err(regexp_subset_error(
            "only (?:...) non-capturing groups are portable; (?flags) differ on Postgres",
        )),
        Ast::Assertion(assertion) => match assertion.kind {
            AssertionKind::StartLine
            | AssertionKind::EndLine
            | AssertionKind::StartText => Ok(()),
            _ => Err(regexp_subset_error(
                "only ^, $ and \\A are portable anchors; \\b \\B \\z and lookaround differ on Postgres",
            )),
        },
        Ast::ClassUnicode(_) | Ast::ClassPerl(_) => Err(regexp_subset_error(
            "Unicode property classes (\\p{...}) and \\d \\w \\s match non-ASCII on this engine but ASCII-only on Postgres; spell out ASCII ranges like [0-9]",
        )),
        Ast::ClassBracketed(class) => check_regexp_class_set(&class.kind),
        Ast::Group(group) => {
            if matches!(group.kind, GroupKind::CaptureName { .. }) {
                return Err(regexp_subset_error(
                    "named groups (?P<name>) are not portable to Postgres; use plain (...) instead",
                ));
            }
            if group.flags().is_some_and(|flags| !flags.items.is_empty()) {
                return Err(regexp_subset_error(
                    "only (?:...) non-capturing groups are portable; (?flags:...) differ on Postgres",
                ));
            }
            check_regexp_ast(&group.ast)
        }
        Ast::Repetition(repetition) => {
            use regex_syntax::ast::{RepetitionKind, RepetitionRange};
            let max = match repetition.op.kind {
                RepetitionKind::Range(RepetitionRange::Exactly(max))
                | RepetitionKind::Range(RepetitionRange::AtLeast(max))
                | RepetitionKind::Range(RepetitionRange::Bounded(_, max)) => Some(max),
                _ => None,
            };
            if max.is_some_and(|max| max > 1_000_000) {
                return Err(regexp_subset_error(
                    "repetition quantities above 1000000 do not compile on every engine",
                ));
            }
            check_regexp_ast(&repetition.ast)
        }
        Ast::Alternation(alternation) => alternation
            .asts
            .iter()
            .try_for_each(check_regexp_ast),
        Ast::Concat(concat) => concat.asts.iter().try_for_each(check_regexp_ast),
    }
}

/// I2: `REPLACE` is both the `REPLACE INTO` / `INSERT OR REPLACE` write
/// and the portable `replace()` string function. Only the write positions
/// are rejected: a leading `REPLACE` (never reached — the statement must
/// start with SELECT or WITH), `REPLACE INTO`, and `INSERT OR REPLACE`.
/// Anywhere else (`SELECT 1 AS replace`, a column named `replace`) the
/// word is data, and the call form `replace(` is admitted by the portable
/// function check.
/// E1 M3: the shared repair for engine keyword clocks. `now_ms()` is the
/// only portable clock: one Native-supplied millisecond value per
/// statement, stamped on the result beside `as_of_seq`.
pub const CLOCK_KEYWORD_REPAIR: &str = "use now_ms() for the current time in milliseconds since the Unix epoch (e.g. WHERE updated_at_ms >= now_ms() - 7*86400000)";

/// E1 M3: deny `CURRENT_DATE`, `CURRENT_TIME` and `CURRENT_TIMESTAMP` as
/// bare keywords (and in call form — the word is a `Word` token either
/// way) with the portable repair. `words` are already lowercased and skip
/// strings, comments and quoted identifiers by construction, so only real
/// keyword uses fail. Bare-word aliases must be quoted instead.
fn reject_clock_keywords(words: &[(String, usize)]) -> Result<()> {
    if let Some((word, _)) = words.iter().find(|(word, _)| {
        matches!(
            word.as_str(),
            "current_date" | "current_time" | "current_timestamp"
        )
    }) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("{word} is unavailable — {CLOCK_KEYWORD_REPAIR}"),
        ));
    }
    Ok(())
}

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
        let listed = unmapped
            .split("Queryable relations on sqlite-local: ")
            .nth(1)
            .expect("profile-filtered relation list");
        let names = listed.trim_end_matches('.').split(", ").collect::<Vec<_>>();
        for relation in [
            "records",
            "body_blocks",
            "my_message_state",
            "my_mentions",
            "effective_relationship_endpoints",
            "catalog_columns",
        ] {
            assert!(
                names.contains(&relation),
                "{relation} absent from {unmapped}"
            );
        }
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
        assert!(!pg_list.contains("body_blocks"), "{pg_list}");
        assert!(!pg_list.contains("my_message_state"), "{pg_list}");
        assert!(
            !pg_list.contains("effective_relationship_endpoints"),
            "{pg_list}"
        );
        assert!(pg_list.contains("body_task_items"), "{pg_list}");
        assert!(pg_list.contains("catalog_columns"), "{pg_list}");
        assert!(blocked_relation_repair("records", SqliteLocal).is_none());
        assert!(blocked_relation_repair("RECORDS", SqliteLocal).is_none());
        assert!(blocked_relation_repair("", SqliteLocal).is_none());
    }

    #[test]
    fn unknown_column_repair_lists_that_relations_columns() {
        use QuerySqlProfile::SqliteLocal;
        let repair =
            unknown_column_repair("titel", &["records"], SqliteLocal).expect("single repair");
        // States only the remedy: no restated engine error.
        assert!(!repair.contains("no such column"), "{repair}");
        assert!(
            repair.starts_with(
                "Hint: valid columns of records are id, type, kind, name, body, home_id, \
                 lifecycle, persistence, maturity, summary, is_current, successor_count \
                 … (21 total). Full list: SELECT column_name FROM catalog_columns \
                 WHERE relation_name = 'records' ORDER BY column_position."
            ),
            "{repair}"
        );
        // Wide relations stay bounded: only the cap is listed.
        assert!(!repair.contains("deleted_at_ms"), "{repair}");
    }

    #[test]
    fn unknown_column_repair_is_profile_aware_and_bounded() {
        use QuerySqlProfile::{PostgresServer, SqliteLocal};
        // sqlite-only relations vanish on Postgres: empty scope falls back
        // to the catalog pointer instead of naming unqueryable columns.
        let pg = unknown_column_repair("message_id", &["messages_awaiting_reply"], PostgresServer)
            .expect("pg fallback");
        assert_eq!(
            pg,
            "Hint: list valid columns with SELECT relation_name, column_name \
             FROM catalog_columns ORDER BY relation_name, column_position."
        );
        // Same scope on SQLite names the columns.
        let lite = unknown_column_repair("message_id", &["messages_awaiting_reply"], SqliteLocal)
            .expect("sqlite repair");
        assert!(
            lite.contains("valid columns of messages_awaiting_reply are message_id"),
            "{lite}"
        );
        // Over-wide scopes fall back rather than growing without bound.
        let wide = unknown_column_repair(
            "titel",
            &["records", "links", "facet_values", "blobs", "vocabularies"],
            SqliteLocal,
        )
        .expect("wide fallback");
        assert_eq!(
            wide,
            "Hint: list valid columns with SELECT relation_name, column_name \
             FROM catalog_columns ORDER BY relation_name, column_position."
        );
        assert!(unknown_column_repair("", &[], SqliteLocal).is_none());
    }

    #[test]
    fn unknown_column_repair_names_every_in_scope_relation() {
        use QuerySqlProfile::SqliteLocal;
        let repair = unknown_column_repair("titel", &["records", "links"], SqliteLocal)
            .expect("join repair");
        assert!(
            repair.starts_with("Hint: 'titel' is not a column of any relation in scope. "),
            "{repair}"
        );
        assert!(!repair.contains("ambiguous"), "{repair}");
        assert!(repair.contains("Valid columns of records are "), "{repair}");
        assert!(repair.contains("valid columns of links are "), "{repair}");
        assert!(
            repair.contains("WHERE relation_name IN ('records', 'links')"),
            "{repair}"
        );
    }

    #[test]
    fn join_detail_repair_reads_as_two_sentences() {
        assert_eq!(
            join_detail_repair("no such column: titel", "Hint: valid columns are id."),
            "no such column: titel. Hint: valid columns are id."
        );
        assert_eq!(
            join_detail_repair(
                "column \"titel\" does not exist",
                "Hint: valid columns are id."
            ),
            "column \"titel\" does not exist. Hint: valid columns are id."
        );
        assert_eq!(
            join_detail_repair("already a sentence.", "Hint: valid columns are id."),
            "already a sentence. Hint: valid columns are id."
        );
        assert_eq!(
            join_detail_repair("trailing colon:", "Hint: valid columns are id."),
            "trailing colon:; Hint: valid columns are id."
        );
    }

    #[test]
    fn unknown_column_repair_worst_case_stays_bounded() {
        use QuerySqlProfile::SqliteLocal;
        let repair = unknown_column_repair(
            "titel",
            &["records", "links", "facet_values", "blobs"],
            SqliteLocal,
        )
        .expect("max accepted scope");
        assert!(repair.len() < 1024, "worst case is {} bytes", repair.len());
    }
    #[test]
    fn unknown_column_in_detail_reads_every_engine_spelling() {
        assert_eq!(
            unknown_column_in_detail("no such column: titel"),
            Some("titel".to_owned())
        );
        assert_eq!(
            unknown_column_in_detail("no such column: r.nme"),
            Some("r.nme".to_owned())
        );
        assert_eq!(
            unknown_column_in_detail("no such column: \"r\".\"nme\""),
            Some("r.nme".to_owned())
        );
        assert_eq!(
            unknown_column_in_detail("column \"titel\" does not exist"),
            Some("titel".to_owned())
        );
        assert_eq!(
            unknown_column_in_detail("column \"r\".\"nme\" does not exist"),
            Some("r.nme".to_owned())
        );
        assert_eq!(unknown_column_in_detail("no such table: records"), None);
        assert_eq!(unknown_column_in_detail("syntax error"), None);
    }

    #[test]
    fn statement_scope_resolves_aliases_and_joins() {
        let scope = statement_scope("SELECT r.nme FROM records r");
        assert_eq!(scope.len(), 1);
        assert_eq!(scope[0].0, "records");
        assert_eq!(scope[0].1.as_deref(), Some("r"));
        assert_eq!(resolve_column_scope("r.nme", &scope), vec!["records"]);
        assert_eq!(resolve_column_scope("records.nme", &scope), vec!["records"]);
        let join =
            statement_scope("SELECT titel FROM records JOIN links ON links.target_id = records.id");
        let names: Vec<&str> = join.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["records", "links"]);
        assert_eq!(resolve_column_scope("titel", &join).len(), 2);
        let comma = statement_scope("SELECT x FROM records a, links AS l");
        assert_eq!(comma.len(), 2);
        assert_eq!(resolve_column_scope("l.id", &comma), vec!["links"]);
        assert_eq!(resolve_column_scope("q.id", &comma).len(), 2);
        let empty = statement_scope("SELECT 1");
        assert!(empty.is_empty());
    }

    #[test]
    fn statement_scope_ignores_strings_and_comments() {
        // `FROM links` inside a string literal or comment is not a target.
        assert_eq!(
            statement_scope("SELECT titel FROM records WHERE note = 'FROM links'"),
            vec![("records".to_owned(), None)]
        );
        assert_eq!(
            statement_scope("SELECT titel FROM records WHERE note = 'it''s FROM links'"),
            vec![("records".to_owned(), None)]
        );
        assert_eq!(
            statement_scope("SELECT titel FROM records /* FROM links */ WHERE id = ?1"),
            vec![("records".to_owned(), None)]
        );
        assert_eq!(
            statement_scope("SELECT titel FROM records -- FROM links\nWHERE id = ?1"),
            vec![("records".to_owned(), None)]
        );
        // Quoted identifiers never act as keywords.
        assert_eq!(
            statement_scope("SELECT \"from\" FROM records"),
            vec![("records".to_owned(), None)]
        );
    }

    #[test]
    fn statement_scope_falls_back_on_ctes_and_subqueries() {
        // A CTE body names `records`, but the outer query reads `recent`:
        // listing `records` columns would be wrong, so the scope is empty.
        assert!(
            statement_scope("WITH recent AS (SELECT id FROM records) SELECT nme FROM recent")
                .is_empty()
        );
        assert!(statement_scope("SELECT nme FROM (SELECT id FROM records) x").is_empty());
        assert!(
            statement_scope("SELECT nme FROM records WHERE id IN (SELECT id FROM links)")
                .is_empty()
        );
        // WITH anywhere (even lowercase-mixed) falls back.
        assert!(statement_scope("with r as (select id from records) select nme from r").is_empty());
    }

    #[test]
    fn statement_scope_handles_case_join_syntax_and_aliases() {
        assert_eq!(
            statement_scope("SELECT TITEL FROM RECORDS"),
            vec![("records".to_owned(), None)]
        );
        let aliased = statement_scope("SELECT R.NME FROM RECORDS AS R");
        assert_eq!(aliased, vec![("records".to_owned(), Some("R".to_owned()))]);
        assert_eq!(resolve_column_scope("r.nme", &aliased), vec!["records"]);
        let left = statement_scope("SELECT titel FROM records LEFT JOIN links USING (target_id)");
        let names: Vec<&str> = left.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["records", "links"]);
        // A comma after a non-logical target still re-arms the FROM list.
        let comma = statement_scope("SELECT nme FROM my_cte, records");
        assert_eq!(comma, vec![("records".to_owned(), None)]);
        let trailing = statement_scope("SELECT nme FROM records, my_cte");
        assert_eq!(trailing, vec![("records".to_owned(), None)]);
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
    fn catalog_card_names_every_relation_and_core_columns() {
        let card = sql_read_catalog_card();
        assert!(
            card.len() <= SQL_READ_CARD_MAX_BYTES,
            "card is {} bytes ({} over the {} budget)",
            card.len(),
            card.len().saturating_sub(SQL_READ_CARD_MAX_BYTES),
            SQL_READ_CARD_MAX_BYTES
        );
        assert!(card.contains("assumed_order"));
        assert!(card.contains("Saved SQL, nested/CTE LIMITs, OFFSET and FETCH"));
        assert!(card.contains("require ORDER BY"));
        assert!(card.contains("page by record_id, block_index, chunk_index"));
        assert!(card.contains("catalog_columns"));
        // The card renders in descriptor prose, never in a SQL batch,
        // so its notes may use semicolons freely.
        for relation in LOGICAL_RELATIONS {
            // Match the line start so a name that prefixes another relation
            // (schema_config, effective_relationships) cannot pass by accident.
            assert!(
                card.contains(&format!("\n{}:", relation.name))
                    || card.contains(&format!("\n{}(", relation.name)),
                "card omits {}",
                relation.name
            );
            assert!(
                CARD_NOTES.iter().any(|(name, _)| *name == relation.name),
                "no card note for {}",
                relation.name
            );
            // Core relations inline their full column list; every other
            // relation is named only, and `catalog_columns` carries its columns.
            let header = format!("{}({})", relation.name, relation.columns.join(","));
            if CARD_COLUMN_RELATIONS.contains(&relation.name) {
                assert!(
                    card.contains(&header),
                    "card omits core columns for {}",
                    relation.name
                );
            } else {
                assert!(
                    !card.contains(&header),
                    "card inlines non-core columns for {}",
                    relation.name
                );
            }
        }
        for name in CARD_COLUMN_RELATIONS {
            assert!(
                LOGICAL_RELATIONS
                    .iter()
                    .any(|relation| relation.name == *name),
                "card-column relation {name} is not a logical relation"
            );
        }
        // A pinned non-core relation: columns reach the agent via `catalog_columns`,
        // not the card.
        assert!(!card.contains("schema_config_json_nodes(config_id,ordinal"));
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
            ("SELECT max(a, b) FROM records", "CASE"),
            ("SELECT min(a, b) FROM records", "CASE"),
            ("SELECT max(a, b, c) FROM records", "CASE"),
            ("SELECT min(a, b, c) FROM records", "CASE"),
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
    fn multi_argument_max_min_names_case_before_group_by() {
        // Native 775605c: `max`/`min` with two or more arguments are
        // SQLite's scalar form, refused before the GROUP BY check with a
        // CASE repair that requires explicit NULL handling. Single-argument
        // aggregates stay admitted, and stored saved SQL keeps the legacy
        // allowance.
        for sql in [
            "SELECT max(1, 2) AS m",
            "SELECT min(1, 2) AS m FROM records",
            "SELECT max(a, b, c) FROM records",
            "SELECT min(a, b, c) FROM records",
            "SELECT id, max(length(name), 5) AS m FROM records WHERE id = ?1",
            "SELECT \"max\"(1, 2) FROM records",
        ] {
            for profile in PROFILES {
                let error = classify_single_read_statement(*profile, sql).unwrap_err();
                let rendered = error.to_string();
                assert!(
                    rendered.contains("CASE"),
                    "{profile:?}: {sql}: missing CASE repair: {rendered}"
                );
                assert!(
                    rendered.contains("NULL"),
                    "{profile:?}: {sql}: missing NULL-handling note: {rendered}"
                );
                assert!(
                    !rendered.contains("GROUP BY"),
                    "{profile:?}: {sql}: misleading GROUP BY: {rendered}"
                );
            }
        }
        for sql in [
            "SELECT max(id) FROM records",
            "SELECT min(id) FROM records",
            "SELECT max(length(name)) FROM records",
            "SELECT MAX(id), MIN(id) FROM records",
            "SELECT 'max(1, 2)' AS value FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
        for sql in [
            "SELECT max(1, 2) AS m",
            "SELECT id, max(length(name), 5) AS m FROM records WHERE id = ?1",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_stored_saved_sql(*profile, sql).is_ok(),
                    "{profile:?} stored: {sql}"
                );
            }
        }
    }

    #[test]
    fn regexp_is_admitted_with_exactly_two_arguments() {
        // E1 M3: the canonical portable form on every profile; `?N`
        // placeholders are admitted for the execution-time value check.
        for sql in [
            "SELECT regexp('a', body) FROM records",
            "SELECT REGEXP('a+', body) FROM records",
            "SELECT regexp(?1, body) FROM records",
            "SELECT \"regexp\"('a', body) FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
        // One portable shape only: columns, expressions and non-canonical
        // literal spellings are rejected with the shape repair instead of
        // being silently admitted to diverge per engine.
        for sql in [
            "SELECT regexp(pattern, body) FROM records",
            "SELECT regexp(lower(name), body) FROM records",
            "SELECT regexp('a' || 'b', body) FROM records",
            "SELECT regexp(123, body) FROM records",
            "SELECT regexp(\"pattern\", body) FROM records",
            "SELECT regexp(E'a+', body) FROM records",
        ] {
            for profile in PROFILES {
                let error = classify_single_read_statement(*profile, sql).unwrap_err();
                assert!(
                    error.to_string().contains("single-quoted text literal"),
                    "{profile:?}: {sql}: {error}"
                );
            }
        }
        // Dollar-quoted patterns reach the shape check on Postgres (where
        // they lex as strings); elsewhere the placeholder scan fails
        // closed first. Either way they are never admitted.
        let error = classify_single_read_statement(
            QuerySqlProfile::PostgresServer,
            "SELECT regexp($$a+$$, body) FROM records",
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("single-quoted text literal"),
            "{error}"
        );
        for (sql, repair) in [
            ("SELECT regexp('a') FROM records", "exactly two arguments"),
            (
                "SELECT regexp('a', body, 'x') FROM records",
                "exactly two arguments",
            ),
            ("SELECT regexp() FROM records", "exactly two arguments"),
        ] {
            for profile in PROFILES {
                let error = classify_single_read_statement(*profile, sql).unwrap_err();
                assert!(
                    error.to_string().contains(repair),
                    "{profile:?}: {sql}: {error}"
                );
            }
        }
    }

    #[test]
    fn regexp_literal_patterns_outside_the_subset_are_rejected() {
        // E1 M3: literal patterns the engines cannot evaluate identically
        // fail here with the subset repair — never silently at runtime.
        for (sql, repair) in [
            (
                "SELECT regexp('a(?=b)', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('(a)\\1', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('\\p{L}+', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('(?i)abc', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('(?P<word>\\w+)', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('a\\b', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('\\d+', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('\\w+', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('a\\z', body) FROM records",
                "outside the portable subset",
            ),
            (
                "SELECT regexp('[[:alpha:]]', body) FROM records",
                "outside the portable subset",
            ),
        ] {
            for profile in PROFILES {
                let error = classify_single_read_statement(*profile, sql).unwrap_err();
                assert!(
                    error.to_string().contains(repair),
                    "{profile:?}: {sql}: {error}"
                );
            }
        }
        // Non-ASCII literals and over-cap literals fail with their own
        // repairs; in-subset literals (incl. ''-escaped quotes) pass.
        for profile in PROFILES {
            let error =
                classify_single_read_statement(*profile, "SELECT regexp('ä', body) FROM records")
                    .unwrap_err();
            assert!(error.to_string().contains("ASCII-only"), "{error}");
            let big = format!("SELECT regexp('{}', body) FROM records", "a".repeat(1025));
            let error = classify_single_read_statement(*profile, &big).unwrap_err();
            assert!(error.to_string().contains("1024-byte"), "{error}");
            for sql in [
                "SELECT regexp('it''s (?:a|b)+[0-9]', body) FROM records",
                "SELECT regexp('^a.c$', body) FROM records",
                "SELECT regexp('[a-z]+@[0-9]{2,4}', body) FROM records",
                "SELECT regexp('\\A[a-z]+', body) FROM records",
            ] {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn regexp_bound_patterns_meet_literal_rules() {
        // E1 M3 repair: every execution path validates bound `?N` patterns
        // against the same subset and cap as literals.
        fn params(values: Vec<QuerySqlParameter>) -> Vec<QuerySqlParameter> {
            values
        }
        let text = |value: Option<&str>| QuerySqlParameter::Text {
            value: value.map(str::to_string),
        };
        for profile in PROFILES {
            validate_regexp_bound_patterns(
                *profile,
                "SELECT regexp(?1, body) FROM records",
                &params(vec![text(Some("^[aB]+$"))]),
            )
            .unwrap();
            validate_regexp_bound_patterns(
                *profile,
                "SELECT regexp(?1, body) FROM records",
                &params(vec![text(None)]),
            )
            .unwrap();
            for (bound, repair) in [
                (text(Some("(?=a)")), "outside the portable subset"),
                (text(Some(&"a".repeat(1025))), "1024-byte"),
                (
                    QuerySqlParameter::Integer {
                        value: Some("3".into()),
                    },
                    "must be text",
                ),
            ] {
                let error = validate_regexp_bound_patterns(
                    *profile,
                    "SELECT regexp(?1, body) FROM records",
                    &params(vec![bound]),
                )
                .unwrap_err();
                assert!(error.to_string().contains(repair), "{profile:?}: {error}");
            }
            // Gapped placeholders fail closed even here (the positional
            // check normally fires first at execution).
            let error = validate_regexp_bound_patterns(
                *profile,
                "SELECT regexp(?2, body) FROM records",
                &params(vec![text(Some("a"))]),
            )
            .unwrap_err();
            assert!(error.to_string().contains("must match exactly"), "{error}");
        }
    }

    #[test]
    fn now_ms_is_admitted_with_empty_parentheses_on_every_profile() {
        // E1 M3: the only portable clock, under both allowances (stored
        // definitions keep working). Casing and whitespace vary; arguments
        // never do.
        for sql in [
            "SELECT now_ms() FROM records",
            "SELECT NOW_MS() FROM records",
            "SELECT Now_Ms( ) FROM records",
            "SELECT now_ms() AS t, now_ms() AS u FROM records",
            "SELECT * FROM records WHERE updated_at_ms >= now_ms() - 7*86400000",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
                assert!(
                    classify_stored_saved_sql(*profile, sql).is_ok(),
                    "{profile:?} stored: {sql}"
                );
                assert!(
                    statement_uses_now_ms(*profile, sql).unwrap(),
                    "{profile:?}: {sql}"
                );
            }
        }
        assert_eq!(
            count_now_ms_calls(QuerySqlProfile::SqliteLocal, "SELECT now_ms(), now_ms()").unwrap(),
            2
        );
        for sql in [
            "SELECT id FROM records",
            "SELECT ?1 FROM records",
            "SELECT 'now_ms()' FROM records",
            "SELECT \"now_ms\" FROM records",
            "-- now_ms()\nSELECT id FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    !statement_uses_now_ms(*profile, sql).unwrap(),
                    "{profile:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn now_ms_with_arguments_is_rejected_with_the_arity_repair() {
        // E1 M3: the clock takes no arguments on any profile, under both
        // allowances.
        for sql in [
            "SELECT now_ms(1) FROM records",
            "SELECT now_ms('x') FROM records",
            "SELECT now_ms(1, 2) FROM records",
            "SELECT now_ms(-- comment\n) FROM records",
        ] {
            for profile in PROFILES {
                for classified in [
                    classify_single_read_statement(*profile, sql),
                    classify_stored_saved_sql(*profile, sql),
                ] {
                    let error = classified.unwrap_err();
                    assert!(
                        error.to_string().contains("takes no arguments"),
                        "{profile:?}: {sql}: {error}"
                    );
                }
                let error = count_now_ms_calls(*profile, sql).unwrap_err();
                assert!(
                    error.to_string().contains("takes no arguments"),
                    "{profile:?}: {sql}: {error}"
                );
            }
        }
    }

    #[test]
    fn keyword_clocks_are_rejected_with_the_portable_repair() {
        // E1 M3: hidden per-engine clocks stay refused — bare, cased, and
        // call-form — under both allowances, with the `now_ms()` repair.
        for sql in [
            "SELECT CURRENT_TIMESTAMP FROM records",
            "SELECT current_date FROM records",
            "SELECT Current_Time FROM records",
            "SELECT CURRENT_TIMESTAMP() FROM records",
            "SELECT * FROM records WHERE created_at > CURRENT_DATE",
        ] {
            for profile in PROFILES {
                for classified in [
                    classify_single_read_statement(*profile, sql),
                    classify_stored_saved_sql(*profile, sql),
                ] {
                    let error = classified.unwrap_err();
                    assert!(
                        error.to_string().contains("now_ms()"),
                        "{profile:?}: {sql}: {error}"
                    );
                }
            }
        }
        // Quoted spellings are identifiers and literals, not keywords.
        for sql in [
            "SELECT 'CURRENT_TIMESTAMP' FROM records",
            "SELECT \"current_date\" FROM records",
            "SELECT 1 AS \"current_timestamp\" FROM records",
            "-- CURRENT_DATE\nSELECT id FROM records",
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
    fn now_ms_rewrite_binds_every_use_to_one_hidden_placeholder() {
        // E1 M3: two uses in one statement share one placeholder, so one
        // bound value fixes both. Caller text, strings, comments and quoted
        // identifiers are untouched.
        let (rewritten, count) = rewrite_now_ms_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT now_ms() AS a, NOW_MS() AS b FROM records WHERE updated_at_ms >= now_ms( ) - ?1",
            "?2",
        )
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(
            rewritten,
            "SELECT ?2 AS a, ?2 AS b FROM records WHERE updated_at_ms >= ?2 - ?1"
        );
        // No clock, no rewrite.
        let (same, count) = rewrite_now_ms_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT id FROM records WHERE id = ?1",
            "?2",
        )
        .unwrap();
        assert_eq!(count, 0);
        assert_eq!(same, "SELECT id FROM records WHERE id = ?1");
        // Literals, comments and quoted identifiers are not calls.
        let (same, count) = rewrite_now_ms_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT 'now_ms()' AS a, \"now_ms\" AS b FROM records -- now_ms()",
            "?1",
        )
        .unwrap();
        assert_eq!(count, 0);
        assert!(same.contains("'now_ms()'"), "{same}");
        // A CTE definition is exempt like every other call scan.
        let (same, count) = rewrite_now_ms_calls(
            QuerySqlProfile::SqliteLocal,
            "WITH now_ms(x) AS (SELECT 1) SELECT * FROM now_ms",
            "?1",
        )
        .unwrap();
        assert_eq!(count, 0);
        assert!(same.contains("WITH now_ms(x)"), "{same}");
        // Arguments fail with the arity repair, never silently.
        let error = rewrite_now_ms_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT now_ms(1) FROM records",
            "?1",
        )
        .unwrap_err();
        assert!(error.to_string().contains("takes no arguments"), "{error}");
    }

    #[test]
    fn default_order_splices_ordinals_before_a_top_level_limit() {
        let columns = |labels: &[&str]| {
            labels
                .iter()
                .map(|label| (*label).to_owned())
                .collect::<Vec<_>>()
        };
        // Plain unordered LIMIT gains every output column in projection order.
        let (rewritten, assumed) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT id, name FROM records LIMIT 10",
            &columns(&["id", "name"]),
        )
        .expect("plain unordered LIMIT rewrites");
        assert_eq!(
            rewritten, "SELECT id, name FROM records ORDER BY 1, 2 LIMIT 10",
            "{rewritten}"
        );
        assert_eq!(assumed.columns, vec!["id".to_owned(), "name".to_owned()]);
        assert_eq!(assumed.order_by, "ORDER BY 1, 2");
        assert_eq!(assumed.reason, ASSUMED_ORDER_REASON);
        // CTE-prefixed statements splice the outer LIMIT only.
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "WITH c AS (SELECT id FROM records LIMIT 5) SELECT id FROM c LIMIT 3",
            &columns(&["id"]),
        )
        .expect("CTE top-level LIMIT rewrites");
        assert_eq!(
            rewritten,
            "WITH c AS (SELECT id FROM records LIMIT 5) SELECT id FROM c ORDER BY 1 LIMIT 3",
            "{rewritten}"
        );
        // Compound top level orders the compound result.
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT id FROM records UNION ALL SELECT id FROM links LIMIT 7",
            &columns(&["id"]),
        )
        .expect("compound LIMIT rewrites");
        assert!(
            rewritten.ends_with("UNION ALL SELECT id FROM links ORDER BY 1 LIMIT 7"),
            "{rewritten}"
        );
        // OFFSET stays after its LIMIT.
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT id FROM records LIMIT 10 OFFSET 4",
            &columns(&["id"]),
        )
        .expect("LIMIT with OFFSET rewrites");
        assert_eq!(
            rewritten, "SELECT id FROM records ORDER BY 1 LIMIT 10 OFFSET 4",
            "{rewritten}"
        );
        // Placeholder LIMIT counts splice the same way.
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT id FROM records WHERE updated_at_ms > ?1 LIMIT ?2",
            &columns(&["id"]),
        )
        .expect("placeholder LIMIT rewrites");
        assert_eq!(
            rewritten, "SELECT id FROM records WHERE updated_at_ms > ?1 ORDER BY 1 LIMIT ?2",
            "{rewritten}"
        );
        // The words LIMIT / ORDER BY inside literals, comments and quoted
        // identifiers never decide.
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT '-- limit' AS x, \"order by\" AS y, id FROM records LIMIT 2",
            &columns(&["x", "y", "id"]),
        )
        .expect("quoted LIMIT/ORDER BY words do not decide");
        assert_eq!(
            rewritten,
            "SELECT '-- limit' AS x, \"order by\" AS y, id FROM records ORDER BY 1, 2, 3 LIMIT 2",
            "{rewritten}"
        );
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "/* ORDER BY id */ SELECT id FROM records -- a limit note\nLIMIT 2",
            &columns(&["id"]),
        )
        .expect("comment LIMIT/ORDER BY words do not decide");
        assert!(
            rewritten.contains("-- a limit note\n ORDER BY 1 LIMIT 2"),
            "{rewritten}"
        );
        // Nested-only unordered LIMITs never rewrite: subquery and CTE body.
        assert!(apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT * FROM (SELECT a FROM t LIMIT 5) s ORDER BY a",
            &columns(&["a"]),
        )
        .is_none());
        assert!(apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "WITH c AS (SELECT a FROM t LIMIT 5) SELECT a FROM c ORDER BY a",
            &columns(&["a"]),
        )
        .is_none());
        // An unordered top level over an unordered nest still splices the
        // outer LIMIT (the nested refusal fires downstream, unchanged).
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT * FROM (SELECT a FROM t LIMIT 5) s LIMIT 3",
            &columns(&["a"]),
        )
        .expect("outer LIMIT splices over an unordered nest");
        assert!(
            rewritten.ends_with("LIMIT 5) s ORDER BY 1 LIMIT 3"),
            "{rewritten}"
        );
        // Already-ordered statements, however cased, never rewrite.
        for sql in [
            "SELECT id FROM records ORDER BY id LIMIT 5",
            "select id from records order by id limit 5",
            "SELECT id FROM records ORDER BY 1 LIMIT 5",
        ] {
            assert!(
                apply_default_order(QuerySqlProfile::SqliteLocal, sql, &columns(&["id"])).is_none(),
                "{sql}"
            );
        }
        // Bare OFFSET without LIMIT, FETCH without a LIMIT word, and empty
        // output columns never rewrite.
        assert!(apply_default_order(
            QuerySqlProfile::PostgresServer,
            "SELECT id FROM records OFFSET 5",
            &columns(&["id"]),
        )
        .is_none());
        assert!(apply_default_order(
            QuerySqlProfile::PostgresServer,
            "SELECT id FROM t FETCH FIRST 5 ROWS ONLY",
            &columns(&["id"]),
        )
        .is_none());
        assert!(apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT id FROM records LIMIT 5",
            &[],
        )
        .is_none());
        // A bare `limit` identifier without a clause LIMIT never rewrites;
        // with a clause it splices at the clause (the engine AST confirms
        // the shape before splicing, so this is belt and braces).
        assert!(apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT limit FROM t",
            &columns(&["limit"]),
        )
        .is_none());
        let (rewritten, _) = apply_default_order(
            QuerySqlProfile::SqliteLocal,
            "SELECT limit FROM t LIMIT 3",
            &columns(&["limit"]),
        )
        .expect("clause LIMIT splices past a same-named identifier");
        assert_eq!(
            rewritten, "SELECT limit FROM t ORDER BY 1 LIMIT 3",
            "{rewritten}"
        );
    }

    #[test]
    fn utc_date_label_is_admitted_with_exactly_one_argument_on_every_profile() {
        // Native e25665c: the portable UTC date label, under both
        // allowances. Casing and whitespace vary; arity never does.
        for sql in [
            "SELECT utc_date_label(0) FROM records",
            "SELECT UTC_DATE_LABEL(created_at_ms) FROM records",
            "SELECT Utc_Date_Label( updated_at_ms ) FROM records",
            "SELECT utc_date_label(?1) FROM records",
            "SELECT utc_date_label(NULL) FROM records",
            "SELECT utc_date_label(utc_date_label(0)) FROM records",
        ] {
            for profile in PROFILES {
                assert!(
                    classify_single_read_statement(*profile, sql).is_ok(),
                    "{profile:?}: {sql}"
                );
                assert!(
                    classify_stored_saved_sql(*profile, sql).is_ok(),
                    "{profile:?} stored: {sql}"
                );
            }
        }
        // Quoted spellings are identifiers and literals, not calls.
        for sql in [
            "SELECT 'utc_date_label(0)' FROM records",
            "SELECT \"utc_date_label\" FROM records",
            "-- utc_date_label(0)\nSELECT id FROM records",
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
    fn utc_date_label_arity_is_exact_on_every_profile() {
        // Native e25665c: zero or two-plus arguments fail with the arity
        // repair on every profile, under both allowances; the rewrite agrees.
        for sql in [
            "SELECT utc_date_label() FROM records",
            "SELECT utc_date_label( ) FROM records",
            "SELECT utc_date_label(1, 2) FROM records",
            "SELECT utc_date_label(1,2,3) FROM records",
        ] {
            for profile in PROFILES {
                for classified in [
                    classify_single_read_statement(*profile, sql),
                    classify_stored_saved_sql(*profile, sql),
                ] {
                    let error = classified.unwrap_err();
                    assert!(
                        error.to_string().contains("exactly one argument"),
                        "{profile:?}: {sql}: {error}"
                    );
                }
                for engine in [UtcDateLabelEngine::Sqlite, UtcDateLabelEngine::Postgres] {
                    let error = rewrite_utc_date_label_calls(*profile, sql, engine).unwrap_err();
                    assert!(
                        error.to_string().contains("exactly one argument"),
                        "{profile:?}: {sql}: {error}"
                    );
                }
            }
        }
    }

    #[test]
    fn utc_date_label_rejects_text_literal_and_text_bound_arguments() {
        // Native e25665c follow-on: the integer contract is enforced where
        // the value is visible — a single-quoted literal fails at
        // classification, a `Text`-typed bound placeholder fails at
        // execution validation — because the engines fork on text (SQLite
        // coerces, Postgres errors). Integers, NULL, columns and integer
        // bounds stay admitted.
        for sql in [
            "SELECT utc_date_label('abc') FROM records",
            "SELECT utc_date_label('123') FROM records",
            "SELECT UTC_DATE_LABEL('') FROM records",
        ] {
            for profile in PROFILES {
                for classified in [
                    classify_single_read_statement(*profile, sql),
                    classify_stored_saved_sql(*profile, sql),
                ] {
                    let error = classified.unwrap_err();
                    assert!(
                        error.to_string().contains("integer epoch milliseconds"),
                        "{profile:?}: {sql}: {error}"
                    );
                }
            }
        }
        // Bound values: `Text` with content is refused; NULL in any binding
        // and every non-text binding are admitted.
        let bound = |sql: &str, parameters: Vec<QuerySqlParameter>| {
            validate_utc_date_label_bound_args(QuerySqlProfile::SqliteLocal, sql, &parameters)
        };
        let error = bound(
            "SELECT utc_date_label(?1) FROM records",
            vec![QuerySqlParameter::Text {
                value: Some("abc".into()),
            }],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("integer epoch milliseconds"),
            "{error}"
        );
        for parameters in [
            vec![QuerySqlParameter::Integer {
                value: Some("0".into()),
            }],
            vec![QuerySqlParameter::Integer { value: None }],
            vec![QuerySqlParameter::Text { value: None }],
            vec![QuerySqlParameter::Real { value: Some(0.5) }],
        ] {
            bound("SELECT utc_date_label(?1) FROM records", parameters).unwrap();
        }
    }

    #[test]
    fn utc_date_label_rewrite_lowers_without_survivors_or_placeholders() {
        // Native e25665c: one call becomes an engine expression with no
        // surviving portable name and no new placeholder; literals, comments
        // and quoted forms are untouched.
        let (rewritten, count) = rewrite_utc_date_label_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT utc_date_label(created_at_ms) FROM records WHERE id = ?1",
            UtcDateLabelEngine::Sqlite,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert!(!rewritten.contains("utc_date_label"), "{rewritten}");
        assert!(rewritten.contains("strftime"), "{rewritten}");
        assert!(rewritten.contains("created_at_ms"), "{rewritten}");
        assert!(rewritten.contains("?1"), "{rewritten}");
        let (rewritten, count) = rewrite_utc_date_label_calls(
            QuerySqlProfile::PostgresServer,
            "SELECT utc_date_label($1) FROM records",
            UtcDateLabelEngine::Postgres,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert!(!rewritten.contains("utc_date_label"), "{rewritten}");
        assert!(rewritten.contains("to_timestamp"), "{rewritten}");
        assert!(rewritten.contains("$1"), "{rewritten}");
        // SQLite lowering carries no portable-name survivor and keeps the
        // session-timezone-free UTC spelling.
        let (rewritten, _) = rewrite_utc_date_label_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT utc_date_label(0) FROM records",
            UtcDateLabelEngine::Sqlite,
        )
        .unwrap();
        assert!(rewritten.contains("'unixepoch'"), "{rewritten}");
        // No label, no rewrite.
        let (same, count) = rewrite_utc_date_label_calls(
            QuerySqlProfile::SqliteLocal,
            "SELECT 'utc_date_label(0)' FROM records -- utc_date_label(0)",
            UtcDateLabelEngine::Sqlite,
        )
        .unwrap();
        assert_eq!(count, 0);
        assert!(same.contains("'utc_date_label(0)'"), "{same}");
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
        let actors = relation("actors");
        assert_eq!(actors.identity, "native.query-sql.actors");
        assert_eq!(actors.semantic_version, 1);
        assert!(actors.caller_relative);
        assert_eq!(actors.profiles, &["sqlite-local"]);
        assert_eq!(actors.columns, &["actor", "person_id", "display_name"]);
        let runs = relation("runs");
        assert_eq!(runs.identity, "native.query-sql.runs");
        assert_eq!(runs.semantic_version, 1);
        assert!(runs.caller_relative);
        assert_eq!(runs.completeness, "complete");
        assert_eq!(runs.profiles, &["sqlite-local"]);
        assert_eq!(
            runs.columns,
            &[
                "run_key",
                "principal_person_id",
                "started_at_ms",
                "ended_at_ms",
                "reported_model",
                "reported_client",
                "model_assurance",
            ]
        );
        let run_intents = relation("run_intents");
        assert_eq!(run_intents.identity, "native.query-sql.run-intents");
        assert_eq!(run_intents.semantic_version, 1);
        assert!(run_intents.caller_relative);
        assert_eq!(run_intents.completeness, "best_effort");
        assert_eq!(run_intents.profiles, &["sqlite-local"]);
        assert_eq!(
            run_intents.columns,
            &["run_key", "ordinal", "intent", "declared_at_ms"]
        );
        // No global sequence travels through either relation (a5804e8).
        for column in runs.columns.iter().chain(run_intents.columns) {
            assert!(
                !column.contains("seq") && *column != "activity_id",
                "{column} would leak a global sequence or activity id"
            );
        }
        // D6 (b2583dc): two caller-relative SQLite relations. No column
        // names an account, subject, sequence, version or head, so neither a
        // counter nor another viewer's identity can travel through them.
        for (name, identity, columns) in [
            (
                "my_message_state",
                "native.query-sql.my-message-state",
                &[
                    "message_id",
                    "stage",
                    "unread",
                    "is_own",
                    "mentioned",
                    "flagged",
                    "muted",
                    "archived",
                    "snoozed_until",
                    "snoozed_until_ms",
                    "reactable",
                ][..],
            ),
            (
                "my_mentions",
                "native.query-sql.my-mentions",
                &[
                    "source_id",
                    "source_kind",
                    "via",
                    "own_source",
                    "mentioned_at",
                    "mentioned_at_ms",
                    "seen",
                ][..],
            ),
        ] {
            let contract = relation(name);
            assert_eq!(contract.identity, identity);
            assert_eq!(contract.semantic_version, 1);
            assert!(contract.caller_relative);
            assert_eq!(contract.completeness, "complete");
            assert_eq!(contract.profiles, &["sqlite-local"]);
            assert_eq!(contract.columns, columns);
            for column in contract.columns {
                for forbidden in ["seq", "version", "head", "account", "subject", "actor"] {
                    assert!(
                        !column.contains(forbidden),
                        "{name}.{column} names a {forbidden}"
                    );
                }
            }
        }
        let facet_times = relation("facet_times");
        assert_eq!(facet_times.identity, "native.query-sql.facet-times");
        assert_eq!(facet_times.semantic_version, 1);
        assert!(facet_times.caller_relative);
        assert_eq!(facet_times.profiles, &["sqlite-local"]);
        assert!(
            !facet_times
                .columns
                .iter()
                .any(|column| column.contains("seq")),
            "facet_times exposes no global sequence"
        );
    }

    #[test]
    fn content_events_alone_advances_for_the_honest_local_cursor_name() {
        let content = LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "content_events")
            .unwrap();
        assert_eq!(LOGICAL_CATALOG_REVISION, 4);
        assert_eq!(content.semantic_version, CONTENT_EVENTS_RELATION_VERSION);
        assert_eq!(content.semantic_version, 4);
        assert_eq!(
            content.columns,
            &[
                "local_seq",
                "id",
                "record_id",
                "type",
                "actor",
                "run_key",
                "parent_key",
                "channel_kind",
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
        assert_eq!(contract.revision, 5);
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

    #[test]
    fn bare_scalars_infer_their_tags() {
        let request: QuerySqlRequest = serde_json::from_value(json!({
            "sql": "SELECT ?1, ?2, ?3, ?4, ?5",
            "parameters": ["uuid-value", 42, 1.5, true, null]
        }))
        .expect("bare scalars deserialize");
        assert!(request.validate().is_ok());
        assert!(matches!(
            &request.parameters[0],
            QuerySqlParameter::Text { value: Some(value) } if value == "uuid-value"
        ));
        assert!(matches!(
            &request.parameters[1],
            QuerySqlParameter::Integer { value: Some(value) } if value == "42"
        ));
        assert!(matches!(
            &request.parameters[2],
            QuerySqlParameter::Real { value: Some(value) } if *value == 1.5
        ));
        assert!(matches!(
            &request.parameters[3],
            QuerySqlParameter::Boolean { value: Some(true) }
        ));
        assert!(matches!(
            &request.parameters[4],
            QuerySqlParameter::Text { value: None }
        ));
    }

    #[test]
    fn bare_integers_stay_exact_at_the_i64_edges() {
        let request: QuerySqlRequest = serde_json::from_value(json!({
            "sql": "SELECT ?1, ?2",
            "parameters": [9223372036854775807_i64, -9223372036854775808_i64]
        }))
        .expect("i64 edges deserialize");
        assert!(request.validate().is_ok());
        assert!(matches!(
            &request.parameters[0],
            QuerySqlParameter::Integer { value: Some(value) }
                if value == "9223372036854775807"
        ));
        assert!(matches!(
            &request.parameters[1],
            QuerySqlParameter::Integer { value: Some(value) }
                if value == "-9223372036854775808"
        ));
    }

    #[test]
    fn malformed_entries_name_the_expected_shape_and_index() {
        let array_err = serde_json::from_value::<QuerySqlRequest>(json!({
            "sql": "SELECT ?1, ?2",
            "parameters": ["ok", ["nested"]]
        }))
        .expect_err("array entry must fail");
        let message = array_err.to_string();
        assert!(message.contains("parameters[1]"), "{message}");
        assert!(message.contains("each parameter must be"), "{message}");

        let u64_err = serde_json::from_value::<QuerySqlRequest>(json!({
            "sql": "SELECT ?1",
            "parameters": [18446744073709551615_u64]
        }))
        .expect_err("u64 beyond i64 must fail");
        let message = u64_err.to_string();
        assert!(message.contains("parameters[0]"), "{message}");
        assert!(message.contains("signed 64-bit"), "{message}");

        let missing_value = serde_json::from_value::<QuerySqlRequest>(json!({
            "sql": "SELECT ?1",
            "parameters": [{"type": "text"}]
        }))
        .expect_err("missing value must fail");
        let message = missing_value.to_string();
        assert!(message.contains("parameters[0]"), "{message}");
        assert!(message.contains("missing field `value`"), "{message}");

        let diagnostic = parameters_shape_diagnostic(&json!(["ok", {"nope": true}]))
            .expect("diagnostic names the offender");
        assert!(diagnostic.contains("parameters[1]"), "{diagnostic}");
        assert!(
            diagnostic.contains("each parameter must be"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("\"nope\""), "{diagnostic}");
        assert!(parameters_shape_diagnostic(&json!(["ok", 7])).is_none());
    }

    #[test]
    fn function_registry_covers_exactly_the_prior_portable_names() {
        // E1 M3: the registry table must cover exactly the portable names —
        // the 23 the validator admitted before the registry existed, plus
        // `utc_date_label` (Native e25665c). No removals, no renames.
        // `PORTABLE_FUNCTIONS` is derived from the table, so this pins the
        // table itself.
        let expected = [
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
            "now_ms",
            "ntile",
            "nullif",
            "percent_rank",
            "rank",
            "regexp",
            "replace",
            "round",
            "row_number",
            "substr",
            "sum",
            "trim",
            "upper",
            "utc_date_label",
        ];
        let mut registered: Vec<&str> = FUNCTION_REGISTRY.iter().map(|decl| decl.name).collect();
        registered.sort_unstable();
        assert_eq!(registered, expected, "registry rows");
        let mut derived: Vec<&str> = PORTABLE_FUNCTIONS.to_vec();
        derived.sort_unstable();
        assert_eq!(derived, expected, "derived PORTABLE_FUNCTIONS");
    }

    #[test]
    fn function_registry_names_are_case_insensitively_unique() {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for decl in FUNCTION_REGISTRY {
            assert_eq!(
                decl.name,
                decl.name.to_ascii_lowercase(),
                "registry names stay lowercase"
            );
            assert!(
                seen.insert(decl.name.to_ascii_lowercase()),
                "duplicate registry name: {}",
                decl.name
            );
        }
    }

    #[test]
    fn function_registry_per_engine_availability() {
        // E1 M3 + M4 evidence (1e192ae) recharacterized on exact 0.8.0
        // (task 3333335): the six window functions are NOT Turso-supported
        // (the engine resolves the names but compiles every window program
        // as non-read-only, refused by the isolated query-only projection)
        // and must never be marked so without execution proof; everything
        // else is all-engine (regexp and now_ms proven on all three;
        // aggregates in the shared corpus; `utc_date_label` proven on
        // SQLite+Turso locally with PG runtime proof owed to the
        // postgres-tests vector test in this slice, which CI runs).
        // Admission is deliberately unchanged: `is_portable_function`
        // stays true for all 24 names on every profile in this slice; the
        // Turso validator refuses the six with the query-only repair.
        const WINDOW: [&str; 6] = [
            "cume_dist",
            "dense_rank",
            "ntile",
            "percent_rank",
            "rank",
            "row_number",
        ];
        for decl in FUNCTION_REGISTRY {
            let window = WINDOW.contains(&decl.name);
            assert!(
                function_supported_on(decl.name, QuerySqlProfile::SqliteLocal),
                "{} on SqliteLocal",
                decl.name
            );
            assert!(
                function_supported_on(decl.name, QuerySqlProfile::PostgresServer),
                "{} on PostgresServer",
                decl.name
            );
            assert_eq!(
                function_supported_on(decl.name, QuerySqlProfile::TursoLocal),
                !window,
                "{} on TursoLocal",
                decl.name
            );
            assert!(
                function_supported_on(
                    &decl.name.to_ascii_uppercase(),
                    QuerySqlProfile::SqliteLocal
                ),
                "{} (upper)",
                decl.name
            );
            // Admission unchanged, windows included.
            assert!(is_portable_function(decl.name));
        }
        assert!(!function_supported_on(
            "current_principal",
            QuerySqlProfile::SqliteLocal
        ));
        assert!(function_decl("current_principal").is_none());
        assert!(!is_portable_function("current_principal"));
    }

    #[test]
    fn function_registry_context_input_metadata() {
        let now_ms = function_decl("now_ms").expect("now_ms is registered");
        assert_eq!(now_ms.kind, FunctionKind::ContextInput);
        assert!(now_ms.time_dependent);
        let regexp = function_decl("regexp").expect("regexp is registered");
        assert_eq!(regexp.kind, FunctionKind::Scalar);
        assert!(!regexp.time_dependent);
        // Native e25665c: the date label is a pure scalar — its output
        // depends only on its argument, never on the clock — on all engines.
        let label = function_decl("utc_date_label").expect("utc_date_label is registered");
        assert_eq!(label.kind, FunctionKind::Scalar);
        assert!(!label.time_dependent);
        for profile in PROFILES {
            assert!(
                function_supported_on("utc_date_label", *profile),
                "utc_date_label on {profile:?}"
            );
        }
        // Case-insensitive lookup returns the same declaration.
        assert_eq!(function_decl("NOW_MS"), Some(now_ms));
        // Everything else is a non-time-dependent scalar.
        for decl in FUNCTION_REGISTRY {
            if decl.name == "now_ms" {
                continue;
            }
            assert_eq!(decl.kind, FunctionKind::Scalar, "{}", decl.name);
            assert!(!decl.time_dependent, "{}", decl.name);
        }
        // Admission still agrees with the registry, including casing.
        assert!(is_portable_function("NOW_MS"));
        assert!(is_portable_function("Regexp"));
    }

    #[test]
    fn request_schema_admits_bare_scalars_beside_typed_entries() {
        let schema = request_schema();
        let items = &schema["properties"]["parameters"]["items"]["anyOf"];
        let branches = items.as_array().expect("anyOf branches");
        assert_eq!(branches.len(), 6, "one typed branch plus five bare scalars");
        assert_eq!(
            branches[0]["oneOf"].as_array().expect("typed oneOf").len(),
            7,
            "typed entries keep all seven tags"
        );
        for (branch, kind) in branches
            .iter()
            .zip(["typed", "string", "integer", "number", "boolean", "null"])
        {
            if kind != "typed" {
                assert_eq!(branch["type"], json!(kind), "bare {kind} branch");
            }
        }
    }

    #[test]
    fn placeholder_slots_require_contiguous_ordering() {
        let profile = QuerySqlProfile::SqliteLocal;
        for (sql, expected) in [
            ("SELECT id FROM records", vec![]),
            ("SELECT id FROM records WHERE id = ?1", vec![1]),
            (
                "SELECT id FROM records WHERE id = ?2 OR name = ?1",
                vec![1, 2],
            ),
            ("SELECT id FROM records WHERE id = ?1 OR id = ?1", vec![1]),
        ] {
            let statement = classify_single_read_statement(profile, sql).expect("admitted");
            assert_eq!(
                placeholder_slots(profile, &statement).expect("slots"),
                expected,
                "{sql}"
            );
        }
        for sql in [
            "SELECT id FROM records WHERE id = ?1 OR id = ?3",
            "SELECT id FROM records WHERE id = ?2",
        ] {
            let statement = classify_single_read_statement(profile, sql).expect("admitted");
            assert!(placeholder_slots(profile, &statement).is_err(), "{sql}");
        }
    }

    #[test]
    fn parameter_type_registry_lists_seven_tags() {
        for tag in [
            "boolean",
            "integer",
            "real",
            "text",
            "bytes",
            "json",
            "timestamp",
        ] {
            assert!(parameter_type_known(tag), "{tag}");
        }
        assert!(!parameter_type_known("frob"));
    }
}
