//! Backend-neutral presentation rules for `describe_schema`.
//!
//! Physical adapters discover only their own allowlisted Native relations and
//! pass their driver-native column spelling through these helpers. This keeps
//! the public model stable without exposing engine catalog names or unrelated
//! schemas.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{
    CONTROL_PROJECTION_TABLES, DERIVATION_PROJECTION_TABLES, META_PROJECTION_TABLES,
    PROJECTION_TABLES,
};

pub(crate) const AUTHORITY_MODEL: &str = "event-authoritative: content_events is authoritative for content projections; meta_events is authoritative for vocabularies, vocabulary_values, and schema_config; policy_events is authoritative for portable policy; control_events is authoritative for portable control state; projections are replayable and must never be written directly";

pub(crate) fn table_role(table: &str) -> &'static str {
    if matches!(
        table,
        "content_events" | "meta_events" | "policy_events" | "control_events" | "derivation_events"
    ) {
        "authoritative"
    } else if table == "content_event_sources" {
        "authoritative source provenance (immutable companion to content_events)"
    } else if PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from content_events; never write directly)"
    } else if META_PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from meta_events; never write directly)"
    } else if matches!(table, "record_policies" | "policy_entries") {
        "projection (rebuildable from policy_events; never write directly)"
    } else if CONTROL_PROJECTION_TABLES.contains(&table) || table == "control_projections" {
        "projection (rebuildable from control_events; never write directly)"
    } else if DERIVATION_PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from derivation_events; never write directly)"
    } else if table == "blobs" {
        "substrate (byte tier, direct-write by design)"
    } else if table == "bindings" {
        "substrate (durable external-identity mappings, direct-write by design)"
    } else if table == "binding_systems" {
        "substrate (engine-governed identity-system registry)"
    } else if table == "binding_audit" {
        "substrate (append-only binding lifecycle audit)"
    } else if matches!(table, "database_identity" | "database_identity_audit") {
        "substrate (protected portable database identity and append-only lifecycle audit)"
    } else if table == "authorization_revision" {
        "substrate (monotonic authorization cache-invalidation fence)"
    } else if table == "storage_portability_policy" {
        "substrate (portable storage-policy admission state)"
    } else if table == "run_contexts" {
        "substrate (durable run-context state)"
    } else if table == "request_interactions" {
        "substrate (append-only request interaction evidence)"
    } else if matches!(table, "schema_migrations" | "event_cursor" | "log_cursors") {
        "substrate (engine migration and append-position state)"
    } else if matches!(
        table,
        "message_audience"
            | "message_audience_state"
            | "message_audiences"
            | "message_origin_state"
            | "message_origin_principals"
    ) {
        "projection (backend-normalized Message communication state)"
    } else if table.starts_with("records_fts") || table.starts_with("records_name_idx") {
        "derived index (backend-native full-text search over records)"
    } else {
        "substrate (backend-qualified operational state)"
    }
}

fn physical_fallback_type(physical: &str) -> &'static str {
    let physical = physical.to_ascii_lowercase();
    if physical.contains("bool") {
        "BOOLEAN"
    } else if physical.contains("int") || physical == "serial" || physical == "bigserial" {
        "INTEGER"
    } else if physical.contains("real")
        || physical.contains("double")
        || physical.contains("numeric")
        || physical.contains("decimal")
    {
        "REAL"
    } else if physical.contains("blob") || physical.contains("bytea") {
        "BLOB"
    } else if physical.contains("json") {
        "JSON"
    } else if physical.contains("time") || physical.contains("date") {
        "TIMESTAMP"
    } else {
        "TEXT"
    }
}

/// Logical types shared by every qualified `describe_schema` adapter.
///
/// Physical affinity is only a fallback: SQLite-family engines intentionally
/// store booleans, JSON, and timestamps in INTEGER/TEXT carriers, while
/// Postgres has native spellings for each. The table/column identity is the
/// portable contract and therefore wins over the driver's physical spelling.
pub(crate) fn logical_column_type(table: &str, column: &str, physical: &str) -> &'static str {
    if matches!(
        (table, column),
        ("bindings", "is_canonical")
            | ("binding_systems", "stub_allowed")
            | ("binding_systems", "authoritative_provenance")
            | ("binding_systems", "required_durable")
    ) {
        "BOOLEAN"
    } else if matches!(
        (table, column),
        ("content_events", "payload")
            | ("meta_events", "payload")
            | ("policy_events", "payload")
            | ("control_events", "payload")
            | ("facet_values", "value")
            | ("vocabulary_values", "metadata")
            | ("schema_config", "data")
            | ("control_projections", "payload")
            | ("request_interactions", "arguments")
            | ("request_interactions", "run_context")
            | ("storage_portability_policy", "targets")
            | ("storage_portability_policy", "revision_floors")
            | ("storage_portability_policy", "allow_conversions")
    ) {
        "JSON"
    } else if column.ends_with("_at") || column == "as_of" || column == "observed_at" {
        "TIMESTAMP"
    } else {
        physical_fallback_type(physical)
    }
}

/// Cross-engine cells whose semantic carriers deliberately differ.
/// Adapter physical tests assert every one against their live catalog.
pub(crate) const SHARED_LOGICAL_COLUMN_CONTRACT: &[(&str, &str, &str)] = &[
    ("content_events", "payload", "JSON"),
    ("content_events", "created_at", "TIMESTAMP"),
    ("facet_values", "value", "JSON"),
    ("bindings", "is_canonical", "BOOLEAN"),
    ("blobs", "bytes", "BLOB"),
    ("blobs", "size_bytes", "INTEGER"),
    ("vocabulary_values", "ordinal", "REAL"),
    ("vocabulary_values", "metadata", "JSON"),
    ("schema_config", "data", "JSON"),
    ("policy_events", "payload", "JSON"),
    ("storage_portability_policy", "targets", "JSON"),
    ("run_contexts", "updated_at", "TIMESTAMP"),
];

pub(crate) fn shared_logical_contract_holds(tables: &BTreeMap<String, Vec<Value>>) -> bool {
    shared_logical_contract_mismatches(tables).is_empty()
}

pub(crate) fn shared_logical_contract_mismatches(
    tables: &BTreeMap<String, Vec<Value>>,
) -> Vec<String> {
    SHARED_LOGICAL_COLUMN_CONTRACT
        .iter()
        .filter(|(table, column, expected)| {
            !tables.get(*table).is_some_and(|columns| {
                columns
                    .iter()
                    .any(|candidate| candidate["name"] == *column && candidate["type"] == *expected)
            })
        })
        .map(|(table, column, expected)| format!("{table}.{column}:{expected}"))
        .collect()
}

/// Mechanical meaning of the content-log identity and position columns whose
/// physical spelling alone is easy to over-interpret. Sequence values remain
/// useful inside one database, while portable identities and origin-qualified
/// positions retain their meaning across database boundaries.
pub(crate) fn column_semantics(table: &str, name: &str) -> Option<Value> {
    let (semantic_role, portability) = match (table, name) {
        ("content_events", "seq") => ("database_local_replay_position", "non_portable"),
        ("content_events", "id") => ("portable_event_identity", "portable"),
        ("content_event_sources", "source_seq") => {
            ("origin_replay_position", "portable_with_origin_database_id")
        }
        ("content_event_causal_frontier", "parent_event_id") => {
            ("causal_parent_event_identity", "portable")
        }
        _ => return None,
    };
    Some(json!({
        "semantic_role": semantic_role,
        "portability": portability,
    }))
}

pub(crate) fn column(
    table: &str,
    name: String,
    physical_type: String,
    notnull: bool,
    pk: bool,
) -> Value {
    let logical_type = logical_column_type(table, &name, &physical_type);
    let mut value = json!({
        "name": name,
        "type": logical_type,
        "physical_type": physical_type,
        "notnull": notnull,
        "pk": pk,
    });
    if let Some(metadata) = column_semantics(table, value["name"].as_str().unwrap_or_default()) {
        value
            .as_object_mut()
            .expect("column metadata is an object")
            .extend(
                metadata
                    .as_object()
                    .expect("column semantics are an object")
                    .clone(),
            );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "postgres", feature = "turso-local"))]
    #[test]
    fn logical_types_do_not_follow_backend_carrier_spelling() {
        for (table, column, expected) in SHARED_LOGICAL_COLUMN_CONTRACT {
            let postgres = match *expected {
                "BOOLEAN" => "boolean",
                "JSON" => "jsonb",
                "TIMESTAMP" => "timestamp with time zone",
                "BLOB" => "bytea",
                "REAL" => "double precision",
                _ => "bigint",
            };
            let turso = match *expected {
                "BLOB" => "BLOB",
                "REAL" => "REAL",
                "INTEGER" => "INTEGER",
                _ => "TEXT",
            };
            assert_eq!(logical_column_type(table, column, postgres), *expected);
            assert_eq!(logical_column_type(table, column, turso), *expected);
        }
    }

    #[test]
    fn content_event_identity_and_positions_have_mechanical_semantics() {
        for (table, column, role, portability) in [
            (
                "content_events",
                "seq",
                "database_local_replay_position",
                "non_portable",
            ),
            (
                "content_events",
                "id",
                "portable_event_identity",
                "portable",
            ),
            (
                "content_event_sources",
                "source_seq",
                "origin_replay_position",
                "portable_with_origin_database_id",
            ),
            (
                "content_event_causal_frontier",
                "parent_event_id",
                "causal_parent_event_identity",
                "portable",
            ),
        ] {
            let metadata = column_semantics(table, column).unwrap();
            assert_eq!(metadata["semantic_role"], role);
            assert_eq!(metadata["portability"], portability);
        }
        assert!(column_semantics("meta_events", "seq").is_none());
    }
}
