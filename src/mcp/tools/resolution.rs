//! Compact, exact, caller-authorized record-name resolution.
//!
//! `query_record` is intentionally a record retrieval language.  Exact
//! existence checks have a different result contract: one small, positional
//! answer per input, including ambiguity rather than an arbitrary winner.
//! This module owns that semantic batch primitive without routing N copies of
//! `query_record` through the registry.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::{BearerTargetMemo, Capability};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::portable_sql::BorrowedSqliteStatementExecutor;
use crate::schema::{ARCHIVED_FACET_KEY, SPINE_TYPES};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, principal};

const TOOL: &str = "resolve_many";
pub(crate) const MAX_RESOLVE_NAMES: usize = 100;
const MAX_NAME_CHARACTERS: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveManyArgs {
    names: Vec<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
    include_archived: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
struct IdentityMatch {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ResolveManyItem {
    Resolved {
        index: usize,
        input: String,
        #[serde(rename = "match")]
        resolved: IdentityMatch,
    },
    NotFound {
        index: usize,
        input: String,
    },
    Ambiguous {
        index: usize,
        input: String,
        match_count: usize,
        matches: Vec<IdentityMatch>,
    },
    /// Honest absence (`docs/honest-absence-contract.md` §5a). Resolution by
    /// name is exactly where collapsing "not held here" into "not found"
    /// produces a duplicate record, because a caller that fails to resolve a
    /// name is usually about to create it.
    ///
    /// Unreachable until record-level subsets ship; landed early so the
    /// vocabulary precedes anything that can produce it. The allow is the
    /// cost of that: nothing constructs it yet outside the test that pins its
    /// wire form, and that is the intended state rather than an oversight.
    #[allow(dead_code)]
    NotHeld {
        index: usize,
        input: String,
    },
}

/// Authoritative operation schema.  The executor contract should reuse this
/// value rather than projecting a broader query schema.
pub(crate) fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "names": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_RESOLVE_NAMES,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_NAME_CHARACTERS
                },
                "description": "Record names matched by exact code-point equality. Input order and duplicates are preserved."
            },
            "type": {
                "type": "string",
                "enum": SPINE_TYPES,
                "description": "Optional exact spine-type constraint applied to every input."
            },
            "kind": {
                "type": "string",
                "minLength": 1,
                "description": "Optional exact stored kind constraint applied to every input."
            },
            "include_archived": {
                "type": "boolean",
                "description": "Include archived records in matching (default false). Tombstoned records are never candidates."
            }
        },
        "required": ["names"],
        "additionalProperties": false
    })
}

pub(crate) fn register_resolution_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ResolveMany,
        "Resolve a bounded list of exact record names in one caller-authorized snapshot. \
         Returns one compact indexed result per input, distinguishing resolved, not_found, \
         and ambiguous without allowing hidden records to affect visible cardinality. \
         Optional type and kind constrain every input; matching is exact, not lexical or fuzzy.",
        input_schema(),
        resolve_many,
    )
}

/// Resolve a bounded name batch inside one caller-owned SQLite snapshot.
///
/// Candidate discovery is one SQL query over the distinct input set.  The
/// authorization fold retains one bearer-walk memo across every candidate,
/// and only caller-visible ordinary records enter the cardinality used to
/// decide resolved versus ambiguous.  Hidden matches therefore cannot turn a
/// visible singleton into an ambiguity oracle.
pub(crate) async fn resolve_many(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ResolveManyArgs = parse_args(TOOL, arguments)?;
    validate_args(&args)?;

    let mut snapshot = db.write_pool().begin().await?;
    let result = resolve_many_in(&mut snapshot, &caller, &args).await;
    match result {
        Ok(value) => {
            snapshot.rollback().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = snapshot.rollback().await;
            Err(error)
        }
    }
}

fn validate_args(args: &ResolveManyArgs) -> Result<()> {
    if args.names.is_empty() {
        return Err(Error::engine(format!("{TOOL}: 'names' must not be empty")));
    }
    if args.names.len() > MAX_RESOLVE_NAMES {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_RESOLVE_NAMES} names per call"
        )));
    }
    for (index, name) in args.names.iter().enumerate() {
        let characters = name.chars().count();
        if name.is_empty() {
            return Err(Error::engine(format!(
                "{TOOL}: names[{index}] must not be empty"
            )));
        }
        if characters > MAX_NAME_CHARACTERS {
            return Err(Error::engine(format!(
                "{TOOL}: names[{index}] must be at most {MAX_NAME_CHARACTERS} characters"
            )));
        }
    }
    if let Some(record_type) = args.record_type.as_deref() {
        if !SPINE_TYPES.contains(&record_type) {
            return Err(Error::engine(format!(
                "{TOOL}: unknown record type '{record_type}'"
            )));
        }
    }
    if args.kind.as_deref().is_some_and(str::is_empty) {
        return Err(Error::engine(format!("{TOOL}: 'kind' must not be empty")));
    }
    Ok(())
}

async fn resolve_many_in(
    snapshot: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    args: &ResolveManyArgs,
) -> Result<Value> {
    let distinct = args.names.iter().cloned().collect::<BTreeSet<_>>();
    let placeholders = vec!["?"; distinct.len()].join(",");
    let mut sql = format!(
        "SELECT r.id,r.name,r.type,r.kind FROM records r \
         WHERE r.deleted_at IS NULL AND r.name COLLATE BINARY IN ({placeholders})"
    );
    if args.record_type.is_some() {
        sql.push_str(" AND r.type = ?");
    }
    if args.kind.is_some() {
        sql.push_str(" AND r.kind = ?");
    }
    if !args.include_archived.unwrap_or(false) {
        sql.push_str(
            " AND NOT EXISTS (SELECT 1 FROM facet_values archived \
             WHERE archived.record_id = r.id AND archived.key = ?)",
        );
    }
    sql.push_str(" ORDER BY r.name COLLATE BINARY,r.id");

    let mut query = sqlx::query(&sql);
    for name in &distinct {
        query = query.bind(name);
    }
    if let Some(record_type) = args.record_type.as_deref() {
        query = query.bind(record_type);
    }
    if let Some(kind) = args.kind.as_deref() {
        query = query.bind(kind);
    }
    if !args.include_archived.unwrap_or(false) {
        query = query.bind(ARCHIVED_FACET_KEY);
    }
    let rows = query.fetch_all(&mut **snapshot).await?;

    let mut visible_by_name: BTreeMap<String, Vec<IdentityMatch>> = BTreeMap::new();
    let mut authorization_memo = BearerTargetMemo::default();
    for row in rows {
        let id: String = row.try_get("id")?;
        // This is the same ordinary-record admission seam used by get_record:
        // governed attribution records and malformed comments do not become
        // general-purpose resolution candidates.
        if !crate::query::read::ordinary_record_read_eligible_live_in(snapshot, &id).await? {
            continue;
        }
        let visible = {
            let mut executor = BorrowedSqliteStatementExecutor::new(snapshot);
            crate::authorization::allows_record_memoized(
                &mut executor,
                &mut authorization_memo,
                principal(caller),
                &id,
                Capability::View,
            )
            .await?
        };
        if !visible {
            continue;
        }
        let candidate = IdentityMatch {
            id,
            name: row.try_get("name")?,
            record_type: row.try_get("type")?,
            kind: row.try_get("kind")?,
        };
        visible_by_name
            .entry(candidate.name.clone())
            .or_default()
            .push(candidate);
    }

    let mut resolved_count = 0usize;
    let mut not_found_count = 0usize;
    let mut ambiguous_count = 0usize;
    // Never incremented today: a time window leaves the projection complete,
    // so every visible record is held. The counter exists so the shape a
    // caller parses does not change when record-level subsets arrive.
    let not_held_count = 0usize;
    let results = args
        .names
        .iter()
        .enumerate()
        .map(
            |(index, input)| match visible_by_name.get(input).map(Vec::as_slice) {
                Some([resolved]) => {
                    resolved_count += 1;
                    ResolveManyItem::Resolved {
                        index,
                        input: input.clone(),
                        resolved: resolved.clone(),
                    }
                }
                Some(matches) if matches.len() > 1 => {
                    ambiguous_count += 1;
                    ResolveManyItem::Ambiguous {
                        index,
                        input: input.clone(),
                        match_count: matches.len(),
                        matches: matches.to_vec(),
                    }
                }
                _ => {
                    not_found_count += 1;
                    ResolveManyItem::NotFound {
                        index,
                        input: input.clone(),
                    }
                }
            },
        )
        .collect::<Vec<_>>();

    Ok(json!({
        "results": results,
        "counts": {
            "resolved": resolved_count,
            "not_found": not_found_count,
            "ambiguous": ambiguous_count,
            // Disclosed separately from any authorization redaction, per the
            // ratified fork 1 of a42f6e3: "exists, you may not see it" and
            // "exists, this device does not have it" are different facts and a
            // caller may act differently on each. Always 0 until record-level
            // subsets ship.
            "not_held": not_held_count
        },
        "type": args.record_type,
        "kind": args.kind,
        "include_archived": args.include_archived.unwrap_or(false),
        "match": "exact"
    }))
}

#[cfg(test)]
mod honest_absence_tests {
    use super::*;

    /// Pins the wire form of the honest-absence status before anything can
    /// produce it. The point of landing the variant early is that a caller
    /// can be written against it now; that is only true if the shape is
    /// fixed, and only a test fixes it.
    #[test]
    fn not_held_serializes_as_its_own_status() {
        let item = ResolveManyItem::NotHeld {
            index: 2,
            input: "Quarterly plan".into(),
        };
        assert_eq!(
            serde_json::to_value(&item).unwrap(),
            json!({ "status": "not_held", "index": 2, "input": "Quarterly plan" }),
            "not_held is a status of its own, distinguishable from not_found"
        );
    }
}
