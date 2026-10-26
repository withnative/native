//! Proven type/kind candidate domains; every admitted row keeps the live gate.
use super::{contract::QuerySqlParameter, predicates};
use std::collections::BTreeSet;

pub(super) struct Plan {
    pub predicate: String,
    pub parameters: Vec<String>,
}

pub(super) fn plan(
    statement: &str,
    parameters: &[QuerySqlParameter],
    reads: &BTreeSet<(String, String)>,
) -> Option<Plan> {
    let values = |column| {
        predicates::relation_values(statement, parameters, "records", column)
            .map(|values| values.into_iter().collect::<Vec<_>>())
    };
    let (types, kinds) = (values("type"), values("kind"));
    let (predicate, parameters) = classes(reads, types.as_deref(), kinds.as_deref())?;
    Some(Plan {
        predicate,
        parameters,
    })
}

/// Necessary type/kind sets have already been proved for every physical
/// records scan. A records-only statement can use them before the live gate:
/// no other public relation needs records outside that domain. Currency and
/// placement cells retain full staging because they consult other visible IDs.
fn classes(
    reads: &BTreeSet<(String, String)>,
    types: Option<&[String]>,
    kinds: Option<&[String]>,
) -> Option<(String, Vec<String>)> {
    if super::predicates::full_staging()
        || reads.is_empty()
        || reads.iter().any(|(r, c)| {
            r != "records" || ["home_id", "is_current", "successor_count"].contains(&c.as_str())
        })
    {
        return None;
    }
    let mut filters = Vec::new();
    let mut parameters = Vec::new();
    for (column, field, bound) in [
        ("primary_type", "v1_type", types),
        ("kind", "v1_kind", kinds),
    ] {
        if let Some(bound) = bound {
            parameters.push(serde_json::to_string(bound).ok()?);
            filters.push(format!(
                "(CASE WHEN r.pin_family='{}' AND r.pin_version=1 THEN {} ELSE r.{column} END) IN (SELECT value FROM json_each(?{}))",
                crate::v2_standard::v1_compat::FAMILY,
                super::field(field),
                parameters.len() + 1,
            ));
        }
    }
    (!filters.is_empty()).then(|| (filters.join(" AND "), parameters))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn planned(sql: &str) -> bool {
        let (reads, _) = super::super::guard::inspect_kernel_v2_stored_saved_sql(sql).unwrap();
        plan(sql, &[], &reads).is_some()
    }
    #[test]
    fn only_closed_records_with_bounds_for_every_scan_can_narrow_candidates() {
        for sql in [
            "SELECT count(*) FROM records WHERE type='Annotation' AND kind='comment'",
            "SELECT id FROM records WHERE kind='attachment' OR kind='comment'",
            "SELECT r.id FROM records r WHERE r.type='Document' AND r.type='Message'",
            "SELECT r.id,(SELECT count(*) FROM records s WHERE s.kind='comment') FROM records r WHERE r.kind='task'",
        ] { assert!(planned(sql), "{sql}"); }
        for sql in [
            "SELECT id FROM records",
            "SELECT id FROM records WHERE type='WorkItem' OR name='other'",
            "SELECT r.id,(SELECT count(*) FROM records) FROM records r WHERE r.type='WorkItem'",
            "SELECT id FROM records WHERE type COLLATE NOCASE='WorkItem'",
            "SELECT id,home_id FROM records WHERE type='WorkItem'",
            "SELECT id,is_current FROM records WHERE type='WorkItem'",
            "SELECT id,successor_count FROM records WHERE type='WorkItem'",
            "SELECT r.id,(SELECT count(*) FROM blobs) FROM records r WHERE r.type='WorkItem'",
            "SELECT r.id,(SELECT value FROM facet_values WHERE record_id=r.id AND key='priority') FROM records r WHERE r.type='WorkItem'",
        ] { assert!(!planned(sql), "{sql}"); }
    }
}
