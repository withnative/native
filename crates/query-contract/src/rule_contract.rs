//! Engine-neutral rule-input dependency contract (task 81c1d95, pure slice).
//!
//! Pure types plus the compatibility policy shared by rule admission and
//! invocation and by saved governed SQL: data in, verdict out. No database
//! handles, no I/O, no caller-supplied catalog at runtime — the root crate
//! builds the [`CatalogSnapshot`] from the live catalog (`LOGICAL_RELATIONS`)
//! and the checkers compare pinned requirements against it. Unit tests build
//! synthetic snapshots directly; that constructor is test-only by convention.
//!
//! A rule requirement pins, per input relation: the exact global catalog
//! revision, the exact profile id and revision, the relation identity and
//! semantic version, and the columns read (or population-only for column-less
//! reads such as `COUNT(*)`). Additive catalog changes — relations or columns
//! the rule never pinned — cannot break it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::sql_contract::{categorized_error, QuerySqlErrorCategory};
use crate::Result;

/// Audited SQLite caller-view key proof, not a storage-wide PK assumption.
/// records.id is non-null through its visible-id equijoin; links and facets
/// preserve their NOT NULL UNIQUE composites through unique visibility joins.
/// SQLite TEXT PRIMARY KEY alone permits duplicate NULLs (including links.id).
/// All four pins must match; catalog/profile/proof changes require a new audit.
pub const RULE_ORDER_PROOF_VERSION: u32 = 2;
pub fn rule_stable_unique_keys(
    identity: &str,
    semantic_version: u32,
    profile_id: &str,
    profile_revision: u32,
    proof_version: u32,
) -> Option<&'static [&'static [&'static str]]> {
    if profile_id != "sqlite-local"
        || profile_revision != 1
        || proof_version != RULE_ORDER_PROOF_VERSION
    {
        return None;
    }
    match (identity, semantic_version) {
        ("native.query-sql.records", 1) => Some(&[&["id"]]),
        ("native.query-sql.links", 1) => Some(&[&["source_id", "target_id", "relationship"]]),
        ("native.query-sql.facet-values", 1) => Some(&[&["record_id", "key"]]),
        ("native.query-sql.content-events", 4) => Some(&[&["local_seq"]]),
        _ => None,
    }
}

/// The live catalog as plain data: global breaking revision, serving profile,
/// and every relation the profile serves with its contract metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogSnapshot {
    pub revision: u32,
    pub profile_id: String,
    pub profile_revision: u32,
    pub relations: Vec<RelationSnapshot>,
}

/// One served relation: identity pins survive storage migrations and the name
/// is the caller-visible spelling. `completeness` is descriptive catalog
/// metadata only — the shared structural checker ignores it (saved governed
/// SQL legitimately reads `best_effort` relations); rule-side eligibility is
/// the separate [`check_rule_eligibility`] gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationSnapshot {
    pub identity: String,
    pub name: String,
    pub semantic_version: u32,
    pub columns: Vec<String>,
    pub completeness: String,
    pub profiles: Vec<String>,
}

/// One pinned input relation of a rule read-set. `columns` is the exact set
/// the authoritative extractor observed; `population_only` marks column-less
/// reads (`COUNT(*)`, `EXISTS (SELECT 1 ...)`) that need the relation present
/// but no particular column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedRelation {
    pub identity: String,
    pub name: String,
    pub semantic_version: u32,
    pub columns: BTreeSet<String>,
    pub population_only: bool,
}

/// The authoritative read-set of one rule input statement: pinned relations
/// ordered by name, contiguous `?N` parameter slots (`1..=N`), and whether
/// the statement uses the `now_ms()` hidden time parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInputReadset {
    pub relations: Vec<PinnedRelation>,
    pub parameter_slots: Vec<usize>,
    pub uses_now_ms: bool,
}

/// Global breaking revision: additive changes never bump it (see
/// `LOGICAL_CATALOG_REVISION`), so a mismatch fires only on breaking
/// value-model changes — never silently ignored.
pub fn check_catalog_revision(actual: &CatalogSnapshot, catalog_revision: u32) -> Result<()> {
    if catalog_revision != actual.revision {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "pinned catalog revision {catalog_revision} is incompatible with \
                 the active catalog revision {} (value-model change): re-admit",
                actual.revision
            ),
        ));
    }
    Ok(())
}

/// Exact serving-profile gate: id and revision must equal the live catalog's.
pub fn check_profile_pin(
    actual: &CatalogSnapshot,
    profile_id: &str,
    profile_revision: u32,
) -> Result<()> {
    if profile_id != actual.profile_id || profile_revision != actual.profile_revision {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "pinned profile {profile_id}@{profile_revision} is incompatible with \
                 the active profile {}@{}: re-admit",
                actual.profile_id, actual.profile_revision
            ),
        ));
    }
    Ok(())
}

/// Exact global gate: breaking revision plus serving profile, composed from
/// the two predicates so saved governed SQL and rules share one policy.
pub fn check_catalog_pin(
    actual: &CatalogSnapshot,
    catalog_revision: u32,
    profile_id: &str,
    profile_revision: u32,
) -> Result<()> {
    check_catalog_revision(actual, catalog_revision)?;
    check_profile_pin(actual, profile_id, profile_revision)
}

/// Look a served relation up by caller-visible name. Saved SQL iterates the
/// live catalog (always found); rules resolve extractor-observed names.
pub fn find_relation<'a>(actual: &'a CatalogSnapshot, name: &str) -> Option<&'a RelationSnapshot> {
    actual.relations.iter().find(|r| r.name == name)
}

/// Exact identity/version predicate shared by rules and saved governed SQL.
pub fn check_relation_identity(
    live: &RelationSnapshot,
    identity: &str,
    semantic_version: u32,
) -> Result<()> {
    if live.identity != identity || live.semantic_version != semantic_version {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "relation '{}' identity/version is incompatible with {}@{}",
                live.name, live.identity, live.semantic_version
            ),
        ));
    }
    Ok(())
}

/// Whether the relation is served on the given profile.
pub fn relation_serves_profile(live: &RelationSnapshot, profile_id: &str) -> bool {
    live.profiles.iter().any(|p| p == profile_id)
}

/// Relations whose rows are transient by construction: populated lazily per
/// call and carrying no stable content (a single-column queue drained by
/// evaluation). Deterministic rules cannot depend on them even though the
/// catalog marks them `complete`.
pub const RULE_INELIGIBLE_TRANSIENT: &[&str] = &["messages_awaiting_reply"];

/// Rule-side eligibility over a live relation: refuses `best_effort` and
/// transient relations even if one were ever admitted. This is NOT part of
/// the shared structural pin checker — saved governed SQL keeps reading
/// best-effort relations — rule admission and invocation apply it on top,
/// via extraction and the call gate.
pub fn check_rule_eligibility(live: &RelationSnapshot) -> Result<()> {
    if live.completeness != "complete" {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("rule inputs reject best-effort relation '{}'", live.name),
        ));
    }
    if RULE_INELIGIBLE_TRANSIENT.contains(&live.name.as_str()) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("rule inputs reject transient relation '{}'", live.name),
        ));
    }
    Ok(())
}

/// Per-relation gate against the live catalog, composed from the shared
/// predicates: the named relation must exist, keep its identity and semantic
/// version, remain served on the active profile, and still carry every pinned
/// column. Pinned columns are always checked — even on population-marked pins:
/// an empty set needs presence alone, but any pinned column must exist, so a
/// mixed column+population pin checks all columns. Relations the rule never
/// pinned are ignored, so additive catalog growth is nonbreaking.
pub fn check_relation_pin(actual: &CatalogSnapshot, pinned: &PinnedRelation) -> Result<()> {
    let Some(live) = find_relation(actual, &pinned.name) else {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("rule input relation '{}' is no longer served", pinned.name),
        ));
    };
    check_relation_identity(live, &pinned.identity, pinned.semantic_version)?;
    if !relation_serves_profile(live, &actual.profile_id) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "rule input relation '{}' is unavailable in profile {}",
                pinned.name, actual.profile_id
            ),
        ));
    }
    if let Some(column) = pinned.columns.iter().find(|c| !live.columns.contains(c)) {
        return Err(categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "rule input relation '{}' no longer carries column '{column}'",
                pinned.name
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> CatalogSnapshot {
        CatalogSnapshot {
            revision: 4,
            profile_id: "sqlite-local".to_owned(),
            profile_revision: 1,
            relations: vec![
                RelationSnapshot {
                    identity: "native.query-sql.records".to_owned(),
                    name: "records".to_owned(),
                    semantic_version: 1,
                    columns: vec!["id".to_owned(), "name".to_owned()],
                    completeness: "complete".to_owned(),
                    profiles: vec!["sqlite-local".to_owned()],
                },
                RelationSnapshot {
                    identity: "native.query-sql.links".to_owned(),
                    name: "links".to_owned(),
                    semantic_version: 1,
                    columns: vec!["id".to_owned()],
                    completeness: "complete".to_owned(),
                    profiles: vec!["sqlite-local".to_owned()],
                },
                RelationSnapshot {
                    identity: "native.semantic.agent_activity".to_owned(),
                    name: "agent_activity".to_owned(),
                    semantic_version: 3,
                    columns: vec!["activity_id".to_owned()],
                    completeness: "best_effort".to_owned(),
                    profiles: vec!["sqlite-local".to_owned()],
                },
                RelationSnapshot {
                    identity: "native.query-sql.messages-awaiting-reply".to_owned(),
                    name: "messages_awaiting_reply".to_owned(),
                    semantic_version: 1,
                    columns: vec!["message_id".to_owned()],
                    completeness: "complete".to_owned(),
                    profiles: vec!["sqlite-local".to_owned()],
                },
            ],
        }
    }

    fn pinned(name: &str) -> PinnedRelation {
        PinnedRelation {
            identity: format!("native.query-sql.{name}"),
            name: name.to_owned(),
            semantic_version: 1,
            columns: BTreeSet::from(["id".to_owned()]),
            population_only: false,
        }
    }

    #[test]
    fn catalog_pin_is_exact_but_additive_growth_passes() {
        let live = catalog();
        assert!(check_catalog_pin(&live, 4, "sqlite-local", 1).is_ok());
        assert!(check_catalog_pin(&live, 5, "sqlite-local", 1).is_err());
        assert!(check_catalog_pin(&live, 4, "sqlite-local", 2).is_err());
        assert!(check_catalog_pin(&live, 4, "postgres-server", 1).is_err());
        // Additive growth (a relation the rule never pinned) is nonbreaking:
        // the pinned subset still checks clean against the bigger catalog.
        let mut grown = live.clone();
        grown.relations.push(RelationSnapshot {
            identity: "native.query-sql.actors".to_owned(),
            name: "actors".to_owned(),
            semantic_version: 1,
            columns: vec!["actor".to_owned()],
            completeness: "complete".to_owned(),
            profiles: vec!["sqlite-local".to_owned()],
        });
        assert!(check_catalog_pin(&grown, 4, "sqlite-local", 1).is_ok());
        assert!(check_relation_pin(&grown, &pinned("records")).is_ok());
    }

    #[test]
    fn relation_pin_refuses_breaks_and_keeps_population() {
        let live = catalog();
        assert!(check_relation_pin(&live, &pinned("records")).is_ok());
        // Dropped column refuses; unrelated consumer on other columns passes.
        let mut dropped = pinned("records");
        dropped.columns.insert("gone".to_owned());
        assert!(check_relation_pin(&live, &dropped).is_err());
        // Semantic bump refuses until re-admission.
        let mut bumped = pinned("records");
        bumped.semantic_version = 2;
        assert!(check_relation_pin(&live, &bumped).is_err());
        // Identity change (storage migration renamed the contract) refuses.
        let mut renamed = pinned("records");
        renamed.identity = "native.query-sql.other".to_owned();
        assert!(check_relation_pin(&live, &renamed).is_err());
        // Removed relation refuses.
        assert!(check_relation_pin(&live, &pinned("actors")).is_err());
        // Population-only (COUNT(*)) needs presence alone, no columns.
        let population = PinnedRelation {
            columns: BTreeSet::new(),
            population_only: true,
            ..pinned("links")
        };
        assert!(check_relation_pin(&live, &population).is_ok());
        // Relation withdrawn from this profile refuses.
        let mut moved = live.clone();
        moved.relations[1].profiles = vec!["postgres-server".to_owned()];
        assert!(check_relation_pin(&moved, &pinned("links")).is_err());
        // Mixed column+population pins still check every pinned column.
        let mut mixed = PinnedRelation {
            population_only: true,
            ..pinned("records")
        };
        mixed.columns.insert("gone".to_owned());
        assert!(check_relation_pin(&live, &mixed).is_err());
    }

    #[test]
    fn structural_pins_ignore_completeness_but_eligibility_refuses() {
        let live = catalog();
        // Saved governed SQL legitimately reads best-effort relations: the
        // shared structural checker must NOT reject them.
        let activity = PinnedRelation {
            identity: "native.semantic.agent_activity".to_owned(),
            name: "agent_activity".to_owned(),
            semantic_version: 3,
            columns: BTreeSet::from(["activity_id".to_owned()]),
            population_only: false,
        };
        assert!(check_relation_pin(&live, &activity).is_ok());
        // Rule-side eligibility refuses best-effort AND transient relations,
        // even though the catalog marks the transient one `complete`.
        let live_activity = find_relation(&live, "agent_activity").expect("present");
        assert!(check_rule_eligibility(live_activity).is_err());
        let live_queue = find_relation(&live, "messages_awaiting_reply").expect("present");
        assert!(check_rule_eligibility(live_queue).is_err());
        let live_records = find_relation(&live, "records").expect("present");
        assert!(check_rule_eligibility(live_records).is_ok());
    }
}
