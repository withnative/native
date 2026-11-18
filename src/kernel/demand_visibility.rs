//! Demand-scoped live visibility for finite point reads (design 73ad275 §6,
//! slice S1). The workspace census (`visible_home_anchors_as`) evaluates every
//! home; a finite read needs only the homes its demanded records can depend
//! on. This module loads exactly those homes, walks their parent chains by
//! primary key, loads policy rows for only the anchors it finds, and then runs
//! the census's own evaluator (`evaluate_homes`) over them.
//!
//! There is no stored per-principal state. A home this loader omits is simply
//! absent from the caller's scope table, and the unchanged record predicate
//! treats an absent home as not visible: omission can only under-admit.
//!
//! Callers must fall back to the census whenever this returns
//! [`Demand::Fallback`].
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Demanded records beyond this go to the census. The two served shapes
/// demand one record (plus its logical ancestors, at most the depth cap).
pub(crate) const MAX_DEMANDED: usize = 2 * MAX_HOME_DEPTH + 2;
/// Records reachable through part_of/supersedes from the demanded set.
/// One bearer chain is at most `MAX_DERIVED_BEARER_DEPTH` long; the cap
/// leaves room for a few successors and their chains.
const MAX_CANDIDATES: usize = 4096;

pub(crate) struct DemandScope {
    pub homes: VisibleHomeAnchors,
    /// The rows staging can admit: the demand, its active successors and its
    /// placement dependencies.
    pub staged: Vec<String>,
}

pub(crate) enum Demand {
    Scope(DemandScope),
    /// The census must serve this read. Reason codes are internal only.
    Fallback(&'static str),
}

/// Candidate closure: demanded IDs, active supersedes successors of them,
/// their placement dependencies (`?4`), and every active outgoing part_of
/// chain from those, to the derived-bearer depth cap. Both the derived-bearer
/// rule and the Message guard follow only active outgoing part_of links, so
/// this is a structural superset of the records their predicates read.
/// Bounded by LIMIT so overflow is visible.
const STAGED_SQL: &str = "SELECT value FROM json_each(?1) UNION SELECT l.source_id FROM json_each(?1) d CROSS JOIN main.kernel_generic_links l ON l.target_id=d.value AND l.relationship='supersedes' AND l.active=1 UNION SELECT r.id FROM json_each(?2) d CROSS JOIN main.kernel_records r ON r.id=d.value";
const CANDIDATES_SQL: &str = "WITH RECURSIVE seeds(id) AS (SELECT value FROM json_each(?1) UNION SELECT l.source_id FROM json_each(?1) d CROSS JOIN main.kernel_generic_links l ON l.target_id=d.value AND l.relationship='supersedes' AND l.active=1 UNION SELECT value FROM json_each(?4)), chain(id,depth) AS (SELECT id,0 FROM seeds UNION SELECT l.target_id,c.depth+1 FROM chain c CROSS JOIN main.kernel_generic_links l ON l.source_id=c.id AND l.relationship='part_of' AND l.active=1 WHERE c.depth<?2) SELECT DISTINCT id FROM chain LIMIT ?3";

/// Live, demand-scoped equivalent of `visible_home_anchors_as` for the homes
/// of `candidates`' closure. `dependencies` are the logical-placement
/// candidates the demanded rows' cells can name (records or bare homes);
/// their authority homes are loaded too, and they are staged rows. Returns
/// `Fallback` for any input this path does not cover; never a partial answer.
pub(crate) async fn demand_home_anchors_as(
    conn: &mut SqliteConnection,
    principal: &str,
    demanded: &[String],
    dependencies: &[String],
    root_aliases: demand_root_aliases::State,
) -> Result<Demand> {
    if demanded.is_empty() || demanded.len() > MAX_DEMANDED || dependencies.len() > MAX_DEMANDED {
        return Ok(Demand::Fallback("demand_size"));
    }
    // Folder-scoped apps filter homes through bulk logical placement and a
    // workspace-wide Message closure; both are census-shaped. Keep them there.
    if let Some(scope) = app_installs::scope::active_scope_on(conn, principal).await? {
        if scope.folders().is_some() {
            return Ok(Demand::Fallback("scoped_app"));
        }
    }
    // The special root masking clause can consult a secondary alias outside
    // this demand. Its once-per-generation census runs off the request path.
    if dependencies.iter().any(|id| id == "native:root") {
        let root_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root')",
        )
        .fetch_one(&mut *conn)
        .await?;
        if !root_exists {
            match root_aliases {
                demand_root_aliases::State::NoRecordlessRootAliases => {}
                demand_root_aliases::State::HasAliases => {
                    return Ok(Demand::Fallback("root_secondary_alias"))
                }
                demand_root_aliases::State::Unknown => {
                    return Ok(Demand::Fallback("root_alias_unknown"))
                }
            }
        }
    }
    let candidates: Vec<String> = sqlx::query_scalar(CANDIDATES_SQL)
        .bind(serde_json::to_string(demanded)?)
        .bind(crate::authorization::MAX_DERIVED_BEARER_DEPTH as i64)
        .bind(MAX_CANDIDATES as i64 + 1)
        .bind(serde_json::to_string(dependencies)?)
        .fetch_all(&mut *conn)
        .await?;
    if candidates.len() > MAX_CANDIDATES {
        return Ok(Demand::Fallback("candidate_overflow"));
    }
    let staged: Vec<String> = sqlx::query_scalar(STAGED_SQL)
        .bind(serde_json::to_string(demanded)?)
        .bind(serde_json::to_string(dependencies)?)
        .fetch_all(&mut *conn)
        .await?;
    // The census returns no homes for a caller outside the roster; so does
    // this. Host services bypass the roster exactly as there.
    if !hosted_identity::admitted(conn, principal).await? {
        return Ok(Demand::Scope(DemandScope {
            homes: VisibleHomeAnchors {
                homes: Vec::new(),
                failed_homes: 0,
            },
            staged,
        }));
    }
    // Homes the staged predicate can consult: each candidate's physical home
    // (records, bearers, guard messages, placement dependencies) plus the
    // workspace root, whose visibility the logical-home cell may read, plus
    // any placement dependency that is itself a census home (the cell reads
    // a bare home's own row). Homes with no root row keep a NULL owner, as
    // in the census.
    let mut homes: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT h.home_id,k.owner_id FROM (SELECT DISTINCT r.home_id FROM json_each(?1) c CROSS JOIN main.kernel_records r ON r.id=c.value UNION SELECT ?2 UNION SELECT d.value FROM json_each(?3) d WHERE EXISTS(SELECT 1 FROM main.kernel_roots k WHERE k.root_id=d.value) OR EXISTS(SELECT 1 FROM main.kernel_records r WHERE r.home_id=d.value)) h LEFT JOIN main.kernel_roots k ON k.root_id=h.home_id ORDER BY h.home_id",
    )
    .bind(serde_json::to_string(&candidates)?)
    .bind(crate::events::KERNEL_ROOT_ID)
    .bind(serde_json::to_string(dependencies)?)
    .fetch_all(&mut *conn)
    .await?;
    homes.dedup_by(|a, b| a.0 == b.0);
    // Load exactly the facts `evaluate_homes` reads, by running the same walk
    // (boundary test, depth cap, parent step) against memoized lookups. Every
    // key the evaluator consults is therefore present in the partial maps,
    // and a node shared by several walks is queried once.
    let mut parents = BTreeMap::<String, Option<String>>::new();
    let mut boundaries = BTreeSet::<String>::new();
    let mut is_boundary = BTreeMap::<String, bool>::new();
    let mut no_root_row = BTreeSet::<String>::new();
    for (home, _) in &homes {
        let mut node = home.clone();
        let mut depth = 0usize;
        loop {
            let boundary = match is_boundary.get(&node) {
                Some(known) => *known,
                None => {
                    let found: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM main.kernel_policies WHERE root_id=?)",
                    )
                    .bind(&node)
                    .fetch_one(&mut *conn)
                    .await?;
                    is_boundary.insert(node.clone(), found);
                    found
                }
            };
            if boundary {
                boundaries.insert(node);
                break;
            }
            depth += 1;
            if depth > MAX_HOME_DEPTH || no_root_row.contains(&node) {
                break;
            }
            let parent = match parents.get(&node) {
                Some(parent) => parent.clone(),
                None => {
                    let row: Option<Option<String>> = sqlx::query_scalar(
                        "SELECT parent_id FROM main.kernel_roots WHERE root_id=?",
                    )
                    .bind(&node)
                    .fetch_optional(&mut *conn)
                    .await?;
                    match row {
                        Some(parent) => {
                            parents.insert(node.clone(), parent.clone());
                            parent
                        }
                        None => {
                            // No root row: the census's map lacks it too.
                            no_root_row.insert(node);
                            break;
                        }
                    }
                }
            };
            match parent {
                Some(parent) => node = parent,
                None => break,
            }
        }
    }
    let anchors: BTreeSet<String> = boundaries.clone();
    let mut policies = BTreeMap::<String, Vec<(String, String, String, String)>>::new();
    for (home, kind, id, effect, capability) in
        sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT root_id,subject_kind,subject_id,effect,capability FROM main.kernel_policy_entries WHERE root_id IN (SELECT value FROM json_each(?1))",
        )
        .bind(serde_json::to_string(&anchors)?)
        .fetch_all(&mut *conn)
        .await?
    {
        policies
            .entry(home)
            .or_default()
            .push((kind, id, effect, capability));
    }
    policies.extend(hosted_identity::policy_rows_for_anchors_on(conn, principal, &anchors).await?);
    let homes = evaluate_homes(principal, homes, &parents, &boundaries, &policies, None)?;
    Ok(Demand::Scope(DemandScope { homes, staged }))
}
