//! Recovery sources and ownership counts (Foci v2 G7, increment 6; design note
//! 13157ec §7.3, §8.4).
//!
//! After `replace(home)` the new home is empty and the old homes still hold
//! the data. The recovery fence (`slots_eval::recovery_debt_on`) stays up
//! while the principal owns `holds`-family records in any non-current home of
//! the slot's lineage. This module supplies the rest of what a rehome batch
//! needs, so G6's real batch does not have to reopen G7:
//!
//! - `outstanding_sources_on`: the records still to move, ordered and bounded;
//! - `recovery_source_eligible_on`: the **recovery** placement predicate
//!   (non-current lineage home, beneficiary-owned, a held family, Edit). The
//!   ordinary predicate (`foci_record_admissible_on`) is its mirror: current
//!   home. A batch applies this one to each source and the ordinary one to
//!   each result;
//! - `visible_foreign_on`: the anomaly count for foreign-owned Foci records
//!   (Decision 6, option A), visibility-safe and bounded (design note 681a449
//!   §4.2);
//! - `outstanding_bounded_on`: the batch's `remaining`, bounded the same way.
//!
//! The counts read only `kernel_records` metadata (`id`, `home_id`,
//! `owner_id`, `pin_family`) plus policy tables, never field rows. A foreign
//! row's visibility is decided by its home alone, so hidden homes are dropped
//! before any cap applies.
//!
//! Everything here runs on a connection the caller owns and writes nothing.
use super::slots::{self, SlotSpec, HOME_FOCI_PRIVATE};
use super::slots_eval::{capability_on, current_target};
use super::*;

fn home_spec() -> Result<&'static SlotSpec> {
    slots::slot_spec(HOME_FOCI_PRIVATE).ok_or_else(|| Error::engine("unknown slot"))
}

/// Rows of `kernel_records` (as `r`) in a **non-current** home of the home
/// slot's lineage (lineage row `l`), of a `holds` family, with this owner
/// condition. Binds, in order: principal, slot, owner, then the families.
fn earlier_homes_sql(select: &str, owner_condition: &str, holds: usize, tail: &str) -> String {
    let marks = vec!["?"; holds].join(",");
    format!(
        "SELECT {select} FROM kernel_slot_lineage l \
         JOIN kernel_records r ON r.home_id = l.target_id \
         WHERE l.principal_id=? AND l.slot=? \
         AND l.target_id <> (SELECT target_id FROM kernel_slots WHERE principal_id=l.principal_id AND slot=l.slot) \
         AND {owner_condition} AND r.pin_family IN ({marks}) {tail}"
    )
}

/// The principal's records still to move out of earlier homes: owned by them,
/// of a held family, in a non-current home of the lineage. Ordered by id so a
/// batch is deterministic, and bounded by `limit`.
pub(crate) async fn outstanding_sources_on(
    conn: &mut SqliteConnection,
    principal: &str,
    limit: i64,
) -> Result<Vec<String>> {
    let spec = home_spec()?;
    if spec.holds.is_empty() || limit < 1 {
        return Ok(Vec::new());
    }
    let sql = earlier_homes_sql(
        "r.id",
        "r.owner_id=?",
        spec.holds.len(),
        "ORDER BY r.id LIMIT ?",
    );
    let mut query = sqlx::query_scalar(&sql)
        .bind(principal)
        .bind(spec.name)
        .bind(principal);
    for family in spec.holds {
        query = query.bind(*family);
    }
    Ok(query.bind(limit).fetch_all(&mut *conn).await?)
}

/// The count cap: counts are exact up to and including `CAP`, then saturate
/// and carry a flag. Placeholder value (design note 681a449 §4.2).
pub(crate) const CAP: i64 = 1_000;

/// A count that saturates at `CAP`. `capped` means there were more than `CAP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bounded {
    pub count: i64,
    pub capped: bool,
}

impl Bounded {
    fn from_scan(scanned: i64) -> Self {
        Self {
            count: scanned.min(CAP),
            capped: scanned > CAP,
        }
    }
}

/// How many records `outstanding_sources_on` would return without a limit,
/// saturating at `CAP` (the batch's `remaining`). The principal's own rows
/// are always visible to them, so the flag reveals nothing. An owned row
/// whose id is also a home id is counted: it must reach the recovery
/// predicate, where it fails the batch.
pub(crate) async fn outstanding_bounded_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Bounded> {
    let spec = home_spec()?;
    if spec.holds.is_empty() {
        return Ok(Bounded::from_scan(0));
    }
    let inner = earlier_homes_sql("1", "r.owner_id=?", spec.holds.len(), "LIMIT ?");
    let sql = format!("SELECT COUNT(*) FROM ({inner})");
    let mut query = sqlx::query_scalar(&sql)
        .bind(principal)
        .bind(spec.name)
        .bind(principal);
    for family in spec.holds {
        query = query.bind(*family);
    }
    let scanned: i64 = query.bind(CAP + 1).fetch_one(&mut *conn).await?;
    Ok(Bounded::from_scan(scanned))
}

/// The recovery placement predicate: a record the rehome batch may pick up.
/// The principal owns it, it is of a `holds` family, it sits in a
/// **non-current** home of the home slot's lineage, and the principal can
/// Edit it. A record in the current home, in a home outside the lineage,
/// owned by someone else or of another family is not a source.
pub(crate) async fn recovery_source_eligible_on(
    conn: &mut SqliteConnection,
    principal: &str,
    record_id: &str,
) -> Result<bool> {
    let spec = home_spec()?;
    let row: Option<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT home_id, owner_id, pin_family FROM kernel_records WHERE id=?")
            .bind(record_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((home_id, owner, family)) = row else {
        return Ok(false);
    };
    if owner.as_deref() != Some(principal)
        || !family.is_some_and(|family| spec.holds.contains(&family.as_str()))
    {
        return Ok(false);
    }
    let Some(current) = current_target(conn, principal, spec.name).await? else {
        return Ok(false);
    };
    if current == home_id {
        return Ok(false);
    }
    let in_lineage: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_slot_lineage WHERE principal_id=? AND slot=? AND target_id=?)",
    )
    .bind(principal)
    .bind(spec.name)
    .bind(&home_id)
    .fetch_one(&mut *conn)
    .await?;
    if !in_lineage {
        return Ok(false);
    }
    Ok(capability_on(conn, principal, record_id)
        .await?
        .allows(Capability::Edit))
}

/// Which of the principal's homes `visible_foreign_on` looks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForeignScope {
    /// The current target only.
    Current,
    /// Every lineage target except the current one.
    Earlier,
}

/// Foreign Foci rows the principal can View: `total` saturates at `CAP`,
/// `entries` are at most `limit` of the same rows, ordered by id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VisibleForeign {
    pub total: i64,
    pub capped: bool,
    pub entries: Vec<String>,
}

/// Rows of `kernel_records` (as `r`) in the given homes that are foreign
/// (owner NULL or not the principal), of a `holds` family, and **ordinary**:
/// the id is not also a home id. The owner condition covers three owner
/// ranges (NULL, below, above the principal id), allowing index use on
/// `idx_kernel_records_home_owner`; the actual seek plan is engine-dependent
/// and unmeasured here. Binds, in order: the homes, principal (twice), then
/// the families.
fn foreign_rows_sql(select: &str, homes: usize, holds: usize, tail: &str) -> String {
    let homes = vec!["?"; homes].join(",");
    let families = vec!["?"; holds].join(",");
    format!(
        "SELECT {select} FROM kernel_records r WHERE r.home_id IN ({homes}) \
         AND (r.owner_id IS NULL OR r.owner_id < ? OR r.owner_id > ?) \
         AND r.pin_family IN ({families}) \
         AND NOT EXISTS (SELECT 1 FROM kernel_roots k WHERE k.root_id = r.id) {tail}"
    )
}

/// The homes a scope covers: at most the number of generations, never a
/// number of rows.
async fn scope_homes(
    conn: &mut SqliteConnection,
    principal: &str,
    spec: &SlotSpec,
    scope: ForeignScope,
) -> Result<Vec<String>> {
    let Some(current) = current_target(conn, principal, spec.name).await? else {
        return Ok(Vec::new());
    };
    match scope {
        ForeignScope::Current => Ok(vec![current]),
        ForeignScope::Earlier => Ok(sqlx::query_scalar(
            "SELECT target_id FROM kernel_slot_lineage \
             WHERE principal_id=? AND slot=? AND target_id <> ? ORDER BY target_id",
        )
        .bind(principal)
        .bind(spec.name)
        .bind(current)
        .fetch_all(&mut *conn)
        .await?),
    }
}

/// Foreign-owned Foci records in the principal's current or earlier homes
/// that the principal can View: what a batch skips and what ordinary
/// consumers exclude (Decision 6, option A).
///
/// A foreign **ordinary** record has no policy of its own and the principal
/// is not its owner, so its capability is the policy capability at its home's
/// nearest anchor, the same for every such row in that home. Visibility is
/// therefore all-or-nothing per home: one probe row per candidate home is
/// evaluated, and the cap applies only to rows in homes that passed. A hidden
/// home contributes nothing to `total`, `capped` or `entries`, and a row
/// whose id is also a home id is never probed, counted or listed (it fails
/// closed). `total = min(n, CAP)` and `capped = n > CAP`, where `n` counts
/// the eligible ordinary visible rows. `limit` bounds `entries`; 0 asks for
/// the counts only.
pub(crate) async fn visible_foreign_on(
    conn: &mut SqliteConnection,
    principal: &str,
    scope: ForeignScope,
    limit: i64,
) -> Result<VisibleForeign> {
    let spec = home_spec()?;
    if spec.holds.is_empty() {
        return Ok(VisibleForeign::default());
    }
    let mut kept = Vec::new();
    for home in scope_homes(conn, principal, spec, scope).await? {
        let sql = foreign_rows_sql("r.id", 1, spec.holds.len(), "LIMIT 1");
        let mut query = sqlx::query_scalar(&sql)
            .bind(&home)
            .bind(principal)
            .bind(principal);
        for family in spec.holds {
            query = query.bind(*family);
        }
        let probe: Option<String> = query.fetch_optional(&mut *conn).await?;
        let Some(probe) = probe else { continue };
        if capability_on(conn, principal, &probe)
            .await?
            .allows(Capability::View)
        {
            kept.push(home);
        }
    }
    if kept.is_empty() {
        return Ok(VisibleForeign::default());
    }
    let mut binds: Vec<&str> = kept.iter().map(String::as_str).collect();
    binds.extend([principal, principal]);
    binds.extend(spec.holds.iter().copied());
    let inner = foreign_rows_sql("1", kept.len(), spec.holds.len(), "LIMIT ?");
    let sql = format!("SELECT COUNT(*) FROM ({inner})");
    let mut query = sqlx::query_scalar(&sql);
    for value in &binds {
        query = query.bind(*value);
    }
    let scanned: i64 = query.bind(CAP + 1).fetch_one(&mut *conn).await?;
    let counted = Bounded::from_scan(scanned);
    let entries = if limit > 0 {
        let sql = foreign_rows_sql(
            "r.id",
            kept.len(),
            spec.holds.len(),
            "ORDER BY r.id LIMIT ?",
        );
        let mut query = sqlx::query_scalar(&sql);
        for value in &binds {
            query = query.bind(*value);
        }
        query.bind(limit).fetch_all(&mut *conn).await?
    } else {
        Vec::new()
    };
    Ok(VisibleForeign {
        total: counted.count,
        capped: counted.capped,
        entries,
    })
}

/// Ids present as both a record and a home. The kernel's evaluator and the
/// count algorithm assume the two id spaces are disjoint; admission keeps
/// them so (increment 3b), and this finds historical overlaps admission never
/// saw (direct SQL, old logs, corruption). For host start-up and a G8 dry
/// run, not for principals, so no visibility rule applies.
pub(crate) async fn kernel_id_space_overlap(db: &Db) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT r.id FROM kernel_roots k JOIN kernel_records r ON r.id = k.root_id ORDER BY r.id",
    )
    .fetch_all(db.pool())
    .await?)
}
