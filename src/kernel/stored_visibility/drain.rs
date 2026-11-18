//! The drain (design 73ad275 D1; slice 2b.1, brief 87a004f): bounded batches
//! of derivation, each in a write transaction of its own, never inside a
//! canonical write. Shadow only and dormant: nothing schedules it yet, and
//! nothing reads what it writes to answer a request.
//!
//! # The invariant (I1)
//!
//! A `p_dirty` key is deleted only in a drain transaction that, for every
//! family depending on its kind and every `building` or `live` generation,
//! either re-derives every dependent row in that transaction's snapshot or
//! makes the family unready with its rebuild cursor back at the start. The
//! transaction holds the writer lock (`BEGIN IMMEDIATE`), so no canonical
//! write commits between its reads and its commit. In 2b.1 every key that a
//! family depends on escalates (the second branch); no descendant discovery
//! is attempted.
//!
//! # Order of a batch
//!
//! 1. Refuse, writing nothing, unless the object set is exact, marking is on
//!    and the stored `(generation, family, version, fingerprint)` set equals
//!    the compiled one. Unknown, missing, newer or same-version-different
//!    state is never "repaired" here; a later reviewed upgrade protocol owns
//!    takeover.
//! 2. If a generation's era or epoch differs from `p_marking`'s (an older
//!    binary's or a raw invalidation), adopt them and reset every family:
//!    old rows are never trusted on the strength of an epoch they missed.
//! 3. Take up to `Budget::keys` dirty keys. For each family depending on a
//!    key's kind, either escalate the family ([`KeyAction::Escalate`]) or
//!    refresh or delete the key's stored dependents in every generation
//!    ([`KeyAction::Target`]) within the batch's shared row allowance; a
//!    target that does not fit escalates its family instead, before the key
//!    is cleared. Then delete the keys. A family escalated in the batch
//!    skips its remaining targeted work: its restarted rebuild redoes it.
//! 4. Advance each unready family's rebuild by what is left of the row
//!    allowance, and mark it ready when both of its streams are exhausted.
//! 5. Promote a `building` generation whose families are all ready.
//!
//! Each batch therefore ends in finitely many batches once mutations stop.

// No production caller yet (slice 2b.1 is test-only; scheduling is 2b.5).
#![cfg_attr(not(test), allow(dead_code))]

use super::*;

/// Batch bounds; `batches` bounds one [`catch_up`] call.
///
/// `rows` is **one shared row allowance per batch**. Targeted refreshes and
/// deletes (Principal rows; ScopeAccess pairs of one principal or anchor)
/// spend it first, repeated touches counted each time, then rebuild steps
/// take only what is left, family by family and generation by generation.
/// With F families and G building or live generations (G = 1 in 2b), one
/// batch does at most:
///
/// * `keys` dirty keys read and deleted, and F escalations;
/// * `rows` derived and written (or deleted) rows in total;
/// * `rows + keys × F × G` targeted candidate probes: a target reads at
///   most `remaining + 1` candidates, and one that does not fit escalates
///   its family before the key is cleared, writing nothing;
/// * per rebuild step, at most twice its share from the two streams, plus
///   at most `share + 1` principal seeks and one anchor probe for
///   ScopeAccess's base;
/// * HomeAnchor derivations of at most `MAX_HOME_DEPTH + 1` memoized node
///   probes each; Principal one binding seek; ScopeAccess two existence
///   seeks plus its anchor's policy load (once per anchor per batch).
///
/// **Measured exceptions, not bounded by these numbers** (they must be
/// qualified in 2b.5 before any production drain): the roster select and
/// parse and each membership scan; per anchor, its grant and subject count,
/// template JSON bytes and event history read by the hosted loader.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Budget {
    pub keys: i64,
    pub rows: i64,
    pub batches: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            keys: 64,
            rows: 64,
            batches: 4096,
        }
    }
}

/// Why a batch did nothing. A refusal never writes and is never retried in
/// a loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No accelerator objects (marking off or dropped): nothing to maintain.
    Absent,
    /// Not the exact compiled set: never trusted, never written.
    Drifted,
    /// Marking disabled.
    MarkingOff,
    /// No `building` or `live` generation.
    NoGeneration,
    /// The stored generation/family/version/fingerprint set differs from
    /// this binary's.
    IncompatibleState,
}

/// What one batch did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BatchOutcome {
    /// Every family ready and no dirty key: nothing to do.
    Idle,
    /// A generation adopted the marking era and epoch; every family reset.
    Adopted,
    /// Work done.
    Progress {
        keys_cleared: usize,
        escalated: bool,
        rows_targeted: usize,
        rows_derived: usize,
        rows_deleted: usize,
    },
    Refused(Refusal),
}

/// Points at which a test can pause or fail the drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Gate {
    /// [`catch_up`]: after the read preflight, before the writer lease.
    Preflighted,
    /// After escalating and deleting the batch's dirty keys.
    Escalated,
    /// After computing a rebuild step, before applying it.
    Derived,
    /// After advancing a rebuild cursor, before commit.
    RebuildAdvanced,
    /// [`catch_up`]: after a batch commits.
    Committed,
}

/// Deliberate defects for the witnesses' sensitivity controls (test only).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Defect {
    /// Delete dirty keys without escalating their families.
    SkipEscalation,
    /// Delete dirty keys without refreshing their targeted rows.
    SkipTarget,
    /// Escalate without resetting the rebuild cursor.
    ContinueCursor,
}

#[cfg(test)]
pub(crate) type GateFn =
    std::sync::Arc<dyn Fn(Gate) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync>;

/// Handle-scoped hooks, passed explicitly; production passes the default,
/// which does nothing.
#[derive(Clone, Default)]
pub(crate) struct Hooks {
    #[cfg(test)]
    pub(crate) gate: Option<GateFn>,
    #[cfg(test)]
    pub(crate) defect: Option<Defect>,
}

impl Hooks {
    async fn at(&self, gate: Gate) -> Result<()> {
        #[cfg(test)]
        if let Some(hook) = &self.gate {
            return hook(gate).await;
        }
        let _ = gate;
        Ok(())
    }

    fn defect(&self) -> Option<&'static str> {
        #[cfg(test)]
        let defect = self.defect.map(|d| match d {
            Defect::SkipEscalation => "skip_escalation",
            Defect::ContinueCursor => "continue_cursor",
            Defect::SkipTarget => "skip_target",
        });
        #[cfg(not(test))]
        let defect = None;
        defect
    }
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct GenerationRow {
    generation: i64,
    role: String,
    marking_since_seq: i64,
    invalidation_epoch: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct StateRow {
    generation: i64,
    family: String,
    derivation_version: i64,
    fingerprint: String,
    ready: bool,
    build_after: Option<String>,
}

/// The validated view a batch works from, read in its own snapshot.
struct View {
    marking: MarkingRow,
    generations: Vec<GenerationRow>,
    states: Vec<StateRow>,
}

async fn view_on(conn: &mut SqliteConnection) -> Result<std::result::Result<View, Refusal>> {
    match object_state_on(conn).await? {
        ObjectState::Absent => return Ok(Err(Refusal::Absent)),
        ObjectState::Drifted => return Ok(Err(Refusal::Drifted)),
        ObjectState::Exact => {}
    }
    let Some(marking) = marking_row_on(conn).await? else {
        return Ok(Err(Refusal::Drifted));
    };
    if !marking.enabled {
        return Ok(Err(Refusal::MarkingOff));
    }
    let generations: Vec<GenerationRow> = sqlx::query_as(
        "SELECT generation, role, marking_since_seq, invalidation_epoch FROM main.p_generation WHERE role IN ('building', 'live') ORDER BY generation",
    )
    .fetch_all(&mut *conn)
    .await?;
    if generations.is_empty() {
        return Ok(Err(Refusal::NoGeneration));
    }
    let states: Vec<StateRow> = sqlx::query_as(
        "SELECT s.generation, s.family, s.derivation_version, s.fingerprint, s.ready, s.build_after FROM main.p_state s JOIN main.p_generation g ON g.generation = s.generation WHERE g.role IN ('building', 'live') ORDER BY s.generation, s.family",
    )
    .fetch_all(&mut *conn)
    .await?;
    // Exact equality with the compiled families, before any write.
    let mut stored: Vec<(i64, &str, i64, &str)> = states
        .iter()
        .map(|s| {
            (
                s.generation,
                s.family.as_str(),
                s.derivation_version,
                s.fingerprint.as_str(),
            )
        })
        .collect();
    stored.sort();
    let mut compiled: Vec<(i64, &str, i64, &str)> = generations
        .iter()
        .flat_map(|g| {
            Family::ALL.iter().map(move |f| {
                (
                    g.generation,
                    f.as_str(),
                    f.derivation_version(),
                    f.fingerprint(),
                )
            })
        })
        .collect();
    compiled.sort();
    if stored != compiled {
        return Ok(Err(Refusal::IncompatibleState));
    }
    Ok(Ok(View {
        marking,
        generations,
        states,
    }))
}

impl View {
    fn adopted(&self) -> bool {
        self.generations.iter().all(|g| {
            g.marking_since_seq == self.marking.marking_since_seq
                && g.invalidation_epoch == self.marking.invalidation_epoch
        })
    }

    fn idle(&self, dirty: bool) -> bool {
        self.adopted() && !dirty && self.states.iter().all(|s| s.ready)
    }
}

async fn any_dirty_on(conn: &mut SqliteConnection) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.p_dirty)")
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// A stored key kind. One this binary does not know (only a foreign writer
/// could produce one) counts as `ws`.
fn kind_of(kind: &str) -> KeyKind {
    KeyKind::ALL
        .into_iter()
        .find(|k| k.as_str() == kind)
        .unwrap_or(KeyKind::Ws)
}

/// The families that depend on a key kind.
fn dependents_of(kind: KeyKind) -> Vec<Family> {
    Family::ALL
        .into_iter()
        .filter(|f| f.depends_on().contains(&kind))
        .collect()
}

/// Make `family` unready in every building or live generation with its
/// rebuild cursor back at the start.
async fn escalate_on(
    conn: &mut SqliteConnection,
    family: Family,
    now: i64,
    defect: Option<&'static str>,
) -> Result<()> {
    let sql = if defect == Some("continue_cursor") {
        "UPDATE main.p_state SET ready = 0, written_at = ?2 WHERE family = ?1 AND generation IN (SELECT generation FROM main.p_generation WHERE role IN ('building', 'live'))"
    } else {
        "UPDATE main.p_state SET ready = 0, build_after = NULL, written_at = ?2 WHERE family = ?1 AND generation IN (SELECT generation FROM main.p_generation WHERE role IN ('building', 'live'))"
    };
    sqlx::query(sql)
        .bind(family.as_str())
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// One bounded batch in the caller's write transaction. Directly testable;
/// [`catch_up`] is the lease-holding loop around it.
pub(crate) async fn drain_batch_on(
    conn: &mut SqliteConnection,
    budget: &Budget,
    hooks: &Hooks,
) -> Result<BatchOutcome> {
    require_transaction(conn, "drain batch")?;
    let view = match view_on(conn).await? {
        Ok(view) => view,
        Err(refusal) => return Ok(BatchOutcome::Refused(refusal)),
    };
    if !view.adopted() {
        // Never trust rows built under an era or epoch this generation
        // missed: adopt the current ones and rebuild everything.
        for sql in RESET_AND_ADOPT_SQL {
            sqlx::query(sql).execute(&mut *conn).await?;
        }
        return Ok(BatchOutcome::Adopted);
    }
    let dirty = any_dirty_on(conn).await?;
    if view.idle(dirty) {
        return Ok(BatchOutcome::Idle);
    }
    let now = chrono::Utc::now().timestamp();
    let defect = hooks.defect();

    // Dirty keys: escalate every dependent family, then delete the key.
    let keys: Vec<(String, String)> =
        sqlx::query_as("SELECT kind, key FROM main.p_dirty ORDER BY kind, key LIMIT ?")
            .bind(budget.keys.max(1))
            .fetch_all(&mut *conn)
            .await?;
    let mut escalate = std::collections::BTreeSet::new();
    let mut targets: Vec<(Family, KeyKind, &str)> = Vec::new();
    for (kind, key) in &keys {
        let kind = kind_of(kind);
        for family in dependents_of(kind) {
            match family.key_action(kind) {
                KeyAction::Escalate => {
                    escalate.insert(family);
                }
                KeyAction::Target => targets.push((family, kind, key.as_str())),
            }
        }
    }
    if defect == Some("skip_escalation") {
        escalate.clear();
    }
    if defect == Some("skip_target") {
        targets.clear();
    }
    for family in &escalate {
        escalate_on(conn, *family, now, defect).await?;
    }
    // One shared row allowance for this batch: targeted refreshes and
    // deletes, then rebuild rows, across every family and generation.
    let mut remaining = budget.rows.max(1);
    let mut cache = derive::BatchCache::default();
    let mut rows_targeted = 0;
    for (family, kind, key) in &targets {
        if escalate.contains(family) {
            continue;
        }
        for generation in view.generations.iter().map(|g| g.generation) {
            match derive::target_on(conn, *family, generation, *kind, key, remaining, &mut cache)
                .await?
            {
                derive::Targeted::Done(cost) => {
                    remaining -= cost;
                    rows_targeted += cost as usize;
                }
                // More dependents than the allowance left: escalate now, in
                // this transaction and before the key is cleared.
                derive::Targeted::Overflow => {
                    escalate.insert(*family);
                    escalate_on(conn, *family, now, defect).await?;
                    break;
                }
            }
        }
    }
    for (kind, key) in &keys {
        sqlx::query("DELETE FROM main.p_dirty WHERE kind = ? AND key = ?")
            .bind(kind)
            .bind(key)
            .execute(&mut *conn)
            .await?;
    }
    if !keys.is_empty() {
        hooks.at(Gate::Escalated).await?;
    }

    // Rebuild: one bounded step per unready family and generation, each
    // taking only what is left of the allowance.
    let states: Vec<StateRow> = sqlx::query_as(
        "SELECT s.generation, s.family, s.derivation_version, s.fingerprint, s.ready, s.build_after FROM main.p_state s JOIN main.p_generation g ON g.generation = s.generation WHERE g.role IN ('building', 'live') AND s.ready = 0 ORDER BY s.generation, s.family",
    )
    .fetch_all(&mut *conn)
    .await?;
    let head = content_head_on(conn).await?;
    let (mut rows_derived, mut rows_deleted) = (0, 0);
    for state in &states {
        if remaining <= 0 {
            break;
        }
        let family = Family::from_str(&state.family)
            .expect("the exact state check admits only known families");
        let step = derive::rebuild_step_on(
            conn,
            family,
            state.generation,
            state.build_after.as_deref(),
            remaining,
            &mut cache,
        )
        .await?;
        if step.restart {
            // A cursor this family could not have written: start again,
            // never trust or loop on it.
            sqlx::query(
                "UPDATE main.p_state SET ready = 0, build_after = NULL, written_at = ? WHERE generation = ? AND family = ?",
            )
            .bind(now)
            .bind(state.generation)
            .bind(&state.family)
            .execute(&mut *conn)
            .await?;
            continue;
        }
        remaining -= (step.derived.len() + step.deleted.len()) as i64;
        hooks.at(Gate::Derived).await?;
        derive::apply_step_on(conn, family, state.generation, &step).await?;
        rows_derived += step.derived.len();
        rows_deleted += step.deleted.len();
        match &step.cursor {
            Some(cursor) => sqlx::query(
                "UPDATE main.p_state SET build_after = ?, written_at = ? WHERE generation = ? AND family = ?",
            )
            .bind(cursor)
            .bind(now)
            .bind(state.generation)
            .bind(&state.family),
            None => sqlx::query(
                "UPDATE main.p_state SET ready = 1, build_after = NULL, built_through_seq = ?, written_at = ? WHERE generation = ? AND family = ?",
            )
            .bind(head)
            .bind(now)
            .bind(state.generation)
            .bind(&state.family),
        }
        .execute(&mut *conn)
        .await?;
        hooks.at(Gate::RebuildAdvanced).await?;
    }
    sqlx::query(
        "UPDATE main.p_generation AS g SET role = 'live' WHERE g.role = 'building' AND NOT EXISTS (SELECT 1 FROM main.p_state s WHERE s.generation = g.generation AND s.ready = 0)",
    )
    .execute(&mut *conn)
    .await?;
    Ok(BatchOutcome::Progress {
        keys_cleared: keys.len(),
        escalated: !escalate.is_empty(),
        rows_targeted,
        rows_derived,
        rows_deleted,
    })
}

/// Drain until idle, a refusal, or the batch budget: a read preflight, then
/// one write transaction per batch under the deployment write admission and
/// the labelled writer lease. The batch revalidates everything in its own
/// snapshot, so an absent, dropped, disabled or incompatible set found under
/// the lease returns without writing; this never installs, recreates or
/// enables anything. Returns the last outcome.
pub(crate) async fn catch_up(db: &Db, budget: &Budget, hooks: &Hooks) -> Result<BatchOutcome> {
    let mut last = BatchOutcome::Idle;
    for _ in 0..budget.batches.max(1) {
        {
            let mut read = db.pool().begin().await?;
            let marker: i64 = sqlx::query_scalar("PRAGMA main.application_id")
                .fetch_one(&mut *read)
                .await?;
            if marker != crate::db::V2_APPLICATION_ID {
                return Ok(BatchOutcome::Refused(Refusal::Absent));
            }
            match view_on(&mut read).await? {
                Err(refusal) => return Ok(BatchOutcome::Refused(refusal)),
                Ok(view) => {
                    let dirty = any_dirty_on(&mut read).await?;
                    if view.idle(dirty) {
                        return Ok(BatchOutcome::Idle);
                    }
                }
            }
        }
        hooks.at(Gate::Preflighted).await?;
        #[cfg(feature = "v2-kernel-probe")]
        let _admission = db.sql_event_projection_write_admission()?;
        // The labelled lease attributes critical-section holds to the drain
        // in write diagnostics (the write-budget measurement seam).
        #[cfg(feature = "v2-kernel-probe")]
        let mut tx = crate::db::begin_write_labelled(db.write_pool(), "stored_visibility").await?;
        #[cfg(not(feature = "v2-kernel-probe"))]
        let mut tx = crate::db::begin_write(db.write_pool()).await?;
        // A fresh request scope per batch: the roster parse is cached by its
        // immutable event id within this batch only.
        last =
            crate::kernel::hosted_identity::scope_request(drain_batch_on(&mut tx, budget, hooks))
                .await?;
        match last {
            BatchOutcome::Refused(_) | BatchOutcome::Idle => {
                tx.rollback().await?;
                return Ok(last);
            }
            BatchOutcome::Adopted | BatchOutcome::Progress { .. } => {
                tx.commit().await?;
                hooks.at(Gate::Committed).await?;
                tokio::task::yield_now().await;
            }
        }
    }
    Ok(last)
}
