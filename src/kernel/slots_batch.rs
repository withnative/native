//! The rehome batch and its driver (Foci v2 G6, increment 1; design note
//! 681a449 §4, building on 13157ec §8.4, "The rehome batch contract"). G7
//! proved the contract with a `cfg(test)` stand-in; this is the same batch,
//! promoted.
//!
//! One `begin_write` transaction (or the caller's, for the `_in` form):
//! 1. the current home must satisfy **structure** (`require_private_home_on`),
//!    not readiness, because the batch runs while the fence is up;
//! 2. the current target must be the `expected_target` the caller observed,
//!    else `generation_changed`;
//! 3. up to N sources come from `outstanding_sources_on`, and each is
//!    confirmed by `recovery_source_eligible_on` in this transaction; a source
//!    that is not eligible fails the whole batch, naming the record;
//! 4. each is moved with the existing rehome event through
//!    `rehome_record_in`, inside this transaction;
//! 5. each moved record must now pass the ordinary predicate, or the batch
//!    errors and rolls back whole;
//! 6. the receipt is `{target_id, moved, remaining, remaining_capped,
//!    foreign_skipped, foreign_capped, complete}`. Debt is not read from any
//!    stored state, and `complete` is decided by `recovery_debt_on` alone, so
//!    a repeat call is always safe and a capped count never decides readiness.
//!
//! `rehome_until_ready` is a convenience loop over single batches. The
//! recovery protocol is the single batch.
use super::slots;
use super::slots_eval::{self, SlotRefusal};
use super::slots_recovery::{self, ForeignScope};
use super::*;
use std::future::Future;

/// The most sources one batch may move. One batch holds the single writer
/// lock, so an unsatisfiable request is an error, not a clamp. Placeholder.
pub(crate) const MAX_BATCH: usize = 100;

/// The most batches one driver call may run. Placeholder.
pub(crate) const MAX_DRIVE_BATCHES: usize = 100;

/// What a batch did. `moved <= size`; `remaining` and `foreign_skipped` are
/// exact up to and including `slots_recovery::CAP`, then saturate with their
/// flags. `complete` means no recovery debt in this transaction after the
/// moves, which is `remaining == 0 && !remaining_capped`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchReceipt {
    pub target_id: String,
    pub moved: usize,
    pub remaining: i64,
    pub remaining_capped: bool,
    pub foreign_skipped: i64,
    pub foreign_capped: bool,
    pub complete: bool,
}

/// A batch that did not run, as a result rather than an error. The batch
/// checks structure only, so `recovery_incomplete` never appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchRefusal {
    /// The current home is absent, widened, missing, forbidden or the root:
    /// there is no correct private destination.
    Home(SlotRefusal),
    /// The current home is not the one the caller observed.
    GenerationChanged,
}

pub(crate) type Batch = Result<std::result::Result<BatchReceipt, BatchRefusal>>;

/// Test seam for the part-way-failure fixtures, like `AttemptHooks`. Both
/// run inside the open transaction; an `Err` aborts the batch whole.
/// `after_select` runs once the sources are chosen and before they are
/// checked; `after_moves` runs once they are moved and before the ordinary
/// predicate is applied.
pub(crate) trait BatchHooks: Send + Sync {
    fn after_select<'a>(
        &'a self,
        _tx: &'a mut Transaction<'static, Sqlite>,
        _sources: &'a [String],
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    fn after_moves<'a>(
        &'a self,
        _tx: &'a mut Transaction<'static, Sqlite>,
        _moved: &'a [String],
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}

pub(crate) struct NoBatchHooks;
impl BatchHooks for NoBatchHooks {}

/// One batch on the caller's transaction. Every caller aborts on error; none
/// catches it and commits partial work.
pub(crate) async fn rehome_batch_in<H: BatchHooks>(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    hooks: &H,
    principal: &str,
    expected_target: &str,
    size: usize,
) -> Batch {
    if size == 0 || size > MAX_BATCH || !slots::valid_slot_id(expected_target) {
        return Err(Error::engine("malformed rehome batch request"));
    }
    let destination = match slots_eval::require_private_home_on(tx, principal).await? {
        Ok(target) => target.target_id,
        Err(refusal) => return Ok(Err(BatchRefusal::Home(refusal))),
    };
    if destination != expected_target {
        return Ok(Err(BatchRefusal::GenerationChanged));
    }
    let limit = i64::try_from(size).map_err(|_| Error::engine("batch size too large"))?;
    let sources = slots_recovery::outstanding_sources_on(tx, principal, limit).await?;
    hooks.after_select(tx, &sources).await?;
    for source in &sources {
        // Selection and eligibility must agree; a disagreement is corruption,
        // not something to skip silently. The id is the principal's own
        // record, so naming it discloses nothing.
        let is_home: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
                .bind(source)
                .fetch_one(&mut **tx)
                .await?;
        if is_home {
            return Err(Error::engine(format!(
                "outstanding source {source} is also a home id"
            )));
        }
        if !slots_recovery::recovery_source_eligible_on(tx, principal, source).await? {
            return Err(Error::engine(format!(
                "outstanding source {source} is not eligible"
            )));
        }
    }
    for source in &sources {
        rehome_record_in(db, tx, acts, principal, source, &destination).await?;
    }
    hooks.after_moves(tx, &sources).await?;
    for source in &sources {
        if !slots_eval::foci_record_admissible_on(tx, principal, source).await? {
            return Err(Error::engine(format!(
                "moved record {source} is not admissible"
            )));
        }
    }
    let spec =
        slots::slot_spec(slots::HOME_FOCI_PRIVATE).ok_or_else(|| Error::engine("unknown slot"))?;
    let remaining = slots_recovery::outstanding_bounded_on(tx, principal).await?;
    let foreign =
        slots_recovery::visible_foreign_on(tx, principal, ForeignScope::Earlier, 0).await?;
    let complete = !slots_eval::recovery_debt_on(tx, principal, spec).await?;
    if complete != (remaining.count == 0 && !remaining.capped) {
        return Err(Error::engine(
            "remaining count disagrees with recovery debt",
        ));
    }
    Ok(Ok(BatchReceipt {
        target_id: destination,
        moved: sources.len(),
        remaining: remaining.count,
        remaining_capped: remaining.capped,
        foreign_skipped: foreign.total,
        foreign_capped: foreign.capped,
        complete,
    }))
}

/// One batch in its own write transaction: committed when it ran, rolled back
/// when it was refused or failed.
pub(crate) async fn rehome_batch_with<H: BatchHooks>(
    db: &Db,
    hooks: &H,
    principal: &str,
    expected_target: &str,
    size: usize,
) -> Batch {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let batch = rehome_batch_in(
        db,
        &mut tx,
        &mut acts,
        hooks,
        principal,
        expected_target,
        size,
    )
    .await;
    match batch {
        Ok(Ok(receipt)) => {
            tx.commit().await?;
            Ok(Ok(receipt))
        }
        other => {
            tx.rollback().await?;
            other
        }
    }
}

/// `rehome_batch_with` and no hooks.
pub(crate) async fn rehome_batch(
    db: &Db,
    principal: &str,
    expected_target: &str,
    size: usize,
) -> Batch {
    rehome_batch_with(db, &NoBatchHooks, principal, expected_target, size).await
}

/// Why a driver call stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriveStop {
    /// A batch left no recovery debt.
    Complete,
    /// A batch was refused; the target is never silently updated.
    Refused(BatchRefusal),
    /// `max_batches` ran out. Call again with the same target.
    BatchLimit,
}

/// Progress of one driver call: the committed batches only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriveReport {
    pub batches: usize,
    pub moved_total: usize,
    pub last: Option<BatchReceipt>,
    pub stop: DriveStop,
}

/// Run single batches until the principal's recovery debt is gone. Each batch
/// commits on its own, so progress survives a crash and a new call resumes.
/// `expected_target` is fixed for the whole call: a refusal stops the loop and
/// is returned with the progress made. A batch that moved nothing yet left
/// debt is an error, never a loop (it cannot occur in valid state).
pub(crate) async fn rehome_until_ready_with<H: BatchHooks>(
    db: &Db,
    hooks: &H,
    principal: &str,
    expected_target: &str,
    size: usize,
    max_batches: usize,
) -> Result<DriveReport> {
    if max_batches == 0 || max_batches > MAX_DRIVE_BATCHES {
        return Err(Error::engine("malformed rehome driver request"));
    }
    let mut report = DriveReport {
        batches: 0,
        moved_total: 0,
        last: None,
        stop: DriveStop::BatchLimit,
    };
    for _ in 0..max_batches {
        let receipt = match rehome_batch_with(db, hooks, principal, expected_target, size).await? {
            Ok(receipt) => receipt,
            Err(refusal) => {
                report.stop = DriveStop::Refused(refusal);
                return Ok(report);
            }
        };
        report.batches += 1;
        report.moved_total += receipt.moved;
        let (complete, moved) = (receipt.complete, receipt.moved);
        report.last = Some(receipt);
        if complete {
            report.stop = DriveStop::Complete;
            return Ok(report);
        }
        if moved == 0 {
            return Err(Error::engine("rehome batch made no progress"));
        }
    }
    Ok(report)
}

/// `rehome_until_ready_with` and no hooks.
pub(crate) async fn rehome_until_ready(
    db: &Db,
    principal: &str,
    expected_target: &str,
    size: usize,
    max_batches: usize,
) -> Result<DriveReport> {
    rehome_until_ready_with(
        db,
        &NoBatchHooks,
        principal,
        expected_target,
        size,
        max_batches,
    )
    .await
}
