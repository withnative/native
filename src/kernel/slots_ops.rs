//! Slot operations: the home slot with its provisioner seam (Foci v2 G7,
//! increment 4) and the record slot (increment 5); design note 13157ec §4.4,
//! §6.2, §6.4, §7.1, §8.4.
//!
//! Each operation runs in one `BEGIN IMMEDIATE` transaction: replay lookup,
//! evaluate, act on the action/state table, create the target (the home
//! through the host-held `HomeProvisioner`, the preferences record through
//! `create_input_in`), register through the sealed route with the same act,
//! re-evaluate and check the postcondition. Refusals and no-ops write
//! nothing. `evaluate` stays the only producer of `status` and `reason`; this
//! module chooses `outcome` and `refusal`. Both slots share one retry rule:
//! only a UNIQUE violation raised by the registration is retried, once.
use super::slots::{self, HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_eval::{
    self, Evaluation, Refusal, SlotOutcome, SlotReceipt, SlotStatus, UnusableReason,
};
use super::*;
use std::future::Future;

/// What the provisioner is handed: the caller's open transaction (already
/// `BEGIN IMMEDIATE`), the act allocation shared by the whole operation, and
/// the beneficiary. The provisioner must not begin, commit or roll back.
pub(crate) struct SlotTxContext<'a> {
    pub db: &'a Db,
    pub tx: &'a mut Transaction<'static, Sqlite>,
    pub acts: &'a mut crate::act::ActAllocation,
    pub principal: &'a str,
}

/// `Home` carries the new home's id. `Unavailable` means only that the
/// configured capability is missing (for example no designated parent). A
/// fault is an `Err`, never `Unavailable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvisionOutcome {
    Home(String),
    Unavailable,
}

/// The G6 seam. An implementation creates exactly one home in the caller's
/// transaction: owner the beneficiary, its own anchor, entries exactly one
/// allow-Manage for the beneficiary. It does not register the slot. Authority
/// and the designated parent are constructor state, never request fields.
pub(crate) trait HomeProvisioner: Send + Sync {
    fn provision_home_in<'a>(
        &'a self,
        cx: &'a mut SlotTxContext<'_>,
    ) -> impl Future<Output = Result<ProvisionOutcome>> + Send;
}

/// Installed by non-test probe builds until G6 injects the real provisioner:
/// always `Unavailable`, writes nothing.
#[allow(dead_code)] // The host wiring that installs it is G6's.
pub(crate) struct NoProvisioner;

impl HomeProvisioner for NoProvisioner {
    async fn provision_home_in(&self, _cx: &mut SlotTxContext<'_>) -> Result<ProvisionOutcome> {
        Ok(ProvisionOutcome::Unavailable)
    }
}

/// Test seam for the UNIQUE backstop (fixture 10). `before_register` runs
/// inside the open transaction just before the slot event is appended; an
/// `Err` aborts the attempt as if the append had failed. `after_rollback`
/// runs once the failed attempt's transaction has ended and released the
/// writer lock, before any retry.
pub(crate) trait AttemptHooks: Send + Sync {
    fn before_register<'a>(
        &'a self,
        _tx: &'a mut Transaction<'static, Sqlite>,
        _attempt: u32,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    fn after_rollback(&self, _attempt: u32) -> impl Future<Output = ()> + Send {
        async {}
    }
}

pub(crate) struct NoHooks;
impl AttemptHooks for NoHooks {}

#[derive(Clone, Copy)]
enum Action<'a> {
    Ensure,
    Replace { expected: &'a str },
}

/// What one attempt decided. `Commit` carries a receipt for a write that
/// passed its postcondition; `NoWrite` rolls back.
enum Decision {
    Commit(SlotReceipt),
    NoWrite(SlotReceipt),
}

fn is_unique_violation(error: &Error) -> bool {
    matches!(error, Error::Sqlx(sqlx::Error::Database(e)) if e.is_unique_violation())
}

/// Why an attempt failed. Only a UNIQUE violation raised by the slot
/// registration itself (the sealed append and its fold) is a `Collision` and
/// may be retried; every other error, including a UNIQUE storage error raised
/// by the provisioner, is a `Fault` and reaches the caller unchanged.
enum Failure {
    Collision(Error),
    Fault(Error),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Failure::Fault(error)
    }
}

impl Failure {
    fn into_error(self) -> Error {
        match self {
            Failure::Collision(error) | Failure::Fault(error) => error,
        }
    }
}

type Attempt<T> = std::result::Result<T, Failure>;

/// `ensure(home)`: create the home only when the slot is absent.
pub(crate) async fn ensure_home<P: HomeProvisioner>(
    db: &Db,
    provisioner: &P,
    principal: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    ensure_home_with(db, provisioner, &NoHooks, principal, reason).await
}

pub(crate) async fn ensure_home_with<P: HomeProvisioner, H: AttemptHooks>(
    db: &Db,
    provisioner: &P,
    hooks: &H,
    principal: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    run(db, provisioner, hooks, principal, Action::Ensure, reason).await
}

/// `replace(home, expected_target)`: compare-and-set replacement of an
/// unusable home, retry-safe through the lineage table.
pub(crate) async fn replace_home<P: HomeProvisioner>(
    db: &Db,
    provisioner: &P,
    principal: &str,
    expected_target: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    replace_home_with(
        db,
        provisioner,
        &NoHooks,
        principal,
        expected_target,
        reason,
    )
    .await
}

pub(crate) async fn replace_home_with<P: HomeProvisioner, H: AttemptHooks>(
    db: &Db,
    provisioner: &P,
    hooks: &H,
    principal: &str,
    expected_target: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    let action = Action::Replace {
        expected: expected_target,
    };
    run(db, provisioner, hooks, principal, action, reason).await
}

/// A blank reason, or a malformed `expected_target`, is an error before any
/// transactional replay or state decision, never a `cas_mismatch` or `absent`
/// refusal.
fn validate_request(action: Action<'_>, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        return Err(Error::engine("slot reason must not be blank"));
    }
    if let Action::Replace { expected } = action {
        if !slots::valid_slot_id(expected) {
            return Err(Error::engine("invalid slot target id"));
        }
    }
    Ok(())
}

/// One attempt, plus at most one retry after a typed UNIQUE violation in the
/// slot registration: the failed attempt rolls back whole, and the retry
/// rereads the winner's state.
async fn retrying<H, F, Fut>(hooks: &H, attempt_once: F) -> Result<SlotReceipt>
where
    H: AttemptHooks,
    F: Fn(u32) -> Fut,
    Fut: Future<Output = Attempt<SlotReceipt>>,
{
    let mut attempt = 0;
    loop {
        match attempt_once(attempt).await {
            Err(Failure::Collision(_)) if attempt == 0 => {
                hooks.after_rollback(attempt).await;
                attempt += 1;
            }
            other => return other.map_err(Failure::into_error),
        }
    }
}

async fn run<P: HomeProvisioner, H: AttemptHooks>(
    db: &Db,
    provisioner: &P,
    hooks: &H,
    principal: &str,
    action: Action<'_>,
    reason: &str,
) -> Result<SlotReceipt> {
    validate_request(action, reason)?;
    retrying(hooks, |attempt| async move {
        let mut tx = begin_write(db.write_pool()).await?;
        let decided = decide(
            db,
            &mut tx,
            provisioner,
            hooks,
            principal,
            action,
            reason,
            attempt,
        )
        .await;
        conclude(tx, decided).await
    })
    .await
}

/// End the attempt's transaction: commit a write that passed its
/// postcondition, roll back everything else.
async fn conclude(
    tx: Transaction<'static, Sqlite>,
    decided: Attempt<Decision>,
) -> Attempt<SlotReceipt> {
    match decided {
        Ok(Decision::Commit(receipt)) => {
            tx.commit().await.map_err(|e| Failure::Fault(e.into()))?;
            Ok(receipt)
        }
        Ok(Decision::NoWrite(receipt)) => {
            tx.rollback().await.map_err(|e| Failure::Fault(e.into()))?;
            Ok(receipt)
        }
        Err(failure) => {
            let _ = tx.rollback().await;
            Err(failure)
        }
    }
}

fn refused(evaluation: Evaluation, refusal: Option<Refusal>, slot: &str) -> Decision {
    Decision::NoWrite(evaluation.into_receipt(slot, SlotOutcome::Refused, refusal, None))
}

#[allow(clippy::too_many_arguments)]
async fn decide<P: HomeProvisioner, H: AttemptHooks>(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    provisioner: &P,
    hooks: &H,
    principal: &str,
    action: Action<'_>,
    reason: &str,
    attempt: u32,
) -> Attempt<Decision> {
    let slot = HOME_FOCI_PRIVATE;
    slots_eval::require_account(tx, principal).await?;
    // A retried replace looks up its own earlier effect first, before the
    // absent, CAS and health checks (design §6.4).
    if let Action::Replace { expected } = action {
        if let Some(decision) = replay_first(tx, principal, slot, expected).await? {
            return Ok(decision);
        }
    }
    let current = slots_eval::evaluate(tx, principal, slot).await?;
    let previous = match action {
        Action::Ensure => match current.status {
            SlotStatus::Healthy => {
                return Ok(Decision::NoWrite(current.into_receipt(
                    slot,
                    SlotOutcome::Existing,
                    None,
                    Some(false),
                )))
            }
            SlotStatus::Unusable => return Ok(refused(current, None, slot)),
            SlotStatus::Absent => None,
        },
        Action::Replace { expected } => {
            if current.status == SlotStatus::Absent {
                return Ok(refused(current, Some(Refusal::Absent), slot));
            }
            let stored = slots_eval::current_target(tx, principal, slot).await?;
            if stored.as_deref() != Some(expected) {
                return Ok(refused(current, Some(Refusal::CasMismatch), slot));
            }
            match (current.status, current.reason) {
                (SlotStatus::Healthy, _) => {
                    return Ok(refused(current, Some(Refusal::NotUnusable), slot))
                }
                (_, Some(UnusableReason::RecoveryIncomplete)) => {
                    return Ok(refused(current, Some(Refusal::UnsupportedRecovery), slot))
                }
                _ => Some(expected),
            }
        }
    };

    let mut acts = crate::act::ActAllocation::new();
    let provisioned = {
        let mut cx = SlotTxContext {
            db,
            tx: &mut *tx,
            acts: &mut acts,
            principal,
        };
        provisioner.provision_home_in(&mut cx).await?
    };
    let ProvisionOutcome::Home(home) = provisioned else {
        // Nothing was provisioned; the attempt rolls back, so nothing the
        // provisioner might have staged survives.
        return Ok(refused(
            current,
            Some(Refusal::ProvisionerUnavailable),
            slot,
        ));
    };
    verify_created_here(tx, &acts, &home).await?;

    // Only a UNIQUE violation raised here, by the registration, is a
    // retryable collision. The hook stands in for the append in tests.
    let registered = async {
        hooks.before_register(&mut *tx, attempt).await?;
        // Admission re-checks the lineage and the home's structure, never debt.
        slots::append_registration_in(db, tx, &mut acts, principal, slot, &home, previous, reason)
            .await
            .map(|_| ())
    }
    .await;
    if let Err(error) = registered {
        return Err(if is_unique_violation(&error) {
            Failure::Collision(error)
        } else {
            Failure::Fault(error)
        });
    }

    let after = slots_eval::evaluate(tx, principal, slot).await?;
    let sound = match previous {
        // The first home has no earlier homes, so debt is zero: it is ready.
        None => after.status == SlotStatus::Healthy,
        // A replacement must be structurally sound; recovery debt may keep
        // it fenced.
        Some(_) => {
            after.status == SlotStatus::Healthy
                || (after.status == SlotStatus::Unusable
                    && after.reason == Some(UnusableReason::RecoveryIncomplete))
        }
    };
    if !sound || after.target_id.as_deref() != Some(home.as_str()) {
        return Err(Error::engine("slot postcondition failed after registration").into());
    }
    let outcome = match previous {
        None => SlotOutcome::Created,
        Some(_) => SlotOutcome::Replaced,
    };
    Ok(Decision::Commit(after.into_receipt(
        slot,
        outcome,
        None,
        Some(true),
    )))
}

/// Operations only register something they created in this transaction: the
/// returned id must be a canonical id whose `home_created` or
/// `home_created_for` event carries the operation's act. Any other id (a record, a root, an existing home) is a
/// provisioner contract violation.
async fn verify_created_here(
    tx: &mut Transaction<'static, Sqlite>,
    acts: &crate::act::ActAllocation,
    home: &str,
) -> Result<()> {
    if !slots::valid_slot_id(home) {
        return Err(Error::engine("provisioned home id is not a canonical id"));
    }
    let created_in_act: Option<i64> =
        sqlx::query_scalar("SELECT act FROM content_events WHERE record_id=? AND type IN (?,?)")
            .bind(home)
            .bind(KERNEL_HOME_CREATED_EVENT)
            .bind(slots::HOME_CREATED_FOR)
            .fetch_optional(&mut **tx)
            .await?;
    match (created_in_act, acts.get()) {
        (Some(created), Some(current)) if created == current => Ok(()),
        _ => Err(Error::engine(
            "provisioned home was not created in this transaction",
        )),
    }
}

/// The lineage lookup of design §6.4. `None` means no earlier replacement of
/// `expected` exists and the action table applies.
async fn replay_first(
    tx: &mut Transaction<'static, Sqlite>,
    principal: &str,
    slot: &str,
    expected: &str,
) -> Result<Option<Decision>> {
    let winner: Option<String> = sqlx::query_scalar(
        "SELECT target_id FROM kernel_slot_lineage WHERE principal_id=? AND slot=? AND previous_target_id=?",
    )
    .bind(principal)
    .bind(slot)
    .bind(expected)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(winner) = winner else {
        return Ok(None);
    };
    // A retry never returns a stored receipt: it evaluates the current
    // target for the caller in this transaction.
    let current = slots_eval::evaluate(tx, principal, slot).await?;
    let stored = slots_eval::current_target(tx, principal, slot).await?;
    if stored.as_deref() != Some(winner.as_str()) {
        return Ok(Some(refused(current, Some(Refusal::MappingChanged), slot)));
    }
    if current.status == SlotStatus::Healthy {
        return Ok(Some(Decision::NoWrite(current.into_receipt(
            slot,
            SlotOutcome::Replayed,
            None,
            Some(false),
        ))));
    }
    // The winner is unusable, including `recovery_incomplete`: never repair or
    // reset.
    Ok(Some(refused(current, Some(Refusal::AlreadyReplaced), slot)))
}

/// What `ensure(record)` creates: an empty preferences list. The pin is the
/// one adopted at the home, resolved by `create_input_in`.
const EMPTY_PREFERENCES: &str = r#"{"foci":[]}"#;

/// `ensure(record)`: create the preferences record in the current private
/// home only when the slot is absent and the home is ready. It never creates
/// the home (Decision 2): the Foci host calls `ensure(home)` first.
pub(crate) async fn ensure_record(db: &Db, principal: &str, reason: &str) -> Result<SlotReceipt> {
    ensure_record_with(db, &NoHooks, principal, reason).await
}

pub(crate) async fn ensure_record_with<H: AttemptHooks>(
    db: &Db,
    hooks: &H,
    principal: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    run_record(db, hooks, principal, Action::Ensure, reason).await
}

/// `replace(record, expected_target)`: compare-and-set replacement of an
/// unusable preferences record, retry-safe through the lineage table. A
/// record sitting in a non-current home is rehomed, not replaced
/// (Decision 4): that case is `unsupported_recovery`.
pub(crate) async fn replace_record(
    db: &Db,
    principal: &str,
    expected_target: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    replace_record_with(db, &NoHooks, principal, expected_target, reason).await
}

pub(crate) async fn replace_record_with<H: AttemptHooks>(
    db: &Db,
    hooks: &H,
    principal: &str,
    expected_target: &str,
    reason: &str,
) -> Result<SlotReceipt> {
    let action = Action::Replace {
        expected: expected_target,
    };
    run_record(db, hooks, principal, action, reason).await
}

async fn run_record<H: AttemptHooks>(
    db: &Db,
    hooks: &H,
    principal: &str,
    action: Action<'_>,
    reason: &str,
) -> Result<SlotReceipt> {
    validate_request(action, reason)?;
    retrying(hooks, |attempt| async move {
        let mut tx = begin_write(db.write_pool()).await?;
        let decided = decide_record(db, &mut tx, hooks, principal, action, reason, attempt).await;
        conclude(tx, decided).await
    })
    .await
}

/// The record half of the action/state table (design §4.4). The home state is
/// evaluated in this same transaction, and no record is created unless the
/// home slot is ready in it.
async fn decide_record<H: AttemptHooks>(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    hooks: &H,
    principal: &str,
    action: Action<'_>,
    reason: &str,
    attempt: u32,
) -> Attempt<Decision> {
    let slot = RECORD_FOCI_PREFERENCES;
    slots_eval::require_account(tx, principal).await?;
    if let Action::Replace { expected } = action {
        if let Some(decision) = replay_first(tx, principal, slot, expected).await? {
            return Ok(decision);
        }
    }
    let current = slots_eval::evaluate(tx, principal, slot).await?;
    let previous = match action {
        Action::Ensure => match current.status {
            SlotStatus::Healthy => {
                return Ok(Decision::NoWrite(current.into_receipt(
                    slot,
                    SlotOutcome::Existing,
                    None,
                    Some(false),
                )))
            }
            SlotStatus::Unusable => return Ok(refused(current, None, slot)),
            SlotStatus::Absent => None,
        },
        Action::Replace { expected } => {
            if current.status == SlotStatus::Absent {
                return Ok(refused(current, Some(Refusal::Absent), slot));
            }
            let stored = slots_eval::current_target(tx, principal, slot).await?;
            if stored.as_deref() != Some(expected) {
                return Ok(refused(current, Some(Refusal::CasMismatch), slot));
            }
            match (current.status, current.reason) {
                (SlotStatus::Healthy, _) => {
                    return Ok(refused(current, Some(Refusal::NotUnusable), slot))
                }
                // Misplaced, or placed by a home that failed closed: the
                // preferences may be intact, so a fresh empty record would be
                // data loss that looks like recovery. Rehoming is the way.
                (_, Some(UnusableReason::WrongHome)) => {
                    return Ok(refused(current, Some(Refusal::UnsupportedRecovery), slot))
                }
                // The record is in the current home and the home is the
                // problem; a new record would sit in the same home.
                (_, Some(UnusableReason::NotPrivate | UnusableReason::RecoveryIncomplete)) => {
                    return Ok(refused(current, Some(Refusal::HomeUnusable), slot))
                }
                _ => Some(expected),
            }
        }
    };

    // The healthy-home prerequisite, in this transaction.
    let home = slots_eval::evaluate(tx, principal, HOME_FOCI_PRIVATE).await?;
    let home_id = match (home.status, home.target_id) {
        (SlotStatus::Healthy, Some(home_id)) => home_id,
        _ => return Ok(refused(current, Some(Refusal::HomeUnusable), slot)),
    };

    let mut acts = crate::act::ActAllocation::new();
    let target = create_input_in(
        db,
        tx,
        &mut acts,
        principal,
        crate::v2_standard::foci::PREFERENCES_FAMILY,
        "focus_preferences",
        FieldInput::Raw(EMPTY_PREFERENCES),
        &home_id,
    )
    .await?;

    let registered = async {
        hooks.before_register(&mut *tx, attempt).await?;
        slots::append_registration_in(
            db, tx, &mut acts, principal, slot, &target, previous, reason,
        )
        .await
        .map(|_| ())
    }
    .await;
    if let Err(error) = registered {
        return Err(if is_unique_violation(&error) {
            Failure::Collision(error)
        } else {
            Failure::Fault(error)
        });
    }

    // Creating a record must end healthy: its home was ready a moment ago, so
    // anything else is an engine fault that rolls back the new record too.
    let after = slots_eval::evaluate(tx, principal, slot).await?;
    if after.status != SlotStatus::Healthy || after.target_id.as_deref() != Some(target.as_str()) {
        return Err(Error::engine("slot postcondition failed after registration").into());
    }
    let outcome = match previous {
        None => SlotOutcome::Created,
        Some(_) => SlotOutcome::Replaced,
    };
    Ok(Decision::Commit(after.into_receipt(
        slot,
        outcome,
        None,
        Some(true),
    )))
}
