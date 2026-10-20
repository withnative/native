//! Slot evaluator, receipts, structure and readiness predicates, and the
//! transaction-bound gate (Foci v2 G7, increment 2; design note 13157ec §3.2,
//! §4.2–§4.3, §5, §7.3).
//!
//! Three notions are kept apart:
//! - **Structure**: the target satisfies the slot's registry predicate. For a
//!   home: it exists, is a home, is owned by the principal, has its own
//!   anchor, and the policy is exactly one allow-Manage entry for the
//!   principal. Registration admission checks this.
//! - **Recovery debt**: the principal still owns records of a `holds` family
//!   in a non-current home of the slot's lineage.
//! - **Readiness**: structure is sound *and* debt is zero. Ordinary use and
//!   the `healthy` status need this.
//!
//! `evaluate` is the only producer of `status` and `reason`. Everything here
//! runs on a connection the caller owns, so a host operation can gate and
//! read or write inside one transaction. Nothing here writes.
use super::slots::{self, SlotKind, SlotSpec};
use super::*;

/// The receipt's `status`: `healthy` means ready (structure and no debt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SlotStatus {
    Healthy,
    Absent,
    Unusable,
}

/// Why a slot is `unusable`, in precedence order. `archived` is reserved for
/// G1 and is not produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnusableReason {
    Missing,
    Forbidden,
    WrongTarget,
    WrongHome,
    NotPrivate,
    RecoveryIncomplete,
}

impl UnusableReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Forbidden => "forbidden",
            Self::WrongTarget => "wrong_target",
            Self::WrongHome => "wrong_home",
            Self::NotPrivate => "not_private",
            Self::RecoveryIncomplete => "recovery_incomplete",
        }
    }
}

/// What an action did. Never null in a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SlotOutcome {
    Inspected,
    Created,
    Existing,
    Replaced,
    Replayed,
    Refused,
}

/// Why an action refused. Only `inspect` exists in this increment, so nothing
/// here is produced yet; the closed set is declared so the receipt shape does
/// not change when `ensure` and `replace` arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Refusal {
    Absent,
    NotUnusable,
    CasMismatch,
    MappingChanged,
    UnsupportedRecovery,
    AlreadyReplaced,
    HomeUnusable,
    ProvisionerUnavailable,
}

/// The total receipt: all nine fields are always present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SlotReceipt {
    pub slot: String,
    pub status: SlotStatus,
    pub outcome: SlotOutcome,
    pub reason: Option<UnusableReason>,
    pub refusal: Option<Refusal>,
    /// The target when healthy or unusable; null when absent and when
    /// `forbidden`.
    pub target_id: Option<String>,
    /// Record slot, healthy only: the record's CAS token.
    pub content_revision: Option<i64>,
    /// Null in G7, always: v2 has no policy revision until G12. A null here is
    /// not the audience witness.
    pub policy_revision: Option<i64>,
    pub created: Option<bool>,
}

/// What `evaluate` found. The only source of a receipt's `status`, `reason`,
/// `target_id` and guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub status: SlotStatus,
    pub reason: Option<UnusableReason>,
    pub target_id: Option<String>,
    /// Healthy record slot only: the current home the record sits in.
    pub home_id: Option<String>,
    pub content_revision: Option<i64>,
}

impl Evaluation {
    fn absent() -> Self {
        Self {
            status: SlotStatus::Absent,
            reason: None,
            target_id: None,
            home_id: None,
            content_revision: None,
        }
    }

    /// The receipt for an action that chose `outcome`, `refusal` and
    /// `created`. Status, reason, target and guards stay the evaluator's.
    pub(crate) fn into_receipt(
        self,
        slot: &str,
        outcome: SlotOutcome,
        refusal: Option<Refusal>,
        created: Option<bool>,
    ) -> SlotReceipt {
        SlotReceipt {
            slot: slot.into(),
            status: self.status,
            outcome,
            reason: self.reason,
            refusal,
            target_id: self.target_id,
            content_revision: self.content_revision,
            policy_revision: None,
            created,
        }
    }
}

/// A slot that passed the gate: the target, and for a record slot the home it
/// sits in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotTarget {
    pub target_id: String,
    pub home_id: Option<String>,
}

/// A gate that stayed shut: the evaluator's status and reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotRefusal {
    pub status: SlotStatus,
    pub reason: Option<UnusableReason>,
}

/// `Err` of the inner result is a semantic refusal; `Err` of the outer one is
/// an engine fault.
pub(crate) type Gate = std::result::Result<SlotTarget, SlotRefusal>;

fn spec_for(slot: &str) -> Result<&'static SlotSpec> {
    slots::slot_spec(slot).ok_or_else(|| Error::engine("unknown slot"))
}

pub(super) async fn require_account(conn: &mut SqliteConnection, principal: &str) -> Result<()> {
    let kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM kernel_principals WHERE principal_id=?")
            .bind(principal)
            .fetch_optional(&mut *conn)
            .await?;
    if kind.as_deref() != Some("account") {
        return Err(Error::engine("slot principal must be an account"));
    }
    Ok(())
}

pub(super) async fn current_target(
    conn: &mut SqliteConnection,
    principal: &str,
    slot: &str,
) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT target_id FROM kernel_slots WHERE principal_id=? AND slot=?")
            .bind(principal)
            .bind(slot)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

#[cfg(test)]
thread_local! {
    /// Evaluations on this thread, for the work-bound fixtures.
    pub(super) static CAPABILITY_EVALUATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// The principal's effective capability, with the kernel's uniform
/// "missing or hidden" refusal read as no capability at all.
pub(super) async fn capability_on(
    conn: &mut SqliteConnection,
    principal: &str,
    target: &str,
) -> Result<Capability> {
    #[cfg(test)]
    CAPABILITY_EVALUATIONS.with(|count| count.set(count.get() + 1));
    match kernel_effective_capability_on(conn, principal, target).await {
        Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => Ok(Capability::None),
        other => other,
    }
}

/// Recovery debt: the principal owns a record of one of the slot's `holds`
/// families in a non-current home of the slot's lineage. Recomputed from the
/// data on every call, so it survives restart and partial failure. Records
/// owned by someone else are not counted.
pub(crate) async fn recovery_debt_on(
    conn: &mut SqliteConnection,
    principal: &str,
    spec: &SlotSpec,
) -> Result<bool> {
    if spec.holds.is_empty() {
        return Ok(false);
    }
    let marks = vec!["?"; spec.holds.len()].join(",");
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM kernel_slot_lineage l \
         JOIN kernel_records r ON r.home_id = l.target_id \
         WHERE l.principal_id=? AND l.slot=? \
         AND l.target_id <> (SELECT target_id FROM kernel_slots WHERE principal_id=l.principal_id AND slot=l.slot) \
         AND r.owner_id=? AND r.pin_family IN ({marks}))"
    );
    let mut query = sqlx::query_scalar(&sql)
        .bind(principal)
        .bind(spec.name)
        .bind(principal);
    for family in spec.holds {
        query = query.bind(*family);
    }
    Ok(query.fetch_one(&mut *conn).await?)
}

/// Home structure (rows 1, 2, 3 and 5 of the precedence table) and, when
/// `with_debt`, readiness (row 6). `None` means sound.
async fn home_reason(
    conn: &mut SqliteConnection,
    principal: &str,
    spec: &SlotSpec,
    home_id: &str,
    with_debt: bool,
) -> Result<Option<UnusableReason>> {
    let owner: Option<Option<String>> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
            .bind(home_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(owner) = owner else {
        return Ok(Some(UnusableReason::Missing));
    };
    if !capability_on(conn, principal, home_id)
        .await?
        .allows(Capability::Manage)
    {
        return Ok(Some(UnusableReason::Forbidden));
    }
    if home_id == KERNEL_ROOT_ID {
        return Ok(Some(UnusableReason::WrongTarget));
    }
    if owner.as_deref() != Some(principal) {
        return Ok(Some(UnusableReason::NotPrivate));
    }
    let anchored: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policies WHERE root_id=?)")
            .bind(home_id)
            .fetch_one(&mut *conn)
            .await?;
    if !anchored {
        return Ok(Some(UnusableReason::NotPrivate));
    }
    let entries: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT subject_kind, subject_id, effect, capability FROM kernel_policy_entries WHERE root_id=?",
    )
    .bind(home_id)
    .fetch_all(&mut *conn)
    .await?;
    let sole_manage = matches!(entries.as_slice(), [(kind, subject, effect, capability)]
        if kind == "account" && subject == principal && effect == "allow"
            && Capability::from_policy_str(capability) == Some(Capability::Manage));
    if !sole_manage {
        return Ok(Some(UnusableReason::NotPrivate));
    }
    if with_debt && recovery_debt_on(conn, principal, spec).await? {
        return Ok(Some(UnusableReason::RecoveryIncomplete));
    }
    Ok(None)
}

/// `home_id, owner_id, pin_family, kind` of a `kernel_records` row.
type RecordRow = (String, Option<String>, Option<String>, Option<String>);

/// Record structure and its home dependency (rows 1 to 6). The record slot is
/// ready only if its own checks pass and its home is ready, so every home
/// reason other than `not_private` and `recovery_incomplete` fails closed as
/// `wrong_home`.
async fn record_reason(
    conn: &mut SqliteConnection,
    principal: &str,
    spec: &SlotSpec,
    record_id: &str,
) -> Result<Option<UnusableReason>> {
    let want = spec
        .record
        .as_ref()
        .ok_or_else(|| Error::engine("slot is not a record slot"))?;
    let row: Option<RecordRow> =
        sqlx::query_as("SELECT home_id, owner_id, pin_family, kind FROM kernel_records WHERE id=?")
            .bind(record_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((home_id, owner, family, kind)) = row else {
        return Ok(Some(UnusableReason::Missing));
    };
    if !capability_on(conn, principal, record_id)
        .await?
        .allows(Capability::Manage)
    {
        return Ok(Some(UnusableReason::Forbidden));
    }
    if family.as_deref() != Some(want.family)
        || kind.as_deref() != Some(want.kind)
        || owner.as_deref() != Some(principal)
    {
        return Ok(Some(UnusableReason::WrongTarget));
    }
    if current_target(conn, principal, want.home_slot)
        .await?
        .as_deref()
        != Some(home_id.as_str())
    {
        return Ok(Some(UnusableReason::WrongHome));
    }
    let home_spec = spec_for(want.home_slot)?;
    Ok(
        match home_reason(conn, principal, home_spec, &home_id, true).await? {
            None => None,
            Some(reason @ (UnusableReason::NotPrivate | UnusableReason::RecoveryIncomplete)) => {
                Some(reason)
            }
            Some(_) => Some(UnusableReason::WrongHome),
        },
    )
}

/// The one producer of `status` and `reason`. No row means `absent`;
/// otherwise the first matching reason wins (design §4.3).
pub(crate) async fn evaluate(
    conn: &mut SqliteConnection,
    principal: &str,
    slot: &str,
) -> Result<Evaluation> {
    let spec = spec_for(slot)?;
    require_account(conn, principal).await?;
    let Some(target) = current_target(conn, principal, slot).await? else {
        return Ok(Evaluation::absent());
    };
    let reason = match spec.kind {
        SlotKind::Home => home_reason(conn, principal, spec, &target, true).await?,
        SlotKind::Record => record_reason(conn, principal, spec, &target).await?,
    };
    let Some(reason) = reason else {
        let (home_id, content_revision) = match spec.kind {
            SlotKind::Home => (None, None),
            SlotKind::Record => {
                let revision: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id=?",
                )
                .bind(&target)
                .fetch_one(&mut *conn)
                .await?;
                let home: String =
                    sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
                        .bind(&target)
                        .fetch_one(&mut *conn)
                        .await?;
                (Some(home), Some(revision))
            }
        };
        return Ok(Evaluation {
            status: SlotStatus::Healthy,
            reason: None,
            target_id: Some(target),
            home_id,
            content_revision,
        });
    };
    Ok(Evaluation {
        status: SlotStatus::Unusable,
        reason: Some(reason),
        // A hidden target's id is not disclosed.
        target_id: (reason != UnusableReason::Forbidden).then_some(target),
        home_id: None,
        content_revision: None,
    })
}

/// Read-only inspection on the caller's connection. It never provisions and
/// writes nothing.
pub(crate) async fn inspect_on(
    conn: &mut SqliteConnection,
    principal: &str,
    slot: &str,
) -> Result<SlotReceipt> {
    Ok(evaluate(conn, principal, slot).await?.into_receipt(
        slot,
        SlotOutcome::Inspected,
        None,
        None,
    ))
}

/// `inspect` in its own read snapshot.
pub(crate) async fn inspect(db: &Db, principal: &str, slot: &str) -> Result<SlotReceipt> {
    let mut snapshot = db.write_pool().begin().await?;
    let receipt = inspect_on(&mut snapshot, principal, slot).await;
    snapshot.rollback().await?;
    receipt
}

/// The registration admission check: the structure the slot's registry entry
/// declares, evaluated in the admitting transaction. A home needs structure
/// only (a replacement starts with debt); a record needs its own structure
/// and a ready home.
pub(crate) async fn admit_structure_on(
    conn: &mut SqliteConnection,
    principal: &str,
    slot: &str,
    target_id: &str,
) -> Result<()> {
    let spec = spec_for(slot)?;
    let reason = match spec.kind {
        SlotKind::Home => home_reason(conn, principal, spec, target_id, false).await?,
        SlotKind::Record => record_reason(conn, principal, spec, target_id).await?,
    };
    match reason {
        None => Ok(()),
        Some(reason) => Err(Error::engine(format!(
            "slot target is not valid for the slot: {}",
            reason.as_str()
        ))),
    }
}

fn refusal_of(evaluation: &Evaluation) -> SlotRefusal {
    SlotRefusal {
        status: evaluation.status,
        reason: evaluation.reason,
    }
}

/// The transaction-bound gate: passes only on readiness. Every Foci host
/// operation opens one transaction, calls this on it, and does its content
/// reads and writes on the same transaction.
pub(crate) async fn require_healthy_slot_on(
    conn: &mut SqliteConnection,
    principal: &str,
    slot: &str,
) -> Result<Gate> {
    let evaluation = evaluate(conn, principal, slot).await?;
    if evaluation.status != SlotStatus::Healthy {
        return Ok(Err(refusal_of(&evaluation)));
    }
    let target_id = evaluation
        .target_id
        .ok_or_else(|| Error::engine("healthy slot has no target"))?;
    Ok(Ok(SlotTarget {
        target_id,
        home_id: evaluation.home_id,
    }))
}

/// Structure of the principal's current private home only, ignoring recovery
/// debt. The rehome batch needs a correct private destination while ordinary
/// use is still fenced.
pub(crate) async fn require_private_home_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Gate> {
    let spec = spec_for(slots::HOME_FOCI_PRIVATE)?;
    require_account(conn, principal).await?;
    let Some(home) = current_target(conn, principal, spec.name).await? else {
        return Ok(Err(refusal_of(&Evaluation::absent())));
    };
    Ok(
        match home_reason(conn, principal, spec, &home, false).await? {
            None => Ok(SlotTarget {
                target_id: home,
                home_id: None,
            }),
            Some(reason) => Err(SlotRefusal {
                status: SlotStatus::Unusable,
                reason: Some(reason),
            }),
        },
    )
}

/// The ordinary admissibility predicate (Decision 6, option A): a record may
/// be consumed by ordinary Foci use only if the principal owns it, it is of a
/// `holds` family, and it sits in the principal's **current** private home.
/// A record that fails is excluded and counted by the consumer, never used
/// silently. Recovery sources use a different predicate (they must sit in a
/// non-current home): `slots_recovery::recovery_source_eligible_on`.
pub(crate) async fn foci_record_admissible_on(
    conn: &mut SqliteConnection,
    principal: &str,
    record_id: &str,
) -> Result<bool> {
    let spec = spec_for(slots::HOME_FOCI_PRIVATE)?;
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
    Ok(current_target(conn, principal, spec.name).await?.as_deref() == Some(home_id.as_str()))
}
