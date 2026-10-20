//! Gated Foci host operations (Foci v2 G7, increment 5; design note 13157ec
//! §5). The rule for every Foci host operation is: open one transaction, call
//! the gate on it, and do every content read and write for that operation on
//! the same transaction. These are the first consumers of that rule: reading
//! and revising the preferences record (gated on the record slot), and
//! revising a Focus, a saved view or the Focus order (gated on the home slot
//! and the ordinary admissibility predicate, because generic revise checks
//! only Edit and the revision). Increment 6 adds the other two consumers
//! Decision 6 names: reading one Foci record and listing the Foci records of
//! a family. Both exclude what the ordinary predicate rejects, and the listing
//! reports how many foreign-owned records it left out.
//!
//! A shut gate or an inadmissible record is a semantic refusal returned as a
//! result; engine faults and revision conflicts stay errors. The `_in`
//! variants run on a transaction the caller owns, so a test, or a later host
//! operation, can interleave other work around them.
use super::slots::{HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_eval::{self, SlotRefusal};
use super::slots_recovery::{self, ForeignScope};
use super::*;

/// Why a gated operation did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UseRefusal {
    /// The slot gate stayed shut: the evaluator's status and reason.
    Gate(SlotRefusal),
    /// The target is not a Foci record the principal may use: not owned by
    /// them, not of a Foci family, or not in their current private home.
    NotAdmissible,
}

pub(crate) type Used<T> = std::result::Result<T, UseRefusal>;

/// Read the preferences record under the record-slot gate, on the caller's
/// connection. `None` inside the result means the principal cannot view it.
pub(crate) async fn read_preferences_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Used<Option<KernelRecordView>>> {
    let target = match slots_eval::require_healthy_slot_on(conn, principal, RECORD_FOCI_PREFERENCES)
        .await?
    {
        Ok(target) => target,
        Err(refusal) => return Ok(Err(UseRefusal::Gate(refusal))),
    };
    Ok(Ok(read_record_on(conn, principal, &target.target_id).await?))
}

/// Revise the preferences record: the record slot's gate, then the revision
/// check and write, all on this transaction.
pub(crate) async fn revise_preferences_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    input: FieldInput<'_>,
    expected_revision: i64,
) -> Result<Used<()>> {
    let target =
        match slots_eval::require_healthy_slot_on(tx, principal, RECORD_FOCI_PREFERENCES).await? {
            Ok(target) => target,
            Err(refusal) => return Ok(Err(UseRefusal::Gate(refusal))),
        };
    revise_input_in(
        db,
        tx,
        acts,
        principal,
        &target.target_id,
        input,
        Some(expected_revision),
    )
    .await?;
    Ok(Ok(()))
}

/// Revise a Focus, a saved view or the Focus order: the home slot's gate, the
/// ordinary admissibility predicate on the target, then the revision check
/// and write, all on this transaction.
pub(crate) async fn revise_foci_record_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    record_id: &str,
    input: FieldInput<'_>,
    expected_revision: i64,
) -> Result<Used<()>> {
    if let Err(refusal) =
        slots_eval::require_healthy_slot_on(tx, principal, HOME_FOCI_PRIVATE).await?
    {
        return Ok(Err(UseRefusal::Gate(refusal)));
    }
    if !slots_eval::foci_record_admissible_on(tx, principal, record_id).await? {
        return Ok(Err(UseRefusal::NotAdmissible));
    }
    revise_input_in(
        db,
        tx,
        acts,
        principal,
        record_id,
        input,
        Some(expected_revision),
    )
    .await?;
    Ok(Ok(()))
}

/// The principal's own Foci records of one family in their current home, and
/// how many foreign-owned Foci records in that home were left out (only those
/// the principal can View; no field of a foreign record is read). The count
/// is exact up to and including `slots_recovery::CAP`, then saturates and
/// `foreign_capped` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FociListing {
    pub records: Vec<String>,
    pub foreign_skipped: i64,
    pub foreign_capped: bool,
}

/// Read one Foci record under the home-slot gate and the ordinary
/// admissibility predicate, on the caller's connection. A record the
/// predicate rejects is a `NotAdmissible` refusal; it is never read.
pub(crate) async fn read_foci_record_on(
    conn: &mut SqliteConnection,
    principal: &str,
    record_id: &str,
) -> Result<Used<Option<KernelRecordView>>> {
    if let Err(refusal) =
        slots_eval::require_healthy_slot_on(conn, principal, HOME_FOCI_PRIVATE).await?
    {
        return Ok(Err(UseRefusal::Gate(refusal)));
    }
    if !slots_eval::foci_record_admissible_on(conn, principal, record_id).await? {
        return Ok(Err(UseRefusal::NotAdmissible));
    }
    Ok(Ok(read_record_on(conn, principal, record_id).await?))
}

/// List the principal's Foci records of `family` under the home-slot gate.
/// The selection filters on ownership and the current home in SQL, so a
/// foreign-owned record is never selected; the count of those comes from a
/// separate ids-only query (design §7.3).
pub(crate) async fn list_foci_records_on(
    conn: &mut SqliteConnection,
    principal: &str,
    family: &str,
) -> Result<Used<FociListing>> {
    let target =
        match slots_eval::require_healthy_slot_on(conn, principal, HOME_FOCI_PRIVATE).await? {
            Ok(target) => target,
            Err(refusal) => return Ok(Err(UseRefusal::Gate(refusal))),
        };
    let spec =
        super::slots::slot_spec(HOME_FOCI_PRIVATE).ok_or_else(|| Error::engine("unknown slot"))?;
    if !spec.holds.contains(&family) {
        return Err(Error::engine("not a Foci family"));
    }
    let records: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM kernel_records WHERE home_id=? AND owner_id=? AND pin_family=? ORDER BY id",
    )
    .bind(&target.target_id)
    .bind(principal)
    .bind(family)
    .fetch_all(&mut *conn)
    .await?;
    let foreign =
        slots_recovery::visible_foreign_on(conn, principal, ForeignScope::Current, 0).await?;
    Ok(Ok(FociListing {
        records,
        foreign_skipped: foreign.total,
        foreign_capped: foreign.capped,
    }))
}

/// Commit a transaction whose operation ran, roll back one that was refused
/// or failed.
async fn finish(tx: Transaction<'static, Sqlite>, used: Result<Used<()>>) -> Result<Used<()>> {
    match used {
        Ok(Ok(())) => {
            tx.commit().await?;
            Ok(Ok(()))
        }
        other => {
            tx.rollback().await?;
            other
        }
    }
}

/// `revise_preferences_in` in its own write transaction.
pub(crate) async fn revise_preferences(
    db: &Db,
    principal: &str,
    input: FieldInput<'_>,
    expected_revision: i64,
) -> Result<Used<()>> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let used =
        revise_preferences_in(db, &mut tx, &mut acts, principal, input, expected_revision).await;
    finish(tx, used).await
}

/// `revise_foci_record_in` in its own write transaction.
pub(crate) async fn revise_foci_record(
    db: &Db,
    principal: &str,
    record_id: &str,
    input: FieldInput<'_>,
    expected_revision: i64,
) -> Result<Used<()>> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let used = revise_foci_record_in(
        db,
        &mut tx,
        &mut acts,
        principal,
        record_id,
        input,
        expected_revision,
    )
    .await;
    finish(tx, used).await
}
