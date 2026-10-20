//! Evaluator, inspect, structure admission and gate fixtures (Foci v2 G7
//! increment 2): fixtures 1 and 17 to 25 of the design note, with the
//! operation halves (`ensure`, `replace`) left to the increments that build
//! them. States unreachable through v2 writes (`missing`, `forbidden`,
//! `wrong_target`) are made by direct SQL on the projection; each fixture says
//! so. Every inspect assertion compares the whole nine-field receipt.
use super::slots::{self, HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_eval::{
    self, Refusal, SlotOutcome, SlotReceipt, SlotRefusal, SlotStatus, UnusableReason,
};
use super::slots_tests::{engine_error, provisioned, spec, World};
use super::*;
use crate::v2_standard::foci::{FOCUS_FAMILY, PREFERENCES_FAMILY};
use serde_json::json;

pub(super) fn receipt(
    slot: &str,
    status: SlotStatus,
    reason: Option<UnusableReason>,
    target: Option<&str>,
    revision: Option<i64>,
) -> SlotReceipt {
    SlotReceipt {
        slot: slot.into(),
        status,
        outcome: SlotOutcome::Inspected,
        reason,
        refusal: None,
        target_id: target.map(String::from),
        content_revision: revision,
        policy_revision: None,
        created: None,
    }
}

pub(super) fn unusable(slot: &str, reason: UnusableReason, target: Option<&str>) -> SlotReceipt {
    receipt(slot, SlotStatus::Unusable, Some(reason), target, None)
}

impl World {
    pub(super) async fn inspect(&self, principal: &str, slot: &str) -> SlotReceipt {
        slots_eval::inspect(&self.db, principal, slot)
            .await
            .unwrap()
    }
    /// A beneficiary with a ready home slot and a ready preferences slot.
    /// Returns `(home, record)`.
    pub(super) async fn ready(&self, principal: &str) -> (String, String) {
        let home = self.home(principal).await;
        self.register(principal, HOME_FOCI_PRIVATE, &home, None)
            .await
            .unwrap();
        let record = self.record_in(principal, &home).await;
        self.register(principal, RECORD_FOCI_PREFERENCES, &record, None)
            .await
            .unwrap();
        (home, record)
    }
    pub(super) async fn focus_in(&self, owner: &str, home: &str) -> String {
        create_json_as(
            &self.db,
            owner,
            FOCUS_FAMILY,
            "focus",
            r##"{"name":"Now","colour":"#112233","view_order":[]}"##,
            home,
        )
        .await
        .unwrap()
    }
    pub(super) async fn revision(&self, record: &str) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id=?")
            .bind(record)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    pub(super) async fn sql(&self, statement: &str, binds: &[&str]) {
        let mut query = sqlx::query(statement);
        for bind in binds {
            query = query.bind(*bind);
        }
        query.execute(self.db.write_pool()).await.unwrap();
    }
    pub(super) async fn set_slot_target(&self, principal: &str, slot: &str, target: &str) {
        self.sql(
            "UPDATE kernel_slots SET target_id=? WHERE principal_id=? AND slot=?",
            &[target, principal, slot],
        )
        .await;
    }
    pub(super) async fn widen(&self, home: &str, principal: &str) {
        replace_home_policy(
            &self.db,
            principal,
            home,
            &[(principal, "manage"), (&self.admin, "view")],
        )
        .await
        .unwrap();
    }
    pub(super) async fn restore(&self, home: &str, principal: &str) {
        replace_home_policy(&self.db, principal, home, &[(principal, "manage")])
            .await
            .unwrap();
    }
    pub(super) async fn gate(&self, principal: &str, slot: &str) -> slots_eval::Gate {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let gate = slots_eval::require_healthy_slot_on(&mut tx, principal, slot)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        gate
    }
}

pub(super) fn closed(status: SlotStatus, reason: Option<UnusableReason>) -> slots_eval::Gate {
    Err(SlotRefusal { status, reason })
}

/// The receipt as explicit nine-key JSON, built by hand from the expected
/// fields so it does not depend on the serialiser it checks.
pub(super) fn nine_keys(expected: &SlotReceipt) -> serde_json::Value {
    let status = match expected.status {
        SlotStatus::Healthy => "healthy",
        SlotStatus::Absent => "absent",
        SlotStatus::Unusable => "unusable",
    };
    let outcome = match expected.outcome {
        SlotOutcome::Inspected => "inspected",
        SlotOutcome::Created => "created",
        SlotOutcome::Existing => "existing",
        SlotOutcome::Replaced => "replaced",
        SlotOutcome::Replayed => "replayed",
        SlotOutcome::Refused => "refused",
    };
    let refusal = expected.refusal.map(|refusal| match refusal {
        Refusal::Absent => "absent",
        Refusal::NotUnusable => "not_unusable",
        Refusal::CasMismatch => "cas_mismatch",
        Refusal::MappingChanged => "mapping_changed",
        Refusal::UnsupportedRecovery => "unsupported_recovery",
        Refusal::AlreadyReplaced => "already_replaced",
        Refusal::HomeUnusable => "home_unusable",
        Refusal::ProvisionerUnavailable => "provisioner_unavailable",
    });
    json!({
        "slot": expected.slot,
        "status": status,
        "outcome": outcome,
        "reason": expected.reason.map(UnusableReason::as_str),
        "refusal": refusal,
        "target_id": expected.target_id,
        "content_revision": expected.content_revision,
        "policy_revision": null,
        "created": expected.created,
    })
}

/// `got` equals `expected` field by field and serialises to exactly the nine
/// keys of the receipt contract.
pub(super) fn assert_receipt(got: &SlotReceipt, expected: &SlotReceipt) {
    assert_eq!(got, expected);
    let value = serde_json::to_value(got).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 9);
    assert_eq!(value, nine_keys(expected));
}

impl World {
    /// The full nine-field receipt matches and inspection wrote nothing: no
    /// event, no act and no table change. Captures state around the inspect,
    /// after the caller's setup mutations.
    pub(super) async fn assert_inspect(&self, principal: &str, slot: &str, expected: SlotReceipt) {
        let before = self.state().await;
        let got = self.inspect(principal, slot).await;
        assert_receipt(&got, &expected);
        assert_eq!(before, self.state().await);
    }
}

/// Fixture 1: a new principal inspects both slots. `absent`, all nine fields,
/// no event and no act. Inspect never provisions, and agent principals are
/// refused with an error.
#[tokio::test]
async fn inspect_of_a_new_principal_is_absent_and_writes_nothing() {
    let w = World::fresh().await;
    let agent = create_principal(&w.db, "agent", "Agent", "agent:a", &w.admin)
        .await
        .unwrap();
    let before = w.state().await;
    for slot in [HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES] {
        let got = w.inspect(&w.other, slot).await;
        assert_eq!(got, receipt(slot, SlotStatus::Absent, None, None, None));
        // Absent is repeatable and still writes nothing.
        assert_eq!(got, w.inspect(&w.other, slot).await);
    }
    assert_eq!(before, w.state().await);

    // All nine fields are always present in the serialised receipt.
    let got = w.inspect(&w.other, HOME_FOCI_PRIVATE).await;
    assert_eq!(
        serde_json::to_value(&got).unwrap(),
        json!({"slot": HOME_FOCI_PRIVATE, "status": "absent", "outcome": "inspected",
               "reason": null, "refusal": null, "target_id": null,
               "content_revision": null, "policy_revision": null, "created": null})
    );

    // Unknown slots and non-account principals are errors, never receipts.
    engine_error(
        slots_eval::inspect(&w.db, &w.other, "home:nope").await,
        "unknown slot",
    );
    engine_error(
        slots_eval::inspect(&w.db, &agent, HOME_FOCI_PRIVATE).await,
        "slot principal must be an account",
    );
    engine_error(
        slots_eval::inspect(&w.db, &Uuid::new_v4().to_string(), HOME_FOCI_PRIVATE).await,
        "slot principal must be an account",
    );
    assert_eq!(before, w.state().await);
}

/// A ready principal reports `healthy` for both slots, with the record's CAS
/// token and the home slot's null token; an edit moves the token. Another
/// principal sees only their own slots.
#[tokio::test]
async fn ready_slots_are_healthy_and_keyed_by_principal() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let before = w.state().await;
    assert_eq!(
        w.inspect(&w.other, HOME_FOCI_PRIVATE).await,
        receipt(
            HOME_FOCI_PRIVATE,
            SlotStatus::Healthy,
            None,
            Some(&home),
            None
        )
    );
    let revision = w.revision(&record).await;
    assert_eq!(
        w.inspect(&w.other, RECORD_FOCI_PREFERENCES).await,
        receipt(
            RECORD_FOCI_PREFERENCES,
            SlotStatus::Healthy,
            None,
            Some(&record),
            Some(revision)
        )
    );
    assert_eq!(before, w.state().await);
    revise_json_as_expected(
        &w.db,
        &w.other,
        &record,
        r#"{"foci":[{"focus_id":"focus-now","tier":"now","hidden":false}]}"#,
        Some(revision),
    )
    .await
    .unwrap();
    let edited = w.revision(&record).await;
    assert!(edited > revision);
    let got = w.inspect(&w.other, RECORD_FOCI_PREFERENCES).await;
    assert_eq!(got.content_revision, Some(edited));
    // The admin has no slots of their own and cannot see these.
    for slot in [HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES] {
        assert_eq!(
            w.inspect(&w.admin, slot).await,
            receipt(slot, SlotStatus::Absent, None, None, None)
        );
    }
}

/// Fixture 17, inspect half. Direct SQL: the record row is gone, or the slot
/// points at an id that is not a home. `missing`, guards null, the target id
/// still shown. (`replace` of a missing record is increment 5.)
#[tokio::test]
async fn a_deleted_target_is_missing() {
    let w = World::fresh().await;
    let (_home, record) = w.ready(&w.other).await;
    w.sql(
        "DELETE FROM kernel_record_fields WHERE record_id=?",
        &[&record],
    )
    .await;
    w.sql(
        "DELETE FROM kernel_record_metadata WHERE record_id=?",
        &[&record],
    )
    .await;
    w.sql("DELETE FROM kernel_records WHERE id=?", &[&record])
        .await;
    w.assert_inspect(
        &w.other,
        RECORD_FOCI_PREFERENCES,
        unusable(
            RECORD_FOCI_PREFERENCES,
            UnusableReason::Missing,
            Some(&record),
        ),
    )
    .await;
    let nowhere = Uuid::new_v4().to_string();
    w.set_slot_target(&w.other, HOME_FOCI_PRIVATE, &nowhere)
        .await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        unusable(HOME_FOCI_PRIVATE, UnusableReason::Missing, Some(&nowhere)),
    )
    .await;
    // The lineage keeps what the slot held.
    let lineage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_slot_lineage")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(lineage, 2);
}

/// Fixture 18. Direct SQL: the slot points at a record of another family, at
/// one the principal does not own, or at the workspace root: `wrong_target`.
/// A target the principal cannot see is `forbidden` with the id withheld.
#[tokio::test]
async fn a_wrong_or_hidden_target_is_reported_without_leaking() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let (admin_home, _) = w.ready(&w.admin).await;
    let slot = RECORD_FOCI_PREFERENCES;

    // Another family, owned by the principal, in their own home.
    let focus = w.focus_in(&w.other, &home).await;
    w.set_slot_target(&w.other, slot, &focus).await;
    assert_eq!(
        w.inspect(&w.other, slot).await,
        unusable(slot, UnusableReason::WrongTarget, Some(&focus))
    );
    // The right family and kind, but owned by someone else (made by SQL).
    w.set_slot_target(&w.other, slot, &record).await;
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.admin, &record],
    )
    .await;
    assert_eq!(
        w.inspect(&w.other, slot).await,
        unusable(slot, UnusableReason::WrongTarget, Some(&record))
    );
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.other, &record],
    )
    .await;
    assert_eq!(w.inspect(&w.other, slot).await.status, SlotStatus::Healthy);

    // The home slot at the workspace root: the principal's effective
    // capability on it is below Manage, which outranks `wrong_target`.
    w.set_slot_target(&w.other, HOME_FOCI_PRIVATE, KERNEL_ROOT_ID)
        .await;
    assert_eq!(
        w.inspect(&w.other, HOME_FOCI_PRIVATE).await,
        unusable(HOME_FOCI_PRIVATE, UnusableReason::Forbidden, None)
    );
    // The admin, who holds Manage on the root, sees `wrong_target` for it.
    w.set_slot_target(&w.admin, HOME_FOCI_PRIVATE, KERNEL_ROOT_ID)
        .await;
    assert_eq!(
        w.inspect(&w.admin, HOME_FOCI_PRIVATE).await,
        unusable(
            HOME_FOCI_PRIVATE,
            UnusableReason::WrongTarget,
            Some(KERNEL_ROOT_ID)
        )
    );

    // A record in another principal's private home: the principal can see
    // nothing of it, so the id is withheld.
    let hidden = w.record_in(&w.admin, &admin_home).await;
    w.set_slot_target(&w.other, slot, &hidden).await;
    assert_eq!(
        w.inspect(&w.other, slot).await,
        unusable(slot, UnusableReason::Forbidden, None)
    );
    assert_eq!(
        serde_json::to_value(w.inspect(&w.other, slot).await).unwrap()["target_id"],
        json!(null)
    );
}

/// Fixture 19: each precedence pair reports the higher-ranked reason only.
/// Pairs are built by direct SQL and policy changes; the order is the table
/// of design §4.3.
#[tokio::test]
async fn precedence_pairs_report_the_higher_reason() {
    let slot = RECORD_FOCI_PREFERENCES;

    // missing + widened: the record is gone and its home is widened.
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    w.widen(&home, &w.other).await;
    w.sql(
        "DELETE FROM kernel_record_fields WHERE record_id=?",
        &[&record],
    )
    .await;
    w.sql(
        "DELETE FROM kernel_record_metadata WHERE record_id=?",
        &[&record],
    )
    .await;
    w.sql("DELETE FROM kernel_records WHERE id=?", &[&record])
        .await;
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::Missing, Some(&record)),
    )
    .await;

    // forbidden + wrong_target: a hidden record of the wrong family.
    let w = World::fresh().await;
    let (_home, _record) = w.ready(&w.other).await;
    let (admin_home, _) = w.ready(&w.admin).await;
    let hidden_focus = w.focus_in(&w.admin, &admin_home).await;
    w.set_slot_target(&w.other, slot, &hidden_focus).await;
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::Forbidden, None),
    )
    .await;

    // wrong_target + wrong_home: a record of the wrong family in a home the
    // slot does not point at.
    let w = World::fresh().await;
    let (_home, _record) = w.ready(&w.other).await;
    let elsewhere = w.home(&w.other).await;
    let stray = w.focus_in(&w.other, &elsewhere).await;
    w.set_slot_target(&w.other, slot, &stray).await;
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::WrongTarget, Some(&stray)),
    )
    .await;

    // wrong_home + not_private: the right record in a non-current home, and
    // the current home widened.
    let w = World::fresh().await;
    let (_home, record) = w.ready(&w.other).await;
    let current = w.home(&w.other).await;
    w.set_slot_target(&w.other, HOME_FOCI_PRIVATE, &current)
        .await;
    w.widen(&current, &w.other).await;
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::WrongHome, Some(&record)),
    )
    .await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        unusable(
            HOME_FOCI_PRIVATE,
            UnusableReason::NotPrivate,
            Some(&current),
        ),
    )
    .await;

    // not_private + recovery_incomplete: the replacement home is widened
    // while the old home still holds owned Foci records. Structure outranks
    // debt; restoring the policy leaves only the debt.
    let w = World::fresh().await;
    let (h1, record) = w.ready(&w.other).await;
    let h2 = w.home(&w.other).await;
    w.register(&w.other, HOME_FOCI_PRIVATE, &h2, Some(&h1))
        .await
        .unwrap();
    w.widen(&h2, &w.other).await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        unusable(HOME_FOCI_PRIVATE, UnusableReason::NotPrivate, Some(&h2)),
    )
    .await;
    w.restore(&h2, &w.other).await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        unusable(
            HOME_FOCI_PRIVATE,
            UnusableReason::RecoveryIncomplete,
            Some(&h2),
        ),
    )
    .await;
    // The preferences record is still in H1, so it is a placement problem.
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::WrongHome, Some(&record)),
    )
    .await;
}

/// Debt is derived from the data on every evaluation: a Foci record of any
/// held family in a non-current home fences ordinary use, even after the
/// preferences record has moved; foreign-owned records and other families do
/// not; and the fence lifts by itself when the last record has moved.
#[tokio::test]
async fn recovery_debt_is_derived_and_fences_until_drained() {
    let w = World::fresh().await;
    let (h1, record) = w.ready(&w.other).await;
    let focus = w.focus_in(&w.other, &h1).await;
    let h2 = w.home(&w.other).await;
    w.register(&w.other, HOME_FOCI_PRIVATE, &h2, Some(&h1))
        .await
        .unwrap();
    let home_slot = HOME_FOCI_PRIVATE;
    let recovering = unusable(home_slot, UnusableReason::RecoveryIncomplete, Some(&h2));
    assert_eq!(w.inspect(&w.other, home_slot).await, recovering);

    // Moving the preferences record first lifts nothing: the home is still
    // recovering, so the record slot reports the same reason.
    rehome_record_as(&w.db, &w.other, &record, &h2)
        .await
        .unwrap();
    assert_eq!(w.inspect(&w.other, home_slot).await, recovering);
    assert_eq!(
        w.inspect(&w.other, RECORD_FOCI_PREFERENCES).await,
        unusable(
            RECORD_FOCI_PREFERENCES,
            UnusableReason::RecoveryIncomplete,
            Some(&record)
        )
    );
    assert_eq!(
        w.gate(&w.other, RECORD_FOCI_PREFERENCES).await,
        closed(
            SlotStatus::Unusable,
            Some(UnusableReason::RecoveryIncomplete)
        )
    );

    // Records of the principal's other families are not debt, and records
    // owned by someone else are ignored (a planted record cannot hold the
    // fence open). Both are made by SQL on the projection.
    rehome_record_as(&w.db, &w.other, &focus, &h2)
        .await
        .unwrap();
    assert_eq!(
        w.inspect(&w.other, home_slot).await.status,
        SlotStatus::Healthy
    );
    w.sql(
        "UPDATE kernel_records SET home_id=?, owner_id=? WHERE id=?",
        &[&h1, &w.admin, &focus],
    )
    .await;
    assert_eq!(
        w.inspect(&w.other, home_slot).await.status,
        SlotStatus::Healthy
    );
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.other, &focus],
    )
    .await;
    assert_eq!(w.inspect(&w.other, home_slot).await, recovering);

    // A late principal-owned write into a drained old home is debt again.
    rehome_record_as(&w.db, &w.other, &focus, &h2)
        .await
        .unwrap();
    assert_eq!(
        w.inspect(&w.other, home_slot).await.status,
        SlotStatus::Healthy
    );
    let late = w.focus_in(&w.other, &h1).await;
    assert_eq!(w.inspect(&w.other, home_slot).await, recovering);
    rehome_record_as(&w.db, &w.other, &late, &h2).await.unwrap();
    assert_eq!(
        w.inspect(&w.other, RECORD_FOCI_PREFERENCES).await.status,
        SlotStatus::Healthy
    );
}

/// Fixture 20, inspect half: the record is `missing` whatever its home is
/// doing (absent, widened, ready). The replace results are increment 5.
#[tokio::test]
async fn a_missing_record_is_missing_in_every_home_state() {
    let slot = RECORD_FOCI_PREFERENCES;
    for state in ["absent", "widened", "ready"] {
        let w = World::fresh().await;
        let (home, record) = w.ready(&w.other).await;
        w.sql(
            "DELETE FROM kernel_record_fields WHERE record_id=?",
            &[&record],
        )
        .await;
        w.sql(
            "DELETE FROM kernel_record_metadata WHERE record_id=?",
            &[&record],
        )
        .await;
        w.sql("DELETE FROM kernel_records WHERE id=?", &[&record])
            .await;
        match state {
            "absent" => {
                w.sql(
                    "DELETE FROM kernel_slots WHERE principal_id=? AND slot=?",
                    &[&w.other, HOME_FOCI_PRIVATE],
                )
                .await;
                w.assert_inspect(
                    &w.other,
                    HOME_FOCI_PRIVATE,
                    receipt(HOME_FOCI_PRIVATE, SlotStatus::Absent, None, None, None),
                )
                .await;
            }
            "widened" => w.widen(&home, &w.other).await,
            _ => {}
        }
        let expected = unusable(slot, UnusableReason::Missing, Some(&record));
        let before = w.state().await;
        let got = w.inspect(&w.other, slot).await;
        assert_eq!(got, expected, "home {state}");
        assert_eq!(
            serde_json::to_value(&got).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "home {state}"
        );
        assert_eq!(before, w.state().await, "home {state}");
    }
}

/// Fixture 21: an emptied home policy is `not_private`. The owner floor still
/// gives the owner Manage, so it is not `forbidden`; the entries are simply
/// not exactly one. A policy with an extra reader, or with only Edit, is
/// `not_private` too, and a home with no own anchor is.
#[tokio::test]
async fn a_home_policy_that_is_not_the_sole_manage_entry_is_not_private() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let slot = HOME_FOCI_PRIVATE;
    replace_home_policy(&w.db, &w.other, &home, &[])
        .await
        .unwrap();
    assert_eq!(
        w.inspect(&w.other, slot).await,
        unusable(slot, UnusableReason::NotPrivate, Some(&home))
    );
    // The record slot reports the home's reason, with its own id shown.
    assert_eq!(
        w.inspect(&w.other, RECORD_FOCI_PREFERENCES).await,
        unusable(
            RECORD_FOCI_PREFERENCES,
            UnusableReason::NotPrivate,
            Some(&record)
        )
    );
    replace_home_policy(&w.db, &w.other, &home, &[(&w.other, "edit")])
        .await
        .unwrap();
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::NotPrivate, Some(&home)),
    )
    .await;
    w.widen(&home, &w.other).await;
    w.assert_inspect(
        &w.other,
        slot,
        unusable(slot, UnusableReason::NotPrivate, Some(&home)),
    )
    .await;
    w.restore(&home, &w.other).await;
    assert_eq!(w.inspect(&w.other, slot).await.status, SlotStatus::Healthy);

    // No own anchor: the home would inherit its parent's audience.
    let anchorless = create_home(&w.db, KERNEL_ROOT_ID, None, &w.other).await;
    assert!(
        anchorless.is_err(),
        "the beneficiary cannot create under the root"
    );
    let by_admin = create_home(&w.db, KERNEL_ROOT_ID, None, &w.admin)
        .await
        .unwrap();
    w.set_slot_target(&w.other, slot, &by_admin).await;
    assert_ne!(w.inspect(&w.other, slot).await.status, SlotStatus::Healthy);
    // Owned by the admin, so even a sole-Manage policy for the beneficiary
    // is not private: the owner floor keeps the admin's access.
    let admin_owned = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.other, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    w.set_slot_target(&w.other, slot, &admin_owned).await;
    assert_eq!(
        w.inspect(&w.other, slot).await,
        unusable(slot, UnusableReason::NotPrivate, Some(&admin_owned))
    );
}

/// Fixture 22: the ancestor admin and a service principal cannot read the
/// beneficiary's home or record, and cannot widen or restore its policy: the
/// uniform hidden-or-missing refusal, indistinguishable from a missing home.
#[tokio::test]
async fn admins_and_services_cannot_see_or_widen_a_private_home() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let service = create_principal(&w.db, "agent", "Service", "agent:svc", &w.admin)
        .await
        .unwrap();
    let nowhere = Uuid::new_v4().to_string();
    for actor in [&w.admin, &service] {
        assert_eq!(
            kernel_effective_capability(&w.db, actor, &home)
                .await
                .unwrap(),
            Capability::None
        );
        assert!(read_record_as(&w.db, actor, &record)
            .await
            .unwrap()
            .is_none());
        let before = w.state().await;
        for target in [&home, &nowhere] {
            engine_error(
                replace_home_policy(&w.db, actor, target, &[(actor.as_str(), "manage")]).await,
                HIDDEN_OR_MISSING,
            );
        }
        assert_eq!(before, w.state().await);
    }
}

/// Fixture 23: who can widen. The beneficiary can; so can a later Manage
/// grantee. An unrelated principal and the root admin are refused with the
/// uniform error. (This documents the ordinary principal-checked API only;
/// raw append is fixture 24.)
#[tokio::test]
async fn only_manage_holders_can_replace_a_home_policy() {
    let w = World::fresh().await;
    let (home, _record) = w.ready(&w.other).await;
    let grantee = create_principal(&w.db, "account", "Grantee", "acct:grantee", &w.admin)
        .await
        .unwrap();
    let stranger = create_principal(&w.db, "account", "Stranger", "acct:stranger", &w.admin)
        .await
        .unwrap();
    for actor in [&stranger, &w.admin] {
        engine_error(
            replace_home_policy(&w.db, actor, &home, &[(actor.as_str(), "manage")]).await,
            HIDDEN_OR_MISSING,
        );
    }
    // The beneficiary grants Manage, which already breaks privacy.
    replace_home_policy(
        &w.db,
        &w.other,
        &home,
        &[(&w.other, "manage"), (&grantee, "manage")],
    )
    .await
    .unwrap();
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        unusable(HOME_FOCI_PRIVATE, UnusableReason::NotPrivate, Some(&home)),
    )
    .await;
    // The grantee can now replace the policy too, and can widen it further.
    replace_home_policy(
        &w.db,
        &grantee,
        &home,
        &[
            (&w.other, "manage"),
            (&grantee, "manage"),
            (&stranger, "view"),
        ],
    )
    .await
    .unwrap();
    // The stranger, now a reader, still cannot replace it.
    engine_error(
        replace_home_policy(&w.db, &stranger, &home, &[(&stranger, "manage")]).await,
        HIDDEN_OR_MISSING,
    );
    // The owner floor lets the beneficiary restore it.
    w.restore(&home, &w.other).await;
    assert_eq!(
        w.inspect(&w.other, HOME_FOCI_PRIVATE).await.status,
        SlotStatus::Healthy
    );
}

/// Fixture 24, boundary test (documents, does not endorse): the raw gated
/// append of `kernel.home_policy_replaced.v1` is accepted from any actor and
/// widens the home. Home-policy replacement is not a sealed event; the
/// evaluator is what notices.
#[tokio::test]
async fn raw_append_of_a_policy_event_is_accepted_and_noticed_by_inspect() {
    let w = World::fresh().await;
    let (home, _record) = w.ready(&w.other).await;
    let stranger = create_principal(&w.db, "account", "Stranger", "acct:stranger", &w.admin)
        .await
        .unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        &w.db,
        &mut tx,
        AppendSpec {
            record_id: home.clone(),
            event_type: KERNEL_POLICY_REPLACED_EVENT.into(),
            payload: json!({"entries": [
                {"subject_id": w.other, "capability": "manage"},
                {"subject_id": stranger, "capability": "view"},
            ]}),
            actor: Some(stranger.clone()),
        },
        &mut acts,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        w.inspect(&w.other, HOME_FOCI_PRIVATE).await,
        unusable(HOME_FOCI_PRIVATE, UnusableReason::NotPrivate, Some(&home))
    );
}

/// Fixture 25, inspect half. Direct SQL: the home slot points at a home owned
/// by someone else whose policy names only that owner, and the principal's
/// preferences record sits in it. Home `unusable`/`forbidden` with the id
/// withheld; record slot `unusable`/`wrong_home` with its own id shown, and
/// the record's own Manage (the owner floor) does not rescue it. The gate
/// refuses both. (`replace(record)` is `unsupported_recovery`, increment 5.)
#[tokio::test]
async fn a_forbidden_home_makes_the_record_slot_wrong_home() {
    let w = World::fresh().await;
    let (_home, record) = w.ready(&w.other).await;
    let foreign = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.other, "edit"), (&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    w.sql(
        "UPDATE kernel_records SET home_id=? WHERE id=?",
        &[&foreign, &record],
    )
    .await;
    w.set_slot_target(&w.other, HOME_FOCI_PRIVATE, &foreign)
        .await;
    replace_home_policy(&w.db, &w.admin, &foreign, &[(&w.admin, "manage")])
        .await
        .unwrap();
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        unusable(HOME_FOCI_PRIVATE, UnusableReason::Forbidden, None),
    )
    .await;
    w.assert_inspect(
        &w.other,
        RECORD_FOCI_PREFERENCES,
        unusable(
            RECORD_FOCI_PREFERENCES,
            UnusableReason::WrongHome,
            Some(&record),
        ),
    )
    .await;
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        closed(SlotStatus::Unusable, Some(UnusableReason::Forbidden))
    );
    assert_eq!(
        w.gate(&w.other, RECORD_FOCI_PREFERENCES).await,
        closed(SlotStatus::Unusable, Some(UnusableReason::WrongHome))
    );
}

/// The gate passes only on readiness and hands back the target (and, for a
/// record, its home). Absent is a refusal, not an error.
#[tokio::test]
async fn the_gate_passes_only_when_ready() {
    let w = World::fresh().await;
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        closed(SlotStatus::Absent, None)
    );
    let (home, record) = w.ready(&w.other).await;
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        Ok(slots_eval::SlotTarget {
            target_id: home.clone(),
            home_id: None
        })
    );
    assert_eq!(
        w.gate(&w.other, RECORD_FOCI_PREFERENCES).await,
        Ok(slots_eval::SlotTarget {
            target_id: record,
            home_id: Some(home.clone())
        })
    );
    w.widen(&home, &w.other).await;
    for slot in [HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES] {
        assert_eq!(
            w.gate(&w.other, slot).await,
            closed(SlotStatus::Unusable, Some(UnusableReason::NotPrivate))
        );
    }
}

/// One transaction, gate then read: `read_record_on` shares the gate's
/// connection, so the open private home cannot change between the two. It
/// agrees with `read_record_as` on what it returns.
#[tokio::test]
async fn gate_and_read_share_one_transaction() {
    let w = World::fresh().await;
    let (_home, record) = w.ready(&w.other).await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let target = slots_eval::require_healthy_slot_on(&mut tx, &w.other, RECORD_FOCI_PREFERENCES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.target_id, record);
    let view = read_record_on(&mut tx, &w.other, &target.target_id)
        .await
        .unwrap()
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        Some(view),
        read_record_as(&w.db, &w.other, &record).await.unwrap()
    );
    // A principal who cannot see the record gets nothing from the same call.
    let mut tx = w.db.write_pool().begin().await.unwrap();
    assert!(read_record_on(&mut tx, &w.admin, &record)
        .await
        .unwrap()
        .is_none());
    tx.rollback().await.unwrap();
}

/// Increment 3: two `create_input_in` calls in one write transaction share
/// one act allocation. Both records commit together with a single new act.
#[tokio::test]
async fn two_creates_in_one_transaction_share_one_act() {
    let w = World::fresh().await;
    let home = w.home(&w.other).await;
    let before = w.state().await;
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let first = create_input_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        PREFERENCES_FAMILY,
        "focus_preferences",
        FieldInput::Raw(r#"{"foci":[]}"#),
        &home,
    )
    .await
    .unwrap();
    let second = create_input_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        PREFERENCES_FAMILY,
        "focus_preferences",
        FieldInput::Raw(r#"{"foci":[]}"#),
        &home,
    )
    .await
    .unwrap();
    assert_ne!(first, second);
    tx.commit().await.unwrap();
    assert!(read_record_as(&w.db, &w.other, &first)
        .await
        .unwrap()
        .is_some());
    assert!(read_record_as(&w.db, &w.other, &second)
        .await
        .unwrap()
        .is_some());
    let after = w.state().await;
    assert_eq!(after.events, before.events + 2);
    assert_eq!(after.acts, before.acts + 1);
}

/// Increment 3: rolling back the outer transaction after `create_input_in`
/// and `revise_input_in` leaves no record, no event and no act.
#[tokio::test]
async fn rollback_after_create_and_revise_leaves_nothing() {
    let w = World::fresh().await;
    let home = w.home(&w.other).await;
    let record = w.record_in(&w.other, &home).await;
    let revision = w.revision(&record).await;
    let before = w.state().await;
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let fresh = create_input_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        PREFERENCES_FAMILY,
        "focus_preferences",
        FieldInput::Raw(r#"{"foci":[]}"#),
        &home,
    )
    .await
    .unwrap();
    revise_input_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        &record,
        FieldInput::Raw(r#"{"foci":[]}"#),
        Some(revision),
    )
    .await
    .unwrap();
    assert_eq!(acts.get(), Some(before.next_act + 1));
    tx.rollback().await.unwrap();
    assert!(read_record_as(&w.db, &w.other, &fresh)
        .await
        .unwrap()
        .is_none());
    assert_eq!(w.revision(&record).await, revision);
    // The rolled-back transaction handed its act back: the counter itself is
    // where it was, and the next write takes the same number.
    let act_state: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(act_state, before.next_act);
    assert_eq!(before, w.state().await);
}

/// `require_private_home_on` checks structure only: a home that is private
/// but still carries recovery debt passes it and fails the readiness gate; a
/// widened home fails both.
#[tokio::test]
async fn the_private_home_check_ignores_debt_but_not_structure() {
    let w = World::fresh().await;
    let private_home = |w: &World| {
        let (db, who) = (w.db.clone(), w.other.clone());
        async move {
            let mut tx = db.write_pool().begin().await.unwrap();
            let gate = slots_eval::require_private_home_on(&mut tx, &who)
                .await
                .unwrap();
            tx.rollback().await.unwrap();
            gate
        }
    };
    assert_eq!(private_home(&w).await, closed(SlotStatus::Absent, None));
    let (h1, _record) = w.ready(&w.other).await;
    let h2 = w.home(&w.other).await;
    w.register(&w.other, HOME_FOCI_PRIVATE, &h2, Some(&h1))
        .await
        .unwrap();
    // H2 is private but the old home holds the preferences record.
    assert_eq!(
        private_home(&w).await,
        Ok(slots_eval::SlotTarget {
            target_id: h2.clone(),
            home_id: None
        })
    );
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        closed(
            SlotStatus::Unusable,
            Some(UnusableReason::RecoveryIncomplete)
        )
    );
    w.widen(&h2, &w.other).await;
    assert_eq!(
        private_home(&w).await,
        closed(SlotStatus::Unusable, Some(UnusableReason::NotPrivate))
    );
}

/// The ordinary admissibility predicate (Decision 6, option A): owned by the
/// principal, of a held family, in the current home. Foreign-owned records,
/// other families, records in old homes and unknown ids are all excluded.
#[tokio::test]
async fn ordinary_admissibility_requires_owner_family_and_current_home() {
    let w = World::fresh().await;
    let (h1, record) = w.ready(&w.other).await;
    let focus = w.focus_in(&w.other, &h1).await;
    let check = |id: String| {
        let (db, who) = (w.db.clone(), w.other.clone());
        async move {
            let mut tx = db.write_pool().begin().await.unwrap();
            let ok = slots_eval::foci_record_admissible_on(&mut tx, &who, &id)
                .await
                .unwrap();
            tx.rollback().await.unwrap();
            ok
        }
    };
    assert!(check(record.clone()).await);
    assert!(check(focus.clone()).await);
    assert!(!check(Uuid::new_v4().to_string()).await);
    // A foreign-owned record in the current home (made by SQL: a stale or
    // hostile writer) is excluded, not consumed.
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.admin, &focus],
    )
    .await;
    assert!(!check(focus.clone()).await);
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.other, &focus],
    )
    .await;
    // A record of a family the slot does not hold.
    w.sql(
        "UPDATE kernel_records SET pin_family='native.other' WHERE id=?",
        &[&focus],
    )
    .await;
    assert!(!check(focus.clone()).await);
    // Replacing the home leaves the old records in a non-current home.
    let h2 = w.home(&w.other).await;
    w.register(&w.other, HOME_FOCI_PRIVATE, &h2, Some(&h1))
        .await
        .unwrap();
    assert!(!check(record.clone()).await);
    rehome_record_as(&w.db, &w.other, &record, &h2)
        .await
        .unwrap();
    assert!(check(record).await);
}

/// Registration admission now checks structure (design §3.2, §6.2). Each case
/// is refused with the failing reason and nothing is written.
#[tokio::test]
async fn admission_refuses_structurally_invalid_targets() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let refused = |reason: &'static str| format!("slot target is not valid for the slot: {reason}");

    // Home owned by the admin, with the beneficiary as sole Manage: the owner
    // floor would keep the admin's access.
    let admin_owned = create_home(&w.db, KERNEL_ROOT_ID, Some(&[(&p, "manage")]), &w.admin)
        .await
        .unwrap();
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &admin_owned),
        ),
        &refused("not_private"),
    )
    .await;
    // The admin owns it but its policy names the beneficiary, not the admin.
    w.refused(
        spec(
            &w.admin,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &admin_owned),
        ),
        &refused("not_private"),
    )
    .await;
    // No own anchor.
    let anchorless = create_home(&w.db, KERNEL_ROOT_ID, None, &w.admin)
        .await
        .unwrap();
    w.refused(
        spec(
            &w.admin,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &anchorless),
        ),
        &refused("not_private"),
    )
    .await;
    // A second entry, or the wrong capability.
    for entries in [
        vec![(w.admin.as_str(), "manage"), (p.as_str(), "view")],
        vec![(w.admin.as_str(), "edit")],
        vec![],
    ] {
        let home = create_home(&w.db, KERNEL_ROOT_ID, Some(&entries), &w.admin)
            .await
            .unwrap();
        w.refused(
            spec(
                &w.admin,
                slots::PROVISIONED,
                provisioned(HOME_FOCI_PRIVATE, &home),
            ),
            &refused("not_private"),
        )
        .await;
    }

    // A record slot needs the home slot first, then a record of its own in
    // that home.
    let home = w.home(&p).await;
    let record = w.record_in(&p, &home).await;
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(RECORD_FOCI_PREFERENCES, &record),
        ),
        &refused("wrong_home"),
    )
    .await;
    w.register(&p, HOME_FOCI_PRIVATE, &home, None)
        .await
        .unwrap();
    let elsewhere = w.home(&p).await;
    let stray = w.record_in(&p, &elsewhere).await;
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(RECORD_FOCI_PREFERENCES, &stray),
        ),
        &refused("wrong_home"),
    )
    .await;
    let focus = w.focus_in(&p, &home).await;
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(RECORD_FOCI_PREFERENCES, &focus),
        ),
        &refused("wrong_target"),
    )
    .await;
    // A record in another principal's home is not visible to the beneficiary.
    let (admin_home, _) = w.ready(&w.admin).await;
    let admin_record = w.record_in(&w.admin, &admin_home).await;
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(RECORD_FOCI_PREFERENCES, &admin_record),
        ),
        &refused("forbidden"),
    )
    .await;
    // The record slot also needs a ready home: a home with recovery debt is
    // not enough, though the same home would be admitted as a replacement.
    let replacement = w.home(&p).await;
    w.register(&p, HOME_FOCI_PRIVATE, &replacement, Some(&home))
        .await
        .unwrap();
    let in_replacement = w.record_in(&p, &replacement).await;
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(RECORD_FOCI_PREFERENCES, &in_replacement),
        ),
        &refused("recovery_incomplete"),
    )
    .await;

    // A valid record registers once its home is ready.
    rehome_record_as(&w.db, &p, &record, &replacement)
        .await
        .unwrap();
    rehome_record_as(&w.db, &p, &focus, &replacement)
        .await
        .unwrap();
    w.register(&p, RECORD_FOCI_PREFERENCES, &in_replacement, None)
        .await
        .unwrap();
    assert_eq!(
        w.inspect(&p, RECORD_FOCI_PREFERENCES).await.status,
        SlotStatus::Healthy
    );
    w.replay_equal().await;
}

/// The fold stays policy independent: an event admitted while the home was
/// private replays even though the home has since been widened, because replay
/// checks lineage only.
#[tokio::test]
async fn replay_ignores_todays_policy() {
    let w = World::fresh().await;
    let (home, _record) = w.ready(&w.other).await;
    w.widen(&home, &w.other).await;
    replace_home_policy(&w.db, &w.other, &home, &[])
        .await
        .unwrap();
    w.replay_equal().await;
    assert_eq!(
        w.inspect(&w.other, HOME_FOCI_PRIVATE).await.reason,
        Some(UnusableReason::NotPrivate)
    );
}

/// The reserved refusal set is closed and serialises in snake case, so the
/// receipt shape does not change when the operations land.
#[test]
fn receipt_vocabulary_is_closed_and_snake_case() {
    for (refusal, text) in [
        (Refusal::Absent, "absent"),
        (Refusal::NotUnusable, "not_unusable"),
        (Refusal::CasMismatch, "cas_mismatch"),
        (Refusal::MappingChanged, "mapping_changed"),
        (Refusal::UnsupportedRecovery, "unsupported_recovery"),
        (Refusal::AlreadyReplaced, "already_replaced"),
        (Refusal::HomeUnusable, "home_unusable"),
        (Refusal::ProvisionerUnavailable, "provisioner_unavailable"),
    ] {
        assert_eq!(serde_json::to_value(refusal).unwrap(), json!(text));
    }
    for (reason, text) in [
        (UnusableReason::Missing, "missing"),
        (UnusableReason::Forbidden, "forbidden"),
        (UnusableReason::WrongTarget, "wrong_target"),
        (UnusableReason::WrongHome, "wrong_home"),
        (UnusableReason::NotPrivate, "not_private"),
        (UnusableReason::RecoveryIncomplete, "recovery_incomplete"),
    ] {
        assert_eq!(serde_json::to_value(reason).unwrap(), json!(text));
        assert_eq!(reason.as_str(), text);
    }
    assert_eq!(PREFERENCES_FAMILY, "native.foci.preferences");
}
