//! Transaction-bound gate fixtures (Foci v2 G7 increment 5): fixtures 12 to 16
//! of the design note. Every Foci host operation opens one transaction, calls
//! the gate on it, and does its content reads and writes on the same
//! transaction. These fixtures drive the schedules that rule exists for: a
//! widen between gate and use, a home-slot replace between gate and use, the
//! negative control showing the old two-call shape lets the use through, and
//! the Focus, saved-view and order revise checks.
//!
//! The interleavings use the file-backed WAL database `World` creates, because
//! the in-memory database cannot show a reader and a writer on separate
//! connections.
use super::slots::{HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_eval::{self, SlotRefusal, SlotStatus, UnusableReason};
use super::slots_eval_tests::closed;
use super::slots_host::{
    read_preferences_on, revise_foci_record, revise_foci_record_in, revise_preferences,
    revise_preferences_in, UseRefusal,
};
use super::slots_tests::World;
use super::*;
use crate::v2_standard::foci::SAVED_VIEW_FAMILY;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

const PREFS: &str = RECORD_FOCI_PREFERENCES;

/// Spawn a competing writer and return once it has reached the write-begin
/// boundary: the notification fires immediately before its first
/// `BEGIN IMMEDIATE` is submitted, so the caller knows the task is running and
/// about to queue for the lock the caller holds, with no elapsed-time guess.
/// The timeout only bounds a hang; it never orders anything. The returned
/// handle must still be pending when the caller checks it, because the writer
/// cannot get past `BEGIN IMMEDIATE` until the caller's transaction ends.
pub(super) async fn spawn_queued_writer<T, F>(work: F) -> tokio::task::JoinHandle<T>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let started = Arc::new(tokio::sync::Notify::new());
    let handle = tokio::spawn(crate::db::with_before_begin_write_notification(
        started.clone(),
        work,
    ));
    tokio::time::timeout(Duration::from_secs(30), started.notified())
        .await
        .expect("the competing writer never reached its write begin");
    handle
}

/// The gate's refusal as a gated operation reports it.
fn shut(status: SlotStatus, reason: UnusableReason) -> UseRefusal {
    UseRefusal::Gate(SlotRefusal {
        status,
        reason: Some(reason),
    })
}

fn one_focus(id: &str) -> String {
    format!(r#"{{"foci":[{{"focus_id":"{id}","tier":"now","hidden":false}}]}}"#)
}

impl World {
    async fn latest_seq(&self, record: &str, event_type_like: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=? AND type LIKE ?",
        )
        .bind(record)
        .bind(event_type_like)
        .fetch_one(self.db.pool())
        .await
        .unwrap()
    }
    async fn field(&self, principal: &str, record: &str, name: &str) -> serde_json::Value {
        let view = read_record_as(&self.db, principal, record)
            .await
            .unwrap()
            .unwrap();
        view.fields.get(name).cloned().unwrap_or_default()
    }
}

/// Fixture 12 (file): write path. T1 opens a write transaction and the gate
/// passes. T2 then tries to widen the home and queues for the writer lock.
/// T1's reads and revisions run under a private home and commit; only then
/// does the widen apply, ordered after them. The next gate call refuses
/// `not_private`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_widen_waits_for_the_write_transaction_that_passed_the_gate() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let focus = w.focus_in(&w.other, &home).await;
    let (pref_rev, focus_rev) = (w.revision(&record).await, w.revision(&focus).await);

    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let gate = slots_eval::require_healthy_slot_on(&mut tx, &w.other, HOME_FOCI_PRIVATE)
        .await
        .unwrap();
    assert!(gate.is_ok());

    let widen = {
        let (db, who, admin, target) =
            (w.db.clone(), w.other.clone(), w.admin.clone(), home.clone());
        spawn_queued_writer(async move {
            replace_home_policy(&db, &who, &target, &[(&who, "manage"), (&admin, "view")]).await
        })
        .await
    };
    assert!(
        !widen.is_finished(),
        "T2 reached its write begin and must wait for T1's write lock"
    );

    // T1's work still sees a private home, because the widen cannot commit.
    assert!(revise_preferences_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        FieldInput::Raw(&one_focus("f1")),
        pref_rev,
    )
    .await
    .unwrap()
    .is_ok());
    assert!(revise_foci_record_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        &focus,
        FieldInput::Raw(r#"{"name":"Later"}"#),
        focus_rev,
    )
    .await
    .unwrap()
    .is_ok());
    let during = read_preferences_on(&mut tx, &w.other).await.unwrap();
    assert!(during.unwrap().is_some());
    assert!(!widen.is_finished());
    tx.commit().await.unwrap();
    widen.await.unwrap().unwrap();

    // The revisions are ordered before the widen; the next gate refuses.
    let policy = w.latest_seq(&home, "kernel.home_policy_replaced%").await;
    assert!(w.latest_seq(&record, "kernel.record_revised%").await < policy);
    assert!(w.latest_seq(&focus, "kernel.record_revised%").await < policy);
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        closed(SlotStatus::Unusable, Some(UnusableReason::NotPrivate))
    );
    assert_eq!(w.field(&w.other, &focus, "name").await, "Later");
}

/// Fixture 13 (file): read path. R1 opens a read transaction on its own
/// connection and the gate passes. A writer widens the home and changes the
/// record on another connection and commits while R1 stays open. R1's later
/// content read sees the pre-widen state consistently: it is ordered before
/// the writer. A new reader R2 is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_passed_the_gate_keeps_one_snapshot() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let revision = w.revision(&record).await;

    let mut r1 = w.db.write_pool().begin().await.unwrap();
    let target = slots_eval::require_healthy_slot_on(&mut r1, &w.other, PREFS)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.target_id, record);

    // The writer commits on other connections while R1 stays open.
    w.widen(&home, &w.other).await;
    revise_json_as_expected(
        &w.db,
        &w.other,
        &record,
        &one_focus("after-widen"),
        Some(revision),
    )
    .await
    .unwrap();

    let view = read_record_on(&mut r1, &w.other, &target.target_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.fields.get("foci"), Some(&serde_json::json!([])));
    assert_eq!(view.revision, revision);
    let entries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kernel_policy_entries WHERE root_id=?")
            .bind(&home)
            .fetch_one(&mut *r1)
            .await
            .unwrap();
    assert_eq!(entries, 1, "R1 still sees the private policy");
    // Inside R1 the gate agrees with itself.
    assert!(
        slots_eval::require_healthy_slot_on(&mut r1, &w.other, PREFS)
            .await
            .unwrap()
            .is_ok()
    );
    r1.rollback().await.unwrap();

    // R2, opened after the commit, is refused.
    let mut r2 = w.db.write_pool().begin().await.unwrap();
    assert_eq!(
        read_preferences_on(&mut r2, &w.other).await.unwrap(),
        Err(shut(SlotStatus::Unusable, UnusableReason::NotPrivate))
    );
    r2.rollback().await.unwrap();
}

/// Fixture 14: the negative control. The old two-call shape, a gate in its own
/// transaction and then `read_record_as` (or an ordinary revise), lets the use
/// through after a widen in between. The one-transaction shape does not.
#[tokio::test]
async fn the_old_two_call_shape_lets_a_widened_home_through() {
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let revision = w.revision(&record).await;

    // Gate in its own transaction: it passes and the transaction ends.
    let target = w.gate(&w.other, PREFS).await.unwrap();
    assert_eq!(target.target_id, record);
    w.widen(&home, &w.other).await;

    // The separate read succeeds after the widen, and so does an ungated write.
    let leaked = read_record_as(&w.db, &w.other, &target.target_id)
        .await
        .unwrap();
    assert!(leaked.is_some(), "the old shape read from an exposed home");
    revise_json_as_expected(&w.db, &w.other, &record, &one_focus("leak"), Some(revision))
        .await
        .unwrap();
    // The gate itself would have refused at that point.
    assert_eq!(
        w.gate(&w.other, PREFS).await,
        closed(SlotStatus::Unusable, Some(UnusableReason::NotPrivate))
    );

    // Control: the one-transaction shape refuses both uses, and writes nothing.
    let revision = w.revision(&record).await;
    let before = w.state().await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    assert_eq!(
        read_preferences_on(&mut tx, &w.other).await.unwrap(),
        Err(shut(SlotStatus::Unusable, UnusableReason::NotPrivate))
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        revise_preferences(&w.db, &w.other, FieldInput::Raw(&one_focus("no")), revision)
            .await
            .unwrap(),
        Err(shut(SlotStatus::Unusable, UnusableReason::NotPrivate))
    );
    assert_eq!(before, w.state().await);
}

/// Fixture 15: replacing the home slot between a gate and a use. In different
/// transactions a stale use is possible: it lands in a record whose home was
/// since replaced away. In one write transaction the use runs entirely before
/// the exposure and the replacement, and later uses are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacing_the_home_between_gate_and_use() {
    // Different transactions: the gate passes, the home is exposed and
    // replaced, then the use runs and succeeds against the stale answer.
    let w = World::fresh().await;
    let (h1, record) = w.ready(&w.other).await;
    let target = w.gate(&w.other, PREFS).await.unwrap();
    w.widen(&h1, &w.other).await;
    let h2 = w.rec_replace_home(&w.other, &h1).await.target_id.unwrap();
    assert_ne!(h1, h2);
    revise_json_as_expected(
        &w.db,
        &w.other,
        &target.target_id,
        &one_focus("stale"),
        Some(w.revision(&record).await),
    )
    .await
    .unwrap();
    assert_eq!(w.rec_home_of(&record).await, h1, "written in the old home");
    assert_eq!(
        w.inspect(&w.other, PREFS).await.reason,
        Some(UnusableReason::WrongHome)
    );

    // One transaction: the replacement waits for the use.
    let w = World::fresh().await;
    let (h1, record) = w.ready(&w.other).await;
    let revision = w.revision(&record).await;
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    assert!(
        slots_eval::require_healthy_slot_on(&mut tx, &w.other, HOME_FOCI_PRIVATE)
            .await
            .unwrap()
            .is_ok()
    );
    let exposed_then_replaced = {
        let w2 = (w.db.clone(), w.other.clone(), w.admin.clone(), h1.clone());
        spawn_queued_writer(async move {
            let (db, who, admin, h1) = w2;
            replace_home_policy(&db, &who, &h1, &[(&who, "manage"), (&admin, "view")])
                .await
                .unwrap();
            let provisioner = super::slots_ops_tests::TestProvisioner::new(
                &admin,
                super::slots_ops_tests::Mode::Honest,
            );
            super::slots_ops::replace_home(&db, &provisioner, &who, &h1, "test")
                .await
                .unwrap()
        })
        .await
    };
    assert!(
        !exposed_then_replaced.is_finished(),
        "the exposure reached its write begin and must wait for T1"
    );
    assert!(revise_preferences_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        FieldInput::Raw(&one_focus("before")),
        revision,
    )
    .await
    .unwrap()
    .is_ok());
    tx.commit().await.unwrap();
    let replaced = exposed_then_replaced.await.unwrap();
    let h2 = replaced.target_id.unwrap();
    // The use is entirely before the exposure and the replacement.
    let use_seq = w.latest_seq(&record, "kernel.record_revised%").await;
    assert!(use_seq < w.latest_seq(&h1, "kernel.home_policy_replaced%").await);
    assert_eq!(
        w.field(&w.other, &record, "foci").await[0]["focus_id"],
        "before"
    );
    // Afterwards the home is recovering, so every gated use is refused.
    let revision = w.revision(&record).await;
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        closed(
            SlotStatus::Unusable,
            Some(UnusableReason::RecoveryIncomplete)
        )
    );
    let before = w.state().await;
    assert_eq!(
        revise_preferences(
            &w.db,
            &w.other,
            FieldInput::Raw(&one_focus("after")),
            revision
        )
        .await
        .unwrap(),
        Err(shut(SlotStatus::Unusable, UnusableReason::WrongHome))
    );
    assert_eq!(before, w.state().await);
    assert_ne!(h1, h2);
}

/// Fixture 16: Focus, saved-view and order revise run the gate and the
/// ordinary admissibility predicate on the write transaction, because generic
/// revise checks only Edit and the revision. A Focus owned by someone else, a
/// record of another family, a record in a home that is not the current home
/// and an unknown id are all refused although Edit and the revision pass; the
/// valid ones succeed with the revision checked on the same transaction; a
/// stale revision conflicts and writes nothing.
#[tokio::test]
async fn focus_view_and_order_revise_go_through_the_gate() {
    let w = World::fresh().await;
    let (home, pref) = w.ready(&w.other).await;
    let focus = w.focus_in(&w.other, &home).await;
    let view = create_json_as(
        &w.db,
        &w.other,
        SAVED_VIEW_FAMILY,
        "record_view",
        r#"{"name":"V","definition":{"app":"native.docs","target":{"record_id":"kernel:root"}}}"#,
        &home,
    )
    .await
    .unwrap();

    // The valid ones succeed: a Focus, its view order, a saved view.
    let rev = w.revision(&focus).await;
    assert!(revise_foci_record(
        &w.db,
        &w.other,
        &focus,
        FieldInput::Raw(r#"{"name":"Later"}"#),
        rev
    )
    .await
    .unwrap()
    .is_ok());
    assert_eq!(w.field(&w.other, &focus, "name").await, "Later");
    let rev = w.revision(&focus).await;
    assert!(revise_foci_record(
        &w.db,
        &w.other,
        &focus,
        FieldInput::Raw(&format!(r#"{{"view_order":["{view}"]}}"#)),
        rev,
    )
    .await
    .unwrap()
    .is_ok());
    assert_eq!(
        w.field(&w.other, &focus, "view_order").await[0],
        view.as_str()
    );
    let rev = w.revision(&view).await;
    assert!(revise_foci_record(
        &w.db,
        &w.other,
        &view,
        FieldInput::Raw(r#"{"name":"W"}"#),
        rev
    )
    .await
    .unwrap()
    .is_ok());
    // The Focus order: the preferences list, through the record slot's gate.
    let rev = w.revision(&pref).await;
    assert!(
        revise_preferences(&w.db, &w.other, FieldInput::Raw(&one_focus(&focus)), rev)
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        w.field(&w.other, &pref, "foci").await[0]["focus_id"],
        focus.as_str()
    );

    // A stale revision conflicts on the same write transaction, writing nothing.
    let before = w.state().await;
    let stale = revise_foci_record(
        &w.db,
        &w.other,
        &focus,
        FieldInput::Raw(r#"{"name":"Never"}"#),
        w.revision(&focus).await - 1,
    )
    .await;
    assert!(matches!(stale, Err(Error::Conflict(_))), "got {stale:?}");
    assert_eq!(before, w.state().await);
    let stale_prefs =
        revise_preferences(&w.db, &w.other, FieldInput::Raw(&one_focus("x")), rev - 1).await;
    assert!(
        matches!(stale_prefs, Err(Error::Conflict(_))),
        "got {stale_prefs:?}"
    );
    assert_eq!(before, w.state().await);

    // Refused records: each would pass generic Edit and the revision.
    let foreign = w.focus_in(&w.other, &home).await;
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.admin, &foreign],
    )
    .await;
    let other_family = w.focus_in(&w.other, &home).await;
    w.sql(
        "UPDATE kernel_records SET pin_family='native.other' WHERE id=?",
        &[&other_family],
    )
    .await;
    let elsewhere_home = w.home(&w.other).await;
    let elsewhere = create_json_as(
        &w.db,
        &w.other,
        crate::v2_standard::foci::FOCUS_FAMILY,
        "focus",
        r##"{"name":"Elsewhere","view_order":[]}"##,
        &elsewhere_home,
    )
    .await
    .unwrap();
    let unknown = Uuid::new_v4().to_string();
    for (label, id) in [
        ("foreign-owned", &foreign),
        ("other family", &other_family),
        ("not the current home", &elsewhere),
        ("unknown", &unknown),
    ] {
        let before = w.state().await;
        let rev = w.revision(id).await;
        let got = revise_foci_record(&w.db, &w.other, id, FieldInput::Raw(r#"{"name":"Z"}"#), rev)
            .await
            .unwrap();
        assert_eq!(got, Err(UseRefusal::NotAdmissible), "{label}");
        assert_eq!(before, w.state().await, "{label} wrote");
    }
    // Control: generic revise, without the gate, passes for the ones whose
    // definition still resolves, so the refusals above are G7's own.
    for id in [&foreign, &elsewhere] {
        let rev = w.revision(id).await;
        let mut tx = begin_write(w.db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        revise_input_in(
            &w.db,
            &mut tx,
            &mut acts,
            &w.other,
            id,
            FieldInput::Raw(r#"{"name":"Z"}"#),
            Some(rev),
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
    }
}

/// Fixture 16, old-home and shut-gate cases. A Focus owned by the principal
/// that still sits in a replaced-away home, and every revise while the home
/// is exposed or recovering, are refused by the gate itself: the debt fences
/// the whole home. Once everything has moved into the current home the same
/// revise succeeds.
#[tokio::test]
async fn a_shut_gate_refuses_every_revise_until_the_home_is_ready() {
    let w = World::fresh().await;
    let (h1, pref) = w.ready(&w.other).await;
    let focus = w.focus_in(&w.other, &h1).await;
    w.widen(&h1, &w.other).await;
    let (focus_rev, pref_rev) = (w.revision(&focus).await, w.revision(&pref).await);
    let before = w.state().await;
    let exposed = shut(SlotStatus::Unusable, UnusableReason::NotPrivate);
    assert_eq!(
        revise_foci_record(
            &w.db,
            &w.other,
            &focus,
            FieldInput::Raw(r#"{"name":"A"}"#),
            focus_rev
        )
        .await
        .unwrap(),
        Err(exposed)
    );
    assert_eq!(
        revise_preferences(&w.db, &w.other, FieldInput::Raw(&one_focus("a")), pref_rev)
            .await
            .unwrap(),
        Err(exposed)
    );
    assert_eq!(before, w.state().await);

    let h2 = w.rec_replace_home(&w.other, &h1).await.target_id.unwrap();
    let before = w.state().await;
    assert_eq!(
        revise_foci_record(
            &w.db,
            &w.other,
            &focus,
            FieldInput::Raw(r#"{"name":"A"}"#),
            focus_rev
        )
        .await
        .unwrap(),
        Err(shut(
            SlotStatus::Unusable,
            UnusableReason::RecoveryIncomplete
        ))
    );
    assert_eq!(
        revise_preferences(&w.db, &w.other, FieldInput::Raw(&one_focus("a")), pref_rev)
            .await
            .unwrap(),
        Err(shut(SlotStatus::Unusable, UnusableReason::WrongHome))
    );
    assert_eq!(before, w.state().await);

    // Moving everything into the current home reopens the gate.
    rehome_record_as(&w.db, &w.other, &pref, &h2).await.unwrap();
    rehome_record_as(&w.db, &w.other, &focus, &h2)
        .await
        .unwrap();
    let focus_rev = w.revision(&focus).await;
    assert!(revise_foci_record(
        &w.db,
        &w.other,
        &focus,
        FieldInput::Raw(r#"{"name":"A"}"#),
        focus_rev
    )
    .await
    .unwrap()
    .is_ok());
    let pref_rev = w.revision(&pref).await;
    assert!(
        revise_preferences(&w.db, &w.other, FieldInput::Raw(&one_focus("a")), pref_rev)
            .await
            .unwrap()
            .is_ok()
    );
}
