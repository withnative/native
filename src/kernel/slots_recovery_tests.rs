//! Recovery fence, source selection and ownership fixtures (Foci v2 G7
//! increment 6): fixtures 30 to 36 of the design note (13157ec §8.4, §9), plus
//! direct checks of the new helpers and of the Decision 6 consumers.
//!
//! The batch under test is `slots_batch`, the real batch (Foci v2 G6
//! increment 1) that took over from G7's `cfg(test)` stand-in. Everything runs on the file-backed
//! WAL database `World` creates, so the restart fixtures close every handle
//! and reopen the same file. Concurrency is ordered with the
//! before-begin-write notification seam, never with sleeps.
use super::slots::{HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_batch::{
    rehome_batch, rehome_batch_in, rehome_batch_with, BatchHooks, BatchReceipt, BatchRefusal,
    NoBatchHooks,
};
use super::slots_eval::UnusableReason as Why;
use super::slots_eval::{self, Refusal, SlotOutcome, SlotReceipt, SlotRefusal, SlotStatus};
use super::slots_eval_tests::{assert_receipt, closed, unusable};
use super::slots_gate_tests::spawn_queued_writer;
use super::slots_host;
use super::slots_host::{
    list_foci_records_on, read_foci_record_on, revise_foci_record, FociListing, UseRefusal,
};
use super::slots_ops::replace_home;
use super::slots_ops_tests::{Mode, TestProvisioner};
use super::slots_recovery::{self, visible_foreign_on, ForeignScope};
use super::slots_tests::World;
use super::*;
use crate::v2_standard::foci::{FOCUS_FAMILY, SAVED_VIEW_FAMILY};

const HOME: &str = HOME_FOCI_PRIVATE;
const PREFS: &str = RECORD_FOCI_PREFERENCES;

/// A home-slot receipt, all nine fields.
fn hr(
    status: SlotStatus,
    outcome: SlotOutcome,
    reason: Option<Why>,
    refusal: Option<Refusal>,
    target: Option<&str>,
    created: Option<bool>,
) -> SlotReceipt {
    SlotReceipt {
        slot: HOME.into(),
        status,
        outcome,
        reason,
        refusal,
        target_id: target.map(String::from),
        content_revision: None,
        policy_revision: None,
        created,
    }
}

/// `unusable`/`recovery_incomplete` for the home slot, with `outcome`.
fn recovering(
    outcome: SlotOutcome,
    refusal: Option<Refusal>,
    target: &str,
    created: Option<bool>,
) -> SlotReceipt {
    hr(
        SlotStatus::Unusable,
        outcome,
        Some(Why::RecoveryIncomplete),
        refusal,
        Some(target),
        created,
    )
}

fn healthy_home(outcome: SlotOutcome, target: &str, created: bool) -> SlotReceipt {
    hr(
        SlotStatus::Healthy,
        outcome,
        None,
        None,
        Some(target),
        Some(created),
    )
}

/// A receipt for a batch that left nothing capped: `complete` exactly when
/// nothing remains.
pub(super) fn receipt(
    target: &str,
    moved: usize,
    remaining: i64,
    foreign_skipped: i64,
) -> BatchReceipt {
    BatchReceipt {
        target_id: target.into(),
        moved,
        remaining,
        remaining_capped: false,
        foreign_skipped,
        foreign_capped: false,
        complete: remaining == 0,
    }
}

/// Fails the batch after every move, inside the open transaction.
pub(super) struct FailAfterMoves;
impl BatchHooks for FailAfterMoves {
    async fn after_moves(
        &self,
        _tx: &mut Transaction<'static, Sqlite>,
        _moved: &[String],
    ) -> Result<()> {
        Err(Error::engine("injected batch fault"))
    }
}

pub(super) fn home_refusal(status: SlotStatus, reason: Option<Why>) -> BatchRefusal {
    BatchRefusal::Home(SlotRefusal { status, reason })
}

/// Holds a `replace_home` inside its open transaction: `before_register`
/// signals entry, then waits for release. The replace keeps the writer lock
/// while held, so a queued batch reaches its write-begin boundary and pends.
struct HoldReplace {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

impl super::slots_ops::AttemptHooks for HoldReplace {
    async fn before_register(
        &self,
        _tx: &mut Transaction<'static, Sqlite>,
        _attempt: u32,
    ) -> Result<()> {
        self.entered.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(30), self.release.notified())
            .await
            .expect("the test never released the held replace");
        Ok(())
    }
}

/// A principal's ready home with six Foci records in it: the preferences
/// record, a Focus and four saved views (the §8.4 trace).
pub(super) struct Six {
    pub(super) home: String,
    pub(super) pref: String,
    pub(super) rest: Vec<String>,
}

impl Six {
    pub(super) fn all(&self) -> Vec<String> {
        let mut all = vec![self.pref.clone()];
        all.extend(self.rest.iter().cloned());
        all
    }
}

impl World {
    pub(super) async fn rc_principal(&self, name: &str) -> String {
        create_principal(
            &self.db,
            "account",
            name,
            &format!("acct:{name}"),
            &self.admin,
        )
        .await
        .unwrap()
    }
    pub(super) fn rc_prov(&self) -> TestProvisioner {
        TestProvisioner::new(&self.admin, Mode::Honest)
    }
    pub(super) async fn rc_view(&self, owner: &str, home: &str) -> String {
        create_json_as(
            &self.db,
            owner,
            SAVED_VIEW_FAMILY,
            "record_view",
            r#"{"name":"V","definition":{"app":"native.docs","target":{"record_id":"kernel:root"}}}"#,
            home,
        )
        .await
        .unwrap()
    }
    /// The real operations: `ensure(home)`, `ensure(record)`, then a Focus and
    /// four saved views the principal owns, all in the new home.
    pub(super) async fn rc_six(&self, principal: &str) -> Six {
        let home = self.rec_home(principal).await;
        let pref = self.rec_ensure(principal).await.target_id.unwrap();
        let mut rest = vec![self.focus_in(principal, &home).await];
        for _ in 0..4 {
            rest.push(self.rc_view(principal, &home).await);
        }
        Six { home, pref, rest }
    }
    /// Widen the home, then replace the slot: commits into `recovering`.
    pub(super) async fn rc_widen_and_replace(&self, principal: &str, home: &str) -> String {
        self.widen(home, principal).await;
        self.rec_replace_home(principal, home)
            .await
            .target_id
            .unwrap()
    }
    pub(super) async fn rc_replace_home(&self, principal: &str, expected: &str) -> SlotReceipt {
        replace_home(&self.db, &self.rc_prov(), principal, expected, "test")
            .await
            .unwrap()
    }
    pub(super) async fn rc_batch(
        &self,
        principal: &str,
        expected: &str,
        size: usize,
    ) -> BatchReceipt {
        rehome_batch(&self.db, principal, expected, size)
            .await
            .unwrap()
            .unwrap()
    }
    /// A batch that must be refused, and wrote nothing.
    pub(super) async fn rc_batch_refused(
        &self,
        principal: &str,
        expected: &str,
        size: usize,
    ) -> BatchRefusal {
        let before = self.state().await;
        let refusal = rehome_batch(&self.db, principal, expected, size)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(before, self.state().await);
        refusal
    }
    pub(super) async fn rc_homes(&self, ids: &[String]) -> Vec<String> {
        let mut homes = Vec::new();
        for id in ids {
            homes.push(self.rec_home_of(id).await);
        }
        homes
    }
    pub(super) async fn rc_outstanding(&self, principal: &str, limit: i64) -> Vec<String> {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let ids = slots_recovery::outstanding_sources_on(&mut tx, principal, limit)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        ids
    }
    pub(super) async fn rc_remaining(&self, principal: &str) -> i64 {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let n = slots_recovery::outstanding_bounded_on(&mut tx, principal)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(!n.capped);
        n.count
    }
    pub(super) async fn rc_eligible(&self, principal: &str, id: &str) -> bool {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let ok = slots_recovery::recovery_source_eligible_on(&mut tx, principal, id)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        ok
    }
    pub(super) async fn rc_admissible(&self, principal: &str, id: &str) -> bool {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let ok = slots_eval::foci_record_admissible_on(&mut tx, principal, id)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        ok
    }
    /// `(foreign in earlier homes, foreign in the current home)`.
    pub(super) async fn rc_foreign(&self, principal: &str) -> (i64, i64) {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let earlier = visible_foreign_on(&mut tx, principal, ForeignScope::Earlier, 0)
            .await
            .unwrap();
        let current = visible_foreign_on(&mut tx, principal, ForeignScope::Current, 0)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(!earlier.capped && !current.capped);
        (earlier.total, current.total)
    }
    pub(super) async fn rc_list(&self, principal: &str, family: &str) -> Result<FociListing> {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let listing = list_foci_records_on(&mut tx, principal, family)
            .await
            .map(|used| used.unwrap());
        tx.rollback().await.unwrap();
        listing
    }
    pub(super) async fn rc_policy_events(&self) -> i64 {
        self.rec_events("kernel.home_policy_replaced.v1").await
    }
    pub(super) async fn rc_rehome_events(&self) -> i64 {
        self.rec_events(KERNEL_REHOMED_EVENT).await
    }
    /// Direct SQL: the home's rows are gone; the slot mapping stays.
    pub(super) async fn rc_delete_home(&self, home: &str) {
        self.sql("DELETE FROM kernel_policies WHERE root_id=?", &[home])
            .await;
        self.sql("DELETE FROM kernel_roots WHERE root_id=?", &[home])
            .await;
    }
    /// Direct SQL: a record owned by someone else, as a stale or hostile
    /// writer would leave it. `owner_id` is the only column that changes.
    pub(super) async fn rc_plant(&self, owner: &str, record: &str) {
        self.sql(
            "UPDATE kernel_records SET owner_id=? WHERE id=?",
            &[owner, record],
        )
        .await;
    }
    /// Direct SQL: hand a home to another owner whose policy names only them.
    pub(super) async fn rc_hand_home_to(&self, home: &str, owner: &str) {
        self.sql(
            "UPDATE kernel_roots SET owner_id=? WHERE root_id=?",
            &[owner, home],
        )
        .await;
        self.sql(
            "UPDATE kernel_policy_entries SET subject_id=? WHERE root_id=?",
            &[owner, home],
        )
        .await;
    }
}

pub(super) fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

// -- the helpers ------------------------------------------------------------

/// `outstanding_sources_on` returns the principal's own held-family records in
/// non-current lineage homes, ordered by id and bounded by the limit. It
/// ignores the current home, other families, foreign-owned records and homes
/// outside the lineage; it is empty with no slot at all.
#[tokio::test]
async fn outstanding_sources_are_ordered_bounded_and_owned() {
    let w = World::fresh().await;
    let p = w.other.clone();
    assert!(w.rc_outstanding(&p, 10).await.is_empty());
    let six = w.rc_six(&p).await;
    // Nothing is outstanding while the home is current.
    assert!(w.rc_outstanding(&p, 10).await.is_empty());
    assert_eq!(w.rc_remaining(&p).await, 0);

    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    let all = sorted(six.all());
    assert_eq!(w.rc_outstanding(&p, 100).await, all);
    assert_eq!(w.rc_outstanding(&p, 4).await, all[..4].to_vec());
    assert_eq!(w.rc_outstanding(&p, 1).await, all[..1].to_vec());
    assert!(w.rc_outstanding(&p, 0).await.is_empty());
    assert_eq!(w.rc_remaining(&p).await, 6);

    // Other families, foreign owners and unrelated homes are not sources.
    w.sql(
        "UPDATE kernel_records SET pin_family='native.other' WHERE id=?",
        &[&six.rest[0]],
    )
    .await;
    w.rc_plant(&w.admin, &six.rest[1]).await;
    let stray = w.rec_home_of(&six.rest[2]).await;
    assert_eq!(stray, six.home);
    let unrelated = w.rc_principal("third").await;
    let elsewhere = w.rec_home(&unrelated).await;
    let outside = w.rc_view(&unrelated, &elsewhere).await;
    w.rc_plant(&p, &outside).await;
    let expected = sorted(vec![
        six.pref.clone(),
        six.rest[2].clone(),
        six.rest[3].clone(),
        six.rest[4].clone(),
    ]);
    assert_eq!(w.rc_outstanding(&p, 100).await, expected);
    assert_eq!(w.rc_remaining(&p).await, 4);

    // Draining the earlier home leaves nothing; the current home never counts.
    assert_eq!(w.rc_batch(&p, &h2, 10).await.moved, 4);
    assert!(w.rc_outstanding(&p, 100).await.is_empty());
    assert_eq!(w.rc_remaining(&p).await, 0);
}

/// The recovery placement predicate accepts exactly: beneficiary-owned, held
/// family, non-current lineage home, Edit. Its mirror, the ordinary predicate,
/// accepts the same record only once it has moved to the current home.
#[tokio::test]
async fn recovery_eligibility_is_the_mirror_of_ordinary_admissibility() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let focus = six.rest[0].clone();
    // In the current home: the ordinary predicate holds, the recovery one not.
    assert!(w.rc_admissible(&p, &focus).await);
    assert!(!w.rc_eligible(&p, &focus).await);

    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    assert!(!w.rc_admissible(&p, &focus).await);
    assert!(w.rc_eligible(&p, &focus).await);
    // Not eligible: unknown id, a home id, another family, a foreign owner.
    assert!(!w.rc_eligible(&p, &Uuid::new_v4().to_string()).await);
    assert!(!w.rc_eligible(&p, &six.home).await);
    w.sql(
        "UPDATE kernel_records SET pin_family='native.other' WHERE id=?",
        &[&focus],
    )
    .await;
    assert!(!w.rc_eligible(&p, &focus).await);
    w.sql(
        "UPDATE kernel_records SET pin_family=? WHERE id=?",
        &[FOCUS_FAMILY, &focus],
    )
    .await;
    w.rc_plant(&w.admin, &focus).await;
    assert!(!w.rc_eligible(&p, &focus).await);
    w.rc_plant(&p, &focus).await;
    assert!(w.rc_eligible(&p, &focus).await);
    // A home outside the lineage is no recovery source, however it is owned.
    let unrelated = w.rc_principal("third").await;
    let elsewhere = w.rec_home(&unrelated).await;
    let outside = w.rc_view(&unrelated, &elsewhere).await;
    w.rc_plant(&p, &outside).await;
    assert!(!w.rc_eligible(&p, &outside).await);
    // Another principal has no slot, so nothing is a source for them.
    assert!(!w.rc_eligible(&unrelated, &focus).await);
    // After the move, the roles swap.
    w.rc_batch(&p, &h2, 10).await;
    assert!(w.rc_admissible(&p, &focus).await);
    assert!(!w.rc_eligible(&p, &focus).await);
}

// -- fixture 30 -------------------------------------------------------------

/// Fixture 30: replacement commits into `recovering` (review N1). The new home
/// is structurally sound while the old one holds six owned Foci records: the
/// receipt is `replaced`/`created:true` with the evaluator's actual status,
/// both guards null, and the lineage has generation 2. No rollback.
#[tokio::test]
async fn replacement_commits_into_recovering() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    w.widen(&six.home, &p).await;
    let got = w.rc_replace_home(&p, &six.home).await;
    let h2 = got.target_id.clone().unwrap();
    assert_receipt(
        &got,
        &recovering(SlotOutcome::Replaced, None, &h2, Some(true)),
    );
    assert_ne!(h2, six.home);
    // Committed: generation 2 in the lineage, history kept.
    let lineage: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT generation, target_id, previous_target_id FROM kernel_slot_lineage WHERE principal_id=? AND slot=? ORDER BY generation",
    )
    .bind(&p)
    .bind(HOME)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(
        lineage,
        vec![
            (1, six.home.clone(), None),
            (2, h2.clone(), Some(six.home.clone()))
        ]
    );
    // All six are debt; the fence is up for both slots.
    assert_eq!(w.rc_remaining(&p).await, 6);
    w.assert_inspect(&p, HOME, unusable(HOME, Why::RecoveryIncomplete, Some(&h2)))
        .await;
    w.assert_inspect(&p, PREFS, unusable(PREFS, Why::WrongHome, Some(&six.pref)))
        .await;
    assert_eq!(
        w.gate(&p, HOME).await,
        closed(SlotStatus::Unusable, Some(Why::RecoveryIncomplete))
    );
    w.replay_equal().await;
}

// -- fixture 31 -------------------------------------------------------------

/// Fixture 31: the operations in each of the five home states (§8.4 table).
/// One principal per state. Slot-level operations that are refused or no-ops
/// write nothing; a policy restore changes no slot or health state but still
/// appends a policy event.
#[tokio::test]
async fn operations_in_each_home_state_match_the_table() {
    let w = World::fresh().await;

    // absent: ordinary use refused, replace `absent`, batch has no destination.
    let absent = w.rc_principal("absent").await;
    assert_eq!(
        w.gate(&absent, HOME).await,
        closed(SlotStatus::Absent, None)
    );
    let unknown = Uuid::new_v4().to_string();
    let before = w.state().await;
    assert_receipt(
        &w.rc_replace_home(&absent, &unknown).await,
        &hr(
            SlotStatus::Absent,
            SlotOutcome::Refused,
            None,
            Some(Refusal::Absent),
            None,
            None,
        ),
    );
    assert_eq!(before, w.state().await);
    assert_eq!(
        w.rc_batch_refused(&absent, &unknown, 3).await,
        home_refusal(SlotStatus::Absent, None)
    );
    // ... and `ensure` provisions, landing in ready.
    let created = w.rec_home(&absent).await;
    assert!(w.gate(&absent, HOME).await.is_ok());
    assert_ne!(created, unknown);

    // ready: ordinary use allowed; ensure is a no-op; replace is not_unusable;
    // the batch moves nothing; a restore appends a policy event only.
    let ready = w.rc_principal("ready").await;
    let six = w.rc_six(&ready).await;
    assert!(w.gate(&ready, HOME).await.is_ok());
    let before = w.state().await;
    assert_receipt(
        &w.rc_replace_home(&ready, &six.home).await,
        &hr(
            SlotStatus::Healthy,
            SlotOutcome::Refused,
            None,
            Some(Refusal::NotUnusable),
            Some(&six.home),
            None,
        ),
    );
    assert_eq!(before, w.state().await);
    let before = w.state().await;
    assert_eq!(
        w.rc_batch(&ready, &six.home, 5).await,
        receipt(&six.home, 0, 0, 0)
    );
    assert_eq!(before, w.state().await);
    let policy_before = w.rc_policy_events().await;
    w.restore(&six.home, &ready).await;
    assert_eq!(w.rc_policy_events().await, policy_before + 1);
    w.assert_inspect(
        &ready,
        HOME,
        hr(
            SlotStatus::Healthy,
            SlotOutcome::Inspected,
            None,
            None,
            Some(&six.home),
            None,
        ),
    )
    .await;

    // recovering: ordinary use, ensure and replace refused; a stale batch is
    // refused; a restore changes nothing; the batch runs.
    let recov = w.rc_principal("recov").await;
    let six = w.rc_six(&recov).await;
    let h2 = w.rc_widen_and_replace(&recov, &six.home).await;
    assert_eq!(
        w.gate(&recov, HOME).await,
        closed(SlotStatus::Unusable, Some(Why::RecoveryIncomplete))
    );
    let before = w.state().await;
    let ensured = crate::kernel::slots_ops::ensure_home(&w.db, &w.rc_prov(), &recov, "test")
        .await
        .unwrap();
    assert_receipt(&ensured, &recovering(SlotOutcome::Refused, None, &h2, None));
    assert_receipt(
        &w.rc_replace_home(&recov, &h2).await,
        &recovering(
            SlotOutcome::Refused,
            Some(Refusal::UnsupportedRecovery),
            &h2,
            None,
        ),
    );
    assert_receipt(
        &w.rc_replace_home(&recov, &six.home).await,
        &recovering(
            SlotOutcome::Refused,
            Some(Refusal::AlreadyReplaced),
            &h2,
            None,
        ),
    );
    assert_eq!(before, w.state().await);
    assert_eq!(
        w.rc_batch_refused(&recov, &six.home, 2).await,
        BatchRefusal::GenerationChanged
    );
    let (slots_before, policy_before) = (
        dump_all_kernel_tables(&w.db).await.unwrap(),
        w.rc_policy_events().await,
    );
    w.restore(&h2, &recov).await;
    assert_eq!(w.rc_policy_events().await, policy_before + 1);
    let after = dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(
        (slots_before.slots, slots_before.slot_lineage),
        (after.slots, after.slot_lineage)
    );
    w.assert_inspect(
        &recov,
        HOME,
        unusable(HOME, Why::RecoveryIncomplete, Some(&h2)),
    )
    .await;
    assert_eq!(w.rc_batch(&recov, &h2, 2).await, receipt(&h2, 2, 4, 0));

    // exposed: ordinary use, ensure and the batch are refused; a restore is
    // the way back; replace is allowed.
    let exposed = w.rc_principal("exposed").await;
    let six = w.rc_six(&exposed).await;
    w.widen(&six.home, &exposed).await;
    assert_eq!(
        w.gate(&exposed, HOME).await,
        closed(SlotStatus::Unusable, Some(Why::NotPrivate))
    );
    let before = w.state().await;
    let ensured = crate::kernel::slots_ops::ensure_home(&w.db, &w.rc_prov(), &exposed, "test")
        .await
        .unwrap();
    assert_receipt(
        &ensured,
        &hr(
            SlotStatus::Unusable,
            SlotOutcome::Refused,
            Some(Why::NotPrivate),
            None,
            Some(&six.home),
            None,
        ),
    );
    assert_eq!(before, w.state().await);
    assert_eq!(
        w.rc_batch_refused(&exposed, &six.home, 3).await,
        home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate))
    );
    w.restore(&six.home, &exposed).await;
    assert!(w.gate(&exposed, HOME).await.is_ok());
    w.widen(&six.home, &exposed).await;
    let replaced = w.rc_replace_home(&exposed, &six.home).await;
    assert_eq!(replaced.outcome, SlotOutcome::Replaced);
    assert_eq!(replaced.created, Some(true));

    // broken: the same, for a home whose rows are gone.
    let broken = w.rc_principal("broken").await;
    let home = w.rec_home(&broken).await;
    w.rc_delete_home(&home).await;
    assert_eq!(
        w.gate(&broken, HOME).await,
        closed(SlotStatus::Unusable, Some(Why::Missing))
    );
    assert_eq!(
        w.rc_batch_refused(&broken, &home, 3).await,
        home_refusal(SlotStatus::Unusable, Some(Why::Missing))
    );
    let before = w.state().await;
    let ensured = crate::kernel::slots_ops::ensure_home(&w.db, &w.rc_prov(), &broken, "test")
        .await
        .unwrap();
    assert_receipt(
        &ensured,
        &hr(
            SlotStatus::Unusable,
            SlotOutcome::Refused,
            Some(Why::Missing),
            None,
            Some(&home),
            None,
        ),
    );
    assert_eq!(before, w.state().await);
    let fresh = w.rc_replace_home(&broken, &home).await;
    let new_home = fresh.target_id.clone().unwrap();
    assert_receipt(
        &fresh,
        &healthy_home(SlotOutcome::Replaced, &new_home, true),
    );
    // No replay_equal here: the broken home was made by direct SQL on the
    // projection (design §9), which a replay would rebuild.
}

// -- fixture 32 -------------------------------------------------------------

/// Fixture 32 (file): the §8.4 trace, end to end. Six records in H1; widen;
/// replace; batch of 3; a batch that dies before commit with its first
/// rehome appended; close every handle and reopen the same file; inspect;
/// batch to completion. With `replay`, the projections are also rebuilt from
/// the log after reopening and compared.
async fn the_end_to_end_trace(replay: bool) {
    let mut w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let all = six.all();
    let h1 = six.home.clone();

    // Step 0: ready.
    assert!(w.gate(&p, HOME).await.is_ok());
    assert!(w.gate(&p, PREFS).await.is_ok());
    assert_eq!(w.rc_remaining(&p).await, 0);

    // Step 1: someone with Manage widens H1. Exposed.
    w.widen(&h1, &p).await;
    w.assert_inspect(&p, HOME, unusable(HOME, Why::NotPrivate, Some(&h1)))
        .await;
    w.assert_inspect(&p, PREFS, unusable(PREFS, Why::NotPrivate, Some(&six.pref)))
        .await;
    assert_eq!(
        w.rc_batch_refused(&p, &h1, 3).await,
        home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate))
    );

    // Step 2: replace commits into recovering. Retries are refused.
    let got = w.rc_replace_home(&p, &h1).await;
    let h2 = got.target_id.clone().unwrap();
    assert_receipt(
        &got,
        &recovering(SlotOutcome::Replaced, None, &h2, Some(true)),
    );
    w.assert_inspect(&p, PREFS, unusable(PREFS, Why::WrongHome, Some(&six.pref)))
        .await;
    assert!(w.gate(&p, PREFS).await.is_err());
    let before = w.state().await;
    assert_receipt(
        &w.rc_replace_home(&p, &h1).await,
        &recovering(
            SlotOutcome::Refused,
            Some(Refusal::AlreadyReplaced),
            &h2,
            None,
        ),
    );
    assert_receipt(
        &w.rc_replace_home(&p, &h2).await,
        &recovering(
            SlotOutcome::Refused,
            Some(Refusal::UnsupportedRecovery),
            &h2,
            None,
        ),
    );
    let record_replace = w.rec_replace(&p, &six.pref).await;
    assert_eq!(record_replace.refusal, Some(Refusal::UnsupportedRecovery));
    assert_eq!(before, w.state().await);

    // Step 3: batch 1. Three move; the fence stays up whether or not the
    // preferences record was among them.
    assert_eq!(w.rc_batch(&p, &h2, 3).await, receipt(&h2, 3, 3, 0));
    let after_batch_1 = w.rc_homes(&all).await;
    assert_eq!(after_batch_1.iter().filter(|home| **home == h2).count(), 3);
    w.assert_inspect(&p, HOME, unusable(HOME, Why::RecoveryIncomplete, Some(&h2)))
        .await;
    let pref_reason = if w.rec_home_of(&six.pref).await == h2 {
        Why::RecoveryIncomplete
    } else {
        Why::WrongHome
    };
    w.assert_inspect(&p, PREFS, unusable(PREFS, pref_reason, Some(&six.pref)))
        .await;
    assert!(w.gate(&p, PREFS).await.is_err());
    let durable = w.state().await;

    // Step 4: crash. Batch 2 moves all three sources, then `FailAfterMoves`
    // (the after-all-moves hook) fails it inside the open write transaction;
    // the process dies before commit: the transaction is dropped, never
    // committed or rolled back by the batch.
    {
        let mut tx = begin_write(w.db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        let died = rehome_batch_in(&w.db, &mut tx, &mut acts, &FailAfterMoves, &p, &h2, 3).await;
        assert!(died.is_err());
        let uncommitted: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type=?")
                .bind(KERNEL_REHOMED_EVENT)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(
            uncommitted, 6,
            "three committed plus batch 2's three appended rehomes"
        );
        drop(tx);
    }

    // Step 5: restart. Close every handle and reopen the same file.
    w.reopen().await;
    assert_eq!(durable, w.state().await, "nothing from batch 2 persists");
    if replay {
        w.replay_equal().await;
        assert_eq!(durable, w.state().await);
    }
    assert_eq!(w.rc_homes(&all).await, after_batch_1);
    w.assert_inspect(&p, HOME, unusable(HOME, Why::RecoveryIncomplete, Some(&h2)))
        .await;
    assert_eq!(w.rc_remaining(&p).await, 3);
    assert!(w.gate(&p, HOME).await.is_err());
    // The driver re-reads the current home and calls the batch with it.
    let current = w.inspect(&p, HOME).await.target_id.unwrap();
    assert_eq!(current, h2);

    // Step 6: batch 2.
    assert_eq!(
        w.rc_batch(&p, &current, 3).await,
        receipt(&current, 3, 0, 0)
    );

    // Step 7: complete. The fence lifted by itself; no completion event.
    w.assert_inspect(
        &p,
        HOME,
        hr(
            SlotStatus::Healthy,
            SlotOutcome::Inspected,
            None,
            None,
            Some(&h2),
            None,
        ),
    )
    .await;
    assert_eq!(w.inspect(&p, PREFS).await.status, SlotStatus::Healthy);
    assert!(w.gate(&p, HOME).await.is_ok());
    assert!(w.gate(&p, PREFS).await.is_ok());
    assert_eq!(w.rc_homes(&all).await, vec![h2.clone(); 6]);
    assert_eq!(w.rc_list(&p, FOCUS_FAMILY).await.unwrap().records.len(), 1);
    assert_eq!(
        w.rc_list(&p, SAVED_VIEW_FAMILY)
            .await
            .unwrap()
            .records
            .len(),
        4
    );
    // A retry of step 2's replace is now a replay.
    let before = w.state().await;
    assert_receipt(
        &w.rc_replace_home(&p, &h1).await,
        &healthy_home(SlotOutcome::Replayed, &h2, false),
    );
    assert_eq!(before, w.state().await);
    w.replay_equal().await;
    // Exactly six rehome events: the died batch left none behind.
    assert_eq!(w.rc_rehome_events().await, 6);
}

#[tokio::test]
async fn the_end_to_end_trace_survives_a_restart() {
    the_end_to_end_trace(false).await;
}

#[tokio::test]
async fn the_end_to_end_trace_replays_after_a_restart() {
    the_end_to_end_trace(true).await;
}

// -- fixture 33 -------------------------------------------------------------

/// Fixture 33: moving the preferences record first, directly, lifts nothing.
/// Both slots stay unusable until the last Foci record has moved, and the
/// gated read of the preferences stays refused.
#[tokio::test]
async fn moving_the_preferences_first_lifts_nothing() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    rehome_record_as(&w.db, &p, &six.pref, &h2).await.unwrap();

    let fenced = |slot: &str, target: &str| unusable(slot, Why::RecoveryIncomplete, Some(target));
    w.assert_inspect(&p, HOME, fenced(HOME, &h2)).await;
    w.assert_inspect(&p, PREFS, fenced(PREFS, &six.pref)).await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let read = slots_host::read_preferences_on(&mut tx, &p).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        read.unwrap_err(),
        UseRefusal::Gate(SlotRefusal {
            status: SlotStatus::Unusable,
            reason: Some(Why::RecoveryIncomplete),
        })
    );

    // The rest moves in two batches; nothing lifts until the last one.
    assert_eq!(w.rc_batch(&p, &h2, 3).await, receipt(&h2, 3, 2, 0));
    w.assert_inspect(&p, PREFS, fenced(PREFS, &six.pref)).await;
    assert_eq!(w.rc_batch(&p, &h2, 3).await.remaining, 0);
    assert!(w.gate(&p, HOME).await.is_ok());
    assert!(w.gate(&p, PREFS).await.is_ok());
    w.replay_equal().await;
}

// -- fixture 34 -------------------------------------------------------------

/// Fixture 34: three generations. H1 is replaced from exposed, some records
/// move, H2 is widened (exposed: the batch refuses) and replaced in turn. Debt
/// then spans H1 and H2; a widen and restore of H3 in the middle changes no
/// slot; batches move records from both straight to H3. Replacement is only
/// ever taken from an exposed or broken home.
#[tokio::test]
async fn three_generations_recover_straight_into_the_current_home() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let all = six.all();
    let h1 = six.home.clone();

    let h2 = w.rc_widen_and_replace(&p, &h1).await;
    assert_eq!(w.rc_batch(&p, &h2, 2).await.remaining, 4);
    let homes = w.rc_homes(&all).await;
    assert_eq!(homes.iter().filter(|home| **home == h1).count(), 4);
    assert_eq!(homes.iter().filter(|home| **home == h2).count(), 2);

    // Widened mid-recovery: exposed, so the batch refuses; structure outranks
    // debt in the evaluator.
    w.widen(&h2, &p).await;
    w.assert_inspect(&p, HOME, unusable(HOME, Why::NotPrivate, Some(&h2)))
        .await;
    assert_eq!(
        w.rc_batch_refused(&p, &h2, 2).await,
        home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate))
    );

    // Replace again, from exposed. H2's two records join H1's four.
    let got = w.rc_replace_home(&p, &h2).await;
    let h3 = got.target_id.clone().unwrap();
    assert_receipt(
        &got,
        &recovering(SlotOutcome::Replaced, None, &h3, Some(true)),
    );
    assert_eq!(w.rc_remaining(&p).await, 6);
    let lineage: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT generation, target_id, previous_target_id FROM kernel_slot_lineage WHERE principal_id=? AND slot=? ORDER BY generation",
    )
    .bind(&p)
    .bind(HOME)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(
        lineage,
        vec![
            (1, h1.clone(), None),
            (2, h2.clone(), Some(h1.clone())),
            (3, h3.clone(), Some(h2.clone()))
        ]
    );
    // Replacing from recovering is refused.
    assert_receipt(
        &w.rc_replace_home(&p, &h3).await,
        &recovering(
            SlotOutcome::Refused,
            Some(Refusal::UnsupportedRecovery),
            &h3,
            None,
        ),
    );

    // Widen H3 once more and restore it (Route A): no slot changes, the debt
    // is still six, and a stale batch is refused.
    let slots_before = dump_all_kernel_tables(&w.db).await.unwrap();
    let slots_before = (slots_before.slots, slots_before.slot_lineage);
    w.widen(&h3, &p).await;
    assert_eq!(
        w.rc_batch_refused(&p, &h3, 2).await,
        home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate))
    );
    w.restore(&h3, &p).await;
    let slots_after = dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(slots_before, (slots_after.slots, slots_after.slot_lineage));
    w.assert_inspect(&p, HOME, unusable(HOME, Why::RecoveryIncomplete, Some(&h3)))
        .await;
    assert_eq!(
        w.rc_batch_refused(&p, &h2, 2).await,
        BatchRefusal::GenerationChanged
    );

    // Batches move records from both earlier homes straight to H3.
    assert_eq!(w.rc_batch(&p, &h3, 4).await, receipt(&h3, 4, 2, 0));
    assert_eq!(w.rc_batch(&p, &h3, 4).await, receipt(&h3, 2, 0, 0));
    assert_eq!(w.rc_homes(&all).await, vec![h3.clone(); 6]);
    assert!(w.gate(&p, HOME).await.is_ok());
    assert!(w.gate(&p, PREFS).await.is_ok());
    w.replay_equal().await;
}

// -- fixture 35 -------------------------------------------------------------

/// Fixture 35: planted records. Foreign-owned Foci records in an older home
/// neither hold the fence open nor get moved, and are counted only if the
/// principal can View them, from a query that reads ids and no fields. A
/// principal-owned record written late into the older home is debt again and
/// is moved. In the current home, a foreign-owned record is excluded by every
/// consumer and counted as an anomaly.
#[tokio::test]
async fn planted_records_are_debt_when_owned_and_ignored_when_foreign() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h1 = six.home.clone();
    // Two foreign-owned Foci records planted in H1 (a stale or hostile writer).
    let foreign_focus = w.focus_in(&p, &h1).await;
    let foreign_view = w.rc_view(&p, &h1).await;
    w.rc_plant(&w.admin, &foreign_focus).await;
    w.rc_plant(&w.admin, &foreign_view).await;
    // They do not make the home unready while it is the current home either:
    // the fence looks at earlier homes only.
    assert!(w.gate(&p, HOME).await.is_ok());

    let h2 = w.rc_widen_and_replace(&p, &h1).await;
    // Six owned records are debt; the foreign ones are not, and not sources.
    assert_eq!(w.rc_remaining(&p).await, 6);
    assert_eq!(w.rc_outstanding(&p, 100).await, sorted(six.all()));
    assert!(!w.rc_eligible(&p, &foreign_focus).await);
    assert_eq!(w.rc_foreign(&p).await, (2, 0));
    w.sql(
        "DELETE FROM kernel_record_fields WHERE record_id=?",
        &[&foreign_focus],
    )
    .await;
    assert_eq!(
        w.rc_foreign(&p).await,
        (2, 0),
        "the count reads ids and owners, never fields"
    );

    // The batch drains the debt and lifts the fence without touching them.
    let events = w.rc_rehome_events().await;
    assert_eq!(w.rc_batch(&p, &h2, 10).await, receipt(&h2, 6, 0, 2));
    assert_eq!(w.rc_rehome_events().await, events + 6);
    assert_eq!(
        w.rc_homes(&[foreign_focus.clone(), foreign_view.clone()])
            .await,
        vec![h1.clone(); 2]
    );
    assert!(w.gate(&p, HOME).await.is_ok());

    // A stale principal-owned write into the older home is debt again.
    let late = w.focus_in(&p, &h1).await;
    assert_eq!(w.rc_remaining(&p).await, 1);
    w.assert_inspect(&p, HOME, unusable(HOME, Why::RecoveryIncomplete, Some(&h2)))
        .await;
    assert_eq!(w.rc_batch(&p, &h2, 10).await, receipt(&h2, 1, 0, 2));
    assert_eq!(w.rec_home_of(&late).await, h2);

    // Foreign records the principal cannot see are not counted. The owned
    // record written late into the handed-away home still moves: its owner
    // floor gives Edit whatever the home's policy says.
    w.rc_hand_home_to(&h1, &w.admin).await;
    assert_eq!(w.rc_foreign(&p).await, (0, 0));
    let stray = six.rest[0].clone();
    w.sql(
        "UPDATE kernel_records SET home_id=? WHERE id=?",
        &[&h1, &stray],
    )
    .await;
    assert_eq!(w.rc_remaining(&p).await, 1);
    assert_eq!(w.rc_batch(&p, &h2, 10).await, receipt(&h2, 1, 0, 0));
    assert_eq!(w.rec_home_of(&stray).await, h2);

    // In the current home, a foreign-owned record is excluded by every
    // consumer and counted.
    let kept = six.rest[1].clone();
    w.rc_plant(&w.admin, &kept).await;
    assert!(!w.rc_admissible(&p, &kept).await);
    assert_eq!(w.rc_foreign(&p).await, (0, 1));
    let listing = w.rc_list(&p, FOCUS_FAMILY).await.unwrap();
    assert_eq!(
        listing.records,
        sorted(vec![stray.clone(), late.clone()]),
        "the planted Focus is not listed"
    );
    assert_eq!(listing.foreign_skipped, 1);
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let read = read_foci_record_on(&mut tx, &p, &kept).await.unwrap();
    let own = read_foci_record_on(&mut tx, &p, &late).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(read.unwrap_err(), UseRefusal::NotAdmissible);
    assert_eq!(own.unwrap().unwrap().id, late);
    let revision = w.revision(&kept).await;
    let revised = revise_foci_record(
        &w.db,
        &p,
        &kept,
        FieldInput::Raw(r#"{"name":"Taken"}"#),
        revision,
    )
    .await
    .unwrap();
    assert_eq!(revised.unwrap_err(), UseRefusal::NotAdmissible);
    // Unknown families are an error, not a listing.
    assert!(w.rc_list(&p, "native.other").await.is_err());
}

// -- fixture 36 -------------------------------------------------------------

/// Fixture 36: Route A. Widen, then restore: no slot changes, the home and
/// the record are healthy again (or recovering while earlier debt remains),
/// and the principal that was added loses access.
#[tokio::test]
async fn restoring_the_policy_changes_no_slot() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let (home, record) = w.ready(&p).await;
    let slots = |d: KernelTableDump| (d.slots, d.slot_lineage);
    let before = slots(dump_all_kernel_tables(&w.db).await.unwrap());

    w.widen(&home, &p).await;
    assert!(read_record_as(&w.db, &w.admin, &record)
        .await
        .unwrap()
        .is_some());
    assert_eq!(w.inspect(&p, HOME).await.reason, Some(Why::NotPrivate));
    assert_eq!(w.inspect(&p, PREFS).await.reason, Some(Why::NotPrivate));
    w.restore(&home, &p).await;
    assert_eq!(before, slots(dump_all_kernel_tables(&w.db).await.unwrap()));
    assert_eq!(w.inspect(&p, HOME).await.status, SlotStatus::Healthy);
    assert_eq!(w.inspect(&p, PREFS).await.status, SlotStatus::Healthy);
    assert!(read_record_as(&w.db, &w.admin, &record)
        .await
        .unwrap()
        .is_none());

    // With earlier debt outstanding, a restore of the current home returns to
    // recovering, not ready.
    let q = w.rc_principal("mid").await;
    let six = w.rc_six(&q).await;
    let h2 = w.rc_widen_and_replace(&q, &six.home).await;
    w.rc_batch(&q, &h2, 2).await;
    let before = slots(dump_all_kernel_tables(&w.db).await.unwrap());
    w.widen(&h2, &q).await;
    w.assert_inspect(&q, HOME, unusable(HOME, Why::NotPrivate, Some(&h2)))
        .await;
    w.restore(&h2, &q).await;
    assert_eq!(before, slots(dump_all_kernel_tables(&w.db).await.unwrap()));
    w.assert_inspect(&q, HOME, unusable(HOME, Why::RecoveryIncomplete, Some(&h2)))
        .await;
    assert_eq!(w.rc_remaining(&q).await, 4);
    w.rc_batch(&q, &h2, 10).await;
    assert!(w.gate(&q, HOME).await.is_ok());
    w.replay_equal().await;
}

// -- the batch itself -------------------------------------------------------

/// A batch is one transaction: a fault after its first move leaves nothing
/// behind (events, acts, the act counter, tables), and a retry then succeeds.
/// Malformed requests are errors with nothing written.
#[tokio::test]
async fn a_failing_or_malformed_batch_writes_nothing() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;

    let before = w.state().await;
    let failed = rehome_batch_with(&w.db, &FailAfterMoves, &p, &h2, 3).await;
    assert!(failed.is_err());
    assert_eq!(before, w.state().await);
    for (expected, size) in [
        (h2.as_str(), 0),
        ("x", 3),
        ("", 3),
        (h2.to_uppercase().as_str(), 3),
    ] {
        assert!(rehome_batch(&w.db, &p, expected, size).await.is_err());
        assert_eq!(before, w.state().await);
    }
    assert_eq!(w.rc_batch(&p, &h2, 3).await.moved, 3);
}

/// Two batches with the same `expected_target` serialise on the writer lock.
/// The second is queued (proved with the before-begin-write seam, not time)
/// while the first holds its transaction, then sees the first's moves: every
/// record is moved exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_batches_move_each_record_once() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;

    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let first = rehome_batch_in(&w.db, &mut tx, &mut acts, &NoBatchHooks, &p, &h2, 3)
        .await
        .unwrap()
        .unwrap();
    let second = {
        let (db, who, home) = (w.db.clone(), p.clone(), h2.clone());
        spawn_queued_writer(async move { rehome_batch(&db, &who, &home, 3).await }).await
    };
    assert!(
        !second.is_finished(),
        "the second batch reached its write begin and must wait for the first"
    );
    assert_eq!(first, receipt(&h2, 3, 3, 0));
    tx.commit().await.unwrap();
    assert_eq!(
        second.await.unwrap().unwrap().unwrap(),
        receipt(&h2, 3, 0, 0)
    );
    let distinct: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT record_id) FROM content_events WHERE type=?")
            .bind(KERNEL_REHOMED_EVENT)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!((distinct, w.rc_rehome_events().await), (6, 6));
    assert!(w.gate(&p, HOME).await.is_ok());
}

/// Fixture 61: racing batches. A controlling `begin_write` holds the lock.
/// Two size-6 batches are each started through `spawn_queued_writer`; both
/// reach the write-begin boundary and remain unfinished. Release. Whichever
/// gets the lock first moves everything and the other moves nothing, so each
/// record is moved once whatever the order. This replaces
/// `racing_batches_never_double_move`. The proof witnesses arrival at the
/// begin boundary while the controlling transaction holds the lock, not
/// SQLite's internal queue membership (the 9f80162 qualification).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_batches_never_double_move() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    let control = begin_write(w.db.write_pool()).await.unwrap();
    let run = |db, who: String, home: String| {
        spawn_queued_writer(async move { rehome_batch(&db, &who, &home, 6).await })
    };
    let a = run(w.db.clone(), p.clone(), h2.clone()).await;
    let b = run(w.db.clone(), p.clone(), h2.clone()).await;
    assert!(
        !a.is_finished(),
        "first batch reached its write begin and waits for the control"
    );
    assert!(
        !b.is_finished(),
        "second batch reached its write begin and waits for the control"
    );
    drop(control);
    let (a, b) = (
        a.await.unwrap().unwrap().unwrap(),
        b.await.unwrap().unwrap().unwrap(),
    );
    let mut moved = vec![a.moved, b.moved];
    moved.sort();
    assert_eq!(moved, vec![0, 6]);
    assert!((a.complete, b.complete) == (true, true));
    assert_eq!((a.remaining, b.remaining), (0, 0));
    assert_eq!(w.rc_rehome_events().await, 6);
    assert!(w.gate(&p, HOME).await.is_ok());
}

/// Fixture 60: a replace held at its hook queues a batch behind it. H2 is
/// seeded first, so both older generations hold sources. The batch reaches
/// its write-begin boundary (proved with the seam, not time) and pends;
/// release commits the replace to H3, and the batch is refused
/// `GenerationChanged` with zero writes. A batch with the new target then
/// drains both H1 and H2 into H3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_queued_behind_replace_sees_the_new_generation() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    assert_eq!(w.rc_batch(&p, &h2, 2).await.moved, 2);
    let seeded = w.rc_homes(&six.all()).await;
    assert!(seeded.contains(&six.home), "H1 still holds sources");
    assert!(seeded.contains(&h2), "H2 now holds sources too");
    w.widen(&h2, &p).await;
    let events_before = w.rc_rehome_events().await;
    let homes_before = w.rc_homes(&six.all()).await;

    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let hooks = HoldReplace {
        entered: entered.clone(),
        release: release.clone(),
    };
    let (db, prov, who, expected) = (w.db.clone(), w.rc_prov(), p.clone(), h2.clone());
    let replacing = tokio::spawn(async move {
        super::slots_ops::replace_home_with(&db, &prov, &hooks, &who, &expected, "test").await
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the held replace never reached its hook");
    let batch = {
        let (db, who, home) = (w.db.clone(), p.clone(), h2.clone());
        spawn_queued_writer(async move { rehome_batch(&db, &who, &home, 3).await }).await
    };
    assert!(
        !batch.is_finished(),
        "the batch reached its write begin and must wait for the replace"
    );
    release.notify_one();
    let replaced = replacing.await.unwrap().unwrap();
    let h3 = replaced.target_id.clone().expect("replace has a target");
    assert_eq!(replaced.outcome, SlotOutcome::Replaced);
    assert_eq!(
        batch.await.unwrap().unwrap().unwrap_err(),
        BatchRefusal::GenerationChanged
    );
    assert_eq!(w.rc_rehome_events().await, events_before);
    assert_eq!(w.rc_homes(&six.all()).await, homes_before);
    let moved = w.rc_batch(&p, &h3, 10).await;
    assert_eq!(moved.moved, 6);
    assert_eq!(moved.remaining, 0);
    assert!(moved.complete);
    assert_eq!(w.rc_homes(&six.all()).await, vec![h3.clone(); 6]);
    assert!(w.gate(&p, HOME).await.is_ok());
}

/// Fixture 62: a controlling transaction rehomes one source and holds. A
/// size-10 batch queued behind it (proved with the seam, not time) pends;
/// commit lets the batch move the other five. The held record is moved once,
/// six distinct rehome events exist in total, and the gate is healthy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_queued_behind_a_single_rehome_moves_the_rest_once() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    let all = sorted(six.all());
    let first = all[0].clone();

    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    rehome_record_in(&w.db, &mut tx, &mut acts, &p, &first, &h2)
        .await
        .unwrap();
    let queued = {
        let (db, who, home) = (w.db.clone(), p.clone(), h2.clone());
        spawn_queued_writer(async move { rehome_batch(&db, &who, &home, 10).await }).await
    };
    assert!(
        !queued.is_finished(),
        "the batch reached its write begin and must wait for the single rehome"
    );
    tx.commit().await.unwrap();
    let receipt = queued.await.unwrap().unwrap().unwrap();
    assert_eq!(receipt.moved, 5);
    assert_eq!(receipt.remaining, 0);
    assert!(receipt.complete);
    assert_eq!(w.rec_home_of(&first).await, h2);
    assert_eq!(w.rc_homes(&all).await, vec![h2.clone(); 6]);
    let distinct: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT record_id) FROM content_events WHERE type=?")
            .bind(KERNEL_REHOMED_EVENT)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!((distinct, w.rc_rehome_events().await), (6, 6));
    assert!(w.gate(&p, HOME).await.is_ok());
}

/// A widen during recovery. The batch's structure check and its moves are one
/// transaction, so a widen queued behind it (proved with the seam) applies
/// after the batch commits: the batch ran entirely under a private home, and
/// the next batch is refused until the policy is restored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_widen_during_recovery_waits_for_the_batch_and_then_fences_the_next() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;

    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let batch = rehome_batch_in(&w.db, &mut tx, &mut acts, &NoBatchHooks, &p, &h2, 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.moved, 2);
    let widen = {
        let (db, who, admin, target) = (w.db.clone(), p.clone(), w.admin.clone(), h2.clone());
        spawn_queued_writer(async move {
            replace_home_policy(&db, &who, &target, &[(&who, "manage"), (&admin, "view")]).await
        })
        .await
    };
    assert!(
        !widen.is_finished(),
        "the widen reached its write begin and must wait for the batch"
    );
    tx.commit().await.unwrap();
    widen.await.unwrap().unwrap();

    // The moves are ordered before the widen; the next batch is refused.
    let last_move: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE type=?")
        .bind(KERNEL_REHOMED_EVENT)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let widened: i64 = sqlx::query_scalar(
        "SELECT MAX(seq) FROM content_events WHERE type='kernel.home_policy_replaced.v1'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(last_move < widened);
    assert_eq!(
        w.rc_batch_refused(&p, &h2, 2).await,
        home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate))
    );
    assert_eq!(w.rc_remaining(&p).await, 4);
    w.restore(&h2, &p).await;
    assert_eq!(w.rc_batch(&p, &h2, 10).await.remaining, 0);
    assert!(w.gate(&p, PREFS).await.is_ok());
}

/// The gated consumers refuse while the home is recovering, and read nothing.
#[tokio::test]
async fn consumers_are_refused_while_recovering() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    let shut = UseRefusal::Gate(SlotRefusal {
        status: SlotStatus::Unusable,
        reason: Some(Why::RecoveryIncomplete),
    });
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let read = read_foci_record_on(&mut tx, &p, &six.rest[0])
        .await
        .unwrap();
    let list = list_foci_records_on(&mut tx, &p, FOCUS_FAMILY)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(read.unwrap_err(), shut);
    assert_eq!(list.unwrap_err(), shut);
    w.rc_batch(&p, &h2, 10).await;
    let listing = w.rc_list(&p, SAVED_VIEW_FAMILY).await.unwrap();
    assert_eq!(listing.records.len(), 4);
    assert_eq!(listing.foreign_skipped, 0);
}
