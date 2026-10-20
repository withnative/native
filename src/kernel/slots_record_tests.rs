//! Record slot `ensure` and `replace` fixtures (Foci v2 G7 increment 5):
//! fixtures 3 to 5, the record halves of 6 to 10, 17, 18 and 25, fixture 20,
//! and the replay rules of 26 to 29 as they apply to a record. Fixture 7's
//! home half lives here too, so both slot types share one fault hook.
//!
//! Every receipt assertion compares all nine fields and their explicit JSON;
//! every refusal and no-op also proves it wrote nothing (events, acts, the act
//! counter and both slot tables unchanged). States the v2 writes cannot reach
//! (`missing`, `forbidden`, `wrong_target`) are made by direct SQL on the
//! projection, and each fixture says so; those skip `replay_equal`, because a
//! rebuild would resurrect the rows the SQL removed (design §9).
use super::slots::{self, HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_eval::{Refusal, SlotOutcome, SlotReceipt, SlotStatus, UnusableReason};
use super::slots_eval_tests::{assert_receipt, closed, unusable};
use super::slots_ops::{
    ensure_home, ensure_home_with, ensure_record, ensure_record_with, replace_home,
    replace_home_with, replace_record, replace_record_with, AttemptHooks,
};
use super::slots_ops_tests::{Mode, TestProvisioner};
use super::slots_tests::{engine_error, World};
use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const SLOT: &str = RECORD_FOCI_PREFERENCES;

fn rec(
    status: SlotStatus,
    outcome: SlotOutcome,
    reason: Option<UnusableReason>,
    refusal: Option<Refusal>,
    target: Option<&str>,
    revision: Option<i64>,
    created: Option<bool>,
) -> SlotReceipt {
    SlotReceipt {
        slot: SLOT.into(),
        status,
        outcome,
        reason,
        refusal,
        target_id: target.map(String::from),
        content_revision: revision,
        policy_revision: None,
        created,
    }
}

/// `healthy` after `outcome`, with the record's own revision token.
fn healthy(outcome: SlotOutcome, target: &str, revision: i64, created: bool) -> SlotReceipt {
    rec(
        SlotStatus::Healthy,
        outcome,
        None,
        None,
        Some(target),
        Some(revision),
        Some(created),
    )
}

/// A refusal reporting the current mapping's status and reason. A refusal's
/// `created` is null, and its guards are null unless the mapping is healthy.
fn refusal_of(
    status: SlotStatus,
    reason: Option<UnusableReason>,
    refusal: Option<Refusal>,
    target: Option<&str>,
) -> SlotReceipt {
    rec(
        status,
        SlotOutcome::Refused,
        reason,
        refusal,
        target,
        None,
        None,
    )
}

/// The home is not ready, so a record cannot be created, and the record slot
/// itself is still absent.
fn absent_home_unusable() -> SlotReceipt {
    refusal_of(SlotStatus::Absent, None, Some(Refusal::HomeUnusable), None)
}

impl World {
    pub(super) async fn rec_ensure(&self, principal: &str) -> SlotReceipt {
        ensure_record(&self.db, principal, "test").await.unwrap()
    }
    pub(super) async fn rec_replace(&self, principal: &str, expected: &str) -> SlotReceipt {
        replace_record(&self.db, principal, expected, "test")
            .await
            .unwrap()
    }
    pub(super) async fn rec_ensure_wrote_nothing(&self, principal: &str, expected: SlotReceipt) {
        let before = self.state().await;
        assert_receipt(&self.rec_ensure(principal).await, &expected);
        assert_eq!(before, self.state().await);
    }
    pub(super) async fn rec_replace_wrote_nothing(
        &self,
        principal: &str,
        target: &str,
        expected: SlotReceipt,
    ) {
        let before = self.state().await;
        assert_receipt(&self.rec_replace(principal, target).await, &expected);
        assert_eq!(before, self.state().await);
    }
    /// A ready home slot for `principal`, made through the real operation.
    pub(super) async fn rec_home(&self, principal: &str) -> String {
        let provisioner = TestProvisioner::new(&self.admin, Mode::Honest);
        ensure_home(&self.db, &provisioner, principal, "test")
            .await
            .unwrap()
            .target_id
            .unwrap()
    }
    pub(super) async fn rec_replace_home(&self, principal: &str, expected: &str) -> SlotReceipt {
        let provisioner = TestProvisioner::new(&self.admin, Mode::Honest);
        replace_home(&self.db, &provisioner, principal, expected, "test")
            .await
            .unwrap()
    }
    pub(super) async fn rec_count(&self, statement: &str, bind: &str) -> i64 {
        sqlx::query_scalar(statement)
            .bind(bind)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    pub(super) async fn rec_events(&self, event_type: &str) -> i64 {
        self.rec_count(
            "SELECT COUNT(*) FROM content_events WHERE type=?",
            event_type,
        )
        .await
    }
    /// Direct SQL: delete a record's projection rows, leaving the slot mapping
    /// and its events alone. The mapping stays; the target is gone.
    pub(super) async fn rec_delete_rows(&self, record: &str) {
        self.sql(
            "DELETE FROM kernel_record_fields WHERE record_id=?",
            &[record],
        )
        .await;
        self.sql(
            "DELETE FROM kernel_record_metadata WHERE record_id=?",
            &[record],
        )
        .await;
        self.sql("DELETE FROM kernel_records WHERE id=?", &[record])
            .await;
    }
    pub(super) async fn rec_home_of(&self, record: &str) -> String {
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(record)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
}

/// Fixture 3 (and the absent-record rows of the table). `ensure(record)`
/// never creates the home: with no home slot, an exposed home or a recovering
/// home it is `refused`/`home_unusable`, the record slot stays `absent`, and
/// nothing is written. Decision 2.
#[tokio::test]
async fn ensure_record_never_creates_the_home() {
    let w = World::fresh().await;
    w.rec_ensure_wrote_nothing(&w.other, absent_home_unusable())
        .await;
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_roots WHERE owner_id=?",
            &w.other
        )
        .await,
        0,
        "no home was created for the beneficiary"
    );
    w.assert_inspect(
        &w.other,
        SLOT,
        super::slots_eval_tests::receipt(SLOT, SlotStatus::Absent, None, None, None),
    )
    .await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        super::slots_eval_tests::receipt(HOME_FOCI_PRIVATE, SlotStatus::Absent, None, None, None),
    )
    .await;

    // An exposed home (not private) is not ready either.
    let h1 = w.rec_home(&w.other).await;
    w.widen(&h1, &w.other).await;
    w.rec_ensure_wrote_nothing(&w.other, absent_home_unusable())
        .await;

    // A recovering home: replaced while it still holds an owned Foci record.
    let focus = w.focus_in(&w.other, &h1).await;
    let h2 = w.rec_replace_home(&w.other, &h1).await.target_id.unwrap();
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE).await,
        closed(
            SlotStatus::Unusable,
            Some(UnusableReason::RecoveryIncomplete)
        )
    );
    w.rec_ensure_wrote_nothing(&w.other, absent_home_unusable())
        .await;
    assert_eq!(w.rec_home_of(&focus).await, h1);
    assert_eq!(
        w.rec_count("SELECT COUNT(*) FROM kernel_records WHERE home_id=?", &h2)
            .await,
        0,
        "nothing was created in the recovering home"
    );
}

/// Fixture 4: `ensure(record)` after the home creates the record, owned by
/// the principal, in the slot's home, with an empty list; the slot event is
/// the next event after the create, in the same act. The receipt carries the
/// record's own revision token, and the replay rebuilds the same tables.
#[tokio::test]
async fn ensure_record_creates_in_the_home_in_one_act() {
    let w = World::fresh().await;
    let home = w.rec_home(&w.other).await;
    let before = w.state().await;
    let max_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let got = w.rec_ensure(&w.other).await;
    let record = got.target_id.clone().unwrap();
    let revision = w.revision(&record).await;
    assert_receipt(
        &got,
        &healthy(SlotOutcome::Created, &record, revision, true),
    );

    let rows: Vec<(i64, String, i64)> =
        sqlx::query_as("SELECT seq, type, act FROM content_events WHERE seq > ? ORDER BY seq")
            .bind(max_seq)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(),
        ["kernel.record_created.v1", slots::PROVISIONED]
    );
    assert_eq!(
        rows[1].0,
        rows[0].0 + 1,
        "the slot event follows the create"
    );
    assert_eq!(rows[0].2, rows[1].2, "one transaction, one act");
    assert_eq!(rows[0].2, before.next_act + 1);
    assert_eq!(
        revision, rows[0].0,
        "the revision is the create event's seq"
    );

    let view = read_record_as(&w.db, &w.other, &record)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.home_id, home);
    assert_eq!(view.family.as_deref(), Some("native.foci.preferences"));
    assert_eq!(view.kind.as_deref(), Some("focus_preferences"));
    assert_eq!(serde_json::Value::Object(view.fields), json!({"foci": []}));
    let owner: String = sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id=?")
        .bind(&record)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(owner, w.other);
    // A second ensure writes nothing.
    w.rec_ensure_wrote_nothing(
        &w.other,
        healthy(SlotOutcome::Existing, &record, revision, false),
    )
    .await;
    w.replay_equal().await;
}

/// Fixture 5: editing the preferences record, then `ensure`, returns
/// `existing` with the new revision token and writes nothing.
#[tokio::test]
async fn ensure_record_after_an_edit_reports_the_new_revision() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let record = w.rec_ensure(&w.other).await.target_id.unwrap();
    let first = w.revision(&record).await;
    revise_json_as_expected(
        &w.db,
        &w.other,
        &record,
        r#"{"foci":[{"focus_id":"f1","tier":"now","hidden":false}]}"#,
        Some(first),
    )
    .await
    .unwrap();
    let second = w.revision(&record).await;
    assert!(second > first);
    w.rec_ensure_wrote_nothing(
        &w.other,
        healthy(SlotOutcome::Existing, &record, second, false),
    )
    .await;
    w.assert_inspect(
        &w.other,
        SLOT,
        rec(
            SlotStatus::Healthy,
            SlotOutcome::Inspected,
            None,
            None,
            Some(&record),
            Some(second),
            None,
        ),
    )
    .await;
    w.replay_equal().await;
}

/// Fixture 6, record half: principal B starts absent, gets a record of their
/// own, and a `replace` with A's id is a CAS mismatch that reports B's own
/// mapping. Nothing of A's appears in B's receipts, and B cannot read A's
/// record.
#[tokio::test]
async fn record_slots_are_isolated_between_principals() {
    let w = World::fresh().await;
    let b = create_principal(&w.db, "account", "B", "acct:b", &w.admin)
        .await
        .unwrap();
    w.rec_home(&w.other).await;
    let a_record = w.rec_ensure(&w.other).await.target_id.unwrap();
    // B has no home yet, so their record cannot be created.
    w.rec_ensure_wrote_nothing(&b, absent_home_unusable()).await;
    w.rec_home(&b).await;
    let ensured = w.rec_ensure(&b).await;
    let b_record = ensured.target_id.clone().unwrap();
    assert_ne!(a_record, b_record);
    let b_revision = w.revision(&b_record).await;
    assert_receipt(
        &ensured,
        &healthy(SlotOutcome::Created, &b_record, b_revision, true),
    );
    let before = w.state().await;
    let refused = w.rec_replace(&b, &a_record).await;
    // A healthy mapping carries its guard even in a refusal.
    assert_receipt(
        &refused,
        &rec(
            SlotStatus::Healthy,
            SlotOutcome::Refused,
            None,
            Some(Refusal::CasMismatch),
            Some(&b_record),
            Some(b_revision),
            None,
        ),
    );
    assert_eq!(before, w.state().await);
    for receipt in [&ensured, &refused] {
        assert!(!serde_json::to_string(receipt).unwrap().contains(&a_record));
    }
    assert!(read_record_as(&w.db, &b, &a_record)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        w.inspect(&w.other, SLOT).await.target_id.as_deref(),
        Some(a_record.as_str())
    );
}

/// A fault hook: the first (and only) attempt fails after the target was
/// created and before the slot event is appended. It is a plain engine error,
/// not a UNIQUE violation, so it must reach the caller unchanged and unretried.
struct FailBeforeRegister {
    calls: AtomicU32,
}

impl FailBeforeRegister {
    fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
        }
    }
}

impl AttemptHooks for FailBeforeRegister {
    async fn before_register(
        &self,
        _tx: &mut Transaction<'static, Sqlite>,
        _attempt: u32,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(Error::engine("injected fault before registration"))
    }
}

/// Fixture 7: a fault after the target is created and before the slot event is
/// appended, for each slot type and each action. The error reaches the caller
/// once (no retry); the target, its event, the slot row and the act counter
/// all roll back.
#[tokio::test]
async fn a_fault_between_create_and_registration_leaves_nothing() {
    const FAULT: &str = "injected fault before registration";
    let honest = |w: &World| TestProvisioner::new(&w.admin, Mode::Honest);

    // Home slot, ensure: the provisioner has created the home in the shared
    // transaction when the fault fires.
    let w = World::fresh().await;
    let (before, homes) = (
        w.state().await,
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_roots WHERE owner_id=?",
            &w.other,
        )
        .await,
    );
    let hook = FailBeforeRegister::new();
    engine_error(
        ensure_home_with(&w.db, &honest(&w), &hook, &w.other, "test").await,
        FAULT,
    );
    assert_eq!(hook.calls.load(Ordering::SeqCst), 1, "not retried");
    assert_eq!(before, w.state().await);
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_roots WHERE owner_id=?",
            &w.other
        )
        .await,
        homes
    );

    // Home slot, replace.
    let h1 = w.rec_home(&w.other).await;
    w.widen(&h1, &w.other).await;
    let before = w.state().await;
    let hook = FailBeforeRegister::new();
    engine_error(
        replace_home_with(&w.db, &honest(&w), &hook, &w.other, &h1, "test").await,
        FAULT,
    );
    assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_roots WHERE owner_id=?",
            &w.other
        )
        .await,
        1
    );
    w.replay_equal().await;

    // Record slot, ensure.
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let before = w.state().await;
    let records = w
        .rec_count(
            "SELECT COUNT(*) FROM kernel_records WHERE owner_id=?",
            &w.other,
        )
        .await;
    let hook = FailBeforeRegister::new();
    engine_error(
        ensure_record_with(&w.db, &hook, &w.other, "test").await,
        FAULT,
    );
    assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_records WHERE owner_id=?",
            &w.other
        )
        .await,
        records
    );
    assert_eq!(w.rec_events(slots::PROVISIONED).await, 1, "only the home's");

    // Record slot, replace (a missing record, so the replace would commit).
    let record = w.rec_ensure(&w.other).await.target_id.unwrap();
    w.rec_delete_rows(&record).await;
    let before = w.state().await;
    let hook = FailBeforeRegister::new();
    engine_error(
        replace_record_with(&w.db, &hook, &w.other, &record, "test").await,
        FAULT,
    );
    assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);
    assert_eq!(w.rec_events(slots::REPLACED).await, 0);
}

/// Fixture 8, record half: two concurrent `ensure(record)` calls for one
/// principal give one `created`, one `existing`, one record and one slot row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_record_ensures_have_one_winner() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let spawn = |w: &World| {
        let (db, who) = (w.db.clone(), w.other.clone());
        tokio::spawn(async move { ensure_record(&db, &who, "race").await.unwrap() })
    };
    let (a, b) = (spawn(&w), spawn(&w));
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    let mut got = [a, b];
    got.sort_by_key(|r| format!("{:?}", r.outcome));
    let record = got[0].target_id.clone().unwrap();
    let revision = w.revision(&record).await;
    // `Created` sorts before `Existing`.
    assert_receipt(
        &got[0],
        &healthy(SlotOutcome::Created, &record, revision, true),
    );
    assert_receipt(
        &got[1],
        &healthy(SlotOutcome::Existing, &record, revision, false),
    );
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_records WHERE pin_family=?",
            "native.foci.preferences"
        )
        .await,
        1
    );
    let slots = w.state().await.dump.slots;
    assert_eq!(slots.iter().filter(|row| row.1 == SLOT).count(), 1);
    w.replay_equal().await;
}

/// Fixture 9, record half: two concurrent `replace(record)` calls with the same
/// `expected_target`. The new record is ready at once, so one is `replaced`
/// and the other `replayed`, with exactly one new record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_record_replaces_have_one_winner() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let r1 = w.rec_ensure(&w.other).await.target_id.unwrap();
    w.rec_delete_rows(&r1).await;
    let spawn = |w: &World| {
        let (db, who, r1) = (w.db.clone(), w.other.clone(), r1.clone());
        tokio::spawn(async move { replace_record(&db, &who, &r1, "race").await.unwrap() })
    };
    let (a, b) = (spawn(&w), spawn(&w));
    let mut got = [a.await.unwrap(), b.await.unwrap()];
    got.sort_by_key(|r| format!("{:?}", r.outcome));
    let r2 = got[0].target_id.clone().unwrap();
    assert_ne!(r1, r2);
    let revision = w.revision(&r2).await;
    // `Replaced` sorts before `Replayed`.
    assert_receipt(
        &got[0],
        &healthy(SlotOutcome::Replaced, &r2, revision, true),
    );
    assert_receipt(
        &got[1],
        &healthy(SlotOutcome::Replayed, &r2, revision, false),
    );
    assert_eq!(w.rec_events(slots::REPLACED).await, 1);
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_records WHERE pin_family=?",
            "native.foci.preferences"
        )
        .await,
        1,
        "the deleted record's row is gone and exactly one new record exists"
    );
}

/// Fixture 10, record half. The first attempt's slot append fails with a typed
/// UNIQUE violation and rolls back whole, including the record it created;
/// an independent writer then commits a winner through the public operation;
/// exactly one retry rereads it.
struct RecordBackstop {
    db: Db,
    principal: String,
    /// The record the winner replaces, if any.
    replaces: Option<String>,
    inject_every_attempt: bool,
    baseline: (i64, i64),
    registers: AtomicU32,
    rollbacks: AtomicU32,
    winner: Mutex<Option<String>>,
}

impl RecordBackstop {
    async fn new(w: &World, replaces: Option<&str>, inject_every_attempt: bool) -> Arc<Self> {
        let state = w.state().await;
        Arc::new(Self {
            db: w.db.clone(),
            principal: w.other.clone(),
            replaces: replaces.map(String::from),
            inject_every_attempt,
            baseline: (state.events, state.next_act),
            registers: AtomicU32::new(0),
            rollbacks: AtomicU32::new(0),
            winner: Mutex::new(None),
        })
    }
}

impl AttemptHooks for RecordBackstop {
    async fn before_register(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        attempt: u32,
    ) -> Result<()> {
        self.registers.fetch_add(1, Ordering::SeqCst);
        if attempt > 0 && !self.inject_every_attempt {
            return Ok(());
        }
        // A genuine duplicate primary key: the same typed error a collision
        // with a committed winner would raise. No error text is parsed.
        let insert = "INSERT INTO kernel_slots(principal_id,slot,target_id,generation,set_seq) VALUES(?,?,?,1,1)";
        for _ in 0..2 {
            sqlx::query(insert)
                .bind(&self.principal)
                .bind(SLOT)
                .bind("injected")
                .execute(&mut **tx)
                .await?;
        }
        unreachable!("the second insert violates the primary key")
    }
    async fn after_rollback(&self, attempt: u32) {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(self.db.pool())
            .await
            .unwrap();
        let next_act: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(self.db.pool())
            .await
            .unwrap();
        assert_eq!(
            (events, next_act),
            self.baseline,
            "attempt {attempt} leaked"
        );
        if self.inject_every_attempt {
            return;
        }
        // Only now, with the writer lock free, does the winner commit.
        let receipt = match &self.replaces {
            None => ensure_record(&self.db, &self.principal, "winner").await,
            Some(previous) => replace_record(&self.db, &self.principal, previous, "winner").await,
        }
        .unwrap();
        *self.winner.lock().unwrap() = receipt.target_id;
    }
}

#[tokio::test]
async fn record_unique_backstop_rereads_once_for_ensure() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let hook = RecordBackstop::new(&w, None, false).await;
    let got = ensure_record_with(&w.db, &*hook, &w.other, "race")
        .await
        .unwrap();
    let winner = hook.winner.lock().unwrap().clone().unwrap();
    let revision = w.revision(&winner).await;
    assert_receipt(
        &got,
        &healthy(SlotOutcome::Existing, &winner, revision, false),
    );
    // One failed attempt, one retry, and the retry registered nothing.
    assert_eq!(hook.registers.load(Ordering::SeqCst), 1);
    assert_eq!(hook.rollbacks.load(Ordering::SeqCst), 1);
    // The abandoned attempt's record does not exist: the winner's is the only one.
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_records WHERE pin_family=?",
            "native.foci.preferences"
        )
        .await,
        1
    );
    assert_eq!(w.rec_events(slots::PROVISIONED).await, 2, "home and record");
    w.replay_equal().await;
}

#[tokio::test]
async fn record_unique_backstop_rereads_once_for_replace() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let r1 = w.rec_ensure(&w.other).await.target_id.unwrap();
    w.rec_delete_rows(&r1).await;
    let hook = RecordBackstop::new(&w, Some(&r1), false).await;
    let got = replace_record_with(&w.db, &*hook, &w.other, &r1, "race")
        .await
        .unwrap();
    let winner = hook.winner.lock().unwrap().clone().unwrap();
    let revision = w.revision(&winner).await;
    assert_receipt(
        &got,
        &healthy(SlotOutcome::Replayed, &winner, revision, false),
    );
    assert_eq!(hook.registers.load(Ordering::SeqCst), 1);
    assert_eq!(hook.rollbacks.load(Ordering::SeqCst), 1);
    assert_eq!(w.rec_events(slots::REPLACED).await, 1);
    assert_eq!(
        w.rec_count(
            "SELECT COUNT(*) FROM kernel_records WHERE pin_family=?",
            "native.foci.preferences"
        )
        .await,
        1
    );
}

/// The retry is capped at one: a second UNIQUE violation is the caller's
/// error, with nothing written and the act counter untouched.
#[tokio::test]
async fn a_second_record_unique_violation_is_an_error() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    let hook = RecordBackstop::new(&w, None, true).await;
    let before = w.state().await;
    let err = ensure_record_with(&w.db, &*hook, &w.other, "race")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Sqlx(sqlx::Error::Database(e)) if e.is_unique_violation()));
    assert_eq!(hook.registers.load(Ordering::SeqCst), 2);
    assert_eq!(hook.rollbacks.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);
}

/// Fixture 17, record half. Direct SQL: the record's rows are gone but its
/// mapping is intact. `missing` with the id still shown; `ensure` refuses with
/// a null refusal; `replace` creates a new record in the same home, in one act
/// with its slot event, and the lineage keeps the history.
#[tokio::test]
async fn a_missing_record_is_replaced_in_the_same_home() {
    let w = World::fresh().await;
    let (home, r1) = w.ready(&w.other).await;
    w.rec_delete_rows(&r1).await;
    w.assert_inspect(
        &w.other,
        SLOT,
        unusable(SLOT, UnusableReason::Missing, Some(&r1)),
    )
    .await;
    w.rec_ensure_wrote_nothing(
        &w.other,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::Missing),
            None,
            Some(&r1),
        ),
    )
    .await;
    let max_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let got = w.rec_replace(&w.other, &r1).await;
    let r2 = got.target_id.clone().unwrap();
    assert_ne!(r1, r2);
    let revision = w.revision(&r2).await;
    assert_receipt(&got, &healthy(SlotOutcome::Replaced, &r2, revision, true));
    assert_eq!(w.rec_home_of(&r2).await, home);
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT type, act FROM content_events WHERE seq > ? ORDER BY seq")
            .bind(max_seq)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["kernel.record_created.v1", slots::REPLACED]
    );
    assert_eq!(rows[0].1, rows[1].1, "one transaction, one act");
    let lineage: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT generation, target_id, previous_target_id FROM kernel_slot_lineage WHERE slot=? ORDER BY generation",
    )
    .bind(SLOT)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(
        lineage,
        vec![(1, r1.clone(), None), (2, r2, Some(r1.clone()))]
    );
    // The old record's events are untouched; only its projection row is gone.
    assert!(w.revision(&r1).await > 0);
}

/// Fixture 18, record half. Direct SQL: the slot points at a record of another
/// family, or at one the principal does not own: `wrong_target`, which
/// `replace` repairs in a ready home. A record the principal cannot see is
/// `forbidden` with the id withheld from every receipt; a caller who knows the
/// id can still replace it.
#[tokio::test]
async fn a_wrong_or_hidden_record_is_withheld_and_replaceable() {
    // Another family, owned by the principal, in their own home.
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    let focus = w.focus_in(&w.other, &home).await;
    w.set_slot_target(&w.other, SLOT, &focus).await;
    w.rec_ensure_wrote_nothing(
        &w.other,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::WrongTarget),
            None,
            Some(&focus),
        ),
    )
    .await;
    let got = w.rec_replace(&w.other, &focus).await;
    let fixed = got.target_id.clone().unwrap();
    assert_receipt(
        &got,
        &healthy(
            SlotOutcome::Replaced,
            &fixed,
            w.revision(&fixed).await,
            true,
        ),
    );
    assert_ne!(fixed, record);
    assert_eq!(w.rec_home_of(&fixed).await, home);

    // The right family and kind, owned by someone else (made by SQL).
    let w = World::fresh().await;
    let (_home, record) = w.ready(&w.other).await;
    w.sql(
        "UPDATE kernel_records SET owner_id=? WHERE id=?",
        &[&w.admin, &record],
    )
    .await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::WrongTarget),
            Some(Refusal::CasMismatch),
            Some(&record),
        ),
    )
    .await;
    let got = w.rec_replace(&w.other, &record).await;
    let fixed = got.target_id.clone().unwrap();
    assert_ne!(fixed, record);
    assert_receipt(
        &got,
        &healthy(
            SlotOutcome::Replaced,
            &fixed,
            w.revision(&fixed).await,
            true,
        ),
    );

    // A record in another principal's private home: nothing of it is visible.
    let w = World::fresh().await;
    let (_home, _record) = w.ready(&w.other).await;
    let (admin_home, _) = w.ready(&w.admin).await;
    let hidden = w.record_in(&w.admin, &admin_home).await;
    w.set_slot_target(&w.other, SLOT, &hidden).await;
    let withheld = |refusal| {
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::Forbidden),
            refusal,
            None,
        )
    };
    w.rec_ensure_wrote_nothing(&w.other, withheld(None)).await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        withheld(Some(Refusal::CasMismatch)),
    )
    .await;
    let got = w.rec_replace(&w.other, &hidden).await;
    let fixed = got.target_id.clone().unwrap();
    assert_receipt(
        &got,
        &healthy(
            SlotOutcome::Replaced,
            &fixed,
            w.revision(&fixed).await,
            true,
        ),
    );
    assert_ne!(fixed, hidden);
}

/// Fixture 20: a `missing` record is `unusable`/`missing` whatever the home
/// is doing, but `replace` creates the new record only when the home is ready:
/// `home_unusable` with the home absent, `home_unusable` with it widened,
/// `replaced` with it ready. (Direct SQL deletes the record's rows and, in
/// the first case, the home mapping.)
#[tokio::test]
async fn a_missing_record_is_replaced_only_into_a_ready_home() {
    for case in ["absent", "widened", "ready"] {
        let w = World::fresh().await;
        let (home, record) = w.ready(&w.other).await;
        w.rec_delete_rows(&record).await;
        match case {
            "absent" => {
                w.sql(
                    "DELETE FROM kernel_slots WHERE principal_id=? AND slot=?",
                    &[&w.other, HOME_FOCI_PRIVATE],
                )
                .await
            }
            "widened" => w.widen(&home, &w.other).await,
            _ => {}
        }
        w.assert_inspect(
            &w.other,
            SLOT,
            unusable(SLOT, UnusableReason::Missing, Some(&record)),
        )
        .await;
        // `ensure` on an existing unusable record never uses `home_unusable`.
        w.rec_ensure_wrote_nothing(
            &w.other,
            refusal_of(
                SlotStatus::Unusable,
                Some(UnusableReason::Missing),
                None,
                Some(&record),
            ),
        )
        .await;
        if case == "ready" {
            let got = w.rec_replace(&w.other, &record).await;
            let fixed = got.target_id.clone().unwrap();
            assert_receipt(
                &got,
                &healthy(
                    SlotOutcome::Replaced,
                    &fixed,
                    w.revision(&fixed).await,
                    true,
                ),
            );
            assert_eq!(w.rec_home_of(&fixed).await, home);
        } else {
            w.rec_replace_wrote_nothing(
                &w.other,
                &record,
                refusal_of(
                    SlotStatus::Unusable,
                    Some(UnusableReason::Missing),
                    Some(Refusal::HomeUnusable),
                    Some(&record),
                ),
            )
            .await;
        }
    }
}

/// Fixture 25, record half. Direct SQL: the home slot points at a foreign-owned
/// home whose policy names only the other owner, and the principal's own
/// preferences record sits in it. The home is `forbidden`; the record slot is
/// `wrong_home` with its own id shown; the gate refuses; `replace(record)` is
/// `unsupported_recovery` and `ensure` refuses with a null refusal. The
/// record's own owner floor does not rescue it.
#[tokio::test]
async fn a_record_in_a_forbidden_home_is_wrong_home_and_not_replaceable() {
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
        SLOT,
        unusable(SLOT, UnusableReason::WrongHome, Some(&record)),
    )
    .await;
    assert_eq!(
        w.gate(&w.other, SLOT).await,
        closed(SlotStatus::Unusable, Some(UnusableReason::WrongHome))
    );
    let wrong_home = |refusal| {
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::WrongHome),
            refusal,
            Some(&record),
        )
    };
    w.rec_ensure_wrote_nothing(&w.other, wrong_home(None)).await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &record,
        wrong_home(Some(Refusal::UnsupportedRecovery)),
    )
    .await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        wrong_home(Some(Refusal::CasMismatch)),
    )
    .await;
}

/// Decision 4. A valid owned record in a non-current home is rehomed, not
/// replaced: `replace` is `unsupported_recovery`, the preferences survive, and
/// moving the record into the current home makes both slots ready again.
#[tokio::test]
async fn a_record_in_an_old_home_is_rehomed_not_replaced() {
    let w = World::fresh().await;
    let h1 = w.rec_home(&w.other).await;
    let record = w.rec_ensure(&w.other).await.target_id.unwrap();
    revise_json_as_expected(
        &w.db,
        &w.other,
        &record,
        r#"{"foci":[{"focus_id":"keep","tier":"now","hidden":false}]}"#,
        Some(w.revision(&record).await),
    )
    .await
    .unwrap();
    w.widen(&h1, &w.other).await;
    let h2 = w.rec_replace_home(&w.other, &h1).await.target_id.unwrap();
    assert_ne!(h1, h2);
    w.assert_inspect(
        &w.other,
        SLOT,
        unusable(SLOT, UnusableReason::WrongHome, Some(&record)),
    )
    .await;
    let wrong_home = |refusal| {
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::WrongHome),
            refusal,
            Some(&record),
        )
    };
    w.rec_ensure_wrote_nothing(&w.other, wrong_home(None)).await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &record,
        wrong_home(Some(Refusal::UnsupportedRecovery)),
    )
    .await;
    // The preferences are intact and still the slot's target.
    let view = read_record_as(&w.db, &w.other, &record)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::Value::Object(view.fields)["foci"][0]["focus_id"],
        "keep"
    );
    // Rehoming, not replacing, restores both slots.
    rehome_record_as(&w.db, &w.other, &record, &h2)
        .await
        .unwrap();
    assert_eq!(
        w.gate(&w.other, HOME_FOCI_PRIVATE)
            .await
            .map(|t| t.target_id),
        Ok(h2)
    );
    let revision = w.revision(&record).await;
    w.rec_ensure_wrote_nothing(
        &w.other,
        healthy(SlotOutcome::Existing, &record, revision, false),
    )
    .await;
}

/// The `not_private` and `recovery_incomplete` rows: the record is in the
/// current home and the home is the problem, so `ensure` refuses with a null
/// refusal and `replace` is `home_unusable`. A new record would sit in the
/// same home.
#[tokio::test]
async fn a_record_in_an_unready_home_is_refused_as_home_unusable() {
    // not_private: the home is widened.
    let w = World::fresh().await;
    let (home, record) = w.ready(&w.other).await;
    w.widen(&home, &w.other).await;
    let state = |refusal| {
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::NotPrivate),
            refusal,
            Some(&record),
        )
    };
    w.assert_inspect(
        &w.other,
        SLOT,
        unusable(SLOT, UnusableReason::NotPrivate, Some(&record)),
    )
    .await;
    w.rec_ensure_wrote_nothing(&w.other, state(None)).await;
    w.rec_replace_wrote_nothing(&w.other, &record, state(Some(Refusal::HomeUnusable)))
        .await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        state(Some(Refusal::CasMismatch)),
    )
    .await;

    // recovery_incomplete: the record moved into the replacement home, but a
    // Focus is still in the first one.
    let w = World::fresh().await;
    let (h1, record) = w.ready(&w.other).await;
    let _focus = w.focus_in(&w.other, &h1).await;
    w.widen(&h1, &w.other).await;
    let h2 = w.rec_replace_home(&w.other, &h1).await.target_id.unwrap();
    rehome_record_as(&w.db, &w.other, &record, &h2)
        .await
        .unwrap();
    let state = |refusal| {
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::RecoveryIncomplete),
            refusal,
            Some(&record),
        )
    };
    w.assert_inspect(
        &w.other,
        SLOT,
        unusable(SLOT, UnusableReason::RecoveryIncomplete, Some(&record)),
    )
    .await;
    w.rec_ensure_wrote_nothing(&w.other, state(None)).await;
    w.rec_replace_wrote_nothing(&w.other, &record, state(Some(Refusal::HomeUnusable)))
        .await;
}

/// The healthy-slot rows: `replace` on a ready record is `not_unusable`, with a
/// wrong id `cas_mismatch`, and on an absent slot `absent`. Zero writes, and
/// the receipts carry the current mapping's guard.
#[tokio::test]
async fn record_replace_refuses_healthy_wrong_and_absent() {
    let w = World::fresh().await;
    w.rec_home(&w.other).await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        refusal_of(SlotStatus::Absent, None, Some(Refusal::Absent), None),
    )
    .await;
    let record = w.rec_ensure(&w.other).await.target_id.unwrap();
    let revision = w.revision(&record).await;
    let ready = |refusal| {
        rec(
            SlotStatus::Healthy,
            SlotOutcome::Refused,
            None,
            Some(refusal),
            Some(&record),
            Some(revision),
            None,
        )
    };
    w.rec_replace_wrote_nothing(&w.other, &record, ready(Refusal::NotUnusable))
        .await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        ready(Refusal::CasMismatch),
    )
    .await;
}

/// Fixtures 26 to 29 as they apply to a record: a retry after a replace is
/// `replayed` and writes nothing; replacing again from the winner makes the
/// original retry `mapping_changed` with the current mapping's fields; and a
/// winner that has since become unusable gives `already_replaced`.
#[tokio::test]
async fn record_replace_retries_are_replayed_or_mapping_changed() {
    let w = World::fresh().await;
    let (home, r1) = w.ready(&w.other).await;
    w.rec_delete_rows(&r1).await;
    let first = w.rec_replace(&w.other, &r1).await;
    let r2 = first.target_id.clone().unwrap();
    let rev2 = w.revision(&r2).await;
    assert_receipt(&first, &healthy(SlotOutcome::Replaced, &r2, rev2, true));
    w.rec_replace_wrote_nothing(
        &w.other,
        &r1,
        healthy(SlotOutcome::Replayed, &r2, rev2, false),
    )
    .await;

    // Replace from the winner; the original retry now sees a changed mapping.
    w.rec_delete_rows(&r2).await;
    let r3 = w.rec_replace(&w.other, &r2).await.target_id.unwrap();
    let rev3 = w.revision(&r3).await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &r1,
        rec(
            SlotStatus::Healthy,
            SlotOutcome::Refused,
            None,
            Some(Refusal::MappingChanged),
            Some(&r3),
            Some(rev3),
            None,
        ),
    )
    .await;

    // The winner of the latest replacement turns unusable: already_replaced,
    // never repaired.
    w.widen(&home, &w.other).await;
    w.rec_replace_wrote_nothing(
        &w.other,
        &r2,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::NotPrivate),
            Some(Refusal::AlreadyReplaced),
            Some(&r3),
        ),
    )
    .await;
}

/// Malformed requests are errors with nothing written, each isolated so it
/// cannot be masked by another check: a blank reason (valid target and
/// account), an agent principal (valid reason and target), and a malformed
/// `expected_target` (absent slot, present slot) which must not read as
/// `absent` or `cas_mismatch`.
#[tokio::test]
async fn malformed_record_requests_are_errors() {
    let w = World::fresh().await;
    let agent = create_principal(&w.db, "agent", "Agent", "agent:a", &w.admin)
        .await
        .unwrap();
    w.rec_home(&w.other).await;
    let before = w.state().await;
    engine_error(
        ensure_record(&w.db, &w.other, "  ").await,
        "slot reason must not be blank",
    );
    engine_error(
        ensure_record(&w.db, &agent, "test").await,
        "slot principal must be an account",
    );
    engine_error(
        replace_record(&w.db, &agent, &Uuid::new_v4().to_string(), "test").await,
        "slot principal must be an account",
    );
    engine_error(
        replace_record(&w.db, &w.other, &Uuid::new_v4().to_string(), "").await,
        "slot reason must not be blank",
    );
    assert_eq!(before, w.state().await);

    // The slot is absent for `fresh_one` and present for `other`.
    let fresh_one = create_principal(&w.db, "account", "Fresh", "acct:fresh", &w.admin)
        .await
        .unwrap();
    let record = w.rec_ensure(&w.other).await.target_id.unwrap();
    let bad = [
        "x".to_string(),
        String::new(),
        Uuid::new_v4().to_string().to_uppercase(),
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        "886313e1-3b8a-5372-9b90-0c9aee199e5d".to_string(),
        "550e8400-e29b-41d4-0716-446655440000".to_string(),
        KERNEL_ROOT_ID.to_string(),
    ];
    for principal in [&w.other, &fresh_one] {
        for target in &bad {
            let before = w.state().await;
            engine_error(
                replace_record(&w.db, principal, target, "test").await,
                "invalid slot target id",
            );
            assert_eq!(before, w.state().await, "{target:?}");
        }
    }
    assert_eq!(
        w.inspect(&w.other, SLOT).await.target_id.as_deref(),
        Some(record.as_str())
    );
}
