//! Sealed beneficiary home creation fixtures (Foci v2 G6 increment 3; design
//! note 681a449 §3.3, §8): 47 and 48 for admission and the generic barriers,
//! 50 for G7's created-here check, 51 for the authority frontier (the two
//! frontier tests live beside the claims and relation ports), and 74 for the
//! configuration boundary and the fold. The provisioner itself arrives in
//! increment 4; the stand-in below composes the real `validate_on` and
//! `append_home_for_in` the way it will.
use super::slots::{self, HOME_CREATED_FOR, HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::slots_eval::SlotOutcome;
use super::slots_eval_tests::assert_receipt;
use super::slots_ops::{
    ensure_home, replace_home, HomeProvisioner, ProvisionOutcome, SlotTxContext,
};
use super::slots_ops_tests::{ready, Mode, TestProvisioner};
use super::slots_tests::{engine_error, World};
use super::*;
use serde_json::{json, Value};

/// An operator-created `agent` service holding Manage only on one parent.
pub(super) struct Fx {
    pub(super) w: World,
    pub(super) svc: String,
    pub(super) p0: String,
    pub(super) cfg: slots::ProvisionerConfig,
}

impl Fx {
    pub(super) async fn fresh() -> Self {
        Self::on(World::fresh().await).await
    }
    pub(super) async fn on(w: World) -> Self {
        let (svc, p0, cfg) = designate(&w.db, &w.admin).await;
        Self { w, svc, p0, cfg }
    }
    /// Provision a home for `owner` in its own transaction and act.
    pub(super) async fn provision(&self, owner: &str) -> Result<EventRow> {
        provision_for(&self.w.db, &self.cfg, owner).await
    }
    pub(super) async fn agent(&self, name: &str) -> String {
        create_principal(
            &self.w.db,
            "agent",
            name,
            &format!("agent:{}", Uuid::new_v4()),
            &self.w.admin,
        )
        .await
        .unwrap()
    }
    pub(super) async fn count(&self, statement: &str, bind: &str) -> i64 {
        sqlx::query_scalar(statement)
            .bind(bind)
            .fetch_one(self.w.db.pool())
            .await
            .unwrap()
    }
}

/// The operator's one-off setup: the service, and the parent with its own
/// anchor `[(service, manage)]` owned by the admin.
pub(super) async fn designate(db: &Db, admin: &str) -> (String, String, slots::ProvisionerConfig) {
    let svc = create_principal(db, "agent", "Provisioner", "agent:provisioner", admin)
        .await
        .unwrap();
    let p0 = create_home(db, KERNEL_ROOT_ID, Some(&[(&svc, "manage")]), admin)
        .await
        .unwrap();
    let cfg = slots::ProvisionerConfig {
        service: svc.clone(),
        parent: p0.clone(),
    };
    (svc, p0, cfg)
}

pub(super) async fn provision_for(
    db: &Db,
    cfg: &slots::ProvisionerConfig,
    owner: &str,
) -> Result<EventRow> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let validated = cfg.validate_on(&mut tx).await?;
    let event =
        slots::append_home_for_in(db, &mut acts, validated, owner, HOME_FOCI_PRIVATE).await?;
    tx.commit().await?;
    Ok(event)
}

fn home_for(actor: &str, parent: &str, owner: &str, slot: &str) -> AppendSpec {
    AppendSpec {
        record_id: Uuid::new_v4().to_string(),
        event_type: HOME_CREATED_FOR.into(),
        payload: json!({"parent_id": parent, "owner_id": owner, "slot": slot}),
        actor: Some(actor.into()),
    }
}

/// The real composition a G6 provisioner will run: validate the
/// configuration on the open transaction, then append through the sole
/// appender. Registers nothing.
struct SealedProvisioner {
    cfg: slots::ProvisionerConfig,
    /// Owner the home is created for; `None` is the beneficiary.
    owner: Option<String>,
    /// Add a second policy entry by direct SQL after the sealed append.
    extra_entry: Option<String>,
}

impl SealedProvisioner {
    fn honest(cfg: &slots::ProvisionerConfig) -> Self {
        Self {
            cfg: cfg.clone(),
            owner: None,
            extra_entry: None,
        }
    }
}

impl HomeProvisioner for SealedProvisioner {
    async fn provision_home_in(&self, cx: &mut SlotTxContext<'_>) -> Result<ProvisionOutcome> {
        let validated = self.cfg.validate_on(&mut *cx.tx).await?;
        let owner = self.owner.as_deref().unwrap_or(cx.principal);
        let event =
            slots::append_home_for_in(cx.db, &mut *cx.acts, validated, owner, HOME_FOCI_PRIVATE)
                .await?;
        if let Some(subject) = &self.extra_entry {
            sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'account', ?, 'allow', 'view')")
                .bind(&event.record_id)
                .bind(subject)
                .execute(&mut **cx.tx)
                .await?;
        }
        Ok(ProvisionOutcome::Home(event.record_id))
    }
}

/// Design fixture 47, positive half: the fold installs the beneficiary as
/// owner with exactly one own entry, allow-Manage for them. The service and
/// the admin end with no access; replay rebuilds the same tables.
#[tokio::test]
async fn provisioning_installs_the_beneficiary_as_sole_manager() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    let event = fx.provision(&w.other).await.unwrap();
    let home = event.record_id.clone();
    assert_eq!(event.event_type, HOME_CREATED_FOR);
    assert_eq!(event.actor.as_deref(), Some(fx.svc.as_str()));
    let payload: Value = serde_json::from_str(event.payload.as_deref().unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({"parent_id": fx.p0, "owner_id": w.other, "slot": HOME_FOCI_PRIVATE})
    );

    let (parent, owner): (String, String) =
        sqlx::query_as("SELECT parent_id, owner_id FROM kernel_roots WHERE root_id=?")
            .bind(&home)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!((parent, owner), (fx.p0.clone(), w.other.clone()));
    let policies = fx
        .count(
            "SELECT COUNT(*) FROM kernel_policies WHERE root_id=?",
            &home,
        )
        .await;
    assert_eq!(policies, 1, "the home has its own anchor");
    let entries: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT subject_kind, subject_id, effect, capability FROM kernel_policy_entries WHERE root_id=?",
    )
    .bind(&home)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(
        entries,
        [(
            "account".into(),
            w.other.clone(),
            "allow".into(),
            "manage".into()
        )]
    );
    for (principal, capability) in [
        (&w.other, Capability::Manage),
        (&fx.svc, Capability::None),
        (&w.admin, Capability::None),
    ] {
        let mut conn = w.db.pool().acquire().await.unwrap();
        assert_eq!(
            super::slots_eval::capability_on(&mut conn, principal, &home)
                .await
                .unwrap(),
            capability
        );
    }
    // The service can still provision for someone else.
    let other_owner = create_principal(&w.db, "account", "Third", "acct:third", &w.admin)
        .await
        .unwrap();
    fx.provision(&other_owner).await.unwrap();
    w.replay_equal().await;
}

/// Design fixture 47: admission refuses each config-independent rule through
/// the sealed route, with zero events written.
#[tokio::test]
async fn admission_refuses_each_rule_with_nothing_written() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    let s2 = fx.agent("Second service").await;
    let missing = Uuid::new_v4().to_string();

    // An account admin has Manage on the root, but is neither an agent nor
    // may the root be the parent: refused twice over.
    w.refused(
        home_for(&w.admin, KERNEL_ROOT_ID, &w.other, HOME_FOCI_PRIVATE),
        "home creation actor must be an agent",
    )
    .await;
    w.refused(
        home_for(&fx.svc, KERNEL_ROOT_ID, &w.other, HOME_FOCI_PRIVATE),
        "home creation parent must not be the root",
    )
    .await;
    // An agent without Manage on the parent.
    w.refused(
        home_for(&s2, &fx.p0, &w.other, HOME_FOCI_PRIVATE),
        "home creation actor lacks Manage on the parent",
    )
    .await;
    w.refused(
        home_for(&fx.svc, &fx.p0, &fx.svc, HOME_FOCI_PRIVATE),
        "home owner must not be the creating actor",
    )
    .await;
    // The owner must be an account: an agent, and an unknown principal.
    for owner in [s2.as_str(), missing.as_str()] {
        w.refused(
            home_for(&fx.svc, &fx.p0, owner, HOME_FOCI_PRIVATE),
            "home owner must be an account",
        )
        .await;
    }
    // The slot must be a registered home slot.
    for slot in [RECORD_FOCI_PREFERENCES, "home:not_registered"] {
        w.refused(
            home_for(&fx.svc, &fx.p0, &w.other, slot),
            "home slot is not a registered home slot",
        )
        .await;
    }
    w.refused(
        home_for(&fx.svc, &missing, &w.other, HOME_FOCI_PRIVATE),
        "home creation parent is not a home",
    )
    .await;
    let mut no_actor = home_for(&fx.svc, &fx.p0, &w.other, HOME_FOCI_PRIVATE);
    no_actor.actor = None;
    w.refused(no_actor, "home creation requires an actor").await;
    // The id must be canonical and fresh: not an existing home or record.
    let record_home = w.home(&w.other).await;
    let record = w.record_in(&w.other, &record_home).await;
    for (id, message) in [
        ("not-a-uuid", "home id is not a canonical id"),
        (fx.p0.as_str(), "home id is not fresh"),
        (record.as_str(), "home id is not fresh"),
    ] {
        w.refused(
            AppendSpec {
                record_id: id.into(),
                ..home_for(&fx.svc, &fx.p0, &w.other, HOME_FOCI_PRIVATE)
            },
            message,
        )
        .await;
    }
    // The payload is closed: no policy field, no extras.
    for extra in ["entries", "policy", "unexpected"] {
        let mut spec = home_for(&fx.svc, &fx.p0, &w.other, HOME_FOCI_PRIVATE);
        spec.payload[extra] = json!([{"subject_id": w.admin, "capability": "manage"}]);
        let before = w.state().await;
        assert!(w.append_raw(spec).await.is_err());
        assert_eq!(before, w.state().await);
    }
    // Control: the same shape, valid, is admitted.
    w.append_raw(home_for(&fx.svc, &fx.p0, &w.other, HOME_FOCI_PRIVATE))
        .await
        .unwrap();
    w.replay_equal().await;
}

/// Design fixture 48, second half. The five generic barriers are exercised
/// with this type beside the two registration types in
/// `slots_tests::generic_public_import_and_projector_seams_refuse_slot_events`.
/// Here: the generic type is still refused on the slot route, and the fold
/// refuses to project a row that does not match the log.
#[tokio::test]
async fn slot_route_and_logged_match_hold_for_the_new_type() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    w.refused(
        AppendSpec {
            record_id: Uuid::new_v4().to_string(),
            event_type: KERNEL_HOME_CREATED_EVENT.into(),
            payload: json!({"parent_id": fx.p0, "owner_id": w.other, "entries": []}),
            actor: Some(w.admin.clone()),
        },
        "kernel slot admission requires a slot event",
    )
    .await;

    let event = fx.provision(&w.other).await.unwrap();
    let before = w.state().await;
    for forged in [
        EventRow {
            payload: Some(
                json!({"parent_id": fx.p0, "owner_id": w.admin, "slot": HOME_FOCI_PRIVATE})
                    .to_string(),
            ),
            ..event.clone()
        },
        EventRow {
            actor: Some(w.admin.clone()),
            ..event.clone()
        },
        EventRow {
            record_id: Uuid::new_v4().to_string(),
            ..event.clone()
        },
    ] {
        let mut tx = w.db.write_pool().begin().await.unwrap();
        engine_error(
            crate::projector::project(&mut tx, &forged).await,
            "slot projection requires the kernel-issued logged event",
        );
        tx.rollback().await.unwrap();
    }
    assert_eq!(before, w.state().await);
}

/// A fresh account that has no slot yet.
async fn beneficiary(w: &World) -> String {
    create_principal(
        &w.db,
        "account",
        "Fresh",
        &format!("acct:{}", Uuid::new_v4()),
        &w.admin,
    )
    .await
    .unwrap()
}

/// Design fixture 50: G7's created-here check accepts a `home_created_for`
/// home from this transaction and still refuses everything else.
#[tokio::test]
async fn created_here_check_accepts_only_this_transactions_homes() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    let not_here = "provisioned home was not created in this transaction";

    // The sealed route's home, end to end: created and registered in one act,
    // and the beneficiary's slot is healthy.
    let p = beneficiary(w).await;
    let max_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let got = ensure_home(&w.db, &SealedProvisioner::honest(&fx.cfg), &p, "test")
        .await
        .unwrap();
    let home = got.target_id.clone().unwrap();
    // All nine receipt fields (review a784fdc note 2), not a three-field tuple.
    assert_receipt(&got, &ready(SlotOutcome::Created, &home, true));
    let rows: Vec<(String, i64, Option<String>)> =
        sqlx::query_as("SELECT type, act, actor FROM content_events WHERE seq > ? ORDER BY seq")
            .bind(max_seq)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        [HOME_CREATED_FOR, slots::PROVISIONED]
    );
    assert_eq!(rows[0].1, rows[1].1, "one transaction, one act");
    assert_eq!(rows[0].2.as_deref(), Some(fx.svc.as_str()));
    assert_eq!(rows[1].2.as_deref(), Some(p.as_str()));
    w.replay_equal().await;

    // A second beneficiary: replace goes through the sealed route too.
    let q = beneficiary(w).await;
    let first = ensure_home(&w.db, &SealedProvisioner::honest(&fx.cfg), &q, "test")
        .await
        .unwrap()
        .target_id
        .unwrap();
    replace_home_policy(&w.db, &q, &first, &[(&q, "manage"), (&w.admin, "view")])
        .await
        .unwrap();
    let replaced = replace_home(
        &w.db,
        &SealedProvisioner::honest(&fx.cfg),
        &q,
        &first,
        "test",
    )
    .await
    .unwrap();
    assert_ne!(replaced.target_id.as_deref(), Some(first.as_str()));
    assert_receipt(
        &replaced,
        &ready(
            SlotOutcome::Replaced,
            replaced.target_id.as_deref().unwrap(),
            true,
        ),
    );

    // Errors with zero writes: a sealed home from an earlier transaction, and
    // a record id.
    let record_home = w.home(&w.other).await;
    let record = w.record_in(&w.other, &record_home).await;
    for id in [home.clone(), record] {
        let r = beneficiary(w).await;
        let before = w.state().await;
        let err = ensure_home(
            &w.db,
            &TestProvisioner::new(&w.admin, Mode::Returns(id)),
            &r,
            "test",
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), not_here);
        assert_eq!(before, w.state().await);
    }

    // A generic-type home created in this transaction is accepted.
    let s = beneficiary(w).await;
    let got = ensure_home(
        &w.db,
        &TestProvisioner::new(&w.admin, Mode::Honest),
        &s,
        "test",
    )
    .await
    .unwrap();
    assert_receipt(
        &got,
        &ready(
            SlotOutcome::Created,
            got.target_id.as_deref().unwrap(),
            true,
        ),
    );

    // Same-act sealed homes that break the structure are refused by G7's
    // registration check, with rollback: the wrong owner, and an extra entry.
    let t = beneficiary(w).await;
    let someone = beneficiary(w).await;
    for (provisioner, reason) in [
        (
            SealedProvisioner {
                owner: Some(someone),
                ..SealedProvisioner::honest(&fx.cfg)
            },
            "forbidden",
        ),
        (
            SealedProvisioner {
                extra_entry: Some(w.admin.clone()),
                ..SealedProvisioner::honest(&fx.cfg)
            },
            "not_private",
        ),
    ] {
        let before = w.state().await;
        let err = ensure_home(&w.db, &provisioner, &t, "test")
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("slot target is not valid for the slot: {reason}")
        );
        assert_eq!(before, w.state().await);
    }
}

/// `validate_on` rejects a misconfiguration as an error, never as
/// `Unavailable`, and writes nothing.
#[tokio::test]
async fn a_broken_configuration_is_an_error() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    let account = w.other.clone();
    let record_home = w.home(&w.other).await;
    let record = w.record_in(&w.other, &record_home).await;
    let s2 = fx.agent("Second service").await;
    let unmanaged = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    for (service, parent, message) in [
        (
            &fx.svc,
            KERNEL_ROOT_ID,
            "designated parent must not be the workspace root",
        ),
        (
            &fx.svc,
            &Uuid::new_v4().to_string(),
            "designated parent is not a home",
        ),
        (&fx.svc, &record, "designated parent is not a home"),
        (&account, &fx.p0, "provisioning service is not an agent"),
        (
            &Uuid::new_v4().to_string(),
            &fx.p0,
            "provisioning service is not an agent",
        ),
        (
            &s2,
            &fx.p0,
            "provisioning service lacks Manage on the designated parent",
        ),
        (
            &fx.svc,
            &unmanaged,
            "provisioning service lacks Manage on the designated parent",
        ),
    ] {
        let cfg = slots::ProvisionerConfig {
            service: service.to_string(),
            parent: parent.to_string(),
        };
        let p = beneficiary(w).await;
        let before = w.state().await;
        let err = ensure_home(&w.db, &SealedProvisioner::honest(&cfg), &p, "test")
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), message, "{service} / {parent}");
        assert_eq!(before, w.state().await);
    }
    // Revoking the service's Manage after setup is an error on the next call.
    replace_home_policy(&w.db, &w.admin, &fx.p0, &[])
        .await
        .unwrap();
    let p = beneficiary(w).await;
    let err = ensure_home(&w.db, &SealedProvisioner::honest(&fx.cfg), &p, "test")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "provisioning service lacks Manage on the designated parent"
    );
}

/// Insert a row in the log by direct SQL, as a raw importer would leave it,
/// and fold it without admission. Rolls back.
async fn fold_unadmitted(w: &World, spec: AppendSpec) -> Result<()> {
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let id = Uuid::new_v4().to_string();
    let payload = spec.payload.to_string();
    let created_at = "2026-10-14T00:00:00.000Z".to_string();
    sqlx::query("INSERT INTO content_events (id, record_id, type, payload, actor, causal_envelope_version, causal_status, created_at) VALUES (?, ?, ?, ?, ?, 1, 'legacy_unknown', ?)")
        .bind(&id).bind(&spec.record_id).bind(&spec.event_type).bind(&payload).bind(&spec.actor).bind(&created_at)
        .execute(&mut *tx).await.unwrap();
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id=?")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let event = EventRow {
        local_seq: seq,
        id,
        record_id: spec.record_id,
        event_type: spec.event_type,
        payload: Some(payload),
        actor: spec.actor,
        created_at,
        run_key: None,
        parent_key: None,
        intent: None,
        act: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let result = slots::project(&mut tx, &event).await;
    tx.rollback().await.unwrap();
    result
}

/// Design fixture 74: admission is capability-based, not configuration-based;
/// the fold repeats the config-independent rules but checks no capability;
/// and the appender takes actor and parent only from the validated config.
#[tokio::test]
async fn config_boundary_and_fold() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    // (a) An agent with Manage on a different non-root parent passes
    // admission: it documents what admission does not enforce.
    let s2 = fx.agent("Second service").await;
    let p1 = create_home(&w.db, KERNEL_ROOT_ID, Some(&[(&s2, "manage")]), &w.admin)
        .await
        .unwrap();
    let accepted = w
        .append_raw(home_for(&s2, &p1, &w.other, HOME_FOCI_PRIVATE))
        .await
        .unwrap();
    assert_eq!(accepted.actor.as_deref(), Some(s2.as_str()));

    // (b) The fold, run directly on events admission never saw.
    for (spec, message) in [
        (
            home_for(&w.admin, &fx.p0, &w.other, HOME_FOCI_PRIVATE),
            "home creation actor must be an agent",
        ),
        (
            home_for(&fx.svc, KERNEL_ROOT_ID, &w.other, HOME_FOCI_PRIVATE),
            "home creation parent must not be the root",
        ),
        (
            home_for(&fx.svc, &fx.p0, &fx.svc, HOME_FOCI_PRIVATE),
            "home owner must not be the creating actor",
        ),
        (
            home_for(&fx.svc, &fx.p0, &s2, HOME_FOCI_PRIVATE),
            "home owner must be an account",
        ),
    ] {
        engine_error(fold_unadmitted(w, spec).await, message);
    }
    // Control: the fold checks no capability. An agent with no Manage on the
    // parent folds, because that was admission's call and may have changed.
    let s3 = fx.agent("Unprivileged").await;
    fold_unadmitted(w, home_for(&s3, &fx.p0, &w.other, HOME_FOCI_PRIVATE))
        .await
        .unwrap();

    // (c) A configured provisioning never uses S2 or P1.
    let event = fx.provision(&w.other).await.unwrap();
    assert_eq!(event.actor.as_deref(), Some(fx.svc.as_str()));
    let payload: Value = serde_json::from_str(event.payload.as_deref().unwrap()).unwrap();
    assert_eq!(payload["parent_id"], json!(fx.p0));
    assert_ne!(payload["parent_id"], json!(p1));
    w.replay_equal().await;
}
