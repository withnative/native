//! Router-accepted, handle-bound personal observations. No raw authority leaves
//! this capability. Catalog/session authentication remains a fresh host duty.
use super::{personal_registry, personal_registry_test_support as test_support, RealtimeHub};
use crate::{db::Db, identity::hosted::HostedMembershipArrival, Error, Result};
use std::sync::{atomic::Ordering, Arc, Mutex};
use test_support::{
    BaselineSnapshot, PersonalAlphaRegistryReadTestPoint as ReadPoint,
    PersonalAlphaRegistryStageTestPoint as StagePoint,
};

pub(super) struct Incarnation;
pub(super) enum CurrentDbSlot {
    Provisional(Db),
    Accepted {
        db: Db,
        incarnation: Arc<Incarnation>,
    },
    Retired,
}
impl CurrentDbSlot {
    pub(super) fn db(&self) -> Option<&Db> {
        match self {
            Self::Provisional(db) | Self::Accepted { db, .. } => Some(db),
            Self::Retired => None,
        }
    }
}
impl std::fmt::Debug for CurrentDbSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Provisional(_) => "Provisional",
            Self::Accepted { .. } => "Accepted",
            Self::Retired => "Retired",
        })
    }
}

struct ScopeTag;
#[derive(Default)]
struct Baseline {
    initial_staged: bool,
    fingerprint: Option<personal_registry::PersonalAlphaRegistryFingerprint>,
}

/// Server-observed live catalog identity inputs. This is an internal Rust
/// boundary, never request parameters or an alternative authentication API.
pub struct PersonalAlphaRegistryIdentity<'a> {
    pub email: &'a str,
    pub catalog_user_id: &'a str,
    pub arrival: &'a HostedMembershipArrival,
    pub public_principal: Option<&'a str>,
}

/// Complete observation or privately Unknown after a projection probe error.
/// Only the bound scope can produce it; no Debug/serde/digest accessor.
pub struct PersonalAlphaRegistryObservation {
    scope: Arc<ScopeTag>,
    fingerprint: Option<personal_registry::PersonalAlphaRegistryFingerprint>,
}

/// Owned prompt staged with its baseline under the accepted-slot guard.
/// Transport can lose it; reconnect must force a new authoritative list.
pub struct PersonalAlphaRegistryPrompt(());
impl PersonalAlphaRegistryPrompt {
    pub fn event_name(&self) -> &'static str {
        "alpha-registry"
    }
    pub fn data(&self) -> &'static str {
        r#"{"version":"native.alpha-registry-invalidation.v1"}"#
    }
}

/// A stream-lifetime capability: no Db/pool/executor or raw marker accessor,
/// no account rebinding. Both observation and read-only identity use this Db.
pub struct PersonalAlphaRegistryScope {
    db: Db,
    hub: Arc<RealtimeHub>,
    incarnation: Arc<Incarnation>,
    account: String,
    tag: Arc<ScopeTag>,
    baseline: Mutex<Baseline>,
}
fn refused() -> Error {
    Error::engine("personal alpha registry scope refused")
}

impl RealtimeHub {
    /// Bind only the already-connected router-accepted handle. Attach's staged
    /// pool and a matching portable ID alone never grant this capability.
    pub fn bind_personal_alpha_registry(
        self: &Arc<Self>,
        stream_db: &Db,
        trusted_account: &str,
    ) -> Result<PersonalAlphaRegistryScope> {
        if trusted_account.trim().is_empty()
            || !stream_db
                .realtime_hub()
                .is_some_and(|hub| Arc::ptr_eq(&hub, self))
        {
            return Err(refused());
        }
        let slot = self
            .current_db
            .read()
            .expect("realtime current db poisoned");
        let CurrentDbSlot::Accepted { db, incarnation } = &*slot else {
            return Err(refused());
        };
        if self.terminal.load(Ordering::SeqCst)
            || db.handle_id() != stream_db.handle_id()
            || db.pool().is_closed()
            || db.write_pool().is_closed()
        {
            return Err(refused());
        }
        Ok(PersonalAlphaRegistryScope {
            db: db.clone(),
            hub: self.clone(),
            incarnation: incarnation.clone(),
            account: trusted_account.into(),
            tag: Arc::new(ScopeTag),
            baseline: Mutex::new(Baseline::default()),
        })
    }
}

impl PersonalAlphaRegistryScope {
    fn matches(&self, slot: &CurrentDbSlot) -> bool {
        !self.hub.terminal.load(Ordering::SeqCst)
            && !self.db.pool().is_closed()
            && !self.db.write_pool().is_closed()
            && matches!(slot, CurrentDbSlot::Accepted { db, incarnation } if db.handle_id() == self.db.handle_id() && Arc::ptr_eq(incarnation, &self.incarnation))
    }
    /// Liveness only. Publication must use the guarded staging operation.
    pub fn check_current(&self) -> Result<()> {
        let slot = self
            .hub
            .current_db
            .read()
            .expect("realtime current db poisoned");
        if self.matches(&slot) {
            Ok(())
        } else {
            Err(refused())
        }
    }

    /// Fresh host authentication must precede this call for each initial,
    /// control, lag and lease observation. Missing/moved canonical identity
    /// refuses without any writer/provisioning. A projection error is Unknown,
    /// never empty/unchanged. Replacement discards even an Unknown result.
    pub async fn observe(
        &self,
        identity: PersonalAlphaRegistryIdentity<'_>,
    ) -> Result<PersonalAlphaRegistryObservation> {
        self.check_current()?;
        let portable = crate::identity::database_id(&self.db).await;
        self.check_current()?;
        if portable.map_err(|_| refused())? != self.hub.database_id {
            return Err(refused());
        }
        let fingerprint = test_support::read(
            ReadPoint::Projection,
            personal_registry::probe_checked(&self.db, &self.account, || self.check_current()),
        )
        .await
        .ok();
        self.check_current()?;
        self.check_account_identity_read_only(identity, ReadPoint::IdentityObservation)
            .await?;
        Ok(PersonalAlphaRegistryObservation {
            scope: self.tag.clone(),
            fingerprint,
        })
    }

    /// Fresh final canonical identity observation after the host's FINAL live
    /// catalog context. Uses only this captured accepted Db, never repairs or
    /// returns an account. Host must stage immediately after this completes,
    /// with no intervening await; staging still guards the accepted pair.
    pub async fn recheck_identity_read_only(
        &self,
        identity: PersonalAlphaRegistryIdentity<'_>,
    ) -> Result<()> {
        self.check_current()?;
        let portable = crate::identity::database_id(&self.db).await;
        self.check_current()?;
        if portable.map_err(|_| refused())? != self.hub.database_id {
            return Err(refused());
        }
        self.check_account_identity_read_only(identity, ReadPoint::FinalIdentity)
            .await
    }

    async fn check_account_identity_read_only(
        &self,
        identity: PersonalAlphaRegistryIdentity<'_>,
        point: ReadPoint,
    ) -> Result<()> {
        self.check_current()?;
        let account = test_support::read(
            point,
            crate::identity::hosted::reconciled_hosted_identity_read_only(
                &self.db,
                identity.email,
                identity.catalog_user_id,
                identity.arrival,
                identity.public_principal,
            ),
        )
        .await;
        self.check_current()?;
        if account.map_err(|_| refused())?.as_deref() != Some(self.account.as_str()) {
            return Err(refused());
        }
        Ok(())
    }

    /// Synchronous local publication point: verify accepted incarnation, stage
    /// an owned version-only prompt AND decide baseline together under one slot
    /// read guard. No await/yield/backpressure under the guard. Host must perform
    /// fresh live auth fencing before invoking this, never reuse old proofs.
    pub fn stage_initial(
        &self,
        observation: PersonalAlphaRegistryObservation,
    ) -> Result<Option<PersonalAlphaRegistryPrompt>> {
        self.stage(observation, true)
    }
    pub fn stage_update(
        &self,
        observation: PersonalAlphaRegistryObservation,
    ) -> Result<Option<PersonalAlphaRegistryPrompt>> {
        self.stage(observation, false)
    }
    fn stage(
        &self,
        observation: PersonalAlphaRegistryObservation,
        initial: bool,
    ) -> Result<Option<PersonalAlphaRegistryPrompt>> {
        let controls = test_support::current();
        let before = controls
            .as_ref()
            .map(|_| self.baseline_snapshot_for_tests());
        if let Some(controls) = &controls {
            controls.stage_checkpoint(StagePoint::BeforeLock, initial);
        }
        let slot = self
            .hub
            .current_db
            .read()
            .expect("realtime current db poisoned");
        if !self.matches(&slot) || !Arc::ptr_eq(&self.tag, &observation.scope) {
            if let (Some(controls), Some(before)) = (&controls, before) {
                controls.record_stage(before, self.baseline_snapshot_for_tests(), true);
            }
            return Err(refused());
        }
        if let Some(controls) = &controls {
            controls.stage_checkpoint(StagePoint::HoldingLock, initial);
        }
        let mut baseline = self
            .baseline
            .lock()
            .expect("personal registry baseline poisoned");
        let level = initial && !baseline.initial_staged;
        let changed = observation
            .fingerprint
            .as_ref()
            .is_some_and(|value| baseline.fingerprint.as_ref() != Some(value));
        let result = if level || changed {
            let prompt = PersonalAlphaRegistryPrompt(());
            if observation.fingerprint.is_some() {
                baseline.fingerprint = observation.fingerprint;
            }
            baseline.initial_staged = true;
            Ok(Some(prompt))
        } else {
            // Failed probes retain Unknown or the last known baseline. No
            // acknowledgement of changed state without staging its prompt.
            Ok(None)
        };
        if let (Some(controls), Some(before)) = (&controls, before) {
            controls.record_stage(
                before,
                BaselineSnapshot {
                    initial: baseline.initial_staged,
                    fingerprint: baseline.fingerprint.clone(),
                },
                false,
            );
        }
        result
    }
    fn baseline_snapshot_for_tests(&self) -> BaselineSnapshot {
        let baseline = self
            .baseline
            .lock()
            .expect("personal registry baseline poisoned");
        BaselineSnapshot {
            initial: baseline.initial_staged,
            fingerprint: baseline.fingerprint.clone(),
        }
    }
}

#[cfg(test)]
#[path = "personal_scope_tests.rs"]
mod tests;
