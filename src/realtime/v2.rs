//! W7's declared app-data evaluator plugs into the kernel freshness hub here.
//! Transport never interprets declarations or treats an app id as authority.
use super::*;
use crate::mcp::Caller;
use crate::need_subscriptions::{ConnectionToken, GateSnapshot, NeedClosedReason, SubscriptionId};
use futures::future::BoxFuture;
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct AppDataRequest {
    pub package: String,
    pub expected_install_event_id: String,
    /// None requests the consented snapshot; Some requests one declared need.
    pub need: Option<String>,
    pub params: Value,
}

/// Authority held at subscription admission, never refreshed in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppDataGate {
    pub principal: String,
    pub consent_status: String,
    pub executable: bool,
    pub revocation_epoch: u64,
    pub install_generation: u64,
    pub surface: GateSnapshot,
}

#[derive(Debug)]
pub struct AppDataEvaluation {
    /// The ordinary v1-shaped live_read result, including its revision pointer.
    pub result: Value,
    pub gate: AppDataGate,
    pub time_dependent: bool,
}

/// W7 implements both methods using kernel-owned state and ordinary reads.
/// EVERY call must check membership via account_admitted_before against the
/// current roster, consent status/executable/revocation epoch and install
/// generation, source View and visibility of all returned data. A cached
/// caller or earlier evaluation is never authority. Errors close subscriptions.
pub trait AppDataNeeds: Send + Sync + std::fmt::Debug {
    fn evaluate<'a>(
        &'a self,
        db: &'a Db,
        caller: &'a Caller,
        request: &'a AppDataRequest,
    ) -> BoxFuture<'a, crate::Result<AppDataEvaluation>>;

    fn revalidate<'a>(
        &'a self,
        db: &'a Db,
        caller: &'a Caller,
        request: &'a AppDataRequest,
    ) -> BoxFuture<'a, crate::Result<AppDataGate>>;
}

/// Read-only H3 fence for transports between full host admissions.
#[doc(hidden)]
pub async fn admitted_caller(db: &Db, caller: &Caller) -> crate::Result<String> {
    crate::mcp::kernel_v2::principal(db, caller).await
}

impl RealtimeHub {
    /// Host composition installs W7's evaluator on the retained hub. Absence
    /// must leave app.subscribe.v2 unadvertised; it is never an empty success.
    pub fn set_app_data_needs(&self, evaluator: Arc<dyn AppDataNeeds>) {
        *self.app_data_needs.write().expect("app evaluator poisoned") = Some(evaluator);
    }

    pub fn has_app_data_needs(&self) -> bool {
        self.app_data_needs
            .read()
            .expect("app evaluator poisoned")
            .is_some()
    }

    fn app_data_needs(&self) -> crate::Result<Arc<dyn AppDataNeeds>> {
        self.app_data_needs
            .read()
            .expect("app evaluator poisoned")
            .clone()
            .ok_or_else(|| crate::Error::engine("v2 app data refused [evaluator_unavailable]"))
    }

    /// Every evaluation and emit gate resolves live H3 admission. The SSE
    /// connection's host access hook independently revalidates catalog custody.
    pub async fn evaluate_app_data(
        &self,
        caller: &Caller,
        request: &AppDataRequest,
    ) -> crate::Result<AppDataEvaluation> {
        let evaluator = self.app_data_needs()?;
        let db = self
            .current_db()
            .ok_or_else(|| crate::Error::engine("realtime database handle unavailable"))?;
        let principal = admitted_caller(&db, caller).await?;
        let evaluated = evaluator.evaluate(&db, caller, request).await?;
        if evaluated.gate.principal != principal || !evaluated.gate.executable {
            return Err(crate::Error::engine(
                "v2 app data refused [principal_or_consent]",
            ));
        }
        Ok(evaluated)
    }

    pub async fn revalidate_app_data(
        &self,
        caller: &Caller,
        request: &AppDataRequest,
    ) -> crate::Result<AppDataGate> {
        let evaluator = self.app_data_needs()?;
        let db = self
            .current_db()
            .ok_or_else(|| crate::Error::engine("realtime database handle unavailable"))?;
        let principal = admitted_caller(&db, caller).await?;
        let gate = evaluator.revalidate(&db, caller, request).await?;
        if gate.principal != principal || !gate.executable {
            return Err(crate::Error::engine(
                "v2 app data refused [principal_or_consent]",
            ));
        }
        Ok(gate)
    }
    /// W7 calls this after registering a pending subscription and BEFORE
    /// activation, using the returned evaluation as its baseline. Missing pins
    /// refuse at emission; the evaluated baseline and admission pin must agree.
    pub async fn admit_app_data_subscription(
        &self,
        caller: &Caller,
        token: &ConnectionToken,
        id: &SubscriptionId,
        request: &AppDataRequest,
    ) -> crate::Result<AppDataEvaluation> {
        let evaluated = self.evaluate_app_data(caller, request).await?;
        let gate = self.revalidate_app_data(caller, request).await?;
        if evaluated.gate != gate {
            return Err(crate::Error::engine(
                "v2 app data refused [admission_gate_changed]",
            ));
        }
        let mut registry = self.need_registry().lock().expect("need registry poisoned");
        if registry
            .connection_footing(token)
            .is_none_or(|(account, member)| account != caller.credential() || !member)
            || !registry.pin_app_data_gate(token, id, request, gate)
        {
            return Err(crate::Error::engine(
                "v2 app data refused [subscription_binding]",
            ));
        }
        Ok(evaluated)
    }

    /// Compare against the immutable admission pin. Also used on lease ticks,
    /// so quiet subscriptions cannot survive a revoked consent or evaluator.
    pub async fn check_app_data_subscription(
        &self,
        caller: &Caller,
        token: &ConnectionToken,
        id: &SubscriptionId,
    ) -> crate::Result<AppDataEvaluation> {
        let state = {
            let registry = self.need_registry().lock().expect("need registry poisoned");
            if registry
                .connection_footing(token)
                .is_none_or(|(account, member)| account != caller.credential() || !member)
            {
                return Err(crate::Error::engine(
                    "v2 app data refused [subscription_binding]",
                ));
            }
            registry
                .subscription_state(token, id)
                .ok_or_else(|| crate::Error::engine("v2 app data refused [subscription_missing]"))?
        };
        let request = AppDataRequest {
            package: state.binding.package,
            expected_install_event_id: state.binding.install_event_id,
            need: None,
            params: serde_json::json!({}),
        };
        let checked = async {
            let held = state.app_data_gate.ok_or_else(|| {
                crate::Error::engine("v2 app data refused [admission_gate_missing]")
            })?;
            let evaluated = self.evaluate_app_data(caller, &request).await?;
            let fresh = self.revalidate_app_data(caller, &request).await?;
            if !fresh.executable
                || !evaluated.gate.executable
                || held != fresh
                || held != evaluated.gate
            {
                return Err(crate::Error::engine(
                    "v2 app data refused [admission_gate_changed]",
                ));
            }
            Ok(evaluated)
        }
        .await;
        if checked.is_err() {
            self.need_registry()
                .lock()
                .expect("need registry poisoned")
                .close_subscription(token, id, NeedClosedReason::AccessLost);
        }
        checked
    }
}
