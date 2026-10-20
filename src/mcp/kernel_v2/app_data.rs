//! W6c's native declared-data seam. The frozen native.app.v2 packages
//! declare no engine needs; kit SQL remains ordinary authenticated query_sql.
use super::*;
use crate::kernel::app_installs::{self as installs, AppSourceAdmission};
use crate::mcp::tools::alpha_tabs::LiveReadSubscribe;
use crate::need_subscriptions::GateSnapshot;
use crate::need_subscriptions::{params_digest, ConnectionToken, SubscriptionId, SurfaceBinding};
use crate::realtime::v2::{AppDataEvaluation, AppDataGate, AppDataNeeds, AppDataRequest};
use crate::realtime::RealtimeHub;
use futures::future::BoxFuture;
use std::sync::Arc;

const SNAPSHOT: &str = "native.app.snapshot.v2";

#[derive(Debug, Default)]
pub struct NativeAppDataNeeds;

fn invalid(code: &str) -> Error {
    Error::engine(format!("manage_alpha_tabs: live read refused [{code}]"))
}

fn validate_request(request: &AppDataRequest, source: &AppSourceAdmission) -> Result<()> {
    let declaration: Value = serde_json::from_str(
        source.pin["consented_declaration"]
            .as_str()
            .ok_or_else(|| invalid("source_declaration_missing"))?,
    )?;
    if declaration["contract"] != "native.app.v2"
        || declaration["needs"]
            .as_array()
            .is_none_or(|needs| !needs.is_empty())
        || declaration["effects"]
            .as_array()
            .is_none_or(|effects| !effects.is_empty())
        || declaration.get("sessions").is_some()
    {
        return Err(invalid("unsupported_declaration_on_v2"));
    }
    if request.need.is_some() {
        return Err(invalid("undeclared_need"));
    }
    if request
        .params
        .as_object()
        .is_none_or(|params| !params.is_empty())
    {
        return Err(invalid("invalid_params"));
    }
    Ok(())
}

fn pin_string(source: &AppSourceAdmission, key: &str) -> Result<String> {
    source.pin[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("source_pin_changed"))
}

fn gate(source: &AppSourceAdmission) -> Result<AppDataGate> {
    Ok(AppDataGate {
        principal: source.principal.clone(),
        // These states are established afresh by admit_data_as, including
        // account_admitted_before, source View and the revocation comparison.
        consent_status: "installed".into(),
        executable: true,
        revocation_epoch: u64::try_from(source.revocation_epoch)
            .map_err(|_| invalid("revocation_epoch_invalid"))?,
        install_generation: u64::try_from(source.install_event_seq)
            .map_err(|_| invalid("install_generation_invalid"))?,
        surface: GateSnapshot {
            install_event_id: source.generation.clone(),
            status: "installed".into(),
            adoption: "shell_adopt.v1".into(),
            declaration_digest: pin_string(source, "declaration_digest")?,
            bundle_sha256: pin_string(source, "bundle_sha256")?,
            source_event_id: pin_string(source, "source_revision")?,
            source_revision: pin_string(source, "source_revision")?,
            runtime: Some("native.html.v1".into()),
        },
    })
}

impl AppDataNeeds for NativeAppDataNeeds {
    fn evaluate<'a>(
        &'a self,
        db: &'a Db,
        caller: &'a Caller,
        request: &'a AppDataRequest,
    ) -> BoxFuture<'a, Result<AppDataEvaluation>> {
        Box::pin(async move {
            let source = installs::admit_data_as(
                db,
                caller,
                &request.package,
                &request.expected_install_event_id,
            )
            .await?;
            validate_request(request, &source)?;
            let gate = gate(&source)?;
            // TODO(first declared need returning data): bind the relevant
            // membership/access epoch into the subscription gate before
            // returning rows. A drop and rejoin entirely between frame checks
            // is presently indistinguishable; this is safe only while rows=[].
            let rows = json!([]);
            let rows_sha256 = crate::canonical_json::digest_json(&rows);
            let pin = json!({"package":source.package,"version":source.version,
                "digest":source.pin["digest"],"artifact_id":source.pin["artifact_id"],
                "source_revision":source.pin["source_revision"],
                "declaration_digest":source.pin["declaration_digest"]});
            let revision_digest = crate::canonical_json::digest_json(&json!({
                "rows":rows,"pin":pin,"install_event_id":source.generation,
                "declared_needs":[],
            }));
            let input = json!({"version":"native.artifact-input.v1","mode":"live",
                "sample_preview":false,"records":[],"records_sha256":rows_sha256,"inputs":{}});
            let input_digest = crate::mcp::tools::alpha_tabs::alpha_tab_sample_input_digest(&input);
            Ok(AppDataEvaluation {
                result: json!({"package":request.package,"install_event_id":source.generation,
                    "pin":pin,"source":{"event_id":source.pin["source_revision"],
                        "bundle_sha256":source.pin["bundle_sha256"],"runtime":"native.html.v1"},
                    "need":SNAPSHOT,"declared_needs":[],"input":input,"input_digest":input_digest,
                    "rows_sha256":rows_sha256,"as_of_ms":null,"time_dependent":false,
                    "revision":{"revision_digest":revision_digest,"rows_sha256":rows_sha256},
                    "window":{"bounded_window":true},"live_reads":true,"effects_wired":false}),
                gate,
                time_dependent: false,
            })
        })
    }

    fn revalidate<'a>(
        &'a self,
        db: &'a Db,
        caller: &'a Caller,
        request: &'a AppDataRequest,
    ) -> BoxFuture<'a, Result<AppDataGate>> {
        Box::pin(async move {
            let source = installs::admit_data_as(
                db,
                caller,
                &request.package,
                &request.expected_install_event_id,
            )
            .await?;
            validate_request(request, &source)?;
            gate(&source)
        })
    }
}

/// Registration and its admission pin belong to W6c's existing registry.
/// Cancellation before the tool response is ready releases both pending and
/// newly active entries; no second subscription authority is introduced.
struct Pending {
    hub: Arc<RealtimeHub>,
    token: ConnectionToken,
    id: SubscriptionId,
    keep: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.keep {
            self.hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .unsubscribe(&self.token, &self.id);
        }
    }
}

fn revision(result: &Value) -> Result<&str> {
    result["revision"]["revision_digest"]
        .as_str()
        .filter(|digest| !digest.is_empty())
        .ok_or_else(|| invalid("revision_missing"))
}

pub(super) async fn live_read(
    db: &Db,
    caller: &Caller,
    request: AppDataRequest,
    subscribe: Option<LiveReadSubscribe>,
    if_revision: Option<String>,
) -> Result<Value> {
    let hub = RealtimeHub::for_database(db)
        .filter(|hub| hub.has_app_data_needs())
        .ok_or_else(|| invalid("evaluator_unavailable"))?;
    let mut pending = None;
    let mut refused = None;
    if let Some(subscribe) = subscribe {
        if let Some(token) = ConnectionToken::from_hex(subscribe.stream.trim()) {
            let registered = hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .subscribe_pending(
                    &token,
                    caller.credential(),
                    hub.database_identity(),
                    SurfaceBinding::alpha_tab(&request.package, &request.expected_install_event_id),
                    SNAPSHOT,
                    &params_digest(Some(&request.params)),
                );
            match registered {
                Ok(id) => {
                    pending = Some(Pending {
                        hub: hub.clone(),
                        token,
                        id,
                        keep: false,
                    })
                }
                Err(reason) => refused = Some(reason.as_code().to_owned()),
            }
        } else {
            refused = Some("stream_unknown".into());
        }
    }
    let mut evaluated = if let Some(pending) = &pending {
        hub.admit_app_data_subscription(caller, &pending.token, &pending.id, &request)
            .await?
    } else {
        let evaluated = hub.evaluate_app_data(caller, &request).await?;
        if evaluated.gate != hub.revalidate_app_data(caller, &request).await? {
            return Err(invalid("admission_gate_changed"));
        }
        evaluated
    };
    let mut subscription = None;
    if let Some(pending) = &mut pending {
        let dirty = {
            let mut registry = hub.need_registry().lock().expect("need registry poisoned");
            let activated = registry.activate_with_probe_safety(
                &pending.token,
                &pending.id,
                revision(&evaluated.result)?,
                evaluated.time_dependent,
                None,
                false,
            );
            if activated == Some(true) {
                registry.clear_dirty_for_catchup(&pending.token, &pending.id);
            }
            activated
        };
        match dirty {
            Some(dirty) => {
                if dirty {
                    // The hub compares to the immutable admission pin; a
                    // changed gate closes rather than refreshing that pin.
                    evaluated = hub
                        .check_app_data_subscription(caller, &pending.token, &pending.id)
                        .await?;
                    let still_active = hub
                        .need_registry()
                        .lock()
                        .expect("need registry poisoned")
                        .activate_with_probe_safety(
                            &pending.token,
                            &pending.id,
                            revision(&evaluated.result)?,
                            evaluated.time_dependent,
                            None,
                            false,
                        );
                    if still_active.is_none() {
                        return Err(invalid("stream_unknown"));
                    }
                    let mut registry = hub.need_registry().lock().expect("need registry poisoned");
                    if still_active == Some(true) {
                        // A write during the immediate rerun belongs to the
                        // scheduler; the rerun cannot consume that wake.
                        registry.enqueue_dirty_with_trigger(
                            &pending.token,
                            &pending.id,
                            true,
                            crate::need_metrics::Trigger::Subscribe,
                        );
                    }
                    registry.finish_catchup(&pending.token, &pending.id);
                }
                subscription = Some(json!({"id":pending.id.as_str(),
                    "time_dependent":evaluated.time_dependent}));
            }
            None => refused = Some("stream_unknown".into()),
        }
    }
    let mut result = if if_revision
        .as_deref()
        .is_some_and(|held| evaluated.result["revision"]["revision_digest"].as_str() == Some(held))
    {
        json!({"package":evaluated.result["package"],
            "install_event_id":evaluated.result["install_event_id"],
            "pin":evaluated.result["pin"],"revision":evaluated.result["revision"],
            "unchanged":true})
    } else {
        evaluated.result
    };
    if let Some(subscription) = subscription {
        result["subscription"] = subscription;
        if let Some(pending) = &mut pending {
            pending.keep = true;
        }
    }
    if let Some(refused) = refused {
        result["subscribe_refused"] = json!(refused);
    }
    Ok(result)
}

pub(super) fn unsubscribe(db: &Db, caller: &Caller, stream: &str, subscription: &str) -> Value {
    if let (Some(hub), Some(token)) = (
        RealtimeHub::for_database(db),
        ConnectionToken::from_hex(stream.trim()),
    ) {
        let mut registry = hub.need_registry().lock().expect("need registry poisoned");
        if registry
            .connection_footing(&token)
            .is_some_and(|(account, _)| account == caller.credential())
        {
            registry.unsubscribe(&token, &SubscriptionId::from_wire(subscription));
        }
    }
    json!({"subscription":subscription,"unsubscribed":true})
}
