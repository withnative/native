//! Off-default installed first-party record bridge. One verified workspace,
//! one original custody journal and one private W with native Get/discovery.
use super::*;
use crate::fork::working_v2::{
    manager::{MaterializationWait, WorkingControl, WorkingManager},
    BindingControl, OwnerPinnedBase, VerifiedCloseReason, WorkingBinding,
};
use crate::node::journal::CustodyBinding;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex as StdMutex,
};

enum AdmissionOutcome {
    Canonical(String),
    Published(
        Box<crate::fork::working_v2::manager::WorkingAck>,
        String,
        Arc<WriteGate>,
    ),
    Unresolved(Error),
}
enum WorkingPreparation {
    Existing,
    Create(
        crate::mcp::kernel_v2::writes::replay::FirstPartyCreateContext,
        Value,
    ),
    CurrentRead(Value),
}
struct Active {
    manager: WorkingManager,
    control: WorkingControl,
    close: BindingControl,
    caller: crate::mcp::Caller,
    base_lease: crate::mcp::standby_stdio::WorkingBaseLease,
    binding: CustodyBinding,
    gate: Arc<WriteGate>,
}
#[derive(Default)]
struct Enrollment {
    active: Option<Arc<Active>>,
    completed: u64,
    materializing: bool,
    wait: Option<MaterializationWait>,
}
impl Enrollment {
    fn seal(&mut self, control: &WorkingControl, completed_before: u64) {
        if self.completed != completed_before || self.completed == u64::MAX {
            control.requires_undo();
        } else if self.materializing {
            self.wait = control.awaiting_materialization();
        }
    }
}
#[derive(Default)]
struct State {
    active: StdMutex<Enrollment>,
    preparing: Arc<Mutex<()>>,
    paused: AtomicBool,
    recovery_started: AtomicBool,
}
#[derive(Clone, Default)]
pub(super) struct WorkingCopies(Arc<State>);
impl WorkingCopies {
    #[cfg(test)]
    pub(super) fn acknowledgements_paused(&self) -> bool {
        self.0.paused.load(Ordering::Acquire)
    }
    fn active(&self) -> Option<Arc<Active>> {
        self.0
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active
            .clone()
    }
    pub(super) fn close_account_switch(&self) {
        self.0.paused.store(true, Ordering::Release);
        if let Some(active) = self.active() {
            active.close.close(VerifiedCloseReason::AccountSwitch);
        }
    }
    pub(super) fn observe(&self, hints: &RefreshHints) {
        hints.observe_accepted_kernel_deltas(Arc::new(Observer(self.clone())));
    }
}
struct Observer(WorkingCopies);
impl crate::standby::AcceptedKernelDeltaObserver for Observer {
    fn begin(&self) {
        let mut slot = self.0 .0.active.lock().unwrap_or_else(|e| e.into_inner());
        slot.materializing = true;
        if let Some(active) = &slot.active {
            slot.wait = active.control.awaiting_materialization();
        }
    }
    fn no_publication(&self) {
        let mut slot = self.0 .0.active.lock().unwrap_or_else(|e| e.into_inner());
        slot.materializing = false;
        let wait = slot.wait.take();
        if let (Some(active), Some(wait)) = (&slot.active, wait) {
            active.control.no_publication(wait);
        }
    }
    fn finish(&self) {
        let mut slot = self.0 .0.active.lock().unwrap_or_else(|e| e.into_inner());
        slot.wait = None;
        slot.materializing = false;
        slot.completed = slot.completed.saturating_add(1);
        if let Some(active) = &slot.active {
            active.control.requires_undo();
        }
    }
    fn committed(&self, accepted: crate::standby::AcceptedKernelDelta) {
        let mut slot = self.0 .0.active.lock().unwrap_or_else(|e| e.into_inner());
        slot.wait = None;
        slot.materializing = false;
        slot.completed = slot.completed.saturating_add(1);
        if let Some(active) = &slot.active {
            active.control.accepted_kernel(accepted);
        }
        // No W exists yet: completion is remembered under the SAME enrollment
        // fence. A constructor spanning this publication cannot ACK its old
        // copied base or invent a replacement witness from a head alone.
    }
}
fn binding(scope: &CustodyBinding) -> WorkingBinding {
    WorkingBinding {
        account_id: scope.account_id.clone(),
        database_id: scope.database_id.clone(),
        origin_database_id: scope.origin_database_id.clone(),
        history_lineage: scope.history_lineage.clone(),
        resource_origin: scope.resource_origin.clone(),
        install_id: scope.install_id.clone(),
    }
}
fn refused(message: &Value, error: impl std::fmt::Display) -> Option<String> {
    frame_error(
        message.get("id"),
        &error.to_string(),
        json!({"outcome":"not_sent", "reason":"working_append_unavailable", "held":false}),
    )
}
fn read_unavailable(message: &Value, error: impl std::fmt::Display) -> Option<String> {
    frame_error(
        message.get("id"),
        &error.to_string(),
        json!({"outcome":"unavailable", "reason":"working_read_unavailable",
            "pending_custody":"unchanged", "accepted_only_fallback":false}),
    )
}
fn reply(message: &Value, value: Value, text: &str) -> Option<String> {
    super::super::tool_reply(
        message.get("id"),
        json!({"content":[{"type":"text","text":text}],"structuredContent":value,"isError":false}),
        crate::mcp::is_modern_request(message),
    )
}
impl Failover {
    /// This route precedes accepted-copy/default/session-floor routing. A
    /// successfully published pending append cannot be hidden by that fallback.
    pub(super) async fn try_working_route(
        &self,
        message: &Value,
        revision: Option<&str>,
        caller: &super::super::Caller,
    ) -> Option<String> {
        if !self.upstream.config.working_note_appends {
            return None;
        }
        let (executor, operation, envelope) = target(message)?;
        let args = envelope
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        // Keep app discovery on its established hosted-only route. An
        // attributed request never initializes or recovers first-party W.
        if executor == "records_read"
            && matches!(operation.as_str(), "search" | "query_record")
            && super::super::app_proof::attributed(message)
        {
            return if self.working.active().is_some() {
                read_unavailable(message, "working discovery is first-party only")
            } else {
                None
            };
        }
        if executor == "records_read"
            && matches!(operation.as_str(), "get_record" | "search" | "query_record")
        {
            if self.state.lock().await.account_unconfirmed {
                return account_unconfirmed_refusal(message);
            }
            if self.state.lock().await.persisted.account_mismatch {
                self.working.close_account_switch();
                return read_unavailable(
                    message,
                    "working account binding closed after a confirmed account change",
                );
            }
            let active = if let Some(active) = self.working.active() {
                active
            } else {
                let scope = match gate::Outage::custody_binding(self).await {
                    Some(scope) => scope,
                    None => {
                        if self
                            .gate
                            .as_ref()
                            .is_some_and(|gate| !gate.retained_working_may_exist())
                        {
                            return None;
                        }
                        return read_unavailable(message, "working recovery binding unavailable; retained pending work cannot be replaced by an accepted-only read");
                    }
                };
                let scoped = match self
                    .gate
                    .as_ref()
                    .ok_or_else(|| Error::engine("working gate unavailable"))
                    .and_then(|gate| gate.scoped_v2_gate(&scope))
                {
                    Ok(scoped) => scoped,
                    Err(error) => return read_unavailable(message, error),
                };
                let target = match scoped.working_retained_target() {
                    Ok(Some(target)) => target,
                    Ok(None) => return None,
                    Err(error) => return read_unavailable(message, error),
                };
                match self
                    .ensure_working_active(
                        &scope,
                        scoped,
                        target.0,
                        target.1,
                        caller,
                        Some(message),
                    )
                    .await
                {
                    Ok(active) => active,
                    Err(error) => return read_unavailable(message, error),
                }
            };
            if operation != "get_record" {
                if super::super::app_proof::attributed(message) {
                    return read_unavailable(message, "working discovery is first-party only");
                }
                return match active
                    .manager
                    .discover(active.caller.clone(), &operation, args)
                    .await
                {
                    Ok((publication, mut value)) => {
                        value["standby_context"] =
                            serde_json::to_value(active.base_lease.context())
                                .unwrap_or(Value::Null);
                        value["node_working"] = json!({"publication":publication,"canonical":"pending_or_reconciling","accepted_base_pinned":true,"awaiting_qualified_undo":self.working.0.paused.load(Ordering::Acquire)||active.manager.awaiting_reconciliation()});
                        reply(message,value,"This discovery result includes this node's pending edits; canonical acceptance and reconciliation are separate.")
                    }
                    Err(error) => read_unavailable(message, error),
                };
            }
            if super::super::app_proof::attributed(message) {
                return read_unavailable(message, "working reads are first-party only");
            }
            return match active
                .manager
                .read_arguments(active.caller.clone(), args.clone())
                .await
            {
                Ok((publication, mut value)) => {
                    value["standby_context"] =
                        serde_json::to_value(active.base_lease.context()).unwrap_or(Value::Null);
                    value["node_working"] = json!({"publication":publication,"canonical":"pending_or_reconciling","accepted_base_pinned":true,"awaiting_qualified_undo":self.working.0.paused.load(Ordering::Acquire)||active.manager.awaiting_reconciliation()});
                    reply(message, value, "This note includes this node's pending edits; canonical acceptance and reconciliation are separate.")
                }
                Err(error) => read_unavailable(message, error),
            };
        }
        if executor == "records_read" && self.working.active().is_some() {
            return read_unavailable(message, "pending working visibility is currently qualified for native Get only; search/list do not include these pending edits");
        }
        if operation == "create_record"
            && !crate::mcp::kernel_v2::writes::replay::first_party_final_create_enabled()
        {
            return None;
        }
        crate::mcp::kernel_v2::writes::replay::RecordOperation::from_catalog(
            &executor, &operation,
        )?;
        if super::super::app_proof::attributed(message) {
            return refused(message, "working append accepts first-party requests only");
        }
        if matches!(super::super::local_route(message), Ok(true)) {
            return refused(message, "explicit local routing does not admit writes");
        }
        if caller.cancel.is_cancelled() {
            return refused(message, "cancelled before working admission");
        }
        let result = self.working_append(message, revision, caller).await;
        match result {
            Ok(AdmissionOutcome::Canonical(reply)) => Some(reply),
            Ok(AdmissionOutcome::Published(ack, key, gate)) => {
                gate.wake_queue();
                reply(message, json!({"outcome":"accepted_pending","id":ack.record_id,"operation":operation,"journal_entry":ack.proposal_id,"idempotency_key":key,"local_visibility":"working_applied","publication":ack.publication,"canonical":"pending"}), "Accepted pending: the edit is visible in this node's working copy and is waiting for canonical acceptance.")
            }
            Ok(AdmissionOutcome::Unresolved(error)) => frame_error(
                message.get("id"),
                &error.to_string(),
                json!({"outcome":"unknown", "may_already_be_applied":true, "reason":"working_append_unresolved", "retry":"same_original_key", "may_have_been_admitted":true}),
            ),
            Err(error) => refused(message, error),
        }
    }
    async fn working_base_for_request(
        &self,
        scope: &CustodyBinding,
        gate: &WriteGate,
        caller: &super::super::Caller,
    ) -> Result<crate::mcp::standby_stdio::WorkingBaseLease> {
        let binding = binding(scope);
        tokio::select! {
            biased;
            _ = caller.cancel.cancelled() => Err(Error::engine("cancelled awaiting initial working serving lease")),
            lease = self.dispatcher.initial_working_base(&binding, gate.working_deadline(caller)) => lease,
        }
    }
    async fn ensure_working_active(
        &self,
        scope: &CustodyBinding,
        scoped: Arc<WriteGate>,
        record: String,
        contract: String,
        caller: &super::super::Caller,
        current_read: Option<&Value>,
    ) -> Result<Arc<Active>> {
        if let Some(active) = self.working.active() {
            if &active.binding != scope {
                return Err(Error::engine("working account namespace changed"));
            }
            return Ok(active);
        }
        let _prepare = self.working.0.preparing.lock().await;
        self.ensure_working_active_locked(
            scope,
            scoped,
            record,
            contract,
            caller,
            current_read.map_or(WorkingPreparation::Existing, |message| {
                WorkingPreparation::CurrentRead(message.clone())
            }),
        )
        .await
    }
    async fn ensure_working_active_locked(
        &self,
        scope: &CustodyBinding,
        scoped: Arc<WriteGate>,
        _record: String,
        contract: String,
        caller: &super::super::Caller,
        preparation: WorkingPreparation,
    ) -> Result<Arc<Active>> {
        let active = if let Some(active) = self.working.active() {
            active
        } else {
            let enrollment_completed = self
                .working
                .0
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .completed;
            let lease = self
                .working_base_for_request(scope, &scoped, caller)
                .await?;
            let source = lease.db();
            let (base, native_caller) = tokio::select! {
                biased;
                _ = caller.cancel.cancelled() => return Err(Error::engine("cancelled verifying current working source")),
                result = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(scoped.working_deadline(caller)),
                    OwnerPinnedBase::from_serving(lease.clone(), binding(scope)),
                ) => result.map_err(|_| Error::engine("request budget expired verifying current working source"))??,
            };
            // This head and the retained owner/audit snapshot are the SAME cut.
            // The immutable checkpoint manifest is not the current in-place head.
            let accepted_act = base.authority_act();
            {
                let state = self.state.lock().await;
                if state.persistence_failed
                    || state
                        .persisted
                        .floor
                        .act
                        .is_some_and(|floor| floor > accepted_act)
                    || state
                        .persisted
                        .floor
                        .lineage
                        .as_ref()
                        .is_some_and(|lineage| lineage != &scope.history_lineage)
                {
                    return Err(Error::engine(
                        "accepted working base does not cover the verified canonical floor",
                    ));
                }
            }
            let mut journal = scoped.working_journal(binding(scope))?;
            if self.upstream.config.working_refusal_drafts {
                journal = journal.with_refusal_drafts()?;
            }
            let retained_location = journal.location()?;
            let retained = {
                let fence = journal.capture().await?;
                if retained_location.is_none() && !fence.view().proposals().is_empty() {
                    return Err(Error::engine(
                        "retained working location missing; full custody retained",
                    ));
                }
                fence.view().proposals().to_vec()
            };
            let mut snapshot = source.pool().begin().await?;
            let actor = crate::mcp::kernel_v2::principal_on(&mut snapshot, &native_caller).await?;
            snapshot.rollback().await?;
            if retained
                .iter()
                .any(|original| original.actor() != actor || original.binding() != &binding(scope))
            {
                return Err(Error::engine("retained working original does not match the current owner/target; originals retained"));
            }
            let retained_create = retained
                .iter()
                .find(|original| original.operation() == "create_record");
            let create = match preparation {
                WorkingPreparation::Create(context, args) => Some((context, args)),
                WorkingPreparation::Existing => None,
                WorkingPreparation::CurrentRead(message) => {
                    if let Some(original) = retained_create {
                        if super::super::app_proof::attributed(&message) {
                            return Err(Error::engine(
                                "retained create recovery is first-party only",
                            ));
                        }
                        let (executor, operation, envelope) = target(&message)
                            .ok_or_else(|| Error::engine("current recovery read missing"))?;
                        if executor != "records_read"
                            || !matches!(
                                operation.as_str(),
                                "get_record" | "search" | "query_record"
                            )
                        {
                            return Err(Error::engine(
                                "retained create needs a genuine current native read",
                            ));
                        }
                        let args = envelope
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({}));
                        let (fresh_caller, annotations) =
                            crate::mcp::registry::working_ingress_context(
                                &source,
                                native_caller.clone(),
                                &envelope,
                            )
                            .await?;
                        // This is the ACTUAL read and its verified current Caller,
                        // never an original create scope reconstructed from disk.
                        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
                            &fresh_caller,
                            &operation,
                            &args,
                            annotations.intent.as_deref(),
                        );
                        let (observed,) = dispatch.scope(async {
                            (crate::mcp::kernel_v2::writes::replay::FirstPartyCreateContext::observe_current_read(&fresh_caller),)
                        }).await;
                        let observed = observed?;
                        if observed.identity() != original.proposal_identity() {
                            return Err(Error::engine("observed execution context differs from retained create; original retained"));
                        }
                        Some((observed, original.arguments().clone()))
                    } else {
                        None
                    }
                }
            };
            if retained_create.is_some() && create.is_none() {
                return Err(Error::engine(
                    "retained create requires current first-party read recovery; original retained",
                ));
            }
            // Retained W is selected before the destructive fresh-copy path.
            // Its original anchor remains immutable; restart admission proves
            // the current accepted cut before private readers are published.
            // A failed attempt can retain an indeterminate original owner
            // graph. Do not start another copy in this process or infer its
            // files unowned merely because the outer manager did not return.
            if self.working.0.recovery_started.swap(true, Ordering::AcqRel) {
                return Err(Error::engine("working recovery already attempted; retained owner/files require process recovery"));
            }
            let area_root = self.upstream.config.socket_directory.join("working-copy");
            use std::os::unix::fs::DirBuilderExt;
            match fs::DirBuilder::new().mode(0o700).create(&area_root) {
                Ok(()) => File::open(&self.upstream.config.socket_directory)?.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            super::super::check_owned(&fs::symlink_metadata(&area_root)?, 0o700)?;
            // Recovery never deletes a previous complete W. An actual
            // process restart acquires the journal owner, but same-process
            // read workers or uncertain graphs must never be inferred dead.
            // Reclamation needs their actual lease proof and remains unwired.
            let area_id = retained_location
                .as_ref()
                .map(|l| l.area.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let generation_root = area_root.join(&area_id);
            let area = if retained_location.is_some() {
                crate::fork::ForkArea::open_retained(
                    &generation_root,
                    &[source.path().to_path_buf()],
                )
            } else {
                fs::DirBuilder::new().mode(0o700).create(&generation_root)?;
                File::open(&area_root)?.sync_all()?;
                crate::fork::ForkArea::new(&generation_root, &[source.path().to_path_buf()])
            }
            .map_err(|error| Error::engine(error.to_string()))?;
            journal = journal.with_location_scope(area_root.clone(), area_id)?;
            let (close, guard) = BindingControl::new();
            let (manager, control) = WorkingManager::open_workspace_shared(
                base,
                native_caller.clone(),
                (area, crate::fork::ForkLimits::default()),
                journal,
                guard,
                (contract.clone(), create.map(|(context, _)| context)),
            )
            .await?;
            let active = Arc::new(Active {
                manager,
                control,
                close,
                caller: native_caller,
                base_lease: lease,
                binding: scope.clone(),
                gate: scoped.clone(),
            });
            let mut slot = self
                .working
                .0
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.working.0.paused.load(Ordering::Acquire) {
                active.close.close(VerifiedCloseReason::AccountSwitch);
                return Err(Error::engine(
                    "working enrollment fenced by a confirmed owner change",
                ));
            }
            slot.seal(&active.control, enrollment_completed);
            slot.active = Some(active.clone());
            drop(slot);
            active.gate.wake_queue();
            active
        };
        Ok(active)
    }
    async fn working_append(
        &self,
        message: &Value,
        revision: Option<&str>,
        caller: &super::super::Caller,
    ) -> Result<AdmissionOutcome> {
        let (executor, operation, envelope) =
            target(message).ok_or_else(|| Error::engine("working operation missing"))?;
        let record_operation =
            crate::mcp::kernel_v2::writes::replay::RecordOperation::from_catalog(
                &executor, &operation,
            )
            .ok_or_else(|| Error::engine("unsupported working record operation"))?;
        let args = envelope
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        // Initialization and the first original admission share the existing
        // preparer. Other reads never take this mutex. The journal fence is
        // released before W copying and never spans canonical HTTP.
        let create_turn = if operation == "create_record" {
            Some(self.working.0.preparing.clone().lock_owned().await)
        } else {
            None
        };
        let scope = gate::Outage::custody_binding(self).await.ok_or_else(|| {
            Error::engine("verified working account/database credential binding unavailable")
        })?;
        let root_gate = self
            .gate
            .as_ref()
            .ok_or_else(|| Error::engine("working custody gate unavailable"))?;
        let scoped = root_gate.scoped_v2_gate(&scope)?;
        if self.upstream.install_key.is_some() {
            let credential = gate::Outage::custody_credential(self)
                .await
                .ok_or_else(|| Error::auth("enrolled journal credential unavailable"))?;
            scoped
                .verify_enrolled_custody(&self.upstream, credential)
                .await?;
        }
        let capture_lease = self
            .working_base_for_request(&scope, &scoped, caller)
            .await?;
        let source = capture_lease.db();
        let (original_caller, original_annotations) =
            crate::mcp::registry::working_ingress_context(
                &source,
                capture_lease.caller(),
                &envelope,
            )
            .await?;
        let (native_tool, native_args) =
            crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()?
                .working_native_arguments(&executor, &operation, &args)?;
        let original_scope = crate::provenance::ProvenanceDispatch::from_caller(
            &original_caller,
            &native_tool,
            &native_args,
            original_annotations.intent.as_deref(),
        );
        let mut snapshot = source.pool().begin().await?;
        let actor = crate::mcp::kernel_v2::principal_on(&mut snapshot, &original_caller).await?;
        // Codec 7 remains the qualified plain-note append adapter. Broader
        // writes use codec 9 without reinterpreting any retained original.
        let append_shape = operation == "update_record"
            && crate::fork::validate_shape_kernel_v2("update_record", &args, 1024 * 1024).is_ok();
        let accepted_note = if append_shape && self.working.active().is_none() {
            let visible = crate::kernel::read_record_on(
                &mut snapshot,
                &actor,
                args["id"].as_str().unwrap_or_default(),
            )
            .await?;
            visible.is_some_and(|record| {
                (record.family.as_deref() == Some(crate::v2_standard::DOCUMENT_FAMILY)
                    && record.kind.as_deref() == Some("note"))
                    || (record.family.as_deref() == Some(crate::v2_standard::v1_compat::FAMILY)
                        && record.fields.get("v1_type").and_then(Value::as_str) == Some("Document")
                        && record.fields.get("v1_kind").and_then(Value::as_str) == Some("note"))
            })
        } else {
            false
        };
        snapshot.rollback().await?;
        let legacy_append = if append_shape {
            if let Some(active) = self.working.active() {
                let (_, value) = active
                    .manager
                    .read(
                        active.caller.clone(),
                        args["id"].as_str().unwrap_or_default(),
                    )
                    .await?;
                value["records"].as_array().is_some_and(|records| {
                    records.len() == 1
                        && records[0]["type"] == "Document"
                        && records[0]["kind"] == "note"
                })
            } else {
                accepted_note
            }
        } else {
            false
        };
        let legacy_create = operation == "create_record"
            && crate::mcp::kernel_v2::writes::replay::validate_first_party_create_source(&args)
                .is_ok();
        let (captured, create_context) = if operation == "create_record" {
            let (original,)=original_scope.scope(crate::store::with_event_annotations(original_annotations,async {
                (if legacy_create { crate::mcp::kernel_v2::writes::replay::CapturedFirstPartyCreate::capture(original_caller,args.clone()) } else { crate::mcp::kernel_v2::writes::replay::CapturedFirstPartyCreate::capture_record(original_caller,args.clone()) },)
            })).await;
            let original = original?;
            let proposal = scoped
                .prepare_working_create(&actor, &original, None)
                .await?;
            let context = original.context().clone();
            (
                if legacy_create {
                    WorkingManager::captured_create(&original, proposal)?
                } else {
                    WorkingManager::captured_record_create(&original, proposal)?
                },
                Some(context),
            )
        } else {
            let (captured,) = original_scope
                .scope(crate::store::with_event_annotations(
                    original_annotations,
                    async {
                        (if legacy_append {
                            WorkingManager::capture_original(original_caller, args.clone())
                        } else {
                            WorkingManager::capture_record_original(
                                original_caller,
                                record_operation,
                                args.clone(),
                            )
                        },)
                    },
                ))
                .await;
            (captured?, None)
        };
        let record = record_operation
            .primary_target(captured.proposal().args())
            .ok_or_else(|| Error::engine("working target missing"))?
            .to_owned();
        let mut prepared = message.clone();
        prepared["params"]["arguments"]["arguments"] = captured.wire_arguments().clone();
        let body = prepared.to_string();
        let contract = scoped
            .working_contract(
                &gate::WriteRequest {
                    body: &body,
                    message: &prepared,
                    revision,
                    caller,
                    outage: Some(self),
                    no_hold: false,
                },
                &captured,
            )
            .await?;
        if let Some(reply) =
            scoped.working_terminal_reply(&actor, captured.proposal(), message.get("id"))?
        {
            return Ok(AdmissionOutcome::Canonical(reply));
        }
        if self.working.0.paused.load(Ordering::Acquire) {
            return Err(Error::engine(
                "AwaitingQualifiedUndo: working view retained; new pending acknowledgements paused",
            ));
        }
        let active = if create_turn.is_some() {
            self.ensure_working_active_locked(
                &scope,
                scoped,
                record.clone(),
                contract.clone(),
                caller,
                create_context.map_or(WorkingPreparation::Existing, |context| {
                    WorkingPreparation::Create(context, captured.proposal().args().clone())
                }),
            )
            .await?
        } else {
            self.ensure_working_active(
                &scope,
                scoped,
                record.clone(),
                contract.clone(),
                caller,
                None,
            )
            .await?
        };
        if active.binding != scope {
            return Err(Error::engine("working account namespace changed"));
        }
        if let Some(act) = self
            .dispatcher
            .serving_context()
            .and_then(|context| context.serving_head_act)
        {
            active.manager.observe_serving_act(act).await;
        }
        if gate::Outage::custody_binding(self).await.as_ref() != Some(&scope) {
            return Err(Error::engine(
                "working credential/account binding changed before admission",
            ));
        }
        let key = args
            .get("idempotency_key")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("working append requires its original idempotency key"))?
            .to_owned();
        // No ambient scope is reconstructed here: only the sealed original
        // captured before async manager preparation enters detached custody.
        let captured = if let Some(turn) = create_turn {
            captured.with_preparation(turn)
        } else {
            captured
        };
        let future = active
            .manager
            .append_original_contract(captured, Some(contract))?;
        let result =
            tokio::time::timeout_at(active.gate.working_deadline(caller).into(), future).await;
        let result=match result {Ok(result)=>result,Err(_)=>Err(Error::engine("working admission still owned; reconciliation deadline reached; retry the same original key"))};
        match result {
            Ok(ack) => Ok(AdmissionOutcome::Published(
                Box::new(ack),
                key,
                active.gate.clone(),
            )),
            Err(error @ Error::Conflict(_)) => Err(error),
            Err(error) => Ok(AdmissionOutcome::Unresolved(error)),
        }
    }
    pub(super) async fn working_published(&self, scope: &CustodyBinding, ordinal: i64) -> bool {
        let Some(active) = self.working.active() else {
            return false;
        };
        active.binding == *scope
            && active
                .manager
                .published_prefix()
                .await
                .is_ok_and(|prefix| prefix >= ordinal)
    }
    pub(super) async fn working_dispatch_exclusions(
        &self,
        scope: &CustodyBinding,
    ) -> Option<Vec<String>> {
        let active = self.working.active()?;
        if active.binding != *scope {
            return None;
        }
        active.manager.dispatch_exclusions().await.ok()
    }
    pub(super) fn working_canonical_changed(&self, scope: &CustodyBinding) {
        if self
            .working
            .active()
            .is_some_and(|active| active.binding == *scope)
        {
            if let Some(active) = self.working.active() {
                active.control.canonical_changed();
            }
        }
    }
}

#[cfg(test)]
pub(super) fn enrollment_before_active_for_test(
    control: &WorkingControl,
    completed: Option<crate::standby::AcceptedKernelDelta>,
) {
    use crate::standby::AcceptedKernelDeltaObserver;
    let copies = WorkingCopies::default();
    let observed = copies.0.active.lock().unwrap().completed;
    let observer = Observer(copies.clone());
    observer.begin();
    if let Some(accepted) = completed {
        observer.committed(accepted);
    }
    copies.0.active.lock().unwrap().seal(control, observed);
}

impl Failover {
    /// Owner-only socket operation. No Caller/actor/key is accepted from the
    /// command: the current actual serving lease resolves the principal.
    pub(in crate::node) async fn owner_original_recovery(
        &self,
        id: &str,
        settle: bool,
    ) -> Result<Value> {
        let scope = gate::Outage::custody_binding(self)
            .await
            .ok_or_else(|| Error::engine("verified recovery account unavailable"))?;
        if self.state.lock().await.account_unconfirmed
            || self.state.lock().await.persisted.account_mismatch
        {
            return Err(Error::engine("recovery owner binding unavailable"));
        }
        let root = self
            .gate
            .as_ref()
            .ok_or_else(|| Error::engine("recovery journal unavailable"))?;
        let scoped = root.scoped_v2_gate(&scope)?;
        let deadline = std::time::Instant::now() + super::super::REQUEST_BUDGET;
        let lease = self
            .dispatcher
            .initial_working_base(&binding(&scope), deadline)
            .await?;
        let db = lease.db();
        let mut read = db.pool().begin().await?;
        let lease_caller = lease.caller();
        let principal = crate::mcp::kernel_v2::principal_on(&mut read, &lease_caller).await?;
        read.rollback().await?;
        let entry = scoped
            .journal
            .get(id)
            .ok_or_else(|| Error::engine("recovery original unavailable"))?;
        let original = crate::node::journal::working_v2::settlement_original(&entry)?;
        if principal != original.principal_id
            || scope.account_id != original.account_id
            || scope.database_id != original.database_id
            || scope.origin_database_id != original.origin_database_id
        {
            return Err(Error::engine("recovery owner differs"));
        }
        let mut existing = None;
        if let Some(active) = self.working.active() {
            if active.binding != scope {
                return Err(Error::engine("recovery working namespace changed"));
            }
            active
                .manager
                .check_recovery_owner(&binding(&scope), &principal)?;
            if self.upstream.config.working_refusal_drafts {
                existing = active.manager.original_disposition(id).await?;
            }
            if settle && existing.is_none() {
                active.control.requires_undo();
            }
        }
        let saved = if settle && existing.is_none() {
            scoped
                .settle_working_original(&self.upstream, self, id, &principal, deadline)
                .await?
        } else {
            entry
        };
        // Recheck after all awaits and before exposing even original metadata.
        if gate::Outage::custody_binding(self).await.as_ref() != Some(&scope) {
            return Err(Error::engine("recovery account changed"));
        }
        let (mut recovered_publication, mut disposition) = existing
            .map_or((None, None), |(publication, kind)| {
                (Some(publication), kind)
            });
        if let Some(active) = self.working.active() {
            active
                .manager
                .check_recovery_owner(&binding(&scope), &principal)?;
            if settle && recovered_publication.is_none() {
                active.control.canonical_changed();
                if saved
                    .working_resolution_ref()
                    .and_then(|r| r.answer())
                    .is_some_and(|a| a["verdict"] == "unapplied_terminal")
                {
                    let (publication, kind) =
                        active.manager.await_terminal_draft(id, deadline).await?;
                    recovered_publication = Some(publication);
                    disposition = kind;
                    active
                        .manager
                        .check_recovery_owner(&binding(&scope), &principal)?;
                }
            }
        }
        if gate::Outage::custody_binding(self).await.as_ref() != Some(&scope) {
            return Err(Error::engine("recovery account changed"));
        }
        let mut response = json!({"entry_id":saved.id,"operation":original.operation,"idempotency_key":original.operation_key,
            "original_arguments":original.arguments,"resolution":saved.working_resolution_ref(),
            "canonical_attempt_reply":saved.reply,"payload_retained":true,"recovered_publication":recovered_publication,"queue":"paused_if_resolution_requested"});
        if let Some(disposition) = disposition {
            response["disposition"] = json!(disposition);
        }
        Ok(response)
    }
}
