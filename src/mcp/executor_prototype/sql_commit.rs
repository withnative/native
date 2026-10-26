//! Trusted dispatch after stored plan signature, identity and visible echo admission.
use super::*;

const HOSTED_WORKSPACE_WRITER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

pub(super) const HOSTED_GUARDED_SQL_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(5);

const GUARDED_REPLAY_TIMEOUT: &str =
    "guarded durable receipt replay exceeded 5 seconds; retry the same plan";

type DispatchFailure = Arc<std::sync::Mutex<Option<(String, bool)>>>;
tokio::task_local! {
    static ADMITTED: (selected::commit::Approval, DispatchFailure);
}

pub(in super::super) async fn dispatch_admitted(db: crate::Db, caller: Caller) -> Result<Value> {
    let (approval, failure) = ADMITTED
        .try_with(Clone::clone)
        .map_err(|_| Error::engine(crate::mcp::tools::sql_write::DIRECT_REFUSAL))?;
    if !caller.write_plan_execution().is_some_and(|e| {
        e.plan_id == approval.plan_id
            && e.executor == SQL_WRITE_EXECUTOR
            && e.operation == SQL_WRITE_OPERATION
    }) {
        return Err(Error::engine(crate::mcp::tools::sql_write::DIRECT_REFUSAL));
    }
    let result = selected::commit::execute(&db, &caller, &approval).await;
    if let Err(e) = &result {
        *failure.lock().expect("SQL dispatch failure lock") =
            Some((e.to_string(), matches!(e, Error::Conflict(_))));
    }
    result
}

// Local unit fixtures can exercise hosted cancellation with transaction phase
// gates without assembling a hosted catalog. Production follows guard ownership.
#[cfg(test)]
tokio::task_local! {
    pub(super) static TEST_GUARDED_DISPATCH: ();
}

/// Retryable refusal when another hosted SQL commit already holds the
/// single-flight permit. The plan stays unclaimed (Prepared) and nothing is
/// dispatched, so retrying the SAME plan_id is safe.
pub(super) const SQL_COMMIT_BUSY_CODE: &str = "sql_commit_busy";

const SQL_COMMIT_BUSY_DETAIL: &str =
    "another hosted SQL commit holds the catalog guard; retry the SAME plan shortly";

impl ExecutorPrototypeStdioServer {
    pub(super) async fn execute_sql_commit(
        &self,
        context: RevalidationContext<'_>,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Value {
        let _admission_lease = persistence_lease.clone();
        // Retain the outer admitted deployment persistence lease for the whole
        // transaction and sidecar completion, including the private Rust route.
        let dispatch_count = std::sync::atomic::AtomicU64::new(0);
        match self
            .run_sql_commit(&context, persistence_lease, &dispatch_count)
            .await
        {
            Ok(body) => body,
            Err((code, detail, uncertain)) => {
                let mut error = if uncertain {
                    PlanError::indeterminate(&detail)
                } else {
                    PlanError::new(code, &detail, false)
                };
                error.source_dispatch_count =
                    dispatch_count.load(std::sync::atomic::Ordering::Relaxed);
                if uncertain {
                    error.continuation = Some(
                        json!({"action":"retry_same_plan_for_durable_receipt","retryable":true,"retry_ready":false,"new_plan_safe":false}),
                    );
                }
                if code == SQL_COMMIT_BUSY_CODE {
                    // Refused before claim: the plan is still Prepared and
                    // nothing dispatched, so the same plan_id retries cleanly.
                    error.continuation = Some(
                        json!({"action":"retry_same_plan","retryable":true,"retry_ready":true,"new_plan_safe":false}),
                    );
                }
                self.write_plan_error(
                    context.id,
                    context.modern,
                    context.contract,
                    context.envelope,
                    context.telemetry_request,
                    error,
                )
                .await
            }
        }
    }

    async fn complete_sql_commit(
        &self,
        c: &RevalidationContext<'_>,
        attempt: &str,
        result: &Value,
    ) -> Result<()> {
        let store = &self.write_runtime.as_ref().expect("write runtime").store;
        match store.complete(c.plan_id, attempt, result, now_ms()).await {
            Ok(()) => Ok(()),
            Err(error) => {
                // Two positive-receipt observers may complete the same fence.
                // A confirmed matching terminal row settles that CAS race;
                // storage errors or a different payload do not.
                if matches!(store.load(c.plan_id, now_ms()).await, Ok(Some(ref row))
                    if row.payload == c.initially_loaded.payload && row.key_id == c.initially_loaded.key_id
                    && matches!(row.state, StoredState::Completed { source_dispatch_count: 1, .. }))
                {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    fn sql_commit_phase(
        &self,
        c: &RevalidationContext<'_>,
        phase: super::super::telemetry::TelemetryPhase,
        outcome: super::super::telemetry::TelemetryOutcome,
    ) {
        if let (Some(telemetry), Some(request)) = (&self.telemetry, c.telemetry_request) {
            telemetry.emit(super::super::telemetry::EventSpec {
                request: Some(request.clone()),
                phase,
                outcome,
                counts: super::super::telemetry::TelemetryCounts {
                    attempt_bucket: super::super::telemetry::attempt_bucket(1),
                    dispatch_count_bucket: super::super::telemetry::dispatch_bucket(1),
                    ..super::super::telemetry::TelemetryCounts::default()
                },
                ..super::super::telemetry::EventSpec::default()
            });
        }
    }

    async fn run_sql_commit(
        &self,
        c: &RevalidationContext<'_>,
        persistence_lease: Option<DeploymentPersistenceLease>,
        dispatch_count: &std::sync::atomic::AtomicU64,
    ) -> std::result::Result<Value, (&'static str, String, bool)> {
        // One hosted SQL commit at a time per process: hold the permit from
        // before revalidation and claim until the catalog guard below is
        // released. A refused caller never claimed, so its plan stays Prepared
        // and the same plan_id retries cleanly. The local/unguarded path has
        // no shared guard and stays as-is.
        let permit = self.try_acquire_sql_commit_single_flight()?;
        self.run_sql_commit_inner(c, persistence_lease, dispatch_count, permit)
            .await
    }

    pub(super) fn try_acquire_sql_commit_single_flight(
        &self,
    ) -> std::result::Result<Option<tokio::sync::OwnedSemaphorePermit>, (&'static str, String, bool)>
    {
        let semaphore = match &self.hosted_authority {
            None => return Ok(None),
            Some(authority) => match authority.sql_commit_single_flight() {
                None => return Ok(None),
                Some(semaphore) => semaphore,
            },
        };
        semaphore.try_acquire_owned().map(Some).map_err(|_| {
            (
                SQL_COMMIT_BUSY_CODE,
                SQL_COMMIT_BUSY_DETAIL.to_string(),
                false,
            )
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn run_sql_commit_inner(
        &self,
        c: &RevalidationContext<'_>,
        persistence_lease: Option<DeploymentPersistenceLease>,
        dispatch_count: &std::sync::atomic::AtomicU64,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> std::result::Result<Value, (&'static str, String, bool)> {
        self.require_sql_commit()
            .map_err(|e| ("commit_unavailable", e.to_string(), false))?;
        let runtime = self.write_runtime.as_ref().expect("admitted write runtime");
        let db = sqlite_engine(&self.engine, "SQL commit")
            .map_err(|e| ("commit_unavailable", e.to_string(), false))?;
        // This is the verified SIGNED preparation, never a fresh preparation
        // or caller-supplied approval object. The adapter compares it in BEGIN IMMEDIATE.
        let mut approval = selected::commit::Approval::new(
            c.plan.id.clone(),
            SqlWritePreparation {
                canonical_source_arguments: c.plan.canonical_source_arguments.clone(),
                target_id: c.plan.target_id.clone(),
                target: c.plan.target.clone(),
                state_revision: c.plan.state_revision.clone(),
                target_state_digest: c.plan.target_state_digest.clone(),
                effect: c.plan.effect.clone(),
                effect_summary: c.plan.effect_summary.clone(),
                operation_evidence: c.plan.operation_evidence.clone(),
            },
        );
        if self.hosted_authority.is_some() {
            approval.writer_deadline = Some(HOSTED_WORKSPACE_WRITER_DEADLINE);
        }
        if approval.prepared.canonical_source_arguments["execution_profile"]
            != selected::commit::PROFILE
            || approval.prepared.effect["execution_profile"] != selected::commit::PROFILE
            || approval.prepared.operation_evidence["execution_profile"]
                != selected::commit::PROFILE
            || approval.prepared.effect["preview_only"] != false
        {
            return Err((
                "plan_integrity_failed",
                "commit profile is not bound throughout the signed preparation".into(),
                false,
            ));
        }
        let caller = self
            .caller
            .clone()
            .with_channel(crate::provenance::Channel::Mcp)
            .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: c.plan.id.clone(),
                effect_digest: c.plan.effect_digest.clone(),
                executor: c.plan.executor.clone(),
                operation: c.plan.operation.clone(),
            });
        let mut stored = c.initially_loaded.clone();
        // Only Prepared can acquire a new claim. Reload/claim races join the
        // positive-receipt path; they never dispatch a second time.
        let attempt = if matches!(stored.state, StoredState::Prepared) {
            let revalidation =
                match selected::prepare(db, &caller, c.plan.revalidation_arguments.clone()).await {
                    Ok(current)
                        if current.canonical_source_arguments
                            == approval.prepared.canonical_source_arguments
                            && current.effect == approval.prepared.effect
                            && current.operation_evidence
                                == approval.prepared.operation_evidence
                            && current.target_state_digest
                                == approval.prepared.target_state_digest
                            && current.state_revision == approval.prepared.state_revision
                            && current.target == approval.prepared.target
                            && current.target_id == approval.prepared.target_id
                            && current.effect_summary == approval.prepared.effect_summary =>
                    {
                        Ok(())
                    }
                    Ok(_) => Err((
                        "plan_stale",
                        "approved selection, authority, sources, state or effect changed".into(),
                        false,
                    )),
                    Err(e) => Err((
                        if matches!(e, Error::Conflict(_)) {
                            "plan_stale"
                        } else {
                            "plan_revalidation_failed"
                        },
                        e.to_string(),
                        false,
                    )),
                };
            if let Err(error) = revalidation {
                let latest = runtime
                    .store
                    .load(c.plan_id, now_ms())
                    .await
                    .map_err(|e| ("plan_store_unavailable", e.to_string(), false))?
                    .ok_or_else(|| ("plan_not_found", "plan disappeared".into(), false))?;
                if latest.payload != stored.payload || latest.key_id != stored.key_id {
                    return Err((
                        "plan_integrity_failed",
                        "stored signed payload changed".into(),
                        false,
                    ));
                }
                if matches!(latest.state, StoredState::Prepared) {
                    return Err(error);
                }
                // A concurrent execution can change the selected state while
                // this early check runs. Join its receipt path, never reselect
                // the original write or acquire another execution claim.
                let advanced = RevalidationContext {
                    initially_loaded: &latest,
                    id: c.id.clone(),
                    modern: c.modern,
                    contract: c.contract,
                    envelope: c.envelope,
                    plan_id: c.plan_id,
                    plan: c.plan,
                    telemetry_request: c.telemetry_request,
                    started: c.started,
                };
                return Box::pin(self.run_sql_commit_inner(
                    &advanced,
                    persistence_lease,
                    dispatch_count,
                    permit,
                ))
                .await;
            }
            #[cfg(test)]
            runtime
                .claim_attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match runtime
                .store
                .claim(c.plan_id, now_ms())
                .await
                .map_err(|e| {
                    (
                        "plan_execution_indeterminate",
                        format!("claim outcome could not be confirmed; retry the same plan: {e}"),
                        true,
                    )
                })? {
                ClaimOutcome::Claimed { plan, attempt_id } => {
                    if plan.payload != stored.payload || plan.key_id != stored.key_id {
                        let _ = runtime
                            .store
                            .mark_indeterminate(
                                c.plan_id,
                                &attempt_id,
                                "claimed payload changed",
                                now_ms(),
                            )
                            .await;
                        return Err((
                            "plan_integrity_failed",
                            "claimed signed payload changed".into(),
                            true,
                        ));
                    }
                    Some(attempt_id)
                }
                ClaimOutcome::Existing(existing) => {
                    stored = existing;
                    None
                }
                ClaimOutcome::NotFound => {
                    return Err(("plan_not_found", "plan disappeared".into(), false))
                }
            }
        } else {
            None
        };
        if let Some(attempt) = attempt {
            // Claim first, then lock current hosted authority through the domain
            // commit. Release before plan completion, which shares the catalog.
            let authority_guard = match self.acquire_sql_commit_authority(&caller).await {
                Ok(guard) => guard,
                Err(error) => {
                    let _ = runtime
                        .store
                        .mark_indeterminate(
                            c.plan_id,
                            &attempt,
                            "SQL authority admission refused before dispatch",
                            now_ms(),
                        )
                        .await;
                    return Err(error);
                }
            };
            dispatch_count.store(1, std::sync::atomic::Ordering::Relaxed);
            self.sql_commit_phase(
                c,
                super::super::telemetry::TelemetryPhase::PlanClaimed,
                super::super::telemetry::TelemetryOutcome::Succeeded,
            );
            self.sql_commit_phase(
                c,
                super::super::telemetry::TelemetryPhase::DispatchBegun,
                super::super::telemetry::TelemetryOutcome::Started,
            );
            let failure: DispatchFailure = Arc::new(std::sync::Mutex::new(None));
            let dispatch = async {
                #[cfg(test)]
                {
                    runtime
                        .dispatch_attempts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Some(gate) = &runtime.dispatch_gate {
                        gate.entered.add_permits(1);
                        gate.release
                            .acquire()
                            .await
                            .expect("dispatch gate open")
                            .forget();
                    }
                }
                let mut arguments = c.plan.canonical_source_arguments.clone();
                for key in ["run_key", "parent_key"] {
                    if let Some(value) = c.envelope.get(key) {
                        arguments[key] = value.clone();
                    }
                }
                arguments["format"] = json!("json");
                let message = json!({"jsonrpc":"2.0","id":c.id,"method":"tools/call","params":{"name":"sql_write","arguments":arguments}});
                ADMITTED
                    .scope(
                        (approval.clone(), failure.clone()),
                        self.delegate_with_caller_and_persistence(
                            message,
                            caller.clone(),
                            persistence_lease,
                        ),
                    )
                    .await
            };
            let guarded = authority_guard.is_some();
            #[cfg(test)]
            let guarded = guarded || TEST_GUARDED_DISPATCH.try_with(|_| ()).is_ok();
            let outcome = if guarded {
                tokio::time::timeout(HOSTED_GUARDED_SQL_DEADLINE, dispatch).await
            } else {
                Ok(dispatch.await)
            };
            if let Some(guard) = authority_guard {
                guard
                    .rollback()
                    .await
                    .map_err(|e| ("plan_execution_indeterminate", e.to_string(), true))?;
            }
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(_) => {
                    let reason = "SQL guarded dispatch exceeded 5 seconds; attempt remains claimed; retry the same plan for durable receipt recovery";
                    let _ = runtime
                        .store
                        .mark_indeterminate(c.plan_id, &attempt, reason, now_ms())
                        .await;
                    return Err(("plan_execution_indeterminate", reason.into(), true));
                }
            };
            let mut body = outcome_body(outcome).ok_or_else(|| {
                (
                    "plan_execution_indeterminate",
                    "missing SQL source response".into(),
                    true,
                )
            })?;
            add_executor_meta(&mut body, self.executor_meta());
            if c.modern {
                if let Some(result) = body.get_mut("result") {
                    protocol::add_modern_result_fields(result);
                }
            }
            self.sql_commit_phase(
                c,
                super::super::telemetry::TelemetryPhase::DispatchCompleted,
                if response_succeeded(&body) {
                    super::super::telemetry::TelemetryOutcome::Succeeded
                } else {
                    super::super::telemetry::TelemetryOutcome::Rejected
                },
            );
            if !response_succeeded(&body) {
                let _ = runtime
                    .store
                    .mark_indeterminate(
                        c.plan_id,
                        &attempt,
                        "SQL dispatch did not return a durable success",
                        now_ms(),
                    )
                    .await;
                let issue = failure.lock().expect("SQL dispatch failure lock").clone();
                return Err(match issue {
                    Some((detail, true)) => ("plan_stale", detail, false),
                    Some((detail, false)) if detail == crate::db::SQL_WORKSPACE_BUSY => ("plan_execution_indeterminate", detail, true),
                    _ => ("plan_execution_indeterminate", "SQL dispatch did not confirm a commit; retry the same plan for positive receipt recovery".into(), true),
                });
            }
            let result = body["result"].clone();
            if let Err(error) = self.complete_sql_commit(c, &attempt, &result).await {
                let _ = runtime
                    .store
                    .mark_indeterminate(
                        c.plan_id,
                        &attempt,
                        "domain receipt exists but sidecar completion failed",
                        now_ms(),
                    )
                    .await;
                return Err(("plan_execution_indeterminate", error.to_string(), true));
            }
            self.sql_commit_phase(
                c,
                super::super::telemetry::TelemetryPhase::PlanCompleted,
                super::super::telemetry::TelemetryOutcome::Succeeded,
            );
            self.trace.record(json!({"schema":TRACE_SCHEMA,"kind":"write_plan_executed","mode":"execute","executor":c.plan.executor,"operation":c.plan.operation,"plan_id":c.plan.id,"source_dispatch_count":1,"completed":true}));
            return Ok(body);
        }
        if stored.payload != c.initially_loaded.payload
            || stored.key_id != c.initially_loaded.key_id
        {
            return Err((
                "plan_integrity_failed",
                "stored signed payload changed".into(),
                false,
            ));
        }
        match &stored.state {
            StoredState::Completed { .. }
            | StoredState::Executing { .. }
            | StoredState::Indeterminate { .. } => {
                dispatch_count.store(1, std::sync::atomic::Ordering::Relaxed);
                let authority_guard = self.acquire_sql_commit_authority(&caller).await?;
                let replay = selected::commit::replay_receipt(db, &caller, &approval);
                let guarded = authority_guard.is_some();
                #[cfg(test)]
                let guarded = guarded || TEST_GUARDED_DISPATCH.try_with(|_| ()).is_ok();
                let outcome = if guarded {
                    tokio::time::timeout(HOSTED_GUARDED_SQL_DEADLINE, replay).await
                } else {
                    Ok(replay.await)
                };
                // Release on success, misses, errors and timeout before any
                // sidecar repair. A timed-out read never changes the plan fence.
                if let Some(guard) = authority_guard {
                    guard
                        .rollback()
                        .await
                        .map_err(|e| ("plan_execution_indeterminate", e.to_string(), true))?;
                }
                let receipt = outcome
                    .map_err(|_| {
                        (
                            "plan_execution_indeterminate",
                            GUARDED_REPLAY_TIMEOUT.into(),
                            true,
                        )
                    })?
                    .map_err(|e| {
                        if matches!(e, Error::Conflict(_)) {
                            (
                                "receipt_unavailable",
                                "committed receipt is unavailable".into(),
                                false,
                            )
                        } else if e.to_string() == selected::commit::REPLAY_WORKSPACE_BUSY {
                            ("plan_execution_indeterminate", e.to_string(), true)
                        } else {
                            (
                                "plan_execution_indeterminate",
                                "durable receipt could not be checked; retry this same plan".into(),
                                true,
                            )
                        }
                    })?
                    .ok_or_else(|| {
                        (
                            "plan_execution_indeterminate",
                            "no matching positive domain receipt; this claim cannot execute again"
                                .into(),
                            true,
                        )
                    })?;
                // Reconstructed domain receipts bypass source dispatch, so
                // restore its outward counter projection and current request
                // context. Never disclose owner-only acts from the envelope.
                let run_context = run_context_for_engine(
                    &self.engine,
                    self.caller.clone(),
                    c.envelope,
                    self.registry.public_origin(),
                    self.registry.deployment_mutation_barrier(),
                )
                .await;
                let mut body =
                    json!({"result":commit_result(receipt, &caller, run_context, c.modern)});
                add_executor_meta(&mut body, self.executor_meta());
                let result = body["result"].clone();
                if let StoredState::Executing { attempt_id, .. }
                | StoredState::Indeterminate { attempt_id, .. } = &stored.state
                {
                    self.complete_sql_commit(c, attempt_id, &result)
                        .await
                        .map_err(|e| ("plan_execution_indeterminate", e.to_string(), true))?;
                }
                Ok(self.replay_write_plan(
                    c.id.clone(),
                    c.plan,
                    result,
                    1,
                    c.telemetry_request,
                    c.started,
                    c.modern,
                ))
            }
            StoredState::Expired => Err((
                "plan_expired",
                "write plan expired before claim".into(),
                false,
            )),
            StoredState::Prepared => Err((
                "plan_store_conflict",
                "plan has no execution fence".into(),
                false,
            )),
        }
    }

    pub(super) async fn acquire_sql_commit_authority(
        &self,
        caller: &Caller,
    ) -> std::result::Result<
        Option<sqlx::Transaction<'static, sqlx::Sqlite>>,
        (&'static str, String, bool),
    > {
        match &self.hosted_authority {
            Some(authority) => authority
                .acquire_sql_commit_authority(caller)
                .await
                .map(Some)
                .map_err(|e| {
                    let uncertain = !matches!(e, Error::Conflict(_));
                    ("commit_authority_unavailable", e.to_string(), uncertain)
                }),
            None => Ok(None),
        }
    }
}

fn commit_result(mut receipt: Value, caller: &Caller, run_context: Value, modern: bool) -> Value {
    let mut ids = receipt["item_attestation_ids"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    ids.push(receipt["anchor_id"].clone());
    receipt["action_attestation_ids"] = json!(ids);
    if !caller.counter_footing().is_owner() {
        crate::mcp::counter_fence::withhold_receipt_acts("sql_write", &mut receipt);
    }
    let receipt = attach_run_context(receipt, run_context);
    let mut result = protocol::call_result_content(
        "sql_write",
        render::Format::Json,
        ToolResult::from(receipt),
        None,
    );
    if modern {
        protocol::add_modern_result_fields(&mut result);
    }
    result
}
