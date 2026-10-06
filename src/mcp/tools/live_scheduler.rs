//! M2 need scheduler (task `61e11ad`, design `ee12faf` §2.3–2.5).
//!
//! One scheduler per database, driven by the hub's existing broadcasts:
//! content wakes mark everything dirty (debounced), grant/control movement
//! forces gate re-checks, and each dirty subscription gets at most one
//! re-run in flight plus its dirty flag — trivially satisfied by this
//! sequential drain. The per-connection token bucket and dirtied-order
//! queue bound shared load; latest-wins drops superseded computations;
//! `delivery` counts emissions only. Teardown always wins: the send decision
//! re-checks the subscription under the registry lock, and teardown takes
//! the same lock. Transport (the SSE sink `select!`, `stream` announcement,
//! drop-guard removal, demotion hooks) lives in the held `/events` handler.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

/// Fresh per-connection authority probe, owned by the registry entries;
/// re-exported here for the SSE layer and tests.
pub use crate::need_subscriptions::AccessHook;

use crate::mcp::registry::Caller;
use crate::mcp::tools::alpha_tabs::{
    replay_snapshot_for_probe, rerun_keyed_for_scheduler, rerun_snapshot_for_scheduler,
    snapshot_clock_bindings, snapshot_surface_gates,
};
use crate::need_metrics::{Outcome, PullKind, RerunSample, Trigger, VmWorkObserver};
use crate::need_subscriptions::{
    closed_reason_for_refusal, gate_drift_reason, ConnectionToken, NeedClosedReason, SubscriptionId,
};
use crate::realtime::RealtimeHub;

/// Fresh authority verdict for one subscription's connection.
enum AccessVerdict {
    Valid(Box<Caller>),
    Revoked,
    Gone,
}

/// One actual scheduler re-run. Drop covers every early exit and keeps the
/// measurement off the viewer response and stream path.
struct RunObservation {
    hub: Arc<RealtimeHub>,
    token: ConnectionToken,
    id: SubscriptionId,
    need: String,
    started: Instant,
    dirty: crate::need_subscriptions::DirtyMeasurement,
    outcome: Outcome,
    output_rows: usize,
    evaluation_started: bool,
    vm_work: VmWorkObserver,
    vm_work_in_flight: bool,
    retry_work: bool,
    forcing: bool,
    keyed_dirty: bool,
    saw_content_event: bool,
}

impl Drop for RunObservation {
    fn drop(&mut self) {
        {
            let mut registry = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned");
            if self.retry_work
                && !self.hub.is_terminal()
                && registry.restore_rerun_work(
                    &self.token,
                    &self.id,
                    &self.dirty,
                    self.forcing,
                    self.keyed_dirty,
                    self.saw_content_event,
                )
                && !self.evaluation_started
            {
                // Transferred associations were not dropped or evaluated.
                self.dirty.content_acts.clear();
                self.dirty.unknown_act = false;
            }
            registry.finish_rerun(&self.token, &self.id);
        }
        let duration = self.started.elapsed();
        let latency = (self.outcome == Outcome::Delivered).then(|| self.dirty.since.elapsed());
        let vm_work = self.vm_work.sample();
        tracing::debug!(
            target: "native_live_need_metrics",
            hub_instance = %self.hub.metrics_hub_id(),
            trigger = ?self.dirty.trigger,
            need_bucket = crate::need_metrics::NeedMetrics::need_bucket(&self.need),
            outcome = ?self.outcome,
            duration_ms = duration.as_millis() as u64,
            output_rows = self.output_rows,
            attention_candidate_vm_progress_callbacks_1000 = vm_work.attention_candidate_callbacks,
            declared_sql_vm_progress_callbacks_1000 = vm_work.declared_sql_callbacks,
            vm_work_complete = !self.vm_work_in_flight,
            evaluation_started = self.evaluation_started,
            attributed_content_acts = self.dirty.content_acts.len(),
            unknown_act_association = self.dirty.unknown_act,
            "live need push scheduler rerun"
        );
        self.hub
            .need_metrics()
            .lock()
            .expect("need metrics poisoned")
            .note_rerun(RerunSample {
                need: &self.need,
                trigger: self.dirty.trigger,
                outcome: self.outcome,
                duration,
                output_rows: self.output_rows,
                trigger_to_delivery: latency,
                content_acts: &self.dirty.content_acts,
                unknown_act: self.dirty.unknown_act,
                evaluation_started: self.evaluation_started,
                vm_work,
                vm_work_complete: !self.vm_work_in_flight,
            });
    }
}

fn materialized_output_rows(result: &serde_json::Value) -> usize {
    let input = &result["input"];
    let records = input["records"].as_array().map_or(0, Vec::len);
    let sql = input["sql"].as_object().map_or(0, |needs| {
        needs
            .values()
            .map(|need| need["rows"].as_array().map_or(0, Vec::len))
            .sum()
    });
    records + sql
}

#[derive(Clone, Copy)]
struct ProbeComparison<'a> {
    before_content: i64,
    after_content: Option<i64>,
    before_vector: &'a crate::realtime::InboxInvalidationVector,
    after_vector: Option<&'a crate::realtime::InboxInvalidationVector>,
    scheduler_vector: Option<&'a crate::realtime::InboxInvalidationVector>,
    sampled_state: &'a crate::need_subscriptions::SubscriptionRecord,
    current_state: Option<&'a crate::need_subscriptions::SubscriptionRecord>,
    sampled_digest: &'a str,
}

impl ProbeComparison<'_> {
    fn verdict(&self) -> Option<bool> {
        let current = self.current_state?;
        (self.after_content == Some(self.before_content)
            && self.after_vector == Some(self.before_vector)
            && self.scheduler_vector == Some(self.before_vector)
            && current.lifecycle == crate::need_subscriptions::SubscriptionLifecycle::Active
            && !current.dirty
            && !current.in_flight
            && !current.catchup_in_flight
            && !current.stale
            && current.clock_replay_safe
            && current.clock_replay_safe == self.sampled_state.clock_replay_safe
            && current.baseline == self.sampled_state.baseline)
            .then(|| self.sampled_state.baseline.as_deref() != Some(self.sampled_digest))
    }
}

/// One database's need scheduler. Owns no subscriptions and pins no `Db`
/// handle itself; all state lives in the hub registry under short
/// synchronous locks (never held across an await), and every re-run fetches
/// the hub's current handle — the router LRU may close the spawn-time handle
/// on replacement.
pub struct NeedScheduler {
    hub: Arc<RealtimeHub>,
    rotation: usize,
    probe_cursor: usize,
    clock_probe_cursor: usize,
    probe_clock_next: bool,
    start: Instant,
    last_vector: Option<crate::realtime::InboxInvalidationVector>,
}

impl NeedScheduler {
    pub fn new(hub: Arc<RealtimeHub>) -> Self {
        Self {
            hub,
            rotation: 0,
            probe_cursor: 0,
            clock_probe_cursor: 0,
            probe_clock_next: false,
            start: Instant::now(),
            last_vector: None,
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Run until the hub's broadcast senders close (hub terminalize). Content
    /// wakes mark everything dirty; inbox wakes force gate re-checks when
    /// the authorization or control components move — awareness/candidate
    /// movement alone is the viewer-addressed inbox bell's business, never a
    /// need wake. A lagged receiver fails safe: content lag dirties all,
    /// inbox lag forces all, and the next `Ok` re-baselines.
    pub async fn run_forever(mut self) {
        let mut content_rx = self.hub.subscribe();
        let mut inbox_rx = self.hub.subscribe_inbox();
        // Seed the inbox baseline before the first receive: without it the
        // first vector after startup cannot tell a grant/control change from
        // steady state, and a grant/control change affecting an active
        // subscription would miss its required force wake. If the seed read
        // fails, the first vector forces instead (fail safe: a spurious
        // re-run costs liveness, a missed wake costs safety).
        if let Ok(vector) = self.hub.inbox_invalidation_vector().await {
            self.last_vector = Some(vector);
        }
        let mut heartbeat = tokio::time::interval(Duration::from_millis(50));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut clock_poll = tokio::time::interval(Duration::from_millis(
            crate::need_subscriptions::CLOCK_POLL_MS,
        ));
        clock_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut metrics_poll = tokio::time::interval(Duration::from_secs(60));
        metrics_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        metrics_poll.tick().await;
        loop {
            tokio::select! {
                received = content_rx.recv() => match received {
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // The hub marked every durable event before fan-out.
                        // Even a lagged receiver has no dirty work to repair.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
                received = inbox_rx.recv() => match received {
                    Ok(vector) => {
                        self.note_inbox_vector(vector);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        self.mark_forcing(Trigger::Control);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
                _ = clock_poll.tick() => {
                    // M1: each time-dependent subscription owns a jittered
                    // due time. A one-second scan marks only due ids; the
                    // ordinary 50 ms drain spends the existing budget.
                    self.poll_clocks_once();
                },
                _ = heartbeat.tick() => {
                    self.drain().await;
                },
                _ = metrics_poll.tick() => {
                    // Keep one sampled snapshot per report interval so
                    // measurement cannot double the scheduler's probe load.
                    if self.probe_clock_next {
                        self.probe_clock_once().await;
                    } else {
                        self.probe_once().await;
                    }
                    self.probe_clock_next = !self.probe_clock_next;
                    self.report_metrics();
                }
            }
        }
    }

    fn poll_clocks_once(&self) -> usize {
        let marked = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .mark_due_clock_ticks(Instant::now());
        if marked > 0 {
            self.hub
                .need_metrics()
                .lock()
                .expect("need metrics poisoned")
                .note_trigger(Trigger::Tick);
        }
        marked
    }

    fn note_inbox_vector(&mut self, vector: crate::realtime::InboxInvalidationVector) {
        // No baseline (seed read failed): force. A missed grant/control wake
        // could leave a revoked viewer receiving values; a spurious re-run
        // only costs a quiet pass.
        let trigger = match &self.last_vector {
            None => Some(Trigger::Control),
            Some(previous) if vector.authorization != previous.authorization => {
                Some(Trigger::Grant)
            }
            Some(previous) if vector.control != previous.control => Some(Trigger::Control),
            Some(_) => None,
        };
        self.last_vector = Some(vector);
        // The vector never names a package, so a forcing wake re-checks all.
        // Control events stay internal: this only schedules re-runs, and no
        // count or timing derived from them reaches a frame.
        if let Some(trigger) = trigger {
            self.mark_forcing(trigger);
        }
    }

    /// A probe can discover a stable vector advance even if its broadcast
    /// wake was lost. Reconcile it through the ordinary grant/control wake
    /// path before considering a digest comparison; the probe itself remains
    /// inconclusive for this interval.
    fn reconcile_probe_vector(
        &mut self,
        observed: &crate::realtime::InboxInvalidationVector,
    ) -> bool {
        if self.last_vector.as_ref() == Some(observed) {
            return true;
        }
        self.note_inbox_vector(observed.clone());
        false
    }

    fn mark_forcing(&mut self, trigger: Trigger) {
        self.hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .mark_forcing_with_trigger(None, trigger);
        self.hub
            .need_metrics()
            .lock()
            .expect("need metrics poisoned")
            .note_trigger(trigger);
    }

    /// Sample one clean subscription outside the push path. Both durable
    /// content and inbox vectors must be stable and already observed by the
    /// scheduler; a concurrent wake makes the probe inconclusive. A
    /// persistent mismatch is counted and queued for recovery.
    async fn probe_once(&mut self) {
        let sample = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .probe_candidate(self.probe_cursor);
        let Some((token, id, state)) = sample else {
            return;
        };
        self.probe_cursor = self.probe_cursor.wrapping_add(1);
        let Some(before_content) = self.hub.settled_content_seq().await else {
            self.note_probe(None);
            return;
        };
        let Ok(before_vector) = self.hub.inbox_invalidation_vector().await else {
            self.note_probe(None);
            return;
        };
        let recent_content = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .last_content_event_at()
            .is_some_and(|wake| wake.elapsed() < Duration::from_secs(2));
        if !self.reconcile_probe_vector(&before_vector) || recent_content {
            self.note_probe(None);
            return;
        }
        let AccessVerdict::Valid(caller) = self.resolve_caller(&token).await else {
            self.note_probe(None);
            return;
        };
        let Some(db) = self.hub.current_db() else {
            self.note_probe(None);
            return;
        };
        let mut sql_attempted = false;
        let Ok((_, digest, _, _)) = rerun_snapshot_for_scheduler(
            &db,
            &caller,
            &state.binding.package,
            &state.binding.install_event_id,
            &mut sql_attempted,
            None,
        )
        .await
        else {
            self.note_probe(None);
            return;
        };
        let after_content = self.hub.settled_content_seq().await;
        let after_vector = self.hub.inbox_invalidation_vector().await.ok();
        let mut registry = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned");
        let current = registry.subscription_state(&token, &id);
        let verdict = ProbeComparison {
            before_content,
            after_content,
            before_vector: &before_vector,
            after_vector: after_vector.as_ref(),
            scheduler_vector: self.last_vector.as_ref(),
            sampled_state: &state,
            current_state: current.as_ref(),
            sampled_digest: &digest,
        }
        .verdict();
        let Some(mismatch) = verdict else {
            drop(registry);
            self.note_probe(None);
            return;
        };
        if mismatch {
            registry.enqueue_dirty_with_trigger(&token, &id, true, Trigger::Resync);
        }
        drop(registry);
        self.note_probe(Some(mismatch));
    }

    /// Replay one time-dependent snapshot with its own stored per-statement
    /// clocks. A fresh wall clock would report legitimate changes that are
    /// not due for a push yet. This sample measures missed data/authority
    /// invalidation only; the separate due-work audit measures overdue ticks.
    async fn probe_clock_once(&mut self) {
        // Fixed suppression indices keep the report bounded: no eligible,
        // content sequence, authority vector, recent write, access/db,
        // replay/gates, state race.
        let sample = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .probe_clock_candidate(self.clock_probe_cursor);
        let Some((token, id, state)) = sample else {
            self.note_clock_probe(Err(0));
            return;
        };
        self.clock_probe_cursor = self.clock_probe_cursor.wrapping_add(1);
        let Some(clocks) = state.clock_bindings.as_ref() else {
            self.note_clock_probe(Err(6));
            return;
        };
        let Some(before_content) = self.hub.settled_content_seq().await else {
            self.note_clock_probe(Err(1));
            return;
        };
        let Ok(before_vector) = self.hub.inbox_invalidation_vector().await else {
            self.note_clock_probe(Err(2));
            return;
        };
        if !self.reconcile_probe_vector(&before_vector) {
            self.note_clock_probe(Err(2));
            return;
        }
        let recent_content = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .last_content_event_at()
            .is_some_and(|wake| wake.elapsed() < Duration::from_secs(2));
        if recent_content {
            self.note_clock_probe(Err(3));
            return;
        }
        let AccessVerdict::Valid(caller) = self.resolve_caller(&token).await else {
            self.note_clock_probe(Err(4));
            return;
        };
        let Some(db) = self.hub.current_db() else {
            self.note_clock_probe(Err(4));
            return;
        };
        let Ok((result, digest, gate)) = replay_snapshot_for_probe(
            &db,
            &caller,
            &state.binding.package,
            &state.binding.install_event_id,
            clocks,
        )
        .await
        else {
            self.note_clock_probe(Err(5));
            return;
        };
        if snapshot_clock_bindings(&result).as_ref() != Some(clocks) {
            self.note_clock_probe(Err(5));
            return;
        }
        let Ok(fresh_gate) = snapshot_surface_gates(
            &db,
            &caller,
            &state.binding.package,
            &state.binding.install_event_id,
        )
        .await
        else {
            self.note_clock_probe(Err(5));
            return;
        };
        if gate_drift_reason(&gate, &fresh_gate).is_some() {
            self.note_clock_probe(Err(5));
            return;
        }
        let after_content = self.hub.settled_content_seq().await;
        let after_vector = self.hub.inbox_invalidation_vector().await.ok();
        let mut registry = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned");
        let stable = after_content == Some(before_content)
            && after_vector.as_ref() == Some(&before_vector)
            && self.last_vector.as_ref() == Some(&before_vector)
            && registry.probe_clock_sample_still_eligible(&token, &id, &state);
        if !stable {
            drop(registry);
            self.note_clock_probe(Err(6));
            return;
        }
        let mismatch = state.baseline.as_deref() != Some(digest.as_str());
        if mismatch {
            registry.enqueue_dirty_with_trigger(&token, &id, true, Trigger::Resync);
        }
        drop(registry);
        self.note_clock_probe(Ok(mismatch));
    }

    #[doc(hidden)]
    pub async fn probe_clock_once_for_tests(&mut self) {
        self.last_vector = self.hub.inbox_invalidation_vector().await.ok();
        self.probe_clock_once().await;
    }

    fn note_clock_probe(&self, mismatch: Result<bool, usize>) {
        self.hub
            .need_metrics()
            .lock()
            .expect("need metrics poisoned")
            .note_clock_probe(mismatch);
    }

    /// Integration-test seam: seed the same vector baseline `run_forever`
    /// seeds before its first receive, then execute one sampled probe.
    #[doc(hidden)]
    pub async fn probe_once_for_tests(&mut self) {
        self.last_vector = self.hub.inbox_invalidation_vector().await.ok();
        self.probe_once().await;
    }

    fn note_probe(&self, mismatch: Option<bool>) {
        self.hub
            .need_metrics()
            .lock()
            .expect("need metrics poisoned")
            .note_probe(mismatch);
    }

    fn report_metrics(&self) {
        let snapshot = self
            .hub
            .need_metrics()
            .lock()
            .expect("need metrics poisoned")
            .clone();
        let (
            subscriptions,
            probe_eligible,
            clock_probe_eligible,
            probe_activity_excluded,
            pending_act_overflows,
            teardown_pending_act_drops,
            clock_due,
        ) = {
            let registry = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned");
            (
                registry.subscription_count(),
                registry.probe_eligible_count(),
                registry.probe_clock_eligible_count(),
                registry.probe_activity_excluded_count(),
                registry.act_attribution_losses().0,
                registry.act_attribution_losses().1,
                registry.clock_due_audit(Instant::now()),
            )
        };
        let act_evaluation_attempt_associations: u64 = snapshot
            .recent_acts
            .iter()
            .map(|act| act.evaluation_attempt_associations)
            .sum();
        let recent_distinct_dirtied_targets: u64 = snapshot
            .recent_acts
            .iter()
            .map(|act| act.distinct_dirtied_targets)
            .sum();
        tracing::info!(
            target: "native_live_need_metrics",
            hub_instance = %self.hub.metrics_hub_id(),
            known_content_acts = snapshot.known_content_acts,
            known_act_distinct_dirtied_targets = snapshot.known_act_distinct_dirtied_targets,
            known_act_evaluation_attempt_associations = snapshot.known_act_evaluation_attempt_associations,
            unknown_act_events = snapshot.unknown_act_events,
            unknown_act_target_pairs = snapshot.unknown_act_target_pairs,
            unknown_act_evaluation_attempt_associations = snapshot.unknown_act_evaluation_attempt_associations,
            content_events = snapshot.content_events,
            event_queue_inserts = snapshot.content_event_queue_inserts,
            event_pending_targets = snapshot.content_event_pending_targets,
            event_coalesced = snapshot.content_event_coalesced,
            probe_attempts = snapshot.probe_attempts,
            probe_mismatches = snapshot.probe_mismatches,
            probe_inconclusive = snapshot.probe_inconclusive,
            clock_probe_attempts = snapshot.clock_probe_attempts,
            clock_probe_mismatches = snapshot.clock_probe_mismatches,
            clock_probe_suppressed_no_eligible = snapshot.clock_probe_suppressed[0],
            clock_probe_suppressed_content = snapshot.clock_probe_suppressed[1],
            clock_probe_suppressed_authority = snapshot.clock_probe_suppressed[2],
            clock_probe_suppressed_recent_write = snapshot.clock_probe_suppressed[3],
            clock_probe_suppressed_access_or_db = snapshot.clock_probe_suppressed[4],
            clock_probe_suppressed_replay_or_gate = snapshot.clock_probe_suppressed[5],
            clock_probe_suppressed_state_race = snapshot.clock_probe_suppressed[6],
            attribution_overflows = snapshot.attribution_overflows,
            pre_evaluation_association_drops = snapshot.pre_evaluation_association_drops,
            subscribe_catchup_association_drops = snapshot.subscribe_catchup_association_drops,
            pending_act_overflows,
            teardown_pending_act_drops,
            recent_act_samples = snapshot.recent_acts.len(),
            recent_distinct_dirtied_targets,
            recent_act_evaluation_attempt_associations = act_evaluation_attempt_associations,
            subscriptions,
            probe_eligible_clock_free = probe_eligible,
            probe_eligible_clock_dependent = clock_probe_eligible,
            probe_excluded_activity = probe_activity_excluded,
            clock_due_periods = clock_due.due_periods,
            clock_covered_periods = clock_due.covered_periods,
            clock_covering_evaluations = clock_due.covering_evaluations,
            clock_late_covering_evaluations = clock_due.late_covering_evaluations,
            clock_max_cover_lateness_ms = clock_due.max_cover_lateness_ms,
            clock_time_dependent_subscriptions = clock_due.time_dependent_subscriptions,
            clock_unpolled_due_subscriptions = clock_due.unpolled_due_subscriptions,
            clock_unpolled_due_periods = clock_due.unpolled_due_periods,
            clock_pending_subscriptions = clock_due.pending_subscriptions,
            clock_pending_periods = clock_due.pending_periods,
            clock_overdue_subscriptions = clock_due.overdue_subscriptions,
            clock_budget_deferred_subscriptions = clock_due.budget_deferred_subscriptions,
            clock_budget_deferral_attempts = clock_due.budget_deferral_attempts,
            clock_removed_unserved_periods = clock_due.removed_unserved_periods,
            clock_retired_unserved_periods = clock_due.retired_unserved_periods,
            clock_removed_unpolled_due_periods = clock_due.removed_unpolled_due_periods,
            clock_retired_unpolled_due_periods = clock_due.retired_unpolled_due_periods,
            "live need push scheduler summary"
        );
        for (index, bucket) in snapshot.buckets.iter().enumerate() {
            if bucket.reruns == 0 {
                continue;
            }
            tracing::info!(
                target: "native_live_need_metrics",
                hub_instance = %self.hub.metrics_hub_id(),
                need_bucket = index,
                reruns = bucket.reruns,
                content_reruns = bucket.trigger(Trigger::Content),
                grant_reruns = bucket.trigger(Trigger::Grant),
                control_reruns = bucket.trigger(Trigger::Control),
                demotion_reruns = bucket.trigger(Trigger::Demotion),
                tick_reruns = bucket.trigger(Trigger::Tick),
                resync_reruns = bucket.trigger(Trigger::Resync),
                subscribe_reruns = bucket.trigger(Trigger::Subscribe),
                retry_reruns = bucket.trigger(Trigger::Retry),
                output_rows = bucket.output_rows,
                attention_candidate_vm_progress_callbacks_1000 = bucket.attention_candidate_vm_progress_callbacks_1000,
                declared_sql_vm_progress_callbacks_1000 = bucket.declared_sql_vm_progress_callbacks_1000,
                vm_work_evaluations = bucket.vm_callback_histogram.iter().sum::<u64>(),
                incomplete_vm_evaluations = bucket.incomplete_vm_evaluations,
                p50_vm_progress_callbacks_1000_bound = bucket.vm_callback_bound(50),
                p95_vm_progress_callbacks_1000_bound = bucket.vm_callback_bound(95),
                delivered = bucket.outcome(Outcome::Delivered),
                quiet = bucket.outcome(Outcome::Quiet),
                closed = bucket.outcome(Outcome::Closed),
                coalesced = bucket.outcome(Outcome::Coalesced),
                stale = bucket.outcome(Outcome::Stale),
                budget_deferred_attempts = bucket.outcome(Outcome::BudgetDeferred),
                retried = bucket.outcome(Outcome::Retried),
                p50_duration_ms_bound = bucket.duration_bound(50),
                p95_duration_ms_bound = bucket.duration_bound(95),
                p50_delivery_ms_bound = bucket.delivery_latency_bound(50),
                p95_delivery_ms_bound = bucket.delivery_latency_bound(95),
                "live need push scheduler bucket"
            );
        }
        for (index, bucket) in snapshot.pull_buckets.iter().enumerate() {
            let total: u64 = bucket.evaluations.iter().sum();
            if total == 0 && bucket.cancelled_evaluations == 0 {
                continue;
            }
            tracing::info!(
                target: "native_live_need_metrics",
                hub_instance = %self.hub.metrics_hub_id(),
                need_bucket = index,
                evaluations = total,
                plain_evaluations = bucket.evaluations(PullKind::Plain),
                subscribe_evaluations = bucket.evaluations(PullKind::Subscribe),
                resync_evaluations = bucket.evaluations(PullKind::Resync),
                resubscribe_evaluations = bucket.evaluations(PullKind::Resubscribe),
                catchup_evaluations = bucket.evaluations(PullKind::Catchup),
                plain_failures = bucket.failures(PullKind::Plain),
                subscribe_failures = bucket.failures(PullKind::Subscribe),
                resync_failures = bucket.failures(PullKind::Resync),
                resubscribe_failures = bucket.failures(PullKind::Resubscribe),
                catchup_failures = bucket.failures(PullKind::Catchup),
                cancelled_evaluations = bucket.cancelled_evaluations,
                cancelled_after_sql_attempt = bucket.cancelled_after_sql_attempt,
                evaluations_reaching_sql = bucket.evaluations_reaching_sql,
                output_rows = bucket.output_rows,
                attention_candidate_vm_progress_callbacks_1000 = bucket.attention_candidate_vm_progress_callbacks_1000,
                declared_sql_vm_progress_callbacks_1000 = bucket.declared_sql_vm_progress_callbacks_1000,
                vm_work_evaluations = bucket.vm_callback_histogram.iter().sum::<u64>(),
                p50_vm_progress_callbacks_1000_bound = bucket.vm_callback_bound(50),
                p95_vm_progress_callbacks_1000_bound = bucket.vm_callback_bound(95),
                p50_duration_ms_bound = bucket.duration_bound(50),
                p95_duration_ms_bound = bucket.duration_bound(95),
                "live need synchronous pull evaluations"
            );
        }
    }

    /// Drain every connection's dirty queue once, rotating the start index
    /// for inter-connection fairness. Each connection spends its own budget;
    /// deferred subscriptions stay queued in dirtied order. Debounced entries
    /// wait out the remainder of `DEBOUNCE_MS` after the last content wake;
    /// forcing entries skip the wait. Stale flushes go first, ungated by
    /// debounce or budget: they carry ids, not computations.
    pub async fn drain(&mut self) {
        let tokens = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .connection_tokens();
        for token in &tokens {
            self.flush_stale_once(token);
        }
        loop {
            let tokens = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .connection_tokens();
            if tokens.is_empty() {
                return;
            }
            let mut progress = false;
            for index in 0..tokens.len() {
                let token = tokens[(self.rotation + index) % tokens.len()].clone();
                if self.drain_one(&token).await {
                    progress = true;
                }
            }
            self.rotation = self.rotation.wrapping_add(1);
            if !progress {
                return;
            }
        }
    }

    /// One `need-stale` flush attempt for a connection (§2.4): take this
    /// connection's stale ids (live flags plus closure tombstones — only
    /// this connection's) and `try_send` a single frame naming exactly
    /// them. A full sink restores the set for the next pass; a closed sink
    /// removes the connection. At most once per `drain`, so a persistently
    /// full sink waits for the next wake instead of spinning.
    fn flush_stale_once(&mut self, token: &ConnectionToken) {
        let (ids, sender) = {
            let mut registry = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned");
            if !registry.stale_pending(token) {
                return;
            }
            let ids = registry.take_stale_ids(token);
            if ids.is_empty() {
                return;
            }
            (ids, registry.sink_sender(token))
        };
        let Some(sender) = sender else {
            self.hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .restore_stale_ids(token, ids);
            return;
        };
        let frame = crate::need_subscriptions::NeedSinkFrame::Stale(
            crate::need_subscriptions::NeedStaleFrame {
                version: crate::need_subscriptions::NEED_FRAME_VERSION.to_string(),
                subscriptions: ids.iter().map(|id| id.as_str().to_string()).collect(),
            },
        );
        match crate::need_subscriptions::sink_outcome(sender.try_send(frame)) {
            crate::need_subscriptions::SinkOutcome::Sent => {}
            crate::need_subscriptions::SinkOutcome::Stale => {
                self.hub
                    .need_registry()
                    .lock()
                    .expect("need registry poisoned")
                    .restore_stale_ids(token, ids);
            }
            crate::need_subscriptions::SinkOutcome::Closed => {
                self.hub
                    .need_registry()
                    .lock()
                    .expect("need registry poisoned")
                    .remove_connection(token);
            }
        }
    }

    /// Pop and re-run one dirty subscription on `token`. Returns whether a
    /// re-run happened (a pop without budget or within debounce is not
    /// progress: the entry stays queued).
    async fn drain_one(&mut self, token: &ConnectionToken) -> bool {
        let entry = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .peek_dirty(token);
        let Some(entry) = entry else {
            return false;
        };
        if !entry.forcing && self.debounce_due().is_some() {
            return false;
        }
        if !self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .try_take_budget(token, self.now_ms())
        {
            // Counts failed budget attempts, not distinct subscriptions or
            // re-runs. The queued entry remains eligible on the next drain.
            if let Some(state) = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .subscription_state(token, &entry.id)
            {
                self.hub
                    .need_registry()
                    .lock()
                    .expect("need registry poisoned")
                    .note_clock_budget_deferred(token, &entry.id);
                self.hub
                    .need_metrics()
                    .lock()
                    .expect("need metrics poisoned")
                    .note_scheduling_outcome(&state.need, Outcome::BudgetDeferred);
            }
            return false;
        }
        // Pop only once budget is spent: the permit pays for this re-run.
        let Some(entry) = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .pop_dirty(token)
        else {
            return false;
        };
        self.rerun_one(token, &entry.id, entry.forcing).await;
        true
    }

    /// Milliseconds until debounced entries may run, if the last content
    /// wake is still inside the debounce window.
    fn debounce_due(&self) -> Option<u64> {
        let woke = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .last_content_event_at()?;
        let elapsed = woke.elapsed().as_millis() as u64;
        if elapsed < crate::need_subscriptions::DEBOUNCE_MS {
            Some(crate::need_subscriptions::DEBOUNCE_MS - elapsed)
        } else {
            None
        }
    }

    /// Re-run one popped subscription: full evaluation under the viewer's
    /// current authority, digest gate, emit gate, then send or close. The
    /// record's dirty flag was cleared by the pop only in the queue sense —
    /// a trigger firing mid-run sets `record.dirty` again through the
    /// registry, and the next drain picks it up (one in flight plus a flag).
    async fn rerun_one(&mut self, token: &ConnectionToken, id: &SubscriptionId, forcing: bool) {
        let state = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .subscription_state(token, id);
        let Some(state) = state else {
            return;
        };
        if state.lifecycle != crate::need_subscriptions::SubscriptionLifecycle::Active {
            return;
        }
        // Clear the dirty flag as this run starts; concurrent triggers
        // re-set it for the next pass.
        let dirty = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .clear_dirty(token, id);
        let Some(dirty) = dirty else {
            return;
        };
        let mut observation = RunObservation {
            hub: Arc::clone(&self.hub),
            token: token.clone(),
            id: id.clone(),
            need: state.need.clone(),
            started: Instant::now(),
            dirty,
            outcome: Outcome::Retried,
            output_rows: 0,
            evaluation_started: false,
            vm_work: VmWorkObserver::default(),
            vm_work_in_flight: false,
            retry_work: false,
            forcing,
            keyed_dirty: state.keyed_dirty,
            saw_content_event: state.saw_content_event,
        };
        // A vanished connection is teardown: drop the frame, never emit.
        // Authority is resolved fresh (hook when wired): a scheduler wake
        // racing ahead of the SSE loop's role update must still see the
        // revocation. Revoked access closes with `access_lost`, never emits.
        let caller = match self.resolve_caller(token).await {
            AccessVerdict::Valid(caller) => caller,
            AccessVerdict::Revoked => {
                self.close(token, id, NeedClosedReason::AccessLost).await;
                observation.outcome = Outcome::Closed;
                return;
            }
            AccessVerdict::Gone => {
                observation.outcome = Outcome::Closed;
                return;
            }
        };
        // Eviction is not hub teardown. Preserve the drained work until a
        // usable handle is accepted; terminal teardown clears the registry.
        #[cfg(test)]
        retirement_test_boundary("evaluation");
        let Some(db) = self.hub.current_db() else {
            observation.retry_work = !self.hub.is_terminal();
            observation.outcome = if observation.retry_work {
                Outcome::Retried
            } else {
                Outcome::Closed
            };
            return;
        };
        observation.vm_work_in_flight = true;
        let rerun = rerun_snapshot_for_scheduler(
            &db,
            &caller,
            &state.binding.package,
            &state.binding.install_event_id,
            &mut observation.evaluation_started,
            Some(&observation.vm_work),
        )
        .await;
        observation.vm_work_in_flight = false;
        match rerun {
            Err(error) => {
                // A refusal closes; an infrastructure failure re-queues for
                // the next pass instead of dropping the subscription.
                match refusal_code_of(&error) {
                    Some(code) => {
                        self.close(token, id, closed_reason_for_refusal(&code))
                            .await;
                        observation.outcome = Outcome::Closed;
                    }
                    None => observation.retry_work = true,
                }
            }
            Ok((result, digest, gate, clock_replay_safe)) => {
                let completed_at = Instant::now();
                self.hub
                    .need_registry()
                    .lock()
                    .expect("need registry poisoned")
                    .note_clock_snapshot_evaluated(
                        token,
                        id,
                        observation.dirty.clock_schedule_epoch,
                        observation.dirty.clock_due_generation,
                        completed_at,
                    );
                observation.output_rows = materialized_output_rows(&result);
                if state.baseline.as_deref() == Some(digest.as_str()) {
                    observation.outcome = if self
                        .hub
                        .need_registry()
                        .lock()
                        .expect("need registry poisoned")
                        .note_quiet_evaluation(
                            token,
                            id,
                            &digest,
                            snapshot_clock_bindings(&result),
                            clock_replay_safe,
                        ) {
                        Outcome::Quiet
                    } else {
                        Outcome::Coalesced
                    };
                } else {
                    observation.outcome = self
                        .emit(
                            token,
                            id,
                            &state.baseline,
                            result,
                            &digest,
                            &gate,
                            clock_replay_safe,
                        )
                        .await;
                }
                observation.retry_work |= observation.outcome == Outcome::Retried;
                if observation.outcome != Outcome::Closed
                    && (state.keyed_dirty || observation.dirty.trigger != Trigger::Content)
                {
                    observation.retry_work |= self
                        .rerun_keyed_variants(token, id, &state, &caller, &db, &gate)
                        .await;
                }
            }
        }
    }

    /// A content wake schedules comparisons only. No keyed flag or frame
    /// leaves the server until one viewer-scoped re-read differs from the
    /// stored fingerprint. Each declared key holds at most 32 variants.
    async fn rerun_keyed_variants(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        state: &crate::need_subscriptions::SubscriptionRecord,
        caller: &Caller,
        db: &crate::db::Db,
        gate: &crate::need_subscriptions::GateSnapshot,
    ) -> bool {
        for (key, variant) in state.keyed.variants_with_key() {
            let fresh_revision = match rerun_keyed_for_scheduler(
                db,
                caller,
                &state.binding.package,
                &state.binding.install_event_id,
                key,
                variant.params.clone(),
            )
            .await
            {
                Ok(revision) => revision,
                Err(error) => {
                    if let Some(code) = refusal_code_of(&error) {
                        self.close(token, id, closed_reason_for_refusal(&code))
                            .await;
                    } else {
                        return true;
                    }
                    return false;
                }
            };
            if fresh_revision == variant.revision {
                continue;
            }
            let current_caller = match self.resolve_caller(token).await {
                AccessVerdict::Valid(caller) => caller,
                AccessVerdict::Revoked => {
                    self.close(token, id, NeedClosedReason::AccessLost).await;
                    return false;
                }
                AccessVerdict::Gone => return false,
            };
            #[cfg(test)]
            retirement_test_boundary("keyed");
            let Some(current_db) = self.hub.current_db() else {
                return !self.hub.is_terminal();
            };
            let fresh_gate = match snapshot_surface_gates(
                &current_db,
                &current_caller,
                &state.binding.package,
                &state.binding.install_event_id,
            )
            .await
            {
                Ok(gate) => gate,
                Err(error) => {
                    if let Some(code) = refusal_code_of(&error) {
                        self.close(token, id, closed_reason_for_refusal(&code))
                            .await;
                    } else {
                        return true;
                    }
                    return false;
                }
            };
            if let Some(reason) = gate_drift_reason(gate, &fresh_gate) {
                self.close(token, id, reason).await;
                return false;
            }
            let disposition = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .emit_keyed_hint(
                    token,
                    id,
                    key,
                    &variant.params_digest,
                    &variant.revision,
                    &fresh_revision,
                );
            if disposition != crate::need_subscriptions::EmitDisposition::Sent {
                if matches!(
                    disposition,
                    crate::need_subscriptions::EmitDisposition::NoSink
                        | crate::need_subscriptions::EmitDisposition::Stale
                ) {
                    return true;
                }
                return false;
            }
        }
        false
    }

    /// Re-queue after an infrastructure failure (never a refusal): the next
    /// pass retries instead of silently dropping the subscription.
    fn requeue(&mut self, token: &ConnectionToken, id: &SubscriptionId) {
        self.hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .enqueue_dirty(token, id, false);
    }

    /// Emit path (§2.3): re-check the surface gates without row reads, then
    /// send through the serialized registry entry point: the final
    /// active/baseline/access check, the synchronous `try_send`, and the
    /// delivery/baseline update happen under one registry lock — the same
    /// lock teardown takes — with no await inside. Teardown wins: any
    /// mismatch drops the frame silently. `delivery` rises by 1 per emitted
    /// frame; a `null` (over-cap) body still advances baseline and delivery
    /// so the host never loops.
    #[allow(clippy::too_many_arguments)]
    async fn emit(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        compared_baseline: &Option<String>,
        result: serde_json::Value,
        digest: &str,
        gate: &crate::need_subscriptions::GateSnapshot,
        clock_replay_safe: bool,
    ) -> Outcome {
        let state = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .subscription_state(token, id);
        let Some(state) = state else {
            return Outcome::Coalesced;
        };
        // Fresh authority again at emit: the re-run's evaluation and this
        // gate are separated by awaits, and access may have been lost
        // between them. Revoked closes; vanished drops silently.
        let caller = match self.resolve_caller(token).await {
            AccessVerdict::Valid(caller) => caller,
            AccessVerdict::Revoked => {
                self.close(token, id, NeedClosedReason::AccessLost).await;
                return Outcome::Closed;
            }
            AccessVerdict::Gone => return Outcome::Coalesced,
        };
        // Current handle again at emit: evaluation and gate are separated
        // by awaits, and replacement may have landed between them.
        #[cfg(test)]
        retirement_test_boundary("emit");
        let Some(db) = self.hub.current_db() else {
            return if self.hub.is_terminal() {
                Outcome::Closed
            } else {
                Outcome::Retried
            };
        };
        let fresh = match snapshot_surface_gates(
            &db,
            &caller,
            &state.binding.package,
            &state.binding.install_event_id,
        )
        .await
        {
            Ok(fresh) => fresh,
            Err(error) => match refusal_code_of(&error) {
                Some(code) => {
                    self.close(token, id, closed_reason_for_refusal(&code))
                        .await;
                    return Outcome::Closed;
                }
                None => {
                    self.requeue(token, id);
                    return Outcome::Retried;
                }
            },
        };
        if let Some(reason) = gate_drift_reason(gate, &fresh) {
            self.close(token, id, reason).await;
            return Outcome::Closed;
        }
        let rows_sha256 = result
            .get("revision")
            .and_then(|revision| revision.get("rows_sha256"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        // M1 slice 1: the delivered frame carries the stamp of the
        // delivered snapshot evaluation (the max of its per-need statement
        // clocks); exact per-need bind clocks ride in each need's
        // `input.sql[key].now_ms_ms`. The registry nulls it when the body
        // is over cap (`result: None` travels stamp-less; the host
        // re-reads for rows).
        let as_of_ms = result.get("as_of_ms").and_then(serde_json::Value::as_i64);
        // One serialized step: final check, send, and state update share
        // the registry lock. No await inside; `try_send` never blocks.
        let clocks = snapshot_clock_bindings(&result);
        let disposition = self
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .emit_need_with_clocks(
                token,
                id,
                compared_baseline.as_deref(),
                digest,
                &rows_sha256,
                result,
                as_of_ms,
                clocks,
                clock_replay_safe,
            );
        match disposition {
            crate::need_subscriptions::EmitDisposition::Closed => {
                self.hub
                    .need_registry()
                    .lock()
                    .expect("need registry poisoned")
                    .remove_connection(token);
                Outcome::Closed
            }
            crate::need_subscriptions::EmitDisposition::NoSink => {
                // No sink registered yet (SSE layer attaches on connect):
                // keep the entry queued so the next pass retries instead
                // of dropping the subscription.
                self.requeue(token, id);
                Outcome::Retried
            }
            crate::need_subscriptions::EmitDisposition::Sent => Outcome::Delivered,
            crate::need_subscriptions::EmitDisposition::Stale => Outcome::Stale,
            crate::need_subscriptions::EmitDisposition::Gone => Outcome::Coalesced,
        }
    }

    /// Close path: one serialized registry step sends `need-closed` (or
    /// tombstones the id on a full sink) and removes the record, so the
    /// closure can never be lost between send and teardown. The record never
    /// lingers either way.
    async fn close(
        &mut self,
        token: &ConnectionToken,
        id: &SubscriptionId,
        reason: NeedClosedReason,
    ) {
        self.hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .close_subscription(token, id, reason);
    }

    /// Resolve the `Caller` a re-run or emit evaluates under, with *current*
    /// authority. The connection's hook (installed by its SSE stream) is
    /// awaited on every call; the registry footing is only the
    /// standalone/test fallback when no stream installed one. Guests
    /// evaluate with their own account grants only, never the members
    /// baseline. `Revoked` vs `Gone` matters: revoked access closes the
    /// subscription with `access_lost`, a vanished connection drops silently.
    async fn resolve_caller(&self, token: &ConnectionToken) -> AccessVerdict {
        let (footing, hook) = {
            let registry = self
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned");
            (
                registry.connection_footing(token),
                registry.access_hook(token),
            )
        };
        let Some((account, stale_member)) = footing else {
            return AccessVerdict::Gone;
        };
        match hook {
            None => AccessVerdict::Valid(Box::new(
                Caller::authenticated(account).with_hosting_member(stale_member),
            )),
            Some(hook) => match hook().await {
                Some(member) => AccessVerdict::Valid(Box::new(
                    Caller::authenticated(account).with_hosting_member(member),
                )),
                None => AccessVerdict::Revoked,
            },
        }
    }
}

/// Extract a `[code]` refusal from a tool error message. `None` means
/// infrastructure noise (pool, serialization), never a gate verdict.
fn refusal_code_of(error: &crate::error::Error) -> Option<String> {
    let message = error.to_string();
    let open = message.rfind('[')?;
    let code = message.get(open + 1..)?.strip_suffix(']')?;
    if code.is_empty() || code.contains(char::is_whitespace) {
        return None;
    }
    Some(code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::need_subscriptions::{params_digest, SurfaceBinding};

    fn vector(authorization: i64, control: i64) -> crate::realtime::InboxInvalidationVector {
        crate::realtime::InboxInvalidationVector {
            content: 0,
            awareness: 0,
            candidates: 0,
            control,
            authorization,
        }
    }

    async fn scheduler_with_subscription() -> (NeedScheduler, ConnectionToken, SubscriptionId) {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (_db, hub) = RealtimeHub::attach(db, None).await.unwrap();
        let digest = params_digest(None);
        let token = hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .register_connection("alice", "db-1", true);
        let id = hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1"),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .activate(&token, &id, "digest-1");
        (NeedScheduler::new(hub), token, id)
    }

    #[tokio::test]
    async fn scheduler_clock_poll_queues_only_due_clock_subscriptions() {
        let (scheduler, token, id) = scheduler_with_subscription().await;
        {
            let registry = scheduler.hub.need_registry();
            let mut registry = registry.lock().expect("need registry poisoned");
            registry.activate_with_clock(&token, &id, "digest-1", true);
            registry.set_clock_due_for_test(&token, &id, Instant::now() - Duration::from_secs(1));
        }
        assert_eq!(scheduler.poll_clocks_once(), 1);
        let queued = scheduler
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .pop_dirty(&token)
            .expect("due subscription queued");
        assert_eq!(queued.id, id);
        assert!(queued.forcing);
        assert_eq!(scheduler.poll_clocks_once(), 0);
    }

    #[tokio::test]
    async fn clock_probe_repairs_lost_grant_and_control_wakes_before_comparing() {
        for trigger in [Trigger::Grant, Trigger::Control] {
            let (mut scheduler, token, id) = scheduler_with_subscription().await;
            scheduler
                .hub
                .need_registry()
                .lock()
                .unwrap()
                .activate_with_evaluation(
                    &token,
                    &id,
                    "digest-1",
                    true,
                    Some(std::collections::BTreeMap::from([(
                        "lane.clock".to_string(),
                        10,
                    )])),
                );
            let observed = scheduler.hub.inbox_invalidation_vector().await.unwrap();
            let mut missed = observed.clone();
            match trigger {
                Trigger::Grant => missed.authorization -= 1,
                Trigger::Control => missed.control -= 1,
                _ => unreachable!(),
            }
            scheduler.last_vector = Some(missed);
            scheduler.probe_clock_once().await;
            let metrics = scheduler.hub.need_metrics().lock().unwrap().clone();
            assert_eq!(metrics.clock_probe_attempts, 0);
            assert_eq!(metrics.clock_probe_suppressed[2], 1);
            let needs = scheduler.hub.need_registry().lock().unwrap();
            let state = needs.subscription_state(&token, &id).unwrap();
            assert!(state.dirty);
            assert_eq!(state.dirty_trigger, Some(trigger));
            assert_eq!(needs.dirty_len(&token), 1);
        }
    }

    #[tokio::test]
    async fn install_gate_refusal_does_not_attribute_a_sql_attempt() {
        let (mut scheduler, token, id) = scheduler_with_subscription().await;
        {
            let mut registry = scheduler.hub.need_registry().lock().unwrap();
            registry.activate_with_clock(&token, &id, "digest-1", true);
            registry.set_clock_due_for_test(&token, &id, Instant::now() - Duration::from_secs(1));
            registry.mark_content_event_with_act(Some(77));
            registry.mark_due_clock_ticks(Instant::now());
            registry.enqueue_dirty_with_trigger(&token, &id, true, Trigger::Content);
        }
        // This fixture has a valid connection but no installed alpha tab.
        // The live-read gate refuses before the first snapshot SQL query.
        scheduler.drain().await;
        let metrics = scheduler.hub.need_metrics().lock().unwrap().clone();
        assert_eq!(metrics.known_act_evaluation_attempt_associations, 0);
        assert_eq!(metrics.pre_evaluation_association_drops, 1);
        let bucket =
            &metrics.buckets[crate::need_metrics::NeedMetrics::need_bucket("attention.query.v1")];
        assert_eq!(bucket.reruns, 1);
        assert_eq!(bucket.outcome(Outcome::Closed), 1);
        let clock = scheduler
            .hub
            .need_registry()
            .lock()
            .unwrap()
            .clock_due_audit(Instant::now());
        assert_eq!(clock.due_periods, 1);
        assert_eq!(clock.covered_periods, 0);
        assert_eq!(clock.removed_unserved_periods, 1);
    }

    #[tokio::test]
    async fn content_debounce_starts_before_broadcast_receiver_runs() {
        let (scheduler, token, _) = scheduler_with_subscription().await;
        scheduler
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .mark_content_event();
        assert!(scheduler.debounce_due().is_some());
        assert_eq!(
            scheduler
                .hub
                .need_registry()
                .lock()
                .unwrap()
                .dirty_len(&token),
            1
        );
    }

    #[tokio::test]
    async fn first_vector_without_baseline_forces() {
        let (mut scheduler, token, _id) = scheduler_with_subscription().await;
        // No seeded baseline (seed read failed): the first vector forces,
        // so a grant/control change at startup cannot miss its wake.
        scheduler.note_inbox_vector(vector(1, 0));
        let queued = scheduler
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .pop_dirty(&token)
            .unwrap();
        assert!(queued.forcing);
    }

    #[tokio::test]
    async fn seeded_baseline_only_forces_on_grant_or_control() {
        let (mut scheduler, token, _id) = scheduler_with_subscription().await;
        scheduler.last_vector = Some(vector(1, 5));
        // Awareness/candidate-only movement is the inbox bell's business.
        scheduler.note_inbox_vector(vector(1, 5));
        assert!(scheduler
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .pop_dirty(&token)
            .is_none());
        // Authorization movement forces; control movement forces.
        scheduler.note_inbox_vector(vector(2, 5));
        scheduler.note_inbox_vector(vector(2, 6));
        let hub = scheduler.hub.clone();
        let first = hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .pop_dirty(&token)
            .unwrap();
        assert!(first.forcing);
    }

    #[tokio::test]
    async fn missed_delivery_probe_requires_stable_fences_and_clean_state() {
        let (scheduler, token, id) = scheduler_with_subscription().await;
        let state = scheduler
            .hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .subscription_state(&token, &id)
            .unwrap();
        let vector = vector(1, 2);
        let mismatch = ProbeComparison {
            before_content: 9,
            after_content: Some(9),
            before_vector: &vector,
            after_vector: Some(&vector),
            scheduler_vector: Some(&vector),
            sampled_state: &state,
            current_state: Some(&state),
            sampled_digest: "new-visible-digest",
        };
        assert_eq!(mismatch.verdict(), Some(true));
        assert_eq!(
            ProbeComparison {
                sampled_digest: "digest-1",
                ..mismatch
            }
            .verdict(),
            Some(false)
        );
        assert_eq!(
            ProbeComparison {
                after_content: Some(10),
                ..mismatch
            }
            .verdict(),
            None
        );
        let mut dirty = state.clone();
        dirty.dirty = true;
        assert_eq!(
            ProbeComparison {
                current_state: Some(&dirty),
                ..mismatch
            }
            .verdict(),
            None
        );
    }
}

#[cfg(test)]
tokio::task_local! {
    static RETIREMENT_BOUNDARY: Arc<dyn Fn(&str) + Send + Sync>;
}
#[cfg(test)]
fn retirement_test_boundary(phase: &str) {
    let _ = RETIREMENT_BOUNDARY.try_with(|hook| hook(phase));
}
#[cfg(test)]
#[path = "personal_registry_scheduler_tests.rs"]
mod personal_registry_scheduler_tests;
