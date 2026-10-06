//! Internal, bounded live-need measurement (M3). No field in this module is
//! serialized into a tool result or SSE frame. The hub owns one accumulator
//! per database; labels are fixed-size buckets, never identities or digests.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const NEED_BUCKETS: usize = 16;
pub const COMMIT_WINDOW: usize = 256;
const LATENCY_BINS_MS: [u64; 17] = [
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    1_024,
    2_048,
    4_096,
    8_192,
    16_384,
    32_768,
    u64::MAX,
];
/// Progress callbacks are coarse units of 1,000 SQLite VM instructions.
/// Zero means the measured phase used fewer than 1,000 instructions.
const VM_CALLBACK_BINS: [u64; 18] = [
    0,
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    1_024,
    2_048,
    4_096,
    8_192,
    16_384,
    32_768,
    u64::MAX,
];

#[derive(Clone, Default)]
pub struct VmWorkObserver {
    attention_candidate: Arc<AtomicU64>,
    declared_sql: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmWorkSample {
    pub attention_candidate_callbacks: u64,
    pub declared_sql_callbacks: u64,
}

impl VmWorkSample {
    fn total(self) -> u64 {
        self.attention_candidate_callbacks
            .saturating_add(self.declared_sql_callbacks)
    }
}

impl VmWorkObserver {
    pub fn attention_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.attention_candidate)
    }

    pub fn declared_sql_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.declared_sql)
    }

    pub fn sample(&self) -> VmWorkSample {
        VmWorkSample {
            attention_candidate_callbacks: self.attention_candidate.load(Ordering::Relaxed),
            declared_sql_callbacks: self.declared_sql.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Content,
    Grant,
    Control,
    Demotion,
    Tick,
    Resync,
    Subscribe,
    Retry,
}

impl Trigger {
    const fn index(self) -> usize {
        self as usize
    }

    /// A gate or subscription wake must retain its attribution when a
    /// content event lands while the same re-run is still queued.
    pub const fn is_forcing(self) -> bool {
        !matches!(self, Self::Content | Self::Retry)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    Quiet,
    Closed,
    Coalesced,
    Stale,
    BudgetDeferred,
    Retried,
}

impl Outcome {
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NeedBucket {
    pub reruns: u64,
    pub reruns_by_trigger: [u64; 8],
    pub output_rows: u64,
    pub outcomes: [u64; 7],
    pub duration_ms: [u64; 17],
    pub trigger_to_delivery_ms: [u64; 17],
    pub attention_candidate_vm_progress_callbacks_1000: u64,
    pub declared_sql_vm_progress_callbacks_1000: u64,
    pub vm_callback_histogram: [u64; 18],
    /// A cancelled evaluation may still have worker-side VM work in flight.
    /// Those partial counts are excluded from the totals and histogram.
    pub incomplete_vm_evaluations: u64,
}

impl NeedBucket {
    pub fn outcome(&self, outcome: Outcome) -> u64 {
        self.outcomes[outcome.index()]
    }

    pub fn trigger(&self, trigger: Trigger) -> u64 {
        self.reruns_by_trigger[trigger.index()]
    }

    /// Histogram upper bound, in milliseconds. This is deliberately a bound
    /// rather than a falsely precise percentile from bucketed observations.
    pub fn delivery_latency_bound(&self, percentile: u64) -> Option<u64> {
        histogram_bound(&self.trigger_to_delivery_ms, percentile)
    }

    pub fn duration_bound(&self, percentile: u64) -> Option<u64> {
        histogram_bound(&self.duration_ms, percentile)
    }

    pub fn vm_callback_bound(&self, percentile: u64) -> Option<u64> {
        histogram_bound_with_bins(&self.vm_callback_histogram, &VM_CALLBACK_BINS, percentile)
    }
}

fn histogram_bound(histogram: &[u64; 17], percentile: u64) -> Option<u64> {
    histogram_bound_with_bins(histogram, &LATENCY_BINS_MS, percentile)
}

fn histogram_bound_with_bins<const N: usize>(
    histogram: &[u64; N],
    bounds: &[u64; N],
    percentile: u64,
) -> Option<u64> {
    let total: u64 = histogram.iter().sum();
    if total == 0 {
        return None;
    }
    let target = total.saturating_mul(percentile).div_ceil(100);
    let mut seen = 0;
    for (index, count) in histogram.iter().enumerate() {
        seen += count;
        if seen >= target {
            return Some(bounds[index]);
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActSample {
    /// Internal transaction identity from committed content_events.act.
    pub act: i64,
    pub content_events: u64,
    /// Distinct subscription ids dirtied by this act, including subscriptions
    /// created between rows of the same act.
    pub distinct_dirtied_targets: u64,
    /// Snapshot-query attempts associated with this act. One attempt may
    /// cover several coalesced acts, so sums are non-additive. A gate closure
    /// before the query starts is counted as a coverage loss instead.
    pub evaluation_attempt_associations: u64,
}

#[derive(Clone, Copy)]
pub struct RerunSample<'a> {
    pub need: &'a str,
    pub trigger: Trigger,
    pub outcome: Outcome,
    pub duration: Duration,
    pub output_rows: usize,
    pub trigger_to_delivery: Option<Duration>,
    pub content_acts: &'a [i64],
    pub unknown_act: bool,
    pub evaluation_started: bool,
    pub vm_work: VmWorkSample,
    pub vm_work_complete: bool,
}

/// Synchronous tool-handler evaluations are measured separately from push
/// scheduler re-runs. A resync that also requests a subscription has its own
/// kind so neither operation is hidden in the push delivery ratio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullKind {
    Plain,
    Subscribe,
    Resync,
    Resubscribe,
    Catchup,
}

impl PullKind {
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PullBucket {
    pub evaluations: [u64; 5],
    pub failures: [u64; 5],
    /// Futures cancelled before returning do not enter `evaluations` or
    /// contribute a VM-work sample; surface the missing coverage explicitly.
    pub cancelled_evaluations: u64,
    pub cancelled_after_sql_attempt: u64,
    /// Evaluations reaching at least one snapshot SQL attempt, not the
    /// number of statements (one snapshot may execute several needs).
    pub evaluations_reaching_sql: u64,
    pub output_rows: u64,
    pub duration_ms: [u64; 17],
    pub attention_candidate_vm_progress_callbacks_1000: u64,
    pub declared_sql_vm_progress_callbacks_1000: u64,
    pub vm_callback_histogram: [u64; 18],
}

impl PullBucket {
    pub fn evaluations(&self, kind: PullKind) -> u64 {
        self.evaluations[kind.index()]
    }

    pub fn failures(&self, kind: PullKind) -> u64 {
        self.failures[kind.index()]
    }

    pub fn duration_bound(&self, percentile: u64) -> Option<u64> {
        histogram_bound(&self.duration_ms, percentile)
    }

    pub fn vm_callback_bound(&self, percentile: u64) -> Option<u64> {
        histogram_bound_with_bins(&self.vm_callback_histogram, &VM_CALLBACK_BINS, percentile)
    }
}

#[derive(Clone, Debug)]
pub struct NeedMetrics {
    pub known_content_acts: u64,
    pub known_act_distinct_dirtied_targets: u64,
    pub known_act_evaluation_attempt_associations: u64,
    pub unknown_act_events: u64,
    pub unknown_act_target_pairs: u64,
    pub unknown_act_evaluation_attempt_associations: u64,
    pub content_events: u64,
    pub content_event_queue_inserts: u64,
    pub content_event_pending_targets: u64,
    pub content_event_coalesced: u64,
    pub triggers: [u64; 8],
    pub buckets: [NeedBucket; NEED_BUCKETS],
    pub pull_buckets: [PullBucket; NEED_BUCKETS],
    pub probe_attempts: u64,
    pub probe_mismatches: u64,
    pub probe_inconclusive: u64,
    pub clock_probe_attempts: u64,
    pub clock_probe_mismatches: u64,
    /// Suppression buckets: no eligible subscription, unstable content,
    /// unstable authority, recent write, access/db, evaluation, and race.
    pub clock_probe_suppressed: [u64; 7],
    pub attribution_overflows: u64,
    pub pre_evaluation_association_drops: u64,
    pub subscribe_catchup_association_drops: u64,
    pub recent_acts: VecDeque<ActSample>,
}

impl Default for NeedMetrics {
    fn default() -> Self {
        Self {
            known_content_acts: 0,
            known_act_distinct_dirtied_targets: 0,
            known_act_evaluation_attempt_associations: 0,
            unknown_act_events: 0,
            unknown_act_target_pairs: 0,
            unknown_act_evaluation_attempt_associations: 0,
            content_events: 0,
            content_event_queue_inserts: 0,
            content_event_pending_targets: 0,
            content_event_coalesced: 0,
            triggers: [0; 8],
            buckets: std::array::from_fn(|_| NeedBucket::default()),
            pull_buckets: std::array::from_fn(|_| PullBucket::default()),
            probe_attempts: 0,
            probe_mismatches: 0,
            probe_inconclusive: 0,
            clock_probe_attempts: 0,
            clock_probe_mismatches: 0,
            clock_probe_suppressed: [0; 7],
            attribution_overflows: 0,
            pre_evaluation_association_drops: 0,
            subscribe_catchup_association_drops: 0,
            recent_acts: VecDeque::new(),
        }
    }
}

impl NeedMetrics {
    pub fn note_subscribe_catchup_association_drops(&mut self, count: u64) {
        self.subscribe_catchup_association_drops += count;
    }

    pub fn need_bucket(need: &str) -> usize {
        let hash = Sha256::digest(need.as_bytes());
        usize::from(hash[0]) % NEED_BUCKETS
    }

    pub fn note_content_event(
        &mut self,
        act: Option<i64>,
        distinct_act_targets: usize,
        targets: usize,
        newly_queued: usize,
        pending: usize,
    ) {
        self.content_events += 1;
        self.content_event_queue_inserts += newly_queued as u64;
        self.content_event_pending_targets += pending as u64;
        self.content_event_coalesced +=
            targets.saturating_sub(pending).saturating_sub(newly_queued) as u64;
        self.triggers[Trigger::Content.index()] += 1;
        if let Some(act) = act {
            self.known_act_distinct_dirtied_targets += distinct_act_targets as u64;
            if self.recent_acts.back().is_none_or(|last| last.act != act) {
                self.known_content_acts += 1;
                if self.recent_acts.len() == COMMIT_WINDOW {
                    self.recent_acts.pop_front();
                }
                self.recent_acts.push_back(ActSample {
                    act,
                    content_events: 0,
                    distinct_dirtied_targets: 0,
                    evaluation_attempt_associations: 0,
                });
            }
            let sample = self
                .recent_acts
                .back_mut()
                .expect("act sample just inserted");
            sample.content_events += 1;
            sample.distinct_dirtied_targets += distinct_act_targets as u64;
        } else {
            self.unknown_act_events += 1;
            self.unknown_act_target_pairs += targets as u64;
        }
    }

    pub fn note_trigger(&mut self, trigger: Trigger) {
        self.triggers[trigger.index()] += 1;
    }

    pub fn note_rerun(&mut self, sample: RerunSample<'_>) {
        let bucket = &mut self.buckets[Self::need_bucket(sample.need)];
        bucket.reruns += 1;
        bucket.reruns_by_trigger[sample.trigger.index()] += 1;
        bucket.outcomes[sample.outcome.index()] += 1;
        // `output_rows` is the number materialized for the need. It is not
        // SQLite/Postgres physical rows scanned; the engines do not expose
        // that measurement through `query_sql` today.
        bucket.output_rows += sample.output_rows as u64;
        bucket.duration_ms[latency_bin(sample.duration)] += 1;
        if let Some(latency) = sample.trigger_to_delivery {
            bucket.trigger_to_delivery_ms[latency_bin(latency)] += 1;
        }
        if sample.evaluation_started {
            if sample.vm_work_complete {
                bucket.attention_candidate_vm_progress_callbacks_1000 +=
                    sample.vm_work.attention_candidate_callbacks;
                bucket.declared_sql_vm_progress_callbacks_1000 +=
                    sample.vm_work.declared_sql_callbacks;
                bucket.vm_callback_histogram[vm_callback_bin(sample.vm_work.total())] += 1;
            } else {
                bucket.incomplete_vm_evaluations += 1;
            }
        }
        if sample.evaluation_started {
            for act in sample.content_acts {
                self.known_act_evaluation_attempt_associations += 1;
                if let Some(commit) = self.recent_acts.iter_mut().find(|c| c.act == *act) {
                    commit.evaluation_attempt_associations += 1;
                } else {
                    self.attribution_overflows += 1;
                }
            }
            self.unknown_act_evaluation_attempt_associations += u64::from(sample.unknown_act);
        } else {
            self.pre_evaluation_association_drops +=
                sample.content_acts.len() as u64 + u64::from(sample.unknown_act);
        }
    }

    pub fn note_scheduling_outcome(&mut self, need: &str, outcome: Outcome) {
        self.buckets[Self::need_bucket(need)].outcomes[outcome.index()] += 1;
    }

    pub fn note_probe(&mut self, mismatch: Option<bool>) {
        match mismatch {
            Some(mismatch) => {
                self.probe_attempts += 1;
                self.probe_mismatches += u64::from(mismatch);
            }
            None => self.probe_inconclusive += 1,
        }
    }

    pub fn note_clock_probe(&mut self, mismatch: Result<bool, usize>) {
        match mismatch {
            Ok(mismatch) => {
                self.clock_probe_attempts += 1;
                self.clock_probe_mismatches += u64::from(mismatch);
            }
            Err(reason) => self.clock_probe_suppressed[reason] += 1,
        }
    }

    pub fn note_pull(
        &mut self,
        need: &str,
        kind: PullKind,
        duration: Duration,
        sql_attempted: bool,
        output_rows: Option<usize>,
        vm_work: VmWorkSample,
    ) {
        let bucket = &mut self.pull_buckets[Self::need_bucket(need)];
        bucket.evaluations[kind.index()] += 1;
        bucket.failures[kind.index()] += u64::from(output_rows.is_none());
        bucket.evaluations_reaching_sql += u64::from(sql_attempted);
        bucket.output_rows += output_rows.unwrap_or(0) as u64;
        bucket.duration_ms[latency_bin(duration)] += 1;
        if sql_attempted {
            bucket.attention_candidate_vm_progress_callbacks_1000 +=
                vm_work.attention_candidate_callbacks;
            bucket.declared_sql_vm_progress_callbacks_1000 += vm_work.declared_sql_callbacks;
            bucket.vm_callback_histogram[vm_callback_bin(vm_work.total())] += 1;
        }
    }

    pub fn note_cancelled_pull(&mut self, need: &str, sql_attempted: bool) {
        let bucket = &mut self.pull_buckets[Self::need_bucket(need)];
        bucket.cancelled_evaluations += 1;
        bucket.cancelled_after_sql_attempt += u64::from(sql_attempted);
    }
}

fn vm_callback_bin(callbacks: u64) -> usize {
    VM_CALLBACK_BINS
        .iter()
        .position(|bound| callbacks <= *bound)
        .unwrap_or(VM_CALLBACK_BINS.len() - 1)
}

fn latency_bin(duration: Duration) -> usize {
    let millis = duration.as_millis().min(u128::from(u64::MAX)) as u64;
    LATENCY_BINS_MS
        .iter()
        .position(|bound| millis <= *bound)
        .unwrap_or(LATENCY_BINS_MS.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_work_keeps_query_phases_separate_and_excludes_incomplete_pushes() {
        let mut metrics = NeedMetrics::default();
        let need = "attention.query.v1";
        let complete = VmWorkSample {
            attention_candidate_callbacks: 3,
            declared_sql_callbacks: 7,
        };
        let mut rerun = RerunSample {
            need,
            trigger: Trigger::Content,
            outcome: Outcome::Quiet,
            duration: Duration::from_millis(1),
            output_rows: 0,
            trigger_to_delivery: None,
            content_acts: &[],
            unknown_act: false,
            evaluation_started: true,
            vm_work: complete,
            vm_work_complete: true,
        };
        metrics.note_rerun(rerun);
        rerun.vm_work = VmWorkSample {
            attention_candidate_callbacks: 100,
            declared_sql_callbacks: 200,
        };
        rerun.vm_work_complete = false;
        metrics.note_rerun(rerun);
        let bucket = &metrics.buckets[NeedMetrics::need_bucket(need)];
        assert_eq!(bucket.attention_candidate_vm_progress_callbacks_1000, 3);
        assert_eq!(bucket.declared_sql_vm_progress_callbacks_1000, 7);
        assert_eq!(bucket.vm_callback_histogram.iter().sum::<u64>(), 1);
        assert_eq!(bucket.vm_callback_bound(95), Some(16));
        assert_eq!(bucket.incomplete_vm_evaluations, 1);

        metrics.note_pull(
            need,
            PullKind::Plain,
            Duration::from_millis(1),
            true,
            Some(0),
            complete,
        );
        let pull = &metrics.pull_buckets[NeedMetrics::need_bucket(need)];
        assert_eq!(pull.attention_candidate_vm_progress_callbacks_1000, 3);
        assert_eq!(pull.declared_sql_vm_progress_callbacks_1000, 7);
        assert_eq!(pull.vm_callback_bound(95), Some(16));
        metrics.note_cancelled_pull(need, true);
        let pull = &metrics.pull_buckets[NeedMetrics::need_bucket(need)];
        assert_eq!(pull.cancelled_evaluations, 1);
        assert_eq!(pull.cancelled_after_sql_attempt, 1);
        assert_eq!(pull.vm_callback_histogram.iter().sum::<u64>(), 1);
    }

    #[test]
    fn bounded_labels_commit_window_and_histogram() {
        let mut metrics = NeedMetrics::default();
        metrics.note_content_event(Some(1), 2, 2, 2, 0);
        metrics.note_rerun(RerunSample {
            need: "attention.query.v1",
            trigger: Trigger::Content,
            outcome: Outcome::Delivered,
            duration: Duration::from_millis(3),
            output_rows: 7,
            trigger_to_delivery: Some(Duration::from_millis(90)),
            content_acts: &[1],
            unknown_act: false,
            evaluation_started: true,
            vm_work: VmWorkSample::default(),
            vm_work_complete: true,
        });
        let bucket = &metrics.buckets[NeedMetrics::need_bucket("attention.query.v1")];
        assert_eq!(bucket.reruns, 1);
        assert_eq!(bucket.output_rows, 7);
        assert_eq!(bucket.outcome(Outcome::Delivered), 1);
        assert_eq!(bucket.delivery_latency_bound(95), Some(128));
        assert_eq!(metrics.recent_acts[0].evaluation_attempt_associations, 1);
        for act in 2..=(COMMIT_WINDOW as i64 + 1) {
            metrics.note_content_event(Some(act), 0, 0, 0, 0);
        }
        assert_eq!(metrics.recent_acts.len(), COMMIT_WINDOW);
        assert_ne!(metrics.recent_acts[0].act, 1);
    }

    #[test]
    fn visible_quiet_coalesced_and_missed_probe_remain_distinct() {
        let mut metrics = NeedMetrics::default();
        metrics.note_content_event(Some(1), 1, 1, 1, 0);
        metrics.note_content_event(Some(1), 0, 1, 0, 0);
        metrics.note_rerun(RerunSample {
            need: "attention.query.v1",
            trigger: Trigger::Content,
            outcome: Outcome::Delivered,
            duration: Duration::from_millis(5),
            output_rows: 3,
            trigger_to_delivery: Some(Duration::from_millis(200)),
            content_acts: &[1],
            unknown_act: false,
            evaluation_started: true,
            vm_work: VmWorkSample::default(),
            vm_work_complete: true,
        });
        metrics.note_rerun(RerunSample {
            need: "attention.query.v1",
            trigger: Trigger::Tick,
            outcome: Outcome::Quiet,
            duration: Duration::from_millis(2),
            output_rows: 3,
            trigger_to_delivery: None,
            content_acts: &[],
            unknown_act: false,
            evaluation_started: true,
            vm_work: VmWorkSample::default(),
            vm_work_complete: true,
        });
        metrics.note_probe(Some(false));
        metrics.note_probe(Some(true));
        metrics.note_probe(None);
        let bucket = &metrics.buckets[NeedMetrics::need_bucket("attention.query.v1")];
        assert_eq!(metrics.content_events, 2);
        assert_eq!(metrics.content_event_queue_inserts, 1);
        assert_eq!(metrics.content_event_coalesced, 1);
        assert_eq!(bucket.reruns, 2);
        assert_eq!(bucket.outcome(Outcome::Delivered), 1);
        assert_eq!(bucket.outcome(Outcome::Quiet), 1);
        assert_eq!(bucket.reruns_by_trigger[Trigger::Content.index()], 1);
        assert_eq!(bucket.reruns_by_trigger[Trigger::Tick.index()], 1);
        assert_eq!(metrics.recent_acts[0].evaluation_attempt_associations, 1);
        assert_eq!(metrics.recent_acts[0].distinct_dirtied_targets, 1);
        assert_eq!(
            (
                metrics.probe_attempts,
                metrics.probe_mismatches,
                metrics.probe_inconclusive
            ),
            (2, 1, 1)
        );
    }

    #[test]
    fn two_acts_can_share_one_actual_scheduler_evaluation() {
        let mut metrics = NeedMetrics::default();
        metrics.note_content_event(Some(41), 1, 1, 1, 0);
        metrics.note_content_event(Some(42), 1, 1, 0, 0);
        metrics.note_rerun(RerunSample {
            need: "attention.query.v1",
            trigger: Trigger::Content,
            outcome: Outcome::Quiet,
            duration: Duration::from_millis(1),
            output_rows: 0,
            trigger_to_delivery: None,
            content_acts: &[41, 42],
            unknown_act: false,
            evaluation_started: true,
            vm_work: VmWorkSample::default(),
            vm_work_complete: true,
        });
        let bucket = &metrics.buckets[NeedMetrics::need_bucket("attention.query.v1")];
        assert_eq!(bucket.reruns, 1);
        assert_eq!(metrics.known_content_acts, 2);
        assert_eq!(metrics.recent_acts[0].evaluation_attempt_associations, 1);
        assert_eq!(metrics.recent_acts[1].evaluation_attempt_associations, 1);
    }

    #[test]
    fn pre_evaluation_close_does_not_claim_sql_work_for_an_act() {
        let mut metrics = NeedMetrics::default();
        metrics.note_content_event(Some(51), 1, 1, 1, 0);
        metrics.note_rerun(RerunSample {
            need: "attention.query.v1",
            trigger: Trigger::Content,
            outcome: Outcome::Closed,
            duration: Duration::from_millis(1),
            output_rows: 0,
            trigger_to_delivery: None,
            content_acts: &[51],
            unknown_act: false,
            evaluation_started: false,
            vm_work: VmWorkSample::default(),
            vm_work_complete: true,
        });
        assert_eq!(metrics.known_act_evaluation_attempt_associations, 0);
        assert_eq!(metrics.recent_acts[0].evaluation_attempt_associations, 0);
        assert_eq!(metrics.pre_evaluation_association_drops, 1);
        let bucket = &metrics.buckets[NeedMetrics::need_bucket("attention.query.v1")];
        assert_eq!(bucket.reruns, 1);
        assert_eq!(bucket.outcome(Outcome::Closed), 1);
    }
}
