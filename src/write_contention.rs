//! Process-global write-contention measurement for the per-workspace writer.
//!
//! Exactly one writer per workspace assigns sequence (decision `2885ba0`), and
//! until this existed nobody knew what that costs. Two numbers settle it: how
//! often a writer has to queue for `BEGIN IMMEDIATE`, and how long a write
//! transaction then holds the reserved lock. The first was already computed by
//! [`crate::db::begin_write`]'s bounded retry loop and thrown away; the second
//! was not measured anywhere.
//!
//! Why process-global rather than request-local. The per-request counters in
//! [`crate::request_work`] are opt-in behind `X-Native-Measure`, so they only
//! ever describe requests an operator deliberately made — a synthetic workload,
//! not production traffic. The dominant source of per-workspace write pressure
//! is the involuntary capture write that ordinary *read* calls queue onto the
//! background capture worker, which runs outside any request task. An aggregate
//! that lives in the process and is emitted to the log sees all of it, and is
//! what an operator can read back from deployment logs without holding a
//! session open.
//!
//! Why the critical section is measured at connection release rather than at
//! the commit. There are 245 `begin_write` call sites and 287 commit sites, and
//! a transaction can also end by being dropped. Returning the connection to its
//! pool is the seam that sees commits, rollbacks and drops alike, so it is both
//! the cheapest close and the only one that is not skewed towards whatever
//! ordinary commits look like — a commit-site measurement would silently omit
//! every rollback. Measured, not assumed: SQLx performs that return from
//! whichever task drops the connection, which is frequently not the task that
//! opened the transaction. That is also why there is no request-scoped
//! `write_held` phase to pair with `write_wait`.
//!
//! It is not, however, a seam *every* ending reaches, and the losses are not
//! all of one kind. Two counters report them, kept apart because conflating
//! them would hide the one that can move a conclusion.
//!
//! `unobserved_closes` covers the duration-independent losses: SQLx closes a
//! connection without running `after_release` when its pool is closing and when
//! the connection has outlived `max_lifetime` (thirty minutes by default, which
//! the write pools do not override). Neither correlates with how long a
//! transaction held the lock, so they thin the sample without tilting it.
//!
//! `domain_mismatches` counts closes refused because the releasing pool's
//! domain disagreed with the one recorded at open. A trickle is address reuse.
//! A steady stream is a caller declaring a domain its pool does not match,
//! which loses that domain's whole distribution — so it is counted where that
//! is visible rather than inside the benign-sounding bucket.
//!
//! `held_over_cap` covers the loss that does correlate, and is therefore the
//! one to read first. All three are cumulative since process start, unlike the
//! windowed counts beside them. Sections are abandoned after [`STALE_SECTION_AFTER`],
//! because an entry that old is far more likely to be a leaked key than a live
//! transaction — but "more likely" is not "certainly", and the rule drops
//! precisely the longest holds. **The `held` distribution is censored at that
//! cap**: no sample above it can exist, and the reported maximum cannot exceed
//! it. A nonzero `held_over_cap` means the true tail is longer than the numbers
//! below it can show, and no argument about critical-section length should be
//! made from a window where it is nonzero without saying so.
//!
//! What it deliberately does not carry: no workspace identity, no database
//! path, no record, no principal. These are counts and durations only. Per
//! workspace aggregation is a separate, later question, and it is the point at
//! which disclosure would need thinking about.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Upper bounds, in microseconds, of the fixed histogram buckets. A reported
/// percentile is the upper bound of the bucket the percentile falls in, so it
/// is an upper estimate and never a smaller number than the truth. Buckets are
/// fixed rather than adaptive so that two samples from different deployments
/// are directly comparable.
/// The bounded writer deadline, and therefore the largest bucket bound. Lives
/// here because the histogram is the thing that must not silently stop covering
/// the deadline; `crate::db::WRITER_DEADLINE` is derived from it.
pub(crate) const WRITER_DEADLINE_MICROS: u64 = 15_000_000;

const BUCKET_BOUNDS_MICROS: [u64; 15] = [
    100,                    // 0.1ms
    250,                    //
    500,                    //
    1_000,                  // 1ms
    2_500,                  //
    5_000,                  //
    10_000,                 // 10ms
    25_000,                 //
    50_000,                 //
    100_000,                // 100ms
    250_000,                //
    500_000,                //
    1_000_000,              // 1s
    5_000_000,              // 5s
    WRITER_DEADLINE_MICROS, // the writer deadline
];

/// The write pool a sample came from. `begin_write` serves both the workspace
/// writer whose serialisation this exists to measure and the hosted
/// control-plane catalogue, and mixing the two would corrupt the distribution
/// the MVCC question turns on. The pool that releases the connection knows
/// which it is, so samples are routed at close rather than at open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteDomain {
    Workspace,
    HostCatalog,
}

#[derive(Debug, Default)]
struct Histogram {
    buckets: [AtomicU64; BUCKET_BOUNDS_MICROS.len() + 1],
    count: AtomicU64,
    total_micros: AtomicU64,
    max_micros: AtomicU64,
}

impl Histogram {
    fn record(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let index = BUCKET_BOUNDS_MICROS
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(BUCKET_BOUNDS_MICROS.len());
        self.buckets[index].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_micros.fetch_add(micros, Ordering::Relaxed);
        self.max_micros.fetch_max(micros, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let mut buckets = [0u64; BUCKET_BOUNDS_MICROS.len() + 1];
        for (slot, bucket) in buckets.iter_mut().zip(self.buckets.iter()) {
            *slot = bucket.load(Ordering::Relaxed);
        }
        HistogramSnapshot {
            buckets,
            count: self.count.load(Ordering::Relaxed),
            total_micros: self.total_micros.load(Ordering::Relaxed),
            max_micros: self.max_micros.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HistogramSnapshot {
    buckets: [u64; BUCKET_BOUNDS_MICROS.len() + 1],
    pub count: u64,
    pub total_micros: u64,
    pub max_micros: u64,
}

impl HistogramSnapshot {
    fn difference(self, earlier: Self) -> Self {
        let mut buckets = [0u64; BUCKET_BOUNDS_MICROS.len() + 1];
        for (slot, (later, earlier)) in buckets
            .iter_mut()
            .zip(self.buckets.iter().zip(earlier.buckets.iter()))
        {
            *slot = later.saturating_sub(*earlier);
        }
        Self {
            buckets,
            count: self.count.saturating_sub(earlier.count),
            total_micros: self.total_micros.saturating_sub(earlier.total_micros),
            // A window's maximum cannot be recovered by subtraction. This is
            // the running maximum since process start, and the emitted field
            // is named to say so rather than to imply a per-window peak.
            max_micros: self.max_micros,
        }
    }

    /// The upper bound of the bucket containing the `quantile` observation, in
    /// microseconds. `None` when the window is empty, and `None` rather than a
    /// fabricated number when every observation is in the unbounded overflow
    /// bucket, which has no upper bound to report.
    pub fn quantile_micros(&self, quantile: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        // Rank is 1-based and rounds up, so q=0 selects the first observation
        // and q=1 the last.
        let rank = (quantile * self.count as f64).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            seen += bucket;
            if seen >= rank {
                return BUCKET_BOUNDS_MICROS.get(index).copied();
            }
        }
        None
    }
}

#[derive(Debug, Default)]
struct Totals {
    /// Successful `BEGIN IMMEDIATE` acquisitions.
    transactions: AtomicU64,
    /// Acquisitions that had to retry at least once because another writer
    /// held the reserved lock for longer than SQLite's own `busy_timeout`.
    busy_retried_transactions: AtomicU64,
    /// Those retry iterations, summed.
    busy_retries: AtomicU64,
    /// Retry iterations spent waiting for a canceled transaction's rollback to
    /// drain before pooled reuse. Ordinary housekeeping, counted apart so it
    /// cannot be read as contention.
    cleanup_retries: AtomicU64,
    /// Acquisitions that never succeeded, whether the bounded deadline expired
    /// or the error was not retriable.
    failures: AtomicU64,
    /// Time spent inside the bounded retry loop: queueing for the writer.
    wait: Histogram,
    /// `BEGIN IMMEDIATE` to connection release: the critical section.
    held: Histogram,
}

/// Critical sections opened whose close was never observed and which were
/// collected as stale, so the sample was dropped rather than guessed. The
/// domain is unknowable for these — it is resolved at close, which by
/// definition did not happen — so this is one process-wide figure, and a
/// nonzero value qualifies every `held` distribution below it.
static UNOBSERVED_CLOSES: AtomicU64 = AtomicU64::new(0);

/// Sections discarded for exceeding [`STALE_SECTION_AFTER`], wherever the age
/// predicate is applied. Counted apart from `UNOBSERVED_CLOSES` because this
/// loss is duration-correlated by construction: it censors the distribution's
/// own tail. Cumulative since process start, like `UNOBSERVED_CLOSES` and
/// unlike every windowed field beside it on the line. See the module doc.
static HELD_OVER_CAP: AtomicU64 = AtomicU64::new(0);

/// Closes whose pool domain disagreed with the domain recorded at open.
///
/// Kept out of `UNOBSERVED_CLOSES` because it does not mean what the other
/// entries there mean. Address reuse across pools produces the odd one; a
/// caller that declares the wrong domain for its pool produces a steady stream
/// and silently loses that domain's whole distribution. Folded into the
/// thinning bucket, that would read as benign. Cumulative since process start.
static DOMAIN_MISMATCHES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
struct Registry {
    workspace: Totals,
    catalog: Totals,
}

impl Registry {
    fn totals(&self, domain: WriteDomain) -> &Totals {
        match domain {
            WriteDomain::Workspace => &self.workspace,
            WriteDomain::HostCatalog => &self.catalog,
        }
    }
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}

/// Open critical sections, keyed by the raw SQLite connection pointer that is
/// holding the reserved lock. A physical write connection can hold at most one
/// transaction at a time, so the key is unique while the entry is live, and a
/// later `BEGIN` on the same pointer overwrites rather than accumulates.
fn open_sections() -> &'static Mutex<HashMap<usize, OpenSection>> {
    static SECTIONS: OnceLock<Mutex<HashMap<usize, OpenSection>>> = OnceLock::new();
    SECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Clone, Copy, Debug)]
struct OpenSection {
    opened: Instant,
    /// The pool the section was opened on, known at `BEGIN IMMEDIATE`. The
    /// close also derives a domain, from the pool doing the releasing. They
    /// must agree; if they do not, the entry is a stale one whose connection
    /// address has been reused by a different pool, and attributing it would
    /// contaminate exactly the split this measurement depends on.
    domain: WriteDomain,
    /// The diagnosed operation holding the lock, if the opener names one.
    /// Only the host-catalog journal names its operations today; workspace
    /// writes pass `None` and stay domain-aggregated.
    operation: Option<&'static str>,
}

/// A hold at or above this age logs its operation (when labelled): ordinary
/// catalog journal writes are milliseconds, so a seconds-long hold is the
/// contention signal bbbd18b had to reconstruct from unattributed maxima.
const SLOW_HOLD_LOG_AFTER: Duration = Duration::from_secs(1);

/// Ceiling on tracked open sections. A pool holds at most `max_connections`
/// physical write connections, so this is orders of magnitude above the live
/// set even with many databases open; it exists so that a leak — a connection
/// destroyed without ever being released back to its pool — cannot grow the
/// map without bound.
const MAX_TRACKED_SECTIONS: usize = 4_096;

/// The age past which a tracked section is treated as leaked rather than live.
///
/// This is leak collection, not a timeout — nothing is cancelled — but it is
/// also the point at which the `held` distribution is censored, because a
/// transaction that genuinely runs this long is discarded alongside the leaked
/// keys it exists to reclaim. Chosen far above any plausible critical section
/// (the bounded writer deadline is 15s), and every discard is counted in
/// `held_over_cap` so the censoring is visible rather than assumed away.
const STALE_SECTION_AFTER: Duration = Duration::from_secs(300);

/// Record the outcome of a bounded `BEGIN IMMEDIATE` acquisition. `wait` is the
/// time spent inside the retry loop, which is the queueing delay a writer paid
/// because another writer held the reserved lock.
pub(crate) fn record_begin(
    domain: WriteDomain,
    retries: crate::db::BeginRetries,
    wait: Duration,
    failed: bool,
) {
    let totals = registry().totals(domain);
    if failed {
        totals.failures.fetch_add(1, Ordering::Relaxed);
    } else {
        totals.transactions.fetch_add(1, Ordering::Relaxed);
    }
    if retries.busy > 0 {
        totals
            .busy_retried_transactions
            .fetch_add(1, Ordering::Relaxed);
        totals
            .busy_retries
            .fetch_add(retries.busy as u64, Ordering::Relaxed);
    }
    if retries.cleanup > 0 {
        totals
            .cleanup_retries
            .fetch_add(retries.cleanup as u64, Ordering::Relaxed);
    }
    totals.wait.record(wait);
    #[cfg(test)]
    observed::note_begin(observed::Begin {
        domain,
        retries,
        wait,
        failed,
    });
    // Also driven from here so that a process which begins writes but whose
    // closes are never observed still reports the half it does know.
    maybe_report();
}

/// Mark the reserved lock as taken by the connection at `connection_key`.
/// `operation` names the holder when the opener knows it (the host-catalog
/// journal); pass `None` for anonymous workspace writes.
pub(crate) fn open_critical_section(
    domain: WriteDomain,
    connection_key: usize,
    operation: Option<&'static str>,
) {
    let now = Instant::now();
    let mut sections = open_sections()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if sections.len() >= MAX_TRACKED_SECTIONS {
        let before = sections.len();
        sections.retain(|_, section| {
            now.saturating_duration_since(section.opened) < STALE_SECTION_AFTER
        });
        // Same age predicate as the windowed sweep, so the same classification:
        // these are censored samples. Counting them as duration-independent
        // losses here would let `held_over_cap` read zero for a window whose
        // tail this branch had just cut.
        HELD_OVER_CAP.fetch_add((before - sections.len()) as u64, Ordering::Relaxed);
        if sections.len() >= MAX_TRACKED_SECTIONS {
            // Refusing a brand-new section because the map is still full. Not
            // age-based, so not tail-censoring.
            UNOBSERVED_CLOSES.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    if sections
        .insert(
            connection_key,
            OpenSection {
                opened: now,
                domain,
                operation,
            },
        )
        .is_some()
    {
        // The previous section on this connection never closed. Overwriting it
        // is right — the connection cannot hold two transactions — but the
        // sample it would have produced is gone, so say so. Duration-
        // independent: the connection was reused, which says nothing about how
        // long the lost transaction held the lock.
        UNOBSERVED_CLOSES.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(test)]
    observed::note_open(connection_key);
}

/// Close the critical section for a released connection and record how long it
/// held the reserved lock. A release with no open section is an ordinary
/// non-transactional use of the write pool and records nothing — the absence of
/// a sample, not a zero.
pub(crate) fn close_critical_section(domain: WriteDomain, connection_key: usize) {
    let Some(section) = open_sections()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&connection_key)
    else {
        return;
    };
    if section.domain != domain {
        // A reused connection address from a pool that is not this one — or a
        // caller declaring a domain its pool does not match, which is a defect
        // rather than a coincidence. Either way not a measurement of anything.
        DOMAIN_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let held = section.opened.elapsed();
    if held >= STALE_SECTION_AFTER {
        // Far more likely a stale entry whose connection was destroyed without
        // ever being released than a real five-minute transaction — but not
        // certainly, which is why this is counted where a reader will see that
        // the tail has been cut rather than folded in with the losses that
        // carry no such implication.
        HELD_OVER_CAP.fetch_add(1, Ordering::Relaxed);
        return;
    }
    registry().totals(domain).held.record(held);
    if held >= SLOW_HOLD_LOG_AFTER {
        if let Some(operation) = section.operation {
            eprintln!(
                "write-contention-slow domain={domain:?} operation={operation} held_ms={}",
                held.as_millis()
            );
        }
    }
    #[cfg(test)]
    observed::note_held(domain, connection_key, held);
    maybe_report();
}

/// A point-in-time view of one domain's totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DomainSnapshot {
    pub transactions: u64,
    pub busy_retried_transactions: u64,
    pub busy_retries: u64,
    pub cleanup_retries: u64,
    pub failures: u64,
    pub wait: HistogramSnapshot,
    pub held: HistogramSnapshot,
}

impl DomainSnapshot {
    fn difference(self, earlier: Self) -> Self {
        Self {
            transactions: self.transactions.saturating_sub(earlier.transactions),
            busy_retried_transactions: self
                .busy_retried_transactions
                .saturating_sub(earlier.busy_retried_transactions),
            busy_retries: self.busy_retries.saturating_sub(earlier.busy_retries),
            cleanup_retries: self.cleanup_retries.saturating_sub(earlier.cleanup_retries),
            failures: self.failures.saturating_sub(earlier.failures),
            wait: self.wait.difference(earlier.wait),
            held: self.held.difference(earlier.held),
        }
    }

    fn is_empty(&self) -> bool {
        self.transactions == 0 && self.failures == 0 && self.held.count == 0
    }
}

/// Test-only per-task observation of the samples this module records.
///
/// The aggregate above is process-global and the test binary is one process
/// running many tests at once, so a test that asserted on it would be asserting
/// on every other test's writes too. These record what the *calling task*
/// produced, which is both race-free and a sharper statement of the property
/// under test.
#[cfg(test)]
pub(crate) mod observed {
    use super::*;
    use std::sync::Arc;

    tokio::task_local! {
        static OBSERVATIONS: Arc<Mutex<Observations>>;
    }

    #[derive(Debug, Default)]
    pub(crate) struct Observations {
        /// One entry per bounded `BEGIN IMMEDIATE` acquisition.
        pub begins: Vec<Begin>,
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Begin {
        pub domain: WriteDomain,
        pub retries: crate::db::BeginRetries,
        pub wait: Duration,
        pub failed: bool,
    }

    pub(crate) async fn observing<F: std::future::Future>(future: F) -> (F::Output, Observations) {
        let sink = Arc::new(Mutex::new(Observations::default()));
        let output = OBSERVATIONS.scope(Arc::clone(&sink), future).await;
        let observations =
            std::mem::take(&mut *sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
        (output, observations)
    }

    pub(super) fn note_begin(begin: Begin) {
        let _ = OBSERVATIONS.try_with(|sink| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .begins
                .push(begin)
        });
    }

    /// Closed critical sections, addressed by the connection that held the
    /// lock. Deliberately not task-local like `begins`: SQLx returns a
    /// connection to its pool from whichever task drops it, which is not
    /// reliably the task that opened the transaction, so a task-local sink
    /// would report a false zero. Keying by connection is race-free between
    /// concurrent tests without needing to be.
    fn closed() -> &'static Mutex<HashMap<usize, (WriteDomain, Duration)>> {
        static CLOSED: OnceLock<Mutex<HashMap<usize, (WriteDomain, Duration)>>> = OnceLock::new();
        CLOSED.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// The critical section recorded for `connection_key`, if one has closed.
    pub(crate) fn section_for(connection_key: usize) -> Option<(WriteDomain, Duration)> {
        closed()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&connection_key)
            .copied()
    }

    /// Forget any earlier section for this connection. SQLite reuses a freed
    /// connection's address, so without this a test could read a previous
    /// test's sample and conclude a still-open section had already closed.
    pub(super) fn note_open(connection_key: usize) {
        closed()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&connection_key);
    }

    pub(super) fn note_held(domain: WriteDomain, connection_key: usize, held: Duration) {
        closed()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(connection_key, (domain, held));
    }
}

pub(crate) fn snapshot(domain: WriteDomain) -> DomainSnapshot {
    let totals = registry().totals(domain);
    DomainSnapshot {
        transactions: totals.transactions.load(Ordering::Relaxed),
        busy_retried_transactions: totals.busy_retried_transactions.load(Ordering::Relaxed),
        busy_retries: totals.busy_retries.load(Ordering::Relaxed),
        cleanup_retries: totals.cleanup_retries.load(Ordering::Relaxed),
        failures: totals.failures.load(Ordering::Relaxed),
        wait: totals.wait.snapshot(),
        held: totals.held.snapshot(),
    }
}

/// How often a window may be emitted. Chosen so that a busy process logs at a
/// human rate rather than per write: the question this instrument answers is
/// "is the writer under pressure", which is a rate question, and a per-write
/// line would both cost more than the measurement and drown the log it has to
/// be read out of.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// Milliseconds since the process-wide measurement epoch at which the next
/// window becomes due. Mirrors `ReportState::next_due` so the common case can
/// be decided without locking; the lock remains authoritative.
static NEXT_DUE_MILLIS: AtomicU64 = AtomicU64::new(0);

fn measurement_epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn millis_since_epoch(instant: Instant) -> u64 {
    u64::try_from(
        instant
            .saturating_duration_since(measurement_epoch())
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn report_may_be_due() -> bool {
    millis_since_epoch(Instant::now()) >= NEXT_DUE_MILLIS.load(Ordering::Relaxed)
}

struct ReportState {
    next_due: Instant,
    workspace: DomainSnapshot,
    catalog: DomainSnapshot,
}

fn report_state() -> &'static Mutex<ReportState> {
    static STATE: OnceLock<Mutex<ReportState>> = OnceLock::new();
    STATE.get_or_init(|| {
        let next_due = Instant::now() + REPORT_EVERY;
        NEXT_DUE_MILLIS.store(millis_since_epoch(next_due), Ordering::Relaxed);
        Mutex::new(ReportState {
            next_due,
            workspace: DomainSnapshot::default(),
            catalog: DomainSnapshot::default(),
        })
    })
}

/// Emit a window if one is due. Driven by measurement traffic rather than by a
/// timer task: a process doing no writes has nothing to report, and one doing
/// writes is already awake.
fn maybe_report() {
    let now = Instant::now();
    // Fast path: one relaxed load per write, rather than a process-global mutex
    // on a hot path belonging to an instrument whose whole subject is
    // serialisation. The mutex below is taken only when a window may be due,
    // and re-checks the deadline under the lock.
    if !report_may_be_due() {
        return;
    }
    let mut state = report_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if now < state.next_due {
        return;
    }
    let elapsed = REPORT_EVERY + now.saturating_duration_since(state.next_due);
    state.next_due = now + REPORT_EVERY;
    NEXT_DUE_MILLIS.store(millis_since_epoch(state.next_due), Ordering::Relaxed);
    collect_abandoned_sections(now);
    let workspace_now = snapshot(WriteDomain::Workspace);
    let catalog_now = snapshot(WriteDomain::HostCatalog);
    let workspace = workspace_now.difference(state.workspace);
    let catalog = catalog_now.difference(state.catalog);
    state.workspace = workspace_now;
    state.catalog = catalog_now;
    drop(state);
    if workspace.is_empty() && catalog.is_empty() {
        return;
    }
    if !workspace.is_empty() {
        eprintln!("{}", report_line("workspace", elapsed, &workspace));
    }
    if !catalog.is_empty() {
        eprintln!("{}", report_line("host_catalog", elapsed, &catalog));
    }
}

/// Drop sections that have aged past [`STALE_SECTION_AFTER`], so the loss is
/// reported within a bounded time rather than only once the map fills.
///
/// Age is all this knows. Almost every entry it collects is one whose
/// connection was closed rather than released, but a live transaction running
/// longer than the cap is indistinguishable from here and is collected too —
/// which is why these are counted as censored samples, not as abandoned ones.
/// Driven from the report, so it runs at most once a window.
fn collect_abandoned_sections(now: Instant) {
    let mut sections = open_sections()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let before = sections.len();
    sections
        .retain(|_, section| now.saturating_duration_since(section.opened) < STALE_SECTION_AFTER);
    let collected = before - sections.len();
    drop(sections);
    if collected > 0 {
        HELD_OVER_CAP.fetch_add(collected as u64, Ordering::Relaxed);
    }
}

/// One greppable line per window per domain. `write-contention` is the anchor
/// an operator greps deployment logs for; every field is `key=value` so the
/// line parses without a schema.
fn report_line(domain: &str, window: Duration, sample: &DomainSnapshot) -> String {
    format!(
        "write-contention domain={domain} window_s={window_s} transactions={transactions} \
busy_retried={busy_retried} busy_retries={busy_retries} cleanup_retries={cleanup_retries} failures={failures} \
wait_p50_ms={wait_p50} wait_p90_ms={wait_p90} wait_p99_ms={wait_p99} wait_mean_ms={wait_mean:.3} \
held_n={held_n} held_p50_ms={held_p50} held_p90_ms={held_p90} held_p99_ms={held_p99} \
held_mean_ms={held_mean:.3} held_max_ms_since_start={held_max:.3} \
unobserved_closes={unobserved} held_over_cap={over_cap} domain_mismatches={mismatches}",
        window_s = window.as_secs(),
        transactions = sample.transactions,
        busy_retried = sample.busy_retried_transactions,
        busy_retries = sample.busy_retries,
        cleanup_retries = sample.cleanup_retries,
        failures = sample.failures,
        wait_p50 = bucket_field(sample.wait.quantile_micros(0.50)),
        wait_p90 = bucket_field(sample.wait.quantile_micros(0.90)),
        wait_p99 = bucket_field(sample.wait.quantile_micros(0.99)),
        wait_mean = mean_millis(sample.wait.total_micros, sample.wait.count),
        held_n = sample.held.count,
        held_p50 = bucket_field(sample.held.quantile_micros(0.50)),
        held_p90 = bucket_field(sample.held.quantile_micros(0.90)),
        held_p99 = bucket_field(sample.held.quantile_micros(0.99)),
        held_mean = mean_millis(sample.held.total_micros, sample.held.count),
        held_max = sample.held.max_micros as f64 / 1_000.0,
        unobserved = UNOBSERVED_CLOSES.load(Ordering::Relaxed),
        over_cap = HELD_OVER_CAP.load(Ordering::Relaxed),
        mismatches = DOMAIN_MISMATCHES.load(Ordering::Relaxed),
    )
}

/// A quantile that has no bucket upper bound — an empty window, or every
/// observation past the largest bucket — is reported as `unbounded`, never as a
/// number that was not measured.
fn bucket_field(micros: Option<u64>) -> String {
    match micros {
        Some(micros) => format!("{:.3}", micros as f64 / 1_000.0),
        None => "unbounded".to_string(),
    }
}

fn mean_millis(total_micros: u64, count: u64) -> f64 {
    if count == 0 {
        return 0.0;
    }
    total_micros as f64 / count as f64 / 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn histogram_of(samples: &[Duration]) -> HistogramSnapshot {
        let histogram = Histogram::default();
        for sample in samples {
            histogram.record(*sample);
        }
        histogram.snapshot()
    }

    #[test]
    fn quantile_reports_the_containing_bucket_upper_bound() {
        let snapshot = histogram_of(&[
            Duration::from_micros(50),
            Duration::from_micros(50),
            Duration::from_micros(50),
            Duration::from_millis(40),
        ]);
        // Three of four observations are in the first bucket, so p50 and p90
        // land there; p99 falls in the observation at 40ms, whose bucket is
        // bounded at 50ms.
        assert_eq!(snapshot.quantile_micros(0.50), Some(100));
        assert_eq!(snapshot.quantile_micros(0.90), Some(50_000));
        assert_eq!(snapshot.quantile_micros(0.99), Some(50_000));
    }

    #[test]
    fn empty_and_overflowing_windows_report_no_number() {
        assert_eq!(histogram_of(&[]).quantile_micros(0.50), None);
        let overflowed = histogram_of(&[Duration::from_secs(60)]);
        assert_eq!(overflowed.quantile_micros(0.50), None);
        assert_eq!(bucket_field(overflowed.quantile_micros(0.50)), "unbounded");
        // The observation is still counted and still contributes to the mean
        // and the maximum: only its quantile has no bound to report.
        assert_eq!(overflowed.count, 1);
        assert_eq!(overflowed.max_micros, 60_000_000);
    }

    #[test]
    fn a_window_is_the_difference_between_two_snapshots() {
        let earlier = DomainSnapshot {
            transactions: 10,
            busy_retried_transactions: 2,
            busy_retries: 3,
            cleanup_retries: 0,
            failures: 1,
            wait: histogram_of(&[Duration::from_micros(10)]),
            held: histogram_of(&[Duration::from_millis(1)]),
        };
        let later = DomainSnapshot {
            transactions: 25,
            busy_retried_transactions: 2,
            busy_retries: 3,
            cleanup_retries: 0,
            failures: 1,
            wait: histogram_of(&[Duration::from_micros(10), Duration::from_micros(10)]),
            held: histogram_of(&[Duration::from_millis(1), Duration::from_millis(2)]),
        };
        let window = later.difference(earlier);
        assert_eq!(window.transactions, 15);
        assert_eq!(window.busy_retried_transactions, 0);
        assert_eq!(window.held.count, 1);
        assert!(!window.is_empty());
    }

    #[test]
    fn an_unopened_close_records_nothing_rather_than_zero() {
        // An ordinary non-transactional query on the write pool releases a
        // connection that never took the reserved lock. Recording a zero for
        // it would pull every percentile down.
        //
        // Asserted through the per-connection sink rather than the global
        // counters, which sibling tests in this binary are writing to
        // concurrently.
        let key = 0xdead_beef;
        close_critical_section(WriteDomain::Workspace, key);
        assert!(observed::section_for(key).is_none());
    }

    /// Every path that discards on age must classify the discard the same way.
    /// The map-full branch in `open_critical_section` once used the age
    /// predicate but counted into the duration-independent bucket, which let
    /// the censored-tail counter read zero for a window whose tail it had just
    /// cut — the one reading an engine decision would most want to trust.
    ///
    /// Asserted as a lower bound on a monotonic counter, because sibling tests
    /// in this binary are recording into the same process-wide totals.
    #[test]
    fn the_map_full_sweep_counts_its_discards_as_censored_samples() {
        let stale = Instant::now() - STALE_SECTION_AFTER - Duration::from_secs(1);
        let planted = MAX_TRACKED_SECTIONS;
        // Read before planting, not after. A sibling test's own open can run
        // the sweep first and consume the planted backlog; the bound below
        // still holds then, because whoever sweeps them adds to the same
        // counter. Reading afterwards would miss exactly that increment and
        // fail.
        let before = HELD_OVER_CAP.load(Ordering::Relaxed);
        {
            let mut sections = open_sections()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for index in 0..planted {
                sections.insert(
                    0xffff_0000_0000_0000 + index,
                    OpenSection {
                        opened: stale,
                        domain: WriteDomain::Workspace,
                        operation: None,
                    },
                );
            }
        }
        // The map is at capacity with nothing but over-cap entries, so this
        // open triggers the sweep.
        open_critical_section(WriteDomain::Workspace, 0xeeee_0000_0000_0001, None);
        close_critical_section(WriteDomain::Workspace, 0xeeee_0000_0000_0001);
        assert!(
            HELD_OVER_CAP.load(Ordering::Relaxed) >= before + planted as u64,
            "the map-full sweep did not count its age-based discards as censored"
        );
    }

    #[test]
    fn a_close_from_the_wrong_pool_is_refused_rather_than_misattributed() {
        // A connection address reused by a different pool. Attributing its
        // section to the releasing pool would contaminate exactly the split
        // the MVCC question depends on.
        let key = 0xfeed_face;
        open_critical_section(WriteDomain::Workspace, key, None);
        close_critical_section(WriteDomain::HostCatalog, key);
        assert!(observed::section_for(key).is_none());
        // The entry is consumed either way, so a later honest close of a
        // genuinely new section is unaffected.
        open_critical_section(WriteDomain::Workspace, key, None);
        close_critical_section(WriteDomain::Workspace, key);
        assert_eq!(
            observed::section_for(key).map(|section| section.0),
            Some(WriteDomain::Workspace)
        );
    }

    #[test]
    fn a_report_line_names_every_field_it_prints() {
        let sample = DomainSnapshot {
            transactions: 4,
            busy_retried_transactions: 1,
            busy_retries: 7,
            cleanup_retries: 2,
            failures: 0,
            wait: histogram_of(&[Duration::from_micros(40)]),
            held: histogram_of(&[Duration::from_millis(3)]),
        };
        let line = report_line("workspace", Duration::from_secs(60), &sample);
        assert!(line.contains("unobserved_closes="));
        assert!(
            line.contains("held_over_cap="),
            "the censored-tail count must be on every line, not only when it moves"
        );
        assert!(line.contains("domain_mismatches="));
        assert!(line.starts_with("write-contention domain=workspace window_s=60 "));
        assert!(line
            .contains("transactions=4 busy_retried=1 busy_retries=7 cleanup_retries=2 failures=0"));
        assert!(line.contains("held_n=1"));
        assert!(line.contains("held_p50_ms=5.000"));
        for field in line.split(' ').skip(1) {
            assert!(field.contains('='), "field {field} is not key=value");
        }
    }
}
