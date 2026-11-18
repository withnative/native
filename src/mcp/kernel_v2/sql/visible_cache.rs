//! Cross-request visible-set cache for full v2 staging (Native b171a9d,
//! slices 2-4). Hosted read-write serving registers a cache for its handle;
//! inspection, CLI, standby and member handles do not enable it. Folder-scoped
//! apps use grant-keyed entries, seeded by narrowing the person's known set.
//!
//! What it caches: per (database file, resolved principal, folder grant, gate variant), the
//! ids the visibility gate admitted (`_v2_visible` on the full-staging path).
//! Ids only. Home scopes are staged fresh on every read, and every staged row
//! is re-read from main, so content is always current; only *which ids* are
//! staged can lag.
//!
//! Identity vs staleness: the key (principal + grant + variant) isolates one
//! person from another. The incarnation, persisted access epoch and cursor
//! fence *staleness* only. A last-known set is never served across principals.
//!
//! Validation runs inside the reader's own staging snapshot:
//! * an entry newer than the snapshot is never used (older snapshots miss);
//! * the content-event delta since the entry's stamp is classified
//!   ([`crate::kernel::access_fence`]): NoEffect advances the cursor;
//!   PatchClosure re-runs the same gate over the subjects and their reverse
//!   active `part_of` closure (bounded by `MAX_DERIVED_BEARER_DEPTH`) and patches
//!   in place, so ordinary creates, edits, comments and links are reused, not
//!   discarded; PatchHome is a cursor advance (a fresh home has no records);
//! * anything else (RecomputePrincipals/All, unknown, an epoch change, any meta
//!   delta, an oversized delta or closure overflow) serves the principal's
//!   last-known set immediately and starts one background refresh
//!   (single-flight). Per Richard's continuity direction (Native d433cb7) the
//!   read is not blocked; previously visible ids may be served until the
//!   refresh lands. There is **no forced cutoff**: if refreshes keep failing,
//!   the principal's last-known result stays usable and each later read retries
//!   (still single-flight) until one converges. Richard rejected a timed
//!   fallback to blocking fresh reads as "too disruptive" (b171a9d).
//!
//! While a refresh is pending after an epoch-only change (for example a
//! rebuild), a record deleted since the stamp can still have its current row
//! staged until the refresh lands; that is the bounded last-known staleness
//! Richard accepted (d433cb7). Ordinary native deletes are PatchClosure events
//! and are patched out immediately.
//!
//! Admission and caller-to-principal resolution happen before staging and are
//! never skipped; an offboarded principal is refused, not stale-served. Standby and member handles are never registered. Calls with
//! candidates, exact ids, class scopes, record limits or history windows do
//! not use it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::kernel::access_fence::{self, AccessClass};
use crate::{Db, Result};

const CAPACITY: usize = 8;
const DELTA_LIMIT: i64 = 512;
const CLOSURE_CAP: usize = 10_000;
/// Periodic background re-verify (Native 788c170). A timer owned by the
/// serving registration re-runs the full gate for every cached entry whose
/// last **successful full verification** is at least this old. It ticks every
/// half interval (plus up to 5% jitter), so an entry's worst-case age before a
/// full re-verify starts is about 1.5 × this (about 4.5 minutes). Age
/// is reset only by a full gate scan (a miss's publish or a refresh), never by
/// hits, cursor advances or in-place patches, so a busy, constantly patched
/// entry still converges any classification gap. Reads never wait on it and
/// nothing expires. A read that finds its entry overdue also starts a refresh
/// (in addition to the timer, never instead of it).
pub(crate) const REVERIFY_INTERVAL: Duration = Duration::from_secs(180);
/// Graceful stop: let an in-flight timer refresh finish before aborting it.
const STOP_GRACE: Duration = Duration::from_secs(2);

const SCOPES_DDL: &str = "CREATE TEMP TABLE IF NOT EXISTS _v2_scopes(home_id TEXT PRIMARY KEY, valid INTEGER, policy_view INTEGER, home_view INTEGER)";
pub(super) const HOMES: &str =
    "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    file: std::path::PathBuf,
    principal: String,
    /// Canonical folder grant. None shares the ordinary person/All entry.
    app_scope: Option<crate::kernel::app_installs::AppScope>,
    /// The only gate variant at this call site: whether the message guard is
    /// compiled in (`sql_record_visible(.., messages)`).
    messages: bool,
}

#[derive(Clone)]
struct Entry {
    key: Key,
    incarnation: uuid::Uuid,
    epoch: i64,
    content: i64,
    meta: i64,
    ids: Arc<BTreeSet<String>>,
    stale_since: Option<Instant>,
    /// When a full gate scan last produced (or confirmed) this set. Patches
    /// inherit it; misses and refreshes reset it.
    verified_at: Instant,
}

#[derive(Default)]
pub(crate) struct Cache {
    /// This registration's re-verify interval ([`REVERIFY_INTERVAL`] in
    /// production; shorter in tests).
    interval: Mutex<Duration>,
    entries: Mutex<Vec<Entry>>,
    refreshing: Mutex<HashSet<Key>>,
    pub(crate) stats: Mutex<Stats>,
    /// Test override of [`STATS_WINDOW`], and the lines the timer emitted.
    #[cfg(test)]
    pub(crate) stats_window: Mutex<Option<Duration>>,
    #[cfg(test)]
    pub(crate) emitted: Mutex<Vec<String>>,
    /// Test switch: make this cache's background refreshes fail.
    #[cfg(test)]
    pub(crate) fail_refresh: std::sync::atomic::AtomicBool,
    /// Test switch: behave as if no cache were registered, keeping entries.
    #[cfg(test)]
    pub(crate) bypass: std::sync::atomic::AtomicBool,
    /// Test hook: park a refresh inside its transaction (signal, then wait forever).
    #[cfg(test)]
    pub(crate) park: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

/// Monotonic counters for one registration: read by tests, and differenced
/// into the periodic aggregate [`stats_line`]. Counts and durations only;
/// never a principal, record id, SQL text, payload or file path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stats {
    pub(crate) hits: u64,
    pub(crate) patches: u64,
    pub(crate) misses: u64,
    pub(crate) stale_serves: u64,
    pub(crate) refreshes: u64,
    pub(crate) reverifies: u64,
    pub(crate) timer_refreshes: u64,
    pub(crate) timer_exits: u64,
    pub(crate) refresh_failures: u64,
    pub(crate) refresh_us: u64,
    pub(crate) refresh_max_us: u64,
    /// Plan decisions and the time spent making them (delta read, classify,
    /// closure patch) inside the reader's staging snapshot.
    pub(crate) plans: u64,
    pub(crate) plan_us: u64,
    pub(crate) plan_max_us: u64,
    /// Content events read by plan deltas (at most `DELTA_LIMIT + 1` per plan,
    /// so a lower bound when a delta overflows), and closure ids re-gated.
    pub(crate) delta_rows: u64,
    pub(crate) closure_ids: u64,
    /// `_v2_visible` population time: from cached ids (including serialising
    /// them) vs the full gate (including publishing the result on a miss).
    pub(crate) cached_stages: u64,
    pub(crate) cached_stage_us: u64,
    pub(crate) gate_stages: u64,
    pub(crate) gate_stage_us: u64,
}

/// Minimum span of one aggregate stats window per registration. The line is
/// emitted by the re-verify timer, which ticks every ~interval/2 (90 s plus
/// up to 5% jitter in production), so a window closes at the first tick at
/// or after this span: about 5-6.5 minutes, and `window_s` reports the
/// actual span. At most one line per window per serving handle (N serving
/// workspaces give N lines, deliberately without a handle identifier), none
/// for a window without cache activity, and none once serving stops; the
/// partial window in progress at stop is not reported.
pub(crate) const STATS_WINDOW: Duration = Duration::from_secs(300);

fn micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

impl Cache {
    fn bump(&self, f: impl FnOnce(&mut Stats)) {
        f(&mut self.stats.lock().unwrap());
    }

    fn record_refresh(&self, ok: bool, elapsed: Duration) {
        let us = micros(elapsed);
        self.bump(|s| {
            if ok {
                s.refreshes += 1;
            } else {
                s.refresh_failures += 1;
            }
            s.refresh_us = s.refresh_us.saturating_add(us);
            s.refresh_max_us = s.refresh_max_us.max(us);
        });
    }

    /// Gauges for the stats line: entries, stale entries, cached ids, and
    /// refreshes in flight.
    fn gauges(&self) -> (usize, usize, usize, usize) {
        let entries = self.entries.lock().unwrap();
        (
            entries.len(),
            entries.iter().filter(|e| e.stale_since.is_some()).count(),
            entries.iter().map(|e| e.ids.len()).sum(),
            self.refreshing.lock().unwrap().len(),
        )
    }

    fn get(&self, key: &Key) -> Option<Entry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| &e.key == key)
            .cloned()
    }

    /// Replace only with a newer (or equal-stamp, fresher) entry; LRU bound.
    fn publish(&self, entry: Entry) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(i) = entries.iter().position(|e| e.key == entry.key) {
            let old = &entries[i];
            if old.incarnation == entry.incarnation
                && (old.content, old.meta) > (entry.content, entry.meta)
            {
                return;
            }
            entries.remove(i);
        }
        entries.insert(0, entry);
        entries.truncate(CAPACITY);
    }

    fn mark_stale(&self, key: &Key) -> Instant {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        match entries.iter_mut().find(|e| &e.key == key) {
            Some(e) => *e.stale_since.get_or_insert(now),
            None => now,
        }
    }
}

/// One serving handle's cache registration: owns exactly one `Db` clone (the
/// only strong handle the timer machinery holds), the cache, the stop signal
/// and the timer task. The timer holds only `Weak<Registration>`, takes the
/// `Db` clone per tick for the duration of its refreshes, and exits when the
/// registration is gone or stopped. `stop_serving` drops the clone, signals
/// stop, and aborts the timer only after [`STOP_GRACE`]. Refreshes run in a
/// drop-guarded transaction, so an abort never returns a pooled connection
/// with an open transaction.
pub(crate) struct Registration {
    cache: Arc<Cache>,
    /// Set once a read has seen the persisted epoch; until then the first
    /// ordinary write creates it in its own transaction.
    epoch_ready: std::sync::atomic::AtomicBool,
    db: Mutex<Option<Db>>,
    stop: tokio::sync::watch::Sender<bool>,
    timer: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

fn registry() -> &'static Mutex<HashMap<uuid::Uuid, Arc<Registration>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<uuid::Uuid, Arc<Registration>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

fn cache_of(db: &Db) -> Option<Arc<Cache>> {
    registry()
        .lock()
        .unwrap()
        .get(&db.handle_id())
        .map(|r| r.cache.clone())
}

fn for_db(db: &Db) -> Option<Arc<Cache>> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return None;
    }
    let cache = cache_of(db)?;
    #[cfg(test)]
    if cache.bypass.load(std::sync::atomic::Ordering::SeqCst) {
        return None;
    }
    Some(cache)
}

/// Serving start (Native 788c170): the only enablement path. For a read-write
/// serving handle, register this handle's cache and start its re-verify
/// timer. **It never writes**: a serving open triggered by a read must leave
/// the database bytes unchanged. The persisted access epoch is created by the
/// handle's first ordinary write, inside that write's own transaction
/// ([`ensure_epoch_in_write`]); until it exists the cache does not publish.
/// Hosted serving calls it when it opens a workspace's read-write serving
/// handle; generic, inspection, CLI, standby and member opens never do.
/// Idempotent per handle.
pub(crate) async fn start_serving(db: &Db) -> Result<()> {
    start_serving_with_interval(db, REVERIFY_INTERVAL).await
}

async fn start_serving_with_interval(db: &Db, interval: Duration) -> Result<()> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Ok(());
    }
    if registry().lock().unwrap().contains_key(&db.handle_id()) {
        return Ok(());
    }
    let cache = Arc::new(Cache::default());
    *cache.interval.lock().unwrap() = interval;
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let registration = Arc::new(Registration {
        cache,
        epoch_ready: std::sync::atomic::AtomicBool::new(false),
        db: Mutex::new(Some(db.clone())),
        stop,
        timer: Mutex::new(None),
    });
    let timer = tokio::spawn(run_timer(Arc::downgrade(&registration), stop_rx, interval));
    *registration.timer.lock().unwrap() = Some(timer);
    let mut registry = registry().lock().unwrap();
    if registry.contains_key(&db.handle_id()) {
        // Lost a start race: stop ours, keep the registered one.
        drop(registry);
        shut_down(registration);
        return Ok(());
    }
    registry.insert(db.handle_id(), registration);
    Ok(())
}

/// Called from the ordinary event append path inside its write transaction:
/// for a registered serving handle whose epoch is not yet confirmed, create
/// and seed it in this same transaction. A rollback simply means the next
/// write tries again (an append in a transaction that is always rolled back,
/// such as a preview or dry run, just repeats the harmless attempt). Never
/// called for unregistered handles (prepare, migration, cutover, inspection,
/// CLI, standby replay and member copy all use unregistered handles).
pub(crate) async fn ensure_epoch_in_write(db: &Db, tx: &mut sqlx::SqliteConnection) -> Result<()> {
    let pending = registry()
        .lock()
        .unwrap()
        .get(&db.handle_id())
        .is_some_and(|r| !r.epoch_ready.load(std::sync::atomic::Ordering::Acquire));
    if pending {
        access_fence::ensure_epoch_on(tx).await?;
    }
    Ok(())
}

fn mark_epoch_ready(db: &Db) {
    if let Some(r) = registry().lock().unwrap().get(&db.handle_id()) {
        r.epoch_ready
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Unregister a retired (or closing) serving handle's cache: drop its `Db`
/// clone, stop the timer gracefully, abort it only after [`STOP_GRACE`].
pub(crate) fn stop_serving(db: &Db) {
    let registration = registry().lock().unwrap().remove(&db.handle_id());
    if let Some(registration) = registration {
        shut_down(registration);
    }
}

fn shut_down(registration: Arc<Registration>) {
    registration.db.lock().unwrap().take();
    let _ = registration.stop.send(true);
    let timer = registration.timer.lock().unwrap().take();
    drop(registration);
    if let Some(mut timer) = timer {
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if tokio::time::timeout(STOP_GRACE, &mut timer).await.is_err() {
                        timer.abort();
                    }
                });
            }
            Err(_) => timer.abort(),
        }
    }
}

/// Close-time hook: a registration still present when its handle closes was
/// not retired through the router; stop it and say so.
pub(crate) fn stop_serving_on_close(db: &Db) {
    if registry().lock().unwrap().contains_key(&db.handle_id()) {
        tracing::warn!(target: "native_ce::visible_cache", "visible-set cache registration still present at handle close; stopping it");
        stop_serving(db);
    }
}

/// Differences the monotonic [`Stats`] into one bounded aggregate line per
/// [`STATS_WINDOW`]. A window with no cache activity emits nothing.
struct StatsWindow {
    started: Instant,
    last: Stats,
}

impl StatsWindow {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            last: Stats::default(),
        }
    }

    fn tick(&mut self, cache: &Cache, now: Instant) -> Option<String> {
        let elapsed = now.saturating_duration_since(self.started);
        #[cfg(test)]
        let span = cache.stats_window.lock().unwrap().unwrap_or(STATS_WINDOW);
        #[cfg(not(test))]
        let span = STATS_WINDOW;
        if elapsed < span {
            return None;
        }
        let current = *cache.stats.lock().unwrap();
        let line = stats_line(elapsed, &self.last, &current, cache.gauges());
        self.started = now;
        self.last = current;
        line
    }
}

/// The aggregate line: `visible-cache` anchor and `key=value` fields.
/// Counters are monotonic per registration (never reset) and the line
/// reports their difference over the window; `*_mean_ms` are window means;
/// `*_max_ms_since_start` are maxima since registration; `entries`,
/// `stale_entries`, `cached_ids` and `refreshing` are gauges at emission.
/// `refresh_mean_ms` averages successful and failed refreshes. `None` when
/// the window saw no plans, stages or refreshes.
fn stats_line(
    window: Duration,
    last: &Stats,
    now: &Stats,
    (entries, stale_entries, cached_ids, refreshing): (usize, usize, usize, usize),
) -> Option<String> {
    let d = |f: fn(&Stats) -> u64| f(now).saturating_sub(f(last));
    let plans = d(|s| s.plans);
    let cached_stages = d(|s| s.cached_stages);
    let gate_stages = d(|s| s.gate_stages);
    let refreshes = d(|s| s.refreshes);
    let refresh_failures = d(|s| s.refresh_failures);
    if plans + cached_stages + gate_stages + refreshes + refresh_failures == 0 {
        return None;
    }
    let mean_ms = |us: u64, n: u64| {
        if n == 0 {
            0.0
        } else {
            us as f64 / n as f64 / 1000.0
        }
    };
    Some(format!(
        "visible-cache window_s={window_s} plans={plans} hits={hits} patches={patches} misses={misses} \
stale_serves={stale_serves} reverifies={reverifies} refreshes={refreshes} refresh_failures={refresh_failures} \
timer_refreshes={timer_refreshes} delta_rows={delta_rows} closure_ids={closure_ids} \
plan_mean_ms={plan_mean:.3} plan_max_ms_since_start={plan_max:.3} \
cached_stages={cached_stages} cached_stage_mean_ms={cached_mean:.3} \
gate_stages={gate_stages} gate_stage_mean_ms={gate_mean:.3} \
refresh_mean_ms={refresh_mean:.3} refresh_max_ms_since_start={refresh_max:.3} \
entries={entries} stale_entries={stale_entries} cached_ids={cached_ids} refreshing={refreshing}",
        window_s = window.as_secs(),
        hits = d(|s| s.hits),
        patches = d(|s| s.patches),
        misses = d(|s| s.misses),
        stale_serves = d(|s| s.stale_serves),
        reverifies = d(|s| s.reverifies),
        timer_refreshes = d(|s| s.timer_refreshes),
        delta_rows = d(|s| s.delta_rows),
        closure_ids = d(|s| s.closure_ids),
        plan_mean = mean_ms(d(|s| s.plan_us), plans),
        plan_max = now.plan_max_us as f64 / 1000.0,
        cached_mean = mean_ms(d(|s| s.cached_stage_us), cached_stages),
        gate_mean = mean_ms(d(|s| s.gate_stage_us), gate_stages),
        refresh_mean = mean_ms(d(|s| s.refresh_us), refreshes + refresh_failures),
        refresh_max = now.refresh_max_us as f64 / 1000.0,
    ))
}

async fn run_timer(
    registration: std::sync::Weak<Registration>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    interval: Duration,
) {
    let exit_cache = registration.upgrade().map(|r| Arc::downgrade(&r.cache));
    let mut window = StatsWindow::new(Instant::now());
    loop {
        // Tick at half the interval so an entry verified just after a tick is
        // never more than ~1.5 x interval old when re-verified.
        let half = interval / 2;
        let spread = (interval.as_millis() as u64 / 20).max(1);
        let jitter =
            Duration::from_millis(u64::from(uuid::Uuid::new_v4().as_bytes()[0]) * spread / 255);
        tokio::select! {
            _ = tokio::time::sleep(half + jitter) => {}
            _ = stop.changed() => break,
        }
        if *stop.borrow() {
            break;
        }
        let Some(live) = registration.upgrade() else {
            break;
        };
        let (db, cache) = (live.db.lock().unwrap().clone(), live.cache.clone());
        drop(live);
        let Some(db) = db else {
            break;
        };
        reverify_due(&db, &cache, interval).await;
        drop(db);
        // Serving may have stopped during the refreshes: emit nothing then.
        if *stop.borrow() {
            break;
        }
        if let Some(line) = window.tick(&cache, Instant::now()) {
            eprintln!("{line}");
            #[cfg(test)]
            cache.emitted.lock().unwrap().push(line);
        }
    }
    if let Some(cache) = exit_cache.and_then(|w| w.upgrade()) {
        cache.bump(|s| s.timer_exits += 1);
    }
}

/// One timer tick: fully re-verify every entry whose last successful full
/// verification is at least `interval` old (single-flight per key).
async fn reverify_due(db: &Db, cache: &Arc<Cache>, interval: Duration) {
    let due: Vec<Key> = cache
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.incarnation == db.handle_id() && e.verified_at.elapsed() >= interval)
        .map(|e| e.key.clone())
        .collect();
    for key in due {
        if !cache.refreshing.lock().unwrap().insert(key.clone()) {
            continue;
        }
        let started = Instant::now();
        let result = refresh(
            db,
            cache,
            &key.principal,
            key.messages,
            key.app_scope.clone(),
        )
        .await;
        cache.refreshing.lock().unwrap().remove(&key);
        cache.record_refresh(result.is_ok(), started.elapsed());
        if result.is_ok() {
            cache.bump(|s| s.timer_refreshes += 1);
        }
    }
}

/// Test-only enablement through the serving path.
#[cfg(test)]
pub(crate) async fn enable_for_test(db: &Db) -> Arc<Cache> {
    start_serving(db).await.unwrap();
    seed_epoch_for_test(db).await;
    cache_of(db).unwrap()
}

/// Test-only: seed the epoch as the first ordinary write would.
#[cfg(test)]
pub(crate) async fn seed_epoch_for_test(db: &Db) {
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    ensure_epoch_in_write(db, &mut tx).await.unwrap();
    tx.commit().await.unwrap();
}

/// Test-only: serving start with a short re-verify interval.
#[cfg(test)]
pub(crate) async fn enable_with_interval_for_test(db: &Db, interval: Duration) -> Arc<Cache> {
    start_serving_with_interval(db, interval).await.unwrap();
    seed_epoch_for_test(db).await;
    cache_of(db).unwrap()
}

/// Test-only: register through the real serving path without seeding.
#[cfg(test)]
pub(crate) async fn start_serving_for_test(db: &Db) {
    start_serving(db).await.unwrap();
}

/// Test-only: shorten this handle's stats window.
#[cfg(test)]
pub(crate) fn set_stats_window_for_test(db: &Db, window: Duration) {
    if let Some(cache) = cache_of(db) {
        *cache.stats_window.lock().unwrap() = Some(window);
    }
}

/// Test-only: a weak view of this handle's registration (lifecycle checks).
#[cfg(test)]
pub(crate) fn registration_weak_for_test(db: &Db) -> std::sync::Weak<Registration> {
    registry()
        .lock()
        .unwrap()
        .get(&db.handle_id())
        .map(Arc::downgrade)
        .unwrap_or_default()
}

/// Test-only: run one refresh directly (cancellation-safety checks).
#[cfg(test)]
pub(crate) async fn refresh_for_test(db: &Db, actor: &str) -> Result<()> {
    let cache = cache_of(db).expect("registered");
    refresh(db, &cache, actor, true, None).await
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn refresh_scope_for_test(
    db: &Db,
    actor: &str,
    scope: crate::kernel::app_installs::AppScope,
) -> Result<()> {
    let cache = cache_of(db).expect("registered");
    refresh(db, &cache, actor, true, Some(scope)).await
}

/// Test-only: park the next refresh inside its transaction; the returned
/// notifier is signalled once it has parked.
#[cfg(test)]
pub(crate) fn park_refresh_for_test(db: &Db) -> Arc<tokio::sync::Notify> {
    let cache = cache_of(db).expect("registered");
    let entered = Arc::new(tokio::sync::Notify::new());
    *cache.park.lock().unwrap() = Some(entered.clone());
    entered
}

/// Test-only: make every entry look last verified longer ago than the interval.
#[cfg(test)]
pub(crate) fn age_entries_for_test(db: &Db) {
    if let Some(cache) = cache_of(db) {
        let interval = *cache.interval.lock().unwrap();
        for entry in cache.entries.lock().unwrap().iter_mut() {
            entry.verified_at = Instant::now() - interval - Duration::from_secs(1);
        }
    }
}

#[cfg(test)]
pub(crate) fn disable_for_test(db: &Db) {
    stop_serving(db);
}

#[cfg(test)]
pub(crate) fn stats(db: &Db) -> Stats {
    cache_of(db)
        .map(|c| *c.stats.lock().unwrap())
        .unwrap_or_default()
}

/// Test switch: run reads as uncached fresh staging without dropping entries.
#[cfg(test)]
pub(crate) fn set_bypass_for_test(db: &Db, bypass: bool) {
    if let Some(cache) = cache_of(db) {
        cache
            .bypass
            .store(bypass, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Test switch: make this handle's background refreshes fail (or recover).
#[cfg(test)]
pub(crate) fn set_fail_refresh(db: &Db, fail: bool) {
    if let Some(cache) = cache_of(db) {
        cache
            .fail_refresh
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Test helper: run [`plan`] for `db`'s registered cache on a caller-held
/// connection whose snapshot is already open, with fresh scopes staged.
#[cfg(test)]
pub(crate) async fn plan_kind_for_test(
    conn: &mut sqlx::SqliteConnection,
    db: &Db,
    actor: &str,
) -> &'static str {
    let ctx = Context {
        db: db.clone(),
        cache: for_db(db).expect("registered"),
    };
    sqlx::query(SCOPES_DDL).execute(&mut *conn).await.unwrap();
    sqlx::query("DELETE FROM temp._v2_scopes")
        .execute(&mut *conn)
        .await
        .unwrap();
    let scope = crate::kernel::visible_home_anchors_as(conn, actor)
        .await
        .unwrap();
    for h in scope.homes {
        sqlx::query("INSERT INTO temp._v2_scopes VALUES(?,?,?,?)")
            .bind(h.home_id)
            .bind(h.policy_valid)
            .bind(h.policy_view)
            .bind(h.home_view)
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let messages = messages_on(conn).await.unwrap();
    let visibility = crate::kernel::sql_record_visible("r", "?1", HOMES, messages);
    let snap = snapshot_on(conn).await.unwrap();
    match plan(conn, &ctx, actor, messages, &visibility, snap)
        .await
        .unwrap()
    {
        Plan::Use(_) => "use",
        Plan::Miss { publish: true } => "miss_publish",
        Plan::Miss { publish: false } => "miss_no_publish",
    }
}

#[derive(Clone)]
pub(super) struct Context {
    db: Db,
    cache: Arc<Cache>,
}

tokio::task_local! { static CONTEXT: Context; }

/// Run staging `work` with this handle's cache in scope, if one is registered.
pub(super) async fn scoped<F: std::future::Future>(db: &Db, work: F) -> F::Output {
    match for_db(db) {
        Some(cache) => {
            CONTEXT
                .scope(
                    Context {
                        db: db.clone(),
                        cache,
                    },
                    work,
                )
                .await
        }
        None => work.await,
    }
}

pub(super) fn current() -> Option<Context> {
    CONTEXT.try_with(Clone::clone).ok()
}

/// Cursor and epoch visible in the caller's snapshot.
#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    epoch: Option<i64>,
    content: i64,
    meta: i64,
}

pub(super) async fn snapshot_on(conn: &mut sqlx::SqliteConnection) -> Result<Snapshot> {
    let epoch = access_fence::read_epoch_on(conn).await?;
    let (content, meta): (i64, i64) = sqlx::query_as("SELECT coalesce((SELECT max(seq) FROM main.content_events),0),coalesce((SELECT max(seq) FROM main.meta_events),0)")
        .fetch_one(&mut *conn)
        .await?;
    Ok(Snapshot {
        epoch,
        content,
        meta,
    })
}

pub(super) enum Plan {
    /// Stage exactly these ids (no gate scan).
    Use(Arc<BTreeSet<String>>),
    /// Stage normally; publish the result when `publish`.
    Miss { publish: bool },
}

/// Decide, inside the staging snapshot, how to populate `_v2_visible`.
/// `_v2_scopes` must already be staged (PatchClosure re-runs the gate).
pub(super) async fn plan(
    conn: &mut sqlx::SqliteConnection,
    ctx: &Context,
    actor: &str,
    messages: bool,
    visibility: &str,
    snap: Snapshot,
) -> Result<Plan> {
    let started = Instant::now();
    let plan = plan_inner(conn, ctx, actor, messages, visibility, snap).await;
    let us = micros(started.elapsed());
    ctx.cache.bump(|s| {
        s.plans += 1;
        s.plan_us = s.plan_us.saturating_add(us);
        s.plan_max_us = s.plan_max_us.max(us);
    });
    plan
}

/// Record how long `_v2_visible` population took, from cached ids
/// (`cached`) or through the full visibility gate.
pub(super) fn record_stage(ctx: &Context, cached: bool, elapsed: Duration) {
    let us = micros(elapsed);
    ctx.cache.bump(|s| {
        if cached {
            s.cached_stages += 1;
            s.cached_stage_us = s.cached_stage_us.saturating_add(us);
        } else {
            s.gate_stages += 1;
            s.gate_stage_us = s.gate_stage_us.saturating_add(us);
        }
    });
}

async fn plan_inner(
    conn: &mut sqlx::SqliteConnection,
    ctx: &Context,
    actor: &str,
    messages: bool,
    visibility: &str,
    snap: Snapshot,
) -> Result<Plan> {
    let Some(epoch) = snap.epoch else {
        return Ok(Plan::Miss { publish: false });
    };
    mark_epoch_ready(&ctx.db);
    let key = key(conn, ctx, actor, messages).await?;
    let Some(entry) = ctx.cache.get(&key) else {
        // A new folder grant may reuse the person's known set, but only
        // after narrowing it through this grant's staged homes. Keep the
        // original verification stamp and catch up in the background.
        if key.app_scope.is_some() {
            let broader = Key {
                app_scope: None,
                ..key.clone()
            };
            if let Some(entry) = ctx.cache.get(&broader).filter(|e| {
                e.incarnation == ctx.db.handle_id()
                    && e.content <= snap.content
                    && e.meta <= snap.meta
            }) {
                let ids: Vec<String> = sqlx::query_scalar(&format!(
                    "SELECT r.id FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?2)) AND ({visibility})"
                ))
                .bind(actor)
                .bind(serde_json::to_string(&*entry.ids)?)
                .fetch_all(&mut *conn).await?;
                let ids: Arc<BTreeSet<String>> = Arc::new(ids.into_iter().collect());
                ctx.cache.publish(Entry {
                    key: key.clone(),
                    ids: ids.clone(),
                    ..entry
                });
                ctx.cache.bump(|s| s.hits += 1);
                spawn_refresh(ctx, &key, actor, messages);
                return Ok(Plan::Use(ids));
            }
        }
        ctx.cache.bump(|s| s.misses += 1);
        return Ok(Plan::Miss { publish: true });
    };
    if entry.incarnation != ctx.db.handle_id() {
        ctx.cache.bump(|s| s.misses += 1);
        return Ok(Plan::Miss { publish: true });
    }
    // Never use an entry from ahead of this reader's snapshot.
    if entry.content > snap.content || entry.meta > snap.meta {
        ctx.cache.bump(|s| s.misses += 1);
        return Ok(Plan::Miss { publish: false });
    }
    if entry.epoch != epoch || entry.meta != snap.meta {
        return Ok(serve_stale(ctx, &key, &entry, actor, messages));
    }
    if entry.content == snap.content {
        ctx.cache.bump(|s| s.hits += 1);
        reverify_if_due(ctx, &key, &entry, actor, messages);
        return Ok(Plan::Use(entry.ids.clone()));
    }
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT type,payload,record_id FROM main.content_events WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?",
    )
    .bind(entry.content)
    .bind(snap.content)
    .bind(DELTA_LIMIT + 1)
    .fetch_all(&mut *conn)
    .await?;
    let delta_rows = rows.len() as u64;
    ctx.cache.bump(|s| s.delta_rows += delta_rows);
    if rows.len() as i64 > DELTA_LIMIT {
        return Ok(serve_stale(ctx, &key, &entry, actor, messages));
    }
    let mut subjects = BTreeSet::new();
    for (event_type, payload, record) in rows {
        // An unparseable payload could hide a refinement (e.g. a rehome's
        // `parent_update`), so it takes the conservative refresh path.
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload) else {
            return Ok(serve_stale(ctx, &key, &entry, actor, messages));
        };
        let is_home: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_roots WHERE root_id=?)")
                .bind(&record)
                .fetch_one(&mut *conn)
                .await?;
        match access_fence::classify(&event_type, &payload, is_home) {
            AccessClass::NoEffect | AccessClass::PatchHome => {}
            AccessClass::PatchClosure => {
                subjects.insert(record);
                for field in ["source_id", "target_id"] {
                    if let Some(id) = payload.get(field).and_then(|v| v.as_str()) {
                        subjects.insert(id.to_owned());
                    }
                }
            }
            AccessClass::RecomputePrincipals | AccessClass::RecomputeAll => {
                return Ok(serve_stale(ctx, &key, &entry, actor, messages));
            }
        }
    }
    let mut ids = (*entry.ids).clone();
    let patched = !subjects.is_empty();
    if patched {
        let Some(closure) = closure_on(conn, &subjects).await? else {
            return Ok(serve_stale(ctx, &key, &entry, actor, messages));
        };
        let closure_ids = closure.len() as u64;
        ctx.cache.bump(|s| s.closure_ids += closure_ids);
        let admitted: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT r.id FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?2)) AND ({visibility})"
        ))
        .bind(actor)
        .bind(serde_json::to_string(&closure)?)
        .fetch_all(&mut *conn)
        .await?;
        for id in &closure {
            ids.remove(id);
        }
        ids.extend(admitted);
    }
    let ids = Arc::new(ids);
    reverify_if_due(ctx, &key, &entry, actor, messages);
    ctx.cache.publish(Entry {
        content: snap.content,
        meta: snap.meta,
        ids: ids.clone(),
        stale_since: None,
        ..entry
    });
    ctx.cache
        .bump(|s| if patched { s.patches += 1 } else { s.hits += 1 });
    Ok(Plan::Use(ids))
}

/// Publish the gate output just staged by a miss, stamped at this snapshot.
pub(super) async fn publish_staged(
    conn: &mut sqlx::SqliteConnection,
    ctx: &Context,
    actor: &str,
    messages: bool,
    snap: Snapshot,
) -> Result<()> {
    let Some(epoch) = snap.epoch else {
        return Ok(());
    };
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM temp._v2_visible")
        .fetch_all(&mut *conn)
        .await?;
    ctx.cache.publish(Entry {
        key: key(conn, ctx, actor, messages).await?,
        incarnation: ctx.db.handle_id(),
        epoch,
        content: snap.content,
        meta: snap.meta,
        ids: Arc::new(ids.into_iter().collect()),
        stale_since: None,
        verified_at: Instant::now(),
    });
    Ok(())
}

async fn key(
    conn: &mut sqlx::SqliteConnection,
    ctx: &Context,
    actor: &str,
    messages: bool,
) -> Result<Key> {
    let app_scope = crate::kernel::app_installs::scope::active_scope_on(conn, actor)
        .await?
        .filter(|scope| scope.is_scoped());
    Ok(Key {
        file: ctx.db.path().to_owned(),
        principal: actor.to_owned(),
        app_scope,
        messages,
    })
}

/// Serve the principal's last-known set and start one background refresh.
fn serve_stale(ctx: &Context, key: &Key, entry: &Entry, actor: &str, messages: bool) -> Plan {
    ctx.cache.mark_stale(key);
    ctx.cache.bump(|s| s.stale_serves += 1);
    spawn_refresh(ctx, key, actor, messages);
    Plan::Use(entry.ids.clone())
}

/// Start the periodic re-verify for an entry that is due (served meanwhile).
fn reverify_if_due(ctx: &Context, key: &Key, entry: &Entry, actor: &str, messages: bool) {
    if entry.verified_at.elapsed() > *ctx.cache.interval.lock().unwrap() {
        ctx.cache.bump(|s| s.reverifies += 1);
        spawn_refresh(ctx, key, actor, messages);
    }
}

/// One single-flight background refresh per key.
fn spawn_refresh(ctx: &Context, key: &Key, actor: &str, messages: bool) {
    let first = ctx.cache.refreshing.lock().unwrap().insert(key.clone());
    if first {
        let (db, cache, actor, key) = (
            ctx.db.clone(),
            ctx.cache.clone(),
            actor.to_owned(),
            key.clone(),
        );
        tokio::spawn(async move {
            let started = Instant::now();
            let result = refresh(&db, &cache, &actor, messages, key.app_scope.clone()).await;
            cache.refreshing.lock().unwrap().remove(&key);
            cache.record_refresh(result.is_ok(), started.elapsed());
        });
    }
}

/// Recompute a principal's gate output in a fresh snapshot, exactly as full
/// staging does (fresh scopes, same variant, same predicate), and publish it.
pub(super) async fn refresh(
    db: &Db,
    cache: &Cache,
    actor: &str,
    messages_hint: bool,
    app_scope: Option<crate::kernel::app_installs::AppScope>,
) -> Result<()> {
    let work = refresh_inner(db, cache, actor, messages_hint, app_scope.clone());
    match app_scope {
        Some(scope) => {
            crate::kernel::app_installs::scope::with_scope_override(actor, scope, work).await
        }
        None => work.await,
    }
}

async fn refresh_inner(
    db: &Db,
    cache: &Cache,
    actor: &str,
    messages_hint: bool,
    app_scope: Option<crate::kernel::app_installs::AppScope>,
) -> Result<()> {
    #[cfg(test)]
    if cache.fail_refresh.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(crate::Error::engine(
            "forced visible-cache refresh failure (test)",
        ));
    }
    let mut conn = db.governed_pool().acquire().await?;
    // Drop-guarded: if this future is aborted or dropped mid-way, sqlx rolls
    // the transaction back before the connection can serve another borrower.
    let mut tx = sqlx::Acquire::begin(&mut *conn).await?;
    let result = async {
        let snap = snapshot_on(&mut tx).await?;
        #[cfg(test)]
        let parked = cache.park.lock().unwrap().take();
        #[cfg(test)]
        if let Some(entered) = parked {
            entered.notify_one();
            std::future::pending::<()>().await;
        }
        let Some(epoch) = snap.epoch else {
            return Ok(None);
        };
        sqlx::query(SCOPES_DDL).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM temp._v2_scopes")
            .execute(&mut *tx)
            .await?;
        let scope = crate::kernel::visible_home_anchors_as(&mut tx, actor).await?;
        let rows: Vec<_> = scope
            .homes
            .into_iter()
            .map(|h| (h.home_id, h.policy_valid, h.policy_view, h.home_view))
            .collect();
        for batch in rows.chunks(256) {
            sqlx::query("INSERT INTO temp._v2_scopes SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]') FROM json_each(?)")
                .bind(serde_json::to_string(batch)?)
                .execute(&mut *tx)
                .await?;
        }
        let messages = messages_on(&mut tx).await?;
        let visibility = crate::kernel::sql_record_visible("r", "?1", HOMES, messages);
        let ids: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT r.id FROM main.kernel_records r WHERE ({visibility})"
        ))
        .bind(actor)
        .fetch_all(&mut *tx)
        .await?;
        Ok::<_, crate::Error>(Some((snap, epoch, messages, ids)))
    }
    .await;
    let _ = tx.rollback().await;
    let Some((snap, epoch, messages, ids)) = result? else {
        return Ok(());
    };
    // A variant flip (first Message created) publishes under the new variant;
    // the old variant's entry then simply ages out of use.
    let _ = messages_hint;
    cache.publish(Entry {
        key: Key {
            file: db.path().to_owned(),
            principal: actor.to_owned(),
            app_scope,
            messages,
        },
        incarnation: db.handle_id(),
        epoch,
        content: snap.content,
        meta: snap.meta,
        ids: Arc::new(ids.into_iter().collect()),
        stale_since: None,
        verified_at: Instant::now(),
    });
    Ok(())
}

/// The gate's message-guard variant for this snapshot (same probe as staging).
pub(super) async fn messages_on(conn: &mut sqlx::SqliteConnection) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')")
        .fetch_one(&mut *conn)
        .await?)
}

/// Subjects plus their reverse active `part_of` closure, or `None` on overflow
/// (depth reaching the shared bearer bound, or more than [`CLOSURE_CAP`] ids).
async fn closure_on(
    conn: &mut sqlx::SqliteConnection,
    subjects: &BTreeSet<String>,
) -> Result<Option<BTreeSet<String>>> {
    let depth = i64::try_from(crate::authorization::MAX_DERIVED_BEARER_DEPTH).unwrap_or(i64::MAX);
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "WITH RECURSIVE c(id,depth) AS (SELECT value,0 FROM json_each(?1) UNION SELECT l.source_id,c.depth+1 FROM main.kernel_generic_links l JOIN c ON l.target_id=c.id WHERE l.active=1 AND l.relationship='part_of' AND c.depth<?2) SELECT id,max(depth) FROM c GROUP BY id LIMIT ?3",
    )
    .bind(serde_json::to_string(subjects)?)
    .bind(depth)
    .bind(i64::try_from(CLOSURE_CAP).unwrap_or(i64::MAX) + 1)
    .fetch_all(&mut *conn)
    .await?;
    if rows.len() > CLOSURE_CAP || rows.iter().any(|(_, d)| *d >= depth) {
        return Ok(None);
    }
    Ok(Some(rows.into_iter().map(|(id, _)| id).collect()))
}

#[cfg(test)]
mod stats_tests {
    use super::*;

    #[test]
    fn stats_line_is_bounded_aggregate_and_silent_when_idle() {
        let idle = Stats::default();
        assert_eq!(
            stats_line(STATS_WINDOW, &idle, &idle, (0, 0, 0, 0)),
            None,
            "an idle window emits nothing"
        );
        let last = Stats {
            hits: 5,
            plans: 5,
            plan_us: 5_000,
            ..Stats::default()
        };
        let now = Stats {
            hits: 9,
            patches: 2,
            misses: 1,
            stale_serves: 1,
            plans: 13,
            plan_us: 13_000,
            plan_max_us: 4_000,
            delta_rows: 30,
            closure_ids: 3,
            cached_stages: 12,
            cached_stage_us: 24_000,
            gate_stages: 1,
            gate_stage_us: 120_000,
            refreshes: 1,
            refresh_failures: 1,
            refresh_us: 300_000,
            refresh_max_us: 200_000,
            ..last
        };
        let line = stats_line(Duration::from_secs(301), &last, &now, (2, 1, 17_003, 0))
            .expect("activity emits a line");
        assert_eq!(
            line,
            "visible-cache window_s=301 plans=8 hits=4 patches=2 misses=1 stale_serves=1 reverifies=0 \
refreshes=1 refresh_failures=1 timer_refreshes=0 delta_rows=30 closure_ids=3 plan_mean_ms=1.000 \
plan_max_ms_since_start=4.000 cached_stages=12 cached_stage_mean_ms=2.000 gate_stages=1 \
gate_stage_mean_ms=120.000 refresh_mean_ms=150.000 refresh_max_ms_since_start=200.000 entries=2 \
stale_entries=1 cached_ids=17003 refreshing=0"
        );
    }

    #[test]
    fn stats_window_emits_at_most_once_per_window() {
        let cache = Cache::default();
        let start = Instant::now();
        let mut window = StatsWindow::new(start);
        cache.bump(|s| s.plans += 1);
        assert_eq!(window.tick(&cache, start + STATS_WINDOW / 2), None);
        assert!(window.tick(&cache, start + STATS_WINDOW).is_some());
        // The window restarts; the next tick inside it stays silent even
        // with new activity, and an idle full window emits nothing.
        cache.bump(|s| s.plans += 1);
        assert_eq!(
            window.tick(&cache, start + STATS_WINDOW + Duration::from_secs(1)),
            None
        );
        assert!(window.tick(&cache, start + STATS_WINDOW * 2).is_some());
        assert_eq!(window.tick(&cache, start + STATS_WINDOW * 3), None);
    }
}
