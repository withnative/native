//! Bounded, caller-independent schema analysis. No authority decisions are cached.
use super::*;
use crate::Error;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, OnceLock,
};

#[derive(Clone)]
pub(crate) struct Budget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    interrupts: Arc<Mutex<Vec<rusqlite::InterruptHandle>>>,
    #[cfg(test)]
    test_control: Option<Arc<ValidationRunTestControl>>,
}
impl Budget {
    fn stopped(&self) -> bool {
        #[cfg(test)]
        if let Some(control) = &self.test_control {
            return self.cancelled.load(Ordering::Acquire) || control.now() >= self.deadline;
        }
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.stopped() {
            Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "named view validation deadline or cancellation",
            ))
        } else {
            Ok(())
        }
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        for handle in self
            .interrupts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            handle.interrupt();
        }
    }
}
thread_local! { static ACTIVE: RefCell<Option<Budget>> = const { RefCell::new(None) }; }
pub(super) fn current() -> Option<Budget> {
    ACTIVE.with(|b| b.borrow().clone())
}
pub(super) fn arm(conn: &rusqlite::Connection) -> Result<()> {
    if let Some(budget) = current() {
        budget.check()?;
        budget
            .interrupts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(conn.get_interrupt_handle());
        let progress = budget.clone();
        conn.progress_handler(
            100,
            Some(move || {
                #[cfg(test)]
                if let Some(control) = &progress.test_control {
                    control.observe_progress();
                }
                progress.stopped()
            }),
        );
        conn.authorizer(Some(move |_: AuthContext<'_>| {
            if budget.stopped() {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    }
    Ok(())
}
struct CancelOnDrop(Budget);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The worker owns all fresh connections. Cancellation interrupts them and the
/// retiring task joins the worker even when its requesting future is dropped.
pub(crate) async fn run<T: Send + 'static>(
    deadline: Instant,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    run_inner(
        deadline,
        work,
        #[cfg(test)]
        None,
    )
    .await
}

// Shared body retains the original deadline, admission and retirement ordering.
// Only the test entry can supply an owned, operation-local clock/observation.
async fn run_inner<T: Send + 'static>(
    deadline: Instant,
    work: impl FnOnce() -> Result<T> + Send + 'static,
    #[cfg(test)] test_control: Option<Arc<ValidationRunTestControl>>,
) -> Result<T> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let slots = SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
        .clone();
    let budget = Budget {
        deadline,
        cancelled: Arc::new(AtomicBool::new(false)),
        interrupts: Arc::new(Mutex::new(Vec::new())),
        #[cfg(test)]
        test_control,
    };
    budget.check()?;
    let guard = CancelOnDrop(budget.clone());
    let until = tokio::time::Instant::from_std(deadline);
    #[cfg(not(test))]
    let permit = tokio::time::timeout_at(until, slots.acquire_owned()).await;
    #[cfg(test)]
    let permit = timeout_for_test(until, budget.test_control.as_ref(), slots.acquire_owned()).await;
    let permit = permit
        .map_err(|_| {
            sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "named view validator queue deadline",
            )
        })?
        .map_err(|_| contract_violation("validator queue closed"))?;
    let worker_budget = budget.clone();
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(worker_budget.clone()));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                ACTIVE.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        #[cfg(test)]
        if let Some(control) = &worker_budget.test_control {
            control.wait_before_work();
        }
        worker_budget.check()?;
        let result = work();
        worker_budget.check()?;
        result
    });
    let (send, recv) = tokio::sync::oneshot::channel();
    #[cfg(test)]
    let retiring_control = budget.test_control.clone();
    tokio::spawn(async move {
        let result = worker
            .await
            .map_err(|e| contract_violation(format!("validator worker: {e}")))
            .and_then(|r| r);
        // Actual JoinHandle settlement precedes this observation: worker locals,
        // connection, ACTIVE reset and original permit have all been dropped.
        #[cfg(test)]
        if let Some(control) = retiring_control {
            control.retired.notify_one();
        }
        let _ = send.send(result);
    });
    #[cfg(not(test))]
    let result = tokio::time::timeout_at(until, recv).await;
    #[cfg(test)]
    let result = timeout_for_test(until, budget.test_control.as_ref(), recv).await;
    let result = result
        .map_err(|_| {
            sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "named view validator deadline",
            )
        })?
        .map_err(|_| contract_violation("validator worker unavailable"))?;
    drop(guard);
    result
}

// Test controls own only clock/observation/gate state. They never retain a
// Budget, connection, permit, worker, closure or future. Captures point one way.
#[cfg(test)]
pub(super) enum ValidationRunTestMode {
    ObserveVm,
    HoldBeforeWork,
}

#[cfg(test)]
pub(super) struct ValidationRunTestControl {
    origin: Instant,
    deadline: Instant,
    expired: AtomicBool,
    expiry: tokio::sync::watch::Sender<bool>,
    interested: AtomicBool,
    validator_built: AtomicBool,
    observed_vm: AtomicBool,
    vm: tokio::sync::Notify,
    before: tokio::sync::Notify,
    retired: tokio::sync::Notify,
    gate: Mutex<bool>,
    gate_changed: std::sync::Condvar,
}

#[cfg(test)]
pub(super) struct ValidationRunTestRelease(Arc<ValidationRunTestControl>);

#[cfg(test)]
impl Drop for ValidationRunTestRelease {
    fn drop(&mut self) {
        // Installed before dispatch; synchronous and unconditional on failure.
        self.0.expire_at_deadline();
        self.0.release_before_work();
    }
}

#[cfg(test)]
pub(super) fn validation_run_test_control(
    mode: ValidationRunTestMode,
) -> (Arc<ValidationRunTestControl>, ValidationRunTestRelease) {
    let origin = Instant::now();
    let (expiry, _) = tokio::sync::watch::channel(false);
    let control = Arc::new(ValidationRunTestControl {
        origin,
        deadline: origin + Duration::from_millis(100),
        expired: AtomicBool::new(false),
        expiry,
        interested: AtomicBool::new(false),
        validator_built: AtomicBool::new(false),
        observed_vm: AtomicBool::new(false),
        vm: tokio::sync::Notify::new(),
        before: tokio::sync::Notify::new(),
        retired: tokio::sync::Notify::new(),
        gate: Mutex::new(matches!(mode, ValidationRunTestMode::ObserveVm)),
        gate_changed: std::sync::Condvar::new(),
    });
    let release = ValidationRunTestRelease(control.clone());
    (control, release)
}

#[cfg(test)]
impl ValidationRunTestControl {
    fn now(&self) -> Instant {
        if self.expired.load(Ordering::Acquire) {
            self.deadline
        } else {
            self.origin
        }
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(super) fn observe_next_statement(&self) {
        self.interested.store(true, Ordering::Release);
    }
    // Called by the worker only AFTER building its actual validator. Interest
    // armed by the test thread cannot turn setup VM steps into query evidence.
    pub(super) fn validator_built(&self) {
        self.validator_built.store(true, Ordering::Release);
    }
    fn observe_progress(&self) {
        if self.validator_built.load(Ordering::Acquire)
            && self.interested.swap(false, Ordering::AcqRel)
        {
            self.observed_vm.store(true, Ordering::Release);
            self.vm.notify_one();
        }
    }
    pub(super) fn has_vm_started(&self) -> bool {
        self.observed_vm.load(Ordering::Acquire)
    }
    pub(super) async fn vm_started(&self) {
        self.vm.notified().await;
    }
    pub(super) async fn before_work(&self) {
        self.before.notified().await;
    }
    pub(super) async fn worker_retired(&self) {
        self.retired.notified().await;
    }
    pub(super) fn expire_at_deadline(&self) {
        // Clock advance only. Cancellation and actual interrupt custody remain
        // the original CancelOnDrop/Budget::cancel path, never a test substitute.
        self.expired.store(true, Ordering::Release);
        self.expiry.send_replace(true);
    }
    async fn deadline_expired(&self) {
        let mut expiry = self.expiry.subscribe();
        loop {
            if *expiry.borrow_and_update() {
                return;
            }
            expiry
                .changed()
                .await
                .expect("control retains expiry sender");
        }
    }
    fn wait_before_work(&self) {
        let mut released = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*released {
            // The worker already owns its original permit. This is a dispatch
            // gate for ONE operation, not proof of eight-slot saturation.
            self.before.notify_one();
            while !*released {
                released = self
                    .gate_changed
                    .wait(released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }
    pub(super) fn release_before_work(&self) {
        *self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.gate_changed.notify_all();
    }
}

#[cfg(test)]
async fn timeout_for_test<F: std::future::Future>(
    until: tokio::time::Instant,
    control: Option<&Arc<ValidationRunTestControl>>,
    work: F,
) -> std::result::Result<F::Output, ()> {
    let Some(control) = control else {
        return tokio::time::timeout_at(until, work).await.map_err(|_| ());
    };
    tokio::select! {
        biased;
        result = work => Ok(result),
        _ = control.deadline_expired() => Err(()),
    }
}

#[cfg(test)]
pub(super) async fn run_controlled_for_test<T: Send + 'static>(
    control: Arc<ValidationRunTestControl>,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    run_inner(control.deadline(), work, Some(control)).await
}

type Reads = BTreeSet<(String, String)>;
struct Entry {
    key: String,
    value: std::result::Result<Reads, String>,
    bytes: usize,
}
#[derive(Default)]
struct Cache {
    entries: VecDeque<Entry>,
    bytes: usize,
}
impl Cache {
    fn insert(&mut self, entry: Entry) {
        if entry.bytes > 8 * 1024 * 1024 || self.entries.iter().any(|e| e.key == entry.key) {
            return;
        }
        while self.entries.len() >= 128 || self.bytes + entry.bytes > 8 * 1024 * 1024 {
            if let Some(old) = self.entries.pop_front() {
                self.bytes -= old.bytes;
            } else {
                break;
            }
        }
        self.bytes += entry.bytes;
        self.entries.push_back(entry);
    }
}
static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
const VALIDATOR_REVISION: u32 = 2;
#[cfg(test)]
pub(crate) fn clear_cache() {
    if let Some(cache) = CACHE.get() {
        *cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Cache::default();
    }
}

#[cfg(test)]
pub(crate) fn evict_cache_entry(digest: &str) {
    if let Some(cache) = CACHE.get() {
        let mut cache = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .entries
            .retain(|entry| !entry.key.starts_with(&format!("{digest}:")));
        cache.bytes = cache.entries.iter().map(|entry| entry.bytes).sum();
    }
}

#[cfg(test)]
static BUILDS: OnceLock<Mutex<BTreeMap<String, usize>>> = OnceLock::new();
#[cfg(test)]
pub(crate) fn builds(digest: &str) -> usize {
    BUILDS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap()
        .get(digest)
        .copied()
        .unwrap_or(0)
}
pub(crate) async fn analyze(
    closure: &crate::named_views::closure::Closure,
    deadline: Instant,
) -> Result<Reads> {
    let retained = closure.clone();
    analyze_with(closure, deadline, move || retained.analyze_schema()).await
}

pub(crate) enum Outcome {
    Valid(Reads),
    Invalid(Error),
}
pub(crate) async fn analyze_diagnostic(
    closure: &crate::named_views::closure::Closure,
    deadline: Instant,
) -> Result<Outcome> {
    let retained = closure.clone();
    analyze_classified(closure, deadline, move || retained.analyze_schema()).await
}
pub(crate) async fn analyze_with(
    closure: &crate::named_views::closure::Closure,
    deadline: Instant,
    work: impl FnOnce() -> std::result::Result<Reads, super::named_views::SchemaFailure>
        + Send
        + 'static,
) -> Result<Reads> {
    match analyze_classified(closure, deadline, work).await? {
        Outcome::Valid(reads) => Ok(reads),
        Outcome::Invalid(error) => Err(error),
    }
}
async fn analyze_classified(
    closure: &crate::named_views::closure::Closure,
    deadline: Instant,
    work: impl FnOnce() -> std::result::Result<Reads, super::named_views::SchemaFailure>
        + Send
        + 'static,
) -> Result<Outcome> {
    if Instant::now() >= deadline {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::Timeout,
            "named view validation deadline",
        ));
    }
    // The closure digest includes every exact tuple; each definition digest
    // commits to its source pins. Current visibility/source checks run BEFORE
    // this function on every request. Never cache their results or timeouts.
    let key = format!(
        "{}:{VALIDATOR_REVISION}:{}",
        closure.digest,
        sql_contract::LOGICAL_CATALOG_REVISION
    );
    let cache = CACHE.get_or_init(|| Mutex::new(Cache::default()));
    {
        let mut c = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(position) = c.entries.iter().position(|e| e.key == key) {
            let entry = c.entries.remove(position).unwrap();
            let result = entry.value.clone().map_err(Error::engine);
            c.entries.push_back(entry);
            return Ok(match result {
                Ok(reads) => Outcome::Valid(reads),
                Err(error) => Outcome::Invalid(error),
            });
        }
    }
    #[cfg(test)]
    {
        *BUILDS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap()
            .entry(closure.digest.clone())
            .or_default() += 1;
    }
    let weight = closure
        .nodes
        .iter()
        .map(|n| serde_json::to_vec(&n.definition).map(|v| v.len()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    // Typed worker outcome: only schema rule failures are retained. Worker
    // panic, setup, resource, serialization and queue/deadline failures escape
    // through the outer Result and never enter the cache.
    let outcome = run(deadline, move || Ok(work())).await?;
    let (result, cacheable) = match outcome {
        Ok(reads) => (Ok(reads), true),
        Err(super::named_views::SchemaFailure::Rule(error)) => (Err(error), true),
        Err(super::named_views::SchemaFailure::Infrastructure(error)) => return Err(error),
    };
    if Instant::now() < deadline
        && cacheable
        && result
            .as_ref()
            .err()
            .is_none_or(|e| matches!(e, Error::Engine(_)))
    {
        let value = result
            .as_ref()
            .map(Clone::clone)
            .map_err(ToString::to_string);
        let bytes = weight
            + key.len()
            + match &value {
                Ok(reads) => reads.iter().map(|(a, b)| a.len() + b.len() + 64).sum(),
                Err(e) => e.len(),
            };
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(Entry { key, value, bytes });
    }

    Ok(match result {
        Ok(reads) => Outcome::Valid(reads),
        Err(error) => Outcome::Invalid(error),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_view_cache_enforces_entry_and_byte_bounds() {
        let mut cache = Cache::default();
        let entry = |i: usize, bytes| Entry {
            key: i.to_string(),
            value: Ok(BTreeSet::new()),
            bytes,
        };
        for i in 0..129 {
            cache.insert(entry(i, 1));
        }
        assert_eq!(cache.entries.len(), 128);
        assert_eq!(cache.bytes, 128);
        assert_eq!(cache.entries.front().unwrap().key, "1");
        cache.insert(entry(130, 8 * 1024 * 1024));
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.bytes, 8 * 1024 * 1024);
        cache.insert(entry(131, 8 * 1024 * 1024 + 1));
        assert_eq!(cache.entries.front().unwrap().key, "130");
    }
    #[tokio::test]
    async fn named_view_cancellation_denies_sqlite_prepare_without_vm_work() {
        let result = run(Instant::now() + Duration::from_secs(2), || {
            let validators = super::super::NamedViewValidators::new(&[(
                "view_prepare".into(),
                "SELECT id FROM records".into(),
            )])?;
            current().unwrap().cancel();
            // No VM steps run: SQLite authorizer denies during prepare itself.
            let error = validators
                .inspect("SELECT id FROM view_prepare")
                .unwrap_err();
            assert!(error.to_string().contains("not authorized"), "{error}");
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(
            result.to_string().contains("deadline or cancellation")
                || result.to_string().contains("validator queue deadline"),
            "{result}"
        );
    }
}
