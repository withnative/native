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
}
impl Budget {
    fn stopped(&self) -> bool {
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
        conn.progress_handler(100, Some(move || progress.stopped()));
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
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let slots = SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
        .clone();
    let budget = Budget {
        deadline,
        cancelled: Arc::new(AtomicBool::new(false)),
        interrupts: Arc::new(Mutex::new(Vec::new())),
    };
    budget.check()?;
    let guard = CancelOnDrop(budget.clone());
    let until = tokio::time::Instant::from_std(deadline);
    let permit = tokio::time::timeout_at(until, slots.acquire_owned())
        .await
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
        worker_budget.check()?;
        let result = work();
        worker_budget.check()?;
        result
    });
    let (send, recv) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = worker
            .await
            .map_err(|e| contract_violation(format!("validator worker: {e}")))
            .and_then(|r| r);
        let _ = send.send(result);
    });
    let result = tokio::time::timeout_at(until, recv)
        .await
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

pub(crate) async fn analyze_with(
    closure: &crate::named_views::closure::Closure,
    deadline: Instant,
    work: impl FnOnce() -> std::result::Result<Reads, super::named_views::SchemaFailure>
        + Send
        + 'static,
) -> Result<Reads> {
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
            return result;
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
        Err(super::named_views::SchemaFailure::Infrastructure(error)) => (Err(error), false),
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

    result
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
        assert!(result.to_string().contains("deadline or cancellation"));
    }
}
