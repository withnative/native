//! A bounded, payload-free dump of instrumented pending node futures.
//! This is application-level instrumentation, not a native thread backtrace.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Clone)]
struct Task {
    name: &'static str,
    started_at: String,
    started: Instant,
}

#[derive(Default)]
struct Registry {
    next: u64,
    tasks: BTreeMap<u64, Task>,
}

fn registry() -> &'static Mutex<Registry> {
    static TASKS: OnceLock<Mutex<Registry>> = OnceLock::new();
    TASKS.get_or_init(Mutex::default)
}

pub(crate) struct Pending(Option<u64>);

impl Pending {
    pub(crate) fn new(name: &'static str) -> Self {
        let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
        // Connection floods must not make diagnostics unbounded.
        if registry.tasks.len() >= 1024 {
            return Self(None);
        }
        registry.next += 1;
        let id = registry.next;
        registry.tasks.insert(
            id,
            Task {
                name,
                started_at: chrono::Utc::now().to_rfc3339(),
                started: Instant::now(),
            },
        );
        Self(Some(id))
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(id) = self.0 {
            registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tasks
                .remove(&id);
        }
    }
}

pub(crate) async fn track<T>(name: &'static str, future: impl Future<Output = T>) -> T {
    let _pending = Pending::new(name);
    future.await
}

pub(crate) fn snapshot() -> serde_json::Value {
    let registry = registry().lock().unwrap_or_else(|e| e.into_inner());
    let tasks: Vec<_> = registry
        .tasks
        .iter()
        .map(|(id, task)| {
            serde_json::json!({
                "id": id, "future": task.name, "started_at": task.started_at,
                "elapsed_ms": task.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            })
        })
        .collect();
    serde_json::json!({
        "scope": "instrumented node futures; nested entries represent pending phases, not independent tasks",
        "capacity": 1024, "at_capacity": tasks.len() == 1024, "pending": tasks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_pending_future_removes_its_entry() {
        {
            let future = track(
                "diagnostic cancellation fixture",
                std::future::pending::<()>(),
            );
            tokio::pin!(future);
            tokio::select! {
                _ = &mut future => unreachable!(),
                _ = tokio::task::yield_now() => {},
            }
            assert!(snapshot()["pending"]
                .as_array()
                .unwrap()
                .iter()
                .any(|task| task["future"] == "diagnostic cancellation fixture"));
        }
        assert!(!snapshot()["pending"]
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["future"] == "diagnostic cancellation fixture"));
    }
}
