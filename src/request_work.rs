//! Opt-in request-local counters for hosted diagnostic measurements.
//!
//! Ordinary requests install no scope. Instrumented storage and custody seams
//! therefore pay only a task-local lookup before returning.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

tokio::task_local! {
    static CURRENT: Arc<Counters>;
}

#[derive(Debug, Default)]
pub(crate) struct Counters {
    catalog_statements: AtomicU64,
    workspace_writer_acquisitions: AtomicU64,
}

impl Counters {
    pub(crate) fn record_catalog_statement(&self) {
        self.catalog_statements.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_workspace_writer_acquisition(&self) {
        self.workspace_writer_acquisitions
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// A request's opt-in storage and custody counters.
#[derive(Clone, Debug)]
pub struct RequestWork {
    counters: Arc<Counters>,
    custody: Arc<native_federation::CustodyWorkCounters>,
}

/// Point-in-time request work totals.
///
/// `catalog_statements` is the literal number of SQLite `SQLITE_TRACE_STMT`
/// events while the request owns catalog-pool checkouts. It includes explicit
/// transaction controls and trigger/virtual-table substatements. Connection
/// setup and release sanitization run outside the attached interval.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestWorkSnapshot {
    pub catalog_statements: u64,
    pub workspace_writer_acquisitions: u64,
    pub custody_shared_locks: u64,
    pub custody_exclusive_locks: u64,
}

impl RequestWork {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(Counters::default()),
            custody: Arc::new(native_federation::CustodyWorkCounters::default()),
        }
    }

    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        let counters = Arc::clone(&self.counters);
        native_federation::with_custody_scope(
            Arc::clone(&self.custody),
            CURRENT.scope(counters, future),
        )
        .await
    }

    pub fn snapshot(&self) -> RequestWorkSnapshot {
        let (custody_shared_locks, custody_exclusive_locks) = self.custody.snapshot();
        RequestWorkSnapshot {
            catalog_statements: self.counters.catalog_statements.load(Ordering::Relaxed),
            workspace_writer_acquisitions: self
                .counters
                .workspace_writer_acquisitions
                .load(Ordering::Relaxed),
            custody_shared_locks,
            custody_exclusive_locks,
        }
    }
}

impl Default for RequestWork {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn current() -> Option<Arc<Counters>> {
    CURRENT.try_with(Arc::clone).ok()
}

pub(crate) fn record_workspace_writer_acquisition() {
    let _ = CURRENT.try_with(|counters| counters.record_workspace_writer_acquisition());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_scopes_are_isolated_and_do_not_leak() {
        let first = RequestWork::new();
        let second = RequestWork::new();
        tokio::join!(
            first.scope(async {
                record_workspace_writer_acquisition();
                record_workspace_writer_acquisition();
            }),
            second.scope(async {
                record_workspace_writer_acquisition();
            }),
        );
        assert_eq!(first.snapshot().workspace_writer_acquisitions, 2);
        assert_eq!(second.snapshot().workspace_writer_acquisitions, 1);
        record_workspace_writer_acquisition();
        assert_eq!(first.snapshot().workspace_writer_acquisitions, 2);
        assert!(current().is_none());
    }
}
