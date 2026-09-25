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
    catalog_acquisitions: AtomicU64,
    workspace_reader_acquisitions: AtomicU64,
    workspace_writer_acquisitions: AtomicU64,
    write_transactions: AtomicU64,
    write_begin_busy_retried_transactions: AtomicU64,
    write_begin_busy_retries: AtomicU64,
    write_begin_cleanup_retries: AtomicU64,
    write_begin_wait_micros: AtomicU64,
}

impl Counters {
    pub(crate) fn record_catalog_statement(&self) {
        self.catalog_statements.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_catalog_acquisition(&self) {
        self.catalog_acquisitions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_workspace_reader_acquisition(&self) {
        self.workspace_reader_acquisitions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_workspace_writer_acquisition(&self) {
        self.workspace_writer_acquisitions
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_write_begin(&self, retries: crate::db::BeginRetries, wait_micros: u64) {
        self.write_transactions.fetch_add(1, Ordering::Relaxed);
        if retries.busy > 0 {
            self.write_begin_busy_retried_transactions
                .fetch_add(1, Ordering::Relaxed);
            self.write_begin_busy_retries
                .fetch_add(retries.busy as u64, Ordering::Relaxed);
        }
        if retries.cleanup > 0 {
            self.write_begin_cleanup_retries
                .fetch_add(retries.cleanup as u64, Ordering::Relaxed);
        }
        self.write_begin_wait_micros
            .fetch_add(wait_micros, Ordering::Relaxed);
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
    pub catalog_acquisitions: u64,
    pub workspace_reader_acquisitions: u64,
    pub workspace_writer_acquisitions: u64,
    pub custody_shared_locks: u64,
    pub custody_exclusive_locks: u64,
    /// `BEGIN IMMEDIATE` acquisitions attempted in this request, successful or
    /// not. A request that writes nothing reports zero here.
    pub write_transactions: u64,
    /// How many of those had to retry because another writer still held the
    /// reserved lock after SQLite's own five-second `busy_timeout`. Ordinary
    /// queueing never reaches here — it is absorbed inside SQLite and shows up
    /// only in `write_begin_wait_micros`.
    pub write_begin_busy_retried_transactions: u64,
    /// Those retry iterations, summed.
    pub write_begin_busy_retries: u64,
    /// Retry iterations spent waiting for a canceled transaction's rollback to
    /// drain before pooled reuse. Housekeeping, not contention, and counted
    /// apart so it cannot be mistaken for it.
    pub write_begin_cleanup_retries: u64,
    /// Total time spent inside the bounded retry loop, in microseconds.
    pub write_begin_wait_micros: u64,
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
            catalog_acquisitions: self.counters.catalog_acquisitions.load(Ordering::Relaxed),
            workspace_reader_acquisitions: self
                .counters
                .workspace_reader_acquisitions
                .load(Ordering::Relaxed),
            workspace_writer_acquisitions: self
                .counters
                .workspace_writer_acquisitions
                .load(Ordering::Relaxed),
            custody_shared_locks,
            custody_exclusive_locks,
            write_transactions: self.counters.write_transactions.load(Ordering::Relaxed),
            write_begin_busy_retried_transactions: self
                .counters
                .write_begin_busy_retried_transactions
                .load(Ordering::Relaxed),
            write_begin_busy_retries: self
                .counters
                .write_begin_busy_retries
                .load(Ordering::Relaxed),
            write_begin_cleanup_retries: self
                .counters
                .write_begin_cleanup_retries
                .load(Ordering::Relaxed),
            write_begin_wait_micros: self
                .counters
                .write_begin_wait_micros
                .load(Ordering::Relaxed),
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

/// Record a bounded `BEGIN IMMEDIATE` acquisition against this request, if one
/// is being measured. Recorded whether the acquisition succeeded or exhausted
/// its deadline: a request that gave up waiting is the most contended request
/// there is, and dropping it would bias the counter towards calm.
pub(crate) fn record_write_begin(retries: crate::db::BeginRetries, wait_micros: u64) {
    let _ = CURRENT.try_with(|counters| counters.record_write_begin(retries, wait_micros));
}

pub(crate) fn record_workspace_reader_acquisition() {
    let _ = CURRENT.try_with(|counters| counters.record_workspace_reader_acquisition());
}

pub(crate) fn record_catalog_acquisition() {
    let _ = CURRENT.try_with(|counters| counters.record_catalog_acquisition());
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
                record_catalog_acquisition();
                record_workspace_reader_acquisition();
                record_workspace_writer_acquisition();
                record_workspace_writer_acquisition();
            }),
            second.scope(async {
                record_workspace_reader_acquisition();
                record_workspace_writer_acquisition();
            }),
        );
        assert_eq!(first.snapshot().catalog_acquisitions, 1);
        assert_eq!(second.snapshot().catalog_acquisitions, 0);
        assert_eq!(first.snapshot().workspace_reader_acquisitions, 1);
        assert_eq!(second.snapshot().workspace_reader_acquisitions, 1);
        assert_eq!(first.snapshot().workspace_writer_acquisitions, 2);
        assert_eq!(second.snapshot().workspace_writer_acquisitions, 1);
        record_workspace_writer_acquisition();
        assert_eq!(first.snapshot().workspace_writer_acquisitions, 2);
        assert!(current().is_none());
    }
}
