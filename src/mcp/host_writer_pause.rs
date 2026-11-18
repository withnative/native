//! Process-scoped pause for background writers that the freeze lease does not
//! cover (backup sweep, snapshot upload, catalog purges).
//!
//! Pause is cooperative: an in-flight VACUUM INTO or object upload finishes at
//! its existing clean boundary, then no new pass starts until resume. A new
//! process has a new gate, so a restart cannot inherit a paused serving loop.
//!
//! Cooperative also means unbounded: the clean boundary of a fleet-wide upload
//! pass is the end of that pass. A caller that has production work waiting on
//! the drain must use [`WriterPause::pause_and_drain_timeout`] and give up
//! rather than wait a pass out.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

/// Shared pause flag plus in-flight counter for one serving process.
#[derive(Clone, Debug)]
pub struct WriterPause {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    paused: AtomicBool,
    in_flight: AtomicUsize,
    notify: Notify,
}

impl Default for WriterPause {
    fn default() -> Self {
        Self::new()
    }
}

impl WriterPause {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                paused: AtomicBool::new(false),
                in_flight: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
        }
    }

    pub fn is_paused(&self) -> bool {
        self.inner.paused.load(Ordering::SeqCst)
    }

    pub fn pause(&self) {
        self.inner.paused.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    pub fn resume(&self) {
        self.inner.paused.store(false, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Set pause, then wait until every in-flight pass has dropped its guard.
    pub async fn pause_and_drain(&self) {
        self.pause();
        self.wait_idle().await;
    }

    /// Set pause, then wait up to `timeout` for every in-flight pass to drop
    /// its guard. `true` if the gate drained, `false` if the bound expired.
    ///
    /// The gate stays paused either way: a caller that gives up owns the
    /// decision to [`resume`](Self::resume). An unbounded
    /// [`pause_and_drain`](Self::pause_and_drain) is the right call when
    /// nothing is waiting on the drain; it is the wrong call when production
    /// writes are queued behind it, because a single in-flight fleet pass can
    /// hold the gate for minutes.
    pub async fn pause_and_drain_timeout(&self, timeout: Duration) -> bool {
        self.pause();
        tokio::time::timeout(timeout, self.wait_idle())
            .await
            .is_ok()
    }

    pub async fn wait_idle(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Wait until the gate is not paused (or return immediately if it is not).
    pub async fn wait_while_paused(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.is_paused() {
                return;
            }
            notified.await;
        }
    }

    /// Start a sweep/upload/purge pass. `None` if the lease has paused writers.
    pub fn try_begin(&self) -> Option<InFlightGuard> {
        if self.is_paused() {
            return None;
        }
        self.inner.in_flight.fetch_add(1, Ordering::SeqCst);
        if self.is_paused() {
            self.release_one();
            return None;
        }
        Some(InFlightGuard {
            inner: Arc::clone(&self.inner),
        })
    }

    // Gate identity, not current pause intent: an admitted pass drains normally.
    #[cfg(feature = "mcp-executor-prototype")]
    pub(crate) fn owns(&self, pass: &InFlightGuard) -> bool {
        Arc::ptr_eq(&self.inner, &pass.inner)
    }

    fn release_one(&self) {
        let previous = self.inner.in_flight.fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            self.inner.notify.notify_waiters();
        }
    }
}

/// Held for the duration of one background pass.
#[derive(Debug)]
#[must_use = "dropping the guard is what marks the pass idle"]
pub struct InFlightGuard {
    inner: Arc<Inner>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let previous = self.inner.in_flight.fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            self.inner.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pause_waits_for_in_flight_then_blocks_new_passes() {
        let pause = WriterPause::new();
        let guard = pause.try_begin().expect("open gate admits a pass");
        let waiter = pause.clone();
        let drained = tokio::spawn(async move {
            waiter.pause_and_drain().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !drained.is_finished(),
            "drain must wait for the in-flight pass"
        );
        drop(guard);
        tokio::time::timeout(Duration::from_secs(2), drained)
            .await
            .expect("drain after drop")
            .unwrap();
        assert!(pause.try_begin().is_none());
        pause.resume();
        assert!(pause.try_begin().is_some());
    }

    #[tokio::test]
    async fn bounded_drain_reports_whether_the_gate_went_idle() {
        let pause = WriterPause::new();
        assert!(
            pause.pause_and_drain_timeout(Duration::from_secs(5)).await,
            "an idle gate drains immediately"
        );
        pause.resume();

        let guard = pause.try_begin().expect("open gate admits a pass");
        assert!(
            !pause
                .pause_and_drain_timeout(Duration::from_millis(50))
                .await,
            "a pass that outlives the bound must report the bound expired"
        );
        // The bound expiring does not resume: the caller owns that choice.
        assert!(pause.is_paused());
        assert!(pause.try_begin().is_none());
        pause.resume();
        drop(guard);
        assert!(pause.try_begin().is_some());
    }
}
