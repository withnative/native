//! In-memory, process-local state that keeps routine verification cheap.
//!
//! Nothing here is persisted: a restart (or an older binary) starts clear and
//! simply does the full work once. None of it is authority for account
//! binding, write admission or deletion safety; each use below names the
//! narrow harm it avoids and keeps the check that guards that harm.
//!
//! * [`Flights`]: single-flight per (generation, consumer). Two callers that
//!   want the same generation verified never run two passes at once; the
//!   second waits and reuses the first's completed, input-stamped result.
//! * [`FreshBuilds`]: generations this process itself built and device-
//!   verified during a refresh. A connected handoff of such a generation
//!   needs only cheap identity checks in the foreground; the heavy phases run
//!   in the background and a failure there stops serving it.
//! * [`RetentionBackoff`]: a prior that keeps failing the same way, with
//!   unchanged inputs, is not re-copied and re-checked every sweep. It is
//!   never deleted by this mechanism.
use super::verification_status::StatusStamp;
use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type FlightKey = (String, Vec<u8>);

#[derive(Debug, Default)]
pub(super) struct Flight {
    gate: Arc<tokio::sync::Mutex<()>>,
    /// Count of passes that completed successfully. A waiter that saw this
    /// advance while it queued may reuse that pass.
    completed_ok: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Flights(Arc<Mutex<HashMap<FlightKey, Arc<Flight>>>>);

/// Held for the duration of one verification pass of one generation.
pub(super) struct FlightTurn {
    flight: Arc<Flight>,
    _gate: tokio::sync::OwnedMutexGuard<()>,
    /// True when another pass for the same key completed successfully while
    /// this caller waited for its turn.
    pub(super) shared: bool,
}

impl FlightTurn {
    pub(super) fn record_success(&self) {
        self.flight
            .completed_ok
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Flights {
    /// Wait for this key's turn. Cancellation is polled while queued, so a
    /// shutdown never waits behind someone else's long pass.
    pub(super) async fn enter(&self, id: &str, consumer: Vec<u8>) -> Result<FlightTurn> {
        let flight = {
            let mut slots = self.0.lock().expect("standby verification flights");
            // Drop idle slots so the map stays as small as the live work.
            slots.retain(|_, flight| Arc::strong_count(flight) > 1);
            slots.entry((id.to_owned(), consumer)).or_default().clone()
        };
        let seen = flight
            .completed_ok
            .load(std::sync::atomic::Ordering::Acquire);
        let owned = loop {
            check_verification_cancellation()?;
            if let Ok(guard) =
                tokio::time::timeout(Duration::from_millis(100), flight.gate.clone().lock_owned())
                    .await
            {
                break guard;
            }
        };
        let shared = flight
            .completed_ok
            .load(std::sync::atomic::Ordering::Acquire)
            != seen;
        Ok(FlightTurn {
            flight,
            _gate: owned,
            shared,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct FreshBuilds(Arc<Mutex<VecDeque<FlightKey>>>);

const FRESH_BUILDS_KEPT: usize = 8;

impl FreshBuilds {
    pub(super) fn note(&self, id: &str, consumer: Vec<u8>) {
        let mut builds = self.0.lock().expect("standby fresh builds");
        builds.retain(|(known, known_consumer)| !(known == id && *known_consumer == consumer));
        builds.push_back((id.to_owned(), consumer));
        while builds.len() > FRESH_BUILDS_KEPT {
            builds.pop_front();
        }
    }

    pub(super) fn contains(&self, id: &str, consumer: &[u8]) -> bool {
        self.0
            .lock()
            .expect("standby fresh builds")
            .iter()
            .any(|(known, known_consumer)| known == id && known_consumer == consumer)
    }

    pub(super) fn forget(&self, id: &str, consumer: &[u8]) {
        self.0
            .lock()
            .expect("standby fresh builds")
            .retain(|(known, known_consumer)| !(known == id && known_consumer == consumer));
    }
}

pub(super) const BACKOFF_FIRST: Duration = Duration::from_secs(10 * 60);
pub(super) const BACKOFF_CAP: Duration = Duration::from_secs(6 * 60 * 60);
/// Upper bound for a restored failure count: 64 doublings already exceed any
/// schedule the cap can express, so anything above reads as corruption.
pub(super) const BACKOFF_MAX_FAILURES: u32 = 64;

#[derive(Debug)]
struct Failing {
    stamp: StatusStamp,
    failures: u32,
    retry_at: Instant,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RetentionBackoff(Arc<Mutex<HashMap<FlightKey, Failing>>>);

impl RetentionBackoff {
    /// True while a prior that failed with exactly these inputs is still
    /// backing off. A changed copy (any stamped input) is retried at once.
    pub(super) fn holds(&self, id: &str, consumer: &[u8], stamp: &StatusStamp) -> bool {
        let entries = self.0.lock().expect("standby retention backoff");
        entries
            .get(&(id.to_owned(), consumer.to_vec()))
            .is_some_and(|failing| failing.stamp == *stamp && Instant::now() < failing.retry_at)
    }

    /// Record a failure; returns true the first time this copy is seen to
    /// fail with these inputs, so the caller logs it once.
    pub(super) fn record_failure(&self, id: &str, consumer: &[u8], stamp: StatusStamp) -> bool {
        let mut entries = self.0.lock().expect("standby retention backoff");
        let key = (id.to_owned(), consumer.to_vec());
        // Clamp at the largest count a restore accepts: the delay is already
        // capped, so this only keeps a restart from losing the 6 h backoff.
        let failures = match entries.get(&key) {
            Some(previous) if previous.stamp == stamp => previous
                .failures
                .saturating_add(1)
                .min(BACKOFF_MAX_FAILURES),
            _ => 1,
        };
        let delay = BACKOFF_FIRST
            .saturating_mul(1u32 << failures.saturating_sub(1).min(10))
            .min(BACKOFF_CAP);
        let first = failures == 1;
        entries.insert(
            key,
            Failing {
                stamp,
                failures,
                retry_at: Instant::now() + delay,
            },
        );
        first
    }

    pub(super) fn clear(&self, id: &str, consumer: &[u8]) {
        self.0
            .lock()
            .expect("standby retention backoff")
            .remove(&(id.to_owned(), consumer.to_vec()));
    }

    /// The current entry for persistence: stamp, consecutive failure count
    /// and retry time. Read right after `record_failure` to durably keep the
    /// same 10 minute to 6 hour shape across processes.
    pub(super) fn entry(&self, id: &str, consumer: &[u8]) -> Option<(StatusStamp, u32, Instant)> {
        self.0
            .lock()
            .expect("standby retention backoff")
            .get(&(id.to_owned(), consumer.to_vec()))
            .map(|failing| (failing.stamp.clone(), failing.failures, failing.retry_at))
    }

    /// Restore an entry read from durable storage (a restart starts clear).
    /// An expired retry time still restores the failure count, so the next
    /// definite failure with unchanged inputs keeps doubling instead of
    /// restarting at 10 minutes.
    pub(super) fn restore(
        &self,
        id: &str,
        consumer: &[u8],
        stamp: StatusStamp,
        failures: u32,
        retry_at: Instant,
    ) {
        self.0.lock().expect("standby retention backoff").insert(
            (id.to_owned(), consumer.to_vec()),
            Failing {
                stamp,
                failures,
                retry_at,
            },
        );
    }

    /// Forget entries for generations that no longer exist.
    pub(super) fn retain_ids(&self, ids: &[String]) {
        self.0
            .lock()
            .expect("standby retention backoff")
            .retain(|(id, _), _| ids.contains(id));
    }

    #[cfg(test)]
    pub(super) fn expire_all(&self) {
        for failing in self.0.lock().unwrap().values_mut() {
            failing.retry_at = Instant::now();
        }
    }
}
