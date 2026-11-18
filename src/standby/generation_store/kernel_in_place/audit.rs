//! The required audit of an in-place-advanced copy (design record 5065900 §5).
//!
//! An in-place apply proves each delta, but the fast path never reads rows a
//! delta does not change, and nothing re-reads a quiet workspace. The audit
//! closes that: every N seconds (default six hours) the refresh controller re-judges
//! the rows against the last receipt on a read-only WAL snapshot, and writes
//! when the snapshot was acquired into `audits/<generation_id>.json`. Online
//! local reads are served only while that time is within 2N; offline reads
//! keep serving and disclose the age.
//!
//! The record is the LAST verdict: a success moves it forward, a failure
//! replaces it (the copy is then not eligible), and an infrastructure error
//! (busy, I/O, cancelled) never touches it, so a stalled audit cannot refresh
//! eligibility. Evidence from an apply (a base receipt, a full-scan apply) is
//! published only after its transaction commits. The record is scoped to its
//! generation: a new generation is unaudited until its base receipt.
use super::*;
use chrono::{DateTime, Utc};

pub(crate) const AUDIT_VERIFIED: &str = "verified";
/// The rows match the receipt; only the optional accumulator cache disagreed
/// (the invalid-cache marker is written and the next writer reseeds).
pub(crate) const AUDIT_CACHE_INVALID: &str = "cache_invalid";
pub(crate) const AUDIT_FAILED: &str = "failed";
/// Six hours (Richard, 16 Nov 2026, Native task ff74f06 / design note 983490f
/// §5): an audit costs about two minutes of whole-file reading on a
/// production-sized copy, and damage at rest is rare and unrelated to write
/// activity. A restart audits at once regardless (see `next_audit_delay`).
pub(crate) const DEFAULT_AUDIT_INTERVAL_SECONDS: u64 = 6 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AuditRecord {
    pub generation_id: String,
    /// The last receipt's ordinal at the audit (informational; `-1` when a
    /// failed audit could not read it).
    pub ordinal: i64,
    /// When the audit's read snapshot was acquired (RFC 3339).
    pub snapshot_acquired_at: String,
    pub outcome: String,
}

impl AuditRecord {
    pub(crate) fn passed(&self) -> bool {
        matches!(self.outcome.as_str(), AUDIT_VERIFIED | AUDIT_CACHE_INVALID)
    }

    pub(crate) fn acquired(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.snapshot_acquired_at)
            .ok()
            .map(|at| at.with_timezone(&Utc))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditResult {
    /// Not advanced in place (or not kernel v2): nothing to audit.
    NotApplicable,
    Verified,
    CacheInvalid,
    /// The rows disagree with the last receipt. The copy keeps serving
    /// offline, is not eligible for online reads, and the next refresh
    /// replaces it with a whole snapshot.
    Failed,
}

impl GenerationStore {
    /// Seconds between required audits, or `None` when none is required (the
    /// in-place flag is off).
    pub(crate) fn audit_interval(&self) -> Option<std::time::Duration> {
        match self
            .audit_interval_seconds
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            0 => None,
            seconds => Some(std::time::Duration::from_secs(seconds)),
        }
    }

    pub(crate) fn set_audit_interval(&self, interval: Option<std::time::Duration>) {
        self.audit_interval_seconds.store(
            interval.map_or(0, |interval| interval.as_secs().max(1)),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn audit_file(&self, id: &str) -> PathBuf {
        self.root.join("audits").join(format!("{id}.json"))
    }

    /// The generation's last audit verdict. A missing, unreadable or foreign
    /// record is `None`, which counts as unaudited.
    pub(crate) fn generation_audit(&self, id: &str) -> Option<AuditRecord> {
        if !is_generation_id(id) {
            return None;
        }
        let bytes = fs::read(self.audit_file(id)).ok()?;
        let record: AuditRecord = serde_json::from_slice(&bytes).ok()?;
        (record.generation_id == id && record.acquired().is_some()).then_some(record)
    }

    /// The monotonic time of the last successful audit this process observed
    /// for `id` (the instant its snapshot was acquired, translated onto the
    /// monotonic clock when it was published). `None` until one is observed.
    pub(crate) fn audit_last_success(&self, id: &str) -> Option<std::time::Instant> {
        self.audit_observed.lock().ok()?.get(id).copied()
    }

    fn observe_audit(&self, id: &str, acquired: DateTime<Utc>, passed: bool) {
        let Ok(mut observed) = self.audit_observed.lock() else {
            return;
        };
        if !passed {
            observed.remove(id);
            return;
        }
        let behind = Utc::now()
            .signed_duration_since(acquired)
            .to_std()
            .unwrap_or_default();
        let at = std::time::Instant::now()
            .checked_sub(behind)
            .unwrap_or_else(std::time::Instant::now);
        let entry = observed.entry(id.to_owned()).or_insert(at);
        if at > *entry {
            *entry = at;
        }
    }

    /// Publish a verdict, serialised under one lock (a file lock, so a second
    /// process agrees) and ordered by `snapshot_acquired_at`: a verdict
    /// replaces the existing one only if its snapshot was acquired STRICTLY
    /// later, or at the same instant and it is a failure. A verifier that
    /// pinned clean rows, finished late, and tries to publish `verified` over
    /// a newer `failed` therefore changes nothing.
    pub(crate) fn write_audit(
        &self,
        id: &str,
        ordinal: i64,
        acquired: DateTime<Utc>,
        outcome: &str,
    ) -> Result<()> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let record = AuditRecord {
            generation_id: id.to_owned(),
            ordinal,
            snapshot_acquired_at: acquired.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            outcome: outcome.to_owned(),
        };
        // Compare at the precision the record keeps.
        let acquired = record.acquired().unwrap_or(acquired);
        let directory = self.root.join("audits");
        let lock = open_generation_lock(&directory, id, "lock")?;
        lock_generation_bounded(&lock, true)?;
        let replace = match self
            .generation_audit(id)
            .and_then(|existing| existing.acquired().map(|at| (at, existing.passed())))
        {
            None => true,
            Some((at, _)) if acquired > at => true,
            Some((at, existing_passed)) if acquired == at => existing_passed && !record.passed(),
            Some(_) => false,
        };
        if replace {
            at_rest::persist_private_file(
                &directory,
                &self.audit_file(id),
                &serde_json::to_vec(&record)?,
            )?;
            self.observe_audit(id, acquired, record.passed());
        }
        drop(lock);
        Ok(())
    }

    /// Run the required audit of `generation` once, now.
    ///
    /// Reads a consistent WAL snapshot and writes nothing to the database:
    /// the whole receipt chain, the canonical event rows and blobs, and the
    /// rows' projection against every digest the last receipt certifies (the
    /// set digest, and v1 when it is certified); then, on that SAME snapshot,
    /// `quick_check`, the foreign-key check and the shape/frontier checks
    /// (at-rest coverage 1, design record 983490f). Classification follows
    /// the Full check: receipt-versus-rows is a failure (the copy is flagged
    /// for a whole snapshot), cache-versus-rows passes and leaves the
    /// invalid-cache marker. An infrastructure error is returned and records
    /// nothing.
    ///
    /// The new checks (`quick_check`, foreign keys, shape/frontier) count as
    /// audit failures exactly like a receipt mismatch: the legacy record is
    /// `failed` and a whole snapshot is required. Startup's full pass already
    /// refuses a copy on those same checks, so this is the same refusal found
    /// sooner (after detected trouble, a failed audit leads to a full check).
    ///
    /// Only this audit writes a PASSED at-rest record; a failure writes a
    /// FAILED one. Each step is a timed `native_ce::standby::verification`
    /// phase, and the whole audit logs one `audit finished` line, so the
    /// journal shows what an audit costs.
    pub(crate) async fn run_required_audit(
        &self,
        generation: &InstalledGeneration,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<AuditResult> {
        let id = &generation.id;
        if generation.manifest.kernel_v2.is_none() || !self.advanced_in_place(id)? {
            return Ok(AuditResult::NotApplicable);
        }
        #[cfg(test)]
        if FORCE_INFRASTRUCTURE_ERROR.with(|flag| flag.replace(false)) {
            return Err(Error::Io(std::io::Error::other("injected audit I/O error")));
        }
        // Retention takes this lease exclusively before removing a generation.
        let _lease = self.acquire_serving_lease(id)?;
        let started = std::time::Instant::now();
        let (state, acquired) = self.check_in_place_at_rest_acquired(generation).await;
        let finished = |outcome: &str| {
            tracing::info!(target: "native_ce::standby::audit", outcome,
                elapsed_ms = started.elapsed().as_millis(), "audit finished");
        };
        match state {
            Ok((
                state @ InPlaceState::Sound {
                    applied,
                    accumulator,
                    ..
                },
                evidence,
            )) => {
                let acquired = acquired.unwrap_or_else(Utc::now);
                let evidence = evidence.ok_or_else(|| {
                    Error::engine("kernel-v2 in-place copy: audit produced no receipt evidence")
                })?;
                // The stronger record. If it cannot be saved there is simply
                // no fresh passing at-rest record, which is safe (a later
                // caller falls back to the full check): log it and carry on
                // with today's success handling unchanged.
                if let Err(error) = self.write_at_rest_passed(id, acquired, &evidence) {
                    tracing::warn!(target: "native_ce::standby::audit", error = %error,
                        "audit passed but its at-rest record could not be saved");
                }
                self.record_integrity_findings(id, state);
                let (result, outcome) = if accumulator == AccumulatorStatus::Invalid {
                    (AuditResult::CacheInvalid, AUDIT_CACHE_INVALID)
                } else {
                    (AuditResult::Verified, AUDIT_VERIFIED)
                };
                self.write_audit(id, applied as i64, acquired, outcome)?;
                finished(outcome);
                Ok(result)
            }
            Ok((InPlaceState::NotAdvanced, _)) => Ok(AuditResult::NotApplicable),
            // Busy, I/O, cancelled: says nothing about the copy. Nothing is
            // recorded, so the last success keeps aging.
            Err(error) if audit_infrastructure_error(&error) => Err(error),
            Err(_) => {
                finished(AUDIT_FAILED);
                let acquired = acquired.unwrap_or_else(Utc::now);
                // Record the failure everywhere before reporting any error:
                // a failed write of one record must not hide the failure from
                // the others.
                let at_rest = self.write_at_rest_failed(id, acquired);
                let legacy = self.write_audit(id, -1, acquired, AUDIT_FAILED);
                let refresh = self.require_full_refresh(generation);
                self.cache_completed_verification(id, observed, false);
                at_rest.and(legacy).and(refresh)?;
                Ok(AuditResult::Failed)
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test seam: the next verifier to pin a snapshot signals `.0`, then waits
    /// for `.1` before doing anything else.
    pub(crate) static PIN_SEAM: std::cell::RefCell<
        Option<(std::sync::Arc<tokio::sync::Notify>, std::sync::Arc<tokio::sync::Notify>)>,
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) async fn stall_after_pin() {
    if let Some((reached, proceed)) = PIN_SEAM.with(|seam| seam.borrow_mut().take()) {
        reached.notify_one();
        proceed.notified().await;
    }
}

#[cfg(test)]
thread_local! {
    /// Test fault: the next audit hits an infrastructure error before it reads.
    pub(crate) static FORCE_INFRASTRUCTURE_ERROR: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
#[allow(dead_code)] // used by the v2-kernel-probe audit tests
impl GenerationStore {
    /// Write a record exactly as given, bypassing the monotonic rule (to age a
    /// verdict for a test without waiting).
    pub(crate) fn write_audit_unchecked(&self, record: &AuditRecord) {
        fs::write(
            self.audit_file(&record.generation_id),
            serde_json::to_vec(record).unwrap(),
        )
        .unwrap();
        // Age the monotonic observation with it, as if this process had seen
        // the success when it was new.
        let mut observed = self.audit_observed.lock().unwrap();
        match record.acquired() {
            Some(at) if record.passed() => {
                let behind = Utc::now()
                    .signed_duration_since(at)
                    .to_std()
                    .unwrap_or_default();
                let instant = std::time::Instant::now()
                    .checked_sub(behind)
                    .unwrap_or_else(std::time::Instant::now);
                observed.insert(record.generation_id.clone(), instant);
            }
            _ => {
                observed.remove(&record.generation_id);
            }
        }
    }

    /// Forget what this process observed (as after a restart).
    pub(crate) fn forget_audit_observations(&self) {
        self.audit_observed.lock().unwrap().clear();
    }

    pub(crate) fn remove_audit(&self, id: &str) {
        let _ = fs::remove_file(self.audit_file(id));
    }

    pub(crate) fn raw_audit_bytes(&self, id: &str) -> Option<Vec<u8>> {
        fs::read(self.audit_file(id)).ok()
    }
}
