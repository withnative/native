//! Coalesced device checks after serving publication. Never a readiness gate.
use super::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CURRENT_RECHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Default)]
pub(super) struct MaintenanceControl {
    state: Mutex<MaintenanceState>,
    finished: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct MaintenanceState {
    running: bool,
    pending: bool,
    last_current_recheck: Option<Instant>,
}

struct RefreshVerificationRetry<'a> {
    store: &'a GenerationStore,
    observed: &'a ObservedInstalledConsumerIdentity,
}

impl Drop for RefreshVerificationRetry<'_> {
    fn drop(&mut self) {
        if check_verification_cancellation().is_err() {
            return;
        }
        if let Ok(pointer) = self.store.read_pointer() {
            // "Is the current copy already verified?": a trusted-at-rest
            // stamp counts, or every refresh would reschedule a sweep.
            if self
                .store
                .cached_verification_trusting(&pointer.generation_id, self.observed)
                .is_none()
                && self.store.current_recheck_due()
            {
                self.store.schedule_maintenance(self.observed);
            }
        }
    }
}

impl GenerationStore {
    /// Retry unknown observations after errors or rollbacks, with backoff.
    /// Settled negative verdicts wait for changed inputs; shutdown never retries.
    pub(crate) fn retry_verification_after_refresh<'a>(
        &'a self,
        observed: &'a ObservedInstalledConsumerIdentity,
    ) -> impl Drop + 'a {
        RefreshVerificationRetry {
            store: self,
            observed,
        }
    }

    #[cfg(test)]
    pub(crate) fn pause_next_verification(&self) -> VerificationPause {
        let pause = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        *self.verification_pause.lock().unwrap() = Some(pause.clone());
        pause
    }

    /// Hold the next consumer rebind, once it has the checkpoint lease.
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) fn pause_next_rebind(&self) -> VerificationPause {
        let pause = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        *self.rebind_pause.lock().unwrap() = Some(pause.clone());
        pause
    }

    /// Run on a separate runtime/thread: verification contains synchronous
    /// copies/hashing and must not occupy the serving or refresher runtime.
    /// Publication coalesces requests arriving during an existing pass.
    pub(crate) fn schedule_maintenance(&self, observed: &ObservedInstalledConsumerIdentity) {
        {
            let mut state = self
                .maintenance
                .state
                .lock()
                .expect("standby maintenance state");
            state.pending = true;
            if state.running {
                return;
            }
            state.running = true;
        }
        let store = self.clone();
        let observed = observed.clone();
        let cancellation = VERIFICATION_CANCELLATION
            .with(|cell| cell.borrow().clone())
            .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let dispatcher = tracing::dispatcher::get_default(Clone::clone);
        let spawned = std::thread::Builder::new().name("standby-retention".into())
            .stack_size(64 * 1024 * 1024).spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    tracing::dispatcher::with_default(&dispatcher, || with_verification_cancellation(cancellation, || {
                        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                        runtime.block_on(async {
                            loop {
                                {
                                    let mut state = store.maintenance.state.lock().expect("standby maintenance state");
                                    if !state.pending || check_verification_cancellation().is_err() {
                                        state.running = false;
                                        store.maintenance.finished.notify_waiters();
                                        return Ok::<_, Error>(());
                                    }
                                    state.pending = false;
                                }
                                if verification_phase("background-retention", store.maintain_generations(&observed, true)).await.is_err() {
                                    tracing::warn!(target: "native_ce::standby::verification", "standby background retention deferred");
                                }
                            }
                        })
                    }))
                }));
                if !matches!(result, Ok(Ok(()))) {
                    store.maintenance.state.lock().expect("standby maintenance state").running = false;
                    store.maintenance.finished.notify_waiters();
                    tracing::warn!(target: "native_ce::standby::verification", "standby background retention stopped");
                }
            });
        if spawned.is_err() {
            self.maintenance
                .state
                .lock()
                .expect("standby maintenance state")
                .running = false;
            self.maintenance.finished.notify_waiters();
            tracing::warn!(target: "native_ce::standby::verification", "standby background retention unavailable");
        }
    }

    #[cfg(test)]
    pub(crate) async fn maintenance_idle(&self) {
        loop {
            let notified = self.maintenance.finished.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.maintenance.state.lock().unwrap().running {
                return;
            }
            notified.await;
        }
    }

    /// Only discovery/pinning and final deletion hold promotion coordination.
    /// Reuse current's matching completed observation, or recover a missing
    /// verdict with a leased private-copy check outside promotion coordination.
    pub(super) async fn maintain_generations(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
        verify_priors: bool,
    ) -> Result<Vec<String>> {
        let (pointer, mut candidates, mut warnings, excess) = {
            let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
            let mut warnings = self.cleanup_pruning_workspaces();
            warnings.extend(self.cleanup_rebind_temps());
            let ids = self.generation_ids()?;
            let pinned_extra = self.pinned_v1_generation()?.is_some_and(|id| {
                ids.contains(&id)
                    && self
                        .read_pointer()
                        .ok()
                        .is_some_and(|pointer| pointer.generation_id != id)
            });
            let excess = ids.len() > 3 + usize::from(pinned_extra);
            if !verify_priors && !excess {
                return Ok(warnings);
            }
            let pointer = self.read_pointer()?;
            let candidates = ids
                .iter()
                .filter(|id| **id != pointer.generation_id)
                .filter_map(|id| self.verify_generation_identity(id).ok())
                .collect::<Vec<_>>();
            (pointer, candidates, warnings, excess)
        };
        // A TrustedAtRest stamp counts here: re-running the trust check every
        // sweep would digest content_event_heads for nothing. Retention and
        // deletion decisions below keep the strict observation on purpose.
        if self
            .cached_verification_trusting(&pointer.generation_id, observed)
            .is_none()
        {
            self.recheck_unknown_current(&pointer, observed).await?;
        }
        // No deletion can be safe without current. Avoid spending another
        // multi-generation pass establishing a floor we cannot use.
        if excess && self.cached_verification(&pointer.generation_id, observed) != Some(true) {
            return Ok(warnings);
        }
        candidates.sort_by(compare_generation_newest_first);
        // Holding the two priors' leases protects the known-good floor from
        // another retention process while later deletion checks run.
        //
        // Routine sweeps stay cheap (fast by default, 22d0148): a prior
        // already device-verified by this process and unchanged since (the
        // stamp covers its files' size, mtime, inode, head and receipt) is
        // not re-copied and re-checked, and a prior that failed with these
        // same inputs is not retried until they change or its backoff
        // expires. The heavy fresh check is spent where it protects
        // something: on a copy about to be deleted, and, just before that
        // deletion, on the floor that deletion relies on. Nothing is ever
        // deleted on a cached observation alone, and a failing copy is kept.
        let consumer = serde_jcs::to_vec(observed)?;
        // An unreadable generation listing must never read as "no
        // generations": the in-memory table keeps its old forget-on-error
        // behaviour, but disk pruning only runs on a successful listing, so
        // a failed listing can never delete live verdicts.
        match self.generation_ids() {
            Ok(live_ids) => {
                self.retention_backoff.retain_ids(&live_ids);
                self.prune_persisted_backoffs(&live_ids);
            }
            Err(_) => self.retention_backoff.retain_ids(&[]),
        }
        // (generation, stamp when last checked, lease, checked afresh this sweep)
        let mut keep: Vec<(
            InstalledGeneration,
            verification_status::StatusStamp,
            File,
            bool,
        )> = Vec::new();
        for candidate in candidates {
            check_verification_cancellation()?;
            if self.pinned_v1_generation()?.as_deref() == Some(&candidate.id)
                || self.shape_pin_contains(&candidate.id)?
            {
                continue;
            }
            let lease = {
                let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
                if !self.pointer_still_selects(&pointer)? {
                    return Ok(warnings);
                }
                self.acquire_serving_lease(&candidate.id)?
            };
            let cached = self.cached_verification(&candidate.id, observed);
            if cached == Some(true) && (!excess || keep.len() < 2) {
                keep.push((
                    candidate.clone(),
                    self.status_stamp(&candidate.id, observed)?,
                    lease,
                    false,
                ));
                continue;
            }
            // Same inputs, same failure: not re-copied until its backoff
            // (10 minutes doubling to 6 hours, in memory and across
            // processes) expires or the copy changes.
            if let Ok(stamp) = self.status_stamp(&candidate.id, observed) {
                if self.persisted_backoff_holds(&candidate.id, &consumer, &stamp) {
                    continue;
                }
            }
            let before = self.status_stamp(&candidate.id, observed).ok();
            if let Err(error) = self
                .verify_generation_for_startup(&candidate.id, observed, "retention")
                .await
            {
                self.settle_prior_failure(&candidate.id, &consumer, before, &error);
                continue;
            }
            self.retention_backoff.clear(&candidate.id, &consumer);
            self.clear_persisted_backoff(&candidate.id);
            // The verifier may create a consumer receipt. Its own observation
            // must have survived all byte/head changes before we use it.
            if self.cached_verification(&candidate.id, observed) != Some(true) {
                continue;
            }
            let after = self.status_stamp(&candidate.id, observed)?;
            // Preserve the before/after guard for non-binding inputs too.
            if !self.verification_inputs_unchanged(before, &after) {
                continue;
            }
            if keep.len() < 2 || !excess {
                keep.push((candidate, after, lease, true));
                continue;
            }
            drop(lease);
            // Deleting relies on the floor being good: give any floor copy
            // that was only observed, not checked, its fresh check first.
            for floor in keep.iter_mut() {
                if floor.3 {
                    continue;
                }
                let id = floor.0.id.clone();
                let before = self.status_stamp(&id, observed).ok();
                if self
                    .verify_generation_for_startup(&id, observed, "retention")
                    .await
                    .is_err()
                    || self.cached_verification(&id, observed) != Some(true)
                {
                    return Ok(warnings);
                }
                let after = self.status_stamp(&id, observed)?;
                if !self.verification_inputs_unchanged(before, &after) {
                    return Ok(warnings);
                }
                floor.1 = after;
                floor.3 = true;
            }
            let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
            if !self.pointer_still_selects(&pointer)? {
                return Ok(warnings);
            }
            // A live verified current (including one advanced by our refresher)
            // and two unchanged good priors are required before any deletion.
            if self.cached_verification(&pointer.generation_id, observed) != Some(true)
                || keep.iter().any(|(generation, stamp, _, _)| {
                    self.status_stamp(&generation.id, observed).ok().as_ref() != Some(stamp)
                })
                || self.status_stamp(&candidate.id, observed)? != after
            {
                continue;
            }
            let exclusive = open_generation_lease(&self.root.join("leases"), &candidate.id)?;
            match fs2::FileExt::try_lock_exclusive(&exclusive) {
                Ok(()) => {
                    if let Err(error) = self.remove_published_generation(&candidate.id) {
                        warnings.push(format!("{}: prune failed: {error}", candidate.id));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    warnings.push(format!("{}: lease unavailable: {error}", candidate.id))
                }
            }
        }
        Ok(warnings)
    }

    /// Only a definite verdict starts the repeat-failure backoff. An
    /// infrastructure error (I/O, a lock, cancellation) says nothing about the
    /// copy: it is logged as such and retried at the next sweep.
    pub(super) fn settle_prior_failure(
        &self,
        id: &str,
        consumer: &[u8],
        before: Option<verification_status::StatusStamp>,
        error: &Error,
    ) {
        if audit_infrastructure_error(error) {
            if check_verification_cancellation().is_ok() {
                tracing::warn!(target: "native_ce::standby::verification", generation_id = %id,
                    "standby retained generation check could not complete; retrying next sweep");
            }
            return;
        }
        if let Some(stamp) = before {
            if self.retention_backoff.record_failure(id, consumer, stamp) {
                let (check, refusal) = retention_failure_diagnostic(error);
                tracing::warn!(target: "native_ce::standby::verification", generation_id = %id,
                    check, refusal = %refusal,
                    "standby retained generation fails verification; keeping it and backing off");
            }
            // Durably keep the same backoff shape across processes. This only
            // changes retry timing: the keep/delete rules below still never
            // serve or delete on a cached (or persisted) verdict alone.
            self.persist_backoff(id, consumer);
        }
    }

    fn current_recheck_due(&self) -> bool {
        self.maintenance
            .state
            .lock()
            .expect("standby maintenance state")
            .last_current_recheck
            .is_none_or(|last| last.elapsed() >= CURRENT_RECHECK_INTERVAL)
    }

    async fn recheck_unknown_current(
        &self,
        pointer: &CurrentPointer,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<()> {
        if !self.current_recheck_due() {
            return Ok(());
        }
        let refresh_dir = self
            .root
            .parent()
            .expect("generation store parent")
            .join("refresh");
        create_private_directory(&refresh_dir)?;
        let attempt = super::super::refresh::open_private_lock(&refresh_dir.join("attempt.lock"))?;
        // Same order as refresh: attempt, then promotion, then generation lease.
        // Never await attempt.lock while holding promotion coordination. This
        // lock protects only current's rare recovery check, never prior checks.
        loop {
            check_verification_cancellation()?;
            match attempt.try_lock_exclusive() {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let _lease = {
            let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
            if !self.pointer_still_selects(pointer)?
                || self
                    .cached_verification_trusting(&pointer.generation_id, observed)
                    .is_some()
            {
                return Ok(());
            }
            self.acquire_serving_lease(&pointer.generation_id)?
        };
        {
            let mut state = self
                .maintenance
                .state
                .lock()
                .expect("standby maintenance state");
            if state
                .last_current_recheck
                .is_some_and(|last| last.elapsed() < CURRENT_RECHECK_INTERVAL)
            {
                return Ok(());
            }
            state.last_current_recheck = Some(Instant::now());
        }
        // Trust by what was checked as it was applied: a qualifying copy
        // skips the whole-file pass and records TrustedAtRest provenance.
        // Anything short of trust runs exactly the full pass, which owns the
        // verdict and the S0 count under the maintenance_recheck reason (not
        // startup_recheck, which is reserved for the post-startup recheck).
        // Cooperating delta writers cannot race this check.
        let _ = self
            .verify_generation_trusting_at_rest(
                &pointer.generation_id,
                observed,
                "maintenance_recheck",
            )
            .await;
        Ok(())
    }

    fn pointer_still_selects(&self, selected: &CurrentPointer) -> Result<bool> {
        let current = self.read_pointer()?;
        Ok(current.generation_id == selected.generation_id
            && current.snapshot_sha256 == selected.snapshot_sha256)
    }
}

/// Which admission check refused a retained copy, and its refusal text, for
/// the retained-generation WARN. Errors without check attribution (plain
/// engine refusals from identity/shape gates) report as `unclassified` with
/// the full refusal text.
fn retention_failure_diagnostic(error: &Error) -> (&'static str, String) {
    match error {
        Error::StandbyAdmission { check, source } => (check.token(), source.to_string()),
        _ => ("unclassified", error.to_string()),
    }
}

/// Durable repeat-failure backoff for retained copies, kept beside the heads
/// as `heads/<generation id>.retention-backoff.json`. It records the same
/// 10 minute doubling to 6 hour shape as the in-memory backoff, keyed by a
/// fingerprint of the exact inputs the failure was recorded against, so a
/// changed copy is never covered by a stale verdict. A corrupt or unreadable
/// sidecar is treated as no verdict, never fatal.
const PERSISTED_BACKOFF_VERSION: u32 = 1;
const PERSISTED_BACKOFF_SUFFIX: &str = ".retention-backoff.json";
/// Slack for wall-clock granularity when bounding a restored retry time: a
/// retry farther ahead than the cap plus this reads as corruption.
const BACKOFF_VALIDATION_SLACK_MS: u64 = 60_000;

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedRetentionBackoff {
    version: u32,
    generation_id: String,
    consumer_hex: String,
    stamp_fingerprint: String,
    failures: u32,
    retry_at_ms: u64,
}

impl GenerationStore {
    fn retention_backoff_path(&self, id: &str) -> PathBuf {
        self.root
            .join("heads")
            .join(format!("{id}{PERSISTED_BACKOFF_SUFFIX}"))
    }

    /// Stable fingerprint of the inputs a failure verdict was recorded
    /// against (bytes, head, receipt, pointer). Any change to the copy
    /// changes the fingerprint, so the copy is retried at once.
    fn backoff_fingerprint(stamp: &verification_status::StatusStamp) -> String {
        hex::encode(Sha256::digest(format!("{stamp:?}")))
    }

    /// Cross-process repeat-failure backoff: in memory first, then the
    /// sidecar. Restoring a sidecar hit into memory keeps later sweeps of
    /// this process cheap; restoring an expired one keeps only its failure
    /// count, so the next definite failure keeps doubling.
    fn persisted_backoff_holds(
        &self,
        id: &str,
        consumer: &[u8],
        stamp: &verification_status::StatusStamp,
    ) -> bool {
        if self.retention_backoff.holds(id, consumer, stamp) {
            return true;
        }
        let bytes = match fs::read(self.retention_backoff_path(id)) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let persisted: PersistedRetentionBackoff = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if persisted.version != PERSISTED_BACKOFF_VERSION
            || persisted.generation_id != id
            || persisted.consumer_hex != hex::encode(consumer)
            || persisted.stamp_fingerprint != Self::backoff_fingerprint(stamp)
        {
            return false;
        }
        // Reject implausible values: no doubling schedule the cap expresses
        // can produce them, so they read as corruption, never as a verdict.
        if persisted.failures == 0 || persisted.failures > verification_flight::BACKOFF_MAX_FAILURES
        {
            return false;
        }
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_millis() as u64,
            Err(_) => return false,
        };
        if persisted.retry_at_ms.saturating_sub(now_ms)
            > verification_flight::BACKOFF_CAP.as_millis() as u64 + BACKOFF_VALIDATION_SLACK_MS
        {
            return false;
        }
        if persisted.retry_at_ms <= now_ms {
            self.retention_backoff.restore(
                id,
                consumer,
                stamp.clone(),
                persisted.failures,
                Instant::now(),
            );
            return false;
        }
        self.retention_backoff.restore(
            id,
            consumer,
            stamp.clone(),
            persisted.failures,
            Instant::now() + Duration::from_millis(persisted.retry_at_ms - now_ms),
        );
        true
    }

    /// Durably keep the backoff just recorded (or re-recorded) for this copy.
    /// Best effort: write failures are ignored, and a partial write reads
    /// back as no verdict. Called only for definite verdicts, never for
    /// infrastructure errors.
    fn persist_backoff(&self, id: &str, consumer: &[u8]) {
        let Some((stamp, failures, retry_at)) = self.retention_backoff.entry(id, consumer) else {
            return;
        };
        let Some(now_ms) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|elapsed| elapsed.as_millis() as u64)
        else {
            return;
        };
        let retry_at_ms = now_ms.saturating_add(
            retry_at
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        );
        let verdict = PersistedRetentionBackoff {
            version: PERSISTED_BACKOFF_VERSION,
            generation_id: id.into(),
            consumer_hex: hex::encode(consumer),
            stamp_fingerprint: Self::backoff_fingerprint(&stamp),
            failures,
            retry_at_ms,
        };
        let Ok(bytes) = serde_json::to_vec(&verdict) else {
            return;
        };
        // Atomic publish: a crash between truncate and write must never leave
        // a torn sidecar behind. The temp name is unique per write and never
        // matches the sidecar suffix, so readers and pruning never pick it
        // up, and a leftover temp file is harmless.
        let target = self.retention_backoff_path(id);
        let temp = self
            .root
            .join("heads")
            .join(format!(".retention-backoff-{}.tmp", uuid::Uuid::new_v4()));
        if fs::write(&temp, bytes).is_ok() {
            let _ = fs::rename(&temp, &target);
        }
    }

    fn clear_persisted_backoff(&self, id: &str) {
        let _ = fs::remove_file(self.retention_backoff_path(id));
    }

    /// Drop sidecars for generations that no longer exist. Best effort, and
    /// conservative: only an exact `<64-hex-id>.retention-backoff.json` name
    /// with a valid id is a candidate, and a candidate is removed only on
    /// positive proof of absence — the generation directory must read as
    /// absent with an explicit not-found, and a fresh listing must succeed
    /// and still miss the id. Any inspection error keeps the file. A
    /// leftover race only costs an extra verification on a later sweep (and
    /// a failing copy re-persists on its next definite failure); verdicts
    /// never gate serving or deletion.
    fn prune_persisted_backoffs(&self, ids: &[String]) {
        let Ok(entries) = fs::read_dir(self.root.join("heads")) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(PERSISTED_BACKOFF_SUFFIX) else {
                continue;
            };
            if !is_generation_id(id) || ids.iter().any(|known| known == id) {
                continue;
            }
            match fs::symlink_metadata(self.root.join("generations").join(id)) {
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
            match self.generation_ids() {
                Ok(fresh) if !fresh.iter().any(|known| known == id) => {}
                _ => continue,
            }
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::device_verification_tests::{capture, fixture};
    use super::super::tests::{observed, stage};
    use super::*;

    fn current_checks(logs: &str) -> usize {
        logs.lines()
            .filter(|line| {
                line.contains("standby startup phase finished")
                    && line.contains("phase=\"startup-generation-verify\"")
            })
            .count()
    }

    #[tokio::test]
    async fn corrupt_current_is_settled_across_ticks_and_skips_excess_priors() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let (_dir, db, store, _active) = fixture().await;
        let mut current = None;
        for ordinal in 0..3 {
            crate::store::create_record(
                &db,
                serde_json::json!({
                    "type":"Document", "kind":"note", "name":format!("bad-current-{ordinal}")
                }),
            )
            .await
            .unwrap();
            let (snapshot, manifest) = stage(&store, &db, &format!("bad-current-{ordinal}")).await;
            current = Some(
                store
                    .install_staged(&snapshot, &manifest, &observed())
                    .await
                    .unwrap(),
            );
        }
        let current = current.unwrap();
        for id in store.generation_ids().unwrap() {
            store.invalidate_verification(&id, &observed());
        }
        set_mode(&current.snapshot_path, 0o600).unwrap();
        fs::write(&current.snapshot_path, b"corrupt current").unwrap();
        set_mode(&current.snapshot_path, 0o400).unwrap();
        let (_, logs) = capture(async {
            drop(store.retry_verification_after_refresh(&observed()));
            store.maintenance_idle().await;
            assert_eq!(
                store.cached_verification(&current.id, &observed()),
                Some(false)
            );
            for _ in 0..4 {
                // Expire the backoff: the negative verdict itself must settle
                // retries, both through the guard and explicit maintenance.
                store.maintenance.state.lock().unwrap().last_current_recheck = None;
                drop(store.retry_verification_after_refresh(&observed()));
                store.maintenance_idle().await;
                store.maintain_generations(&observed(), true).await.unwrap();
            }
        })
        .await;
        assert_eq!(current_checks(&logs), 1, "{logs}");
        let status = store.inspect_status(&observed()).await;
        assert_eq!(status.unusable_candidate_count, 1);
        assert_eq!(
            status.unverified_candidate_count, 3,
            "excess priors were not checked"
        );
        assert_eq!(store.generation_ids().unwrap().len(), 4);
        db.close().await;
    }

    #[tokio::test]
    async fn unknown_current_recovery_holds_attempt_lock_and_backs_off() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let (_dir, db, store, active) = fixture().await;
        let writer = store
            .open_head_writer(&active.generation)
            .await
            .unwrap()
            .unwrap();
        writer.close().await;
        let id = &active.generation.id;
        assert_eq!(store.cached_verification(id, &observed()), None);
        let (entered, resume) = store.pause_next_verification();
        let (_, logs) = capture(async {
            drop(store.retry_verification_after_refresh(&observed()));
            tokio::time::timeout(Duration::from_secs(30), entered.notified())
                .await
                .unwrap();
            let attempt_path = store.root.parent().unwrap().join("refresh/attempt.lock");
            let attempt = super::super::super::refresh::open_private_lock(&attempt_path).unwrap();
            assert_eq!(
                attempt.try_lock_exclusive().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let promotion = OpenOptions::new()
                .read(true)
                .write(true)
                .open(store.root.join("promotion.lock"))
                .unwrap();
            promotion.try_lock_exclusive().unwrap();
            drop(promotion);
            // A noncooperating input change still refuses a stale observation.
            let bytes = fs::read(&active.generation.snapshot_path).unwrap();
            fs::write(&active.generation.snapshot_path, bytes).unwrap();
            resume.notify_one();
            tokio::time::timeout(Duration::from_secs(60), store.maintenance_idle())
                .await
                .unwrap();
            assert_eq!(store.cached_verification(id, &observed()), None);
            attempt.try_lock_exclusive().unwrap();
            drop(attempt);
            for _ in 0..4 {
                drop(store.retry_verification_after_refresh(&observed()));
                store.maintenance_idle().await;
                store.maintain_generations(&observed(), true).await.unwrap();
            }
        })
        .await;
        assert_eq!(
            current_checks(&logs),
            1,
            "unknown checks must back off: {logs}"
        );
        store.maintenance.state.lock().unwrap().last_current_recheck =
            Some(Instant::now() - CURRENT_RECHECK_INTERVAL);
        drop(store.retry_verification_after_refresh(&observed()));
        tokio::time::timeout(Duration::from_secs(60), store.maintenance_idle())
            .await
            .unwrap();
        assert_eq!(store.cached_verification(id, &observed()), Some(true));
        db.close().await;
    }

    #[tokio::test]
    async fn cancelled_refresh_drop_does_not_schedule_recovery() {
        let (_dir, db, store, active) = fixture().await;
        store.invalidate_verification(&active.generation.id, &observed());
        with_verification_cancellation(Arc::new(std::sync::atomic::AtomicBool::new(true)), || {
            drop(store.retry_verification_after_refresh(&observed()));
        });
        {
            let state = store.maintenance.state.lock().unwrap();
            assert!(!state.running && !state.pending);
            assert!(state.last_current_recheck.is_none());
        }
        db.close().await;
    }
}
