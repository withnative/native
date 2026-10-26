//! Coalesced device checks after serving publication. Never a readiness gate.
use super::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
            if self
                .store
                .cached_verification(&pointer.generation_id, self.observed)
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
        if self
            .cached_verification(&pointer.generation_id, observed)
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
        let mut keep: Vec<(InstalledGeneration, verification_status::StatusStamp, File)> =
            Vec::new();
        for candidate in candidates {
            check_verification_cancellation()?;
            if self.pinned_v1_generation()?.as_deref() == Some(&candidate.id) {
                continue;
            }
            let lease = {
                let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
                if !self.pointer_still_selects(&pointer)? {
                    return Ok(warnings);
                }
                self.acquire_serving_lease(&candidate.id)?
            };
            // With excess copies, establish the two-prior floor with fresh
            // device checks before deleting anything. Metadata observations
            // cannot protect a good older copy behind a silently damaged prior.
            if !excess && self.cached_verification(&candidate.id, observed) == Some(true) {
                keep.push((
                    candidate.clone(),
                    self.status_stamp(&candidate.id, observed)?,
                    lease,
                ));
                continue;
            }
            let before = self.status_stamp(&candidate.id, observed).ok();
            if self
                .verify_generation_for_startup(&candidate.id, observed)
                .await
                .is_err()
            {
                continue;
            }
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
            if keep.len() < 2 {
                keep.push((candidate, after, lease));
                continue;
            }
            if !excess {
                continue;
            }
            drop(lease);
            let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
            if !self.pointer_still_selects(&pointer)? {
                return Ok(warnings);
            }
            // A live verified current (including one advanced by our refresher)
            // and two unchanged good priors are required before any deletion.
            if self.cached_verification(&pointer.generation_id, observed) != Some(true)
                || keep.iter().any(|(generation, stamp, _)| {
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
                    .cached_verification(&pointer.generation_id, observed)
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
        // Cooperating delta writers cannot race this check. Keep the stamp
        // guard too: other input changes still leave an unknown observation.
        let _ = self
            .verify_generation_for_startup(&pointer.generation_id, observed)
            .await;
        Ok(())
    }

    fn pointer_still_selects(&self, selected: &CurrentPointer) -> Result<bool> {
        let current = self.read_pointer()?;
        Ok(current.generation_id == selected.generation_id
            && current.snapshot_sha256 == selected.snapshot_sha256)
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
