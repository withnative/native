//! Non-secret observations, separate from receipt/FULL scheduling phases.
use super::*;
use std::io::Read as _;

const STALE_SECONDS: i64 = 120;
pub(super) const BYTE_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const OBSERVATION_FILE: &str = "transfer-progress.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferObservation {
    attempt_id: String,
    progress: StandbyTransferProgress,
}

// Advisory state must never replace durable cooldown/failure bookkeeping.
pub(super) fn merge_observation(dir: &Path, state: &mut StandbyRefreshState) -> Result<()> {
    if !state.refresh_active {
        return Ok(());
    }
    let Some(attempt_id) = state
        .last_attempt_id
        .as_deref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
    else {
        return Ok(());
    };
    let path = dir.join(OBSERVATION_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.len() > MAX_STATUS_DIAGNOSTIC_FILE_BYTES => {
            return Err(Error::engine("standby progress exceeds its bound"))
        }
        Ok(_) => {}
    }
    require_regular_file(&path)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_STATUS_DIAGNOSTIC_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATUS_DIAGNOSTIC_FILE_BYTES {
        return Err(Error::engine("standby progress exceeds its bound"));
    }
    let observation: TransferObservation = serde_json::from_slice(&bytes)?;
    let observed_id = uuid::Uuid::parse_str(&observation.attempt_id)
        .map_err(|_| Error::engine("invalid standby progress attempt"))?;
    if observed_id == attempt_id {
        if !observation.progress.valid(true) {
            return Err(Error::engine("invalid standby progress"));
        }
        state.transfer_progress = Some(observation.progress);
    }
    Ok(())
}

pub(super) fn clear_observation(dir: &Path) -> Result<()> {
    match fs::remove_file(dir.join(OBSERVATION_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyTransferStage {
    Following,
    Capture,
    Download,
    Verification,
    Publication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyTransferActivity {
    Active,
    Inactive,
    Interrupted,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyTransferProgress {
    pub stage: StandbyTransferStage,
    pub activity: StandbyTransferActivity,
    pub updated_at: String,
    pub bytes_completed: Option<u64>,
    pub bytes_remaining: Option<u64>,
    pub bytes_total: Option<u64>,
    /// Local custody only; remote reuse still requires an authorized poll.
    pub retained_for_resume: bool,
}

impl StandbyTransferProgress {
    pub(super) fn following() -> Self {
        Self::new(StandbyTransferStage::Following, None, false)
    }

    fn new(stage: StandbyTransferStage, bytes: Option<(u64, u64)>, retained: bool) -> Self {
        Self {
            stage,
            activity: StandbyTransferActivity::Active,
            updated_at: now(),
            bytes_completed: bytes.map(|(_, completed)| completed),
            bytes_total: bytes.map(|(total, _)| total),
            bytes_remaining: bytes.and_then(|(total, completed)| total.checked_sub(completed)),
            retained_for_resume: retained,
        }
    }

    pub(crate) fn valid(&self, active: bool) -> bool {
        let counts = match (self.bytes_total, self.bytes_completed, self.bytes_remaining) {
            (None, None, None) => {
                !active
                    || matches!(
                        self.stage,
                        StandbyTransferStage::Following | StandbyTransferStage::Capture
                    )
            }
            (Some(total), Some(completed), Some(remaining)) => {
                total > 0
                    && total
                        <= binary_resume::MAX_COMPLETED_RANGES as u64
                            * binary_resume::RESUME_CHUNK_BYTES
                    && completed <= total
                    && remaining == total - completed
                    && !matches!(
                        self.stage,
                        StandbyTransferStage::Capture | StandbyTransferStage::Following
                    )
                    && (!matches!(
                        self.stage,
                        StandbyTransferStage::Verification | StandbyTransferStage::Publication
                    ) || completed == total)
            }
            _ => false,
        };
        counts
            && valid_status_timestamp(&Some(self.updated_at.clone()))
            && ((self.activity == StandbyTransferActivity::Active) == active)
            && (!self.retained_for_resume
                || !matches!(
                    self.stage,
                    StandbyTransferStage::Following | StandbyTransferStage::Publication
                ))
    }

    pub(crate) fn observed(mut self, at: Option<chrono::DateTime<chrono::Utc>>) -> Self {
        if self.activity == StandbyTransferActivity::Active {
            let age = at
                .zip(chrono::DateTime::parse_from_rfc3339(&self.updated_at).ok())
                .map(|(at, updated)| at.signed_duration_since(updated).num_seconds());
            if age.is_none_or(|age| !(0..=STALE_SECONDS).contains(&age)) {
                self.activity = StandbyTransferActivity::Stale;
            }
        }
        self
    }
}

/// A persisted active bit is not proof that its process is still running.
/// No lock is created or modified by status readers.
pub(super) fn observe_owner(dir: &Path, state: &mut StandbyRefreshState) -> Result<()> {
    if !state.refresh_active {
        return Ok(());
    }
    let active = (|| -> std::io::Result<bool> {
        let path = dir.join("attempt.lock");
        fs::symlink_metadata(&path)?;
        require_regular_file(&path)
            .map_err(|_| std::io::Error::other("invalid standby attempt lock"))?;
        let lock = File::open(&path)?;
        match fs2::FileExt::try_lock_shared(&lock) {
            Ok(()) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(error),
        }
    })();
    let active = match active {
        Ok(active) => active,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !active {
        state.refresh_active = false;
        if let Some(progress) = &mut state.transfer_progress {
            progress.activity = StandbyTransferActivity::Interrupted;
        }
    }
    Ok(())
}

pub(super) struct AttemptActivity<'a> {
    controller: &'a StandbyRefreshController,
    attempt_id: uuid::Uuid,
}
impl<'a> AttemptActivity<'a> {
    pub(super) fn new(controller: &'a StandbyRefreshController, attempt_id: uuid::Uuid) -> Self {
        Self {
            controller,
            attempt_id,
        }
    }
}
impl Drop for AttemptActivity<'_> {
    fn drop(&mut self) {
        let result = (|| -> Result<()> {
            let lock = open_private_lock(&self.controller.refresh_dir.join("trigger.lock"))?;
            lock.lock_exclusive()?;
            let mut state = self.controller.state()?;
            if state.refresh_active
                && state.last_attempt_id.as_deref() == Some(&self.attempt_id.to_string())
            {
                state.refresh_active = false;
                self.controller.settle_transfer_progress(&mut state, false);
                if let Some(progress) = &mut state.transfer_progress {
                    progress.activity = StandbyTransferActivity::Interrupted;
                }
                self.controller.write_state_unlocked(&state)?;
            }
            Ok(())
        })();
        if result.is_err() {
            tracing::warn!("standby transfer activity cleanup unavailable");
        }
    }
}

impl StandbyRefreshController {
    pub(super) fn record_transfer_stage(
        &self,
        stage: StandbyTransferStage,
        bytes: Option<(u64, u64)>,
        retained: bool,
    ) -> std::result::Result<(), AttemptError> {
        {
            let lock =
                open_private_lock(&self.refresh_dir.join("trigger.lock")).map_err(local_io)?;
            lock.lock_exclusive()
                .map_err(|error| local_io(error.into()))?;
            let state = self.state().map_err(local_io)?;
            // Acquisition-only callers have no active refresh diagnostics.
            if !state.refresh_active {
                return Ok(());
            }
            let progress = StandbyTransferProgress::new(stage, bytes, retained);
            if !progress.valid(true) {
                return Err(local_io(Error::engine("invalid standby transfer counters")));
            }
            let Some(attempt_id) = state
                .last_attempt_id
                .as_deref()
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
            else {
                return Ok(());
            };
            // Advisory observation: atomic replacement, without an extra fsync
            // beyond durable range-ledger writes and attempt bookkeeping.
            let bytes = serde_jcs::to_vec(&TransferObservation {
                attempt_id: attempt_id.to_string(),
                progress,
            })
            .map_err(|error| local_io(error.into()))?;
            if bytes.len() as u64 > MAX_STATUS_DIAGNOSTIC_FILE_BYTES {
                return Err(local_io(Error::engine(
                    "standby progress exceeds its bound",
                )));
            }
            let mut temp = tempfile::Builder::new()
                .prefix(".transfer-progress-")
                .tempfile_in(&self.refresh_dir)
                .map_err(|error| local_io(error.into()))?;
            temp.write_all(&bytes)
                .map_err(|error| local_io(error.into()))?;
            temp.persist(self.refresh_dir.join(OBSERVATION_FILE))
                .map_err(|error| local_io(error.error.into()))?;
        }
        #[cfg(test)]
        {
            let pause = {
                let mut pause = self.transfer_pause.lock().unwrap();
                if pause.as_ref().is_some_and(|pause| pause.stage == stage) {
                    pause.take()
                } else {
                    None
                }
            };
            if let Some(pause) = pause {
                pause.entered.send(()).unwrap();
                pause.resume.recv_timeout(Duration::from_secs(20)).unwrap();
            }
        }
        Ok(())
    }

    pub(super) fn settle_transfer_progress(
        &self,
        state: &mut StandbyRefreshState,
        successful: bool,
    ) {
        if state.transfer_progress.is_none() {
            return;
        }
        let binding = self.resume_binding();
        let retained = binary_resume::load_resume_ledger(&self.refresh_dir, &binding)
            .ok()
            .flatten()
            .filter(|ledger| {
                let path = self.refresh_dir.join("binary-resume.partial.db");
                require_regular_file(&path).is_ok()
                    && fs::metadata(path)
                        .is_ok_and(|metadata| metadata.len() == ledger.range_size())
            });
        let mut progress = if successful {
            StandbyTransferProgress::following()
        } else if let Some(ledger) = retained {
            StandbyTransferProgress::new(
                StandbyTransferStage::Download,
                Some((
                    ledger.range_size(),
                    ledger.completed.iter().map(|range| range.length).sum(),
                )),
                true,
            )
        } else if transfer_repr::load_pending_transfer(&self.refresh_dir, &binding)
            .ok()
            .flatten()
            .is_some()
            || binary_resume::load_pending_capture(&self.refresh_dir, &binding)
                .ok()
                .flatten()
                .is_some()
        {
            StandbyTransferProgress::new(StandbyTransferStage::Capture, None, true)
        } else {
            let mut progress = state.transfer_progress.clone().unwrap();
            progress.bytes_completed = None;
            progress.bytes_remaining = None;
            progress.bytes_total = None;
            progress.retained_for_resume = false;
            progress
        };
        progress.activity = StandbyTransferActivity::Inactive;
        state.transfer_progress = Some(progress);
    }
}

#[cfg(test)]
pub(super) struct TransferPause {
    pub stage: StandbyTransferStage,
    pub entered: std::sync::mpsc::Sender<()>,
    pub resume: std::sync::mpsc::Receiver<()>,
}
