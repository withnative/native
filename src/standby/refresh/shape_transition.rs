//! A bounded exception to ordinary FULL cooldown. A changing head or process
//! restart cannot replenish a shape-transition episode's transfer budget.
use super::*;
use crate::standby::shapes::{self, Entry, Shape};

const WINDOW: i64 = 6 * 60 * 60 * 1000;
const CAP: u32 = 3;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Episode {
    version: u32,
    origin: String,
    from: Shape,
    to: Shape,
    window_started_ms: i64,
    attempts: u32,
    last_attempt_ms: i64,
}

impl Episode {
    fn eligible(&mut self, now_ms: i64) -> i64 {
        if now_ms >= self.window_started_ms.saturating_add(WINDOW) {
            self.window_started_ms = now_ms;
            self.attempts = 0;
            self.last_attempt_ms = 0;
        }
        match self.attempts {
            0 => now_ms,
            n if n >= CAP => self.window_started_ms.saturating_add(WINDOW),
            1 => self.last_attempt_ms.saturating_add(60_000),
            _ => self.last_attempt_ms.saturating_add(300_000),
        }
    }
}

/// A single transition's declared peak, held by the existing attempt/transfer
/// owner. This is a free-space gate, not a promise about other disk users.
/// Pins and serving files already consume available space and are never freed.
pub(super) struct TransitionTransferBudget {
    wire_bytes: u64,
    remaining_peak: u64,
}

impl StandbyRefreshController {
    pub(super) fn transition_transfer_budget(
        &self,
        manifest: &StandbySnapshotManifest,
        wire_bytes: u64,
    ) -> Result<Option<TransitionTransferBudget>> {
        // Serialize the sample with publication, never hold this lock across
        // network I/O or block a reader's generation handoff for a download.
        let staging = self.store.staging_dir();
        let promotion = open_private_lock(
            &staging
                .parent()
                .ok_or_else(|| Error::engine("transition staging has no owner"))?
                .join("promotion.lock"),
        )?;
        fs2::FileExt::try_lock_shared(&promotion)?;
        if shapes::manifest(manifest).is_none() {
            return Err(Error::engine(shapes::UNSUPPORTED));
        }
        // Same-shape FULLs also retain the serving copy and mandatory pins.
        // They need the same peak gate; shape equality grants no disk space.
        let decoded = manifest.snapshot.size_bytes;
        let ceiling =
            binary_resume::MAX_COMPLETED_RANGES as u64 * binary_resume::RESUME_CHUNK_BYTES;
        if decoded == 0 || decoded > ceiling || wire_bytes == 0 || wire_bytes > ceiling {
            return Err(Error::engine(
                "transition_disk_budget: declared snapshot exceeds the bounded transfer",
            ));
        }
        let prior = self.store.full_predecessor_scratch_bytes()?;
        // FULL admission copies decoded staging into owned publication. The
        // decoded-stage rename itself allocates no extra copy. Existing files
        // may require a consistent fallback copy and the unchanged two-copy
        // free-space margin at shape-pin publication. An empty store has no
        // predecessor to pin, so its envelope needs only the two real copies.
        // Some stages do not overlap; no space is promised to other disk users.
        let copies = if prior == 0 { 2 } else { 4 };
        let budget = TransitionTransferBudget {
            wire_bytes,
            remaining_peak: decoded
                .saturating_mul(copies)
                .saturating_add(prior)
                .saturating_add(16 * 1024 * 1024),
        };
        self.check_transition_transfer_budget(Some(&budget), 0)?;
        Ok(Some(budget))
    }

    pub(super) fn check_transition_transfer_budget(
        &self,
        budget: Option<&TransitionTransferBudget>,
        completed: u64,
    ) -> Result<()> {
        let Some(budget) = budget else {
            return Ok(());
        };
        let needed = budget
            .remaining_peak
            .saturating_add(budget.wire_bytes.saturating_sub(completed));
        let available = fs2::available_space(self.store.staging_dir())?;
        #[cfg(test)]
        let available = self.kernel_available_space.unwrap_or(available);
        if available < needed {
            return Err(Error::engine("transition_disk_budget: retain serving copy and rollback pins; free disk to refresh"));
        }
        Ok(())
    }

    fn transition_episode(&self) -> Result<Option<Episode>> {
        let path = self.refresh_dir.join("shape-transition.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
            Ok(meta) if meta.len() > 4096 => {
                return Err(Error::engine("receiver transition state exceeds bound"))
            }
            Ok(_) => {}
        }
        require_regular_file(&path)?;
        let episode: Episode = serde_json::from_slice(&fs::read(path)?)?;
        let valid = shapes::lookup(&episode.from)
            .zip(shapes::lookup(&episode.to))
            .is_some_and(|(from, to)| from.shape() != to.shape() && shapes::follows(from, to));
        if episode.version != 1
            || episode.origin != self.runtime.origin_database_id
            || !valid
            || episode.attempts > CAP
        {
            return Err(Error::engine("invalid receiver transition episode"));
        }
        Ok(Some(episode))
    }

    fn write_transition(&self, episode: &Episode) -> Result<()> {
        let mut temp = tempfile::NamedTempFile::new_in(&self.refresh_dir)?;
        temp.write_all(&serde_jcs::to_vec(episode)?)?;
        temp.as_file().sync_all()?;
        temp.persist(self.refresh_dir.join("shape-transition.json"))
            .map_err(|e| e.error)?;
        File::open(&self.refresh_dir)?.sync_all()?;
        Ok(())
    }

    pub(super) fn observe_transition(&self, from: &Entry, to: &Entry) -> Result<()> {
        let old = self.transition_episode()?;
        if old.is_some_and(|e| e.from == from.shape() && e.to == to.shape()) {
            return Ok(());
        }
        self.write_transition(&Episode {
            version: 1,
            origin: self.runtime.origin_database_id.clone(),
            from: from.shape(),
            to: to.shape(),
            window_started_ms: chrono::Utc::now().timestamp_millis(),
            attempts: 0,
            last_attempt_ms: 0,
        })
    }

    pub(super) fn transition_eligible(&self, current: &InstalledGeneration) -> Result<Option<i64>> {
        let Some(mut episode) = self.transition_episode()? else {
            return Ok(None);
        };
        if shapes::manifest(&current.manifest).map(Entry::shape) != Some(episode.from.clone()) {
            return Ok(None);
        }
        let until = episode.eligible(chrono::Utc::now().timestamp_millis());
        self.write_transition(&episode)?;
        Ok(Some(until))
    }

    pub(super) fn consume_transition_attempt(&self) -> Result<()> {
        let mut episode = self
            .transition_episode()?
            .ok_or_else(|| Error::engine("receiver transition episode disappeared"))?;
        let now = chrono::Utc::now().timestamp_millis();
        if episode.eligible(now) > now {
            return Err(Error::engine("receiver transition backoff"));
        }
        episode.attempts += 1;
        episode.last_attempt_ms = now;
        self.write_transition(&episode)
    }

    pub(super) fn complete_transition(&self, current: &InstalledGeneration) -> Result<()> {
        if self
            .transition_episode()?
            .is_some_and(|e| shapes::manifest(&current.manifest).map(Entry::shape) == Some(e.to))
        {
            fs::remove_file(self.refresh_dir.join("shape-transition.json"))?;
            File::open(&self.refresh_dir)?.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transition_budget_survives_head_changes_and_caps_retries() {
        let mut e = Episode {
            version: 1,
            origin: "fixture".into(),
            from: shapes::v2(1, shapes::V2_94).unwrap().shape(),
            to: shapes::v2(1, shapes::V2_95).unwrap().shape(),
            window_started_ms: 1000,
            attempts: 0,
            last_attempt_ms: 0,
        };
        assert_eq!(e.eligible(1000), 1000);
        for (n, now, expected) in [
            (1, 1000, 61000),
            (2, 61000, 361000),
            (3, 361000, 1000 + WINDOW),
        ] {
            e.attempts = n;
            e.last_attempt_ms = now;
            let restored: Episode =
                serde_json::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
            e = restored;
            assert_eq!(e.eligible(now), expected);
        }
        assert_eq!(e.eligible(1000 + WINDOW), 1000 + WINDOW);
        assert_eq!(e.attempts, 0);
    }
}
