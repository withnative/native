//! Receiver transitions retain a rollback generation independently of the
//! legacy v1-to-v2 operator pin. A never releases these pins; A2 must first
//! prove rollback closure. Unknown/broken pin evidence refuses pruning.
use super::*;
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    version: u32,
    generations: BTreeMap<String, String>,
}

impl GenerationStore {
    fn shape_pins(&self) -> Result<Pins> {
        let path = self.root.join("shape-rollback-pins.json");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Pins {
                    version: 1,
                    generations: BTreeMap::new(),
                });
            }
            Err(error) => return Err(error.into()),
            Ok(meta) if meta.len() > 16 * 1024 => {
                return Err(Error::engine("shape rollback pin exceeds budget"))
            }
            Ok(_) => {}
        }
        require_regular_no_symlink(&path)?;
        let pins: Pins = serde_json::from_slice(&fs::read(path)?)?;
        if pins.version != 1
            || pins.generations.len() > super::super::shapes::REGISTRY.len()
            || pins.generations.values().any(|id| !is_generation_id(id))
        {
            return Err(Error::engine(
                "invalid shape rollback pins; retention refused",
            ));
        }
        Ok(pins)
    }

    pub(super) fn shape_pin_contains(&self, id: &str) -> Result<bool> {
        Ok(self
            .shape_pins()?
            .generations
            .values()
            .any(|pinned| pinned == id))
    }

    /// Called under promotion.lock, after candidate and predecessor admission,
    /// and before durable publication. At most one pin per rollback shape.
    pub(super) fn pin_shape_transition(
        &self,
        current_path: &Path,
        before: &StandbySnapshotManifest,
        after: &StandbySnapshotManifest,
    ) -> Result<()> {
        let (Some(old), Some(new)) = (
            super::super::shapes::manifest(before),
            super::super::shapes::manifest(after),
        ) else {
            return Ok(());
        };
        // The operator-controlled v1→v2 pin has its own release protocol.
        // Generic pins cover only transitions within one registry family.
        if old.family != new.family || old.shape() == new.shape() {
            return Ok(());
        }
        let mut pins = self.shape_pins()?;
        let key = format!(
            "{:?}-{}-{}",
            old.family, old.engine_schema, old.schema_sha256
        );
        let id = current_path
            .parent()
            .and_then(Path::file_name)
            .and_then(|id| id.to_str())
            .filter(|id| is_generation_id(id))
            .ok_or_else(|| Error::engine("shape pin predecessor is not published"))?;
        if pins
            .generations
            .get(&key)
            .is_some_and(|pinned| pinned == id)
        {
            return Ok(());
        }
        // A downgraded binary may have admitted a fresher copy of this same
        // rollback shape. Atomically repin that verified predecessor; never
        // accumulate another pin or retain only an older same-shape floor.
        // Existing retained/pinned bytes already consume available space.
        // Reserve another candidate-sized copy plus a margin for publication
        // and WAL rather than freeing rollback data to complete a transition.
        let needed = after
            .snapshot
            .size_bytes
            .saturating_mul(2)
            .saturating_add(16 * 1024 * 1024);
        let available = fs2::available_space(&self.root)?;
        #[cfg(test)]
        let available = self.shape_pin_space.lock().unwrap().unwrap_or(available);
        if available < needed {
            return Err(Error::engine(
                "transition_disk_budget: retain rollback copy; free disk to refresh",
            ));
        }
        pins.generations.insert(key, id.into());
        let mut temp = tempfile::NamedTempFile::new_in(&self.root)?;
        temp.write_all(&serde_jcs::to_vec(&pins)?)?;
        temp.as_file().sync_all()?;
        temp.persist(self.root.join("shape-rollback-pins.json"))
            .map_err(|e| e.error)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}
