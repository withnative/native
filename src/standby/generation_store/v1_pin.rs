//! A rollback pin outlives ordinary current-plus-two retention.
use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct V1Pin {
    contract: String,
    version: u32,
    generation_id: String,
}
impl GenerationStore {
    pub fn pinned_v1_generation(&self) -> Result<Option<String>> {
        let path = self.root.join("v1-rollback-pin.json");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        require_regular_no_symlink(&path)?;
        let pin: V1Pin = serde_json::from_slice(&fs::read(path)?)?;
        if pin.contract != "native.standby-v1-rollback-pin.v1"
            || pin.version != 1
            || !is_generation_id(&pin.generation_id)
        {
            return Err(Error::engine("invalid v1 rollback pin; retention refused"));
        }
        Ok(Some(pin.generation_id))
    }
    pub(super) async fn pin_newest_v1(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<()> {
        let mut generations: Vec<_> = self
            .generation_ids()?
            .iter()
            .filter_map(|id| self.verify_generation_identity(id).ok())
            .filter(|g| g.manifest.kernel_v2.is_none())
            .collect();
        generations.sort_by(compare_generation_newest_first);
        for generation in generations {
            if self
                .verify_generation_for_startup(&generation.id, observed)
                .await
                .is_err()
            {
                continue;
            }
            let pin = V1Pin {
                contract: "native.standby-v1-rollback-pin.v1".into(),
                version: 1,
                generation_id: generation.id,
            };
            let mut temp = tempfile::NamedTempFile::new_in(&self.root)?;
            temp.write_all(&serde_jcs::to_vec(&pin)?)?;
            temp.as_file().sync_all()?;
            temp.persist(self.root.join("v1-rollback-pin.json"))
                .map_err(|e| e.error)?;
            File::open(&self.root)?.sync_all()?;
            return Ok(());
        }
        Err(Error::engine(
            "v1 to v2 switch requires a verified v1 rollback generation",
        ))
    }
    /// Explicit offline operator action. Stop reader/controller before switch_back;
    /// hot readers deliberately refuse a v2-to-v1 downgrade. No generation is deleted.
    pub async fn release_v1_pin(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
        switch_back: bool,
    ) -> Result<()> {
        let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
        let id = self
            .pinned_v1_generation()?
            .ok_or_else(|| Error::engine("no v1 rollback pin"))?;
        if switch_back {
            let generation = self.verify_generation_for_startup(&id, observed).await?;
            if generation.manifest.kernel_v2.is_some() {
                return Err(Error::engine("rollback pin does not select v1"));
            }
            self.write_pointer(&CurrentPointer {
                contract: POINTER_CONTRACT.into(),
                version: 1,
                generation_id: id,
                snapshot_sha256: generation.manifest.snapshot.sha256,
            })?;
        }
        fs::remove_file(self.root.join("v1-rollback-pin.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}
