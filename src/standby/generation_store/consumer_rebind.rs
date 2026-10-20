//! Local acceptance evidence. Immutable producer/admission provenance stays intact.
use super::*;
use crate::standby_snapshot::StandbyConsumerIdentity;

const CONTRACT: &str = "native.standby-consumer-rebind.v1";
const CHECKS: &[&str] = &[
    "generation-route-origin",
    "manifest",
    "format",
    "checkpoint-bytes-or-consistent-copy",
    "engine-frontier",
    "sqlite-quick-check-foreign-keys",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerRebind {
    pub contract: String,
    pub version: u32,
    pub generation_id: String,
    pub original_consumer: StandbyConsumerIdentity,
    pub accepted_consumer: ObservedInstalledConsumerIdentity,
    pub native_interchange_revision: u64,
    pub accepted_at: String,
    pub checks_passed: Vec<String>,
}

// A checksum detects accidental/partial edits; this owner-local file is not a
// signature or a substitute for verifying the current database contents.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    acceptance: ConsumerRebind,
    sha256: String,
}

fn require_same_format(
    original: &StandbyConsumerIdentity,
    observed: &ObservedInstalledConsumerIdentity,
) -> Result<()> {
    original.validate_declaration()?;
    let mut declaration = original.clone();
    declaration.source_sha.clone_from(&observed.source_sha);
    declaration
        .artifact_sha256
        .clone_from(&observed.artifact_sha256);
    declaration.validate_observed_installed(observed)?;
    if observed.engine_schema_version != crate::CURRENT_ENGINE_SCHEMA_VERSION
        || observed.ddl_sha256 != crate::schema::FROZEN_DDL_SHA256
        || super::super::release_head::release_revision(original.engine_schema_version)?
            != crate::interchange::REVISION
    {
        return Err(Error::engine("standby consumer rebind format mismatch"));
    }
    Ok(())
}

impl GenerationStore {
    pub(super) fn rebind_path(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> PathBuf {
        self.root.join("heads").join(format!(
            "{id}.consumer-rebind-{}.json",
            observed.artifact_sha256
        ))
    }

    fn read_consumer_rebind(
        &self,
        generation: &InstalledGeneration,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<Option<ConsumerRebind>> {
        let path = self.rebind_path(&generation.id, observed);
        // symlink_metadata also notices dangling symlinks, which must refuse.
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(metadata) if metadata.len() > 16 * 1024 => {
                return Err(Error::engine("standby consumer rebind too large"));
            }
            Ok(_) => {}
        }
        require_regular_no_symlink(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::metadata(&path)?;
            if metadata.nlink() != 1 || metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(Error::engine("invalid standby consumer rebind file shape"));
            }
        }
        let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        let invalid = || Error::engine("invalid standby consumer rebind evidence");
        let acceptance = value.get("acceptance").ok_or_else(invalid)?;
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(acceptance)?));
        if value.get("sha256").and_then(|hash| hash.as_str()) != Some(digest.as_str()) {
            return Err(invalid());
        }
        // Check known identity coordinates before interpreting an extensible
        // receipt. Extra fields are allowed at this step, never identity edits.
        for (key, expected) in [
            ("generation_id", serde_json::to_value(&generation.id)?),
            (
                "original_consumer",
                serde_json::to_value(&generation.manifest.consumer)?,
            ),
            ("accepted_consumer", serde_json::to_value(observed)?),
        ] {
            let actual = acceptance.get(key).ok_or_else(invalid)?;
            let matches = if let Some(fields) = expected.as_object() {
                fields
                    .iter()
                    .all(|(name, expected)| actual.get(name) == Some(expected))
            } else {
                actual == &expected
            };
            if !matches {
                return Err(invalid());
            }
        }
        if acceptance.get("contract").and_then(|v| v.as_str()) != Some(CONTRACT)
            || acceptance.get("version").and_then(|v| v.as_u64()) != Some(1)
            || acceptance.get("checks_passed") != Some(&serde_json::to_value(CHECKS)?)
        {
            return Ok(None);
        }
        let receipt: Receipt = match serde_json::from_value(value) {
            Ok(receipt) => receipt,
            // A different build's extended receipt is not reusable evidence.
            Err(error) if error.to_string().starts_with("unknown field") => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let acceptance = receipt.acceptance;
        if acceptance.native_interchange_revision != crate::interchange::REVISION
            || chrono::DateTime::parse_from_rfc3339(&acceptance.accepted_at).is_err()
        {
            return Err(invalid());
        }
        require_same_format(&acceptance.original_consumer, &acceptance.accepted_consumer)?;
        Ok(Some(acceptance))
    }

    /// Remove only this implementation's temporary receipts while holding
    /// their publication lock. A concurrent publisher keeps its temp file.
    pub(super) fn cleanup_rebind_temps(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let result = (|| -> Result<()> {
            let heads = self.root.join("heads");
            for entry in fs::read_dir(&heads)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name
                    .to_str()
                    .and_then(|name| name.strip_prefix(".consumer-rebind-"))
                else {
                    continue;
                };
                let parts: Vec<_> = name.split('-').collect();
                if parts.len() != 3
                    || !is_generation_id(parts[0])
                    || !is_generation_id(parts[1])
                    || !parts[2].ends_with(".tmp")
                {
                    continue;
                }
                let lock = open_generation_lock(
                    &self.root.join("leases"),
                    parts[0],
                    &format!("consumer-rebind-{}", parts[1]),
                )?;
                match fs2::FileExt::try_lock_exclusive(&lock) {
                    Ok(()) => {
                        fs::remove_file(entry.path())?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            File::open(heads)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            warnings.push("consumer rebind temporary cleanup failed".into());
        }
        warnings
    }

    /// Common read-only acceptance rule for installed generations. Original
    /// consumers intentionally ignore sidecars, including on rollback.
    pub(in crate::standby) fn consumer_rebind(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<Option<ConsumerRebind>> {
        let result = (|| {
            let generation = self.verify_generation_identity(id)?;
            if generation
                .manifest
                .consumer
                .validate_observed_installed(observed)
                .is_ok()
            {
                return Ok(None);
            }
            require_same_format(&generation.manifest.consumer, observed)?;
            let acceptance = self
                .read_consumer_rebind(&generation, observed)?
                .filter(|acceptance| acceptance.accepted_consumer == *observed)
                .ok_or_else(|| Error::engine("standby consumer has no matching rebind"))?;
            Ok(Some(acceptance))
        })();
        if result.is_err() {
            // A refusal is stronger evidence than a matching metadata stamp.
            self.invalidate_verification(id, observed);
        }
        result
    }

    /// Re-admit only after the existing device verifier succeeds. Serialize
    /// competing rebindings, and pin checkpoint bytes against the first delta.
    /// True means this call verified the copy; activation can reuse that check.
    pub(in crate::standby) async fn ensure_consumer_binding(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<bool> {
        let result = self.ensure_consumer_binding_inner(id, observed).await;
        if result.is_err() {
            self.invalidate_verification(id, observed);
        }
        result
    }

    async fn ensure_consumer_binding_inner(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<bool> {
        let _lease = self.acquire_serving_lease(id)?;
        let generation = self.verify_generation_identity(id)?;
        if generation
            .manifest
            .consumer
            .validate_observed_installed(observed)
            .is_ok()
        {
            return Ok(false);
        }
        require_same_format(&generation.manifest.consumer, observed)?;
        let lock = open_generation_lock(
            &self.root.join("leases"),
            id,
            &format!("consumer-rebind-{}", observed.artifact_sha256),
        )?;
        let cancellation = VERIFICATION_CANCELLATION.with(|cell| cell.borrow().clone());
        let _lock = tokio::task::spawn_blocking(move || -> Result<File> {
            loop {
                if cancellation
                    .as_ref()
                    .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
                {
                    return Err(Error::engine("standby verification cancelled"));
                }
                match fs2::FileExt::try_lock_exclusive(&lock) {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(25))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(lock)
        })
        .await
        .map_err(|_| Error::Io(std::io::Error::other("standby consumer rebind lock failed")))??;
        // Unknown receipts are not reused; checksum/identity failures refuse.
        if self
            .read_consumer_rebind(&generation, observed)?
            .is_some_and(|acceptance| acceptance.accepted_consumer == *observed)
        {
            return Ok(false);
        }
        let checkpoint = open_generation_lock(&self.root.join("leases"), id, "checkpoint")?;
        fs2::FileExt::lock_shared(&checkpoint)?;
        let advanced = self.advanced_in_place(id)?;
        if advanced {
            drop(checkpoint);
        }
        let before = self.status_stamp(id, observed).ok();
        // Consumer format was checked above; keep the original manifest for
        // every other check and never mutate it to impersonate a new admission.
        verification_phase(
            "startup-snapshot",
            verify_snapshot_contents(
                &generation.snapshot_path,
                &generation.manifest,
                None,
                &self.staging_dir(),
                advanced,
            ),
        )
        .await?;
        check_verification_cancellation()?;
        let acceptance = ConsumerRebind {
            contract: CONTRACT.into(),
            version: 1,
            generation_id: id.into(),
            original_consumer: generation.manifest.consumer.clone(),
            accepted_consumer: observed.clone(),
            native_interchange_revision: crate::interchange::REVISION,
            accepted_at: chrono::Utc::now().to_rfc3339(),
            checks_passed: CHECKS.iter().map(|check| (*check).into()).collect(),
        };
        let sha256 = hex::encode(Sha256::digest(serde_jcs::to_vec(&acceptance)?));
        let heads = self.root.join("heads");
        let mut temporary = tempfile::Builder::new()
            .prefix(&format!(
                ".consumer-rebind-{id}-{}-",
                observed.artifact_sha256
            ))
            .suffix(".tmp")
            .tempfile_in(&heads)?;
        set_mode(temporary.path(), 0o600)?;
        temporary.write_all(&serde_jcs::to_vec(&Receipt { acceptance, sha256 })?)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(self.rebind_path(id, observed))
            .map_err(|error| error.error)?;
        File::open(heads)?.sync_all()?;
        self.remember_verification(id, observed, before, true);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{observed, stage};
    use super::*;
    use tracing::instrument::WithSubscriber;

    async fn fixture() -> (
        tempfile::TempDir,
        crate::Db,
        GenerationStore,
        InstalledGeneration,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store =
            GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
        let (snapshot, manifest) = stage(&store, &db, "base").await;
        let generation = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        (dir, db, store, generation)
    }

    fn replacement() -> ObservedInstalledConsumerIdentity {
        ObservedInstalledConsumerIdentity {
            source_sha: "d".repeat(40),
            artifact_sha256: "e".repeat(64),
            ..observed()
        }
    }

    #[tokio::test]
    async fn same_format_swap_rebinds_and_serves_without_changing_provenance() {
        let (_dir, db, store, generation) = fixture().await;
        let manifest_path = generation.snapshot_path.with_file_name("manifest.json");
        let before = fs::read(&manifest_path).unwrap();
        let head = store
            .record_synced(
                &generation,
                generation.manifest.head_act.unwrap(),
                &generation.manifest.captured_at,
            )
            .unwrap();
        let head_path = store
            .root
            .join("heads")
            .join(format!("{}.json", generation.id));
        let head_before = fs::read(&head_path).unwrap();
        let StandbyStartupOutcome::Serving(active) =
            store.activate_for_startup(&replacement()).await.unwrap()
        else {
            panic!("same-format startup")
        };
        assert_eq!(active.generation.id, generation.id);
        assert_eq!(fs::read(manifest_path).unwrap(), before);
        assert_eq!(fs::read(head_path).unwrap(), head_before);
        assert_eq!(
            store.generation_head(&generation.id).unwrap().unwrap(),
            head
        );
        let acceptance = store
            .consumer_rebind(&generation.id, &replacement())
            .unwrap()
            .unwrap();
        assert_eq!(acceptance.original_consumer, generation.manifest.consumer);
        assert_eq!(acceptance.accepted_consumer, replacement());
        assert_eq!(
            acceptance.native_interchange_revision,
            crate::interchange::REVISION
        );
        let reader = crate::db::open_existing_database_standby_read_only(
            active.generation.snapshot_path.to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
            .fetch_one(reader.pool())
            .await
            .unwrap();
        reader.close().await;
        // Another compatible build re-verifies rather than trusting the prior consumer.
        let mut next = replacement();
        next.artifact_sha256 = "f".repeat(64);
        store
            .ensure_consumer_binding(&generation.id, &next)
            .await
            .unwrap();
        assert!(store
            .consumer_rebind(&generation.id, &replacement())
            .unwrap()
            .is_some());
        assert!(store
            .consumer_rebind(&generation.id, &next)
            .unwrap()
            .is_some());
        // Original-consumer acceptance remains independent of local evidence.
        assert!(store
            .consumer_rebind(&generation.id, &observed())
            .unwrap()
            .is_none());
        let first_path = store.rebind_path(&generation.id, &replacement());
        let next_path = store.rebind_path(&generation.id, &next);
        assert!(first_path.exists() && next_path.exists());
        drop(active);
        store.remove_published_generation(&generation.id).unwrap();
        assert!(!first_path.exists() && !next_path.exists());
        db.close().await;
    }

    #[tokio::test]
    async fn format_mismatches_never_publish_a_rebind() {
        let (_dir, db, store, generation) = fixture().await;
        for fault in ["schema", "ddl", "platform", "malformed"] {
            let mut changed = replacement();
            match fault {
                "schema" => changed.engine_schema_version += 1,
                "ddl" => changed.ddl_sha256 = "f".repeat(64),
                "platform" => {
                    changed.platform = crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64
                }
                "malformed" => changed.source_sha = "invalid".into(),
                _ => unreachable!(),
            }
            assert!(
                store
                    .ensure_consumer_binding(&generation.id, &changed)
                    .await
                    .is_err(),
                "{fault}"
            );
            assert!(!store.rebind_path(&generation.id, &replacement()).exists());
        }
        db.close().await;
    }

    #[tokio::test]
    async fn corrupt_checkpoint_or_advanced_copy_refuses_rebinding() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        for advanced in [false, true] {
            let (_dir, db, store, generation) = fixture().await;
            if advanced {
                let mut head = store
                    .record_synced(
                        &generation,
                        generation.manifest.head_act.unwrap(),
                        &generation.manifest.captured_at,
                    )
                    .unwrap();
                head.materialization =
                    crate::standby_snapshot::StandbyGenerationMaterialization::Delta;
                store.write_generation_head(&head).unwrap();
            }
            set_mode(&generation.snapshot_path, 0o600).unwrap();
            fs::write(&generation.snapshot_path, b"corrupt snapshot").unwrap();
            set_mode(&generation.snapshot_path, 0o400).unwrap();
            let logs = test_diagnostics::Capture::default();
            let error = store
                .ensure_consumer_binding(&generation.id, &replacement())
                .with_subscriber(logs.subscriber())
                .await
                .unwrap_err();
            if advanced {
                assert!(
                    logs.output()
                        .lines()
                        .any(|line| line.contains("phase=\"advanced-consistent-copy\"")
                            && line.contains("ok=false")),
                    "{}: {}",
                    error,
                    logs.output()
                );
                assert!(
                    matches!(error, Error::Sqlx(sqlx::Error::Database(ref source)) if source.code().as_deref() == Some("26")),
                    "{error}"
                );
            } else {
                assert!(
                    matches!(
                        error,
                        Error::StandbyAdmission {
                            check: StandbyAdmissionCheck::ByteIdentity,
                            ..
                        }
                    ),
                    "{error}"
                );
            }
            assert!(!store.rebind_path(&generation.id, &replacement()).exists());
            db.close().await;
        }
    }

    #[tokio::test]
    async fn tampered_rebind_is_refused_including_revision_and_identity() {
        let (_dir, db, store, generation) = fixture().await;
        store
            .ensure_consumer_binding(&generation.id, &replacement())
            .await
            .unwrap();
        let path = store.rebind_path(&generation.id, &replacement());
        let original = fs::read(&path).unwrap();
        for fault in [
            "checksum",
            "generation",
            "original",
            "accepted",
            "revision",
            "time",
        ] {
            let mut receipt: Receipt = serde_json::from_slice(&original).unwrap();
            match fault {
                "checksum" => receipt.acceptance.accepted_at = "2026-10-15T00:00:00Z".into(),
                "generation" => receipt.acceptance.generation_id = "f".repeat(64),
                "original" => receipt.acceptance.original_consumer.source_sha = "f".repeat(40),
                "revision" => receipt.acceptance.native_interchange_revision += 1,
                "accepted" => receipt.acceptance.accepted_consumer.source_sha = "f".repeat(40),
                "time" => receipt.acceptance.accepted_at = "invalid".into(),
                _ => unreachable!(),
            }
            // Semantic checks must reject even a correctly checksummed edit.
            if fault != "checksum" {
                receipt.sha256 = hex::encode(Sha256::digest(
                    serde_jcs::to_vec(&receipt.acceptance).unwrap(),
                ));
            }
            let value = serde_json::to_value(receipt).unwrap();
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            store.remember_verification(
                &generation.id,
                &replacement(),
                store.status_stamp(&generation.id, &replacement()).ok(),
                true,
            );
            assert!(
                store
                    .consumer_rebind(&generation.id, &replacement())
                    .is_err(),
                "{fault}"
            );
            assert!(
                store.inspect_status(&replacement()).await.current.is_none(),
                "{fault}"
            );
            store.remember_verification(
                &generation.id,
                &replacement(),
                store.status_stamp(&generation.id, &replacement()).ok(),
                true,
            );
            assert!(
                store
                    .ensure_consumer_binding(&generation.id, &replacement())
                    .await
                    .is_err(),
                "{fault}"
            );
            assert!(
                store.inspect_status(&replacement()).await.current.is_none(),
                "{fault}"
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                serde_json::to_vec(&value).unwrap(),
                "bad evidence must not be repaired"
            );
        }
        db.close().await;
    }
    #[tokio::test]
    async fn status_does_not_publish_rebindings_and_startup_verifies_once() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let (_dir, db, store, generation) = fixture().await;
        let status = store.inspect_status(&replacement()).await;
        assert!(status.current.is_none());
        assert!(!store.rebind_path(&generation.id, &replacement()).exists());
        let logs = test_diagnostics::Capture::default();
        store
            .verify_generation_for_startup(&generation.id, &replacement())
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        assert_eq!(
            logs.output()
                .lines()
                .filter(
                    |line| line.contains("phase=\"sqlite-quick-check-foreign-keys\"")
                        && line.contains("standby phase finished")
                )
                .count(),
            1,
            "{}",
            logs.output()
        );
        assert!(store.inspect_status(&replacement()).await.current.is_some());
        assert!(!store
            .ensure_consumer_binding(&generation.id, &replacement())
            .await
            .unwrap());
        db.close().await;
    }

    #[tokio::test]
    async fn unknown_receipt_shapes_are_reverified_but_identity_and_checksum_still_refuse() {
        let (_dir, db, store, generation) = fixture().await;
        let replacement = replacement();
        store
            .ensure_consumer_binding(&generation.id, &replacement)
            .await
            .unwrap();
        let path = store.rebind_path(&generation.id, &replacement);
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for fault in [
            "contract",
            "version",
            "checks",
            "receipt-field",
            "acceptance-field",
            "consumer-field",
        ] {
            let mut value = original.clone();
            match fault {
                "contract" => value["acceptance"]["contract"] = "future-contract".into(),
                "version" => value["acceptance"]["version"] = 2.into(),
                "checks" => {
                    value["acceptance"]["checks_passed"] = serde_json::json!(["future-check"])
                }
                "receipt-field" => value["future"] = true.into(),
                "acceptance-field" => value["acceptance"]["future"] = true.into(),
                "consumer-field" => {
                    value["acceptance"]["accepted_consumer"]["future"] = true.into()
                }
                _ => unreachable!(),
            }
            value["sha256"] = hex::encode(Sha256::digest(
                serde_jcs::to_vec(&value["acceptance"]).unwrap(),
            ))
            .into();
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            // Model a matching metadata observation despite changed receipt
            // bytes. The explicit refusal must evict it independently of stat.
            store.remember_verification(
                &generation.id,
                &replacement,
                store.status_stamp(&generation.id, &replacement).ok(),
                true,
            );
            assert_eq!(
                store.cached_verification(&generation.id, &replacement),
                Some(true)
            );
            assert!(
                store.consumer_rebind(&generation.id, &replacement).is_err(),
                "{fault}"
            );
            assert_eq!(
                store.cached_verification(&generation.id, &replacement),
                None,
                "{fault}"
            );
            // Inspection only reads even an unfamiliar receipt.
            assert!(store.inspect_status(&replacement).await.current.is_none());
            assert_eq!(
                fs::read(&path).unwrap(),
                serde_json::to_vec(&value).unwrap()
            );
            assert!(
                store
                    .ensure_consumer_binding(&generation.id, &replacement)
                    .await
                    .unwrap(),
                "{fault}"
            );
            assert!(store
                .consumer_rebind(&generation.id, &replacement)
                .unwrap()
                .is_some());
        }
        db.close().await;
    }

    #[tokio::test]
    async fn cleanup_removes_orphan_receipts_but_keeps_active_publishers() {
        let (_dir, db, store, generation) = fixture().await;
        let consumer = replacement();
        let path = store.root.join("heads").join(format!(
            ".consumer-rebind-{}-{}-orphan.tmp",
            generation.id, consumer.artifact_sha256
        ));
        fs::write(&path, b"unfinished").unwrap();
        let lock = open_generation_lock(
            &store.root.join("leases"),
            &generation.id,
            &format!("consumer-rebind-{}", consumer.artifact_sha256),
        )
        .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        assert!(store.cleanup_rebind_temps().is_empty());
        assert!(path.exists());
        drop(lock);
        assert!(store.cleanup_rebind_temps().is_empty());
        assert!(!path.exists());
        db.close().await;
    }
}
