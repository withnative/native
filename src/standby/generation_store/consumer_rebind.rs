//! Local acceptance evidence. Immutable producer/admission provenance stays intact.
use super::*;
use crate::standby_snapshot::StandbyConsumerIdentity;

const CONTRACT: &str = "native.standby-consumer-rebind.v1";
pub(super) fn runtime_declaration() -> serde_json::Value {
    serde_json::json!({"contract":CONTRACT,"version":1,
        "source":"src/standby/generation_store/consumer_rebind.rs#ConsumerRebind",
        "binding":["exact_observed_artifact_sha256","source_and_platform","generation_id","consumer_coordinates","verified_generation_checks"],
        "unknown_fields":"reject","release_edge_qualification":false,
        "authority":"candidate_and_generation_specific_local_acceptance_not_signature_or_release_edge"})
}

const CHECKS: &[&str] = &[
    "generation-route-origin",
    "manifest",
    "format",
    "checkpoint-bytes-or-consistent-copy",
    "engine-frontier",
    "sqlite-quick-check-foreign-keys",
];
/// What a rebind of a copy advanced in place actually ran when it was trusted
/// at rest instead of passing a whole-file check: the identity, manifest and
/// format checks, the shape/frontier check, and the at-rest trust itself
/// (named with the audited receipt ordinal). Not the byte, consistent-copy or
/// SQLite health checks, so it never claims them.
const TRUSTED_CHECKS: &[&str] = &[
    "generation-route-origin",
    "manifest",
    "format",
    "engine-frontier",
];
const TRUSTED_CHECK_PREFIX: &str = "trusted-at-rest:";

fn known_checks(checks: Option<&serde_json::Value>) -> bool {
    let Some(checks) = checks else { return false };
    if checks == &serde_json::json!(CHECKS) {
        return true;
    }
    let Some(list) = checks.as_array() else {
        return false;
    };
    list.len() == TRUSTED_CHECKS.len() + 1
        && list.iter().zip(TRUSTED_CHECKS).all(|(a, b)| a == b)
        && list
            .last()
            .and_then(|last| last.as_str())
            .is_some_and(|last| {
                last.strip_prefix(TRUSTED_CHECK_PREFIX)
                    .is_some_and(|ordinal| ordinal.parse::<u64>().is_ok())
            })
}

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

/// How [`GenerationStore::prepare_consumer_binding`] satisfied the binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedOutcome {
    /// This call verified the copy and published a new receipt.
    Verified,
    /// A valid receipt for this consumer already existed; nothing was re-verified.
    ReceiptReused,
    /// The installed consumer already matches the manifest; no rebind is needed.
    NotNeeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedConsumer {
    pub generation_id: String,
    pub outcome: PreparedOutcome,
    /// The verification was the at-rest trust of a copy advanced in place, not
    /// a whole-file pass (the receipt then says so). False when reused.
    pub trusted_at_rest: bool,
}

// A checksum detects accidental/partial edits; this owner-local file is not a
// signature or a substitute for verifying the current database contents.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    acceptance: ConsumerRebind,
    sha256: String,
}

/// The directory sync after publishing a receipt failed. Stay an I/O error with
/// its original kind: it is infrastructure, not a verification refusal, so
/// callers retry instead of demanding a whole snapshot.
fn receipt_sync_error(error: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        error.kind(),
        format!(
            "consumer rebind receipt was published but its durability is uncertain \
             (directory sync failed: {error}); re-running will reuse or re-verify it"
        ),
    ))
}

fn require_same_format(
    manifest: &StandbySnapshotManifest,
    observed: &ObservedInstalledConsumerIdentity,
) -> Result<()> {
    manifest.validate()?;
    let _entry = super::super::shapes::manifest(manifest)
        .ok_or_else(|| Error::engine("standby consumer rebind has an unsupported actual shape"))?;
    if manifest.consumer.platform != observed.platform {
        return Err(Error::engine(
            "standby consumer rebind platform or wire mismatch",
        ));
    }
    let primary_supported = if manifest.kernel_v2.is_some() {
        // V1 build coordinates are executable identity metadata on a v2 copy.
        super::super::shapes::v2(
            observed.kernel_v2_reader.reader_format,
            &observed.kernel_v2_reader.schema_sha256,
        )
        .is_some()
    } else {
        // A v2-only reader change cannot alter v1 format compatibility.
        super::super::shapes::v1(observed.engine_schema_version, &observed.ddl_sha256).is_some()
    };
    if !primary_supported {
        return Err(Error::engine(
            "accepting executable has an unknown primary format",
        ));
    }
    // This is a new accepting executable, not a reattribution of the producer.
    // Validate its own identity, without comparing its primary schema to the
    // original consumer's primary. Device verification follows before receipt.
    StandbyConsumerIdentity {
        kernel_v2_reader: observed.kernel_v2_reader.clone(),
        contract: crate::standby_snapshot::STANDBY_CONSUMER_CONTRACT.into(),
        version: 1,
        platform: observed.platform,
        source_sha: observed.source_sha.clone(),
        artifact_sha256: observed.artifact_sha256.clone(),
        engine_schema_version: observed.engine_schema_version,
        ddl_sha256: observed.ddl_sha256.clone(),
    }
    .validate_declaration()?;
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
            || !known_checks(acceptance.get("checks_passed"))
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
        if acceptance.original_consumer != generation.manifest.consumer
            || acceptance.accepted_consumer != *observed
            || !super::super::shapes::manifest(&generation.manifest).is_some_and(|entry| {
                entry
                    .wire_revisions
                    .contains(&acceptance.native_interchange_revision)
            })
            || chrono::DateTime::parse_from_rfc3339(&acceptance.accepted_at).is_err()
        {
            return Err(invalid());
        }
        require_same_format(&generation.manifest, &acceptance.accepted_consumer)?;
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
                .validate_observed_installed(observed)
                .is_ok()
            {
                return Ok(None);
            }
            require_same_format(&generation.manifest, observed)?;
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
        self.ensure_consumer_binding_depth(id, observed, false)
            .await
            .map(|(verified, _)| verified)
    }

    /// [`Self::ensure_consumer_binding`] for a caller that may accept a copy
    /// advanced in place that is trusted at rest instead of a whole-file pass.
    /// Returns `(verified, trusted)`: `trusted` says the verification was the
    /// at-rest trust, not a full pass. A caller that does not opt in
    /// (`allow_trusted` false: retention, audits) always gets the full checks.
    pub(in crate::standby) async fn ensure_consumer_binding_depth(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        allow_trusted: bool,
    ) -> Result<(bool, bool)> {
        self.bind_consumer(id, observed, allow_trusted, false)
            .await
            .map(|(outcome, trusted)| (outcome == PreparedOutcome::Verified, trusted))
    }

    /// Verify the accepted generation for `observed` and publish its rebind
    /// receipt, without serving it: no reader lock or marker, no refresh
    /// controller or attempt lock, no journal and no hosted contact. It takes
    /// only the shared serving lease and, unless the copy is trusted at rest,
    /// the shared checkpoint lease, as a rebind always does, so it can run
    /// beside a process serving the same replica root and applying in-place
    /// deltas. Like startup, rebind and handoff, it accepts a copy advanced in
    /// place that is trusted at rest instead of a whole-file pass, and the
    /// receipt then says so. The receipt is keyed by generation and consumer
    /// artifact and ignored by original consumers.
    pub async fn prepare_consumer_binding(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<PreparedConsumer> {
        let hint = self
            .accepted_identity_hint()?
            .ok_or_else(|| Error::engine("standby has no accepted generation to prepare"))?;
        // The same descriptor check fast startup applies: the pointer must name
        // this generation's checkpoint, or neither a receipt nor a pass is
        // meaningful for what the node would actually serve.
        if self
            .verify_generation_identity(&hint.generation_id)?
            .manifest
            .snapshot
            .sha256
            != hint.snapshot_sha256
        {
            return Err(Error::engine(
                "standby accepted pointer does not match its generation's snapshot digest",
            ));
        }
        let (outcome, trusted_at_rest) = self
            .bind_consumer(&hint.generation_id, observed, true, true)
            .await?;
        Ok(PreparedConsumer {
            generation_id: hint.generation_id,
            outcome,
            trusted_at_rest,
        })
    }

    /// [`Self::prepare_consumer_binding`] for a synchronous one-shot caller:
    /// runs on a dedicated 64 MiB-stack thread with its own current-thread
    /// runtime, as the standby handoff worker does, because the debug-build
    /// verifier futures exceed a default thread stack.
    pub fn prepare_consumer_binding_blocking(
        self,
        observed: ObservedInstalledConsumerIdentity,
    ) -> Result<PreparedConsumer> {
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::Builder::new()
            .name("standby-prepare-consumer".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                with_verification_cancellation(cancellation, || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(self.prepare_consumer_binding(&observed))
                })
            })
            .map_err(Error::Io)?
            .join()
            .map_err(|_| Error::engine("standby prepare-consumer worker panicked"))?
    }

    /// `read_only_in_place`: prepare's mode, which leaves the head sidecar,
    /// accumulator marker and audit record to the serving process.
    async fn bind_consumer(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        allow_trusted: bool,
        read_only_in_place: bool,
    ) -> Result<(PreparedOutcome, bool)> {
        let result = self
            .ensure_consumer_binding_inner(id, observed, allow_trusted, read_only_in_place)
            .await;
        if result.is_err() {
            self.invalidate_verification(id, observed);
        }
        result
    }

    async fn ensure_consumer_binding_inner(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        allow_trusted: bool,
        read_only_in_place: bool,
    ) -> Result<(PreparedOutcome, bool)> {
        #[cfg(not(any(test, feature = "v2-kernel-probe")))]
        let _ = read_only_in_place;
        let _lease = self.acquire_serving_lease(id)?;
        let generation = self.verify_generation_identity(id)?;
        if generation
            .manifest
            .validate_observed_installed(observed)
            .is_ok()
        {
            return Ok((PreparedOutcome::NotNeeded, false));
        }
        require_same_format(&generation.manifest, observed)?;
        let lock = open_generation_lock(
            &self.root.join("leases"),
            id,
            &format!("consumer-rebind-{}", observed.artifact_sha256),
        )?;
        let cancellation = VERIFICATION_CANCELLATION.with(|cell| cell.borrow().clone());
        let _lock = tokio::task::spawn_blocking(move || -> Result<File> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::engine("standby consumer rebind lock wait timed out"));
                }
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
            return Ok((PreparedOutcome::ReceiptReused, false));
        }
        let before = self.status_stamp(id, observed).ok();
        // Binding is what this call establishes (same format, checked above).
        // A copy advanced in place that is trusted at rest needs no whole-file
        // pass to be re-bound; anything else runs every check as before.
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        let trusted_ordinal = if allow_trusted && generation.manifest.kernel_v2.is_some() {
            self.trusted_ordinal(&generation).await
        } else {
            None
        };
        #[cfg(not(any(test, feature = "v2-kernel-probe")))]
        let trusted_ordinal: Option<i64> = {
            let _ = allow_trusted;
            None
        };
        if trusted_ordinal.is_none() {
            let checkpoint = acquire_checkpoint_shared(&self.root.join("leases"), id).await?;
            let advanced = self.advanced_in_place(id)?;
            if advanced {
                drop(checkpoint);
            }
            #[cfg(test)]
            {
                let pause = self.rebind_pause.lock().unwrap().take();
                if let Some((entered, resume)) = pause {
                    entered.notify_one();
                    resume.notified().await;
                }
            }
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
            // `Ok(true)` lets activation skip its own verification, so a rebind
            // must run every check activation would: including, for a kernel-v2
            // copy advanced in place, its receipts, canonical rows and head.
            #[cfg(any(test, feature = "v2-kernel-probe"))]
            if advanced && generation.manifest.kernel_v2.is_some() {
                if read_only_in_place {
                    // Prepare runs beside the serving process, which owns the head
                    // sidecar, accumulator marker and audit record. Run the same
                    // proof but leave every one of them to its owner; the node's
                    // own startup admits the copy and writes them.
                    verification_phase("kernel-in-place-integrity", async {
                        self.check_in_place_integrity_acquired(
                            &generation,
                            super::kernel_in_place::IntegrityDepth::Full,
                        )
                        .await
                        .0
                        .map(|_| ())
                    })
                    .await?;
                } else {
                    verification_phase(
                        "kernel-in-place-integrity",
                        self.admit_kernel_in_place(
                            &generation,
                            super::kernel_in_place::IntegrityDepth::Full,
                        ),
                    )
                    .await?;
                }
            }
        }
        check_verification_cancellation()?;
        let acceptance = ConsumerRebind {
            contract: CONTRACT.into(),
            version: 1,
            generation_id: id.into(),
            original_consumer: generation.manifest.consumer.clone(),
            accepted_consumer: observed.clone(),
            native_interchange_revision: crate::interchange::REVISION,
            accepted_at: chrono::Utc::now().to_rfc3339(),
            checks_passed: match trusted_ordinal {
                None => CHECKS.iter().map(|check| (*check).into()).collect(),
                Some(ordinal) => TRUSTED_CHECKS
                    .iter()
                    .map(|check| (*check).into())
                    .chain([format!("{TRUSTED_CHECK_PREFIX}{ordinal}")])
                    .collect(),
            },
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
        // The receipt attests format compatibility at verification time, not
        // the database's later contents; startup re-verifies those itself.
        temporary
            .persist(self.rebind_path(id, observed))
            .map_err(|error| error.error)?;
        // From here the receipt is complete and truthful: never delete it.
        File::open(&heads)
            .and_then(|directory| directory.sync_all())
            .map_err(receipt_sync_error)?;
        self.remember_verification_at(id, observed, before, true, trusted_ordinal.is_some());
        Ok((PreparedOutcome::Verified, trusted_ordinal.is_some()))
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

    /// Every regular file under the store, relative to its root, with bytes.
    fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(&path).unwrap(),
                    );
                }
            }
        }
        let mut out = Default::default();
        walk(root, root, &mut out);
        out
    }

    /// Prepare must be safe beside a live serving process: the original
    /// consumer's reader lock and marker, the accepted pointer and the manifest
    /// stay as they were, and the only new durable file is the receipt.
    #[tokio::test]
    async fn prepare_publishes_only_a_receipt_beside_a_live_original_reader() {
        let (dir, db, store, generation) = fixture().await;
        let original = observed();
        let _reader = store.hold_serving_reader(&generation.id).unwrap();
        store
            .record_serving_reader(&generation.id, &original)
            .unwrap();
        let before = tree(&store.root);
        assert!(store.served_by_build(&generation.id, &original.source_sha));

        // The one-shot opens its own store over the same replica root.
        let cli_store = GenerationStore::open(
            dir.path().join("replica"),
            "route-1",
            store.expected_origin_id.clone(),
        )
        .unwrap();
        let prepared = cli_store
            .prepare_consumer_binding_blocking(replacement())
            .unwrap();
        assert_eq!(prepared.generation_id, generation.id);
        assert_eq!(prepared.outcome, PreparedOutcome::Verified);

        let receipt = store.rebind_path(&generation.id, &replacement());
        assert!(receipt.exists());
        let after = tree(&store.root);
        let added: Vec<_> = after
            .keys()
            .filter(|path| !before.contains_key(*path))
            // Lock files under leases/ carry no content and may be created.
            .filter(|path| !path.starts_with("leases"))
            .collect();
        assert_eq!(
            added,
            [&receipt.strip_prefix(&store.root).unwrap().to_path_buf()]
        );
        for (path, bytes) in &before {
            assert_eq!(after.get(path), Some(bytes), "{} changed", path.display());
        }
        // Still served by the original build, and not marked as served by B.
        assert!(store.served_by_build(&generation.id, &original.source_sha));
        assert!(!store.served_by_build(&generation.id, &replacement().source_sha));
        assert!(!store.root.parent().unwrap().join("refresh").exists());
        db.close().await;
    }

    #[tokio::test]
    async fn second_prepare_reuses_the_receipt_and_startup_accepts_it() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let (_dir, db, store, generation) = fixture().await;
        let first = store
            .prepare_consumer_binding(&replacement())
            .await
            .unwrap();
        assert_eq!(first.outcome, PreparedOutcome::Verified);
        let path = store.rebind_path(&generation.id, &replacement());
        let receipt = fs::read(&path).unwrap();

        let logs = test_diagnostics::Capture::default();
        let second = store
            .prepare_consumer_binding(&replacement())
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        assert_eq!(second.outcome, PreparedOutcome::ReceiptReused);
        assert!(
            !logs.output().contains("sqlite-quick-check-foreign-keys"),
            "a reused receipt must not re-verify: {}",
            logs.output()
        );
        assert_eq!(fs::read(&path).unwrap(), receipt);

        // The upgraded node's own startup accepts the prepared copy without
        // replacing the receipt.
        store
            .verify_generation_for_startup(&generation.id, &replacement(), "consumer_rebind")
            .await
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), receipt);
        assert!(store.inspect_status(&replacement()).await.current.is_some());
        db.close().await;
    }

    #[tokio::test]
    async fn prepare_for_the_original_consumer_needs_no_rebind() {
        let (_dir, db, store, generation) = fixture().await;
        let prepared = store.prepare_consumer_binding(&observed()).await.unwrap();
        assert_eq!(prepared.generation_id, generation.id);
        assert_eq!(prepared.outcome, PreparedOutcome::NotNeeded);
        assert!(!store.rebind_path(&generation.id, &observed()).exists());
        db.close().await;
    }

    #[test]
    fn a_failed_receipt_sync_is_infrastructure_with_its_kind_and_a_plain_message() {
        for kind in [
            std::io::ErrorKind::Other,
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let error = receipt_sync_error(std::io::Error::new(kind, "fsync failed"));
            assert!(audit_infrastructure_error(&error), "{kind:?}");
            let Error::Io(io) = &error else {
                panic!("not an I/O error: {error}")
            };
            assert_eq!(io.kind(), kind);
            let message = error.to_string();
            assert!(message.contains("published but its durability is uncertain"));
            assert!(message.contains("reuse or re-verify"));
        }
    }

    #[tokio::test]
    async fn prepare_refuses_a_pointer_whose_digest_names_other_bytes() {
        let (_dir, db, store, generation) = fixture().await;
        let mut pointer = store.read_pointer().unwrap();
        assert_eq!(pointer.generation_id, generation.id);
        pointer.snapshot_sha256 = "0".repeat(64);
        store.write_pointer(&pointer).unwrap();
        // Neither a fresh verification nor a reused receipt may pass.
        for _ in 0..2 {
            assert!(store
                .prepare_consumer_binding(&replacement())
                .await
                .is_err());
            assert!(!store.rebind_path(&generation.id, &replacement()).exists());
        }
        pointer.snapshot_sha256 = generation.manifest.snapshot.sha256.clone();
        store.write_pointer(&pointer).unwrap();
        store
            .prepare_consumer_binding(&replacement())
            .await
            .unwrap();
        pointer.snapshot_sha256 = "0".repeat(64);
        store.write_pointer(&pointer).unwrap();
        assert!(store
            .prepare_consumer_binding(&replacement())
            .await
            .is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn prepare_refuses_without_publishing_a_receipt() {
        let (dir, db, store, generation) = fixture().await;
        let mut changed = replacement();
        changed.ddl_sha256 = "f".repeat(64);
        let before = tree(&store.root);
        assert!(store.prepare_consumer_binding(&changed).await.is_err());
        assert!(!store.rebind_path(&generation.id, &changed).exists());
        let cli_store = GenerationStore::open(
            dir.path().join("replica"),
            "route-1",
            store.expected_origin_id.clone(),
        )
        .unwrap();
        assert!(cli_store
            .prepare_consumer_binding_blocking(changed)
            .is_err());
        let after = tree(&store.root);
        assert!(after
            .keys()
            .all(|path| before.contains_key(path) || path.starts_with("leases")));

        // Nothing accepted yet: nothing to prepare.
        let empty = tempfile::tempdir().unwrap();
        let bare = GenerationStore::open(
            empty.path().join("replica"),
            "route-1",
            store.expected_origin_id.clone(),
        )
        .unwrap();
        assert!(bare.prepare_consumer_binding(&replacement()).await.is_err());
        db.close().await;
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
        for fault in ["schema", "previous-schema", "ddl", "platform", "malformed"] {
            let mut changed = replacement();
            match fault {
                "schema" => changed.engine_schema_version += 1,
                "previous-schema" => changed.engine_schema_version -= 1,
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
            "original-reader",
            "accepted-reader",
            "time",
        ] {
            let mut receipt: Receipt = serde_json::from_slice(&original).unwrap();
            match fault {
                "checksum" => receipt.acceptance.accepted_at = "2026-10-15T00:00:00Z".into(),
                "generation" => receipt.acceptance.generation_id = "f".repeat(64),
                "original" => receipt.acceptance.original_consumer.source_sha = "f".repeat(40),
                "original-reader" => {
                    receipt
                        .acceptance
                        .original_consumer
                        .kernel_v2_reader
                        .reader_format += 1
                }
                "accepted-reader" => {
                    receipt
                        .acceptance
                        .accepted_consumer
                        .kernel_v2_reader
                        .reader_format += 1
                }
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
            .verify_generation_for_startup(&generation.id, &replacement(), "consumer_rebind")
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
