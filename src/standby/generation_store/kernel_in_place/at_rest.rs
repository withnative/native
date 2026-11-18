//! The local at-rest audit record (design record 983490f, §3 and §4).
//!
//! `audits/<generation>.json` (see `audit.rs`) is online-eligibility evidence:
//! base, apply-time and admission successes all refresh it. That is too weak
//! to ever excuse a restart from the full check, so the stronger claim lives
//! in its OWN file, `audits/<generation>.at-rest.json`, under its OWN lock:
//!
//! * a PASSED record is written only by the scheduled audit (coverage 1: the
//!   receipt Full check, `quick_check`, the foreign-key check and the
//!   shape/frontier checks, all on one pinned read snapshot). A weaker
//!   success (base receipt, full-scan apply, admission) never writes one and
//!   so can never replace one;
//! * a FAILED record is written by ANY writer that finds trouble, so a weak
//!   writer's failure removes standing trust at once. A failure is STICKY for
//!   its generation: only another failure replaces it (a failed copy is
//!   replaced by a whole new generation). A passed record replaces a passed
//!   one only if its receipt ordinal is not lower. The wall clock never
//!   decides precedence (it can be set back); `snapshot_acquired_at` is
//!   information only;
//! * an infrastructure error (busy, I/O, cancelled) writes nothing.
//!
//! The file is a device-local fact about this device's bytes. It is never a
//! Native record and never leaves the node. A missing, torn or unparsable file
//! is simply "no record". Nothing reads it to make a trust decision yet (S3).
use super::*;
use chrono::{DateTime, Utc};

pub(crate) const AT_REST_KIND: &str = "at-rest-audit";
/// What the record's checks covered (see the module doc).
pub(crate) const AT_REST_COVERAGE: u32 = 1;
/// Bumped by a binary that changes what coverage 1 means; records written
/// under another version stop counting.
pub(crate) const TRUST_RULE_VERSION: u32 = 1;
pub(crate) const AT_REST_PASSED: &str = "passed";
pub(crate) const AT_REST_FAILED: &str = "failed";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AtRestRecord {
    pub generation_id: String,
    pub kind: String,
    pub coverage: u32,
    pub outcome: String,
    /// The receipt ordinal `chain_sha256` belongs to; `-1` on a failure that
    /// could not read it.
    pub ordinal: i64,
    /// The chain hash of receipt `ordinal`, read on the SAME snapshot as the
    /// checks. Empty on a failure.
    pub chain_sha256: String,
    /// `"v1"` or `"v2"`; empty on a failure.
    pub receipts_ddl: String,
    pub trust_rule_version: u32,
    /// When the checking read snapshot was acquired (RFC 3339).
    pub snapshot_acquired_at: String,
}

impl AtRestRecord {
    pub(crate) fn passed(&self) -> bool {
        self.outcome == AT_REST_PASSED
    }

    pub(crate) fn acquired(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.snapshot_acquired_at)
            .ok()
            .map(|at| at.with_timezone(&Utc))
    }
}

/// What the receipts said on the audit's pinned snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AtRestEvidence {
    pub ordinal: i64,
    pub chain_sha256: String,
    pub receipts_ddl: ReceiptsDdl,
}

impl ReceiptsDdl {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// Write `bytes` to `target` (mode 0600), durably: file contents and the
/// directory entry are both fsynced, as rebind receipts are.
pub(super) fn persist_private_file(directory: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(directory)?;
    temp.write_all(bytes)?;
    set_mode(temp.path(), 0o600)?;
    temp.as_file().sync_all()?;
    temp.persist(target).map_err(|e| e.error)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

impl GenerationStore {
    pub(crate) fn at_rest_file(&self, id: &str) -> PathBuf {
        self.root.join("audits").join(format!("{id}.at-rest.json"))
    }

    /// The generation's at-rest record. A missing, torn, foreign or
    /// legacy-kind file is `None`.
    pub(crate) fn generation_at_rest(&self, id: &str) -> Option<AtRestRecord> {
        if !is_generation_id(id) {
            return None;
        }
        let bytes = fs::read(self.at_rest_file(id)).ok()?;
        let record: AtRestRecord = serde_json::from_slice(&bytes).ok()?;
        (record.generation_id == id && record.kind == AT_REST_KIND && record.acquired().is_some())
            .then_some(record)
    }

    /// Publish a PASSED record. Only the scheduled audit calls this.
    pub(crate) fn write_at_rest_passed(
        &self,
        id: &str,
        acquired: DateTime<Utc>,
        evidence: &AtRestEvidence,
    ) -> Result<()> {
        #[cfg(test)]
        if FAIL_AT_REST_WRITE.with(|flag| flag.replace(false)) {
            return Err(Error::Io(std::io::Error::other(
                "injected at-rest record write error",
            )));
        }
        self.write_at_rest(
            id,
            acquired,
            AT_REST_PASSED,
            evidence.ordinal,
            &evidence.chain_sha256,
            evidence.receipts_ddl.label(),
        )
    }

    /// Publish a FAILED record. Any writer that finds trouble calls this.
    pub(crate) fn write_at_rest_failed(&self, id: &str, acquired: DateTime<Utc>) -> Result<()> {
        self.write_at_rest(id, acquired, AT_REST_FAILED, -1, "", "")
    }

    /// A weaker writer found trouble: record it, but never let the record
    /// write mask the error the caller is about to return.
    pub(crate) fn note_at_rest_failure(&self, id: &str, acquired: Option<DateTime<Utc>>) {
        if let Err(error) = self.write_at_rest_failed(id, acquired.unwrap_or_else(Utc::now)) {
            tracing::warn!(target: "native_ce::standby::audit", error = %error,
                "could not record a failed at-rest verdict");
        }
    }

    /// [`Self::note_at_rest_failure`] for an error from an apply or admission:
    /// busy, I/O, cancelled, out-of-disk and an injected crash say nothing
    /// about the copy and record nothing.
    pub(crate) fn note_at_rest_refusal(
        &self,
        id: &str,
        acquired: Option<DateTime<Utc>>,
        error: &Error,
    ) {
        let injected = matches!(error, Error::Engine(message) if message == INJECTED_CRASH);
        if audit_infrastructure_error(error) || is_kernel_disk_refusal(error) || injected {
            return;
        }
        self.note_at_rest_failure(id, acquired);
    }

    /// Serialised under the at-rest lock (a file lock, so a second process
    /// agrees). Precedence never uses the wall clock:
    /// * a failure always replaces whatever is there;
    /// * a pass never replaces a failure;
    /// * a pass replaces a pass only if its receipt ordinal is not lower
    ///   (ordinals only grow within a generation).
    fn write_at_rest(
        &self,
        id: &str,
        acquired: DateTime<Utc>,
        outcome: &str,
        ordinal: i64,
        chain_sha256: &str,
        receipts_ddl: &str,
    ) -> Result<()> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let record = AtRestRecord {
            generation_id: id.to_owned(),
            kind: AT_REST_KIND.to_owned(),
            coverage: AT_REST_COVERAGE,
            outcome: outcome.to_owned(),
            ordinal,
            chain_sha256: chain_sha256.to_owned(),
            receipts_ddl: receipts_ddl.to_owned(),
            trust_rule_version: TRUST_RULE_VERSION,
            snapshot_acquired_at: acquired.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        };
        let directory = self.root.join("audits");
        let lock = open_generation_lock(&directory, id, "at-rest.lock")?;
        lock_generation_bounded(&lock, true)?;
        let replace = match self.generation_at_rest(id) {
            None => true,
            Some(_) if !record.passed() => true,
            Some(existing) => existing.passed() && record.ordinal >= existing.ordinal,
        };
        if replace {
            persist_private_file(
                &directory,
                &self.at_rest_file(id),
                &serde_json::to_vec(&record)?,
            )?;
        }
        drop(lock);
        Ok(())
    }

    /// The receipts DDL the generation's database carries now, or `None` if
    /// it cannot be read (the caller then treats the record as unchanged).
    pub(crate) async fn database_receipts_ddl(
        &self,
        generation: &InstalledGeneration,
    ) -> Option<ReceiptsDdl> {
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&generation.snapshot_path)
                .create_if_missing(false)
                .read_only(true)
                .busy_timeout(std::time::Duration::from_secs(5)),
        )
        .await
        .ok()?;
        let ddl = receipts_ddl(&mut conn).await.ok();
        let _ = conn.close().await;
        ddl
    }
}

#[cfg(test)]
thread_local! {
    /// Test fault: the next passed at-rest record write fails (a crash between
    /// the audit and the record write).
    pub(crate) static FAIL_AT_REST_WRITE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Coverage 1 beyond the receipt check, on the audit's pinned snapshot. Each
/// step is a timed phase so the journal shows where an audit's time goes.
///
/// First, SQLite's own health: `quick_check` and the foreign-key check. They
/// are the cheap steps, so they run before the long receipt Full and a damaged
/// file is reported without waiting for it.
pub(super) async fn health_checks(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    verification_phase("audit-quick-check", async {
        let rows: Vec<String> = sqlx::query_scalar("PRAGMA quick_check")
            .fetch_all(&mut *tx)
            .await?;
        if rows.len() != 1 || rows[0] != "ok" {
            return Err(Error::engine(
                "kernel-v2 in-place copy: SQLite quick_check failed",
            ));
        }
        Ok(())
    })
    .await?;
    verification_phase("audit-foreign-keys", async {
        let violated: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
                .fetch_one(&mut *tx)
                .await?;
        if violated {
            return Err(Error::engine(
                "kernel-v2 in-place copy: foreign-key violation",
            ));
        }
        Ok(())
    })
    .await
}

/// After the receipt Full check, still on the same snapshot: the shape and
/// frontier checks startup supplies today (`validate_generation_shape` and
/// `validate_advanced_state` are path wrappers over these connection-level
/// checks), and the receipt coordinates the record is anchored to.
pub(super) async fn shape_and_evidence(
    tx: &mut sqlx::SqliteConnection,
    generation: &InstalledGeneration,
) -> Result<AtRestEvidence> {
    verification_phase("audit-shape", async {
        crate::standby::kernel_v2::validate_manifest_on(tx, &generation.manifest, true).await
    })
    .await?;
    // The anchor: receipt `ordinal` and its chain hash, on this snapshot.
    let ddl = receipts_ddl(&mut *tx).await?;
    let last = last_receipt(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("kernel-v2 in-place copy: empty receipt chain"))?;
    Ok(AtRestEvidence {
        ordinal: last.ordinal,
        chain_sha256: last.chain_sha256,
        receipts_ddl: ddl,
    })
}

#[cfg(test)]
#[allow(dead_code)] // used by the v2-kernel-probe audit tests
impl GenerationStore {
    pub(crate) fn remove_at_rest(&self, id: &str) {
        let _ = fs::remove_file(self.at_rest_file(id));
    }

    pub(crate) fn raw_at_rest_bytes(&self, id: &str) -> Option<Vec<u8>> {
        fs::read(self.at_rest_file(id)).ok()
    }

    /// The plain (trust-off) verifier that retention uses.
    pub(crate) async fn verify_plain_for_test(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        self.verify_generation_for_startup(id, observed, "test")
            .await
    }

    /// The verifier startup, the recheck and handoff use.
    pub(crate) async fn verify_trusting_for_test(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        self.verify_generation_trusting_at_rest(id, observed, "test")
            .await
    }

    /// The handoff's recheck of a previously serving generation when no live
    /// predecessor object matches (the fallback branch).
    pub(crate) async fn predecessor_fallback_for_test(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        self.verify_reader_predecessor(id, observed, None).await
    }

    /// One retention sweep, as the background maintenance runs it.
    pub(crate) async fn sweep_for_test(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<Vec<String>> {
        self.maintain_generations(observed, true).await
    }

    /// The deferred background check of a handed-off generation.
    pub(crate) async fn deferred_handoff_check_for_test(
        &self,
        generation: &InstalledGeneration,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<()> {
        DeferredHandoffChecks {
            store: self.clone(),
            observed: observed.clone(),
            generation: generation.clone(),
            _lease: self.acquire_serving_lease(&generation.id)?,
        }
        .run()
        .await
    }

    /// The process-local stamp as a whole-file-proof reader sees it, and as a
    /// reader content with an at-rest trusted pass sees it.
    pub(crate) fn stamps_for_test(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> (Option<bool>, Option<bool>) {
        (
            self.cached_verification(id, observed),
            self.cached_verification_trusting(id, observed),
        )
    }

    /// Write a head sidecar as given (to plant a damage signal without the
    /// failed at-rest record `require_full_refresh` also writes).
    pub(crate) fn write_head_for_test(&self, head: &GenerationHead) {
        self.write_generation_head(head).unwrap();
    }
}

/// The record and its replacement rules need no database: a bare store.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as Age;

    fn store() -> (tempfile::TempDir, GenerationStore, String) {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::open(dir.path().join("replica"), "route-1", None).unwrap();
        (dir, store, "a".repeat(64))
    }

    fn evidence(ordinal: i64) -> AtRestEvidence {
        AtRestEvidence {
            ordinal,
            chain_sha256: format!("{ordinal:064x}"),
            receipts_ddl: ReceiptsDdl::V2,
        }
    }

    #[test]
    fn a_passed_record_carries_the_coverage_1_fields_in_a_private_file() {
        let (_dir, store, id) = store();
        let t = Utc::now();
        store.write_at_rest_passed(&id, t, &evidence(7)).unwrap();
        let record = store.generation_at_rest(&id).unwrap();
        assert_eq!(record.kind, "at-rest-audit");
        assert_eq!(record.coverage, 1);
        assert_eq!(record.outcome, "passed");
        assert_eq!((record.ordinal, record.receipts_ddl.as_str()), (7, "v2"));
        assert_eq!(record.chain_sha256, format!("{:064x}", 7));
        assert_eq!(record.trust_rule_version, TRUST_RULE_VERSION);
        assert_eq!(record.generation_id, id);
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(store.at_rest_file(&id))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // It lives beside the online-eligibility record, not in it.
        assert!(store.generation_audit(&id).is_none());
        assert!(store
            .at_rest_file(&id)
            .ends_with(format!("audits/{id}.at-rest.json")));
    }

    #[test]
    fn a_failure_is_sticky_and_the_wall_clock_never_decides() {
        let (_dir, store, id) = store();
        let noon = Utc::now();
        store.write_at_rest_passed(&id, noon, &evidence(1)).unwrap();
        // The clock went back: a failure stamped a minute EARLIER still wins.
        store
            .write_at_rest_failed(&id, noon - Age::minutes(1))
            .unwrap();
        assert!(!store.generation_at_rest(&id).unwrap().passed());
        // A pass stamped LATER (or at the same instant) cannot erase it.
        for stamp in [noon, noon + Age::hours(1)] {
            store
                .write_at_rest_passed(&id, stamp, &evidence(99))
                .unwrap();
            assert!(!store.generation_at_rest(&id).unwrap().passed());
        }
        // Only a failure replaces a failure.
        store
            .write_at_rest_failed(&id, noon - Age::hours(1))
            .unwrap();
        assert!(!store.generation_at_rest(&id).unwrap().passed());
    }

    #[test]
    fn a_pass_replaces_a_pass_only_at_an_ordinal_not_lower() {
        let (_dir, store, id) = store();
        let t = Utc::now();
        store.write_at_rest_passed(&id, t, &evidence(10)).unwrap();
        // An older audit finishing late (lower ordinal) changes nothing, even
        // with a later stamp.
        store
            .write_at_rest_passed(&id, t + Age::hours(1), &evidence(7))
            .unwrap();
        assert_eq!(store.generation_at_rest(&id).unwrap().ordinal, 10);
        // An equal ordinal may replace (a newer look at the same history).
        let later = t + Age::seconds(5);
        store
            .write_at_rest_passed(&id, later, &evidence(10))
            .unwrap();
        assert_eq!(
            store.generation_at_rest(&id).unwrap().snapshot_acquired_at,
            later.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        );
        store.write_at_rest_passed(&id, t, &evidence(11)).unwrap();
        assert_eq!(store.generation_at_rest(&id).unwrap().ordinal, 11);
    }

    #[test]
    fn publishers_racing_under_the_lock_cannot_leave_a_pass_over_a_failure() {
        for round in 0..20 {
            let (_dir, store, _) = store();
            let id = format!("{round:064x}");
            let store = std::sync::Arc::new(store);
            let t = Utc::now();
            let passers: Vec<_> = (0..3)
                .map(|worker| {
                    let (store, id) = (store.clone(), id.clone());
                    std::thread::spawn(move || {
                        for ordinal in 0..10 {
                            store
                                .write_at_rest_passed(
                                    &id,
                                    t + Age::seconds(worker * 100 + ordinal),
                                    &evidence(ordinal),
                                )
                                .unwrap();
                        }
                    })
                })
                .collect();
            let failer = {
                let (store, id) = (store.clone(), id.clone());
                // Stamped before every pass: the clock does not matter.
                std::thread::spawn(move || {
                    store.write_at_rest_failed(&id, t - Age::hours(1)).unwrap();
                })
            };
            for handle in passers.into_iter().chain([failer]) {
                handle.join().unwrap();
            }
            assert!(
                !store.generation_at_rest(&id).unwrap().passed(),
                "round {round}"
            );
        }
    }

    #[test]
    fn a_torn_or_legacy_file_is_no_record_and_does_not_block_a_new_one() {
        let (_dir, store, id) = store();
        fs::write(store.at_rest_file(&id), b"{\"generation_id\":").unwrap();
        assert!(store.generation_at_rest(&id).is_none());
        // A record without the new kind (as the online-eligibility record
        // looks) never counts.
        let legacy = serde_json::json!({
            "generation_id": id, "ordinal": 3, "outcome": "verified",
            "snapshot_acquired_at": Utc::now().to_rfc3339(),
        });
        fs::write(store.at_rest_file(&id), legacy.to_string()).unwrap();
        assert!(store.generation_at_rest(&id).is_none());
        store
            .write_at_rest_passed(&id, Utc::now(), &evidence(4))
            .unwrap();
        assert_eq!(store.generation_at_rest(&id).unwrap().ordinal, 4);
    }

    #[test]
    fn a_failed_write_leaves_no_passing_record() {
        let (_dir, store, id) = store();
        FAIL_AT_REST_WRITE.with(|flag| flag.set(true));
        assert!(store
            .write_at_rest_passed(&id, Utc::now(), &evidence(1))
            .is_err());
        assert!(store.generation_at_rest(&id).is_none());
        assert!(store.raw_at_rest_bytes(&id).is_none());
    }

    #[test]
    fn infrastructure_errors_and_injected_crashes_record_nothing_but_refusals_do() {
        let (_dir, store, id) = store();
        let busy = Error::Io(std::io::Error::other("busy"));
        let cancelled = Error::engine("standby verification cancelled");
        let crash = Error::engine(INJECTED_CRASH);
        for error in [&busy, &cancelled, &crash] {
            store.note_at_rest_refusal(&id, None, error);
            assert!(store.generation_at_rest(&id).is_none(), "{error:?}");
        }
        store.note_at_rest_refusal(&id, None, &Error::engine("kernel_v2_projection_divergence"));
        assert!(!store.generation_at_rest(&id).unwrap().passed());
    }

    #[test]
    fn pruning_a_generation_removes_the_at_rest_record_and_its_lock() {
        let (_dir, store, id) = store();
        let other = "b".repeat(64);
        for id in [&id, &other] {
            store
                .write_at_rest_passed(id, Utc::now(), &evidence(1))
                .unwrap();
            store
                .write_audit(id, 1, Utc::now(), audit::AUDIT_VERIFIED)
                .unwrap();
        }
        let audits = store.root.join("audits");
        assert!(audits.join(format!("{id}.at-rest.json")).exists());
        assert!(audits.join(format!("{id}.at-rest.lock")).exists());
        store.remove_generation_head(&id).unwrap();
        for name in ["json", "lock", "at-rest.json", "at-rest.lock"] {
            assert!(!audits.join(format!("{id}.{name}")).exists(), "{name}");
        }
        // Another generation's files are untouched.
        assert!(store.generation_at_rest(&other).is_some());
    }
}
