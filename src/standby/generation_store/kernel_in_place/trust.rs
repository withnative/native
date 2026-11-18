//! Trust a kernel-v2 copy advanced in place by what was checked as it was
//! applied (design record 983490f, §3).
//!
//! A copy is *trusted for use* when its identity and consumer binding pass
//! (never waived), it is advanced in place, a strengthened Light check passes,
//! a qualifying PASSED at-rest record exists, the receipts after that record's
//! anchor pass the same predicates Full applies, and nothing signals damage.
//! Then startup, the post-startup recheck, the same-format consumer rebind and
//! handoff to an existing copy skip the whole-file pass. Any doubt means "not
//! trusted", and the caller takes today's full path unchanged.
//!
//! What this accepts (§2): damage at rest to rows, events or blobs that no
//! later delta touched is found by the next scheduled audit, not at restart.
use super::at_rest::{AtRestRecord, AT_REST_COVERAGE, TRUST_RULE_VERSION};
use super::*;

/// More receipts than this after the anchor means the history has grown long
/// without an audit: take the full path (a re-checkpoint is overdue anyway).
const SUFFIX_LIMIT: i64 = 8192;

/// Why a copy is not trusted (logged; never shown to a person).
type Doubt = &'static str;

impl GenerationStore {
    /// True only when [`Self::trusted_generation`] finds the copy trusted
    /// (the callers need the generation too, so they use that).
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn trusted_for_use(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> bool {
        self.trusted_generation(id, observed).await.is_some()
    }

    /// The generation, when it is trusted for use by this consumer. Identity
    /// and consumer binding are checked every time and are never waived by
    /// anything about the advanced state.
    pub(crate) async fn trusted_generation(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Option<InstalledGeneration> {
        let generation = self.verify_generation_identity(id).ok()?;
        generation.manifest.validate().ok()?;
        let bound = generation
            .manifest
            .validate_observed_installed(observed)
            .is_ok();
        if !bound && self.consumer_rebind(id, observed).is_err() {
            return None;
        }
        self.trusted_state(&generation).await.then_some(generation)
    }

    /// Every condition except identity and binding, which the caller has
    /// established its own way (the consumer rebind is itself the binding
    /// check). Logged as one `startup-trusted-at-rest` phase.
    pub(crate) async fn trusted_state(&self, generation: &InstalledGeneration) -> bool {
        self.trusted_ordinal(generation).await.is_some()
    }

    /// [`Self::trusted_state`], returning the audited receipt ordinal the trust
    /// rests on (a rebind records it in its receipt).
    pub(crate) async fn trusted_ordinal(&self, generation: &InstalledGeneration) -> Option<i64> {
        verification_phase("startup-trusted-at-rest", async {
            self.trust_verdict(generation)
                .await
                .map_err(|doubt| Error::engine(format!("not trusted at rest: {doubt}")))
        })
        .await
        .ok()
    }

    async fn trust_verdict(
        &self,
        generation: &InstalledGeneration,
    ) -> std::result::Result<i64, Doubt> {
        let id = &generation.id;
        // Never-advanced copies keep today's check, byte hash included.
        let head = self
            .generation_head(id)
            .map_err(|_| "head_unreadable")?
            .ok_or("not_advanced")?;
        if !head.advanced_in_place() || generation.manifest.kernel_v2.is_none() {
            return Err("not_advanced");
        }
        // A definite damage signal is never excused.
        if head.full_refresh_required
            || self
                .generation_audit(id)
                .is_some_and(|record| !record.passed())
        {
            return Err("damage_signal");
        }
        let record = self.generation_at_rest(id).ok_or("no_record")?;
        if !record.passed() {
            return Err("damage_signal");
        }
        if record.coverage != AT_REST_COVERAGE || record.trust_rule_version != TRUST_RULE_VERSION {
            return Err("unknown_rule");
        }
        // Retention takes this lease exclusively before removing a generation.
        let _lease = self.acquire_serving_lease(id).map_err(|_| "busy")?;
        let mut conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&generation.snapshot_path)
                .create_if_missing(false)
                .read_only(true)
                .busy_timeout(std::time::Duration::from_secs(5)),
        )
        .await
        .map_err(|_| "unreadable")?;
        let verdict = async {
            let mut tx = sqlx::Connection::begin(&mut conn).await?;
            // One pinned snapshot for every read below.
            let _ = sqlx::query_scalar::<_, i64>("SELECT 1 FROM sqlite_schema LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;
            let result = verify_trusted_on(&mut tx, generation, head.head_act, &record).await;
            tx.rollback().await?;
            result
        }
        .await;
        let _ = conn.close().await;
        verdict.map_err(|_| "check_refused")?;
        #[cfg(test)]
        stall_before_reread().await;
        // The verdicts above were read BEFORE the database checks. A failed
        // verdict (or a damage flag) published meanwhile must not be missed:
        // read them again and require that nothing got worse. A newer PASSED
        // record is fine (a concurrent audit renewed it); a failure, a
        // missing record or a raised flag is not.
        let after = self
            .generation_head(id)
            .map_err(|_| "head_unreadable")?
            .ok_or("not_advanced")?;
        if after.full_refresh_required
            || !after.advanced_in_place()
            || self
                .generation_audit(id)
                .is_some_and(|record| !record.passed())
        {
            return Err("damage_signal");
        }
        let later = self.generation_at_rest(id).ok_or("no_record")?;
        if !later.passed()
            || later.coverage != record.coverage
            || later.trust_rule_version != record.trust_rule_version
            || later.ordinal < record.ordinal
        {
            return Err("damage_signal");
        }
        Ok(record.ordinal)
    }
}

/// Strengthened Light, then the suffix check, on the caller's pinned snapshot.
///
/// Light (today's checks): the receipts continue the database, the sidecar
/// does not lead it, and the cutover rows equal the anchor. Added here, because
/// Light skips what Full makes sure of: the derived tables equal the last
/// receipt's digest, and the coordinates, schema, projection tables and origin
/// equal the checkpoint's. The existing Light depth keeps its cost for the
/// refresh tick and the predecessor recheck; these extra reads run only when a
/// whole-file pass is being skipped.
///
/// Suffix: receipt `record.ordinal` has the recorded chain hash under the
/// recorded DDL, and every later receipt passes the same predicates Full
/// applies and links onto the one before. Only receipt rows are read.
async fn verify_trusted_on(
    tx: &mut sqlx::SqliteConnection,
    generation: &InstalledGeneration,
    head_act: i64,
    record: &AtRestRecord,
) -> Result<()> {
    let bad = |what: &str| Error::engine(format!("kernel-v2 trusted copy: {what}"));
    let manifest = &generation.manifest;
    let base = manifest
        .kernel_v2
        .as_ref()
        .ok_or_else(|| bad("not a kernel-v2 generation"))?;
    verify_receipts_on(tx, generation, head_act, IntegrityDepth::Light).await?;
    let ddl = receipts_ddl(&mut *tx).await?;
    if record.receipts_ddl != ddl.label() {
        return Err(bad("receipts DDL differs from the audited one"));
    }
    let last = last_receipt(&mut *tx)
        .await?
        .ok_or_else(|| bad("empty receipt chain"))?;
    if derived_digest(&mut *tx).await? != last.derived_sha256 {
        return Err(bad("derived tables differ from the last receipt"));
    }
    // Genesis event, schema digest, projection tables and origin against the
    // checkpoint (the same comparison startup makes for an advanced copy).
    crate::standby::kernel_v2::validate_manifest_on(tx, manifest, true).await?;
    if record.ordinal < 0 || last.ordinal < record.ordinal {
        // The database is behind the audit: an older database was restored.
        return Err(bad("the audited receipt is missing"));
    }
    if last.ordinal - record.ordinal > SUFFIX_LIMIT {
        return Err(bad("too many receipts after the audited one"));
    }
    let anchored: Option<Receipt> = sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} WHERE ordinal=?",
        ddl.columns()
    ))
    .bind(record.ordinal)
    .fetch_optional(&mut *tx)
    .await?;
    let anchored = anchored.ok_or_else(|| bad("the audited receipt is missing"))?;
    let cutover: String = sqlx::query_scalar(&format!(
        "SELECT fixed_sha256 FROM {RECEIPTS_TABLE} WHERE ordinal=0"
    ))
    .fetch_one(&mut *tx)
    .await?;
    // Authenticate the anchor's CONTENTS, not just its stored hash: recompute
    // its link from the hash before it (the genesis hash at ordinal 0) exactly
    // as Full does, and apply Full's per-receipt predicates to it. The result
    // must equal both the stored and the recorded chain hash.
    let (previous, before) = if record.ordinal == 0 {
        (None, genesis_hash(&manifest.snapshot.sha256))
    } else {
        let previous: Option<Receipt> = sqlx::query_as(&format!(
            "SELECT {} FROM {RECEIPTS_TABLE} WHERE ordinal=?",
            ddl.columns()
        ))
        .bind(record.ordinal - 1)
        .fetch_optional(&mut *tx)
        .await?;
        let previous =
            previous.ok_or_else(|| bad("the receipt before the audited one is missing"))?;
        let hash = previous.chain_sha256.clone();
        (Some(previous), hash)
    };
    if !receipt_well_formed(
        &anchored,
        previous.as_ref(),
        record.ordinal,
        ddl,
        manifest,
        base,
        &cutover,
    ) {
        return Err(bad("the audited receipt is malformed"));
    }
    let relinked = anchored.link(&before, ddl);
    if relinked != anchored.chain_sha256 || relinked != record.chain_sha256 {
        return Err(bad("the audited receipt's chain hash differs"));
    }
    let suffix: Vec<Receipt> = sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} WHERE ordinal>? ORDER BY ordinal",
        ddl.columns()
    ))
    .bind(record.ordinal)
    .fetch_all(&mut *tx)
    .await?;
    let mut previous = &anchored;
    let mut chain = anchored.chain_sha256.clone();
    for receipt in &suffix {
        if !receipt_well_formed(
            receipt,
            Some(previous),
            previous.ordinal + 1,
            ddl,
            manifest,
            base,
            &cutover,
        ) {
            return Err(bad("a receipt after the audited one is malformed"));
        }
        chain = receipt.link(&chain, ddl);
        if chain != receipt.chain_sha256 {
            return Err(bad("the receipt chain after the audited one is broken"));
        }
        previous = receipt;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test seam: the next trust check signals `.0` once its database checks
    /// are done, then waits for `.1` before it re-reads the verdicts.
    pub(crate) static REREAD_SEAM: std::cell::RefCell<
        Option<(std::sync::Arc<tokio::sync::Notify>, std::sync::Arc<tokio::sync::Notify>)>,
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
async fn stall_before_reread() {
    if let Some((reached, proceed)) = REREAD_SEAM.with(|seam| seam.borrow_mut().take()) {
        reached.notify_one();
        proceed.notified().await;
    }
}
