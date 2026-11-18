//! The set path of an in-place apply (design record 5065900, slice 5 / N2).
//!
//! A version-2 delta carries the hosted set digest. When this copy's
//! accumulator cache is provably current, the fold runs under slice 4's
//! capture, each touched table's accumulator is multiplied by its captured
//! delta, and the composed whole digest is compared with hosted's. A match
//! commits a `delta-set` receipt that certifies only the set digest, and
//! skips the whole-database scan. Anything else (an anomaly, a mismatch, an
//! absent or invalid cache, a suppressed generation, a version-1 delta) takes
//! exactly one full dual scan inside the same transaction: if it matches
//! hosted the receipt records both digests and the accumulator is reseeded,
//! otherwise the apply refuses with `kernel_v2_projection_divergence`. There
//! is no second scan and no loop.
//!
//! What the fast path proves: the composed digest equals hosted's. Damage in a
//! row whose content the delta does not change (untouched, or touched without
//! net change) commits on the fast path and is caught by the next Full check
//! or audit; a delta that changes a damaged row cannot hide it (the damaged
//! base image makes the composition diverge, and the one full scan refuses).
use super::*;
use crate::kernel::projection_capture::{CaptureOutcome, TableDelta};
use crate::kernel::projection_dump::{set_digest, SetDump, SetTableDump, SetValue};
use crate::kernel::projection_set::{MuHash, Num3072, BYTE_SIZE};

/// After this many damaged-cache reseeds in one generation the set path is
/// off for that generation until it is re-checkpointed. That outcome means a
/// capture bug or a damaged cache; suppression avoids repeating a failed fast
/// path and its doubled cost. Later applies still take one full scan each.
pub(crate) const SUPPRESS_AFTER_RESEEDS: u64 = 2;
pub(crate) const DIVERGENCE: &str = "kernel_v2_projection_divergence";

#[cfg(test)]
thread_local! {
    /// Test fault: corrupt the composed value of the first touched table, as a
    /// capture bug would, so the mismatch path is reachable.
    pub(crate) static FORCE_COMPOSE_ERROR: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Test fault: the capture reports this anomaly instead of its outcome.
    pub(crate) static FORCE_ANOMALY: std::cell::RefCell<Option<crate::kernel::projection_capture::Anomaly>> =
        const { std::cell::RefCell::new(None) };
    /// Test fault: behave as the previous release (N1) would on this apply:
    /// v1 digest only, accumulator emptied.
    pub(crate) static FORCE_N1: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One row of the accumulator cache.
#[derive(Clone, Debug)]
pub(crate) struct AccRow {
    pub name: String,
    pub schema_sha256: String,
    pub rows: i64,
    /// The 384-byte little-endian normalised value.
    pub value: Vec<u8>,
    /// Changed by this apply (and so written back).
    pub dirty: bool,
}

enum AccLoad {
    Absent,
    Invalid,
    Valid(Vec<AccRow>),
}

/// How this apply proves the projection.
pub(crate) enum Route {
    /// The first receipts DDL and a version-1 delta: this node's original
    /// behaviour, the v1 digest only.
    V1,
    /// Fold under capture and compose against the (valid) accumulator.
    Set(Vec<AccRow>),
    /// One full dual scan, both digests recorded, accumulator reseeded. The
    /// cause says why the set path was not attempted.
    FullScan(&'static str),
}

/// What a proven apply certifies.
pub(crate) enum Proof {
    /// The composed accumulator and the set digest it composes to (which is
    /// hosted's when the delta carries one, and this node's own when not).
    Set(Vec<AccRow>, String),
    Dual {
        set_sha256: String,
        values: Vec<SetValue>,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CaptureSizes {
    pub touches: usize,
    pub old_images: usize,
}

/// What the set path did on one attempt (`last_set_path`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SetPathResult {
    Fast,
    Anomaly(String),
    MismatchReseeded(String),
    Divergence,
    /// The set path was not attempted (absent or invalid cache, suppressed,
    /// or a version-1 delta); a full scan proved the apply.
    Skipped(&'static str),
}

impl SetPathResult {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Anomaly(_) => "anomaly",
            Self::MismatchReseeded(_) => "mismatch_reseeded",
            Self::Divergence => "divergence",
            Self::Skipped(_) => "skipped",
        }
    }

    pub(crate) fn label(&self) -> String {
        match self {
            Self::Fast => "fast".into(),
            Self::Anomaly(reason) => format!("anomaly:{reason}"),
            Self::MismatchReseeded(table) => format!("mismatch_reseeded:{table}"),
            Self::Divergence => "divergence".into(),
            Self::Skipped(cause) => format!("skipped:{cause}"),
        }
    }
}

/// Per-generation outcome counts (`heads/<id>.set-path.json`).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SetPathCounters {
    pub fast: u64,
    pub anomaly: u64,
    pub mismatch_reseeded: u64,
    pub divergence: u64,
    pub skipped: u64,
}

impl SetPathCounters {
    pub(crate) fn record(&mut self, kind: &str) {
        match kind {
            "fast" => self.fast += 1,
            "anomaly" => self.anomaly += 1,
            "mismatch_reseeded" => self.mismatch_reseeded += 1,
            "divergence" => self.divergence += 1,
            _ => self.skipped += 1,
        }
    }
}

fn report(timings: &PhaseTimings, result: &SetPathResult, sizes: Option<CaptureSizes>) {
    timings.set_set_path(serde_json::json!({
        "kind": result.kind(),
        "last_set_path": result.label(),
        "capture": sizes.map(|sizes| serde_json::json!({
            "touches": sizes.touches,
            "old_images": sizes.old_images,
        })),
    }));
}

fn summaries(rows: &[AccRow]) -> Vec<SetTableDump> {
    rows.iter()
        .map(|row| SetTableDump {
            name: row.name.clone(),
            schema_sha256: row.schema_sha256.clone(),
            rows: row.rows.max(0) as u64,
            set_sha256: hex::encode(sha2::Sha256::digest(&row.value)),
        })
        .collect()
}

/// The accumulator rows, if and only if the cache is provably current: every
/// row is at the last receipt's ordinal, and the digest the rows compose to
/// equals the set digest that receipt certifies. O(tables).
async fn load_accumulator(
    conn: &mut sqlx::SqliteConnection,
    previous: &Receipt,
) -> Result<AccLoad> {
    use sqlx::Row as _;
    if !accumulator_table_present(conn).await? {
        return Ok(AccLoad::Absent);
    }
    let raw = sqlx::query(&format!(
        "SELECT name,schema_sha256,rows,value,ordinal FROM {ACCUMULATOR_TABLE} ORDER BY name"
    ))
    .fetch_all(&mut *conn)
    .await?;
    if raw.is_empty() {
        return Ok(AccLoad::Absent);
    }
    let Some(certified) = previous.projection_set_sha256.as_deref() else {
        return Ok(AccLoad::Invalid);
    };
    let mut rows = Vec::with_capacity(raw.len());
    for row in &raw {
        let decoded = (|| -> std::result::Result<_, sqlx::Error> {
            Ok((
                row.try_get::<String, _>(0)?,
                row.try_get::<String, _>(1)?,
                row.try_get::<i64, _>(2)?,
                row.try_get::<Vec<u8>, _>(3)?,
                row.try_get::<i64, _>(4)?,
            ))
        })();
        match decoded {
            Ok((name, schema_sha256, count, value, ordinal))
                if value.len() == BYTE_SIZE && count >= 0 && ordinal == previous.ordinal =>
            {
                rows.push(AccRow {
                    name,
                    schema_sha256,
                    rows: count,
                    value,
                    dirty: false,
                });
            }
            _ => return Ok(AccLoad::Invalid),
        }
    }
    Ok(if set_digest(&summaries(&rows))? == certified {
        AccLoad::Valid(rows)
    } else {
        AccLoad::Invalid
    })
}

/// Choose how this apply proves the projection (before any mutation). Moves a
/// first-DDL generation to the second DDL when a version-2 delta first arrives.
pub(crate) async fn plan(
    tx: &mut sqlx::SqliteConnection,
    delta: &kernel_v2_delta::KernelDelta,
    suppressed: bool,
) -> Result<Route> {
    let inconsistent = || Error::engine(RECEIPTS_INCONSISTENT);
    #[cfg(test)]
    if FORCE_N1.with(std::cell::Cell::get) {
        return Ok(Route::V1);
    }
    let ddl = receipts_ddl(tx).await.map_err(|_| inconsistent())?;
    // Versions 2 and 3 both use the set path; only version 2 carries a digest
    // to compare with.
    let v2_delta = delta.version != kernel_v2_delta::WIRE_VERSION_1;
    match (v2_delta, ddl) {
        (false, ReceiptsDdl::V1) => Ok(Route::V1),
        (false, ReceiptsDdl::V2) => Ok(Route::FullScan("v1_delta")),
        (true, ReceiptsDdl::V1) => {
            upgrade_receipts_to_v2(tx).await?;
            Ok(Route::FullScan("no_accumulator"))
        }
        (true, ReceiptsDdl::V2) => {
            if suppressed {
                return Ok(Route::FullScan("suppressed"));
            }
            let previous = last_receipt(tx)
                .await
                .map_err(|_| inconsistent())?
                .ok_or_else(inconsistent)?;
            Ok(match load_accumulator(tx, &previous).await? {
                AccLoad::Valid(rows) => Route::Set(rows),
                AccLoad::Absent => Route::FullScan("no_accumulator"),
                AccLoad::Invalid => Route::FullScan("accumulator_invalid"),
            })
        }
    }
}

/// Rewrite a first-DDL receipt chain under the second DDL, in this
/// transaction. The old chain is verified link by link first (anchored to the
/// checkpoint hash the base receipt carries), then every receipt is re-linked
/// under the second format; nothing else about a receipt changes.
async fn upgrade_receipts_to_v2(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    let inconsistent = || Error::engine(RECEIPTS_INCONSISTENT);
    let old: Vec<Receipt> = sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} ORDER BY ordinal",
        ReceiptsDdl::V1.columns()
    ))
    .fetch_all(&mut *tx)
    .await?;
    let base = old.first().ok_or_else(inconsistent)?;
    if base.kind != "base" || base.ordinal != 0 {
        return Err(inconsistent());
    }
    let mut chain = genesis_hash(&base.delta_sha256);
    for (index, receipt) in old.iter().enumerate() {
        if receipt.ordinal != index as i64
            || receipt.link(&chain, ReceiptsDdl::V1) != receipt.chain_sha256
        {
            return Err(inconsistent());
        }
        chain = receipt.chain_sha256.clone();
    }
    sqlx::query(&format!("DROP TABLE {RECEIPTS_TABLE}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query(RECEIPTS_DDL_V2).execute(&mut *tx).await?;
    let mut chain = genesis_hash(&base.delta_sha256);
    for mut receipt in old {
        receipt.chain_sha256 = receipt.link(&chain, ReceiptsDdl::V2);
        chain = receipt.chain_sha256.clone();
        insert_receipt(tx, &receipt, ReceiptsDdl::V2).await?;
    }
    Ok(())
}

/// `A_t * delta_t`: false if the composed row count would go negative.
fn compose(row: &mut AccRow, delta: &TableDelta) -> bool {
    let mut bytes = [0_u8; BYTE_SIZE];
    bytes.copy_from_slice(&row.value);
    let mut value = MuHash::from_numerator(Num3072::from_le_bytes(&bytes));
    value.combine(&delta.delta);
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut composed = value.normalise();
    #[cfg(test)]
    if FORCE_COMPOSE_ERROR.with(|flag| flag.replace(false)) {
        composed[0] ^= 1;
    }
    row.value = composed.to_vec();
    row.rows += delta.row_delta;
    row.dirty = true;
    row.rows >= 0
}

/// Compose every touched table and, when the delta carries hosted's set digest,
/// compare with it: each touched table's schema first, then the whole digest.
/// `Ok(digest)` is the composed whole-set digest; `Err(table)` names the first
/// table that disagrees (or that the cache cannot compose). A delta without a
/// digest (wire version 3) is composed with nothing to compare against.
async fn compose_and_check(
    tx: &mut sqlx::SqliteConnection,
    acc: &mut [AccRow],
    deltas: &[TableDelta],
    hosted: Option<&SetDump>,
) -> Result<std::result::Result<String, String>> {
    for delta in deltas {
        let Some(row) = acc.iter_mut().find(|row| row.name == delta.name) else {
            return Ok(Err(delta.name.clone()));
        };
        if !compose(row, delta) {
            return Ok(Err(delta.name.clone()));
        }
        let live = crate::kernel::projection_dump::table_schema_sha256(tx, &delta.name).await?;
        if let Some(hosted) = hosted {
            let agrees = hosted
                .tables
                .iter()
                .find(|table| table.name == delta.name)
                .is_some_and(|table| table.schema_sha256 == live);
            if !agrees {
                return Ok(Err(delta.name.clone()));
            }
        }
        row.schema_sha256 = live;
    }
    let composed = summaries(acc);
    let digest = set_digest(&composed)?;
    let Some(hosted) = hosted else {
        return Ok(Ok(digest));
    };
    if digest == hosted.sha256 {
        return Ok(Ok(digest));
    }
    // Name the table that disagrees (or the first difference in the table set).
    let culprit = composed
        .iter()
        .find(|table| !hosted.tables.iter().any(|theirs| theirs == *table))
        .map(|table| table.name.clone())
        .or_else(|| hosted.tables.first().map(|table| table.name.clone()))
        .unwrap_or_default();
    Ok(Err(culprit))
}

/// The single full dual scan: it must reproduce every digest the delta carries
/// (hosted's v1 digest and its set digest). A mismatch is divergence. A delta
/// that carries none (wire version 3) is not compared with anything; the scan
/// then only reseeds the cache and gives the receipt its digest.
async fn full_scan(
    tx: &mut sqlx::SqliteConnection,
    delta: &kernel_v2_delta::KernelDelta,
    success: SetPathResult,
    sizes: Option<CaptureSizes>,
    timings: &PhaseTimings,
) -> Result<Proof> {
    timings.mark_full_scan();
    let (v1, set, values) = crate::kernel::projection_dump::dump_on_dual_values(tx).await?;
    timings.lap("apply_full_scan");
    // Whatever digests the delta carries must match; version 3 carries none.
    let matches = delta
        .head
        .projection_sha256
        .as_ref()
        .is_none_or(|hosted| *hosted == v1.sha256)
        && delta
            .head
            .projection_set
            .as_ref()
            .is_none_or(|hosted| hosted.sha256 == set.sha256);
    if !matches {
        report(timings, &SetPathResult::Divergence, sizes);
        return Err(Error::engine(DIVERGENCE));
    }
    report(timings, &success, sizes);
    Ok(Proof::Dual {
        set_sha256: set.sha256,
        values,
    })
}

/// Prove a `Set` or `FullScan` route. `capture` is the outcome of the fold's
/// capture (present exactly for `Route::Set`).
pub(crate) async fn prove(
    tx: &mut sqlx::SqliteConnection,
    delta: &kernel_v2_delta::KernelDelta,
    route: Route,
    capture: Option<(CaptureOutcome, CaptureSizes)>,
    timings: &PhaseTimings,
) -> Result<Proof> {
    match route {
        Route::V1 => Err(Error::engine("the v1 route has no set proof")),
        Route::FullScan(cause) => {
            full_scan(tx, delta, SetPathResult::Skipped(cause), None, timings).await
        }
        Route::Set(mut acc) => {
            let (outcome, sizes) =
                capture.ok_or_else(|| Error::engine("set route without a capture"))?;
            // `None` for wire version 3: composed, nothing to compare.
            let hosted = delta.head.projection_set.as_ref();
            #[cfg(test)]
            let outcome = match FORCE_ANOMALY.with(|slot| slot.borrow_mut().take()) {
                Some(anomaly) => CaptureOutcome::Anomaly(anomaly),
                None => outcome,
            };
            let mut composed_digest = None;
            let failure = match outcome {
                CaptureOutcome::Anomaly(anomaly) => Some(SetPathResult::Anomaly(anomaly.reason())),
                CaptureOutcome::Delta(deltas) => {
                    match compose_and_check(tx, &mut acc, &deltas, hosted).await? {
                        Ok(digest) => {
                            composed_digest = Some(digest);
                            None
                        }
                        Err(table) => Some(SetPathResult::MismatchReseeded(table)),
                    }
                }
            };
            timings.lap("apply_set_compose");
            match failure {
                None => {
                    report(timings, &SetPathResult::Fast, Some(sizes));
                    let digest = composed_digest
                        .ok_or_else(|| Error::engine("set route composed no digest"))?;
                    Ok(Proof::Set(acc, digest))
                }
                Some(failure) => full_scan(tx, delta, failure, Some(sizes), timings).await,
            }
        }
    }
}

async fn ensure_accumulator_table(conn: &mut sqlx::SqliteConnection) -> Result<()> {
    if !accumulator_table_present(conn).await? {
        sqlx::query(ACCUMULATOR_DDL).execute(conn).await?;
    }
    Ok(())
}

/// Write back the composed accumulator at the new receipt's ordinal.
pub(crate) async fn write_composed(
    conn: &mut sqlx::SqliteConnection,
    acc: &[AccRow],
    ordinal: i64,
) -> Result<()> {
    ensure_accumulator_table(conn).await?;
    for row in acc.iter().filter(|row| row.dirty) {
        sqlx::query(&format!(
            "UPDATE {ACCUMULATOR_TABLE} SET schema_sha256=?, rows=?, value=? WHERE name=?"
        ))
        .bind(&row.schema_sha256)
        .bind(row.rows)
        .bind(&row.value)
        .bind(&row.name)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(&format!("UPDATE {ACCUMULATOR_TABLE} SET ordinal=?"))
        .bind(ordinal)
        .execute(conn)
        .await?;
    Ok(())
}

/// Replace the whole accumulator with what a full scan computed.
pub(crate) async fn reseed(
    conn: &mut sqlx::SqliteConnection,
    values: &[SetValue],
    ordinal: i64,
) -> Result<()> {
    ensure_accumulator_table(conn).await?;
    sqlx::query(&format!("DELETE FROM {ACCUMULATOR_TABLE}"))
        .execute(&mut *conn)
        .await?;
    for value in values {
        sqlx::query(&format!(
            "INSERT INTO {ACCUMULATOR_TABLE}(name,schema_sha256,rows,value,ordinal) VALUES(?,?,?,?,?)"
        ))
        .bind(&value.name)
        .bind(&value.schema_sha256)
        .bind(value.rows as i64)
        .bind(&value.value)
        .bind(ordinal)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}
