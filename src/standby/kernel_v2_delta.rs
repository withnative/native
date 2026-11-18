//! A separate, closed wire format for kernel-v2 events; no v1 section relabelling.
use super::generation_store::kernel_in_place::{self, set_path};
use super::kernel_v2::{self, KernelGeneration};
use super::phase_timings::PhaseTimings;
use crate::interchange::{ConflictMode, Section, SelectionBind};
use crate::kernel::projection_dump::SetDump;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;

/// The fold ran on a connection that does not enforce foreign keys.
pub(crate) const FOREIGN_KEYS_OFF: &str = "kernel_v2_delta_foreign_keys_not_enforced";
const CONTRACT: &str = "native.standby-kernel-v2-delta.v1";
/// The wire versions this build can parse. 1 carries the v1 projection digest
/// only; 2 adds `head.projection_set`; 3 carries NO projection digest at all
/// (the host skips the full scan that dominates a cut). Every other integrity
/// check of a delta is the same in all three versions.
pub(crate) const WIRE_VERSION_1: u32 = 1;
pub(crate) const WIRE_VERSION_2: u32 = 2;
pub(crate) const WIRE_VERSION_3: u32 = 3;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelDelta {
    pub contract: String,
    pub version: u32,
    pub origin_database_id: String,
    pub from_exclusive_act: i64,
    pub head: KernelDeltaHead,
    pub sections: Vec<Section>,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelDeltaHead {
    pub generation: KernelGeneration,
    /// The ordered v1 digest. Present in versions 1 and 2, absent in 3;
    /// `KernelDelta::parse` enforces which.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_sha256: Option<String>,
    /// The set digest of every projection table (wire version 2 only). Absent
    /// in versions 1 and 3, whose bytes are unchanged by this field's existence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_set: Option<SetDump>,
}
impl std::ops::Deref for KernelDeltaHead {
    type Target = KernelGeneration;
    fn deref(&self) -> &Self::Target {
        &self.generation
    }
}

impl KernelDelta {
    fn digest(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("content_sha256");
        Ok(crate::standby_snapshot::sha256_bytes(&serde_jcs::to_vec(
            &value,
        )?))
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_jcs::to_vec(self)?)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let delta: Self = serde_json::from_slice(bytes)?;
        if delta.bytes()? != bytes
            || delta.contract != CONTRACT
            // Which proofs a version carries is strict: 1 the v1 digest alone,
            // 2 both, 3 neither. Nothing else is a delta.
            || !match delta.version {
                WIRE_VERSION_1 => {
                    delta.head.projection_sha256.is_some() && delta.head.projection_set.is_none()
                }
                WIRE_VERSION_2 => {
                    delta.head.projection_sha256.is_some() && delta.head.projection_set.is_some()
                }
                WIRE_VERSION_3 => {
                    delta.head.projection_sha256.is_none() && delta.head.projection_set.is_none()
                }
                _ => false,
            }
            || delta.digest()? != delta.content_sha256
        {
            return Err(Error::engine(
                "invalid kernel-v2 delta contract/canonical bytes/digest",
            ));
        }
        delta.head.validate()?;
        if let Some(v1) = &delta.head.projection_sha256 {
            if v1.len() != 64
                || !v1
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::engine("invalid kernel-v2 projection digest"));
            }
        }
        if let Some(set) = &delta.head.projection_set {
            validate_set(set)?;
        }
        if !crate::identity::is_database_id(&delta.origin_database_id)
            || delta.from_exclusive_act < 0
            || delta.from_exclusive_act > delta.head.head_act
            || delta
                .sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                != [
                    "content_events",
                    "meta_events",
                    "kernel_blobs",
                    "content_event_causal_frontier",
                ]
        {
            return Err(Error::engine("invalid kernel-v2 delta bounds or inventory"));
        }
        for section in &delta.sections {
            if section.format != crate::interchange::SECTION_FORMAT
                || section.revision != crate::interchange::REVISION
            {
                return Err(Error::engine("kernel-v2 delta section codec mismatch"));
            }
            crate::interchange::validate_section_shape(section)?;
        }
        Ok(delta)
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Structure of a carried set digest: sorted unique table names, well-formed
/// digests, and a whole-digest that is the one its summaries produce.
fn validate_set(set: &SetDump) -> Result<()> {
    let invalid = || Error::engine("invalid kernel-v2 projection set digest");
    if !is_lower_hex_64(&set.sha256)
        || !set
            .tables
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
        || set.tables.iter().any(|table| {
            table.name.is_empty()
                || !is_lower_hex_64(&table.schema_sha256)
                || !is_lower_hex_64(&table.set_sha256)
        })
        || crate::kernel::projection_dump::set_digest(&set.tables)? != set.sha256
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) const MAX_BLOB_INVENTORY: usize = 65_536;

/// A delta is SMALL when the work it asks of the serving copy is bounded by
/// numbers that do not depend on the size of the database: at most this many
/// content+meta event rows, whole acts, and new-blob bytes. Everything else is
/// LARGE and keeps the conservative treatment (one-minute rest after replay,
/// and the staged copy-and-publish path when in-place deltas are enabled).
pub(crate) const SMALL_DELTA_MAX_EVENTS: usize = 256;
pub(crate) const SMALL_DELTA_MAX_ACTS: i64 = 128;
pub(crate) const SMALL_DELTA_MAX_BLOB_BYTES: u64 = 4 * 1024 * 1024;

/// What a delta asks of the copy that applies it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelDeltaSize {
    pub acts: i64,
    pub events: usize,
    pub blob_bytes: u64,
}

impl KernelDeltaSize {
    pub(crate) fn is_small(&self) -> bool {
        self.acts <= SMALL_DELTA_MAX_ACTS
            && self.events <= SMALL_DELTA_MAX_EVENTS
            && self.blob_bytes <= SMALL_DELTA_MAX_BLOB_BYTES
    }
}

impl KernelDelta {
    /// The delta's size, from its already-validated sections. Blob bytes are
    /// the declared `size_bytes` of each carried blob (apply later checks each
    /// declaration against the bytes); a missing column counts the encoded
    /// length, which can only overstate.
    pub(crate) fn size(&self) -> KernelDeltaSize {
        let events = self.sections[0].rows.len() + self.sections[1].rows.len();
        let blobs = &self.sections[2];
        let size_column = blobs.columns.iter().position(|c| c.name == "size_bytes");
        let blob_bytes = blobs
            .rows
            .iter()
            .map(|row| match size_column.map(|index| &row[index]) {
                Some(crate::interchange::Cell::Integer(size)) => (*size).max(0) as u64,
                _ => row
                    .iter()
                    .map(|cell| match cell {
                        crate::interchange::Cell::Blob(text)
                        | crate::interchange::Cell::Text(text) => text.len() as u64,
                        _ => 0,
                    })
                    .sum(),
            })
            .fold(0_u64, u64::saturating_add);
        KernelDeltaSize {
            acts: self.head.head_act - self.from_exclusive_act,
            events,
            blob_bytes,
        }
    }
}

pub(crate) fn validate_blob_inventory(inventory: &[String]) -> Result<()> {
    if inventory.len() > MAX_BLOB_INVENTORY
        || !inventory.windows(2).all(|p| p[0] < p[1])
        || inventory.iter().any(|sha| {
            sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(Error::engine("invalid kernel-v2 base blob inventory"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) async fn cut(
    conn: &mut SqliteConnection,
    from: i64,
    inventory: &[String],
) -> Result<KernelDelta> {
    cut_versioned(conn, from, inventory, WIRE_VERSION_1).await
}

/// [`cut`] at an explicit wire version. Version 1 is byte-identical to what
/// `cut` always produced; version 2 additionally carries the set digest,
/// computed in the same ordered pass as the v1 digest; version 3 carries no
/// digest and skips the scan entirely. (Hosted negotiates only 1 and 2 today:
/// nothing offers 3.)
#[cfg(test)]
pub(crate) async fn cut_versioned(
    conn: &mut SqliteConnection,
    from: i64,
    inventory: &[String],
    wire_version: u32,
) -> Result<KernelDelta> {
    Ok(cut_versioned_timed(conn, from, inventory, wire_version)
        .await?
        .0)
}

/// Step timings of one kernel cut, for the delta-cut timing log (task
/// 445e3aa). Milliseconds and a row count only.
#[derive(Default)]
pub(crate) struct CutTimings {
    /// Receipt coverage, coordinates and origin.
    pub head_ms: u64,
    pub sections_ms: u64,
    /// Zero for version 3, which skips the projection scan.
    pub projection_ms: u64,
    /// Sealing the content digest and re-validating the canonical bytes.
    pub seal_ms: u64,
    /// Rows across the cut's sections.
    pub rows: usize,
}

/// [`cut_versioned`] that also reports where the time went.
pub(crate) async fn cut_versioned_timed(
    conn: &mut SqliteConnection,
    from: i64,
    inventory: &[String],
    wire_version: u32,
) -> Result<(KernelDelta, CutTimings)> {
    if !matches!(
        wire_version,
        WIRE_VERSION_1 | WIRE_VERSION_2 | WIRE_VERSION_3
    ) {
        return Err(Error::engine("unsupported kernel-v2 delta wire version"));
    }
    validate_blob_inventory(inventory)?;
    let started = std::time::Instant::now();
    crate::kernel::mcp_write_receipts::require_covered_on(conn).await?;
    let head = kernel_v2::coordinates(conn).await?;
    let origin_database_id = kernel_v2::origin(conn, &head).await?;
    let mut timings = CutTimings {
        head_ms: started.elapsed().as_millis() as u64,
        ..CutTimings::default()
    };
    if from < 0 || from > head.head_act {
        return Err(Error::engine("kernel-v2 delta lower bound beyond head"));
    }
    let started = std::time::Instant::now();
    let mut sections = Vec::new();
    for name in ["content_events", "meta_events"] {
        sections.push(
            crate::interchange::export_act_range_section(conn, name, from, head.head_act).await?,
        );
    }
    // The consumer names only verified CAS keys, never byte payloads. This also
    // finds unbound blobs added without advancing the event/act head.
    sections.push(
        crate::interchange::export_where_section(
            conn,
            "kernel_blobs",
            "sha256 NOT IN (SELECT value FROM json_each(?))",
            &[SelectionBind::Text(serde_json::to_string(inventory)?)],
        )
        .await?,
    );
    sections.push(
        crate::interchange::export_where_section(
            conn,
            "content_event_causal_frontier",
            "event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)",
            &[
                SelectionBind::Integer(from),
                SelectionBind::Integer(head.head_act),
            ],
        )
        .await?,
    );
    timings.sections_ms = started.elapsed().as_millis() as u64;
    timings.rows = sections.iter().map(|section| section.rows.len()).sum();
    let started = std::time::Instant::now();
    let (projection_sha256, projection_set) = match wire_version {
        WIRE_VERSION_2 => {
            let (v1, set) = crate::kernel::projection_dump::dump_on_dual(conn).await?;
            (Some(v1.sha256), Some(set))
        }
        // No scan at all: this is the cost version 3 exists to avoid.
        WIRE_VERSION_3 => (None, None),
        _ => (
            Some(crate::kernel::projection_dump::dump_on(conn).await?.sha256),
            None,
        ),
    };
    timings.projection_ms = started.elapsed().as_millis() as u64;
    let started = std::time::Instant::now();
    let mut delta = KernelDelta {
        contract: CONTRACT.into(),
        version: wire_version,
        origin_database_id,
        from_exclusive_act: from,
        head: KernelDeltaHead {
            generation: head,
            projection_sha256,
            projection_set,
        },
        sections,
        content_sha256: String::new(),
    };
    delta.content_sha256 = delta.digest()?;
    let delta = KernelDelta::parse(&delta.bytes()?)?;
    timings.seal_ms = started.elapsed().as_millis() as u64;
    Ok((delta, timings))
}

// Only the authenticated transport can construct this witness.
pub(crate) struct TrustedKernelDelta {
    delta: KernelDelta,
}
impl TrustedKernelDelta {
    pub(super) fn from_authenticated(
        witness: super::delta_transport::AuthenticatedKernelDelta,
    ) -> Self {
        Self {
            delta: witness.into_delta(),
        }
    }
    /// Only the probe-gated fork tests mint this witness directly; the
    /// authenticated transport is the sole production constructor.
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) fn assume_trusted_for_test(delta: KernelDelta) -> Result<Self> {
        Ok(Self {
            delta: KernelDelta::parse(&delta.bytes()?)?,
        })
    }
    pub(crate) fn delta(&self) -> &KernelDelta {
        &self.delta
    }
}

pub(crate) async fn apply(
    db: &crate::Db,
    trusted: &TrustedKernelDelta,
    timings: &PhaseTimings,
) -> Result<()> {
    apply_with_hook(db, trusted, timings, ApplyMode::Staged, &|| Ok(())).await
}

/// Where the fold runs. `InPlace` is the serving database itself: the apply
/// receipt is written in the same transaction, so the data never advances
/// without it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyMode {
    Staged,
    InPlace,
    /// [`ApplyMode::InPlace`] with the set path switched off for this
    /// generation (repeated damaged-cache reseeds): a version-2 delta takes the
    /// one full scan.
    InPlaceSetSuppressed,
}

impl ApplyMode {
    fn in_place(self) -> bool {
        !matches!(self, Self::Staged)
    }
}

/// Facts a fold establishes about the delta it applied: the act and sequence
/// heads it moved, the blob count it certifies, and the delta it consumed.
/// These are the facts the in-place path would write into its receipt; the
/// receipt itself is written by [`certify_fold_in_transaction`].
///
/// Read by the seam tests and the future working-copy rebase; no production
/// reader yet.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct AppliedDeltaFacts {
    pub from_act: i64,
    pub to_act: i64,
    pub content_seq_from: i64,
    pub content_seq_to: i64,
    pub meta_seq_from: i64,
    pub meta_seq_to: i64,
    pub blob_count: i64,
    pub delta_sha256: String,
}

/// A delta folded into a caller-owned transaction, before certification.
/// Carries everything [`certify_fold_in_transaction`] needs: the starting
/// generation, the proof route, and the set-path capture when one was armed.
pub(crate) struct FoldedDelta {
    before: KernelGeneration,
    mode: ApplyMode,
    route: Option<set_path::Route>,
    capture: Option<(
        crate::kernel::projection_capture::CaptureOutcome,
        set_path::CaptureSizes,
    )>,
    facts: AppliedDeltaFacts,
}

/// Inspectors for the seam tests and the future working-copy rebase; no
/// production reader yet.
#[allow(dead_code)]
impl FoldedDelta {
    /// The generation the fold started from.
    pub(crate) fn before(&self) -> &KernelGeneration {
        &self.before
    }
    /// The mode this fold ran under.
    pub(crate) fn mode(&self) -> ApplyMode {
        self.mode
    }
    /// The facts the fold established (pre-receipt).
    pub(crate) fn facts(&self) -> &AppliedDeltaFacts {
        &self.facts
    }
}

/// The certified result of a fold: the applied facts plus the in-place apply
/// receipt, when the mode writes one ([`ApplyMode::Staged`] certifies the
/// projection digest without writing a receipt).
///
/// Read by the seam tests and the future working-copy rebase; no production
/// reader yet.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct CertifiedFold {
    pub facts: AppliedDeltaFacts,
    pub receipt: Option<kernel_in_place::Receipt>,
}

/// Fold one already-verified trusted delta into a caller-supplied
/// transaction: continuity checks, blob and event ingest, `act_state`,
/// `replay_projection_tail_on`, and the postcondition and coordinate checks.
///
/// This never begins, commits or rolls back a transaction of its own: the
/// caller owns `tx` and decides its fate. It takes no `Db`, holds no pool
/// connection beyond `tx`, and never wakes realtime; the caller wakes
/// realtime itself after its outer commit (via
/// `Db::commit_kernel_content` or equivalent). Timings laps are emitted in
/// the same order as [`apply_with_hook`].
pub(crate) async fn fold_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    trusted: &TrustedKernelDelta,
    timings: &PhaseTimings,
    mode: ApplyMode,
) -> Result<FoldedDelta> {
    fold_with_coordinates(
        tx,
        trusted,
        timings,
        mode,
        &CoordinateAdmission::Accepted(std::marker::PhantomData),
    )
    .await
}

// Private strategy only: no global schema exemptions, accepted verification
// override, caller-supplied ignored objects, or conversion into certification.
enum CoordinateAdmission<'a> {
    Accepted(std::marker::PhantomData<&'a ()>),
    #[cfg(feature = "v2-kernel-probe")]
    Working(
        &'a kernel_v2::WorkingKernelSchema,
        &'a crate::kernel::working_undo::Collector,
    ),
}

/// Per-replay-run decoder evidence. No caller can select its entry: the fold
/// mints it only from its already checked native coordinates, or a full replay
/// observes the actual native schema on its pinned connection. Never serialized.
pub(crate) struct ProjectionShape {
    entry: &'static crate::standby::shapes::Entry,
}
impl ProjectionShape {
    fn from_coordinates(generation: &KernelGeneration) -> Result<Self> {
        let entry = crate::standby::shapes::v2(generation.reader_format, &generation.schema_sha256)
            .ok_or_else(|| Error::engine("projection decoder shape is unregistered"))?;
        Ok(Self { entry })
    }

    pub(crate) async fn observe_on(conn: &mut SqliteConnection) -> Result<Self> {
        Self::from_coordinates(&kernel_v2::coordinates(conn).await?)
    }

    pub(crate) fn observation_envelope(&self) -> bool {
        self.entry.observation_envelope
    }
}
impl CoordinateAdmission<'_> {
    async fn coordinates(&self, conn: &mut SqliteConnection) -> Result<KernelGeneration> {
        match self {
            Self::Accepted(_) => kernel_v2::coordinates(conn).await,
            #[cfg(feature = "v2-kernel-probe")]
            Self::Working(schema, collector) => schema.coordinates_on(conn, collector).await,
        }
    }
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct WorkingFold<'phase, 'conn> {
    tx: &'phase mut sqlx::Transaction<'conn, sqlx::Sqlite>,
    collector: &'phase crate::kernel::working_undo::Collector,
    schema: &'phase kernel_v2::WorkingKernelSchema,
}
#[cfg(feature = "v2-kernel-probe")]
impl<'phase, 'conn> WorkingFold<'phase, 'conn> {
    pub(crate) async fn new(
        tx: &'phase mut sqlx::Transaction<'conn, sqlx::Sqlite>,
        collector: &'phase crate::kernel::working_undo::Collector,
        schema: &'phase kernel_v2::WorkingKernelSchema,
        expected: &KernelGeneration,
        origin: &str,
    ) -> Result<Self> {
        let actual = schema.coordinates_on(tx, collector).await?;
        if &actual != expected || kernel_v2::origin(tx, &actual).await? != origin {
            return Err(Error::engine(
                "working native fold restored coordinates/origin differ",
            ));
        }
        Ok(Self {
            tx,
            collector,
            schema,
        })
    }
    /// Consumes the sole mutable Tx borrow. No FoldedDelta escapes: that type
    /// can feed accepted certification. Only checked native coordinates return.
    pub(crate) async fn fold(
        self,
        trusted: &TrustedKernelDelta,
        timings: &PhaseTimings,
    ) -> Result<KernelGeneration> {
        let _folded = fold_with_coordinates(
            self.tx,
            trusted,
            timings,
            ApplyMode::Staged,
            &CoordinateAdmission::Working(self.schema, self.collector),
        )
        .await?;
        Ok(trusted.delta().head.generation.clone())
    }
}
async fn fold_with_coordinates(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    trusted: &TrustedKernelDelta,
    timings: &PhaseTimings,
    mode: ApplyMode,
    admission: &CoordinateAdmission<'_>,
) -> Result<FoldedDelta> {
    let delta = trusted.delta();
    // Every foreign key in the kernel schema is immediate (none is DEFERRABLE)
    // and nothing on the fold path turns enforcement off or defers it, so with
    // enforcement on a violation cannot be introduced by this transaction. The
    // whole-database scan this replaces is run by the full integrity check and
    // at publication instead; here the guarantee is that enforcement is on.
    let enforcing: i64 = sqlx::query_scalar("SELECT foreign_keys FROM pragma_foreign_keys")
        .fetch_one(&mut **tx)
        .await?;
    if enforcing != 1 {
        return Err(Error::engine(FOREIGN_KEYS_OFF));
    }
    timings.lap("apply_foreign_keys_enforced");
    let before = admission.coordinates(&mut *tx).await?;
    let origin = kernel_v2::origin(&mut *tx, &before).await?;
    if before.head_act != delta.from_exclusive_act
        || origin != delta.origin_database_id
        || before.genesis_event_id != delta.head.genesis_event_id
        || before.schema_sha256 != delta.head.schema_sha256
    {
        return Err(Error::engine("kernel-v2 delta fails base continuity"));
    }
    timings.lap("apply_base_continuity");
    let route = if mode.in_place() {
        kernel_in_place::verify_prior_state(&mut *tx).await?;
        timings.lap("apply_prior_state");
        let route =
            set_path::plan(&mut *tx, delta, mode == ApplyMode::InPlaceSetSuppressed).await?;
        timings.lap("apply_set_plan");
        Some(route)
    } else {
        None
    };
    for section in &delta.sections {
        crate::interchange::validate_destination_section(&mut *tx, section).await?;
    }
    timings.lap("apply_validate_sections");
    for (section, old_seq) in delta.sections[..2]
        .iter()
        .zip([before.content_event_seq, before.meta_event_seq])
    {
        let seq_index = section
            .columns
            .iter()
            .position(|c| c.name == "seq")
            .ok_or_else(|| Error::engine("event section lacks sequence"))?;
        let act_index = section
            .columns
            .iter()
            .position(|c| c.name == "act")
            .ok_or_else(|| Error::engine("event section lacks act"))?;
        for row in &section.rows {
            if !matches!(row[seq_index],crate::interchange::Cell::Integer(seq) if seq > old_seq)
                || !matches!(row[act_index],crate::interchange::Cell::Integer(act) if act > before.head_act && act <= delta.head.head_act)
            {
                return Err(Error::engine(
                    "kernel-v2 event lies outside the advertised tail",
                ));
            }
        }
    }
    timings.lap("apply_check_tail");
    let blobs = &delta.sections[2];
    let sha_column = blobs
        .columns
        .iter()
        .position(|c| c.name == "sha256")
        .ok_or_else(|| Error::engine("blob section lacks digest"))?;
    let mut added_blobs = Vec::new();
    for row in &blobs.rows {
        let crate::interchange::Cell::Text(sha) = &row[sha_column] else {
            return Err(Error::engine("blob digest is not text"));
        };
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_blobs WHERE sha256=?)")
                .bind(sha)
                .fetch_one(&mut **tx)
                .await?;
        if !exists {
            added_blobs.push(sha.clone());
        }
    }
    timings.lap("apply_blob_scan");
    // The fold. Under the set path it runs with slice 4's capture armed on
    // the writer; the capture is disarmed and read back before anything else.
    let mut capture = None;
    if matches!(route, Some(set_path::Route::Set(_))) {
        let mut hooked = crate::kernel::projection_capture::Hooked::arm(&mut *tx).await?;
        timings.lap("apply_capture_arm");
        fold(&mut hooked, delta, &before, added_blobs, timings, admission).await?;
        let sizes = set_path::CaptureSizes {
            touches: hooked.touched_len(),
            old_images: hooked.base_rows_len(),
        };
        let outcome = hooked.finish().await?;
        timings.lap("apply_capture_finish");
        capture = Some((outcome, sizes));
    } else {
        fold(&mut *tx, delta, &before, added_blobs, timings, admission).await?;
    }
    let facts = AppliedDeltaFacts {
        from_act: before.head_act,
        to_act: delta.head.head_act,
        content_seq_from: before.content_event_seq,
        content_seq_to: delta.head.content_event_seq,
        meta_seq_from: before.meta_event_seq,
        meta_seq_to: delta.head.meta_event_seq,
        blob_count: delta.head.blob_count,
        delta_sha256: delta.content_sha256.clone(),
    };
    Ok(FoldedDelta {
        before,
        mode,
        route,
        capture,
        facts,
    })
}

/// Certify a fold on the same caller-owned transaction: run the
/// projection-digest check (a full scan when the delta carries a v1 digest)
/// and, for in-place modes, write the apply receipt. Staged modes certify
/// without writing a receipt. Like [`fold_in_transaction`] this never
/// commits, rolls back or wakes realtime. Callers that want certification
/// invoke this explicitly after the fold; timings laps continue in
/// [`apply_with_hook`] order.
pub(crate) async fn certify_fold_in_transaction(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    trusted: &TrustedKernelDelta,
    folded: FoldedDelta,
    timings: &PhaseTimings,
) -> Result<CertifiedFold> {
    let delta = trusted.delta();
    let FoldedDelta {
        before,
        mode,
        route,
        capture,
        facts,
    } = folded;
    // The fold and its certification must agree on the delta: a mismatch is
    // a caller bug, never something to certify past.
    if facts.delta_sha256 != delta.content_sha256 {
        return Err(Error::engine(
            "certify_fold_in_transaction delta does not match the fold",
        ));
    }
    let receipt = match route {
        None | Some(set_path::Route::V1) => {
            // Version 3 carries no projection digest, so only that comparison
            // is skipped: the content digest, bindings, act and sequence
            // continuity and the replay postcondition were checked above.
            if let Some(expected) = &delta.head.projection_sha256 {
                timings.mark_full_scan();
                let digest = crate::kernel::projection_dump::dump_on_observed(
                    &mut *tx,
                    &mut |table, rows, took| timings.table(table, rows, took),
                )
                .await?
                .sha256;
                timings.lap("apply_projection_digest");
                if &digest != expected {
                    return Err(Error::engine("kernel_v2_projection_divergence"));
                }
            }
            if mode.in_place() {
                let receipt =
                    kernel_in_place::record_delta_receipt(&mut *tx, &before, delta).await?;
                timings.note_receipt_ordinal(receipt.ordinal);
                timings.lap("apply_receipt");
                Some(receipt)
            } else {
                None
            }
        }
        Some(route) => {
            let proof = set_path::prove(&mut *tx, delta, route, capture, timings).await?;
            timings.lap("apply_projection_proof");
            let certified = match &proof {
                set_path::Proof::Set(acc, set_sha256) => {
                    kernel_in_place::Certified::Set { acc, set_sha256 }
                }
                set_path::Proof::Dual { set_sha256, values } => {
                    kernel_in_place::Certified::Dual { set_sha256, values }
                }
            };
            let receipt =
                kernel_in_place::record_receipt(&mut *tx, &before, delta, certified).await?;
            if matches!(proof, set_path::Proof::Dual { .. }) {
                timings.note_receipt_ordinal(receipt.ordinal);
            }
            timings.lap("apply_receipt");
            Some(receipt)
        }
    };
    Ok(CertifiedFold { facts, receipt })
}

/// [`apply`], calling `before_commit` after every check has passed and
/// immediately before the commit. A refusal from the hook rolls the whole
/// transaction back exactly as a failed check does.
pub(crate) async fn apply_with_hook(
    db: &crate::Db,
    trusted: &TrustedKernelDelta,
    timings: &PhaseTimings,
    mode: ApplyMode,
    before_commit: &(dyn Fn() -> Result<()> + Send + Sync),
) -> Result<()> {
    // Thin wrapper over the transaction-owned seams: the fold and its
    // certification run on this transaction, which commits here. Behaviour,
    // errors, timings laps and receipts are unchanged.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    timings.lap("apply_begin_write");
    let folded = fold_in_transaction(&mut tx, trusted, timings, mode).await?;
    let _certified = certify_fold_in_transaction(&mut tx, trusted, folded, timings).await?;
    before_commit()?;
    tx.commit().await?;
    timings.lap("apply_commit");
    Ok(())
}

/// Everything between validation and the projection proof: ingest the
/// sections, check the added blobs, the act and sequence continuity, advance
/// the act counter, replay the projection tail and check the postcondition.
async fn fold(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    delta: &KernelDelta,
    before: &KernelGeneration,
    added_blobs: Vec<String>,
    timings: &PhaseTimings,
    admission: &CoordinateAdmission<'_>,
) -> Result<()> {
    for section in &delta.sections {
        crate::interchange::ingest_section_rows(
            tx,
            section,
            if ["kernel_blobs", "content_event_causal_frontier"].contains(&section.name.as_str()) {
                ConflictMode::ImmutableAllowIdentical
            } else {
                ConflictMode::ActLogRefuseExisting
            },
        )
        .await?;
    }
    timings.lap("apply_ingest");
    // The admitted base already verified its existing immutable bytes. Check
    // only rows actually inserted by this delta, one at a time.
    for digest in added_blobs {
        let (bytes, size): (Vec<u8>, i64) =
            sqlx::query_as("SELECT bytes,size_bytes FROM kernel_blobs WHERE sha256=?")
                .bind(&digest)
                .fetch_one(&mut **tx)
                .await?;
        if size != bytes.len() as i64 || crate::standby_snapshot::sha256_bytes(&bytes) != digest {
            return Err(Error::engine("kernel-v2 delta blob checksum mismatch"));
        }
    }
    timings.lap("apply_blob_verify");
    // Validate contiguous whole acts and exact sequence tails before replay.
    let (acts,lo,hi): (i64,Option<i64>,Option<i64>) = sqlx::query_as("SELECT COUNT(DISTINCT act),MIN(act),MAX(act) FROM (SELECT act FROM content_events WHERE act>? UNION ALL SELECT act FROM meta_events WHERE act>?)")
        .bind(before.head_act).bind(before.head_act).fetch_one(&mut **tx).await?;
    if acts != delta.head.head_act - before.head_act
        || (acts > 0 && (lo != Some(before.head_act + 1) || hi != Some(delta.head.head_act)))
    {
        return Err(Error::engine("kernel-v2 delta has an act gap"));
    }
    for (table, old, new) in [
        (
            "content_events",
            before.content_event_seq,
            delta.head.content_event_seq,
        ),
        (
            "meta_events",
            before.meta_event_seq,
            delta.head.meta_event_seq,
        ),
    ] {
        let (count, min, max): (i64, Option<i64>, Option<i64>) = sqlx::query_as(&format!(
            "SELECT COUNT(*),MIN(seq),MAX(seq) FROM {table} WHERE seq>?"
        ))
        .bind(old)
        .fetch_one(&mut **tx)
        .await?;
        if new < old
            || count != new - old
            || (count > 0 && (min != Some(old + 1) || max != Some(new)))
        {
            return Err(Error::engine("kernel-v2 delta has a sequence gap"));
        }
    }
    timings.lap("apply_gap_checks");
    sqlx::query("UPDATE act_state SET next_act=? WHERE singleton=1")
        .bind(delta.head.head_act)
        .execute(&mut **tx)
        .await?;
    if acts > 0 {
        match admission {
            CoordinateAdmission::Accepted(_) => {
                crate::kernel::replay_projection_tail_on(
                    tx,
                    before.content_event_seq,
                    before.meta_event_seq,
                )
                .await?;
            }
            #[cfg(feature = "v2-kernel-probe")]
            CoordinateAdmission::Working(_, _) => {
                crate::kernel::replay_projection_tail_on_registered_copy(
                    tx,
                    before.content_event_seq,
                    before.meta_event_seq,
                    ProjectionShape::from_coordinates(before)?,
                )
                .await?;
            }
        }
    }
    timings.lap("apply_replay_projection");
    if admission.coordinates(tx).await? != delta.head.generation {
        return Err(Error::engine("kernel-v2 delta postcondition mismatch"));
    }
    timings.lap("apply_postcondition");
    Ok(())
}
