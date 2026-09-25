//! Unified all-domain exact-act materialisation and head finalisation into a
//! destination already materialised at the delta's lower bound.
//!
//! Slices R3.1 and R4 of cb551d7. This is the all-domain counterpart of the
//! test-only R2 content materialiser: it consumes a **trusted**
//! [`TrustedAuthorityActDelta`] (a nominal wrapper over the P0
//! [`ValidatedAuthorityActDelta`]) whose act sections span any supported
//! canonical domain, applies it to a destination already materialised at
//! `F1`, and on success advances that destination's head to `F2` — atomically,
//! in one deferred-foreign-key write transaction.
//!
//! # Trust boundary and companion completeness
//!
//! The P0 `content_sha256` is **unsigned**: it detects accidental edits, not
//! authorship, and any producer can recompute it. A [`ValidatedAuthorityActDelta`]
//! is therefore only a structurally valid claim about an authority. In
//! particular the unsigned bytes cannot prove that the immutable-companion
//! closure is *complete* — a producer can omit a `relationship_federation_events`
//! row and no local derivation can distinguish that omission from an authority
//! that genuinely had no row, because relationship routing provenance is not a
//! function of the bytes.
//!
//! That guarantee is supplied by the nominal [`TrustedAuthorityActDelta`] type
//! (see its semantic contract). Its production mint is
//! [`TrustedAuthorityActDelta::from_authenticated_transport`], which accepts
//! only the sealed witness built by `standby::delta_transport` after the exact
//! bytes were received over the authenticated hosted transport and validated
//! end to end. The explicit test-only `assume_trusted_for_test` constructor is
//! `#[cfg(test)]`; there is no `authenticated` boolean, raw principal,
//! `From`/`Deref`, or public constructor.
//! `apply_authority_act_delta_and_finalize_head` accepts only the trusted type,
//! so **companion membership is the sole routing fact** and the core never
//! infers routing from the issuer or from endpoint reference origins. The mint
//! re-checks the carried origin and bounds, and the exact authenticated bytes
//! flow unchanged into this apply, which finalises the head in the same
//! transaction.
//!
//! The route is deliberately exact rather than replay-from-scratch:
//!
//! 1. A pure preflight (before any transaction) re-pins the two authority
//!    lanes, refuses a delta whose act range carries a database identity
//!    mint/rekey (a whole-snapshot fallback, never an incremental bindings
//!    fold), and decodes the relationship act section and its federation
//!    companion into the typed preserved-act replay inputs. Conformance of
//!    those inputs is a wire-shape check only; transport authenticity remains
//!    load-bearing and outside this core.
//! 2. One write transaction opens with `PRAGMA defer_foreign_keys = ON`. The
//!    destination [`AuthorityActHeadV2`] is read in that same snapshot and
//!    every replicated coordinate is compared: `head_act` must be exactly
//!    `F1`, the pins (contract/version, origin, interchange revision,
//!    portability policy, act cutovers, content causal cutover, binding seeds,
//!    webhook pins) must equal the carried head, and every local log maximum
//!    must not exceed the carried target. Every act section is additionally
//!    checked to be the contiguous prefix the carried rows extend, from the
//!    local per-log maximum and the carried section's own identities rather
//!    than `head_act` alone, so an overlap or a gap is refused before the
//!    first mutation. The advisory `source_engine_schema` and the
//!    database-local `authorization_revision` are never compared.
//! 3. Every act section and companion (including `relationship_events`) is
//!    pinned to the live destination schema before the first mutation.
//! 4. Every act section except `relationship_events` and every companion is
//!    exact-ingested with R1's per-class conflict modes. Relationship rows are
//!    never generically preinserted: they are folded through the one
//!    preserved-act replay seam so assertions, endpoint activity, federation
//!    companions and receiver-local admissions are initialised together.
//! 5. The derived domains fold in a settled order: binding audit first (safe
//!    under the deferred foreign keys; the reachable same-act
//!    content-create-then-binding-add is admitted), then content, then policy
//!    with a bounded nearest-anchor refresh for each distinct affected record,
//!    then meta/control/derivation, then awareness and notification candidates,
//!    then the carried relationship rows, then bounded validity/admission
//!    refreshes. `awareness_command_intents` and `external_observations` are
//!    ingest-only.
//! 6. Before commit, every act section is re-exported for `(F1, F2]` and
//!    compared exactly against the carried section (format, revision, name,
//!    columns, primary key, rows and cell storage classes) and every companion
//!    is re-derived through the one shared closure SQL and compared exactly.
//!    Any failure rolls the whole transaction back.
//! 7. R4 head finalisation, in the same transaction and after every
//!    section/companion postcondition: one compare-and-set `UPDATE` writes
//!    **only** `act_state.next_act` from `F1` to `F2` (singleton `= 1` and
//!    expected `F1`; exactly one row or the whole apply refuses). The replicated
//!    head is then re-probed and required to equal every coordinate the delta
//!    carried, now at `head_act = F2`, through the shared coordinate comparison
//!    helper. A disagreement after the write rolls back the logs, companions,
//!    projections **and** `act_state` together. No other head coordinate is
//!    written: per-log maxima and non-sequenced watermarks are derived from the
//!    ingested logs, while storage policy, cutovers, binding seeds, webhook
//!    pins, the advisory engine schema and any generation state are never
//!    written by finalisation. The database-local `authorization_revision` is
//!    not a finalisation coordinate either: it is a derived epoch that the
//!    materialisation's own projection and policy/binding writes advance
//!    through the engine triggers, and it is never replicated or finalised as a
//!    head coordinate.
//!
//! # Bounds of the proof
//!
//! As in R2, the re-derivation proves that the carried sections are the exact
//! reachable closure of the materialised rows and that the destination state
//! is internally consistent with the carried target. It cannot prove per-act
//! row completeness, the absence of optional authority rows the destination
//! never had a reason to read, or companion-closure completeness; those are
//! guaranteed by the [`TrustedAuthorityActDelta`] contract and the transport,
//! so authenticity stays load-bearing.
//! It also cannot fold a database identity mint or rekey: that changes the
//! origin every `native-record` identifier is encoded against, so the delta is
//! refused with an explicit whole-snapshot fallback rather than silently
//! rebuilding identifiers against a retired origin.
//!
//! Two deliberate fail-closed refusals are documented here rather than papered
//! over:
//!
//! * **Relationship `seq` is coupled to SQLite `AUTOINCREMENT`.** The carried
//!   `relationship_events` rows are replayed through the preserved-act seam,
//!   which lets the destination assign `seq` rather than inserting it. The
//!   in-transaction postcondition export compares the destination's
//!   `relationship_events` section byte-for-byte with the carried one, so a
//!   destination whose relationship sequence state diverges (a deleted row, a
//!   rolled-back AUTOINCREMENT, a manually reseeded sequence) fails the
//!   postcondition and the whole transaction rolls back. That is a refusal, not
//!   a silent mis-materialisation.
//! * **Act-less pin drift is a plain refusal, not a typed fallback.** The
//!   storage portability policy (and the other non-act head pins) can change
//!   under a compare-and-set revision with no act allocation. A destination
//!   whose pin disagrees with the carried head refuses with an explicit pin
//!   error. It is deliberately **not** classified as
//!   [`ActMaterialiseRefusal::WholeSnapshotRequired`]: the recovery may well be
//!   a whole snapshot, but conflating a pin revision with a database identity
//!   change would make the typed classification lie. It is left as a low,
//!   explicit refusal with the error naming the disagreeing pin.

#![allow(dead_code)] // R3.1/R4 core; the controller/transport wiring lands later.

use std::collections::{BTreeMap, BTreeSet};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::interchange::{
    export_act_range_section, ingest_section_rows, validate_destination_section,
    validate_section_shape, Cell, ConflictMode, Section,
};
use crate::standby::act_delta::{AuthorityActDeltaHeadV1, ValidatedAuthorityActDelta};
use crate::standby::authority_probe::{read_authority_act_head_on, AuthorityActHeadV2};
use crate::standby::companion_closure;
use crate::standby::receiver::require_authority_lanes;

/// The act-stamped relationship log whose rows are domain-folded through the
/// preserved-act replay seam instead of the generic ingest primitive.
const RELATIONSHIP_TABLE: &str = "relationship_events";
/// The non-sequenced act log whose rows only refresh receiver-local validity
/// state after the generic ingest; it has no projection of its own.
const VALIDITY_TABLE: &str = "provenance_attestation_validity_events";
/// The identity-change ledger. A non-empty carried section is a whole-snapshot
/// fallback, never an incremental apply.
const IDENTITY_AUDIT_TABLE: &str = "database_identity_audit";

/// A compact report of one all-domain materialisation. `from_exclusive_act` is
/// `F1` and `to_inclusive_act` is `F2`; `no_op` is an empty interval, in which
/// case nothing was written and every count is zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActMaterialiseOutcome {
    pub(crate) no_op: bool,
    pub(crate) from_exclusive_act: i64,
    pub(crate) to_inclusive_act: i64,
    pub(crate) inserted_rows: usize,
    pub(crate) identical_rows: usize,
    pub(crate) folded_events: usize,
}

/// A local, typed refusal classification for the incremental path. It is
/// deliberately small: R4 can pattern-match it to route to a whole-snapshot
/// install, and no refresh/status API is widened for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActMaterialiseRefusal {
    /// A database identity mint or rekey landed in the delta interval. The
    /// incremental bindings-only fold would rebuild `native-record`
    /// identifiers against a retired origin, so the caller must take a whole
    /// snapshot instead.
    WholeSnapshotRequired,
}

impl ActMaterialiseRefusal {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::WholeSnapshotRequired => {
                "database identity change in act range requires whole-snapshot fallback"
            }
        }
    }

    pub(crate) fn into_error(self) -> Error {
        Error::engine(self.message())
    }

    /// Recognise this classification from the engine error text it produces.
    /// The message is a closed local literal, so this is a local projection of
    /// [`Self::into_error`], not a second error taxonomy.
    pub(crate) fn classify(error: &Error) -> Option<Self> {
        (error.to_string() == Self::WholeSnapshotRequired.message())
            .then_some(Self::WholeSnapshotRequired)
    }
}

/// The pure preflight result: the typed relationship replay inputs and the
/// distinct carried attestation ids whose receiver-local admissions must be
/// refreshed after the fold.
struct MaterialisePlan {
    relationship_events: Vec<crate::relationship::RelationshipReplayEvent>,
    federated_identities: BTreeSet<(String, String)>,
    validity_attestation_ids: Vec<String>,
    validity_event_count: usize,
}

/// A validated authority act delta whose exact bytes, origin and act bounds the
/// caller asserts were authenticated from the pinned authority's exact-cut
/// endpoint.
///
/// # Semantic contract (load-bearing; deliberately not enforceable here)
///
/// [`ValidatedAuthorityActDelta`] proves only *structural* integrity: the
/// closed document parses, its digest matches, the lanes are the canonical
/// act/companion inventory, and the acts cover `(F1, F2]`. The P0
/// `content_sha256` is **unsigned** — any producer can recompute it after an
/// edit — so a `ValidatedAuthorityActDelta` on its own is an untrusted claim
/// about an authority, never proof. In particular the unsigned bytes cannot
/// prove the companion closure is *complete*: a producer can omit a
/// `relationship_federation_events` row, and no local derivation can tell that
/// omission from an authority that genuinely had no such row, because
/// relationship routing provenance is not a function of the unsigned bytes.
///
/// This nominal type is the boundary at which that guarantee is supplied **by
/// construction**. A holder asserts that
///
/// * `validated` is the exact immutable bytes received from the pinned
///   authority exact-cut endpoint and authenticated end to end;
/// * the authority origin and the `(F1, F2]` bounds carried here were read from
///   that same authenticated observation and match the inner carried
///   head/bounds (checked at mint time);
/// * the companion closure in those bytes is the authority's own complete
///   closure from the same source snapshot.
///
/// Companion membership is therefore the **sole** routing fact for the
/// relationship fold; the materialiser never infers routing from the issuer or
/// from endpoint reference origins.
///
/// Trust is minted in exactly one production place,
/// [`TrustedAuthorityActDelta::from_authenticated_transport`], which accepts
/// only the sealed witness built by the authenticated hosted transport
/// (`crate::standby::delta_transport`) from the exact received bytes. The
/// witness type's fields are private to that module and it has no constructor,
/// no `Deserialize` and no `Clone`, so no other production path can mint trust
/// from raw [`ValidatedAuthorityActDelta`] bytes; the mint re-checks the
/// carried origin and bounds before wrapping. The separately named
/// [`TrustedAuthorityActDelta::assume_trusted_for_test`] is test-only
/// (`#[cfg(test)]`).
pub(crate) struct TrustedAuthorityActDelta {
    validated: ValidatedAuthorityActDelta,
    authority_origin: String,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
}

impl TrustedAuthorityActDelta {
    /// The one place trust is actually wrapped. It re-checks the asserted
    /// origin and act bounds against the inner carried head and cut before
    /// constructing the wrapper, so a witness can never carry a coordinate set
    /// that disagrees with its bytes.
    fn mint_checked(
        validated: ValidatedAuthorityActDelta,
        authority_origin: &str,
        from_exclusive_act: i64,
        to_inclusive_act: i64,
    ) -> Result<Self> {
        require(
            validated.authority_head().origin_database_id() == authority_origin,
            "trusted delta authenticated origin disagrees with the carried authority head",
        )?;
        require(
            validated.act_cut().from_exclusive_act() == from_exclusive_act,
            "trusted delta authenticated lower bound disagrees with the carried cut",
        )?;
        require(
            validated.act_cut().to_inclusive_act() == to_inclusive_act,
            "trusted delta authenticated upper bound disagrees with the carried cut",
        )?;
        Ok(Self {
            validated,
            authority_origin: authority_origin.to_string(),
            from_exclusive_act,
            to_inclusive_act,
        })
    }

    /// Test-only trust mint. It asserts the authenticated origin and act
    /// bounds match the inner carried head and cut, then wraps the value. The
    /// production mint ([`Self::from_authenticated_transport`]) accepts only
    /// the sealed transport witness; production code cannot name this type's
    /// fields or construct it from raw bytes.
    #[cfg(test)]
    pub(crate) fn assume_trusted_for_test(
        validated: ValidatedAuthorityActDelta,
        authority_origin: &str,
        from_exclusive_act: i64,
        to_inclusive_act: i64,
    ) -> Result<Self> {
        Self::mint_checked(
            validated,
            authority_origin,
            from_exclusive_act,
            to_inclusive_act,
        )
    }

    /// The production trust mint. It accepts only the sealed witness built by
    /// [`crate::standby::delta_transport`] after the exact bytes were received
    /// over the authenticated hosted transport and validated end to end.
    ///
    /// The witness type's fields are private to `delta_transport`, so no other
    /// production module can build one; this is the only production path that
    /// can reach [`Self::mint_checked`] from raw validated bytes. The carried
    /// origin and bounds are re-checked here rather than trusted from the
    /// witness.
    pub(crate) fn from_authenticated_transport(
        witness: crate::standby::delta_transport::AuthenticatedAuthorityActDelta,
    ) -> Result<Self> {
        let (validated, authority_origin, from_exclusive_act, to_inclusive_act) =
            witness.into_parts();
        Self::mint_checked(
            validated,
            &authority_origin,
            from_exclusive_act,
            to_inclusive_act,
        )
    }

    /// The carried authority head evidence. Immutable borrow only; the wrapper
    /// exposes no way to substitute the underlying bytes.
    pub(crate) fn authority_head(&self) -> &AuthorityActDeltaHeadV1 {
        self.validated.authority_head()
    }

    /// The carried whole-act cut. Immutable borrow only.
    pub(crate) fn act_cut(&self) -> &crate::standby::act_cut::AuthorityActCut {
        self.validated.act_cut()
    }

    /// The authority origin authenticated by the transport.
    pub(crate) fn authority_origin(&self) -> &str {
        &self.authority_origin
    }

    /// The exact canonical delta bytes this trusted value was minted from. The
    /// wrapper exposes no way to substitute them; this is a read-only
    /// reserialization of the validated document, proven byte-identical to the
    /// received bytes at validation time.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validated.canonical_bytes()
    }

    /// The exclusive lower bound (`F1`) authenticated by the transport.
    #[allow(clippy::wrong_self_convention)] // mirrors AuthorityActCut::from_exclusive_act
    pub(crate) fn from_exclusive_act(&self) -> i64 {
        self.from_exclusive_act
    }

    /// The inclusive upper bound (`F2`) authenticated by the transport.
    pub(crate) fn to_inclusive_act(&self) -> i64 {
        self.to_inclusive_act
    }

    fn validated(&self) -> &ValidatedAuthorityActDelta {
        &self.validated
    }
}

/// Apply a trusted all-domain exact-act delta to a destination already
/// materialised at the delta's lower bound (`F1`), finalising the destination
/// head to the delta's upper bound (`F2`) on success.
///
/// This accepts only [`TrustedAuthorityActDelta`]: the companion closure's
/// completeness is a transport guarantee (see its semantic contract), not
/// something derivable from the unsigned P0 bytes. Preflight is pure and runs
/// before any transaction. Validation, ingest, folding, postconditions, head
/// finalisation and the final carried-head re-check all run in one
/// deferred-foreign-key write transaction, so any failure — including one
/// induced after the head write — leaves logs, companions, projections and
/// `act_state` unchanged. On success the destination log and projections
/// include the delta and `act_state` has advanced from `F1` to `F2`. Only the
/// singleton act counter is written by finalisation: R4 deliberately does not
/// write cutovers, storage policy, binding seeds, webhook pins, the advisory
/// engine schema, or any generation state. The database-local
/// `authorization_revision` is not written by finalisation either; it is a
/// derived epoch that the materialisation's own projection/policy/binding
/// writes advance through the engine triggers, and it is never a replicated or
/// finalised head coordinate. An empty interval (`F1 == F2`) remains a checked
/// zero-mutation no-op.
pub(crate) async fn apply_authority_act_delta_and_finalize_head(
    db: &Db,
    delta: &TrustedAuthorityActDelta,
) -> Result<ActMaterialiseOutcome> {
    let plan = preflight(delta.validated())?;

    let mut tx = db.write_pool().begin().await?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await?;

    let outcome = run_materialisation(&mut tx, delta, &plan).await;
    match outcome {
        Ok(outcome) if outcome.no_op => {
            // An empty interval is a true zero-mutation no-op. The destination
            // head was still read and checked above, but nothing was written.
            let _ = tx.rollback().await;
            Ok(outcome)
        }
        Ok(outcome) => {
            tx.commit().await?;
            Ok(outcome)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Pure structural preflight on the validated delta, before any transaction.
///
/// It re-pins the two lanes at the unified entry point, refuses a delta that
/// carries a database identity change, and decodes the carried relationship
/// act section and its federation companion through the wire-boundary
/// decoders. Failure is a refusal with nothing written; the destination is not
/// even read.
fn preflight(delta: &ValidatedAuthorityActDelta) -> Result<MaterialisePlan> {
    let cut = delta.act_cut();
    let act_names = cut
        .sections()
        .iter()
        .map(|section| section.name.as_str())
        .collect::<Vec<_>>();
    let companion_names = cut
        .companions()
        .iter()
        .map(|section| section.name.as_str())
        .collect::<Vec<_>>();
    require_authority_lanes(&act_names, &companion_names)?;

    // A database identity mint or rekey in the interval cannot be folded
    // incrementally. Refuse before the destination is even read.
    let identity_audit = cut
        .section(IDENTITY_AUDIT_TABLE)
        .ok_or_else(|| Error::engine("authority act delta is missing database_identity_audit"))?;
    if !identity_audit.rows.is_empty() {
        return Err(ActMaterialiseRefusal::WholeSnapshotRequired.into_error());
    }

    let relationship_section = cut
        .section(RELATIONSHIP_TABLE)
        .ok_or_else(|| Error::engine("authority act delta is missing relationship_events"))?;
    let relationship_events =
        crate::relationship::relationship_replay_events_from_section(relationship_section)?;
    let federation_section = cut
        .companion("relationship_federation_events")
        .ok_or_else(|| Error::engine("authority act delta is missing its federation companion"))?;
    let federated_identities =
        crate::relationship::relationship_federation_identities_from_section(
            federation_section,
            &relationship_events,
        )?;

    let validity_section = cut
        .section(VALIDITY_TABLE)
        .ok_or_else(|| Error::engine("authority act delta is missing its validity section"))?;
    let validity_event_count = validity_section.rows.len();
    let validity_attestation_ids = carried_validity_attestation_ids(validity_section)?;

    Ok(MaterialisePlan {
        relationship_events,
        federated_identities,
        validity_attestation_ids,
        validity_event_count,
    })
}

/// The distinct attestation ids a carried `provenance_attestation_validity_events`
/// section names. These are the attestations whose receiver-local admission
/// state depends on the replayed validity log.
fn carried_validity_attestation_ids(section: &Section) -> Result<Vec<String>> {
    let index = section
        .columns
        .iter()
        .position(|column| column.name == "attestation_id")
        .ok_or_else(|| {
            Error::engine("provenance_attestation_validity_events has no attestation_id column")
        })?;
    let mut ids = BTreeSet::new();
    for row in &section.rows {
        match row.get(index) {
            Some(Cell::Text(id)) => {
                ids.insert(id.clone());
            }
            _ => {
                return Err(Error::engine(
                    "provenance_attestation_validity_events attestation_id is not text",
                ))
            }
        }
    }
    Ok(ids.into_iter().collect())
}

/// Require every carried `provenance_attestation_validity_events` row to
/// continue its attestation's ordinal sequence contiguously from the
/// destination's current `MAX(ordinal)`, before ingest and therefore before any
/// mutation.
///
/// The section is ordered by its `id` primary key, not by ordinal, so this
/// groups by attestation and requires each group's ordinals to be exactly
/// `local_max + 1, local_max + 2, ...`. A gap, a duplicate ordinal (which the
/// `UNIQUE (attestation_id, ordinal)` constraint would refuse at insert anyway)
/// or a backwards step refuses here with a named error. Every addition is
/// overflow-checked.
async fn require_validity_ordinal_continuation(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    section: &Section,
) -> Result<()> {
    let attestation_index = section
        .columns
        .iter()
        .position(|column| column.name == "attestation_id")
        .ok_or_else(|| Error::engine("validity section has no attestation_id column"))?;
    let ordinal_index = section
        .columns
        .iter()
        .position(|column| column.name == "ordinal")
        .ok_or_else(|| Error::engine("validity section has no ordinal column"))?;

    let mut per_attestation = BTreeMap::<String, Vec<i64>>::new();
    for row in &section.rows {
        let attestation_id = match row.get(attestation_index) {
            Some(Cell::Text(value)) => value.clone(),
            _ => {
                return Err(Error::engine(
                    "carried validity row attestation_id is not text",
                ))
            }
        };
        let ordinal = match row.get(ordinal_index) {
            Some(Cell::Integer(value)) => *value,
            _ => {
                return Err(Error::engine(
                    "carried validity row ordinal is not an integer",
                ))
            }
        };
        per_attestation
            .entry(attestation_id)
            .or_default()
            .push(ordinal);
    }

    for (attestation_id, mut ordinals) in per_attestation {
        ordinals.sort_unstable();
        let local_max: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(ordinal) FROM provenance_attestation_validity_events WHERE attestation_id = ?",
        )
        .bind(&attestation_id)
        .fetch_one(&mut **tx)
        .await?;
        let mut expected = match local_max {
            Some(value) => value
                .checked_add(1)
                .ok_or_else(|| Error::engine("validity ordinal overflows"))?,
            None => 0,
        };
        for ordinal in ordinals {
            require(
                ordinal == expected,
                "carried validity ordinals do not continue contiguously from the destination sequence",
            )?;
            expected = ordinal
                .checked_add(1)
                .ok_or_else(|| Error::engine("validity ordinal overflows"))?;
        }
    }
    Ok(())
}

async fn run_materialisation(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    delta: &TrustedAuthorityActDelta,
    plan: &MaterialisePlan,
) -> Result<ActMaterialiseOutcome> {
    let cut = delta.act_cut();
    let carried_head = delta.authority_head();
    let from_exclusive_act = cut.from_exclusive_act();
    let to_inclusive_act = cut.to_inclusive_act();
    let mut outcome = ActMaterialiseOutcome {
        from_exclusive_act,
        to_inclusive_act,
        ..ActMaterialiseOutcome::default()
    };

    // The destination head is read in this same transaction/snapshot, so the
    // prefix checks and the later ingest cannot observe different states.
    let local_head = read_authority_act_head_on(&mut *tx).await?;
    require_replicated_pins_equal(carried_head, &local_head)?;
    require(
        local_head.head_act == from_exclusive_act,
        "act materialisation destination head act is not the delta's lower bound",
    )?;

    if from_exclusive_act == to_inclusive_act {
        // An empty interval is a true no-op, but the destination must already
        // be the exact carried target: every carried lane and companion is
        // empty (guaranteed by the closed validator) and every local
        // replicated coordinate equals the carried head.
        require_empty_interval(cut)?;
        require_local_maxima_equal_carried(carried_head, &local_head)?;
        require(
            local_head.head_act == carried_head.head_act(),
            "act materialisation empty interval destination head is not the carried head",
        )?;
        outcome.no_op = true;
        return Ok(outcome);
    }

    // Destination-schema pin every act and companion before the first
    // mutation, including relationship_events: a tampered column list or
    // primary key anywhere refuses with nothing written.
    for section in cut.sections().iter().chain(cut.companions()) {
        validate_section_shape(section)?;
        validate_destination_section(tx, section).await?;
    }

    // Local-prefix check per act section: the destination log must be the
    // contiguous prefix the carried rows extend, or the destination is not the
    // `F1` the authority cut from. Overlap is also refused by the act-log
    // conflict mode below; a gap is refused here, before any mutation.
    require_section_prefixes(carried_head, &local_head, cut)?;

    // The carried validity ordinals must continue each attestation's
    // destination sequence contiguously. This is checked before the first
    // mutation so a gap, duplicate or backwards step refuses with nothing
    // written.
    let validity_section = cut
        .section(VALIDITY_TABLE)
        .ok_or_else(|| Error::engine("authority act delta is missing its validity section"))?;
    require_validity_ordinal_continuation(tx, validity_section).await?;

    // Exact ingest with R1's per-class conflict modes. Relationship rows are
    // deliberately excluded: the preserved-act replay seam below is the only
    // writer of that domain.
    let (inserted_rows, identical_rows) = ingest_except_relationship(tx, cut).await?;
    outcome.inserted_rows = inserted_rows;
    outcome.identical_rows = identical_rows;

    fold_binding_audit(tx, from_exclusive_act, to_inclusive_act, &mut outcome).await?;
    fold_content(tx, from_exclusive_act, to_inclusive_act, &mut outcome).await?;
    fold_policy(tx, from_exclusive_act, to_inclusive_act, &mut outcome).await?;
    fold_meta_control_derivation(tx, from_exclusive_act, to_inclusive_act, &mut outcome).await?;
    fold_awareness_and_candidates(tx, from_exclusive_act, to_inclusive_act, &mut outcome).await?;
    fold_relationship(tx, plan, &mut outcome).await?;
    fold_validity_and_admissions(tx, plan, &mut outcome).await?;

    // In-transaction postconditions. Export every act section for the exact
    // range and require exact equality with the carried section, and re-derive
    // the whole companion closure and require exact equality. Only after these
    // hold is the head allowed to advance.
    require_exact_act_sections(tx, cut).await?;
    require_exact_companion_closure(tx, cut).await?;

    // R4 finalisation: exactly one write, the singleton act counter from `F1`
    // to `F2`, compare-and-set on the expected `F1`. Zero rows means a
    // concurrent or overlapping writer owns a different state and the whole
    // apply refuses rather than clobber it.
    finalize_act_state(tx, from_exclusive_act, to_inclusive_act).await?;

    // Re-probe the head after the write and require it to equal every
    // coordinate the delta carried, now at `head_act = F2`. The shared
    // coordinate helper deliberately omits the advisory `source_engine_schema`
    // (absent from the wire) and the database-local `authorization_revision`
    // (never replicated), so their absence is handled rather than guessed. A
    // disagreement here rolls back the logs, companions, projections and the
    // act counter together.
    let end_head = read_authority_act_head_on(&mut *tx).await?;
    require(
        end_head.head_act == to_inclusive_act,
        "act materialisation finalised head act is not the delta's upper bound",
    )?;
    require(
        carried_head.matches_authority_head(&end_head),
        "act materialisation finalised head disagrees with the carried replicated coordinates",
    )?;

    Ok(outcome)
}

/// The R4 finalisation write: advance `act_state.next_act` from `F1` to `F2`
/// with a compare-and-set on the singleton and the expected `F1`.
///
/// The update is a plain assignment of the validated carried upper bound, so
/// there is no arithmetic to overflow; the `F2 > F1` guard is fail-closed
/// against a non-advancing interval (the equal case is already a no-op before
/// this point). Requiring exactly one affected row refuses if the destination
/// is not the `F1` the delta was cut from, rather than silently overwriting a
/// concurrent writer's state. No other table or column is touched.
async fn finalize_act_state(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<()> {
    require(
        to_inclusive_act > from_exclusive_act,
        "act materialisation cannot finalise a non-advancing act interval",
    )?;
    let result =
        sqlx::query("UPDATE act_state SET next_act = ?2 WHERE singleton = 1 AND next_act = ?1")
            .bind(from_exclusive_act)
            .bind(to_inclusive_act)
            .execute(&mut **tx)
            .await?;
    require(
        result.rows_affected() == 1,
        "act materialisation act_state finalisation compare-and-set matched no row",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// Exact-ingest every act section except the relationship log, plus every
/// companion, with R1's conflict modes: act logs refuse any existing primary
/// key, companions admit an exactly identical retry and refuse divergence.
async fn ingest_except_relationship(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    cut: &crate::standby::act_cut::AuthorityActCut,
) -> Result<(usize, usize)> {
    let mut inserted_rows = 0usize;
    let mut identical_rows = 0usize;
    for section in cut.sections() {
        if section.name == RELATIONSHIP_TABLE {
            continue;
        }
        let outcome = ingest_section_rows(tx, section, ConflictMode::ActLogRefuseExisting).await?;
        inserted_rows += outcome.inserted;
        identical_rows += outcome.identical;
    }
    for section in cut.companions() {
        let outcome =
            ingest_section_rows(tx, section, ConflictMode::ImmutableAllowIdentical).await?;
        inserted_rows += outcome.inserted;
        identical_rows += outcome.identical;
    }
    Ok((inserted_rows, identical_rows))
}

// ---------------------------------------------------------------------------
// Folds
// ---------------------------------------------------------------------------

/// Fold the binding ledger into the live `bindings` index first. This runs
/// before content so a same-act binding add that references a record created
/// by an in-window content event is admitted under the deferred foreign keys;
/// the content fold below then creates the record before commit.
async fn fold_binding_audit(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    let events = crate::identity::binding_audit::binding_audit_in_act_range(
        &mut *tx,
        from_exclusive_act,
        to_inclusive_act,
    )
    .await?;
    crate::identity::binding_audit::replay_bindings(&mut *tx, &events).await?;
    outcome.folded_events += events.len();
    Ok(())
}

/// Fold the content log through the one projector, in `seq` order. `project`
/// never appends a log row and never allocates an act.
async fn fold_content(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    let events =
        crate::query::events::events_in_act_range(&mut *tx, from_exclusive_act, to_inclusive_act)
            .await?;
    for event in &events {
        crate::projector::project(&mut *tx, event)
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "act materialisation content projector failed for event {} (seq {}): {error}",
                    event.id, event.local_seq
                ))
            })?;
    }
    outcome.folded_events += events.len();
    Ok(())
}

/// Fold the policy log, then refresh the derived nearest-anchor index for each
/// distinct affected record. The refresh is bounded to the changed records'
/// subtrees; it never walks the whole record tree.
async fn fold_policy(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    let events =
        crate::policy::policy_events_in_act_range(&mut *tx, from_exclusive_act, to_inclusive_act)
            .await?;
    let mut roots = BTreeSet::new();
    for event in &events {
        roots.insert(event.record_id.clone());
    }
    crate::policy::replay_policy(&mut *tx, &events).await?;
    for root in roots {
        crate::authorization::refresh_policy_anchor_subtree(&mut *tx, &root).await?;
    }
    outcome.folded_events += events.len();
    Ok(())
}

/// Fold the independent meta, control and derivation logs through their own
/// per-event projectors in `seq` order.
async fn fold_meta_control_derivation(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    let meta =
        crate::meta::meta_events_in_act_range(&mut *tx, from_exclusive_act, to_inclusive_act)
            .await?;
    for event in &meta {
        crate::projector::meta::project_meta(&mut *tx, event).await?;
    }
    let control =
        crate::control::control_events_in_act_range(&mut *tx, from_exclusive_act, to_inclusive_act)
            .await?;
    for event in &control {
        crate::control::project_control(&mut *tx, event).await?;
    }
    let derivation = crate::derivation::derivation_events_in_act_range(
        &mut *tx,
        from_exclusive_act,
        to_inclusive_act,
    )
    .await?;
    for event in &derivation {
        crate::derivation::project_event(&mut *tx, event).await?;
    }
    outcome.folded_events += meta.len() + control.len() + derivation.len();
    Ok(())
}

/// Fold the awareness log, then the notification candidate log it fans into.
/// The candidate fold is a separate per-event fold because the candidate log is
/// its own authoritative source; a rebuild must never re-emit candidates.
async fn fold_awareness_and_candidates(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    let awareness = crate::awareness::awareness_events_in_act_range(
        &mut *tx,
        from_exclusive_act,
        to_inclusive_act,
    )
    .await?;
    for event in &awareness {
        crate::awareness::project_awareness_event(&mut *tx, event).await?;
    }
    let candidates = crate::awareness::notification_candidate_events_in_act_range(
        &mut *tx,
        from_exclusive_act,
        to_inclusive_act,
    )
    .await?;
    for event in &candidates {
        crate::awareness::project_notification_candidate_event(&mut *tx, event).await?;
    }
    outcome.folded_events += awareness.len() + candidates.len();
    Ok(())
}

/// Fold the carried relationship rows through the one preserved-act replay
/// seam (allocating no act), then re-derive receiver-local admission state for
/// exactly the replayed events. This is bounded to the replayed rows; it never
/// scans or recomputes the whole relationship log.
async fn fold_relationship(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    plan: &MaterialisePlan,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    crate::relationship::replay_relationship_events(
        tx,
        &plan.relationship_events,
        &plan.federated_identities,
    )
    .await?;
    crate::relationship::initialize_receiver_local_state_for_replayed_events_in(
        tx,
        &plan.relationship_events,
    )
    .await?;
    outcome.folded_events += plan.relationship_events.len();
    Ok(())
}

/// Refresh receiver-local admissions for each distinct carried attestation id.
/// The validity rows themselves were exact-ingested above; this is the bounded
/// derived-state fold the live validity writer performs after its insert.
async fn fold_validity_and_admissions(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    plan: &MaterialisePlan,
    outcome: &mut ActMaterialiseOutcome,
) -> Result<()> {
    for attestation_id in &plan.validity_attestation_ids {
        crate::relationship::refresh_receiver_local_admissions_for_attestation_in(
            tx,
            attestation_id,
        )
        .await?;
    }
    outcome.folded_events += plan.validity_event_count;
    Ok(())
}

// ---------------------------------------------------------------------------
// Head comparison and prefix checks
// ---------------------------------------------------------------------------

/// The replicated coordinates shared by the wire evidence and a locally
/// observed head, excluding `head_act` (which the destination holds at `F1`
/// until finalisation) and the advisory engine schema. `authorization_revision`
/// is database-local and never appears in either value.
fn require_replicated_pins_equal(
    carried: &AuthorityActDeltaHeadV1,
    local: &AuthorityActHeadV2,
) -> Result<()> {
    require(
        local.contract == carried.contract() && local.version == carried.version(),
        "act materialisation destination head contract disagrees with the carried head",
    )?;
    require(
        local.origin_database_id == carried.origin_database_id(),
        "act materialisation destination origin disagrees with the carried head",
    )?;
    require(
        local.native_interchange_revision == carried.native_interchange_revision(),
        "act materialisation destination interchange revision disagrees with the carried head",
    )?;
    require(
        local.storage_portability_policy.as_ref() == carried.storage_portability_policy(),
        "act materialisation destination portability policy disagrees with the carried head",
    )?;
    require(
        local.act_cutovers.as_slice() == carried.act_cutovers(),
        "act materialisation destination act cutovers disagree with the carried head",
    )?;
    require(
        &local.content_causal_cutover == carried.content_causal_cutover(),
        "act materialisation destination content causal cutover disagrees with the carried head",
    )?;
    require(
        local.binding_systems.as_slice() == carried.binding_systems(),
        "act materialisation destination binding seeds disagree with the carried head",
    )?;
    require(
        local.webhook_endpoint_count == carried.webhook_endpoint_count()
            && local.webhook_credential_count == carried.webhook_credential_count(),
        "act materialisation destination webhook pins disagree with the carried head",
    )
}

/// The destination's maxima must not exceed the carried target: it may lag
/// (the delta extends it) but it may never be ahead of the authority it is
/// materialising from. Tables are compared by name in their shared order.
fn require_local_maxima_within_carried(
    carried: &AuthorityActDeltaHeadV1,
    local: &AuthorityActHeadV2,
) -> Result<()> {
    require(
        local.per_log_max_seq.len() == carried.per_log_max_seq().len(),
        "act materialisation destination per-log diagnostics are incomplete",
    )?;
    for (local_row, carried_row) in local.per_log_max_seq.iter().zip(carried.per_log_max_seq()) {
        require(
            local_row.table == carried_row.table,
            "act materialisation destination per-log diagnostics are out of order",
        )?;
        require(
            local_row.max_seq <= carried_row.max_seq,
            "act materialisation destination log is ahead of the carried target",
        )?;
    }
    require(
        local.non_sequenced_max_acts.len() == carried.non_sequenced_max_acts().len(),
        "act materialisation destination non-sequenced watermarks are incomplete",
    )?;
    for (local_row, carried_row) in local
        .non_sequenced_max_acts
        .iter()
        .zip(carried.non_sequenced_max_acts())
    {
        require(
            local_row.table == carried_row.table,
            "act materialisation destination non-sequenced watermarks are out of order",
        )?;
        require(
            local_row.max_act <= carried_row.max_act,
            "act materialisation destination non-sequenced log is ahead of the carried target",
        )?;
    }
    Ok(())
}

/// The destination's maxima must equal the carried target exactly. This is the
/// postcondition form; the advisory engine schema and the database-local
/// `authorization_revision` are not part of it.
fn require_local_maxima_equal_carried(
    carried: &AuthorityActDeltaHeadV1,
    local: &AuthorityActHeadV2,
) -> Result<()> {
    require(
        local.per_log_max_seq.len() == carried.per_log_max_seq().len(),
        "act materialisation destination per-log diagnostics are incomplete",
    )?;
    for (local_row, carried_row) in local.per_log_max_seq.iter().zip(carried.per_log_max_seq()) {
        require(
            local_row.table == carried_row.table,
            "act materialisation destination per-log diagnostics are out of order",
        )?;
        require(
            local_row.max_seq == carried_row.max_seq,
            "act materialisation destination log maximum disagrees with the carried target",
        )?;
    }
    require(
        local.non_sequenced_max_acts.len() == carried.non_sequenced_max_acts().len(),
        "act materialisation destination non-sequenced watermarks are incomplete",
    )?;
    for (local_row, carried_row) in local
        .non_sequenced_max_acts
        .iter()
        .zip(carried.non_sequenced_max_acts())
    {
        require(
            local_row.table == carried_row.table,
            "act materialisation destination non-sequenced watermarks are out of order",
        )?;
        require(
            local_row.max_act == carried_row.max_act,
            "act materialisation destination non-sequenced watermark disagrees with the carried target",
        )?;
    }
    Ok(())
}

/// Every carried lane and companion is empty. The closed delta validator already
/// enforces this on an empty interval; this re-asserts it at the entry point so
/// a future validator change cannot quietly turn the no-op into a mutation.
fn require_empty_interval(cut: &crate::standby::act_cut::AuthorityActCut) -> Result<()> {
    for section in cut.sections().iter().chain(cut.companions()) {
        require(
            section.rows.is_empty(),
            "act materialisation empty interval carries rows",
        )?;
    }
    Ok(())
}

/// Reject an overlap or a gap using the local per-log maximum and the carried
/// section's own identities, not `head_act` alone.
///
/// For a sequenced log the carried section's smallest primary key must be
/// exactly one past the local maximum (a gap refuses) and its largest must be
/// the carried target maximum. An empty carried section is only coherent when
/// the local maximum already equals the target, otherwise the delta silently
/// omits rows the target claims. For a non-sequenced act log the carried rows
/// are act-stamped in `(F1, F2]`; an empty section must already be at the
/// carried watermark and a non-empty one must reach it exactly.
fn require_section_prefixes(
    carried: &AuthorityActDeltaHeadV1,
    local: &AuthorityActHeadV2,
    cut: &crate::standby::act_cut::AuthorityActCut,
) -> Result<()> {
    require_local_maxima_within_carried(carried, local)?;

    for table in crate::act::CANONICAL_EVENT_TABLES {
        let section = cut
            .section(table)
            .ok_or_else(|| Error::engine(format!("authority act delta is missing {table}")))?;
        let local_row = per_log_row(&local.per_log_max_seq, table)?;
        let carried_row = per_log_row(carried.per_log_max_seq(), table)?;
        if section.rows.is_empty() {
            require(
                local_row.max_seq == carried_row.max_seq,
                "act materialisation carries no rows for a sequenced log that must advance",
            )?;
            continue;
        }
        let seq_index = section
            .columns
            .iter()
            .position(|column| column.name == "seq")
            .ok_or_else(|| {
                Error::engine(format!(
                    "act materialisation section '{table}' has no seq column"
                ))
            })?;
        let mut expected = local_row
            .max_seq
            .checked_add(1)
            .ok_or_else(|| Error::engine("act materialisation destination sequence overflows"))?;
        let mut reached: Option<i64> = None;
        for row in &section.rows {
            let seq = match row.get(seq_index) {
                Some(Cell::Integer(value)) => *value,
                _ => {
                    return Err(Error::engine(format!(
                        "act materialisation section '{table}' carries a non-integer seq"
                    )))
                }
            };
            // The section is ordered by its `seq` primary key, so this walks
            // the ordered cells and refuses any internal gap or repeat, not
            // just a min/max disagreement.
            require(
                seq == expected,
                "act materialisation sequenced section is not contiguous from the destination sequence",
            )?;
            reached = Some(seq);
            expected = seq
                .checked_add(1)
                .ok_or_else(|| Error::engine("act materialisation sequenced section overflows"))?;
        }
        require(
            reached == Some(carried_row.max_seq),
            "act materialisation section does not reach the carried log maximum",
        )?;
    }

    for table in crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES {
        let section = cut
            .section(table)
            .ok_or_else(|| Error::engine(format!("authority act delta is missing {table}")))?;
        let local_row = non_sequenced_row(&local.non_sequenced_max_acts, table)?;
        let carried_row = non_sequenced_row(carried.non_sequenced_max_acts(), table)?;
        if section.rows.is_empty() {
            require(
                local_row.max_act == carried_row.max_act,
                "act materialisation carries no rows for a non-sequenced log that must advance",
            )?;
            continue;
        }
        let act_index = section
            .columns
            .iter()
            .position(|column| column.name == "act")
            .ok_or_else(|| {
                Error::engine(format!(
                    "act materialisation section '{table}' has no act column"
                ))
            })?;
        for row in &section.rows {
            let act = match row.get(act_index) {
                Some(Cell::Integer(value)) => *value,
                _ => {
                    return Err(Error::engine(format!(
                        "act materialisation section '{table}' carries a non-integer act"
                    )))
                }
            };
            require(
                act > local_row.max_act,
                "act materialisation non-sequenced row does not advance past the destination watermark",
            )?;
        }
        require(
            section_is_at_act(section, act_index, carried_row.max_act)?,
            "act materialisation section does not reach the carried non-sequenced watermark",
        )?;
    }
    Ok(())
}

fn per_log_row<'a>(
    rows: &'a [crate::standby::authority_probe::LogMaxSeqV1],
    table: &str,
) -> Result<&'a crate::standby::authority_probe::LogMaxSeqV1> {
    rows.iter()
        .find(|row| row.table == table)
        .ok_or_else(|| Error::engine(format!("head is missing its {table} per-log diagnostic")))
}

fn non_sequenced_row<'a>(
    rows: &'a [crate::standby::authority_probe::NonSequencedMaxActV1],
    table: &str,
) -> Result<&'a crate::standby::authority_probe::NonSequencedMaxActV1> {
    rows.iter().find(|row| row.table == table).ok_or_else(|| {
        Error::engine(format!(
            "head is missing its {table} non-sequenced watermark"
        ))
    })
}

fn section_is_at_act(section: &Section, act_index: usize, expected: i64) -> Result<bool> {
    for row in &section.rows {
        match row.get(act_index) {
            Some(Cell::Integer(value)) if *value == expected => return Ok(true),
            Some(Cell::Integer(_)) => {}
            _ => {
                return Err(Error::engine(format!(
                    "act materialisation section '{}' carries a non-integer act",
                    section.name
                )))
            }
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Postconditions
// ---------------------------------------------------------------------------

/// Export every act section for the exact range and require exact equality with
/// the carried section: format, revision, name, ordered columns, declared
/// primary key and ordered rows with exact cell storage classes.
async fn require_exact_act_sections(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    cut: &crate::standby::act_cut::AuthorityActCut,
) -> Result<()> {
    for (index, table) in crate::act::ACT_STAMPED_TABLES.iter().enumerate() {
        let derived = export_act_range_section(
            &mut *tx,
            table,
            cut.from_exclusive_act(),
            cut.to_inclusive_act(),
        )
        .await?;
        require_sections_equal(&derived, &cut.sections()[index], "act")?;
    }
    Ok(())
}

/// Re-derive every companion through the one shared closure SQL and require
/// exact equality with the carried companion closure.
async fn require_exact_companion_closure(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    cut: &crate::standby::act_cut::AuthorityActCut,
) -> Result<()> {
    let derived = companion_closure::read_companion_sections_on(
        &mut *tx,
        cut.from_exclusive_act(),
        cut.to_inclusive_act(),
    )
    .await?;
    require(
        derived.len() == cut.companions().len(),
        "act materialisation companion closure inventory diverges from the carried closure",
    )?;
    for (derived, carried) in derived.iter().zip(cut.companions()) {
        require_sections_equal(derived, carried, "companion")?;
    }
    Ok(())
}

/// Exact section equality. Every dimension is compared, so a re-derived section
/// that matches only by row count cannot pass.
fn require_sections_equal(derived: &Section, carried: &Section, lane: &str) -> Result<()> {
    require(
        derived.name == carried.name && derived.format == carried.format,
        &format!("re-derived {lane} identity diverges from the carried {lane}"),
    )?;
    require(
        derived.revision == carried.revision,
        &format!("re-derived {lane} revision diverges from the carried {lane}"),
    )?;
    require(
        derived.columns == carried.columns,
        &format!("re-derived {lane} columns diverge from the carried {lane}"),
    )?;
    require(
        derived.primary_key == carried.primary_key,
        &format!("re-derived {lane} primary key diverges from the carried {lane}"),
    )?;
    require(
        derived.rows == carried.rows,
        &format!("re-derived {lane} rows diverge from the carried {lane}"),
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::engine(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::path::Path;

    use serde_json::{Map, Value};

    use crate::events::EventRow;
    use crate::relationship::{
        core_relationship_type_manifest, prepare_relationship_with_assertion, AssertionCreatedV1,
        CreateRelationshipWithAssertion, EndpointSemantics, OriginAdmissionV1,
        RelationshipCoordinate, RelationshipCreatedV1, RelationshipEndpoint,
        RelationshipEventCoordinate,
    };
    use crate::standby::act_cut::read_authority_act_cut;
    use crate::standby::act_delta::{build_authority_act_delta, validate_authority_act_delta};
    use crate::standby::authority_probe::read_authority_act_head;

    const NOW: &str = "2026-08-12T12:34:56.123Z";
    const RECORD_A_ID: &str = "4e1a0000-0000-4000-8000-0000000000a1";
    const RECORD_B_ID: &str = "4e1a0000-0000-4000-8000-0000000000a2";
    const SEED_RECORD_ID: &str = "1a7e4000-0000-4000-8000-0000000000c1";

    async fn fresh_source() -> crate::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    async fn head_act(db: &crate::Db) -> i64 {
        read_authority_act_head(db).await.unwrap().head_act
    }

    async fn destination_at_current_head(source: &crate::Db, dir: &Path, name: &str) -> crate::Db {
        let bytes = crate::interchange::export_canonical_interchange(source)
            .await
            .unwrap();
        crate::interchange::import_canonical_interchange(&bytes, &dir.join(name))
            .await
            .unwrap()
    }

    fn value_of(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).unwrap()
    }

    async fn build_delta(source: &crate::Db, base: i64) -> (Vec<u8>, Value) {
        let head = head_act(source).await;
        let cut = read_authority_act_cut(source, base, head).await.unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        validate_authority_act_delta(&bytes).unwrap();
        let value = value_of(&bytes);
        (bytes, value)
    }

    /// Test-only trust mint, binding the authenticated coordinates to the inner
    /// carried head/bounds. Production has no trust constructor in this slice.
    fn trust(delta: ValidatedAuthorityActDelta) -> TrustedAuthorityActDelta {
        let origin = delta.authority_head().origin_database_id().to_string();
        let from = delta.act_cut().from_exclusive_act();
        let to = delta.act_cut().to_inclusive_act();
        TrustedAuthorityActDelta::assume_trusted_for_test(delta, &origin, from, to).unwrap()
    }

    /// The nominal gating: raw bytes validate into a `ValidatedAuthorityActDelta`
    /// (structural integrity only), and the only way to reach
    /// `apply_authority_act_delta_and_finalize_head` is through the trust mint,
    /// which refuses a
    /// mismatched authenticated origin or act bounds. Gating is enforced by the
    /// apply signature and the wrapper's private fields, not by a runtime flag.
    #[tokio::test]
    async fn trusted_wrapper_rejects_mismatched_authenticated_coordinates() {
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "trust seed").await;
        let f1 = head_act(&source).await;
        append_record(&source, RECORD_A_ID, "trust target").await;
        let (bytes, _) = build_delta(&source, f1).await;

        // Raw validation yields the structural type only.
        let validated = validate_authority_act_delta(&bytes).unwrap();
        let origin = validated.authority_head().origin_database_id().to_string();
        let from = validated.act_cut().from_exclusive_act();
        let to = validated.act_cut().to_inclusive_act();
        drop(validated);

        let mint = || validate_authority_act_delta(&bytes).unwrap();
        assert!(
            TrustedAuthorityActDelta::assume_trusted_for_test(
                mint(),
                "ndb_ffffffffffffffffffffffffffffffff",
                from,
                to,
            )
            .is_err(),
            "a mismatched authenticated origin must refuse"
        );
        assert!(
            TrustedAuthorityActDelta::assume_trusted_for_test(mint(), &origin, from + 1, to)
                .is_err(),
            "a mismatched authenticated lower bound must refuse"
        );
        assert!(
            TrustedAuthorityActDelta::assume_trusted_for_test(mint(), &origin, from, to + 1)
                .is_err(),
            "a mismatched authenticated upper bound must refuse"
        );
        TrustedAuthorityActDelta::assume_trusted_for_test(mint(), &origin, from, to).unwrap();
        source.close().await;
    }

    async fn count(db: &crate::Db, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn act_state(db: &crate::Db) -> i64 {
        sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn append_record(db: &crate::Db, record_id: &str, name: &str) -> EventRow {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                }),
                actor: None,
            },
        )
        .await
        .unwrap()
    }

    async fn content_identities(db: &crate::Db) -> Vec<(i64, String, Option<i64>)> {
        sqlx::query_as("SELECT seq, id, act FROM content_events ORDER BY seq")
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    async fn binding_rows(db: &crate::Db) -> Vec<(String, String, String, i64)> {
        sqlx::query_as(
            "SELECT record_id, system, identifier, is_canonical FROM bindings
              ORDER BY record_id, system, identifier",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    async fn relationship_event_rows(db: &crate::Db) -> Vec<(i64, String, Option<i64>)> {
        sqlx::query_as("SELECT seq, id, act FROM relationship_events ORDER BY seq")
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    async fn relationship_rows(db: &crate::Db) -> Vec<(String, String, i64, String)> {
        sqlx::query_as(
            "SELECT relationship_origin_db_id, relationship_id, stream_version, status
               FROM relationships ORDER BY relationship_origin_db_id, relationship_id",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    async fn policy_entry_rows(db: &crate::Db) -> Vec<(String, String, String, String, String)> {
        sqlx::query_as(
            "SELECT policy_anchor_id, subject_kind, subject_id, effect, capability
               FROM policy_entries ORDER BY policy_anchor_id, subject_kind, subject_id, capability",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    fn principal(id: &str) -> crate::identity::BindingClaim {
        crate::identity::BindingClaim {
            system: "native-principal".into(),
            identifier: format!("native/{id}"),
        }
    }

    fn mutation_context<'a>(
        actor: &'a str,
        reason: &'a str,
    ) -> crate::identity::MutationContext<'a> {
        crate::identity::MutationContext {
            actor,
            reason,
            run_key: Some("test-agent-abc123"),
            parent_key: None,
            intent: Some("exercise the unified materialiser"),
            is_member: true,
            internal: false,
            source_read_authorized: false,
        }
    }

    /// A production-shaped relationship genesis under `origin`, mirroring the
    /// relationship kernel's own fixture so the carried relationship section is
    /// genuinely reachable through the wire decoder.
    fn relationship_command(origin: &str) -> CreateRelationshipWithAssertion {
        let a_ref = crate::identity::encode_native_record(origin, RECORD_A_ID).unwrap();
        let b_ref = crate::identity::encode_native_record(origin, RECORD_B_ID).unwrap();
        let endpoints = vec![
            RelationshipEndpoint {
                role: "participant".into(),
                portable_ref: a_ref.clone(),
                record_type: Some("Document".into()),
                record_kind: Some("note".into()),
                record_id: None,
            },
            RelationshipEndpoint {
                role: "participant".into(),
                portable_ref: b_ref,
                record_type: Some("Document".into()),
                record_kind: Some("note".into()),
                record_id: None,
            },
        ];
        let definition = core_relationship_type_manifest()
            .unwrap()
            .relationship_types
            .into_iter()
            .find(|definition| definition.id == "relates_to.v1")
            .unwrap();
        let key = definition
            .canonical_proposition_key(
                &endpoints
                    .iter()
                    .map(RelationshipEndpoint::proposition_endpoint)
                    .collect::<Vec<_>>(),
                &BTreeMap::new(),
            )
            .unwrap();
        let relationship_created = RelationshipCreatedV1 {
            schema_version: 1,
            relationship_revision: 1,
            relationship_type: "relates_to".into(),
            type_definition_id: "relates_to.v1".into(),
            endpoint_semantics: EndpointSemantics::Symmetric,
            endpoints,
            identity_qualifiers: Map::new(),
            canonical_proposition_key: key,
            reducer_id: "default".into(),
            reducer_version: 1,
            legacy_link: None,
        };
        let assertion_created = AssertionCreatedV1 {
            schema_version: 1,
            relationship: RelationshipCoordinate {
                relationship_origin_db_id: origin.into(),
                relationship_id: uuid::Uuid::new_v4().to_string(),
                relationship_revision: 1,
            },
            relationship_created_event: RelationshipEventCoordinate {
                issuer_origin_db_id: origin.into(),
                event_id: uuid::Uuid::new_v4().to_string(),
            },
            stance: "support".into(),
            semantic_claimant: "native-principal:local".into(),
            on_behalf_of: Some("semantic-subject:test".into()),
            rationale: Some("test support".into()),
            valid_from: None,
            valid_until: None,
            causal_parents: Vec::new(),
            origin_admission: OriginAdmissionV1::test_fixture(
                "relates_to.v1",
                "anchor_authorised_support",
                "participant",
                &a_ref,
                "edit_either_anchor_view_both.v1",
                &"a".repeat(64),
                "action-attestation-test",
            ),
            authoring_action_attestation_id: "action-attestation-test".into(),
        };
        prepare_relationship_with_assertion(
            origin,
            "native-principal:local",
            NOW,
            NOW,
            relationship_created,
            assertion_created,
        )
        .unwrap()
    }

    /// Emit one act that spans content+binding (`resolve_external` writes the
    /// stub record and its native-principal binding in one transaction) and one
    /// act that spans relationship+policy (the relationship genesis and a policy
    /// replacement share one act allocation). Returns `(F1, F2)`.
    async fn emit_two_multidomain_acts(source: &crate::Db) -> (i64, i64) {
        let f1 = head_act(source).await;

        let actor = crate::identity::resolve_stdio_account_identity(source, None)
            .await
            .unwrap();
        let ctx = mutation_context(&actor, "unified materialiser content+binding act");
        let stub = crate::identity::resolve_external(
            source,
            &ctx,
            &[principal("r31")],
            &crate::identity::StubHints::default(),
        )
        .await
        .unwrap();
        assert!(stub.created, "the stub record and binding are authored");
        // The content create and its binding add share one act even though the
        // stub path may first stamp an identity-only observation act.
        let shared: i64 = sqlx::query_scalar(
            "SELECT act FROM content_events WHERE record_id = ? AND type = 'record.created'",
        )
        .bind(&stub.record_id)
        .fetch_one(source.pool())
        .await
        .unwrap();
        let binding_act: i64 = sqlx::query_scalar(
            "SELECT act FROM binding_audit WHERE new_record_id = ? AND action = 'add'",
        )
        .bind(&stub.record_id)
        .fetch_one(source.pool())
        .await
        .unwrap();
        assert_eq!(shared, binding_act, "content and binding share one act");
        let after_binding = head_act(source).await;
        assert!(
            after_binding > f1,
            "the content+binding act advances the head"
        );

        let origin = crate::identity::database_id(source).await.unwrap();
        let command = relationship_command(&origin);
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::relationship::create_relationship_with_assertion_in(&mut tx, &command, &mut alloc)
            .await
            .unwrap();
        crate::authorization::replace_explicit_policy_on_with_reason(
            &mut tx,
            &actor,
            crate::schema::ROOT_RECORD_ID,
            vec![crate::authorization::AllowEntry::members(
                crate::authorization::Capability::Edit,
            )],
            "unified materialiser relationship+policy act",
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let f2 = head_act(source).await;
        assert_eq!(f2, after_binding + 1, "relationship+policy is one act");
        (f1, f2)
    }

    /// The headline contract: a destination materialised at F1 via canonical
    /// interchange receives a two-act delta spanning content, binding,
    /// relationship and policy; every log, projection, act section and
    /// companion matches the source, conformance holds, and the head is
    /// finalised from F1 to F2.
    #[tokio::test]
    async fn unified_delta_applies_coverage_domains_exactly_and_keeps_a_conforming_destination() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "materialise seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        assert_eq!(act_state(&destination).await, f1);

        let (f1, f2) = emit_two_multidomain_acts(&source).await;

        let (bytes, value) = build_delta(&source, f1).await;
        // The delta really carries the intended domains.
        let section_names = |lane: &str| -> Vec<String> {
            value[lane]
                .as_array()
                .unwrap()
                .iter()
                .filter(|section| !section["rows"].as_array().unwrap().is_empty())
                .map(|section| section["name"].as_str().unwrap().to_string())
                .collect()
        };
        let acts = section_names("act_sections");
        assert!(acts.contains(&"content_events".to_string()), "{acts:?}");
        assert!(acts.contains(&"binding_audit".to_string()), "{acts:?}");
        assert!(
            acts.contains(&"relationship_events".to_string()),
            "{acts:?}"
        );
        assert!(acts.contains(&"policy_events".to_string()), "{acts:?}");

        let delta = validate_authority_act_delta(&bytes).unwrap();
        let carried_head = delta.authority_head().clone();
        let outcome = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();
        assert!(!outcome.no_op);
        assert_eq!(outcome.from_exclusive_act, f1);
        assert_eq!(outcome.to_inclusive_act, f2);
        assert!(outcome.inserted_rows > 0);

        assert_eq!(
            content_identities(&destination).await,
            content_identities(&source).await
        );
        assert_eq!(
            binding_rows(&destination).await,
            binding_rows(&source).await
        );
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationship_event_rows(&source).await
        );
        assert_eq!(
            relationship_rows(&destination).await,
            relationship_rows(&source).await
        );
        assert_eq!(
            policy_entry_rows(&destination).await,
            policy_entry_rows(&source).await
        );

        // R4 finalisation: act_state and the probed head act advance to F2 and
        // every replicated coordinate equals the carried head.
        assert_eq!(act_state(&destination).await, f2);
        assert_eq!(head_act(&destination).await, f2);
        let finalised = read_authority_act_head(&destination).await.unwrap();
        assert!(
            carried_head.matches_authority_head(&finalised),
            "the finalised destination head equals every carried replicated coordinate"
        );

        let check = crate::conformance::check_rebuild_and_diff(&destination).await;
        assert!(check.ok, "content conformance: {:?}", check.violations);
        let relationship =
            crate::conformance::check_rebuild_and_diff_relationship(&destination).await;
        assert!(
            relationship.ok,
            "relationship conformance: {:?}",
            relationship.violations
        );
        let policy = crate::conformance::check_rebuild_and_diff_policy(&destination).await;
        assert!(policy.ok, "policy conformance: {:?}", policy.violations);
        let meta = crate::conformance::check_rebuild_and_diff_meta(&destination).await;
        assert!(meta.ok, "meta conformance: {:?}", meta.violations);
        let control = crate::conformance::check_rebuild_and_diff_control(&destination).await;
        assert!(control.ok, "control conformance: {:?}", control.violations);
        let derivation = crate::conformance::check_rebuild_and_diff_derivation(&destination).await;
        assert!(
            derivation.ok,
            "derivation conformance: {:?}",
            derivation.violations
        );

        // A retry of the same delta fails closed: the destination head has
        // finalised to F2, so the delta's lower bound is no longer the local
        // head and the apply refuses before any mutation.
        let retry_delta = validate_authority_act_delta(&bytes).unwrap();
        let retry = apply_authority_act_delta_and_finalize_head(&destination, &trust(retry_delta))
            .await
            .unwrap_err();
        assert!(
            retry.to_string().contains("lower bound"),
            "retry refusal: {retry}"
        );

        destination.close().await;
        source.close().await;
    }

    /// Main's body-mention projection is a content fold carried by a normal
    /// act delta and verified with the rest of the materialised snapshot.
    #[tokio::test]
    async fn mention_bearing_content_delta_materialises_record_mentions() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "mention seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "mentions-f1.db").await;
        crate::store::append(
            &source,
            crate::store::AppendSpec {
                record_id: SEED_RECORD_ID.into(),
                event_type: "record.updated".into(),
                payload: serde_json::json!({"body": "See [[My Note]] and abc1234"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();
        let query =
            "SELECT source_id, occurrence_ix, source_event_seq, authored_reference, lookup_key
                     FROM record_mentions ORDER BY source_id, occurrence_ix";
        let expected = sqlx::query_as::<_, (String, i64, i64, String, String)>(query)
            .fetch_all(source.pool())
            .await
            .unwrap();
        assert!(!expected.is_empty());
        let actual = sqlx::query_as::<_, (String, i64, i64, String, String)>(query)
            .fetch_all(destination.pool())
            .await
            .unwrap();
        assert_eq!(actual, expected);
        let check = crate::conformance::check_rebuild_and_diff(&destination).await;
        assert!(check.ok, "content conformance: {:?}", check.violations);
        destination.close().await;
        source.close().await;
    }

    /// An empty interval is a genuine zero-mutation no-op, but it still reads
    /// and checks the destination replicated coordinates.
    #[tokio::test]
    async fn empty_interval_is_a_zero_mutation_noop() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "noop seed").await;
        let f = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;
        let bindings_before = binding_rows(&destination).await;
        let relationships_before = relationship_event_rows(&destination).await;
        let policies_before = policy_entry_rows(&destination).await;
        let head_before = read_authority_act_head(&destination).await.unwrap();

        let cut = read_authority_act_cut(&source, f, f).await.unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let outcome = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();
        assert!(outcome.no_op);
        assert_eq!(outcome.from_exclusive_act, f);
        assert_eq!(outcome.to_inclusive_act, f);
        assert_eq!(outcome.inserted_rows, 0);
        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(binding_rows(&destination).await, bindings_before);
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationships_before
        );
        assert_eq!(policy_entry_rows(&destination).await, policies_before);
        assert_eq!(act_state(&destination).await, f);
        assert_eq!(
            read_authority_act_head(&destination).await.unwrap(),
            head_before,
            "an empty interval must not change any head coordinate"
        );
        destination.close().await;
        source.close().await;
    }

    /// Overlap, origin drift and policy drift all refuse before any mutation and
    /// leave the destination untouched.
    #[tokio::test]
    async fn overlap_origin_and_policy_drift_refuse_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "drift seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;
        let records_before = count(&destination, "records").await;

        let (_, _) = emit_two_multidomain_acts(&source).await;
        let (bytes, _) = build_delta(&source, f1).await;

        // Overlap: a destination already at the carried head cannot accept the
        // delta because its head act is no longer F1.
        let advanced = destination_at_current_head(&source, dir.path(), "advanced.db").await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let overlap = apply_authority_act_delta_and_finalize_head(&advanced, &trust(delta))
            .await
            .unwrap_err();
        assert!(
            overlap.to_string().contains("lower bound"),
            "overlap refusal: {overlap}"
        );
        advanced.close().await;

        // Origin drift: rewrite the carried origin and recompute the digest.
        let mut origin = value_of(&bytes);
        origin["authority_head"]["origin_database_id"] =
            serde_json::json!("ndb_0123456789abcdef0123456789abcdef");
        resign(&mut origin);
        let origin_delta =
            validate_authority_act_delta(&serde_jcs::to_vec(&origin).unwrap()).unwrap();
        let origin_error =
            apply_authority_act_delta_and_finalize_head(&destination, &trust(origin_delta))
                .await
                .unwrap_err();
        assert!(
            origin_error.to_string().contains("origin"),
            "{origin_error}"
        );

        // Policy drift: a different but internally valid portability policy pin.
        let mut policy = value_of(&bytes);
        policy["authority_head"]["storage_portability_policy"] = serde_json::json!({
            "policy_revision": 1,
            "source_profile_id": "kite-local",
            "source_profile_revision": 1,
            "source_mode": "embedded",
        });
        resign(&mut policy);
        let policy_delta =
            validate_authority_act_delta(&serde_jcs::to_vec(&policy).unwrap()).unwrap();
        let policy_error =
            apply_authority_act_delta_and_finalize_head(&destination, &trust(policy_delta))
                .await
                .unwrap_err();
        assert!(
            policy_error.to_string().contains("portability policy"),
            "{policy_error}"
        );

        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(count(&destination, "records").await, records_before);
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// A database identity change in the interval is refused with the typed
    /// whole-snapshot fallback before the destination is read or mutated.
    #[tokio::test]
    async fn identity_change_in_range_is_a_typed_whole_snapshot_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "identity seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;

        append_record(&source, RECORD_A_ID, "identity target").await;
        let (bytes, value) = build_delta(&source, f1).await;

        // Fabricate a shape-valid database_identity_audit row in the interval.
        let mut tampered = value;
        let index = section_index(&tampered, "act_sections", IDENTITY_AUDIT_TABLE);
        let width = tampered["act_sections"][index]["columns"]
            .as_array()
            .unwrap()
            .len();
        let mut row = (0..width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        let act_column = column_index(&tampered, "act_sections", index, "act");
        row[act_column] = serde_json::json!({"type": "integer", "value": f1 + 1});
        tampered["act_sections"][index]["rows"] = serde_json::json!([row]);
        resign(&mut tampered);
        let delta = validate_authority_act_delta(&serde_jcs::to_vec(&tampered).unwrap()).unwrap();

        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap_err();
        assert_eq!(
            ActMaterialiseRefusal::classify(&error),
            Some(ActMaterialiseRefusal::WholeSnapshotRequired),
            "typed fallback: {error}"
        );
        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(act_state(&destination).await, f1);
        assert!(!bytes.is_empty());
        destination.close().await;
        source.close().await;
    }

    /// A structurally valid but semantically malformed event in a later domain
    /// reaches its projector, fails, and rolls back the earlier domains' logs,
    /// projections and companions.
    #[tokio::test]
    async fn malformed_later_domain_event_rolls_back_the_earlier_domains() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "rollback seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        let (_, _) = emit_two_multidomain_acts(&source).await;
        let (_bytes, value) = build_delta(&source, f1).await;

        let mut tampered = value;
        let index = section_index(&tampered, "act_sections", "policy_events");
        let type_index = column_index(&tampered, "act_sections", index, "type");
        tampered["act_sections"][index]["rows"][0][type_index] =
            serde_json::json!({"type": "text", "value": "policy.unknown.v1"});
        resign(&mut tampered);
        let delta = validate_authority_act_delta(&serde_jcs::to_vec(&tampered).unwrap()).unwrap();

        let content_before = content_identities(&destination).await;
        let bindings_before = binding_rows(&destination).await;
        let relationships_before = relationship_event_rows(&destination).await;
        let frontier_before = count(&destination, "content_event_causal_frontier").await;
        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("policy"),
            "policy refusal: {error}"
        );

        assert_eq!(content_identities(&destination).await, content_before);
        assert_eq!(binding_rows(&destination).await, bindings_before);
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationships_before
        );
        assert_eq!(
            count(&destination, "content_event_causal_frontier").await,
            frontier_before,
            "companions roll back with the earlier domains"
        );
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// A non-sequenced act-stamped log (`external_observations`) is ingest-only:
    /// the row is carried and written exactly, with no projection fold, and the
    /// destination head finalises to F2. A raw production-shaped fixture is used
    /// because the observation authors are out of scope here.
    #[tokio::test]
    async fn non_sequenced_external_observation_is_ingest_only() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "observation seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        // One act of its own: a stamped external observation.
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let act = alloc.get_or_allocate(&mut tx).await.unwrap();
        let observation_id = "obs-r31-non-sequenced";
        sqlx::query(
            "INSERT INTO external_observations
               (id, record_id, source_system, source_identifier, quality, as_of, observed_at,
                actor, reason, materialization_policy, freshness, retention_state,
                source_availability, refresh_outcome, act)
             VALUES (?1,?2,'native-principal','r31','reported','2026-01-01T00:00:00.000Z',
                     '2026-01-01T00:00:00.000Z','test:actor','non-sequenced ingest',
                     'identity_only','unknown','none','available','not_attempted',?3)",
        )
        .bind(observation_id)
        .bind(SEED_RECORD_ID)
        .bind(act)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let f2 = head_act(&source).await;
        assert_eq!(f2, f1 + 1);

        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let outcome = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();
        assert!(!outcome.no_op);

        let observed: String =
            sqlx::query_scalar("SELECT reason FROM external_observations WHERE id = ?")
                .bind(observation_id)
                .fetch_one(destination.pool())
                .await
                .unwrap();
        assert_eq!(observed, "non-sequenced ingest");
        assert_eq!(act_state(&destination).await, f2);
        assert_eq!(head_act(&destination).await, f2);
        destination.close().await;
        source.close().await;
    }

    /// The apply path is incremental: it never rebuilds unrelated projection
    /// state. A deliberately corrupted row the delta does not mention survives
    /// the apply, which a global rebuild would have repaired.
    #[tokio::test]
    async fn apply_does_not_globally_rebuild_unrelated_projection_state() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "incremental seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        // Corrupt an unrelated projected column on the destination.
        sqlx::query("UPDATE records SET name = 'corrupted' WHERE id = ?")
            .bind(SEED_RECORD_ID)
            .execute(destination.write_pool())
            .await
            .unwrap();

        let (_, _) = emit_two_multidomain_acts(&source).await;
        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();

        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(SEED_RECORD_ID)
            .fetch_one(destination.pool())
            .await
            .unwrap();
        assert_eq!(
            name, "corrupted",
            "an incremental apply must not repair unrelated projections"
        );
        destination.close().await;
        source.close().await;
    }

    // --- test-local helpers mirroring the R2 fixtures -----------------------

    fn resign(value: &mut Value) {
        use sha2::{Digest, Sha256};
        let mut payload = value.clone();
        payload.as_object_mut().unwrap().remove("content_sha256");
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap()));
        value["content_sha256"] = Value::String(digest);
    }

    // === R3.1 review follow-up: mutation-style coverage =====================

    const FOREIGN_ORIGIN: &str = "ndb_77777777777777777777777777777777";

    async fn log_rows(db: &crate::Db, table: &str) -> Vec<(i64, String, Option<i64>)> {
        sqlx::query_as(&format!("SELECT seq, id, act FROM {table} ORDER BY seq"))
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    /// `provenance_attestation_validity_events` has no `seq` column (its
    /// primary key is `id`), so it is read by id.
    async fn validity_rows(db: &crate::Db) -> Vec<(String, Option<i64>)> {
        sqlx::query_as("SELECT id, act FROM provenance_attestation_validity_events ORDER BY id")
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    /// A `relationship.created.v1` payload under `origin` whose endpoints carry
    /// that origin's own resolved record ids. A local projection preserves those
    /// ids; a federation-companioned projection resolves them against this
    /// authority's records and drops them when absent.
    fn relationship_created_for(origin: &str) -> (String, String) {
        let a_ref = crate::identity::encode_native_record(origin, RECORD_A_ID).unwrap();
        let b_ref = crate::identity::encode_native_record(origin, RECORD_B_ID).unwrap();
        let relationship_id = uuid::Uuid::new_v4().to_string();
        let endpoints = vec![
            RelationshipEndpoint {
                role: "participant".into(),
                portable_ref: a_ref,
                record_type: Some("Document".into()),
                record_kind: Some("note".into()),
                record_id: Some(RECORD_A_ID.into()),
            },
            RelationshipEndpoint {
                role: "participant".into(),
                portable_ref: b_ref,
                record_type: Some("Document".into()),
                record_kind: Some("note".into()),
                record_id: Some(RECORD_B_ID.into()),
            },
        ];
        let definition = core_relationship_type_manifest()
            .unwrap()
            .relationship_types
            .into_iter()
            .find(|definition| definition.id == "relates_to.v1")
            .unwrap();
        let canonical_proposition_key = definition
            .canonical_proposition_key(
                &endpoints
                    .iter()
                    .map(RelationshipEndpoint::proposition_endpoint)
                    .collect::<Vec<_>>(),
                &BTreeMap::new(),
            )
            .unwrap();
        let created = RelationshipCreatedV1 {
            schema_version: 1,
            relationship_revision: 1,
            relationship_type: "relates_to".into(),
            type_definition_id: "relates_to.v1".into(),
            endpoint_semantics: EndpointSemantics::Symmetric,
            endpoints,
            identity_qualifiers: Map::new(),
            canonical_proposition_key,
            reducer_id: "default".into(),
            reducer_version: 1,
            legacy_link: None,
        };
        let payload = String::from_utf8(crate::derivation::canonical_json(
            &serde_json::to_value(&created).unwrap(),
        ))
        .unwrap();
        (relationship_id, payload)
    }

    /// Insert a production-shaped relationship event and, when requested, its
    /// federation companion row in one act. The federation writer itself is
    /// only reachable through a verified envelope, which is out of scope for
    /// this fixture, so the rows mirror exactly what `append_imported_event_in`
    /// writes.
    async fn insert_relationship_event(
        source: &crate::Db,
        issuer_origin: &str,
        with_federation: bool,
    ) -> (String, String) {
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let act = alloc.get_or_allocate(&mut tx).await.unwrap();
        let (relationship_id, payload) = relationship_created_for(issuer_origin);
        let event_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO relationship_events
               (id,stream_kind,stream_id,stream_version,relationship_origin_db_id,relationship_id,
                type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act)
             VALUES (?1,'relationship',?2,1,?3,?2,'relationship.created.v1',?4,'relay',
                     ?3,'2026-01-02T00:00:00.000Z','2026-01-02T00:00:01.000Z',?5)",
        )
        .bind(&event_id)
        .bind(&relationship_id)
        .bind(issuer_origin)
        .bind(&payload)
        .bind(act)
        .execute(&mut *tx)
        .await
        .unwrap();
        if with_federation {
            sqlx::query(
                "INSERT INTO relationship_federation_events
                   (issuer_origin_db_id,event_id,fingerprint,source_batch_origin_db_id,envelope_id,
                    authenticated_peer_principal,origin_trust_state,origin_evidence_state,received_at)
                 VALUES (?1,?2,?3,?1,'env-r31','peer:r31','direct_origin','verified',
                         '2026-01-02T00:00:01.000Z')",
            )
            .bind(issuer_origin)
            .bind(&event_id)
            .bind("0".repeat(64))
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
        (event_id, relationship_id)
    }

    async fn insert_foreign_relationship_event(source: &crate::Db) -> (String, String) {
        insert_relationship_event(source, FOREIGN_ORIGIN, true).await
    }

    /// A minimal, shape-valid local action attestation so a carried validity log
    /// has a real FK target. The validity companion closure selects it by the
    /// in-window validity rows, exactly as the live closure does.
    async fn seed_attestation(source: &crate::Db, attestation_id: &str) {
        let origin = crate::identity::database_id(source).await.unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_attestations
               (id,schema_version,principal,executor_kind,channel,operation,action_commitment,
                action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES (?1,1,'test:principal','local','local','test.operation','{}',?2,?3,
                     'test:issuer',?4,'2026-01-02T00:00:00.000Z')",
        )
        .bind(attestation_id)
        .bind("0".repeat(64))
        .bind("0".repeat(64))
        .bind(&origin)
        .execute(source.write_pool())
        .await
        .unwrap();
    }

    /// Append `count` validity events for one attestation, alternating
    /// invalidate/restore, all sharing one act.
    async fn append_validity_events(source: &crate::Db, attestation_id: &str, count: usize) {
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        for index in 0..count {
            let change = if index % 2 == 0 {
                crate::provenance::ValidityChange::Invalidated
            } else {
                crate::provenance::ValidityChange::Restored
            };
            crate::provenance::append_validity_event_in(
                &mut tx,
                &mut alloc,
                attestation_id,
                change,
                "r31 validity reason",
                "test:issuer",
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    /// Finding 1: an internal gap in a sequenced section refuses before any
    /// mutation even though whole-act coverage is retained by another lane.
    #[tokio::test]
    async fn sequenced_section_internal_gap_refuses_with_zero_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "gap seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        // Act F1+1: two content events in one act. Act F1+2: a relationship
        // genesis, so coverage of F1+2 is not carried by the tampered lane.
        crate::store::append_batch(
            &source,
            vec![
                crate::store::AppendSpec {
                    record_id: SEED_RECORD_ID.into(),
                    event_type: "record.updated".into(),
                    payload: serde_json::json!({"summary": "gap one"}),
                    actor: None,
                },
                crate::store::AppendSpec {
                    record_id: SEED_RECORD_ID.into(),
                    event_type: "record.updated".into(),
                    payload: serde_json::json!({"summary": "gap two"}),
                    actor: None,
                },
            ],
        )
        .await
        .unwrap();
        let origin = crate::identity::database_id(&source).await.unwrap();
        crate::relationship::create_relationship_with_assertion(
            &source,
            &relationship_command(&origin),
        )
        .await
        .unwrap();

        let (_bytes, mut value) = build_delta(&source, f1).await;
        let content_index = section_index(&value, "act_sections", "content_events");
        let seq_index = column_index(&value, "act_sections", content_index, "seq");
        // local content max is f1-relative; read the two content seqs.
        let first_seq = value["act_sections"][content_index]["rows"][0][seq_index]["value"]
            .as_i64()
            .unwrap();
        value["act_sections"][content_index]["rows"][1][seq_index] =
            serde_json::json!({"type": "integer", "value": first_seq + 2});
        // Keep the carried head's content maximum consistent with the tamper so
        // the refusal is the internal gap, not a max/min disagreement.
        let head_logs = value["authority_head"]["per_log_max_seq"]
            .as_array()
            .unwrap()
            .iter()
            .position(|row| row["table"] == "content_events")
            .unwrap();
        value["authority_head"]["per_log_max_seq"][head_logs]["max_seq"] =
            serde_json::json!(first_seq + 2);
        resign(&mut value);
        let delta = validate_authority_act_delta(&serde_jcs::to_vec(&value).unwrap()).unwrap();

        let before = content_identities(&destination).await;
        let relationships = relationship_rows(&destination).await;
        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("contiguous"),
            "internal gap refusal: {error}"
        );
        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(relationship_rows(&destination).await, relationships);
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// Finding 2: a shape-valid carried withdrawal whose proposal is absent
    /// reaches the shared candidate projector, fails closed, and rolls back the
    /// whole transaction.
    #[tokio::test]
    async fn candidate_withdrawal_without_proposal_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "candidate seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::awareness::append_notification_candidate_in(
            &mut tx,
            "acct:r31",
            "message:r31",
            "routine_arrival",
            "routine",
            None,
            "metadata_only",
            "recipient_policy",
            "policy-r31",
            "record.updated",
            "src-r31",
            &mut alloc,
        )
        .await
        .unwrap();
        crate::awareness::withdraw_notification_candidates_in(
            &mut tx,
            "acct:r31",
            "message:r31",
            None,
            "awareness.preference.changed",
            "src-r31",
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let (_bytes, mut value) = build_delta(&source, f1).await;
        let index = section_index(&value, "act_sections", "notification_candidate_events");
        // Repoint the withdrawal at a candidate key with no proposal, keeping
        // the section's seqs contiguous and whole-act coverage intact. The
        // shared candidate projector must fail closed rather than no-op.
        let action_index = column_index(&value, "act_sections", index, "action");
        let key_index = column_index(&value, "act_sections", index, "candidate_key");
        let rows = value["act_sections"][index]["rows"].as_array().unwrap();
        let withdrawal = rows
            .iter()
            .find(|row| row[action_index]["value"] == "withdrawn")
            .cloned()
            .expect("the source log has a withdrawal");
        let mut withdrawal = withdrawal;
        withdrawal[key_index] = serde_json::json!({"type": "text", "value": "acct:r31:message:r31:routine_arrival:absent"});
        let proposal = rows
            .iter()
            .find(|row| row[action_index]["value"] == "proposed")
            .cloned()
            .expect("the source log has a proposal");
        value["act_sections"][index]["rows"] = serde_json::json!([proposal, withdrawal]);
        resign(&mut value);
        let delta = validate_authority_act_delta(&serde_jcs::to_vec(&value).unwrap()).unwrap();

        let candidates_before = count(&destination, "notification_candidates").await;
        let content_before = content_identities(&destination).await;
        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("exactly one existing proposal"),
            "candidate refusal: {error}"
        );
        assert_eq!(
            count(&destination, "notification_candidates").await,
            candidates_before
        );
        assert_eq!(content_identities(&destination).await, content_before);
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// Finding 3: the ordinal continuation is validated against a nonzero
    /// destination `MAX(ordinal)`. A valid continuation from that base applies
    /// exactly; a tampered gap from the same base refuses with zero mutation.
    #[tokio::test]
    async fn validity_ordinal_continuation_and_gap_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "validity seed").await;
        let f1 = head_act(&source).await;
        // Snapshot the destination at F1 before the attestation exists, so the
        // interchange conformance gate never sees a local-only fixture
        // attestation; the deltas then carry it as a companion.
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        seed_attestation(&source, "attestation-r31-valid").await;

        // First delta: ordinal 0, materialised receiver-locally.
        append_validity_events(&source, "attestation-r31-valid", 1).await;
        let fmid = head_act(&source).await;
        assert_eq!(fmid, f1 + 1);
        let (first_bytes, _) = build_delta(&source, f1).await;
        let first = validate_authority_act_delta(&first_bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(first))
            .await
            .unwrap();
        assert_eq!(
            validity_rows(&destination).await,
            validity_rows(&source).await
        );
        // The first apply finalised the destination head to fmid, which is
        // exactly the base the second delta is cut against.
        assert_eq!(act_state(&destination).await, fmid);

        // Second delta from the nonzero base: ordinals 1 and 2 continue.
        append_validity_events(&source, "attestation-r31-valid", 2).await;
        let f2 = head_act(&source).await;
        assert_eq!(f2, fmid + 1);
        let (second_bytes, _) = build_delta(&source, fmid).await;
        let second = validate_authority_act_delta(&second_bytes).unwrap();
        let second_outcome =
            apply_authority_act_delta_and_finalize_head(&destination, &trust(second))
                .await
                .unwrap();
        assert_eq!(
            second_outcome.folded_events, 2,
            "folded_events counts validity rows, not distinct attestations"
        );
        assert_eq!(
            validity_rows(&destination).await,
            validity_rows(&source).await
        );
        assert_eq!(
            log_rows(&destination, "content_events").await,
            log_rows(&source, "content_events").await
        );
        assert_eq!(act_state(&destination).await, f2);

        // Third delta from base ordinal 2, tampered to skip ordinal 4.
        append_validity_events(&source, "attestation-r31-valid", 3).await;
        let (_gap_bytes, mut value) = build_delta(&source, f2).await;
        let index = section_index(
            &value,
            "act_sections",
            "provenance_attestation_validity_events",
        );
        let ordinal_index = column_index(&value, "act_sections", index, "ordinal");
        let rows = value["act_sections"][index]["rows"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(rows.len(), 3);
        let kept = rows
            .iter()
            .filter(|row| row[ordinal_index]["value"] != serde_json::json!(4))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(kept.len(), 2);
        value["act_sections"][index]["rows"] = serde_json::json!(kept);
        resign(&mut value);
        let gap_delta = validate_authority_act_delta(&serde_jcs::to_vec(&value).unwrap()).unwrap();

        let before = validity_rows(&destination).await;
        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(gap_delta))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("contiguously"),
            "validity gap refusal: {error}"
        );
        assert_eq!(validity_rows(&destination).await, before);
        assert_eq!(act_state(&destination).await, f2);
        destination.close().await;
        source.close().await;
    }

    /// A production-shaped federated relationship delta routes through the
    /// receiver-resolved path (the foreign endpoints are dropped because the
    /// replica has no matching binding). Companion membership is the sole
    /// routing fact; the trusted wrapper supplies completeness.
    #[tokio::test]
    async fn federated_relationship_delta_applies_receiver_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "federation seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let (event_id, relationship_id) = insert_foreign_relationship_event(&source).await;
        assert_eq!(head_act(&source).await, f1 + 1);

        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationship_event_rows(&source).await
        );
        let endpoints: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT record_id FROM relationship_endpoints
              WHERE relationship_origin_db_id = ? ORDER BY ordinal",
        )
        .bind(FOREIGN_ORIGIN)
        .fetch_all(destination.pool())
        .await
        .unwrap();
        assert_eq!(endpoints, vec![None, None], "federated endpoints resolve");
        assert_eq!(act_state(&destination).await, f1 + 1);
        assert!(!event_id.is_empty() && !relationship_id.is_empty());
        destination.close().await;
        source.close().await;
    }

    /// A carried same-origin event with a legitimate federation companion is
    /// accepted: companion membership is permitted, not required, for a
    /// same-origin event. It is routed through the federated replay path, which
    /// resolves its origin-local endpoint ids against this authority's records.
    #[tokio::test]
    async fn same_origin_event_with_federation_companion_routes_federated() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "same-origin seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        let origin = crate::identity::database_id(&source).await.unwrap();
        // RECORD_A_ID is deliberately absent from the replica, so local routing
        // would preserve the carried id while federated routing resolves it to
        // None: the assertion below discriminates the two.
        let (event_id, relationship_id) = insert_relationship_event(&source, &origin, true).await;
        assert_eq!(head_act(&source).await, f1 + 1);

        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();

        let endpoints: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT record_id FROM relationship_endpoints
              WHERE relationship_origin_db_id = ? ORDER BY ordinal",
        )
        .bind(&origin)
        .fetch_all(destination.pool())
        .await
        .unwrap();
        assert_eq!(
            endpoints,
            vec![None, None],
            "a federated same-origin event resolves receiver-locally"
        );
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationship_event_rows(&source).await
        );
        let federation_on_destination: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM relationship_federation_events
              WHERE issuer_origin_db_id = ? AND event_id = ?",
        )
        .bind(&origin)
        .bind(&event_id)
        .fetch_one(destination.pool())
        .await
        .unwrap();
        assert_eq!(federation_on_destination, 1, "companion is carried");
        assert!(!relationship_id.is_empty());
        assert_eq!(act_state(&destination).await, f1 + 1);
        destination.close().await;
        source.close().await;
    }

    /// Finding 5: real writers for meta, awareness, notification candidates,
    /// derivation and control produce carried events that materialise exactly,
    /// with non-vacuous conformance for each domain.
    #[tokio::test]
    async fn real_writer_domains_materialise_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "domain seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        // meta
        crate::meta::create_vocabulary(&source, "r31_vocabulary", Some("r31-vocab-id"))
            .await
            .unwrap();
        // awareness (preference)
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::awareness::set_preference(
            &mut tx,
            "acct:r31",
            "message:r31",
            crate::awareness::PreferenceAction::Mute,
            None,
            0,
            "idem-pref-r31",
            "test",
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // candidates (proposed then withdrawn in one act)
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::awareness::append_notification_candidate_in(
            &mut tx,
            "acct:r31",
            "message:r31",
            "routine_arrival",
            "routine",
            None,
            "metadata_only",
            "recipient_policy",
            "policy-r31",
            "record.updated",
            "src-r31",
            &mut alloc,
        )
        .await
        .unwrap();
        crate::awareness::withdraw_notification_candidates_in(
            &mut tx,
            "acct:r31",
            "message:r31",
            None,
            "awareness.preference.changed",
            "src-r31",
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // derivation
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::derivation::append_derivation_event_in(
            &mut tx,
            crate::derivation::NewDerivationEvent::authored(
                "idem-derivation-r31",
                "test:actor",
                None,
                "r31 derivation",
                crate::derivation::DerivationEventPayload::SeriesCreated(
                    crate::derivation::DerivationSeriesCreated {
                        id: "series-r31".into(),
                        series_key: "r31-series".into(),
                        definition: serde_json::json!({"kind": "test"}),
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // control
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::control::append_control_event_in(
            &mut tx,
            crate::control::NewControlEvent::authored(
                "idem-control-r31",
                "activity-r31",
                "acct:r31",
                Some("scout-bread-abc123".into()),
                "r31 control",
                crate::control::ControlEventPayload::AgentRunStarted(
                    crate::control::AgentRunStartedPayload {
                        activity_id: "activity-r31".into(),
                        account_id: "acct:r31".into(),
                        started_at: "2026-01-02T00:00:00.000Z".into(),
                        reported_mcp_client_name: None,
                        reported_mcp_client_version: None,
                        reported_model: None,
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // awareness_command_intents (ingest-only non-sequenced act log)
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let attestation = crate::awareness::VerifiedHumanInteraction {
            nonce: "r31-intent-nonce".into(),
            executor_ref: "trusted-ui".into(),
        };
        crate::awareness::register_human_batch_command(
            &mut tx,
            "acct:r31",
            crate::awareness::HumanStage::Acknowledged,
            &[],
            &std::collections::BTreeMap::new(),
            "idem-intent-r31",
            None,
            &attestation,
            "reviewed",
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let f2 = head_act(&source).await;
        assert!(f2 > f1);

        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        // The delta actually carries each domain.
        let cut = delta.act_cut();
        for table in [
            "meta_events",
            "awareness_events",
            "notification_candidate_events",
            "derivation_events",
            "control_events",
            "awareness_command_intents",
        ] {
            assert!(
                !cut.section(table).unwrap().rows.is_empty(),
                "delta carries {table}"
            );
        }
        apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();

        for table in [
            "meta_events",
            "awareness_events",
            "notification_candidate_events",
            "derivation_events",
            "control_events",
        ] {
            assert_eq!(
                log_rows(&destination, table).await,
                log_rows(&source, table).await,
                "{table} log matches"
            );
        }
        // `awareness_command_intents` has a composite primary key and no `seq`,
        // and is intentionally ingest-only: the row is written with no
        // projection fold.
        assert_eq!(
            sqlx::query_as::<_, (String, String, Option<i64>)>(
                "SELECT subject_account_id, idempotency_key, act
                   FROM awareness_command_intents
                  ORDER BY subject_account_id, idempotency_key",
            )
            .fetch_all(destination.pool())
            .await
            .unwrap(),
            sqlx::query_as::<_, (String, String, Option<i64>)>(
                "SELECT subject_account_id, idempotency_key, act
                   FROM awareness_command_intents
                  ORDER BY subject_account_id, idempotency_key",
            )
            .fetch_all(source.pool())
            .await
            .unwrap()
        );
        // The awareness preference projection, not just its log.
        assert_eq!(
            sqlx::query_as::<_, (String, String, i64, i64, Option<String>, i64, i64)>(
                "SELECT subject_account_id, message_id, attention_flag, muted,
                        snoozed_until, archived, version
                   FROM message_preferences ORDER BY subject_account_id, message_id",
            )
            .fetch_all(destination.pool())
            .await
            .unwrap(),
            sqlx::query_as::<_, (String, String, i64, i64, Option<String>, i64, i64)>(
                "SELECT subject_account_id, message_id, attention_flag, muted,
                        snoozed_until, archived, version
                   FROM message_preferences ORDER BY subject_account_id, message_id",
            )
            .fetch_all(source.pool())
            .await
            .unwrap()
        );
        assert_eq!(
            sqlx::query_as::<_, (String, String)>(
                "SELECT candidate_key, status FROM notification_candidates ORDER BY candidate_key",
            )
            .fetch_all(destination.pool())
            .await
            .unwrap(),
            sqlx::query_as::<_, (String, String)>(
                "SELECT candidate_key, status FROM notification_candidates ORDER BY candidate_key",
            )
            .fetch_all(source.pool())
            .await
            .unwrap()
        );

        let meta = crate::conformance::check_rebuild_and_diff_meta(&destination).await;
        assert!(meta.ok, "meta conformance: {:?}", meta.violations);
        let control = crate::conformance::check_rebuild_and_diff_control(&destination).await;
        assert!(control.ok, "control conformance: {:?}", control.violations);
        let derivation = crate::conformance::check_rebuild_and_diff_derivation(&destination).await;
        assert!(
            derivation.ok,
            "derivation conformance: {:?}",
            derivation.violations
        );
        assert_eq!(act_state(&destination).await, f2);
        destination.close().await;
        source.close().await;
    }

    // === R4 finalisation coverage ===========================================

    /// R4 test 1: a successful trusted apply advances `act_state` to F2 and the
    /// full re-probed replicated head matches every coordinate the delta
    /// carried. This is the production apply, not a test-only stand-in.
    #[tokio::test]
    async fn finalization_advances_act_state_and_matches_carried_head() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "finalize seed").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        assert_eq!(act_state(&destination).await, f1);

        let (f1, f2) = emit_two_multidomain_acts(&source).await;
        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let carried = delta.authority_head().clone();

        let outcome = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();
        assert!(!outcome.no_op);
        assert_eq!(outcome.from_exclusive_act, f1);
        assert_eq!(outcome.to_inclusive_act, f2);
        assert_eq!(act_state(&destination).await, f2);

        let reprobed = read_authority_act_head(&destination).await.unwrap();
        assert_eq!(reprobed.head_act, f2, "the probed head act advances to F2");
        assert!(
            carried.matches_authority_head(&reprobed),
            "the finalised head equals every carried replicated coordinate"
        );
        destination.close().await;
        source.close().await;
    }

    /// R4 test 2: a failure induced strictly after the finalisation write rolls
    /// back the logs, projections, companions and `act_state` together. The
    /// induction is a test-only database trigger on `act_state` that perturbs a
    /// pinned head coordinate the moment the counter advances; there is no
    /// production seam or behaviour switch.
    #[tokio::test]
    async fn post_finalization_mismatch_rolls_back_every_write() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "rollback finalize seed").await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let (f1, _f2) = emit_two_multidomain_acts(&source).await;
        let (bytes, _) = build_delta(&source, f1).await;

        let content_before = content_identities(&destination).await;
        let bindings_before = binding_rows(&destination).await;
        let relationships_before = relationship_event_rows(&destination).await;
        let policies_before = policy_entry_rows(&destination).await;
        let companions_before = companion_row_counts(&destination).await;
        let head_before = read_authority_act_head(&destination).await.unwrap();

        // A test-only trigger perturbs the pinned content causal cutover exactly
        // when the act counter advances. The apply must notice the resulting
        // disagreement on its post-finalisation re-probe and roll back.
        sqlx::query(
            "CREATE TRIGGER r4_induce_finalization_mismatch
               AFTER UPDATE ON act_state
               WHEN NEW.next_act <> OLD.next_act
             BEGIN
               UPDATE content_event_causal_cutover
                  SET last_legacy_local_seq = last_legacy_local_seq + 1
                WHERE singleton = 1;
             END",
        )
        .execute(destination.write_pool())
        .await
        .unwrap();

        let delta = validate_authority_act_delta(&bytes).unwrap();
        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("finalised head disagrees"),
            "post-finalisation refusal: {error}"
        );

        assert_eq!(content_identities(&destination).await, content_before);
        assert_eq!(binding_rows(&destination).await, bindings_before);
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationships_before
        );
        assert_eq!(policy_entry_rows(&destination).await, policies_before);
        assert_eq!(
            companion_row_counts(&destination).await,
            companions_before,
            "companion row sets roll back with the logs, including the federation companion"
        );
        assert_eq!(act_state(&destination).await, f1);
        assert_eq!(
            read_authority_act_head(&destination).await.unwrap(),
            head_before,
            "the induced post-finalisation refusal restores every head coordinate"
        );
        destination.close().await;
        source.close().await;
    }

    /// R4 test 4: once a delta has finalised the destination, retrying the same
    /// bytes refuses at the lower-bound check with zero additional mutation.
    #[tokio::test]
    async fn retry_after_finalization_refuses_with_zero_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "retry seed").await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let (f1, f2) = emit_two_multidomain_acts(&source).await;
        let (bytes, _) = build_delta(&source, f1).await;

        let first = validate_authority_act_delta(&bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(first))
            .await
            .unwrap();
        assert_eq!(act_state(&destination).await, f2);
        let head_after_first = read_authority_act_head(&destination).await.unwrap();
        let content_after_first = content_identities(&destination).await;
        let bindings_after_first = binding_rows(&destination).await;
        let relationships_after_first = relationship_event_rows(&destination).await;

        let retry = validate_authority_act_delta(&bytes).unwrap();
        let error = apply_authority_act_delta_and_finalize_head(&destination, &trust(retry))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("lower bound"),
            "retry refusal: {error}"
        );

        assert_eq!(act_state(&destination).await, f2);
        assert_eq!(
            read_authority_act_head(&destination).await.unwrap(),
            head_after_first
        );
        assert_eq!(content_identities(&destination).await, content_after_first);
        assert_eq!(binding_rows(&destination).await, bindings_after_first);
        assert_eq!(
            relationship_event_rows(&destination).await,
            relationships_after_first
        );
        destination.close().await;
        source.close().await;
    }

    /// R4 test 5: finalisation writes only the act counter. Every pinned head
    /// coordinate — contract/version, origin, interchange revision, storage
    /// portability policy, act cutovers, the content causal cutover, binding
    /// seeds, the webhook pins and the advisory engine schema — is unchanged;
    /// the derived per-log and non-sequenced maxima advance only because the
    /// ingested logs did.
    #[tokio::test]
    async fn finalization_writes_no_pinned_coordinate() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "pinned seed").await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        let head_before = read_authority_act_head(&destination).await.unwrap();
        let act_cutover_before = act_cutover_snapshot(&destination).await;
        let causal_cutover_before = causal_cutover_snapshot(&destination).await;
        let policy_before = storage_policy_snapshot(&destination).await;
        let binding_systems_before = binding_system_snapshot(&destination).await;
        let endpoints_before = count(&destination, "webhook_endpoints").await;
        let credentials_before = count(&destination, "webhook_credentials").await;

        let (f1, f2) = emit_two_multidomain_acts(&source).await;
        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_authority_act_delta_and_finalize_head(&destination, &trust(delta))
            .await
            .unwrap();

        let head_after = read_authority_act_head(&destination).await.unwrap();
        assert_eq!(head_after.head_act, f2, "only the act counter advances");
        assert_eq!(head_after.contract, head_before.contract);
        assert_eq!(head_after.version, head_before.version);
        assert_eq!(
            head_after.origin_database_id,
            head_before.origin_database_id
        );
        assert_eq!(
            head_after.native_interchange_revision,
            head_before.native_interchange_revision
        );
        assert_eq!(
            head_after.source_engine_schema,
            head_before.source_engine_schema
        );
        assert_eq!(
            head_after.storage_portability_policy,
            head_before.storage_portability_policy
        );
        assert_eq!(head_after.act_cutovers, head_before.act_cutovers);
        assert_eq!(
            head_after.content_causal_cutover,
            head_before.content_causal_cutover
        );
        assert_eq!(head_after.binding_systems, head_before.binding_systems);
        assert_eq!(
            head_after.webhook_endpoint_count,
            head_before.webhook_endpoint_count
        );
        assert_eq!(
            head_after.webhook_credential_count,
            head_before.webhook_credential_count
        );

        assert_eq!(act_cutover_snapshot(&destination).await, act_cutover_before);
        assert_eq!(
            causal_cutover_snapshot(&destination).await,
            causal_cutover_before
        );
        assert_eq!(storage_policy_snapshot(&destination).await, policy_before);
        assert_eq!(
            binding_system_snapshot(&destination).await,
            binding_systems_before
        );
        assert_eq!(
            count(&destination, "webhook_endpoints").await,
            endpoints_before
        );
        assert_eq!(
            count(&destination, "webhook_credentials").await,
            credentials_before
        );
        destination.close().await;
        source.close().await;
    }

    /// R4 review follow-up: `finalize_act_state`'s compare-and-set refuses with
    /// zero rows when its expected lower bound is not the live `act_state`, and
    /// the counter is not moved. This is a direct unit exercise of the private
    /// helper inside a transaction that is then rolled back; it pins the CAS
    /// predicate and the fail-closed refusal, and claims nothing about a race.
    #[tokio::test]
    async fn finalize_act_state_zero_row_compare_and_set_refuses() {
        let source = fresh_source().await;
        append_record(&source, SEED_RECORD_ID, "cas seed").await;
        let live = act_state(&source).await;

        let mut tx = source.write_pool().begin().await.unwrap();
        // The guard admits the interval (`to > from`) but the expected lower
        // bound is not the live counter, so the singleton CAS matches no row.
        let error = finalize_act_state(&mut tx, live + 1, live + 2)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("compare-and-set matched no row"),
            "zero-row CAS refusal: {error}"
        );
        let unchanged: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(
            unchanged, live,
            "a refused compare-and-set leaves act_state unchanged"
        );
        tx.rollback().await.unwrap();

        assert_eq!(act_state(&source).await, live);
        source.close().await;
    }

    /// Row counts for every immutable-companion table in the shared closure
    /// order. A post-finalisation rollback must restore all of them, including
    /// `relationship_federation_events` and `blobs`.
    async fn companion_row_counts(db: &crate::Db) -> Vec<(String, i64)> {
        let mut counts = Vec::new();
        for table in crate::standby::companion_closure::COMPANION_TABLES {
            counts.push((table.to_string(), count(db, table).await));
        }
        counts
    }

    async fn act_cutover_snapshot(db: &crate::Db) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT json_object('domain',domain,'last',last_legacy_seq,'at',cutover_at,
                                 'from',from_engine_schema)
               FROM act_cutover ORDER BY domain",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    async fn causal_cutover_snapshot(db: &crate::Db) -> String {
        sqlx::query_scalar(
            "SELECT json_object('last',last_legacy_local_seq,'at',cutover_at,
                                 'from',from_engine_schema)
               FROM content_event_causal_cutover WHERE singleton = 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    async fn storage_policy_snapshot(db: &crate::Db) -> Option<String> {
        sqlx::query_scalar(
            "SELECT json_object('rev',policy_revision,'enforcement',enforcement,
                                 'profile',source_profile_id,'profile_rev',source_profile_revision,
                                 'mode',source_mode,'targets',targets,'floors',revision_floors,
                                 'conversions',allow_conversions,'catalog',catalog_sha256,
                                 'updated',updated_at)
               FROM storage_portability_policy WHERE singleton = 1",
        )
        .fetch_optional(db.pool())
        .await
        .unwrap()
    }

    async fn binding_system_snapshot(db: &crate::Db) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT json_object('system',system,'normalizer',normalizer,'type',compatible_type,
                                 'kind',compatible_kind,'visibility',visibility,'add',add_policy,
                                 'remove',remove_policy,'canonicalize',canonicalize_policy,
                                 'transfer',transfer_policy,'reconciliation',reconciliation_rule,
                                 'stub',stub_allowed,'authoritative',authoritative_provenance,
                                 'durable',required_durable)
               FROM binding_systems ORDER BY system",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    fn section_index(value: &Value, lane: &str, name: &str) -> usize {
        value[lane]
            .as_array()
            .unwrap()
            .iter()
            .position(|section| section["name"] == name)
            .unwrap_or_else(|| panic!("delta carries {name} in {lane}"))
    }

    fn column_index(value: &Value, lane: &str, section: usize, column: &str) -> usize {
        value[lane][section]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|candidate| candidate["name"] == column)
            .unwrap_or_else(|| panic!("{column} column present"))
    }

    /// A row read back through the full relationship reader for comparison.
    #[allow(dead_code)]
    async fn all_relationship_event_rows(
        db: &crate::Db,
    ) -> Vec<crate::relationship::RelationshipReplayEvent> {
        let mut conn = db.write_pool().acquire().await.unwrap();
        crate::relationship::read_all_relationship_events(&mut conn)
            .await
            .unwrap()
    }
}
