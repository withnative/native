//! Content-only exact-act delta materialisation into a destination already
//! materialised at F1.
//!
//! **Test-only, retired from non-test builds.** This module is declared
//! `#[cfg(test)]` in `standby/mod.rs`: it is a closed R2 proof, has no callers
//! outside its own tests, and — because it accepts a merely structurally valid
//! [`ValidatedAuthorityActDelta`] with no trust gate and commits while leaving
//! `act_state` at F1 — it must not be reachable from a non-test build. The
//! finalising `act_materialise` path is the only non-test apply. Its tests are
//! preserved unchanged.
//!
//! Slice R2 of cb551d7. This consumes a P0 [`ValidatedAuthorityActDelta`] whose
//! act sections carry content events only and applies it atomically: it pins
//! every carried section to the destination schema, ingests the exact rows with
//! R1's conflict modes, decodes the newly inserted content rows, folds them
//! through [`crate::projector::project`] in `seq` order, re-derives the whole
//! immutable-companion closure from the materialised destination, and commits
//! only when that closure is byte-exact against the carried companion.
//!
//! It deliberately does **not** finalise any authority head coordinate or
//! `act_state`, a cutover, or a generation. The content projection is not
//! read-only in every respect, though: folding content events writes the
//! projection tables, and the engine's `records`, `record_policies`,
//! `policy_entries` and `bindings` triggers advance the database-local derived
//! `authorization_revision` epoch. That epoch is a database-local derivation,
//! never a replicated authority coordinate, so R2 neither carries nor finalises
//! it. A real continuation will finalise the head in the full materialiser
//! (R4); until then this slice is an internal proof that can apply at most one
//! content-only delta to an F1 destination because the destination `act_state`
//! intentionally remains F1 while its content log and projections include F2.
//!
//! # Bounds of the proof
//!
//! The re-derivation is a real check, but a bounded one. It proves the carried
//! companion is the exact reachable closure of the materialised content rows,
//! which rejects extra unreachable carried rows and a carried row that
//! references a missing blob. It cannot prove per-act row completeness or the
//! absence of optional authority rows the destination never had a reason to
//! read: a producer that omitted a legitimately reachable optional row would
//! still leave the re-derived closure equal because that row is absent on both
//! sides. Transport authenticity is therefore load-bearing and entirely outside
//! this core: the delta document is an unsigned structural carrier, and only
//! the authenticated origin/transport path can make its claims authoritative.

#![allow(dead_code)] // R2 core; the controller/transport wiring lands later.

use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::EventRow;
use crate::interchange::{validate_destination_section, validate_section_shape, Cell, Section};
use crate::standby::act_delta::{AuthorityActDeltaHeadV1, ValidatedAuthorityActDelta};
use crate::standby::authority_probe::{
    read_authority_act_head_on, AuthorityActHeadV2, LogMaxSeqV1,
};

/// The only act-stamped table a content-only delta may carry.
const CONTENT_TABLE: &str = "content_events";

/// The relationship federation companions are relationship-domain state. A
/// content-only cut carries none of their rows, and the materialiser refuses a
/// delta that does rather than applying a relationship-domain act through a
/// content route.
const RELATIONSHIP_FEDERATION_COMPANIONS: [&str; 3] = [
    "relationship_federation_events",
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
];

/// Every companion a content-only cut is allowed to carry rows for. Any other
/// companion must be empty. This is deliberately the content/replicated-message/
/// provenance/blob subset; the three relationship federation companions are not
/// on the list and must be empty.
const ALLOWED_NONEMPTY_COMPANIONS: [&str; 10] = [
    "content_event_causal_frontier",
    "content_event_sources",
    "replicated_message_provenance",
    "destination_message_ingest",
    "replicated_message_references",
    "provenance_interaction_receipts",
    "provenance_action_attestations",
    "provenance_action_events",
    "provenance_action_outputs",
    "blobs",
];

/// A compact report of one content-only materialisation. `no_op` is an empty
/// interval: nothing was written, and `inserted_rows`/`projected_events` are
/// zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ContentMaterialiseOutcome {
    pub(crate) no_op: bool,
    pub(crate) inserted_rows: usize,
    pub(crate) identical_rows: usize,
    pub(crate) content_rows: usize,
    pub(crate) projected_events: usize,
}

/// Apply a validated content-only exact-act delta to a destination already
/// materialised at the delta's lower bound.
///
/// Validation, ingest, projection, companion re-derivation and the final
/// `act_state` check all run in one deferred-foreign-key write transaction.
/// Any failure rolls the whole transaction back, so logs, companions and
/// projections are all-or-nothing. On success the destination content log and
/// projections include the delta, while `act_state` intentionally remains F1.
pub(crate) async fn apply_content_act_delta(
    db: &Db,
    delta: &ValidatedAuthorityActDelta,
) -> Result<ContentMaterialiseOutcome> {
    preflight_content_only(delta)?;

    let mut tx = db.write_pool().begin().await?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await?;

    let outcome = run_content_materialisation(&mut tx, delta).await;
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

async fn run_content_materialisation(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    delta: &ValidatedAuthorityActDelta,
) -> Result<ContentMaterialiseOutcome> {
    let cut = delta.act_cut();
    let carried_head = delta.authority_head();
    let from_exclusive_act = cut.from_exclusive_act();
    let to_inclusive_act = cut.to_inclusive_act();
    let content_section = cut
        .section(CONTENT_TABLE)
        .ok_or_else(|| Error::engine("content-only delta is missing its content_events section"))?;

    // The destination head is read in this same transaction/snapshot, so the
    // prefix check and the later ingest cannot observe different states.
    let local_head = read_authority_act_head_on(&mut *tx).await?;
    require_destination_prefix_matches_carried_head(carried_head, &local_head, from_exclusive_act)?;

    let mut outcome = ContentMaterialiseOutcome::default();
    if from_exclusive_act == to_inclusive_act {
        // An empty interval must still be an exact no-op against the carried
        // target: the destination content log has to already be at the carried
        // content maximum, or the destination is not the F1 the authority cut
        // from. This is the only frontier check that a zero-row delta still
        // makes; nothing else is read or written.
        require(
            local_content_max_seq(&local_head)? == carried_content_max_seq(carried_head)?,
            "content materialisation empty interval content log does not match the carried content maximum",
        )?;
        outcome.no_op = true;
        return Ok(outcome);
    }

    // Destination-schema pin every act and companion before the first mutation.
    // A tampered column list or primary key anywhere refuses with nothing
    // written.
    for section in cut.sections().iter().chain(cut.companions()) {
        validate_section_shape(section)?;
        validate_destination_section(tx, section).await?;
    }

    // Local-prefix check: the destination content log must be the contiguous
    // prefix the carried content rows extend. Overlap is refused by the act-log
    // conflict mode below; a gap is refused here, before any mutation.
    let local_content_max: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
            .fetch_one(&mut **tx)
            .await?;
    require_local_content_prefix(local_content_max, content_section)?;

    // Exact ingest with R1's per-class conflict modes: act logs refuse any
    // existing key; companions admit an identical retry and refuse divergence.
    let ingest = crate::standby::receiver::ingest_sections_in_transaction(
        tx,
        cut.sections(),
        cut.companions(),
    )
    .await?;
    outcome.inserted_rows = ingest.inserted_rows;
    outcome.identical_rows = ingest.identical_rows;

    // Read exactly the newly inserted content rows by act range and require
    // their decoded identities equal the carried content section.
    let events =
        crate::query::events::events_in_act_range(&mut *tx, from_exclusive_act, to_inclusive_act)
            .await?;
    require_decoded_content_matches_section(&events, content_section)?;
    outcome.content_rows = events.len();

    // The materialised content log must advance exactly to the carried target,
    // never past it and never short of it.
    let materialised_max: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
            .fetch_one(&mut **tx)
            .await?;
    require(
        materialised_max == carried_content_max_seq(carried_head)?,
        "content materialisation content log does not reach the carried content maximum",
    )?;

    // Fold each new event through the projector, in seq order. `project` is
    // called directly: it never appends a log row and never allocates an act.
    for event in &events {
        crate::projector::project(&mut *tx, event)
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "content materialisation projector failed for event {} (seq {}): {error}",
                    event.id, event.local_seq
                ))
            })?;
    }
    outcome.projected_events = events.len();

    // Re-derive every companion from the now-materialised destination through
    // the one shared closure SQL and require exact equality: format, revision,
    // name, columns, primary key and rows in the same deterministic order.
    let derived = crate::standby::companion_closure::read_companion_sections_on(
        &mut *tx,
        from_exclusive_act,
        to_inclusive_act,
    )
    .await?;
    require_companion_sections_equal(&derived, cut.companions())?;

    // R2 never allocates an act. The destination head must still be F1 even
    // though its content log and projections now include F2; R4 finalises the
    // head atomically in the full materialiser.
    let end_act: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
        .fetch_one(&mut **tx)
        .await?;
    require(
        end_act == from_exclusive_act,
        "content materialisation must leave act_state at F1; R2 does not allocate an act",
    )?;

    Ok(outcome)
}

/// Pure structural preflight on the validated delta, before any transaction.
///
/// It re-pins the two lanes at the content entry point, requires every
/// act-stamped section except `content_events` to be empty, requires every
/// companion outside the content-only allow-list to be empty (which includes
/// the three relationship federation companions), and requires every carried
/// `provenance_action_outputs` row to be content-domain.
fn preflight_content_only(delta: &ValidatedAuthorityActDelta) -> Result<()> {
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
    crate::standby::receiver::require_authority_lanes(&act_names, &companion_names)?;

    for section in cut.sections() {
        require(
            section.name == CONTENT_TABLE || section.rows.is_empty(),
            "content-only delta carries rows in a non-content act section",
        )?;
    }

    for section in cut.companions() {
        if RELATIONSHIP_FEDERATION_COMPANIONS.contains(&section.name.as_str()) {
            require(
                section.rows.is_empty(),
                "content-only delta carries relationship federation companion rows",
            )?;
        }
        if !ALLOWED_NONEMPTY_COMPANIONS.contains(&section.name.as_str()) {
            require(
                section.rows.is_empty(),
                "content-only delta carries rows in a disallowed companion",
            )?;
        }
    }

    let outputs = cut
        .companion("provenance_action_outputs")
        .ok_or_else(|| Error::engine("content-only delta is missing provenance_action_outputs"))?;
    require_provenance_outputs_content_only(outputs)?;
    Ok(())
}

fn require_provenance_outputs_content_only(section: &Section) -> Result<()> {
    let domain_index = section
        .columns
        .iter()
        .position(|column| column.name == "output_domain")
        .ok_or_else(|| {
            Error::engine("provenance_action_outputs section has no output_domain column")
        })?;
    for row in &section.rows {
        match row.get(domain_index) {
            Some(Cell::Text(domain)) if domain == "content" => {}
            _ => {
                return Err(Error::engine(
                    "content-only delta carries a non-content provenance_action_outputs row",
                ))
            }
        }
    }
    Ok(())
}

/// The focused destination-prefix comparison on the carried wire head.
///
/// Every replicated coordinate must match the locally observed destination head
/// except the content log's own `MAX(seq)`, which is the one coordinate a
/// content-only application is allowed to advance, and `head_act`, which is
/// required to be exactly the delta's lower bound F1 rather than the carried
/// target F2. The advisory `source_engine_schema` is deliberately not compared:
/// the wire does not carry it and engine identity never gates materialisation.
fn require_destination_prefix_matches_carried_head(
    carried: &AuthorityActDeltaHeadV1,
    local: &AuthorityActHeadV2,
    expected_local_head_act: i64,
) -> Result<()> {
    require(
        local.head_act == expected_local_head_act,
        "content materialisation destination head act is not the delta's lower bound",
    )?;
    require(
        local.contract == carried.contract() && local.version == carried.version(),
        "content materialisation destination head contract disagrees with the carried head",
    )?;
    require(
        local.origin_database_id == carried.origin_database_id(),
        "content materialisation destination origin disagrees with the carried head",
    )?;
    require(
        local.native_interchange_revision == carried.native_interchange_revision(),
        "content materialisation destination interchange revision disagrees with the carried head",
    )?;
    require(
        local.storage_portability_policy.as_ref() == carried.storage_portability_policy(),
        "content materialisation destination portability policy disagrees with the carried head",
    )?;
    require(
        local.act_cutovers.as_slice() == carried.act_cutovers(),
        "content materialisation destination act cutovers disagree with the carried head",
    )?;
    require(
        &local.content_causal_cutover == carried.content_causal_cutover(),
        "content materialisation destination content causal cutover disagrees with the carried head",
    )?;
    require(
        local.binding_systems.as_slice() == carried.binding_systems(),
        "content materialisation destination binding seeds disagree with the carried head",
    )?;
    require(
        local.webhook_endpoint_count == carried.webhook_endpoint_count()
            && local.webhook_credential_count == carried.webhook_credential_count(),
        "content materialisation destination webhook pins disagree with the carried head",
    )?;
    require(
        local.non_sequenced_max_acts.as_slice() == carried.non_sequenced_max_acts(),
        "content materialisation destination non-sequenced act watermarks disagree with the carried head",
    )?;

    require(
        local.per_log_max_seq.len() == carried.per_log_max_seq().len(),
        "content materialisation destination per-log diagnostics are incomplete",
    )?;
    for (local_row, carried_row) in local.per_log_max_seq.iter().zip(carried.per_log_max_seq()) {
        require(
            local_row.table == carried_row.table,
            "content materialisation destination per-log diagnostics are out of order",
        )?;
        if local_row.table == CONTENT_TABLE {
            require(
                local_row.max_seq <= carried_row.max_seq,
                "content materialisation destination content log is ahead of the carried target",
            )?;
        } else {
            require(
                local_row.max_seq == carried_row.max_seq,
                "content materialisation destination non-content log maximum disagrees with the carried head",
            )?;
        }
    }
    Ok(())
}

/// The carried content log's own target maximum (`content_events` `MAX(seq)`),
/// which a successful materialisation must reach exactly.
fn carried_content_max_seq(carried: &AuthorityActDeltaHeadV1) -> Result<i64> {
    content_max_seq_from_per_log(carried.per_log_max_seq())
}

/// The destination content log's own maximum from the head observed in the
/// same transaction. The authority-head probe computes it as
/// `COALESCE(MAX(seq), 0)`, so an empty interval compares like for like.
fn local_content_max_seq(local: &AuthorityActHeadV2) -> Result<i64> {
    content_max_seq_from_per_log(&local.per_log_max_seq)
}

fn content_max_seq_from_per_log(rows: &[LogMaxSeqV1]) -> Result<i64> {
    rows.iter()
        .find(|row| row.table == CONTENT_TABLE)
        .map(|row| row.max_seq)
        .ok_or_else(|| Error::engine("head is missing its content_events per-log diagnostic"))
}

/// The destination content log must be the contiguous prefix the carried rows
/// extend: the smallest carried `seq` is exactly one past the destination
/// maximum. Overlap is also refused later by the act-log conflict mode; this
/// check refuses a gap before any mutation. A carried section with no rows is
/// impossible on a non-empty interval (whole-act coverage), so it is a
/// fail-closed error here rather than a silent no-op.
fn require_local_content_prefix(local_content_max: i64, section: &Section) -> Result<()> {
    let seq_index = section
        .columns
        .iter()
        .position(|column| column.name == "seq")
        .ok_or_else(|| Error::engine("content_events section has no seq column"))?;
    let mut min_seq: Option<i64> = None;
    for row in &section.rows {
        let seq = integer_cell(row, seq_index, "seq")?;
        min_seq = Some(min_seq.map_or(seq, |current| current.min(seq)));
    }
    let Some(min_seq) = min_seq else {
        return Err(Error::engine(
            "content-only delta on a non-empty interval carries no content rows",
        ));
    };
    let expected = local_content_max
        .checked_add(1)
        .ok_or_else(|| Error::engine("destination content sequence overflows"))?;
    require(
        min_seq == expected,
        "content-only delta is not the contiguous successor of the destination content log",
    )
}

/// Require the decoded rows to equal the carried content section by count and
/// identity. The section is ordered by its primary key (`seq`) and the reader
/// orders by `seq`, so a positional comparison is exact.
fn require_decoded_content_matches_section(events: &[EventRow], section: &Section) -> Result<()> {
    require(
        events.len() == section.rows.len(),
        "decoded content row count diverges from the carried content section",
    )?;
    let column = |name: &str| {
        section
            .columns
            .iter()
            .position(|candidate| candidate.name == name)
            .ok_or_else(|| Error::engine(format!("content_events section has no {name} column")))
    };
    let seq_index = column("seq")?;
    let id_index = column("id")?;
    let record_id_index = column("record_id")?;
    let type_index = column("type")?;
    let act_index = column("act")?;
    for (event, row) in events.iter().zip(&section.rows) {
        require(
            event.local_seq == integer_cell(row, seq_index, "seq")?,
            "decoded content row seq diverges from the carried content section",
        )?;
        require(
            event.id == text_cell(row, id_index, "id")?,
            "decoded content row id diverges from the carried content section",
        )?;
        require(
            event.record_id == text_cell(row, record_id_index, "record_id")?,
            "decoded content row record_id diverges from the carried content section",
        )?;
        require(
            event.event_type == text_cell(row, type_index, "type")?,
            "decoded content row type diverges from the carried content section",
        )?;
        require(
            event.act == optional_integer_cell(row, act_index, "act")?,
            "decoded content row act diverges from the carried content section",
        )?;
    }
    Ok(())
}

/// Exact companion-closure equality. Every dimension is compared, so a
/// re-derived section that matches only by row count cannot pass: the carried
/// format, revision, name, column list, primary key and ordered rows must all
/// be identical.
fn require_companion_sections_equal(derived: &[Section], carried: &[Section]) -> Result<()> {
    require(
        derived.len() == carried.len(),
        "re-derived companion closure inventory diverges from the carried closure",
    )?;
    for (derived, carried) in derived.iter().zip(carried.iter()) {
        require(
            derived.name == carried.name && derived.format == carried.format,
            "re-derived companion identity diverges from the carried companion",
        )?;
        require(
            derived.revision == carried.revision,
            "re-derived companion revision diverges from the carried companion",
        )?;
        require(
            derived.columns == carried.columns,
            "re-derived companion columns diverge from the carried companion",
        )?;
        require(
            derived.primary_key == carried.primary_key,
            "re-derived companion primary key diverges from the carried companion",
        )?;
        require(
            derived.rows == carried.rows,
            "re-derived companion rows diverge from the carried companion",
        )?;
    }
    Ok(())
}

fn integer_cell(row: &[Cell], index: usize, name: &str) -> Result<i64> {
    match row.get(index) {
        Some(Cell::Integer(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "content materialisation content cell '{name}' is not an integer"
        ))),
    }
}

fn optional_integer_cell(row: &[Cell], index: usize, name: &str) -> Result<Option<i64>> {
    match row.get(index) {
        Some(Cell::Integer(value)) => Ok(Some(*value)),
        Some(Cell::Null) | None => Ok(None),
        _ => Err(Error::engine(format!(
            "content materialisation content cell '{name}' is not an integer or null"
        ))),
    }
}

fn text_cell(row: &[Cell], index: usize, name: &str) -> Result<String> {
    match row.get(index) {
        Some(Cell::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "content materialisation content cell '{name}' is not text"
        ))),
    }
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

    use std::path::Path;

    use sha2::{Digest, Sha256};

    use crate::interchange::{Cell, Section, REVISION, SECTION_FORMAT};
    use crate::standby::act_cut::read_authority_act_cut;
    use crate::standby::act_delta::{build_authority_act_delta, validate_authority_act_delta};

    const RECORD_ID: &str = "1a7e4000-0000-4000-8000-0000000000d1";
    const TARGET_ID: &str = "1a7e4000-0000-4000-8000-0000000000d2";
    const ANNOTATION_ID: &str = "1a7e4000-0000-4000-8000-0000000000d3";

    async fn fresh_source() -> crate::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    async fn head_act(db: &crate::Db) -> i64 {
        crate::standby::authority_probe::read_authority_act_head(db)
            .await
            .unwrap()
            .head_act
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

    /// Build a destination at the source's current act by canonical
    /// interchange export/import, exactly as the acceptance contract requires.
    async fn destination_at_current_head(source: &crate::Db, dir: &Path, name: &str) -> crate::Db {
        let bytes = crate::interchange::export_canonical_interchange(source)
            .await
            .unwrap();
        crate::interchange::import_canonical_interchange(&bytes, &dir.join(name))
            .await
            .unwrap()
    }

    fn value_of(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        serde_jcs::to_vec(value).unwrap()
    }

    /// Recompute the digest after a structural mutation so a refusal is
    /// attributable to the intended check, not the digest.
    fn resign(value: &mut serde_json::Value) {
        let mut payload = value.clone();
        payload.as_object_mut().unwrap().remove("content_sha256");
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap()));
        value["content_sha256"] = serde_json::Value::String(digest);
    }

    fn section_index(value: &serde_json::Value, lane: &str, name: &str) -> usize {
        value[lane]
            .as_array()
            .unwrap()
            .iter()
            .position(|section| section["name"] == name)
            .unwrap_or_else(|| panic!("delta carries {name} in {lane}"))
    }

    fn column_index(value: &serde_json::Value, lane: &str, section: usize, column: &str) -> usize {
        value[lane][section]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|candidate| candidate["name"] == column)
            .unwrap_or_else(|| panic!("{column} column present"))
    }

    /// Build the delta from `base` (the destination's act) to the source's
    /// current head, validate it, and return its bytes and parsed value.
    async fn build_delta(source: &crate::Db, base: i64) -> (Vec<u8>, serde_json::Value) {
        let head = head_act(source).await;
        let cut = read_authority_act_cut(source, base, head).await.unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        // The canonical document must validate before it is applied anywhere.
        validate_authority_act_delta(&bytes).unwrap();
        let value = value_of(&bytes);
        (bytes, value)
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

    /// Exact `(seq, id, act)` tuples for the content log, ordered by seq.
    async fn content_identities(db: &crate::Db) -> Vec<(i64, String, Option<i64>)> {
        sqlx::query_as("SELECT seq, id, act FROM content_events ORDER BY seq")
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    /// A shape-valid fabricated companion row: every declared cell NULL, then
    /// each named cell set. P0's structural validation admits it; the
    /// materialiser decides reachability.
    fn fabricated_companion_row(
        value: &serde_json::Value,
        section: &str,
        cells: &[(&str, serde_json::Value)],
    ) -> Vec<serde_json::Value> {
        let index = section_index(value, "companion_sections", section);
        let width = value["companion_sections"][index]["columns"]
            .as_array()
            .unwrap()
            .len();
        let mut row = (0..width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        for (column, cell) in cells {
            let column = column_index(value, "companion_sections", index, column);
            row[column] = cell.clone();
        }
        row
    }

    /// The acceptance contract's headline case: a destination materialised at
    /// F1 via canonical interchange, one content-only act advanced on the
    /// source to F2, the delta built and validated, then applied. Content
    /// identities and the content projection must match the source, and the
    /// destination must remain a conforming content-log projection (rebuild and
    /// diff).
    #[tokio::test]
    async fn content_only_delta_applies_exactly_and_keeps_a_conforming_projection() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "materialise fixture").await;
        let f1 = head_act(&source).await;

        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        assert_eq!(act_state(&destination).await, f1);

        // Advance the source content-only to F2.
        append_record(&source, TARGET_ID, "materialise target").await;
        let f2 = head_act(&source).await;
        assert_eq!(f2, f1 + 1);

        let (bytes, _) = build_delta(&source, f1).await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let outcome = apply_content_act_delta(&destination, &delta).await.unwrap();
        assert!(!outcome.no_op);
        assert_eq!(outcome.content_rows, 1);
        assert_eq!(outcome.projected_events, 1);

        // Exact content identities match the source, and the F1 event is
        // preserved.
        assert_eq!(
            content_identities(&destination).await,
            content_identities(&source).await
        );
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(TARGET_ID)
            .fetch_one(destination.pool())
            .await
            .unwrap();
        assert_eq!(name, "materialise target");

        // act_state deliberately remains F1: R2 never finalises the head.
        assert_eq!(act_state(&destination).await, f1);

        // The destination content log and its projections are self-consistent.
        let check = crate::conformance::check_rebuild_and_diff(&destination).await;
        assert!(check.ok, "rebuild-and-diff: {:?}", check.violations);

        destination.close().await;
        source.close().await;
    }

    /// One same-act transaction with multiple content events keeps each event's
    /// causal parent/frontier through the cut, the ingest and the re-derived
    /// companion closure.
    #[tokio::test]
    async fn same_act_multiple_content_events_preserve_the_causal_frontier() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        // A first content act establishes the destination's F1 and gives the
        // batch a real head to point at.
        let first = append_record(&source, RECORD_ID, "frontier root").await;
        let f1 = first.act.unwrap();

        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        assert_eq!(act_state(&destination).await, f1);

        let batch = crate::store::append_batch(
            &source,
            vec![
                crate::store::AppendSpec {
                    record_id: RECORD_ID.into(),
                    event_type: "record.updated".into(),
                    payload: serde_json::json!({"summary": "batch one"}),
                    actor: None,
                },
                crate::store::AppendSpec {
                    record_id: RECORD_ID.into(),
                    event_type: "record.updated".into(),
                    payload: serde_json::json!({"summary": "batch two"}),
                    actor: None,
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(batch[0].act, batch[1].act);
        assert_eq!(batch[0].act, Some(f1 + 1));

        let (bytes, value) = build_delta(&source, f1).await;
        let content = section_index(&value, "act_sections", CONTENT_TABLE);
        assert!(
            value["act_sections"][content]["rows"]
                .as_array()
                .unwrap()
                .len()
                >= 2,
            "the same-act batch is carried whole"
        );

        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_content_act_delta(&destination, &delta).await.unwrap();

        assert_eq!(
            content_identities(&destination).await,
            content_identities(&source).await
        );
        // The second batch event's frontier references the first, carried
        // exactly through the companion section.
        let frontier: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_id, parent_event_id FROM content_event_causal_frontier
              WHERE event_id = ? ORDER BY parent_event_id",
        )
        .bind(&batch[1].id)
        .fetch_all(destination.pool())
        .await
        .unwrap();
        assert_eq!(frontier, vec![(batch[1].id.clone(), batch[0].id.clone())]);
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// An inline blob referenced by a `facet.set blob_ref` and an
    /// `annotation.target.set` is carried, projected, and readable on the
    /// destination.
    #[tokio::test]
    async fn inline_blob_and_annotation_target_projection() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        let target = append_record(&source, TARGET_ID, "blob target").await;
        let f1 = target.act.unwrap();

        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        assert_eq!(act_state(&destination).await, f1);

        let blob =
            crate::blob::insert_blob(&source, b"inline bytes", Some("text/plain"), Some("b.txt"))
                .await
                .unwrap();
        crate::store::append(
            &source,
            crate::store::AppendSpec {
                record_id: TARGET_ID.into(),
                event_type: "facet.set".into(),
                payload: serde_json::json!({"key": "blob_ref", "value": blob.id}),
                actor: None,
            },
        )
        .await
        .unwrap();
        crate::store::create_record(
            &source,
            serde_json::json!({
                "id": ANNOTATION_ID,
                "type": "Annotation",
                "kind": "citation",
                "name": "",
            }),
        )
        .await
        .unwrap();
        crate::store::append(
            &source,
            crate::store::AppendSpec {
                record_id: ANNOTATION_ID.into(),
                event_type: "annotation.target.set".into(),
                payload: serde_json::json!({
                    "target_record_id": TARGET_ID,
                    "source_slot": "blob",
                    "blob_id": blob.id,
                    "source_sha256": "0".repeat(64),
                    "selectors": [],
                }),
                actor: None,
            },
        )
        .await
        .unwrap();

        let (bytes, value) = build_delta(&source, f1).await;
        let blobs = section_index(&value, "companion_sections", "blobs");
        assert_eq!(
            value["companion_sections"][blobs]["rows"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "the referenced inline blob is carried"
        );
        let delta = validate_authority_act_delta(&bytes).unwrap();
        apply_content_act_delta(&destination, &delta).await.unwrap();

        let copied_bytes: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT bytes FROM blobs WHERE id = ?")
                .bind(&blob.id)
                .fetch_one(destination.pool())
                .await
                .unwrap();
        assert_eq!(copied_bytes.as_deref(), Some(b"inline bytes".as_slice()));

        let facet_blob: String = sqlx::query_scalar(
            "SELECT value FROM facet_values WHERE record_id = ? AND key = 'blob_ref'",
        )
        .bind(TARGET_ID)
        .fetch_one(destination.pool())
        .await
        .unwrap();
        assert_eq!(facet_blob, blob.id);

        let targeted_blob: String =
            sqlx::query_scalar("SELECT blob_id FROM annotation_targets WHERE annotation_id = ?")
                .bind(ANNOTATION_ID)
                .fetch_one(destination.pool())
                .await
                .unwrap();
        assert_eq!(targeted_blob, blob.id);

        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// An empty interval is a genuine zero-mutation no-op, but it still reads
    /// and checks the destination origin/frontier/pins.
    #[tokio::test]
    async fn empty_interval_is_a_zero_mutation_noop() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "noop fixture").await;
        let f = head_act(&source).await;

        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;

        let cut = read_authority_act_cut(&source, f, f).await.unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let outcome = apply_content_act_delta(&destination, &delta).await.unwrap();
        assert!(outcome.no_op);
        assert_eq!(outcome.inserted_rows, 0);
        assert_eq!(outcome.content_rows, 0);
        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(act_state(&destination).await, f);
        assert_eq!(head_act(&destination).await, f);

        destination.close().await;
        source.close().await;
    }

    /// An empty interval is not a blanket no-op: the destination content log
    /// must already reach the carried content maximum. A destination whose act
    /// head coordinate matches but whose content frontier lags refuses rather
    /// than reporting success on a state the authority did not cut from.
    #[tokio::test]
    async fn empty_interval_refuses_when_local_content_log_lags_the_carried_target() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "lag fixture").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        append_record(&source, TARGET_ID, "lag target").await;
        let f2 = head_act(&source).await;
        assert_eq!(f2, f1 + 1);

        let cut = read_authority_act_cut(&source, f2, f2).await.unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        let delta = validate_authority_act_delta(&bytes).unwrap();

        // Move only the act head to F2 so every other coordinate matches while
        // the content log still stops at F1.
        sqlx::query("UPDATE act_state SET next_act = ? WHERE singleton = 1")
            .bind(f2)
            .execute(destination.write_pool())
            .await
            .unwrap();
        let before = content_identities(&destination).await;

        let error = apply_content_act_delta(&destination, &delta)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("content maximum"),
            "lagging empty interval refusal: {error}"
        );
        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(act_state(&destination).await, f2);

        destination.close().await;
        source.close().await;
    }

    /// Overlap, origin mismatch and a carried content target the rows cannot
    /// reach all refuse before any mutation.
    #[tokio::test]
    async fn overlap_origin_and_frontier_mismatches_refuse_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "prefix fixture").await;
        let f1 = head_act(&source).await;

        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;

        append_record(&source, TARGET_ID, "prefix target").await;
        let (bytes, _) = build_delta(&source, f1).await;

        // Overlap: a destination already at F2 cannot accept the F1->F2 delta
        // because its head act is no longer F1.
        let advanced = destination_at_current_head(&source, dir.path(), "f2.db").await;
        let delta = validate_authority_act_delta(&bytes).unwrap();
        let overlap_error = apply_content_act_delta(&advanced, &delta)
            .await
            .unwrap_err();
        assert!(
            overlap_error.to_string().contains("head act")
                || overlap_error.to_string().contains("lower bound"),
            "overlap refusal: {overlap_error}"
        );
        advanced.close().await;

        // Origin mismatch: rewrite the carried origin and recompute the digest.
        let mut origin = value_of(&bytes);
        origin["authority_head"]["origin_database_id"] =
            serde_json::json!("ndb_0123456789abcdef0123456789abcdef");
        resign(&mut origin);
        let origin_delta = validate_authority_act_delta(&canonical(&origin)).unwrap();
        let origin_error = apply_content_act_delta(&destination, &origin_delta)
            .await
            .unwrap_err();
        assert!(
            origin_error.to_string().contains("origin"),
            "origin refusal: {origin_error}"
        );

        // Frontier mismatch: the carried content target maximum is beyond what
        // the carried rows can reach. The document is still structurally valid
        // after re-signing, so the materialiser is what refuses it.
        let mut frontier = value_of(&bytes);
        let content_index = frontier["authority_head"]["per_log_max_seq"]
            .as_array()
            .unwrap()
            .iter()
            .position(|row| row["table"] == CONTENT_TABLE)
            .unwrap();
        frontier["authority_head"]["per_log_max_seq"][content_index]["max_seq"] =
            serde_json::json!(1_000_000);
        resign(&mut frontier);
        let frontier_delta = validate_authority_act_delta(&canonical(&frontier)).unwrap();
        let frontier_error = apply_content_act_delta(&destination, &frontier_delta)
            .await
            .unwrap_err();
        assert!(
            frontier_error.to_string().contains("content maximum"),
            "frontier refusal: {frontier_error}"
        );

        assert_eq!(
            content_identities(&destination).await,
            before,
            "no failed apply may mutate the destination"
        );
        assert_eq!(act_state(&destination).await, f1);

        destination.close().await;
        source.close().await;
    }

    /// Policy and binding-seed drift refuse before mutation.
    #[tokio::test]
    async fn policy_and_seed_drift_refuse_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "drift fixture").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;
        let records_before = count(&destination, "records").await;
        let companions_before = count(&destination, "content_event_causal_frontier").await;

        append_record(&source, TARGET_ID, "drift target").await;
        let (bytes, _) = build_delta(&source, f1).await;

        let mut seed = value_of(&bytes);
        seed["authority_head"]["binding_systems"][0]["normalizer"] =
            serde_json::json!("drifted-v1");
        resign(&mut seed);
        assert!(
            validate_authority_act_delta(&canonical(&seed)).is_err(),
            "binding seed drift must be refused by the closed validator"
        );

        // A portability policy pin that is valid on its own but disagrees with
        // the destination is refused by the materialiser, not the validator.
        let mut policy = value_of(&bytes);
        policy["authority_head"]["storage_portability_policy"] = serde_json::json!({
            "policy_revision": 1,
            "source_profile_id": "kite-local",
            "source_profile_revision": 1,
            "source_mode": "embedded",
        });
        resign(&mut policy);
        let policy_delta = validate_authority_act_delta(&canonical(&policy)).unwrap();
        let policy_error = apply_content_act_delta(&destination, &policy_delta)
            .await
            .unwrap_err();
        assert!(
            policy_error.to_string().contains("portability policy"),
            "policy refusal: {policy_error}"
        );

        assert_eq!(
            content_identities(&destination).await,
            before,
            "no refused apply may mutate the content log"
        );
        assert_eq!(
            count(&destination, "records").await,
            records_before,
            "no refused apply may mutate the projection"
        );
        assert_eq!(
            count(&destination, "content_event_causal_frontier").await,
            companions_before,
            "no refused apply may mutate companions"
        );
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// A non-content act section refuses, and so does a relationship-only
    /// companion.
    #[tokio::test]
    async fn non_content_act_and_relationship_companion_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "domain fixture").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;
        let before = content_identities(&destination).await;
        let records_before = count(&destination, "records").await;
        let companions_before = count(&destination, "content_event_causal_frontier").await;

        append_record(&source, TARGET_ID, "domain target").await;
        let (_bytes, value) = build_delta(&source, f1).await;

        // A fabricated in-range derivation_events row is structurally valid but
        // is not a content act.
        let mut tampered = value.clone();
        let derivation = section_index(&tampered, "act_sections", "derivation_events");
        let act_column = column_index(&tampered, "act_sections", derivation, "act");
        let width = tampered["act_sections"][derivation]["columns"]
            .as_array()
            .unwrap()
            .len();
        let mut row = (0..width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        row[act_column] = serde_json::json!({"type": "integer", "value": f1 + 1});
        tampered["act_sections"][derivation]["rows"] = serde_json::json!([row]);
        resign(&mut tampered);
        let non_content = validate_authority_act_delta(&canonical(&tampered)).unwrap();
        let error = apply_content_act_delta(&destination, &non_content)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("non-content act section"),
            "non-content act refusal: {error}"
        );

        // A relationship federation companion row refuses at preflight.
        let mut companion = value;
        let federation = section_index(
            &companion,
            "companion_sections",
            "relationship_federation_events",
        );
        let fed_width = companion["companion_sections"][federation]["columns"]
            .as_array()
            .unwrap()
            .len();
        let fed_row = (0..fed_width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        companion["companion_sections"][federation]["rows"] = serde_json::json!([fed_row]);
        resign(&mut companion);
        let federation_delta = validate_authority_act_delta(&canonical(&companion)).unwrap();
        let error = apply_content_act_delta(&destination, &federation_delta)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("relationship federation companion"),
            "relationship companion refusal: {error}"
        );

        assert_eq!(
            content_identities(&destination).await,
            before,
            "no refused apply may mutate the content log"
        );
        assert_eq!(
            count(&destination, "records").await,
            records_before,
            "no refused apply may mutate the projection"
        );
        assert_eq!(
            count(&destination, "content_event_causal_frontier").await,
            companions_before,
            "no refused apply may mutate companions"
        );
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// A re-signed extra unreachable content companion row refuses and the
    /// whole transaction rolls back.
    #[tokio::test]
    async fn extra_unreachable_companion_refuses_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "unreachable fixture").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        append_record(&source, TARGET_ID, "unreachable target").await;
        // An out-of-window content event: its source row is NOT selected by the
        // in-window closure, but it is a real event so the FK admits the row.
        let out_of_window_event_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq LIMIT 1",
        )
        .bind(RECORD_ID)
        .fetch_one(source.pool())
        .await
        .unwrap();
        let (_bytes, value) = build_delta(&source, f1).await;

        // A fully NOT-NULL-complete `content_event_sources` row for the
        // out-of-window event. It inserts under the deferred FK, but the
        // re-derived closure cannot reach it, so the exact compare refuses it.
        let mut tampered = value;
        let sources = section_index(&tampered, "companion_sections", "content_event_sources");
        let width = tampered["companion_sections"][sources]["columns"]
            .as_array()
            .unwrap()
            .len();
        let mut row = (0..width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        for (column, cell) in [
            (
                "event_id",
                serde_json::json!({"type": "text", "value": out_of_window_event_id}),
            ),
            (
                "origin_database_id",
                serde_json::json!({"type": "text", "value": "ndb_0123456789abcdef0123456789abcdef"}),
            ),
            (
                "source_seq",
                serde_json::json!({"type": "integer", "value": 1}),
            ),
            (
                "source_record_id",
                serde_json::json!({"type": "text", "value": "source-record"}),
            ),
            (
                "source_principal",
                serde_json::json!({"type": "text", "value": "acct:source"}),
            ),
            (
                "source_fingerprint",
                serde_json::json!({"type": "text", "value": "0".repeat(64)}),
            ),
        ] {
            let index = column_index(&tampered, "companion_sections", sources, column);
            row[index] = cell;
        }
        tampered["companion_sections"][sources]["rows"] = serde_json::json!([row]);
        resign(&mut tampered);
        let delta = validate_authority_act_delta(&canonical(&tampered)).unwrap();

        let before = content_identities(&destination).await;
        let error = apply_content_act_delta(&destination, &delta)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("diverge"),
            "unreachable companion refusal: {error}"
        );
        assert_eq!(
            content_identities(&destination).await,
            before,
            "content log rolled back"
        );
        assert_eq!(
            count(&destination, "content_event_sources").await,
            0,
            "companions rolled back"
        );
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// Trust-boundary regression, explicitly **not** an authenticity property.
    ///
    /// A re-signed `content_event_sources` row anchored to a genuine in-window
    /// content event id is admitted: it is structurally valid and reachable
    /// through the closure, so the destination-side re-derivation cannot tell it
    /// from an authority-authored row. This pins the documented boundary — the
    /// delta is an unsigned structural carrier, and only the authenticated
    /// origin/transport path can rule such a forged row out. It demonstrates
    /// what the local proof cannot establish; it is not a claim that the row is
    /// authentic.
    #[tokio::test]
    async fn trust_boundary_re_signed_in_window_companion_row_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "boundary fixture").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        append_record(&source, TARGET_ID, "boundary target").await;
        let in_window_event_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
        )
        .bind(TARGET_ID)
        .fetch_one(source.pool())
        .await
        .unwrap();
        let (_bytes, value) = build_delta(&source, f1).await;

        // A forged source row anchored to the genuine in-window event: the
        // closure reaches it, so the exact compare admits it alongside the
        // content event.
        let mut tampered = value;
        let row = fabricated_companion_row(
            &tampered,
            "content_event_sources",
            &[
                (
                    "event_id",
                    serde_json::json!({"type": "text", "value": in_window_event_id}),
                ),
                (
                    "origin_database_id",
                    serde_json::json!({"type": "text", "value": "ndb_0123456789abcdef0123456789abcdef"}),
                ),
                (
                    "source_seq",
                    serde_json::json!({"type": "integer", "value": 1}),
                ),
                (
                    "source_record_id",
                    serde_json::json!({"type": "text", "value": "forged-source"}),
                ),
                (
                    "source_principal",
                    serde_json::json!({"type": "text", "value": "acct:forged"}),
                ),
                (
                    "source_fingerprint",
                    serde_json::json!({"type": "text", "value": "0".repeat(64)}),
                ),
            ],
        );
        let sources = section_index(&tampered, "companion_sections", "content_event_sources");
        tampered["companion_sections"][sources]["rows"] = serde_json::json!([row]);
        resign(&mut tampered);
        let delta = validate_authority_act_delta(&canonical(&tampered)).unwrap();

        let outcome = apply_content_act_delta(&destination, &delta).await.unwrap();
        assert!(!outcome.no_op);

        // The forged row is now durable on the destination: only the
        // authenticated transport/origin path can rule it out, not this core.
        let source_record: String = sqlx::query_scalar(
            "SELECT source_record_id FROM content_event_sources WHERE event_id = ?",
        )
        .bind(&in_window_event_id)
        .fetch_one(destination.pool())
        .await
        .unwrap();
        assert_eq!(source_record, "forged-source");
        assert_eq!(act_state(&destination).await, f1);

        destination.close().await;
        source.close().await;
    }

    /// A malformed-but-cell-valid content payload passes structural validation
    /// and reaches the projector, which fails and rolls back the content log,
    /// companions and projections; `act_state` is unchanged.
    #[tokio::test]
    async fn malformed_content_payload_reaches_the_projector_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let source = fresh_source().await;
        append_record(&source, RECORD_ID, "malformed fixture").await;
        let f1 = head_act(&source).await;
        let destination = destination_at_current_head(&source, dir.path(), "f1.db").await;

        append_record(&source, TARGET_ID, "malformed target").await;
        let (_bytes, value) = build_delta(&source, f1).await;

        let mut tampered = value;
        let content = section_index(&tampered, "act_sections", CONTENT_TABLE);
        let payload_column = column_index(&tampered, "act_sections", content, "payload");
        tampered["act_sections"][content]["rows"][0][payload_column] = serde_json::json!({
            "type": "text",
            "value": serde_json::json!({"unknown_event_type": true}).to_string(),
        });
        resign(&mut tampered);
        let delta = validate_authority_act_delta(&canonical(&tampered)).unwrap();

        let before = content_identities(&destination).await;
        let records_before = count(&destination, "records").await;
        let error = apply_content_act_delta(&destination, &delta)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("projector"),
            "projector refusal: {error}"
        );
        assert_eq!(content_identities(&destination).await, before);
        assert_eq!(count(&destination, "records").await, records_before);
        assert_eq!(act_state(&destination).await, f1);
        destination.close().await;
        source.close().await;
    }

    /// The companion equality check compares every dimension, not just row
    /// count.
    #[test]
    fn companion_equality_is_exact_and_deterministic() {
        let section = |rev: u64, rows: Vec<Vec<Cell>>| Section {
            format: SECTION_FORMAT.into(),
            revision: rev,
            name: "content_event_sources".into(),
            columns: vec![crate::interchange::Column {
                name: "event_id".into(),
                declared_type: "TEXT".into(),
            }],
            primary_key: vec!["event_id".into()],
            rows,
        };
        let base = section(REVISION, vec![vec![Cell::Text("a".into())]]);
        require_companion_sections_equal(std::slice::from_ref(&base), std::slice::from_ref(&base))
            .unwrap();

        let different = section(REVISION, vec![vec![Cell::Text("b".into())]]);
        assert!(
            require_companion_sections_equal(&[different], std::slice::from_ref(&base)).is_err()
        );

        let wrong_revision = section(REVISION - 1, base.rows.clone());
        assert!(
            require_companion_sections_equal(&[wrong_revision], std::slice::from_ref(&base))
                .is_err()
        );
    }
}
