//! Bounded immutable-companion and blob closure for the authority act cut.
//!
//! Slice 2c of cb551d7. Companion tables are immutable canonical state with no
//! act of their own: they are selected by joining from identifiers carried by
//! the thirteen act-stamped cut sections, then from identifiers discovered
//! along the explicitly bounded edges below. Every selection is expressed as a
//! nested SQL subquery over the live database, so the cut never scans a
//! companion table and never walks an unbounded edge.
//!
//! The edges, and only these edges, are walked:
//!
//! * `content_event_causal_frontier` and `content_event_sources` are keyed by
//!   in-window `content_events.id`. A causal parent may be out of window or
//!   foreign; it is carried as a column, never followed as a row.
//! * `replicated_message_provenance` is keyed by the selected
//!   `content_event_sources.event_id`; absence is honest for a non-message
//!   replicated event.
//! * `destination_message_ingest` is keyed by the selected provenance
//!   `source_event_id`, never by `message_id`. An absent ingest row is honest.
//! * `replicated_message_references` is keyed by the selected ingest
//!   `message_id` through `source_message_id`; an unresolved or missing target
//!   is valid and is never chased through `resolved_local_id`.
//! * `provenance_action_events` and `provenance_action_outputs` are keyed by
//!   in-window content and relationship event ids by their declared
//!   output-event link. Only the attestations those rows reference, and only
//!   the interaction receipts those attestations reference, are pulled. The
//!   closure never fans out from a receipt or attestation into all history.
//! * the relationship federation companions are keyed by in-window
//!   relationship event ids and the explicit
//!   `authoring_action_attestation_id` declared in a selected assertion's
//!   payload, then only the outputs of those attestations. Missing optional
//!   federation state is honest.
//! * `blobs` are pulled by primary key from identifiers computed from the
//!   actual portable payload schema of in-window canonical events: a
//!   `facet.set` with `key = 'blob_ref'` and an `annotation.target.set` with a
//!   `blob_id`. Arbitrary strings are never inferred as blob identifiers; a
//!   referenced blob that is missing or nonportable refuses the whole cut.
//!
//! No future leakage: every subquery is anchored on the same
//! `(from_exclusive_act, to_inclusive_act]` predicate as the act cut, so a row
//! created before or after the interval is unreachable unless an in-window row
//! names it through one of the bounded edges above.

use std::collections::BTreeSet;

use sqlx::{Row as _, SqliteConnection};

use crate::error::{Error, Result};
use crate::events::{AnnotationTargetSetPayload, FacetSetPayload};
use crate::interchange::{Section, SelectionBind};

/// The immutable canonical companions carried by every authority act cut.
///
/// This list is not the source of truth: the standby classification is. The
/// `companion_inventory_matches_the_classification` test fails closed if this
/// list and the classified [`crate::schema::standby_classification::StandbyTableKind::ImmutableCanonicalCompanion`]
/// set ever diverge, so a new companion cannot ship uncarried and a removed
/// one cannot ship carried.
pub(crate) const COMPANION_TABLES: [&str; 13] = [
    "content_event_causal_frontier",
    "content_event_sources",
    "replicated_message_provenance",
    "destination_message_ingest",
    "replicated_message_references",
    "provenance_interaction_receipts",
    "provenance_action_attestations",
    "provenance_action_events",
    "provenance_action_outputs",
    "relationship_federation_events",
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
    "blobs",
];

/// Read every companion section inside the caller's open read transaction.
/// The order is exactly [`COMPANION_TABLES`]; `blobs` is handled separately
/// because its identifiers come from canonical event payloads rather than a
/// column-to-column join.
pub(crate) async fn read_companion_sections_on(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<Section>> {
    let mut sections = Vec::with_capacity(COMPANION_TABLES.len());
    for table in COMPANION_TABLES {
        sections.push(
            read_companion_section_on(conn, table, from_exclusive_act, to_inclusive_act).await?,
        );
    }
    Ok(sections)
}

/// Read exactly one companion section inside the caller's open transaction.
///
/// This is the one SQL rule source for a companion: the authority-side cut and
/// R2's destination-side re-derivation both call it, so a receiver cannot
/// silently compare against a second, weaker closure. `table` must be one of
/// [`COMPANION_TABLES`]; `blobs` is handled separately because its identifiers
/// come from canonical event payloads rather than a column-to-column join.
pub(crate) async fn read_companion_section_on(
    conn: &mut SqliteConnection,
    table: &str,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Section> {
    if table == "blobs" {
        read_blobs_section_on(conn, from_exclusive_act, to_inclusive_act).await
    } else {
        let (where_clause, binds) =
            companion_selection(table, from_exclusive_act, to_inclusive_act)?;
        let bindings = binds
            .into_iter()
            .map(SelectionBind::Integer)
            .collect::<Vec<_>>();
        crate::interchange::export_where_section(conn, table, &where_clause, &bindings).await
    }
}

/// The fixed `WHERE` fragment and positional act-bound values for one
/// companion table. Every fragment is a literal here; nothing from a caller or
/// a row reaches the SQL text.
///
/// An unknown table is a fail-closed `Err`, never a panic: a caller that names
/// a table outside [`COMPANION_TABLES`] must be refused rather than aborting
/// the process.
fn companion_selection(table: &str, from: i64, to: i64) -> Result<(String, Vec<i64>)> {
    let bounds = vec![from, to];
    let selection = match table {
        "content_event_causal_frontier" | "content_event_sources" => (
            "event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)".to_string(),
            bounds,
        ),
        "replicated_message_provenance" => (
            "source_event_id IN (\
               SELECT event_id FROM content_event_sources \
               WHERE event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?))"
                .to_string(),
            bounds,
        ),
        "destination_message_ingest" => (
            "source_event_id IN (\
               SELECT source_event_id FROM replicated_message_provenance \
               WHERE source_event_id IN (\
                 SELECT event_id FROM content_event_sources \
                 WHERE event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)))"
                .to_string(),
            bounds,
        ),
        "replicated_message_references" => (
            "source_message_id IN (\
               SELECT message_id FROM destination_message_ingest \
               WHERE source_event_id IN (\
                 SELECT source_event_id FROM replicated_message_provenance \
                 WHERE source_event_id IN (\
                   SELECT event_id FROM content_event_sources \
                   WHERE event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?))))"
                .to_string(),
            bounds,
        ),
        "provenance_action_events" => (
            "output_event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)"
                .to_string(),
            bounds,
        ),
        "provenance_action_outputs" => (
            "(output_domain = 'content' \
                AND output_event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)) \
             OR (output_domain = 'relationship' \
                AND output_event_id IN (SELECT id FROM relationship_events WHERE act > ? AND act <= ?))"
                .to_string(),
            vec![from, to, from, to],
        ),
        "provenance_action_attestations" => (
            format!(
                "id IN ({} UNION {} UNION {})",
                provenance_action_events_selection(),
                provenance_action_outputs_selection(),
                validity_attestation_selection(),
            ),
            vec![from, to, from, to, from, to, from, to],
        ),
        "provenance_interaction_receipts" => (
            format!(
                "id IN (SELECT interaction_receipt_id FROM provenance_action_attestations \
                 WHERE interaction_receipt_id IS NOT NULL AND id IN ({} UNION {} UNION {}))",
                provenance_action_events_selection(),
                provenance_action_outputs_selection(),
                validity_attestation_selection(),
            ),
            vec![from, to, from, to, from, to, from, to],
        ),
        // The relationship companions are selected by the exact
        // `(issuer_origin_db_id, id)` and
        // `(issuer_origin_db_id, authoring_action_attestation_id)` pairs the
        // in-window events declare, so the driver is always the act-stamped
        // relationship log, never a scan of the companion table.
        "relationship_federation_events" => (
            "(issuer_origin_db_id, event_id) IN (\
               SELECT issuer_origin_db_id, id FROM relationship_events \
               WHERE act > ? AND act <= ?)"
                .to_string(),
            bounds,
        ),
        "relationship_foreign_action_attestations" => (
            "(issuer_origin_db_id, attestation_id) IN (\
               SELECT issuer_origin_db_id, json_extract(payload, '$.authoring_action_attestation_id') \
               FROM relationship_events \
               WHERE act > ? AND act <= ? AND type = 'assertion.created.v1' \
                 AND json_extract(payload, '$.authoring_action_attestation_id') IS NOT NULL)"
                .to_string(),
            bounds,
        ),
        "relationship_foreign_action_outputs" => (
            "(issuer_origin_db_id, attestation_id) IN (\
               SELECT issuer_origin_db_id, attestation_id FROM relationship_foreign_action_attestations \
               WHERE (issuer_origin_db_id, attestation_id) IN (\
                 SELECT issuer_origin_db_id, json_extract(payload, '$.authoring_action_attestation_id') \
                 FROM relationship_events \
                 WHERE act > ? AND act <= ? AND type = 'assertion.created.v1' \
                   AND json_extract(payload, '$.authoring_action_attestation_id') IS NOT NULL))"
                .to_string(),
            bounds,
        ),
        other => {
            return Err(Error::engine(format!(
                "no companion selection for unknown table '{other}'"
            )))
        }
    };
    Ok(selection)
}

fn provenance_action_events_selection() -> &'static str {
    "SELECT action_attestation_id FROM provenance_action_events \
     WHERE output_event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)"
}

fn provenance_action_outputs_selection() -> &'static str {
    "SELECT action_attestation_id FROM provenance_action_outputs \
     WHERE (output_domain = 'content' \
              AND output_event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)) \
        OR (output_domain = 'relationship' \
              AND output_event_id IN (SELECT id FROM relationship_events WHERE act > ? AND act <= ?))"
}

fn validity_attestation_selection() -> &'static str {
    "SELECT attestation_id FROM provenance_attestation_validity_events WHERE act > ? AND act <= ?"
}

/// The referenced blob identifiers, computed only from the actual portable
/// payload schema of in-window canonical events. Only `facet.set` with
/// `key = 'blob_ref'` and `annotation.target.set` with a `blob_id` are treated
/// as references; no other string is ever inferred to be a blob id.
async fn referenced_blob_ids_on(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<BTreeSet<String>> {
    let rows = sqlx::query(
        "SELECT type, payload FROM content_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(&mut *conn)
    .await?;

    let mut referenced = BTreeSet::new();
    for row in &rows {
        let event_type: String = row.try_get("type")?;
        let payload: Option<String> = row.try_get("payload")?;
        let Some(payload) = payload else { continue };
        match event_type.as_str() {
            "facet.set" => {
                let parsed: FacetSetPayload = serde_json::from_str(&payload).map_err(|error| {
                    Error::engine(format!(
                        "authority act cut cannot read in-window facet.set payload: {error}"
                    ))
                })?;
                if parsed.key == crate::blob::BLOB_REF_FACET_KEY {
                    if let Some(value) = parsed.value {
                        if !value.is_empty() {
                            referenced.insert(value);
                        }
                    }
                }
            }
            "annotation.target.set" => {
                let parsed: AnnotationTargetSetPayload =
                    serde_json::from_str(&payload).map_err(|error| {
                        Error::engine(format!(
                            "authority act cut cannot read in-window annotation.target.set payload: {error}"
                        ))
                    })?;
                if let Some(blob_id) = parsed.blob_id {
                    if !blob_id.is_empty() {
                        referenced.insert(blob_id);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(referenced)
}

/// Pull the referenced blobs by primary key and refuse the cut if any is
/// missing or nonportable. An empty reference set yields an empty section
/// without touching the table.
async fn read_blobs_section_on(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Section> {
    let referenced = referenced_blob_ids_on(conn, from_exclusive_act, to_inclusive_act).await?;
    if referenced.is_empty() {
        return crate::interchange::export_where_section(conn, "blobs", "0", &[]).await;
    }

    let payload = serde_json::to_string(&referenced.iter().collect::<Vec<_>>())?;
    let rows = sqlx::query(
        "SELECT id, storage_tier FROM blobs WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(&payload)
    .fetch_all(&mut *conn)
    .await?;

    let mut found = BTreeSet::new();
    for row in &rows {
        let id: String = row.try_get("id")?;
        let storage_tier: String = row.try_get("storage_tier")?;
        if storage_tier != "inline" {
            return Err(Error::engine(format!(
                "authority act cut cannot carry nonportable blob '{id}' with storage_tier '{storage_tier}'"
            )));
        }
        found.insert(id);
    }
    if let Some(missing) = referenced.iter().find(|id| !found.contains(*id)) {
        return Err(Error::engine(format!(
            "authority act cut references a missing blob: {missing}"
        )));
    }

    crate::interchange::export_where_section(
        conn,
        "blobs",
        "id IN (SELECT value FROM json_each(?))",
        &[SelectionBind::Text(payload)],
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{companion_selection, COMPANION_TABLES};
    use crate::schema::standby_classification::{
        StandbyTableKind, DERIVED_GLOBAL_TABLES, TABLE_CLASSIFICATIONS,
    };

    /// Every declared companion has a selection, and an unknown table is a
    /// fail-closed error rather than a panic. `blobs` is dispatched separately
    /// by `read_companion_section_on`, so `companion_selection` itself does not
    /// know it and refuses it here.
    #[test]
    fn companion_selection_is_total_and_fails_closed_on_unknown_tables() {
        for table in COMPANION_TABLES.iter().filter(|table| **table != "blobs") {
            assert!(
                companion_selection(table, 0, 1).is_ok(),
                "companion {table} has no selection"
            );
        }
        assert!(companion_selection("blobs", 0, 1).is_err());
        assert!(companion_selection("not_a_companion", 0, 1).is_err());
    }

    /// The closure inventory is the classification, not a parallel list: a new
    /// or removed `ImmutableCanonicalCompanion` fails closed here, and a
    /// companion may never also be act-stamped. `DerivedGlobal` stays empty.
    #[test]
    fn companion_inventory_matches_the_classification() {
        let classified: BTreeSet<&str> = TABLE_CLASSIFICATIONS
            .iter()
            .filter(|(_, kind)| *kind == StandbyTableKind::ImmutableCanonicalCompanion)
            .map(|(table, _)| *table)
            .collect();
        let declared: BTreeSet<&str> = COMPANION_TABLES.iter().copied().collect();
        assert_eq!(
            classified, declared,
            "companion closure inventory drifted from the standby classification"
        );
        assert_eq!(
            COMPANION_TABLES.len(),
            declared.len(),
            "duplicate companion table in the closure inventory"
        );
        for table in COMPANION_TABLES {
            assert!(
                !crate::act::ACT_STAMPED_TABLES.contains(&table),
                "companion {table} is also act-stamped"
            );
            assert!(
                crate::interchange::SECTION_NAMES.contains(&table),
                "companion {table} is missing from canonical interchange"
            );
        }
        assert!(
            DERIVED_GLOBAL_TABLES.is_empty(),
            "DerivedGlobal must stay empty"
        );
    }
}
