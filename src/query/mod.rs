//! The READ layer (tool-surface finding 1; stage 1 of build task 094a59a).
//!
//! `store` is write-only and the projector only writes — this module is the
//! crate's projection-read API, the layer ~19 of the 26 shipping tools stand
//! on. Nothing here writes: every function takes `&Db` and reads projections
//! (`records`, `links`, `facet_values`), the authoritative `events` log, or the
//! meta tier — the tool layer never reaches into tables itself.
//!
//! Shape (docs/tool-surface.md, substrate section):
//!   - `read`     — record fetch + enrichment, batch with partial success
//!   - `tree`     — recursive containment walk, depth-limited, per-node counts
//!   - `pipeline` — the structured filter/traversal/count engine
//!   - `fts`      — FTS5 search (`records_fts`, stemmed) + name-prefix
//!     (`records_name_idx`, unstemmed sibling)
//!   - `sql`      — validated read-only SQL (SELECT-only, allowed relations)
//!   - `cascade`  — the pack → user `schema_config` resolver (finding 4)
//!   - `lifecycle` — governed interpretation of the shared lifecycle carrier
//!   - `events`   — the public reader of the authoritative log
//!   - `lineage`  — the run-key lineage walk (fbfaf25 §5.3), depth-capped and
//!     cycle-detecting. Not a tool at v1; it exists because `parent_key` is an
//!     unverified caller assertion and the walk over one must terminate
//!
//! Return types are `serde::Serialize` throughout: per decision 2231ad3,
//! tool handlers return structured values and transports render them — the read
//! layer returns data ready for that seam.
//!
//! Default visibility rule, applied uniformly: **searches and pipeline queries
//! exclude tombstoned records always, suggestion records unless explicitly
//! queried by kind, internal semantic Unit envelopes, and archived records unless asked**
//! (`archived` is engine-reserved precisely so default queries can dispatch on
//! it — schema contract). Direct fetch by id (`read`, `events`) returns what
//! you name, archived or not — pointing at a record IS asking for it.

pub mod activity;
pub mod cascade;
pub(crate) mod error;
pub mod events;
pub mod fts;
pub mod lens;
pub mod lifecycle;
pub mod lineage;
pub mod pipeline;
pub mod principal;
pub mod read;
pub mod sql;
pub mod sql_contract;
pub mod tree;
#[cfg(feature = "turso-local")]
pub(crate) mod turso_sql;
#[cfg(feature = "turso-local")]
pub(crate) mod turso_validate;

/// Run the exact Turso SQL admission parser used by the local provider.
///
/// This narrow seam lets the held qualification harness prove the shipping
/// parser without exposing its implementation module.
#[cfg(feature = "turso-local")]
#[doc(hidden)]
pub fn validate_turso_query_sql(sql: &str) -> crate::Result<()> {
    turso_validate::validate(sql)
}

// Executable evidence for Native task f40021f. This is deliberately test-only:
// the spike proves an ACL-safe `query_sql` seam without changing the shipping
// SQL contract before the authorization schema is ratified.
#[cfg(test)]
mod sql_acl_spike;

pub use principal::QueryPrincipal;

use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;

use crate::error::Result;

/// A `records` projection row, as read back. Field names match the DDL columns
/// (`record_type` serializes as `type`).
#[derive(Debug, Clone, Serialize)]
pub struct RecordRow {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
    pub body: Option<String>,
    pub home_id: Option<String>,
    /// Physical lifecycle carrier used by writes, filters and internal logic.
    /// Structured reads expose only `lifecycle_interpretation`.
    #[serde(skip)]
    pub lifecycle: Option<String>,
    pub lifecycle_interpretation: lifecycle::LifecycleInterpretation,
    pub owner_id: Option<String>,
    pub persistence: String,
    pub maturity: Option<String>,
    pub summary: Option<String>,
    pub last_activity_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    /// Immutable authored communication context. Present for every Message;
    /// historical Messages explicitly report `legacy_unknown` rather than
    /// borrowing identity from placement, audience or visibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub communication_origin: Option<serde_json::Value>,
    /// Destination-owned enrichment for an authenticated inbound Message.
    /// Absent for local and non-Message records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_provenance: Option<serde_json::Value>,
}

/// The `records` column list matching [`record_from_row`], for reuse in SELECTs.
pub(crate) const RECORD_COLUMNS: &str = "id, type, kind, name, body, home_id, \
     lifecycle, owner_id, persistence, maturity, summary, \
     last_activity_at, created_at, updated_at, deleted_at";

pub(crate) fn record_from_row(row: &SqliteRow) -> Result<RecordRow> {
    Ok(RecordRow {
        id: row.try_get("id")?,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        body: row.try_get("body")?,
        home_id: row.try_get("home_id")?,
        lifecycle: row.try_get("lifecycle")?,
        lifecycle_interpretation: lifecycle::LifecycleInterpretation::Absent(
            lifecycle::AbsentLifecycleInterpretation {
                axis: None,
                vocabulary: None,
            },
        ),
        owner_id: row.try_get("owner_id")?,
        persistence: row.try_get("persistence")?,
        maturity: row.try_get("maturity")?,
        summary: row.try_get("summary")?,
        last_activity_at: row.try_get("last_activity_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
        communication_origin: None,
        federation_provenance: None,
    })
}

pub(crate) async fn hydrate_communication_origin_on(
    conn: &mut sqlx::SqliteConnection,
    record: &mut RecordRow,
) -> Result<()> {
    if record.record_type != "Message" {
        return Ok(());
    }
    let row = sqlx::query(
        "SELECT status,origin_type,collection_id,direct_set_digest,participant_count
           FROM message_origin_state WHERE message_id=?",
    )
    .bind(&record.id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Err(crate::error::Error::engine(format!(
            "Message {} has no communication-origin projection state",
            record.id
        )));
    };
    let status: String = row.try_get("status")?;
    if status == "legacy_unknown" {
        record.communication_origin = Some(serde_json::json!({"type":"legacy_unknown"}));
        return Ok(());
    }
    match row.try_get::<Option<String>, _>("origin_type")?.as_deref() {
        Some("collection") => {
            let collection_id: String = row.try_get("collection_id")?;
            let context_key = format!("collection:{collection_id}");
            record.communication_origin = Some(serde_json::json!({
                "type":"collection",
                "collection_id":collection_id,
                "context_key":context_key,
            }));
        }
        Some("direct") => {
            let principals = sqlx::query_scalar::<_, String>(
                "SELECT principal_id FROM message_origin_principals
                  WHERE message_id=? ORDER BY principal_id",
            )
            .bind(&record.id)
            .fetch_all(&mut *conn)
            .await?;
            let stored_digest: String = row.try_get("direct_set_digest")?;
            let stored_count: i64 = row.try_get("participant_count")?;
            let digest = crate::events::direct_origin_set_digest(&principals);
            if stored_count != principals.len() as i64 || stored_digest != digest {
                return Err(crate::error::Error::engine(format!(
                    "Message {} has inconsistent direct communication-origin projection",
                    record.id
                )));
            }
            let context_key = crate::events::direct_origin_context_key(&principals);
            record.communication_origin = Some(serde_json::json!({
                "type":"direct",
                "principals":principals,
                "context_key":context_key,
            }));
        }
        _ => {
            return Err(crate::error::Error::engine(format!(
                "Message {} has invalid declared communication-origin state",
                record.id
            )));
        }
    }
    Ok(())
}

pub(crate) async fn hydrate_communication_origin_in_pool(
    pool: &sqlx::SqlitePool,
    record: &mut RecordRow,
) -> Result<()> {
    let mut conn = pool.acquire().await?;
    hydrate_communication_origin_on(&mut conn, record).await
}

impl RecordRow {
    /// Replace the safe unhydrated absence with the effective governed view.
    pub(crate) fn hydrate_lifecycle(&mut self, interpreter: &lifecycle::LifecycleInterpreter) {
        self.lifecycle_interpretation = interpreter.interpret(
            &self.record_type,
            self.kind.as_deref(),
            self.home_id.as_deref(),
            self.lifecycle.as_deref(),
        );
    }
}

pub(crate) async fn hydrate_federation_provenance_on(
    conn: &mut sqlx::SqliteConnection,
    record: &mut RecordRow,
) -> Result<()> {
    if record.record_type != "Message" {
        return Ok(());
    }
    let row = sqlx::query(
        "SELECT e.seq AS local_sequence,e.id AS source_event_id,
                s.origin_database_id,s.source_seq,s.source_record_id,
                s.source_principal,s.source_fingerprint,
                p.source_account_token,p.source_created_at,p.payload_digest,
                p.envelope_id,p.envelope_digest,d.relay_state,d.ingest_state,
                d.received_at,d.sender_state,d.sender_record_id,d.display_hint,
                sender_record.name AS sender_local_name
           FROM destination_message_ingest d
           JOIN replicated_message_provenance p ON p.source_event_id=d.source_event_id
           JOIN content_event_sources s ON s.event_id=p.source_event_id
           JOIN content_events e ON e.id=p.source_event_id
           LEFT JOIN records sender_record ON sender_record.id=d.sender_record_id
          WHERE d.message_id=?",
    )
    .bind(&record.id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(()) };
    let reference_rows = sqlx::query(
        "SELECT reference_id,relationship,target_origin_db_id,target_record_id,
                target_binding,display_label,source_digest,resolved_local_id
           FROM replicated_message_references
          WHERE source_message_id=? ORDER BY reference_id",
    )
    .bind(&record.id)
    .fetch_all(&mut *conn)
    .await?;
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for reference in reference_rows {
        let local_id: Option<String> = reference.try_get("resolved_local_id")?;
        let value = serde_json::json!({
            "reference_id": reference.try_get::<String, _>("reference_id")?,
            "relationship": reference.try_get::<String, _>("relationship")?,
            "target": {
                "origin_database_id": reference.try_get::<String, _>("target_origin_db_id")?,
                "record_id": reference.try_get::<String, _>("target_record_id")?,
                "binding": reference.try_get::<Option<String>, _>("target_binding")?,
            },
            "display_label": reference.try_get::<Option<String>, _>("display_label")?,
            "source_digest": reference.try_get::<String, _>("source_digest")?,
            "local_record_id": local_id,
        });
        if value["local_record_id"].is_null() {
            unresolved.push(value);
        } else {
            resolved.push(value);
        }
    }
    record.federation_provenance = Some(serde_json::json!({
        "direction": "inbound",
        "inert": true,
        "origin": {
            "database_id": row.try_get::<String, _>("origin_database_id")?,
            "record_id": row.try_get::<String, _>("source_record_id")?,
            "event_id": row.try_get::<String, _>("source_event_id")?,
            "sequence": row.try_get::<i64, _>("source_seq")?,
            "timestamp": row.try_get::<String, _>("source_created_at")?,
            "principal": row.try_get::<String, _>("source_principal")?,
            "account_token": row.try_get::<String, _>("source_account_token")?,
            "fingerprint": row.try_get::<String, _>("source_fingerprint")?,
            "payload_digest": row.try_get::<String, _>("payload_digest")?,
            "envelope_id": row.try_get::<String, _>("envelope_id")?,
            "envelope_digest": row.try_get::<String, _>("envelope_digest")?,
        },
        "destination": {
            "relay_state": row.try_get::<String, _>("relay_state")?,
            "ingest_state": row.try_get::<String, _>("ingest_state")?,
            "received_at": row.try_get::<String, _>("received_at")?,
            "local_sequence": row.try_get::<i64, _>("local_sequence")?,
        },
        "sender": {
            "state": row.try_get::<String, _>("sender_state")?,
            "trusted_local_record_id": row.try_get::<Option<String>, _>("sender_record_id")?,
            "trusted_local_name": row.try_get::<Option<String>, _>("sender_local_name")?,
            "display_hint": row.try_get::<Option<String>, _>("display_hint")?,
        },
        "references": { "resolved": resolved, "unresolved": unresolved },
    }));
    Ok(())
}

pub(crate) async fn hydrate_federation_provenance_in_pool(
    pool: &sqlx::SqlitePool,
    record: &mut RecordRow,
) -> Result<()> {
    let mut conn = pool.acquire().await?;
    hydrate_federation_provenance_on(&mut conn, record).await
}

/// A `links` row, as read back.
#[derive(Debug, Clone, Serialize)]
pub struct LinkRow {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    pub note: Option<String>,
    pub created_at: String,
}

pub(crate) fn link_from_row(row: &SqliteRow) -> Result<LinkRow> {
    Ok(LinkRow {
        id: row.try_get("id")?,
        source_id: row.try_get("source_id")?,
        target_id: row.try_get("target_id")?,
        relationship: row.try_get("relationship")?,
        note: row.try_get("note")?,
        created_at: row.try_get("created_at")?,
    })
}

/// An open/pack facet on a record (a `facet_values` row; spine facets live as
/// columns on [`RecordRow`], not here).
#[derive(Debug, Clone, Serialize)]
pub struct FacetValueRow {
    pub key: String,
    pub value: Option<serde_json::Value>,
    pub vocab_ref: Option<String>,
    /// This facet's compare-and-set token — `MAX(event_seq)` over the record's
    /// observations of this key, in the one encoding
    /// `artifact_intents::FacetVersion` defines and the write path parses.
    /// Without it no caller could populate an artifact invocation's `observed`
    /// preconditions. Absent for reads that project no observation series
    /// (historical valid-time views).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// The SQL fragment excluding archived records: no `archived` facet row.
/// (`archived` only ever holds 'true' — the projector rejects anything else —
/// so presence alone is the test.)
pub(crate) const NOT_ARCHIVED: &str = "NOT EXISTS (SELECT 1 FROM facet_values av \
     WHERE av.record_id = r.id AND av.key = 'archived')";

/// Governed Annotation families are not ordinary discovery results.
/// Their governed identity predicates include active aliases and exclude
/// quarantined lookalikes. Opt-ins stay independent so querying one hidden
/// family never exposes the other.
pub const SUGGESTION_KIND: &str = crate::generated::kinds::CoreKind::AnnotationSuggestion.token();
pub const CITATION_KIND: &str = crate::generated::kinds::CoreKind::AnnotationCitation.token();
pub const COMMENT_KIND: &str = crate::generated::kinds::CoreKind::AnnotationComment.token();
pub const ATTRIBUTION_KIND: &str = "attribution";

pub(crate) fn suggestion_predicate(record_alias: &str) -> String {
    crate::generated::kinds::CoreKind::AnnotationSuggestion.sql_matches(record_alias)
}

pub(crate) fn citation_predicate(record_alias: &str) -> String {
    crate::generated::kinds::CoreKind::AnnotationCitation.sql_matches(record_alias)
}

pub(crate) fn comment_predicate(record_alias: &str) -> String {
    crate::generated::kinds::CoreKind::AnnotationComment.sql_matches(record_alias)
}

pub(crate) fn attribution_predicate(record_alias: &str) -> String {
    crate::meta::kind::sql_matches_identity(
        record_alias,
        "Annotation",
        "vv:voc:kind:Annotation:attribution",
    )
}

pub(crate) fn acknowledgement_predicate(record_alias: &str) -> String {
    crate::generated::kinds::CoreKind::AnnotationAcknowledgement.sql_matches(record_alias)
}

pub(crate) fn not_attribution_predicate(record_alias: &str) -> String {
    format!("NOT ({})", attribution_predicate(record_alias))
}

pub(crate) fn not_acknowledgement_predicate(record_alias: &str) -> String {
    format!("NOT ({})", acknowledgement_predicate(record_alias))
}

pub(crate) fn not_suggestion_predicate(record_alias: &str) -> String {
    format!("NOT ({})", suggestion_predicate(record_alias))
}

pub(crate) fn not_citation_predicate(record_alias: &str) -> String {
    format!("NOT ({})", citation_predicate(record_alias))
}

pub(crate) fn not_comment_predicate(record_alias: &str) -> String {
    format!("NOT ({})", comment_predicate(record_alias))
}

pub(crate) fn hidden_visibility_predicate(
    record_alias: &str,
    include_suggestions: bool,
    include_citations: bool,
    include_comments: bool,
) -> String {
    let mut predicates = Vec::new();
    if !include_suggestions {
        predicates.push(not_suggestion_predicate(record_alias));
    }
    if !include_citations {
        predicates.push(not_citation_predicate(record_alias));
    }
    if !include_comments {
        predicates.push(not_comment_predicate(record_alias));
    }
    // Attribution claims have only dedicated interpretation reads in V1.
    // Unlike suggestion/citation/comment, no generic query opt-in exposes
    // their IDs or lets them distort ordinary browse and child counts.
    predicates.push(not_attribution_predicate(record_alias));
    // Acknowledgements are authoritative obligation evidence consumed through
    // Message state. They have no generic discovery opt-in: exposing them
    // would leak a hidden recipient action and distort browse/child counts.
    predicates.push(not_acknowledgement_predicate(record_alias));
    // Unit envelopes remain directly addressable and available through the
    // freshness API, but they are not ordinary workspace artefacts.  Keeping
    // them out of generic browse/search/query results is the provisional
    // presentation half of the record-envelope architecture.
    predicates.push(format!(
        "NOT EXISTS (SELECT 1 FROM semantic_units _su WHERE _su.unit_id = {record_alias}.id)"
    ));
    // Hide the identity envelope even at an event prefix between its
    // record.created and unit.created.v1 events, when a historical replay has
    // not projected the semantic identity row yet.
    predicates.push(format!(
        "NOT ({record_alias}.type = 'Entity' AND {record_alias}.kind IS 'semantic-unit')"
    ));
    if predicates.is_empty() {
        "1".into()
    } else {
        predicates.join(" AND ")
    }
}

pub(crate) fn not_hidden_predicate(record_alias: &str) -> String {
    hidden_visibility_predicate(record_alias, false, false, false)
}
