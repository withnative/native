//! Meta event types — the rows of the authoritative `meta_events` log and the
//! payload shapes the meta projector folds (decision ba9f97e).
//!
//! The vocabulary tracks the EXISTING mutation sites rather than inventing a
//! model: vocabulary verbs across `crate::meta::vocabulary` (the propose ->
//! promote -> deprecate FSM, alias, metadata reorder, and guarded hard deletes)
//! and one across `crate::meta::schema_config`. Nothing here is speculative —
//! every type has a call site, and a mutation site without a type would be a
//! hole in the fold.
//!
//! Why a SEPARATE log rather than more types on the content log: the content
//! projector ends in `unknown event type`, so a meta event in `content_events`
//! breaks `replay()` — and with it historical `as_of` reads and the content
//! rebuild-and-diff — on the first row. And `content_events.record_id` is NOT
//! NULL, while meta mutations are not record-scoped. Both refusals are correct
//! and the separation keeps the record projector's zero schema dependency intact.

use serde::{Deserialize, Serialize};

/// The canonical meta event types the meta projector folds. CLOSED — anything
/// else is `unknown meta event type` at the fold, exactly as on the content tier.
pub const META_EVENT_TYPES: [&str; 11] = [
    "vocabulary.created",
    "vocabulary.deleted",
    "vocab_value.proposed",
    "vocab_value.promoted",
    "vocab_value.deprecated",
    "vocab_value.aliased",
    "vocab_value.reordered",
    "vocab_value.gloss_set",
    "vocab_value.metadata_set",
    "vocab_value.deleted",
    "schema_config.set",
];

/// A row as stored in / read from the `meta_events` log. `payload` is JSON text.
///
/// `subject_id` is the meta ROW the event acts on — a vocabulary id, a vocabulary
/// value id, or a `schema_config` row id. It is the meta tier's analogue of
/// `EventRow::record_id`, and the reason the two logs cannot share a table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaEventRow {
    pub seq: i64,
    pub id: String,
    pub subject_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Option<String>,
    pub actor: Option<String>,
    pub created_at: String,
}

// ---- Payload shapes (the JSON in meta_events.payload) ----------------------
//
// Every payload carries the full row state the fold needs, never a delta against
// what the projection currently holds: the fold must reproduce the row from the
// log alone, into a fresh database, without reading back what it is building.

/// Payload of `vocabulary.created`. `subject_id` carries the id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabularyCreatedPayload {
    pub name: String,
}

/// Payload of `vocab_value.proposed` — the whole row as first written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabValueProposedPayload {
    pub vocabulary_id: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gloss: Option<String>,
    /// 'proposed' for the lifecycle verb, 'active' for a seeded value — seeding
    /// legitimately skips the proposal step, and the fold must reproduce which
    /// one happened rather than assume.
    pub status: String,
    /// Fractional per-vocabulary ordering. Defaults preserve replay of events
    /// written before the field existed; value/id are deterministic tie-breaks.
    #[serde(default)]
    pub ordinal: f64,
    /// Progression meaning, distinct from the governance lifecycle `status`.
    #[serde(default = "default_terminality")]
    pub terminality: String,
    /// Versioned per-value metadata. Old events replay to the empty object.
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
}

fn default_terminality() -> String {
    "open".into()
}

fn default_metadata() -> serde_json::Value {
    serde_json::json!({})
}

/// Payload of `vocab_value.metadata_set`. The full JSON value is carried so
/// replay reproduces the stored bytes without consulting current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabValueMetadataSetPayload {
    pub metadata: serde_json::Value,
}

/// Payload of `vocab_value.reordered`. Reordering is deliberately its own
/// metadata event: it cannot promote, deprecate, alias, delete, or recreate the
/// value as a side effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabValueReorderedPayload {
    pub ordinal: f64,
}

/// Payload of `vocab_value.gloss_set`. Like reordering, glossing is its own
/// metadata event so that correcting what a value MEANS cannot promote,
/// deprecate, alias, delete, or re-propose it as a side effect — `propose_value`
/// is the only other writer of `gloss`, and it is closed to values that already
/// exist. `Option` is the full state of the column, not an "unset" marker: a
/// gloss cleared back to null must replay as null rather than as no-op.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabValueGlossSetPayload {
    pub gloss: Option<String>,
}

/// Payload of `vocab_value.aliased`: the canonical value this one redirects to.
/// Aliasing also deprecates the value, in the same fold step — an alias is a
/// redirect, not a live value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabValueAliasedPayload {
    pub alias_of: String,
}

/// Payload of `schema_config.set` — the full row, both layers.
///
/// One type covers the user-layer upsert and the pack-layer seed because events
/// are only ever appended for a write that actually LANDED: the pack path's
/// `INSERT OR IGNORE` appends nothing when the row already exists, so folding
/// this as an unconditional upsert reproduces both paths exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaConfigSetPayload {
    pub layer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub data: String,
    /// Full-row scope: absent/null is global; a record id anchors the row to
    /// that record's direct members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to_collection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_lineage: Option<String>,
}

// `vocabulary.deleted`, `vocab_value.promoted`, `vocab_value.deprecated` and
// `vocab_value.deleted` need no payload beyond `subject_id` — the verb plus the
// subject is the whole event. They are appended with an empty JSON object.
