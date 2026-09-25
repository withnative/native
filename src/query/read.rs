//! `query::read` — record fetch + enrichment. Backs tools 6 (`get_record`),
//! 10 (`render_record`), 14 (`resolve_facets`), and every tool that needs a
//! record back.
//!
//! Batch is **partial-success by contract** (decision 2231ad3, workbench-driven):
//! a missing id yields a `NotFound` item in place, never a failed batch.
//!
//! Enrichment is **bounded by default** (decision 5055a9c): the list-valued
//! sections carry a window plus the true total, in the same shape
//! `tree::TreeNode` already uses — a bounded payload plus the count that says
//! what it is a window onto. **`offset` is unbounded, so paging reaches
//! everything** — that is the recovery path, and it does not depend on any tool
//! that has not shipped. `manage_links` (registered) reads links unwindowed;
//! `query_record` will be the nicer bulk listing when stage 5 lands, and is not
//! something a caller can be sent to today.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::Value;
use sqlx::{Row, Sqlite, Transaction};

use super::lens::ReadLens;
use super::{
    link_from_row, record_from_row, tree, FacetValueRow, LinkRow, RecordRow, RECORD_COLUMNS,
};
use crate::db::Db;
use crate::error::Result;
use crate::schema::ARCHIVED_FACET_KEY;

use super::error::contract_violation;

/// Default window on each list-valued enrichment. 200 deliberately matches the
/// workbench spec's client-side windowing rule (56642c0 §3.2) so client and
/// server agree on one number rather than two.
pub const DEFAULT_ENRICH_LIMIT: i64 = 200;

/// Hard ceiling on an explicit `limit`. This is what makes the section
/// *bounded* rather than merely *defaulted*: a caller cannot opt back into an
/// unbounded payload. It costs no reach — `offset` has no ceiling, so paging
/// past this is always available. What it forbids is one enormous response.
pub const MAX_ENRICH_LIMIT: i64 = 1_000;
/// Suggestion summaries are subsequently hydrated through `get_record`, whose
/// input batch is capped at 100 ids. Keep one suggestion page compatible with
/// that boundary.
pub const MAX_SUGGESTIONS_LIMIT: i64 = 100;
pub const DEFAULT_SUGGESTIONS_LIMIT: i64 = 100;
pub const MAX_CITATIONS_LIMIT: i64 = 100;
pub const DEFAULT_CITATIONS_LIMIT: i64 = 100;
pub const MAX_COMMENTS_LIMIT: i64 = 100;
pub const DEFAULT_COMMENTS_LIMIT: i64 = 50;

/// A lightweight child entry on an enriched record. `archived` is surfaced so
/// tools can apply the default visibility rule without a second query.
#[derive(Debug, Clone, Serialize)]
pub struct ChildSummary {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
    pub archived: bool,
}

/// A comment window carries the authored utterance and thread state directly;
/// clients must not issue one full-record read per row merely to render a
/// thread. `summary` is reserved for a resolved root's resolution prose.
#[derive(Debug, Clone, Serialize)]
pub struct CommentSummary {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
    pub body: String,
    #[serde(skip)]
    pub lifecycle: Option<String>,
    #[serde(skip)]
    home_id: Option<String>,
    pub lifecycle_interpretation: super::lifecycle::LifecycleInterpretation,
    pub summary: Option<String>,
    pub owner_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub archived: bool,
    /// Direct roots carry their own target. Replies carry the root comment's
    /// resolved target context without copying selector rows into reply state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::citations::AnnotationTargetView>,
    /// Who produced the utterance currently being read, on every axis the
    /// engine can separate.
    ///
    /// `owner_id` above is STANDING — whose workspace this sits in. It is not
    /// the speaker, and a thread that renders it as one collapses distinct
    /// runs into a single participant that appears to argue with itself. This
    /// field is the speaker; it is hydrated by the read path that knows the
    /// viewer, so it is absent from raw projection reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contribution: Option<crate::contribution::ContributionProvenance>,
}

/// How much of each list-valued enrichment to return.
///
/// Children and links are windowed independently because they are unbounded
/// for different reasons — children by how wide a container is authored, links
/// by how often a record is referenced — and a caller usually wants to page
/// one, not both.
#[derive(Debug, Clone, Copy)]
pub struct EnrichOptions {
    pub children_limit: i64,
    pub children_offset: i64,
    pub links_limit: i64,
    pub links_offset: i64,
    /// Include `kind:suggestion` summaries in the separate `suggestions`
    /// collection. Ordinary child paging remains unchanged, and the separate
    /// `suggestion_count` is always reported.
    pub include_suggestions: bool,
    pub suggestions_limit: i64,
    pub suggestions_offset: i64,
    pub include_citations: bool,
    pub citations_limit: i64,
    pub citations_offset: i64,
    pub include_comments: bool,
    pub comments_limit: i64,
    pub comments_offset: i64,
}

impl Default for EnrichOptions {
    fn default() -> Self {
        EnrichOptions {
            children_limit: DEFAULT_ENRICH_LIMIT,
            children_offset: 0,
            links_limit: DEFAULT_ENRICH_LIMIT,
            links_offset: 0,
            include_suggestions: false,
            suggestions_limit: DEFAULT_SUGGESTIONS_LIMIT,
            suggestions_offset: 0,
            include_citations: false,
            citations_limit: DEFAULT_CITATIONS_LIMIT,
            citations_offset: 0,
            include_comments: false,
            comments_limit: DEFAULT_COMMENTS_LIMIT,
            comments_offset: 0,
        }
    }
}

impl EnrichOptions {
    /// Reject out-of-range windows rather than clamping them. A caller that
    /// asks for 5,000 children has a wrong model of this call; silently
    /// handing back 1,000 would let it ship that model.
    fn validate(&self) -> Result<()> {
        for (name, limit, offset) in [
            ("children", self.children_limit, self.children_offset),
            ("links", self.links_limit, self.links_offset),
            (
                "suggestions",
                self.suggestions_limit,
                self.suggestions_offset,
            ),
            ("citations", self.citations_limit, self.citations_offset),
            ("comments", self.comments_limit, self.comments_offset),
        ] {
            if limit < 0 {
                return Err(contract_violation(format!("{name} limit must be >= 0")));
            }
            let maximum = if matches!(name, "suggestions" | "citations" | "comments") {
                MAX_SUGGESTIONS_LIMIT
            } else {
                MAX_ENRICH_LIMIT
            };
            if limit > maximum {
                return Err(contract_violation(format!(
                    "{name} limit must be <= {maximum} \
                     (page with {name}_offset — offset is unbounded)"
                )));
            }
            if offset < 0 {
                return Err(contract_violation(format!("{name} offset must be >= 0")));
            }
        }
        Ok(())
    }
}

/// Encode a facet's observation sequence as the host-issued version token.
///
/// One encoding, produced here and parsed by the artifact write path, so a
/// caller can only ever echo back a token the host itself issued.
fn facet_version(event_seq: Option<i64>) -> Option<String> {
    event_seq.map(|event_seq| {
        native_artifact_runtime::artifact_intents::FacetVersion::Observation { event_seq }.encode()
    })
}

/// Opt-in oldest/newest visible-event attribution for record bylines.
///
/// Both ends are metadata-shaped history events (the same shape
/// `get_history` with `detail: metadata` returns), or null when the record
/// has no visible event on that end. The key's presence on an enriched
/// record is the capability signal: absent means the caller did not opt in
/// (or the reader never serves the projection), never "no history".
#[derive(Debug, Clone, Serialize)]
pub struct HistorySummary {
    pub oldest: Option<Value>,
    pub latest: Option<Value>,
}

/// One aggregated outgoing body mention: a distinct
/// `(authored_reference, lookup_key, form)` from the record's current body,
/// with its occurrence count and its read-time resolution against the
/// caller-visible records.
///
/// Resolution is deliberately read-time and caller-relative, never stored: a
/// short reference can be ambiguous now and unique later, and resolving it at
/// write time would freeze a fact about the world into a function of the body.
/// Only *visible* candidates participate, so an invisible record sharing the
/// prefix never turns a unique reference into an ambiguity — the same
/// anti-oracle rule `record_ref` enforces.
#[derive(Debug, Clone, Serialize)]
pub struct MentionOut {
    /// The reference exactly as authored in the body.
    pub authored_reference: String,
    /// `authored_reference` lowercased, the key matched against record ids.
    pub lookup_key: String,
    /// Lexical form: `url`, `wiki_hex`, `wiki_name` or `bare_hex`.
    pub form: String,
    /// How many times this reference occurs in the record's current body.
    pub occurrence_count: i64,
    pub resolution: MentionResolution,
}

/// The read-time resolution of one outgoing mention, against caller-visible
/// records only.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MentionResolution {
    /// No visible record matched the reference.
    Unresolved,
    /// Exactly one visible record matched; named because it is visible.
    Resolved { id: String, name: String },
    /// More than one visible record matched. Only the count is disclosed; the
    /// candidates are never named, so an ambiguity is not an enumeration.
    Ambiguous { visible_candidate_count: i64 },
}

/// One aggregated incoming body mention: a visible source record whose body
/// referenced this record, with the total occurrence count and the distinct
/// authored references that matched.
#[derive(Debug, Clone, Serialize)]
pub struct MentionIn {
    pub source_id: String,
    pub source_name: String,
    pub occurrence_count: i64,
    /// Distinct authored references from that source that matched, sorted.
    pub authored_references: Vec<String>,
    /// Distinct lexical forms from that source, sorted.
    pub forms: Vec<String>,
}

/// One record with its enrichments: open facets, links both directions,
/// live children, and the ancestor chain (root first).
///
/// `children`, `suggestions`, `links_out` and `links_in` are **windows**; the
/// matching `*_count` field is the true total, so a truncated section is always
/// visible as such. `facets` and `ancestors` are unwindowed by design — a record's
/// facets are bounded by what was authored on it, and an ancestor chain by
/// tree depth. Neither grows with the size of the brain.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedRecord {
    #[serde(flatten)]
    pub record: RecordRow,
    /// True iff the engine-reserved `archived` facet is set.
    pub archived: bool,
    /// Safe summary facts for ACL-aware navigation. Neither field exposes a
    /// policy anchor or a hidden ancestor.
    pub custody_boundary: bool,
    pub containment_path_visible: bool,
    /// Derived from anchored schema declarations; never stored on the record.
    pub bears_shape: bool,
    /// Runtime interpretation of the stored kind. Unknown/proposed/deprecated
    /// values remain readable but report `quarantined: true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_governance: Option<crate::meta::kind::KindResolution>,
    /// Open/pack facets (spine facets are columns on the record itself).
    pub facets: Vec<FacetValueRow>,
    pub links_out: Vec<LinkRow>,
    /// Total outbound links, whether or not `links_out` is a window onto them.
    pub links_out_count: i64,
    pub links_in: Vec<LinkRow>,
    /// Total inbound links, whether or not `links_in` is a window onto them.
    pub links_in_count: i64,
    /// Outgoing body mentions, aggregated by authored reference and resolved
    /// read-time against caller-visible records. `None` means the adapter does
    /// not serve the mention projection (or the record has no current mention),
    /// so the key is absent rather than empty — the same capability contract
    /// `superseded_by` documents. Populated by the visibility-filtering layer,
    /// never by a raw projection reader.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions_out: Option<Vec<MentionOut>>,
    /// Total distinct outgoing mention groups, whether or not `mentions_out`
    /// is a window onto them. Caller-independent: the authored references come
    /// from the record's own body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions_out_count: Option<i64>,
    /// Incoming body mentions from caller-visible sources, ordered and windowed
    /// deterministically. Counts are computed AFTER visibility filtering, so a
    /// hidden source never moves a total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions_in: Option<Vec<MentionIn>>,
    /// Total distinct incoming source records, caller-relative and counted
    /// after visibility filtering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions_in_count: Option<i64>,
    /// Incoming `supersedes` links, disclosed — never derived from the
    /// `links_in` window above, which is a page the caller sized. The signal
    /// is the incoming link alone: `maturity: superseded` is a separate
    /// authored signal and is not ORed in here. Absent (not empty) when no
    /// live record names this one as superseded, and absent on backends that
    /// do not serve this projection. Viewer-relative naming (which successors
    /// are named vs merely counted) is applied by the visibility-filtering
    /// layer, not here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<SupersededBy>,
    pub children: Vec<ChildSummary>,
    /// Total live children, whether or not `children` is a window onto them —
    /// the same contract `tree::TreeNode::child_count` already carries.
    pub child_count: i64,
    /// Suggestion children are a separate opt-in collection so their paging
    /// never distorts the ordinary children window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestions: Option<Vec<ChildSummary>>,
    /// Total live suggestion children, independent of the visible child
    /// window. This lets default reads disclose hidden escrow without mixing it
    /// into ordinary containment navigation.
    pub suggestion_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub citations: Option<Vec<ChildSummary>>,
    pub citation_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<Vec<CommentSummary>>,
    pub comment_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::citations::AnnotationTargetView>,
    /// The same generic contribution projection comments consume. Records are
    /// the reason it is generic: nothing here is comment-shaped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contribution: Option<crate::contribution::ContributionProvenance>,
    /// Opt-in oldest/newest visible-event attribution for bylines. `None`
    /// (key absent) means the caller did not opt in; `Some` with null ends
    /// means opted in but no visible event exists on that end. Populated by
    /// the `get_record` tool layer, never by raw projection readers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_summary: Option<HistorySummary>,
    /// Containment chain, root first, excluding the record itself.
    pub ancestors: Vec<tree::AncestorEntry>,
    /// Advisory freshness projection: present only when at least one
    /// freshness-kernel Occurrence is bound to this record. Served by the
    /// SQLite `get_record` live path alone; every other reader (historical
    /// lens, `query_record`, `render_record`, portable adapters) leaves this
    /// `None` so the key stays absent from their output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<crate::freshness::FreshnessQualification>,
}

/// One item of a batch get — partial success, in input order.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchGetItem {
    Found(Box<EnrichedRecord>),
    NotFound {
        id: String,
    },
    /// Honest absence (`docs/honest-absence-contract.md` §5a): the record is
    /// not held by this replica, which is a different fact from not existing.
    /// A caller that collapses this into `NotFound` will create the duplicate
    /// record this contract exists to prevent.
    ///
    /// Unreachable until record-level subsets ship — a time window leaves the
    /// projection complete, so every record that exists is held. The variant
    /// lands ahead of them so the wire vocabulary a caller must handle is
    /// fixed before anything can produce it, and so that a caller matching
    /// exhaustively fails to compile rather than silently mis-reading it.
    NotHeld {
        id: String,
    },
}

/// One named successor in a [`SupersededBy`] disclosure. `display_reference`
/// is absent, never null, when there is no short reference to give — a
/// renderer degrades to the full id there.
#[derive(Debug, Clone, Serialize)]
pub struct SupersededByItem {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
}

/// The incoming-`supersedes` disclosure on an enriched record: up to
/// [`MAX_SUPERSEDED_ITEMS`] named successors plus the true total, in the same
/// window-plus-total shape the link and children sections already use. An
/// invisible successor is counted in `total_count` but never named in
/// `items` — that redaction happens in the visibility-filtering layer.
#[derive(Debug, Clone, Serialize)]
pub struct SupersededBy {
    pub items: Vec<SupersededByItem>,
    pub total_count: i64,
}

/// Cap on named successors. Succession is normally singular; the cap exists
/// so convergent corrections stay bounded rather than paged.
pub const MAX_SUPERSEDED_ITEMS: usize = 3;

/// Incoming `supersedes` successors for a whole set of records in one indexed
/// statement, grouped by target id. Each group's order is the disclosure
/// order (`created_at`, then `source_id` — the same stable order the
/// attribution successor lookup already uses); only targets with at least one
/// live successor appear, and tombstoned replacements disclose nothing. One
/// statement rather than one per row: the same batching rule the containment
/// walk documents in `tree.rs` — the row sets annotated here are already
/// windowed, so nothing fetched is discarded. Never a filter over a caller's
/// `links_in` window, so paging links cannot hide a successor.
pub(crate) async fn load_superseded_by_batch<'e, E>(
    executor: E,
    ids: &[String],
) -> Result<HashMap<String, Vec<(String, String)>>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let mut grouped: HashMap<String, Vec<(String, String)>> = HashMap::new();
    if ids.is_empty() {
        return Ok(grouped);
    }
    let ids_json = serde_json::to_string(ids)?;
    let rows = sqlx::query(
        "SELECT l.target_id, s.id, s.name FROM links l JOIN records s ON s.id = l.source_id
          WHERE l.relationship = 'supersedes' AND s.deleted_at IS NULL
            AND l.target_id IN (SELECT value FROM json_each(?))
          ORDER BY l.target_id, l.created_at, l.source_id",
    )
    .bind(ids_json)
    .fetch_all(executor)
    .await?;
    for row in rows {
        let target: String = row.try_get("target_id")?;
        let successor: (String, String) = (row.try_get("id")?, row.try_get("name")?);
        grouped.entry(target).or_default().push(successor);
    }
    Ok(grouped)
}

/// Truncate an ordered successor list to the named disclosure window. This
/// always runs AFTER visibility filtering at the emission site, so an
/// invisible head never hides a nameable tail. Totals are the caller's job:
/// count the full set, never the truncated window.
pub(crate) fn truncate_superseded_items(
    successors: Vec<(String, String)>,
) -> Vec<SupersededByItem> {
    successors
        .into_iter()
        .take(MAX_SUPERSEDED_ITEMS)
        .map(|(id, name)| SupersededByItem {
            id,
            name,
            display_reference: None,
        })
        .collect()
}

/// Incoming `supersedes` successors of one record, via the batch loader.
/// Returns `None` — absent, not empty — when nothing live names this record
/// as superseded. The single-record read paths have no viewer to filter
/// against, so the window applies here; the visibility-filtering layer
/// reloads the full set and re-truncates after filtering (see
/// `truncate_superseded_items`).
pub(crate) async fn load_superseded_by<'e, E>(executor: E, id: &str) -> Result<Option<SupersededBy>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let mut grouped =
        load_superseded_by_batch(executor, std::slice::from_ref(&id.to_owned())).await?;
    let Some(successors) = grouped.remove(id) else {
        return Ok(None);
    };
    let total_count = successors.len() as i64;
    let items = truncate_superseded_items(successors);
    Ok(Some(SupersededBy { items, total_count }))
}

// ---------------------------------------------------------------------------
// record_mentions read model
//
// The projection stores only lexical evidence (authored reference, lookup key,
// form). Targets are resolved here, at read time, against caller-visible
// records — never stored. Two consequences follow and are load-bearing:
//
//  * resolution is a function of the current visible namespace, so it is
//    computed in the visibility-filtering layer, not by a raw reader; and
//  * only visible candidates participate, so a hidden record sharing a prefix
//    can never turn a unique reference into an ambiguity.
// ---------------------------------------------------------------------------

/// The addressable shape of an authored lookup key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MentionLookupPlan {
    /// A full canonical (dashed, lowercase) UUID.
    Exact(String),
    /// A canonical dashed prefix, matched by range scan like `record_ref`.
    Prefix(String),
    /// Not addressable by any prefix or exact form.
    Unaddressable,
}

fn undash_lower(input: &str) -> Option<String> {
    let mut hex = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'-' => {}
            b'0'..=b'9' | b'a'..=b'f' => hex.push(byte as char),
            b'A'..=b'F' => hex.push(byte.to_ascii_lowercase() as char),
            _ => return None,
        }
    }
    Some(hex)
}

/// Re-insert the canonical UUID dashes at positions 8, 12, 16 and 20 — the
/// exact transform `record_ref::canonical_prefix` applies.
fn dash_hex_prefix(hex: &str) -> String {
    let mut out = String::with_capacity(hex.len() + 4);
    for (index, character) in hex.chars().enumerate() {
        if matches!(index, 8 | 12 | 16 | 20) {
            out.push('-');
        }
        out.push(character);
    }
    out
}

/// Classify an authored lookup key against the addressable record namespace,
/// mirroring `record_ref`'s shape gates.
pub(crate) fn mention_lookup_plan(lookup_key: &str) -> MentionLookupPlan {
    let Some(hex) = undash_lower(lookup_key) else {
        return MentionLookupPlan::Unaddressable;
    };
    let lowered = lookup_key.to_ascii_lowercase();
    if crate::mcp::record_ref::is_canonical_uuid(&lowered) {
        return MentionLookupPlan::Exact(lowered);
    }
    if (6..32).contains(&hex.len()) {
        return MentionLookupPlan::Prefix(dash_hex_prefix(&hex));
    }
    MentionLookupPlan::Unaddressable
}

/// Every authored lookup key that would reverse-resolve to `record_id` (a
/// canonical dashed UUID): its exact form and each undashed/dashed prefix of
/// length 6..=31, the same range `record_ref` accepts as a prefix. Undashed and
/// canonical-dashed forms are both emitted because the scanner preserves the
/// authored dashes. Empty for ids outside the canonical UUID namespace.
pub(crate) fn mention_incoming_lookup_keys(record_id: &str) -> Vec<String> {
    let Some(hex) = undash_lower(record_id) else {
        return Vec::new();
    };
    let lowered = record_id.to_ascii_lowercase();
    if hex.len() != 32 || !crate::mcp::record_ref::is_canonical_uuid(&lowered) {
        return Vec::new();
    }
    let mut keys = vec![lowered];
    for len in 6..32usize {
        let part = &hex[..len];
        keys.push(part.to_string());
        let dashed = dash_hex_prefix(part);
        if dashed != part {
            keys.push(dashed);
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

/// One raw outgoing group straight from the projection.
#[derive(Debug, Clone)]
pub(crate) struct RawMentionOut {
    pub authored_reference: String,
    pub lookup_key: String,
    pub form: String,
    pub occurrence_count: i64,
}

pub(crate) async fn mention_out_groups<'e, E>(
    executor: E,
    source_id: &str,
) -> Result<Vec<RawMentionOut>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let rows = sqlx::query(
        "SELECT authored_reference, lookup_key, form, COUNT(*) AS occurrence_count
           FROM record_mentions WHERE source_id = ?
          GROUP BY authored_reference, lookup_key, form
          ORDER BY lookup_key, form, authored_reference",
    )
    .bind(source_id)
    .fetch_all(executor)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(RawMentionOut {
                authored_reference: row.try_get("authored_reference")?,
                lookup_key: row.try_get("lookup_key")?,
                form: row.try_get("form")?,
                occurrence_count: row.try_get("occurrence_count")?,
            })
        })
        .collect()
}

/// Live canonical-UUID candidates for a dashed prefix. The half-open range plus
/// the `g` sentinel are the same index-friendly shape `record_ref::prefix_rows`
/// uses.
///
/// Deliberately **uncapped**, unlike `record_ref`'s bounded scan. `record_ref`
/// can cap because every candidate is raw: if a degenerate prefix ever had more
/// than the cap, the extra rows only make an already-ambiguous prefix
/// ambiguous. Here the result must be computed over *visible* candidates only,
/// and caller-chosen ids make many records sharing a prefix reachable — a hidden
/// block that sorts ahead of the one visible match would otherwise crowd it out
/// of a `LIMIT` and turn a resolved reference into a false `unresolved` (or a
/// false ambiguity), which is exactly the hidden-collision disclosure this slice
/// forbids. The scan is bounded in practice by the 6-hex prefix floor; the
/// reverse incoming query is likewise uncapped.
pub(crate) async fn mention_prefix_candidates<'e, E>(
    executor: E,
    prefix: &str,
) -> Result<Vec<String>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let upper = format!("{prefix}g");
    let rows = sqlx::query(
        "SELECT id FROM records
          WHERE id >= ? AND id < ? AND deleted_at IS NULL AND length(id) = 36
          ORDER BY id",
    )
    .bind(prefix)
    .bind(upper)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .iter()
        .map(|row| row.try_get::<String, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|id| crate::mcp::record_ref::is_canonical_uuid(id))
        .collect())
}

pub(crate) async fn mention_record_live<'e, E>(executor: E, id: &str) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM records WHERE id = ? AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(executor)
            .await?;
    Ok(found.is_some())
}

#[derive(Debug, Clone)]
pub(crate) struct RawMentionIn {
    pub source_id: String,
    pub source_name: String,
    pub authored_reference: String,
    pub form: String,
    pub occurrence_count: i64,
}

pub(crate) async fn mention_incoming_rows<'e, E>(
    executor: E,
    lookup_keys_json: &str,
) -> Result<Vec<RawMentionIn>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let rows = sqlx::query(
        "SELECT m.source_id AS source_id, r.name AS source_name,
                m.authored_reference AS authored_reference, m.form AS form,
                COUNT(*) AS occurrence_count
           FROM record_mentions m
           JOIN records r ON r.id = m.source_id
          WHERE m.lookup_key IN (SELECT value FROM json_each(?))
            AND r.deleted_at IS NULL
          GROUP BY m.source_id, m.authored_reference, m.form
          ORDER BY m.source_id, m.authored_reference, m.form",
    )
    .bind(lookup_keys_json)
    .fetch_all(executor)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(RawMentionIn {
                source_id: row.try_get("source_id")?,
                source_name: row.try_get("source_name")?,
                authored_reference: row.try_get("authored_reference")?,
                form: row.try_get("form")?,
                occurrence_count: row.try_get("occurrence_count")?,
            })
        })
        .collect()
}

pub(crate) async fn mention_names<'e, E>(
    executor: E,
    ids_json: &str,
) -> Result<HashMap<String, String>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let rows = sqlx::query(
        "SELECT id, name FROM records
          WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(ids_json)
    .fetch_all(executor)
    .await?;
    rows.iter()
        .map(|row| Ok((row.try_get("id")?, row.try_get("name")?)))
        .collect()
}

/// Mention evidence read from one projection, before authorization.
pub(crate) struct GatheredMentions {
    groups: Vec<RawMentionOut>,
    /// Candidate record ids per outgoing group (parallel to `groups`).
    candidates: Vec<Vec<String>>,
    incoming: Vec<RawMentionIn>,
}

impl GatheredMentions {
    /// Every record id whose visibility decides this read: outgoing resolution
    /// candidates plus incoming source records. One set-wise authorization fold
    /// covers the whole record.
    pub(crate) fn authorization_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.candidates.iter().flatten().cloned().collect();
        ids.extend(self.incoming.iter().map(|row| row.source_id.clone()));
        ids.sort();
        ids.dedup();
        ids
    }
}

/// Read all mention evidence for one record from the projection `conn`. Reads
/// only; no authorization decision is made here.
pub(crate) async fn gather_mentions(
    conn: &mut sqlx::SqliteConnection,
    record_id: &str,
) -> Result<GatheredMentions> {
    let groups = mention_out_groups(&mut *conn, record_id).await?;
    let mut candidates = Vec::with_capacity(groups.len());
    for group in &groups {
        let ids = match mention_lookup_plan(&group.lookup_key) {
            MentionLookupPlan::Exact(id) => {
                if mention_record_live(&mut *conn, &id).await? {
                    vec![id]
                } else {
                    Vec::new()
                }
            }
            MentionLookupPlan::Prefix(prefix) => {
                mention_prefix_candidates(&mut *conn, &prefix).await?
            }
            MentionLookupPlan::Unaddressable => Vec::new(),
        };
        candidates.push(ids);
    }
    let lookup_keys = mention_incoming_lookup_keys(record_id);
    let incoming = if lookup_keys.is_empty() {
        Vec::new()
    } else {
        let keys_json = serde_json::to_string(&lookup_keys)?;
        mention_incoming_rows(&mut *conn, &keys_json).await?
    };
    Ok(GatheredMentions {
        groups,
        candidates,
        incoming,
    })
}

/// The four mention fields, resolved after authorization. `None` means absent
/// (unsupported adapter or nothing to disclose), never an empty placeholder.
#[derive(Debug, Default)]
pub(crate) struct ResolvedMentions {
    pub out: Option<Vec<MentionOut>>,
    pub out_count: Option<i64>,
    pub incoming: Option<Vec<MentionIn>>,
    pub incoming_count: Option<i64>,
}

/// Resolve gathered evidence against the caller-visible id set and assemble
/// the four fields. `limit`/`offset` window both directions deterministically,
/// after filtering — never before, so hidden peers cannot shift a page.
pub(crate) async fn finish_mentions(
    conn: &mut sqlx::SqliteConnection,
    gathered: GatheredMentions,
    visible: &HashSet<String>,
    limit: i64,
    offset: i64,
) -> Result<ResolvedMentions> {
    let visible_per_group: Vec<Vec<String>> = gathered
        .candidates
        .iter()
        .map(|candidates| {
            candidates
                .iter()
                .filter(|id| visible.contains(*id))
                .cloned()
                .collect()
        })
        .collect();
    let mut resolved_ids: Vec<String> = visible_per_group
        .iter()
        .filter(|ids| ids.len() == 1)
        .map(|ids| ids[0].clone())
        .collect();
    resolved_ids.sort();
    resolved_ids.dedup();
    let names = if resolved_ids.is_empty() {
        HashMap::new()
    } else {
        let ids_json = serde_json::to_string(&resolved_ids)?;
        mention_names(&mut *conn, &ids_json).await?
    };

    let out_count = gathered.groups.len() as i64;
    let out = if gathered.groups.is_empty() {
        None
    } else {
        let resolved = gathered
            .groups
            .iter()
            .zip(visible_per_group.iter())
            .map(|(group, visible_ids)| MentionOut {
                authored_reference: group.authored_reference.clone(),
                lookup_key: group.lookup_key.clone(),
                form: group.form.clone(),
                occurrence_count: group.occurrence_count,
                resolution: match visible_ids.as_slice() {
                    [] => MentionResolution::Unresolved,
                    [id] => MentionResolution::Resolved {
                        id: id.clone(),
                        name: names.get(id).cloned().unwrap_or_default(),
                    },
                    many => MentionResolution::Ambiguous {
                        visible_candidate_count: many.len() as i64,
                    },
                },
            })
            .collect::<Vec<_>>();
        let windowed = resolved
            .into_iter()
            .skip(offset.max(0) as usize)
            .take(limit.max(0) as usize)
            .collect::<Vec<_>>();
        Some(windowed)
    };

    // Incoming rows arrive ordered by (source_id, authored_reference, form), so
    // one linear fold groups them by source.
    let mut sources: Vec<MentionIn> = Vec::new();
    for row in &gathered.incoming {
        if !visible.contains(&row.source_id) {
            continue;
        }
        match sources.last_mut() {
            Some(last) if last.source_id == row.source_id => {
                last.occurrence_count += row.occurrence_count;
                if !last.authored_references.contains(&row.authored_reference) {
                    last.authored_references
                        .push(row.authored_reference.clone());
                }
                if !last.forms.contains(&row.form) {
                    last.forms.push(row.form.clone());
                }
            }
            _ => sources.push(MentionIn {
                source_id: row.source_id.clone(),
                source_name: row.source_name.clone(),
                occurrence_count: row.occurrence_count,
                authored_references: vec![row.authored_reference.clone()],
                forms: vec![row.form.clone()],
            }),
        }
    }
    for source in &mut sources {
        source.authored_references.sort();
        source.authored_references.dedup();
        source.forms.sort();
        source.forms.dedup();
    }
    let reachable = !sources.is_empty();
    let incoming_count = sources.len() as i64;
    let incoming = if sources.is_empty() {
        None
    } else {
        Some(
            sources
                .into_iter()
                .skip(offset.max(0) as usize)
                .take(limit.max(0) as usize)
                .collect::<Vec<_>>(),
        )
    };

    Ok(ResolvedMentions {
        out,
        out_count: (!gathered.groups.is_empty()).then_some(out_count),
        incoming,
        incoming_count: reachable.then_some(incoming_count),
    })
}

/// Fetch one record with default-windowed enrichments — see
/// [`get_record_with`] to page a section.
pub async fn get_record(db: &Db, id: &str) -> Result<Option<EnrichedRecord>> {
    get_record_with_lens(&ReadLens::live(db), id, EnrichOptions::default()).await
}

/// Fetch one record with enrichments. Returns `None` if the id does not exist.
/// Direct fetch returns what you name: archived and tombstoned records come
/// back (with `archived` / `deleted_at` telling you so) — pointing at a record
/// is asking for it.
pub async fn get_record_with(
    db: &Db,
    id: &str,
    opts: EnrichOptions,
) -> Result<Option<EnrichedRecord>> {
    get_record_with_lens(&ReadLens::live(db), id, opts).await
}

/// Fetch through an explicit content/meta/blob lens. Historical callers must
/// use this entry point so a replay projection can never masquerade as a full
/// database.
pub async fn get_record_with_lens(
    lens: &ReadLens<'_>,
    id: &str,
    opts: EnrichOptions,
) -> Result<Option<EnrichedRecord>> {
    get_record_with_lens_inner(lens, id, opts, None).await
}

/// Caller-relative lens read. Historical content comes from the projection,
/// but derived suggestion/citation candidates are authorized by their current
/// live bearer before their totals and windows are computed.
pub async fn get_record_with_lens_as(
    lens: &ReadLens<'_>,
    id: &str,
    opts: EnrichOptions,
    principal: crate::authorization::Principal<'_>,
) -> Result<Option<EnrichedRecord>> {
    get_record_with_lens_inner(lens, id, opts, Some(principal)).await
}

async fn get_record_with_lens_inner(
    lens: &ReadLens<'_>,
    id: &str,
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Option<EnrichedRecord>> {
    opts.validate()?;
    if let Some(principal) = principal {
        let visible = crate::authorization::effective_capability_in_pool(
            lens.meta().snapshot_pool(),
            principal,
            id,
        )
        .await
        .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
        if !visible {
            return Ok(None);
        }
    }
    let db = lens.projection().snapshot_pool();
    let sql = format!("SELECT {RECORD_COLUMNS} FROM records WHERE id = ?");
    let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(db).await? else {
        return Ok(None);
    };
    let mut record = record_from_row(&row)?;
    super::hydrate_communication_origin_in_pool(db, &mut record).await?;
    super::hydrate_federation_provenance_in_pool(db, &mut record).await?;
    let bears_shape = super::cascade::bears_shape_in_pool(lens.meta().snapshot_pool(), id).await?;
    let kind_governance = match record.kind.as_deref() {
        Some(kind) => Some(
            crate::meta::kind::resolve_in_pool(
                lens.meta().snapshot_pool(),
                &record.record_type,
                kind,
            )
            .await?,
        ),
        None => None,
    };
    let is_comment = kind_governance.as_ref().is_some_and(|resolution| {
        crate::generated::kinds::CoreKind::AnnotationComment.matches(resolution)
    });
    if is_comment && !valid_comment_with_lens(lens, id).await? {
        return Ok(None);
    }

    let facet_rows = sqlx::query(
        "SELECT fv.key, fv.value, fv.vocab_ref,
                (SELECT MAX(fo.event_seq) FROM facet_observations fo
                  WHERE fo.record_id = fv.record_id AND fo.key = fv.key) AS version
           FROM facet_values fv WHERE fv.record_id = ? ORDER BY fv.key",
    )
    .bind(id)
    .fetch_all(db)
    .await?;
    let schema_rows = super::cascade::schema_config_rows_for_principal_in_pool(
        lens.meta().snapshot_pool(),
        principal,
    )
    .await?;
    let lifecycle_interpreter = super::lifecycle::LifecycleInterpreter::load_from_pool(
        lens.meta().snapshot_pool(),
        schema_rows.clone(),
    )
    .await?;
    record.hydrate_lifecycle(&lifecycle_interpreter);
    let facet_shapes = super::cascade::facets_for_record_context(
        &schema_rows,
        &record.record_type,
        record.kind.as_deref(),
        None,
    );
    let mut archived = false;
    let mut facets = Vec::with_capacity(facet_rows.len());
    for f in &facet_rows {
        let key: String = f.try_get("key")?;
        if key == ARCHIVED_FACET_KEY {
            archived = true;
            continue;
        }
        let stored: Option<String> = f.try_get("value")?;
        let object_typed = facet_shapes
            .get(&key)
            .and_then(|shape| shape.get("type"))
            .and_then(Value::as_str)
            == Some("object");
        let value = stored.map(|stored| {
            if object_typed {
                serde_json::from_str::<Value>(&stored)
                    .ok()
                    .filter(Value::is_object)
                    .unwrap_or(Value::String(stored))
            } else {
                Value::String(stored)
            }
        });
        facets.push(FacetValueRow {
            key,
            value,
            vocab_ref: f.try_get("vocab_ref")?,
            version: facet_version(f.try_get("version")?),
        });
    }

    // The counts are separate statements rather than a correlated column so
    // that a section's total is still reported when its window is zero-length
    // — `limit: 0` is how a caller says "how many are there?" without paying
    // for any of them.
    //
    // Both link orderings end in `id` — not decoration. `(relationship,
    // created_at)` is not unique: links added in one `append_batch` share a
    // transaction timestamp, so a paged read over that order has no stable
    // membership and can repeat or skip rows across pages. `children` already
    // ordered `(name, id)` and was total; links were not, and offset paging is
    // what turned that from cosmetic into a defect.
    let links_out_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id = ?")
        .bind(id)
        .fetch_one(db)
        .await?;
    let links_out = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
          FROM links WHERE source_id = ? ORDER BY relationship, created_at, id
          LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(opts.links_limit)
    .bind(opts.links_offset)
    .fetch_all(db)
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;

    let links_in_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE target_id = ?")
        .bind(id)
        .fetch_one(db)
        .await?;
    let links_in = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
          FROM links WHERE target_id = ? ORDER BY relationship, created_at, id
          LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(opts.links_limit)
    .bind(opts.links_offset)
    .fetch_all(db)
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;

    // Disclosure, not a window: the full ordered successor list feeds the
    // capped `superseded_by` projection, so links paging cannot hide one.
    let superseded_by = load_superseded_by(db, id).await?;

    // Counts live visible children, archived included — matching what the `children`
    // window itself returns. `tree::descendants`' `child_count` excludes
    // archived unless asked, because the walk it annotates skips archived
    // subtrees whole; enrichment has no such walk to agree with.
    let not_hidden = super::not_hidden_predicate("r");
    let suggestion_candidates = artifact_summaries(
        lens,
        id,
        crate::generated::kinds::CoreKind::AnnotationSuggestion,
        principal,
    )
    .await?;
    let citation_candidates = artifact_summaries(
        lens,
        id,
        crate::generated::kinds::CoreKind::AnnotationCitation,
        principal,
    )
    .await?;
    let comment_candidates = comment_summaries(lens, id, principal).await?;
    let suggestion_count = suggestion_candidates.len() as i64;
    let citation_count = citation_candidates.len() as i64;
    let comment_count = comment_candidates.len() as i64;
    let child_count_sql = format!(
        "SELECT COUNT(*) FROM records r
          WHERE r.home_id = ? AND r.deleted_at IS NULL
            AND {not_hidden}"
    );
    let child_count: i64 = sqlx::query_scalar(&child_count_sql)
        .bind(id)
        .fetch_one(db)
        .await?;
    let children_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
          FROM records r
          WHERE r.home_id = ? AND r.deleted_at IS NULL
            AND {not_hidden}
          ORDER BY r.name, r.id
          LIMIT ? OFFSET ?"
    );
    let children = sqlx::query(&children_sql)
        .bind(ARCHIVED_FACET_KEY)
        .bind(id)
        .bind(opts.children_limit)
        .bind(opts.children_offset)
        .fetch_all(db)
        .await?
        .iter()
        .map(|c| {
            Ok(ChildSummary {
                id: c.try_get("id")?,
                record_type: c.try_get("type")?,
                kind: c.try_get("kind")?,
                name: c.try_get("name")?,
                archived: c.try_get::<i64, _>("archived")? != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let suggestions = if opts.include_suggestions {
        Some(
            suggestion_candidates
                .into_iter()
                .skip(opts.suggestions_offset as usize)
                .take(opts.suggestions_limit as usize)
                .collect(),
        )
    } else {
        None
    };

    let citations = if opts.include_citations {
        Some(
            citation_candidates
                .into_iter()
                .skip(opts.citations_offset as usize)
                .take(opts.citations_limit as usize)
                .collect(),
        )
    } else {
        None
    };
    let mut comments: Option<Vec<CommentSummary>> = opts.include_comments.then(|| {
        comment_candidates
            .into_iter()
            .skip(opts.comments_offset as usize)
            .take(opts.comments_limit as usize)
            .collect::<Vec<_>>()
    });
    if let Some(comments) = comments.as_mut() {
        hydrate_comment_targets_with_lens(lens, comments).await?;
    }
    let target = if record.record_type == "Annotation" {
        let target_owner = if is_comment {
            comment_context_owner_with_lens(lens, id).await?
        } else {
            id.to_string()
        };
        crate::citations::read_target_view_with_lens(lens, &target_owner).await?
    } else {
        None
    };

    let ancestors = tree::ancestors_from(lens.projection(), id).await?;

    Ok(Some(EnrichedRecord {
        record,
        archived,
        custody_boundary: false,
        containment_path_visible: true,
        bears_shape,
        kind_governance,
        facets,
        links_out,
        links_out_count,
        links_in,
        links_in_count,
        // Mention fields are filled by the visibility-filtering layer, which
        // alone knows the caller. A raw projection reader leaves them absent
        // (never empty) so an unfiltered caller cannot mistake raw resolution
        // for an authorized answer.
        mentions_out: None,
        mentions_out_count: None,
        mentions_in: None,
        mentions_in_count: None,
        superseded_by,
        children,
        child_count,
        suggestions,
        suggestion_count,
        citations,
        citation_count,
        comments,
        comment_count,
        target,
        contribution: None,
        // Opt-in byline attribution; the `get_record` tool layer attaches it
        // after visibility filtering when the caller asks. Raw readers leave
        // it absent so the key stays a capability signal.
        history_summary: None,
        ancestors,
        // Historical and non-`get_record` readers never serve this
        // projection; the SQLite `get_record` live path attaches it after
        // visibility filtering.
        freshness: None,
    }))
}

async fn artifact_summaries(
    lens: &ReadLens<'_>,
    bearer_id: &str,
    family: crate::generated::kinds::CoreKind,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<ChildSummary>> {
    let db = lens.projection().snapshot_pool();
    let tokens = crate::meta::kind::active_identity_tokens_in_pool(
        lens.meta().snapshot_pool(),
        family.record_type(),
        family.value_id(),
    )
    .await?;
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r
          WHERE r.deleted_at IS NULL AND r.type = ? AND r.kind IN ({placeholders})
            AND EXISTS (
                SELECT 1 FROM links bearer
                 WHERE bearer.source_id = r.id
                   AND bearer.relationship = 'part_of'
                   AND bearer.target_id = ?
            )
          ORDER BY r.created_at, r.id"
    );
    let mut query = sqlx::query(&sql)
        .bind(ARCHIVED_FACET_KEY)
        .bind(family.record_type());
    for token in tokens {
        query = query.bind(token);
    }
    let rows = query.bind(bearer_id).fetch_all(db).await?;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        if let Some(principal) = principal {
            let visible = crate::authorization::effective_capability_in_pool(
                lens.meta().snapshot_pool(),
                principal,
                &id,
            )
            .await
            .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
            if !visible {
                continue;
            }
        }
        summaries.push(ChildSummary {
            id,
            record_type: row.try_get("type")?,
            kind: row.try_get("kind")?,
            name: row.try_get("name")?,
            archived: row.try_get::<i64, _>("archived")? != 0,
        });
    }
    Ok(summaries)
}

fn valid_comment_fields(
    is_reply: bool,
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> bool {
    if body.is_none_or(|body| body.trim().is_empty()) {
        return false;
    }
    if is_reply {
        return lifecycle.is_none() && summary.is_none();
    }
    match lifecycle {
        // `informational` is the named form of the legacy null root: an FYI
        // that carries no resolution summary. Both spellings read alike.
        None | Some(crate::comments::INFORMATIONAL) | Some(crate::comments::OPEN) => {
            summary.is_none()
        }
        Some(crate::comments::RESOLVED) => {
            summary.is_some_and(|summary| !summary.trim().is_empty())
        }
        Some(_) => false,
    }
}

pub(crate) async fn resolves_comment(
    lens: &ReadLens<'_>,
    record_type: &str,
    kind: Option<&str>,
) -> Result<bool> {
    let Some(kind) = kind else { return Ok(false) };
    let resolution =
        crate::meta::kind::resolve_in_pool(lens.meta().snapshot_pool(), record_type, kind).await?;
    Ok(crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution))
}

pub(crate) async fn valid_comment_with_lens(lens: &ReadLens<'_>, id: &str) -> Result<bool> {
    let db = lens.projection().snapshot_pool();
    let row = sqlx::query(
        "SELECT type, kind, body, lifecycle, summary, deleted_at
           FROM records WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(false) };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(false);
    }
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if !resolves_comment(lens, &record_type, kind.as_deref()).await? {
        return Ok(false);
    }
    let bearers: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links
          WHERE source_id = ? AND relationship = 'part_of' ORDER BY target_id",
    )
    .bind(id)
    .fetch_all(db)
    .await?;
    if bearers.len() != 1 {
        return Ok(false);
    }
    let bearer = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(&bearers[0])
        .fetch_optional(db)
        .await?;
    let Some(bearer) = bearer else {
        return Ok(false);
    };
    if bearer.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(false);
    }
    let bearer_type: String = bearer.try_get("type")?;
    let bearer_kind: Option<String> = bearer.try_get("kind")?;
    let is_reply = resolves_comment(lens, &bearer_type, bearer_kind.as_deref()).await?;
    let own_target = sqlx::query(
        "SELECT target_record_id, source_slot FROM annotation_targets WHERE annotation_id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    if let Some(target) = own_target {
        if is_reply
            || target.try_get::<String, _>("target_record_id")? != bearers[0].as_str()
            || target.try_get::<String, _>("source_slot")? != "body"
        {
            return Ok(false);
        }
    }
    if is_reply {
        // A reply may bear only on a valid root, never another reply.
        let root = sqlx::query(
            "SELECT root.type, root.kind, root.body, root.lifecycle, root.summary,
                    root.deleted_at, COUNT(root_part.target_id) AS bearer_count,
                    MIN(root_part.target_id) AS root_bearer_id
               FROM records root
               LEFT JOIN links root_part
                 ON root_part.source_id = root.id AND root_part.relationship = 'part_of'
              WHERE root.id = ?
              GROUP BY root.id",
        )
        .bind(&bearers[0])
        .fetch_optional(db)
        .await?;
        let Some(root) = root else { return Ok(false) };
        if root.try_get::<Option<String>, _>("deleted_at")?.is_some()
            || root.try_get::<i64, _>("bearer_count")? != 1
            || !valid_comment_fields(
                false,
                root.try_get::<Option<String>, _>("body")?.as_deref(),
                root.try_get::<Option<String>, _>("lifecycle")?.as_deref(),
                root.try_get::<Option<String>, _>("summary")?.as_deref(),
            )
        {
            return Ok(false);
        }
        let root_bearer_id: String = root.try_get("root_bearer_id")?;
        let root_target = sqlx::query(
            "SELECT target_record_id, source_slot FROM annotation_targets WHERE annotation_id = ?",
        )
        .bind(&bearers[0])
        .fetch_optional(db)
        .await?;
        if let Some(target) = root_target {
            if target.try_get::<String, _>("target_record_id")? != root_bearer_id.as_str()
                || target.try_get::<String, _>("source_slot")? != "body"
            {
                return Ok(false);
            }
        }
        let root_bearer = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
            .bind(root_bearer_id)
            .fetch_optional(db)
            .await?;
        let Some(root_bearer) = root_bearer else {
            return Ok(false);
        };
        if root_bearer
            .try_get::<Option<String>, _>("deleted_at")?
            .is_some()
        {
            return Ok(false);
        }
        let target_type: String = root_bearer.try_get("type")?;
        let target_kind: Option<String> = root_bearer.try_get("kind")?;
        if resolves_comment(lens, &target_type, target_kind.as_deref()).await? {
            return Ok(false);
        }
    }
    Ok(valid_comment_fields(
        is_reply,
        row.try_get::<Option<String>, _>("body")?.as_deref(),
        row.try_get::<Option<String>, _>("lifecycle")?.as_deref(),
        row.try_get::<Option<String>, _>("summary")?.as_deref(),
    ))
}

fn comment_summary_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<CommentSummary> {
    Ok(CommentSummary {
        id: row.try_get("id")?,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        body: row
            .try_get::<Option<String>, _>("body")?
            .unwrap_or_default(),
        lifecycle: row.try_get("lifecycle")?,
        home_id: row.try_get("home_id")?,
        lifecycle_interpretation: super::lifecycle::LifecycleInterpretation::Absent(
            super::lifecycle::AbsentLifecycleInterpretation {
                axis: None,
                vocabulary: None,
            },
        ),
        summary: row.try_get("summary")?,
        owner_id: row.try_get("owner_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        archived: row.try_get::<i64, _>("archived")? != 0,
        target: None,
        contribution: None,
    })
}

impl CommentSummary {
    fn hydrate_lifecycle(&mut self, interpreter: &super::lifecycle::LifecycleInterpreter) {
        self.lifecycle_interpretation = interpreter.interpret(
            &self.record_type,
            self.kind.as_deref(),
            self.home_id.as_deref(),
            self.lifecycle.as_deref(),
        );
    }
}

async fn hydrate_comment_lifecycles_with_lens(
    lens: &ReadLens<'_>,
    comments: &mut [CommentSummary],
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<()> {
    let schema_rows = super::cascade::schema_config_rows_for_principal_in_pool(
        lens.meta().snapshot_pool(),
        principal,
    )
    .await?;
    let interpreter = super::lifecycle::LifecycleInterpreter::load_from_pool(
        lens.meta().snapshot_pool(),
        schema_rows,
    )
    .await?;
    for comment in comments {
        comment.hydrate_lifecycle(&interpreter);
    }
    Ok(())
}

async fn comment_context_owner_with_lens(lens: &ReadLens<'_>, id: &str) -> Result<String> {
    Ok(
        comment_context_owners_with_lens(lens, std::slice::from_ref(&id.to_string()))
            .await?
            .remove(id)
            .ok_or(sqlx::Error::RowNotFound)?,
    )
}

/// One batched `comment_context_owner` for a comment page.
///
/// A page's comments resolve through one bearer, so the bearer record and its
/// comment-governance decision are read once per distinct bearer instead of
/// once per comment. Missing links fail with the same `RowNotFound` the
/// single-read path produced.
async fn comment_context_owners_with_lens(
    lens: &ReadLens<'_>,
    ids: &[String],
) -> Result<HashMap<String, String>> {
    let mut owners = HashMap::with_capacity(ids.len());
    if ids.is_empty() {
        return Ok(owners);
    }
    let db = lens.projection().snapshot_pool();
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT source_id, target_id FROM links
          WHERE source_id IN ({placeholders}) AND relationship = 'part_of'
          ORDER BY source_id"
    );
    let mut query = sqlx::query(&sql);
    for id in ids {
        query = query.bind(id);
    }
    let mut bearers: HashMap<String, String> = HashMap::new();
    for row in query.fetch_all(db).await? {
        let source: String = row.try_get("source_id")?;
        bearers
            .entry(source)
            .or_insert_with(|| row.try_get("target_id").unwrap_or_default());
    }
    let mut distinct_bearers = Vec::new();
    for id in ids {
        let bearer = bearers.remove(id).ok_or(sqlx::Error::RowNotFound)?;
        if !distinct_bearers.contains(&bearer) {
            distinct_bearers.push(bearer.clone());
        }
        owners.insert(id.clone(), bearer);
    }
    let placeholders = std::iter::repeat_n("?", distinct_bearers.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT id, type, kind FROM records WHERE id IN ({placeholders})");
    let mut query = sqlx::query(&sql);
    for bearer in &distinct_bearers {
        query = query.bind(bearer);
    }
    let mut bearer_rows: HashMap<String, (String, Option<String>)> = HashMap::new();
    for row in query.fetch_all(db).await? {
        let id: String = row.try_get("id")?;
        bearer_rows.insert(id, (row.try_get("type")?, row.try_get("kind")?));
    }
    let mut governed: HashMap<(String, Option<String>), bool> = HashMap::new();
    for id in ids {
        let bearer = &owners[id];
        let (record_type, kind) = bearer_rows
            .get(bearer)
            .cloned()
            .ok_or(sqlx::Error::RowNotFound)?;
        let is_comment = match governed.entry((record_type.clone(), kind.clone())) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                *entry.insert(resolves_comment(lens, &record_type, kind.as_deref()).await?)
            }
        };
        if !is_comment {
            owners.insert(id.clone(), id.clone());
        }
    }
    Ok(owners)
}

async fn hydrate_comment_targets_with_lens(
    lens: &ReadLens<'_>,
    comments: &mut [CommentSummary],
) -> Result<()> {
    let ids: Vec<String> = comments.iter().map(|comment| comment.id.clone()).collect();
    let owners = comment_context_owners_with_lens(lens, &ids).await?;
    let mut distinct = Vec::new();
    for id in &ids {
        let owner = &owners[id];
        if !distinct.contains(owner) {
            distinct.push(owner.clone());
        }
    }
    let resolved = crate::citations::read_target_views_with_lens(lens, &distinct).await?;
    for comment in comments {
        comment.target = resolved.get(&owners[&comment.id]).cloned().flatten();
    }
    Ok(())
}

async fn comment_context_owner_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<String> {
    Ok(
        comment_context_owners_live_in(tx, std::slice::from_ref(&id.to_string()))
            .await?
            .remove(id)
            .ok_or(sqlx::Error::RowNotFound)?,
    )
}

async fn comment_context_owners_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[String],
) -> Result<HashMap<String, String>> {
    let mut owners = HashMap::with_capacity(ids.len());
    if ids.is_empty() {
        return Ok(owners);
    }
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT source_id, target_id FROM links
          WHERE source_id IN ({placeholders}) AND relationship = 'part_of'
          ORDER BY source_id"
    );
    let mut query = sqlx::query(&sql);
    for id in ids {
        query = query.bind(id);
    }
    let mut bearers: HashMap<String, String> = HashMap::new();
    for row in query.fetch_all(&mut **tx).await? {
        let source: String = row.try_get("source_id")?;
        bearers
            .entry(source)
            .or_insert_with(|| row.try_get("target_id").unwrap_or_default());
    }
    let mut distinct_bearers = Vec::new();
    for id in ids {
        let bearer = bearers.remove(id).ok_or(sqlx::Error::RowNotFound)?;
        if !distinct_bearers.contains(&bearer) {
            distinct_bearers.push(bearer.clone());
        }
        owners.insert(id.clone(), bearer);
    }
    let placeholders = std::iter::repeat_n("?", distinct_bearers.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT id, type, kind FROM records WHERE id IN ({placeholders})");
    let mut query = sqlx::query(&sql);
    for bearer in &distinct_bearers {
        query = query.bind(bearer);
    }
    let mut bearer_rows: HashMap<String, (String, Option<String>)> = HashMap::new();
    for row in query.fetch_all(&mut **tx).await? {
        let id: String = row.try_get("id")?;
        bearer_rows.insert(id, (row.try_get("type")?, row.try_get("kind")?));
    }
    let mut governed: HashMap<(String, Option<String>), bool> = HashMap::new();
    for id in ids {
        let bearer = &owners[id];
        let (record_type, kind) = bearer_rows
            .get(bearer)
            .cloned()
            .ok_or(sqlx::Error::RowNotFound)?;
        let is_comment = match governed.entry((record_type.clone(), kind.clone())) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => *entry.insert(
                crate::comments::is_governed_comment_on(tx, &record_type, kind.as_deref()).await?,
            ),
        };
        if !is_comment {
            owners.insert(id.clone(), id.clone());
        }
    }
    Ok(owners)
}

async fn hydrate_comment_targets_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    comments: &mut [CommentSummary],
) -> Result<()> {
    let ids: Vec<String> = comments.iter().map(|comment| comment.id.clone()).collect();
    let owners = comment_context_owners_live_in(tx, &ids).await?;
    let mut distinct = Vec::new();
    for id in &ids {
        let owner = &owners[id];
        if !distinct.contains(owner) {
            distinct.push(owner.clone());
        }
    }
    let resolved = crate::citations::read_target_views_live_in(tx, &distinct).await?;
    for comment in comments {
        comment.target = resolved.get(&owners[&comment.id]).cloned().flatten();
    }
    Ok(())
}

/// One exact-count, bounded comment window used by `start_work`.
///
/// This seam is deliberately live-only: a valid direct comment inherits the
/// authorization of its bearer, so after authorizing the bearer once the
/// database can count and page comments without materializing every utterance
/// merely to validate it in Rust.
pub(crate) struct CommentWindow {
    pub comments: Vec<CommentSummary>,
    pub total: i64,
}

pub(crate) async fn comment_window_for_work(
    lens: &ReadLens<'_>,
    bearer_id: &str,
    principal: Option<crate::authorization::Principal<'_>>,
    root_lifecycle: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<CommentWindow> {
    debug_assert!(lens.temporal().is_none());
    let db = lens.projection().snapshot_pool();
    if let Some(principal) = principal {
        let visible = crate::authorization::effective_capability_in_pool(
            lens.meta().snapshot_pool(),
            principal,
            bearer_id,
        )
        .await
        .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
        if !visible {
            return Ok(CommentWindow {
                comments: Vec::new(),
                total: 0,
            });
        }
    }
    let tokens = crate::meta::kind::active_identity_tokens_in_pool(
        lens.meta().snapshot_pool(),
        "Annotation",
        crate::generated::kinds::CoreKind::AnnotationComment.value_id(),
    )
    .await?;
    if tokens.is_empty() {
        return Ok(CommentWindow {
            comments: Vec::new(),
            total: 0,
        });
    }
    let bearer = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(bearer_id)
        .fetch_optional(db)
        .await?;
    let Some(bearer) = bearer else {
        return Ok(CommentWindow {
            comments: Vec::new(),
            total: 0,
        });
    };
    if bearer.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(CommentWindow {
            comments: Vec::new(),
            total: 0,
        });
    }
    let bearer_type: String = bearer.try_get("type")?;
    let bearer_kind: Option<String> = bearer.try_get("kind")?;
    let replies = resolves_comment(lens, &bearer_type, bearer_kind.as_deref()).await?;
    if replies {
        // Only a valid root may own a reply window. A valid reply is itself a
        // governed comment, but opening a further window from it would admit
        // the reply-to-reply shape v1 deliberately forbids.
        if !valid_comment_with_lens(lens, bearer_id).await? {
            return Ok(CommentWindow {
                comments: Vec::new(),
                total: 0,
            });
        }
        let root_bearer = sqlx::query(
            "SELECT target.type, target.kind
               FROM links part
               JOIN records target ON target.id = part.target_id AND target.deleted_at IS NULL
              WHERE part.source_id = ? AND part.relationship = 'part_of'",
        )
        .bind(bearer_id)
        .fetch_optional(db)
        .await?;
        let Some(root_bearer) = root_bearer else {
            return Ok(CommentWindow {
                comments: Vec::new(),
                total: 0,
            });
        };
        let target_type: String = root_bearer.try_get("type")?;
        let target_kind: Option<String> = root_bearer.try_get("kind")?;
        if resolves_comment(lens, &target_type, target_kind.as_deref()).await? {
            return Ok(CommentWindow {
                comments: Vec::new(),
                total: 0,
            });
        }
    }

    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let shape = if replies {
        "r.lifecycle IS NULL AND r.summary IS NULL"
    } else {
        // Mirrors `valid_comment_fields`: null and 'informational' are the two
        // spellings of the same unresolvable FYI state. The open-thread count
        // still excludes both, because it binds `r.lifecycle = 'open'` below.
        "((r.lifecycle IS NULL OR r.lifecycle IN ('informational', 'open')) AND r.summary IS NULL
          OR r.lifecycle = 'resolved' AND TRIM(COALESCE(r.summary, '')) <> '')"
    };
    let lifecycle = if root_lifecycle.is_some() {
        "AND r.lifecycle = ?"
    } else {
        ""
    };
    let where_sql = format!(
        "r.deleted_at IS NULL AND r.type = 'Annotation'
         AND r.kind IN ({placeholders})
         AND TRIM(COALESCE(r.body, '')) <> ''
         AND {shape}
         AND (SELECT COUNT(*) FROM links all_part
               WHERE all_part.source_id = r.id
                 AND all_part.relationship = 'part_of') = 1
         AND EXISTS (SELECT 1 FROM links direct
                      WHERE direct.source_id = r.id
                        AND direct.relationship = 'part_of'
                        AND direct.target_id = ?)
         {lifecycle}"
    );

    let count_sql = format!("SELECT COUNT(*) FROM records r WHERE {where_sql}");
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    for token in &tokens {
        count_query = count_query.bind(token);
    }
    count_query = count_query.bind(bearer_id);
    if let Some(lifecycle) = root_lifecycle {
        count_query = count_query.bind(lifecycle);
    }
    let total = count_query.fetch_one(db).await?;

    let order = if replies {
        "r.created_at ASC, r.id ASC"
    } else {
        "r.created_at DESC, r.id DESC"
    };
    let rows_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.body, r.home_id, r.lifecycle, r.summary,
                r.owner_id, r.created_at, r.updated_at,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE {where_sql}
          ORDER BY {order} LIMIT ? OFFSET ?"
    );
    let mut rows_query = sqlx::query(&rows_sql).bind(ARCHIVED_FACET_KEY);
    for token in &tokens {
        rows_query = rows_query.bind(token);
    }
    rows_query = rows_query.bind(bearer_id);
    if let Some(lifecycle) = root_lifecycle {
        rows_query = rows_query.bind(lifecycle);
    }
    let rows = rows_query.bind(limit).bind(offset).fetch_all(db).await?;
    let inherited_target = if replies {
        crate::citations::read_target_view_with_lens(lens, bearer_id).await?
    } else {
        None
    };
    let mut comments = Vec::with_capacity(rows.len());
    for row in rows {
        let mut summary = comment_summary_from_row(&row)?;
        if let (Some(principal), Some(owner_id)) = (principal, summary.owner_id.as_deref()) {
            let owner_visible = crate::authorization::effective_capability_in_pool(
                lens.meta().snapshot_pool(),
                principal,
                owner_id,
            )
            .await
            .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
            if !owner_visible {
                summary.owner_id = None;
            }
        }
        if replies {
            summary.target = inherited_target.clone();
        }
        comments.push(summary);
    }
    if !replies {
        // Direct comments each own their anchor; resolve the page in one
        // batch so comments pinned to the same passage revision share a fold.
        let ids: Vec<String> = comments.iter().map(|comment| comment.id.clone()).collect();
        let views = crate::citations::read_target_views_with_lens(lens, &ids).await?;
        for comment in &mut comments {
            comment.target = views.get(&comment.id).cloned().flatten();
        }
    }
    hydrate_comment_lifecycles_with_lens(lens, &mut comments, principal).await?;
    Ok(CommentWindow { comments, total })
}

/// Direct, visibility-filtered comment rows at the lens's content prefix.
/// Root windows are newest-first; a root's direct replies are oldest-first.
pub(crate) async fn comment_summaries(
    lens: &ReadLens<'_>,
    bearer_id: &str,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<CommentSummary>> {
    let db = lens.projection().snapshot_pool();
    let tokens = crate::meta::kind::active_identity_tokens_in_pool(
        lens.meta().snapshot_pool(),
        "Annotation",
        crate::generated::kinds::CoreKind::AnnotationComment.value_id(),
    )
    .await?;
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let bearer = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(bearer_id)
        .fetch_optional(db)
        .await?;
    let replies = if let Some(bearer) = bearer {
        let record_type: String = bearer.try_get("type")?;
        let kind: Option<String> = bearer.try_get("kind")?;
        resolves_comment(lens, &record_type, kind.as_deref()).await?
    } else {
        false
    };
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let order = if replies {
        "r.created_at ASC, r.id ASC"
    } else {
        "r.created_at DESC, r.id DESC"
    };
    let sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.body, r.home_id, r.lifecycle, r.summary,
                r.owner_id, r.created_at, r.updated_at,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r
          WHERE r.deleted_at IS NULL AND r.type = 'Annotation'
            AND r.kind IN ({placeholders})
            AND EXISTS (SELECT 1 FROM links bearer
                         WHERE bearer.source_id = r.id
                           AND bearer.relationship = 'part_of'
                           AND bearer.target_id = ?)
          ORDER BY {order}"
    );
    let mut query = sqlx::query(&sql).bind(ARCHIVED_FACET_KEY);
    for token in tokens {
        query = query.bind(token);
    }
    let rows = query.bind(bearer_id).fetch_all(db).await?;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        if !valid_comment_with_lens(lens, &id).await? {
            continue;
        }
        let mut summary = comment_summary_from_row(&row)?;
        if let Some(principal) = principal {
            let visible = crate::authorization::effective_capability_in_pool(
                lens.meta().snapshot_pool(),
                principal,
                &id,
            )
            .await
            .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
            if !visible {
                continue;
            }
            if let Some(owner_id) = summary.owner_id.as_deref() {
                let owner_visible = crate::authorization::effective_capability_in_pool(
                    lens.meta().snapshot_pool(),
                    principal,
                    owner_id,
                )
                .await
                .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
                if !owner_visible {
                    summary.owner_id = None;
                }
            }
        }
        summaries.push(summary);
    }
    hydrate_comment_lifecycles_with_lens(lens, &mut summaries, principal).await?;
    Ok(summaries)
}

/// Batch-local shared governance for one live `get_records_live_in` call.
///
/// Caller-visible schema rows plus the full lifecycle vocabulary index depend
/// only on this transaction's snapshot and the principal, so every visible
/// record in the batch would otherwise reload the identical rows: one
/// `schema_config` read, two vocabulary reads, plus repeated scoped-schema
/// bearer authorization. The context loads them once, lazily, on the first
/// visible record that needs them.
///
/// Lazy matters: an empty batch or one where every id is invisible/missing
/// does zero schema/vocabulary work, preserving the previous no-work
/// behavior. Batch-local matters: nothing escapes the call, so a later call
/// on a newer snapshot can never observe stale governance. No global cache,
/// no invalidation machinery.
#[derive(Default)]
struct LiveBatchContext {
    schema_rows: Option<Vec<super::cascade::SchemaConfigRow>>,
    interpreter: Option<super::lifecycle::LifecycleInterpreter>,
}

impl LiveBatchContext {
    async fn shared(
        &mut self,
        tx: &mut Transaction<'_, Sqlite>,
        principal: Option<crate::authorization::Principal<'_>>,
    ) -> Result<(
        &Vec<super::cascade::SchemaConfigRow>,
        &super::lifecycle::LifecycleInterpreter,
    )> {
        if self.interpreter.is_none() {
            let schema_rows =
                super::cascade::schema_config_rows_for_principal_on(tx, principal).await?;
            let interpreter = super::lifecycle::LifecycleInterpreter::load_from_connection(
                tx,
                schema_rows.clone(),
            )
            .await?;
            self.schema_rows = Some(schema_rows);
            self.interpreter = Some(interpreter);
        }
        Ok((
            self.schema_rows
                .as_ref()
                .expect("interpreter implies schema_rows"),
            self.interpreter.as_ref().expect("just loaded"),
        ))
    }
}

/// Canonical live record read. Authorization and every mutable enrichment are
/// evaluated from the caller-owned transaction, so a response cannot combine
/// an authorization decision from one SQLite snapshot with data from another.
/// This takes no lens: all pool-backed reads stay inside the caller's
/// transaction, whether that transaction came from the read or write pool.
pub(crate) async fn get_records_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[String],
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<BatchGetItem>> {
    get_records_live_with_heads_in(tx, ids, opts, principal, None).await
}

/// Live batch with optional body-free heads from the workspace index. The
/// read transaction checks the held fences before using any indexed field, so
/// all bodies, admission decisions and enrichments share the same snapshot.
pub(crate) async fn get_records_live_with_heads_in(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[String],
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
    indexed: Option<&crate::db::IndexedRecordHeads>,
) -> Result<Vec<BatchGetItem>> {
    get_records_live_with_heads_and_usage_in(tx, ids, opts, principal, indexed, None).await
}

/// The tool variant reports whether at least one returned record actually
/// used an indexed header after the in-transaction fence and admission checks.
/// It never treats a merely extracted index candidate as a served hit.
pub(crate) async fn get_records_live_with_heads_and_usage_in(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[String],
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
    indexed: Option<&crate::db::IndexedRecordHeads>,
    mut indexed_header_ids: Option<&mut HashSet<String>>,
) -> Result<Vec<BatchGetItem>> {
    opts.validate()?;
    let heads = if let Some(indexed) = indexed {
        let live: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT epoch FROM authorization_revision WHERE id = 1)",
        )
        .fetch_one(&mut **tx)
        .await?;
        (live == indexed.fences).then_some(&indexed.heads)
    } else {
        None
    };
    let mut shared = LiveBatchContext::default();
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        let mut used_indexed_head = false;
        items.push(
            match get_record_live_in(
                tx,
                id,
                opts,
                principal,
                &mut shared,
                heads.and_then(|heads| heads.get(id)),
                &mut used_indexed_head,
            )
            .await?
            {
                Some(record) => {
                    if used_indexed_head {
                        if let Some(ids) = indexed_header_ids.as_mut() {
                            ids.insert(id.clone());
                        }
                    }
                    BatchGetItem::Found(Box::new(record))
                }
                None => BatchGetItem::NotFound { id: id.clone() },
            },
        );
    }
    Ok(items)
}

/// Whether an id is an ordinary, canonically readable record before any ACL
/// decision is made. Governed derived records deliberately collapse malformed
/// identity to absence, so callers cannot use authorization as an existence
/// oracle for an attribution aggregate or an invalid comment.
pub(crate) async fn ordinary_record_read_eligible_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<bool> {
    let sql = format!("SELECT {RECORD_COLUMNS} FROM records WHERE id = ?");
    let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await? else {
        return Ok(false);
    };
    let record_type: String = row.try_get("type")?;
    let Some(kind) = row.try_get::<Option<String>, _>("kind")? else {
        return Ok(true);
    };
    let resolution = crate::meta::kind::resolve_on(tx, &record_type, &kind).await?;
    if crate::generated::kinds::CoreKind::AnnotationAttribution.matches(&resolution) {
        return Ok(false);
    }
    if !crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution) {
        return Ok(true);
    }
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(false);
    }
    valid_comment_live_in(tx, id, &row).await
}

/// Pool-scoped wrapper for ordinary record admission. The transaction keeps
/// the governed identity and comment-integrity reads on one SQLite snapshot.
pub(crate) async fn ordinary_record_read_eligible(db: &Db, id: &str) -> Result<bool> {
    let mut tx = db.write_pool().begin().await?;
    ordinary_record_read_eligible_live_in(&mut tx, id).await
}

async fn get_record_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
    shared: &mut LiveBatchContext,
    indexed_head: Option<&crate::workspace_index::RecordHead>,
    used_indexed_head: &mut bool,
) -> Result<Option<EnrichedRecord>> {
    if let Some(principal) = principal {
        let visible = crate::authorization::effective_capability_on(tx, principal, id)
            .await
            .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
        if !visible {
            return Ok(None);
        }
    } else if crate::authorization::validate_authorization_shape_on(tx, id, true)
        .await
        .is_err()
    {
        return Ok(None);
    }

    // The index holds every record column except body. A verified head only
    // needs the body from this transaction; a missing/unsupported head keeps
    // the canonical full-row read. Comments keep that row for integrity
    // validation, including custom kind resolution below.
    let indexed_head = indexed_head.filter(|head| head.record_type != "Annotation");
    let using_indexed_head = indexed_head.is_some();
    let (mut record, row) = if let Some(head) = indexed_head {
        let body: Option<Option<String>> =
            sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await?;
        let Some(body) = body else {
            return Ok(None);
        };
        (super::record_from_index_head(head, body), None)
    } else {
        let sql = format!("SELECT {RECORD_COLUMNS} FROM records WHERE id = ?");
        let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await? else {
            return Ok(None);
        };
        (record_from_row(&row)?, Some(row))
    };
    super::hydrate_communication_origin_on(tx, &mut record).await?;
    super::hydrate_federation_provenance_on(tx, &mut record).await?;
    let bears_shape = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM schema_config WHERE applies_to_collection_id = ?)",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    let kind_governance = match record.kind.as_deref() {
        Some(kind) => Some(crate::meta::kind::resolve_on(tx, &record.record_type, kind).await?),
        None => None,
    };
    let is_comment = kind_governance.as_ref().is_some_and(|resolution| {
        crate::generated::kinds::CoreKind::AnnotationComment.matches(resolution)
    });
    if is_comment {
        // Core comment kinds are Annotation records. A custom metadata alias
        // reaching the same kind on another type still needs the same
        // integrity rule; fetch the full row on that rare path.
        let valid = if let Some(row) = row.as_ref() {
            valid_comment_live_in(tx, id, row).await?
        } else {
            let sql = format!("SELECT {RECORD_COLUMNS} FROM records WHERE id = ?");
            let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await? else {
                return Ok(None);
            };
            valid_comment_live_in(tx, id, &row).await?
        };
        if !valid {
            return Ok(None);
        }
    }

    let facet_rows = sqlx::query(
        "SELECT fv.key, fv.value, fv.vocab_ref,
                (SELECT MAX(fo.event_seq) FROM facet_observations fo
                  WHERE fo.record_id = fv.record_id AND fo.key = fv.key) AS version
           FROM facet_values fv WHERE fv.record_id = ? ORDER BY fv.key",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    // Shared governance: schema rows plus the vocabulary index depend only on
    // this transaction's snapshot and the principal, so the batch loads them
    // once. Facet-shape resolution below stays per record from the shared rows.
    let (schema_rows, lifecycle_interpreter) = shared.shared(tx, principal).await?;
    record.hydrate_lifecycle(lifecycle_interpreter);
    let facet_shapes = super::cascade::facets_for_record_context(
        schema_rows,
        &record.record_type,
        record.kind.as_deref(),
        None,
    );
    let mut archived = false;
    let mut facets = Vec::with_capacity(facet_rows.len());
    for facet in &facet_rows {
        let key: String = facet.try_get("key")?;
        if key == ARCHIVED_FACET_KEY {
            archived = true;
            continue;
        }
        let stored: Option<String> = facet.try_get("value")?;
        let object_typed = facet_shapes
            .get(&key)
            .and_then(|shape| shape.get("type"))
            .and_then(Value::as_str)
            == Some("object");
        let value = stored.map(|stored| {
            if object_typed {
                serde_json::from_str::<Value>(&stored)
                    .ok()
                    .filter(Value::is_object)
                    .unwrap_or(Value::String(stored))
            } else {
                Value::String(stored)
            }
        });
        facets.push(FacetValueRow {
            key,
            value,
            vocab_ref: facet.try_get("vocab_ref")?,
            version: facet_version(facet.try_get("version")?),
        });
    }

    let links_out_count = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id = ?")
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    let links_out = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
           FROM links WHERE source_id = ? ORDER BY relationship, created_at, id
           LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(opts.links_limit)
    .bind(opts.links_offset)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;
    let links_in_count = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE target_id = ?")
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    let links_in = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
           FROM links WHERE target_id = ? ORDER BY relationship, created_at, id
           LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(opts.links_limit)
    .bind(opts.links_offset)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;

    // Same disclosure as the pool-backed path above, over this transaction's
    // projection rather than the live pool.
    let superseded_by = load_superseded_by(&mut **tx, id).await?;

    let suggestion_candidates = artifact_summaries_live_in(
        tx,
        id,
        crate::generated::kinds::CoreKind::AnnotationSuggestion,
        principal,
    )
    .await?;
    let citation_candidates = artifact_summaries_live_in(
        tx,
        id,
        crate::generated::kinds::CoreKind::AnnotationCitation,
        principal,
    )
    .await?;
    let comment_candidates =
        comment_summaries_live_in_with(tx, id, principal, lifecycle_interpreter).await?;
    let suggestion_count = suggestion_candidates.len() as i64;
    let citation_count = citation_candidates.len() as i64;
    let comment_count = comment_candidates.len() as i64;

    let not_hidden = super::not_hidden_predicate("r");
    let child_count_sql = format!(
        "SELECT COUNT(*) FROM records r
          WHERE r.home_id = ? AND r.deleted_at IS NULL AND {not_hidden}"
    );
    let child_count = sqlx::query_scalar(&child_count_sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    let children_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r
          WHERE r.home_id = ? AND r.deleted_at IS NULL AND {not_hidden}
          ORDER BY r.name, r.id LIMIT ? OFFSET ?"
    );
    let children = sqlx::query(&children_sql)
        .bind(ARCHIVED_FACET_KEY)
        .bind(id)
        .bind(opts.children_limit)
        .bind(opts.children_offset)
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .map(|row| {
            Ok(ChildSummary {
                id: row.try_get("id")?,
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                name: row.try_get("name")?,
                archived: row.try_get::<i64, _>("archived")? != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let suggestions = opts.include_suggestions.then(|| {
        suggestion_candidates
            .into_iter()
            .skip(opts.suggestions_offset as usize)
            .take(opts.suggestions_limit as usize)
            .collect()
    });
    let citations = opts.include_citations.then(|| {
        citation_candidates
            .into_iter()
            .skip(opts.citations_offset as usize)
            .take(opts.citations_limit as usize)
            .collect()
    });
    let mut comments: Option<Vec<CommentSummary>> = opts.include_comments.then(|| {
        comment_candidates
            .into_iter()
            .skip(opts.comments_offset as usize)
            .take(opts.comments_limit as usize)
            .collect::<Vec<_>>()
    });
    if let Some(comments) = comments.as_mut() {
        hydrate_comment_targets_live_in(tx, comments).await?;
    }
    let target = if record.record_type == "Annotation" {
        let target_owner = if is_comment {
            comment_context_owner_live_in(tx, id).await?
        } else {
            id.to_string()
        };
        crate::citations::read_target_view_live_in(tx, &target_owner).await?
    } else {
        None
    };
    let ancestors = tree::ancestors_on(tx, id).await?;

    *used_indexed_head |= using_indexed_head;
    Ok(Some(EnrichedRecord {
        record,
        archived,
        custody_boundary: false,
        containment_path_visible: true,
        bears_shape,
        kind_governance,
        facets,
        links_out,
        links_out_count,
        links_in,
        links_in_count,
        // Mention fields are filled by the visibility-filtering layer, which
        // alone knows the caller. A raw projection reader leaves them absent
        // (never empty) so an unfiltered caller cannot mistake raw resolution
        // for an authorized answer.
        mentions_out: None,
        mentions_out_count: None,
        mentions_in: None,
        mentions_in_count: None,
        superseded_by,
        children,
        child_count,
        suggestions,
        suggestion_count,
        citations,
        citation_count,
        comments,
        comment_count,
        target,
        contribution: None,
        // Same opt-in rule as the pool-backed path above; only the SQLite
        // `get_record` tool path populates it.
        history_summary: None,
        ancestors,
        // Live transactional readers other than the SQLite `get_record` tool
        // path (e.g. messaging fan-out) never serve this projection.
        freshness: None,
    }))
}

async fn artifact_summaries_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    family: crate::generated::kinds::CoreKind,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<ChildSummary>> {
    let tokens =
        crate::meta::kind::active_identity_tokens_on(tx, family.record_type(), family.value_id())
            .await?;
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r
          WHERE r.deleted_at IS NULL AND r.type = ? AND r.kind IN ({placeholders})
            AND EXISTS (SELECT 1 FROM links bearer
                         WHERE bearer.source_id = r.id
                           AND bearer.relationship = 'part_of'
                           AND bearer.target_id = ?)
          ORDER BY r.created_at, r.id"
    );
    let mut query = sqlx::query(&sql)
        .bind(ARCHIVED_FACET_KEY)
        .bind(family.record_type());
    for token in tokens {
        query = query.bind(token);
    }
    let rows = query.bind(bearer_id).fetch_all(&mut **tx).await?;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        if let Some(principal) = principal {
            let visible = crate::authorization::effective_capability_on(tx, principal, &id)
                .await
                .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
            if !visible {
                continue;
            }
        }
        summaries.push(ChildSummary {
            id,
            record_type: row.try_get("type")?,
            kind: row.try_get("kind")?,
            name: row.try_get("name")?,
            archived: row.try_get::<i64, _>("archived")? != 0,
        });
    }
    Ok(summaries)
}

pub(crate) async fn valid_comment_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<bool> {
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    let body: Option<String> = row.try_get("body")?;
    let lifecycle: Option<String> = row.try_get("lifecycle")?;
    let summary: Option<String> = row.try_get("summary")?;
    Ok(crate::comments::validate_update_on(
        tx,
        "get_record",
        id,
        &record_type,
        kind.as_deref(),
        kind.as_deref(),
        body.as_deref(),
        lifecycle.as_deref(),
        lifecycle.as_deref(),
        summary.as_deref(),
        false,
        false,
        false,
    )
    .await
    .is_ok())
}

async fn comment_summaries_live_in_with(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    principal: Option<crate::authorization::Principal<'_>>,
    interpreter: &super::lifecycle::LifecycleInterpreter,
) -> Result<Vec<CommentSummary>> {
    let tokens = crate::meta::kind::active_identity_tokens_on(
        tx,
        "Annotation",
        crate::generated::kinds::CoreKind::AnnotationComment.value_id(),
    )
    .await?;
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    comment_summaries_live_in_with_tokens(tx, bearer_id, principal, interpreter, tokens).await
}

async fn comment_summaries_live_in_with_tokens(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    principal: Option<crate::authorization::Principal<'_>>,
    interpreter: &super::lifecycle::LifecycleInterpreter,
    tokens: Vec<String>,
) -> Result<Vec<CommentSummary>> {
    let bearer = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(bearer_id)
        .fetch_optional(&mut **tx)
        .await?;
    let replies = if let Some(bearer) = bearer {
        let record_type: String = bearer.try_get("type")?;
        let kind: Option<String> = bearer.try_get("kind")?;
        crate::comments::is_governed_comment_on(tx, &record_type, kind.as_deref()).await?
    } else {
        false
    };
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let order = if replies {
        "r.created_at ASC, r.id ASC"
    } else {
        "r.created_at DESC, r.id DESC"
    };
    let sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.body, r.home_id, r.lifecycle, r.summary,
                r.owner_id, r.created_at, r.updated_at,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r
          WHERE r.deleted_at IS NULL AND r.type = 'Annotation'
            AND r.kind IN ({placeholders})
            AND EXISTS (SELECT 1 FROM links bearer
                         WHERE bearer.source_id = r.id
                           AND bearer.relationship = 'part_of'
                           AND bearer.target_id = ?)
          ORDER BY {order}"
    );
    let mut query = sqlx::query(&sql).bind(ARCHIVED_FACET_KEY);
    for token in tokens {
        query = query.bind(token);
    }
    let rows = query.bind(bearer_id).fetch_all(&mut **tx).await?;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        if !valid_comment_live_in(tx, &id, &row).await? {
            continue;
        }
        let mut summary = comment_summary_from_row(&row)?;
        if let Some(principal) = principal {
            let visible = crate::authorization::effective_capability_on(tx, principal, &id)
                .await
                .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
            if !visible {
                continue;
            }
            if let Some(owner_id) = summary.owner_id.as_deref() {
                let owner_visible =
                    crate::authorization::effective_capability_on(tx, principal, owner_id)
                        .await
                        .is_ok_and(|capability| {
                            capability.allows(crate::authorization::Capability::View)
                        });
                if !owner_visible {
                    summary.owner_id = None;
                }
            }
        }
        summaries.push(summary);
    }
    for summary in &mut summaries {
        summary.hydrate_lifecycle(interpreter);
    }
    Ok(summaries)
}

/// A record's links, both directions — the light fetch backing
/// `manage_links`'s list action (tool 13), which does not need the full
/// enrichment `get_record` pays for.
#[derive(Debug, Serialize)]
pub struct RecordLinks {
    pub links_out: Vec<LinkRow>,
    pub links_in: Vec<LinkRow>,
}

/// Fetch one record's links. Returns `None` if the record does not exist
/// (an id with no links is `Some` with two empty lists — the two cases are
/// different answers).
pub async fn record_links(db: &Db, id: &str) -> Result<Option<RecordLinks>> {
    let exists = sqlx::query("SELECT 1 FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(db.write_pool())
        .await?;
    if exists.is_none() {
        return Ok(None);
    }
    let links_out = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
          FROM links WHERE source_id = ? ORDER BY relationship, created_at, id",
    )
    .bind(id)
    .fetch_all(db.write_pool())
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;
    let links_in = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
          FROM links WHERE target_id = ? ORDER BY relationship, created_at, id",
    )
    .bind(id)
    .fetch_all(db.write_pool())
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;
    Ok(Some(RecordLinks {
        links_out,
        links_in,
    }))
}

pub(crate) async fn record_links_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<RecordLinks>> {
    let exists = sqlx::query("SELECT 1 FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    if exists.is_none() {
        return Ok(None);
    }
    let links_out = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
           FROM links WHERE source_id = ? ORDER BY relationship, created_at, id",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;
    let links_in = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at
           FROM links WHERE target_id = ? ORDER BY relationship, created_at, id",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(link_from_row)
    .collect::<Result<Vec<_>>>()?;
    Ok(Some(RecordLinks {
        links_out,
        links_in,
    }))
}

/// Batch fetch with default-windowed enrichments.
pub async fn get_records(db: &Db, ids: &[String]) -> Result<Vec<BatchGetItem>> {
    get_records_with_lens(&ReadLens::live(db), ids, EnrichOptions::default()).await
}

/// Batch fetch with partial success: one item per input id, in input order —
/// a missing id yields `NotFound` in place and never fails its neighbours.
///
/// The window applies **per record**, so a batch's worst case is
/// `ids.len() × limit`, not `ids.len() ×` however wide the widest container in
/// it happens to be. That product is the reason the window has a ceiling and
/// not merely a default.
pub async fn get_records_with(
    db: &Db,
    ids: &[String],
    opts: EnrichOptions,
) -> Result<Vec<BatchGetItem>> {
    get_records_with_lens(&ReadLens::live(db), ids, opts).await
}

pub async fn get_records_with_lens(
    lens: &ReadLens<'_>,
    ids: &[String],
    opts: EnrichOptions,
) -> Result<Vec<BatchGetItem>> {
    opts.validate()?;
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(match get_record_with_lens(lens, id, opts).await? {
            Some(record) => BatchGetItem::Found(Box::new(record)),
            None => BatchGetItem::NotFound { id: id.clone() },
        });
    }
    Ok(items)
}

pub async fn get_records_with_lens_as(
    lens: &ReadLens<'_>,
    ids: &[String],
    opts: EnrichOptions,
    principal: crate::authorization::Principal<'_>,
) -> Result<Vec<BatchGetItem>> {
    opts.validate()?;
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(
            match get_record_with_lens_as(lens, id, opts, principal).await? {
                Some(record) => BatchGetItem::Found(Box::new(record)),
                None => BatchGetItem::NotFound { id: id.clone() },
            },
        );
    }
    Ok(items)
}

#[cfg(test)]
mod live_snapshot_tests {
    use serde_json::json;

    use super::*;
    use crate::authorization::{Capability, Principal};
    use crate::db::create_database;
    use crate::schema::ROOT_RECORD_ID;
    use crate::store::{create_record, update_record};

    #[tokio::test]
    async fn live_record_data_stays_on_the_authorization_snapshot() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": "9e7ead00-0000-4000-8000-000000000001",
                "type": "Collection",
                "kind": "folder",
                "name": "before",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();

        let principal = Principal::bound("snapshot-account", true);
        let mut snapshot = db.write_pool().begin().await.unwrap();
        let capability = crate::authorization::effective_capability_on(
            &mut snapshot,
            principal,
            "9e7ead00-0000-4000-8000-000000000001",
        )
        .await
        .unwrap();
        assert!(capability.allows(Capability::View));

        update_record(
            &db,
            "9e7ead00-0000-4000-8000-000000000001",
            json!({ "name": "after" }),
        )
        .await
        .unwrap();
        let items = get_records_live_in(
            &mut snapshot,
            &["9e7ead00-0000-4000-8000-000000000001".into()],
            EnrichOptions::default(),
            Some(principal),
        )
        .await
        .unwrap();
        let BatchGetItem::Found(record) = &items[0] else {
            panic!("authorized record should remain visible");
        };
        assert_eq!(record.record.name, "before");
        snapshot.rollback().await.unwrap();

        let current = get_record(&db, "9e7ead00-0000-4000-8000-000000000001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.record.name, "after");
    }
}

#[cfg(test)]
mod indexed_record_header_tests {
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    use serde_json::{json, Value};

    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
    use crate::db::{create_database, IndexedRecordHeads};
    use crate::mcp::{Caller, ToolRegistry};
    use crate::store::{create_record, update_record};

    const ONE: &str = "a61d0000-0000-4000-8000-000000000001";
    const TWO: &str = "a61d0000-0000-4000-8000-000000000002";

    async fn read_batch(
        db: &crate::db::Db,
        ids: &[String],
        account: &str,
        indexed: Option<&IndexedRecordHeads>,
    ) -> Value {
        let mut tx = db.pool().begin().await.unwrap();
        let principal = Some(Principal::bound(account, true));
        let items = get_records_live_with_heads_in(
            &mut tx,
            ids,
            EnrichOptions::default(),
            principal,
            indexed,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        serde_json::to_value(items).unwrap()
    }

    #[tokio::test]
    async fn indexed_header_matches_governed_for_two_principals_and_fence_moves() {
        let db = create_database(":memory:").await.unwrap();
        for (id, name) in [(ONE, "one"), (TWO, "two")] {
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note", "name": name,
                       "body": format!("body of {name}")}),
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:m4-header",
            ONE,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:m4-header",
            TWO,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let ids = vec![ONE.to_string(), TWO.to_string(), "missing".to_string()];
        let mut held = db
            .indexed_record_heads_for(&ids)
            .await
            .expect("current, under-cap index");
        assert_eq!(held.heads.len(), 2);
        for account in ["alice", "bea"] {
            let indexed = read_batch(&db, &ids, account, Some(&held)).await;
            let governed = read_batch(&db, &ids, account, None).await;
            assert_eq!(indexed, governed, "header parity for {account}");
        }
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let writer_checkouts = Arc::new(AtomicU64::new(u64::MAX));
        let response =
            crate::db::with_write_pool_acquisition_sink(Arc::clone(&writer_checkouts), async {
                registry
                    .call(
                        db.clone(),
                        Caller::authenticated("alice"),
                        "get_record",
                        json!({"ids": [ONE]}),
                    )
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(response["records"][0]["status"], "found");
        assert_eq!(
            writer_checkouts.load(Ordering::Relaxed),
            0,
            "live indexed header read is read-pool only"
        );
        // Prove the test exercised the head path, rather than succeeding only
        // because the reader happened to fall back to its canonical SELECT.
        let name = std::mem::replace(
            &mut held.heads.get_mut(ONE).unwrap().name,
            "index-head".into(),
        );
        let injected = read_batch(&db, &ids, "alice", Some(&held)).await;
        assert_eq!(injected[0]["name"], "index-head");
        held.heads.get_mut(ONE).unwrap().name = name;

        // A content commit or authorization narrowing after extraction moves
        // a fence. The old held heads must be ignored inside the read snapshot.
        update_record(&db, ONE, json!({"name":"new one", "body":"new body"}))
            .await
            .unwrap();
        assert_eq!(
            read_batch(&db, &ids, "alice", Some(&held)).await,
            read_batch(&db, &ids, "alice", None).await,
        );
        let mut held_after_content = db
            .indexed_record_heads_for(&ids)
            .await
            .expect("current heads after content fold");
        held_after_content.heads.get_mut(ONE).unwrap().name = "stale-head".into();
        replace_explicit_policy(
            &db,
            "test:m4-narrow",
            ONE,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let indexed = read_batch(&db, &ids, "bea", Some(&held_after_content)).await;
        assert_eq!(indexed, read_batch(&db, &ids, "bea", None).await);
        assert_eq!(indexed[0]["status"], "not_found");
        // Relationship/authorization movement needs a rebuild, not a
        // permanently dark fast path. A poisoned head proves the rebuilt
        // snapshot is used for an authorized caller after narrowing.
        let mut rebuilt = db
            .indexed_record_heads_for(&ids)
            .await
            .expect("header index rebuilt after authorization movement");
        assert_ne!(rebuilt.fences.2, held_after_content.fences.2);
        rebuilt.heads.get_mut(ONE).unwrap().name = "rebuilt-head".into();
        assert_eq!(
            read_batch(&db, &ids, "alice", Some(&rebuilt)).await[0]["name"],
            "rebuilt-head"
        );
        db.close().await;
    }
}

#[cfg(test)]
mod live_batch_context_tests {
    use serde_json::json;

    use super::*;
    use crate::authorization::Principal;
    use crate::db::create_database;
    use crate::query::test_sqlite::SqliteTrace;
    use crate::schema::ROOT_RECORD_ID;
    use crate::store::create_record;

    async fn create_batch_corpus(db: &crate::db::Db, count: usize) -> Vec<String> {
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            // Deterministic UUID-shaped ids keep the batch oracle stable.
            let id = format!("bb7e0000-0000-4000-8000-{index:012}");
            create_record(
                db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": format!("batch {index}"),
                    "home_id": ROOT_RECORD_ID,
                }),
            )
            .await
            .unwrap();
            ids.push(id);
        }
        ids
    }

    async fn traced_batch(
        db: &crate::db::Db,
        ids: &[String],
        principal: Option<Principal<'_>>,
    ) -> (Vec<BatchGetItem>, usize) {
        let mut tx = db.write_pool().begin().await.unwrap();
        let trace = SqliteTrace::install(&mut tx).await.unwrap();
        let items = get_records_live_in(&mut tx, ids, EnrichOptions::default(), principal)
            .await
            .unwrap();
        let work = trace.finish(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
        (items, work.statements)
    }

    async fn traced_singles(
        db: &crate::db::Db,
        ids: &[String],
        principal: Option<Principal<'_>>,
    ) -> (Vec<BatchGetItem>, usize) {
        let mut tx = db.write_pool().begin().await.unwrap();
        let trace = SqliteTrace::install(&mut tx).await.unwrap();
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            let mut one = get_records_live_in(
                &mut tx,
                std::slice::from_ref(id),
                EnrichOptions::default(),
                principal,
            )
            .await
            .unwrap();
            items.push(one.remove(0));
        }
        let work = trace.finish(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
        (items, work.statements)
    }

    #[tokio::test]
    async fn batch_shares_schema_and_vocab_reads() {
        let db = create_database(":memory:").await.unwrap();
        let ids = create_batch_corpus(&db, 5).await;
        let principal = Some(Principal::bound("batch-viewer", true));

        let (_, batch_statements) = traced_batch(&db, &ids, principal).await;
        let (_, singles_statements) = traced_singles(&db, &ids, principal).await;

        // One schema_config read plus vocabularies plus vocabulary_values per
        // governance load, absent scoped bearers. The batch pays it once; five
        // independent single-id batches pay it five times.
        let saved = singles_statements.saturating_sub(batch_statements);
        eprintln!(
            "live batch savings: batch={batch_statements} singles={singles_statements} saved={saved}"
        );
        assert!(
            saved >= 3 * (ids.len() - 1),
            "batch should save at least 3 statements per extra record, \
             batch={batch_statements} singles={singles_statements} saved={saved}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn batch_matches_scalar_oracle_mixed_duplicate_missing_order() {
        let db = create_database(":memory:").await.unwrap();
        let doc_id = "cc7e0000-0000-4000-8000-000000000001".to_string();
        let folder_id = "cc7e0000-0000-4000-8000-000000000002".to_string();
        let task_id = "cc7e0000-0000-4000-8000-000000000003".to_string();
        create_record(
            &db,
            json!({
                "id": doc_id,
                "type": "Document",
                "kind": "note",
                "name": "doc",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": folder_id,
                "type": "Collection",
                "kind": "folder",
                "name": "folder",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": task_id,
                "type": "WorkItem",
                "kind": "task",
                "name": "task",
                "lifecycle": "open",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        // One facet row exercises per-record facet-shape resolution.
        sqlx::query("INSERT INTO facet_values(id, record_id, key, value) VALUES(?,?,?,?)")
            .bind("facet:oracle-1")
            .bind(&doc_id)
            .bind("note")
            .bind("plain")
            .execute(db.write_pool())
            .await
            .unwrap();

        let principal = Some(Principal::bound("oracle-viewer", true));
        let ids = vec![
            task_id.clone(),
            "dd7e0000-0000-4000-8000-000000000099".to_string(),
            doc_id.clone(),
            doc_id.clone(),
            folder_id.clone(),
            task_id.clone(),
        ];
        let (batch, _) = traced_batch(&db, &ids, principal).await;
        let (singles, _) = traced_singles(&db, &ids, principal).await;
        assert_eq!(
            serde_json::to_value(&batch).unwrap(),
            serde_json::to_value(&singles).unwrap(),
            "batch must match sequential single-id reads exactly"
        );
        // Spot-check the contract: order preserved, duplicates preserved,
        // missing yields NotFound in place.
        assert!(matches!(&batch[0], BatchGetItem::Found(_)));
        assert!(matches!(&batch[1], BatchGetItem::NotFound { .. }));
        assert!(matches!(&batch[2], BatchGetItem::Found(_)));
        assert!(matches!(&batch[3], BatchGetItem::Found(_)));
        db.close().await;
    }

    #[tokio::test]
    async fn batch_preserves_hidden_scoped_schemas_and_empty_work() {
        let db = create_database(":memory:").await.unwrap();
        let bearer_id = "dd7e0000-0000-4000-8000-000000000010".to_string();
        let task_id = "dd7e0000-0000-4000-8000-000000000011".to_string();
        create_record(
            &db,
            json!({
                "id": bearer_id,
                "type": "Collection",
                "kind": "folder",
                "name": "bearer",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        // Task stays under ROOT so it remains visible to the viewer on its
        // own policy; the bearer-anchored row below is proven present for the
        // owner and absent for the viewer at the schema layer directly.
        create_record(
            &db,
            json!({
                "id": task_id,
                "type": "WorkItem",
                "kind": "task",
                "name": "scoped-task",
                "lifecycle": "open",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        // Bearer visible only to its owner; the viewer below cannot see it,
        // so the anchored row must stay hidden from them.
        crate::authorization::replace_explicit_policy(
            &db,
            "test:scoped-bearer",
            &bearer_id,
            vec![crate::authorization::AllowEntry::account(
                "acct:owner",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        // Anchored override: when visible it replaces the task lifecycle axis
        // with a hidden one pointing at a nonexistent vocabulary, turning the
        // same stored "open" token from Governed into Unclassified.
        sqlx::query(
            "INSERT INTO schema_config(id, layer, name, data, applies_to_collection_id, created_at)
             VALUES('test:hidden-scoped','user','hidden',?,?, '2026-09-17T00:00:00.000Z')",
        )
        .bind(
            json!({"shapes": {"WorkItem:task": {"facets": {"lifecycle": {
                "axis": {"key": "hidden_axis", "label": "Hidden"},
                "vocab_ref": "nonexistent-vocab"
            }}}}})
            .to_string(),
        )
        .bind(&bearer_id)
        .execute(db.write_pool())
        .await
        .unwrap();

        let viewer = Some(Principal::bound("acct:viewer", true));
        let owner = Some(Principal::bound("acct:owner", true));
        let ids = vec![task_id.clone(), bearer_id.clone()];

        // Oracle comparison alone could share a leak, so assert exclusion at
        // the shared layer directly: the anchored row must be absent from the
        // viewer's schema rows and present for the owner on the same snapshot.
        {
            let mut tx = db.write_pool().begin().await.unwrap();
            let viewer_rows =
                crate::query::cascade::schema_config_rows_for_principal_on(&mut tx, viewer)
                    .await
                    .unwrap();
            assert!(
                viewer_rows.iter().all(|row| row.id != "test:hidden-scoped"),
                "viewer must not observe the hidden scoped schema row"
            );
            let owner_rows =
                crate::query::cascade::schema_config_rows_for_principal_on(&mut tx, owner)
                    .await
                    .unwrap();
            assert!(
                owner_rows.iter().any(|row| row.id == "test:hidden-scoped"),
                "owner must observe the anchored row, proving it exists"
            );
            tx.rollback().await.unwrap();
        }

        let (viewer_batch, _) = traced_batch(&db, &ids, viewer).await;
        let (viewer_singles, _) = traced_singles(&db, &ids, viewer).await;
        assert_eq!(
            serde_json::to_value(&viewer_batch).unwrap(),
            serde_json::to_value(&viewer_singles).unwrap(),
            "viewer-hidden scoped schemas must match the scalar oracle"
        );
        let BatchGetItem::Found(viewer_task) = &viewer_batch[0] else {
            panic!("viewer must see the task on its own policy");
        };
        let viewer_interp =
            serde_json::to_value(&viewer_task.record.lifecycle_interpretation).unwrap();
        assert_eq!(viewer_interp["status"], json!("governed"));
        assert_eq!(viewer_interp["axis"]["key"], json!("work_status"));
        assert!(
            matches!(&viewer_batch[1], BatchGetItem::NotFound { .. }),
            "viewer without bearer access must not see the bearer"
        );

        let (owner_batch, _) = traced_batch(&db, &ids, owner).await;
        let (owner_singles, _) = traced_singles(&db, &ids, owner).await;
        assert_eq!(
            serde_json::to_value(&owner_batch).unwrap(),
            serde_json::to_value(&owner_singles).unwrap(),
            "owner-visible scoped schemas must match the scalar oracle"
        );
        assert!(
            matches!(&owner_batch[1], BatchGetItem::Found(_)),
            "owner must see the bearer, proving the row's bearer exists"
        );

        // Empty batches do no schema/vocabulary work.
        let mut tx = db.write_pool().begin().await.unwrap();
        let trace = SqliteTrace::install(&mut tx).await.unwrap();
        let empty = get_records_live_in(&mut tx, &[], EnrichOptions::default(), viewer)
            .await
            .unwrap();
        let work = trace.finish(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
        assert!(empty.is_empty());
        assert_eq!(work.statements, 0, "empty batch must do no work");

        // All-missing batches never trigger governance loads, so they cost
        // exactly what the same singles cost: no sharing benefit, no extra.
        let missing = vec![
            "ee7e0000-0000-4000-8000-000000000021".to_string(),
            "ee7e0000-0000-4000-8000-000000000022".to_string(),
        ];
        let (_, batch_missing) = traced_batch(&db, &missing, viewer).await;
        let (_, singles_missing) = traced_singles(&db, &missing, viewer).await;
        assert_eq!(
            batch_missing, singles_missing,
            "all-absent batches must not load shared governance"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn batch_context_is_call_local_not_stale() {
        let db = create_database(":memory:").await.unwrap();
        let record_id = "ff7e0000-0000-4000-8000-000000000001".to_string();
        create_record(
            &db,
            json!({
                "id": record_id,
                "type": "Document",
                "kind": "note",
                "name": "stale-probe",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO facet_values(id, record_id, key, value) VALUES(?,?,?,?)")
            .bind("facet:stale-1")
            .bind(&record_id)
            .bind("payload")
            .bind("{\"a\":1}")
            .execute(db.write_pool())
            .await
            .unwrap();

        let principal = Some(Principal::bound("stale-viewer", true));
        let ids = vec![record_id.clone()];
        let (first, _) = traced_batch(&db, &ids, principal).await;
        let first_value = match &first[0] {
            BatchGetItem::Found(record) => record
                .facets
                .iter()
                .find(|facet| facet.key == "payload")
                .and_then(|facet| facet.value.clone()),
            BatchGetItem::NotFound { .. } | BatchGetItem::NotHeld { .. } => {
                panic!("record must be found")
            }
        };
        assert_eq!(first_value, Some(json!("{\"a\":1}")));

        // A later call must see governance committed after the first call:
        // declaring payload as object-typed changes the same stored string
        // into a parsed object. A cross-call cache would stay stale here.
        sqlx::query(
            "INSERT INTO schema_config(id, layer, name, data, created_at)
             VALUES('test:object-payload','user','object payload',?, '2026-09-17T00:00:00.000Z')",
        )
        .bind(
            json!({"shapes": {"Document:note": {"facets": {"payload": {"type": "object"}}}}})
                .to_string(),
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let (second, _) = traced_batch(&db, &ids, principal).await;
        let (oracle, _) = traced_singles(&db, &ids, principal).await;
        assert_eq!(
            serde_json::to_value(&second).unwrap(),
            serde_json::to_value(&oracle).unwrap(),
            "second batch must match a fresh scalar read after governance change"
        );
        let second_value = match &second[0] {
            BatchGetItem::Found(record) => record
                .facets
                .iter()
                .find(|facet| facet.key == "payload")
                .and_then(|facet| facet.value.clone()),
            BatchGetItem::NotFound { .. } | BatchGetItem::NotHeld { .. } => {
                panic!("record must be found")
            }
        };
        assert_eq!(
            second_value,
            Some(json!({"a": 1})),
            "second batch must observe the new object-typed facet shape"
        );
        db.close().await;
    }
}

#[cfg(test)]
mod honest_absence_tests {
    use super::*;

    /// The same pinning as `resolve_many`'s: `not_held` must be a third
    /// status, never a flavour of `not_found`. A client that normalises the
    /// two before an agent sees them reintroduces the failure the contract
    /// exists to prevent.
    #[test]
    fn not_held_is_a_third_batch_status() {
        let item = BatchGetItem::NotHeld {
            id: "a42f6e31-389c-47cd-91b6-8a231df3cec3".into(),
        };
        assert_eq!(
            serde_json::to_value(&item).unwrap(),
            serde_json::json!({
                "status": "not_held",
                "id": "a42f6e31-389c-47cd-91b6-8a231df3cec3"
            })
        );
        let missing = BatchGetItem::NotFound {
            id: "a42f6e31-389c-47cd-91b6-8a231df3cec3".into(),
        };
        assert_ne!(
            serde_json::to_value(&item).unwrap(),
            serde_json::to_value(&missing).unwrap()
        );
    }
}
