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

use std::collections::HashMap;

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
    /// Containment chain, root first, excluding the record itself.
    pub ancestors: Vec<tree::AncestorEntry>,
}

/// One item of a batch get — partial success, in input order.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchGetItem {
    Found(Box<EnrichedRecord>),
    NotFound { id: String },
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
        ancestors,
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

async fn hydrate_comment_lifecycles_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    comments: &mut [CommentSummary],
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<()> {
    let schema_rows = super::cascade::schema_config_rows_for_principal_on(tx, principal).await?;
    let interpreter =
        super::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema_rows).await?;
    for comment in comments {
        comment.hydrate_lifecycle(&interpreter);
    }
    Ok(())
}

async fn comment_context_owner_with_lens(lens: &ReadLens<'_>, id: &str) -> Result<String> {
    let db = lens.projection().snapshot_pool();
    let bearer =
        sqlx::query("SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of'")
            .bind(id)
            .fetch_one(db)
            .await?;
    let bearer_id: String = bearer.try_get("target_id")?;
    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(&bearer_id)
        .fetch_one(db)
        .await?;
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if resolves_comment(lens, &record_type, kind.as_deref()).await? {
        Ok(bearer_id)
    } else {
        Ok(id.to_string())
    }
}

async fn hydrate_comment_targets_with_lens(
    lens: &ReadLens<'_>,
    comments: &mut [CommentSummary],
) -> Result<()> {
    let mut resolved = HashMap::new();
    for comment in comments {
        let owner = comment_context_owner_with_lens(lens, &comment.id).await?;
        if !resolved.contains_key(&owner) {
            resolved.insert(
                owner.clone(),
                crate::citations::read_target_view_with_lens(lens, &owner).await?,
            );
        }
        comment.target = resolved.get(&owner).cloned().flatten();
    }
    Ok(())
}

async fn comment_context_owner_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<String> {
    let bearer_id: String = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(&bearer_id)
        .fetch_one(&mut **tx)
        .await?;
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if crate::comments::is_governed_comment_on(tx, &record_type, kind.as_deref()).await? {
        Ok(bearer_id)
    } else {
        Ok(id.to_string())
    }
}

async fn hydrate_comment_targets_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    lens: &ReadLens<'_>,
    comments: &mut [CommentSummary],
) -> Result<()> {
    let mut resolved = HashMap::new();
    for comment in comments {
        let owner = comment_context_owner_live_in(tx, &comment.id).await?;
        if !resolved.contains_key(&owner) {
            resolved.insert(
                owner.clone(),
                crate::citations::read_target_view_live_in(tx, lens, &owner).await?,
            );
        }
        comment.target = resolved.get(&owner).cloned().flatten();
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
        summary.target = if replies {
            inherited_target.clone()
        } else {
            crate::citations::read_target_view_with_lens(lens, &summary.id).await?
        };
        comments.push(summary);
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

/// Canonical live record read. Authorization and every mutable enrichment are
/// evaluated from the caller-owned transaction, so a response cannot combine
/// an authorization decision from one SQLite snapshot with data from another.
pub(crate) async fn get_records_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    lens: &ReadLens<'_>,
    ids: &[String],
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<BatchGetItem>> {
    opts.validate()?;
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(
            match get_record_live_in(tx, lens, id, opts, principal).await? {
                Some(record) => BatchGetItem::Found(Box::new(record)),
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
    lens: &ReadLens<'_>,
    id: &str,
    opts: EnrichOptions,
    principal: Option<crate::authorization::Principal<'_>>,
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

    let sql = format!("SELECT {RECORD_COLUMNS} FROM records WHERE id = ?");
    let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await? else {
        return Ok(None);
    };
    let mut record = record_from_row(&row)?;
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
    if is_comment && !valid_comment_live_in(tx, id, &row).await? {
        return Ok(None);
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
    let schema_rows = super::cascade::schema_config_rows_for_principal_on(tx, principal).await?;
    let lifecycle_interpreter =
        super::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema_rows.clone())
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
    let comment_candidates = comment_summaries_live_in(tx, id, principal).await?;
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
        hydrate_comment_targets_live_in(tx, lens, comments).await?;
    }
    let target = if record.record_type == "Annotation" {
        let target_owner = if is_comment {
            comment_context_owner_live_in(tx, id).await?
        } else {
            id.to_string()
        };
        crate::citations::read_target_view_live_in(tx, lens, &target_owner).await?
    } else {
        None
    };
    let ancestors = tree::ancestors_on(tx, id).await?;

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
        ancestors,
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

pub(crate) async fn comment_summaries_live_in(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    principal: Option<crate::authorization::Principal<'_>>,
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
    hydrate_comment_lifecycles_live_in(tx, &mut summaries, principal).await?;
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
        let lens = ReadLens::live(&db);
        let items = get_records_live_in(
            &mut snapshot,
            &lens,
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
