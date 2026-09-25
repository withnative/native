//! Bounded, visibility-safe lexical retrieval for the relationship-lint
//! development harness. This module is deliberately not wired to MCP.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::{self, Capability, Principal};
use crate::db::Db;
use crate::error::{Error, Result};

use super::fts::visibility_safe_score;

pub const EXTRACTION_VERSION: &str = "relationship-lint-terms-v1";
pub const UNIVERSE_LIMIT: usize = 5_000;
pub const UNIVERSE_SENTINEL: usize = UNIVERSE_LIMIT + 1;
pub const UNIVERSE_BYTES_LIMIT: usize = 64 * 1024 * 1024;
pub const TERM_LIMIT: usize = 12;
pub const TOKEN_SCALAR_LIMIT: usize = 64;
pub const RANK_NAME_SCALARS: usize = 512;
pub const RANK_BODY_SCALARS: usize = 2_048;
pub const SHORTLIST_LIMIT: usize = 8;

const PAGE_SIZE: i64 = 512;
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is",
    "it", "of", "on", "or", "that", "the", "this", "to", "was", "were", "will", "with",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenMembershipEvidence {
    pub account_id: String,
    pub hosted_database_id: String,
    pub verified_at: String,
    pub source: String,
    /// Catalog role attested at `verified_at`. Absent on payloads minted
    /// before roles were attested, which can only have been members.
    #[serde(default = "default_evidence_role")]
    pub role: String,
}

fn default_evidence_role() -> String {
    "member".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MembershipBasis {
    OfflineUnverifiedNonMember,
    FrozenAuthenticatedMember {
        account_id: String,
        hosted_database_id: String,
        verified_at: String,
        source: String,
        role: String,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionBoundary {
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub exclude_ids: Vec<String>,
    #[serde(default)]
    pub exclude_subtree_ids: Vec<String>,
    /// Evaluation cohort restriction. This observes the materialized policy
    /// anchor's canonical members grant; it never substitutes for actor auth.
    #[serde(default)]
    pub shared_only: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EligibleRequest {
    pub credential: String,
    #[serde(default)]
    pub frozen_membership_evidence: Option<FrozenMembershipEvidence>,
    #[serde(flatten)]
    pub boundary: SelectionBoundary,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalRequest {
    pub credential: String,
    #[serde(default)]
    pub frozen_membership_evidence: Option<FrozenMembershipEvidence>,
    pub subject_id: String,
    #[serde(flatten)]
    pub boundary: SelectionBoundary,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFingerprint {
    pub database_id: String,
    pub record_id: String,
    pub content_revision: i64,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidateRequest {
    pub credential: String,
    #[serde(default)]
    pub frozen_membership_evidence: Option<FrozenMembershipEvidence>,
    pub endpoints: Vec<SourceFingerprint>,
    #[serde(flatten)]
    pub boundary: SelectionBoundary,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotProvenance {
    pub database_id: String,
    pub content_high_water: i64,
    pub authorization_epoch: i64,
    pub membership_basis: MembershipBasis,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecordCapture {
    pub database_id: String,
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: String,
    pub name: String,
    pub body: Option<String>,
    pub home_id: Option<String>,
    pub lifecycle: Option<String>,
    pub updated_at: String,
    pub content_revision: i64,
    pub payload_sha256: String,
}

impl RecordCapture {
    pub fn fingerprint(&self) -> SourceFingerprint {
        SourceFingerprint {
            database_id: self.database_id.clone(),
            record_id: self.id.clone(),
            content_revision: self.content_revision,
            payload_sha256: self.payload_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EligibleMetadata {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: String,
    pub name: String,
    pub home_id: Option<String>,
    pub content_revision: i64,
    pub payload_sha256: String,
    pub body_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalStatus {
    Complete,
    NoQuery,
    NoCandidates,
    Abstained,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstentionReason {
    SubjectUnavailable,
    ScopeUnavailable,
    UniverseBound,
    ByteBound,
}

#[derive(Clone, Debug, Serialize)]
pub struct Completeness {
    pub visible_eligible_count: usize,
    pub selected_eligible_bytes: usize,
    pub universe_complete: bool,
    pub match_pool_complete: bool,
    pub matched_count: usize,
    pub rank_name_scalars: usize,
    pub rank_body_scalars: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct EligibleResponse {
    pub status: RetrievalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstention: Option<AbstentionReason>,
    pub provenance: SnapshotProvenance,
    pub completeness: Completeness,
    pub items: Vec<EligibleMetadata>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExtractionDiagnostics {
    pub version: &'static str,
    pub selected_terms: Vec<String>,
    pub fts_match: Option<String>,
    pub dropped_long_tokens: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RankedCandidate {
    pub rank: usize,
    pub score: f64,
    pub record: RecordCapture,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetrievalResponse {
    pub status: RetrievalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstention: Option<AbstentionReason>,
    pub provenance: SnapshotProvenance,
    pub completeness: Completeness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<RecordCapture>,
    pub extraction: ExtractionDiagnostics,
    pub candidates: Vec<RankedCandidate>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RevalidateResponse {
    pub valid: bool,
    pub provenance: SnapshotProvenance,
    pub reasons: Vec<String>,
    /// Populated only when every endpoint remains authorized and unchanged.
    pub records: Vec<RecordCapture>,
}

#[derive(Clone, Debug)]
struct CandidateRow {
    id: String,
    record_type: String,
    kind: String,
    name: String,
    body: Option<String>,
    home_id: Option<String>,
    lifecycle: Option<String>,
    updated_at: String,
    content_revision: i64,
}

impl CandidateRow {
    fn selected_bytes(&self) -> usize {
        self.name
            .len()
            .saturating_add(self.body.as_deref().map_or(0, str::len))
    }

    fn capture(&self, database_id: &str) -> RecordCapture {
        let payload = serde_json::json!({
            "database_id": database_id,
            "id": self.id,
            "type": self.record_type,
            "kind": self.kind,
            "name": self.name,
            "body": self.body,
            "home_id": self.home_id,
            "lifecycle": self.lifecycle,
            "updated_at": self.updated_at,
            "content_revision": self.content_revision,
        });
        let payload_sha256 = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&payload).expect("JSON value is canonically serializable"),
        ));
        RecordCapture {
            database_id: database_id.into(),
            id: self.id.clone(),
            record_type: self.record_type.clone(),
            kind: self.kind.clone(),
            name: self.name.clone(),
            body: self.body.clone(),
            home_id: self.home_id.clone(),
            lifecycle: self.lifecycle.clone(),
            updated_at: self.updated_at.clone(),
            content_revision: self.content_revision,
            payload_sha256,
        }
    }
}

struct SnapshotContext<'a> {
    principal: Principal<'a>,
    membership_basis: MembershipBasis,
}

fn snapshot_context<'a>(
    credential: &'a str,
    evidence: &'a Option<FrozenMembershipEvidence>,
) -> Result<SnapshotContext<'a>> {
    if credential.trim().is_empty() {
        return Err(Error::engine(
            "relationship lint credential must not be blank",
        ));
    }
    match evidence {
        None => Ok(SnapshotContext {
            principal: Principal::bound(credential, false),
            membership_basis: MembershipBasis::OfflineUnverifiedNonMember,
        }),
        Some(evidence) => {
            if evidence.account_id != credential
                || evidence.hosted_database_id.trim().is_empty()
                || evidence.verified_at.trim().is_empty()
                || evidence.source.trim().is_empty()
            {
                return Err(Error::engine(
                    "frozen membership evidence must be complete and match the credential",
                ));
            }
            // The footing below encodes the evidence's own role claim, not a
            // live lookup, which cannot exist here: the only production
            // entry to this path is the offline standby lint binary, which
            // takes piped requests against a read-only database with no
            // catalog plane to consult. Member evidence is only ever minted
            // for members — the driver mints from live catalog state, where
            // guest and member are distinct — and guest evidence resolves as
            // a non-member here, so a guest attestation can never inherit
            // the members baseline. A request with no evidence resolves as
            // a non-member above, and forged evidence is outside the model:
            // the whole request, credential included, arrives over the same
            // trusted pipe. Downgrade after `verified_at` is inherent to
            // frozen evidence; the attestation age travels in the membership
            // basis provenance so consumers see exactly what was claimed
            // and when.
            let is_member = match evidence.role.as_str() {
                "owner" | "member" => true,
                "guest" => false,
                _ => {
                    return Err(Error::engine(
                        "frozen membership evidence carries an unsupported role",
                    ))
                }
            };
            Ok(SnapshotContext {
                principal: Principal::bound(credential, is_member),
                membership_basis: MembershipBasis::FrozenAuthenticatedMember {
                    account_id: evidence.account_id.clone(),
                    hosted_database_id: evidence.hosted_database_id.clone(),
                    verified_at: evidence.verified_at.clone(),
                    source: evidence.source.clone(),
                    role: evidence.role.clone(),
                },
            })
        }
    }
}

async fn snapshot_provenance(
    tx: &mut Transaction<'_, Sqlite>,
    membership_basis: MembershipBasis,
) -> Result<SnapshotProvenance> {
    let database_id = sqlx::query_scalar::<_, String>(
        "SELECT origin_db_id FROM database_identity WHERE singleton = 1",
    )
    .fetch_one(&mut **tx)
    .await?;
    let content_high_water =
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(&mut **tx)
            .await?;
    let authorization_epoch =
        sqlx::query_scalar::<_, i64>("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(&mut **tx)
            .await?;
    Ok(SnapshotProvenance {
        database_id,
        content_high_water,
        authorization_epoch,
        membership_basis,
    })
}

fn empty_completeness() -> Completeness {
    Completeness {
        visible_eligible_count: 0,
        selected_eligible_bytes: 0,
        universe_complete: false,
        match_pool_complete: false,
        matched_count: 0,
        rank_name_scalars: RANK_NAME_SCALARS,
        rank_body_scalars: RANK_BODY_SCALARS,
    }
}

fn resource_abstention(count: usize, bytes: usize) -> Option<AbstentionReason> {
    if count > UNIVERSE_LIMIT {
        Some(AbstentionReason::UniverseBound)
    } else if bytes > UNIVERSE_BYTES_LIMIT {
        Some(AbstentionReason::ByteBound)
    } else {
        None
    }
}

fn eligible_kind_predicate(alias: &str) -> String {
    let note = crate::generated::kinds::CoreKind::DocumentNote.sql_matches(alias);
    let task = crate::generated::kinds::CoreKind::WorkItemTask.sql_matches(alias);
    format!("(({note}) OR ({task}))")
}

fn shared_cohort_predicate(alias: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM policy_entries shared_entry
          WHERE shared_entry.policy_anchor_id={alias}.policy_anchor_id
            AND shared_entry.subject_kind='members'
            AND shared_entry.subject_id='native:members'
            AND shared_entry.effect='allow'
            AND shared_entry.capability IN ('view','edit'))"
    )
}

async fn subtree_ids(
    tx: &mut Transaction<'_, Sqlite>,
    roots: &[String],
) -> Result<HashSet<String>> {
    if roots.is_empty() {
        return Ok(HashSet::new());
    }
    let roots = serde_json::to_string(roots)?;
    let ids = sqlx::query_scalar::<_, String>(
        "WITH RECURSIVE subtree(id,path) AS (
           SELECT value,json_array(value) FROM json_each(?)
           UNION ALL
           SELECT child.id,json_insert(subtree.path,'$[#]',child.id)
             FROM subtree JOIN records child ON child.home_id=subtree.id
            WHERE NOT EXISTS (SELECT 1 FROM json_each(subtree.path) seen WHERE seen.value=child.id)
         ) SELECT DISTINCT id FROM subtree",
    )
    .bind(roots)
    .fetch_all(&mut **tx)
    .await?;
    Ok(ids.into_iter().collect())
}

async fn boundary_sets(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    boundary: &SelectionBoundary,
) -> Result<std::result::Result<(Option<HashSet<String>>, HashSet<String>), AbstentionReason>> {
    let scope = if let Some(scope_id) = &boundary.scope_id {
        let visible = authorization::effective_capability_on(tx, principal, scope_id)
            .await
            .is_ok_and(|capability| capability.allows(Capability::View));
        if !visible || !super::read::ordinary_record_read_eligible_live_in(tx, scope_id).await? {
            return Ok(Err(AbstentionReason::ScopeUnavailable));
        }
        Some(subtree_ids(tx, std::slice::from_ref(scope_id)).await?)
    } else {
        None
    };
    let mut excluded: HashSet<String> = boundary.exclude_ids.iter().cloned().collect();
    excluded.extend(subtree_ids(tx, &boundary.exclude_subtree_ids).await?);
    Ok(Ok((scope, excluded)))
}

fn candidate_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<CandidateRow> {
    Ok(CandidateRow {
        id: row.try_get("id")?,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        body: row.try_get("body")?,
        home_id: row.try_get("home_id")?,
        lifecycle: row.try_get("lifecycle")?,
        updated_at: row.try_get("updated_at")?,
        content_revision: row.try_get("content_revision")?,
    })
}

async fn candidate_by_id(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    id: &str,
    require_body: bool,
    require_shared: bool,
) -> Result<Option<CandidateRow>> {
    let kind = eligible_kind_predicate("r");
    let archived = super::NOT_ARCHIVED;
    let not_hidden = super::not_hidden_predicate("r");
    let shared = if require_shared {
        format!("AND {}", shared_cohort_predicate("r"))
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT r.id FROM records r
          WHERE r.id=? AND r.deleted_at IS NULL AND {kind} AND {archived}
            AND {not_hidden} {shared}"
    );
    if sqlx::query_scalar::<_, String>(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let visible = authorization::effective_capability_on(tx, principal, id)
        .await
        .is_ok_and(|capability| capability.allows(Capability::View));
    if !visible {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT r.id,r.type,r.kind,r.name,r.body,r.home_id,r.lifecycle,r.updated_at,
                COALESCE((SELECT MAX(seq) FROM content_events ce WHERE ce.record_id=r.id),0) AS content_revision
           FROM records r WHERE r.id=?",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    let mut candidate = candidate_from_row(&row)?;
    if require_body
        && !candidate
            .body
            .as_deref()
            .is_some_and(|body| !body.trim().is_empty())
    {
        return Ok(None);
    }
    redact_home_ids(tx, principal, std::slice::from_mut(&mut candidate)).await?;
    Ok(Some(candidate))
}

/// Parent placement is independently authorized. Child visibility never
/// licenses disclosing a hidden parent identifier.
async fn redact_home_ids(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    rows: &mut [CandidateRow],
) -> Result<()> {
    let parent_ids = rows
        .iter()
        .filter_map(|row| row.home_id.clone())
        .collect::<HashSet<_>>();
    if parent_ids.is_empty() {
        return Ok(());
    }
    let parent_ids_json = serde_json::to_string(&parent_ids)?;
    let not_hidden = super::not_hidden_predicate("r");
    let live_ids = sqlx::query_scalar::<_, String>(&format!(
        "SELECT r.id FROM records r
          WHERE r.id IN (SELECT value FROM json_each(?))
            AND r.deleted_at IS NULL AND {not_hidden}"
    ))
    .bind(parent_ids_json)
    .fetch_all(&mut **tx)
    .await?;
    let visible = authorization::ids_with_capability_preloaded_on(
        tx,
        principal,
        live_ids,
        Capability::View,
        false,
    )
    .await?
    .into_iter()
    .collect::<HashSet<_>>();
    for row in rows {
        if row.home_id.as_ref().is_some_and(|id| !visible.contains(id)) {
            row.home_id = None;
        }
    }
    Ok(())
}

async fn eligible_universe(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    boundary: &SelectionBoundary,
    omit_id: Option<&str>,
) -> Result<std::result::Result<Vec<CandidateRow>, AbstentionReason>> {
    let Ok((scope, excluded)) = boundary_sets(tx, principal, boundary).await? else {
        return Ok(Err(AbstentionReason::ScopeUnavailable));
    };
    let kind = eligible_kind_predicate("r");
    let archived = super::NOT_ARCHIVED;
    let not_hidden = super::not_hidden_predicate("r");
    let shared = if boundary.shared_only {
        format!("AND {}", shared_cohort_predicate("r"))
    } else {
        String::new()
    };
    let mut after = String::new();
    let mut visible_ids = Vec::new();
    let mut visible_bytes = 0_usize;
    loop {
        let sql = format!(
            "SELECT r.id,
                    length(CAST(r.name AS BLOB))
                      + length(CAST(COALESCE(r.body,'') AS BLOB)) AS selected_bytes
               FROM records r
              WHERE r.id>? AND r.deleted_at IS NULL AND {kind} AND {archived}
                AND {not_hidden} {shared}
              ORDER BY r.id LIMIT ?"
        );
        let rows = sqlx::query(&sql)
            .bind(&after)
            .bind(PAGE_SIZE)
            .fetch_all(&mut **tx)
            .await?;
        if rows.is_empty() {
            break;
        }
        after = rows.last().expect("nonempty page").try_get("id")?;
        let mut by_id = BTreeMap::new();
        for row in &rows {
            let id: String = row.try_get("id")?;
            if omit_id == Some(id.as_str())
                || excluded.contains(&id)
                || scope.as_ref().is_some_and(|scope| !scope.contains(&id))
            {
                continue;
            }
            let selected_bytes: i64 = row.try_get("selected_bytes")?;
            let selected_bytes = usize::try_from(selected_bytes)
                .map_err(|_| Error::engine("record selected byte count is invalid"))?;
            by_id.insert(id, selected_bytes);
        }
        let ids = by_id.keys().cloned().collect::<Vec<_>>();
        let authorized = authorization::ids_with_capability_preloaded_on(
            tx,
            principal,
            ids,
            Capability::View,
            false,
        )
        .await?;
        for id in authorized {
            if let Some(selected_bytes) = by_id.remove(&id) {
                visible_ids.push(id);
                visible_bytes = visible_bytes.saturating_add(selected_bytes);
                if let Some(reason) = resource_abstention(visible_ids.len(), visible_bytes) {
                    return Ok(Err(reason));
                }
            }
        }
        if rows.len() < PAGE_SIZE as usize {
            break;
        }
    }
    if visible_ids.is_empty() {
        return Ok(Ok(Vec::new()));
    }
    let ids_json = serde_json::to_string(&visible_ids)?;
    let rows = sqlx::query(
        "SELECT r.id,r.type,r.kind,r.name,r.body,r.home_id,r.lifecycle,r.updated_at,
                COALESCE((SELECT MAX(seq) FROM content_events ce WHERE ce.record_id=r.id),0) AS content_revision
           FROM records r WHERE r.id IN (SELECT value FROM json_each(?)) ORDER BY r.id",
    )
    .bind(ids_json)
    .fetch_all(&mut **tx)
    .await?;
    let mut visible = rows
        .iter()
        .map(candidate_from_row)
        .collect::<Result<Vec<_>>>()?;
    redact_home_ids(tx, principal, &mut visible).await?;
    debug_assert_eq!(visible_ids.len(), visible.len());
    debug_assert_eq!(
        visible_bytes,
        visible
            .iter()
            .map(CandidateRow::selected_bytes)
            .sum::<usize>()
    );
    Ok(Ok(visible))
}

fn provenance_completeness(rows: &[CandidateRow]) -> Completeness {
    Completeness {
        visible_eligible_count: rows.len(),
        selected_eligible_bytes: rows.iter().map(CandidateRow::selected_bytes).sum(),
        universe_complete: true,
        match_pool_complete: true,
        matched_count: 0,
        rank_name_scalars: RANK_NAME_SCALARS,
        rank_body_scalars: RANK_BODY_SCALARS,
    }
}

pub async fn list_eligible(db: &Db, request: &EligibleRequest) -> Result<EligibleResponse> {
    let context = snapshot_context(&request.credential, &request.frozen_membership_evidence)?;
    let mut tx = db.pool().begin().await?;
    let provenance = snapshot_provenance(&mut tx, context.membership_basis).await?;
    let response =
        match eligible_universe(&mut tx, context.principal, &request.boundary, None).await? {
            Ok(rows) => {
                let completeness = provenance_completeness(&rows);
                let items = rows
                    .iter()
                    .map(|row| {
                        let capture = row.capture(&provenance.database_id);
                        EligibleMetadata {
                            id: capture.id,
                            record_type: capture.record_type,
                            kind: capture.kind,
                            name: capture.name,
                            home_id: capture.home_id,
                            content_revision: capture.content_revision,
                            payload_sha256: capture.payload_sha256,
                            body_bytes: capture.body.as_deref().map_or(0, str::len),
                        }
                    })
                    .collect();
                EligibleResponse {
                    status: RetrievalStatus::Complete,
                    abstention: None,
                    provenance,
                    completeness,
                    items,
                }
            }
            Err(reason) => EligibleResponse {
                status: RetrievalStatus::Abstained,
                abstention: Some(reason),
                provenance,
                completeness: empty_completeness(),
                items: Vec::new(),
            },
        };
    tx.rollback().await?;
    Ok(response)
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedTerms {
    terms: Vec<String>,
    dropped_long_tokens: usize,
}

fn token_runs(input: &str) -> Vec<String> {
    input
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_lowercase())
        .collect()
}

fn extract_terms(name: &str, body: &str) -> ExtractedTerms {
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    let mut dropped_long_tokens = 0;
    for token in token_runs(name) {
        if token.chars().count() > TOKEN_SCALAR_LIMIT {
            dropped_long_tokens += 1;
        } else if !STOPWORDS.contains(&token.as_str()) && seen.insert(token.clone()) {
            selected.push(token);
            if selected.len() == TERM_LIMIT {
                return ExtractedTerms {
                    terms: selected,
                    dropped_long_tokens,
                };
            }
        }
    }
    let mut body_terms: HashMap<String, (usize, usize)> = HashMap::new();
    for (position, token) in token_runs(body).into_iter().enumerate() {
        if token.chars().count() > TOKEN_SCALAR_LIMIT {
            dropped_long_tokens += 1;
            continue;
        }
        if STOPWORDS.contains(&token.as_str()) || seen.contains(&token) {
            continue;
        }
        let entry = body_terms.entry(token).or_insert((0, position));
        entry.0 += 1;
    }
    let mut body_terms = body_terms.into_iter().collect::<Vec<_>>();
    body_terms.sort_by(
        |(left_term, (left_count, left_first)), (right_term, (right_count, right_first))| {
            right_count
                .cmp(left_count)
                .then_with(|| left_first.cmp(right_first))
                .then_with(|| left_term.cmp(right_term))
        },
    );
    selected.extend(
        body_terms
            .into_iter()
            .map(|(term, _)| term)
            .take(TERM_LIMIT.saturating_sub(selected.len())),
    );
    ExtractedTerms {
        terms: selected,
        dropped_long_tokens,
    }
}

fn quoted_or_match(terms: &[String]) -> Option<String> {
    (!terms.is_empty()).then(|| {
        terms
            .iter()
            .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" OR ")
    })
}

pub async fn retrieve(db: &Db, request: &RetrievalRequest) -> Result<RetrievalResponse> {
    let context = snapshot_context(&request.credential, &request.frozen_membership_evidence)?;
    let mut tx = db.pool().begin().await?;
    let provenance = snapshot_provenance(&mut tx, context.membership_basis).await?;
    let boundary = boundary_sets(&mut tx, context.principal, &request.boundary).await?;
    let Ok((scope, excluded)) = boundary else {
        let response = RetrievalResponse {
            status: RetrievalStatus::Abstained,
            abstention: Some(AbstentionReason::ScopeUnavailable),
            provenance,
            completeness: empty_completeness(),
            subject: None,
            extraction: ExtractionDiagnostics {
                version: EXTRACTION_VERSION,
                selected_terms: Vec::new(),
                fts_match: None,
                dropped_long_tokens: 0,
            },
            candidates: Vec::new(),
        };
        tx.rollback().await?;
        return Ok(response);
    };
    if excluded.contains(&request.subject_id)
        || scope
            .as_ref()
            .is_some_and(|scope| !scope.contains(&request.subject_id))
    {
        let response = RetrievalResponse {
            status: RetrievalStatus::Abstained,
            abstention: Some(AbstentionReason::SubjectUnavailable),
            provenance,
            completeness: empty_completeness(),
            subject: None,
            extraction: ExtractionDiagnostics {
                version: EXTRACTION_VERSION,
                selected_terms: Vec::new(),
                fts_match: None,
                dropped_long_tokens: 0,
            },
            candidates: Vec::new(),
        };
        tx.rollback().await?;
        return Ok(response);
    }
    let Some(subject_row) = candidate_by_id(
        &mut tx,
        context.principal,
        &request.subject_id,
        true,
        request.boundary.shared_only,
    )
    .await?
    else {
        let response = RetrievalResponse {
            status: RetrievalStatus::Abstained,
            abstention: Some(AbstentionReason::SubjectUnavailable),
            provenance,
            completeness: empty_completeness(),
            subject: None,
            extraction: ExtractionDiagnostics {
                version: EXTRACTION_VERSION,
                selected_terms: Vec::new(),
                fts_match: None,
                dropped_long_tokens: 0,
            },
            candidates: Vec::new(),
        };
        tx.rollback().await?;
        return Ok(response);
    };
    let subject = subject_row.capture(&provenance.database_id);
    let extracted = extract_terms(&subject.name, subject.body.as_deref().unwrap_or(""));
    let match_expression = quoted_or_match(&extracted.terms);
    let extraction = ExtractionDiagnostics {
        version: EXTRACTION_VERSION,
        selected_terms: extracted.terms.clone(),
        fts_match: match_expression.clone(),
        dropped_long_tokens: extracted.dropped_long_tokens,
    };
    let universe = match eligible_universe(
        &mut tx,
        context.principal,
        &request.boundary,
        Some(&request.subject_id),
    )
    .await?
    {
        Ok(rows) => rows,
        Err(reason) => {
            let response = RetrievalResponse {
                status: RetrievalStatus::Abstained,
                abstention: Some(reason),
                provenance,
                completeness: empty_completeness(),
                subject: Some(subject),
                extraction,
                candidates: Vec::new(),
            };
            tx.rollback().await?;
            return Ok(response);
        }
    };
    let mut completeness = provenance_completeness(&universe);
    let Some(match_expression) = match_expression else {
        let response = RetrievalResponse {
            status: RetrievalStatus::NoQuery,
            abstention: None,
            provenance,
            completeness,
            subject: Some(subject),
            extraction,
            candidates: Vec::new(),
        };
        tx.rollback().await?;
        return Ok(response);
    };
    if universe.is_empty() {
        let response = RetrievalResponse {
            status: RetrievalStatus::NoCandidates,
            abstention: None,
            provenance,
            completeness,
            subject: Some(subject),
            extraction,
            candidates: Vec::new(),
        };
        tx.rollback().await?;
        return Ok(response);
    }
    let ids = universe
        .iter()
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    let ids_json = serde_json::to_string(&ids)?;
    let rows = sqlx::query(&format!(
        "SELECT r.id,substr(r.name,1,{RANK_NAME_SCALARS}) AS rank_name,
                substr(COALESCE(r.body,''),1,{RANK_BODY_SCALARS}) AS rank_body
           FROM records_fts JOIN records r ON r.rowid=records_fts.rowid
          WHERE records_fts MATCH ? AND r.id IN (SELECT value FROM json_each(?))
          ORDER BY r.id"
    ))
    .bind(match_expression)
    .bind(ids_json)
    .fetch_all(&mut *tx)
    .await?;
    completeness.matched_count = rows.len();
    let by_id = universe
        .into_iter()
        .map(|row| (row.id.clone(), row))
        .collect::<HashMap<_, _>>();
    let mut ranked = rows
        .into_iter()
        .map(|row| {
            let id: String = row.try_get("id")?;
            let rank_name: String = row.try_get("rank_name")?;
            let rank_body: String = row.try_get("rank_body")?;
            Ok((
                visibility_safe_score(&rank_name, Some(&rank_body), &extracted.terms),
                id,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    ranked.sort_by(|(left_score, left_id), (right_score, right_id)| {
        left_score
            .total_cmp(right_score)
            .then_with(|| left_id.cmp(right_id))
    });
    ranked.dedup_by(|left, right| left.1 == right.1);
    let candidates = ranked
        .into_iter()
        .take(SHORTLIST_LIMIT)
        .enumerate()
        .filter_map(|(index, (score, id))| {
            by_id.get(&id).map(|row| RankedCandidate {
                rank: index + 1,
                score,
                record: row.capture(&provenance.database_id),
            })
        })
        .collect::<Vec<_>>();
    let status = if candidates.is_empty() {
        RetrievalStatus::NoCandidates
    } else {
        RetrievalStatus::Complete
    };
    let response = RetrievalResponse {
        status,
        abstention: None,
        provenance,
        completeness,
        subject: Some(subject),
        extraction,
        candidates,
    };
    tx.rollback().await?;
    Ok(response)
}

pub async fn revalidate(db: &Db, request: &RevalidateRequest) -> Result<RevalidateResponse> {
    let context = snapshot_context(&request.credential, &request.frozen_membership_evidence)?;
    let mut tx = db.pool().begin().await?;
    let provenance = snapshot_provenance(&mut tx, context.membership_basis).await?;
    let Ok((scope, excluded)) =
        boundary_sets(&mut tx, context.principal, &request.boundary).await?
    else {
        let response = RevalidateResponse {
            valid: false,
            provenance,
            reasons: vec!["scope_unavailable".into()],
            records: Vec::new(),
        };
        tx.rollback().await?;
        return Ok(response);
    };
    let mut reasons = Vec::new();
    let mut captures = Vec::new();
    let unique = request
        .endpoints
        .iter()
        .map(|endpoint| endpoint.record_id.as_str())
        .collect::<HashSet<_>>();
    if unique.len() != request.endpoints.len() || request.endpoints.is_empty() {
        reasons.push("endpoints_must_be_nonempty_and_unique".into());
    }
    for expected in &request.endpoints {
        if expected.database_id != provenance.database_id {
            reasons.push(format!("{}:database_changed", expected.record_id));
            continue;
        }
        if excluded.contains(&expected.record_id)
            || scope
                .as_ref()
                .is_some_and(|scope| !scope.contains(&expected.record_id))
        {
            reasons.push(format!("{}:outside_boundary", expected.record_id));
            continue;
        }
        let Some(row) = candidate_by_id(
            &mut tx,
            context.principal,
            &expected.record_id,
            false,
            request.boundary.shared_only,
        )
        .await?
        else {
            reasons.push(format!("{}:unavailable", expected.record_id));
            continue;
        };
        let capture = row.capture(&provenance.database_id);
        if capture.content_revision != expected.content_revision
            || capture.payload_sha256 != expected.payload_sha256
        {
            reasons.push(format!("{}:stale", expected.record_id));
        }
        captures.push(capture);
    }
    let valid = reasons.is_empty();
    let response = RevalidateResponse {
        valid,
        provenance,
        reasons,
        records: if valid { captures } else { Vec::new() },
    };
    tx.rollback().await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn insert_record(
        db: &Db,
        id: &str,
        record_shape: (&str, &str),
        name: &str,
        body: Option<&str>,
        home_id: Option<&str>,
        account: &str,
    ) {
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,body,home_id,policy_anchor_id)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(id)
        .bind(record_shape.0)
        .bind(record_shape.1)
        .bind(name)
        .bind(body)
        .bind(home_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
        authorization::replace_explicit_policy_on(
            &mut tx,
            "test:relationship-lint",
            id,
            vec![authorization::AllowEntry::account(
                account,
                Capability::View,
            )],
            &mut act_alloc,
        )
        .await
        .unwrap();
        db.commit_authorization(tx).await.unwrap();
    }

    fn retrieval_request(subject_id: &str) -> RetrievalRequest {
        RetrievalRequest {
            credential: "acct:test".into(),
            frozen_membership_evidence: None,
            subject_id: subject_id.into(),
            boundary: SelectionBoundary::default(),
        }
    }

    #[test]
    fn unicode_extraction_is_deterministic_and_bounded() {
        let long = "界".repeat(TOKEN_SCALAR_LIMIT + 1);
        let extracted = extract_terms(
            "Résumé foo-bar O’Neil 東京 １２３",
            &format!("foo foo CAFÉ cafe\u{301} {long} 東京"),
        );
        assert_eq!(
            extracted.terms,
            [
                "résumé",
                "foo",
                "bar",
                "o",
                "neil",
                "東京",
                "１２３",
                "café",
                "cafe"
            ]
        );
        assert_eq!(extracted.dropped_long_tokens, 1);
        assert_eq!(
            quoted_or_match(&extracted.terms).unwrap(),
            "\"résumé\" OR \"foo\" OR \"bar\" OR \"o\" OR \"neil\" OR \"東京\" OR \"１２３\" OR \"café\" OR \"cafe\""
        );
    }

    #[test]
    fn name_terms_precede_body_frequency_and_ties_are_stable() {
        let extracted = extract_terms("zeta alpha zeta", "gamma beta gamma beta delta");
        assert_eq!(extracted.terms, ["zeta", "alpha", "gamma", "beta", "delta"]);
    }

    #[test]
    fn pre_body_resource_boundaries_are_exact() {
        assert_eq!(UNIVERSE_SENTINEL, 5_001);
        assert!(resource_abstention(4_999, UNIVERSE_BYTES_LIMIT).is_none());
        assert!(resource_abstention(5_000, UNIVERSE_BYTES_LIMIT).is_none());
        assert!(matches!(
            resource_abstention(5_001, 0),
            Some(AbstentionReason::UniverseBound)
        ));
        assert!(matches!(
            resource_abstention(5_000, UNIVERSE_BYTES_LIMIT + 1),
            Some(AbstentionReason::ByteBound)
        ));
        let row = |name: usize, body: usize| CandidateRow {
            id: "id".into(),
            record_type: "Document".into(),
            kind: "note".into(),
            name: "n".repeat(name),
            body: Some("b".repeat(body)),
            home_id: None,
            lifecycle: None,
            updated_at: "now".into(),
            content_revision: 1,
        };
        assert_eq!(
            row(1, UNIVERSE_BYTES_LIMIT - 1).selected_bytes(),
            UNIVERSE_BYTES_LIMIT
        );
        assert!(row(1, UNIVERSE_BYTES_LIMIT).selected_bytes() > UNIVERSE_BYTES_LIMIT);
    }

    #[tokio::test]
    async fn canonical_permission_filter_hides_corpus_and_parent_ids_before_ranking() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        insert_record(
            &db,
            "hidden-parent",
            ("Collection", "folder"),
            "Hidden parent",
            None,
            None,
            "acct:other",
        )
        .await;
        insert_record(
            &db,
            "subject",
            ("Document", "note"),
            "Quasar relationship",
            Some("the quasar evidence"),
            Some("hidden-parent"),
            "acct:test",
        )
        .await;
        insert_record(
            &db,
            "a-early",
            ("Document", "note"),
            "Quasar",
            None,
            Some("hidden-parent"),
            "acct:test",
        )
        .await;
        insert_record(
            &db,
            "z-late",
            ("WorkItem", "task"),
            "Quasar quasar quasar",
            Some("relationship quasar evidence quasar"),
            None,
            "acct:test",
        )
        .await;

        let before = retrieve(&db, &retrieval_request("subject")).await.unwrap();
        assert!(matches!(before.status, RetrievalStatus::Complete));
        assert_eq!(before.subject.as_ref().unwrap().home_id, None);
        assert_eq!(before.candidates[0].record.id, "z-late");
        assert_eq!(before.candidates[1].record.id, "a-early");
        assert_eq!(before.candidates[1].record.home_id, None);
        let before_scores = before
            .candidates
            .iter()
            .map(|candidate| (candidate.record.id.clone(), candidate.score))
            .collect::<Vec<_>>();

        insert_record(
            &db,
            "hidden-spam",
            ("Document", "note"),
            "Quasar quasar quasar quasar",
            Some(&"quasar ".repeat(1_000)),
            None,
            "acct:other",
        )
        .await;
        let after = retrieve(&db, &retrieval_request("subject")).await.unwrap();
        let after_scores = after
            .candidates
            .iter()
            .map(|candidate| (candidate.record.id.clone(), candidate.score))
            .collect::<Vec<_>>();
        assert_eq!(after_scores, before_scores);
        assert_eq!(after.completeness.visible_eligible_count, 2);

        let excluded_subject = retrieve(
            &db,
            &RetrievalRequest {
                boundary: SelectionBoundary {
                    exclude_subtree_ids: vec!["hidden-parent".into()],
                    ..SelectionBoundary::default()
                },
                ..retrieval_request("subject")
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            excluded_subject.abstention,
            Some(AbstentionReason::SubjectUnavailable)
        ));
        assert!(excluded_subject.subject.is_none());

        let outside_scope = retrieve(
            &db,
            &RetrievalRequest {
                boundary: SelectionBoundary {
                    scope_id: Some("a-early".into()),
                    ..SelectionBoundary::default()
                },
                ..retrieval_request("subject")
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            outside_scope.abstention,
            Some(AbstentionReason::SubjectUnavailable)
        ));
        assert!(outside_scope.subject.is_none());

        insert_record(
            &db,
            "whitespace-subject",
            ("Document", "note"),
            "Whitespace body",
            Some("\u{2003}\n\t"),
            None,
            "acct:test",
        )
        .await;
        let whitespace = retrieve(&db, &retrieval_request("whitespace-subject"))
            .await
            .unwrap();
        assert!(matches!(
            whitespace.abstention,
            Some(AbstentionReason::SubjectUnavailable)
        ));
        assert!(whitespace.subject.is_none());

        let eligible = list_eligible(
            &db,
            &EligibleRequest {
                credential: "acct:test".into(),
                frozen_membership_evidence: None,
                boundary: SelectionBoundary::default(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            eligible
                .items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            ["a-early", "subject", "whitespace-subject", "z-late"]
        );
        assert_eq!(eligible.items[0].body_bytes, 0);

        let shared_only = list_eligible(
            &db,
            &EligibleRequest {
                credential: "acct:test".into(),
                frozen_membership_evidence: None,
                boundary: SelectionBoundary {
                    shared_only: true,
                    ..SelectionBoundary::default()
                },
            },
        )
        .await
        .unwrap();
        assert!(shared_only.items.is_empty());
        db.close().await;
    }

    #[tokio::test]
    async fn revalidation_returns_no_content_when_one_endpoint_is_stale() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        insert_record(
            &db,
            "subject",
            ("Document", "note"),
            "Quasar",
            Some("quasar"),
            None,
            "acct:test",
        )
        .await;
        insert_record(
            &db,
            "candidate",
            ("Document", "note"),
            "Quasar candidate",
            Some("quasar"),
            None,
            "acct:test",
        )
        .await;
        let retrieval = retrieve(&db, &retrieval_request("subject")).await.unwrap();
        let subject = retrieval.subject.unwrap().fingerprint();
        let mut candidate = retrieval.candidates[0].record.fingerprint();
        candidate.payload_sha256 = "0".repeat(64);
        let response = revalidate(
            &db,
            &RevalidateRequest {
                credential: "acct:test".into(),
                frozen_membership_evidence: None,
                endpoints: vec![subject, candidate],
                boundary: SelectionBoundary::default(),
            },
        )
        .await
        .unwrap();
        assert!(!response.valid);
        assert!(response.records.is_empty());
        assert_eq!(response.reasons, ["candidate:stale"]);
        db.close().await;
    }
}

#[cfg(test)]
mod guest_evidence_tests {
    use super::*;

    fn evidence(role: &str) -> Option<FrozenMembershipEvidence> {
        Some(FrozenMembershipEvidence {
            account_id: "acct:guest".into(),
            hosted_database_id: "db:test".into(),
            verified_at: "2026-09-18T00:00:00Z".into(),
            source: "catalog".into(),
            role: role.into(),
        })
    }

    /// P3: frozen evidence carries the attested role, and guest evidence
    /// resolves as a non-member. Member evidence keeps member footing, and
    /// an unknown role fails closed instead of resolving either way.
    #[test]
    fn guest_evidence_maps_to_non_member_footing() {
        let member_evidence = evidence("member");
        let member = snapshot_context("acct:guest", &member_evidence).unwrap();
        assert!(member.principal.is_member);
        let owner_evidence = evidence("owner");
        let owner = snapshot_context("acct:guest", &owner_evidence).unwrap();
        assert!(owner.principal.is_member);
        let guest_evidence = evidence("guest");
        let guest = snapshot_context("acct:guest", &guest_evidence).unwrap();
        assert!(!guest.principal.is_member);
        assert_eq!(guest.principal.account_id, Some("acct:guest"));
        assert!(
            !snapshot_context("acct:guest", &None)
                .unwrap()
                .principal
                .is_member
        );
        let unknown_evidence = evidence("superadmin");
        assert!(snapshot_context("acct:guest", &unknown_evidence).is_err());
    }
}
