//! `query::fts` — the FTS5 query path. Backs tool 17 (`search`).
//!
//! Two indexes, two jobs (decisions 06c105b + 3c40677):
//!   - `records_fts` (name + body, `porter unicode61`) — stemmed full-text
//!     match and snippets. Index and query stem consistently by construction.
//!   - `records_name_idx` (name only, unstemmed `unicode61`) — the prefix
//!     path. Porter stores `running` as `run`, so `runni*` against the stemmed
//!     index silently returns nothing; prefix queries MUST run here.
//!
//! User input is never passed to MATCH raw: tokens are double-quoted into a
//! plain AND-of-terms match string, so FTS5 query syntax in user input cannot
//! error or subvert the search. Ranking rows in `tests/records/search_semantics.rs`
//! preserve the stage-5 intent: name over body, hard enough that a body-spam
//! record cannot outrank a name hit. Authorization removes raw BM25/IDF from
//! the product boundary because hidden corpus rows affect IDF. Shipping ranking
//! is a corpus-independent per-document score computed only after the caller
//! visibility predicate has selected candidates.
//!
//! A third mechanism serves mid-word infix (decision ea7e5bd): [`name_infix`],
//! a bounded per-token `LIKE` pass over `records.name`, run by tool 17 only
//! when FTS results are thin. Query-side by decision — no trigram index, no
//! second re-freeze; the frozen DDL is final on that question.
//!
//! Default visibility: tombstoned excluded always (the FTS triggers keep
//! tombstoned rows indexed — `record.deleted` is an UPDATE), archived excluded
//! unless asked.

use std::collections::HashSet;

use futures::TryStreamExt;
use serde::Serialize;
use sqlx::Row;

use super::{tree, NOT_ARCHIVED};
use crate::db::Db;
use crate::error::Result;

use super::error::contract_violation;

const MAX_LIMIT: i64 = 200;
const TRUSTED_CANDIDATE_CAP: i64 = 5_000;
pub(crate) const TRUSTED_NAME_CHARS: usize = 512;
const TRUSTED_RANK_BODY_CHARS: usize = 2_048;
const TRUSTED_SNIPPET_CHARS: usize = 2_048;
const TRUSTED_CANDIDATE_BYTES: usize = 4 * 1024 * 1024;

/// The Layer-1 near-miss bound (stage-5 call, `8e9f9d3`): tool 17 runs the
/// near-miss mechanisms only when strict FTS returns fewer hits than this.
/// Five is the seam between "results to work with" and "reformulation
/// territory" — below it the payload prompts reformulation and pays for the
/// extra scans; at or above it strict results stand alone.
pub const THIN_RESULTS_THRESHOLD: usize = 5;

/// Row cap per near-miss mechanism (the other half of the bound). Near-misses
/// are prompts for reformulation, not results — a page of them buries the
/// prompt. The time budget needs no separate enforcement: the infix pass is
/// ONE capped full scan of `records.name` (~1.3 MB at the measured 30k-name
/// corpus, 0.26–1.9 ms — b29a84a), and token count is not a multiplier since
/// AND short-circuits per row.
pub const NEAR_MISS_CAP: i64 = 10;

/// One search hit. `score` is corpus-independent (lower is better), so a
/// hidden record cannot change a visible row's score or ordering.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
    /// Redacted unless the parent is independently visible to this caller.
    pub home_id: Option<String>,
    /// Used only for structural near-miss discovery. Never serialized.
    #[serde(skip)]
    pub(crate) raw_home_id: Option<String>,
    pub score: f64,
    /// Body snippet around the match (name-prefix hits carry the name).
    pub snippet: String,
}

/// Options shared by [`search`] and [`name_prefix`].
#[derive(Debug, Clone, Default)]
pub struct FtsOptions {
    /// Restrict to the subtree rooted at this record id (`scope:` contract —
    /// the tree is the search-confidence hedge, 4da80fa).
    pub scope: Option<String>,
    pub include_archived: bool,
    /// Max hits (default 20, capped at 200).
    pub limit: Option<i64>,
    /// Restrict to these record types (empty = all). Applied inside the match
    /// query, so ranked results and pool counts agree with the restriction.
    pub types: Vec<String>,
}

/// Split free text into FTS5-safe quoted terms: each token is double-quoted
/// (embedded quotes doubled), which neutralizes all FTS5 query syntax. Returns
/// `None` when no token survives (punctuation-only input).
fn quoted_terms(input: &str) -> Option<String> {
    let terms: Vec<String> = input
        .split(|c: char| !c.is_alphanumeric() && c != '\u{2019}' && c != '\'')
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" "))
    }
}

/// Tokenize the way `unicode61` does — on runs of non-alphanumeric
/// characters, NOT on whitespace — so this pass and the FTS index never
/// disagree about what a query's terms are (`detail-record layout` must yield
/// `detail`, `record`, `layout`, or the predicate `%detail-record%` reaches
/// nothing). Every token is kept: under AND, dropping one removes a
/// constraint and *widens* recall, the opposite of a safeguard.
pub fn tokenize(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn effective_limit(limit: Option<i64>) -> Result<i64> {
    let limit = limit.unwrap_or(20);
    if limit <= 0 {
        return Err(contract_violation("search limit must be positive"));
    }
    Ok(limit.min(MAX_LIMIT))
}

#[derive(Clone, Copy)]
struct SearchPrincipal<'a> {
    credential: &'a str,
    trusted_local_bypass: bool,
}

async fn run_match(
    db: &Db,
    principal: SearchPrincipal<'_>,
    index_sql: &str, // the FROM/MATCH fragment, index-specific
    match_expr: &str,
    rank_terms: &[String],
    snippet_from_index: bool,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    let limit = effective_limit(opts.limit)?;
    let scope_ids = match &opts.scope {
        Some(root) => Some(
            tree::subtree_ids_with_hidden(db, root, false, false, opts.include_archived).await?,
        ),
        None => None,
    };
    let archived_filter = if opts.include_archived {
        String::new()
    } else {
        format!("AND {NOT_ARCHIVED}")
    };
    let scope_filter = match &scope_ids {
        Some(ids) => {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let placeholders = vec!["?"; ids.len()].join(", ");
            format!("AND r.id IN ({placeholders})")
        }
        None => String::new(),
    };
    let type_filter = if opts.types.is_empty() {
        String::new()
    } else {
        let placeholders = vec!["?"; opts.types.len()].join(", ");
        format!("AND r.type IN ({placeholders})")
    };
    let not_hidden = super::not_hidden_predicate("r");
    let view_filter = view_predicate("r");
    let sql = format!(
        "{index_sql}
          AND r.deleted_at IS NULL
          AND {not_hidden}
          AND {view_filter}
          {archived_filter}
          {scope_filter}
          {type_filter}
          ORDER BY r.id
          LIMIT ?"
    );
    let mut query = sqlx::query(&sql)
        .bind(match_expr)
        .bind(principal.trusted_local_bypass)
        .bind(principal.credential)
        .bind(principal.credential);
    if let Some(ids) = &scope_ids {
        for id in ids {
            query = query.bind(id);
        }
    }
    for t in &opts.types {
        query = query.bind(t);
    }
    let mut stream = query.bind(TRUSTED_CANDIDATE_CAP).fetch(db.write_pool());
    let mut hits = Vec::new();
    let mut candidate_bytes = 0_usize;
    while let Some(row) = stream.try_next().await? {
        let id: String = row.try_get("id")?;
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let name: String = row.try_get("name")?;
        let body: Option<String> = row.try_get("_rank_body")?;
        let raw_home_id: Option<String> = row.try_get("home_id")?;
        let snippet = if snippet_from_index {
            row.try_get("snippet")?
        } else {
            name.clone()
        };
        let row_bytes = id
            .len()
            .saturating_add(record_type.len())
            .saturating_add(kind.as_ref().map_or(0, String::len))
            .saturating_add(name.len())
            .saturating_add(body.as_ref().map_or(0, String::len))
            .saturating_add(raw_home_id.as_ref().map_or(0, String::len))
            .saturating_add(snippet.len());
        if candidate_bytes.saturating_add(row_bytes) > TRUSTED_CANDIDATE_BYTES {
            break;
        }
        candidate_bytes += row_bytes;
        hits.push(SearchHit {
            id,
            record_type,
            kind,
            score: visibility_safe_score(&name, body.as_deref(), rank_terms),
            name,
            home_id: None,
            raw_home_id,
            snippet,
        });
    }
    drop(stream);
    redact_parent_ids(
        db,
        principal.credential,
        principal.trusted_local_bypass,
        &mut hits,
    )
    .await?;
    hits.sort_by(|left, right| {
        left.score
            .total_cmp(&right.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    hits.truncate(limit as usize);
    Ok(hits)
}

/// Caller-view predicate shared by trusted lexical paths. Ordinary records use
/// their own owner/policy anchor. Every Annotation and Document:attachment
/// instead walks exactly-one live `part_of` edges to its first ordinary bearer;
/// malformed, bearerless, multi-bearer, tombstoned, cyclic, and over-depth
/// chains fail closed. The first placeholder selects the unforgeable trusted
/// local policy bypass; the remaining two bind the same transport-authenticated
/// portable credential against that resolved authorization subject.
pub(crate) fn view_predicate(alias: &str) -> String {
    let max_depth = crate::authorization::MAX_DERIVED_BEARER_DEPTH;
    format!(
        "EXISTS (
           WITH RECURSIVE bearer_walk(current_id, path, depth) AS (
             SELECT {alias}.id, json_array({alias}.id), 0
             UNION ALL
             SELECT bearer.id, json_insert(walk.path, '$[#]', bearer.id), walk.depth + 1
             FROM bearer_walk walk
             JOIN records current ON current.id = walk.current_id
             JOIN links part
               ON part.source_id = current.id AND part.relationship = 'part_of'
             JOIN records bearer ON bearer.id = part.target_id
             WHERE (current.type = 'Annotation'
                    OR (current.type = 'Document' AND current.kind IS 'attachment'))
               AND current.deleted_at IS NULL
               AND bearer.deleted_at IS NULL
               AND (SELECT COUNT(*) FROM links all_parts
                    WHERE all_parts.source_id = current.id
                      AND all_parts.relationship = 'part_of') = 1
               AND NOT EXISTS (
                     SELECT 1 FROM json_each(walk.path) visited
                     WHERE visited.value = bearer.id
                   )
               AND walk.depth < {max_depth}
           )
           SELECT 1
           FROM bearer_walk walk
           JOIN records authorization_subject
             ON authorization_subject.id = walk.current_id
           WHERE authorization_subject.deleted_at IS NULL
             AND NOT (authorization_subject.type = 'Annotation'
                      OR (authorization_subject.type = 'Document'
                          AND authorization_subject.kind IS 'attachment'))
             -- Derived artefacts whose bearer is a Unit stay out of generic
             -- lexical discovery; direct Unit reads use composite auth.
             AND NOT EXISTS (
                   SELECT 1 FROM semantic_units semantic_subject
                   WHERE semantic_subject.unit_id = authorization_subject.id
                 )
             AND EXISTS (
                   SELECT 1 FROM record_policies explicit_policy
                   WHERE explicit_policy.record_id = authorization_subject.policy_anchor_id
                 )
             AND (? = 1 OR (EXISTS (
                   SELECT 1 FROM bindings owner_account
                   WHERE owner_account.record_id = authorization_subject.owner_id
                     AND owner_account.system = 'account'
                     AND owner_account.identifier = ?
                     AND owner_account.is_canonical = 1
                 )
                OR EXISTS (
                   SELECT 1 FROM policy_entries entry
                   WHERE entry.policy_anchor_id = authorization_subject.policy_anchor_id
                     AND entry.effect = 'allow'
                     AND entry.capability IN ('view','edit','manage')
                     AND ((entry.subject_kind = 'members'
                           AND entry.subject_id = 'native:members')
                          OR (entry.subject_kind = 'account'
                              AND entry.subject_id = ?))
                 )))
         )"
    )
}

/// Resolve only those IDs that are independently public to this caller. This
/// is intentionally a second authorization check: visibility of a child never
/// implies that its structural parent identifier may be surfaced.
pub(crate) async fn independently_visible_ids(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    ids: &[String],
) -> Result<HashSet<String>> {
    let unique: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let mut visible = HashSet::new();
    for chunk in unique.into_iter().collect::<Vec<_>>().chunks(400) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let not_hidden = super::not_hidden_predicate("r");
        let view_filter = view_predicate("r");
        let sql = format!(
            "SELECT r.id FROM records r
              WHERE r.id IN ({placeholders})
                AND r.deleted_at IS NULL
                AND {not_hidden}
                AND {view_filter}"
        );
        let mut query = sqlx::query_scalar::<_, String>(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        query = query
            .bind(trusted_local_bypass)
            .bind(credential)
            .bind(credential);
        visible.extend(query.fetch_all(db.write_pool()).await?);
    }
    Ok(visible)
}

async fn redact_parent_ids(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    hits: &mut [SearchHit],
) -> Result<()> {
    let parent_ids: Vec<String> = hits
        .iter()
        .filter_map(|hit| hit.raw_home_id.clone())
        .collect();
    let visible =
        independently_visible_ids(db, credential, trusted_local_bypass, &parent_ids).await?;
    for hit in hits {
        hit.home_id = hit
            .raw_home_id
            .as_ref()
            .filter(|id| visible.contains(*id))
            .cloned();
    }
    Ok(())
}

pub(crate) fn visibility_safe_score(name: &str, body: Option<&str>, terms: &[String]) -> f64 {
    let name = name.to_lowercase();
    let body = body.unwrap_or("").to_lowercase();
    let mut relevance = 0_u64;
    for term in terms {
        let term = term.to_lowercase();
        relevance += 10 * name.match_indices(&term).count() as u64;
        relevance += body.match_indices(&term).count() as u64;
        if name == term {
            relevance += 20;
        } else if name.starts_with(&term) {
            relevance += 5;
        }
    }
    -(relevance as f64)
}

/// Stemmed full-text search over name + body (`records_fts`), ranked from the
/// caller-visible candidate text only.
/// Terms are ANDed. Empty/punctuation-only input returns no hits.
pub async fn search(
    db: &Db,
    credential: &str,
    input: &str,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    search_with_policy_bypass(db, credential, false, input, opts).await
}

/// Tool-facing search variant. Trusted local callers bypass policy grants but
/// still pass the identical liveness, shape, cycle, and recursion checks.
pub(crate) async fn search_with_policy_bypass(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    input: &str,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    let Some(match_expr) = quoted_terms(input) else {
        return Ok(Vec::new());
    };
    let index_sql = format!(
        "SELECT r.id, r.type, r.kind,
                substr(r.name, 1, {TRUSTED_NAME_CHARS}) AS name,
                substr(r.body, 1, {TRUSTED_RANK_BODY_CHARS}) AS _rank_body, r.home_id,
                coalesce(substr(snippet(records_fts, 1, '[', ']', ' … ', 12),
                                1, {TRUSTED_SNIPPET_CHARS}), '') AS snippet
          FROM records_fts
          JOIN records r ON r.rowid = records_fts.rowid
          WHERE records_fts MATCH ?"
    );
    let rank_terms = tokenize(input);
    run_match(
        db,
        SearchPrincipal {
            credential,
            trusted_local_bypass,
        },
        &index_sql,
        &match_expr,
        &rank_terms,
        true,
        opts,
    )
    .await
}

/// The UNCAPPED pool size for the same match + visibility + scope + type
/// filters as [`search`] — for callers (`scan`) that promise a full pool
/// count beside a bounded sample. `opts.limit` is ignored by definition.
pub async fn search_pool_count(
    db: &Db,
    credential: &str,
    input: &str,
    opts: &FtsOptions,
) -> Result<i64> {
    search_pool_count_with_policy_bypass(db, credential, false, input, opts).await
}

pub(crate) async fn search_pool_count_with_policy_bypass(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    input: &str,
    opts: &FtsOptions,
) -> Result<i64> {
    let Some(match_expr) = quoted_terms(input) else {
        return Ok(0);
    };
    let scope_ids = match &opts.scope {
        Some(root) => Some(
            tree::subtree_ids_with_hidden(db, root, false, false, opts.include_archived).await?,
        ),
        None => None,
    };
    let archived_filter = if opts.include_archived {
        String::new()
    } else {
        format!("AND {NOT_ARCHIVED}")
    };
    let scope_filter = match &scope_ids {
        Some(ids) => {
            if ids.is_empty() {
                return Ok(0);
            }
            let placeholders = vec!["?"; ids.len()].join(", ");
            format!("AND r.id IN ({placeholders})")
        }
        None => String::new(),
    };
    let type_filter = if opts.types.is_empty() {
        String::new()
    } else {
        let placeholders = vec!["?"; opts.types.len()].join(", ");
        format!("AND r.type IN ({placeholders})")
    };
    let not_hidden = super::not_hidden_predicate("r");
    let view_filter = view_predicate("r");
    let sql = format!(
        "SELECT COUNT(*) AS n
          FROM records_fts
          JOIN records r ON r.rowid = records_fts.rowid
          WHERE records_fts MATCH ?
            AND r.deleted_at IS NULL
            AND {not_hidden}
            AND {view_filter}
            {archived_filter}
            {scope_filter}
            {type_filter}"
    );
    let mut query = sqlx::query(&sql)
        .bind(&match_expr)
        .bind(trusted_local_bypass)
        .bind(credential)
        .bind(credential);
    if let Some(ids) = &scope_ids {
        for id in ids {
            query = query.bind(id);
        }
    }
    for t in &opts.types {
        query = query.bind(t);
    }
    Ok(query.fetch_one(db.write_pool()).await?.try_get("n")?)
}

/// Word-initial prefix search over `name`, against the UNSTEMMED sibling
/// (`records_name_idx`) — the near-miss surface Layer 1 leans on. The final
/// token matches as a prefix; earlier tokens match whole.
pub async fn name_prefix(
    db: &Db,
    credential: &str,
    input: &str,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    name_prefix_with_policy_bypass(db, credential, false, input, opts).await
}

pub(crate) async fn name_prefix_with_policy_bypass(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    input: &str,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    let Some(terms) = quoted_terms(input) else {
        return Ok(Vec::new());
    };
    let match_expr = format!("{terms}*"); // `"foo" "ba"*` — prefix on the last term
    let index_sql = format!(
        "SELECT r.id, r.type, r.kind,
                substr(r.name, 1, {TRUSTED_NAME_CHARS}) AS name,
                substr(r.body, 1, {TRUSTED_RANK_BODY_CHARS}) AS _rank_body, r.home_id
          FROM records_name_idx
          JOIN records r ON r.rowid = records_name_idx.rowid
          WHERE records_name_idx MATCH ?"
    );
    let rank_terms = tokenize(input);
    run_match(
        db,
        SearchPrincipal {
            credential,
            trusted_local_bypass,
        },
        &index_sql,
        &match_expr,
        &rank_terms,
        false,
        opts,
    )
    .await
}

/// Mid-word infix over `records.name` — the bounded per-token `LIKE` pass
/// (decision ea7e5bd; composition fixed by the search contract and pinned by
/// `tests/records/search_semantics.rs`). This is what surfaces `DetailRecordLayout`
/// for "detail record layout": camelCase identifiers are ONE `unicode61`
/// token, unreachable mid-word from either FTS index.
///
/// One `LIKE '%tok%'` predicate per [`tokenize`] token, `AND`-ed (OR
/// degenerates to near-corpus recall); `%`/`_` escaped with an explicit
/// `ESCAPE` clause as a safety net (the tokenizer cannot emit them);
/// ASCII-case-insensitive from `LIKE`'s default semantics — the engine never
/// enables `PRAGMA case_sensitive_like`. Unicode folding is out of v1 scope.
///
/// All-separator input constrains nothing and returns no hits (fails closed).
/// Shorter names order first — with substring predicates, the shortest name
/// containing every token is the tightest match.
pub async fn name_infix(
    db: &Db,
    credential: &str,
    input: &str,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    name_infix_with_policy_bypass(db, credential, false, input, opts).await
}

pub(crate) async fn name_infix_with_policy_bypass(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    input: &str,
    opts: &FtsOptions,
) -> Result<Vec<SearchHit>> {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let limit = effective_limit(opts.limit)?;
    let scope_ids = match &opts.scope {
        Some(root) => Some(
            tree::subtree_ids_with_hidden(db, root, false, false, opts.include_archived).await?,
        ),
        None => None,
    };
    let archived_filter = if opts.include_archived {
        String::new()
    } else {
        format!("AND {NOT_ARCHIVED}")
    };
    let scope_filter = match &scope_ids {
        Some(ids) => {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let placeholders = vec!["?"; ids.len()].join(", ");
            format!("AND r.id IN ({placeholders})")
        }
        None => String::new(),
    };
    let type_filter = if opts.types.is_empty() {
        String::new()
    } else {
        let placeholders = vec!["?"; opts.types.len()].join(", ");
        format!("AND r.type IN ({placeholders})")
    };
    let predicates = vec!["r.name LIKE ? ESCAPE '\\'"; tokens.len()].join(" AND ");
    let not_hidden = super::not_hidden_predicate("r");
    let view_filter = view_predicate("r");
    let sql = format!(
        "SELECT r.id, r.type, r.kind,
                substr(r.name, 1, {TRUSTED_NAME_CHARS}) AS name, r.home_id,
                0.0 AS score,
                substr(r.name, 1, {TRUSTED_SNIPPET_CHARS}) AS snippet
          FROM records r
          WHERE {predicates}
            AND r.deleted_at IS NULL
            AND {not_hidden}
            AND {view_filter}
            {archived_filter}
            {scope_filter}
            {type_filter}
          ORDER BY length(r.name), r.name, r.id
          LIMIT ?"
    );
    let mut query = sqlx::query(&sql);
    for token in &tokens {
        let escaped = token
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        query = query.bind(format!("%{escaped}%"));
    }
    query = query
        .bind(trusted_local_bypass)
        .bind(credential)
        .bind(credential);
    if let Some(ids) = &scope_ids {
        for id in ids {
            query = query.bind(id);
        }
    }
    for t in &opts.types {
        query = query.bind(t);
    }
    let rows = query.bind(limit).fetch_all(db.write_pool()).await?;
    let mut hits = rows
        .iter()
        .map(|row| {
            let raw_home_id = row.try_get("home_id")?;
            Ok(SearchHit {
                id: row.try_get("id")?,
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                name: row.try_get("name")?,
                home_id: None,
                raw_home_id,
                score: row.try_get("score")?,
                snippet: row.try_get("snippet")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    redact_parent_ids(db, credential, trusted_local_bypass, &mut hits).await?;
    Ok(hits)
}
