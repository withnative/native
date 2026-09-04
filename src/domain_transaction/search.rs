//! Bounded backend-native lexical search shared by Postgres and Turso-local.
//!
//! The physical adapter owns candidate selection against its installed FTS
//! index. This module owns the observable Native envelope: argument validation,
//! caller/no-oracle filtering, subtree scope, corpus-independent ranking,
//! deterministic ties, snippets, near-miss prompting, caps, and redaction.
//! It deliberately does not claim tokenizer or index identity between engines.

use std::collections::{HashMap, HashSet};

use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::{json, Value};

use super::views_history::{self, PortableRecord, SnapshotRows, MAX_VIEW_CANDIDATES};
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::portable_sql::DomainStatementExecutor;
use crate::query::fts::{self, SearchHit, NEAR_MISS_CAP, THIN_RESULTS_THRESHOLD};

pub(crate) const NATIVE_CANDIDATE_CAP: i64 = 5_000;
pub(crate) const NATIVE_CANDIDATE_BYTES: usize = 4 * 1024 * 1024;
const RANK_BODY_CHARS: usize = 2_048;
const SNIPPET_CHARS: usize = 2_048;
const SNIPPET_CONTEXT_CHARS: usize = 80;

#[derive(Clone, Debug)]
pub(crate) struct NativeSearchCandidate {
    pub id: String,
    pub name: String,
    pub body: Option<String>,
}

/// Named physical boundary: implementations must use the installed backend
/// FTS index in the caller's already-admitted read snapshot.
pub(crate) trait SearchPhysicalPort: DomainStatementExecutor {
    fn native_lexical_candidates<'a>(
        &'a mut self,
        terms: &'a [String],
        eligible_ids: &'a HashSet<String>,
        cap: i64,
    ) -> BoxFuture<'a, Result<Vec<NativeSearchCandidate>>>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    scope: Option<String>,
    limit: Option<i64>,
    include_archived: Option<bool>,
}

async fn load_snapshot<E: DomainStatementExecutor>(executor: &mut E) -> Result<SnapshotRows> {
    let records = views_history::statement(
        "records",
        &[
            "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r ORDER BY r.id",
        ],
    )?;
    let raw = executor
        .fetch_all(&records, &[], &views_history::record_columns())
        .await
        .map_err(views_history::storage_error)?;
    let mut records = HashMap::with_capacity(raw.len());
    for row in &raw {
        let record = views_history::record_from_row(row)?;
        records.insert(record.row.id.clone(), record);
    }
    // Search has no link-derived eligibility rule. Loading the global link
    // catalogue here used to make unrelated or unauthorized link volume an
    // observable error oracle before caller filtering.
    Ok(SnapshotRows {
        records,
        links: Vec::new(),
    })
}

fn eligible_path(
    rows: &SnapshotRows,
    visible: &HashSet<String>,
    hidden: &HashSet<String>,
    id: &str,
    scope: Option<&str>,
    include_archived: bool,
) -> bool {
    let Some(record) = rows.records.get(id) else {
        return false;
    };
    if record.row.deleted_at.is_some()
        || (!include_archived && record.archived)
        || hidden.contains(id)
        || !visible.contains(id)
    {
        return false;
    }
    // An unscoped search authorizes each bearer independently. Requiring an
    // otherwise-visible child to have a visible containment ancestry would
    // leak tree shape into the global search contract and diverge from the
    // SQLite reference predicate.
    let Some(scope) = scope else {
        return true;
    };
    let mut current = Some(id);
    let mut seen = HashSet::new();
    let mut depth = 0_i64;
    while let Some(candidate) = current {
        if depth > crate::query::tree::MAX_WALK_DEPTH || !seen.insert(candidate) {
            return false;
        }
        let Some(record) = rows.records.get(candidate) else {
            return false;
        };
        // Containment is structural. SQLite walks live, non-governed,
        // non-archived ancestors and authorizes the candidate independently;
        // a visible child therefore survives a policy-redacted intermediate.
        if record.row.deleted_at.is_some()
            || (!include_archived && record.archived)
            || hidden.contains(candidate)
        {
            return false;
        }
        if scope == candidate {
            return true;
        }
        current = record.row.home_id.as_deref();
        depth += 1;
    }
    false
}

fn independently_visible_parent(
    rows: &SnapshotRows,
    visible: &HashSet<String>,
    hidden: &HashSet<String>,
    parent: Option<&String>,
) -> Option<String> {
    parent
        .filter(|id| {
            rows.records
                .get(id.as_str())
                .is_some_and(|record| record.row.deleted_at.is_none())
                && visible.contains(id.as_str())
                && !hidden.contains(id.as_str())
        })
        .cloned()
}

fn char_prefix(value: &str, cap: usize) -> String {
    value.chars().take(cap).collect()
}

fn snippet(name: &str, body: Option<&str>, terms: &[String]) -> String {
    let source = body
        .filter(|body| {
            // ASCII folding preserves byte offsets into `source`. Backend
            // tokenizer/collation identity is deliberately a Partial-cell
            // residual, but arbitrary Unicode input must still be panic-free.
            let folded = body.to_ascii_lowercase();
            terms
                .iter()
                .any(|term| folded.contains(&term.to_ascii_lowercase()))
        })
        .unwrap_or(name);
    let folded = source.to_ascii_lowercase();
    let earliest = terms
        .iter()
        .filter_map(|term| {
            folded
                .find(&term.to_ascii_lowercase())
                .map(|at| (at, term.len()))
        })
        .min_by_key(|(at, _)| *at);
    let Some((byte_at, byte_len)) = earliest else {
        return char_prefix(source, SNIPPET_CHARS);
    };
    let char_at = source[..byte_at].chars().count();
    let match_chars = source[byte_at..byte_at.saturating_add(byte_len).min(source.len())]
        .chars()
        .count();
    let start = char_at.saturating_sub(SNIPPET_CONTEXT_CHARS);
    let end = (char_at + match_chars + SNIPPET_CONTEXT_CHARS).min(source.chars().count());
    let before: String = source.chars().skip(start).take(char_at - start).collect();
    let matched: String = source.chars().skip(char_at).take(match_chars).collect();
    let after: String = source
        .chars()
        .skip(char_at + match_chars)
        .take(end - char_at - match_chars)
        .collect();
    char_prefix(
        &format!(
            "{}{}[{}]{}{}",
            if start > 0 { "… " } else { "" },
            before,
            matched,
            after,
            if end < source.chars().count() {
                " …"
            } else {
                ""
            }
        ),
        SNIPPET_CHARS,
    )
}

fn hit_json(hit: &SearchHit) -> Value {
    json!({
        "id":hit.id,
        "type":hit.record_type,
        "kind":hit.kind,
        "name":hit.name,
        "home_id":hit.home_id,
        "score":hit.score,
        "snippet":hit.snippet,
    })
}

fn words(value: &str) -> Vec<String> {
    fts::tokenize(value)
        .into_iter()
        .map(|token| token.to_lowercase())
        .collect()
}

fn prefix_match(name: &str, terms: &[String]) -> bool {
    let name = words(name);
    let Some((last, leading)) = terms.split_last() else {
        return false;
    };
    leading
        .iter()
        .all(|term| name.contains(&term.to_lowercase()))
        && name
            .iter()
            .any(|word| word.starts_with(&last.to_lowercase()))
}

fn infix_match(name: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return false;
    }
    let name = name.to_ascii_lowercase();
    terms
        .iter()
        .all(|term| name.contains(&term.to_ascii_lowercase()))
}

fn near_hit(
    record: &PortableRecord,
    rows: &SnapshotRows,
    visible: &HashSet<String>,
    hidden: &HashSet<String>,
) -> Value {
    json!({
        "id":record.row.id,
        "type":record.row.record_type,
        "kind":record.row.kind,
        "name":char_prefix(&record.row.name, crate::query::fts::TRUSTED_NAME_CHARS),
        "home_id":independently_visible_parent(rows, visible, hidden, record.row.home_id.as_ref()),
        "score":0.0,
        "snippet":char_prefix(&record.row.name, SNIPPET_CHARS),
    })
}

pub(crate) async fn execute<E: SearchPhysicalPort>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "search";
    let args: SearchArgs = crate::mcp::tools::parse_args(TOOL, arguments)?;
    if args.query.trim().is_empty() {
        return Err(Error::engine("search: 'query' must be non-empty"));
    }
    let limit = fts::effective_limit(args.limit)?;
    let terms = fts::tokenize(&args.query);
    let include_archived = args.include_archived.unwrap_or(false);
    let rows = load_snapshot(executor).await?;
    let visible = views_history::visible_ids(executor, caller, &rows).await?;
    let (hidden, _) = views_history::hidden_ids(executor, &rows.records).await?;
    if let Some(scope) = args.scope.as_deref() {
        // Scope lookup follows the reference no-oracle rule independently of
        // archive filtering. An archived but authorized root is a valid scope;
        // it simply yields no default-archive candidates.
        if rows
            .records
            .get(scope)
            .is_none_or(|record| record.row.deleted_at.is_some())
            || hidden.contains(scope)
            || !visible.contains(scope)
        {
            return Err(Error::engine(format!(
                "search: record {scope} does not exist"
            )));
        }
    }

    let eligible_ids = rows
        .records
        .keys()
        .filter(|id| {
            eligible_path(
                &rows,
                &visible,
                &hidden,
                id,
                args.scope.as_deref(),
                include_archived,
            )
        })
        .cloned()
        .collect::<HashSet<_>>();
    if eligible_ids.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "search eligible catalogue exceeds {MAX_VIEW_CANDIDATES} records"
        )));
    }

    let candidates = if terms.is_empty() {
        Vec::new()
    } else {
        executor
            .native_lexical_candidates(&terms, &eligible_ids, NATIVE_CANDIDATE_CAP + 1)
            .await?
    };
    if candidates.len() > NATIVE_CANDIDATE_CAP as usize {
        return Err(Error::engine(format!(
            "search native lexical candidate set exceeds {NATIVE_CANDIDATE_CAP} records"
        )));
    }
    let mut candidate_bytes = 0_usize;
    let mut hits = Vec::new();
    let mut candidate_ids = HashSet::new();
    for candidate in candidates {
        if !candidate_ids.insert(candidate.id.clone()) || !eligible_ids.contains(&candidate.id) {
            continue;
        }
        let Some(record) = rows.records.get(&candidate.id) else {
            continue;
        };
        let name = char_prefix(&candidate.name, crate::query::fts::TRUSTED_NAME_CHARS);
        let body = candidate
            .body
            .as_deref()
            .map(|body| char_prefix(body, RANK_BODY_CHARS));
        let bytes = candidate.id.len() + name.len() + body.as_ref().map_or(0, String::len);
        if candidate_bytes.saturating_add(bytes) > NATIVE_CANDIDATE_BYTES {
            break;
        }
        candidate_bytes += bytes;
        hits.push(SearchHit {
            id: candidate.id,
            record_type: record.row.record_type.clone(),
            kind: record.row.kind.clone(),
            name: name.clone(),
            home_id: independently_visible_parent(
                &rows,
                &visible,
                &hidden,
                record.row.home_id.as_ref(),
            ),
            raw_home_id: record.row.home_id.clone(),
            score: fts::visibility_safe_score(&name, body.as_deref(), &terms),
            snippet: snippet(&name, candidate.body.as_deref(), &terms),
        });
    }
    hits.sort_by(|left, right| {
        left.score
            .total_cmp(&right.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    hits.truncate(limit as usize);
    let thin = hits.len() < THIN_RESULTS_THRESHOLD;
    let mut payload = json!({
        "query":args.query,
        "scope":args.scope,
        "hits":hits.iter().map(hit_json).collect::<Vec<_>>(),
        "total":hits.len(),
        "returned":hits.len(),
        "limit":limit,
        "limit_reached":hits.len() as i64 == limit,
        "thin":thin,
    });
    if thin {
        let mut seen = hits
            .iter()
            .map(|hit| hit.id.clone())
            .collect::<HashSet<_>>();
        let mut eligible = rows
            .records
            .values()
            .filter(|record| {
                !seen.contains(&record.row.id) && eligible_ids.contains(&record.row.id)
            })
            .collect::<Vec<_>>();
        eligible.sort_by(|left, right| {
            left.row
                .name
                .cmp(&right.row.name)
                .then(left.row.id.cmp(&right.row.id))
        });
        let prefix = eligible
            .iter()
            .copied()
            .filter(|record| prefix_match(&record.row.name, &terms))
            .filter(|record| seen.insert(record.row.id.clone()))
            .take(NEAR_MISS_CAP as usize)
            .map(|record| near_hit(record, &rows, &visible, &hidden))
            .collect::<Vec<_>>();
        let mut infix_candidates = eligible.clone();
        infix_candidates.sort_by(|left, right| {
            left.row
                .name
                .len()
                .cmp(&right.row.name.len())
                .then(left.row.name.cmp(&right.row.name))
                .then(left.row.id.cmp(&right.row.id))
        });
        let infix = infix_candidates
            .iter()
            .copied()
            .filter(|record| infix_match(&record.row.name, &terms))
            .filter(|record| seen.insert(record.row.id.clone()))
            .take(NEAR_MISS_CAP as usize)
            .map(|record| near_hit(record, &rows, &visible, &hidden))
            .collect::<Vec<_>>();
        let homes = hits
            .iter()
            .filter_map(|hit| hit.raw_home_id.as_deref())
            .collect::<HashSet<_>>();
        let siblings = eligible
            .iter()
            .copied()
            .filter(|record| {
                record
                    .row
                    .home_id
                    .as_deref()
                    .is_some_and(|home| homes.contains(home))
            })
            .filter(|record| seen.insert(record.row.id.clone()))
            .take(NEAR_MISS_CAP as usize)
            .map(|record| {
                let mut value = near_hit(record, &rows, &visible, &hidden);
                value.as_object_mut().unwrap().remove("score");
                value.as_object_mut().unwrap().remove("snippet");
                value
            })
            .collect::<Vec<_>>();
        let any = !(prefix.is_empty() && infix.is_empty() && siblings.is_empty());
        let mut guidance = if hits.is_empty() {
            format!("No full-text matches for {:?}.", args.query)
        } else {
            format!(
                "Only {} full-text match(es) for {:?} — likely not exhaustive.",
                hits.len(),
                args.query
            )
        };
        guidance.push_str(" Consider reformulating: try synonyms or alternative phrasings, fewer or more specific terms, or query_record for structured filtering.");
        if any {
            guidance.push_str(" Near-miss candidates are listed under 'near_misses' — name_prefix (typed-prefix neighbours), name_infix (mid-word name matches, e.g. camelCase identifiers), and tree_siblings (records adjacent to the hits).");
        }
        let object = payload.as_object_mut().expect("search payload");
        object.insert(
            "near_misses".into(),
            json!({"name_prefix":prefix,"name_infix":infix,"tree_siblings":siblings}),
        );
        object.insert("guidance".into(), json!(guidance));
    }
    Ok(payload)
}
