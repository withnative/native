//! Post-write "similar records already exist" advisory for `create_record`.
//!
//! This is the SQLite product path only. The Postgres and Turso-local
//! `create_record` implementations and their compact-receipt allowlists are
//! deliberately untouched, so the notice does not appear on those substrates.
//!
//! After a creation commits, this module runs one bounded lexical lookup over
//! the new record's name and reports at most a small fixed number of existing
//! records that look like the same thing. It is advisory and fail-silent: the
//! notice is attached after the write, and any failure in this module is
//! swallowed rather than propagated, so a write can never fail because of it.
//! There is no enforced deadline — bounded work is not bounded latency — but
//! the lookup never blocks on another writer and issues a small fixed number
//! of indexed queries.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use sqlx::Row;

use crate::db::Db;
use crate::error::Result;

use super::super::registry::Caller;

/// Fixed bound on the notice. A long list is noise and gets ignored, which is
/// worse than silence: the writer learns to skip the field.
pub(super) const SIMILAR_EXISTING_LIMIT: usize = 3;

/// Names shorter than this contribute no term. One-character tokens are almost
/// always noise and would make the gate fire on unrelated records.
const MIN_TERM_CHARS: usize = 2;

/// Caps on how far a single creation can fan the query out.
const TERM_LIMIT: usize = 12;
const CANDIDATE_CAP: usize = 50;
const WHY_TERM_LIMIT: usize = 5;

/// The precision rule's stopword list. Deliberately shared with nothing: this
/// is a local, conservative list, and widening it later only removes matches.
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is",
    "it", "its", "of", "on", "or", "that", "the", "this", "to", "was", "were", "will", "with",
];

pub(super) async fn notice_for_create(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    exclude_ids: &[String],
) -> Option<Value> {
    detect(db, caller, record_id, exclude_ids)
        .await
        .ok()
        .flatten()
}

async fn detect(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    exclude_ids: &[String],
) -> Result<Option<Value>> {
    let mut tx = db.write_pool().begin().await?;
    // Read the committed projection, not the caller's arguments: the notice
    // describes what was actually written.
    let record = sqlx::query("SELECT name FROM records WHERE id = ? AND deleted_at IS NULL")
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(record) = record else {
        tx.rollback().await?;
        return Ok(None);
    };
    let name: String = record.try_get("name")?;
    let terms = name_terms(&name);
    if terms.is_empty() {
        // Nothing to gate on. A nameless record gets silence rather than a
        // low-precision guess.
        tx.rollback().await?;
        return Ok(None);
    }
    let own_facet_keys: BTreeSet<String> =
        sqlx::query_scalar("SELECT key FROM facet_values WHERE record_id = ?")
            .bind(record_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();

    let match_expression = terms
        .iter()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ");
    let mut excluded = vec![record_id.to_owned()];
    excluded.extend(exclude_ids.iter().cloned());
    excluded.sort();
    excluded.dedup();
    let excluded_json = serde_json::to_string(&excluded)?;
    let not_archived = crate::query::NOT_ARCHIVED;
    let not_hidden = crate::query::not_hidden_predicate("r");
    let rows = sqlx::query(&format!(
        "SELECT r.id AS id, r.name AS name
           FROM records_fts JOIN records r ON r.rowid = records_fts.rowid
          WHERE records_fts MATCH ?
            AND r.deleted_at IS NULL
            AND {not_archived}
            AND {not_hidden}
            AND r.id NOT IN (SELECT value FROM json_each(?))
          ORDER BY r.id
          LIMIT {CANDIDATE_CAP}"
    ))
    .bind(&match_expression)
    .bind(&excluded_json)
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
        tx.rollback().await?;
        return Ok(None);
    }

    let ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Canonical caller-view admission, set-wise on the same snapshot the
    // candidates were read from.
    let visible = super::visible_ids_in(&mut tx, caller, ids.clone()).await?;

    let visible_ids = ids
        .into_iter()
        .filter(|id| visible.contains(id))
        .collect::<Vec<_>>();
    if visible_ids.is_empty() {
        tx.rollback().await?;
        return Ok(None);
    }
    let visible_json = serde_json::to_string(&visible_ids)?;
    let mut facet_keys: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in sqlx::query(
        "SELECT record_id, key FROM facet_values
          WHERE record_id IN (SELECT value FROM json_each(?))",
    )
    .bind(&visible_json)
    .fetch_all(&mut *tx)
    .await?
    {
        facet_keys
            .entry(row.try_get("record_id")?)
            .or_default()
            .insert(row.try_get("key")?);
    }
    tx.rollback().await?;

    let candidates = rows
        .into_iter()
        .filter_map(|row| {
            let id: String = row.try_get("id").ok()?;
            if !visible.contains(&id) {
                return None;
            }
            Some(Candidate {
                facet_keys: facet_keys.remove(&id).unwrap_or_default(),
                name: row.try_get("name").ok()?,
                id,
            })
        })
        .collect::<Vec<_>>();
    let items = rank_candidates(&name, &terms, &own_facet_keys, &candidates);
    if items.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({ "items": items })))
}

/// One existing record offered as a possible duplicate.
struct Candidate {
    id: String,
    name: String,
    facet_keys: BTreeSet<String>,
}

fn tokenize(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_lowercase())
        .collect()
}

/// The name-derived term set the qualification gate and the lexical candidate
/// query share. Order is first-seen; duplicates are removed.
fn name_terms(name: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut terms = Vec::new();
    for token in tokenize(name) {
        if token.chars().count() < MIN_TERM_CHARS || STOPWORDS.contains(&token.as_str()) {
            continue;
        }
        if seen.insert(token.clone()) {
            terms.push(token);
            if terms.len() == TERM_LIMIT {
                break;
            }
        }
    }
    terms
}

/// Normalized name, so "The Quarterly  Roadmap!" and "quarterly roadmap" are
/// the same name. Built from the same tokenizer that feeds the term gate.
fn normalized_name(name: &str) -> String {
    tokenize(name).join(" ")
}

/// The name tokens the new record's name and a candidate name share. This is
/// the qualifier: two shared tokens, or an exact normalized-name match.
fn shared_name_terms(new_terms: &[String], candidate_name: &str) -> Vec<String> {
    let candidate_tokens = tokenize(candidate_name);
    new_terms
        .iter()
        .filter(|term| candidate_tokens.iter().any(|token| token == *term))
        .cloned()
        .collect()
}

/// Rank the qualified candidates. Pure so the precision rule is testable
/// without a database.
///
/// A candidate qualifies when its name shares at least two tokens with the new
/// record's name, or when the two normalized names are equal. A shared facet
/// key is reported and boosts the rank but never qualifies on its own: facet
/// keys like `project` or `status` are far too common to be a signal by
/// themselves, and a noisy notice is worse than none.
fn rank_candidates(
    new_name: &str,
    new_terms: &[String],
    own_facet_keys: &BTreeSet<String>,
    candidates: &[Candidate],
) -> Vec<Value> {
    let new_normalized = normalized_name(new_name);
    let mut ranked = Vec::new();
    for candidate in candidates {
        let shared_terms = shared_name_terms(new_terms, &candidate.name);
        let exact_name =
            !new_normalized.is_empty() && normalized_name(&candidate.name) == new_normalized;
        let shared_facet_keys = own_facet_keys
            .intersection(&candidate.facet_keys)
            .cloned()
            .collect::<Vec<_>>();
        if !exact_name && shared_terms.len() < 2 {
            continue;
        }
        let score = (if exact_name { 1_000 } else { 0 })
            + 10 * shared_terms.len()
            + 3 * shared_facet_keys.len();
        let why = json!({
            "exact_name": exact_name,
            "shared_name_terms": shared_terms.iter().take(WHY_TERM_LIMIT).collect::<Vec<_>>(),
            "shared_facet_keys": shared_facet_keys.iter().take(WHY_TERM_LIMIT).collect::<Vec<_>>(),
        });
        ranked.push((
            score,
            candidate.name.clone(),
            candidate.id.clone(),
            json!({"id": candidate.id, "name": candidate.name, "why": why}),
        ));
    }
    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    ranked
        .into_iter()
        .take(SIMILAR_EXISTING_LIMIT)
        .map(|(_, _, _, item)| item)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, name: &str, facet_keys: &[&str]) -> Candidate {
        Candidate {
            id: id.into(),
            name: name.into(),
            facet_keys: facet_keys.iter().map(|key| (*key).to_string()).collect(),
        }
    }

    #[test]
    fn two_shared_name_terms_qualify_but_one_does_not() {
        let terms = name_terms("Quarterly product roadmap");
        let candidates = vec![
            candidate("two", "Quarterly roadmap", &[]),
            candidate("one", "Roadmap for Q3", &[]),
        ];
        let items = rank_candidates(
            "Quarterly product roadmap",
            &terms,
            &BTreeSet::new(),
            &candidates,
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], json!("two"));
        assert_eq!(items[0]["why"]["exact_name"], json!(false));
        assert_eq!(
            items[0]["why"]["shared_name_terms"],
            json!(["quarterly", "roadmap"])
        );
    }

    #[test]
    fn exact_name_qualifies_and_a_novel_name_yields_nothing() {
        let terms = name_terms("Résumé");
        let candidates = vec![
            candidate("exact", "Résumé", &[]),
            candidate("novel", "Annual budget", &[]),
        ];
        let items = rank_candidates("Résumé", &terms, &BTreeSet::new(), &candidates);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], json!("exact"));
        assert_eq!(items[0]["why"]["exact_name"], json!(true));
    }

    #[test]
    fn a_shared_facet_key_alone_does_not_qualify_but_is_reported() {
        let terms = name_terms("Quarterly roadmap");
        let own = BTreeSet::from(["project".to_string()]);
        assert!(rank_candidates(
            "Quarterly roadmap",
            &terms,
            &own,
            &[candidate("facet-only", "Roadmap", &["project"])],
        )
        .is_empty());
        let qualified = rank_candidates(
            "Quarterly roadmap",
            &terms,
            &own,
            &[candidate("good", "Quarterly roadmap plan", &["project"])],
        );
        assert_eq!(qualified.len(), 1);
        assert_eq!(qualified[0]["why"]["shared_facet_keys"], json!(["project"]));
    }

    #[tokio::test]
    async fn a_closed_database_yields_no_notice_and_no_error() {
        let db = crate::create_database(":memory:").await.unwrap();
        db.close().await;
        assert!(notice_for_create(&db, &Caller::local(), "missing", &[])
            .await
            .is_none());
    }
}
