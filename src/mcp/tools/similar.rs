//! Lexical duplicate detection for the SQLite `create_record` path.
//!
//! The post-commit `notice_for_create` advisory runs a bounded lexical lookup
//! and reports a small set of similar records. It is fail-silent: lookup
//! failures are swallowed, so the advisory cannot fail a write. There is no
//! enforced deadline; bounded work is not bounded latency.
//!
//! The narrower pre-write `strong_matches_in` gate reads the caller's write
//! transaction and propagates failures. Lifecycle refuses strong matches or
//! records the caller's explicit confirmation before appending. Other
//! substrates accept `confirm` without running either lookup.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use sqlx::Row;

use crate::db::Db;
use crate::domain_transaction::FacetWrite;
use crate::error::Result;
use crate::meta::kind::{KindDedupMode, KindMetadataV1};

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

/// Raw index hits examined per pre-write discovery lane, before eligibility
/// checks. Result caps alone would still scan an arbitrarily large workspace.
const DUPLICATE_SCAN_CAP: usize = 512;

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
        if !name_similarity_passes(new_name, &candidate.name) {
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

/// Strong pre-write matches. All reads stay on the caller's writer snapshot.
/// Discovery work is bounded by raw index-hit caps before record eligibility
/// checks. Reverse index walks avoid sorting whole kinds, target neighbourhoods
/// or phrase-hit sets; CROSS JOIN keeps the capped hits ahead of record lookups.
/// This prefers precision over exhaustive recall; the advisory is independent.
pub(super) async fn strong_matches_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    record_type: &str,
    kind: &str,
    name: &str,
    links: &[super::lifecycle::NewLink],
) -> Result<Vec<Value>> {
    let normalized = duplicate_normalized_name(name);
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    let targets: BTreeSet<&str> = links.iter().map(|link| link.target_id.as_str()).collect();
    let targets_json = serde_json::to_string(&targets)?;
    // Include historical aliases of active kinds in the kind-index lane. Final
    // qualification below resolves canonical identity on this same snapshot.
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT vv.value FROM vocabulary_values vv JOIN vocabularies v ON v.id=vv.vocabulary_id
         JOIN vocabulary_values c ON c.id=COALESCE(vv.alias_of,vv.id)
         WHERE v.name=? AND c.status='active' AND c.value=? LIMIT 50",
    )
    .bind(format!("kind:{record_type}"))
    .bind(kind)
    .fetch_all(&mut **tx)
    .await?;
    let mut kinds: BTreeSet<String> = kinds.into_iter().collect();
    kinds.insert(kind.to_owned());
    let kinds_json = serde_json::to_string(&kinds)?;
    // Each MATERIALIZED hit set caps the index walk itself, including rows
    // later rejected by eligibility. Index-prefix ordering is necessary for
    // aliases and multiple targets: their indexes cannot order global rowids.
    let eligible = format!(
        "r.type=? AND r.kind IN (SELECT value FROM json_each(?))
        AND r.deleted_at IS NULL AND r.is_current=1 AND {}",
        crate::query::NOT_ARCHIVED
    );
    let mut ids: BTreeSet<String> = sqlx::query_scalar(&format!(
        "WITH hits AS MATERIALIZED (
             SELECT rowid AS rid FROM records INDEXED BY idx_records_kind
             WHERE type=? AND kind IN (SELECT value FROM json_each(?)) AND deleted_at IS NULL
             ORDER BY kind DESC, rowid DESC LIMIT {DUPLICATE_SCAN_CAP})
         SELECT r.id FROM hits CROSS JOIN records r ON r.rowid=hits.rid
         WHERE {eligible} LIMIT 100"
    ))
    .bind(record_type)
    .bind(&kinds_json)
    .bind(record_type)
    .bind(&kinds_json)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect();
    // Use all normalized title tokens, including digits and stopwords. A
    // phrase permits a trailing numbered copy suffix without matching body text.
    let expression = format!("name : \"{}\"", normalized.replace('"', "\"\""));
    ids.extend(
        sqlx::query_scalar::<_, String>(&format!(
            "WITH hits AS MATERIALIZED (
                 SELECT rowid AS rid FROM records_fts WHERE records_fts MATCH ?
                 ORDER BY rowid DESC LIMIT {DUPLICATE_SCAN_CAP})
             SELECT r.id FROM hits CROSS JOIN records r ON r.rowid=hits.rid
             WHERE {eligible} LIMIT 50"
        ))
        .bind(expression)
        .bind(record_type)
        .bind(&kinds_json)
        .fetch_all(&mut **tx)
        .await?,
    );
    if !targets.is_empty() {
        ids.extend(
            sqlx::query_scalar::<_, String>(&format!(
                "WITH hits AS MATERIALIZED (
                     SELECT source_id FROM links INDEXED BY idx_links_target
                     WHERE target_id IN (SELECT value FROM json_each(?))
                     ORDER BY target_id DESC, relationship DESC, rowid DESC
                     LIMIT {DUPLICATE_SCAN_CAP})
                 SELECT r.id FROM hits CROSS JOIN records r ON r.id=hits.source_id
                 WHERE {eligible} LIMIT 100"
            ))
            .bind(&targets_json)
            .bind(record_type)
            .bind(&kinds_json)
            .fetch_all(&mut **tx)
            .await?,
        );
    }
    ids.retain(|id| !targets.contains(id.as_str()));
    let visible = super::visible_ids_in(tx, caller, ids.into_iter().collect()).await?;
    if visible.is_empty() {
        return Ok(Vec::new());
    }
    let visible_json = serde_json::to_string(&visible)?;
    let rows = sqlx::query(&format!(
        "SELECT r.id, r.name, r.kind, r.home_id, r.lifecycle
         FROM json_each(?) ids CROSS JOIN records r ON r.id=ids.value
         WHERE r.type=? AND r.deleted_at IS NULL
         AND r.kind IN (SELECT value FROM json_each(?)) AND r.is_current=1 AND {} ORDER BY r.id",
        crate::query::NOT_ARCHIVED
    ))
    .bind(visible_json)
    .bind(record_type)
    .bind(&kinds_json)
    .fetch_all(&mut **tx)
    .await?;
    // Name work is cheap and pure; avoid kind resolution or lifecycle loading
    // for rows that cannot qualify even if they share a target.
    let mut named_rows = Vec::new();
    for row in rows {
        let candidate_name: String = row.try_get("name")?;
        let exact = duplicate_normalized_name(&candidate_name) == normalized;
        if exact || (!targets.is_empty() && shared_target_name_matches(name, &candidate_name)) {
            named_rows.push((row, candidate_name, exact));
        }
    }
    if named_rows.is_empty() {
        return Ok(Vec::new());
    }
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let schema = crate::query::cascade::schema_config_rows_for_principal_on(tx, principal).await?;
    let interpreter =
        crate::query::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema).await?;
    let mut matches = Vec::new();
    for (row, candidate_name, exact) in named_rows {
        let candidate_kind: String = row.try_get("kind")?;
        let resolution = crate::meta::kind::resolve_on(tx, record_type, &candidate_kind).await?;
        let canonical = resolution
            .canonical_kind_for_write()
            .unwrap_or(&candidate_kind);
        if canonical != kind {
            continue;
        }
        let home: Option<String> = row.try_get("home_id")?;
        let lifecycle: Option<String> = row.try_get("lifecycle")?;
        // The interpreter judges the resolved canonical kind, never a
        // historical alias the row happens to be stored under.
        if let crate::query::lifecycle::LifecycleInterpretation::Governed(value) = interpreter
            .interpret(
                record_type,
                Some(canonical),
                home.as_deref(),
                lifecycle.as_deref(),
            )
        {
            if value.terminality.starts_with("terminal_") {
                continue;
            }
        }
        let id: String = row.try_get("id")?;
        let shared_target = if !exact {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND target_id IN (SELECT value FROM json_each(?)))"
            ).bind(&id).bind(&targets_json).fetch_one(&mut **tx).await?
        } else {
            false
        };
        if !exact && !shared_target {
            continue;
        }
        matches.push(json!({"id":id, "name":candidate_name, "kind":kind,
            "why":if exact {"normalized_name"} else {"shared_link_target_and_similar_name"}}));
        if matches.len() == SIMILAR_EXISTING_LIMIT {
            break;
        }
    }
    let refs = matches
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect::<Vec<_>>();
    let references = crate::mcp::record_ref::display_references_in(
        &mut crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx),
        &refs,
    )
    .await?;
    for item in &mut matches {
        item["display_reference"] = json!(references
            .get(item["id"].as_str().unwrap())
            .cloned()
            .flatten());
    }
    Ok(matches)
}

/// A complete declared identity tuple for the duplicate gate. `values` are
/// the new record's own facet values as JSON for the refusal receipt;
/// `stored` is the same tuple in storage text form for comparison.
pub(super) struct DeclaredIdentity {
    pub mode: KindDedupMode,
    pub keys: Vec<String>,
    pub values: BTreeMap<String, Value>,
    pub stored: BTreeMap<String, String>,
}

fn blank_identity_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        _ => false,
    }
}

/// Decide whether the kind's declared identity rule handles this create. Only
/// `facet_tuple` and `external_binding` with a complete tuple do: every
/// declared key must carry a non-blank value on the new record. Anything else
/// — other modes, no metadata, a missing or blank key — falls back to the
/// name/link check.
pub(super) fn declared_identity_for_gate(
    metadata: Option<&KindMetadataV1>,
    facets: &[FacetWrite],
    fields: &serde_json::Map<String, Value>,
) -> Option<DeclaredIdentity> {
    let metadata = metadata?;
    if !matches!(
        metadata.identity.dedup.mode,
        KindDedupMode::FacetTuple | KindDedupMode::ExternalBinding
    ) {
        return None;
    }
    let keys = &metadata.identity.dedup.keys;
    if keys.is_empty() {
        return None;
    }
    let mut values = BTreeMap::new();
    let mut stored = BTreeMap::new();
    for key in keys {
        let value = facets
            .iter()
            .find(|facet| facet.key == *key)
            .map(|facet| facet.value.clone())
            .or_else(|| {
                // Creation files spine facets under their `records` column
                // (`owner` arrives as top-level `owner_id`), so map declared
                // spine keys the same way the candidate side does.
                let field = crate::schema::spine_facet_column(key).unwrap_or(key);
                fields.get(field).cloned()
            });
        let value = value?;
        if blank_identity_value(&value) {
            return None;
        }
        stored.insert(key.clone(), stored_form(&value));
        values.insert(key.clone(), value);
    }
    Some(DeclaredIdentity {
        mode: metadata.identity.dedup.mode,
        keys: keys.clone(),
        values,
        stored,
    })
}

/// Storage text form of one facet value: the exact encoding
/// `FacetWrite::stored_value` persists in `facet_values.value` (and, for
/// spine facets, in their `records` columns). Open facets are compared by
/// stored form, so types the TEXT storage erases — a string "3" versus a
/// number 3 — cannot be told apart here by design; identity rules must not
/// rely on that distinction.
fn stored_form(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => serde_json::to_string(value).expect("a serde_json::Value always serializes"),
    }
}

fn stored_text_matches(new_value: &Value, new_stored: &str, candidate: Option<&str>) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    if new_value.is_string() {
        candidate.trim().to_lowercase() == new_stored.trim().to_lowercase()
    } else {
        candidate == new_stored
    }
}

/// One kind-lane record with its declared open facet values, grouped from
/// the discovery join. Spine values stay on their `records` columns.
struct JoinedRecord {
    id: String,
    name: String,
    kind: String,
    home_id: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    facets: BTreeMap<String, String>,
}

/// Declared-identity pre-write matches. Same eligibility as the name/link
/// gate — current, non-archived, non-terminal, caller-visible records of the
/// same type and canonical kind — but discovery is driven by the kind, not
/// a recency window: one query selects the eligible records of the canonical
/// kind plus its aliases and joins their declared open keys, so the cost is
/// bounded by the kind's size instead of the workspace. The name plays no
/// role here: an identical tuple under a different name is a duplicate, and
/// a different tuple under the same name is not.
pub(super) async fn declared_identity_matches_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    record_type: &str,
    kind: &str,
    identity: &DeclaredIdentity,
) -> Result<Vec<Value>> {
    // Alias-inclusive kind set. No row cap: the kind bounds the work, so an
    // older match is never cut off by newer neighbours.
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT vv.value FROM vocabulary_values vv JOIN vocabularies v ON v.id=vv.vocabulary_id
         JOIN vocabulary_values c ON c.id=COALESCE(vv.alias_of,vv.id)
         WHERE v.name=? AND c.status='active' AND c.value=?",
    )
    .bind(format!("kind:{record_type}"))
    .bind(kind)
    .fetch_all(&mut **tx)
    .await?;
    let mut kinds: BTreeSet<String> = kinds.into_iter().collect();
    kinds.insert(kind.to_owned());
    let kinds_json = serde_json::to_string(&kinds)?;
    let mut open_keys = Vec::new();
    for key in &identity.keys {
        if crate::schema::spine_facet_column(key).is_none() {
            open_keys.push(key);
        }
    }
    let keys_json = serde_json::to_string(&open_keys)?;
    // Eligible records of the kind lane joined to their declared open keys
    // on the UNIQUE(record_id, key) index. Records missing a declared key
    // contribute no row for it and fail the Rust comparison below.
    // CROSS JOIN pins records outermost: an ordinary JOIN lets the planner
    // start from a generic key's index range across every kind instead.
    // Spine-only rules carry no open keys, so the join would match nothing:
    // they read the kind lane directly and compare columns instead.
    let rows = if open_keys.is_empty() {
        sqlx::query(&format!(
            "SELECT r.id, r.name, r.kind, r.home_id, r.lifecycle,
                r.owner_id, r.persistence, r.maturity,
                NULL AS key, NULL AS value
             FROM records r INDEXED BY idx_records_kind
             WHERE r.type=? AND r.kind IN (SELECT value FROM json_each(?))
             AND r.deleted_at IS NULL AND r.is_current=1 AND {} ORDER BY r.id",
            crate::query::NOT_ARCHIVED
        ))
        .bind(record_type)
        .bind(&kinds_json)
        .fetch_all(&mut **tx)
        .await?
    } else {
        sqlx::query(&format!(
            "SELECT r.id, r.name, r.kind, r.home_id, r.lifecycle,
                r.owner_id, r.persistence, r.maturity,
                f.key AS key, f.value AS value
             FROM records r INDEXED BY idx_records_kind
             CROSS JOIN facet_values f ON f.record_id=r.id
                AND f.key IN (SELECT value FROM json_each(?))
             WHERE r.type=? AND r.kind IN (SELECT value FROM json_each(?))
             AND r.deleted_at IS NULL AND r.is_current=1 AND {} ORDER BY r.id",
            crate::query::NOT_ARCHIVED
        ))
        .bind(&keys_json)
        .bind(record_type)
        .bind(&kinds_json)
        .fetch_all(&mut **tx)
        .await?
    };
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    // Group the joined rows back into records, preserving id order, and
    // compare the complete tuple in Rust first: only full-tuple matches pay
    // for visibility, kind resolution and the lifecycle read below.
    let mut records: Vec<JoinedRecord> = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let key: Option<String> = row.try_get("key")?;
        let value: Option<String> = row.try_get("value")?;
        if records
            .last()
            .is_none_or(|last: &JoinedRecord| last.id != id)
        {
            records.push(JoinedRecord {
                id,
                name: row.try_get("name")?,
                kind: row.try_get("kind")?,
                home_id: row.try_get("home_id")?,
                lifecycle: row.try_get("lifecycle")?,
                owner_id: row.try_get("owner_id")?,
                persistence: row.try_get("persistence")?,
                maturity: row.try_get("maturity")?,
                facets: BTreeMap::new(),
            });
        }
        if let (Some(key), Some(value)) = (key, value) {
            records
                .last_mut()
                .expect("a row always extends the record it opened")
                .facets
                .insert(key, value);
        }
    }
    let mut full_matches: Vec<JoinedRecord> = Vec::new();
    for record in records {
        let mut full_match = true;
        for key in &identity.keys {
            let new_value = &identity.values[key.as_str()];
            let new_stored = &identity.stored[key.as_str()];
            let matched = match crate::schema::spine_facet_column(key) {
                Some("lifecycle") => {
                    stored_text_matches(new_value, new_stored, record.lifecycle.as_deref())
                }
                Some("owner_id") => {
                    stored_text_matches(new_value, new_stored, record.owner_id.as_deref())
                }
                Some("persistence") => {
                    stored_text_matches(new_value, new_stored, record.persistence.as_deref())
                }
                Some("maturity") => {
                    stored_text_matches(new_value, new_stored, record.maturity.as_deref())
                }
                _ => stored_text_matches(
                    new_value,
                    new_stored,
                    record.facets.get(key).map(String::as_str),
                ),
            };
            if !matched {
                full_match = false;
                break;
            }
        }
        if full_match {
            full_matches.push(record);
        }
    }
    if full_matches.is_empty() {
        return Ok(Vec::new());
    }
    let visible = super::visible_ids_in(
        tx,
        caller,
        full_matches
            .iter()
            .map(|record| record.id.clone())
            .collect(),
    )
    .await?;
    if visible.is_empty() {
        return Ok(Vec::new());
    }
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let schema = crate::query::cascade::schema_config_rows_for_principal_on(tx, principal).await?;
    let interpreter =
        crate::query::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema).await?;
    let mode = match identity.mode {
        KindDedupMode::FacetTuple => "facet_tuple",
        KindDedupMode::ExternalBinding => "external_binding",
        KindDedupMode::RecordId => "record_id",
        KindDedupMode::Manual => "manual",
    };
    // One kind resolution per distinct stored kind: the lane above admits a
    // canonical kind plus its aliases, so this is rarely more than two.
    let mut canonicals: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut matches = Vec::new();
    for record in full_matches {
        if !visible.contains(&record.id) {
            continue;
        }
        let canonical = match canonicals.get(&record.kind) {
            Some(cached) => cached.clone(),
            None => {
                let resolution =
                    crate::meta::kind::resolve_on(tx, record_type, &record.kind).await?;
                let canonical = resolution
                    .canonical_kind_for_write()
                    .unwrap_or(&record.kind)
                    .to_string();
                canonicals.insert(record.kind.clone(), Some(canonical.clone()));
                Some(canonical)
            }
        };
        if canonical.as_deref() != Some(kind) {
            continue;
        }
        // The interpreter judges the resolved canonical kind, never a
        // historical alias the row happens to be stored under: lifecycle
        // vocabularies are declared per canonical kind, so an alias would
        // misread terminal rows as unclassified and block on them.
        if let crate::query::lifecycle::LifecycleInterpretation::Governed(value) = interpreter
            .interpret(
                record_type,
                Some(canonical.as_deref().unwrap_or(&record.kind)),
                record.home_id.as_deref(),
                record.lifecycle.as_deref(),
            )
        {
            if value.terminality.starts_with("terminal_") {
                continue;
            }
        }
        matches.push(json!({"id":record.id, "name":record.name, "kind":kind,
            "why":"declared_identity",
            "identity":{"mode":mode, "keys":identity.keys, "values":identity.values}}));
        if matches.len() == SIMILAR_EXISTING_LIMIT {
            break;
        }
    }
    let refs = matches
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect::<Vec<_>>();
    let references = crate::mcp::record_ref::display_references_in(
        &mut crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx),
        &refs,
    )
    .await?;
    for item in &mut matches {
        item["display_reference"] = json!(references
            .get(item["id"].as_str().unwrap())
            .cloned()
            .flatten());
    }
    Ok(matches)
}

/// Same threshold as the existing advisory; keep one source of truth.
fn name_similarity_passes(name: &str, candidate: &str) -> bool {
    let normalized = normalized_name(name);
    (!normalized.is_empty() && normalized == normalized_name(candidate))
        || shared_name_terms(&name_terms(name), candidate).len() >= 2
}

// The advisory threshold is necessary but insufficient for a strong match:
// recurring titles must retain identical digit-bearing tokens, and the shorter
// title must contribute all its meaningful terms (without the advisory's cap).
fn shared_target_name_matches(name: &str, candidate: &str) -> bool {
    if !name_similarity_passes(name, candidate) {
        return false;
    }
    let left = tokenize(name);
    let right = tokenize(candidate);
    let digits = |tokens: &[String]| {
        tokens
            .iter()
            .filter(|token| token.chars().any(char::is_numeric))
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    if digits(&left) != digits(&right) {
        return false;
    }
    let meaningful = |tokens: Vec<String>| {
        tokens
            .into_iter()
            .filter(|token| !STOPWORDS.contains(&token.as_str()))
            .collect::<BTreeSet<_>>()
    };
    let left = meaningful(left);
    let right = meaningful(right);
    let (shorter, longer) = if left.len() <= right.len() {
        (&left, &right)
    } else {
        (&right, &left)
    };
    !shorter.is_empty() && shorter.is_subset(longer)
}

fn duplicate_normalized_name(name: &str) -> String {
    let trimmed = name.trim();
    let without_suffix = [('(', ')'), ('[', ']')]
        .into_iter()
        .find_map(|(open, close)| {
            let prefix = trimmed.strip_suffix(close)?;
            let (base, number) = prefix.rsplit_once(open)?;
            (!number.is_empty() && number.chars().all(|c| c.is_ascii_digit())).then_some(base)
        })
        .unwrap_or(trimmed);
    normalized_name(&without_suffix.to_lowercase())
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

    #[test]
    fn duplicate_names_strip_only_one_trailing_numeric_suffix() {
        assert_eq!(
            duplicate_normalized_name(" Opening REVIEWS [2] "),
            "opening reviews"
        );
        assert_eq!(
            duplicate_normalized_name("Opening reviews (3)"),
            "opening reviews"
        );
        assert_eq!(duplicate_normalized_name("Q3 report"), "q3 report");
        assert_ne!(
            duplicate_normalized_name("Q3 report"),
            duplicate_normalized_name("Q4 report")
        );
        assert_eq!(
            duplicate_normalized_name("Reviews (draft)"),
            "reviews draft"
        );
        assert_eq!(duplicate_normalized_name("Reviews (2) [3]"), "reviews 2");
        assert_eq!(
            duplicate_normalized_name("Résumé—review!!"),
            "résumé review"
        );
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
