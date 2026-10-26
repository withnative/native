//! `searchContext` (slice 4a): task-relevant records, model-ranked.
//!
//! Candidates come only from authorised reads: the same `search` handler
//! `/mcp` uses, run with the caller's authorisation (project scope travels
//! as that handler's subtree scope), then one authorised `get_record` per
//! chunk for details. Records the caller cannot read never appear and never
//! reach the model. Ranking reuses the Haiku client; when the model is not
//! configured or fails, the lexical order is returned honestly labelled.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::db::Db;
use crate::error::Result;
use crate::mcp::registry::Caller;

use super::claude;
use super::context_item::{self, short_ref};
use super::native_block::Origin;
use super::store::Store;

/// Candidate records gathered, before filtering and ranking.
pub(super) const CANDIDATE_CAP: usize = 200;
/// Authorised search hits kept per task word; the union is capped above.
const HITS_PER_WORD: i64 = 50;
/// Task words sent to the authorised search, in order.
const MAX_WORDS: usize = 8;
/// The model's one relevance line per item.
pub(super) const WHY_MAX_CHARS: usize = 200;
/// The model's reading of the task.
pub(super) const INTERPRETATION_MAX_CHARS: usize = 300;
/// Candidate description sent to the model, per field.
const CANDIDATE_SUMMARY_MAX_CHARS: usize = 500;
/// Titles are identifiers for ranking, not content: capped tighter.
const CANDIDATE_TITLE_MAX_CHARS: usize = 200;
/// Fallback summary width when the request would otherwise exceed budget.
const CANDIDATE_SUMMARY_NARROW_CHARS: usize = 100;
/// Upper bound on the serialized candidates the model is asked to rank.
const CANDIDATES_MAX_BYTES: usize = 32 * 1024;
const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 50;

pub(super) struct Args {
    task: String,
    project: Option<String>,
    subject: Option<String>,
    kinds: Option<HashSet<String>>,
    include_proposed: bool,
    include_superseded: bool,
    include_sources: bool,
    limit: usize,
}

fn invalid(message: impl Into<String>) -> Value {
    json!({ "success": false, "code": "INVALID_CONTEXT_INPUT", "error": message.into() })
}

fn object_args(arguments: &Value) -> Option<&Map<String, Value>> {
    arguments.as_object()
}

fn parse_bool_flag(include: &Map<String, Value>, key: &str) -> Option<bool> {
    match include.get(key) {
        None | Some(Value::Null) => Some(false),
        Some(Value::Bool(flag)) => Some(*flag),
        Some(_) => None,
    }
}

fn parse_args(arguments: &Value) -> std::result::Result<Args, Value> {
    let args = object_args(arguments).ok_or_else(|| invalid("arguments must be an object"))?;
    let task = match args.get("task") {
        Some(Value::String(task)) if !task.trim().is_empty() => task.clone(),
        _ => return Err(invalid("task is required")),
    };
    if task.len() > claude::QUERY_MAX_BYTES {
        return Err(invalid(format!(
            "task is too long (max {} bytes)",
            claude::QUERY_MAX_BYTES
        )));
    }
    let (project, subject) = match args.get("scope") {
        None | Some(Value::Null) => (None, None),
        Some(Value::Object(scope)) => {
            let one = |key: &str| match scope.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
                Some(_) => Err(invalid(format!("scope.{key} must be a string"))),
            };
            (one("project")?, one("subject")?)
        }
        Some(_) => return Err(invalid("scope must be an object")),
    };
    let kinds = match args.get("kinds") {
        None | Some(Value::Null) => None,
        Some(Value::Array(kinds)) => {
            let mut set = HashSet::new();
            for kind in kinds {
                match kind.as_str() {
                    Some(kind) if !kind.trim().is_empty() => {
                        set.insert(kind.to_string());
                    }
                    _ => return Err(invalid("kinds must be an array of strings")),
                }
            }
            Some(set)
        }
        Some(_) => return Err(invalid("kinds must be an array of strings")),
    };
    let (include_proposed, include_superseded, include_sources) = match args.get("include") {
        None | Some(Value::Null) => (false, false, true),
        Some(Value::Object(include)) => {
            let proposed = parse_bool_flag(include, "proposed")
                .ok_or_else(|| invalid("include.proposed must be a boolean"))?;
            let superseded = parse_bool_flag(include, "superseded")
                .ok_or_else(|| invalid("include.superseded must be a boolean"))?;
            let sources = match include.get("sources") {
                None | Some(Value::Null) => true,
                Some(Value::Bool(sources)) => *sources,
                Some(_) => return Err(invalid("include.sources must be a boolean")),
            };
            (proposed, superseded, sources)
        }
        Some(_) => return Err(invalid("include must be an object")),
    };
    let limit = match args.get("limit") {
        None | Some(Value::Null) => DEFAULT_LIMIT,
        Some(Value::Number(limit)) => match limit.as_u64() {
            Some(limit) if (1..=MAX_LIMIT as u64).contains(&limit) => limit as usize,
            _ => return Err(invalid(format!("limit must be between 1 and {MAX_LIMIT}"))),
        },
        Some(_) => return Err(invalid(format!("limit must be between 1 and {MAX_LIMIT}"))),
    };
    Ok(Args {
        task,
        project,
        subject,
        kinds,
        include_proposed,
        include_superseded,
        include_sources,
        limit,
    })
}

/// Significant search words from the task, in order. Full-text search ANDs
/// its terms, so the task is fanned out one word at a time and unioned by
/// the caller instead.
fn task_words(task: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut seen = HashSet::new();
    for word in task.split(|char: char| !char.is_alphanumeric()) {
        let word = word.to_lowercase();
        if word.chars().count() < 2 || !seen.insert(word.clone()) {
            continue;
        }
        words.push(word);
        if words.len() >= MAX_WORDS {
            break;
        }
    }
    words
}
/// Expand one caller-supplied reference to its canonical record id: full
/// ids and `native:` constants pass through; anything else is treated as a
/// display-reference prefix and resolved through the authorised `query_sql`
/// handler, which shows the caller only what they may see. `None` when the
/// prefix matches nothing visible (or ambiguously many): the caller learns
/// nothing about what exists beyond their view.
pub(super) async fn resolve_input_ref(
    db: &Db,
    caller: &Caller,
    reference: &str,
) -> Result<Option<String>> {
    if reference.starts_with("native:") || reference.chars().count() == 36 {
        return Ok(Some(reference.to_string()));
    }
    let outcome = super::super::querying::query_sql(
        db.clone(),
        caller.clone(),
        json!({
            "sql": format!(
                "SELECT id FROM records r WHERE r.id LIKE ?1 || '%' AND r.deleted_at IS NULL{} LIMIT 2",
                super::extensions::host_exclusion_sql("r"),
            ),
            "parameters": [reference],
        }),
    )
    .await?;
    let mut ids = Vec::new();
    for row in outcome
        .get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = match row {
            Value::Object(map) => map.get("id").and_then(Value::as_str).map(str::to_string),
            Value::Array(cells) => cells.first().and_then(Value::as_str).map(str::to_string),
            _ => None,
        };
        if let Some(id) = id {
            ids.push(id);
        }
    }
    Ok(if ids.len() == 1 { ids.pop() } else { None })
}

/// Resolve a scope reference through the authorised `get_record` path to
/// its canonical id. `None` when the caller cannot read it (or it does not
/// exist): the scope then matches nothing, without revealing which.
async fn resolve_scope(db: &Db, caller: &Caller, reference: &str) -> Option<String> {
    let id = resolve_input_ref(db, caller, reference).await.ok()??;
    let record =
        super::super::lifecycle::get_record(db.clone(), caller.clone(), json!({ "ids": [id] }))
            .await
            .ok()?;
    let found = record.get("records")?.as_array()?.first()?;
    if found.get("status").and_then(Value::as_str) != Some("found") {
        return None;
    }
    super::extensions::without_hidden(db, caller, vec![found.clone()])
        .await
        .ok()?
        .pop()?;
    found.get("id").and_then(Value::as_str).map(str::to_string)
}

/// Candidate ids from the authorised `search` handler `/mcp` uses, one word
/// at a time, unioned in encounter order and capped. Project scope travels
/// as the handler's own subtree scope, so scoping is authorised too.
async fn gather_candidates(
    db: &Db,
    caller: &Caller,
    task: &str,
    project: Option<&str>,
) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    for word in task_words(task) {
        let mut arguments = json!({ "query": word, "limit": HITS_PER_WORD });
        if let Some(project) = project {
            arguments["scope"] = json!(project);
        }
        // On the HCP v2 host hidden records are kept out of the match itself,
        // so they cannot displace anything through the hit cap or the
        // candidate cap below.
        let page = match super::super::querying::search_excluding(
            db.clone(),
            caller.clone(),
            arguments,
            super::extensions::search_exclusion(),
        )
        .await
        {
            Ok(page) => page,
            Err(_) => continue,
        };
        for hit in page
            .get("hits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = hit.get("id").and_then(Value::as_str) {
                if seen.insert(id.to_string()) {
                    ids.push(id.to_string());
                }
            }
            if ids.len() >= CANDIDATE_CAP {
                return Ok(ids);
            }
        }
    }
    Ok(ids)
}

/// Open suggestions on the gathered candidates. Full-text search does not
/// index suggestion bodies, so without this step proposed items could never
/// surface; the design maps them to `proposed` status. Found through the
/// authorised `query_sql` handler with the caller's authorisation, so a
/// suggestion the caller cannot read never appears.
async fn expand_suggestions(db: &Db, caller: &Caller, ids: &[String]) -> Result<Vec<String>> {
    let mut found = Vec::new();
    if ids.is_empty() {
        return Ok(found);
    }
    for chunk in ids.chunks(super::super::lifecycle::MAX_BATCH_GET) {
        let placeholders = chunk
            .iter()
            .enumerate()
            .map(|(index, _)| format!("?{}", index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let outcome = super::super::querying::query_sql(
            db.clone(),
            caller.clone(),
            json!({
                "sql": format!(
                    "SELECT s.id AS id FROM records s \
                     JOIN links l ON l.source_id = s.id AND l.relationship = 'part_of' \
                       AND l.target_id IN ({placeholders}) \
                     WHERE s.type = 'Annotation' AND s.kind = 'suggestion' \
                       AND s.lifecycle = 'open' \
                       AND s.archived = 0 AND s.deleted_at IS NULL{}",
                    super::extensions::host_exclusion_sql("s"),
                ),
                "parameters": chunk,
            }),
        )
        .await?;
        for row in outcome
            .get("rows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = match row {
                Value::Object(map) => map.get("id").and_then(Value::as_str).map(str::to_string),
                Value::Array(cells) => cells.first().and_then(Value::as_str).map(str::to_string),
                _ => None,
            };
            if let Some(id) = id {
                if !ids.contains(&id) {
                    found.push(id);
                }
            }
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// Full authorised records for candidate ids, in chunks. Only `found`
/// records come back: anything the caller cannot read is already gone.
async fn load_records(db: &Db, caller: &Caller, ids: &[String]) -> Result<Vec<Value>> {
    let mut records = Vec::new();
    for chunk in ids.chunks(super::super::lifecycle::MAX_BATCH_GET) {
        let page = super::super::lifecycle::get_record(
            db.clone(),
            caller.clone(),
            json!({ "ids": chunk }),
        )
        .await?;
        for record in page
            .get("records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if record.get("status").and_then(Value::as_str) == Some("found") {
                records.push(record.clone());
            }
        }
    }
    super::extensions::without_hidden(db, caller, records).await
}

/// The `hcp.*` facets of candidate records, through the same authorised
/// `query_sql` handler `/mcp` uses: the catalog marker (excluded from
/// context) and the preference client/evidence facets provenance reuses, plus
/// the two precondition facets that anchor a suggestion to its target.
pub(super) async fn hcp_facets(
    db: &Db,
    caller: &Caller,
    ids: &[String],
) -> Result<HashMap<String, HashMap<String, String>>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut facets: HashMap<String, HashMap<String, String>> = HashMap::new();
    for chunk in ids.chunks(super::super::lifecycle::MAX_BATCH_GET) {
        for (id, keys) in hcp_facets_chunk(db, caller, chunk).await? {
            facets.entry(id).or_default().extend(keys);
        }
    }
    Ok(facets)
}

async fn hcp_facets_chunk(
    db: &Db,
    caller: &Caller,
    ids: &[String],
) -> Result<HashMap<String, HashMap<String, String>>> {
    let placeholders = ids
        .iter()
        .enumerate()
        .map(|(index, _)| format!("?{}", index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT record_id, key, value FROM facet_values \
         WHERE record_id IN ({placeholders}) \
           AND (key LIKE 'hcp.%' OR key IN ('proposal.precondition', 'anchor.base_digest'))"
    );
    let outcome = super::super::querying::query_sql(
        db.clone(),
        caller.clone(),
        json!({ "sql": sql, "parameters": ids }),
    )
    .await?;
    let columns: Vec<String> = outcome
        .get("columns")
        .and_then(Value::as_array)
        .map(|columns| {
            columns
                .iter()
                .filter_map(|column| column.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let cell = |row: &Value, name: &str| -> Option<String> {
        match row {
            Value::Object(map) => map.get(name).and_then(Value::as_str).map(str::to_string),
            Value::Array(cells) => columns
                .iter()
                .position(|column| column == name)
                .and_then(|index| cells.get(index))
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        }
    };
    let mut facets: HashMap<String, HashMap<String, String>> = HashMap::new();
    for row in outcome
        .get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(id), Some(key), Some(value)) =
            (cell(row, "record_id"), cell(row, "key"), cell(row, "value"))
        {
            facets.entry(id).or_default().insert(key, value);
        }
    }
    Ok(facets)
}

/// Whether an item survives the `include` flags.
fn kept(status: Option<&str>, args: &Args) -> bool {
    match status {
        Some("proposed") => args.include_proposed,
        Some("superseded") => args.include_superseded,
        Some("accepted") => true,
        _ => args.include_sources,
    }
}

fn status_bearing(status: Option<&str>) -> bool {
    matches!(status, Some("proposed" | "accepted" | "superseded"))
}

/// Stable partition: status-bearing items first, keeping relative order.
fn rank_first(indices: Vec<usize>, statuses: &[Option<String>]) -> Vec<usize> {
    let mut bearing = Vec::new();
    let mut sources = Vec::new();
    for index in indices {
        if statuses
            .get(index)
            .is_some_and(|status| status_bearing(status.as_deref()))
        {
            bearing.push(index);
        } else {
            sources.push(index);
        }
    }
    bearing.extend(sources);
    bearing
}

fn ok_response(interpretation: Option<String>, ranking: &str, items: Vec<Value>) -> Value {
    let mut body = Map::new();
    body.insert(
        "interpretation".into(),
        interpretation.map(Value::from).unwrap_or(Value::Null),
    );
    body.insert("ranking".into(), Value::String(ranking.to_string()));
    body.insert("items".into(), Value::Array(items));
    let mut out = Map::new();
    out.insert("success".into(), Value::Bool(true));
    out.append(&mut body);
    Value::Object(out)
}

/// One eligible record with everything the item builder needs.
struct Eligible {
    record: Value,
    id: String,
    status: Option<String>,
    is_preference: bool,
    /// The `hcp.client` / `hcp.evidence` facets for preferences, passed to
    /// the slice-3 derivation exactly as Layer 1 passes them.
    hcp_client: Option<String>,
    hcp_evidence: Option<String>,
    /// The target revision an open suggestion is anchored to.
    anchor: Option<String>,
}

/// Detail loading and the `include`/`kinds`/subject filters. Only records
/// the caller can read survive: authorisation already ran in `search` and
/// runs again in `get_record` here.
async fn eligible_records(
    db: &Db,
    caller: &Caller,
    args: &Args,
    ids: &[String],
    subject: Option<&str>,
) -> Result<Vec<Eligible>> {
    let records = load_records(db, caller, ids).await?;
    let found: Vec<String> = records
        .iter()
        .filter_map(|record| record.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let facets = hcp_facets(db, caller, &found).await?;
    // Readability of everything the items may name: status, counts and refs
    // never reveal an unreadable linked record, not even its existence.
    let mut linked: Vec<String> = Vec::new();
    for record in &records {
        for other in subject_links(record)
            .into_iter()
            .chain(context_item::links_out(record, "supersedes"))
            .chain(context_item::links_in(record, "supersedes"))
            .chain(context_item::evidence_ids(record))
            .chain(context_item::links_out(record, "applies_to"))
        {
            if !linked.contains(&other) {
                linked.push(other);
            }
        }
    }
    let mut visible: HashSet<String> = found.iter().cloned().collect();
    for record in load_records(db, caller, &linked).await? {
        if let Some(id) = record.get("id").and_then(Value::as_str) {
            visible.insert(id.to_string());
        }
    }
    let mut eligible = Vec::new();
    for record in records {
        let id = record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if record
            .get("archived")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        // A closed suggestion is a dead proposal, not a source: only open
        // ones ever surface (as `proposed` items when opted in).
        if record.get("type").and_then(Value::as_str) == Some("Annotation")
            && record.get("kind").and_then(Value::as_str) == Some("suggestion")
            && context_item::lifecycle_of(&record).as_deref() != Some("open")
        {
            continue;
        }
        if facets
            .get(&id)
            .and_then(|facets| facets.get("hcp.role"))
            .is_some_and(|role| role == "preference-catalog")
        {
            continue;
        }
        if let Some(kinds) = &args.kinds {
            if !kinds.contains(&context_item::kind_of(&record)) {
                continue;
            }
        }
        if let Some(subject) = subject {
            let linked = context_item::links_out(&record, "subject")
                .into_iter()
                .chain(context_item::links_in(&record, "subject"))
                .chain(subject_links(&record))
                .any(|other| other == subject);
            if !linked {
                continue;
            }
        }
        let status = context_item::status_of(&record, &visible).map(str::to_string);
        if !kept(status.as_deref(), args) {
            continue;
        }
        let is_preference = record.get("type").and_then(Value::as_str) == Some("Resolution")
            && record.get("kind").and_then(Value::as_str) == Some("preference");
        if is_preference && context_item::body_of(&record).trim().is_empty() {
            continue;
        }
        let hcp_client = facets
            .get(&id)
            .and_then(|facets| facets.get("hcp.client"))
            .cloned();
        let hcp_evidence = facets
            .get(&id)
            .and_then(|facets| facets.get("hcp.evidence"))
            .cloned();
        let anchor = context_item::anchor_of(facets.get(&id));
        eligible.push(Eligible {
            record,
            id,
            status,
            is_preference,
            hcp_client,
            hcp_evidence,
            anchor,
        });
    }
    Ok(eligible)
}

/// Links that tie a record to a subject entity beyond the explicit
/// `subject` relationship: person-typed endpoints are resolved later, so
/// any direct link counts here and the entity check runs at build time.
pub(super) fn subject_links(record: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for key in ["links_out", "links_in"] {
        if let Some(links) = record.get(key).and_then(Value::as_array) {
            for link in links {
                let id = if key == "links_out" {
                    link.get("target_id")
                } else {
                    link.get("source_id")
                };
                if let Some(id) = id.and_then(Value::as_str) {
                    ids.push(id.to_string());
                }
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

/// Short references for every id the response may name: the records, their
/// ancestors and their links, in one authorised read.
async fn collect_refs(db: &Db, caller: &Caller, eligible: &[Eligible]) -> Result<RefMaps> {
    let mut ids: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |id: &str| {
        if seen.insert(id.to_string()) {
            ids.push(id.to_string());
        }
    };
    for item in eligible {
        push(&item.id);
        if let Some(ancestors) = item.record.get("ancestors").and_then(Value::as_array) {
            for ancestor in ancestors {
                if let Some(id) = ancestor.get("id").and_then(Value::as_str) {
                    push(id);
                }
            }
        }
        for other in subject_links(&item.record) {
            push(&other);
        }
        for other in context_item::links_out(&item.record, "supersedes") {
            push(&other);
        }
        for other in context_item::links_in(&item.record, "supersedes") {
            push(&other);
        }
    }
    let store = Store::new(db, caller);
    let context = store.context(&ids).await?;
    let refs = context.references;
    Ok(RefMaps { refs })
}

struct RefMaps {
    refs: HashMap<String, Option<String>>,
}

/// The compact candidate descriptions the model ranks. Only what the
/// caller can read, and only fields ranking needs: reference, kind, title,
/// truncated summary and status. Titles are capped tighter than summaries,
/// and summaries narrow further when the whole request would exceed budget.
fn candidate_descriptions(eligible: &[Eligible], refs: &RefMaps) -> Value {
    let mut summaries = CANDIDATE_SUMMARY_MAX_CHARS;
    loop {
        let candidates = Value::Array(
            eligible
                .iter()
                .map(|item| {
                    json!({
                        "ref": short_ref(&refs.refs, &item.id),
                        "kind": context_item::kind_of(&item.record),
                        "title": context_item::truncate_chars(
                            &context_item::title_of(&item.record),
                            CANDIDATE_TITLE_MAX_CHARS,
                        ),
                        "summary": context_item::truncate_chars(
                            &context_item::summary_of(&item.record),
                            summaries,
                        ),
                        "status": item.status.clone().map(Value::from).unwrap_or(Value::Null),
                    })
                })
                .collect(),
        );
        if candidates.to_string().len() <= CANDIDATES_MAX_BYTES
            || summaries <= CANDIDATE_SUMMARY_NARROW_CHARS
        {
            return candidates;
        }
        summaries = CANDIDATE_SUMMARY_NARROW_CHARS;
    }
}

/// Validate the model's answer: drop refs outside the candidate set,
/// de-duplicate, cap `why`, and order status-bearing items first while
/// otherwise keeping the model's order.
fn validate_ranking(
    eligible: &[Eligible],
    refs: &RefMaps,
    ranking: claude::Ranking,
) -> (Option<String>, Vec<(usize, Option<String>)>) {
    let mut order = Vec::new();
    let mut seen = HashSet::new();
    for answered in &ranking.items {
        let index = eligible.iter().position(|item| {
            short_ref(&refs.refs, &item.id) == answered.reference || item.id == answered.reference
        });
        let Some(index) = index else { continue };
        if !seen.insert(index) {
            continue;
        }
        let why = context_item::truncate_chars(answered.why.trim(), WHY_MAX_CHARS);
        order.push((index, Some(why)));
    }
    let statuses: Vec<Option<String>> = eligible.iter().map(|item| item.status.clone()).collect();
    let ranked: Vec<usize> = order.iter().map(|(index, _)| *index).collect();
    let whys: HashMap<usize, Option<String>> = order.into_iter().collect();
    let ordered = rank_first(ranked, &statuses);
    let interpretation =
        context_item::truncate_chars(ranking.interpretation.trim(), INTERPRETATION_MAX_CHARS);
    let items = ordered
        .into_iter()
        .map(|index| (index, whys.get(&index).cloned().flatten()))
        .collect();
    (Some(interpretation), items)
}

/// Build the returned `ContextItem` objects: provenance through the
/// slice-3 derivation for `Resolution/*` records (null elsewhere), the
/// linked person subject, and the parsed value for preferences.
async fn build_items(
    db: &Db,
    caller: &Caller,
    eligible: &[Eligible],
    refs: &RefMaps,
    ranked: &[(usize, Option<String>)],
) -> Result<Vec<Value>> {
    let store = Store::new(db, caller);
    let context = store
        .context(
            &eligible
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
    let person_name = context
        .person_name
        .clone()
        .unwrap_or("account holder".to_string());
    // Neighbours: every record the ranked items may name (subjects,
    // supersession, evidence, applies-to), resolved through one authorised
    // batch so unreadable ones simply stay unnamed.
    let mut neighbour_ids = Vec::new();
    for (index, _) in ranked {
        let record = &eligible[*index].record;
        for other in subject_links(record)
            .into_iter()
            .chain(context_item::links_out(record, "supersedes"))
            .chain(context_item::links_in(record, "supersedes"))
            .chain(context_item::evidence_ids(record))
            .chain(context_item::links_out(record, "applies_to"))
        {
            if !neighbour_ids.contains(&other) {
                neighbour_ids.push(other);
            }
        }
    }
    let neighbours = load_records(db, caller, &neighbour_ids).await?;
    let by_id: HashMap<String, Value> = neighbours
        .into_iter()
        .filter_map(|record| {
            let id = record.get("id").and_then(Value::as_str)?.to_string();
            Some((id, record))
        })
        .collect();
    let mut visible: HashSet<String> = eligible.iter().map(|item| item.id.clone()).collect();
    visible.extend(by_id.keys().cloned());
    let mut items = Vec::with_capacity(ranked.len());
    for (index, why) in ranked {
        let item = &eligible[*index];
        // The `hcp.*` facets describe a body only when the attested writer is
        // an HCP write (`origin_for` checks), so passing them for any record
        // is safe: a record HCP never wrote carries none.
        let hcp = item
            .hcp_client
            .clone()
            .map(|client| (client, item.hcp_evidence.clone()));
        let provenance = if context_item::has_origin(&item.record, hcp.is_some()) {
            match store
                .origin_for(
                    &item.id,
                    &context_item::body_of(&item.record),
                    hcp,
                    &context,
                )
                .await?
            {
                Some((origin, at)) => {
                    context_item::provenance_for(&origin, at.as_deref(), &person_name)
                }
                None => context_item::provenance_for(&Origin::default(), None, &person_name),
            }
        } else {
            context_item::provenance_for(&Origin::default(), None, &person_name)
        };
        let subject = context_item::subject_of(&item.record, &by_id)
            .map(|(id, name)| json!({ "ref": short_ref(&refs.refs, &id), "name": name }));
        let value = if item.is_preference {
            Some(
                serde_json::from_str::<Value>(context_item::body_of(&item.record).trim())
                    .unwrap_or(Value::Null),
            )
        } else {
            None
        };
        items.push(context_item::build_item(
            &item.record,
            &refs.refs,
            &provenance,
            subject,
            value,
            why.clone(),
            &visible,
            &by_id,
            item.anchor.as_deref(),
        ));
    }
    Ok(items)
}

/// The handler: authorised candidates, model ranking with a lexical
/// fallback, validated and filtered into `ContextItem` objects.
pub(super) async fn search_context(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if let Some(refusal) = super::refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match parse_args(&arguments) {
        Ok(args) => args,
        Err(body) => return Ok(body),
    };
    let project = match &args.project {
        Some(reference) => match resolve_scope(&db, &caller, reference).await {
            Some(id) => Some(id),
            None => return Ok(ok_response(None, "lexical", Vec::new())),
        },
        None => None,
    };
    let subject = match &args.subject {
        Some(reference) => match resolve_scope(&db, &caller, reference).await {
            Some(id) => Some(id),
            None => return Ok(ok_response(None, "lexical", Vec::new())),
        },
        None => None,
    };
    let mut ids = gather_candidates(&db, &caller, &args.task, project.as_deref()).await?;
    // The scope root itself is not "under" the project; trace it directly.
    if let Some(project) = project.as_deref() {
        ids.retain(|id| id != project);
    }
    // Proposed items live in suggestion records full-text search does not
    // index; pull the open ones attached to the gathered candidates.
    for suggestion in expand_suggestions(&db, &caller, &ids).await? {
        if ids.len() >= CANDIDATE_CAP {
            break;
        }
        ids.push(suggestion);
    }
    let eligible = eligible_records(&db, &caller, &args, &ids, subject.as_deref()).await?;
    if eligible.is_empty() {
        return Ok(ok_response(None, "lexical", Vec::new()));
    }
    let refs = collect_refs(&db, &caller, &eligible).await?;
    let candidates = candidate_descriptions(&eligible, &refs);
    let lexical = || {
        let statuses: Vec<Option<String>> =
            eligible.iter().map(|item| item.status.clone()).collect();
        rank_first((0..eligible.len()).collect(), &statuses)
            .into_iter()
            .map(|index| (index, None))
            .collect::<Vec<(usize, Option<String>)>>()
    };
    let (interpretation, ranking, ranked) =
        match claude::rank_for_tool(&candidates, &args.task, args.limit).await {
            Ok(ranking) => {
                let (interpretation, ranked) = validate_ranking(&eligible, &refs, ranking);
                if ranked.is_empty() {
                    // The model kept nothing: fall back to the lexical order
                    // rather than answer empty from a non-empty candidate set.
                    (None, "lexical", lexical())
                } else {
                    (interpretation, "model", ranked)
                }
            }
            Err(_) => (None, "lexical", lexical()),
        };
    let ranked: Vec<(usize, Option<String>)> = ranked.into_iter().take(args.limit).collect();
    let items = build_items(&db, &caller, &eligible, &refs, &ranked).await?;
    Ok(ok_response(interpretation, ranking, items))
}
