//! `traceContextItem` (slice 4a): evidence, history and supersession.
//!
//! Every read goes through an authorised path: `get_record` for the item
//! and its neighbours, `get_history` for revisions. A record the caller
//! cannot read is refused with the same `NOT_FOUND` shape as a missing
//! one, so the refusal never reveals that it exists.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;

use super::context_item::{self, short_ref};
use super::native_block::Origin;
use super::store::Store;

const DEFAULT_HISTORY_LIMIT: i64 = 20;
const MAX_HISTORY_LIMIT: i64 = 100;
const CHANGE_MAX_CHARS: usize = 200;
const EXCERPT_MAX_CHARS: usize = 200;

fn invalid(message: impl Into<String>) -> Value {
    json!({ "success": false, "code": "INVALID_CONTEXT_INPUT", "error": message.into() })
}

/// The refusal for an unreadable record: identical to a missing one.
fn not_found() -> Value {
    json!({ "success": false, "code": "NOT_FOUND", "error": "Context item not found" })
}

struct Args {
    reference: String,
    evidence: bool,
    history: bool,
    supersession: bool,
    history_limit: i64,
}

fn parse_args(arguments: &Value) -> std::result::Result<Args, Value> {
    let args = arguments
        .as_object()
        .ok_or_else(|| invalid("arguments must be an object"))?;
    let reference = match args.get("ref") {
        Some(Value::String(reference)) if !reference.trim().is_empty() => reference.clone(),
        _ => return Err(invalid("ref is required")),
    };
    let (mut evidence, mut history, mut supersession) = (true, true, true);
    if let Some(include) = args.get("include") {
        match include {
            Value::Null => {}
            Value::Array(sections) => {
                (evidence, history, supersession) = (false, false, false);
                for section in sections {
                    match section.as_str() {
                        Some("evidence") => evidence = true,
                        Some("history") => history = true,
                        Some("supersession") => supersession = true,
                        _ => {
                            return Err(invalid(
                                "include must list evidence, history and supersession",
                            ));
                        }
                    }
                }
            }
            _ => return Err(invalid("include must be an array")),
        }
    }
    let history_limit = match args.get("historyLimit") {
        None | Some(Value::Null) => DEFAULT_HISTORY_LIMIT,
        Some(Value::Number(limit)) => match limit.as_i64() {
            Some(limit) if (1..=MAX_HISTORY_LIMIT).contains(&limit) => limit,
            _ => {
                return Err(invalid(format!(
                    "historyLimit must be between 1 and {MAX_HISTORY_LIMIT}"
                )))
            }
        },
        Some(_) => {
            return Err(invalid(format!(
                "historyLimit must be between 1 and {MAX_HISTORY_LIMIT}"
            )))
        }
    };
    Ok(Args {
        reference,
        evidence,
        history,
        supersession,
        history_limit,
    })
}

/// The authorised record, or `None` when it is missing or unreadable: both
/// read the same, so the caller never learns which. Short display refs are
/// expanded first, so a `ref` from `searchContext` traces directly.
async fn load_item(db: &Db, caller: &Caller, reference: &str) -> Result<Option<Value>> {
    let id = match super::context_search::resolve_input_ref(db, caller, reference).await {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => return Ok(None),
    };
    let page =
        super::super::lifecycle::get_record(db.clone(), caller.clone(), json!({ "ids": [id] }))
            .await?;
    let found = page
        .get("records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .next();
    let found = found
        .filter(|record| record.get("status").and_then(Value::as_str) == Some("found"))
        .cloned();
    Ok(
        super::extensions::without_hidden(db, caller, found.into_iter().collect())
            .await?
            .pop(),
    )
}

/// One-line description of a history event: its type plus the fields it
/// changed, capped. Reads only what the authorised history already shows.
fn describe_change(event: &Value) -> String {
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("record.updated");
    let mut fields: Vec<String> = event
        .get("payload")
        .and_then(Value::as_object)
        .map(|payload| {
            payload
                .keys()
                .filter(|key| *key != "reason")
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    fields.sort();
    let change = if fields.is_empty() {
        event_type.to_string()
    } else {
        format!("{event_type} ({})", fields.join(", "))
    };
    context_item::truncate_chars(&change, CHANGE_MAX_CHARS)
}

/// Build a `ContextItem` for one authorised record with resolved refs.
/// `facets` carries the `hcp.*` facets of the records being built, so
/// preferences reuse the Layer 1 provenance inputs exactly.
struct Build<'a> {
    store: &'a Store<'a>,
    context: &'a super::store::Context,
    refs: &'a HashMap<String, Option<String>>,
    subjects: &'a HashMap<String, Value>,
    facets: &'a HashMap<String, HashMap<String, String>>,
    visible: &'a HashSet<String>,
    neighbours: &'a HashMap<String, Value>,
}

async fn build_item(build: &Build<'_>, record: &Value) -> Result<Value> {
    let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
    let person_name = build
        .context
        .person_name
        .as_deref()
        .unwrap_or("account holder");
    let is_preference = record.get("type").and_then(Value::as_str) == Some("Resolution")
        && record.get("kind").and_then(Value::as_str) == Some("preference");
    // The `hcp.*` facets describe a body only when the attested writer is an
    // HCP write (`origin_for` checks), so they are passed for any record.
    let hcp = build
        .facets
        .get(id)
        .and_then(|facets| facets.get("hcp.client"))
        .cloned()
        .map(|client| {
            (
                client,
                build
                    .facets
                    .get(id)
                    .and_then(|facets| facets.get("hcp.evidence"))
                    .cloned(),
            )
        });
    let provenance = if context_item::has_origin(record, hcp.is_some()) {
        match build
            .store
            .origin_for(id, &context_item::body_of(record), hcp, build.context)
            .await?
        {
            Some((origin, at)) => context_item::provenance_for(&origin, at.as_deref(), person_name),
            None => context_item::provenance_for(&Origin::default(), None, person_name),
        }
    } else {
        context_item::provenance_for(&Origin::default(), None, person_name)
    };
    let value = if is_preference {
        Some(
            serde_json::from_str::<Value>(context_item::body_of(record).trim())
                .unwrap_or(Value::Null),
        )
    } else {
        None
    };
    let subject = context_item::subject_of(record, build.subjects)
        .map(|(id, name)| json!({ "ref": short_ref(build.refs, &id), "name": name }));
    Ok(context_item::build_item(
        record,
        build.refs,
        &provenance,
        subject,
        value,
        None,
        build.visible,
        build.neighbours,
        context_item::anchor_of(build.facets.get(id)).as_deref(),
    ))
}

/// Authorised batch fetch of neighbour records: unreadable ones are
/// silently absent, never named.
async fn load_neighbours(db: &Db, caller: &Caller, ids: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    for chunk in ids.chunks(super::super::lifecycle::MAX_BATCH_GET) {
        let page = match super::super::lifecycle::get_record(
            db.clone(),
            caller.clone(),
            json!({ "ids": chunk }),
        )
        .await
        {
            Ok(page) => page,
            Err(_) => continue,
        };
        for record in page
            .get("records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if record.get("status").and_then(Value::as_str) == Some("found") {
                out.push(record.clone());
            }
        }
    }
    super::extensions::without_hidden(db, caller, out)
        .await
        .unwrap_or_default()
}

/// The evidence section: one entry per readable evidence-linked record.
fn evidence_section(
    record: &Value,
    neighbours: &HashMap<String, Value>,
    refs: &HashMap<String, Option<String>>,
) -> Vec<Value> {
    context_item::evidence_ids(record)
        .into_iter()
        .filter_map(|id| {
            let other = neighbours.get(&id)?;
            Some(json!({
                "ref": short_ref(refs, &id),
                "title": context_item::title_of(other),
                "role": "basis",
                "excerpt": context_item::truncate_chars(
                    &context_item::summary_of(other),
                    EXCERPT_MAX_CHARS,
                ),
            }))
        })
        .collect()
}

/// The history section through the authorised `get_history` path. The
/// actor of each event reuses the slice-3 disclosure; `revision` is the
/// body digest the event wrote, or the event id when it wrote no body.
async fn history_section(
    db: &Db,
    caller: &Caller,
    store: &Store<'_>,
    person_name: &str,
    id: &str,
    limit: i64,
) -> Result<Vec<Value>> {
    let page = match super::super::history::get_history(
        db.clone(),
        caller.clone(),
        json!({ "record_id": id, "limit": limit, "detail": "full" }),
    )
    .await
    {
        Ok(page) => page,
        Err(Error::Engine(_)) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut entries = Vec::new();
    for event in page
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let event_id = event.get("id").and_then(Value::as_str).unwrap_or_default();
        let revision = event
            .get("payload")
            .and_then(|payload| payload.get("body"))
            .and_then(Value::as_str)
            .map(super::store::sha256_hex)
            .unwrap_or_else(|| event_id.to_string());
        let actor = match store.actor_for_event(event_id, person_name).await? {
            Some(actor) => actor,
            None => Value::Null,
        };
        entries.push(json!({
            "revision": revision,
            "at": event.get("created_at").cloned().unwrap_or(Value::Null),
            "actor": actor,
            "change": describe_change(event),
        }));
    }
    Ok(entries)
}

/// The handler: the item plus the requested evidence, history and
/// supersession sections.
pub(super) async fn trace_context_item(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if let Some(refusal) = super::refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match parse_args(&arguments) {
        Ok(args) => args,
        Err(body) => return Ok(body),
    };
    let Some(record) = load_item(&db, &caller, &args.reference).await? else {
        return Ok(not_found());
    };
    let id = record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let store = Store::new(&db, &caller);
    // Every id the response may name, resolved to short references at once.
    let mut wanted: Vec<String> = vec![id.clone()];
    let mut seen: HashSet<String> = HashSet::from([id.clone()]);
    let mut push = |other: &str| {
        if seen.insert(other.to_string()) {
            wanted.push(other.to_string());
        }
    };
    for other in context_item::evidence_ids(&record) {
        push(&other);
    }
    for other in super::context_search::subject_links(&record) {
        push(&other);
    }
    for other in context_item::links_out(&record, "supersedes") {
        push(&other);
    }
    for other in context_item::links_in(&record, "supersedes") {
        push(&other);
    }
    if let Some(ancestors) = record.get("ancestors").and_then(Value::as_array) {
        for ancestor in ancestors {
            if let Some(ancestor) = ancestor.get("id").and_then(Value::as_str) {
                push(ancestor);
            }
        }
    }
    let neighbours = load_neighbours(&db, &caller, &wanted).await;
    let subjects: HashMap<String, Value> = neighbours
        .iter()
        .filter_map(|other| {
            other
                .get("id")
                .and_then(Value::as_str)
                .map(|other_id| (other_id.to_string(), other.clone()))
        })
        .collect();
    let by_id: HashMap<String, Value> = subjects.clone();
    let context = store.context(&wanted).await?;
    let refs = context.references.clone();
    let person_name = context
        .person_name
        .clone()
        .unwrap_or("account holder".to_string());
    let facets = super::context_search::hcp_facets(&db, &caller, &wanted).await?;
    let mut visible: HashSet<String> = by_id.keys().cloned().collect();
    visible.insert(id.clone());
    let build = Build {
        store: &store,
        context: &context,
        refs: &refs,
        subjects: &subjects,
        facets: &facets,
        visible: &visible,
        neighbours: &by_id,
    };
    let item = build_item(&build, &record).await?;
    let mut body = Map::new();
    body.insert("item".into(), item);
    if args.evidence {
        body.insert(
            "evidence".into(),
            Value::Array(evidence_section(&record, &by_id, &refs)),
        );
    }
    if args.history {
        body.insert(
            "history".into(),
            Value::Array(
                history_section(&db, &caller, &store, &person_name, &id, args.history_limit)
                    .await?,
            ),
        );
    }
    if args.supersession {
        let mut supersedes = Vec::new();
        for other in context_item::links_out(&record, "supersedes") {
            if let Some(record) = by_id.get(&other) {
                supersedes.push(build_item(&build, record).await?);
            }
        }
        let superseded_by = context_item::links_in(&record, "supersedes")
            .into_iter()
            .filter_map(|other| by_id.get(&other))
            .next()
            .map(|record| build_item(&build, record));
        let mut supersession = Map::new();
        supersession.insert("supersedes".into(), Value::Array(supersedes));
        if let Some(superseded_by) = superseded_by {
            supersession.insert("supersededBy".into(), superseded_by.await?);
        } else {
            supersession.insert("supersededBy".into(), Value::Null);
        }
        body.insert("supersession".into(), Value::Object(supersession));
    }
    let mut out = Map::new();
    out.insert("success".into(), Value::Bool(true));
    out.append(&mut body);
    Ok(Value::Object(out))
}
// TRACE_PART2
