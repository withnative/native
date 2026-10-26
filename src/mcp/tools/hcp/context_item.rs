//! The Layer 3 `ContextItem` wire shape (slice 4a).
//!
//! A `ContextItem` projects an existing Native record: every field except
//! `why` is read from Native. `why` is the model's one line on relevance to
//! the task (or `null` on the lexical path, which never invents one).
//!
//! Status follows the accepted design: `proposed`/`accepted` for governing
//! kinds (`Resolution/*`, plus an open `Annotation/suggestion` as the
//! proposed item), `superseded` for any record with an incoming `supersedes`
//! link, otherwise `null`. `lifecycle` passes Native's own state through.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use super::native_block::{basis, recorded_by, Origin};

/// Characters of body text used when a record has no summary. The model
/// never writes summaries: a missing summary falls back to truncated body
/// text, never a model summary.
pub(super) const SUMMARY_FALLBACK_MAX_CHARS: usize = 500;

/// Link relationships counted as evidence for `evidenceCount`. There is no
/// older convention to follow; these are the structural link names this
/// slice reads.
pub(super) const EVIDENCE_RELATIONSHIPS: [&str; 4] =
    ["evidence", "derived_from", "supports", "basis"];

pub(super) fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        text.chars().take(max).collect()
    } else {
        text.to_string()
    }
}

fn record_str(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn links<'v>(record: &'v Value, key: &str) -> Vec<&'v Value> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .collect()
}

/// Outgoing links (`links_out`) of one relationship.
pub(super) fn links_out(record: &Value, relationship: &str) -> Vec<String> {
    links(record, "links_out")
        .iter()
        .filter(|link| link.get("relationship").and_then(Value::as_str) == Some(relationship))
        .filter_map(|link| {
            link.get("target_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// Incoming links (`links_in`) of one relationship.
pub(super) fn links_in(record: &Value, relationship: &str) -> Vec<String> {
    links(record, "links_in")
        .iter()
        .filter(|link| link.get("relationship").and_then(Value::as_str) == Some(relationship))
        .filter_map(|link| {
            link.get("source_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// The status rule: `superseded` wins (any record with a *readable*
/// incoming `supersedes` link — an unreadable successor reveals nothing, not
/// even its existence — or Native's own `superseded` maturity), then
/// `proposed` for an open suggestion or any record at Native's `proposed`
/// maturity (how `proposeContextItem` marks a new record), then `accepted`
/// for a record at `decided` maturity and for any other `Resolution/*`
/// record. Anything else carries no status. `visible` holds the ids this
/// caller is known to read.
pub(super) fn status_of(
    record: &Value,
    visible: &std::collections::HashSet<String>,
) -> Option<&'static str> {
    if links_in(record, "supersedes")
        .iter()
        .any(|id| visible.contains(id))
    {
        return Some("superseded");
    }
    let maturity = record.get("maturity").and_then(Value::as_str);
    if maturity == Some("superseded") {
        return Some("superseded");
    }
    let record_type = record
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = record
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let archived = record
        .get("archived")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if record_type == "Annotation" && kind == "suggestion" && !archived {
        // Only an open suggestion is a live proposal: rejected and withdrawn
        // lifecycles are closed, whatever the archive flag says.
        if lifecycle_of(record).as_deref() == Some("open") {
            return Some("proposed");
        }
        return None;
    }
    if maturity == Some("proposed") {
        return Some("proposed");
    }
    if maturity == Some("decided") || record_type == "Resolution" {
        return Some("accepted");
    }
    None
}

/// Native's own `type/kind`, never an invented enum.
pub(super) fn kind_of(record: &Value) -> String {
    let record_type = record
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("Unknown");
    let kind = record
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    format!("{record_type}/{kind}")
}

/// The human-readable title: the record's name, or its summary, or a
/// truncated body slice when neither exists.
pub(super) fn title_of(record: &Value) -> String {
    if let Some(name) = record_str(record, "name") {
        return name;
    }
    summary_of(record)
}

/// The record's summary, or truncated body text when it has none.
pub(super) fn summary_of(record: &Value) -> String {
    if let Some(summary) = record_str(record, "summary") {
        return summary;
    }
    let body = record
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default();
    truncate_chars(body.trim(), SUMMARY_FALLBACK_MAX_CHARS)
}

pub(super) fn body_of(record: &Value) -> String {
    record
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub(super) fn lifecycle_of(record: &Value) -> Option<String> {
    if let Some(lifecycle) = record_str(record, "lifecycle") {
        return Some(lifecycle);
    }
    // `get_record` reports governed lifecycles structurally.
    record
        .get("lifecycle_interpretation")
        .and_then(|interpretation| interpretation.get("value"))
        .and_then(|value| {
            value
                .get("canonical")
                .or_else(|| value.get("raw"))
                .and_then(Value::as_str)
        })
        .filter(|lifecycle| !lifecycle.is_empty())
        .map(str::to_string)
}

pub(super) fn updated_at_of(record: &Value) -> Option<String> {
    record_str(record, "updated_at").or_else(|| record_str(record, "created_at"))
}

/// Records this item cites as evidence (outgoing) plus records citing it
/// (incoming), under the evidence relationships above.
pub(super) fn evidence_ids(record: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for relationship in EVIDENCE_RELATIONSHIPS {
        ids.extend(links_out(record, relationship));
        ids.extend(links_in(record, relationship));
    }
    ids.sort();
    ids.dedup();
    ids
}

/// The first linked person entity, either direction: `{id, name}`.
pub(super) fn subject_of(
    record: &Value,
    by_id: &HashMap<String, Value>,
) -> Option<(String, String)> {
    let mut linked = Vec::new();
    for link in links(record, "links_out")
        .into_iter()
        .chain(links(record, "links_in"))
    {
        let id = link
            .get("target_id")
            .or_else(|| link.get("source_id"))
            .and_then(Value::as_str)?;
        linked.push(id.to_string());
    }
    linked.sort();
    linked.dedup();
    linked.into_iter().find_map(|id| {
        let other = by_id.get(&id)?;
        if other.get("type").and_then(Value::as_str) != Some("Entity") {
            return None;
        }
        if other.get("kind").and_then(Value::as_str) != Some("person") {
            return None;
        }
        let name = other
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed person")
            .to_string();
        Some((id, name))
    })
}
/// Provenance mapped onto the Layer 3 actor shape, reusing the slice-3
/// derivation: `assertedBy` is the account holder when the basis says the
/// person holds it, `recordedBy` names the body-producing actor under
/// Native's disclosure rule, and `acceptedBy` names that same actor with
/// the acceptance time when an acceptance produced the body.
pub(super) struct ItemProvenance {
    pub asserted: Value,
    pub recorded: Value,
    pub accepted: Value,
}

pub(super) fn provenance_for(
    origin: &Origin,
    body_at: Option<&str>,
    person_name: &str,
) -> ItemProvenance {
    let asserted = match basis(origin) {
        Some(basis) => json!({ "kind": "person", "name": person_name, "basis": basis.as_str() }),
        None => Value::Null,
    };
    let recorded = recorded_by(origin, person_name).unwrap_or(Value::Null);
    let accepted = match (&origin.accepted, &origin.decided) {
        (Some(accepted), _) if !accepted.ambiguous => {
            let mut acceptor = recorded.clone();
            if let (Some(at), Some(object)) = (body_at, acceptor.as_object_mut()) {
                object.insert("at".into(), json!(at));
            }
            if acceptor.is_null() {
                Value::Null
            } else {
                acceptor
            }
        }
        // A proposed record accepted by a maturity change: the acceptor is
        // whoever made that change, which is not who wrote the body.
        (None, Some(decided)) if decided.unique => {
            let by_decider = Origin {
                writer: Some(decided.writer.clone()),
                ..Origin::default()
            };
            let mut acceptor = recorded_by(&by_decider, person_name).unwrap_or(Value::Null);
            if let (Some(at), Some(object)) = (decided.at.as_deref(), acceptor.as_object_mut()) {
                object.insert("at".into(), json!(at));
            }
            acceptor
        }
        _ => Value::Null,
    };
    ItemProvenance {
        asserted,
        recorded,
        accepted,
    }
}

/// Whether provenance is read for this record: governing records, open
/// suggestions (a proposal has a recorded author), and anything an HCP write
/// stamped with its client.
pub(super) fn has_origin(record: &Value, hcp_stamped: bool) -> bool {
    let record_type = record.get("type").and_then(Value::as_str);
    let kind = record.get("kind").and_then(Value::as_str);
    hcp_stamped
        || record_type == Some("Resolution")
        || (record_type == Some("Annotation") && kind == Some("suggestion"))
}

/// The revision a caller passes back as `expectedRevision`: the SHA-256 of
/// the body, which is what Native's `if_body_digest` guards. For an open
/// suggestion with a digest precondition it is instead `anchor`, the revision
/// of its target that the proposal is anchored to (the precondition the engine
/// enforces when the proposal is accepted), because that is what accepting it
/// is conditional on; the proposal's own text is not what changes under it.
pub(super) fn revision_of(record: &Value, anchor: Option<&str>) -> String {
    let is_suggestion = record.get("type").and_then(Value::as_str) == Some("Annotation")
        && record.get("kind").and_then(Value::as_str) == Some("suggestion");
    match anchor {
        Some(anchor) if is_suggestion => anchor.to_ascii_lowercase(),
        _ => super::store::sha256_hex(&body_of(record)),
    }
}

/// The digest a suggestion is anchored to, from its `proposal.precondition`
/// and `anchor.base_digest` facets (as `hcp_facets` reads them).
pub(super) fn anchor_of(facets: Option<&HashMap<String, String>>) -> Option<String> {
    let facets = facets?;
    (facets.get("proposal.precondition").map(String::as_str) == Some("digest"))
        .then(|| facets.get("anchor.base_digest").cloned())
        .flatten()
}

/// Short reference for display, falling back to the full id when Native
/// resolved none (for example a record the caller reads through a path
/// without a reference).
pub(super) fn short_ref(refs: &HashMap<String, Option<String>>, id: &str) -> String {
    refs.get(id)
        .and_then(Option::as_deref)
        .unwrap_or(id)
        .to_string()
}

/// One full `ContextItem` object. `record` is the authorised `get_record`
/// output; `refs` maps every id that appears (the record, its ancestors
/// and its links) to its short reference; `value` is the parsed preference
/// body for `Resolution/preference` records and `None` otherwise.
/// `visible` holds the ids this caller is known to read: links, counts and
/// status never name anything outside it. `neighbours` carries the readable
/// linked records, for `applies_to` names.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_item(
    record: &Value,
    refs: &HashMap<String, Option<String>>,
    provenance: &ItemProvenance,
    subject: Option<Value>,
    value: Option<Value>,
    why: Option<String>,
    visible: &HashSet<String>,
    neighbours: &HashMap<String, Value>,
    anchor: Option<&str>,
) -> Value {
    let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
    let reference = short_ref(refs, id);
    let status = status_of(record, visible)
        .map(Value::from)
        .unwrap_or(Value::Null);
    let mut applies_to: Vec<Value> = Vec::new();
    if let Some(ancestors) = record.get("ancestors").and_then(Value::as_array) {
        for ancestor in ancestors {
            let is_folder = ancestor.get("type").and_then(Value::as_str) == Some("Collection")
                && ancestor.get("kind").and_then(Value::as_str) == Some("folder");
            if !is_folder {
                continue;
            }
            let ancestor_id = ancestor
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if ancestor_id == "native:root" {
                continue;
            }
            applies_to.push(json!({
                "ref": short_ref(refs, ancestor_id),
                "name": ancestor.get("name").and_then(Value::as_str).unwrap_or(""),
            }));
        }
    }
    for other in links_out(record, "applies_to") {
        if !visible.contains(&other) {
            continue;
        }
        let name = neighbours
            .get(&other)
            .and_then(|other| other.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let entry = json!({ "ref": short_ref(refs, &other), "name": name });
        if !applies_to.contains(&entry) {
            applies_to.push(entry);
        }
    }
    let supersedes: Vec<Value> = links_out(record, "supersedes")
        .into_iter()
        .filter(|id| visible.contains(id))
        .map(|id| json!(short_ref(refs, &id)))
        .collect();
    let superseded_by = links_in(record, "supersedes")
        .into_iter()
        .find(|id| visible.contains(id))
        .map(|id| json!(short_ref(refs, &id)))
        .unwrap_or(Value::Null);
    let evidence_count = evidence_ids(record)
        .into_iter()
        .filter(|id| visible.contains(id))
        .count();
    let mut item = json!({
        "ref": reference,
        "url": format!("/{reference}"),
        "kind": kind_of(record),
        "title": title_of(record),
        "summary": summary_of(record),
        "status": status,
        "appliesTo": applies_to,
        "subject": subject.unwrap_or(Value::Null),
        "assertedBy": provenance.asserted,
        "acceptedBy": provenance.accepted,
        "recordedBy": provenance.recorded,
        "revision": revision_of(record, anchor),
        "supersedes": supersedes,
        "supersededBy": superseded_by,
        "evidenceCount": evidence_count,
        "updatedAt": updated_at_of(record).unwrap_or_default(),
        "lifecycle": lifecycle_of(record).map(Value::from).unwrap_or(Value::Null),
        "why": why.map(Value::from).unwrap_or(Value::Null),
    });
    if let Some(value) = value {
        item["value"] = value;
    }
    item
}
