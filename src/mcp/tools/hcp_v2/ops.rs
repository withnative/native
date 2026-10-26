//! The five operations (HCP v2 §5.2.1-§5.2.5) over Native records.
//!
//! Each takes the already-authenticated client's [`Store`] and the raw tool
//! arguments, and returns the Core result object or a [`Failure`]. Arguments
//! are validated here, not by the registry, so a request that violates the
//! tool's schema is a Core `invalid request` tool execution error (§10.4)
//! rather than a protocol error.
//!
//! Provider-set fields (§3.5) are never read from the arguments: the code
//! below does not look at any key the tool schemas do not name.

use chrono::Utc;
use serde_json::{json, Map, Value};

use super::limits::{self, MAX_PREFERENCE_BYTES, MAX_SHORT_TEXT_BYTES};
use super::model::{
    self, category_in_grant, new_entry, next_version, normalize_dimension, valid_category,
    Assertion, ISSUER_ATTESTED, MODEL_INFERRED, REDACTED_FIELDS, STATUS_ACTIVE, STATUS_DELETED,
    USER_DECLARED,
};
use super::store::{entry_urn, Store, Stored};
use super::{Failure, Outcome};

const DEFAULT_MAX_ENTRIES: u64 = 5;
/// The ceiling on entries per response, for every binding (HCP v2 §7.2).
const MAX_ENTRIES_CEILING: u64 = 20;
const MAX_CATEGORIES: usize = 64;
const MAX_ASSERTER_CHARS: usize = 256;
/// `record.provenance.source` when an update does not say where the revised
/// assertion came from (HCP v2 §5.2.4 makes it conditional, but it is a
/// required field of the entry, §4.2).
const SOURCE_UNSPECIFIED: &str = "unspecified";

// ---- argument helpers -------------------------------------------------------

fn object(arguments: &Value) -> Result<&Map<String, Value>, Failure> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    match arguments {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(EMPTY.get_or_init(Map::new)),
        _ => Err(Failure::invalid("arguments must be an object")),
    }
}

fn required<'v>(
    map: &'v Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<&'v str, Failure> {
    match map.get(key) {
        Some(Value::String(text)) if !text.trim().is_empty() => {
            if text.len() > max_bytes {
                Err(Failure::invalid(format!(
                    "{key} is longer than {max_bytes} bytes"
                )))
            } else {
                Ok(text)
            }
        }
        Some(Value::String(_)) => Err(Failure::invalid(format!("{key} must not be blank"))),
        Some(_) => Err(Failure::invalid(format!("{key} must be a string"))),
        None => Err(Failure::invalid(format!("{key} is required"))),
    }
}

/// A string argument that may be absent or null.
fn optional<'v>(
    map: &'v Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<&'v str>, Failure> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= max_bytes => Ok(Some(text)),
        Some(Value::String(_)) => Err(Failure::invalid(format!(
            "{key} is longer than {max_bytes} bytes"
        ))),
        Some(_) => Err(Failure::invalid(format!("{key} must be a string or null"))),
    }
}

/// A positive integer argument that may be absent.
fn positive_integer(map: &Map<String, Value>, key: &str) -> Result<Option<u64>, Failure> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => match value.as_u64() {
            Some(n) if n >= 1 => Ok(Some(n)),
            _ => Err(Failure::invalid(format!(
                "{key} must be a positive integer"
            ))),
        },
    }
}

/// The `declarationType`, `confidence` and `assertedBy` of a write, checked
/// against the confidence rule (HCP v2 §5.2.3) and the Context Client limits
/// of §3.7.
struct Declared<'v> {
    declaration_type: &'v str,
    confidence: Option<&'v str>,
    asserted_by: Option<&'v str>,
}

fn declared<'v>(
    map: &'v Map<String, Value>,
    declaration_type: &'v str,
) -> Result<Declared<'v>, Failure> {
    match declaration_type {
        USER_DECLARED | MODEL_INFERRED => {}
        // A Context Client cannot create an issuer-attested entry (§3.7): a
        // Core rule, so the answer is not authorized, not a schema complaint.
        ISSUER_ATTESTED => return Err(Failure::not_authorized()),
        other => {
            return Err(Failure::invalid(format!(
                "declarationType must be user-declared or model-inferred, not {other:?}"
            )))
        }
    }
    let confidence = match map.get("confidence") {
        None | Some(Value::Null) => None,
        Some(Value::String(c)) if matches!(c.as_str(), "high" | "medium" | "low") => {
            Some(c.as_str())
        }
        Some(_) => {
            return Err(Failure::invalid(
                "confidence must be high, medium, low or null",
            ))
        }
    };
    if declaration_type == MODEL_INFERRED {
        if confidence.is_none() {
            return Err(Failure::invalid(
                "confidence is required when declarationType is model-inferred",
            ));
        }
        let asserted_by = required(map, "assertedBy", MAX_ASSERTER_CHARS * 4)?;
        if asserted_by.trim().chars().count() > MAX_ASSERTER_CHARS {
            return Err(Failure::invalid("assertedBy is too long"));
        }
        Ok(Declared {
            declaration_type,
            confidence,
            asserted_by: Some(asserted_by.trim()),
        })
    } else {
        if confidence.is_some() {
            return Err(Failure::invalid(
                "confidence must be null or omitted unless declarationType is model-inferred",
            ));
        }
        // The Context Subject is the asserter of a user-declared entry: the
        // provider records them (§5.2.3), whatever the client names.
        Ok(Declared {
            declaration_type,
            confidence: None,
            asserted_by: None,
        })
    }
}

/// An entry whose encoded body exceeds the entry bound is refused rather than
/// stored (see `limits::MAX_ENTRY_BYTES`).
fn ensure_fits(entry: &model::Entry) -> Result<(), Failure> {
    if !limits::fits(&entry.0.to_string()) {
        return Err(Failure::invalid(format!(
            "the entry is too large; its encoded form may be at most {} bytes",
            limits::MAX_ENTRY_BYTES
        )));
    }
    Ok(())
}

fn retrieval_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

fn redacted_fields() -> Vec<&'static str> {
    REDACTED_FIELDS.to_vec()
}

// ---- search (§5.2.1) --------------------------------------------------------

pub(super) async fn search(store: &Store<'_>, arguments: &Value) -> Outcome {
    let map = object(arguments)?;
    let query = required(map, "query", MAX_SHORT_TEXT_BYTES)?;
    let purpose = required(map, "purpose", MAX_SHORT_TEXT_BYTES)?;
    let categories: Vec<String> = match map.get("categories") {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_CATEGORIES => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or_else(|| Failure::invalid("categories must be an array of strings"))?,
        Some(Value::Array(_)) => {
            return Err(Failure::invalid(format!(
                "categories must hold between 1 and {MAX_CATEGORIES} slugs"
            )))
        }
        Some(_) => return Err(Failure::invalid("categories must be an array of strings")),
        None => return Err(Failure::invalid("categories is required")),
    };
    if let Some(unknown) = categories.iter().find(|c| !valid_category(c)) {
        return Err(Failure::invalid(format!(
            "{unknown:?} is not a registered category or an hcp-custom: category"
        )));
    }
    // One outside the grant fails the whole search (§5.2.1). With no
    // per-client grants nothing is outside it yet.
    if categories.iter().any(|c| !category_in_grant(c)) {
        return Err(Failure::not_authorized());
    }
    let max_entries = positive_integer(map, "maxEntries")?
        .unwrap_or(DEFAULT_MAX_ENTRIES)
        .min(MAX_ENTRIES_CEILING) as usize;
    let minimal = match map.get("responseDetail") {
        None | Some(Value::Null) => false,
        Some(Value::String(detail)) if detail == "full" => false,
        Some(Value::String(detail)) if detail == "minimal" => true,
        Some(_) => return Err(Failure::invalid("responseDetail must be full or minimal")),
    };

    let mut searched: Vec<String> = Vec::new();
    for category in &categories {
        if !searched.contains(category) {
            searched.push(category.clone());
        }
    }
    // What the person changed in Native since the last call counts first.
    store.pick_up_edits().await?;
    let mut tx = store.begin().await?;
    let now = Utc::now();
    let query_terms = model::terms(query);
    let mut ranked: Vec<(u32, Stored)> = store
        .fold_all_in(&mut tx)
        .await?
        .entries
        .values()
        .map(Stored::from)
        // The fold narrowed the read; the entry decides.
        .filter(|stored| searched.iter().any(|c| c == stored.entry.category()))
        .filter(|stored| stored.entry.visible_to_context_client(now))
        .filter_map(|stored| {
            let score = model::lexical_score(&query_terms, &stored.entry);
            (score > 0).then_some((score, stored))
        })
        .collect();
    ranked.sort_by(|(a_score, a), (b_score, b)| {
        b_score
            .cmp(a_score)
            .then_with(|| b.entry.recorded_at().cmp(a.entry.recorded_at()))
            .then_with(|| a.entry.id().cmp(b.entry.id()))
    });
    let chosen: Vec<Stored> = ranked
        .into_iter()
        .take(max_entries)
        .map(|(_, stored)| stored)
        .collect();

    let entries: Vec<Value> = if chosen.is_empty() {
        Vec::new()
    } else {
        let pseudonym = store.pseudonym();
        chosen
            .iter()
            .map(|stored| {
                if minimal {
                    stored.entry.minimal()
                } else {
                    stored.entry.for_context_client(&pseudonym)
                }
            })
            .collect()
    };

    let retrieval_id = retrieval_id();
    store
        .record_read(
            &mut tx,
            "search",
            purpose,
            &retrieval_id,
            searched.clone(),
            chosen.iter().map(|s| s.entry.id().to_string()).collect(),
        )
        .await?;
    store.commit(tx).await?;

    Ok(json!({
        "entries": entries,
        "retrievalId": retrieval_id,
        // Not the number considered or available: those would tell the
        // client the size of holdings it was not granted (§7.5).
        "minimization": { "method": "lexical", "redactedFields": redacted_fields() },
        "categoriesSearched": categories,
        "timestamp": model::timestamp(now),
    }))
}

// ---- get (§5.2.2) -----------------------------------------------------------

pub(super) async fn get(store: &Store<'_>, arguments: &Value) -> Outcome {
    let map = object(arguments)?;
    let entry_id = required(map, "entryId", MAX_SHORT_TEXT_BYTES)?;
    let purpose = required(map, "purpose", MAX_SHORT_TEXT_BYTES)?;
    let version = positive_integer(map, "version")?;

    let mut tx = store.begin().await?;
    if !store.disclosed_in(&mut tx, entry_id).await? {
        return Err(Failure::not_authorized());
    }
    tx.rollback().await.map_err(crate::error::Error::from)?;
    store.pick_up_edit(entry_id).await?;
    let mut tx = store.begin().await?;
    if !store.disclosed_in(&mut tx, entry_id).await? {
        return Err(Failure::not_authorized());
    }
    let now = Utc::now();
    let stored = store
        .entry_in(&mut tx, entry_id)
        .await?
        .filter(|stored| category_in_grant(stored.entry.category()))
        .filter(|stored| stored.entry.visible_to_context_client(now))
        .ok_or_else(Failure::not_authorized)?;
    let entry = match version {
        None => stored.entry.clone(),
        // A version that does not exist, or is not visible, reads as an
        // absent entry: the answer is the same one a hidden entry gets.
        Some(version) => usize::try_from(version - 1)
            .ok()
            .and_then(|index| stored.versions.get(index))
            .filter(|entry| category_in_grant(entry.category()))
            .filter(|entry| entry.visible_to_context_client(now))
            .cloned()
            .ok_or_else(Failure::not_authorized)?,
    };
    let pseudonym = store.pseudonym();

    let retrieval_id = retrieval_id();
    store
        .record_read(
            &mut tx,
            "get",
            purpose,
            &retrieval_id,
            vec![entry.category().to_string()],
            vec![entry.id().to_string()],
        )
        .await?;
    store.commit(tx).await?;

    // Keep the person's view of the entry in step with it (best effort).
    store.sync_view(stored.entry.id()).await;

    Ok(json!({
        "entry": entry.for_context_client(&pseudonym),
        "retrievalId": retrieval_id,
        "minimization": { "method": "none", "redactedFields": redacted_fields() },
        "timestamp": model::timestamp(now),
    }))
}

// ---- add (§5.2.3) -----------------------------------------------------------

pub(super) async fn add(store: &Store<'_>, arguments: &Value) -> Outcome {
    let map = object(arguments)?;
    let category = required(map, "category", MAX_SHORT_TEXT_BYTES)?;
    let preference = required(map, "preference", MAX_PREFERENCE_BYTES)?;
    let source = required(map, "sourceContext", MAX_SHORT_TEXT_BYTES)?;
    let declaration_type = required(map, "declarationType", MAX_SHORT_TEXT_BYTES)?;
    let dimension = optional(map, "dimension", MAX_SHORT_TEXT_BYTES)?;
    let declared = declared(map, declaration_type)?;
    if !valid_category(category) {
        return Err(Failure::invalid(format!(
            "{category:?} is not a registered category or an hcp-custom: category"
        )));
    }
    if !category_in_grant(category) {
        return Err(Failure::not_authorized());
    }
    // Stored as sent; the normalised spelling goes in the facet (§15.2). A
    // dimension that normalises to nothing addresses no dimension.
    let dimension = dimension.filter(|raw| !normalize_dimension(raw).is_empty());

    let subject_id = store.stored_subject_id();
    let preference_value = json!(preference);
    let recorded_at = model::timestamp(Utc::now());
    let record_id = uuid::Uuid::new_v4().to_string();
    let entry = new_entry(
        &entry_urn(&record_id),
        category,
        dimension,
        &subject_id,
        &Assertion {
            preference: &preference_value,
            declaration_type: declared.declaration_type,
            confidence: declared.confidence,
            asserted_by: declared.asserted_by.unwrap_or(&subject_id),
            source,
            client: &store.client,
            recorded_at: &recorded_at,
            asserted_at: None,
        },
    );
    ensure_fits(&entry)?;

    store.consume_all_resolutions().await?;
    let mut tx = store.begin().await?;
    let mut act = crate::act::ActAllocation::new();
    for urn in store.fold_all_in(&mut tx).await?.entries.keys() {
        store.consume_resolutions_in(&mut tx, &mut act, urn).await?;
    }
    store.append_add(&mut tx, &mut act, &entry).await?;
    store.commit(tx).await?;
    store.sync_version_views(entry.id()).await;

    // Return the write receipt, not the quarantined fold: the response must
    // not reveal whether other holdings caused a conflict (§4.7.2).
    Ok(entry.for_context_client(&store.pseudonym()))
}

// ---- update (§5.2.4) --------------------------------------------------------

pub(super) async fn update(store: &Store<'_>, arguments: &Value) -> Outcome {
    let map = object(arguments)?;
    let entry_id = required(map, "entryId", MAX_SHORT_TEXT_BYTES)?;
    let preference = required(map, "updatedPreference", MAX_PREFERENCE_BYTES)?;
    let reason = required(map, "reason", MAX_SHORT_TEXT_BYTES)?;
    let source =
        optional(map, "sourceContext", MAX_SHORT_TEXT_BYTES)?.unwrap_or(SOURCE_UNSPECIFIED);
    let new_declaration = optional(map, "declarationType", MAX_SHORT_TEXT_BYTES)?;
    // An unknown or forbidden declaration type is the request's fault whatever
    // the entry is.
    if let Some(declaration_type) = new_declaration {
        declared(map, declaration_type)?;
    }

    // An edit the person made in Native comes first: this revision builds on it.
    store.pick_up_edit(entry_id).await?;
    let mut tx = store.begin().await?;
    let mut act = crate::act::ActAllocation::new();
    store
        .consume_resolutions_in(&mut tx, &mut act, entry_id)
        .await?;
    let now = Utc::now();
    let current = store
        .entry_in(&mut tx, entry_id)
        .await?
        .filter(|stored| category_in_grant(stored.entry.category()))
        .filter(|stored| stored.entry.updatable_by_context_client(now))
        .ok_or_else(Failure::not_authorized)?;
    // Omitted means unchanged (§5.2.4); the confidence rule then applies to
    // the type the revision ends up with.
    let declaration_type = new_declaration.unwrap_or_else(|| current.entry.declaration_type());
    let declared = declared(map, declaration_type)?;

    let subject_id = store.stored_subject_id();
    let preference_value = json!(preference);
    let recorded_at = model::timestamp(now);
    let next = next_version(
        &current.entry,
        &Assertion {
            preference: &preference_value,
            declaration_type: declared.declaration_type,
            confidence: declared.confidence,
            asserted_by: declared.asserted_by.unwrap_or(&subject_id),
            source,
            client: &store.client,
            recorded_at: &recorded_at,
            asserted_at: None,
        },
    );
    ensure_fits(&next)?;
    store
        .append_update(&mut tx, &mut act, &current, &next, reason)
        .await?;
    store.commit(tx).await?;
    store.sync_version_views(next.id()).await;
    // The stored revision inherits lifecycle state for conflict evaluation.
    // The receipt always says active, including when revising a quarantined
    // entry; only subsequent retrieval applies the committed quarantine.
    let mut next = next;
    next.set_status(STATUS_ACTIVE);
    Ok(next.for_context_client(&store.pseudonym()))
}

// ---- delete (§5.2.5) --------------------------------------------------------

pub(super) async fn delete(store: &Store<'_>, arguments: &Value) -> Outcome {
    let map = object(arguments)?;
    let entry_id = required(map, "entryId", MAX_SHORT_TEXT_BYTES)?;
    let reason = required(map, "reason", MAX_SHORT_TEXT_BYTES)?;

    store.pick_up_edit(entry_id).await?;
    let mut tx = store.begin().await?;
    let mut act = crate::act::ActAllocation::new();
    store
        .consume_resolutions_in(&mut tx, &mut act, entry_id)
        .await?;
    let now = Utc::now();
    let current = store
        .entry_in(&mut tx, entry_id)
        .await?
        .filter(|stored| category_in_grant(stored.entry.category()))
        // Already deleted or expired reads as absent, like any hidden entry.
        .filter(|stored| stored.entry.status() != STATUS_DELETED && !stored.entry.expired(now))
        .ok_or_else(Failure::not_authorized)?;
    // Only `record.status` changes, so there is no new version (§4.2.1).
    store
        .append_status(
            &mut tx,
            &mut act,
            &current,
            STATUS_DELETED,
            "client_delete",
            reason,
        )
        .await?;
    store.commit(tx).await?;
    store.sync_view(current.entry.id()).await;
    Ok(json!({
        "entryId": current.entry.id(),
        "status": STATUS_DELETED,
        "timestamp": model::timestamp(now),
    }))
}
