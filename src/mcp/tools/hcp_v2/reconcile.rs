//! Reconciling an edit made in Native with what HCP v2 itself recorded.
//!
//! The spec assumes the provider is the only writer of an entry. Here the
//! person can also edit the view record in Native, which is their management
//! interface and stays supported. So the body JSON is never the authority for
//! what the provider asserts: that comes from the entry's events
//! ([`super::fold`]), and an edit is folded in on these rules:
//!
//! * Only the person's own content is taken from an edit: the statement
//!   (`claim.subject.preference`), its expiry and relationship, and the
//!   category, dimension and metadata. Everything else in the body (status,
//!   assurance, submitting client, grant, provider, record time,
//!   confirmations, declaration type, confidence, the version numbers, the
//!   subject) is ignored: the state stays what the events say. An edit cannot
//!   raise an assurance, invent a confirmation or move the version sequence.
//! * What counts as the person's change is measured against the version the
//!   view showed when they edited it (the *base*), not against the current
//!   state, and is applied onto the current state. A view can be behind (its
//!   write failed, or a client revised the entry meanwhile); its unchanged old
//!   content must not undo the newer version, and an edit that changes nothing
//!   the person manages makes no version.
//! * An edit is only taken if the text was last saved by the person's own
//!   account ([`super::view`] checks): text a collaborator saved while the view
//!   was shared or transferred is not the person's, even after the view is
//!   private again.
//! * If the person's change differs from the current version, the edit is a **new
//!   version**: number = current version + 1, with provenance that says what
//!   happened. The asserter is the person, the submitting client is Native
//!   itself, the source is `native-edit`, and there are no confirmations.
//!   Assurance is `unverified`: Native cannot tell a person's click from a
//!   script holding their token. A view is only reconciled while it is private
//!   to the person, so whoever edited it held the person's own access; edits
//!   are therefore all `user-declared`.
//! * An edit that cannot be taken is **rejected, not discarded**: trusted state
//!   does not change and the person's body is left where it is, with a note
//!   on the record saying why ([`super::view`]).
//!
//! The new version is a `hcp.entry.versioned.v1` event, appended in the same
//! transaction that read the body. Persisting it is what keeps version numbers
//! stable: a version that has been exposed is on the log, so a later edit can
//! only produce the next number, never reuse it.
//!
//! Pending verified suggestion resolutions are consumed before reconciliation
//! reads the body. They append version-bound confirmations and their atomic
//! status consequences; later edits start a fresh version without endorsement.

use chrono::DateTime;
use serde_json::{json, Value};

use super::client::ClientIdentity;
use super::limits::{self, MAX_PREFERENCE_BYTES, MAX_SHORT_TEXT_BYTES};
use super::model::{
    next_version, normalize_dimension, valid_category, Assertion, Entry, USER_DECLARED,
};

pub(super) const NATIVE_EDIT_SOURCE: &str = "native-edit";

/// The content of an entry that the person manages.
#[derive(Clone, Debug, PartialEq)]
struct Editable {
    preference: Value,
    expiration: Value,
    relationship: Value,
    category: String,
    dimension: Value,
    metadata: Option<Value>,
}

impl Editable {
    fn of_trusted(entry: &Entry) -> Editable {
        Editable {
            preference: entry.preference().clone(),
            expiration: entry.0["claim"]["expirationDate"].clone(),
            relationship: entry.0["claim"]["subject"]["relationship"].clone(),
            category: entry.category().to_string(),
            dimension: entry.0["record"]["dimension"].clone(),
            metadata: entry.0["record"].get("metadata").cloned(),
        }
    }

    /// The content of an edited body, or why it cannot be taken.
    fn of_edit(entry: &Entry) -> Result<Editable, String> {
        let preference = entry.preference();
        let text = preference.as_str().unwrap_or_default();
        if text.trim().is_empty() {
            return Err("the statement is blank".into());
        }
        if text.len() > MAX_PREFERENCE_BYTES {
            return Err(format!(
                "the statement is longer than {MAX_PREFERENCE_BYTES} bytes"
            ));
        }
        let expiration = &entry.0["claim"]["expirationDate"];
        match expiration {
            Value::Null => {}
            Value::String(at) if DateTime::parse_from_rfc3339(at).is_ok() => {}
            _ => {
                return Err(
                    "the expiry (claim.expirationDate) must be null or an RFC 3339 time".into(),
                )
            }
        }
        let relationship = &entry.0["claim"]["subject"]["relationship"];
        match relationship {
            Value::Null => {}
            Value::String(text) if text.len() <= MAX_SHORT_TEXT_BYTES => {}
            _ => return Err("the relationship must be null or a short text".into()),
        }
        if !valid_category(entry.category()) {
            return Err(format!(
                "{:?} is not a registered category or an hcp-custom: category",
                entry.category()
            ));
        }
        // A dimension that normalises to nothing addresses no dimension.
        let dimension = match &entry.0["record"]["dimension"] {
            Value::Null => Value::Null,
            Value::String(raw) if raw.len() <= MAX_SHORT_TEXT_BYTES => {
                if normalize_dimension(raw).is_empty() {
                    Value::Null
                } else {
                    json!(raw)
                }
            }
            _ => return Err("the dimension must be null or a short text".into()),
        };
        let metadata = match entry.0["record"].get("metadata") {
            None | Some(Value::Null) => None,
            Some(metadata) if metadata.is_object() => Some(metadata.clone()),
            Some(_) => return Err("the metadata must be an object".into()),
        };
        Ok(Editable {
            preference: preference.clone(),
            expiration: expiration.clone(),
            relationship: relationship.clone(),
            category: entry.category().to_string(),
            dimension,
            metadata,
        })
    }
}

/// The version `body` (the person's edit of the view) makes after `current`:
/// `Ok(None)` when it changes nothing the person manages, `Err` with the
/// reason when it cannot be taken. `base` is the version the view showed when
/// the person edited it: only what they changed *from it* is applied, onto
/// `current`, so a view that was behind the state (its write failed, or a
/// client revised the entry meanwhile) cannot undo the newer version.
/// `subject_id` is the stored Context Subject identifier.
pub(super) fn reconcile(
    current: &Entry,
    base: &Entry,
    body: &str,
    subject_id: &str,
    recorded_at: &str,
) -> Result<Option<Entry>, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "the body is not valid JSON".to_string())?;
    let edited = Entry::parse(&value.to_string()).ok_or_else(|| {
        "the body is not a well-formed HCP entry (it needs a type, id, claim.subject.preference, \
         record.category, record.status, record.version and record.provenance)"
            .to_string()
    })?;
    if edited.id() != current.id() {
        return Err("the body is the entry of a different identifier".into());
    }
    let wanted = Editable::of_edit(&edited)?;
    let (from, now) = (Editable::of_trusted(base), Editable::of_trusted(current));
    let mut merged = now.clone();
    if wanted.preference != from.preference {
        merged.preference = wanted.preference;
    }
    if wanted.expiration != from.expiration {
        merged.expiration = wanted.expiration;
    }
    if wanted.relationship != from.relationship {
        merged.relationship = wanted.relationship;
    }
    if wanted.category != from.category {
        merged.category = wanted.category;
    }
    if wanted.dimension != from.dimension {
        merged.dimension = wanted.dimension;
    }
    if wanted.metadata != from.metadata {
        merged.metadata = wanted.metadata;
    }
    if merged == now {
        return Ok(None);
    }
    let wanted = merged;
    let mut next = next_version(
        current,
        &Assertion {
            preference: &wanted.preference,
            declaration_type: USER_DECLARED,
            confidence: None,
            asserted_by: subject_id,
            source: NATIVE_EDIT_SOURCE,
            client: &ClientIdentity::native(),
            recorded_at,
            asserted_at: None,
        },
    );
    next.0["claim"]["expirationDate"] = wanted.expiration;
    next.0["claim"]["subject"]["relationship"] = wanted.relationship;
    let record = next.0["record"]
        .as_object_mut()
        .expect("a parsed entry has a record object");
    record.insert("category".into(), json!(wanted.category));
    record.insert("dimension".into(), wanted.dimension);
    match wanted.metadata {
        Some(metadata) => record.insert("metadata".into(), metadata),
        None => record.remove("metadata"),
    };
    if !limits::fits(&next.0.to_string()) {
        return Err(format!(
            "the entry is too large; its encoded form may be at most {} bytes",
            limits::MAX_ENTRY_BYTES
        ));
    }
    Ok(Some(next))
}
