//! The trusted state of a person's HCP v2 entries: a deterministic fold of
//! their `hcp_state` control events (HCP v2 design: Native record `8ac1e62`).
//!
//! The private record that holds an entry in Native is a *view* the person can
//! edit, share or transfer; nothing in it is evidence. What an entry says, its
//! version sequence, its provenance per version and its status all come from
//! here. [`fold`] is a pure function of the events in log order, so replaying
//! the log (restore, standby, import) reaches the same state, and a judgement
//! made once is never revisited:
//!
//! * An entry belongs to the person who created it. The first event of an
//!   entry must be `hcp.entry.versioned.v1` version 1, cause `add`, naming
//!   that person's own Context Subject identifier. Events for an entry nobody
//!   created, or whose subject is someone else's, are ignored.
//! * Versions are monotonic and never reused: a version is accepted only as
//!   exactly the current version plus one, and its `previousVersion` is the
//!   current version. A repeat or a gap is ignored, so a number a client has
//!   seen can never come to mean a different claim.
//! * A status change must start from the entry's current status and name its
//!   current version.
//!
//! An ignored event stays in the log and in [`Fold::rejected`]; it changes
//! nothing. The events are validated for shape and for the person's aggregate
//! when they are appended (`control::validate_stored_control_event`); the
//! chain rules above are the part that needs the earlier events.

use std::collections::BTreeMap;

use crate::control::{
    HcpEntryConfirmedPayload, HcpEntryStatusSetPayload, HcpEntrySuggestionPayload,
    HcpEntryVersionedPayload,
};

use super::model::{valid_category, Entry};
use super::store::{record_id_of, sha256_hex};

pub(super) const VERSIONED: &str = "hcp.entry.versioned.v1";
pub(super) const STATUS_SET: &str = "hcp.entry.status_set.v1";

/// One `hcp_state` event as read from the log.
#[derive(Clone, Debug)]
pub(super) struct StoredEvent {
    pub seq: i64,
    pub event_type: String,
    pub payload: String,
}

/// One entry as the fold has it.
#[derive(Clone, Debug)]
pub(super) struct FoldedEntry {
    /// Every accepted version, oldest first; `versions[n - 1]` is version `n`
    /// as it stood when it was last changed (a later status change applies to
    /// the version it names).
    pub versions: Vec<Entry>,
    /// The view digest every accepted event recorded, in order.
    pub view_digests: Vec<String>,
    /// The version each of those digests belongs to: the version a view body
    /// with that digest shows (or, for a person's edit, became).
    digest_versions: BTreeMap<String, u64>,
    /// Status events seen for each version, accepted or not, so the next one
    /// gets an unused identity.
    status_events: BTreeMap<u64, u64>,
}

impl FoldedEntry {
    pub(super) fn current(&self) -> &Entry {
        self.versions.last().expect("a folded entry has a version")
    }

    /// How many status events have named `version`.
    pub(super) fn status_events(&self, version: u64) -> u64 {
        self.status_events.get(&version).copied().unwrap_or(0)
    }

    /// The view body digest the current state should have.
    pub(super) fn current_digest(&self) -> String {
        sha256_hex(&self.current().view_body())
    }

    /// The version a view body with this digest is a projection of.
    pub(super) fn version_of_digest(&self, digest: &str) -> Option<u64> {
        self.digest_versions.get(digest).copied()
    }

    /// Whether `digest` is the digest of a view body some event of this entry
    /// recorded: a body that matches is stale, never an edit.
    pub(super) fn knows_digest(&self, digest: &str) -> bool {
        self.view_digests.iter().any(|known| known == digest)
    }
}

/// An event the chain rules ignored, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Rejected {
    pub seq: i64,
    pub why: &'static str,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Fold {
    pub entries: BTreeMap<String, FoldedEntry>,
    pub rejected: Vec<Rejected>,
    pub suggestions: BTreeMap<String, HcpEntrySuggestionPayload>,
    pub resolutions: BTreeMap<String, HcpEntryConfirmedPayload>,
}

/// Fold `events` (one person's `hcp_state` events, in log order) into their
/// entries. `account` and `subject_id` are the person's own account and stored
/// Context Subject identifier.
pub(super) fn fold(account: &str, subject_id: &str, events: &[StoredEvent]) -> Fold {
    let mut state = Fold::default();
    for event in events {
        let outcome = match event.event_type.as_str() {
            VERSIONED => match serde_json::from_str::<HcpEntryVersionedPayload>(&event.payload) {
                Ok(payload) => apply_versioned(&mut state, account, subject_id, payload),
                Err(_) => Err("a version event that cannot be read"),
            },
            STATUS_SET => match serde_json::from_str::<HcpEntryStatusSetPayload>(&event.payload) {
                Ok(payload) => apply_status(&mut state, account, payload),
                Err(_) => Err("a status event that cannot be read"),
            },
            "hcp.entry.suggestion.v1" => {
                serde_json::from_str::<HcpEntrySuggestionPayload>(&event.payload)
                    .map_err(|_| "an unreadable suggestion mapping")
                    .and_then(|p| apply_suggestion(&mut state, account, p))
            }
            "hcp.entry.confirmed.v1" => {
                serde_json::from_str::<HcpEntryConfirmedPayload>(&event.payload)
                    .map_err(|_| "an unreadable confirmation")
                    .and_then(|p| apply_confirmation(&mut state, account, subject_id, p))
            }
            _ => Err("an event type the fold does not know"),
        };
        if let Err(why) = outcome {
            state.rejected.push(Rejected {
                seq: event.seq,
                why,
            });
        }
    }
    state
}

fn apply_versioned(
    state: &mut Fold,
    account: &str,
    subject_id: &str,
    payload: HcpEntryVersionedPayload,
) -> Result<(), &'static str> {
    if payload.account_id != account {
        return Err("an event of another person");
    }
    let record_id = record_id_of(&payload.entry_id).ok_or("an entry id that is not a record id")?;
    let entry =
        Entry::parse(&payload.entry.to_string()).ok_or("an entry that is not well formed")?;
    if entry.id() != payload.entry_id
        || entry.version() != payload.version
        || record_id_of(entry.id()).as_deref() != Some(record_id.as_str())
    {
        return Err("an entry that does not match its event");
    }
    if entry.subject_id() != subject_id {
        return Err("an entry about someone else");
    }
    if !valid_category(entry.category()) {
        return Err("an entry in an unknown category");
    }
    match state.entries.get_mut(&payload.entry_id) {
        None => {
            if payload.version != 1 || payload.cause != "add" {
                return Err("an entry whose first event is not its first version");
            }
            if entry.0["record"]["previousVersion"] != serde_json::Value::Null {
                return Err("a first version that names a previous one");
            }
            state.entries.insert(
                payload.entry_id,
                FoldedEntry {
                    versions: vec![entry],
                    digest_versions: BTreeMap::from([(payload.view_digest.clone(), 1)]),
                    view_digests: vec![payload.view_digest],
                    status_events: BTreeMap::new(),
                },
            );
        }
        Some(folded) => {
            let current = folded.current().version();
            if payload.version != current + 1 {
                return Err("a version that is not the current one plus one");
            }
            if payload.cause == "add" {
                return Err("an add of an entry that exists");
            }
            if entry.0["record"]["previousVersion"].as_u64() != Some(current) {
                return Err("a version that does not follow the current one");
            }
            // A person's edit records the digest of the body they wrote; the
            // normalised version the fold holds is a body of the view too.
            let normalised = sha256_hex(&entry.0.to_string());
            folded
                .digest_versions
                .insert(payload.view_digest.clone(), payload.version);
            if normalised != payload.view_digest {
                folded
                    .digest_versions
                    .insert(normalised.clone(), payload.version);
                folded.view_digests.push(normalised);
            }
            folded.versions.push(entry);
            folded.view_digests.push(payload.view_digest);
        }
    }
    Ok(())
}

fn apply_status(
    state: &mut Fold,
    account: &str,
    payload: HcpEntryStatusSetPayload,
) -> Result<(), &'static str> {
    if payload.account_id != account {
        return Err("an event of another person");
    }
    let folded = state
        .entries
        .get_mut(&payload.entry_id)
        .ok_or("a status change of an entry nobody created")?;
    *folded.status_events.entry(payload.version).or_default() += 1;
    let current = folded.current();
    if payload.version != current.version() {
        return Err("a status change of a version that is not current");
    }
    if payload.from != current.status() {
        return Err("a status change from a status the entry does not have");
    }
    let last = folded.versions.len() - 1;
    folded.versions[last].set_status(&payload.to);
    if let Some(digest) = payload.view_digest {
        folded
            .digest_versions
            .insert(digest.clone(), payload.version);
        folded.view_digests.push(digest);
    }
    Ok(())
}

fn apply_suggestion(
    state: &mut Fold,
    account: &str,
    p: HcpEntrySuggestionPayload,
) -> Result<(), &'static str> {
    let entry = state
        .entries
        .get(&p.entry_id)
        .ok_or("suggestion without entry")?
        .current();
    if p.account_id != account
        || p.version != entry.version()
        || entry.status() != "conflicted"
        || entry.declaration_type() != "model-inferred"
        || p.body_digest != sha256_hex(&entry.view_body())
        || state.suggestions.contains_key(&p.suggestion_id)
    {
        return Err("suggestion mapping does not match the current inference");
    }
    state.suggestions.insert(p.suggestion_id.clone(), p);
    Ok(())
}

fn apply_confirmation(
    state: &mut Fold,
    account: &str,
    subject: &str,
    p: HcpEntryConfirmedPayload,
) -> Result<(), &'static str> {
    let mapping = state
        .suggestions
        .get(&p.suggestion_id)
        .ok_or("confirmation without suggestion mapping")?;
    let folded = state
        .entries
        .get_mut(&p.entry_id)
        .ok_or("confirmation without entry")?;
    if p.account_id != account
        || mapping.entry_id != p.entry_id
        || mapping.version != p.version
        || folded.current().version() != p.version
        || state.resolutions.contains_key(&p.suggestion_id)
        || state
            .resolutions
            .values()
            .any(|r| r.resolution_event_id == p.resolution_event_id)
        || !matches!(p.disposition.as_str(), "confirmed" | "rejected")
    {
        return Err("confirmation is stale, duplicate or mismatched");
    }
    let entry = folded.versions.last_mut().unwrap();
    entry.add_confirmation(&p.disposition, subject, &p.confirmed_at);
    let digest = sha256_hex(&entry.view_body());
    folded.digest_versions.insert(digest.clone(), p.version);
    folded.view_digests.push(digest);
    state.resolutions.insert(p.suggestion_id.clone(), p);
    Ok(())
}
