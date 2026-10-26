//! The HCP v2 entry as exchanged (HCP v2 §4.2, §11.2): the grouped-form JSON,
//! category and dimension rules, redaction for Context Clients (§7.4) and the
//! lexical relevance ordering (§7.3).
//!
//! An entry is held as a `serde_json::Value` so that what is stored is exactly
//! the canonical grouped form and nothing is lost in a round trip through a
//! struct that does not know a field (`record.metadata`, for one).

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

/// `@context` is a fixed constant (HCP v2 §4.1.1, §4.2). The namespace is the
/// draft's placeholder and will change with it.
const CONTEXT: [&str; 2] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://hcp.example/contexts/v1",
];

/// The registered category vocabulary (HCP v2 §4.5).
pub(super) const CATEGORIES: [&str; 9] = [
    "general_preferences",
    "goals_and_constraints",
    "health_context",
    "education_learner_profile",
    "work_context",
    "purchase_history_preferences",
    "values_and_ethics",
    "location_context",
    "coordination_context",
];

const CUSTOM_PREFIX: &str = "hcp-custom:";
const MAX_CATEGORY_CHARS: usize = 128;

pub(super) const STATUS_ACTIVE: &str = "active";
pub(super) const STATUS_DEPRECATED: &str = "deprecated";
pub(super) const STATUS_CONFLICTED: &str = "conflicted";
pub(super) const STATUS_DELETED: &str = "deleted";

pub(super) const USER_DECLARED: &str = "user-declared";
pub(super) const MODEL_INFERRED: &str = "model-inferred";
pub(super) const ISSUER_ATTESTED: &str = "issuer-attested";

/// Fields omitted from every entry returned to a Context Client (HCP v2 §7.4),
/// as literal paths into the grouped-form response body (§7.5).
pub(super) const REDACTED_FIELDS: [&str; 6] = [
    "record.provenance.source",
    "record.provenance.submittedByClient",
    "record.provenance.authorizedUnder",
    "record.provenance.assertedBy.id",
    "record.provenance.confirmations[].confirmedBy",
    "claim.issuer",
];

/// A category slug the protocol can carry: registered, or `hcp-custom:`
/// prefixed with something after the prefix (HCP v2 §4.5).
pub(super) fn valid_category(slug: &str) -> bool {
    if CATEGORIES.contains(&slug) {
        return true;
    }
    slug.strip_prefix(CUSTOM_PREFIX).is_some_and(|rest| {
        !rest.is_empty()
            && slug.chars().count() <= MAX_CATEGORY_CHARS
            && !slug.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

/// Whether the connected person's access reaches a category. Native has no
/// per-client grants yet: every client acts with the person's ordinary access,
/// so every category the protocol can carry is treated as granted. This is the
/// one place a real grant check would go.
pub(super) fn category_in_grant(slug: &str) -> bool {
    valid_category(slug)
}

/// Dimension spelling normalisation (HCP v2 §15.2): trim, lowercase, collapse
/// internal whitespace to a single underscore. Empty means "no dimension".
pub(super) fn normalize_dimension(raw: &str) -> String {
    raw.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
}

/// The ISO-8601 timestamp format HCP responses use.
pub(super) fn timestamp(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// A stored entry: the grouped-form JSON, with typed access to the fields the
/// provider acts on. Parsing is strict about the fields the provider relies on
/// and ignores the rest, because the body is also editable in Native.
#[derive(Clone, Debug)]
pub(super) struct Entry(pub Value);

impl Entry {
    pub(super) fn parse(body: &str) -> Option<Entry> {
        let value: Value = serde_json::from_str(body).ok()?;
        let entry = Entry(value);
        entry.is_well_formed().then_some(entry)
    }

    fn is_well_formed(&self) -> bool {
        let v = &self.0;
        v["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|t| t == "HCPEntry"))
            && v["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("urn:uuid:"))
            && v["claim"]["subject"]["preference"].is_string()
            && v["record"]["category"].is_string()
            && matches!(
                v["record"]["status"].as_str(),
                Some(STATUS_ACTIVE | STATUS_DEPRECATED | STATUS_CONFLICTED | STATUS_DELETED)
            )
            && v["record"]["version"].as_u64().is_some_and(|n| n >= 1)
            && v["record"]["provenance"].is_object()
    }

    pub(super) fn id(&self) -> &str {
        self.0["id"].as_str().unwrap_or_default()
    }

    /// The Context Subject identifier the entry was created with.
    pub(super) fn subject_id(&self) -> &str {
        self.0["claim"]["subject"]["id"]
            .as_str()
            .unwrap_or_default()
    }

    pub(super) fn category(&self) -> &str {
        self.0["record"]["category"].as_str().unwrap_or_default()
    }

    pub(super) fn dimension(&self) -> Option<&str> {
        self.0["record"]["dimension"].as_str()
    }

    pub(super) fn status(&self) -> &str {
        self.0["record"]["status"].as_str().unwrap_or_default()
    }

    pub(super) fn version(&self) -> u64 {
        self.0["record"]["version"].as_u64().unwrap_or(0)
    }

    pub(super) fn declaration_type(&self) -> &str {
        self.0["record"]["declarationType"]
            .as_str()
            .unwrap_or_default()
    }

    pub(super) fn assurance(&self) -> &str {
        self.0["record"]["provenance"]["assertedBy"]["assurance"]
            .as_str()
            .unwrap_or_default()
    }

    /// Preserve confirmation history in the trusted fold and sealed events.
    /// The editable ordinary view independently carries a bounded summary.
    pub(super) fn add_confirmation(&mut self, disposition: &str, subject: &str, at: &str) {
        let all = self.0["record"]["provenance"]["confirmations"]
            .as_array_mut()
            .unwrap();
        all.push(json!({"disposition":disposition,"confirmedBy":{"id":subject},"confirmedAt":at}));
    }

    pub(super) fn view_body(&self) -> String {
        let mut view = self.0.clone();
        if let Some(all) = view["record"]["provenance"]["confirmations"].as_array_mut() {
            if all.len() > 8 {
                all.drain(..all.len() - 8);
            }
        }
        loop {
            let body = view.to_string();
            if crate::control::hcp_entry_fits(&body) {
                return body;
            }
            let Some(all) = view["record"]["provenance"]["confirmations"].as_array_mut() else {
                return body;
            };
            if all.is_empty() {
                // Absence and an empty array both mean no displayed summary
                // (§3.8). Omitting it also leaves room for a longer lifecycle
                // name on a version originally written at the size ceiling.
                view["record"]["provenance"]
                    .as_object_mut()
                    .unwrap()
                    .remove("confirmations");
                return view.to_string();
            }
            all.remove(0);
        }
    }

    /// C3 supplies version-bound confirmations through sealed events. This
    /// accessor is only applied to the trusted fold, never to editable views.
    pub(super) fn confirmed(&self) -> bool {
        self.0["record"]["provenance"]["confirmations"]
            .as_array()
            .and_then(|all| all.last())
            .is_some_and(|last| last["disposition"] == "confirmed")
    }

    pub(super) fn recorded_at(&self) -> &str {
        self.0["record"]["provenance"]["recordedAt"]
            .as_str()
            .unwrap_or_default()
    }

    pub(super) fn preference(&self) -> &Value {
        &self.0["claim"]["subject"]["preference"]
    }

    pub(super) fn set_status(&mut self, status: &str) {
        self.0["record"]["status"] = json!(status);
    }

    /// `claim.expirationDate` has passed. An expiry that cannot be read is
    /// treated as passed: an entry is withheld rather than shown past a date
    /// the provider cannot interpret.
    pub(super) fn expired(&self, now: DateTime<Utc>) -> bool {
        match self.0["claim"]["expirationDate"].as_str() {
            None => false,
            Some(raw) => DateTime::parse_from_rfc3339(raw)
                .map(|at| at.with_timezone(&Utc) <= now)
                .unwrap_or(true),
        }
    }

    /// The Context Subject's most recent confirmation record on this version
    /// rejected it (HCP v2 §3.8).
    pub(super) fn rejected(&self) -> bool {
        self.0["record"]["provenance"]["confirmations"]
            .as_array()
            .and_then(|all| all.last())
            .is_some_and(|last| last["disposition"] == "rejected")
    }

    /// Returned to a Context Client in search and get: not deleted, not
    /// conflicted (HCP v2 §4.7.2, §5.2.5) and not expired (§11.2).
    pub(super) fn visible_to_context_client(&self, now: DateTime<Utc>) -> bool {
        !matches!(self.status(), STATUS_DELETED | STATUS_CONFLICTED) && !self.expired(now)
    }

    /// May a Context Client update this entry? Hidden entries are not
    /// reachable (a deleted or expired entry reads as absent), a conflicted
    /// entry can be revised (HCP v2 §4.7.3), and a rejected current version
    /// cannot (§3.8).
    pub(super) fn updatable_by_context_client(&self, now: DateTime<Utc>) -> bool {
        self.status() != STATUS_DELETED && !self.expired(now) && !self.rejected()
    }

    /// The entry as a Context Client receives it (HCP v2 §7.4): provenance
    /// that identifies other systems or parties is omitted, and the subject is
    /// presented as the pseudonym specific to this client (§3.4).
    pub(super) fn for_context_client(&self, subject_pseudonym: &str) -> Value {
        let mut value = self.0.clone();
        if let Some(subject) = value["claim"]["subject"].as_object_mut() {
            subject.insert("id".into(), json!(subject_pseudonym));
        }
        if let Some(claim) = value["claim"].as_object_mut() {
            claim.remove("issuer");
        }
        if let Some(provenance) = value["record"]["provenance"].as_object_mut() {
            provenance.remove("source");
            provenance.remove("submittedByClient");
            provenance.remove("authorizedUnder");
            if let Some(asserted_by) = provenance
                .get_mut("assertedBy")
                .and_then(Value::as_object_mut)
            {
                asserted_by.remove("id");
            }
            if let Some(confirmations) = provenance
                .get_mut("confirmations")
                .and_then(Value::as_array_mut)
            {
                for confirmation in confirmations {
                    if let Some(map) = confirmation.as_object_mut() {
                        map.remove("confirmedBy");
                    }
                }
            }
        }
        value
    }

    /// The `responseDetail: minimal` form of a Tier 1 entry (HCP v2 §5.3).
    pub(super) fn minimal(&self) -> Value {
        json!({
            "id": self.id(),
            "record": {
                "category": self.category(),
                "dimension": self.dimension(),
            },
            "value": self.preference(),
        })
    }

    /// The text the lexical ordering reads: the preference content.
    fn preference_text(&self) -> String {
        match self.preference() {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        }
    }
}

/// The inputs to a new version of an entry (add, or update).
pub(super) struct Assertion<'a> {
    pub preference: &'a Value,
    pub declaration_type: &'a str,
    pub confidence: Option<&'a str>,
    /// The Context Asserter's identifier: the model for `model-inferred`, the
    /// Context Subject's stored identifier otherwise.
    pub asserted_by: &'a str,
    pub source: &'a str,
    pub client: &'a super::client::ClientIdentity,
    pub recorded_at: &'a str,
    /// When the assertion was made, if known; otherwise `recorded_at`.
    pub asserted_at: Option<&'a str>,
}

fn provenance(assertion: &Assertion<'_>) -> Value {
    json!({
        // Over MCP the only basis for a Context Asserter is the submitting
        // client's word (HCP v2 §3.6, §3.7): never `authenticated`.
        "assertedBy": { "id": assertion.asserted_by, "assurance": "unverified" },
        "assertedAt": assertion.asserted_at.unwrap_or(assertion.recorded_at),
        "source": assertion.source,
        "submittedByClient": assertion.client.as_submitted_by(),
        "authorizedUnder": assertion.client.implicit_grant(),
        "recordedByProvider": super::client::PROVIDER_ID,
        "recordedAt": assertion.recorded_at,
        "confirmations": [],
    })
}

/// Version 1 of a new Tier 1 entry (HCP v2 §4.2, §11.2).
pub(super) fn new_entry(
    entry_urn: &str,
    category: &str,
    dimension: Option<&str>,
    subject_id: &str,
    assertion: &Assertion<'_>,
) -> Entry {
    Entry(json!({
        "@context": CONTEXT,
        "id": entry_urn,
        "type": ["HCPEntry"],
        "credentialType": "NLPreference",
        "claim": {
            "issuer": { "id": assertion.asserted_by, "type": "HCPSource" },
            "issuanceDate": assertion.recorded_at,
            "expirationDate": null,
            "subject": {
                "id": subject_id,
                "relationship": null,
                "preference": assertion.preference,
            },
        },
        "record": {
            "category": category,
            "dimension": dimension,
            "declarationType": assertion.declaration_type,
            "confidence": assertion.confidence,
            "status": STATUS_ACTIVE,
            "version": 1,
            "previousVersion": null,
            "provenance": provenance(assertion),
        },
    }))
}

/// The next version of `previous` (HCP v2 §5.2.4): a revised claim with its
/// own provenance, no confirmations, and `record.version` up by exactly one.
/// Category, dimension, status, `record.metadata`, the subject and the claim's
/// expiry carry over.
pub(super) fn next_version(previous: &Entry, assertion: &Assertion<'_>) -> Entry {
    let mut value = previous.0.clone();
    let version = previous.version() + 1;
    value["claim"]["issuer"] = json!({ "id": assertion.asserted_by, "type": "HCPSource" });
    value["claim"]["issuanceDate"] = json!(assertion.recorded_at);
    value["claim"]["subject"]["preference"] = json!(assertion.preference);
    let record = value["record"]
        .as_object_mut()
        .expect("a parsed entry has a record object");
    record.insert("declarationType".into(), json!(assertion.declaration_type));
    record.insert("confidence".into(), json!(assertion.confidence));
    record.insert("version".into(), json!(version));
    record.insert("previousVersion".into(), json!(previous.version()));
    record.insert("provenance".into(), provenance(assertion));
    Entry(value)
}

// ---- lexical relevance (HCP v2 §7.3) ---------------------------------------

const STOP_WORDS: [&str; 24] = [
    "a", "an", "and", "are", "as", "at", "be", "for", "i", "in", "is", "it", "me", "my", "of",
    "on", "or", "the", "to", "what", "with", "do", "does", "how",
];

/// Lowercased alphanumeric terms, stop words dropped, a trailing plural `s`
/// stripped so "shoes" meets "shoe".
pub(super) fn terms(text: &str) -> Vec<String> {
    let mut seen = Vec::new();
    for raw in text.split(|c: char| !c.is_alphanumeric()) {
        let lower = raw.to_lowercase();
        if lower.chars().count() < 2 || STOP_WORDS.contains(&lower.as_str()) {
            continue;
        }
        let stem = match lower.strip_suffix('s') {
            Some(rest) if lower.chars().count() > 3 && !lower.ends_with("ss") => rest.to_string(),
            _ => lower,
        };
        if !seen.contains(&stem) {
            seen.push(stem);
        }
    }
    seen
}

/// Overlap between the query terms and an entry: a term in the preference
/// counts 2, a term in the dimension counts 1. Zero means the entry does not
/// meet the relevance criterion and is not returned (HCP v2 §7.2: fewer, never
/// padded).
pub(super) fn lexical_score(query_terms: &[String], entry: &Entry) -> u32 {
    let preference = terms(&entry.preference_text());
    let dimension = terms(&entry.dimension().unwrap_or_default().replace('_', " "));
    query_terms
        .iter()
        .map(|term| {
            let in_preference = if preference.contains(term) { 2 } else { 0 };
            let in_dimension = if dimension.contains(term) { 1 } else { 0 };
            in_preference + in_dimension
        })
        .sum()
}
