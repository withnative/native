//! The untrusted invocation an interactive artifact sends to the host, and the
//! authoritative response the host sends back.
//!
//! An invocation names a DECLARED manifest entry (`entry_id`) against the
//! source digest the artifact was rendered from, fills that entry's declared
//! slots, and optionally carries the facet versions it observed. It cannot
//! describe a write directly: the effect, the facet key and the admissible
//! values all come from the compiled manifest entry the host looks up, never
//! from this envelope.
//!
//! What an artifact may say: which entry, which gesture, which slot fillings
//! and values, what it observed. What it may NOT say: who the actor is,
//! whether it is authorized, whether a confirmation happened, or what
//! permission it holds. Those are host facts, and `deny_unknown_fields` keeps
//! an artifact from smuggling them across the bridge.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const INVOCATION_VERSION: &str = "native.artifact-invocation.v1";
pub const INTENT_RESULT_VERSION: &str = "native.artifact-intent-result.v2";

const RESULT_CHANGE_LIMIT: usize = 100;
const RESULT_REFRESH_JSON_LIMIT: usize = 1_048_576;
const MAX_SLOTS: usize = 32;
const MAX_INVOCATION_VALUE_BYTES: usize = 262_144;
const MAX_INVOCATION_VALUE_DEPTH: usize = 8;
const MAX_INVOCATION_VALUE_NODES: usize = 1_024;
const MAX_OBSERVED_RECORDS: usize = 64;
const MAX_OBSERVED_KEYS: usize = 32;

/// One artifact-authored request to run one declared interaction entry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInvocation {
    pub version: String,
    pub artifact_id: String,
    /// Identifies an entry in the manifest compiled from `source_digest`.
    pub entry_id: String,
    /// The body digest the artifact was rendered from. A stale artifact
    /// invoking against an edited manifest is refused on this field alone.
    pub source_digest: String,
    /// Record-domain slot fillings: slot name -> record id.
    #[serde(default)]
    pub slots: BTreeMap<String, String>,
    /// Value-domain slot fillings: slot name -> value.
    #[serde(default)]
    pub values: BTreeMap<String, Value>,
    /// Facet versions the artifact read, as compare-and-set preconditions:
    /// record id -> facet key -> opaque version token.
    #[serde(default)]
    pub observed: BTreeMap<String, BTreeMap<String, String>>,
    pub idempotency_key: String,
    #[serde(default)]
    pub gesture: Option<String>,
}

/// An authoritative host response. Each status carries only the fields
/// meaningful for that result, so invalid combinations cannot cross the bridge.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactIntentResult {
    Committed {
        version: String,
        idempotency_key: String,
        changes: Vec<IntentChange>,
        #[serde(default)]
        refresh: Option<Value>,
    },
    Rejected {
        version: String,
        idempotency_key: String,
        error: IntentError,
    },
    Conflict {
        version: String,
        idempotency_key: String,
        error: IntentError,
        /// The version token the host actually found, in the same encoding the
        /// read path hands out.
        current_version: String,
        /// The exact event whose projected state failed the compare-and-set.
        /// Unlike a later history lookup, this cannot drift to a newer actor.
        conflicting_event_id: String,
        /// Present only when the ordinary actor-disclosure policy permits the
        /// caller to learn this event's actor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        competing_actor: Option<CompetingActor>,
        #[serde(default)]
        refresh: Option<Value>,
    },
    /// Reserved for future irreversible effects. Facet writes are ungated and
    /// optimistic, so the current contract never produces this variant; a failed slot or domain
    /// check is a rejection, never a prompt.
    NeedsConfirmation {
        version: String,
        idempotency_key: String,
        confirmation_id: String,
        changes: Vec<IntentChange>,
    },
    Invalid {
        version: String,
        idempotency_key: String,
        error: IntentError,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompetingActor {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IntentChange {
    pub record_id: String,
    pub key: String,
    #[serde(default)]
    pub before: Option<Value>,
    #[serde(default)]
    pub after: Option<Value>,
    /// The version token this write LEFT on the facet, in the same encoding the
    /// read path hands out, computed inside the write transaction that produced
    /// it.
    ///
    /// It exists so a caller can run a follow-up compare-and-set — an undo, a
    /// correction — against the state its own gesture produced, without
    /// re-reading. A re-read would observe a competing edit and then authorize
    /// overwriting it, which is exactly what the precondition exists to stop.
    ///
    /// Optional and additive: a result serialized without it still deserializes,
    /// so this stays inside `native.artifact-intent-result.v2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntentError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
}

impl IntentError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn retryable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: true,
        }
    }
}

/// A facet's compare-and-set token, in the ONE encoding the read path emits and
/// the write path parses.
///
/// * `Observation` — open facets, versioned by `MAX(event_seq)` over that
///   record's observations of that key.
/// * `Record` — spine facets, which never produce an observation row because
///   they project to `records` columns. Their durable record-wide token is the
///   maximum immutable content-event sequence for that record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FacetVersion {
    Observation { event_seq: i64 },
    Record { event_seq: i64 },
}

impl FacetVersion {
    pub fn encode(&self) -> String {
        match self {
            Self::Observation { event_seq } => format!("obs:{event_seq}"),
            Self::Record { event_seq } => format!("rec:{event_seq}"),
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        if let Some(seq) = token.strip_prefix("obs:") {
            return seq
                .parse()
                .ok()
                .map(|event_seq| Self::Observation { event_seq });
        }
        token
            .strip_prefix("rec:")?
            .parse()
            .ok()
            .map(|event_seq| Self::Record { event_seq })
    }
}

impl ArtifactInvocation {
    /// Validate shape and bounds, independent of authorization, manifest and
    /// database state. Passing this says nothing about whether the invocation
    /// will be admitted — only that it is a well-formed envelope.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.version != INVOCATION_VERSION {
            return Err("unsupported invocation version");
        }
        for value in [&self.artifact_id, &self.entry_id, &self.idempotency_key] {
            validate_identity(value, "invocation identity is blank or too long")?;
        }
        if self.source_digest.len() != 64
            || !self
                .source_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("source_digest must be a lowercase hexadecimal SHA-256 digest");
        }
        if self.slots.len() + self.values.len() > MAX_SLOTS {
            return Err("invocation fills too many slots");
        }
        for (name, record_id) in &self.slots {
            validate_identity(name, "invocation slot name is blank or too long")?;
            validate_identity(record_id, "invocation slot record is blank or too long")?;
        }
        for (name, value) in &self.values {
            validate_identity(name, "invocation slot name is blank or too long")?;
            if value.is_null() || !bounded_invocation_value(value) {
                return Err("invocation value is null, too large, or too deeply nested");
            }
        }
        if self.slots.keys().any(|name| self.values.contains_key(name)) {
            return Err("invocation fills one slot twice");
        }
        if self.observed.len() > MAX_OBSERVED_RECORDS {
            return Err("invocation observes too many records");
        }
        for (record_id, keys) in &self.observed {
            validate_identity(record_id, "observed record is blank or too long")?;
            if keys.len() > MAX_OBSERVED_KEYS {
                return Err("invocation observes too many facets on one record");
            }
            for (key, token) in keys {
                validate_identity(key, "observed facet key is blank or too long")?;
                if FacetVersion::parse(token).is_none() {
                    return Err("observed facet version is not a host-issued token");
                }
            }
        }
        if self
            .gesture
            .as_ref()
            .is_some_and(|gesture| validate_identity(gesture, "x").is_err())
        {
            return Err("invocation gesture is blank or too long");
        }
        Ok(())
    }
}

fn bounded_invocation_value(value: &Value) -> bool {
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_INVOCATION_VALUE_BYTES) {
        return false;
    }
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes += 1;
        if depth > MAX_INVOCATION_VALUE_DEPTH || *nodes > MAX_INVOCATION_VALUE_NODES {
            return false;
        }
        match value {
            Value::Array(values) => values.iter().all(|value| visit(value, depth + 1, nodes)),
            Value::Object(values) => values.values().all(|value| visit(value, depth + 1, nodes)),
            _ => true,
        }
    }
    let mut nodes = 0;
    visit(value, 0, &mut nodes)
}

impl ArtifactIntentResult {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        let (version, idempotency_key) = match self {
            Self::Committed {
                version,
                idempotency_key,
                changes,
                refresh,
            } => {
                validate_changes(changes)?;
                validate_refresh(refresh)?;
                (version, idempotency_key)
            }
            Self::Conflict {
                version,
                idempotency_key,
                error,
                current_version,
                conflicting_event_id,
                competing_actor,
                refresh,
            } => {
                validate_error(error)?;
                if FacetVersion::parse(current_version).is_none() {
                    return Err("conflict version is not a host-issued token");
                }
                validate_identity(
                    conflicting_event_id,
                    "conflicting event identity is blank or too long",
                )?;
                if let Some(actor) = competing_actor {
                    validate_identity(&actor.id, "competing actor identity is blank or too long")?;
                    if let Some(name) = actor.display_name.as_deref() {
                        validate_identity(name, "competing actor name is blank or too long")?;
                    }
                }
                validate_refresh(refresh)?;
                (version, idempotency_key)
            }
            Self::NeedsConfirmation {
                version,
                idempotency_key,
                confirmation_id,
                changes,
            } => {
                validate_identity(
                    confirmation_id,
                    "confirmation identity is blank or too long",
                )?;
                validate_changes(changes)?;
                (version, idempotency_key)
            }
            Self::Rejected {
                version,
                idempotency_key,
                error,
            }
            | Self::Invalid {
                version,
                idempotency_key,
                error,
            } => {
                validate_error(error)?;
                (version, idempotency_key)
            }
        };
        if version != INTENT_RESULT_VERSION {
            return Err("unsupported intent result version");
        }
        validate_identity(
            idempotency_key,
            "intent result identity is blank or too long",
        )
    }

    pub fn rejected(idempotency_key: &str, error: IntentError) -> Self {
        Self::Rejected {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: idempotency_key.into(),
            error,
        }
    }

    pub fn invalid(idempotency_key: &str, error: IntentError) -> Self {
        Self::Invalid {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: idempotency_key.into(),
            error,
        }
    }

    pub fn conflict(
        idempotency_key: &str,
        error: IntentError,
        current: &FacetVersion,
        conflicting_event_id: &str,
        competing_actor: Option<CompetingActor>,
    ) -> Self {
        Self::Conflict {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: idempotency_key.into(),
            error,
            current_version: current.encode(),
            conflicting_event_id: conflicting_event_id.into(),
            competing_actor,
            refresh: None,
        }
    }

    pub fn committed(idempotency_key: &str, changes: Vec<IntentChange>) -> Self {
        Self::Committed {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: idempotency_key.into(),
            changes,
            refresh: None,
        }
    }
}

fn validate_identity(value: &str, error: &'static str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(error);
    }
    Ok(())
}

fn validate_error(error: &IntentError) -> Result<(), &'static str> {
    validate_identity(&error.code, "result error code is blank or too long")?;
    if error.message.is_empty()
        || error.message.len() > 2_000
        || error.message.chars().any(char::is_control)
    {
        return Err("result error message is blank or too long");
    }
    Ok(())
}

fn validate_changes(changes: &[IntentChange]) -> Result<(), &'static str> {
    if changes.is_empty() || changes.len() > RESULT_CHANGE_LIMIT {
        return Err("result change count is out of bounds");
    }
    for change in changes {
        validate_identity(&change.record_id, "facet target is blank or too long")?;
        validate_identity(&change.key, "facet target is blank or too long")?;
        if [&change.before, &change.after]
            .into_iter()
            .flatten()
            .any(Value::is_array)
        {
            return Err("result facet value must be a scalar, object, or null");
        }
        if change
            .version
            .as_deref()
            .is_some_and(|token| FacetVersion::parse(token).is_none())
        {
            return Err("result facet version is not a host-issued token");
        }
    }
    Ok(())
}

fn validate_refresh(refresh: &Option<Value>) -> Result<(), &'static str> {
    if refresh.as_ref().is_some_and(|value| {
        serde_json::to_vec(value)
            .map(|bytes| bytes.len() > RESULT_REFRESH_JSON_LIMIT)
            .unwrap_or(true)
    }) {
        return Err("result refresh is too large");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> ArtifactInvocation {
        ArtifactInvocation {
            version: INVOCATION_VERSION.into(),
            artifact_id: "a".into(),
            entry_id: "mark_triaged".into(),
            source_digest: "a".repeat(64),
            slots: BTreeMap::from([("record".to_owned(), "r".to_owned())]),
            values: BTreeMap::new(),
            observed: BTreeMap::from([(
                "r".to_owned(),
                BTreeMap::from([("triage".to_owned(), "obs:12".to_owned())]),
            )]),
            idempotency_key: "k".into(),
            gesture: Some("click".into()),
        }
    }

    #[test]
    fn accepts_a_well_formed_invocation_and_bounds_its_fields() {
        assert!(invocation().validate_shape().is_ok());
        let mut stale = invocation();
        stale.source_digest = "not-a-digest".into();
        assert_eq!(
            stale.validate_shape(),
            Err("source_digest must be a lowercase hexadecimal SHA-256 digest")
        );
        let mut null_value = invocation();
        null_value.values.insert("choice".into(), Value::Null);
        assert_eq!(
            null_value.validate_shape(),
            Err("invocation value is null, too large, or too deeply nested")
        );
        let mut forged_token = invocation();
        forged_token.observed.insert(
            "r".into(),
            BTreeMap::from([("triage".to_owned(), "12".to_owned())]),
        );
        assert_eq!(
            forged_token.validate_shape(),
            Err("observed facet version is not a host-issued token")
        );
    }

    #[test]
    fn invocation_values_admit_bounded_lists_and_reject_unbounded_shapes() {
        let mut listed = invocation();
        listed
            .values
            .insert("scores".into(), serde_json::json!([1, 2, 3]));
        assert!(listed.validate_shape().is_ok());

        let mut oversized = invocation();
        oversized.values.insert(
            "scores".into(),
            Value::Array(
                (0..MAX_INVOCATION_VALUE_NODES)
                    .map(|_| Value::Bool(true))
                    .collect(),
            ),
        );
        assert_eq!(
            oversized.validate_shape(),
            Err("invocation value is null, too large, or too deeply nested")
        );

        let mut deeply_nested = Value::Bool(true);
        for _ in 0..=MAX_INVOCATION_VALUE_DEPTH {
            deeply_nested = Value::Array(vec![deeply_nested]);
        }
        let mut deep = invocation();
        deep.values.insert("scores".into(), deeply_nested);
        assert_eq!(
            deep.validate_shape(),
            Err("invocation value is null, too large, or too deeply nested")
        );

        // Existing scalar/object facet values remain admitted.
        let mut facet = invocation();
        facet
            .values
            .insert("choice".into(), serde_json::json!({ "value": "triaged" }));
        assert!(facet.validate_shape().is_ok());
    }

    #[test]
    fn an_artifact_cannot_assert_actor_authorization_or_confirmation() {
        for forged in [
            "actor",
            "authorized",
            "permission",
            "confirmed",
            "confirmation_id",
            "session_id",
        ] {
            let mut encoded = serde_json::to_value(invocation()).unwrap();
            encoded[forged] = Value::String("artifact-chosen".into());
            assert!(
                serde_json::from_value::<ArtifactInvocation>(encoded).is_err(),
                "invocation accepted a forged '{forged}' field"
            );
        }
        assert!(serde_json::from_value::<ArtifactIntentResult>(serde_json::json!({
            "status": "rejected", "version": INTENT_RESULT_VERSION, "idempotency_key": "k",
            "error": { "code": "denied", "message": "no", "retryable": false }, "actor": "forged"
        }))
        .is_err());
    }

    #[test]
    fn invocation_round_trips_and_describes_no_effect_of_its_own() {
        let encoded = serde_json::to_value(invocation()).unwrap();
        // The envelope names an entry; it never carries a facet key, a value,
        // or an effect. Those come from the compiled manifest entry.
        for absent in ["effect", "facet", "key", "record_id"] {
            assert!(encoded.get(absent).is_none(), "envelope leaked '{absent}'");
        }
        assert_eq!(encoded["entry_id"], "mark_triaged");
        assert_eq!(
            serde_json::from_value::<ArtifactInvocation>(encoded).unwrap(),
            invocation()
        );
    }

    #[test]
    fn version_tokens_round_trip_at_both_widths() {
        for version in [
            FacetVersion::Observation { event_seq: 41 },
            FacetVersion::Record { event_seq: 83 },
        ] {
            assert_eq!(FacetVersion::parse(&version.encode()), Some(version));
        }
        // The two widths are distinguishable, so an open-facet token can never
        // silently satisfy a spine precondition or the reverse.
        assert_eq!(FacetVersion::parse("obs:not-a-number"), None);
        assert_eq!(FacetVersion::parse("41"), None);
        assert_ne!(
            FacetVersion::Observation { event_seq: 41 }.encode(),
            FacetVersion::Record { event_seq: 41 }.encode()
        );
    }

    #[test]
    fn results_round_trip_and_retain_the_unused_confirmation_variant() {
        let committed = ArtifactIntentResult::committed(
            "k",
            vec![IntentChange {
                record_id: "r".into(),
                key: "triage".into(),
                before: Some(Value::String("untriaged".into())),
                after: Some(Value::String("triaged".into())),
                version: Some("obs:12".into()),
            }],
        );
        assert!(committed.validate_shape().is_ok());
        let encoded = serde_json::to_value(&committed).unwrap();
        assert_eq!(encoded["status"], "committed");
        assert_eq!(
            serde_json::from_value::<ArtifactIntentResult>(encoded).unwrap(),
            committed
        );
        let conflict = ArtifactIntentResult::conflict(
            "k",
            IntentError::retryable("facet_conflict", "the facet moved"),
            &FacetVersion::Observation { event_seq: 9 },
            "event-9",
            Some(CompetingActor {
                id: "account-1".into(),
                display_name: Some("Ada".into()),
            }),
        );
        assert!(conflict.validate_shape().is_ok());
        assert_eq!(
            serde_json::to_value(&conflict).unwrap()["current_version"],
            "obs:9"
        );
        let encoded = serde_json::to_value(&conflict).unwrap();
        assert_eq!(encoded["conflicting_event_id"], "event-9");
        assert_eq!(encoded["competing_actor"]["id"], "account-1");
        assert_eq!(encoded["competing_actor"]["display_name"], "Ada");
        let pending = ArtifactIntentResult::NeedsConfirmation {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: "k".into(),
            confirmation_id: "c".into(),
            changes: vec![IntentChange {
                record_id: "r".into(),
                key: "triage".into(),
                before: None,
                after: Some(Value::String("triaged".into())),
                version: Some("rec:4".into()),
            }],
        };
        assert!(pending.validate_shape().is_ok());
    }

    /// The resulting version token rides on the change, so a caller can run its
    /// next compare-and-set against the state its own write produced. It is
    /// additive: a v2 result written before this field existed still parses.
    #[test]
    fn a_change_carries_the_resulting_version_and_stays_backward_compatible() {
        let committed = ArtifactIntentResult::committed(
            "k",
            vec![IntentChange {
                record_id: "r".into(),
                key: "triage".into(),
                before: None,
                after: Some(Value::String("triaged".into())),
                version: Some("obs:41".into()),
            }],
        );
        assert!(committed.validate_shape().is_ok());
        let encoded = serde_json::to_value(&committed).unwrap();
        // Same envelope version: this is an added field, not a new contract.
        assert_eq!(encoded["version"], INTENT_RESULT_VERSION);
        assert_eq!(encoded["changes"][0]["version"], "obs:41");
        assert_eq!(
            serde_json::from_value::<ArtifactIntentResult>(encoded).unwrap(),
            committed
        );

        // Omitted on the wire when absent, and absent when omitted.
        let without = ArtifactIntentResult::committed(
            "k",
            vec![IntentChange {
                record_id: "r".into(),
                key: "triage".into(),
                before: None,
                after: Some(Value::String("triaged".into())),
                version: None,
            }],
        );
        let encoded = serde_json::to_value(&without).unwrap();
        assert!(
            encoded["changes"][0].get("version").is_none(),
            "an absent token must not be serialized: {encoded}"
        );
        assert_eq!(
            serde_json::from_value::<ArtifactIntentResult>(encoded).unwrap(),
            without
        );
        // An older peer's payload, which never had the field, still parses.
        let legacy = serde_json::json!({
            "status": "committed", "version": INTENT_RESULT_VERSION, "idempotency_key": "k",
            "changes": [{ "record_id": "r", "key": "triage", "after": "triaged" }],
        });
        assert_eq!(
            serde_json::from_value::<ArtifactIntentResult>(legacy).unwrap(),
            without
        );

        // A token an artifact could not have been issued is refused here for
        // the same reason the conflict token is.
        let forged = ArtifactIntentResult::committed(
            "k",
            vec![IntentChange {
                record_id: "r".into(),
                key: "triage".into(),
                before: None,
                after: Some(Value::String("triaged".into())),
                version: Some("41".into()),
            }],
        );
        assert_eq!(
            forged.validate_shape(),
            Err("result facet version is not a host-issued token")
        );
    }
}
