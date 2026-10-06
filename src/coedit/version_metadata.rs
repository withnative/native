//! Reserved version-metadata schema for `record.updated` payloads (m7).
//!
//! A first session version is an ordinary `record.updated` event that carries
//! three reserved top-level keys beside the ordinary fields:
//!
//! - `contributors`: an array of `{principal, executor_kind, run_key?}` rows;
//! - `session`: an opaque non-empty session reference;
//! - `merged_offline`: present (as `true`) only when offline ops are included.
//!
//! [`record_updated_payload`] assembles those keys for a version write and
//! [`validate_version_metadata`] is the shared parser-schema check run by the
//! `record.updated` arm of [`crate::domain_transaction::ProjectorIntent`] at
//! admission, before any durable mutation. The ordinary write path calls the
//! assembler with `None`, which returns the base map byte-identically.
//!
//! Scope limits, deliberate: this unit defines the payload shape and its
//! admission check only. It is NOT a session caller, a version trigger, a
//! ledger drain, a body-validator port, or mirror parity. `run_key` is
//! accepted structurally for a future validated source but is never
//! assembled here, and the schema does not authenticate it.

use serde_json::{Map, Value};

use super::registry::AcknowledgedContributor;
use crate::{Error, Result};

pub(crate) const CONTRIBUTORS_KEY: &str = "contributors";
pub(crate) const SESSION_KEY: &str = "session";
pub(crate) const MERGED_OFFLINE_KEY: &str = "merged_offline";

const PRINCIPAL_KEY: &str = "principal";
const EXECUTOR_KIND_KEY: &str = "executor_kind";
const RUN_KEY: &str = "run_key";

/// Version metadata supplied by a trusted version caller.
pub(crate) struct VersionMetadata<'a> {
    /// Distinct acknowledged contributors, in any order; assembled canonically.
    pub(crate) contributors: &'a [AcknowledgedContributor],
    /// Opaque session reference; must be non-empty.
    pub(crate) session_ref: &'a str,
    /// Whether this version includes ops made offline (present `true` only).
    pub(crate) merged_offline: bool,
}

/// Assemble a `record.updated` payload, appending reserved m7 metadata when
/// present.
///
/// `None` returns `base` unchanged: byte-identical, key order preserved, so
/// the ordinary write path is unaffected. `Some` refuses to overwrite a base
/// that already holds a reserved key, appends canonically deduped/sorted
/// `contributors` and the opaque `session`, and appends `merged_offline` only
/// when it is `true`. Never emits `run_key`.
pub(crate) fn record_updated_payload(
    mut base: Map<String, Value>,
    metadata: Option<&VersionMetadata<'_>>,
) -> Result<Map<String, Value>> {
    let Some(metadata) = metadata else {
        return Ok(base);
    };
    for key in [CONTRIBUTORS_KEY, SESSION_KEY, MERGED_OFFLINE_KEY] {
        if base.contains_key(key) {
            return Err(Error::engine(format!(
                "record.updated payload already contains reserved metadata key '{key}'"
            )));
        }
    }
    let mut pairs: Vec<(String, String)> = metadata
        .contributors
        .iter()
        .map(|contributor| {
            (
                contributor.principal.clone(),
                contributor.executor_kind.clone(),
            )
        })
        .collect();
    pairs.sort();
    pairs.dedup();
    let rows = pairs
        .into_iter()
        .map(|(principal, executor_kind)| {
            let mut row = Map::new();
            row.insert(PRINCIPAL_KEY.into(), Value::String(principal));
            row.insert(EXECUTOR_KIND_KEY.into(), Value::String(executor_kind));
            Value::Object(row)
        })
        .collect();
    base.insert(CONTRIBUTORS_KEY.into(), Value::Array(rows));
    base.insert(
        SESSION_KEY.into(),
        Value::String(metadata.session_ref.to_owned()),
    );
    if metadata.merged_offline {
        base.insert(MERGED_OFFLINE_KEY.into(), Value::Bool(true));
    }
    validate_version_metadata(&base)?;
    Ok(base)
}

/// Validate the reserved m7 metadata keys of a `record.updated` payload.
///
/// Ordinary base fields are never rejected: when none of the reserved keys is
/// present the payload passes untouched. `session` and `contributors` must
/// appear together; `contributors` may be empty (a no-new-ops cut is not yet
/// specified); each row is exactly `{principal, executor_kind}` with non-empty
/// strings plus an optional non-empty `run_key`; `merged_offline` may only be
/// present as `true`.
pub(crate) fn validate_version_metadata(payload: &Map<String, Value>) -> Result<()> {
    let has_contributors = payload.contains_key(CONTRIBUTORS_KEY);
    let has_session = payload.contains_key(SESSION_KEY);
    let has_merged_offline = payload.contains_key(MERGED_OFFLINE_KEY);
    if !has_contributors && !has_session && !has_merged_offline {
        return Ok(());
    }
    if has_contributors != has_session {
        return Err(Error::engine(
            "record.updated version metadata requires 'session' and 'contributors' together",
        ));
    }
    if has_merged_offline && !has_session {
        return Err(Error::engine(
            "record.updated 'merged_offline' requires 'session' and 'contributors'",
        ));
    }
    if has_session {
        match payload.get(SESSION_KEY) {
            Some(Value::String(session)) if !session.is_empty() => {}
            _ => {
                return Err(Error::engine(
                    "record.updated 'session' must be a non-empty string",
                ))
            }
        }
        match payload.get(CONTRIBUTORS_KEY) {
            Some(Value::Array(rows)) => {
                for row in rows {
                    validate_contributor_row(row)?;
                }
            }
            _ => {
                return Err(Error::engine(
                    "record.updated 'contributors' must be an array",
                ))
            }
        }
    }
    if has_merged_offline {
        match payload.get(MERGED_OFFLINE_KEY) {
            Some(Value::Bool(true)) => {}
            _ => {
                return Err(Error::engine(
                    "record.updated 'merged_offline' must be true when present",
                ))
            }
        }
    }
    Ok(())
}

fn validate_contributor_row(row: &Value) -> Result<()> {
    let Some(object) = row.as_object() else {
        return Err(Error::engine(
            "record.updated contributor row must be an object",
        ));
    };
    for key in object.keys() {
        if !matches!(key.as_str(), PRINCIPAL_KEY | EXECUTOR_KIND_KEY | RUN_KEY) {
            return Err(Error::engine(format!(
                "record.updated contributor row has unknown field '{key}'"
            )));
        }
    }
    for key in [PRINCIPAL_KEY, EXECUTOR_KIND_KEY] {
        match object.get(key) {
            Some(Value::String(value)) if !value.is_empty() => {}
            _ => {
                return Err(Error::engine(format!(
                    "record.updated contributor '{key}' must be a non-empty string"
                )))
            }
        }
    }
    if let Some(run_key) = object.get(RUN_KEY) {
        match run_key {
            Value::String(value) if !value.is_empty() => {}
            _ => {
                return Err(Error::engine(
                    "record.updated contributor 'run_key' must be a non-empty string when present",
                ))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pair(principal: &str, executor_kind: &str) -> AcknowledgedContributor {
        AcknowledgedContributor {
            principal: principal.into(),
            executor_kind: executor_kind.into(),
        }
    }

    fn base() -> Map<String, Value> {
        json!({"summary": "hello", "name": "doc"})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn none_returns_base_unchanged_in_order() {
        let payload =
            record_updated_payload(base(), None).expect("ordinary payload assembles unchanged");
        assert_eq!(payload.keys().collect::<Vec<_>>(), vec!["summary", "name"]);
        assert!(!payload.contains_key(CONTRIBUTORS_KEY));
        assert!(!payload.contains_key(SESSION_KEY));
        assert!(!payload.contains_key(MERGED_OFFLINE_KEY));
    }

    #[test]
    fn some_appends_canonical_metadata_and_preserves_base_order() {
        let contributors = [
            pair("zeta", "human"),
            pair("alpha", "agent"),
            pair("zeta", "human"),
        ];
        let metadata = VersionMetadata {
            contributors: &contributors,
            session_ref: "sess-abc",
            merged_offline: false,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert_eq!(
            payload.keys().collect::<Vec<_>>(),
            vec!["summary", "name", CONTRIBUTORS_KEY, SESSION_KEY]
        );
        assert_eq!(payload[SESSION_KEY], json!("sess-abc"));
        assert_eq!(
            payload[CONTRIBUTORS_KEY],
            json!([
                {"principal": "alpha", "executor_kind": "agent"},
                {"principal": "zeta", "executor_kind": "human"},
            ])
        );
        assert!(!payload.contains_key(MERGED_OFFLINE_KEY));
    }

    #[test]
    fn empty_contributors_are_allowed() {
        let metadata = VersionMetadata {
            contributors: &[],
            session_ref: "sess-empty",
            merged_offline: false,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert_eq!(payload[CONTRIBUTORS_KEY], json!([]));
    }

    #[test]
    fn merged_offline_present_only_when_true() {
        let contributors = [pair("alpha", "agent")];
        let metadata = VersionMetadata {
            contributors: &contributors,
            session_ref: "sess-offline",
            merged_offline: true,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert_eq!(payload[MERGED_OFFLINE_KEY], json!(true));
    }

    #[test]
    fn collision_with_base_reserved_key_is_refused() {
        for key in [CONTRIBUTORS_KEY, SESSION_KEY, MERGED_OFFLINE_KEY] {
            let mut base = base();
            base.insert(key.into(), json!("pre-existing"));
            let metadata = VersionMetadata {
                contributors: &[],
                session_ref: "sess",
                merged_offline: false,
            };
            let error = record_updated_payload(base, Some(&metadata)).unwrap_err();
            assert!(
                error.to_string().contains("reserved metadata key"),
                "{error}"
            );
        }
    }

    #[test]
    fn validator_rejects_session_without_contributors_and_orphan_flag() {
        let session_only = json!({"session": "sess"}).as_object().unwrap().clone();
        assert!(validate_version_metadata(&session_only).is_err());
        let contributors_only = json!({"contributors": []}).as_object().unwrap().clone();
        assert!(validate_version_metadata(&contributors_only).is_err());
        let orphan_flag = json!({"merged_offline": true}).as_object().unwrap().clone();
        assert!(validate_version_metadata(&orphan_flag).is_err());
    }

    #[test]
    fn validator_rejects_merged_offline_false_and_empty_session() {
        let false_flag = json!({"session": "s", "contributors": [], "merged_offline": false})
            .as_object()
            .unwrap()
            .clone();
        assert!(validate_version_metadata(&false_flag).is_err());
        let empty_session = json!({"session": "", "contributors": []})
            .as_object()
            .unwrap()
            .clone();
        assert!(validate_version_metadata(&empty_session).is_err());
    }

    #[test]
    fn validator_rejects_malformed_contributor_rows() {
        for row in [
            json!({"executor_kind": "agent"}),
            json!({"principal": "", "executor_kind": "agent"}),
            json!({"principal": "a", "executor_kind": ""}),
            json!({"principal": "a", "executor_kind": "agent", "extra": 1}),
            json!({"principal": "a", "executor_kind": "agent", "run_key": null}),
            json!({"principal": "a", "executor_kind": "agent", "run_key": ""}),
        ] {
            let payload = json!({"session": "s", "contributors": [row]})
                .as_object()
                .unwrap()
                .clone();
            assert!(validate_version_metadata(&payload).is_err(), "{payload:?}");
        }
    }

    #[test]
    fn validator_accepts_structural_future_run_key() {
        let payload = json!({
            "session": "s",
            "contributors": [
                {"principal": "a", "executor_kind": "agent", "run_key": "handle-run-1"}
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        validate_version_metadata(&payload).expect("structural run_key is schema-allowed");
    }

    #[test]
    fn assembled_payload_never_contains_run_key() {
        let contributors = [pair("alpha", "agent")];
        let metadata = VersionMetadata {
            contributors: &contributors,
            session_ref: "sess",
            merged_offline: false,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert!(!payload[CONTRIBUTORS_KEY].to_string().contains("run_key"));
    }
}
