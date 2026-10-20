//! Reserved version-metadata schema for `record.updated` payloads (m7).
//!
//! A first session version is an ordinary `record.updated` event that carries
//! three reserved top-level keys beside the ordinary fields:
//!
//! - `contributors`: an array of `{principal, executor_kind, run_key?, app?,
//!   channel?}` rows, where `app` is `{package, version, install_event_id}` and
//!   `channel` the server-observed transport (e.g. `"mcp"`);
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
//! ledger drain, a body-validator port, or mirror parity. `run_key` and `app`
//! are emitted when the trusted caller supplies them; the schema does not
//! authenticate either.

use serde_json::{Map, Value};

use super::registry::{AcknowledgedContributor, AppAttribution};
use super::span_map::{
    parse_span_map, serialize_span_map, validate_span_map, SpanMap, MAX_SERIALIZED_SPAN_MAP_BYTES,
    MAX_SPAN_MAP_AUTHORS,
};
use crate::{Error, Result};

pub(crate) const CONTRIBUTORS_KEY: &str = "contributors";
pub(crate) const SESSION_KEY: &str = "session";
pub(crate) const MERGED_OFFLINE_KEY: &str = "merged_offline";
/// Reserved key for the canonical per-version span map (`span_map` v1):
/// `{version, offset_kind, authors, spans}` beside `contributors[]`.
/// Read it back through `get_history` with full detail — the same read that
/// surfaces the version's body and contributors.
pub(crate) const SPAN_MAP_KEY: &str = "span_map";

const PRINCIPAL_KEY: &str = "principal";
const EXECUTOR_KIND_KEY: &str = "executor_kind";
const RUN_KEY: &str = "run_key";
const APP_KEY: &str = "app";
const CHANNEL_KEY: &str = "channel";
const APP_PACKAGE_KEY: &str = "package";
const APP_VERSION_KEY: &str = "version";
const APP_INSTALL_EVENT_KEY: &str = "install_event_id";

/// Version metadata supplied by a trusted version caller.
pub(crate) struct VersionMetadata<'a> {
    /// Distinct acknowledged contributors, in any order; assembled canonically.
    pub(crate) contributors: &'a [AcknowledgedContributor],
    /// Opaque session reference; must be non-empty.
    pub(crate) session_ref: &'a str,
    /// Whether this version includes ops made offline (present `true` only).
    pub(crate) merged_offline: bool,
    /// Canonical span map of the version body, when the version comes from
    /// a live session. `contributors[]` keeps meaning activity since the
    /// last cut; the map names the origin of surviving text instead.
    pub(crate) span_map: Option<&'a SpanMap>,
}

/// Assemble a `record.updated` payload, appending reserved m7 metadata when
/// present.
///
/// `None` returns `base` unchanged: byte-identical, key order preserved, so
/// the ordinary write path is unaffected. `Some` refuses to overwrite a base
/// that already holds a reserved key, appends canonically deduped/sorted
/// `contributors` and the opaque `session`, appends `merged_offline` only
/// when it is `true`, and appends the canonical `span_map` (re-checked
/// against author-count and serialized-byte bounds) when supplied. Emits
/// `run_key` and `app` only when supplied.
pub(crate) fn record_updated_payload(
    mut base: Map<String, Value>,
    metadata: Option<&VersionMetadata<'_>>,
) -> Result<Map<String, Value>> {
    let Some(metadata) = metadata else {
        return Ok(base);
    };
    for key in [
        CONTRIBUTORS_KEY,
        SESSION_KEY,
        MERGED_OFFLINE_KEY,
        SPAN_MAP_KEY,
    ] {
        if base.contains_key(key) {
            return Err(Error::engine(format!(
                "record.updated payload already contains reserved metadata key '{key}'"
            )));
        }
    }
    #[allow(clippy::type_complexity)]
    let mut entries: Vec<(
        String,
        String,
        Option<String>,
        Option<AppAttribution>,
        Option<String>,
    )> = metadata
        .contributors
        .iter()
        .map(|contributor| {
            (
                contributor.principal.clone(),
                contributor.executor_kind.clone(),
                contributor.run_key.clone(),
                contributor.app.clone(),
                contributor.channel.clone(),
            )
        })
        .collect();
    entries.sort();
    entries.dedup();
    let rows = entries
        .into_iter()
        .map(|(principal, executor_kind, run_key, app, channel)| {
            let mut row = Map::new();
            row.insert(PRINCIPAL_KEY.into(), Value::String(principal));
            row.insert(EXECUTOR_KIND_KEY.into(), Value::String(executor_kind));
            if let Some(run_key) = run_key.filter(|value| !value.is_empty()) {
                row.insert(RUN_KEY.into(), Value::String(run_key));
            }
            if let Some(app) = app {
                let mut object = Map::new();
                object.insert(APP_PACKAGE_KEY.into(), Value::String(app.package));
                object.insert(APP_VERSION_KEY.into(), Value::String(app.version));
                object.insert(
                    APP_INSTALL_EVENT_KEY.into(),
                    Value::String(app.install_event_id),
                );
                row.insert(APP_KEY.into(), Value::Object(object));
            }
            if let Some(channel) = channel.filter(|value| !value.is_empty()) {
                row.insert(CHANNEL_KEY.into(), Value::String(channel));
            }
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
    if let Some(span_map) = metadata.span_map {
        // Defense in depth on top of the prospective prepare-time caps:
        // author count and serialized bytes are re-checked at assembly, so
        // no code path can persist an unbounded map.
        if span_map.authors.len() > MAX_SPAN_MAP_AUTHORS {
            return Err(Error::engine(
                "record.updated 'span_map' names too many authors",
            ));
        }
        let value = serialize_span_map(span_map);
        let encoded = serde_json::to_string(&value)
            .map_err(|_| Error::engine("record.updated 'span_map' is not serializable"))?;
        if encoded.len() > MAX_SERIALIZED_SPAN_MAP_BYTES {
            return Err(Error::engine(
                "record.updated 'span_map' exceeds its serialized budget",
            ));
        }
        base.insert(SPAN_MAP_KEY.into(), value);
    }
    validate_version_metadata(&base)?;
    Ok(base)
}

/// Validate the reserved m7 metadata keys of a `record.updated` payload.
///
/// Ordinary base fields are never rejected: when none of the reserved keys is
/// present the payload passes untouched — old events without a span map stay
/// valid. `session` and `contributors` must appear together; `contributors`
/// may be empty (a no-new-ops cut is not yet specified); each row is exactly
/// `{principal, executor_kind}` with non-empty strings plus an optional
/// non-empty `run_key`; `merged_offline` may only be present as `true`.
/// `span_map`, when present, requires the version metadata and the version
/// body string, and must parse and tile that body exactly.
pub(crate) fn validate_version_metadata(payload: &Map<String, Value>) -> Result<()> {
    let has_contributors = payload.contains_key(CONTRIBUTORS_KEY);
    let has_session = payload.contains_key(SESSION_KEY);
    let has_merged_offline = payload.contains_key(MERGED_OFFLINE_KEY);
    let has_span_map = payload.contains_key(SPAN_MAP_KEY);
    if !has_contributors && !has_session && !has_merged_offline && !has_span_map {
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
    if has_span_map && !has_session {
        return Err(Error::engine(
            "record.updated 'span_map' requires 'session' and 'contributors'",
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
    if has_span_map {
        let body = match payload.get("body") {
            Some(Value::String(body)) => body.as_str(),
            _ => {
                return Err(Error::engine(
                    "record.updated 'span_map' requires the version body string",
                ))
            }
        };
        let value = payload.get(SPAN_MAP_KEY).expect("checked above");
        // Incoming serialized cap, bounded without materializing the whole
        // encoding: direct canonical admission must not persist an
        // over-budget map padded with unknown fields. Serialization of a
        // JSON value is infallible, so any write error is the cap tripping.
        struct ByteCap {
            count: usize,
        }
        impl std::io::Write for ByteCap {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.count = self.count.saturating_add(buf.len());
                if self.count > MAX_SERIALIZED_SPAN_MAP_BYTES {
                    return Err(std::io::Error::other(
                        "span map exceeds its serialized budget",
                    ));
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(ByteCap { count: 0 }, value).map_err(|_| {
            Error::engine("record.updated 'span_map' exceeds its serialized budget")
        })?;
        let map = parse_span_map(value).map_err(|error| {
            Error::engine(format!(
                "record.updated 'span_map' is malformed ({error:?})"
            ))
        })?;
        validate_span_map(&map, body).map_err(|error| {
            Error::engine(format!(
                "record.updated 'span_map' does not tile the body ({error:?})"
            ))
        })?;
    }
    Ok(())
}

fn validate_contributor_row(row: &Value) -> Result<()> {
    let Some(object) = row.as_object() else {
        return Err(Error::engine(
            "record.updated contributor row must be an object",
        ));
    };
    // Forward-tolerant: unknown fields are accepted and preserved (the
    // payload is stored as written), so a binary that predates a future
    // contributor field can still project events that carry it. Known fields
    // are still validated below.
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
    if let Some(channel) = object.get(CHANNEL_KEY) {
        if !matches!(channel, Value::String(value) if !value.is_empty()) {
            return Err(Error::engine(
                "record.updated contributor 'channel' must be a non-empty string when present",
            ));
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
    if let Some(app) = object.get(APP_KEY) {
        let valid = app.as_object().is_some_and(|app| {
            app.len() == 3
                && [APP_PACKAGE_KEY, APP_VERSION_KEY, APP_INSTALL_EVENT_KEY]
                    .iter()
                    .all(|key| matches!(app.get(*key), Some(Value::String(v)) if !v.is_empty()))
        });
        if !valid {
            return Err(Error::engine(
                "record.updated contributor 'app' must be {package, version, install_event_id} with non-empty strings",
            ));
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
            run_key: None,
            app: None,
            channel: None,
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
            span_map: None,
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
            span_map: None,
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
            span_map: None,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert_eq!(payload[MERGED_OFFLINE_KEY], json!(true));
    }

    #[test]
    fn collision_with_base_reserved_key_is_refused() {
        for key in [
            CONTRIBUTORS_KEY,
            SESSION_KEY,
            MERGED_OFFLINE_KEY,
            SPAN_MAP_KEY,
        ] {
            let mut base = base();
            base.insert(key.into(), json!("pre-existing"));
            let metadata = VersionMetadata {
                contributors: &[],
                session_ref: "sess",
                merged_offline: false,
                span_map: None,
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
    fn validator_accepts_and_preserves_unknown_contributor_fields() {
        let payload = json!({
            "session": "s",
            "contributors": [
                {"principal": "a", "executor_kind": "agent", "extra": 1,
                 "future": {"nested": true}}
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        let before = payload.clone();
        validate_version_metadata(&payload).expect("unknown fields are tolerated");
        assert_eq!(payload, before, "validation never rewrites the payload");
    }

    #[test]
    fn validator_checks_channel() {
        let row = |channel: Value| {
            json!({"session": "s", "contributors": [
                {"principal": "a", "executor_kind": "authenticated_principal", "channel": channel}
            ]})
            .as_object()
            .unwrap()
            .clone()
        };
        validate_version_metadata(&row(json!("mcp"))).expect("a channel string is valid");
        for bad in [json!(""), json!(1), json!(null), json!({"kind": "mcp"})] {
            assert!(
                validate_version_metadata(&row(bad.clone())).is_err(),
                "channel {bad} must be refused"
            );
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
    fn assembled_payload_omits_absent_run_key_and_app() {
        let contributors = [pair("alpha", "agent")];
        let metadata = VersionMetadata {
            contributors: &contributors,
            session_ref: "sess",
            merged_offline: false,
            span_map: None,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert!(!payload[CONTRIBUTORS_KEY].to_string().contains("run_key"));
        assert!(!payload[CONTRIBUTORS_KEY].to_string().contains("app"));
    }

    #[test]
    fn assembled_payload_carries_run_key_and_app_object() {
        let mut contributor = pair("alpha", "human");
        contributor.run_key = Some("run-1".into());
        contributor.app = Some(AppAttribution {
            package: "docs".into(),
            version: "1.2.0".into(),
            install_event_id: "evt-1".into(),
        });
        let contributors = [contributor];
        let metadata = VersionMetadata {
            contributors: &contributors,
            session_ref: "sess",
            merged_offline: false,
            span_map: None,
        };
        let payload = record_updated_payload(base(), Some(&metadata)).unwrap();
        assert_eq!(
            payload[CONTRIBUTORS_KEY],
            json!([{"principal": "alpha", "executor_kind": "human", "run_key": "run-1",
                    "app": {"package": "docs", "version": "1.2.0", "install_event_id": "evt-1"}}])
        );
        let bad = json!({"session": "s", "contributors": [
            {"principal": "a", "executor_kind": "human", "app": "docs@1"}
        ]});
        assert!(validate_version_metadata(bad.as_object().unwrap()).is_err());
    }

    fn span_map_fixture() -> super::super::span_map::SpanMap {
        use super::super::span_map::{Owner, Span, SpanMap, SPAN_MAP_SCHEMA_VERSION};
        SpanMap {
            version: SPAN_MAP_SCHEMA_VERSION,
            authors: vec![
                Owner::PriorVersion,
                Owner::Contributor(pair("alpha", "agent")),
            ],
            spans: vec![
                Span {
                    start: 0,
                    end: 5,
                    author: 0,
                },
                Span {
                    start: 5,
                    end: 8,
                    author: 1,
                },
            ],
        }
    }

    fn version_base(body: &str) -> Map<String, Value> {
        json!({"summary": "hello", "name": "doc", "body": body})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn span_map_round_trips_through_payload() {
        use super::super::span_map::{parse_span_map, validate_span_map};
        let map = span_map_fixture();
        let contributors = [pair("alpha", "agent")];
        let metadata = VersionMetadata {
            contributors: &contributors,
            session_ref: "sess",
            merged_offline: false,
            span_map: Some(&map),
        };
        let payload = record_updated_payload(version_base("helloXYZ"), Some(&metadata)).unwrap();
        assert!(payload.contains_key(SPAN_MAP_KEY));
        validate_version_metadata(&payload).expect("assembled map validates");
        let parsed = parse_span_map(&payload[SPAN_MAP_KEY]).unwrap();
        assert_eq!(parsed, map);
        validate_span_map(&parsed, "helloXYZ").unwrap();
    }

    #[test]
    fn span_map_requires_metadata_and_body() {
        let map = span_map_fixture();
        let value = super::super::span_map::serialize_span_map(&map);
        let orphan = json!({"span_map": value}).as_object().unwrap().clone();
        assert!(validate_version_metadata(&orphan).is_err());
        let no_body = json!({"session": "s", "contributors": [], "span_map": value})
            .as_object()
            .unwrap()
            .clone();
        assert!(validate_version_metadata(&no_body).is_err());
    }

    #[test]
    fn span_map_must_tile_the_version_body() {
        let mut value = super::super::span_map::serialize_span_map(&span_map_fixture());
        value["spans"] = json!([[0, 4, 0], [5, 8, 1]]);
        let payload =
            json!({"session": "s", "contributors": [], "body": "helloXYZ", "span_map": value})
                .as_object()
                .unwrap()
                .clone();
        assert!(validate_version_metadata(&payload).is_err());
    }

    #[test]
    fn span_map_rejects_strict_optionals_and_overflow() {
        let mut value = super::super::span_map::serialize_span_map(&span_map_fixture());
        // Present-but-empty run_key must refuse, not become None.
        value["authors"][1]["run_key"] = json!("");
        let payload =
            json!({"session": "s", "contributors": [], "body": "helloXYZ", "span_map": value})
                .as_object()
                .unwrap()
                .clone();
        assert!(validate_version_metadata(&payload).is_err());
    }

    #[test]
    fn span_map_rejects_over_budget_encoding_before_parse() {
        use super::super::span_map::MAX_SERIALIZED_SPAN_MAP_BYTES;
        // A structurally valid map padded with a huge unknown field must
        // refuse on its encoded size, not parse and persist.
        let mut value = super::super::span_map::serialize_span_map(&span_map_fixture());
        value["padding"] = json!("x".repeat(MAX_SERIALIZED_SPAN_MAP_BYTES));
        let payload =
            json!({"session": "s", "contributors": [], "body": "helloXYZ", "span_map": value})
                .as_object()
                .unwrap()
                .clone();
        let error = validate_version_metadata(&payload).unwrap_err();
        assert!(error.to_string().contains("serialized budget"), "{error}");
    }
}
