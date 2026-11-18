//! Client identity and observation only. No installation or canonical authority.
use std::sync::{Arc, Mutex, OnceLock};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};

pub(crate) const HEADER: &str = "native-client-identity";
pub(crate) const UPDATE_REQUIRED: &str = "client_update_required";
const MAX_ENVELOPE: usize = 16 * 1024;
const MAX_DEMANDS: usize = 64;

/// Bounded, compiled identity; intentionally distinct from receiver shape negotiation
/// and MCP's agent clientInfo. Unstamped sources truthfully report `dev`.
pub(crate) fn advertisement() -> &'static str {
    static HEADER_VALUE: OnceLock<String> = OnceLock::new();
    HEADER_VALUE.get_or_init(|| {
        let source = if crate::FULL_GIT_SHA.len() == 40 && crate::FULL_GIT_SHA.bytes().all(|b| b.is_ascii_hexdigit()) { crate::FULL_GIT_SHA } else { "dev" };
        let mut contracts = vec![
            crate::standby_snapshot::STANDBY_SNAPSHOT_MANIFEST_CONTRACT,
            "native.standby-snapshot-export.v1",
            "native.standby-snapshot-export.v2",
            "native.standby-authority-act-head-response.v1",
            "native.standby-authority-act-delta-response.v1",
            "native.standby-authority-act-delta-export.v1",
        ];
        if cfg!(feature = "v2-kernel-probe") {
            contracts.push("native.standby-kernel-v2-delta.v1");
            if cfg!(feature="mcp-executor-prototype") {
                contracts.push("native.original-settlement.request.v1");
                contracts.push("native.original-settlement.answer.v1");
            }
        }
        json!({"contract":"native.client-identity.v1", "source":source,
            "version":crate::ENGINE_VERSION,"os":std::env::consts::OS,
            "arch":std::env::consts::ARCH,"abi":if cfg!(target_env="gnu") {"gnu"} else if cfg!(target_env="musl") {"musl"} else {"platform"},
            "debug":cfg!(debug_assertions),"mcp":crate::mcp::PROTOCOL_VERSION,
            "capabilities":{"executor":cfg!(feature="mcp-executor-prototype"),
                "kernel_v2":cfg!(feature="v2-kernel-probe")},"contracts":contracts})
        .to_string()
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UpdateRequired {
    /// Only this attempt; never clears uncertainty from a previous attempt.
    pub(crate) definitely_unapplied: bool,
}

pub(crate) struct UniqueJson(pub(crate) Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique-key JSON")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<UniqueJson, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let UniqueJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

// Duplicate known fields are rejected by serde, including outcome evidence.
#[derive(Deserialize)]
struct Refusal {
    error_code: String,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    applied: Option<bool>,
    #[serde(default)]
    may_already_be_applied: Option<bool>,
    #[serde(default)]
    result_type: Option<String>,
}

fn refusal(bytes: &[u8]) -> Option<UpdateRequired> {
    let refusal: Refusal = serde_json::from_slice(bytes).ok()?;
    if refusal.error_code != UPDATE_REQUIRED {
        return None;
    }
    Some(UpdateRequired {
        definitely_unapplied: matches!(refusal.outcome.as_deref(), Some("refused" | "not_sent"))
            && refusal.applied == Some(false)
            && refusal.may_already_be_applied != Some(true)
            && refusal.result_type.is_none(),
    })
}

/// Structured contracts only: Native envelope, RPC error.data, or MCP
/// isError structuredContent. Prose and arbitrary nested content never qualify.
/// Genuine authentication refusals always take precedence.
pub(crate) fn parse(status: Option<u16>, bytes: &[u8]) -> Option<UpdateRequired> {
    if matches!(status, Some(401 | 403)) || bytes.len() > MAX_ENVELOPE {
        return None;
    }
    let UniqueJson(value) = serde_json::from_slice(bytes).ok()?;
    let data = if value.get("jsonrpc").is_some() {
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return None;
        }
        if value.get("result").is_some() && value.get("error").is_some() {
            return None;
        }
        if let Some(error) = value.get("error") {
            error.get("data")?
        } else {
            let result = value.get("result")?;
            if result.get("isError") != Some(&Value::Bool(true)) {
                return None;
            }
            result.get("structuredContent")?
        }
    } else {
        &value
    };
    let mut parsed = refusal(&serde_json::to_vec(data).ok()?)?;
    parsed.definitely_unapplied &= !contradicts_unapplied(&value);
    Some(parsed)
}

fn contradicts_unapplied(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, v)| {
            let conflicts = match key.as_str() {
                "applied" => v != &Value::Bool(false) && !v.is_null(),
                "outcome" => !matches!(v.as_str(), Some("refused" | "not_sent")),
                "isError" => v != &Value::Bool(true),
                "success" => v != &Value::Bool(false),
                "result" => v.get("isError") != Some(&Value::Bool(true)),
                "partial" | "may_already_be_applied" => v != &Value::Bool(false) && !v.is_null(),
                "resultType" | "result_type" | "receipt" | "receipts" | "results" | "acts"
                | "act" => !v.is_null(),
                _ => false,
            };
            conflicts || contradicts_unapplied(v)
        }),
        Value::Array(items) => items.iter().any(contradicts_unapplied),
        _ => false,
    }
}

/// Invalid or duplicate update evidence cannot terminalize a write through
/// the generic refusal path. It establishes demand/uncertainty only.
pub(crate) fn classify(status: Option<u16>, bytes: &[u8]) -> Option<UpdateRequired> {
    if let Some(parsed) = parse(status, bytes) {
        return Some(parsed);
    }
    if matches!(status, Some(401 | 403)) || bytes.len() > MAX_ENVELOPE {
        return None;
    }
    let value: Value = serde_json::from_slice(bytes).ok()?;
    is_candidate(&value).then_some(UpdateRequired {
        definitely_unapplied: false,
    })
}

pub(crate) fn is_candidate(value: &Value) -> bool {
    value.get("error_code").and_then(Value::as_str) == Some(UPDATE_REQUIRED)
        || value
            .pointer("/error/data/error_code")
            .and_then(Value::as_str)
            == Some(UPDATE_REQUIRED)
        || (value.pointer("/result/isError") == Some(&Value::Bool(true))
            && value
                .pointer("/result/structuredContent/error_code")
                .and_then(Value::as_str)
                == Some(UPDATE_REQUIRED))
}

#[derive(Clone, Serialize)]
struct Demand {
    family: String,
    operation: String,
}

#[derive(Default)]
struct State {
    demands: Vec<Demand>,
    overflow: bool,
}

/// One transport/binding lifetime, with no global account registry or credential
/// derived identity. Clones share observations; a new binding gets a new monitor.
/// Successful unrelated traffic never clears an operation's update demand.
#[derive(Clone)]
pub(crate) struct Monitor {
    state: Arc<Mutex<State>>,
    changed: Arc<tokio::sync::watch::Sender<u64>>,
}
impl Default for Monitor {
    fn default() -> Self {
        Self {
            state: Default::default(),
            changed: Arc::new(tokio::sync::watch::channel(0).0),
        }
    }
}
impl Monitor {
    pub(crate) fn observe(
        &self,
        family: &str,
        operation: &str,
        status: Option<u16>,
        bytes: &[u8],
    ) -> Option<UpdateRequired> {
        let parsed = classify(status, bytes)?;
        // Names come from the failed request, never a server-selected wider scope.
        let mut state = self.state.lock().expect("compatibility observations");
        if !state
            .demands
            .iter()
            .any(|d| d.family == family && d.operation == operation)
        {
            if state.demands.len() < MAX_DEMANDS && family.len() <= 128 && operation.len() <= 128 {
                state.demands.push(Demand {
                    family: family.into(),
                    operation: operation.into(),
                });
                self.changed
                    .send_modify(|version| *version = version.saturating_add(1));
            } else if !state.overflow {
                state.overflow = true;
                self.changed
                    .send_modify(|version| *version = version.saturating_add(1));
            }
        }
        Some(parsed)
    }

    pub(crate) fn status(&self) -> Value {
        let state = self.state.lock().expect("compatibility observations");
        json!({"status":if state.demands.is_empty() && !state.overflow {"no_demand"} else {"demand_recorded"},
            "updater":"unavailable","demands":state.demands,"additional_demands":state.overflow})
    }

    #[allow(dead_code)] // Watch seam for the separately delivered updater.
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }
}

fn json_media_type(value: &str) -> bool {
    let token = value.split(';').next().unwrap_or("").trim();
    let Some((family, subtype)) = token.split_once('/') else {
        return false;
    };
    family.eq_ignore_ascii_case("application")
        && (subtype.eq_ignore_ascii_case("json")
            || (subtype.len() > 5
                && subtype.as_bytes()[subtype.len() - 5..].eq_ignore_ascii_case(b"+json")))
}

/// Inspect bounded JSON/error bodies before transport-specific status/fallback
/// decisions. Restore every inspected byte for an old server or another error.
/// Never buffer a snapshot or an event stream. Auth is handled by the caller.
pub(crate) async fn inspect(
    mut response: reqwest::Response,
    monitor: &Monitor,
    family: &str,
    operation: &str,
) -> Result<reqwest::Response> {
    use reqwest::ResponseBuilderExt;
    let status = response.status();
    if matches!(status.as_u16(), 401 | 403) {
        return Ok(response);
    }
    let json = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(json_media_type);
    if status.is_success() && !json {
        return Ok(response);
    }
    let mut rebuilt = http::Response::builder()
        .status(status)
        .version(response.version());
    *rebuilt.headers_mut().expect("response headers") = response.headers().clone();
    *rebuilt.extensions_mut().expect("response extensions") =
        std::mem::take(response.extensions_mut());
    rebuilt = rebuilt.url(response.url().clone());
    let mut prefix = Vec::new();
    let mut complete = false;
    let mut failure = None;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while prefix.len() <= MAX_ENVELOPE {
        match tokio::time::timeout_at(deadline, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                // Preserve ownership of an oversized first chunk, without
                // copying it into our bounded parser buffer.
                if prefix.len().saturating_add(chunk.len()) > MAX_ENVELOPE {
                    let head = futures::stream::iter(vec![
                        Ok::<_, reqwest::Error>(bytes::Bytes::from(prefix)),
                        Ok(chunk),
                    ]);
                    let body = reqwest::Body::wrap_stream(head.chain(response.bytes_stream()));
                    return Ok(reqwest::Response::from(
                        rebuilt.body(body).expect("response reconstruction"),
                    ));
                }
                prefix.extend_from_slice(&chunk);
            }
            Ok(Ok(None)) => {
                complete = true;
                break;
            }
            Ok(Err(error)) => {
                failure = Some(error);
                break;
            }
            Err(_) => break,
        }
    }
    if complete
        && monitor
            .observe(family, operation, Some(status.as_u16()), &prefix)
            .is_some()
    {
        return Err(Error::engine(UPDATE_REQUIRED));
    }
    let prefix = futures::stream::iter(
        std::iter::once(Ok::<_, reqwest::Error>(bytes::Bytes::from(prefix)))
            .chain(failure.map(Err)),
    );
    // Reframing keeps Content-Length headers but a stream has no exact size
    // hint. Callers retain their per-chunk ceilings when content_length() is
    // unknown; no allocation/admission relies solely on that cheap hint.
    let body = reqwest::Body::wrap_stream(prefix.chain(response.bytes_stream()));
    Ok(reqwest::Response::from(
        rebuilt.body(body).expect("response reconstruction"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structured_update_is_distinct_from_auth_prose_and_uncertain_outcomes() {
        let raw = br#"{"error_code":"client_update_required","outcome":"refused","applied":false}"#;
        assert!(parse(Some(426), raw).unwrap().definitely_unapplied);
        assert!(parse(Some(401), raw).is_none());
        assert!(parse(Some(403), raw).is_none());
        assert!(parse(None, br#"{"message":"client_update_required"}"#).is_none());
        assert!(parse(
            None,
            br#"{"error_code":"client_update_required","outcome":"unknown","applied":true}"#
        )
        .is_some_and(|d| !d.definitely_unapplied));
        assert!(parse(None, br#"{"error_code":"client_update_required","outcome":"refused","applied":false,"applied":true}"#).is_none());
        assert!(parse(None, &vec![b' '; MAX_ENVELOPE + 1]).is_none());
        let framed = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"data":serde_json::from_slice::<Value>(raw).unwrap()}});
        assert!(
            parse(None, framed.to_string().as_bytes())
                .unwrap()
                .definitely_unapplied
        );
    }
    #[test]
    fn demand_is_bounded_coalesced_and_binding_local() {
        let a = Monitor::default();
        let b = Monitor::default();
        let watch = a.subscribe();
        let raw = br#"{"error_code":"client_update_required","applied":false,"outcome":"refused"}"#;
        a.observe("mcp", "write", Some(426), raw);
        a.observe("mcp", "write", Some(426), raw);
        assert_eq!(*watch.borrow(), 1);
        a.observe("head", "read", Some(200), b"{}");
        assert_eq!(a.status()["demands"].as_array().unwrap().len(), 1);
        assert_eq!(b.status()["status"], "no_demand");
        for n in 0..100 {
            a.observe("mcp", &n.to_string(), Some(426), raw);
        }
        assert_eq!(a.status()["demands"].as_array().unwrap().len(), MAX_DEMANDS);
        assert_eq!(a.status()["additional_demands"], true);
        assert_eq!(*watch.borrow(), MAX_DEMANDS as u64 + 1);
        a.observe("mcp", &"x".repeat(129), Some(426), raw);
        assert_eq!(*watch.borrow(), MAX_DEMANDS as u64 + 1);
        assert!(advertisement().len() < 2048);
        assert_eq!(
            serde_json::from_str::<Value>(advertisement()).unwrap()["source"],
            if crate::FULL_GIT_SHA.len() == 40
                && crate::FULL_GIT_SHA.bytes().all(|b| b.is_ascii_hexdigit())
            {
                crate::FULL_GIT_SHA
            } else {
                "dev"
            }
        );
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use reqwest::ResponseBuilderExt;

    fn response(status: u16, media: &str, body: reqwest::Body) -> reqwest::Response {
        http::Response::builder()
            .status(status)
            .version(http::Version::HTTP_11)
            .url(reqwest::Url::parse("https://example.test/mcp/db").unwrap())
            .header("content-type", media)
            .header("x-old-server", "yes")
            .extension(42u64)
            .body(body)
            .unwrap()
            .into()
    }
    #[tokio::test]
    async fn old_server_body_and_metadata_survive_bounded_inspection() {
        let bytes = b"{ \"jsonrpc\" : \"2.0\", \"result\" : {\"ok\": true} }\n";
        let monitor = Monitor::default();
        let reply = inspect(
            response(200, "application/json", bytes.to_vec().into()),
            &monitor,
            "mcp",
            "read",
        )
        .await
        .unwrap();
        assert_eq!(reply.status(), 200);
        assert_eq!(reply.version(), http::Version::HTTP_11);
        assert_eq!(reply.url().as_str(), "https://example.test/mcp/db");
        assert_eq!(reply.extensions().get::<u64>(), Some(&42));
        assert_eq!(reply.headers()["x-old-server"], "yes");
        assert_eq!(reply.bytes().await.unwrap().as_ref(), bytes);
        assert_eq!(monitor.status()["status"], "no_demand");
    }
    #[tokio::test]
    async fn oversized_chunks_remain_complete_and_stream_errors_survive() {
        for chunks in [
            vec![vec![b'x'; MAX_ENVELOPE * 4]],
            vec![vec![b'a'; 8000], vec![b'b'; 10000], vec![b'c'; 100]],
        ] {
            let expected = chunks.concat();
            let body = reqwest::Body::wrap_stream(futures::stream::iter(
                chunks.into_iter().map(Ok::<_, std::io::Error>),
            ));
            let reply = inspect(
                response(400, "application/json", body),
                &Monitor::default(),
                "mcp",
                "read",
            )
            .await
            .unwrap();
            assert_eq!(reply.bytes().await.unwrap().as_ref(), expected);
        }
        let body = reqwest::Body::wrap_stream(futures::stream::iter(vec![
            Ok(vec![b'a']),
            Err(std::io::Error::other("broken stream")),
        ]));
        let reply = inspect(
            response(400, "application/json", body),
            &Monitor::default(),
            "mcp",
            "read",
        )
        .await
        .unwrap();
        assert!(reply.bytes().await.is_err());
    }
    #[tokio::test]
    async fn binary_events_and_auth_never_wait_for_body_inspection() {
        for (status, media) in [
            (200, "application/octet-stream"),
            (200, "text/event-stream"),
            (401, "application/json"),
            (403, "application/json"),
        ] {
            let body = reqwest::Body::wrap_stream(futures::stream::pending::<
                std::result::Result<Vec<u8>, std::io::Error>,
            >());
            let reply = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                inspect(
                    response(status, media, body),
                    &Monitor::default(),
                    "events",
                    "subscribe",
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply.status(), status);
        }
    }
    #[tokio::test]
    async fn update_body_records_only_failed_scope_and_never_authentication() {
        let monitor = Monitor::default();
        let bytes = br#"{"error_code":"client_update_required","outcome":"refused","applied":false,"scope":"everything"}"#;
        let error = inspect(
            response(426, "application/json", bytes.to_vec().into()),
            &monitor,
            "delta",
            "range",
        )
        .await
        .unwrap_err();
        assert!(matches!(error,Error::Engine(s) if s == UPDATE_REQUIRED));
        assert_eq!(
            monitor.status()["demands"],
            json!([{"family":"delta","operation":"range"}])
        );
        let reply = inspect(
            response(401, "application/json", bytes.to_vec().into()),
            &monitor,
            "head",
            "read",
        )
        .await
        .unwrap();
        assert_eq!(reply.status(), 401);
        assert_eq!(monitor.status()["demands"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn wrapper_duplicates_and_conflicting_outcomes_never_prove_unapplied() {
        for bytes in [
            br#"{"jsonrpc":"2.0","error":{"data":{"error_code":"client_update_required","outcome":"refused","applied":false,"applied":true}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","error_code":"client_update_required","outcome":"refused","applied":false,"result":{"ok":true},"error":{"data":{"error_code":"client_update_required"}}}"#,
            br#"{"jsonrpc":"2.0","error":{"applied":true,"data":{"error_code":"client_update_required","outcome":"refused","applied":false}}}"#,
            br#"{"error_code":"client_update_required","outcome":"refused","applied":false,"partial":true}"#,
            br#"{"error_code":"client_update_required","outcome":"refused","applied":false,"resultType":"partial"}"#,
        ] {
            assert!(parse(None,bytes).is_none_or(|p| !p.definitely_unapplied));
            assert!(classify(None,bytes).is_some_and(|p| !p.definitely_unapplied));
        }
    }
    #[tokio::test]
    async fn update_required_json_media_tokens_are_case_insensitive_and_support_suffixes() {
        for media in [
            "Application/JSON; charset=UTF-8",
            "application/problem+json",
        ] {
            let monitor = Monitor::default();
            let body =
                br#"{"error_code":"client_update_required","outcome":"refused","applied":false}"#
                    .to_vec();
            let error = inspect(response(200, media, body.into()), &monitor, "mcp", "read")
                .await
                .unwrap_err();
            assert!(matches!(error,Error::Engine(s) if s==UPDATE_REQUIRED));
            assert_eq!(monitor.status()["status"], "demand_recorded");
        }
    }
}
