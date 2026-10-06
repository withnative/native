//! HTTP external advisors (contract v0).
//!
//! An [`HttpAdvisor`] is built from a validated manifest: it `watches` what
//! the manifest watches, POSTs `{"advisor_id","version","context"}` to the
//! manifest endpoint, and maps a 200 `{"advisories":[{"code","message"}]}`
//! reply onto [`Advisory`] values. Anything else — non-200 (including
//! redirects, which are never followed), bad JSON, oversize reply,
//! timeout — is no advice (`Ok(vec![])`), never an error: advisors are
//! fail-open by design (S1).
//!
//! Response caps: at most [`MAX_RESPONSE_BYTES`] of reply body, at most
//! [`MAX_ADVISORIES_PER_CALL`] advisories per call (extras dropped with a
//! warn), messages truncated to [`MAX_MESSAGE_CHARS`] chars with a marker.

use std::time::Duration;

use futures::future::BoxFuture;
use futures::StreamExt as _;

use super::manifest::{watches_match, AdvisorManifest, BASE_CONTEXT_FIELDS};
use super::{AdviceContext, Advisor, Advisory, ADVISOR_TIMEOUT_MS};

/// Largest advisor reply body accepted; over it means no advice.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Largest advisory list accepted per call; extras are dropped with a warn.
pub const MAX_ADVISORIES_PER_CALL: usize = 16;
/// Longest advisory message kept; longer ones are truncated with a marker.
pub const MAX_MESSAGE_CHARS: usize = 2000;
const TRUNCATION_MARKER: &str = "…[truncated]";

/// One process-wide client. Redirects are disabled: the engine POSTs advisor
/// context only to the configured endpoint, never wherever a 3xx points
/// (which could be another host).
fn shared_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("advisor HTTP client builds without exotic config")
        })
        .clone()
}

/// An external advisor called over HTTP (endpoint `http(s)://...`).
pub struct HttpAdvisor {
    manifest: AdvisorManifest,
    digest: String,
    client: reqwest::Client,
}

impl HttpAdvisor {
    /// `manifest_digest` is the digest of the raw install bytes (kept on the
    /// [`Install`](super::install::Install)), not a re-serialization.
    pub fn new(manifest: AdvisorManifest, manifest_digest: String) -> Self {
        Self {
            manifest,
            digest: manifest_digest,
            client: shared_client(),
        }
    }

    pub fn manifest(&self) -> &AdvisorManifest {
        &self.manifest
    }

    /// Effective per-call timeout: the manifest budget, capped by the S1
    /// per-advisor receipt budget so a misdeclared budget cannot stall writes.
    pub fn effective_timeout(&self) -> Duration {
        Duration::from_millis(self.manifest.budget_ms.min(ADVISOR_TIMEOUT_MS))
    }

    /// Context payload: the 4 base fields plus exactly the declared subset.
    /// Unfilled (`None`) values serialise as null, matching the runner's
    /// missing-means-null convention.
    fn context_body(&self, ctx: &AdviceContext) -> serde_json::Value {
        let mut names: Vec<&str> = BASE_CONTEXT_FIELDS.to_vec();
        for field in &self.manifest.context {
            if !names.contains(&field.as_str()) {
                names.push(field.as_str());
            }
        }
        let mut map = serde_json::Map::with_capacity(names.len());
        for name in names {
            map.insert(name.to_owned(), context_field(ctx, name));
        }
        serde_json::Value::Object(map)
    }
}

/// One declared `AdviceContext` field by name.
fn context_field(ctx: &AdviceContext, name: &str) -> serde_json::Value {
    match name {
        "tool" => serde_json::Value::String(ctx.tool.clone()),
        "record_id" => serde_json::Value::String(ctx.record_id.clone()),
        "record_type" => serde_json::Value::String(ctx.record_type.clone()),
        "record_kind" => serde_json::Value::String(ctx.record_kind.clone()),
        "record_name" => ctx
            .record_name
            .clone()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
        "body_chars_before" => ctx
            .body_chars_before
            .map_or(serde_json::Value::Null, |value| value.into()),
        "body_chars_after" => ctx
            .body_chars_after
            .map_or(serde_json::Value::Null, |value| value.into()),
        "recent_body_revisions" => ctx
            .recent_body_revisions
            .map_or(serde_json::Value::Null, |value| value.into()),
        "links_out_count" => ctx
            .links_out_count
            .map_or(serde_json::Value::Null, |value| value.into()),
        "mentions_out_count" => ctx
            .mentions_out_count
            .map_or(serde_json::Value::Null, |value| value.into()),
        "run_key" => ctx
            .run_key
            .clone()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
        "lifecycle_before" => ctx
            .lifecycle_before
            .clone()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
        "lifecycle_after" => ctx
            .lifecycle_after
            .clone()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
        "lifecycle_before_terminality" => ctx
            .lifecycle_before_terminality
            .clone()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
        "lifecycle_after_terminality" => ctx
            .lifecycle_after_terminality
            .clone()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
        "summary_changed_in_write" => ctx
            .summary_changed_in_write
            .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        "summary_changed_since_active" => ctx
            .summary_changed_since_active
            .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        "summary_present" => ctx
            .summary_present
            .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        "claim_held" => ctx
            .claim_held
            .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        "writer_holds_claim" => ctx
            .writer_holds_claim
            .map_or(serde_json::Value::Null, serde_json::Value::Bool),
        _ => serde_json::Value::Null,
    }
}

#[derive(Debug, serde::Deserialize)]
struct RunnerAdvisory {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
    /// Optional severity from the runner. Missing (or anything but exactly
    /// `"warn"`) means `advise`: external advisors pre-dating the field stay
    /// compatible, and an unknown value must not escalate.
    #[serde(default)]
    level: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RunnerResponse {
    #[serde(default)]
    advisories: Vec<RunnerAdvisory>,
}

impl Advisor for HttpAdvisor {
    fn id(&self) -> &str {
        &self.manifest.id
    }

    fn version(&self) -> &str {
        &self.manifest.version
    }

    fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
        watches_match(&self.manifest.watches.tools, tool)
            && watches_match(&self.manifest.watches.types, record_type)
            && watches_match(&self.manifest.watches.kinds, record_kind)
    }

    fn advise<'a>(
        &'a self,
        ctx: &'a AdviceContext,
    ) -> BoxFuture<'a, crate::error::Result<Vec<Advisory>>> {
        Box::pin(async move {
            let body = serde_json::json!({
                "advisor_id": self.manifest.id,
                "version": self.manifest.version,
                "context": self.context_body(ctx),
            });
            let response = self
                .client
                .post(self.manifest.endpoint.as_str())
                .timeout(self.effective_timeout())
                .json(&body)
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        target: "native::advisors",
                        advisor_id = self.manifest.id.as_str(),
                        error = %error,
                        "http advisor unreachable or timed out; no advice"
                    );
                    return Ok(Vec::new());
                }
            };
            if response.status() != reqwest::StatusCode::OK {
                return Ok(Vec::new());
            }
            let body = match read_limited_body(response, &self.manifest.id).await {
                Some(body) => body,
                None => return Ok(Vec::new()),
            };
            let parsed: RunnerResponse = match serde_json::from_slice(&body) {
                Ok(parsed) => parsed,
                Err(error) => {
                    tracing::warn!(
                        target: "native::advisors",
                        advisor_id = self.manifest.id.as_str(),
                        error = %error,
                        "http advisor bad JSON; no advice"
                    );
                    return Ok(Vec::new());
                }
            };
            if parsed.advisories.len() > MAX_ADVISORIES_PER_CALL {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = self.manifest.id.as_str(),
                    count = parsed.advisories.len(),
                    max = MAX_ADVISORIES_PER_CALL,
                    "http advisor answered too many advisories; keeping the first"
                );
            }
            Ok(parsed
                .advisories
                .into_iter()
                .take(MAX_ADVISORIES_PER_CALL)
                .filter(|item| !item.code.is_empty() && !item.message.is_empty())
                .map(|item| Advisory {
                    advisor_id: self.manifest.id.clone(),
                    version: self.manifest.version.clone(),
                    manifest_digest: Some(self.digest.clone()),
                    code: item.code,
                    record_id: ctx.record_id.clone(),
                    message: truncate_message(item.message),
                    level: super::AdvisoryLevel::from_external(item.level.as_deref()),
                    // Further reply fields stay ignored: extending the
                    // external contract beyond level is a later slice.
                    details: None,
                })
                .collect())
        })
    }
}

/// Read a reply body up to [`MAX_RESPONSE_BYTES`]. `None` (with a warn) when
/// the declared or actual length exceeds the cap, or the stream fails.
async fn read_limited_body(response: reqwest::Response, advisor_id: &str) -> Option<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        tracing::warn!(
            target: "native::advisors",
            advisor_id = advisor_id,
            "http advisor reply too large; no advice"
        );
        return None;
    }
    let mut buf = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => {
                if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    tracing::warn!(
                        target: "native::advisors",
                        advisor_id = advisor_id,
                        "http advisor reply too large; no advice"
                    );
                    return None;
                }
                buf.extend_from_slice(&chunk);
            }
            Err(error) => {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = advisor_id,
                    error = %error,
                    "http advisor reply unreadable; no advice"
                );
                return None;
            }
        }
    }
    Some(buf)
}

/// Keep long messages receipt-sized: truncate to [`MAX_MESSAGE_CHARS`] with a
/// marker so the cut is visible rather than silent.
fn truncate_message(message: String) -> String {
    let len = message.chars().count();
    if len <= MAX_MESSAGE_CHARS {
        return message;
    }
    let keep = MAX_MESSAGE_CHARS.saturating_sub(TRUNCATION_MARKER.chars().count());
    let head: String = message.chars().take(keep).collect();
    format!("{head}{TRUNCATION_MARKER}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_manifest(endpoint: &str, budget_ms: u64) -> AdvisorManifest {
        AdvisorManifest {
            id: "test.http".into(),
            version: "0.1.0".into(),
            description: "test".into(),
            endpoint: endpoint.into(),
            watches: super::super::manifest::Watches {
                tools: vec!["update_record".into()],
                types: vec!["*".into()],
                kinds: vec!["*".into()],
            },
            context: vec!["body_chars_after".into()],
            budget_ms,
            enabled: true,
            settings: None,
        }
    }

    fn make_advisor(endpoint: &str, budget_ms: u64) -> HttpAdvisor {
        HttpAdvisor::new(test_manifest(endpoint, budget_ms), "test-digest".into())
    }

    fn test_ctx() -> AdviceContext {
        AdviceContext {
            tool: "update_record".into(),
            record_id: "rec-1".into(),
            record_type: "WorkItem".into(),
            record_kind: "task".into(),
            record_name: None,
            body_chars_before: None,
            body_chars_after: Some(42),
            recent_body_revisions: None,
            recent_same_run_append_streak: None,
            links_out_count: None,
            mentions_out_count: None,
            run_key: None,
            lifecycle_before: None,
            lifecycle_after: None,
            lifecycle_before_terminality: None,
            lifecycle_after_terminality: None,
            summary_changed_in_write: None,
            summary_changed_since_active: None,
            summary_present: None,
            claim_held: None,
            writer_holds_claim: None,
        }
    }

    /// One-shot HTTP server: reads a request, forwards the body, replies.
    async fn serve_once(
        status: u16,
        reply: Vec<u8>,
        delay_ms: u64,
        sender: tokio::sync::oneshot::Sender<(String, serde_json::Value)>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let read = socket.read(&mut buf).await;
            let text = String::from_utf8_lossy(&buf[..read.unwrap_or(0)]).into_owned();
            let body = text
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_owned();
            let parsed: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
            let _ = sender.send((text, parsed));
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            let reason = match status {
                200 => "OK",
                500 => "Internal Server Error",
                _ => "Error",
            };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                reply.len()
            );
            socket.write_all(head.as_bytes()).await.ok();
            socket.write_all(&reply).await.ok();
        });
        addr
    }

    #[tokio::test]
    async fn posts_declared_fields_only_and_maps_reply() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let reply = br#"{"advisories":[{"code":"nudge","message":"link up"}]}"#.to_vec();
        let addr = serve_once(200, reply, 0, sender).await;
        let advisor = make_advisor(&format!("http://{addr}"), 1000);
        let out = advisor.advise(&test_ctx()).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].advisor_id, "test.http");
        assert_eq!(out[0].code, "nudge");
        assert_eq!(out[0].record_id, "rec-1");
        assert_eq!(out[0].manifest_digest.as_deref(), Some("test-digest"));
        let (_, body) = receiver.await.unwrap();
        let context = &body["context"];
        assert_eq!(context["tool"], serde_json::json!("update_record"));
        assert_eq!(context["record_id"], serde_json::json!("rec-1"));
        assert_eq!(context["body_chars_after"], serde_json::json!(42));
        assert!(context.get("links_out_count").is_none());
        assert!(context.get("mentions_out_count").is_none());
    }

    #[tokio::test]
    async fn missing_level_means_advise_and_warn_passes_through() {
        for (reply, expected) in [
            (
                r#"{"advisories":[{"code":"n","message":"m"}]}"#,
                super::super::AdvisoryLevel::Advise,
            ),
            (
                r#"{"advisories":[{"code":"n","message":"m","level":"warn"}]}"#,
                super::super::AdvisoryLevel::Warn,
            ),
            (
                r#"{"advisories":[{"code":"n","message":"m","level":"advise"}]}"#,
                super::super::AdvisoryLevel::Advise,
            ),
            (
                r#"{"advisories":[{"code":"n","message":"m","level":"loud"}]}"#,
                super::super::AdvisoryLevel::Advise,
            ),
        ] {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let addr = serve_once(200, reply.as_bytes().to_vec(), 0, sender).await;
            let out = make_advisor(&format!("http://{addr}"), 1000)
                .advise(&test_ctx())
                .await
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].level, expected, "reply {reply}");
            let _ = receiver.await;
        }
    }

    #[tokio::test]
    async fn non_200_bad_json_and_slow_mean_no_advice() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let addr = serve_once(500, b"{}".to_vec(), 0, sender).await;
        let advisor = make_advisor(&format!("http://{addr}"), 500);
        assert!(advisor.advise(&test_ctx()).await.unwrap().is_empty());
        let _ = receiver.await;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        let addr = serve_once(200, b"not json".to_vec(), 0, sender).await;
        let advisor = make_advisor(&format!("http://{addr}"), 500);
        assert!(advisor.advise(&test_ctx()).await.unwrap().is_empty());
        let _ = receiver.await;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        let reply = br#"{"advisories":[{"code":"late","message":"too late"}]}"#.to_vec();
        let addr = serve_once(200, reply, 500, sender).await;
        let advisor = make_advisor(&format!("http://{addr}"), 50);
        let started = std::time::Instant::now();
        assert!(advisor.advise(&test_ctx()).await.unwrap().is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
        let _ = receiver.await;
    }

    #[test]
    fn timeout_is_capped_by_receipt_budget() {
        let advisor = make_advisor("http://127.0.0.1:9", 30_000);
        assert_eq!(advisor.effective_timeout(), Duration::from_millis(150));
        let advisor = make_advisor("http://127.0.0.1:9", 50);
        assert_eq!(advisor.effective_timeout(), Duration::from_millis(50));
    }

    /// 307 target: records any hit. The advisor must never follow there.
    async fn serve_sink() -> (String, tokio::sync::oneshot::Receiver<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _read = socket.read(&mut buf).await.unwrap_or(0);
            let _ = sender.send(());
            let head = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
            socket.write_all(head.as_bytes()).await.ok();
        });
        (addr, receiver)
    }

    async fn serve_redirect_once(target: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let target = target.to_owned();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let _read = socket.read(&mut buf).await.unwrap_or(0);
            let head = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nlocation: http://{target}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            socket.write_all(head.as_bytes()).await.ok();
        });
        addr
    }

    #[tokio::test]
    async fn redirect_is_not_followed_and_gives_no_advice() {
        let (sink_addr, mut sink_hit) = serve_sink().await;
        let redirect_addr = serve_redirect_once(&sink_addr).await;
        let advisor = make_advisor(&format!("http://{redirect_addr}"), 1000);
        assert!(advisor.advise(&test_ctx()).await.unwrap().is_empty());
        // The sink must have received nothing: the context never left the
        // configured endpoint.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(sink_hit.try_recv().is_err());
    }

    #[tokio::test]
    async fn oversize_reply_means_no_advice() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let big = format!(
            "{{\"advisories\":[{{\"code\":\"x\",\"message\":\"{}\"}}]}}",
            "y".repeat(MAX_RESPONSE_BYTES)
        );
        let addr = serve_once(200, big.into_bytes(), 0, sender).await;
        assert!(make_advisor(&format!("http://{addr}"), 1000)
            .advise(&test_ctx())
            .await
            .unwrap()
            .is_empty());
        let _ = receiver.await;
    }

    #[tokio::test]
    async fn advisory_list_and_messages_are_capped() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let items: Vec<String> = (0..20)
            .map(|index| {
                format!(
                    "{{\"code\":\"c{index}\",\"message\":\"{}\"}}",
                    "m".repeat(2100)
                )
            })
            .collect();
        let reply = format!("{{\"advisories\":[{}]}}", items.join(",")).into_bytes();
        let addr = serve_once(200, reply, 0, sender).await;
        let out = make_advisor(&format!("http://{addr}"), 1000)
            .advise(&test_ctx())
            .await
            .unwrap();
        assert_eq!(out.len(), MAX_ADVISORIES_PER_CALL);
        assert_eq!(out[0].message.chars().count(), MAX_MESSAGE_CHARS);
        assert!(out[0].message.ends_with("…[truncated]"));
        let _ = receiver.await;
    }
}
