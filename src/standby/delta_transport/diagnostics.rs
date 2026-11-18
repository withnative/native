//! Closed, payload-free diagnostics at the point reqwest errors would be lost.
//! Never render an error, URL, request/response body, header or credential into
//! a sink. DNS/TLS hints are deliberately labelled hints: reqwest's public
//! error API does not expose those connector types separately.

use std::error::Error as _;
use std::time::Instant;

const TARGET: &str = "native_ce::standby::transport";

pub(super) struct RequestDiagnostic {
    started: Instant,
    kind: &'static str,
}

#[derive(Debug)]
struct Cause {
    category: &'static str,
    io_kind: &'static str,
    os_error: Option<i32>,
    chain_depth: usize,
    chain_truncated: bool,
}

impl RequestDiagnostic {
    pub(super) fn new(kind: &'static str) -> Self {
        Self {
            started: Instant::now(),
            kind,
        }
    }

    pub(super) fn failure(
        &self,
        phase: &'static str,
        error: &reqwest::Error,
    ) -> crate::error::Error {
        let cause = classify(error);
        tracing::warn!(
            target: TARGET,
            request_kind = self.kind,
            phase,
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            category = cause.category,
            io_kind = cause.io_kind,
            os_error = cause.os_error,
            chain_depth = cause.chain_depth,
            chain_truncated = cause.chain_truncated,
            timeout = error.is_timeout(),
            connect = error.is_connect(),
            body = error.is_body(),
            source_sha = crate::FULL_GIT_SHA,
            platform = std::env::consts::OS,
            "standby HTTP transport failed"
        );
        // Keep historical Network classification/retry semantics. Only the
        // static suffix adds information to the ordinary refresh receipt.
        let prefix = if phase == "response_body" {
            "hosted authority act response was interrupted"
        } else {
            "hosted authority act request failed"
        };
        crate::error::Error::engine(format!("{prefix}: {}", cause.category))
    }

    pub(super) fn response(&self, status: reqwest::StatusCode, maintenance: bool) {
        if maintenance
            || (status.is_client_error() && status.as_u16() != 404)
            || status.is_server_error()
        {
            tracing::warn!(
                target: TARGET,
                request_kind = self.kind,
                phase = "response_headers",
                elapsed_ms = self.started.elapsed().as_millis() as u64,
                http_status = status.as_u16(),
                maintenance,
                source_sha = crate::FULL_GIT_SHA,
                platform = std::env::consts::OS,
                "standby HTTP response refused"
            );
        }
    }
}

fn classify(error: &reqwest::Error) -> Cause {
    let mut cause = Cause {
        category: "request_other",
        io_kind: "none",
        os_error: None,
        chain_depth: 0,
        chain_truncated: false,
    };
    let mut dns_hint = false;
    let mut tls_hint = false;
    let mut source = error.source();
    // Underlying error prose is used only to select fixed hint tokens. It is
    // never retained, returned or logged. Bound the traversal defensively.
    while let Some(current) = source {
        if cause.chain_depth == 12 {
            cause.chain_truncated = true;
            break;
        }
        cause.chain_depth += 1;
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            cause.io_kind = match io.kind() {
                std::io::ErrorKind::ConnectionRefused => "connection_refused",
                std::io::ErrorKind::ConnectionReset => "connection_reset",
                std::io::ErrorKind::ConnectionAborted => "connection_aborted",
                std::io::ErrorKind::TimedOut => "timed_out",
                std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
                std::io::ErrorKind::BrokenPipe => "broken_pipe",
                std::io::ErrorKind::NotConnected => "not_connected",
                std::io::ErrorKind::AddrNotAvailable => "address_unavailable",
                std::io::ErrorKind::OutOfMemory => "out_of_memory",
                _ => "other",
            };
            cause.os_error = io.raw_os_error();
        }
        let text = current.to_string().to_ascii_lowercase();
        dns_hint |= text.contains("dns error")
            || text.contains("failed to lookup address")
            || text.contains("name or service not known");
        tls_hint |= text.contains("tls handshake")
            || text.contains("invalid peer certificate")
            || text.contains("invalid certificate")
            || text.contains("received fatal alert");
        source = current.source();
    }
    cause.category = if error.is_timeout() && error.is_connect() {
        "connect_timeout"
    } else if error.is_timeout() {
        "request_timeout"
    } else if dns_hint {
        "dns_hint"
    } else if tls_hint {
        "tls_hint"
    } else if cause.io_kind != "none" && cause.io_kind != "other" {
        cause.io_kind
    } else if error.is_connect() {
        "connect_other"
    } else if error.is_builder() {
        "builder"
    } else if error.is_body() {
        "body_other"
    } else if error.is_decode() {
        "decode"
    } else {
        "request_other"
    };
    cause
}

/// Parse only diagnostic tokens minted above; never disclose a forged suffix.
pub(in crate::standby) fn failure_detail(message: &str) -> Option<&'static str> {
    let suffix = message
        .strip_prefix("hosted authority act request failed: ")
        .or_else(|| message.strip_prefix("hosted authority act response was interrupted: "))?;
    [
        "connect_timeout",
        "request_timeout",
        "dns_hint",
        "tls_hint",
        "connection_refused",
        "connection_reset",
        "connection_aborted",
        "timed_out",
        "unexpected_eof",
        "broken_pipe",
        "not_connected",
        "address_unavailable",
        "out_of_memory",
        "connect_other",
        "builder",
        "body_other",
        "decode",
        "request_other",
    ]
    .into_iter()
    .find(|token| *token == suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby::delta_transport::{
        AuthorityActDeltaHttp, AuthorityActHttpClient, DeltaHttpMethod, DeltaHttpRequest,
        HttpAuthorityActClient,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture() -> (Capture, impl tracing::Subscriber + Send + Sync) {
        let output = Capture(Arc::new(Mutex::new(Vec::new())));
        let writer = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        (output, subscriber)
    }

    async fn request(
        client: &HttpAuthorityActClient,
        url: String,
        chunked: bool,
    ) -> crate::error::Result<Vec<u8>> {
        if chunked {
            client
                .send(DeltaHttpRequest {
                    method: DeltaHttpMethod::Get,
                    url,
                    bearer: "credential-secret".into(),
                    json: None,
                    range: None,
                    max_body: 1024,
                })
                .await
                .map(|response| response.body)
        } else {
            client.call(url, "credential-secret".into(), serde_json::json!({
                "params":{"name":"private-tool-name", "arguments":{"operation":"authority_act_head"}},
                "private":"request-body-secret",
            })).await
        }
    }

    fn client() -> HttpAuthorityActClient {
        HttpAuthorityActClient {
            compatibility: Default::default(),
            install_key: None,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_millis(150))
                .build()
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn real_connection_refusal_is_classified_without_disclosing_url_or_credentials() {
        for chunked in [false, true] {
            let (output, subscriber) = capture();
            let _guard = tracing::subscriber::set_default(subscriber);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let error = request(
                &client(),
                format!("http://{addr}/path-secret?token=query-secret"),
                chunked,
            )
            .await
            .unwrap_err();
            assert_eq!(
                failure_detail(&error.to_string()),
                Some("connection_refused")
            );
            let log = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
            assert!(log.contains("category=\"connection_refused\""), "{log}");
            assert!(log.contains("phase=\"request\""), "{log}");
            for secret in [
                "path-secret",
                "query-secret",
                "credential-secret",
                "request-body-secret",
                "private-tool-name",
            ] {
                assert!(!log.contains(secret), "{log}");
                assert!(!error.to_string().contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn real_timeout_and_interrupted_body_are_distinct_and_same_client_recovers() {
        for chunked in [false, true] {
            for stalled in [true, false] {
                let (output, subscriber) = capture();
                let _guard = tracing::subscriber::set_default(subscriber);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = [0; 4096];
                    let _ = stream.read(&mut bytes).await.unwrap();
                    if stalled {
                        std::future::pending::<()>().await;
                    } else {
                        stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1024\r\nconnection: close\r\n\r\nbody-secret").await.unwrap();
                    }
                });
                let client = client();
                let error = request(
                    &client,
                    format!("http://{addr}/private?secret=query-secret"),
                    chunked,
                )
                .await
                .unwrap_err();
                server.abort();
                let _ = server.await;
                let log = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
                if stalled {
                    assert_eq!(failure_detail(&error.to_string()), Some("request_timeout"));
                    assert!(log.contains("phase=\"request\""), "{log}");
                } else {
                    assert!(failure_detail(&error.to_string()).is_some());
                    assert!(log.contains("phase=\"response_body\""), "{log}");
                }
                assert!(log.contains("elapsed_ms="), "{log}");
                for secret in [
                    "body-secret",
                    "query-secret",
                    "credential-secret",
                    "request-body-secret",
                ] {
                    assert!(!log.contains(secret), "{log}");
                    assert!(!error.to_string().contains(secret));
                }
                // A later ordinary call on this client succeeds: diagnostics
                // do not poison the client or introduce their own retry.
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = [0; 4096];
                    let _ = stream.read(&mut bytes).await.unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                });
                assert_eq!(
                    request(&client, format!("http://{addr}/"), chunked)
                        .await
                        .unwrap(),
                    b"ok"
                );
                server.await.unwrap();
            }
        }
    }

    struct FailingResolver;
    impl reqwest::dns::Resolve for FailingResolver {
        fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async {
                Err(
                    Box::new(std::io::Error::other("dns error: resolver-secret"))
                        as Box<dyn std::error::Error + Send + Sync>,
                )
            })
        }
    }

    #[tokio::test]
    async fn resolver_failure_keeps_a_hint_without_disclosing_its_message() {
        let (output, subscriber) = capture();
        let _guard = tracing::subscriber::set_default(subscriber);
        let client = HttpAuthorityActClient {
            compatibility: Default::default(),
            install_key: None,
            client: reqwest::Client::builder()
                .no_proxy()
                .dns_resolver(Arc::new(FailingResolver))
                .build()
                .unwrap(),
        };
        let error = request(
            &client,
            "http://private.invalid/path?token=query-secret".into(),
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(failure_detail(&error.to_string()), Some("dns_hint"));
        let log = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(log.contains("category=\"dns_hint\""), "{log}");
        for secret in [
            "resolver-secret",
            "private.invalid",
            "query-secret",
            "credential-secret",
        ] {
            assert!(!log.contains(secret), "{log}");
            assert!(!error.to_string().contains(secret));
        }
    }

    #[test]
    fn busy_export_wire_code_is_preserved_without_conflating_other_conflicts() {
        use crate::standby::delta_transport::{delta_status_error, DeltaHttpResponse};
        for (status, code, expected) in [
            (
                409,
                "export_in_progress",
                "hosted authority act delta export request failed: export_in_progress",
            ),
            (
                409,
                "other_conflict",
                "hosted authority act delta export request failed: capture unavailable",
            ),
            (
                404,
                "handle_not_found",
                "hosted authority act delta export request failed: capture unavailable",
            ),
            (
                503,
                "export_in_progress",
                "hosted authority act delta export HTTP status 503 (export_in_progress)",
            ),
        ] {
            let response = DeltaHttpResponse {
                status,
                api: None,
                content_type: None,
                etag: None,
                content_range: None,
                retry_after_secs: None,
                body: serde_json::to_vec(
                    &serde_json::json!({"error_code":code,"error":"response-body-secret"}),
                )
                .unwrap(),
            };
            assert_eq!(delta_status_error(&response).to_string(), expected);
        }
    }

    #[test]
    fn forged_details_and_non_transport_messages_never_enter_receipts() {
        for message in [
            "hosted authority act request failed: credential-secret",
            "hosted authority act response was interrupted: request_timeout query-secret",
            "payload mentions request_timeout",
        ] {
            assert_eq!(failure_detail(message), None);
        }
    }
}
