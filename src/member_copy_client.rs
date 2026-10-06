//! Authenticated core member-copy HTTP adapter (D2 actual increment).
//!
//! Sibling to the core standby reqwest clients. It pins the exact origin and
//! route, disables redirects/cookies/fallback hosts, bounds every response and
//! header, and derives the sealed [`MemberCopyContext`] only from a successful
//! `Current`/`Replace` whose same-fence account header, exact route/origin,
//! portable manifest origin, consumer and scope all agree. It performs no
//! credential read: the driver reads the guarded selection once and passes it
//! in; the client retains it in the context for every chunk.

use std::time::Duration;

use futures::future::BoxFuture;
use futures::StreamExt as _;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_RANGE, ETAG, RANGE};
use reqwest::{Client, StatusCode};
use url::Url;

use crate::error::{Error, Result};
use crate::export::BINARY_MAX_CHUNK_BYTES;
use crate::member_copy_lifecycle::RevokedCause;
use crate::member_copy_transport::{
    CredentialSelection, MemberCopyAnswer, MemberCopyAttempt, MemberCopyChunk, MemberCopyContext,
    MemberCopyDownloadRefusal, MemberCopyRequest, MemberCopyTransport, MEMBER_COPY_API,
};
use crate::replica_generation::ReplicaGenerationManifest;
use crate::standby_snapshot::StandbyConsumerIdentity;

const API_HEADER: &str = "x-native-member-copy-api";
const ACCOUNT_HEADER: &str = "x-native-member-copy-account-binding";
const MAX_OUTCOME_BYTES: usize = 32 * 1024;
const MAX_ACCOUNT_HEADER_BYTES: usize = 512;
const MAX_HEADER_VALUE_BYTES: usize = 256;

/// The single canonical exact-origin representation used by the config, the
/// driver/owner pin, the context footing and the persisted receipt. Validates
/// with the standby exact-origin rule and returns the canonical serialization
/// (no trailing slash).
pub(crate) fn canonical_origin(raw: &str) -> Result<String> {
    crate::standby::validate_exact_origin(raw)?;
    let origin = Url::parse(raw)
        .map_err(|error| Error::engine(format!("member copy origin is invalid: {error}")))?;
    Ok(origin.as_str().trim_end_matches('/').to_owned())
}

/// Adapter configuration: the exact origin/route pins and the device consumer.
/// It deliberately carries **no** `origin_database_id` — the portable origin is
/// taken only from the authenticated success manifest JSON.
#[derive(Clone, Debug)]
pub struct MemberCopyClientConfig {
    origin: Url,
    canonical_origin: String,
    route_database_id: String,
    consumer: StandbyConsumerIdentity,
}

impl MemberCopyClientConfig {
    pub fn new(
        origin: &str,
        route_database_id: &str,
        consumer: StandbyConsumerIdentity,
    ) -> Result<Self> {
        let canonical_origin = canonical_origin(origin)?;
        let origin = Url::parse(&canonical_origin)
            .map_err(|error| Error::engine(format!("member copy origin is invalid: {error}")))?;
        consumer.validate_declaration()?;
        if route_database_id.is_empty()
            || route_database_id.trim() != route_database_id
            || route_database_id.len() > MAX_HEADER_VALUE_BYTES
            || route_database_id.chars().any(char::is_control)
        {
            return Err(Error::engine("member copy route database id is invalid"));
        }
        Ok(Self {
            origin,
            canonical_origin,
            route_database_id: route_database_id.to_owned(),
            consumer,
        })
    }
}

/// Real reqwest implementation of [`MemberCopyTransport`].
pub struct ReqwestMemberCopyClient {
    http: Client,
    config: MemberCopyClientConfig,
}

impl ReqwestMemberCopyClient {
    pub fn new(config: MemberCopyClientConfig) -> Result<Self> {
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| Error::engine(format!("member copy http client: {error}")))?;
        Ok(Self { http, config })
    }

    /// The normalized exact origin expected in a context this adapter issued.
    fn expected_origin(&self) -> &str {
        &self.config.canonical_origin
    }

    /// Reject a sealed context that was not issued by THIS adapter before its
    /// retained bearer can be used: exact origin, route and consumer must match
    /// the client config (the trait is public, so A's context could otherwise be
    /// presented to adapter B).
    fn confine_context(&self, context: &MemberCopyContext) -> Result<()> {
        if context.server_origin() != self.expected_origin()
            || context.route_database_id() != self.config.route_database_id
            || context.consumer() != &self.config.consumer
        {
            return Err(Error::engine(
                "member copy context does not belong to this adapter",
            ));
        }
        Ok(())
    }

    fn start_url(&self) -> Result<Url> {
        let mut url = self.config.origin.clone();
        url.path_segments_mut()
            .map_err(|_| Error::engine("member copy origin cannot be a base URL"))?
            .pop_if_empty()
            .extend([
                "v1",
                "databases",
                self.config.route_database_id.as_str(),
                "member-copy",
            ]);
        Ok(url)
    }

    fn bytes_url(&self, handle: &str) -> Result<Url> {
        let mut url = self.start_url()?;
        url.path_segments_mut()
            .map_err(|_| Error::engine("member copy origin cannot be a base URL"))?
            .push(handle)
            .push("bytes");
        Ok(url)
    }

    fn bearer(&self, selection: &CredentialSelection) -> Result<HeaderValue> {
        let token = std::str::from_utf8(selection.bearer())
            .map_err(|_| Error::engine("member copy credential is not UTF-8"))?;
        if token.is_empty() || token.chars().any(char::is_control) {
            return Err(Error::engine("member copy credential is invalid"));
        }
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::engine("member copy credential header is invalid"))
    }

    fn api_header(response: &reqwest::Response) -> bool {
        response
            .headers()
            .get(API_HEADER)
            .and_then(|value| value.to_str().ok())
            == Some(MEMBER_COPY_API)
    }

    fn account_header(response: &reqwest::Response) -> Result<String> {
        let mut values = response.headers().get_all(ACCOUNT_HEADER).iter();
        let first = values
            .next()
            .ok_or_else(|| Error::engine("member copy account binding header is missing"))?;
        if values.next().is_some() {
            return Err(Error::engine(
                "member copy account binding header is not unique",
            ));
        }
        let text = first
            .to_str()
            .map_err(|_| Error::engine("member copy account binding header is invalid"))?;
        if text.is_empty()
            || text.len() > MAX_ACCOUNT_HEADER_BYTES
            || text.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "member copy account binding header is invalid",
            ));
        }
        Ok(text.to_owned())
    }

    async fn outcome(
        &self,
        response: reqwest::Response,
        selection: &CredentialSelection,
    ) -> Result<MemberCopyAttempt> {
        let status = response.status();
        let api_ok = Self::api_header(&response);
        match status {
            StatusCode::OK => {
                require_api(api_ok)?;
                let account = Self::account_header(&response)?;
                let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                let outcome: OutcomeBody = serde_json::from_slice(&body).map_err(|error| {
                    Error::engine(format!("member copy outcome is malformed: {error}"))
                })?;
                if outcome.api() != MEMBER_COPY_API {
                    return Err(Error::engine(
                        "member copy outcome api marker disagrees with the contract",
                    ));
                }
                let (answer, scope_ref, manifest) = outcome.into_answer()?;
                let context = MemberCopyContext::new(
                    account,
                    self.expected_origin().to_owned(),
                    self.config.route_database_id.clone(),
                    manifest.origin_database_id.clone(),
                    manifest.consumer.clone(),
                    scope_ref,
                    selection.clone(),
                );
                Ok(MemberCopyAttempt {
                    answer,
                    context: Some(context),
                })
            }
            StatusCode::FORBIDDEN => {
                require_api(api_ok)?;
                let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                Ok(MemberCopyAttempt {
                    answer: MemberCopyAnswer::Revoked {
                        cause: revoked_cause(&body)?,
                    },
                    context: None,
                })
            }
            StatusCode::LOCKED => {
                require_api(api_ok)?;
                let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                require_kind(&body, "locked")?;
                Ok(MemberCopyAttempt {
                    answer: MemberCopyAnswer::Locked,
                    context: None,
                })
            }
            StatusCode::CONFLICT => {
                require_api(api_ok)?;
                let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                require_kind(&body, "restart")?;
                Ok(MemberCopyAttempt {
                    answer: MemberCopyAnswer::Restart,
                    context: None,
                })
            }
            other => Err(Error::engine(format!(
                "member copy request refused with status {}",
                other.as_u16()
            ))),
        }
    }
}

fn require_api(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::engine(
            "member copy protocol response is missing the API marker",
        ))
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalBody {
    api: String,
    kind: String,
}

fn require_kind(body: &[u8], expected: &str) -> Result<()> {
    let refusal: RefusalBody = serde_json::from_slice(body)
        .map_err(|error| Error::engine(format!("member copy refusal is malformed: {error}")))?;
    if refusal.api != MEMBER_COPY_API || refusal.kind != expected {
        return Err(Error::engine(
            "member copy refusal kind disagrees with the status",
        ));
    }
    Ok(())
}

impl MemberCopyTransport for ReqwestMemberCopyClient {
    fn request(
        &self,
        request: MemberCopyRequest,
        selection: &CredentialSelection,
    ) -> BoxFuture<'_, Result<MemberCopyAttempt>> {
        let selection = selection.clone();
        Box::pin(async move {
            if request.db_id != self.config.route_database_id {
                return Err(Error::engine(
                    "member copy request route disagrees with the adapter config",
                ));
            }
            if request.consumer != self.config.consumer {
                return Err(Error::engine(
                    "member copy request consumer disagrees with the adapter config",
                ));
            }
            let body = serde_json::to_vec(&serde_json::json!({
                "contract": MEMBER_COPY_API,
                "version": 1,
                "consumer": request.consumer,
                "installed_generation_id": request.installed_generation_id,
                "installed_scope_ref": request.installed_scope_ref,
            }))
            .map_err(|error| Error::engine(format!("member copy request serialises: {error}")))?;
            let response = self
                .http
                .post(self.start_url()?)
                .header(AUTHORIZATION, self.bearer(&selection)?)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|error| Error::engine(format!("member copy request failed: {error}")))?;
            self.outcome(response, &selection).await
        })
    }

    fn read_range(
        &self,
        context: &MemberCopyContext,
        handle: &str,
        start: u64,
        end: u64,
    ) -> BoxFuture<'_, Result<MemberCopyChunk>> {
        let context = context.clone();
        let handle = handle.to_owned();
        Box::pin(async move {
            self.confine_context(&context)?;
            let response = self
                .http
                .get(self.bytes_url(&handle)?)
                .header(AUTHORIZATION, self.bearer(context.selection())?)
                .header(RANGE, format!("bytes={start}-{end}"))
                .send()
                .await
                .map_err(|error| Error::engine(format!("member copy chunk failed: {error}")))?;
            let api_ok = Self::api_header(&response);
            match response.status() {
                StatusCode::PARTIAL_CONTENT => {
                    require_api(api_ok)?;
                    let headers = response.headers().clone();
                    let bytes = bounded_body(response, BINARY_MAX_CHUNK_BYTES).await?;
                    let (actual_start, actual_end, total_size) = parse_content_range(&headers)?;
                    let sha256 = parse_etag(&headers)?;
                    Ok(MemberCopyChunk::Bytes {
                        bytes,
                        start: actual_start,
                        end: actual_end,
                        total_size,
                        sha256,
                    })
                }
                StatusCode::NOT_FOUND => {
                    require_api(api_ok)?;
                    let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                    require_error_code(&body, "handle_not_found")?;
                    Ok(MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Expired))
                }
                StatusCode::CONFLICT => {
                    require_api(api_ok)?;
                    let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                    require_kind(&body, "restart")?;
                    Ok(MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Restart))
                }
                StatusCode::FORBIDDEN => {
                    require_api(api_ok)?;
                    let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                    Ok(MemberCopyChunk::Refused(
                        MemberCopyDownloadRefusal::Revoked {
                            cause: revoked_cause(&body)?,
                        },
                    ))
                }
                StatusCode::LOCKED => {
                    require_api(api_ok)?;
                    let body = bounded_body(response, MAX_OUTCOME_BYTES).await?;
                    require_kind(&body, "locked")?;
                    Ok(MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Locked))
                }
                other => Err(Error::engine(format!(
                    "member copy chunk refused with status {}",
                    other.as_u16()
                ))),
            }
        })
    }
}

async fn bounded_body(response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let max_u64 = max as u64;
    if let Some(length) = response.content_length() {
        if length > max_u64 {
            return Err(Error::engine("member copy response exceeded its bound"));
        }
    }
    // Stream and stop the moment the budget is exceeded, so a chunked response
    // (no Content-Length) or a false length cannot allocate without bound.
    let mut body: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| Error::engine(format!("member copy response read failed: {error}")))?;
        if (body.len() as u64).saturating_add(chunk.len() as u64) > max_u64 {
            return Err(Error::engine("member copy response exceeded its bound"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_content_range(headers: &HeaderMap) -> Result<(u64, u64, u64)> {
    let raw = headers
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Error::engine("member copy chunk is missing Content-Range"))?;
    let raw = raw
        .strip_prefix("bytes ")
        .ok_or_else(|| Error::engine("member copy Content-Range is malformed"))?;
    let (range, total) = raw
        .split_once('/')
        .ok_or_else(|| Error::engine("member copy Content-Range is malformed"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| Error::engine("member copy Content-Range is malformed"))?;
    let start: u64 = start
        .parse()
        .map_err(|_| Error::engine("member copy Content-Range start is invalid"))?;
    let end: u64 = end
        .parse()
        .map_err(|_| Error::engine("member copy Content-Range end is invalid"))?;
    let total: u64 = total
        .parse()
        .map_err(|_| Error::engine("member copy Content-Range total is invalid"))?;
    if end < start || total <= end {
        return Err(Error::engine("member copy Content-Range is inconsistent"));
    }
    Ok((start, end, total))
}

fn parse_etag(headers: &HeaderMap) -> Result<String> {
    let raw = headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Error::engine("member copy chunk is missing ETag"))?;
    let sha = raw.trim_matches('"');
    if sha.len() != 64 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::engine("member copy ETag is not a SHA-256 digest"));
    }
    Ok(sha.to_ascii_lowercase())
}

fn revoked_cause(body: &[u8]) -> Result<RevokedCause> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Revoked {
        api: String,
        kind: String,
        cause: String,
    }
    let revoked: Revoked = serde_json::from_slice(body)
        .map_err(|error| Error::engine(format!("member copy refusal is malformed: {error}")))?;
    if revoked.api != MEMBER_COPY_API || revoked.kind != "revoked" {
        return Err(Error::engine(
            "member copy revocation disagrees with the contract",
        ));
    }
    match revoked.cause.as_str() {
        "membership_ended" => Ok(RevokedCause::MembershipEnded),
        "role_changed" => Ok(RevokedCause::RoleChanged),
        "session_revoked" => Ok(RevokedCause::SessionRevoked),
        _ => Err(Error::engine("member copy revocation cause is unknown")),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    api: String,
    error_code: String,
}

fn require_error_code(body: &[u8], expected: &str) -> Result<()> {
    let error: ErrorBody = serde_json::from_slice(body)
        .map_err(|error| Error::engine(format!("member copy refusal is malformed: {error}")))?;
    if error.api != MEMBER_COPY_API || error.error_code != expected {
        return Err(Error::engine("member copy error disagrees with the status"));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OutcomeBody {
    Current {
        api: String,
        generation_id: String,
        scope_ref: String,
        ordinal: i64,
        content_digest: String,
        download_handle: String,
        manifest: ReplicaGenerationManifest,
    },
    Replace {
        api: String,
        generation_id: String,
        scope_ref: String,
        scope_changed: bool,
        ordinal: i64,
        content_digest: String,
        download_handle: String,
        manifest: ReplicaGenerationManifest,
    },
}

impl OutcomeBody {
    /// The contract marker carried in the body; must equal [`MEMBER_COPY_API`].
    fn api(&self) -> &str {
        match self {
            OutcomeBody::Current { api, .. } | OutcomeBody::Replace { api, .. } => api,
        }
    }

    fn into_answer(self) -> Result<(MemberCopyAnswer, String, ReplicaGenerationManifest)> {
        match self {
            OutcomeBody::Current {
                api: _,
                generation_id,
                scope_ref,
                ordinal,
                content_digest,
                download_handle,
                manifest,
            } => Ok((
                MemberCopyAnswer::Current {
                    generation_id,
                    scope_ref: scope_ref.clone(),
                    ordinal,
                    content_digest,
                    download_handle,
                    manifest: manifest.clone(),
                },
                scope_ref,
                manifest,
            )),
            OutcomeBody::Replace {
                api: _,
                generation_id,
                scope_ref,
                scope_changed,
                ordinal,
                content_digest,
                download_handle,
                manifest,
            } => Ok((
                MemberCopyAnswer::Replace {
                    generation_id,
                    scope_ref: scope_ref.clone(),
                    scope_changed,
                    ordinal,
                    content_digest,
                    download_handle,
                    manifest: manifest.clone(),
                },
                scope_ref,
                manifest,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::member_copy_transport::{test_consumer, CredentialSelection};

    /// A chunked (`Transfer-Encoding: chunked`, no `Content-Length`) 206 whose
    /// body exceeds the chunk bound must fail at the bound without buffering
    /// the remaining stream.
    #[tokio::test]
    async fn chunked_oversize_response_fails_at_bound() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let sha = "a".repeat(64);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 1024];
            let _ = socket.read(&mut buffer).await;
            let head = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Type: application/vnd.sqlite3\r\nx-native-member-copy-api: native.member-copy.v1\r\nContent-Range: bytes 0-0/100\r\nETag: \"{sha}\"\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            socket.write_all(head.as_bytes()).await.expect("head");
            let chunk = vec![0u8; 64 * 1024];
            for _ in 0..40 {
                socket
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .ok();
                socket.write_all(&chunk).await.ok();
                socket.write_all(b"\r\n").await.ok();
            }
        });

        let origin = format!("http://127.0.0.1:{}", addr.port());
        let config =
            MemberCopyClientConfig::new(&origin, "route-test", test_consumer()).expect("config");
        let client = ReqwestMemberCopyClient::new(config).expect("client");
        let context = MemberCopyContext::new(
            "acct".to_owned(),
            origin,
            "route-test".to_owned(),
            "ndb_0".to_owned(),
            test_consumer(),
            "scope".to_owned(),
            CredentialSelection::for_test(b"bearer"),
        );
        let error = client
            .read_range(&context, "handle", 0, 0)
            .await
            .expect_err("oversize chunked body must refuse");
        assert!(error.to_string().contains("bound"), "{error}");
        server.abort();
    }

    fn sample_manifest() -> ReplicaGenerationManifest {
        ReplicaGenerationManifest {
            contract: crate::replica_generation::REPLICA_GENERATION_CONTRACT.to_owned(),
            version: crate::replica_generation::REPLICA_GENERATION_VERSION,
            origin_database_id: "ndb_00000000000000000000000000000001".to_owned(),
            hosted_route_database_id: "route".to_owned(),
            captured_at: "2026-09-30T00:00:00Z".to_owned(),
            snapshot_completed_at: "2026-09-30T00:00:01Z".to_owned(),
            producer: crate::standby_snapshot::StandbySnapshotEngineIdentity {
                name: "native-ce".to_owned(),
                source_sha: "a".repeat(40),
                schema_version: 1,
                ddl_sha256: "b".repeat(64),
            },
            consumer: test_consumer(),
            bytes: crate::standby_snapshot::StandbySnapshotBytes {
                media_type: crate::standby_snapshot::STANDBY_SNAPSHOT_MEDIA_TYPE.to_owned(),
                size_bytes: 3,
                sha256: "0".repeat(64),
            },
            materialization: crate::standby_snapshot::StandbyGenerationMaterialization::Snapshot,
            scope: crate::holding::ReplicaScope::Member {
                scope_ref: "scope-a".to_owned(),
            },
            ordering: crate::replica_generation::ReplicaOrdering::Scoped { ordinal: 1 },
            holding: crate::holding::HoldingDisclosureV2::member("scope-a".to_owned(), 1),
            profile: crate::replica_generation::ReplicaProfile::MemberReadV1 {
                member_schema_digest: crate::schema::member_schema::member_schema_digest(),
            },
            content_digest: "d".repeat(64),
            own_writes: crate::replica_generation::ReplicaOwnWrites::not_computed(),
            frontier: None,
            schema_incomplete_for: Vec::new(),
        }
    }

    /// The server adds `body["api"]` to every success outcome; the parser must
    /// accept the server-shaped body and reject one missing the marker.
    #[test]
    fn server_shaped_success_body_requires_api_marker() {
        let value = serde_json::json!({
            "api": MEMBER_COPY_API,
            "kind": "current",
            "generation_id": "g",
            "scope_ref": "scope-a",
            "ordinal": 1,
            "content_digest": "d",
            "download_handle": "h",
            "manifest": sample_manifest(),
        });
        let body = serde_json::to_vec(&value).expect("body");
        let parsed: OutcomeBody = serde_json::from_slice(&body).expect("server-shaped body parses");
        assert_eq!(parsed.api(), MEMBER_COPY_API);

        let mut missing = value.clone();
        missing.as_object_mut().expect("object").remove("api");
        let bytes = serde_json::to_vec(&missing).expect("body");
        assert!(
            serde_json::from_slice::<OutcomeBody>(&bytes).is_err(),
            "a success body missing the api marker must reject"
        );
    }

    /// Refusal bodies must carry the api marker and the kind/error_code that
    /// matches the status; a generic proxy body is not a lifecycle signal.
    #[test]
    fn refusal_bodies_require_api_and_kind() {
        assert!(require_kind(
            br#"{"api":"native.member-copy.v1","kind":"locked"}"#,
            "locked"
        )
        .is_ok());
        assert!(require_kind(br#"{"kind":"locked"}"#, "locked").is_err());
        assert!(require_kind(
            br#"{"api":"native.member-copy.v1","kind":"restart"}"#,
            "locked"
        )
        .is_err());
        assert!(require_error_code(
            br#"{"api":"native.member-copy.v1","error_code":"handle_not_found"}"#,
            "handle_not_found"
        )
        .is_ok());
        assert!(require_error_code(
            br#"{"api":"native.member-copy.v1","error_code":"other"}"#,
            "handle_not_found"
        )
        .is_err());
        assert!(revoked_cause(
            br#"{"api":"native.member-copy.v1","kind":"revoked","cause":"session_revoked"}"#
        )
        .is_ok());
        assert!(revoked_cause(br#"{"kind":"revoked","cause":"session_revoked"}"#).is_err());
    }

    /// One canonical exact-origin representation; non-canonical forms are
    /// rejected by the standby exact-origin rule rather than silently rewritten.
    #[test]
    fn canonical_origin_is_exact_and_rejects_non_canonical_forms() {
        assert_eq!(
            canonical_origin("https://example.com").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_origin("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(canonical_origin("https://example.com/").is_err());
        assert!(canonical_origin("https://example.com:443").is_err());
        assert!(canonical_origin("https://Example.com").is_err());
    }

    /// A sealed context issued by another adapter (different origin/route/
    /// consumer) is refused before its retained bearer can be used, with no
    /// request sent.
    #[tokio::test]
    async fn read_range_rejects_foreign_context_before_any_get() {
        let config =
            MemberCopyClientConfig::new("http://127.0.0.1:1", "route-test", test_consumer())
                .expect("config");
        let client = ReqwestMemberCopyClient::new(config).expect("client");
        let foreign = MemberCopyContext::new(
            "acct".to_owned(),
            "http://127.0.0.1:2".to_owned(),
            "route-test".to_owned(),
            "ndb_0".to_owned(),
            test_consumer(),
            "scope".to_owned(),
            CredentialSelection::for_test(b"bearer"),
        );
        let error = client
            .read_range(&foreign, "handle", 0, 0)
            .await
            .expect_err("foreign context must refuse");
        assert!(error.to_string().contains("does not belong"), "{error}");

        let wrong_route = MemberCopyContext::new(
            "acct".to_owned(),
            "http://127.0.0.1:1".to_owned(),
            "other-route".to_owned(),
            "ndb_0".to_owned(),
            test_consumer(),
            "scope".to_owned(),
            CredentialSelection::for_test(b"bearer"),
        );
        assert!(client
            .read_range(&wrong_route, "handle", 0, 0)
            .await
            .is_err());
    }

    /// The request route/consumer must agree with the adapter config before any
    /// POST, rather than being silently ignored.
    #[tokio::test]
    async fn request_rejects_route_or_consumer_mismatch() {
        let config =
            MemberCopyClientConfig::new("http://127.0.0.1:1", "route-test", test_consumer())
                .expect("config");
        let client = ReqwestMemberCopyClient::new(config).expect("client");
        let selection = CredentialSelection::for_test(b"bearer");
        let mut request = MemberCopyRequest {
            db_id: "other".to_owned(),
            consumer: test_consumer(),
            installed_generation_id: None,
            installed_scope_ref: None,
        };
        assert!(client.request(request.clone(), &selection).await.is_err());
        request.db_id = "route-test".to_owned();
        request.consumer = StandbyConsumerIdentity {
            ddl_sha256: "9".repeat(64),
            ..test_consumer()
        };
        assert!(client.request(request, &selection).await.is_err());
    }
}
