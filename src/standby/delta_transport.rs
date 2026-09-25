//! Authenticated hosted authority act-delta transport.
//!
//! Slice D1 of cb551d7. This module is the **only** production path that can
//! mint a `TrustedAuthorityActDelta`. It has two halves that share one closed
//! wire contract:
//!
//! * the **authority half** ([`observe_authority_act_head`] and
//!   [`observe_authority_act_delta`]) reads the head and, when a cut is asked
//!   for, the thirteen act sections and thirteen companions from **one** read
//!   transaction and publishes a closed, bounded response. The caller supplies
//!   `F1` only; `F2` is whatever head the authority itself observed, so a client
//!   can never talk the authority into a different upper bound than the one its
//!   rows came from. These functions carry no authentication: the hosted
//!   operation that calls them enforces HostOwner footing and route binding.
//!
//! * the **client half** (`AuthorityActTransport`) reaches the hosted MCP
//!   endpoint over the same authenticated channel the whole-snapshot refresh
//!   already uses — exact HTTPS/loopback origin, refused redirects, bearer
//!   credential — and validates the response end to end before it builds the
//!   sealed witness the trust mint accepts.
//!
//! # The trust boundary
//!
//! P0's `content_sha256` is unsigned and any producer can recompute it: it is
//! an edit detector, never a signature or a MAC. Authenticity comes from the
//! transport: the bearer credential, the exact-origin pin, the route/origin
//! binding the authenticated server asserts, and TLS. This module therefore
//! treats the response as a *claim* and refuses to advance any coordinate
//! without checking all of:
//!
//! 1. strict JSON-RPC correlation (`jsonrpc`, `id`, no `error`, no partial
//!    `resultType`, `isError` false);
//! 2. a closed response struct (`deny_unknown_fields`, so duplicate known
//!    fields and unknown fields refuse at parse);
//! 3. the bounded HTTP response (`Content-Length` and streamed body ceilings);
//! 4. canonical standard base64 that decodes to exactly the bytes the outer
//!    digest covers;
//! 5. the outer SHA-256 over the exact decoded bytes;
//! 6. the inner P0 document (`validate_authority_act_delta`), including its own
//!    canonical-bytes and `content_sha256` checks;
//! 7. every carried cross-check: route database id, authority
//!    `origin_database_id`, `F1`, `F2`, and the inner `content_sha256`.
//!
//! Only then is `AuthenticatedAuthorityActDelta` built and handed to
//! `TrustedAuthorityActDelta::from_authenticated_transport`, whose witness type
//! is private to this module. There is deliberately no `authenticated` boolean,
//! no raw principal string, and no public constructor: a caller with raw
//! `ValidatedAuthorityActDelta` bytes cannot mint trust because it cannot build
//! the witness.
//!
//! # Bounds
//!
//! The response carries the delta as base64, and a tool with no text renderer
//! is framed by the executor as both a JSON `content` text block and
//! `structuredContent`, so the rendered raw body carries the structured
//! payload **twice**. `MAX_DELTA_BYTES` is therefore set well below the shared
//! 2 MiB MCP response ceiling: at 700,000 decoded bytes the 4/3 base64
//! expansion duplicated into both blocks stays under 2 MiB with envelope
//! headroom. `observe_authority_act_delta` also re-checks the exact structured
//! length against that ceiling, so a framing change cannot publish a response
//! the client would reject as a generic body-too-large error.
//!
//! The authority still materialises the **full** exact cut before it can know
//! its size; this is deliberately not a streaming or paging protocol. A cut
//! over the ceiling is refused with the whole-snapshot fallback message, which
//! is already the typed recovery the controller applies for a delta the
//! authority cannot express.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::standby::act_delta::{
    build_authority_act_delta, validate_authority_act_delta, AuthorityActDeltaHeadV1,
    ValidatedAuthorityActDelta,
};
use crate::standby::act_materialise::TrustedAuthorityActDelta;

/// Closed contract identity for the cheap head-probe response.
pub(crate) const AUTHORITY_ACT_HEAD_RESPONSE_CONTRACT: &str =
    "native.standby-authority-act-head-response.v1";
/// Closed contract identity for the exact-cut response.
pub(crate) const AUTHORITY_ACT_DELTA_RESPONSE_CONTRACT: &str =
    "native.standby-authority-act-delta-response.v1";
/// The only transport response version this module understands.
pub(crate) const AUTHORITY_ACT_RESPONSE_VERSION: u32 = 1;
/// The hosted executor both operations are reached through. The delta cut is a
/// host-owner full-corpus transfer, so it shares the accepted `export`
/// executor's permission shape.
pub(crate) const AUTHORITY_ACT_EXECUTOR: &str = "export";
/// The cheap head probe operation name.
pub(crate) const AUTHORITY_ACT_HEAD_OPERATION: &str = "authority_act_head";
/// The exact-cut operation name.
pub(crate) const AUTHORITY_ACT_DELTA_OPERATION: &str = "authority_act_delta";
/// The shared hosted MCP response ceiling, matching the snapshot refresh.
pub(crate) const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// A tool with no text renderer is framed by the shared protocol as both a
/// JSON text block (`content[0].text = structured.to_string()`) and
/// `structuredContent`. The rendered executor response therefore carries the
/// structured payload **twice**, so a decoded-bytes ceiling alone does not
/// bound the raw HTTP body.
const RENDERED_DUPLICATION: usize = 2;
/// Envelope, executor metadata and `run_context` headroom reserved on top of
/// the duplicated structured payload. Far above any observed framing.
const RENDERED_ENVELOPE_MARGIN: usize = 64 * 1024;
/// A conservative decoded-byte ceiling that, after the standard 4/3 base64
/// expansion and the no-renderer duplication above, keeps the fully rendered
/// executor response under [`MAX_RESPONSE_BYTES`]. A larger exact cut is
/// refused with the whole-snapshot fallback rather than paged. The authority
/// still materialises the full cut before this refusal; there is deliberately
/// no streaming or paging redesign.
pub(crate) const MAX_DELTA_BYTES: usize = 700_000;
/// Bounded route identifier length; the catalog owns the real grammar.
const MAX_ROUTE_DATABASE_ID_BYTES: usize = 200;

/// The conservative upper bound on the raw rendered executor response for a
/// structured payload of `structured_len` bytes. It accounts for the two copies
/// the shared protocol emits for a tool with no renderer and the envelope
/// margin. `observe_authority_act_delta` refuses a response whose decoded delta
/// makes this bound exceed [`MAX_RESPONSE_BYTES`], so oversize reliably returns
/// the intended fallback refusal instead of a generic client body-too-large
/// error.
fn rendered_response_upper_bound(structured_len: usize) -> usize {
    structured_len
        .saturating_mul(RENDERED_DUPLICATION)
        .saturating_add(RENDERED_ENVELOPE_MARGIN)
}

/// The authority's answer to a cheap head probe. Closed: an unknown field, a
/// duplicate field, or an unexpected contract/version refuses.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityActHeadResponseV1 {
    contract: String,
    version: u32,
    route_database_id: String,
    head: AuthorityActDeltaHeadV1,
    /// The executor annotates every result with run correlation. It is not
    /// authority evidence, but `deny_unknown_fields` must admit it or no real
    /// response parses. Never serialized by the authority itself.
    #[serde(
        default,
        rename = "run_context",
        skip_serializing_if = "Value::is_null"
    )]
    _run_context: Value,
}

impl AuthorityActHeadResponseV1 {
    pub fn route_database_id(&self) -> &str {
        &self.route_database_id
    }

    /// The replicated authority-head evidence, exactly the coordinate set the
    /// delta wire carries (the advisory engine schema is not replicated).
    pub(crate) fn head(&self) -> &AuthorityActDeltaHeadV1 {
        &self.head
    }
}

/// The authority's answer to an exact cut. Closed for the same reason.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityActDeltaResponseV1 {
    contract: String,
    version: u32,
    route_database_id: String,
    origin_database_id: String,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    content_sha256: String,
    outer_sha256: String,
    data_base64: String,
    #[serde(
        default,
        rename = "run_context",
        skip_serializing_if = "Value::is_null"
    )]
    _run_context: Value,
}

impl AuthorityActDeltaResponseV1 {
    pub fn route_database_id(&self) -> &str {
        &self.route_database_id
    }

    pub fn origin_database_id(&self) -> &str {
        &self.origin_database_id
    }

    #[allow(clippy::wrong_self_convention)] // mirrors AuthorityActCut::from_exclusive_act
    pub fn from_exclusive_act(&self) -> i64 {
        self.from_exclusive_act
    }

    pub fn to_inclusive_act(&self) -> i64 {
        self.to_inclusive_act
    }

    #[cfg(test)]
    pub(crate) fn outer_sha256(&self) -> &str {
        &self.outer_sha256
    }

    #[cfg(test)]
    pub(crate) fn data_base64(&self) -> &str {
        &self.data_base64
    }
}

fn validate_route_database_id(route_database_id: &str) -> Result<()> {
    require(
        !route_database_id.is_empty()
            && route_database_id.len() <= MAX_ROUTE_DATABASE_ID_BYTES
            && !route_database_id
                .chars()
                .any(|value| value.is_whitespace() || value.is_control() || value == '/'),
        "authority act route database id is invalid",
    )
}

/// The cheap authority head observation. It reads exactly one consistent head
/// and returns the replicated coordinate set; it does not create a delta,
/// handle, or snapshot.
pub async fn observe_authority_act_head(
    db: &crate::Db,
    route_database_id: &str,
) -> Result<AuthorityActHeadResponseV1> {
    validate_route_database_id(route_database_id)?;
    let head = crate::standby::authority_probe::read_authority_act_head(db).await?;
    Ok(AuthorityActHeadResponseV1 {
        contract: AUTHORITY_ACT_HEAD_RESPONSE_CONTRACT.into(),
        version: AUTHORITY_ACT_RESPONSE_VERSION,
        route_database_id: route_database_id.to_string(),
        head: AuthorityActDeltaHeadV1::from_head(&head),
        _run_context: Value::Null,
    })
}

/// The exact authority cut. The caller supplies `F1` only: the authority reads
/// its own head and cuts `(F1, head]` from that same read transaction, so the
/// head, the thirteen act sections and the thirteen companions are one
/// observation and the client cannot assert `F2`. An empty interval (`F1`
/// already at the head) yields the canonical empty delta.
///
/// # Bounds and the oversize refusal
///
/// The authority materialises the **full** cut before it can know its size;
/// this is deliberately not a streaming or paging protocol. Two ceilings then
/// refuse an oversized result with the same whole-snapshot fallback:
///
/// 1. `MAX_DELTA_BYTES` bounds the decoded canonical delta, chosen so the
///    standard 4/3 base64 expansion plus the no-renderer duplication in the
///    rendered executor frame stays under `MAX_RESPONSE_BYTES`;
/// 2. `rendered_response_upper_bound` re-checks the actual structured payload
///    against the raw-body ceiling, so even a change to the framing cannot make
///    the authority publish a response the client would reject as a generic
///    body-too-large error.
///
/// A refusal is an explicit engine error naming the whole-snapshot fallback;
/// the controller (not this module) decides to retry as a full snapshot.
pub async fn observe_authority_act_delta(
    db: &crate::Db,
    route_database_id: &str,
    from_exclusive_act: i64,
) -> Result<AuthorityActDeltaResponseV1> {
    validate_route_database_id(route_database_id)?;
    require(
        from_exclusive_act >= 0,
        "authority act delta lower bound must be non-negative",
    )?;

    let mut tx = db.pool().begin().await?;
    let outcome = read_cut_on(&mut tx, from_exclusive_act).await;
    let rollback = tx.rollback().await;
    let (head_act, origin_database_id, bytes) = match (outcome, rollback) {
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error.into()),
        (Ok(value), Ok(())) => value,
    };

    if bytes.len() > MAX_DELTA_BYTES {
        return Err(Error::engine(
            "authority act delta exceeds the bounded transport ceiling; take a whole snapshot",
        ));
    }

    // Re-validate the exact bytes we are about to publish, so the carried
    // content digest is the one the authority itself proved.
    let validated = validate_authority_act_delta(&bytes)?;
    let content_sha256 = validated.content_sha256().to_string();
    let outer_sha256 = hex::encode(Sha256::digest(&bytes));
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    let response = AuthorityActDeltaResponseV1 {
        contract: AUTHORITY_ACT_DELTA_RESPONSE_CONTRACT.into(),
        version: AUTHORITY_ACT_RESPONSE_VERSION,
        route_database_id: route_database_id.to_string(),
        origin_database_id,
        from_exclusive_act,
        to_inclusive_act: head_act,
        content_sha256,
        outer_sha256,
        data_base64,
        _run_context: Value::Null,
    };

    // The exact structured length the executor will frame (twice) into the raw
    // response, so the published bytes are guaranteed to fit the client's
    // raw-body ceiling rather than failing there as a generic transport error.
    let structured_len = serde_json::to_vec(&response)?.len();
    if rendered_response_upper_bound(structured_len) > MAX_RESPONSE_BYTES {
        return Err(Error::engine(
            "authority act delta exceeds the bounded transport ceiling; take a whole snapshot",
        ));
    }

    Ok(response)
}

/// Read the head and the exact cut on one open connection inside one read
/// transaction, then build the canonical delta. Returns the observed head act,
/// the portable origin, and the exact bytes.
async fn read_cut_on(
    conn: &mut sqlx::SqliteConnection,
    from_exclusive_act: i64,
) -> Result<(i64, String, Vec<u8>)> {
    let head = crate::standby::authority_probe::read_authority_act_head_on(conn).await?;
    require(
        from_exclusive_act <= head.head_act,
        "authority act delta lower bound is beyond the observed authority head",
    )?;
    let cut =
        crate::standby::act_cut::read_authority_act_cut_on(conn, from_exclusive_act, head.head_act)
            .await?;
    let bytes = build_authority_act_delta(&cut)?;
    Ok((head.head_act, head.origin_database_id, bytes))
}

/// The sealed witness that the exact bytes came from the authenticated hosted
/// transport and were validated end to end.
///
/// Every field is private to this module and there is no constructor, no
/// `Deserialize`, and no `Clone`: the only way to obtain one is a successful
/// [`AuthorityActTransport::delta`] call. That is what makes the trust mint
/// impossible from any other production path.
pub(crate) struct AuthenticatedAuthorityActDelta {
    validated: ValidatedAuthorityActDelta,
    authority_origin: String,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
}

impl AuthenticatedAuthorityActDelta {
    /// Consume the witness into the parts the trust mint re-checks.
    pub(crate) fn into_parts(self) -> (ValidatedAuthorityActDelta, String, i64, i64) {
        (
            self.validated,
            self.authority_origin,
            self.from_exclusive_act,
            self.to_inclusive_act,
        )
    }
}

type AuthorityCallFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>>;

/// The one injected HTTP seam. Production uses [`HttpAuthorityActClient`]; tests
/// script it without a socket. It returns the raw response body bytes, and the
/// caller owns every ceiling and parse decision.
trait AuthorityActHttpClient: Send + Sync {
    fn call(&self, endpoint: String, bearer: String, body: Value) -> AuthorityCallFuture;
}

struct HttpAuthorityActClient {
    client: reqwest::Client,
}

impl HttpAuthorityActClient {
    fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| {
                Error::engine(format!("cannot build authority act client: {error}"))
            })?;
        Ok(Self { client })
    }
}

impl AuthorityActHttpClient for HttpAuthorityActClient {
    fn call(&self, endpoint: String, bearer: String, body: Value) -> AuthorityCallFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .post(&endpoint)
                .bearer_auth(&bearer)
                .header(
                    reqwest::header::ACCEPT,
                    "application/json, text/event-stream",
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header("MCP-Protocol-Version", crate::mcp::PROTOCOL_VERSION)
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", AUTHORITY_ACT_EXECUTOR)
                .json(&body)
                .send()
                .await
                .map_err(|_| Error::engine("hosted authority act request failed"))?;
            if matches!(response.status().as_u16(), 401 | 403) {
                return Err(Error::auth("hosted authority act credential refused"));
            }
            if !response.status().is_success() {
                return Err(Error::engine(format!(
                    "hosted authority act HTTP status {}",
                    response.status()
                )));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                return Err(Error::engine("hosted authority act response too large"));
            }
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| Error::engine("hosted authority act response was interrupted"))?
            {
                if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(Error::engine("hosted authority act response too large"));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
    }
}

/// The authenticated authority act client. Construct it once per pinned
/// authority origin/route/origin identity; it never accepts a route from the
/// response itself.
pub(crate) struct AuthorityActTransport {
    endpoint: String,
    bearer: String,
    expected_route_database_id: String,
    expected_origin_database_id: String,
    client: Arc<dyn AuthorityActHttpClient>,
}

impl AuthorityActTransport {
    /// Bind the transport to an exact hosted origin, route, and portable origin
    /// identity. The origin must be an exact HTTPS origin (HTTP only for
    /// loopback), and the credential must be non-empty with no whitespace.
    pub(crate) fn new(
        hosted_origin: &str,
        hosted_route_database_id: &str,
        expected_origin_database_id: &str,
        bearer: &str,
    ) -> Result<Self> {
        super::refresh::validate_exact_origin(hosted_origin)?;
        validate_route_database_id(hosted_route_database_id)?;
        require(
            crate::identity::is_database_id(expected_origin_database_id),
            "authority act expected origin database id is invalid",
        )?;
        require(
            !bearer.is_empty() && !bearer.chars().any(char::is_whitespace),
            "authority act credential is empty or contains whitespace",
        )?;
        let endpoint = format!(
            "{}/mcp/{}",
            hosted_origin,
            percent_encoding::utf8_percent_encode(
                hosted_route_database_id,
                percent_encoding::NON_ALPHANUMERIC
            )
        );
        Ok(Self {
            endpoint,
            bearer: bearer.to_string(),
            expected_route_database_id: hosted_route_database_id.to_string(),
            expected_origin_database_id: expected_origin_database_id.to_string(),
            client: Arc::new(HttpAuthorityActClient::new()?),
        })
    }

    #[cfg(test)]
    fn with_client(
        hosted_origin: &str,
        hosted_route_database_id: &str,
        expected_origin_database_id: &str,
        bearer: &str,
        client: Arc<dyn AuthorityActHttpClient>,
    ) -> Result<Self> {
        let mut transport = Self::new(
            hosted_origin,
            hosted_route_database_id,
            expected_origin_database_id,
            bearer,
        )?;
        transport.client = client;
        Ok(transport)
    }

    /// Cheap probe: the authority's replicated act-head coordinates. Nothing is
    /// trusted from this response beyond a route/origin-bound observation.
    pub(crate) async fn head(&self) -> Result<AuthorityActHeadResponseV1> {
        let body = authority_act_call(AUTHORITY_ACT_HEAD_OPERATION, json!({}));
        let response = self.call::<AuthorityActHeadResponseV1>(body).await?;
        require(
            response.contract == AUTHORITY_ACT_HEAD_RESPONSE_CONTRACT,
            "unknown authority act head response contract",
        )?;
        require(
            response.version == AUTHORITY_ACT_RESPONSE_VERSION,
            "unknown authority act head response version",
        )?;
        require(
            response.route_database_id == self.expected_route_database_id,
            "authority act head response route database id does not match the authenticated route",
        )?;
        require(
            response.head.origin_database_id() == self.expected_origin_database_id,
            "authority act head response origin does not match the pinned authority origin",
        )?;
        response.head.validate()?;
        Ok(response)
    }

    /// Exact cut: fetch, validate, and mint a trusted delta.
    pub(crate) async fn delta(&self, from_exclusive_act: i64) -> Result<TrustedAuthorityActDelta> {
        let body = authority_act_call(
            AUTHORITY_ACT_DELTA_OPERATION,
            json!({ "from_exclusive_act": from_exclusive_act }),
        );
        let response = self.call::<AuthorityActDeltaResponseV1>(body).await?;

        require(
            response.contract == AUTHORITY_ACT_DELTA_RESPONSE_CONTRACT,
            "unknown authority act delta response contract",
        )?;
        require(
            response.version == AUTHORITY_ACT_RESPONSE_VERSION,
            "unknown authority act delta response version",
        )?;
        require(
            response.route_database_id == self.expected_route_database_id,
            "authority act delta response route database id does not match the authenticated route",
        )?;
        require(
            response.origin_database_id == self.expected_origin_database_id,
            "authority act delta response origin does not match the pinned authority origin",
        )?;
        require(
            response.from_exclusive_act == from_exclusive_act,
            "authority act delta response lower bound disagrees with the request",
        )?;
        require(
            response.from_exclusive_act >= 0
                && response.to_inclusive_act >= response.from_exclusive_act,
            "authority act delta response bounds are invalid",
        )?;

        let bytes = decode_canonical_delta(&response.data_base64)?;
        require(
            response.outer_sha256 == hex::encode(Sha256::digest(&bytes)),
            "authority act delta outer digest does not cover the carried bytes",
        )?;

        let validated = validate_authority_act_delta(&bytes)?;
        require(
            response.content_sha256 == validated.content_sha256(),
            "authority act delta content digest disagrees with the carried document",
        )?;
        require(
            response.origin_database_id == validated.authority_head().origin_database_id(),
            "authority act delta response origin disagrees with the carried head",
        )?;
        require(
            response.from_exclusive_act == validated.act_cut().from_exclusive_act(),
            "authority act delta response lower bound disagrees with the carried cut",
        )?;
        require(
            response.to_inclusive_act == validated.act_cut().to_inclusive_act(),
            "authority act delta response upper bound disagrees with the carried cut",
        )?;
        require(
            response.to_inclusive_act == validated.authority_head().head_act(),
            "authority act delta response upper bound disagrees with the carried head",
        )?;

        let witness = AuthenticatedAuthorityActDelta {
            validated,
            authority_origin: response.origin_database_id,
            from_exclusive_act: response.from_exclusive_act,
            to_inclusive_act: response.to_inclusive_act,
        };
        TrustedAuthorityActDelta::from_authenticated_transport(witness)
    }

    /// POST one executor call and parse its closed `structuredContent` directly
    /// into `T`, so serde rejects unknown and duplicate fields at the exact raw
    /// JSON bytes rather than after a `Value` round trip.
    async fn call<T: DeserializeOwned>(&self, body: Value) -> Result<T> {
        let bytes = self
            .client
            .call(self.endpoint.clone(), self.bearer.clone(), body)
            .await?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Error::engine("hosted authority act response too large"));
        }
        let envelope: RpcEnvelope<T> = serde_json::from_slice(&bytes).map_err(|error| {
            Error::engine(format!(
                "hosted authority act returned an invalid protocol response: {error}"
            ))
        })?;
        if envelope.jsonrpc != "2.0" || envelope.id != json!(1) {
            return Err(Error::engine(
                "hosted authority act response correlation mismatch",
            ));
        }
        if let Some(error) = envelope.error {
            return Err(Error::engine(format!(
                "hosted authority act tool call was refused ({})",
                error.code
            )));
        }
        let result = envelope
            .result
            .ok_or_else(|| Error::engine("hosted authority act omitted its tool result"))?;
        let incomplete = result
            .result_type
            .as_deref()
            .is_some_and(|kind| kind != "complete");
        if result.is_error || incomplete {
            return Err(Error::engine("hosted authority act tool reported failure"));
        }
        result
            .structured_content
            .ok_or_else(|| Error::engine("hosted authority act omitted structured content"))
    }
}

/// Decode canonical standard base64 exactly once. A re-encode mismatch refuses
/// whitespace, missing/extra padding, and non-canonical trailing bits, so the
/// decoded bytes are the only bytes the response can cover.
fn decode_canonical_delta(data_base64: &str) -> Result<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .map_err(|_| Error::engine("authority act delta is not valid base64"))?;
    if bytes.len() > MAX_DELTA_BYTES {
        return Err(Error::engine(
            "authority act delta exceeds the bounded transport ceiling",
        ));
    }
    if base64::engine::general_purpose::STANDARD.encode(&bytes) != data_base64 {
        return Err(Error::engine("authority act delta base64 is not canonical"));
    }
    Ok(bytes)
}

fn authority_act_call(operation: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": AUTHORITY_ACT_EXECUTOR,
            "arguments": {
                "operation": operation,
                "arguments": arguments,
            },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {
                    "name": "native-standby-delta-transport",
                    "version": crate::engine_version_string(),
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope<T> {
    jsonrpc: String,
    id: Value,
    result: Option<RpcToolResult<T>>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcToolResult<T> {
    #[serde(rename = "content")]
    _content: Vec<Value>,
    #[serde(rename = "structuredContent")]
    structured_content: Option<T>,
    #[serde(rename = "isError")]
    is_error: bool,
    #[serde(default, rename = "resultType")]
    result_type: Option<String>,
    #[serde(default, rename = "_meta")]
    _meta: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: i64,
    #[serde(rename = "message")]
    _message: String,
    #[serde(default)]
    _data: Value,
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::engine(message))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::standby::authority_probe::read_authority_act_head;

    const ROUTE: &str = "route-1";
    const RECORD_ID: &str = "1a7e4000-0000-4000-8000-0000000000d1";
    const SECOND_RECORD_ID: &str = "1a7e4000-0000-4000-8000-0000000000d2";

    async fn fresh_authority() -> crate::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    async fn append_record(db: &crate::Db, record_id: &str, name: &str) {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    async fn origin(db: &crate::Db) -> String {
        crate::identity::database_id(db).await.unwrap()
    }

    fn envelope(structured: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [],
                "structuredContent": structured,
                "isError": false,
                "resultType": "complete",
                "_meta": {}
            }
        }))
        .unwrap()
    }

    fn delta_envelope(response: &AuthorityActDeltaResponseV1) -> Value {
        serde_json::to_value(response).unwrap()
    }

    struct ScriptedClient {
        raw: Mutex<Vec<u8>>,
    }

    impl ScriptedClient {
        fn new(raw: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                raw: Mutex::new(raw),
            })
        }
    }

    impl AuthorityActHttpClient for ScriptedClient {
        fn call(&self, _endpoint: String, _bearer: String, _body: Value) -> AuthorityCallFuture {
            let raw = self.raw.lock().unwrap().clone();
            Box::pin(async move { Ok(raw) })
        }
    }

    async fn real_authority() -> crate::Db {
        let db = fresh_authority().await;
        append_record(&db, RECORD_ID, "transport authority").await;
        db
    }

    /// `TrustedAuthorityActDelta` is deliberately not `Debug`, so tests cannot
    /// call `unwrap_err`; a refusal carries only its safe message.
    async fn refusal_message(transport: &AuthorityActTransport, from: i64) -> String {
        match transport.delta(from).await {
            Ok(_) => panic!("delta must refuse"),
            Err(error) => error.to_string(),
        }
    }

    #[tokio::test]
    async fn server_observes_head_and_cut_in_one_snapshot_without_a_client_f2() {
        let db = fresh_authority().await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, RECORD_ID, "one act cut").await;
        let head = read_authority_act_head(&db).await.unwrap();
        let origin = head.origin_database_id.clone();

        // The only cut request parameter is F1: F2 is the head the authority
        // itself observed. There is no parameter through which a client could
        // name a different upper bound.
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        assert_eq!(response.route_database_id(), ROUTE);
        assert_eq!(response.origin_database_id(), origin);
        assert_eq!(response.from_exclusive_act(), base);
        assert_eq!(response.to_inclusive_act(), head.head_act);
        assert_eq!(
            response.outer_sha256(),
            hex::encode(Sha256::digest(
                base64::engine::general_purpose::STANDARD
                    .decode(response.data_base64())
                    .unwrap()
            ))
        );
        // The published bytes are the same canonical bytes the authority builds
        // from its own one-observation cut.
        let cut = crate::standby::act_cut::read_authority_act_cut(&db, base, head.head_act)
            .await
            .unwrap();
        let expected = build_authority_act_delta(&cut).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(response.data_base64())
                .unwrap(),
            expected
        );
        db.close().await;
    }

    #[tokio::test]
    async fn server_empty_interval_is_the_canonical_empty_delta() {
        let db = real_authority().await;
        let head_act = read_authority_act_head(&db).await.unwrap().head_act;
        let response = observe_authority_act_delta(&db, ROUTE, head_act)
            .await
            .unwrap();
        assert_eq!(response.from_exclusive_act(), head_act);
        assert_eq!(response.to_inclusive_act(), head_act);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(response.data_base64())
            .unwrap();
        let validated = validate_authority_act_delta(&bytes).unwrap();
        assert_eq!(
            validated.act_cut().from_exclusive_act(),
            validated.act_cut().to_inclusive_act()
        );
        db.close().await;
    }

    #[tokio::test]
    async fn server_refuses_a_lower_bound_beyond_the_head() {
        let db = real_authority().await;
        let head_act = read_authority_act_head(&db).await.unwrap().head_act;
        let error = observe_authority_act_delta(&db, ROUTE, head_act + 1)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("beyond the observed"), "{error}");
        db.close().await;
    }

    #[tokio::test]
    async fn client_accepts_the_exact_authenticated_delta() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "client accept").await;
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        let received = base64::engine::general_purpose::STANDARD
            .decode(response.data_base64())
            .unwrap();

        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            ScriptedClient::new(envelope(delta_envelope(&response))),
        )
        .unwrap();
        let trusted = transport.delta(base).await.unwrap();
        assert_eq!(trusted.authority_origin(), origin);
        assert_eq!(trusted.from_exclusive_act(), base);
        assert_eq!(trusted.to_inclusive_act(), response.to_inclusive_act());
        assert_eq!(
            trusted.canonical_bytes().unwrap(),
            received,
            "the trusted wrapper's immutable bytes must equal the received decoded bytes"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn client_refuses_route_origin_bounds_and_digest_drift() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "client drift").await;
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        let to = response.to_inclusive_act();

        let mut cases: Vec<(&str, Value)> = Vec::new();
        let mut wrong_route = delta_envelope(&response);
        wrong_route["route_database_id"] = json!("route-2");
        cases.push(("route", wrong_route));

        let mut wrong_origin = delta_envelope(&response);
        wrong_origin["origin_database_id"] = json!("ndb_0123456789abcdef0123456789abcdef");
        cases.push(("origin", wrong_origin));

        let mut lower = delta_envelope(&response);
        lower["from_exclusive_act"] = json!(base + 1);
        cases.push(("lower", lower));

        let mut upper = delta_envelope(&response);
        upper["to_inclusive_act"] = json!(to + 1);
        cases.push(("upper", upper));

        let mut inner = delta_envelope(&response);
        inner["content_sha256"] = json!("f".repeat(64));
        cases.push(("inner digest", inner));

        let mut outer = delta_envelope(&response);
        outer["outer_sha256"] = json!("f".repeat(64));
        cases.push(("outer digest", outer));

        for (label, value) in cases {
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                ScriptedClient::new(envelope(value)),
            )
            .unwrap();
            let error = refusal_message(&transport, base).await;
            assert!(!error.contains("wire-secret"), "{label}: {error}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn client_refuses_noncanonical_base64_unknown_and_duplicate_fields() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "client shapes").await;
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();

        let mut whitespace = delta_envelope(&response);
        whitespace["data_base64"] = json!(format!("{}\n", response.data_base64()));
        let mut unknown = delta_envelope(&response);
        unknown["future_coordinate"] = json!(1);
        let mut unknown_head = delta_envelope(&response);
        unknown_head["authority_head_unknown"] = json!(1);

        let duplicate = {
            let text = String::from_utf8(envelope(delta_envelope(&response))).unwrap();
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                .into_bytes()
        };

        for (label, raw) in [
            ("whitespace base64", envelope(whitespace)),
            ("unknown field", envelope(unknown)),
            ("unknown extra field", envelope(unknown_head)),
            ("duplicate field", duplicate),
        ] {
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                ScriptedClient::new(raw),
            )
            .unwrap();
            assert!(transport.delta(base).await.is_err(), "{label} must refuse");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn client_refuses_protocol_faults_and_oversize_bodies() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "client protocol").await;
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        let structured = delta_envelope(&response);

        let mut wrong_id = envelope(structured.clone());
        let text = String::from_utf8(wrong_id.clone()).unwrap();
        wrong_id = text.replacen("\"id\":1", "\"id\":2", 1).into_bytes();
        let rpc_error = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "refused"}
        }))
        .unwrap();
        let is_error = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [],
                "structuredContent": structured.clone(),
                "isError": true,
                "resultType": "complete",
                "_meta": {}
            }
        }))
        .unwrap();
        let partial = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [],
                "structuredContent": structured,
                "isError": false,
                "resultType": "partial",
                "_meta": {}
            }
        }))
        .unwrap();
        let missing = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [], "isError": false, "resultType": "complete", "_meta": {}}
        }))
        .unwrap();
        let oversize = vec![b' '; MAX_RESPONSE_BYTES + 1];

        for (label, raw) in [
            ("id mismatch", wrong_id),
            ("rpc error", rpc_error),
            ("isError", is_error),
            ("partial", partial),
            ("missing structured content", missing),
            ("oversize", oversize),
        ] {
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                ScriptedClient::new(raw),
            )
            .unwrap();
            let error = refusal_message(&transport, base).await;
            assert!(!error.contains("wire-secret"), "{label}: {error}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn head_probe_is_closed_and_bound_to_route_and_origin() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let response = observe_authority_act_head(&db, ROUTE).await.unwrap();
        let value = serde_json::to_value(&response).unwrap();

        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            ScriptedClient::new(envelope(value.clone())),
        )
        .unwrap();
        let head = transport.head().await.unwrap();
        assert_eq!(head.route_database_id(), ROUTE);
        assert_eq!(
            head.head().origin_database_id(),
            origin,
            "the head evidence carries the pinned portable origin"
        );

        let mut unknown = value.clone();
        unknown["future_coordinate"] = json!(1);
        let mut wrong_route = value;
        wrong_route["route_database_id"] = json!("route-3");
        for raw in [envelope(unknown), envelope(wrong_route)] {
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                ScriptedClient::new(raw),
            )
            .unwrap();
            assert!(transport.head().await.is_err());
        }
        db.close().await;
    }

    #[tokio::test]
    async fn trust_mint_rechecks_carried_origin_and_bounds() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "trust recheck").await;
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(response.data_base64())
            .unwrap();
        let validated = validate_authority_act_delta(&bytes).unwrap();
        let to = validated.act_cut().to_inclusive_act();

        // A witness exists only inside this module; production cannot build
        // one. Even a witness is re-checked, so a carried lower bound that
        // disagrees with its bytes cannot mint trust.
        let bad = AuthenticatedAuthorityActDelta {
            validated: validate_authority_act_delta(&bytes).unwrap(),
            authority_origin: origin.clone(),
            from_exclusive_act: base + 1,
            to_inclusive_act: to,
        };
        assert!(TrustedAuthorityActDelta::from_authenticated_transport(bad).is_err());

        let good = AuthenticatedAuthorityActDelta {
            validated,
            authority_origin: origin,
            from_exclusive_act: base,
            to_inclusive_act: to,
        };
        let trusted = TrustedAuthorityActDelta::from_authenticated_transport(good).unwrap();
        assert_eq!(trusted.canonical_bytes().unwrap(), bytes);
        db.close().await;
    }

    #[tokio::test]
    async fn http_client_refuses_redirect_and_auth_and_never_echoes_the_credential() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        db.close().await;

        for status_line in ["302 Found", "401 Unauthorized"] {
            let port = stub_http(status_line, "{\"error\":\"no\"}").await;
            let transport = AuthorityActTransport::new(
                &format!("http://127.0.0.1:{port}"),
                ROUTE,
                &origin,
                "wire-secret",
            )
            .unwrap();
            let error = transport.head().await.unwrap_err().to_string();
            assert!(!error.contains("wire-secret"), "{status_line}: {error}");
        }
    }

    async fn stub_http(status_line: &'static str, body: &'static str) -> u16 {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await;
            let response = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        port
    }

    /// A native authority source for the executor seam: it answers with the
    /// same response builder the hosted runtime wires, so the executor frames
    /// genuine authority bytes rather than a fixture.
    struct NativeAuthorityActSource {
        db: crate::Db,
    }

    impl crate::mcp::AuthorityActSource for NativeAuthorityActSource {
        fn head(
            &self,
            _db: crate::Db,
            _caller: crate::mcp::Caller,
        ) -> futures::future::BoxFuture<'static, Result<AuthorityActHeadResponseV1>> {
            let db = self.db.clone();
            Box::pin(async move { observe_authority_act_head(&db, ROUTE).await })
        }

        fn delta(
            &self,
            _db: crate::Db,
            _caller: crate::mcp::Caller,
            request: crate::mcp::AuthorityActDeltaRequest,
        ) -> futures::future::BoxFuture<'static, Result<AuthorityActDeltaResponseV1>> {
            let db = self.db.clone();
            Box::pin(async move {
                observe_authority_act_delta(&db, ROUTE, request.from_exclusive_act).await
            })
        }
    }

    async fn append_large_record(db: &crate::Db, record_id: &str, body_len: usize) {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "large authority act",
                    "body": "x".repeat(body_len),
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    /// Serve exactly one real `ExecutorPrototypeStdioServer` HTTP round trip.
    /// The client's own request body reaches the executor, and the client parses
    /// the executor's rendered response bytes. The raw response body is sent
    /// back on the receiver so a test can assert the actual framing.
    async fn serve_executor_once(
        server: crate::mcp::ExecutorPrototypeStdioServer,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let body = read_http_body(&mut stream).await;
            let request: Value = serde_json::from_slice(&body).unwrap();
            let response = server
                .handle_message(request)
                .await
                .expect("the executor surface must answer a tools/call");
            let bytes = serde_json::to_vec(&response).unwrap();
            let _ = sender.send(bytes.clone());
            write_http_bytes(&mut stream, &bytes).await;
        });
        (port, receiver)
    }

    async fn read_http_body(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                return Vec::new();
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buffer[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let lower = line.to_ascii_lowercase();
                        lower
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if buffer.len() >= end + 4 + length {
                    return buffer[end + 4..end + 4 + length].to_vec();
                }
            }
        }
    }

    async fn write_http_bytes(stream: &mut tokio::net::TcpStream, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            bytes.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Regression: drive the real executor surface end to end over loopback
    /// HTTP. The client sends its own executor request, the executor dispatches
    /// the real authority source and frames the response (including the
    /// no-renderer `content`/`structuredContent` duplication), and the client
    /// parses those exact bytes and mints a trusted delta whose immutable
    /// canonical bytes equal the received decoded bytes.
    #[tokio::test]
    async fn client_parses_a_real_executor_surface_authority_delta() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        // A non-empty cut: `real_authority` appended one act, and a lower bound
        // of zero carries it.
        let base = 0;
        let expected = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        let received = base64::engine::general_purpose::STANDARD
            .decode(expected.data_base64())
            .unwrap();

        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        crate::mcp::register_authority_act_tools(
            &mut registry,
            Arc::new(NativeAuthorityActSource { db: db.clone() }),
        )
        .unwrap();
        let server = crate::mcp::ExecutorPrototypeStdioServer::new(
            Arc::new(registry),
            db.clone(),
            crate::mcp::Caller::authenticated("authority-act-real-surface")
                .with_hosting_context("host:authority-act-real-surface", ROUTE)
                .with_hosting_owner(true),
            None,
        )
        .await
        .unwrap();

        let (port, raw_receiver) = serve_executor_once(server).await;
        let transport = AuthorityActTransport::new(
            &format!("http://127.0.0.1:{port}"),
            ROUTE,
            &origin,
            "test-credential",
        )
        .unwrap();
        let trusted = transport
            .delta(base)
            .await
            .expect("a delta from the real executor surface must parse");
        assert_eq!(
            trusted.canonical_bytes().unwrap(),
            received,
            "the trusted wrapper must preserve the executor-rendered exact bytes"
        );
        assert_eq!(trusted.to_inclusive_act(), expected.to_inclusive_act());

        // The real frame carries the structured payload twice: once as the
        // JSON text content block and once as structuredContent.
        let raw = raw_receiver.await.unwrap();
        assert!(
            raw.len() < MAX_RESPONSE_BYTES,
            "the real rendered response must fit the client ceiling"
        );
        let occurrences = raw
            .windows(b"data_base64".len())
            .filter(|window| *window == b"data_base64")
            .count();
        assert!(
            occurrences >= 2,
            "the no-renderer executor frame must duplicate the payload ({occurrences} copies)"
        );
        db.close().await;
    }

    /// The decoded ceiling must keep the fully rendered executor response under
    /// the client's raw-body ceiling even though a no-renderer tool duplicates
    /// the structured payload into both `content` and `structuredContent`.
    #[test]
    fn decoded_ceiling_bounds_the_rendered_executor_response() {
        // The structured response is at most the 4/3 base64 expansion of the
        // decoded ceiling plus the bounded head evidence and envelope fields.
        let structured_upper = MAX_DELTA_BYTES / 3 * 4 + 16 * 1024;
        assert!(
            rendered_response_upper_bound(structured_upper) < MAX_RESPONSE_BYTES,
            "{} decoded bytes must render below the {} client ceiling",
            MAX_DELTA_BYTES,
            MAX_RESPONSE_BYTES
        );
        // The pre-review 1.4 MB ceiling would not have fit the duplicated frame:
        // this pins why the ceiling moved.
        assert!(rendered_response_upper_bound(1_400_000 / 3 * 4 + 16 * 1024) > MAX_RESPONSE_BYTES);
    }

    /// Boundary: a real executor-rendered delta just under the ceiling parses
    /// and its raw body stays under the client ceiling; a cut over the ceiling
    /// is refused with the whole-snapshot fallback, not a body-too-large error.
    #[tokio::test]
    async fn rendered_response_stays_under_the_client_ceiling_and_oversize_refuses() {
        let db = fresh_authority().await;
        let origin = origin(&db).await;
        append_large_record(&db, SECOND_RECORD_ID, 500_000).await;
        let base = 0;

        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(response.data_base64())
            .unwrap();
        assert!(
            decoded.len() <= MAX_DELTA_BYTES,
            "the boundary fixture must stay inside the ceiling: {} bytes",
            decoded.len()
        );
        let structured_len = serde_json::to_vec(&response).unwrap().len();
        assert!(
            rendered_response_upper_bound(structured_len) < MAX_RESPONSE_BYTES,
            "the server-side composed bound must hold for the boundary fixture"
        );

        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        crate::mcp::register_authority_act_tools(
            &mut registry,
            Arc::new(NativeAuthorityActSource { db: db.clone() }),
        )
        .unwrap();
        let server = crate::mcp::ExecutorPrototypeStdioServer::new(
            Arc::new(registry),
            db.clone(),
            crate::mcp::Caller::authenticated("authority-act-boundary")
                .with_hosting_context("host:authority-act-boundary", ROUTE)
                .with_hosting_owner(true),
            None,
        )
        .await
        .unwrap();
        let (port, raw_receiver) = serve_executor_once(server).await;
        let transport = AuthorityActTransport::new(
            &format!("http://127.0.0.1:{port}"),
            ROUTE,
            &origin,
            "test-credential",
        )
        .unwrap();
        let trusted = transport
            .delta(base)
            .await
            .expect("a near-ceiling real executor response must parse");
        assert_eq!(trusted.canonical_bytes().unwrap(), decoded);
        let raw = raw_receiver.await.unwrap();
        assert!(
            raw.len() < MAX_RESPONSE_BYTES,
            "raw rendered {} bytes must stay under the {} client ceiling",
            raw.len(),
            MAX_RESPONSE_BYTES
        );

        // A cut over the decoded ceiling is refused with the intended fallback.
        let oversized = fresh_authority().await;
        append_large_record(&oversized, SECOND_RECORD_ID, 800_000).await;
        let error = observe_authority_act_delta(&oversized, ROUTE, 0)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("whole snapshot"), "{error}");

        oversized.close().await;
        db.close().await;
    }
}
