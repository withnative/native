//! Authenticated hosted authority act-delta transport.
//!
//! Slice D1 of cb551d7. This module is the **only** production path that can
//! mint a `TrustedAuthorityActDelta`. It has two halves that share one closed
//! wire contract:
//!
//! * the **authority half** ([`observe_authority_act_head`] and
//!   [`observe_authority_act_delta`]) reads the head and, when a cut is asked
//!   for, the thirteen act sections and fourteen companions from **one** read
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
//!
//! # The chunked route
//!
//! The inline ceiling above cannot carry real workspaces (single events reach
//! ~6.3 MB), so [`AuthorityActTransport::delta`] prefers the versioned HTTP
//! family under `/v1/databases/{db}/standby-delta/exports`: start, poll, ranged
//! reads of at most 1 MiB, cancel. The hosted side captures the same one-read-
//! transaction cut, validates it and spools it privately
//! ([`capture_authority_act_delta_export`]); the client assembles the ranges and
//! then runs exactly the checks the MCP path runs before minting the witness. A
//! cut above [`AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES`] fails as the stable code
//! `delta_too_large`, surfaced as a typed reason (never an integrity refusal). A
//! host without the route answers a bare 404 and the transport falls back to the
//! MCP tool.

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
/// A frozen maintenance copy cannot establish current authority freshness.
/// Keep this fixed and payload-free for the refresh controller's classifier.
pub(crate) const MAINTENANCE_SNAPSHOT_ERROR: &str =
    "hosted authority act is serving a maintenance snapshot";
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
/// Closed request contract for the chunked delta export route.
pub const AUTHORITY_ACT_DELTA_EXPORT_CONTRACT: &str =
    "native.standby-authority-act-delta-export.v1";
/// Media type of the spooled canonical delta bytes served by the chunked route.
pub const AUTHORITY_ACT_DELTA_EXPORT_MEDIA_TYPE: &str =
    "application/vnd.native.standby-authority-act-delta+json";
/// Spool ceiling shared by the hosted capture and the client buffer. A cut above
/// it fails with the stable code `delta_too_large`, and the controller reports
/// that rather than an integrity refusal. Far above any observed single event
/// (about 6.3 MB) yet small enough to hold in memory on both sides.
pub const AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES: usize = 256 * 1024 * 1024;
/// The typed reason both the chunked route (`delta_too_large`) and the legacy
/// MCP oversize refusal surface as. The controller classifies on this exact
/// engine message, never on prose from the wire.
pub(crate) const DELTA_TOO_LARGE_ERROR: &str =
    "hosted authority act delta is too large for a delta transfer";
/// Whether `error` is the typed too-large reason.
pub(crate) fn is_delta_too_large(error: &Error) -> bool {
    matches!(error, Error::Engine(message) if message == DELTA_TOO_LARGE_ERROR)
}
/// Substring of the legacy MCP tool's oversize refusal
/// (`observe_authority_act_delta`), mapped to [`DELTA_TOO_LARGE_ERROR`].
const LEGACY_DELTA_OVERSIZE_FRAGMENT: &str = "authority act delta exceeds the bounded transport";
/// Largest control body (start/poll/cancel) the chunked client will read.
const DELTA_CONTROL_MAX_BYTES: usize = 16 * 1024;
/// One ranged read: the hosted per-request ceiling.
const DELTA_CHUNK_BYTES: u64 = 1024 * 1024;
/// Poll cadence and total patience while the hosted capture runs.
const DELTA_POLL_INTERVAL: Duration = Duration::from_millis(500);
const DELTA_POLL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Spooled file name inside the private export directory.
const AUTHORITY_ACT_DELTA_SPOOL_FILE: &str = "authority-act-delta.json";
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

// Engine recognition also protects the v1 journal in builds without v2 serving.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum AuthorityHead {
    V1(AuthorityActDeltaHeadV1),
    KernelV2(KernelHead),
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelHead {
    contract: String,
    origin_database_id: String,
    pub(crate) generation: super::kernel_v2::KernelGeneration,
}
impl AuthorityHead {
    pub(crate) fn head_act(&self) -> i64 {
        match self {
            Self::V1(h) => h.head_act(),
            Self::KernelV2(h) => h.generation.head_act,
        }
    }
    pub(crate) fn origin_database_id(&self) -> &str {
        match self {
            Self::V1(h) => h.origin_database_id(),
            Self::KernelV2(h) => &h.origin_database_id,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::V1(h) => h.validate(),
            Self::KernelV2(h) => {
                require(
                    h.contract == "native.standby-kernel-v2-head.v1",
                    "unknown kernel-v2 head contract",
                )?;
                h.generation.validate()
            }
        }
    }
    pub(crate) fn is_kernel_v2(&self) -> bool {
        match self {
            Self::V1(_) => false,
            Self::KernelV2(_) => true,
        }
    }
    pub(crate) fn matches_authority_head(&self, head: &super::AuthorityActHeadV1) -> bool {
        match self {
            Self::V1(h) => h.matches_authority_head(head),
            Self::KernelV2(_) => false,
        }
    }
}

/// The authority's answer to a cheap head probe. Unknown fields are ignored
/// so additive extensions parse tolerantly; contract/version and the
/// coordinate validator still refuse what this build cannot understand.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityActHeadResponseV1 {
    contract: String,
    version: u32,
    route_database_id: String,
    head: AuthorityHead,
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
    /// An older serving build can identify v2 for the journal fence, but must
    /// pause acquisition rather than repeatedly download unusable generations.
    pub fn refresh_pause_reason(&self) -> Option<&'static str> {
        if self.head.is_kernel_v2() && !cfg!(feature = "v2-kernel-probe") {
            Some("engine v2 requires v2-kernel-probe build")
        } else {
            None
        }
    }

    pub fn route_database_id(&self) -> &str {
        &self.route_database_id
    }

    /// The replicated authority-head evidence, exactly the coordinate set the
    /// delta wire carries (the advisory engine schema is not replicated).
    pub(crate) fn head(&self) -> &AuthorityHead {
        &self.head
    }
}

/// The authority's answer to an exact cut. Unknown fields are ignored for
/// the same additive-tolerance reason as the head response.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    {
        let mut tx = db.pool().begin().await?;
        if super::kernel_v2::is_v2(&mut tx).await? {
            let generation = super::kernel_v2::coordinates(&mut tx).await?;
            let origin_database_id = super::kernel_v2::origin(&mut tx, &generation).await?;
            tx.rollback().await?;
            return Ok(AuthorityActHeadResponseV1 {
                contract: AUTHORITY_ACT_HEAD_RESPONSE_CONTRACT.into(),
                version: AUTHORITY_ACT_RESPONSE_VERSION,
                route_database_id: route_database_id.into(),
                head: AuthorityHead::KernelV2(KernelHead {
                    contract: "native.standby-kernel-v2-head.v1".into(),
                    origin_database_id,
                    generation,
                }),
                _run_context: Value::Null,
            });
        }
        tx.rollback().await?;
    }
    let head = crate::standby::authority_probe::read_authority_act_head(db).await?;
    Ok(AuthorityActHeadResponseV1 {
        contract: AUTHORITY_ACT_HEAD_RESPONSE_CONTRACT.into(),
        version: AUTHORITY_ACT_RESPONSE_VERSION,
        route_database_id: route_database_id.to_string(),
        head: AuthorityHead::V1(AuthorityActDeltaHeadV1::from_head(&head)),
        _run_context: Value::Null,
    })
}

/// The exact authority cut. The caller supplies `F1` only: the authority reads
/// its own head and cuts `(F1, head]` from that same read transaction, so the
/// head, the thirteen act sections and the fourteen companions are one
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
    observe_authority_act_delta_with_inventory(db, route_database_id, from_exclusive_act, None)
        .await
}

pub async fn observe_authority_act_delta_with_inventory(
    db: &crate::Db,
    route_database_id: &str,
    from_exclusive_act: i64,
    blob_inventory: Option<&[String]>,
) -> Result<AuthorityActDeltaResponseV1> {
    validate_route_database_id(route_database_id)?;
    require(
        from_exclusive_act >= 0,
        "authority act delta lower bound must be non-negative",
    )?;

    let mut tx = db.pool().begin().await?;
    let outcome = read_cut_on(&mut tx, from_exclusive_act, blob_inventory).await;
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
    let content_sha256 = delta_content_digest(&bytes)?;
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

/// Capture the exact authority cut into a private spool for the chunked route.
///
/// This is the same one-read-transaction cut as [`observe_authority_act_delta`]:
/// `F2` is the head the authority observed in that transaction, never anything a
/// client supplied. The bytes are re-validated before they are spooled, so the
/// digests carried in the returned metadata are the ones the authority proved.
/// A cut above `ceiling` fails with [`crate::export::BINARY_DELTA_TOO_LARGE`].
#[doc(hidden)]
pub async fn capture_authority_act_delta_export(
    db: &crate::Db,
    route_database_id: &str,
    from_exclusive_act: i64,
    export_root: &std::path::Path,
    ceiling: usize,
) -> Result<(crate::export::Export, crate::export::BinaryDeltaMeta)> {
    capture_authority_act_delta_export_with_inventory(
        db,
        route_database_id,
        from_exclusive_act,
        export_root,
        ceiling,
        None,
    )
    .await
}

pub async fn capture_authority_act_delta_export_with_inventory(
    db: &crate::Db,
    route_database_id: &str,
    from_exclusive_act: i64,
    export_root: &std::path::Path,
    ceiling: usize,
    blob_inventory: Option<&[String]>,
) -> Result<(crate::export::Export, crate::export::BinaryDeltaMeta)> {
    validate_route_database_id(route_database_id)?;
    require(
        from_exclusive_act >= 0,
        "authority act delta lower bound must be non-negative",
    )?;
    let mut tx = db.pool().begin().await?;
    let outcome = read_cut_on(&mut tx, from_exclusive_act, blob_inventory).await;
    let rollback = tx.rollback().await;
    let (head_act, origin_database_id, bytes) = match (outcome, rollback) {
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error.into()),
        (Ok(value), Ok(())) => value,
    };
    if bytes.len() > ceiling {
        return Err(Error::engine(crate::export::BINARY_DELTA_TOO_LARGE));
    }
    let content_sha256 = delta_content_digest(&bytes)?;
    let meta = crate::export::BinaryDeltaMeta {
        route_database_id: route_database_id.to_string(),
        origin_database_id,
        from_exclusive_act,
        to_inclusive_act: head_act,
        content_sha256,
        outer_sha256: hex::encode(Sha256::digest(&bytes)),
    };
    let export = crate::export::spool_bytes_export(
        Some(export_root),
        AUTHORITY_ACT_DELTA_SPOOL_FILE,
        &bytes,
    )
    .await?;
    Ok((export, meta))
}

/// Read the head and the exact cut on one open connection inside one read
/// transaction, then build the canonical delta. Returns the observed head act,
/// the portable origin, and the exact bytes.
async fn read_cut_on(
    conn: &mut sqlx::SqliteConnection,
    from_exclusive_act: i64,
    blob_inventory: Option<&[String]>,
) -> Result<(i64, String, Vec<u8>)> {
    #[cfg(not(any(test, feature = "v2-kernel-probe")))]
    let _ = blob_inventory;
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    if super::kernel_v2::is_v2(conn).await? {
        let inventory = match blob_inventory {
            Some(inventory) => inventory,
            None if from_exclusive_act == 0 => &[],
            None => {
                return Err(Error::engine(
                    "kernel-v2 delta requires a verified base blob inventory",
                ))
            }
        };
        let delta = super::kernel_v2_delta::cut(conn, from_exclusive_act, inventory).await?;
        return Ok((
            delta.head.head_act,
            delta.origin_database_id.clone(),
            delta.bytes()?,
        ));
    }
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

fn delta_content_digest(bytes: &[u8]) -> Result<String> {
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    if serde_json::from_slice::<Value>(bytes)?["contract"] == "native.standby-kernel-v2-delta.v1" {
        return Ok(super::kernel_v2_delta::KernelDelta::parse(bytes)?.content_sha256);
    }
    Ok(validate_authority_act_delta(bytes)?.content_sha256().into())
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

#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(super) struct AuthenticatedKernelDelta {
    delta: super::kernel_v2_delta::KernelDelta,
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
impl AuthenticatedKernelDelta {
    pub(super) fn into_delta(self) -> super::kernel_v2_delta::KernelDelta {
        self.delta
    }
}

pub(crate) type AuthorityCallFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>>;

/// The one injected HTTP seam. Production uses [`HttpAuthorityActClient`]; tests
/// script it without a socket. It returns the raw response body bytes, and the
/// caller owns every ceiling and parse decision.
pub(crate) trait AuthorityActHttpClient: Send + Sync {
    fn call(&self, endpoint: String, bearer: String, body: Value) -> AuthorityCallFuture;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeltaHttpMethod {
    Post,
    Get,
    Delete,
}

/// One request on the chunked delta route family.
pub(crate) struct DeltaHttpRequest {
    pub(crate) method: DeltaHttpMethod,
    pub(crate) url: String,
    pub(crate) bearer: String,
    pub(crate) json: Option<Value>,
    /// Inclusive `bytes=start-end` range for the bytes route.
    pub(crate) range: Option<(u64, u64)>,
    /// Hard ceiling on the response body the implementation may read.
    pub(crate) max_body: usize,
}

/// The parts of a response the chunked client checks.
pub(crate) struct DeltaHttpResponse {
    pub(crate) status: u16,
    /// The `x-native-export-api` identity header, if any.
    pub(crate) api: Option<String>,
    pub(crate) content_type: Option<String>,
    pub(crate) etag: Option<String>,
    pub(crate) content_range: Option<String>,
    pub(crate) body: Vec<u8>,
}

pub(crate) type DeltaHttpFuture = Pin<Box<dyn Future<Output = Result<DeltaHttpResponse>> + Send>>;

/// The second injected HTTP seam, for the chunked route family. A 401/403 and
/// the maintenance marker are refused by the implementation, exactly as the
/// MCP seam does; every other status is returned for the caller to judge.
pub(crate) trait AuthorityActDeltaHttp: Send + Sync {
    fn send(&self, request: DeltaHttpRequest) -> DeltaHttpFuture;
}

/// Stand-in for a host without the chunked routes: always the 404 an older
/// host answers, so the transport takes the MCP path.
struct NoChunkedDeltaRoute;

impl AuthorityActDeltaHttp for NoChunkedDeltaRoute {
    fn send(&self, _request: DeltaHttpRequest) -> DeltaHttpFuture {
        Box::pin(async {
            Ok(DeltaHttpResponse {
                status: 404,
                api: None,
                content_type: None,
                etag: None,
                content_range: None,
                body: Vec::new(),
            })
        })
    }
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
            let tool_name = body
                .pointer("/params/name")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::engine("authority act request omitted its tool name"))?;
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
                .header("Mcp-Name", tool_name)
                .json(&body)
                .send()
                .await
                .map_err(|_| Error::engine("hosted authority act request failed"))?;
            if matches!(response.status().as_u16(), 401 | 403) {
                return Err(Error::auth("hosted authority act credential refused"));
            }
            // Maintenance serves an authenticated frozen copy, not the live
            // authority. Refuse before reading a body or accepting its head.
            if response
                .headers()
                .get("x-native-read-only")
                .is_some_and(|value| value == "true")
            {
                return Err(Error::engine(MAINTENANCE_SNAPSHOT_ERROR));
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

impl AuthorityActDeltaHttp for HttpAuthorityActClient {
    fn send(&self, request: DeltaHttpRequest) -> DeltaHttpFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let mut builder = match request.method {
                DeltaHttpMethod::Post => client.post(&request.url),
                DeltaHttpMethod::Get => client.get(&request.url),
                DeltaHttpMethod::Delete => client.delete(&request.url),
            }
            .bearer_auth(&request.bearer);
            if let Some((start, end)) = request.range {
                builder = builder.header(reqwest::header::RANGE, format!("bytes={start}-{end}"));
            }
            if let Some(json) = &request.json {
                builder = builder.json(json);
            }
            let mut response = builder
                .send()
                .await
                .map_err(|_| Error::engine("hosted authority act request failed"))?;
            if matches!(response.status().as_u16(), 401 | 403) {
                return Err(Error::auth("hosted authority act credential refused"));
            }
            if response
                .headers()
                .get("x-native-read-only")
                .is_some_and(|value| value == "true")
            {
                return Err(Error::engine(MAINTENANCE_SNAPSHOT_ERROR));
            }
            let header = |response: &reqwest::Response, name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            let status = response.status().as_u16();
            let api = header(&response, "x-native-export-api");
            let content_type = header(&response, "content-type");
            let etag = header(&response, "etag");
            let content_range = header(&response, "content-range");
            if response
                .content_length()
                .is_some_and(|length| length > request.max_body as u64)
            {
                return Err(Error::engine("hosted authority act response too large"));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| Error::engine("hosted authority act response was interrupted"))?
            {
                if body.len().saturating_add(chunk.len()) > request.max_body {
                    return Err(Error::engine("hosted authority act response too large"));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(DeltaHttpResponse {
                status,
                api,
                content_type,
                etag,
                content_range,
                body,
            })
        })
    }
}

/// The authenticated authority act client. Construct it once per pinned
/// authority origin/route/origin identity; it never accepts a route from the
/// response itself.
pub(crate) struct AuthorityActTransport {
    endpoint: String,
    /// `{origin}/v1/databases/{route}/standby-delta/exports`.
    export_base: String,
    bearer: String,
    expected_route_database_id: String,
    expected_origin_database_id: String,
    client: Arc<dyn AuthorityActHttpClient>,
    delta_http: Arc<dyn AuthorityActDeltaHttp>,
    delta_ceiling: usize,
    poll_interval: Duration,
    poll_timeout: Duration,
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
        let export_base = format!(
            "{}/v1/databases/{}/standby-delta/exports",
            hosted_origin,
            percent_encoding::utf8_percent_encode(
                hosted_route_database_id,
                percent_encoding::NON_ALPHANUMERIC
            )
        );
        let http = Arc::new(HttpAuthorityActClient::new()?);
        Ok(Self {
            endpoint,
            export_base,
            bearer: bearer.to_string(),
            expected_route_database_id: hosted_route_database_id.to_string(),
            expected_origin_database_id: expected_origin_database_id.to_string(),
            client: http.clone(),
            delta_http: http,
            delta_ceiling: AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
            poll_interval: DELTA_POLL_INTERVAL,
            poll_timeout: DELTA_POLL_TIMEOUT,
        })
    }

    pub(crate) fn with_client(
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
        // A scripted MCP client has no chunked route behind it: answer as an
        // older host would, so `delta` keeps taking the MCP path.
        transport.delta_http = Arc::new(NoChunkedDeltaRoute);
        Ok(transport)
    }

    /// Replace the chunked-route seam and its timing; for tests.
    #[cfg(test)]
    pub(crate) fn with_delta_http(
        mut self,
        delta_http: Arc<dyn AuthorityActDeltaHttp>,
        poll_interval: Duration,
        poll_timeout: Duration,
        delta_ceiling: usize,
    ) -> Self {
        self.delta_http = delta_http;
        self.poll_interval = poll_interval;
        self.poll_timeout = poll_timeout;
        self.delta_ceiling = delta_ceiling;
        self
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
    ///
    /// The chunked HTTP route is primary: it carries a cut of any size up to the
    /// spool ceiling. A host that predates it answers 404 with no Native error
    /// code on start, and only then does this fall back to the MCP tool, whose
    /// inline base64 is limited to [`MAX_DELTA_BYTES`]. Either way the bytes
    /// pass the same checks before the witness is minted.
    pub(crate) async fn delta(&self, from_exclusive_act: i64) -> Result<TrustedAuthorityActDelta> {
        // Both halves are boxed: their state machines are large in a debug
        // build and `delta` sits inside every refresh attempt's future, so
        // inlining them would enlarge the stack of each caller.
        match Box::pin(self.delta_chunked(from_exclusive_act)).await? {
            Some(trusted) => Ok(trusted),
            None => Box::pin(self.delta_mcp(from_exclusive_act)).await,
        }
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn kernel_delta(
        &self,
        from: i64,
        blob_inventory: &[String],
    ) -> Result<super::kernel_v2_delta::TrustedKernelDelta> {
        super::kernel_v2_delta::validate_blob_inventory(blob_inventory)?;
        if let Some(handle) = self
            .start_delta_export_with_inventory(from, Some(blob_inventory))
            .await?
        {
            let fetched = self.fetch_delta_export(&handle, from).await;
            self.cancel_delta_export(&handle).await;
            let (claim, bytes) = fetched?;
            return self.verify_kernel_delta(from, claim, &bytes);
        }
        let response = self
            .call::<AuthorityActDeltaResponseV1>(authority_act_call(
                AUTHORITY_ACT_DELTA_OPERATION,
                json!({"from_exclusive_act":from,"blob_inventory":blob_inventory}),
            ))
            .await?;
        require(
            response.contract == AUTHORITY_ACT_DELTA_RESPONSE_CONTRACT
                && response.version == AUTHORITY_ACT_RESPONSE_VERSION,
            "invalid kernel-v2 delta response",
        )?;
        let bytes = decode_canonical_delta(&response.data_base64)?;
        self.verify_kernel_delta(
            from,
            DeltaClaim {
                route_database_id: response.route_database_id,
                origin_database_id: response.origin_database_id,
                from_exclusive_act: response.from_exclusive_act,
                to_inclusive_act: response.to_inclusive_act,
                content_sha256: response.content_sha256,
                outer_sha256: response.outer_sha256,
            },
            &bytes,
        )
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn verify_kernel_delta(
        &self,
        from: i64,
        claim: DeltaClaim,
        bytes: &[u8],
    ) -> Result<super::kernel_v2_delta::TrustedKernelDelta> {
        require(
            claim.route_database_id == self.expected_route_database_id
                && claim.origin_database_id == self.expected_origin_database_id
                && claim.from_exclusive_act == from
                && claim.outer_sha256 == hex::encode(Sha256::digest(bytes)),
            "kernel-v2 delta response binding or digest mismatch",
        )?;
        let delta = super::kernel_v2_delta::KernelDelta::parse(bytes)?;
        require(
            delta.origin_database_id == claim.origin_database_id
                && delta.from_exclusive_act == from
                && delta.head.head_act == claim.to_inclusive_act
                && delta.content_sha256 == claim.content_sha256,
            "kernel-v2 delta response disagrees with document",
        )?;
        Ok(
            super::kernel_v2_delta::TrustedKernelDelta::from_authenticated(
                AuthenticatedKernelDelta { delta },
            ),
        )
    }

    async fn delta_mcp(&self, from_exclusive_act: i64) -> Result<TrustedAuthorityActDelta> {
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
        let bytes = decode_canonical_delta(&response.data_base64)?;
        let claim = DeltaClaim {
            route_database_id: response.route_database_id,
            origin_database_id: response.origin_database_id,
            from_exclusive_act: response.from_exclusive_act,
            to_inclusive_act: response.to_inclusive_act,
            content_sha256: response.content_sha256,
            outer_sha256: response.outer_sha256,
        };
        self.verify_and_mint(from_exclusive_act, claim, bytes)
    }

    /// Every check that stands between assembled bytes and the trust witness,
    /// shared by the MCP and chunked paths so neither can be weaker.
    fn verify_and_mint(
        &self,
        from_exclusive_act: i64,
        claim: DeltaClaim,
        bytes: Vec<u8>,
    ) -> Result<TrustedAuthorityActDelta> {
        require(
            claim.route_database_id == self.expected_route_database_id,
            "authority act delta response route database id does not match the authenticated route",
        )?;
        require(
            claim.origin_database_id == self.expected_origin_database_id,
            "authority act delta response origin does not match the pinned authority origin",
        )?;
        require(
            claim.from_exclusive_act == from_exclusive_act,
            "authority act delta response lower bound disagrees with the request",
        )?;
        require(
            claim.from_exclusive_act >= 0 && claim.to_inclusive_act >= claim.from_exclusive_act,
            "authority act delta response bounds are invalid",
        )?;
        require(
            claim.outer_sha256 == hex::encode(Sha256::digest(&bytes)),
            "authority act delta outer digest does not cover the carried bytes",
        )?;

        let validated = validate_authority_act_delta(&bytes)?;
        require(
            claim.content_sha256 == validated.content_sha256(),
            "authority act delta content digest disagrees with the carried document",
        )?;
        require(
            claim.origin_database_id == validated.authority_head().origin_database_id(),
            "authority act delta response origin disagrees with the carried head",
        )?;
        require(
            claim.from_exclusive_act == validated.act_cut().from_exclusive_act(),
            "authority act delta response lower bound disagrees with the carried cut",
        )?;
        require(
            claim.to_inclusive_act == validated.act_cut().to_inclusive_act(),
            "authority act delta response upper bound disagrees with the carried cut",
        )?;
        require(
            claim.to_inclusive_act == validated.authority_head().head_act(),
            "authority act delta response upper bound disagrees with the carried head",
        )?;

        let witness = AuthenticatedAuthorityActDelta {
            validated,
            authority_origin: claim.origin_database_id,
            from_exclusive_act: claim.from_exclusive_act,
            to_inclusive_act: claim.to_inclusive_act,
        };
        TrustedAuthorityActDelta::from_authenticated_transport(witness)
    }

    /// The chunked route: start, poll, ranged reads, cancel. `None` means the
    /// host has no such route (an older host), not that anything failed.
    async fn delta_chunked(
        &self,
        from_exclusive_act: i64,
    ) -> Result<Option<TrustedAuthorityActDelta>> {
        let Some(handle) = self.start_delta_export(from_exclusive_act).await? else {
            return Ok(None);
        };
        let fetched = self.fetch_delta_export(&handle, from_exclusive_act).await;
        // Release the hosted spool as soon as the bytes are in hand or the
        // transfer failed; the idle TTL is only the backstop.
        self.cancel_delta_export(&handle).await;
        let (claim, bytes) = fetched?;
        self.verify_and_mint(from_exclusive_act, claim, bytes)
            .map(Some)
    }

    fn delta_request(
        &self,
        method: DeltaHttpMethod,
        url: String,
        json: Option<Value>,
        range: Option<(u64, u64)>,
        max_body: usize,
    ) -> DeltaHttpRequest {
        DeltaHttpRequest {
            method,
            url,
            bearer: self.bearer.clone(),
            json,
            range,
            max_body,
        }
    }

    /// `Ok(None)` only for a 404 that carries no Native error code.
    async fn start_delta_export(&self, from_exclusive_act: i64) -> Result<Option<String>> {
        self.start_delta_export_with_inventory(from_exclusive_act, None)
            .await
    }

    async fn start_delta_export_with_inventory(
        &self,
        from_exclusive_act: i64,
        blob_inventory: Option<&[String]>,
    ) -> Result<Option<String>> {
        let mut body = json!({"contract": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT, "version":1,"from_exclusive_act":from_exclusive_act});
        if let Some(inventory) = blob_inventory {
            body["blob_inventory"] = json!(inventory);
        }
        let response = self
            .delta_http
            .send(self.delta_request(
                DeltaHttpMethod::Post,
                self.export_base.clone(),
                Some(body),
                None,
                DELTA_CONTROL_MAX_BYTES,
            ))
            .await?;
        if response.status == 404 && wire_error_code(&response.body).is_none() {
            return Ok(None);
        }
        if response.status != 202 {
            return Err(delta_status_error(&response));
        }
        require_delta_api(&response)?;
        let started: DeltaExportStarted = parse_control(&response.body)?;
        require(
            started.status == "pending" && valid_export_handle(&started.export_handle),
            "hosted authority act delta export start response is invalid",
        )?;
        Ok(Some(started.export_handle))
    }

    async fn fetch_delta_export(
        &self,
        handle: &str,
        from_exclusive_act: i64,
    ) -> Result<(DeltaClaim, Vec<u8>)> {
        let ready = self.await_delta_export(handle).await?;
        let claim = DeltaClaim {
            route_database_id: ready.route_database_id.ok_or_else(ready_incomplete)?,
            origin_database_id: ready.origin_database_id.ok_or_else(ready_incomplete)?,
            from_exclusive_act: ready.from_exclusive_act.ok_or_else(ready_incomplete)?,
            to_inclusive_act: ready.to_inclusive_act.ok_or_else(ready_incomplete)?,
            content_sha256: ready.content_sha256.ok_or_else(ready_incomplete)?,
            outer_sha256: ready.outer_sha256.ok_or_else(ready_incomplete)?,
        };
        let size = ready.size_bytes.ok_or_else(ready_incomplete)?;
        require(
            is_sha256_hex(&claim.content_sha256) && is_sha256_hex(&claim.outer_sha256),
            "hosted authority act delta export digests are invalid",
        )?;
        require(
            claim.from_exclusive_act == from_exclusive_act,
            "authority act delta response lower bound disagrees with the request",
        )?;
        require(size > 0, "hosted authority act delta export is empty")?;
        if size > self.delta_ceiling as u64 {
            return Err(Error::engine(DELTA_TOO_LARGE_ERROR));
        }
        let expected_etag = format!("\"{}\"", claim.outer_sha256);
        let url = format!("{}/{handle}/bytes", self.export_base);
        let mut bytes = Vec::with_capacity(size as usize);
        let mut offset = 0_u64;
        while offset < size {
            let end = (offset + DELTA_CHUNK_BYTES - 1).min(size - 1);
            let response = self
                .delta_http
                .send(self.delta_request(
                    DeltaHttpMethod::Get,
                    url.clone(),
                    None,
                    Some((offset, end)),
                    DELTA_CHUNK_BYTES as usize,
                ))
                .await?;
            if response.status != 206 {
                return Err(delta_status_error(&response));
            }
            require_delta_api(&response)?;
            // Every range must describe the same artifact: same media type,
            // same strong validator, same total, and exactly the bytes asked.
            require(
                response.content_type.as_deref() == Some(AUTHORITY_ACT_DELTA_EXPORT_MEDIA_TYPE),
                "hosted authority act delta chunk media type is unexpected",
            )?;
            require(
                response.etag.as_deref() == Some(expected_etag.as_str()),
                "hosted authority act delta chunk validator changed between ranges",
            )?;
            require(
                response.content_range.as_deref()
                    == Some(format!("bytes {offset}-{end}/{size}").as_str()),
                "hosted authority act delta chunk range disagrees with the request",
            )?;
            require(
                response.body.len() as u64 == end - offset + 1,
                "hosted authority act delta chunk length disagrees with its range",
            )?;
            bytes.extend_from_slice(&response.body);
            offset = end + 1;
        }
        Ok((claim, bytes))
    }

    /// Poll until the capture is ready, failed, or out of patience.
    async fn await_delta_export(&self, handle: &str) -> Result<DeltaExportPoll> {
        let url = format!("{}/{handle}", self.export_base);
        let deadline = tokio::time::Instant::now() + self.poll_timeout;
        loop {
            let response = self
                .delta_http
                .send(self.delta_request(
                    DeltaHttpMethod::Get,
                    url.clone(),
                    None,
                    None,
                    DELTA_CONTROL_MAX_BYTES,
                ))
                .await?;
            if response.status != 200 {
                return Err(delta_status_error(&response));
            }
            require_delta_api(&response)?;
            let poll: DeltaExportPoll = parse_control(&response.body)?;
            match poll.status.as_str() {
                "ready" => return Ok(poll),
                "failed" => {
                    return Err(match poll.error_code.as_deref() {
                        Some("delta_too_large") => Error::engine(DELTA_TOO_LARGE_ERROR),
                        Some(code) if is_wire_code(code) => Error::engine(format!(
                            "hosted authority act delta export failed ({code})"
                        )),
                        _ => Error::engine("hosted authority act delta export failed"),
                    })
                }
                "pending" => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(Error::engine(
                            "hosted authority act delta export request failed: capture timed out",
                        ));
                    }
                    tokio::time::sleep(self.poll_interval).await;
                }
                _ => {
                    return Err(Error::engine(
                        "hosted authority act delta export status is unknown",
                    ))
                }
            }
        }
    }

    /// Best effort: the hosted idle TTL reclaims whatever this misses.
    async fn cancel_delta_export(&self, handle: &str) {
        let _ = self
            .delta_http
            .send(self.delta_request(
                DeltaHttpMethod::Delete,
                format!("{}/{handle}", self.export_base),
                None,
                None,
                DELTA_CONTROL_MAX_BYTES,
            ))
            .await;
    }

    /// Parse the closed protocol envelope first, then the successful payload
    /// from its raw JSON so unknown and duplicate authority fields still refuse.
    /// A lean selection refusal is safe to retry: dispatch has not started.
    async fn call<T: DeserializeOwned>(&self, mut body: Value) -> Result<T> {
        for attempt in 0..=1 {
            let bytes = self
                .client
                .call(self.endpoint.clone(), self.bearer.clone(), body.clone())
                .await?;
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(Error::engine("hosted authority act response too large"));
            }
            let invalid_protocol = |error: serde_json::Error| {
                Error::engine(format!(
                    "hosted authority act returned an invalid protocol response: {error}"
                ))
            };
            let envelope: RpcEnvelope<Box<serde_json::value::RawValue>> =
                serde_json::from_slice(&bytes).map_err(invalid_protocol)?;
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
            // Also guard the MCP disclosure when an intermediary omits HTTP
            // headers. Any maintenance marker prevents both lean repair retry
            // and payload acceptance: even an equal frozen head is not a new
            // observation of the live authority.
            if result.meta.get("nativeMaintenance").is_some() {
                return Err(Error::engine(MAINTENANCE_SNAPSHOT_ERROR));
            }
            let incomplete = result
                .result_type
                .as_deref()
                .is_some_and(|kind| kind != "complete");
            if result.is_error || incomplete {
                if result.is_error && !incomplete {
                    if let Some(raw) = result.structured_content {
                        let refusal: Value =
                            serde_json::from_str(raw.get()).map_err(invalid_protocol)?;
                        // The legacy tool's oversize refusal is a typed reason,
                        // not a generic failure: the cut is simply too big for
                        // inline base64 on a host without the chunked route.
                        if refusal
                            .get("error")
                            .and_then(Value::as_str)
                            .is_some_and(|text| text.contains(LEGACY_DELTA_OVERSIZE_FRAGMENT))
                        {
                            return Err(Error::engine(DELTA_TOO_LARGE_ERROR));
                        }
                        if attempt == 0
                            && refusal.pointer("/repair/code").and_then(Value::as_str)
                                == Some("call_executor_required")
                            && refusal
                                .pointer("/repair/retry_ready")
                                .and_then(Value::as_bool)
                                == Some(true)
                        {
                            // Rebuild locally; never follow a server-supplied tool
                            // or arguments from next_call.
                            body["params"]["arguments"]["executor"] =
                                body["params"]["name"].clone();
                            body["params"]["name"] = json!("call_executor");
                            continue;
                        }
                    }
                }
                return Err(Error::engine("hosted authority act tool reported failure"));
            }
            let raw = result
                .structured_content
                .ok_or_else(|| Error::engine("hosted authority act omitted structured content"))?;
            return serde_json::from_str(raw.get()).map_err(invalid_protocol);
        }
        unreachable!("the second attempt always returns")
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

/// What the authority claims about a delta, whichever route carried it.
struct DeltaClaim {
    route_database_id: String,
    origin_database_id: String,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    content_sha256: String,
    outer_sha256: String,
}

#[derive(Deserialize)]
struct DeltaExportStarted {
    export_handle: String,
    status: String,
}

#[derive(Deserialize)]
struct DeltaExportPoll {
    status: String,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    route_database_id: Option<String>,
    #[serde(default)]
    origin_database_id: Option<String>,
    #[serde(default)]
    from_exclusive_act: Option<i64>,
    #[serde(default)]
    to_inclusive_act: Option<i64>,
    #[serde(default)]
    content_sha256: Option<String>,
    #[serde(default)]
    outer_sha256: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

fn ready_incomplete() -> Error {
    Error::engine("hosted authority act delta export ready response is incomplete")
}

fn parse_control<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| {
        Error::engine("hosted authority act delta export returned an invalid response")
    })
}

fn valid_export_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 64
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_wire_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 48
        && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// The stable `error_code` of a Native wire error body, if it carries one.
fn wire_error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.get("error_code")?.as_str()?;
    is_wire_code(code).then(|| code.to_string())
}

/// The chunked routes answer with their own identity; anything else is not the
/// route this client negotiated.
fn require_delta_api(response: &DeltaHttpResponse) -> Result<()> {
    require(
        response.api.as_deref() == Some(AUTHORITY_ACT_DELTA_EXPORT_CONTRACT),
        "hosted authority act delta export response has an unexpected identity",
    )
}

/// Map a refused chunked-route status to an error the controller already
/// classifies: transient hosted trouble reads as a network failure so it never
/// buys a whole snapshot, and only a stable code is ever echoed.
fn delta_status_error(response: &DeltaHttpResponse) -> Error {
    if matches!(response.status, 401 | 403) {
        return Error::auth("hosted authority act credential refused");
    }
    let code = wire_error_code(&response.body);
    match (response.status, code.as_deref()) {
        (_, Some("delta_too_large")) => Error::engine(DELTA_TOO_LARGE_ERROR),
        (409, _) | (404, Some("handle_not_found")) => {
            Error::engine("hosted authority act delta export request failed: capture unavailable")
        }
        (status, Some(code)) => Error::engine(format!(
            "hosted authority act delta export HTTP status {status} ({code})"
        )),
        (status, None) => Error::engine(format!(
            "hosted authority act delta export HTTP status {status}"
        )),
    }
}

fn authority_act_call(operation: &str, arguments: Value) -> Value {
    executor_call(AUTHORITY_ACT_EXECUTOR, operation, arguments, None)
}

/// The JSON-RPC `tools/call` that reaches one hosted executor operation. The
/// optional `format` is the envelope's response representation (for example
/// `json`), kept outside the nested arguments.
pub(crate) fn executor_call(
    executor: &str,
    operation: &str,
    arguments: Value,
    format: Option<&str>,
) -> Value {
    let mut envelope = json!({
        "operation": operation,
        "arguments": arguments,
    });
    if let Some(format) = format {
        envelope["format"] = json!(format);
    }
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": executor,
            "arguments": envelope,
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
    meta: Value,
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

    /// Each request consumes one response; an unexpected retry fails the test.
    struct QueuedClient {
        responses: Mutex<std::collections::VecDeque<Vec<u8>>>,
        requests: Mutex<Vec<Value>>,
    }

    impl QueuedClient {
        fn new(responses: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    impl AuthorityActHttpClient for QueuedClient {
        fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
            self.requests.lock().unwrap().push(body);
            let raw = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected retry");
            Box::pin(async move { Ok(raw) })
        }
    }

    fn tool_refusal(code: &str) -> Vec<u8> {
        let mut response: Value = serde_json::from_slice(&envelope(json!({
            "error": "selection refused",
            "run_context": {},
            "repair": {
                "code": code,
                "retry_ready": true,
                // Deliberately untrusted: the client must retain its own call.
                "next_call": {"tool": "wrong-tool", "arguments": {}}
            }
        })))
        .unwrap();
        response["result"]["isError"] = json!(true);
        serde_json::to_vec(&response).unwrap()
    }

    async fn invoke_authority_call(
        transport: &AuthorityActTransport,
        operation: &str,
    ) -> Result<()> {
        if operation == AUTHORITY_ACT_HEAD_OPERATION {
            transport.head().await.map(|_| ())
        } else {
            transport.delta(0).await.map(|_| ())
        }
    }

    #[tokio::test]
    async fn client_maintenance_metadata_precedes_payload_and_lean_retry_then_recovers() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        for (operation, structured) in [
            (
                AUTHORITY_ACT_HEAD_OPERATION,
                serde_json::to_value(observe_authority_act_head(&db, ROUTE).await.unwrap())
                    .unwrap(),
            ),
            (
                AUTHORITY_ACT_DELTA_OPERATION,
                delta_envelope(&observe_authority_act_delta(&db, ROUTE, 0).await.unwrap()),
            ),
        ] {
            // Production mismatch: the lean maintenance proxy offers a repair
            // to call_executor, but its full-surface frozen upstream does not
            // implement call_executor. Stop at the disclosed selection refusal.
            for raw in [
                envelope(structured.clone()),
                tool_refusal("call_executor_required"),
            ] {
                let mut maintenance: Value = serde_json::from_slice(&raw).unwrap();
                maintenance["result"]["_meta"]["nativeMaintenance"] = json!({
                    "read_only": true, "snapshot_at": "2026-10-15T20:31:33.444Z"
                });
                let client = QueuedClient::new(vec![
                    serde_json::to_vec(&maintenance).unwrap(),
                    envelope(structured.clone()),
                ]);
                let transport = AuthorityActTransport::with_client(
                    "http://localhost",
                    ROUTE,
                    &origin,
                    "wire-secret",
                    client.clone(),
                )
                .unwrap();
                let error = invoke_authority_call(&transport, operation)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.to_string(),
                    Error::engine(MAINTENANCE_SNAPSHOT_ERROR).to_string()
                );
                assert_eq!(client.requests.lock().unwrap().len(), 1, "no lean retry");
                // The next normal response is usable on the same transport.
                invoke_authority_call(&transport, operation).await.unwrap();
                assert_eq!(client.requests.lock().unwrap().len(), 2);
                assert!(client
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request["params"]["name"] == AUTHORITY_ACT_EXECUTOR));
            }
        }
        db.close().await;
    }

    #[tokio::test]
    async fn http_client_maintenance_header_precedes_body_acceptance_for_head_and_delta() {
        use tokio::io::AsyncWriteExt as _;
        let db = real_authority().await;
        let origin = origin(&db).await;
        for operation in [AUTHORITY_ACT_HEAD_OPERATION, AUTHORITY_ACT_DELTA_OPERATION] {
            for status in [
                "200 OK",
                "503 Service Unavailable",
                "401 Unauthorized",
                "403 Forbidden",
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = tokio::spawn(async move {
                    let (mut stream, _, bytes) = accept_mcp_request(&listener).await;
                    let request: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(request["params"]["arguments"]["operation"], operation);
                    // The 200 reproduces the proxy's lean repair offered in
                    // front of a full upstream that rejects call_executor.
                    // Header-only disclosure must stop that retry. Other
                    // statuses use invalid JSON to prove the header/status
                    // decision precedes body parsing.
                    let body = if status == "200 OK" {
                        tool_refusal("call_executor_required")
                    } else {
                        b"invalid".to_vec()
                    };
                    stream.write_all(format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nx-native-read-only: true\r\nx-native-snapshot-at: 2026-10-15T20:31:33.444Z\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()
                    ).as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
                let transport = AuthorityActTransport::new(
                    &format!("http://127.0.0.1:{port}"),
                    ROUTE,
                    &origin,
                    "wire-secret",
                )
                .unwrap();
                let error = invoke_authority_call(&transport, operation)
                    .await
                    .unwrap_err();
                if matches!(status, "401 Unauthorized" | "403 Forbidden") {
                    assert!(matches!(error, Error::Auth(_)));
                } else {
                    assert_eq!(
                        error.to_string(),
                        Error::engine(MAINTENANCE_SNAPSHOT_ERROR).to_string()
                    );
                }
                server.await.unwrap();
            }
        }
        db.close().await;
    }

    #[tokio::test]
    async fn client_direct_success_does_not_retry() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        for (operation, structured) in [
            (
                AUTHORITY_ACT_HEAD_OPERATION,
                serde_json::to_value(observe_authority_act_head(&db, ROUTE).await.unwrap())
                    .unwrap(),
            ),
            (
                AUTHORITY_ACT_DELTA_OPERATION,
                delta_envelope(&observe_authority_act_delta(&db, ROUTE, 0).await.unwrap()),
            ),
        ] {
            let client = QueuedClient::new(vec![envelope(structured)]);
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                client.clone(),
            )
            .unwrap();
            invoke_authority_call(&transport, operation).await.unwrap();
            let arguments = if operation == AUTHORITY_ACT_HEAD_OPERATION {
                json!({})
            } else {
                json!({"from_exclusive_act": 0})
            };
            assert_eq!(
                *client.requests.lock().unwrap(),
                vec![authority_act_call(operation, arguments)]
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn client_lean_refusal_retries_original_envelope_through_call_executor() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        for (operation, mut structured) in [
            (
                AUTHORITY_ACT_HEAD_OPERATION,
                serde_json::to_value(observe_authority_act_head(&db, ROUTE).await.unwrap())
                    .unwrap(),
            ),
            (
                AUTHORITY_ACT_DELTA_OPERATION,
                delta_envelope(&observe_authority_act_delta(&db, ROUTE, 0).await.unwrap()),
            ),
        ] {
            structured["run_context"] = json!({"run_key": "lean-response"});
            let client = QueuedClient::new(vec![
                tool_refusal("call_executor_required"),
                envelope(structured),
            ]);
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                client.clone(),
            )
            .unwrap();
            invoke_authority_call(&transport, operation).await.unwrap();
            let arguments = if operation == AUTHORITY_ACT_HEAD_OPERATION {
                json!({})
            } else {
                json!({"from_exclusive_act": 0})
            };
            let direct = authority_act_call(operation, arguments);
            let mut retry = direct.clone();
            retry["params"]["name"] = json!("call_executor");
            retry["params"]["arguments"]["executor"] = json!(AUTHORITY_ACT_EXECUTOR);
            assert_eq!(*client.requests.lock().unwrap(), vec![direct, retry]);
        }
        db.close().await;
    }

    #[tokio::test]
    async fn client_unrelated_tool_error_does_not_retry() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        for operation in [AUTHORITY_ACT_HEAD_OPERATION, AUTHORITY_ACT_DELTA_OPERATION] {
            let client = QueuedClient::new(vec![tool_refusal("permission_denied")]);
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                client.clone(),
            )
            .unwrap();
            assert!(invoke_authority_call(&transport, operation).await.is_err());
            assert_eq!(client.requests.lock().unwrap().len(), 1);
        }
        db.close().await;
    }

    #[tokio::test]
    async fn client_lean_refusal_retries_at_most_once() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let client = QueuedClient::new(vec![
            tool_refusal("call_executor_required"),
            tool_refusal("call_executor_required"),
        ]);
        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            client.clone(),
        )
        .unwrap();
        assert!(transport.head().await.is_err());
        assert_eq!(client.requests.lock().unwrap().len(), 2);
        db.close().await;
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
        // Additive unknown fields parse tolerantly: the same delta still
        // validates with identical coordinates.
        for (label, raw) in [
            ("unknown field", envelope(unknown)),
            ("unknown extra field", envelope(unknown_head)),
        ] {
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                ScriptedClient::new(raw),
            )
            .unwrap();
            assert!(
                transport.delta(base).await.is_ok(),
                "{label} must parse tolerantly"
            );
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

        // An additive unknown field parses tolerantly and validates to
        // the same coordinates; a wrong route still refuses.
        let mut unknown = value.clone();
        unknown["future_coordinate"] = json!(1);
        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            ScriptedClient::new(envelope(unknown)),
        )
        .unwrap();
        let tolerant = transport.head().await.unwrap();
        assert_eq!(tolerant.head().head_act(), head.head().head_act());
        let mut wrong_route = value;
        wrong_route["route_database_id"] = json!("route-3");
        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            ScriptedClient::new(envelope(wrong_route)),
        )
        .unwrap();
        assert!(transport.head().await.is_err());
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
    #[cfg(feature = "mcp-executor-prototype")]
    struct NativeAuthorityActSource {
        db: crate::Db,
    }

    #[cfg(feature = "mcp-executor-prototype")]
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

    #[cfg(feature = "mcp-executor-prototype")]
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
    #[cfg(feature = "mcp-executor-prototype")]
    async fn serve_executor_once(
        server: crate::mcp::ExecutorPrototypeStdioServer,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _, body) = accept_mcp_request(&listener).await;
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

    /// Accept connections until one is an MCP call. A chunked-route start is
    /// answered with the bare 404 an older host gives, so the client takes the
    /// MCP tool these stubs exist to exercise.
    async fn accept_mcp_request(
        listener: &tokio::net::TcpListener,
    ) -> (tokio::net::TcpStream, String, Vec<u8>) {
        use tokio::io::AsyncWriteExt as _;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (headers, body) = read_http_request(&mut stream).await;
            if headers.starts_with("POST /v1/databases/") {
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                continue;
            }
            return (stream, headers, body);
        }
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        use tokio::io::AsyncReadExt as _;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "HTTP request ended before its body");
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
                    return (
                        headers.into_owned(),
                        buffer[end + 4..end + 4 + length].to_vec(),
                    );
                }
            }
        }
    }

    #[cfg(feature = "mcp-executor-prototype")]
    async fn write_http_bytes(stream: &mut tokio::net::TcpStream, bytes: &[u8]) {
        write_http_response(stream, "200 OK", bytes).await;
    }

    #[cfg(feature = "mcp-executor-prototype")]
    async fn write_http_response(stream: &mut tokio::net::TcpStream, status: &str, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
    #[cfg(feature = "mcp-executor-prototype")]
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

    /// Exercise the production HTTP client against real lean dispatch, including
    /// the routing-header check hosted performs before it reaches lean selection.
    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn client_retries_real_lean_calls_with_matching_http_routing_headers() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let expected = observe_authority_act_delta(&db, ROUTE, 0).await.unwrap();
        let expected_bytes = base64::engine::general_purpose::STANDARD
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
        let server = crate::mcp::ExecutorPrototypeStdioServer::new_for_surface(
            Arc::new(registry),
            db.clone(),
            crate::mcp::Caller::authenticated("authority-act-lean-surface")
                .with_hosting_context("host:authority-act-lean-surface", ROUTE)
                .with_hosting_owner(true),
            None,
            None,
            crate::mcp::ExperimentalExecutors::empty(),
            crate::mcp::McpSurfaceMode::Lean,
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let serving = tokio::spawn(async move {
            let mut exchanges = Vec::new();
            // Head and delta each require one refusal and one retry.
            for _ in 0..4 {
                let (mut stream, headers, bytes) =
                    tokio::time::timeout(Duration::from_secs(15), accept_mcp_request(&listener))
                        .await
                        .unwrap();
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let header = |name: &str| {
                    headers.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case(name).then(|| value.trim())
                    })
                };
                if header("mcp-name") != request["params"]["name"].as_str()
                    || header("mcp-method") != request["method"].as_str()
                {
                    // Mirror hosted's pre-dispatch HEADER_MISMATCH rejection.
                    write_http_response(&mut stream, "400 Bad Request", b"HEADER_MISMATCH").await;
                    panic!("routing headers must match the request body: {headers}");
                }
                let response = server.handle_message(request.clone()).await.unwrap();
                write_http_bytes(&mut stream, &serde_json::to_vec(&response).unwrap()).await;
                exchanges.push((request, response));
            }
            exchanges
        });
        let transport = AuthorityActTransport::new(
            &format!("http://127.0.0.1:{port}"),
            ROUTE,
            &origin,
            "test-credential",
        )
        .unwrap();
        assert_eq!(
            transport.head().await.unwrap().head().head_act(),
            expected.to_inclusive_act()
        );
        let trusted = transport.delta(0).await.unwrap();
        assert_eq!(trusted.canonical_bytes().unwrap(), expected_bytes);
        let exchanges = serving.await.unwrap();
        for (index, (request, response)) in exchanges.iter().enumerate() {
            let operation = if index < 2 {
                AUTHORITY_ACT_HEAD_OPERATION
            } else {
                AUTHORITY_ACT_DELTA_OPERATION
            };
            assert_eq!(request["params"]["arguments"]["operation"], operation);
            if index % 2 == 0 {
                assert_eq!(request["params"]["name"], AUTHORITY_ACT_EXECUTOR);
                assert_eq!(response["result"]["isError"], true);
                assert_eq!(
                    response["result"]["structuredContent"]["repair"]["code"],
                    "call_executor_required"
                );
            } else {
                assert_eq!(request["params"]["name"], "call_executor");
                let mut equivalent = exchanges[index - 1].0.clone();
                equivalent["params"]["name"] = json!("call_executor");
                equivalent["params"]["arguments"]["executor"] = json!(AUTHORITY_ACT_EXECUTOR);
                assert_eq!(*request, equivalent);
                assert_eq!(response["result"]["isError"], false);
            }
        }
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
    #[cfg(feature = "mcp-executor-prototype")]
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

    // ---- chunked route ----------------------------------------------------

    type RecordedRequest = (DeltaHttpMethod, String, Option<(u64, u64)>);

    type Tamper =
        Box<dyn Fn(&DeltaHttpRequest, DeltaHttpResponse) -> DeltaHttpResponse + Send + Sync>;

    /// An honest chunked host over a real cut, with an optional per-response
    /// tamper and a record of every request the client made.
    struct ChunkedHost {
        bytes: Vec<u8>,
        meta: crate::export::BinaryDeltaMeta,
        tamper: Tamper,
        start_status: u16,
        pending_polls: Mutex<usize>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    impl ChunkedHost {
        async fn over(db: &crate::Db, from: i64) -> Arc<Self> {
            let root = tempfile::tempdir().unwrap();
            let (export, meta) = capture_authority_act_delta_export(
                db,
                ROUTE,
                from,
                root.path(),
                AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
            )
            .await
            .unwrap();
            let bytes = std::fs::read(export.path()).unwrap();
            export.cleanup().await;
            Arc::new(Self {
                bytes,
                meta,
                tamper: Box::new(|_, response| response),
                start_status: 202,
                pending_polls: Mutex::new(0),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn with(self: Arc<Self>, edit: impl FnOnce(&mut Self)) -> Arc<Self> {
            let mut host = Arc::try_unwrap(self).ok().expect("unshared host");
            edit(&mut host);
            Arc::new(host)
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn json(status: u16, body: Value) -> DeltaHttpResponse {
            DeltaHttpResponse {
                status,
                api: Some(AUTHORITY_ACT_DELTA_EXPORT_CONTRACT.into()),
                content_type: Some("application/json".into()),
                etag: None,
                content_range: None,
                body: serde_json::to_vec(&body).unwrap(),
            }
        }
    }

    impl AuthorityActDeltaHttp for ChunkedHost {
        fn send(&self, request: DeltaHttpRequest) -> DeltaHttpFuture {
            self.requests.lock().unwrap().push((
                request.method,
                request.url.clone(),
                request.range,
            ));
            assert_eq!(request.bearer, "wire-secret");
            let response = if request.method == DeltaHttpMethod::Post {
                assert_eq!(
                    request.json.as_ref().unwrap(),
                    &json!({
                        "contract": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT,
                        "version": 1,
                        "from_exclusive_act": self.meta.from_exclusive_act,
                    })
                );
                if self.start_status == 202 {
                    Self::json(
                        202,
                        json!({"api": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT,
                               "export_handle": "h-1", "status": "pending",
                               "expires_at": "2099-01-01T00:00:00.000Z"}),
                    )
                } else {
                    Self::json(self.start_status, json!({}))
                }
            } else if request.method == DeltaHttpMethod::Delete {
                Self::json(200, json!({"status": "cancelled"}))
            } else if let Some((start, end)) = request.range {
                assert!(request.url.ends_with("/h-1/bytes"));
                let end = end.min(self.bytes.len() as u64 - 1);
                DeltaHttpResponse {
                    status: 206,
                    api: Some(AUTHORITY_ACT_DELTA_EXPORT_CONTRACT.into()),
                    content_type: Some(AUTHORITY_ACT_DELTA_EXPORT_MEDIA_TYPE.into()),
                    etag: Some(format!("\"{}\"", self.meta.outer_sha256)),
                    content_range: Some(format!("bytes {start}-{end}/{}", self.bytes.len())),
                    body: self.bytes[start as usize..=end as usize].to_vec(),
                }
            } else {
                let mut pending = self.pending_polls.lock().unwrap();
                if *pending > 0 {
                    *pending -= 1;
                    Self::json(200, json!({"status": "pending", "export_handle": "h-1"}))
                } else {
                    Self::json(
                        200,
                        json!({"export_handle": "h-1", "status": "ready",
                               "route_database_id": self.meta.route_database_id,
                               "origin_database_id": self.meta.origin_database_id,
                               "from_exclusive_act": self.meta.from_exclusive_act,
                               "to_inclusive_act": self.meta.to_inclusive_act,
                               "content_sha256": self.meta.content_sha256,
                               "outer_sha256": self.meta.outer_sha256,
                               "size_bytes": self.bytes.len(),
                               "expires_at": "2099-01-01T00:00:00.000Z"}),
                    )
                }
            };
            let response = (self.tamper)(&request, response);
            Box::pin(async move { Ok(response) })
        }
    }

    fn chunked_transport(origin: &str, host: Arc<ChunkedHost>) -> AuthorityActTransport {
        AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            origin,
            "wire-secret",
            // The MCP seam must never be reached on the chunked path.
            QueuedClient::new(vec![]),
        )
        .unwrap()
        .with_delta_http(
            host,
            Duration::from_millis(1),
            Duration::from_secs(2),
            AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
        )
    }

    #[tokio::test]
    async fn chunked_route_assembles_a_multi_range_cut_into_the_same_witness_as_mcp() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "chunked").await;
        // Two and a half mebibytes of referenced blob forces three ranges.
        let blob_bytes: Vec<u8> = (0..2_500_000_u32).map(|n| (n % 251) as u8).collect();
        let blob = crate::blob::insert_blob(&db, &blob_bytes, None, None)
            .await
            .unwrap();
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: SECOND_RECORD_ID.into(),
                event_type: "facet.set".into(),
                payload: json!({"key": "blob_ref", "value": blob.id}),
                actor: None,
            },
        )
        .await
        .unwrap();
        let host = ChunkedHost::over(&db, base).await;
        *host.pending_polls.lock().unwrap() = 2;
        let transport = chunked_transport(&origin, host.clone());
        let trusted = transport.delta(base).await.unwrap();
        assert_eq!(trusted.canonical_bytes().unwrap(), host.bytes);
        assert_eq!(trusted.from_exclusive_act(), base);

        let requests = host.requests();
        let ranges: Vec<_> = requests.iter().filter_map(|request| request.2).collect();
        assert!(ranges.len() >= 3, "{ranges:?}");
        assert_eq!(ranges[0].0, 0);
        for pair in ranges.windows(2) {
            assert_eq!(pair[1].0, pair[0].1 + 1, "sequential, contiguous ranges");
            assert_eq!(pair[0].1 - pair[0].0 + 1, DELTA_CHUNK_BYTES);
        }
        assert_eq!(requests.first().unwrap().0, DeltaHttpMethod::Post);
        assert_eq!(requests.last().unwrap().0, DeltaHttpMethod::Delete);
        assert!(requests[0]
            .1
            .ends_with("/v1/databases/route%2D1/standby-delta/exports"));
        db.close().await;
    }

    /// Run one tampered exchange and return the refusal, cancelling included.
    async fn chunked_refusal(
        db: &crate::Db,
        base: i64,
        tamper: impl Fn(&DeltaHttpRequest, DeltaHttpResponse) -> DeltaHttpResponse
            + Send
            + Sync
            + 'static,
    ) -> (String, Arc<ChunkedHost>) {
        let origin = origin(db).await;
        let host = ChunkedHost::over(db, base)
            .await
            .with(|host| host.tamper = Box::new(tamper));
        let message = refusal_message(&chunked_transport(&origin, host.clone()), base).await;
        (message, host)
    }

    #[tokio::test]
    async fn chunked_route_refuses_inconsistent_ranges_and_cancels() {
        let db = real_authority().await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "chunk drift").await;
        let blob = crate::blob::insert_blob(&db, &vec![7_u8; 1_500_000], None, None)
            .await
            .unwrap();
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: SECOND_RECORD_ID.into(),
                event_type: "facet.set".into(),
                payload: json!({"key": "blob_ref", "value": blob.id}),
                actor: None,
            },
        )
        .await
        .unwrap();

        // Each fault lands on the second range, after the first was accepted.
        type Edit = fn(&mut DeltaHttpResponse);
        let second = |request: &DeltaHttpRequest| request.range.is_some_and(|r| r.0 > 0);
        let faults: [(&str, Edit); 5] = [
            ("validator", |r| {
                r.etag = Some(format!("\"{}\"", "9".repeat(64)))
            }),
            ("media type", |r| {
                r.content_type = Some("application/json".into())
            }),
            ("range", |r| r.content_range = Some("bytes 0-0/1".into())),
            ("length", |r| {
                r.body.pop();
            }),
            ("identity", |r| r.api = None),
        ];
        for (name, edit) in faults {
            let (message, host) = chunked_refusal(&db, base, move |request, mut response| {
                if second(request) {
                    edit(&mut response);
                }
                response
            })
            .await;
            assert!(!message.contains("wire-secret"), "{name}: {message}");
            assert_eq!(
                host.requests().last().unwrap().0,
                DeltaHttpMethod::Delete,
                "{name}: a refused transfer still releases the spool"
            );
        }

        // A flipped byte keeps every header honest and is caught by the digest.
        let (message, _) = chunked_refusal(&db, base, |request, mut response| {
            if request.range.is_some_and(|r| r.0 > 0) {
                response.body[0] ^= 1;
            }
            response
        })
        .await;
        assert!(message.contains("outer digest"), "{message}");
        db.close().await;
    }

    #[tokio::test]
    async fn chunked_route_refuses_route_origin_and_bound_drift_in_the_ready_claim() {
        let db = real_authority().await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "ready drift").await;
        for (field, value) in [
            ("route_database_id", json!("other-route")),
            (
                "origin_database_id",
                json!("ndb_ffffffffffffffffffffffffffffffff"),
            ),
            ("from_exclusive_act", json!(base + 1)),
            ("to_inclusive_act", json!(base + 7)),
            ("content_sha256", json!("a".repeat(64))),
        ] {
            let (message, _) = chunked_refusal(&db, base, move |request, mut response| {
                if request.method == DeltaHttpMethod::Get && request.range.is_none() {
                    let mut body: Value = serde_json::from_slice(&response.body).unwrap();
                    body[field] = value.clone();
                    response.body = serde_json::to_vec(&body).unwrap();
                }
                response
            })
            .await;
            assert!(!message.is_empty(), "{field} drift must refuse");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn only_a_bare_404_means_an_older_host_and_other_refusals_do_not_fall_back() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "older host").await;
        let response = observe_authority_act_delta(&db, ROUTE, base).await.unwrap();

        // A bare 404 falls back to the MCP tool.
        let host = ChunkedHost::over(&db, base)
            .await
            .with(|host| host.start_status = 404);
        let mcp = QueuedClient::new(vec![envelope(delta_envelope(&response))]);
        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            mcp.clone(),
        )
        .unwrap()
        .with_delta_http(
            host,
            Duration::from_millis(1),
            Duration::from_secs(2),
            AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
        );
        transport
            .delta(base)
            .await
            .unwrap_or_else(|_| panic!("fallback must succeed"));
        assert_eq!(mcp.requests.lock().unwrap().len(), 1);

        // A 404 that carries a Native error code is a real refusal.
        let host = ChunkedHost::over(&db, base).await.with(|host| {
            host.tamper = Box::new(|request, mut response| {
                if request.method == DeltaHttpMethod::Post {
                    response.status = 404;
                    response.body = br#"{"error_code":"database_not_found"}"#.to_vec();
                }
                response
            })
        });
        let mcp = QueuedClient::new(vec![]);
        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            mcp.clone(),
        )
        .unwrap()
        .with_delta_http(
            host,
            Duration::from_millis(1),
            Duration::from_secs(2),
            1 << 20,
        );
        let message = refusal_message(&transport, base).await;
        assert!(message.contains("database_not_found"), "{message}");
        assert!(mcp.requests.lock().unwrap().is_empty(), "no MCP fallback");

        // Redirects, auth refusals and hosted unavailability are not an absent route.
        for (status, expect) in [(302, "HTTP status 302"), (503, "HTTP status 503")] {
            let host = ChunkedHost::over(&db, base)
                .await
                .with(|host| host.start_status = status);
            let message = refusal_message(&chunked_transport(&origin, host), base).await;
            assert!(message.contains(expect), "{status}: {message}");
        }
        let host = ChunkedHost::over(&db, base)
            .await
            .with(|host| host.start_status = 409);
        let message = refusal_message(&chunked_transport(&origin, host), base).await;
        assert!(message.contains("request failed"), "{message}");
        db.close().await;
    }

    #[tokio::test]
    async fn too_large_is_typed_from_the_chunked_code_the_client_ceiling_and_the_legacy_refusal() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let base = read_authority_act_head(&db).await.unwrap().head_act;
        append_record(&db, SECOND_RECORD_ID, "too large").await;

        // The hosted capture reports its stable code.
        let host = ChunkedHost::over(&db, base).await.with(|host| {
            host.tamper = Box::new(|request, mut response| {
                if request.method == DeltaHttpMethod::Get && request.range.is_none() {
                    response.body = serde_json::to_vec(&json!({
                        "export_handle": "h-1", "status": "failed",
                        "error_code": "delta_too_large"
                    }))
                    .unwrap();
                }
                response
            })
        });
        let error = chunked_transport(&origin, host.clone())
            .delta(base)
            .await
            .err()
            .expect("refused");
        assert!(is_delta_too_large(&error), "{error}");
        assert_eq!(host.requests().last().unwrap().0, DeltaHttpMethod::Delete);

        // A ready cut above the client's own ceiling is refused before any bytes.
        let host = ChunkedHost::over(&db, base).await;
        let transport = chunked_transport(&origin, host.clone()).with_delta_http(
            host.clone(),
            Duration::from_millis(1),
            Duration::from_secs(2),
            host.bytes.len() - 1,
        );
        let error = transport.delta(base).await.err().expect("refused");
        assert!(is_delta_too_large(&error), "{error}");
        assert!(host.requests().iter().all(|request| request.2.is_none()));

        // The legacy MCP tool's oversize refusal is the same typed reason, on
        // the first attempt and after the lean repair retry.
        let refusal = |text: &str| {
            let mut response: Value = serde_json::from_slice(&envelope(json!({
                "error": text, "run_context": {}
            })))
            .unwrap();
            response["result"]["isError"] = json!(true);
            serde_json::to_vec(&response).unwrap()
        };
        let oversize =
            "authority act delta exceeds the bounded transport ceiling; take a whole snapshot";
        for queued in [
            vec![refusal(oversize)],
            vec![tool_refusal("call_executor_required"), refusal(oversize)],
        ] {
            let transport = AuthorityActTransport::with_client(
                "http://localhost",
                ROUTE,
                &origin,
                "wire-secret",
                QueuedClient::new(queued),
            )
            .unwrap();
            let error = transport.delta(base).await.err().expect("refused");
            assert!(is_delta_too_large(&error), "{error}");
        }
        // Other tool failures stay generic.
        let transport = AuthorityActTransport::with_client(
            "http://localhost",
            ROUTE,
            &origin,
            "wire-secret",
            QueuedClient::new(vec![refusal("something else")]),
        )
        .unwrap();
        let error = transport.delta(base).await.err().expect("refused");
        assert!(!is_delta_too_large(&error), "{error}");
        db.close().await;
    }

    #[tokio::test]
    async fn a_capture_that_never_finishes_times_out_and_is_cancelled() {
        let db = real_authority().await;
        let origin = origin(&db).await;
        let host = ChunkedHost::over(&db, 0).await;
        *host.pending_polls.lock().unwrap() = usize::MAX;
        let transport = chunked_transport(&origin, host.clone()).with_delta_http(
            host.clone(),
            Duration::from_millis(1),
            Duration::from_millis(30),
            AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
        );
        let message = refusal_message(&transport, 0).await;
        assert!(message.contains("request failed"), "{message}");
        assert_eq!(host.requests().last().unwrap().0, DeltaHttpMethod::Delete);
        db.close().await;
    }

    /// The real HTTP seam: refuses redirects, maps 401/403 to Auth, honours the
    /// maintenance marker before any body, and bounds what it reads, on every
    /// method the chunked family uses.
    #[tokio::test]
    async fn chunked_http_seam_keeps_the_existing_redirect_auth_and_maintenance_behaviour() {
        use tokio::io::AsyncWriteExt as _;
        let client = HttpAuthorityActClient::new().unwrap();
        for method in [
            DeltaHttpMethod::Post,
            DeltaHttpMethod::Get,
            DeltaHttpMethod::Delete,
        ] {
            let cases: [(&str, &str, &str); 5] = [
                ("401 Unauthorized", "", "auth"),
                ("403 Forbidden", "", "auth"),
                ("302 Found", "location: http://127.0.0.1:1/x\r\n", "status"),
                ("200 OK", "x-native-read-only: true\r\n", "maintenance"),
                ("206 Partial Content", "", "ok"),
            ];
            for (status, extra, expectation) in cases {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let extra = extra.to_string();
                let status_line = status.to_string();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let (headers, _) = read_http_request(&mut stream).await;
                    assert!(headers
                        .to_ascii_lowercase()
                        .contains("authorization: bearer wire-secret"));
                    let head = format!(
                        "HTTP/1.1 {status_line}\r\n{extra}etag: \"abc\"\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi"
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                });
                let result = client
                    .send(DeltaHttpRequest {
                        method,
                        url: format!("http://127.0.0.1:{port}/v1/x"),
                        bearer: "wire-secret".into(),
                        json: (method == DeltaHttpMethod::Post).then(|| json!({})),
                        range: (method == DeltaHttpMethod::Get).then_some((0, 1)),
                        max_body: 1024,
                    })
                    .await;
                server.await.unwrap();
                match (expectation, result) {
                    ("auth", Err(Error::Auth(message))) => {
                        assert!(!message.contains("wire-secret"))
                    }
                    ("maintenance", Err(error)) => assert_eq!(
                        error.to_string(),
                        Error::engine(MAINTENANCE_SNAPSHOT_ERROR).to_string()
                    ),
                    ("status", Ok(response)) => {
                        assert_eq!(response.status, 302, "redirects are never followed")
                    }
                    ("ok", Ok(response)) => {
                        assert_eq!(response.status, 206);
                        assert_eq!(response.etag.as_deref(), Some("\"abc\""));
                        assert_eq!(response.body, b"hi");
                    }
                    (expected, other) => {
                        panic!(
                            "{method:?} {status}: expected {expected}, got {:?}",
                            other.err()
                        )
                    }
                }
            }
        }
        // A body above the request's ceiling is refused, not truncated.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_http_request(&mut stream).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\n12345678",
                )
                .await;
        });
        let error = client
            .send(DeltaHttpRequest {
                method: DeltaHttpMethod::Get,
                url: format!("http://127.0.0.1:{port}/v1/x"),
                bearer: "wire-secret".into(),
                json: None,
                range: None,
                max_body: 4,
            })
            .await
            .err()
            .expect("oversize body refused");
        assert!(error.to_string().contains("too large"), "{error}");
    }
}
