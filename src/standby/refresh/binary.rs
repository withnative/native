//! Bounded owner-authenticated HTTP acquisition for an initial standby generation.

use super::transfer_repr::SnapshotTransfer;
use super::*;
use futures::{stream, StreamExt};
use reqwest::header::{
    HeaderMap, HeaderName, ACCEPT_ENCODING, ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE,
};

const API_HEADER: HeaderName = HeaderName::from_static("x-native-export-api");
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_IN_FLIGHT_RANGES: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CHUNK_RETRY_DELAYS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(250),
    Duration::from_millis(750),
];

type BinaryFuture<T> = Pin<Box<dyn Future<Output = std::result::Result<T, AttemptError>> + Send>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BinaryExport {
    pub handle: String,
    pub transfer: SnapshotTransfer,
}

impl BinaryExport {
    fn from_ready(ledger: &binary_resume::ResumeLedger) -> Result<Self> {
        ledger.transfer().validate()?;
        Ok(Self {
            handle: ledger.export_handle.clone(),
            transfer: ledger.transfer(),
        })
    }

    fn identity(handle: String) -> Self {
        Self {
            handle,
            transfer: SnapshotTransfer::IdentityV1,
        }
    }
}

#[cfg(test)]
impl From<&str> for BinaryExport {
    fn from(handle: &str) -> Self {
        Self::identity(handle.into())
    }
}

#[cfg(test)]
impl From<String> for BinaryExport {
    fn from(handle: String) -> Self {
        Self::identity(handle)
    }
}

#[derive(Clone)]
pub(super) struct BinaryReadRequest {
    origin: String,
    database: String,
    pub(super) bearer: String,
    handle: BinaryExport,
    pub(super) offset: u64,
    pub(super) length: usize,
    size: u64,
    sha256: String,
}

/// The controller owns staging, hashing and promotion; this seam owns only the
/// bounded wire exchange. Tests can inject a transport without changing the
/// installed-generation path.
pub(super) trait BinarySnapshotClient: Send + Sync {
    fn start(
        &self,
        origin: String,
        database: String,
        bearer: String,
        consumer: StandbyConsumerIdentity,
        transfer: SnapshotTransfer,
    ) -> BinaryFuture<BinaryExport>;
    fn poll(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: BinaryExport,
    ) -> BinaryFuture<BinaryPoll>;
    fn read(&self, request: BinaryReadRequest) -> BinaryFuture<Vec<u8>>;
    fn cancel(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: BinaryExport,
    ) -> BinaryFuture<()>;
}

pub(super) enum BinaryPoll {
    Pending,
    Ready {
        manifest: Box<StandbySnapshotManifest>,
        size: u64,
        sha256: String,
        encoded: Option<(u64, String)>,
    },
}

/// Liveness of retained resume state from one authorized poll.
pub(super) enum ResumeProbe {
    Absent,
    Live,
    Gone,
}

/// Whether the transfer may create a fresh or replacement export.
/// Resumed transfers inside the FULL cooldown run reuse-only: a handle
/// lost between probe and transfer defers instead of capturing again.
#[derive(Clone, Copy)]
pub(super) enum FreshCaptureBudget {
    Allowed,
    ReuseOnly,
}

fn throttled_by_cooldown() -> AttemptError {
    AttemptError::new(
        RefreshFailureClass::Throttled,
        "standby whole snapshot held back by its minimum interval",
        Error::engine("standby whole snapshot held back by its minimum interval"),
    )
}

pub(super) struct HttpBinarySnapshotClient {
    client: reqwest::Client,
}

impl HttpBinarySnapshotClient {
    pub(super) fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| Error::engine("cannot build standby binary HTTP client"))?;
        Ok(Self { client })
    }
}

fn url(
    origin: &str,
    database: &str,
    transfer: SnapshotTransfer,
    handle: Option<&str>,
    bytes: bool,
) -> String {
    let version = match transfer {
        SnapshotTransfer::IdentityV1 => "v1",
        SnapshotTransfer::GzipV1 { .. } => "v2",
    };
    let mut url = format!(
        "{origin}/{version}/databases/{}/standby-snapshot/exports",
        utf8_percent_encode(database, NON_ALPHANUMERIC)
    );
    if let Some(handle) = handle {
        url.push('/');
        url.push_str(&utf8_percent_encode(handle, NON_ALPHANUMERIC).to_string());
    }
    if bytes {
        url.push_str("/bytes");
    }
    url
}

fn network_error(error: reqwest::Error) -> AttemptError {
    if error.is_timeout() {
        AttemptError::new(
            RefreshFailureClass::Timeout,
            "standby binary request timed out",
            Error::engine("standby binary request timed out"),
        )
    } else {
        AttemptError::new(
            RefreshFailureClass::Network,
            "standby binary request failed",
            Error::engine("standby binary request failed"),
        )
    }
}

fn protocol(message: &'static str) -> AttemptError {
    AttemptError::new(
        RefreshFailureClass::Protocol,
        message,
        Error::engine(message),
    )
}

fn status_error(status: reqwest::StatusCode) -> AttemptError {
    match status.as_u16() {
        401 | 403 => AttemptError::new(
            RefreshFailureClass::Authentication,
            "standby binary authentication was refused",
            Error::auth("standby binary authentication was refused"),
        ),
        416 => integrity(
            "standby binary range was refused",
            Error::engine("standby binary range was refused"),
        ),
        408 | 425 | 429 | 500..=599 => AttemptError::new(
            RefreshFailureClass::Network,
            "standby binary endpoint was unavailable",
            Error::engine("standby binary endpoint was unavailable"),
        ),
        _ => protocol("standby binary endpoint refused the request"),
    }
    .with_detail(http_failure_detail(status.as_u16()))
}

fn one_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

fn require_api(
    headers: &HeaderMap,
    transfer: SnapshotTransfer,
) -> std::result::Result<(), AttemptError> {
    transfer
        .validate()
        .map_err(|_| protocol("standby binary transfer representation mismatch"))?;
    if one_header(headers, &API_HEADER) != Some(transfer.route_api())
        || headers.contains_key(CONTENT_ENCODING)
    {
        return Err(protocol("standby binary response contract mismatch"));
    }
    Ok(())
}

async fn bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> std::result::Result<Vec<u8>, AttemptError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(protocol("standby binary response exceeded its bound")
            .with_detail("response_too_large"));
    }
    let mut bytes = Vec::with_capacity(limit);
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(protocol("standby binary response exceeded its bound")
                .with_detail("response_too_large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartBody {
    api: String,
    export_handle: String,
    status: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelBody {
    api: String,
    status: String,
}

fn valid_expiry(value: &str) -> bool {
    value.len() <= 40 && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollBody {
    api: String,
    export_handle: String,
    status: String,
    expires_at: String,
    manifest: Option<StandbySnapshotManifest>,
    size_bytes: Option<u64>,
    sha256: Option<String>,
    error_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GzipPollBody {
    api: String,
    export_handle: String,
    status: String,
    expires_at: String,
    manifest: Option<StandbySnapshotManifest>,
    size_bytes: Option<u64>,
    sha256: Option<String>,
    error_code: Option<String>,
    transfer: Option<SnapshotTransfer>,
    encoded_size_bytes: Option<u64>,
    encoded_sha256: Option<String>,
}

impl BinarySnapshotClient for HttpBinarySnapshotClient {
    fn start(
        &self,
        origin: String,
        database: String,
        bearer: String,
        consumer: StandbyConsumerIdentity,
        transfer: SnapshotTransfer,
    ) -> BinaryFuture<BinaryExport> {
        let client = self.client.clone();
        Box::pin(async move {
            transfer
                .validate()
                .map_err(|_| protocol("standby binary transfer representation mismatch"))?;
            let response = client
                .post(url(&origin, &database, transfer, None, false))
                .bearer_auth(bearer)
                .header(ACCEPT_ENCODING, "identity")
                .json(
                    &json!({"contract": transfer.route_api(), "version": 1, "consumer": consumer}),
                )
                .send()
                .await
                .map_err(network_error)?;
            if response.status() != reqwest::StatusCode::ACCEPTED {
                if transfer != SnapshotTransfer::IdentityV1
                    && response.status() == reqwest::StatusCode::NOT_FOUND
                    && !response.headers().contains_key(&API_HEADER)
                    && !response.headers().contains_key(CONTENT_ENCODING)
                {
                    let bytes = bounded_body(response, MAX_METADATA_BYTES).await?;
                    return Err(status_error(reqwest::StatusCode::NOT_FOUND).with_detail(
                        if bytes.is_empty() {
                            "missing_v2_route"
                        } else {
                            "http_404"
                        },
                    ));
                }
                return Err(status_error(response.status()));
            }
            require_api(response.headers(), transfer)?;
            let body: StartBody =
                serde_json::from_slice(&bounded_body(response, MAX_METADATA_BYTES).await?)
                    .map_err(|_| {
                        protocol("standby binary start response was invalid").with_detail("decode")
                    })?;
            if body.api != transfer.route_api()
                || body.status != "pending"
                || !valid_expiry(&body.expires_at)
                || uuid::Uuid::parse_str(&body.export_handle).is_err()
            {
                return Err(protocol("standby binary start response was invalid"));
            }
            Ok(if transfer == SnapshotTransfer::IdentityV1 {
                BinaryExport::identity(body.export_handle)
            } else {
                BinaryExport {
                    handle: body.export_handle,
                    transfer,
                }
            })
        })
    }

    fn poll(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: BinaryExport,
    ) -> BinaryFuture<BinaryPoll> {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .get(url(
                    &origin,
                    &database,
                    handle.transfer,
                    Some(&handle.handle),
                    false,
                ))
                .bearer_auth(bearer)
                .header(ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(network_error)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(status_error(response.status()));
            }
            require_api(response.headers(), handle.transfer)?;
            let bytes = bounded_body(response, MAX_METADATA_BYTES).await?;
            let (body, encoded) = if handle.transfer == SnapshotTransfer::IdentityV1 {
                (
                    serde_json::from_slice::<PollBody>(&bytes).map_err(|_| {
                        protocol("standby binary poll response was invalid")
                            .with_detail("invalid_response")
                    })?,
                    None,
                )
            } else {
                let gzip: GzipPollBody = serde_json::from_slice(&bytes).map_err(|_| {
                    protocol("standby binary poll response was invalid")
                        .with_detail("invalid_response")
                })?;
                let encoded = if gzip.status == "ready" {
                    if gzip.transfer != Some(handle.transfer) {
                        return Err(protocol("standby binary transfer representation mismatch"));
                    }
                    let (Some(size), Some(sha)) = (gzip.encoded_size_bytes, gzip.encoded_sha256)
                    else {
                        return Err(protocol("standby binary encoded identity is missing"));
                    };
                    transfer_repr::check_byte_identity(size, &sha, "encoded")
                        .map_err(|_| protocol("standby binary encoded identity is invalid"))?;
                    Some((size, sha))
                } else {
                    if gzip.transfer.is_some()
                        || gzip.encoded_size_bytes.is_some()
                        || gzip.encoded_sha256.is_some()
                    {
                        return Err(protocol("standby binary poll response was invalid"));
                    }
                    None
                };
                (
                    PollBody {
                        api: gzip.api,
                        export_handle: gzip.export_handle,
                        status: gzip.status,
                        expires_at: gzip.expires_at,
                        manifest: gzip.manifest,
                        size_bytes: gzip.size_bytes,
                        sha256: gzip.sha256,
                        error_code: gzip.error_code,
                    },
                    encoded,
                )
            };
            if body.api != handle.transfer.route_api()
                || body.export_handle != handle.handle
                || !valid_expiry(&body.expires_at)
            {
                return Err(protocol("standby binary poll response was invalid")
                    .with_detail("invalid_response"));
            }
            match body.status.as_str() {
                "pending"
                    if body.manifest.is_none()
                        && body.size_bytes.is_none()
                        && body.sha256.is_none()
                        && body.error_code.is_none() =>
                {
                    Ok(BinaryPoll::Pending)
                }
                "ready" if body.error_code.is_none() => {
                    let (Some(manifest), Some(size), Some(sha256)) =
                        (body.manifest, body.size_bytes, body.sha256)
                    else {
                        return Err(protocol("standby binary ready response was incomplete"));
                    };
                    manifest.canonical_json().map_err(|_| {
                        integrity(
                            "standby binary manifest was invalid",
                            Error::engine("standby binary manifest was invalid"),
                        )
                    })?;
                    if size == 0
                        || manifest.snapshot.size_bytes != size
                        || manifest.snapshot.sha256 != sha256
                    {
                        return Err(integrity(
                            "standby binary manifest identity mismatch",
                            Error::engine("standby binary manifest identity mismatch"),
                        ));
                    }
                    Ok(BinaryPoll::Ready {
                        manifest: Box::new(manifest),
                        size,
                        sha256,
                        encoded,
                    })
                }
                "failed"
                    if body.manifest.is_none()
                        && body.size_bytes.is_none()
                        && body.sha256.is_none()
                        && body.error_code.is_some() =>
                {
                    Err(protocol("standby binary capture failed").with_detail("tool_failure"))
                }
                _ => Err(protocol("standby binary poll response was invalid")
                    .with_detail("invalid_response")),
            }
        })
    }

    fn read(&self, request: BinaryReadRequest) -> BinaryFuture<Vec<u8>> {
        let client = self.client.clone();
        Box::pin(async move {
            let BinaryReadRequest {
                origin,
                database,
                bearer,
                handle,
                offset,
                length,
                size,
                sha256,
            } = request;
            if length == 0
                || length > MAX_CHUNK_BYTES
                || offset
                    .checked_add(length as u64)
                    .is_none_or(|end| end > size)
            {
                return Err(protocol("standby binary range request was invalid"));
            }
            let end = offset + length as u64 - 1;
            let response = client
                .get(url(
                    &origin,
                    &database,
                    handle.transfer,
                    Some(&handle.handle),
                    true,
                ))
                .bearer_auth(bearer)
                .header(ACCEPT_ENCODING, "identity")
                .header(RANGE, format!("bytes={offset}-{end}"))
                .send()
                .await
                .map_err(network_error)?;
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(status_error(response.status()));
            }
            let headers = response.headers();
            require_api(headers, handle.transfer)?;
            if one_header(headers, &CONTENT_RANGE).map(str::to_owned)
                != Some(format!("bytes {offset}-{end}/{size}"))
                || one_header(headers, &ETAG).map(str::to_owned) != Some(format!("\"{sha256}\""))
                || one_header(headers, &CONTENT_LENGTH) != Some(length.to_string().as_str())
                || one_header(headers, &CONTENT_TYPE)
                    != Some(match handle.transfer {
                        SnapshotTransfer::IdentityV1 => STANDBY_SNAPSHOT_MEDIA_TYPE,
                        SnapshotTransfer::GzipV1 { .. } => "application/gzip",
                    })
                || one_header(headers, &ACCEPT_RANGES) != Some("bytes")
            {
                return Err(integrity(
                    "standby binary range response mismatch",
                    Error::engine("standby binary range response mismatch"),
                ));
            }
            let bytes = bounded_body(response, length).await?;
            if bytes.len() != length {
                return Err(integrity(
                    "standby binary range length mismatch",
                    Error::engine("standby binary range length mismatch"),
                ));
            }
            Ok(bytes)
        })
    }

    fn cancel(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: BinaryExport,
    ) -> BinaryFuture<()> {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .delete(url(
                    &origin,
                    &database,
                    handle.transfer,
                    Some(&handle.handle),
                    false,
                ))
                .bearer_auth(bearer)
                .send()
                .await
                .map_err(network_error)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(status_error(response.status()));
            }
            require_api(response.headers(), handle.transfer)?;
            let body: CancelBody =
                serde_json::from_slice(&bounded_body(response, MAX_METADATA_BYTES).await?)
                    .map_err(|_| protocol("standby binary cancel response was invalid"))?;
            if body.api != handle.transfer.route_api() || body.status != "cancelled" {
                return Err(protocol("standby binary cancel response was invalid"));
            }
            Ok(())
        })
    }
}

async fn discard_owned(
    lease: &binary_work::TransferLease,
    dir: &Path,
) -> std::result::Result<(), AttemptError> {
    let dir = dir.to_owned();
    lease
        .run(move || binary_resume::discard_resume(&dir).map_err(local_io))
        .await
}

struct CancelHandle {
    client: Arc<dyn BinarySnapshotClient>,
    origin: String,
    database: String,
    credential_file: PathBuf,
    handle: BinaryExport,
    armed: bool,
}

impl CancelHandle {
    /// Arm the server DELETE for an explicit terminal fault or a completed
    /// transfer. The guard is disarmed by default so dropping the future —
    /// timeout, task cancellation, shutdown — never deletes an export whose
    /// durable ledger survives for the next attempt.
    fn arm(&mut self) {
        self.armed = true;
    }
}

impl Drop for CancelHandle {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            let origin = self.origin.clone();
            let database = self.database.clone();
            let credential_file = self.credential_file.clone();
            let handle = self.handle.clone();
            runtime.spawn(async move {
                if let Ok(bearer) = read_credential(&credential_file) {
                    let _ = client.cancel(origin, database, bearer, handle).await;
                }
            });
        }
    }
}

impl StandbyRefreshController {
    async fn read_binary_chunk_with_retry(
        &self,
        mut request: BinaryReadRequest,
    ) -> std::result::Result<Vec<u8>, AttemptError> {
        for (attempt, delay) in CHUNK_RETRY_DELAYS.into_iter().enumerate() {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            // No partial bytes reach staging: read() validates the entire
            // 206 body before returning. Every retry keeps this handle and
            // the last completed offset, then rechecks Range, ETag and size.
            // A capture or transfer can outlive an OAuth access token. The
            // owner credential controller atomically replaces this file;
            // reapply its guarded read on every request, including retries.
            request.bearer = read_credential(&self.config.credential_file)?;
            match self.binary_client.read(request.clone()).await {
                Ok(bytes) => return Ok(bytes),
                Err(error)
                    if matches!(
                        error.class,
                        RefreshFailureClass::Network | RefreshFailureClass::Timeout
                    ) && attempt + 1 < CHUNK_RETRY_DELAYS.len() => {}
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded binary chunk retry returns on its last attempt")
    }

    pub(super) async fn download_binary_and_install(
        &self,
        bearer: String,
        snapshot_path: &Path,
        manifest_path: &Path,
        budget: FreshCaptureBudget,
        progress: &mut AttemptProgress,
    ) -> std::result::Result<(InstalledGeneration, Vec<String>), AttemptError> {
        let manifest = self
            .download_binary_with_progress(bearer, snapshot_path, budget, Some(progress))
            .await?;
        self.install_downloaded_snapshot(manifest, snapshot_path, manifest_path)
            .await
    }

    /// Handle-loss signals: the export is gone server-side (sliding expiry
    /// or restart). The caller must clear the unusable cache and decide
    /// between deferral (inside FULL cooldown) and one fresh export.
    pub(super) fn is_binary_handle_gone(error: &AttemptError) -> bool {
        matches!(error.class, RefreshFailureClass::Protocol)
            && matches!(error.detail, "http_404" | "http_410")
    }

    /// Invalid wire contracts and byte identities are terminal. Only auth,
    /// network and timeout failures preserve custody for another attempt.
    fn is_binary_transfer_terminal(error: &AttemptError) -> bool {
        matches!(
            error.class,
            RefreshFailureClass::Protocol | RefreshFailureClass::DownloadIntegrity
        )
    }

    pub(super) fn resume_binding(&self) -> binary_resume::ResumeBinding {
        binary_resume::ResumeBinding {
            origin: self.config.hosted_origin.clone(),
            hosted_route_database_id: self.runtime.hosted_route_database_id.clone(),
            origin_database_id: self.runtime.origin_database_id.clone(),
            consumer: self.declared_consumer(),
        }
    }

    /// Load retained resume state without touching the network. Unparseable
    /// or mis-bound files are discarded so they can never gate progress,
    /// but an undeletable custody file fails loudly instead of proceeding
    /// on uncertain cleanup. Returns ready state when present, else the
    /// pending capture, else None.
    fn load_retained_resume(
        dir: &Path,
        binding: &binary_resume::ResumeBinding,
    ) -> std::result::Result<
        Option<std::result::Result<binary_resume::ResumeLedger, transfer_repr::PendingTransfer>>,
        AttemptError,
    > {
        let loaded = (|| -> Result<_> {
            let ready = binary_resume::load_resume_ledger(dir, binding)?;
            let pending = transfer_repr::load_pending_transfer(dir, binding)?;
            let legacy = binary_resume::load_pending_capture(dir, binding)?;
            // New pending custody is authoritative, never a companion required
            // to interpret an otherwise ambiguous legacy pending record.
            if pending.is_some() && legacy.is_some() {
                return Err(Error::engine("standby conflicting pending custody"));
            }
            let pending = match (pending, legacy) {
                (Some(pending), _) => Some(pending),
                (_, Some(legacy)) => Some(transfer_repr::bind_pending_transfer(
                    SnapshotTransfer::IdentityV1.route_api(),
                    SnapshotTransfer::IdentityV1,
                    legacy,
                )?),
                _ => None,
            };
            if let Some(ready) = ready {
                if let Some(pending) = &pending {
                    if pending.pending.export_handle != ready.export_handle
                        || pending.transfer != ready.transfer()
                    {
                        return Err(Error::engine("standby pending and ready custody disagree"));
                    }
                }
                return Ok(Some(Ok(ready)));
            }
            Ok(pending.map(Err))
        })();
        match loaded {
            Ok(Some(Ok(ready))) => {
                binary_resume::discard_pending(dir).map_err(local_io)?;
                Ok(Some(Ok(ready)))
            }
            Ok(Some(Err(pending))) => Ok(Some(Err(pending))),
            Ok(None) | Err(_) => {
                binary_resume::discard_resume(dir).map_err(local_io)?;
                Ok(None)
            }
        }
    }

    fn check_saved_poll(
        saved: &binary_resume::ResumeLedger,
        poll: &BinaryPoll,
    ) -> std::result::Result<(), AttemptError> {
        let BinaryPoll::Ready {
            manifest,
            size,
            sha256,
            encoded,
        } = poll
        else {
            return Err(protocol("standby ready capture reverted to pending"));
        };
        binary_resume::check_ready_against_poll(saved, manifest, *size, sha256)
            .map_err(|error| integrity("standby binary manifest identity mismatch", error))?;
        saved
            .ready_identity()
            .and_then(|identity| {
                if identity.export_handle != saved.export_handle {
                    return Err(Error::engine("standby resume handle mismatch"));
                }
                identity.check_against_poll(
                    manifest,
                    *size,
                    sha256,
                    encoded.as_ref().map(|pair| pair.0),
                    encoded.as_ref().map(|pair| pair.1.as_str()),
                )
            })
            .map_err(|error| integrity("standby binary manifest identity mismatch", error))
    }

    /// One authorized liveness poll over retained resume state, before the
    /// FULL cooldown gate. Live handles proceed regardless of cooldown
    /// without consuming capture budget; gone handles are cleared for the
    /// ordinary gate; other failures follow existing failure paths and an
    /// authentication refusal never falls back to a fresh capture.
    pub(super) async fn probe_binary_resume(
        &self,
    ) -> std::result::Result<ResumeProbe, AttemptError> {
        if !self.binary_snapshot_enabled {
            return Ok(ResumeProbe::Absent);
        }
        let lease = binary_work::TransferLease::acquire(&self.refresh_dir)?;
        let binding = self.resume_binding();
        let dir = self.refresh_dir.clone();
        let saved_binding = binding.clone();
        let retained = lease
            .run(move || Self::load_retained_resume(&dir, &saved_binding))
            .await?;
        let handle = match &retained {
            None => return Ok(ResumeProbe::Absent),
            Some(Ok(ledger)) => BinaryExport::from_ready(ledger).map_err(local_io)?,
            Some(Err(pending)) => BinaryExport {
                handle: pending.pending.export_handle.clone(),
                transfer: pending.transfer,
            },
        };
        let bearer = read_credential(&self.config.credential_file)?;
        match self
            .binary_client
            .poll(
                binding.origin.clone(),
                binding.hosted_route_database_id.clone(),
                bearer,
                handle.clone(),
            )
            .await
            .and_then(|poll| {
                if let Some(Ok(ready)) = &retained {
                    Self::check_saved_poll(ready, &poll)?;
                }
                Ok(poll)
            }) {
            Ok(_) => Ok(ResumeProbe::Live),
            Err(error) if Self::is_binary_handle_gone(&error) => {
                discard_owned(&lease, &self.refresh_dir).await?;
                Ok(ResumeProbe::Gone)
            }
            Err(error) if Self::is_binary_transfer_terminal(&error) => {
                // Match downloader policy: terminal refusals end custody and
                // surface the error. A later attempt owns capture eligibility.
                // Arm before fallible cleanup so even an unlink/fsync failure
                // still attempts an authorized best-effort server DELETE.
                let _cancel = CancelHandle {
                    client: self.binary_client.clone(),
                    origin: binding.origin,
                    database: binding.hosted_route_database_id,
                    credential_file: self.config.credential_file.clone(),
                    handle,
                    armed: true,
                };
                discard_owned(&lease, &self.refresh_dir).await?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Transfer custody to a durable pending record. Until that succeeds,
    /// dropping the future cancels the otherwise unowned server export.
    async fn start_durable_export(
        &self,
        binding: &binary_resume::ResumeBinding,
        mut progress: Option<&mut AttemptProgress>,
        lease: &binary_work::TransferLease,
    ) -> std::result::Result<
        (BinaryExport, transfer_repr::PendingTransfer, CancelHandle),
        AttemptError,
    > {
        let bearer = read_credential(&self.config.credential_file)?;
        // Record the actual start invocation, including an uncertain response
        // or cancellation while POST is in flight, to retain capture cooldown.
        if let Some(progress) = progress.as_deref_mut() {
            self.record_full_start(progress)?;
        }
        let preferred = SnapshotTransfer::GzipV1 {
            level: transfer_repr::GZIP_TRANSFER_LEVEL,
        };
        let started = self
            .binary_client
            .start(
                binding.origin.clone(),
                binding.hosted_route_database_id.clone(),
                bearer,
                self.declared_consumer(),
                preferred,
            )
            .await;
        let handle = match started {
            Err(error) if error.detail == "missing_v2_route" => {
                // Only the initial empty, unmarked v2 route 404 authorizes
                // compatibility. Reread credentials for this distinct request.
                let bearer = read_credential(&self.config.credential_file)?;
                if let Some(progress) = progress {
                    self.record_full_start(progress)?;
                }
                self.binary_client
                    .start(
                        binding.origin.clone(),
                        binding.hosted_route_database_id.clone(),
                        bearer,
                        self.declared_consumer(),
                        SnapshotTransfer::IdentityV1,
                    )
                    .await?
            }
            other => other?,
        };
        let mut cancel = CancelHandle {
            client: self.binary_client.clone(),
            origin: binding.origin.clone(),
            database: binding.hosted_route_database_id.clone(),
            credential_file: self.config.credential_file.clone(),
            handle: handle.clone(),
            armed: true,
        };
        let capture = transfer_repr::bind_pending_transfer(
            handle.transfer.route_api(),
            handle.transfer,
            binary_resume::pending_capture(binding, handle.handle.clone(), now()),
        )
        .map_err(local_io)?;
        let dir = self.refresh_dir.clone();
        let (capture, cancel) = lease
            .run(move || {
                transfer_repr::save_pending_transfer(&dir, &capture).map_err(local_io)?;
                cancel.armed = false;
                Ok((capture, cancel))
            })
            .await?;
        self.record_transfer_stage(StandbyTransferStage::Capture, None, true)?;
        Ok((handle, capture, cancel))
    }

    pub(super) async fn download_binary_only(
        &self,
        bearer: String,
        snapshot_path: &Path,
        budget: FreshCaptureBudget,
    ) -> std::result::Result<StandbySnapshotManifest, AttemptError> {
        self.download_binary_with_progress(bearer, snapshot_path, budget, None)
            .await
    }

    async fn download_binary_with_progress(
        &self,
        _bearer: String,
        snapshot_path: &Path,
        budget: FreshCaptureBudget,
        mut progress: Option<&mut AttemptProgress>,
    ) -> std::result::Result<StandbySnapshotManifest, AttemptError> {
        let lease = binary_work::TransferLease::acquire(&self.refresh_dir)?;
        let origin = self.config.hosted_origin.clone();
        let database = self.runtime.hosted_route_database_id.clone();
        let binding = self.resume_binding();
        let dir = self.refresh_dir.clone();
        self.record_transfer_stage(StandbyTransferStage::Capture, None, false)?;
        // Durable custody owns the handle across retry, timeout and abort.
        // Only explicit terminal faults or success arm best-effort DELETE.
        let mut cancel;
        let mut started_fresh = false;
        // Pending identity for a handle without ready state yet: either
        // freshly started below or retained from an interrupted capture.
        let mut pending: Option<transfer_repr::PendingTransfer> = None;
        // Saved ready identity, when reuse was authorized for this handle.
        let mut ledger: Option<binary_resume::ResumeLedger> = None;
        let load_dir = dir.clone();
        let load_binding = binding.clone();
        let retained = lease
            .run(move || Self::load_retained_resume(&load_dir, &load_binding))
            .await?;
        let mut handle = match retained {
            None => {
                if matches!(budget, FreshCaptureBudget::ReuseOnly) {
                    // The probe saw a live handle that vanished before the
                    // transfer: the cooldown still holds, so refuse to
                    // create instead of spending capture budget.
                    return Err(throttled_by_cooldown());
                }
                let (started, capture, guard) = self
                    .start_durable_export(&binding, progress.as_deref_mut(), &lease)
                    .await?;
                started_fresh = true;
                pending = Some(capture);
                cancel = guard;
                started
            }
            Some(retained) => {
                let retained_handle = match retained {
                    Ok(saved) => {
                        let handle = BinaryExport::from_ready(&saved).map_err(local_io)?;
                        ledger = Some(saved);
                        handle
                    }
                    Err(saved) => {
                        let handle = BinaryExport {
                            handle: saved.pending.export_handle.clone(),
                            transfer: saved.transfer,
                        };
                        pending = Some(saved);
                        handle
                    }
                };
                cancel = CancelHandle {
                    client: self.binary_client.clone(),
                    origin: origin.clone(),
                    database: database.clone(),
                    credential_file: self.config.credential_file.clone(),
                    handle: retained_handle.clone(),
                    armed: false,
                };
                retained_handle
            }
        };
        // Poll to Ready on the retained or replacement handle. Gone after a
        // replacement already started is terminal: at most one fresh export
        // per attempt. Auth/network/timeout failures preserve custody;
        // terminal protocol/integrity errors discard and cancel it.
        let mut capture_update = tokio::time::Instant::now();
        let (manifest, decoded_size, decoded_sha, encoded) = loop {
            match self
                .binary_client
                .poll(
                    origin.clone(),
                    database.clone(),
                    read_credential(&self.config.credential_file)?,
                    handle.clone(),
                )
                .await
            {
                Err(error) if Self::is_binary_handle_gone(&error) => {
                    discard_owned(&lease, &dir).await?;
                    if started_fresh {
                        return Err(error);
                    }
                    if matches!(budget, FreshCaptureBudget::ReuseOnly) {
                        return Err(throttled_by_cooldown());
                    }
                    ledger = None;
                    let (started, capture, guard) = self
                        .start_durable_export(&binding, progress.as_deref_mut(), &lease)
                        .await?;
                    started_fresh = true;
                    pending = Some(capture);
                    cancel = guard;
                    handle = started;
                }
                Err(error) if Self::is_binary_transfer_terminal(&error) => {
                    cancel.arm();
                    discard_owned(&lease, &dir).await?;
                    return Err(error);
                }
                Err(error) => {
                    return Err(error);
                }
                Ok(BinaryPoll::Pending) => {
                    if let Some(saved) = &ledger {
                        if let Err(error) = Self::check_saved_poll(saved, &BinaryPoll::Pending) {
                            cancel.arm();
                            discard_owned(&lease, &dir).await?;
                            return Err(error);
                        }
                    }
                    if capture_update.elapsed() >= Duration::from_secs(30) {
                        self.record_transfer_stage(StandbyTransferStage::Capture, None, true)?;
                        capture_update = tokio::time::Instant::now();
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                Ok(BinaryPoll::Ready {
                    manifest,
                    size,
                    sha256,
                    encoded,
                }) => {
                    break (manifest, size, sha256, encoded);
                }
            }
        };
        // Adopt the Ready identity: a saved ready ledger must equal the
        // poll; a pending capture upgrades. Changed ready metadata refuses
        // reuse outright instead of splicing captures.
        let mut ledger = match ledger {
            Some(saved) => {
                if Self::check_saved_poll(
                    &saved,
                    &BinaryPoll::Ready {
                        manifest: manifest.clone(),
                        size: decoded_size,
                        sha256: decoded_sha.clone(),
                        encoded: encoded.clone(),
                    },
                )
                .is_err()
                {
                    cancel.arm();
                    discard_owned(&lease, &dir).await?;
                    return Err(integrity(
                        "standby binary manifest identity mismatch",
                        Error::engine("standby binary manifest identity mismatch"),
                    ));
                }
                saved
            }
            None => {
                let capture = pending.take().ok_or_else(|| {
                    local_io(Error::engine("standby resume pending capture is missing"))
                })?;
                match binary_resume::ready_ledger_from_pending(
                    &capture.pending,
                    *manifest.clone(),
                    decoded_size,
                    decoded_sha.clone(),
                    now(),
                ) {
                    Ok(mut adopted) => {
                        match (handle.transfer, &encoded) {
                            (SnapshotTransfer::IdentityV1, None) => {}
                            (SnapshotTransfer::GzipV1 { level: 1 }, Some((size, sha))) => adopted
                                .set_encoded(binary_resume::EncodedResume {
                                    route_api: handle.transfer.route_api().into(),
                                    transfer: handle.transfer,
                                    size_bytes: *size,
                                    sha256: sha.clone(),
                                }),
                            _ => {
                                cancel.arm();
                                discard_owned(&lease, &dir).await?;
                                return Err(protocol(
                                    "standby binary transfer representation mismatch",
                                ));
                            }
                        }
                        if let Err(error) = adopted.ready_identity() {
                            cancel.arm();
                            discard_owned(&lease, &dir).await?;
                            return Err(integrity(
                                "standby binary manifest identity mismatch",
                                error,
                            ));
                        }
                        adopted
                    }
                    Err(_) => {
                        cancel.arm();
                        discard_owned(&lease, &dir).await?;
                        return Err(integrity(
                            "standby binary manifest identity mismatch",
                            Error::engine("standby binary manifest identity mismatch"),
                        ));
                    }
                }
            }
        };
        let size = ledger.range_size();
        let sha256 = ledger.range_sha().to_owned();
        let prepare_dir = dir.clone();
        let prepared = lease
            .run(move || {
                binary_resume::prepare_partial_file(&prepare_dir, size)
                    .map_err(|error| local_io(error).with_detail("unusable_partial"))?;
                if !ledger.completed.is_empty() {
                    ledger = binary_resume::revalidate_cached_ranges(&prepare_dir, &ledger)
                        .map_err(|error| local_io(error).with_detail("unusable_partial"))?;
                }
                binary_resume::save_resume_ledger(&prepare_dir, &ledger).map_err(local_io)?;
                binary_resume::discard_pending(&prepare_dir).map_err(local_io)?;
                Ok(ledger)
            })
            .await;
        let mut ledger = match prepared {
            Err(error) if error.detail == "unusable_partial" => {
                cancel.arm();
                discard_owned(&lease, &dir).await?;
                return Err(error);
            }
            other => other?,
        };
        let mut completed: u64 = ledger.completed.iter().map(|range| range.length).sum();
        self.record_transfer_stage(
            StandbyTransferStage::Download,
            Some((size, completed)),
            true,
        )?;
        let mut last_update = tokio::time::Instant::now();
        // At most four owned range futures, each collecting at most 1 MiB.
        // Dropping this stream on error/timeout/abort drops every request;
        // there are no spawned range tasks. Only this coordinator writes bytes
        // and the ledger, and it commits before polling for another result.
        let ranges = binary_resume::missing_ranges(&ledger)
            .map_err(local_io)?
            .into_iter()
            .flat_map(|(offset, length)| {
                (0..length.div_ceil(MAX_CHUNK_BYTES as u64)).map(move |chunk| {
                    let relative = chunk * MAX_CHUNK_BYTES as u64;
                    (
                        offset + relative,
                        (length - relative).min(MAX_CHUNK_BYTES as u64) as usize,
                    )
                })
            });
        let mut downloads = stream::iter(ranges)
            .map(|(offset, length)| {
                let request = BinaryReadRequest {
                    origin: origin.clone(),
                    database: database.clone(),
                    // The guarded credential read happens immediately before each
                    // request/retry, never when the range is queued.
                    bearer: String::new(),
                    handle: handle.clone(),
                    offset,
                    length,
                    size,
                    sha256: sha256.clone(),
                };
                async move {
                    (
                        offset,
                        length,
                        self.read_binary_chunk_with_retry(request).await,
                    )
                }
            })
            .buffer_unordered(MAX_IN_FLIGHT_RANGES);
        while let Some((offset, length, result)) = downloads.next().await {
            let bytes = match result {
                Ok(bytes) => bytes,
                Err(error) if Self::is_binary_transfer_terminal(&error) => {
                    cancel.arm();
                    discard_owned(&lease, &dir).await?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            if bytes.len() != length {
                cancel.arm();
                discard_owned(&lease, &dir).await?;
                return Err(integrity(
                    "standby binary range length mismatch",
                    Error::engine("standby binary range length mismatch"),
                ));
            }
            let write_dir = dir.clone();
            let persisted = lease
                .run(move || {
                    let hash = binary_resume::write_range_and_hash(&write_dir, offset, &bytes)
                        .map_err(local_io)?;
                    drop(bytes);
                    binary_resume::record_completed_range(&mut ledger, offset, length as u64, hash)
                        .map_err(|error| integrity("standby binary range ledger refused", error))?;
                    binary_resume::save_resume_ledger(&write_dir, &ledger).map_err(local_io)?;
                    Ok(ledger)
                })
                .await;
            ledger = match persisted {
                Err(error) if Self::is_binary_transfer_terminal(&error) => {
                    cancel.arm();
                    discard_owned(&lease, &dir).await?;
                    return Err(error);
                }
                other => other?,
            };
            completed += length as u64;
            if completed == size || last_update.elapsed() >= transfer_progress::BYTE_UPDATE_INTERVAL
            {
                self.record_transfer_stage(
                    StandbyTransferStage::Download,
                    Some((size, completed)),
                    true,
                )?;
                last_update = tokio::time::Instant::now();
            }
        }
        self.record_transfer_stage(
            StandbyTransferStage::Verification,
            Some((size, completed)),
            true,
        )?;
        // The blocking worker owns the lease, input and output cleanup even
        // when timeout/abort drops this waiter. Keep the fixed wire bytes until
        // handoff succeeds, including identity-v1, so cancellation can resume.
        let complete_dir = dir.clone();
        let dest = snapshot_path.to_owned();
        let output = match lease
            .run(move || binary_work::complete_snapshot(&complete_dir, &dest, &ledger))
            .await
        {
            Err(error) if Self::is_binary_transfer_terminal(&error) => {
                cancel.arm();
                discard_owned(&lease, &dir).await?;
                return Err(error);
            }
            other => other?,
        };
        binary_resume::discard_resume(&dir).map_err(local_io)?;
        output.release();
        cancel.arm();
        Ok(*manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_legacy_and_gzip_pending_records_are_invalidated_together() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binary_resume::ResumeBinding {
            origin: "https://example.com".into(),
            hosted_route_database_id: "route".into(),
            origin_database_id: format!("ndb_{}", "d".repeat(32)),
            consumer: wire_consumer(),
        };
        let pending = binary_resume::pending_capture(
            &binding,
            "12345678-1234-1234-1234-1234567890ab".into(),
            now(),
        );
        binary_resume::save_pending_capture(dir.path(), &pending).unwrap();
        let encoded = transfer_repr::bind_pending_transfer(
            transfer_repr::GZIP_EXPORT_API,
            SnapshotTransfer::GzipV1 { level: 1 },
            pending,
        )
        .unwrap();
        transfer_repr::save_pending_transfer(dir.path(), &encoded).unwrap();
        binary_resume::prepare_partial_file(dir.path(), 17).unwrap();
        assert!(
            StandbyRefreshController::load_retained_resume(dir.path(), &binding)
                .unwrap()
                .is_none()
        );
        for file in [
            "binary-pending.json",
            "transfer-pending.json",
            "binary-resume.partial.db",
        ] {
            assert!(
                !dir.path().join(file).exists(),
                "conflicting custody left {file}"
            );
        }
    }

    #[tokio::test]
    async fn v2_start_classifies_only_bare_missing_route_as_fallback() {
        use axum::response::IntoResponse as _;
        use axum::{routing::post, Router};
        for (status, body, api, missing) in [
            (404, "", None, true),
            (404, "", Some(transfer_repr::GZIP_EXPORT_API), false),
            (
                404,
                "{\"error\":{\"code\":\"handle_not_found\"}}",
                None,
                false,
            ),
            (
                404,
                "{\"error\":{\"code\":\"database_not_found\"}}",
                Some(transfer_repr::GZIP_EXPORT_API),
                false,
            ),
            (
                400,
                "{\"error\":{\"code\":\"invalid_request_contract\"}}",
                None,
                false,
            ),
            (401, "", None, false),
            (403, "", None, false),
            (409, "", None, false),
            (429, "", None, false),
        ] {
            let router = Router::new().route(
                "/v2/databases/route/standby-snapshot/exports",
                post(move |axum::Json(request): axum::Json<Value>| async move {
                    assert_eq!(request["contract"], transfer_repr::GZIP_EXPORT_API);
                    assert_eq!(request["version"], 1);
                    assert_eq!(request.as_object().unwrap().len(), 3);
                    let mut response =
                        (axum::http::StatusCode::from_u16(status).unwrap(), body).into_response();
                    if let Some(api) = api {
                        response.headers_mut().insert(
                            "x-native-export-api",
                            axum::http::HeaderValue::from_static(api),
                        );
                    }
                    response
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let error = HttpBinarySnapshotClient::new()
                .unwrap()
                .start(
                    origin,
                    "route".into(),
                    "secret".into(),
                    wire_consumer(),
                    SnapshotTransfer::GzipV1 { level: 1 },
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.detail == "missing_v2_route",
                missing,
                "status {status}, body {body}"
            );
            if matches!(status, 401 | 403) {
                assert_eq!(error.class, RefreshFailureClass::Authentication);
            }
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
    }

    fn wire_consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: 59,
            ddl_sha256: "c".repeat(64),
        }
    }

    #[tokio::test]
    async fn http_range_request_has_a_sixty_second_total_budget() {
        use tokio::io::AsyncReadExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buffer = [0_u8; 1024];
                let count = socket.read(&mut buffer).await.unwrap();
                assert!(count > 0 && headers.len() + count <= 16 * 1024);
                headers.extend_from_slice(&buffer[..count]);
            }
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let client = HttpBinarySnapshotClient::new().unwrap();
        let request = tokio::spawn(client.read(BinaryReadRequest {
            origin: format!("http://127.0.0.1:{port}"),
            database: "route-1".into(),
            bearer: "secret".into(),
            handle: "12345678-1234-1234-1234-1234567890ab".into(),
            offset: 0,
            length: 1,
            size: 1,
            sha256: "0".repeat(64),
        }));
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        // Pause only after connection and request delivery: connect remains
        // independently limited to five seconds in the production builder.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert!(
            !request.is_finished(),
            "WAN requests must survive the former ten-second limit"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            request.await.unwrap().unwrap_err().class,
            RefreshFailureClass::Timeout
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn status_errors_retain_classes_and_add_bounded_details() {
        for (code, class, detail) in [
            (409, RefreshFailureClass::Protocol, "http_409"),
            (418, RefreshFailureClass::Protocol, "http_4xx_other"),
            (401, RefreshFailureClass::Authentication, "http_401"),
            (403, RefreshFailureClass::Authentication, "http_403"),
            (416, RefreshFailureClass::DownloadIntegrity, "http_416"),
            (408, RefreshFailureClass::Network, "http_408"),
            (429, RefreshFailureClass::Network, "http_429"),
            (503, RefreshFailureClass::Network, "http_5xx"),
        ] {
            let error = status_error(reqwest::StatusCode::from_u16(code).unwrap());
            assert_eq!(error.class, class);
            assert_eq!(error.detail, detail);
        }
    }
}
