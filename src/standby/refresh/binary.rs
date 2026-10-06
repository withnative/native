//! Bounded owner-authenticated HTTP acquisition for an initial standby generation.

use super::*;
use reqwest::header::{
    HeaderMap, HeaderName, ACCEPT_ENCODING, ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, RANGE,
};

const API: &str = "native.standby-snapshot-export.v1";
const API_HEADER: HeaderName = HeaderName::from_static("x-native-export-api");
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CHUNK_RETRY_DELAYS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(250),
    Duration::from_millis(750),
];

type BinaryFuture<T> = Pin<Box<dyn Future<Output = std::result::Result<T, AttemptError>> + Send>>;

#[derive(Clone)]
pub(super) struct BinaryReadRequest {
    origin: String,
    database: String,
    pub(super) bearer: String,
    handle: String,
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
    ) -> BinaryFuture<String>;
    fn poll(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: String,
    ) -> BinaryFuture<BinaryPoll>;
    fn read(&self, request: BinaryReadRequest) -> BinaryFuture<Vec<u8>>;
    fn cancel(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: String,
    ) -> BinaryFuture<()>;
}

pub(super) enum BinaryPoll {
    Pending,
    Ready {
        manifest: Box<StandbySnapshotManifest>,
        size: u64,
        sha256: String,
    },
}

pub(super) struct HttpBinarySnapshotClient {
    client: reqwest::Client,
}

impl HttpBinarySnapshotClient {
    pub(super) fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::engine("cannot build standby binary HTTP client"))?;
        Ok(Self { client })
    }
}

fn url(origin: &str, database: &str, handle: Option<&str>, bytes: bool) -> String {
    let mut url = format!(
        "{origin}/v1/databases/{}/standby-snapshot/exports",
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
}

fn one_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

fn require_api(headers: &HeaderMap) -> std::result::Result<(), AttemptError> {
    if one_header(headers, &API_HEADER) != Some(API) {
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
        return Err(protocol("standby binary response exceeded its bound"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(protocol("standby binary response exceeded its bound"));
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

impl BinarySnapshotClient for HttpBinarySnapshotClient {
    fn start(
        &self,
        origin: String,
        database: String,
        bearer: String,
        consumer: StandbyConsumerIdentity,
    ) -> BinaryFuture<String> {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .post(url(&origin, &database, None, false))
                .bearer_auth(bearer)
                .header(ACCEPT_ENCODING, "identity")
                .json(&json!({"contract": API, "version": 1, "consumer": consumer}))
                .send()
                .await
                .map_err(network_error)?;
            if response.status() != reqwest::StatusCode::ACCEPTED {
                return Err(status_error(response.status()));
            }
            require_api(response.headers())?;
            let body: StartBody =
                serde_json::from_slice(&bounded_body(response, MAX_METADATA_BYTES).await?)
                    .map_err(|_| protocol("standby binary start response was invalid"))?;
            if body.api != API
                || body.status != "pending"
                || body.expires_at.is_empty()
                || uuid::Uuid::parse_str(&body.export_handle).is_err()
            {
                return Err(protocol("standby binary start response was invalid"));
            }
            Ok(body.export_handle)
        })
    }

    fn poll(
        &self,
        origin: String,
        database: String,
        bearer: String,
        handle: String,
    ) -> BinaryFuture<BinaryPoll> {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .get(url(&origin, &database, Some(&handle), false))
                .bearer_auth(bearer)
                .header(ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(network_error)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(status_error(response.status()));
            }
            require_api(response.headers())?;
            let body: PollBody =
                serde_json::from_slice(&bounded_body(response, MAX_METADATA_BYTES).await?)
                    .map_err(|_| protocol("standby binary poll response was invalid"))?;
            if body.api != API || body.export_handle != handle || body.expires_at.is_empty() {
                return Err(protocol("standby binary poll response was invalid"));
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
                    })
                }
                "failed"
                    if body.manifest.is_none()
                        && body.size_bytes.is_none()
                        && body.sha256.is_none()
                        && body.error_code.is_some() =>
                {
                    Err(protocol("standby binary capture failed"))
                }
                _ => Err(protocol("standby binary poll response was invalid")),
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
                .get(url(&origin, &database, Some(&handle), true))
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
            require_api(headers)?;
            if one_header(headers, &CONTENT_RANGE).map(str::to_owned)
                != Some(format!("bytes {offset}-{end}/{size}"))
                || one_header(headers, &ETAG).map(str::to_owned) != Some(format!("\"{sha256}\""))
                || one_header(headers, &CONTENT_LENGTH) != Some(length.to_string().as_str())
                || one_header(headers, &CONTENT_TYPE) != Some(STANDBY_SNAPSHOT_MEDIA_TYPE)
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
        handle: String,
    ) -> BinaryFuture<()> {
        let client = self.client.clone();
        Box::pin(async move {
            let _ = client
                .delete(url(&origin, &database, Some(&handle), false))
                .bearer_auth(bearer)
                .send()
                .await;
            Ok(())
        })
    }
}

struct CancelHandle {
    client: Arc<dyn BinarySnapshotClient>,
    origin: String,
    database: String,
    credential_file: PathBuf,
    handle: String,
}

impl Drop for CancelHandle {
    fn drop(&mut self) {
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
    ) -> std::result::Result<(InstalledGeneration, Vec<String>), AttemptError> {
        let manifest = self.download_binary_only(bearer, snapshot_path).await?;
        self.install_downloaded_snapshot(manifest, snapshot_path, manifest_path)
            .await
    }

    pub(super) async fn download_binary_only(
        &self,
        bearer: String,
        snapshot_path: &Path,
    ) -> std::result::Result<StandbySnapshotManifest, AttemptError> {
        let origin = self.config.hosted_origin.clone();
        let database = self.runtime.hosted_route_database_id.clone();
        let handle = self
            .binary_client
            .start(
                origin.clone(),
                database.clone(),
                bearer.clone(),
                self.declared_consumer(),
            )
            .await?;
        let _cancel = CancelHandle {
            client: self.binary_client.clone(),
            origin: origin.clone(),
            database: database.clone(),
            credential_file: self.config.credential_file.clone(),
            handle: handle.clone(),
        };
        let (manifest, size, sha256) = loop {
            match self
                .binary_client
                .poll(
                    origin.clone(),
                    database.clone(),
                    read_credential(&self.config.credential_file)?,
                    handle.clone(),
                )
                .await?
            {
                BinaryPoll::Pending => tokio::time::sleep(POLL_INTERVAL).await,
                BinaryPoll::Ready {
                    manifest,
                    size,
                    sha256,
                } => break (manifest, size, sha256),
            }
        };
        if manifest.hosted_route_database_id != database
            || manifest.origin_database_id != self.runtime.origin_database_id
            || manifest.consumer != self.declared_consumer()
        {
            return Err(integrity(
                "standby binary manifest identity mismatch",
                Error::engine("standby binary manifest identity mismatch"),
            ));
        }
        let mut output = create_private_file(snapshot_path)?;
        let mut digest = Sha256::new();
        let mut offset = 0_u64;
        while offset < size {
            let length = (size - offset).min(MAX_CHUNK_BYTES as u64) as usize;
            let bytes = self
                .read_binary_chunk_with_retry(BinaryReadRequest {
                    origin: origin.clone(),
                    database: database.clone(),
                    bearer: read_credential(&self.config.credential_file)?,
                    handle: handle.clone(),
                    offset,
                    length,
                    size,
                    sha256: sha256.clone(),
                })
                .await?;
            if bytes.len() != length {
                return Err(integrity(
                    "standby binary range length mismatch",
                    Error::engine("standby binary range length mismatch"),
                ));
            }
            output
                .write_all(&bytes)
                .map_err(|error| local_io(error.into()))?;
            digest.update(&bytes);
            offset += length as u64;
        }
        output.sync_all().map_err(|error| local_io(error.into()))?;
        drop(output);
        if hex::encode(digest.finalize()) != sha256 {
            return Err(integrity(
                "standby binary snapshot digest mismatch",
                Error::engine("standby binary snapshot digest mismatch"),
            ));
        }
        Ok(*manifest)
    }
}
