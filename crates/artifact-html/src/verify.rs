//! Bounded client for the separately deployed browser-verifier sidecar.
//!
//! The sidecar is deliberately capability-poor: this module sends one CE-issued,
//! one-use harness URL plus expected digests. It never sends database paths,
//! credentials, artifact source, or a caller-selected URL.

use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{Error, Result};

pub const REQUEST_SCHEMA_VERSION: &str = "native.artifact-verification-request.v1";
pub const RESPONSE_SCHEMA_VERSION: &str = "native.artifact-verification.v1";
pub const MDX_REQUEST_SCHEMA_VERSION: &str = "native.mdx-artifact-verification-request.v1";
pub const MDX_RESPONSE_SCHEMA_VERSION: &str = "native.mdx-artifact-verification.v1";
pub const RESPONSE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct Config {
    endpoint: Url,
    secret: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("endpoint", &self.endpoint)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl Config {
    pub fn new(endpoint: impl AsRef<str>, secret: impl Into<String>) -> Result<Self> {
        let endpoint = Url::parse(endpoint.as_ref())
            .map_err(|_| Error::engine("NATIVE_CE_VERIFIER_URL is not a valid URL"))?;
        let loopback = endpoint
            .host_str()
            .map(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<IpAddr>()
                        .map(|address| address.is_loopback())
                        .unwrap_or(false)
            })
            .unwrap_or(false);
        if !(endpoint.scheme() == "https" || (endpoint.scheme() == "http" && loopback))
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::engine(
                "NATIVE_CE_VERIFIER_URL must be HTTPS (HTTP is allowed only on loopback) without credentials, query, or fragment",
            ));
        }
        let secret = secret.into();
        if secret.trim().len() < 32 {
            return Err(Error::engine(
                "NATIVE_CE_VERIFIER_SECRET must contain at least 32 characters",
            ));
        }
        Ok(Self { endpoint, secret })
    }
}

fn config_slot() -> &'static RwLock<Option<Config>> {
    static CONFIG: OnceLock<RwLock<Option<Config>>> = OnceLock::new();
    CONFIG.get_or_init(|| RwLock::new(None))
}

pub fn configure(config: Option<Config>) {
    *config_slot().write().expect("verifier config poisoned") = config;
}

pub fn configured() -> bool {
    config_slot()
        .read()
        .expect("verifier config poisoned")
        .is_some()
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationRequest {
    pub schema_version: &'static str,
    pub harness_url: String,
    pub expected: Expected,
    pub matrix: Vec<MatrixCase>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Expected {
    pub artifact_id: String,
    pub artifact_digest: String,
    pub runtime_id: &'static str,
    pub body_digest: String,
    pub input_digest: String,
    pub adapter_digest: String,
    pub adapter_revision: u64,
    pub bootstrap_digest: String,
    pub csp_digest: String,
    pub input_mode: &'static str,
    pub input_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Viewport {
    pub width: u16,
    pub height: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixCase {
    pub id: String,
    pub viewport: Viewport,
    pub color_scheme: String,
    pub reduced_motion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationResponse {
    pub schema_version: String,
    pub artifact_id: String,
    pub artifact_digest: String,
    pub runtime_id: String,
    pub adapter_revision: u64,
    pub adapter_digest: String,
    pub bootstrap_digest: String,
    pub csp_digest: String,
    pub body_digest: String,
    pub input: InputAttestation,
    pub browser: BrowserInfo,
    pub started_at: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub cases: Vec<CaseResult>,
    #[serde(default)]
    pub terminal_diagnostic_codes: Vec<String>,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct MdxVerificationRequest {
    pub schema_version: &'static str,
    pub harness_url: String,
    pub expected: MdxExpected,
    pub resources: Vec<MdxResource>,
    pub matrix: [MdxMatrixCase; 1],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdxExpected {
    pub artifact_id: String,
    pub artifact_digest: String,
    pub runtime_id: String,
    pub adapter_revision: u64,
    pub plan_version: String,
    pub capture_scope: String,
    pub source_event_id: String,
    pub source_event_seq: i64,
    pub snapshot_event_id: String,
    pub snapshot_event_seq: i64,
    pub body_digest: String,
    pub dependency_closure_digest: String,
    pub render_digest: String,
    pub plan_digest: String,
    pub style_digest: Option<String>,
    pub renderer_digest: String,
    pub document_digest: String,
    pub csp_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdxResource {
    pub url: String,
    pub digest: String,
    pub bytes: usize,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdxMatrixCase {
    pub id: String,
    pub viewport: Viewport,
    pub color_scheme: String,
    pub reduced_motion: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MdxVerificationResponse {
    pub schema_version: String,
    pub authority: String,
    #[serde(flatten)]
    pub expected: MdxExpected,
    pub browser: BrowserInfo,
    pub started_at: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub resources: Vec<MdxResource>,
    pub case: MdxCaseResult,
    #[serde(default)]
    pub terminal_diagnostic_codes: Vec<String>,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MdxCaseResult {
    pub id: String,
    pub viewport: Viewport,
    pub color_scheme: String,
    pub reduced_motion: String,
    pub duration_ms: u64,
    pub console: Value,
    pub page_errors: Value,
    pub csp_violations: Value,
    pub network_attempts: Value,
    pub crashes: Value,
    #[serde(default)]
    pub screenshot: Option<EvidenceRef>,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InputAttestation {
    pub mode: String,
    pub count: usize,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrowserInfo {
    pub name: String,
    pub version: String,
    pub playwright_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub viewport: Viewport,
    pub color_scheme: String,
    pub reduced_motion: String,
    pub duration_ms: u64,
    pub console: Value,
    pub page_errors: Value,
    pub csp_violations: Value,
    pub network_attempts: Value,
    pub runtime_diagnostics: Value,
    pub crashes: Value,
    pub accessibility: Value,
    pub overflow: Value,
    #[serde(default)]
    pub screenshot: Option<EvidenceRef>,
    #[serde(default)]
    pub pdf: Option<EvidenceRef>,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceRef {
    pub kind: String,
    pub sha256: String,
    pub bytes: usize,
    pub content_type: String,
    #[serde(skip_serializing)]
    pub evidence_path: String,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub page_count: Option<u32>,
}

pub fn adapter_digest() -> String {
    let descriptor =
        serde_json::to_vec(&crate::html::descriptor()).expect("native.html.v1 descriptor is JSON");
    hex::encode(Sha256::digest(descriptor))
}

pub fn artifact_digest(
    artifact_id: &str,
    body_digest: &str,
    input_digest: &str,
    adapter_digest: &str,
) -> String {
    let mut digest = Sha256::new();
    for part in [artifact_id, body_digest, input_digest, adapter_digest] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    hex::encode(digest.finalize())
}

pub fn default_matrix(profile: crate::html::Profile) -> Vec<MatrixCase> {
    let viewports = match profile {
        crate::html::Profile::Document => [(1440, 900), (1024, 768), (390, 844)],
        crate::html::Profile::Slides => [(1600, 900), (1280, 720), (390, 844)],
    };
    viewports
        .into_iter()
        .enumerate()
        .map(|(index, (width, height))| MatrixCase {
            id: format!("viewport-{}", index + 1),
            viewport: Viewport { width, height },
            color_scheme: "light".into(),
            reduced_motion: "no-preference".into(),
            pdf: None,
        })
        .chain(std::iter::once(MatrixCase {
            id: "reduced-motion-print".into(),
            viewport: Viewport {
                width: viewports[0].0,
                height: viewports[0].1,
            },
            color_scheme: "light".into(),
            reduced_motion: "reduce".into(),
            pdf: Some(true),
        }))
        .collect()
}

pub async fn verify(request: &VerificationRequest) -> Result<VerificationResponse> {
    let config = config_slot()
        .read()
        .expect("verifier config poisoned")
        .clone()
        .ok_or_else(|| Error::engine("native.html.v1 verifier is not configured"))?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(75))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| Error::engine(format!("could not build verifier client: {error}")))?;
    let response = client
        .post(config.endpoint)
        .header(AUTHORIZATION, format!("Bearer {}", config.secret))
        .header(CONTENT_TYPE, "application/json")
        .json(request)
        .send()
        .await
        .map_err(|error| Error::engine(format!("verifier request failed: {error}")))?;
    let status = response.status();
    if !(status.is_success() || status == reqwest::StatusCode::BAD_GATEWAY) {
        return Err(Error::engine(format!(
            "verifier returned HTTP {}",
            status.as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|size| size > RESPONSE_LIMIT as u64)
    {
        return Err(Error::engine("verifier response exceeded the size limit"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| Error::engine(format!("could not read verifier response: {error}")))?;
    if bytes.len() > RESPONSE_LIMIT {
        return Err(Error::engine("verifier response exceeded the size limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| Error::engine(format!("verifier response was invalid: {error}")))
}

pub async fn verify_mdx(request: &MdxVerificationRequest) -> Result<MdxVerificationResponse> {
    let config = config_slot()
        .read()
        .expect("verifier config poisoned")
        .clone()
        .ok_or_else(|| Error::engine("artifact verifier is not configured"))?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(75))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| Error::engine(format!("could not build verifier client: {error}")))?;
    let response = client
        .post(config.endpoint)
        .header(AUTHORIZATION, format!("Bearer {}", config.secret))
        .header(CONTENT_TYPE, "application/json")
        .json(request)
        .send()
        .await
        .map_err(|error| Error::engine(format!("verifier request failed: {error}")))?;
    let status = response.status();
    if !(status.is_success() || status == reqwest::StatusCode::BAD_GATEWAY) {
        return Err(Error::engine(format!(
            "verifier returned HTTP {}",
            status.as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|size| size > RESPONSE_LIMIT as u64)
    {
        return Err(Error::engine("verifier response exceeded the size limit"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| Error::engine(format!("could not read verifier response: {error}")))?;
    if bytes.len() > RESPONSE_LIMIT {
        return Err(Error::engine("verifier response exceeded the size limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| Error::engine(format!("verifier response was invalid: {error}")))
}

pub async fn fetch_evidence(reference: &EvidenceRef) -> Result<Vec<u8>> {
    const EVIDENCE_LIMIT: usize = 8 * 1024 * 1024;
    if reference.bytes > EVIDENCE_LIMIT
        || !reference.evidence_path.starts_with("/v1/evidence/")
        || reference.evidence_path.contains('?')
        || reference.evidence_path.contains('#')
    {
        return Err(Error::engine(
            "verifier returned an invalid evidence reference",
        ));
    }
    let config = config_slot()
        .read()
        .expect("verifier config poisoned")
        .clone()
        .ok_or_else(|| Error::engine("native.html.v1 verifier is not configured"))?;
    let url = config
        .endpoint
        .join(&reference.evidence_path)
        .map_err(|_| Error::engine("verifier returned an invalid evidence path"))?;
    if url.origin() != config.endpoint.origin() {
        return Err(Error::engine(
            "verifier evidence escaped its configured origin",
        ));
    }
    let response = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| Error::engine(format!("could not build evidence client: {error}")))?
        .get(url)
        .header(AUTHORIZATION, format!("Bearer {}", config.secret))
        .send()
        .await
        .map_err(|error| Error::engine(format!("evidence request failed: {error}")))?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size > EVIDENCE_LIMIT as u64)
    {
        return Err(Error::engine(
            "verifier evidence was unavailable or oversized",
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| Error::engine(format!("could not read verifier evidence: {error}")))?;
    if bytes.len() != reference.bytes || bytes.len() > EVIDENCE_LIMIT {
        return Err(Error::engine(
            "verifier evidence size did not match its attestation",
        ));
    }
    if hex::encode(Sha256::digest(&bytes)) != reference.sha256 {
        return Err(Error::engine(
            "verifier evidence digest did not match its attestation",
        ));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_https_except_for_loopback_and_secret_is_bounded() {
        assert!(Config::new("https://verifier.example/verify", "x".repeat(32)).is_ok());
        assert!(Config::new("http://localhost:9000/verify", "x".repeat(32)).is_ok());
        assert!(Config::new("http://verifier.example/verify", "x".repeat(32)).is_err());
        assert!(Config::new("https://verifier.example/verify?q=x", "x".repeat(32)).is_err());
        assert!(Config::new("https://verifier.example/verify", "short").is_err());
    }

    #[test]
    fn mdx_wire_contract_is_separate_and_serializes_nullable_styles_exactly() {
        let request = MdxVerificationRequest {
            schema_version: MDX_REQUEST_SCHEMA_VERSION,
            harness_url: "https://workbench.example/internal/artifacts/verification/mdx/ticket"
                .into(),
            expected: MdxExpected {
                artifact_id: "artifact-one".into(),
                artifact_digest: "1".repeat(64),
                runtime_id: "native.mdx.v2".into(),
                adapter_revision: 4,
                plan_version: "1".into(),
                capture_scope: "safe_tree".into(),
                source_event_id: "source-event".into(),
                source_event_seq: 10,
                snapshot_event_id: "snapshot-event".into(),
                snapshot_event_seq: 12,
                body_digest: "2".repeat(64),
                dependency_closure_digest: "3".repeat(64),
                render_digest: "4".repeat(64),
                plan_digest: "5".repeat(64),
                style_digest: None,
                renderer_digest: "6".repeat(64),
                document_digest: "7".repeat(64),
                csp_digest: "8".repeat(64),
            },
            resources: vec![MdxResource {
                url: "https://workbench.example/workbench/assets/app-12345678.js".into(),
                digest: "9".repeat(64),
                bytes: 100,
                kind: "script".into(),
            }],
            matrix: [MdxMatrixCase {
                id: "canonical-screen".into(),
                viewport: Viewport {
                    width: 1440,
                    height: 900,
                },
                color_scheme: "light".into(),
                reduced_motion: "no-preference".into(),
            }],
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(
            value["schema_version"],
            "native.mdx-artifact-verification-request.v1"
        );
        assert_eq!(value["expected"]["style_digest"], Value::Null);
        assert_eq!(value["matrix"].as_array().unwrap().len(), 1);
        assert!(value["matrix"][0].get("pdf").is_none());
        assert!(value["expected"].get("bootstrap_digest").is_none());
    }
}
