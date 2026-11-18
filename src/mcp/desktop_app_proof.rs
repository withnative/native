//! Preparation-only Desktop app identity proof primitive.
//!
//! This module activates no ingress. A later, separately reviewed cookie-session
//! plus same-host Origin handler must be the sole issuer. A proof asserts only
//! app identity: callers still need canonical install/adoption/grant admission,
//! app-operation/consent refusals, and write-transaction revalidation on every
//! call. Generic bearer `native/app` remains refused by the protocol.
//!
//! Proofs belong only in bounded memory and a dedicated redacted HTTP header:
//! never journal, log, debug-print, persist, or transparently replay them. The
//! authenticated account and selected database must supply the expected binding,
//! never request JSON. No verified identity here can construct a trusted Caller.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{Error, Result};

use super::{app_attribution::AppAttribution, HostedPlanKeyProvider};

const FORMAT: &str = "native.desktop-app-identity-proof.v1";
const AUDIENCE: &str = "native.hosted-mcp.desktop-app";
const PURPOSE: &str = "desktop-app-identity";
const READINESS_PURPOSE: &str = "desktop-app-identity-key-readiness";
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROOF_BYTES: usize = 4096;
/// Maximum lifetime; there is no clock-skew grace period after expiration.
pub const MAX_TTL_MS: i64 = 60_000;

/// Exact authenticated account/routing/app context; this carries no authority.
#[derive(Clone, PartialEq, Eq)]
pub struct DesktopAppProofBinding {
    /// Canonical authenticated engine principal, not the public auth/me user ID.
    pub account_id: String,
    pub hosted_db_id: String,
    pub origin_database_id: String,
    /// Canonical TARGET MCP/OAuth resource origin from trusted hosting config,
    /// not the browser cookie Origin, echoed request fields or request Host.
    /// No path, trailing slash, credentials, query or fragment.
    pub hosted_origin: String,
    pub app: AppAttribution,
}

impl DesktopAppProofBinding {
    fn validate(&self) -> Result<()> {
        let origin = url::Url::parse(&self.hosted_origin).map_err(|_| invalid())?;
        if !bounded_token(&self.account_id, 256)
            || !bounded_token(&self.hosted_db_id, 256)
            || !bounded_token(&self.origin_database_id, 256)
            || self.hosted_origin.len() > 512
            || !matches!(origin.scheme(), "https" | "http")
            || origin.origin().ascii_serialization() != self.hosted_origin
        {
            return Err(invalid());
        }
        AppAttribution::new(
            &self.app.package,
            &self.app.version,
            &self.app.install_event_id,
        )
        .map_err(|_| invalid())?;
        Ok(())
    }
}

/// Secret wire value. Intentionally has no serde or Display implementation.
pub struct DesktopAppProof(String);

impl DesktopAppProof {
    /// Expose solely for the later memory-only, redacted header transport.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for DesktopAppProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DesktopAppProof([redacted])")
    }
}

/// Sealed identity result: no JSON deserialization or public constructor.
/// It is not install admission, consent, authority, or a trusted Caller.
pub struct VerifiedDesktopAppIdentity {
    binding: DesktopAppProofBinding,
    expires_at_ms: i64,
}

impl VerifiedDesktopAppIdentity {
    pub fn binding(&self) -> &DesktopAppProofBinding {
        &self.binding
    }

    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

impl std::fmt::Debug for VerifiedDesktopAppIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedDesktopAppIdentity([redacted])")
    }
}

/// Explicitly constructed core capability, with no default, configuration,
/// endpoint or automatic attachment. Shared provider policy/rotation is unchanged.
pub struct DesktopAppProofCore {
    keys: Arc<dyn HostedPlanKeyProvider>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    format: String,
    audience: String,
    purpose: String,
    key_id: String,
    account_id: String,
    hosted_db_id: String,
    origin_database_id: String,
    hosted_origin: String,
    package: String,
    version: String,
    install_event_id: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    key_id: String,
    claims: Claims,
    signature: String,
}

impl DesktopAppProofCore {
    /// Probe this dedicated domain through the operator-owned active key.
    /// Provider errors are replaced with fixed reasons to avoid secret leakage.
    pub async fn new(keys: Arc<dyn HostedPlanKeyProvider>) -> Result<Self> {
        tokio::time::timeout(PROVIDER_TIMEOUT, async {
            let key_id = keys.active_key_id().await.map_err(|_| unavailable())?;
            if !bounded_token(&key_id, 64) {
                return Err(unavailable());
            }
            let challenge = json!({
                "format": FORMAT, "audience": AUDIENCE,
                "purpose": READINESS_PURPOSE, "key_id": key_id,
            });
            let signature = keys
                .seal(key_id.clone(), challenge.clone())
                .await
                .map_err(|_| unavailable())?;
            keys.verify(key_id, challenge, signature)
                .await
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())??;
        Ok(Self { keys })
    }

    /// Trusted in-process issuance only; later ingress MUST enforce cookie +
    /// Origin and canonical installation before calling. Times are Unix millis
    /// from a trusted host clock, never a client-supplied clock.
    pub async fn issue(
        &self,
        binding: &DesktopAppProofBinding,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<DesktopAppProof> {
        binding.validate()?;
        if now_ms < 0 || !(1..=MAX_TTL_MS).contains(&ttl_ms) {
            return Err(invalid());
        }
        let expires_at_ms = now_ms.checked_add(ttl_ms).ok_or_else(invalid)?;
        tokio::time::timeout(PROVIDER_TIMEOUT, async {
            let key_id = self.keys.active_key_id().await.map_err(|_| unavailable())?;
            if !bounded_token(&key_id, 64) {
                return Err(unavailable());
            }
            let claims = Claims {
                format: FORMAT.into(),
                audience: AUDIENCE.into(),
                purpose: PURPOSE.into(),
                key_id,
                account_id: binding.account_id.clone(),
                hosted_db_id: binding.hosted_db_id.clone(),
                origin_database_id: binding.origin_database_id.clone(),
                hosted_origin: binding.hosted_origin.clone(),
                package: binding.app.package.clone(),
                version: binding.app.version.clone(),
                install_event_id: binding.app.install_event_id.clone(),
                issued_at_ms: now_ms,
                expires_at_ms,
                nonce: Uuid::new_v4().to_string(),
            };
            let signature = self
                .keys
                .seal(claims.key_id.clone(), claims.value()?)
                .await
                .map_err(|_| unavailable())?;
            let wire = serde_json::to_string(&Envelope {
                key_id: claims.key_id.clone(),
                claims,
                signature,
            })
            .map_err(|_| invalid())?;
            if wire.len() > MAX_PROOF_BYTES {
                return Err(invalid());
            }
            Ok(DesktopAppProof(wire))
        })
        .await
        .map_err(|_| unavailable())?
    }

    /// Verify against authenticated caller account + selected hosted db/origin
    /// and the exact app carrier. The returned sealed identity never bypasses
    /// canonical app admission; this function does not mutate a Caller. Time is
    /// checked before awaiting the provider: ingress must recheck returned expiry
    /// against a fresh dispatch-time clock before attaching identity or dispatching.
    pub async fn verify(
        &self,
        raw: &str,
        expected: &DesktopAppProofBinding,
        now_ms: i64,
    ) -> Result<VerifiedDesktopAppIdentity> {
        expected.validate()?;
        if raw.len() > MAX_PROOF_BYTES {
            return Err(invalid());
        }
        // Parse directly into strict structs: duplicate and unknown fields refuse.
        let envelope: Envelope = serde_json::from_str(raw).map_err(|_| invalid())?;
        let claims = &envelope.claims;
        if envelope.key_id != claims.key_id
            || claims.format != FORMAT
            || claims.audience != AUDIENCE
            || claims.purpose != PURPOSE
            || !bounded_token(&claims.key_id, 64)
            || claims.binding() != *expected
            || Uuid::parse_str(&claims.nonce)
                .ok()
                .filter(|id| id.to_string() == claims.nonce)
                .is_none()
        {
            return Err(invalid());
        }
        let ttl = claims
            .expires_at_ms
            .checked_sub(claims.issued_at_ms)
            .ok_or_else(invalid)?;
        if claims.issued_at_ms < 0
            || !(1..=MAX_TTL_MS).contains(&ttl)
            || now_ms < claims.issued_at_ms
            || now_ms >= claims.expires_at_ms
        {
            return Err(Error::engine("desktop app proof time refused"));
        }
        tokio::time::timeout(
            PROVIDER_TIMEOUT,
            self.keys
                .verify(claims.key_id.clone(), claims.value()?, envelope.signature),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| invalid())?;
        Ok(VerifiedDesktopAppIdentity {
            binding: expected.clone(),
            expires_at_ms: claims.expires_at_ms,
        })
    }
}

impl Claims {
    fn value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| invalid())
    }

    fn binding(&self) -> DesktopAppProofBinding {
        DesktopAppProofBinding {
            account_id: self.account_id.clone(),
            hosted_db_id: self.hosted_db_id.clone(),
            origin_database_id: self.origin_database_id.clone(),
            hosted_origin: self.hosted_origin.clone(),
            app: AppAttribution {
                package: self.package.clone(),
                version: self.version.clone(),
                install_event_id: self.install_event_id.clone(),
            },
        }
    }
}

fn bounded_token(raw: &str, max: usize) -> bool {
    !raw.is_empty() && raw.len() <= max && raw.bytes().all(|b| b.is_ascii_graphic())
}

fn invalid() -> Error {
    Error::engine("desktop app proof refused")
}
fn unavailable() -> Error {
    Error::engine("desktop app proof key provider unavailable")
}

#[cfg(test)]
mod tests {
    use super::super::DeploymentPlanKeyring;
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use futures::future::BoxFuture;

    fn binding() -> DesktopAppProofBinding {
        DesktopAppProofBinding {
            account_id: "acct-owner".into(),
            hosted_db_id: "hosted-route".into(),
            origin_database_id: "portable-db".into(),
            hosted_origin: "https://app.example".into(),
            app: AppAttribution::new("notes", "1.0.0", "install-1").unwrap(),
        }
    }

    fn keys(active: &str, retained: &[(&str, u8)]) -> Arc<dyn HostedPlanKeyProvider> {
        Arc::new(DeploymentPlanKeyring::from_json(&json!({
            "active_key_id": active,
            "keys": retained.iter().map(|(id, byte)| json!({"id":id,"key":STANDARD.encode([*byte;32])})).collect::<Vec<_>>()
        }).to_string()).unwrap())
    }

    async fn core() -> DesktopAppProofCore {
        DesktopAppProofCore::new(keys("k1", &[("k1", 1)]))
            .await
            .unwrap()
    }

    async fn signed(core: &DesktopAppProofCore, mut wire: Value) -> String {
        wire["signature"] = json!(core
            .keys
            .seal(
                wire["key_id"].as_str().unwrap().into(),
                wire["claims"].clone()
            )
            .await
            .unwrap());
        wire.to_string()
    }

    #[tokio::test]
    async fn desktop_app_proof_cross_instance_rotation_and_key_retirement() {
        let first = core().await;
        let proof = first.issue(&binding(), 10, MAX_TTL_MS).await.unwrap();
        let second = DesktopAppProofCore::new(keys("k2", &[("k1", 1), ("k2", 2)]))
            .await
            .unwrap();
        let verified = second
            .verify(proof.expose_secret(), &binding(), 20)
            .await
            .unwrap();
        assert!(verified.binding() == &binding());
        assert_eq!(verified.expires_at_ms(), 60_010);
        let new_proof = second.issue(&binding(), 20, 100).await.unwrap();
        let third = DesktopAppProofCore::new(keys("k2", &[("k2", 2)]))
            .await
            .unwrap();
        third
            .verify(new_proof.expose_secret(), &binding(), 20)
            .await
            .unwrap();
        assert!(third
            .verify(proof.expose_secret(), &binding(), 20)
            .await
            .is_err());
        let wrong = DesktopAppProofCore::new(keys("k1", &[("k1", 9)]))
            .await
            .unwrap();
        assert!(wrong
            .verify(proof.expose_secret(), &binding(), 20)
            .await
            .is_err());
        assert_eq!(format!("{proof:?}"), "DesktopAppProof([redacted])");
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedDesktopAppIdentity([redacted])"
        );
        let another = first.issue(&binding(), 10, MAX_TTL_MS).await.unwrap();
        assert!(proof.expose_secret() != another.expose_secret());
    }

    #[tokio::test]
    async fn desktop_app_proof_exact_scope_and_signed_claims_refuse() {
        let core = core().await;
        let proof = core.issue(&binding(), 10, 100).await.unwrap();
        for field in [
            "account_id",
            "hosted_db_id",
            "origin_database_id",
            "hosted_origin",
            "package",
            "version",
            "install_event_id",
            "format",
            "purpose",
            "audience",
            "key_id",
            "nonce",
        ] {
            let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
            wire["claims"][field] = json!("foreign");
            // Even an authentic signature cannot waive exact context/domain checks.
            let wire = signed(&core, wire).await;
            assert!(core.verify(&wire, &binding(), 10).await.is_err(), "{field}");
        }
        let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
        wire["key_id"] = json!("k2");
        assert!(core
            .verify(&wire.to_string(), &binding(), 10)
            .await
            .is_err());
        let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
        wire["claims"]["nonce"] = json!(Uuid::new_v4().to_string());
        assert!(core
            .verify(&wire.to_string(), &binding(), 10)
            .await
            .is_err());
        // Different authentic caller/app expectations also refuse unchanged proofs.
        let mut different = binding();
        different.account_id = "another-account".into();
        assert!(core
            .verify(proof.expose_secret(), &different, 10)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn desktop_app_proof_time_boundaries_and_overflow() {
        let core = core().await;
        for (now, ttl) in [(-1, 1), (0, 0), (0, -1), (0, MAX_TTL_MS + 1), (i64::MAX, 1)] {
            assert!(core.issue(&binding(), now, ttl).await.is_err());
        }
        let proof = core.issue(&binding(), 0, 1).await.unwrap();
        core.verify(proof.expose_secret(), &binding(), 0)
            .await
            .unwrap();
        for now in [-1, 1, i64::MAX] {
            assert!(core
                .verify(proof.expose_secret(), &binding(), now)
                .await
                .is_err());
        }
        let proof = core.issue(&binding(), 10, MAX_TTL_MS).await.unwrap();
        core.verify(proof.expose_secret(), &binding(), 60_009)
            .await
            .unwrap();
        assert!(core
            .verify(proof.expose_secret(), &binding(), 60_010)
            .await
            .is_err());
        for (issued, expires) in [
            (-1, 1),
            (0, MAX_TTL_MS + 1),
            (10, 10),
            (10, 9),
            (i64::MIN, i64::MAX),
        ] {
            let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
            wire["claims"]["issued_at_ms"] = json!(issued);
            wire["claims"]["expires_at_ms"] = json!(expires);
            assert!(core
                .verify(&signed(&core, wire).await, &binding(), 10)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn desktop_app_proof_strict_wire_and_origin() {
        let core = core().await;
        for origin in [
            "https://app.example/",
            "https://user@app.example",
            "https://app.example/path",
            "https://app.example?x",
            "https://app.example#x",
            "HTTPS://APP.EXAMPLE",
            "https://app.example:443",
            "file:///tmp/x",
            "null",
        ] {
            let mut bad = binding();
            bad.hosted_origin = origin.into();
            assert!(core.issue(&bad, 0, 1).await.is_err(), "{origin}");
        }
        let proof = core.issue(&binding(), 10, 100).await.unwrap();
        for raw in [
            "".into(),
            "{}".into(),
            "x".repeat(MAX_PROOF_BYTES + 1),
            format!("{{\"key_id\":\"k1\",{}", &proof.expose_secret()[1..]),
        ] {
            assert!(core.verify(&raw, &binding(), 10).await.is_err());
        }
        for field in ["unknown", "authority", "consent"] {
            let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
            wire["claims"][field] = json!(true);
            assert!(core
                .verify(&signed(&core, wire).await, &binding(), 10)
                .await
                .is_err());
        }
        let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
        wire["extra"] = json!(true);
        assert!(core
            .verify(&wire.to_string(), &binding(), 10)
            .await
            .is_err());
        let duplicate_claim = proof.expose_secret().replace(
            "\"purpose\":",
            "\"purpose\":\"desktop-app-identity\",\"purpose\":",
        );
        assert!(core.verify(&duplicate_claim, &binding(), 10).await.is_err());
        let mut bad = binding();
        bad.account_id = "x".repeat(257);
        assert!(core.issue(&bad, 0, 1).await.is_err());
        let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
        wire["signature"] = json!("raw-secret-sentinel");
        let error = core
            .verify(&wire.to_string(), &binding(), 10)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "desktop app proof refused");
    }

    #[tokio::test]
    async fn desktop_app_proof_bidirectional_plan_domain_substitution() {
        let core = core().await;
        let proof = core.issue(&binding(), 10, 100).await.unwrap();
        let mut wire: Value = serde_json::from_str(proof.expose_secret()).unwrap();
        // Actual hosted stored-plan retained-key domain, sealed by the same provider.
        let plan_challenge = json!({"domain":"native.mcp-executor.retained-key.v1", "format":"native.hosted-write-plan-envelope.v1", "key_id":"k1"});
        let plan_signature = core
            .keys
            .seal("k1".into(), plan_challenge.clone())
            .await
            .unwrap();
        let app_signature = wire["signature"].as_str().unwrap().to_owned();
        assert!(core
            .keys
            .verify("k1".into(), plan_challenge, app_signature)
            .await
            .is_err());
        wire["signature"] = json!(plan_signature);
        assert!(core
            .verify(&wire.to_string(), &binding(), 10)
            .await
            .is_err());
        // Readiness signatures cannot substitute for identity either.
        wire["signature"] = json!(core.keys.seal("k1".into(), json!({"format":FORMAT,"audience":AUDIENCE,"purpose":READINESS_PURPOSE,"key_id":"k1"})).await.unwrap());
        assert!(core
            .verify(&wire.to_string(), &binding(), 10)
            .await
            .is_err());
    }

    struct BrokenKeys {
        pending: bool,
        fail_verify: bool,
    }
    impl HostedPlanKeyProvider for BrokenKeys {
        fn active_key_id(&self) -> BoxFuture<'static, Result<String>> {
            let pending = self.pending;
            Box::pin(async move {
                if pending {
                    futures::future::pending().await
                } else {
                    Ok("k1".into())
                }
            })
        }
        fn seal(&self, _: String, payload: Value) -> BoxFuture<'static, Result<String>> {
            assert_eq!(payload["purpose"], READINESS_PURPOSE);
            let fail_verify = self.fail_verify;
            Box::pin(async move {
                if fail_verify {
                    Ok("secret-signature".into())
                } else {
                    Err(Error::engine("secret-sentinel"))
                }
            })
        }
        fn verify(&self, _: String, _: Value, _: String) -> BoxFuture<'static, Result<()>> {
            Box::pin(async { Err(Error::engine("secret-sentinel")) })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn desktop_app_proof_readiness_failure_and_timeout_are_fixed() {
        for (pending, fail_verify) in [(false, false), (false, true), (true, false)] {
            let result = DesktopAppProofCore::new(Arc::new(BrokenKeys {
                pending,
                fail_verify,
            }))
            .await;
            assert_eq!(
                result.err().unwrap().to_string(),
                "desktop app proof key provider unavailable"
            );
        }
    }
}
