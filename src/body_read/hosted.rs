//! Privileged request-bound PRIVATE Hosted integration. No route/tool offers it.
use super::*;
use crate::{
    db::DatabaseOpenMode,
    mcp::{registry::Caller, DeploymentAdmission},
    Db,
};
use sha2::Digest;
use std::result::Result;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;

pub struct Process {
    pub(super) slots: Arc<Semaphore>,
    pub(super) jobs: Arc<sqlite::owned_jobs::Registry>,
    pub(super) codec: &'static Codec,
    epoch: Instant,
    cipher: XChaCha20Poly1305,
    correlation: [u8; 32],
}

/// Observation of the exact already-retained jobs, with no admission authority.
#[cfg(any(test, feature = "body-read-test-support"))]
#[doc(hidden)]
pub struct QualificationJobs(sqlite::owned_jobs::TerminalObservation);
/// A one-shot observation of the next real registration on the selected handle.
#[cfg(any(test, feature = "body-read-test-support"))]
#[doc(hidden)]
pub struct QualificationRegistration(sqlite::owned_jobs::RegistrationObservation);
#[cfg(any(test, feature = "body-read-test-support"))]
impl QualificationRegistration {
    pub async fn registered(self) -> Option<QualificationJobs> {
        self.0.registered().await.map(QualificationJobs)
    }
}
#[cfg(any(test, feature = "body-read-test-support"))]
impl QualificationJobs {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Observe the same retained runners. True requires their real physical
    /// ACK and terminal release; false/panic never establishes cleanup.
    pub async fn wait(self) -> bool {
        self.0.wait().await
    }
}
#[cfg(any(test, feature = "body-read-test-support"))]
impl Process {
    /// Observe before dispatch. This registers no job and grants no authority.
    #[doc(hidden)]
    pub fn observe_registration_for_qualification(&self, db: &Db) -> QualificationRegistration {
        QualificationRegistration(self.jobs.observe_registration(db))
    }
    /// Snapshot only. This cannot cancel, retire, admit, or reset a job.
    #[doc(hidden)]
    pub fn observe_jobs_for_qualification(&self) -> QualificationJobs {
        QualificationJobs(self.jobs.observe_terminal())
    }
}
pub fn process() -> &'static Process {
    static PROCESS: OnceLock<Process> = OnceLock::new();
    PROCESS.get_or_init(|| {
        let mut key = [0; 32];
        let mut correlation = [0; 32];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut correlation);
        Process {
            slots: Arc::new(Semaphore::new(2)),
            jobs: Arc::new(sqlite::owned_jobs::Registry::default()),
            codec: Codec::process(),
            epoch: Instant::now(),
            cipher: XChaCha20Poly1305::new((&key).into()),
            correlation,
        }
    })
}
pub enum AlphaRequest<'a> {
    Issue {
        package: &'a str,
    },
    /// Same admission/source proof, opt-in same-response source correlation.
    IssueMixed {
        package: &'a str,
    },
    Page {
        mount_token: &'a str,
        request_json: &'a [u8],
    },
    Retire {
        mount_token: &'a str,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRefusal {
    Shape,
    Deadline,
    Profile,
    Source,
}
pub struct Ingress<'a> {
    owner: &'static Process,
    db: &'a Db,
    caller: &'a Caller,
    request: AlphaRequest<'a>,
    cookie: &'a str,
    origin: &'a str,
    started: Instant,
    admission: DeploymentAdmission,
}
/// Actual request headers supplied by verified Hosted code. This pair carries
/// no authority; `Ingress::from_verified_host` retains its safety contract.
pub struct HostHeaders<'a> {
    pub cookie: &'a str,
    pub origin: &'a str,
}
impl<'a> Ingress<'a> {
    /// # Safety
    /// Trusted Hosted code MUST authenticate actual Cookie (never Bearer plus
    /// cookie), check configured exact Origin/same-origin/CSRF and selected
    /// folded membership/Db/raw account, and supply its ACTUAL classified
    /// deployment admission. `started` is raw pre-body ingress after process()
    /// initialization. Inputs/action are immutable and request-bound. Package
    /// selection is parent Hosted authored-install selection, not frame
    /// authority. Do not call from MCP/agent/history or public marker flags.
    pub unsafe fn from_verified_host(
        owner: &'static Process,
        db: &'a Db,
        caller: &'a Caller,
        request: AlphaRequest<'a>,
        headers: HostHeaders<'a>,
        started: Instant,
        admission: DeploymentAdmission,
    ) -> Result<Self, IngressRefusal> {
        let HostHeaders { cookie, origin } = headers;
        if !std::ptr::eq(owner, process()) {
            return Err(IngressRefusal::Source);
        }
        if started < owner.epoch
            || started > Instant::now()
            || started
                .checked_add(Duration::from_secs(5))
                .is_none_or(|d| Instant::now() >= d)
        {
            return Err(IngressRefusal::Deadline);
        }
        if db.open_mode() != DatabaseOpenMode::ReadWrite || caller.is_member_copy() {
            return Err(IngressRefusal::Profile);
        }
        if caller.is_trusted_local() || !sqlite::trusted_input(caller.credential()) {
            return Err(IngressRefusal::Source);
        }
        if cookie.is_empty()
            || cookie.len() > 4096
            || origin.is_empty()
            || origin.len() > 256
            || !origin.is_ascii()
        {
            return Err(IngressRefusal::Shape);
        }
        let valid = match request {
            AlphaRequest::Issue { package } | AlphaRequest::IssueMixed { package } => {
                sqlite::alpha_install::package_valid(package)
            }
            AlphaRequest::Page {
                mount_token,
                request_json,
            } => token_shape(mount_token) && request_json.len() <= MAX_REQUEST_BYTES,
            AlphaRequest::Retire { mount_token } => token_shape(mount_token),
        };
        if !valid {
            return Err(IngressRefusal::Shape);
        }
        Ok(Self {
            owner,
            db,
            caller,
            request,
            cookie,
            origin,
            started,
            admission,
        })
    }
}
pub struct CanonicalBytes(pub(super) Box<[u8]>);
impl std::fmt::Debug for CanonicalBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CanonicalBytes(redacted)")
    }
}
impl CanonicalBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRefusal {
    InvalidIngress,
    Busy,
    MountUnavailable,
    Deadline,
    Cancelled,
    HtmlUnavailable,
    Engine,
}
pub enum Reply {
    Issued(CanonicalBytes),
    Body(CanonicalBytes),
    Retired,
    HostRefused(HostRefusal),
}

pub(super) enum OwnedRequest {
    Issue(String),
    IssueMixed(String),
    Page(String, Vec<u8>),
    Retire(String),
}
pub(super) struct Work {
    pub(super) owner: &'static Process,
    pub(super) db: Db,
    pub(super) caller: Caller,
    pub(super) request: OwnedRequest,
    pub(super) cookie: String,
    pub(super) origin: String,
    pub(super) started: Instant,
    pub(super) admission: DeploymentAdmission,
    pub(super) delivery: crate::artifact_html::LaunchDelivery,
    #[cfg(test)]
    pub(super) probe: Option<Arc<sqlite::BrokerProbe>>,
}
pub async fn execute(
    ingress: Ingress<'_>,
    delivery: &crate::artifact_html::LaunchDelivery,
) -> Reply {
    let request = match ingress.request {
        AlphaRequest::Issue { package } => OwnedRequest::Issue(package.into()),
        AlphaRequest::IssueMixed { package } => OwnedRequest::IssueMixed(package.into()),
        AlphaRequest::Page {
            mount_token,
            request_json,
        } => OwnedRequest::Page(mount_token.into(), request_json.into()),
        AlphaRequest::Retire { mount_token } => OwnedRequest::Retire(mount_token.into()),
    };
    sqlite::execute_hosted(Work {
        owner: ingress.owner,
        db: ingress.db.clone(),
        caller: ingress.caller.clone(),
        request,
        cookie: ingress.cookie.into(),
        origin: ingress.origin.into(),
        started: ingress.started,
        admission: ingress.admission,
        delivery: delivery.clone(),
        #[cfg(test)]
        probe: None,
    })
    .await
}
const MOUNT_AAD: &[u8] = b"native.alpha-install.body-mount.v1";
fn token_shape(token: &str) -> bool {
    token.len() <= 6400
        && token.starts_with("abm1.")
        && token[5..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && token.len() >= 85
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OpenedMount {
    v: u8,
    database_id: String,
    viewer: String,
    pub(super) package: String,
    pub(super) source: String,
    pub(super) generation: String,
    pub(super) runtime: String,
    pub(super) declaration: String,
    session: String,
    origin: String,
    mount_id: String,
    issued_ms: u64,
    expires_ms: u64,
}
impl Process {
    fn tag(&self, domain: &[u8], bytes: &[u8]) -> String {
        let mut h =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.correlation).expect("fixed HMAC key");
        h.update(domain);
        h.update(&(bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        hex::encode(h.finalize().into_bytes())
    }
    fn millis(&self, time: Instant) -> Result<u64, HostRefusal> {
        let n = time
            .checked_duration_since(self.epoch)
            .ok_or(HostRefusal::Deadline)?
            .as_millis();
        if n > JS_SAFE as u128 {
            return Err(HostRefusal::Deadline);
        }
        Ok(n as u64)
    }
    pub(super) fn mint(
        &self,
        database: &str,
        viewer: &str,
        package: &str,
        source: &sqlite::ResolvedSource,
        headers: HostHeaders<'_>,
        started: Instant,
    ) -> Result<(String, OpenedMount), HostRefusal> {
        let HostHeaders { cookie, origin } = headers;
        let issued_ms = self.millis(started)?;
        let expires_ms = issued_ms
            .checked_add(LIFETIME_MS)
            .filter(|n| *n <= JS_SAFE)
            .ok_or(HostRefusal::Deadline)?;
        let mut id = [0; 32];
        rand::rng().fill_bytes(&mut id);
        let mount = OpenedMount {
            v: 1,
            database_id: database.into(),
            viewer: viewer.into(),
            package: package.into(),
            source: source.source.clone(),
            generation: source.generation.clone(),
            runtime: source.runtime.clone(),
            declaration: source.declaration.clone(),
            session: self.tag(
                b"native.alpha-install.body-mount.session.v1",
                cookie.as_bytes(),
            ),
            origin: self.tag(
                b"native.alpha-install.body-mount.origin.v1",
                origin.as_bytes(),
            ),
            mount_id: hex::encode(id),
            issued_ms,
            expires_ms,
        };
        let bytes = serde_json::to_vec(&mount).map_err(|_| HostRefusal::Engine)?;
        if bytes.len() > 3072 {
            return Err(HostRefusal::InvalidIngress);
        }
        let mut nonce = [0; 24];
        rand::rng().fill_bytes(&mut nonce);
        let encrypted = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes,
                    aad: MOUNT_AAD,
                },
            )
            .map_err(|_| HostRefusal::Engine)?;
        let token = format!(
            "abm1.{}",
            hex::encode([nonce.as_slice(), encrypted.as_slice()].concat())
        );
        if !token_shape(&token) {
            return Err(HostRefusal::Engine);
        }
        Ok((token, mount))
    }
    pub(super) fn open(
        &self,
        token: &str,
        viewer: &str,
        cookie: &str,
        origin: &str,
    ) -> Result<OpenedMount, HostRefusal> {
        let unavailable = || HostRefusal::MountUnavailable;
        if !token_shape(token) {
            return Err(unavailable());
        }
        let raw = hex::decode(&token[5..]).map_err(|_| unavailable())?;
        if raw.len() < 40 || raw.len() > 3112 {
            return Err(unavailable());
        }
        let decrypted = self
            .cipher
            .decrypt(
                &XNonce::from(<[u8; 24]>::try_from(&raw[..24]).map_err(|_| unavailable())?),
                Payload {
                    msg: &raw[24..],
                    aad: MOUNT_AAD,
                },
            )
            .map_err(|_| unavailable())?;
        if decrypted.len() > 3072
            || decrypted.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
        {
            return Err(unavailable());
        }
        let m: OpenedMount = serde_json::from_slice(&decrypted).map_err(|_| unavailable())?;
        let now = self.millis(Instant::now())?;
        if m.v != 1
            || !crate::identity::is_database_id(&m.database_id)
            || !sqlite::trusted_input(&m.viewer)
            || !sqlite::alpha_install::package_valid(&m.package)
            || [
                &m.source,
                &m.generation,
                &m.runtime,
                &m.declaration,
                &m.session,
                &m.origin,
                &m.mount_id,
            ]
            .iter()
            .any(|s| !digest(s))
            || m.expires_ms > JS_SAFE
            || m.issued_ms.checked_add(LIFETIME_MS) != Some(m.expires_ms)
            || now < m.issued_ms
            || now >= m.expires_ms
        {
            return Err(unavailable());
        }
        if !self.equal(m.viewer.as_bytes(), viewer.as_bytes())
            || !self.equal(
                m.session.as_bytes(),
                self.tag(
                    b"native.alpha-install.body-mount.session.v1",
                    cookie.as_bytes(),
                )
                .as_bytes(),
            )
            || !self.equal(
                m.origin.as_bytes(),
                self.tag(
                    b"native.alpha-install.body-mount.origin.v1",
                    origin.as_bytes(),
                )
                .as_bytes(),
            )
        {
            return Err(unavailable());
        }
        Ok(m)
    }
    pub(super) fn equal(&self, a: &[u8], b: &[u8]) -> bool {
        let mut expected =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.correlation).expect("fixed HMAC key");
        expected.update(b"native.alpha-install.body-mount.compare.v1");
        expected.update(a);
        let tag = expected.finalize().into_bytes();
        let mut actual =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.correlation).expect("fixed HMAC key");
        actual.update(b"native.alpha-install.body-mount.compare.v1");
        actual.update(b);
        actual.verify_slice(&tag).is_ok()
    }
}
impl OpenedMount {
    pub(super) fn database_matches(&self, owner: &Process, database: &str) -> bool {
        owner.equal(self.database_id.as_bytes(), database.as_bytes())
    }
    pub(super) fn source_matches(&self, owner: &Process, s: &sqlite::ResolvedSource) -> bool {
        [
            &self.source,
            &self.generation,
            &self.runtime,
            &self.declaration,
        ]
        .into_iter()
        .zip([&s.source, &s.generation, &s.runtime, &s.declaration])
        .all(|(a, b)| owner.equal(a.as_bytes(), b.as_bytes()))
    }
    pub(super) fn ticket_deadline(&self, owner: &Process) -> Result<Instant, HostRefusal> {
        owner
            .epoch
            .checked_add(Duration::from_millis(self.issued_ms))
            .and_then(|t| t.checked_add(crate::artifact_html::TICKET_TTL))
            .ok_or(HostRefusal::Deadline)
    }
    pub(super) fn metadata(
        &self,
        owner: &Process,
        token: &str,
    ) -> Result<crate::artifact_html::BodyMountMeta, HostRefusal> {
        let array = |s: &str| -> Result<[u8; 32], HostRefusal> {
            hex::decode(s)
                .map_err(|_| HostRefusal::MountUnavailable)?
                .try_into()
                .map_err(|_| HostRefusal::MountUnavailable)
        };
        let issued = owner
            .epoch
            .checked_add(Duration::from_millis(self.issued_ms))
            .ok_or(HostRefusal::Deadline)?;
        let expires = owner
            .epoch
            .checked_add(Duration::from_millis(self.expires_ms))
            .ok_or(HostRefusal::Deadline)?;
        let scope = owner.tag(
            b"native.alpha-install.body-mount.scope.v1",
            &serde_json::to_vec(&[&self.session, &self.database_id, &self.package])
                .map_err(|_| HostRefusal::Engine)?,
        );
        let principal = owner.tag(
            b"native.alpha-install.body-mount.principal.v1",
            self.viewer.as_bytes(),
        );
        crate::artifact_html::BodyMountMeta::checked(
            array(&self.mount_id)?,
            array(&scope)?,
            array(&principal)?,
            Sha256::digest(token.as_bytes()).into(),
            issued,
            expires,
        )
        .map_err(|_| HostRefusal::Engine)
    }
}
pub(super) fn delivery_error(e: crate::artifact_html::BodyDeliveryFailure) -> HostRefusal {
    use crate::artifact_html::BodyDeliveryFailure::*;
    match e {
        Busy => HostRefusal::Busy,
        Expired => HostRefusal::Deadline,
        Cancelled => HostRefusal::Cancelled,
        _ => HostRefusal::MountUnavailable,
    }
}
pub(super) fn still_live(cancel: &AtomicBool, deadline: Instant) -> bool {
    !cancel.load(Ordering::SeqCst) && Instant::now() < deadline
}

#[cfg(test)]
mod tests {
    use super::*;
    fn facts() -> sqlite::ResolvedSource {
        sqlite::ResolvedSource {
            source: "a".repeat(64),
            generation: "b".repeat(64),
            runtime: "c".repeat(64),
            declaration: "d".repeat(64),
            record_type: None,
        }
    }
    #[test]
    fn independent_mounts_bind_viewer_session_origin_and_restart_keys() {
        let p = process();
        let started = Instant::now();
        let ndb = "ndb_0123456789abcdef0123456789abcdef";
        let (a, opened) = p
            .mint(
                ndb,
                "acct_viewer",
                "fixture.app",
                &facts(),
                HostHeaders {
                    cookie: "cookie",
                    origin: "https://parent.test",
                },
                started,
            )
            .unwrap();
        let (b, _) = p
            .mint(
                ndb,
                "acct_viewer",
                "fixture.app",
                &facts(),
                HostHeaders {
                    cookie: "cookie",
                    origin: "https://parent.test",
                },
                started,
            )
            .unwrap();
        assert_ne!(a, b);
        assert!(p
            .open(&a, "acct_viewer", "cookie", "https://parent.test")
            .is_ok());
        for (viewer, cookie, origin) in [
            ("acct_other", "cookie", "https://parent.test"),
            ("acct_viewer", "rotated", "https://parent.test"),
            ("acct_viewer", "cookie", "https://other.test"),
        ] {
            assert!(matches!(
                p.open(&a, viewer, cookie, origin),
                Err(HostRefusal::MountUnavailable)
            ));
        }
        let ticket = opened.ticket_deadline(p).unwrap();
        assert!(ticket <= started + crate::artifact_html::TICKET_TTL);
        assert!(started + crate::artifact_html::TICKET_TTL - ticket < Duration::from_millis(1));
        assert_eq!(opened.expires_ms - opened.issued_ms, LIFETIME_MS);
        let other = Process {
            slots: Arc::new(Semaphore::new(2)),
            jobs: Arc::new(sqlite::owned_jobs::Registry::default()),
            codec: p.codec,
            epoch: p.epoch,
            cipher: XChaCha20Poly1305::new((&[41; 32]).into()),
            correlation: [42; 32],
        };
        assert!(matches!(
            other.open(&a, "acct_viewer", "cookie", "https://parent.test"),
            Err(HostRefusal::MountUnavailable)
        ));
    }
    #[test]
    fn authenticated_mount_plaintext_is_object_only_duplicate_preserving_and_bounded() {
        let p = process();
        let seal = |bytes: &[u8]| {
            let nonce = [9; 24];
            let encrypted = p
                .cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: bytes,
                        aad: MOUNT_AAD,
                    },
                )
                .unwrap();
            format!(
                "abm1.{}",
                hex::encode([nonce.as_slice(), encrypted.as_slice()].concat())
            )
        };
        for bytes in [
            b"[]".as_slice(),
            b"{\"v\":1,\"v\":1}",
            b"{\"v\":null}",
            &[b' '; 3073],
        ] {
            assert!(matches!(
                p.open(&seal(bytes), "acct_viewer", "cookie", "https://parent.test"),
                Err(HostRefusal::MountUnavailable)
            ));
        }
        assert!(!token_shape(&format!("abm1.{}", "a".repeat(6400))));
    }
}

#[cfg(test)]
mod qualification;
