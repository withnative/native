//! Private hosted body delivery provenance, never record-read authority.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

const RESERVED: u8 = 0;
const PUBLISHED: u8 = 1;
const REDEEMED: u8 = 2;
const INVALID: u8 = 3;
const RECORD_BYTES: usize = 512;
const META_BYTES: usize = 65536;
const DELIVERED_BYTES: usize = 1048576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyDeliveryFailure {
    Busy,
    Invalid,
    Expired,
    Cancelled,
    Closed,
}
type BodyResult<T> = std::result::Result<T, BodyDeliveryFailure>;

pub struct BodyMountMeta {
    id: [u8; 32],
    scope: [u8; 32],
    principal: [u8; 32],
    token: [u8; 32],
    issued: Instant,
    expires: Instant,
}
impl BodyMountMeta {
    pub fn checked(
        id: [u8; 32],
        scope: [u8; 32],
        principal: [u8; 32],
        token: [u8; 32],
        issued: Instant,
        expires: Instant,
    ) -> BodyResult<Self> {
        if issued.checked_add(Duration::from_secs(900)) != Some(expires) {
            return Err(BodyDeliveryFailure::Invalid);
        }
        Ok(Self {
            id,
            scope,
            principal,
            token,
            issued,
            expires,
        })
    }
    fn matches(&self, other: &Self) -> bool {
        self.id == other.id
            && self.scope == other.scope
            && self.principal == other.principal
            && self.token == other.token
            && self.issued == other.issued
            && self.expires == other.expires
    }
}
pub struct BodyLaunchContext {
    store: Arc<BodyStore>,
    parent: String,
}
pub struct PreparedLaunch {
    store: std::sync::Weak<BodyStore>,
    html: String,
    headers: HeaderMap,
}
pub struct PublishedLaunch {
    url: String,
    deadline: Instant,
}
impl PublishedLaunch {
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn ticket_deadline(&self) -> Instant {
        self.deadline
    }
}
struct Entry {
    meta: BodyMountMeta,
    state: Arc<AtomicU8>,
    ticket_id: [u8; 32],
    ticket_pending: bool,
    deadline: Instant,
    prepared: Option<PreparedLaunch>,
}
#[derive(Default)]
pub(super) struct BodyState {
    entries: HashMap<[u8; 32], Entry>,
    html_bytes: usize,
}
pub(super) struct BodyStore {
    config: Arc<RuntimeConfig>,
    pub(super) state: Mutex<BodyState>,
    pub(super) closed: AtomicBool,
}
pub(super) struct BodyOwner(pub(super) Arc<BodyStore>);
impl Drop for BodyOwner {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::SeqCst);
    }
}
impl BodyOwner {
    pub(super) fn new(config: Arc<RuntimeConfig>) -> Arc<Self> {
        Arc::new(Self(Arc::new(BodyStore {
            config,
            state: Mutex::new(BodyState::default()),
            closed: AtomicBool::new(false),
        })))
    }
}
pub(super) fn prune(state: &mut BodyState, now: Instant) {
    state.entries.retain(|_, entry| {
        let invalid = entry.state.load(Ordering::SeqCst) == INVALID
            || now >= entry.meta.expires
            || (entry.state.load(Ordering::SeqCst) != REDEEMED && now >= entry.deadline);
        if invalid {
            entry.state.store(INVALID, Ordering::SeqCst);
            if let Some(prepared) = entry.prepared.take() {
                state.html_bytes -= prepared.html.len();
            }
        }
        !invalid
    });
}
impl BodyState {
    pub(super) fn has_ticket(&self, id: &[u8; 32]) -> bool {
        self.entries.values().any(|e| e.ticket_id == *id)
    }
}
impl BodyLaunchContext {
    /// CPU work: the trusted caller must retain its registered physical job.
    pub fn prepare(self, source: String, expected_bundle: [u8; 32]) -> BodyResult<PreparedLaunch> {
        if source.len() > BODY_LIMIT || self.store.closed.load(Ordering::SeqCst) {
            return Err(BodyDeliveryFailure::Invalid);
        }
        let manifest = validate(&source).map_err(|_| BodyDeliveryFailure::Invalid)?;
        if manifest.body_digest != hex::encode(expected_bundle) {
            return Err(BodyDeliveryFailure::Invalid);
        }
        let bootstrap = BOOTSTRAP.replace(
            "__NATIVE_WORKBENCH_ORIGIN__",
            &serde_json::to_string(&self.parent).map_err(|_| BodyDeliveryFailure::Invalid)?,
        );
        let bytes = source
            .len()
            .checked_add("<script>".len())
            .and_then(|n| n.checked_add("</script>".len()))
            .and_then(|n| n.checked_add(bootstrap.len()))
            .ok_or(BodyDeliveryFailure::Invalid)?;
        if bytes > DELIVERED_BYTES {
            return Err(BodyDeliveryFailure::Invalid);
        }
        let html = inject(&source, &self.parent).map_err(|_| BodyDeliveryFailure::Invalid)?;
        if html.len() != bytes {
            return Err(BodyDeliveryFailure::Invalid);
        }
        let mut headers = HeaderMap::new();
        for (name, value) in [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CONTENT_DISPOSITION, "inline"),
            (CACHE_CONTROL, "no-store, private"),
            (PRAGMA, "no-cache"),
            (REFERRER_POLICY, "no-referrer"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        headers.insert("x-dns-prefetch-control", HeaderValue::from_static("off"));
        headers.insert("origin-agent-cluster", HeaderValue::from_static("?1"));
        headers.insert(
            "permissions-policy",
            HeaderValue::from_static(PERMISSIONS_POLICY),
        );
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&csp(&self.parent)).map_err(|_| BodyDeliveryFailure::Invalid)?,
        );
        Ok(PreparedLaunch {
            store: Arc::downgrade(&self.store),
            html,
            headers,
        })
    }
}
pub struct BodyReservation {
    store: Arc<BodyStore>,
    id: [u8; 32],
    state: Arc<AtomicU8>,
    descriptor: PublishedLaunch,
    armed: bool,
}
impl Drop for BodyReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Immediate logical invalidation precedes nonblocking physical cleanup.
        self.state.store(INVALID, Ordering::SeqCst);
        if let Ok(mut state) = self.store.state.try_lock() {
            prune(&mut state, Instant::now());
        }
    }
}
impl BodyReservation {
    pub fn descriptor(&self) -> &PublishedLaunch {
        &self.descriptor
    }
    pub fn publish(mut self, cancelled: &AtomicBool, deadline: Instant) -> BodyResult<()> {
        {
            let mut state = self
                .store
                .state
                .try_lock()
                .map_err(|_| BodyDeliveryFailure::Busy)?;
            let now = Instant::now();
            if self.store.closed.load(Ordering::SeqCst) {
                return Err(BodyDeliveryFailure::Closed);
            }
            if cancelled.load(Ordering::SeqCst) {
                return Err(BodyDeliveryFailure::Cancelled);
            }
            if now >= deadline || now >= self.descriptor.deadline {
                return Err(BodyDeliveryFailure::Expired);
            }
            let entry = state
                .entries
                .get_mut(&self.id)
                .ok_or(BodyDeliveryFailure::Invalid)?;
            if !Arc::ptr_eq(&entry.state, &self.state)
                || entry.state.load(Ordering::SeqCst) != RESERVED
                || now >= entry.meta.expires
            {
                return Err(BodyDeliveryFailure::Invalid);
            }
            entry.state.store(PUBLISHED, Ordering::SeqCst);
            self.armed = false;
        }
        Ok(())
    }
}
impl LaunchDelivery {
    pub fn body_context(&self, parent_origin: &str) -> BodyResult<BodyLaunchContext> {
        if parent_origin.len() > 256
            || !parent_origin.is_ascii()
            || self.config.artifact_origin.len() > 256
        {
            return Err(BodyDeliveryFailure::Invalid);
        }
        let parent = self
            .config
            .resolve_parent_origin(Some(parent_origin))
            .map_err(|_| BodyDeliveryFailure::Invalid)?;
        if self.body.0.closed.load(Ordering::SeqCst) {
            return Err(BodyDeliveryFailure::Closed);
        }
        Ok(BodyLaunchContext {
            store: self.body.0.clone(),
            parent,
        })
    }
    pub fn reserve_body_pair(
        &self,
        prepared: PreparedLaunch,
        meta: BodyMountMeta,
        ticket_deadline: Instant,
    ) -> BodyResult<BodyReservation> {
        let store = &self.body.0;
        let id = meta.id;
        if !prepared
            .store
            .upgrade()
            .is_some_and(|s| Arc::ptr_eq(store, &s))
            || meta.issued.checked_add(TICKET_TTL) != Some(ticket_deadline)
        {
            return Err(BodyDeliveryFailure::Invalid);
        }
        let mut random = [0u8; 32];
        rand::rng().fill_bytes(&mut random);
        let ticket = hex::encode(random);
        let descriptor = PublishedLaunch {
            url: format!(
                "{}/artifact-runtime/v1/launch/{ticket}",
                store.config.artifact_origin
            ),
            deadline: ticket_deadline,
        };
        let entry_state = Arc::new(AtomicU8::new(RESERVED));
        {
            let mut state = store
                .state
                .try_lock()
                .map_err(|_| BodyDeliveryFailure::Busy)?;
            let now = Instant::now();
            if store.closed.load(Ordering::SeqCst) {
                return Err(BodyDeliveryFailure::Closed);
            }
            prune(&mut state, now);
            if now >= ticket_deadline || now >= meta.expires || now < meta.issued {
                return Err(BodyDeliveryFailure::Expired);
            }
            // Legacy and body launches have separately bounded stores. Body
            // reservations never call legacy make_room or evict live entries.
            if state.entries.len() >= LAUNCH_TICKET_MAX_COUNT
                || state
                    .entries
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(RECORD_BYTES))
                    .is_none_or(|n| n > META_BYTES)
                || state
                    .entries
                    .values()
                    .filter(|e| e.meta.principal == meta.principal)
                    .count()
                    >= LAUNCH_TICKET_MAX_PER_PRINCIPAL
                || state
                    .html_bytes
                    .checked_add(prepared.html.len())
                    .is_none_or(|n| n > LAUNCH_TICKET_MAX_BYTES)
            {
                return Err(BodyDeliveryFailure::Busy);
            }
            if state.entries.contains_key(&meta.id)
                || state.entries.values().any(|e| e.ticket_id == random)
            {
                return Err(BodyDeliveryFailure::Invalid);
            }
            state.html_bytes += prepared.html.len();
            state.entries.insert(
                meta.id,
                Entry {
                    meta,
                    state: entry_state.clone(),
                    ticket_id: random,
                    ticket_pending: true,
                    deadline: ticket_deadline,
                    prepared: Some(prepared),
                },
            );
        }
        Ok(BodyReservation {
            store: store.clone(),
            id,
            state: entry_state,
            descriptor,
            armed: true,
        })
    }
    pub fn body_mount_is_redeemed(&self, meta: &BodyMountMeta) -> BodyResult<bool> {
        let mut state = self
            .body
            .0
            .state
            .try_lock()
            .map_err(|_| BodyDeliveryFailure::Busy)?;
        if self.body.0.closed.load(Ordering::SeqCst) {
            return Err(BodyDeliveryFailure::Closed);
        }
        prune(&mut state, Instant::now());
        Ok(state
            .entries
            .get(&meta.id)
            .is_some_and(|e| e.meta.matches(meta) && e.state.load(Ordering::SeqCst) == REDEEMED))
    }
    pub fn retire_body_mount(&self, meta: &BodyMountMeta) -> BodyResult<()> {
        self.retire_body_mount_checked(meta, &AtomicBool::new(false), meta.expires)
    }
    /// The request owner supplies its unchanged clock and cancellation state.
    pub fn retire_body_mount_checked(
        &self,
        meta: &BodyMountMeta,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> BodyResult<()> {
        let mut state = self
            .body
            .0
            .state
            .try_lock()
            .map_err(|_| BodyDeliveryFailure::Busy)?;
        if self.body.0.closed.load(Ordering::SeqCst) {
            return Err(BodyDeliveryFailure::Closed);
        }
        prune(&mut state, Instant::now());
        if cancelled.load(Ordering::SeqCst) {
            return Err(BodyDeliveryFailure::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(BodyDeliveryFailure::Expired);
        }
        if let Some(e) = state.entries.get(&meta.id) {
            if !e.meta.matches(meta) {
                return Err(BodyDeliveryFailure::Invalid);
            }
            e.state.store(INVALID, Ordering::SeqCst);
        }
        prune(&mut state, Instant::now());
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn redeem_body(
        &self,
        token: &str,
        headers: &HeaderMap,
    ) -> BodyResult<Option<Response>> {
        let mut state = self
            .body
            .0
            .state
            .try_lock()
            .map_err(|_| BodyDeliveryFailure::Busy)?;
        let now = Instant::now();
        prune(&mut state, now);
        let Some(id) = sample_delivery::decode_ticket(token) else {
            return Ok(None);
        };
        if !state.has_ticket(&id) {
            return Ok(None);
        }
        match self.redeem_body_in(&mut state, &id, headers, now) {
            TicketLookup::Matched(LaunchOutcome::Delivered(r)) => Ok(Some(r)),
            _ => Err(BodyDeliveryFailure::Invalid),
        }
    }
    pub(super) fn redeem_body_in(
        &self,
        state: &mut BodyState,
        token: &[u8; 32],
        headers: &HeaderMap,
        now: Instant,
    ) -> TicketLookup {
        let id = state
            .entries
            .iter()
            .find_map(|(id, e)| (e.ticket_id == *token).then_some(*id))
            .expect("probed under same lock");
        let entry = state.entries.get_mut(&id).expect("probed under same lock");
        let refuse = |r| TicketLookup::Matched(LaunchOutcome::Refused(r));
        if !host_matches_origin(headers, &self.config.artifact_origin) {
            if matches!(entry.state.load(Ordering::SeqCst), RESERVED | PUBLISHED) {
                entry.state.store(INVALID, Ordering::SeqCst);
                prune(state, now);
            }
            return refuse(LaunchRefusal::WrongHost);
        }
        if entry.state.load(Ordering::SeqCst) == REDEEMED {
            return refuse(LaunchRefusal::Spent);
        }
        if entry.state.load(Ordering::SeqCst) != PUBLISHED {
            return refuse(LaunchRefusal::Unpublished);
        }
        if !entry.ticket_pending || now >= entry.deadline || now >= entry.meta.expires {
            return refuse(LaunchRefusal::Expired);
        }
        let Some(prepared) = entry.prepared.take() else {
            return refuse(LaunchRefusal::Invalid);
        };
        let bytes = prepared.html.len();
        let mut response = prepared.html.into_response();
        *response.headers_mut() = prepared.headers;
        state.html_bytes -= bytes;
        if Instant::now() >= entry.deadline {
            entry.state.store(INVALID, Ordering::SeqCst);
            return refuse(LaunchRefusal::Expired);
        }
        entry.ticket_pending = false;
        entry.state.store(REDEEMED, Ordering::SeqCst);
        TicketLookup::Matched(LaunchOutcome::Delivered(response))
    }
}
impl std::fmt::Debug for PreparedLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLaunch(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn delivery() -> LaunchDelivery {
        LaunchDelivery::isolated_fixture(
            RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap(),
        )
    }
    fn meta(id: u8, started: Instant) -> BodyMountMeta {
        BodyMountMeta::checked(
            [id; 32],
            [1; 32],
            [2; 32],
            [id; 32],
            started,
            started + Duration::from_secs(900),
        )
        .unwrap()
    }
    // Direct output fixture isolates metadata ownership, not HTML validation.
    fn output(d: &LaunchDelivery) -> PreparedLaunch {
        PreparedLaunch {
            store: Arc::downgrade(&d.body.0),
            html: "fixture".into(),
            headers: HeaderMap::new(),
        }
    }
    fn reserve(d: &LaunchDelivery, id: u8, t: Instant) -> BodyReservation {
        d.reserve_body_pair(output(d), meta(id, t), t + TICKET_TTL)
            .unwrap()
    }
    fn redeemed(d: &LaunchDelivery, id: u8, t: Instant) {
        let old = reserve(d, id, t);
        let ticket = old
            .descriptor()
            .url()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        old.publish(&AtomicBool::new(false), t + TICKET_TTL)
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("artifact.test"));
        assert!(d.redeem_body(&ticket, &headers).unwrap().is_some());
        assert!(d.body_mount_is_redeemed(&meta(id, t)).unwrap());
    }
    #[test]
    fn contended_drop_invalidates_immediately_retains_accounting_then_prunes() {
        let d = delivery();
        let t = Instant::now();
        redeemed(&d, 1, t);
        let new = reserve(&d, 2, t);
        let state = new.state.clone();
        let held = d.body.0.state.lock().unwrap();
        drop(new);
        assert_eq!(state.load(Ordering::SeqCst), INVALID);
        assert_eq!(held.entries.len(), 2);
        assert_eq!(held.html_bytes, 7);
        drop(held);
        let third = reserve(&d, 3, t);
        let held = d.body.0.state.lock().unwrap();
        assert_eq!(held.entries.len(), 2);
        assert!(held.entries.contains_key(&[1; 32]));
        assert!(!held.entries.contains_key(&[2; 32]));
        drop(held);
        assert!(d.body_mount_is_redeemed(&meta(1, t)).unwrap());
        drop(third);
    }
    #[test]
    fn busy_publish_cancel_expiry_and_foreign_instance_preserve_old_pair() {
        let d = delivery();
        let t = Instant::now();
        redeemed(&d, 1, t);
        let new = reserve(&d, 2, t);
        let atomic = new.state.clone();
        let held = d.body.0.state.lock().unwrap();
        assert_eq!(
            new.publish(&AtomicBool::new(false), t + TICKET_TTL),
            Err(BodyDeliveryFailure::Busy)
        );
        assert_eq!(atomic.load(Ordering::SeqCst), INVALID);
        drop(held);
        assert_eq!(
            reserve(&d, 3, t).publish(&AtomicBool::new(true), t + TICKET_TTL),
            Err(BodyDeliveryFailure::Cancelled)
        );
        assert_eq!(
            reserve(&d, 4, t).publish(&AtomicBool::new(false), t),
            Err(BodyDeliveryFailure::Expired)
        );
        let foreign = delivery();
        assert!(matches!(
            foreign.reserve_body_pair(output(&d), meta(5, t), t + TICKET_TTL),
            Err(BodyDeliveryFailure::Invalid)
        ));
        let held = d.body.0.state.lock().unwrap();
        assert_eq!(held.entries.len(), 1);
        assert!(held.entries.contains_key(&[1; 32]));
        drop(held);
        assert!(d.body_mount_is_redeemed(&meta(1, t)).unwrap());
        // Labelled isolated owner-lock panic: this proves poison handling, not
        // a real SQLite worker/close failure. Old pairs remain in charged storage.
        let store = d.body.0.clone();
        assert!(std::thread::spawn(move || {
            let _lock = store.state.lock().unwrap();
            panic!("isolated metadata poison");
        })
        .join()
        .is_err());
        assert_eq!(
            d.body_mount_is_redeemed(&meta(1, t)),
            Err(BodyDeliveryFailure::Busy)
        );
        assert_eq!(
            d.retire_body_mount(&meta(1, t)),
            Err(BodyDeliveryFailure::Busy)
        );
        let retained = match d.body.0.state.lock() {
            Err(p) => p.into_inner(),
            Ok(_) => panic!("poison missing"),
        };
        assert!(retained.entries.contains_key(&[1; 32]));
    }
    #[test]
    fn pending_principal_cap_has_no_live_eviction_and_retirement_is_exact() {
        let d = delivery();
        let t = Instant::now();
        let mut guards = Vec::new();
        for id in 0..32 {
            guards.push(reserve(&d, id, t));
        }
        assert!(matches!(
            d.reserve_body_pair(output(&d), meta(33, t), t + TICKET_TTL),
            Err(BodyDeliveryFailure::Busy)
        ));
        assert_eq!(d.body.0.state.lock().unwrap().entries.len(), 32);
        d.retire_body_mount(&meta(1, t)).unwrap();
        assert_eq!(d.body.0.state.lock().unwrap().entries.len(), 31);
        guards
            .remove(0)
            .publish(&AtomicBool::new(false), t + TICKET_TTL)
            .unwrap();
        let held = d.body.0.state.lock().unwrap();
        assert_eq!(
            d.retire_body_mount(&meta(0, t)),
            Err(BodyDeliveryFailure::Busy)
        );
        drop(held);
        assert!(d
            .body
            .0
            .state
            .lock()
            .unwrap()
            .entries
            .contains_key(&[0; 32]));

        // The complete mount-record count and fixed logical metadata cap also
        // count tentative pairs across distinct principals, without eviction.
        let all = delivery();
        let mut all_guards = Vec::new();
        for id in 0..128u8 {
            let mut m = meta(id, t);
            m.principal = [id / 32; 32];
            all_guards.push(
                all.reserve_body_pair(output(&all), m, t + TICKET_TTL)
                    .unwrap(),
            );
        }
        let mut extra = meta(200, t);
        extra.principal = [9; 32];
        assert!(matches!(
            all.reserve_body_pair(output(&all), extra, t + TICKET_TTL),
            Err(BodyDeliveryFailure::Busy)
        ));
        assert_eq!(
            all.body.0.state.lock().unwrap().entries.len() * RECORD_BYTES,
            META_BYTES
        );
        drop(all_guards);
    }
    #[test]
    fn original_ticket_cleanup_and_owner_drop_are_nonrenewing() {
        let d = delivery();
        let t = Instant::now();
        let guard = reserve(&d, 1, t);
        let state = guard.state.clone();
        {
            let mut held = d.body.0.state.lock().unwrap();
            prune(&mut held, t + TICKET_TTL);
            assert!(held.entries.is_empty());
        }
        assert_eq!(state.load(Ordering::SeqCst), INVALID);
        assert_eq!(
            guard.publish(&AtomicBool::new(false), t + Duration::from_secs(900)),
            Err(BodyDeliveryFailure::Invalid)
        );
        let context = d.body_context("https://parent.test").unwrap();
        drop(d);
        assert!(context.store.closed.load(Ordering::SeqCst));
    }
    #[test]
    fn uncached_preparation_matches_exact_seventeen_tag_byte_preflight() {
        let d = delivery();
        let source=r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fixture</title><style>body{margin:0}</style></head><body><main><h1>Hello é😀</h1></main></body></html>"#.to_owned();
        let digest: [u8; 32] = Sha256::digest(source.as_bytes()).into();
        let prepared = d
            .body_context("https://parent.test")
            .unwrap()
            .prepare(source.clone(), digest)
            .unwrap();
        let bootstrap = BOOTSTRAP.replace(
            "__NATIVE_WORKBENCH_ORIGIN__",
            &serde_json::to_string("https://parent.test").unwrap(),
        );
        assert_eq!(prepared.html.len(), source.len() + 17 + bootstrap.len());
        assert!(prepared.html.len() <= DELIVERED_BYTES);
        assert!(matches!(
            d.body_context("https://parent.test")
                .unwrap()
                .prepare(source, [0; 32]),
            Err(BodyDeliveryFailure::Invalid)
        ));
    }
}

#[cfg(test)]
mod router_correction_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    const SOURCE:&str="<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Actual delivery</title></head><body>é😀</body></html>";
    fn metadata(id: u8, t: Instant) -> BodyMountMeta {
        BodyMountMeta::checked(
            [id; 32],
            [1; 32],
            [2; 32],
            [id; 32],
            t,
            t + Duration::from_secs(900),
        )
        .unwrap()
    }
    fn published(d: &LaunchDelivery, id: u8, t: Instant) -> String {
        let output = d
            .body_context("https://parent.test")
            .unwrap()
            .prepare(SOURCE.into(), Sha256::digest(SOURCE.as_bytes()).into())
            .unwrap();
        let guard = d
            .reserve_body_pair(output, metadata(id, t), t + TICKET_TTL)
            .unwrap();
        let url = guard.descriptor().url().to_owned();
        guard
            .publish(&AtomicBool::new(false), t + TICKET_TTL)
            .unwrap();
        url::Url::parse(&url).unwrap().path().to_owned()
    }
    async fn get(d: &LaunchDelivery, path: &str, host: &str) -> Response {
        d.router()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(HOST, host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn wrong_host_reclaims_only_exact_pending_pair_and_spent_identity_is_retained() {
        let d = LaunchDelivery::isolated_fixture(
            RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap(),
        );
        let t = Instant::now();
        let old = published(&d, 1, t);
        let response = get(&d, &old, "artifact.test").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!to_bytes(response.into_body(), DELIVERED_BYTES)
            .await
            .unwrap()
            .is_empty());
        assert!(d.body_mount_is_redeemed(&metadata(1, t)).unwrap());
        {
            let state = d.body.0.state.lock().unwrap();
            assert_eq!(state.html_bytes, 0);
            assert!(!state.entries[&[1; 32]].ticket_pending);
        }
        // Unknown, spent and legacy tickets must not retire the old record.
        assert_ne!(get(&d, &old, "wrong.test").await.status(), StatusCode::OK);
        let legacy_manifest = validate(SOURCE).unwrap();
        let legacy = d
            .issue_launch(SOURCE, &legacy_manifest, "legacy", None, "legacy-artifact")
            .unwrap();
        let legacy_path = url::Url::parse(&legacy.url).unwrap().path().to_owned();
        assert_eq!(
            get(&d, &legacy_path, "artifact.test").await.status(),
            StatusCode::OK
        );
        let new = published(&d, 2, t);
        {
            let state = d.body.0.state.lock().unwrap();
            assert_eq!(state.entries.len(), 2);
            assert!(state.html_bytes > 0);
        }
        assert_ne!(get(&d, &new, "wrong.test").await.status(), StatusCode::OK);
        {
            let state = d.body.0.state.lock().unwrap();
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.html_bytes, 0);
            assert!(state.entries.contains_key(&[1; 32]));
        }
        assert_ne!(
            get(&d, &new, "artifact.test").await.status(),
            StatusCode::OK
        );
        assert!(!d.body_mount_is_redeemed(&metadata(2, t)).unwrap());
        assert!(d.body_mount_is_redeemed(&metadata(1, t)).unwrap());
    }
}
