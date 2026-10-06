//! Bounded instance sample custody and structural composite redemption.
//! These markers describe delivery publication, never database authority.
use super::*;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{MutexGuard, TryLockError};

const RESERVED: u8 = 0;
const PUBLISHED: u8 = 1;
const INVALID: u8 = 2;
const RECORD_BYTES: usize = 512;
const META_BYTES: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SampleFailure {
    Busy,
    Closed,
    Invalid,
    Expired,
}
#[derive(Clone)]
#[doc(hidden)]
pub struct SamplePublicationMarker(Arc<AtomicU8>);
impl SamplePublicationMarker {
    pub fn is_published(&self) -> bool {
        self.0.load(Ordering::SeqCst) == PUBLISHED
    }
    pub fn is_invalid(&self) -> bool {
        self.0.load(Ordering::SeqCst) == INVALID
    }
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn invalidate_unpublished(&self) {
        let _ = self
            .0
            .compare_exchange(RESERVED, INVALID, Ordering::SeqCst, Ordering::SeqCst);
    }
}
struct SampleEntry {
    marker: SamplePublicationMarker,
    expires: Instant,
    principal: String,
    ticket: Option<Ticket>,
}
pub(super) struct SampleStore {
    entries: HashMap<[u8; 32], SampleEntry>,
    bytes: usize,
    owner: Arc<body_delivery::BodyStore>,
}
impl SampleStore {
    pub(super) fn new(owner: Arc<body_delivery::BodyStore>) -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            owner,
        }
    }
    fn closed(&self) -> bool {
        self.owner.closed.load(Ordering::SeqCst)
    }
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| {
            if e.expires <= now || e.marker.is_invalid() {
                if let Some(t) = e.ticket.take() {
                    self.bytes -= t.html.len();
                }
            }
            e.expires > now
        });
    }
    fn contains(&self, id: &[u8; 32]) -> bool {
        self.entries.contains_key(id)
    }
}
#[doc(hidden)]
pub struct SampleTicketReservation {
    store: Arc<Mutex<SampleStore>>,
    id: [u8; 32],
    marker: SamplePublicationMarker,
    descriptor: Launch,
    expires: Instant,
}
impl Drop for SampleTicketReservation {
    fn drop(&mut self) {
        self.marker.invalidate_unpublished();
        if self.marker.is_invalid() {
            if let Ok(mut store) = self.store.try_lock() {
                store.prune(Instant::now());
            }
        }
    }
}
#[doc(hidden)]
pub struct SamplePublicationLease<'a> {
    store: MutexGuard<'a, SampleStore>,
    id: [u8; 32],
    marker: &'a SamplePublicationMarker,
}
impl SampleTicketReservation {
    pub fn descriptor(&self) -> &Launch {
        &self.descriptor
    }
    pub(super) fn original_ticket_deadline(&self) -> Instant {
        self.expires
    }
    pub fn publication_marker(&self) -> SamplePublicationMarker {
        self.marker.clone()
    }
    pub fn try_lock_for_publication(
        &self,
        original_deadline: Instant,
    ) -> std::result::Result<SamplePublicationLease<'_>, SampleFailure> {
        let store = self.store.try_lock().map_err(sample_lock_failure)?;
        if store.closed() {
            return Err(SampleFailure::Closed);
        }
        let e = store.entries.get(&self.id).ok_or(SampleFailure::Invalid)?;
        if !e.marker.same_owner(&self.marker)
            || e.marker.0.load(Ordering::SeqCst) != RESERVED
            || e.ticket.is_none()
        {
            return Err(SampleFailure::Invalid);
        }
        if Instant::now() >= original_deadline || Instant::now() >= e.expires {
            return Err(SampleFailure::Expired);
        }
        Ok(SamplePublicationLease {
            store,
            id: self.id,
            marker: &self.marker,
        })
    }
}
impl SamplePublicationLease<'_> {
    pub fn commit(self, original_deadline: Instant) -> std::result::Result<(), SampleFailure> {
        if self.store.closed() {
            return Err(SampleFailure::Closed);
        }
        let e = self
            .store
            .entries
            .get(&self.id)
            .ok_or(SampleFailure::Invalid)?;
        if Instant::now() >= original_deadline || Instant::now() >= e.expires {
            return Err(SampleFailure::Expired);
        }
        if e.ticket.is_none() || !e.marker.same_owner(self.marker) {
            return Err(SampleFailure::Invalid);
        }
        self.marker
            .0
            .compare_exchange(RESERVED, PUBLISHED, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| SampleFailure::Invalid)?;
        Ok(())
    }
}
fn sample_lock_failure<T>(e: TryLockError<T>) -> SampleFailure {
    match e {
        TryLockError::WouldBlock => SampleFailure::Busy,
        TryLockError::Poisoned(_) => SampleFailure::Closed,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum StoreUnavailable {
    Busy,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum LaunchRefusal {
    Unpublished,
    Invalid,
    Spent,
    Expired,
    WrongHost,
    Collision,
}
#[doc(hidden)]
pub enum LaunchOutcome {
    Delivered(Response),
    Refused(LaunchRefusal),
}
#[doc(hidden)]
pub enum TicketLookup {
    Unknown,
    Matched(LaunchOutcome),
    Unavailable(StoreUnavailable),
}
impl TicketLookup {
    pub(super) fn into_response(self, headers: &HeaderMap, config: &RuntimeConfig) -> Response {
        match self {
            Self::Matched(LaunchOutcome::Delivered(r)) => r,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            Self::Matched(LaunchOutcome::Refused(LaunchRefusal::WrongHost)) => {
                StatusCode::NOT_FOUND.into_response()
            }
            Self::Matched(LaunchOutcome::Refused(LaunchRefusal::Collision)) => {
                StatusCode::GONE.into_response()
            }
            Self::Matched(LaunchOutcome::Refused(_)) => StatusCode::GONE.into_response(),
            Self::Unknown if !host_matches_origin(headers, &config.artifact_origin) => {
                StatusCode::NOT_FOUND.into_response()
            }
            Self::Unknown => StatusCode::GONE.into_response(),
        }
    }
}
pub(super) fn decode_ticket(token: &str) -> Option<[u8; 32]> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut id = [0; 32];
    hex::decode_to_slice(token, &mut id).ok()?;
    Some(id)
}
fn unavailable<T>(e: TryLockError<T>) -> TicketLookup {
    TicketLookup::Unavailable(match e {
        TryLockError::WouldBlock => StoreUnavailable::Busy,
        TryLockError::Poisoned(_) => StoreUnavailable::Closed,
    })
}
impl LaunchDelivery {
    pub fn reserve_sample_launch(
        &self,
        source: &str,
        manifest: &Manifest,
        principal: &str,
        database: Option<&str>,
        artifact_id: &str,
    ) -> std::result::Result<SampleTicketReservation, SampleFailure> {
        self.reserve_sample_with_clock(source, manifest, principal, database, artifact_id, None)
    }
    fn reserve_sample_with_clock(
        &self,
        source: &str,
        manifest: &Manifest,
        principal: &str,
        database: Option<&str>,
        artifact_id: &str,
        fixture_now: Option<Instant>,
    ) -> std::result::Result<SampleTicketReservation, SampleFailure> {
        if principal.trim().is_empty()
            || principal.len() > 256
            || artifact_id.len() > 256
            || database.is_some_and(|s| s.len() > 256)
        {
            return Err(SampleFailure::Invalid);
        }
        let parent = self
            .config
            .resolve_parent_origin(None)
            .map_err(|_| SampleFailure::Invalid)?;
        if parent.len() > 256
            || self.config.artifact_origin.len() > 256
            || manifest.body_digest.len() > 64
        {
            return Err(SampleFailure::Invalid);
        }
        let html = inject(source, &parent).map_err(|_| SampleFailure::Invalid)?;
        let mut id = [0; 32];
        rand::rng().fill_bytes(&mut id);
        let now = fixture_now.unwrap_or_else(Instant::now);
        let expires = now.checked_add(TICKET_TTL).ok_or(SampleFailure::Invalid)?;
        let descriptor = Launch {
            url: format!(
                "{}/artifact-runtime/v1/launch/{}",
                self.config.artifact_origin,
                hex::encode(id)
            ),
            expires_in_ms: TICKET_TTL.as_millis() as u64,
        };
        let marker = SamplePublicationMarker(Arc::new(AtomicU8::new(RESERVED)));
        let entry = SampleEntry {
            marker: marker.clone(),
            expires,
            principal: principal.into(),
            ticket: Some(Ticket {
                html,
                expires,
                principal: principal.into(),
                _issuance_database: database.map(str::to_string),
                _artifact_id: artifact_id.into(),
                _body_digest: manifest.body_digest.clone(),
                _adapter_revision: ADAPTER_REVISION,
                parent_origin: parent,
                attestation: None,
            }),
        };
        self.insert_sample(id, entry, descriptor, now)
    }
    fn insert_sample(
        &self,
        id: [u8; 32],
        entry: SampleEntry,
        descriptor: Launch,
        now: Instant,
    ) -> std::result::Result<SampleTicketReservation, SampleFailure> {
        let marker = entry.marker.clone();
        let expires = entry.expires;
        let mut store = self.tickets.try_lock().map_err(sample_lock_failure)?;
        if store.closed() {
            return Err(SampleFailure::Closed);
        }
        store.prune(now);
        if store.entries.contains_key(&id) {
            return Err(SampleFailure::Invalid);
        }
        if store.entries.len() >= LAUNCH_TICKET_MAX_COUNT
            || store
                .entries
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_mul(RECORD_BYTES))
                .is_none_or(|n| n > META_BYTES)
            || store
                .entries
                .values()
                .filter(|e| e.principal == entry.principal)
                .count()
                >= LAUNCH_TICKET_MAX_PER_PRINCIPAL
            || store
                .bytes
                .checked_add(entry.ticket.as_ref().map_or(0, |t| t.html.len()))
                .is_none_or(|n| n > LAUNCH_TICKET_MAX_BYTES)
        {
            return Err(SampleFailure::Busy);
        }
        let reservation = SampleTicketReservation {
            store: self.tickets.clone(),
            id,
            marker,
            descriptor,
            expires,
        };
        store.bytes += entry.ticket.as_ref().expect("new sample").html.len();
        store.entries.insert(id, entry);
        // Guard was armed before insertion, while the critical section is held.
        Ok(reservation)
    }
    #[cfg(test)]
    pub(super) fn sample_counts(&self) -> (usize, usize) {
        let store = self.tickets.lock().unwrap();
        (store.entries.len(), store.bytes)
    }
    pub fn lookup_launch(&self, token: &str, headers: &HeaderMap) -> TicketLookup {
        self.lookup_launch_at(token, headers, Instant::now())
    }
    pub(super) fn lookup_launch_at(
        &self,
        token: &str,
        headers: &HeaderMap,
        now: Instant,
    ) -> TicketLookup {
        // All occupancies are established BEFORE any lane consumes. No nested helpers.
        let mut legacy = match self.legacy_tickets().try_lock() {
            Ok(s) => s,
            Err(e) => return unavailable(e),
        };
        let mut sample = match self.tickets.try_lock() {
            Ok(s) => s,
            Err(e) => return unavailable(e),
        };
        let mut body = match self.body.0.state.try_lock() {
            Ok(s) => s,
            Err(e) => return unavailable(e),
        };
        if self.body.0.closed.load(Ordering::SeqCst) {
            return TicketLookup::Unavailable(StoreUnavailable::Closed);
        }
        let expired: Vec<_> = legacy
            .entries
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            remove_stored(&mut legacy, &k, |t| t.html.len());
        }
        sample.prune(now);
        body_delivery::prune(&mut body, now);
        let id = decode_ticket(token);
        let b = id.is_some_and(|id| body.has_ticket(&id));
        let s = id.is_some_and(|id| sample.contains(&id));
        let l = legacy.entries.contains_key(token);
        if usize::from(b) + usize::from(s) + usize::from(l) > 1 {
            return TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Collision));
        }
        if b {
            return self.redeem_body_in(&mut body, &id.unwrap(), headers, now);
        }
        if s {
            return self.redeem_sample_in(&mut sample, &id.unwrap(), headers, now);
        }
        if l {
            if !host_matches_origin(headers, &self.config.artifact_origin) {
                return TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::WrongHost));
            }
            let ticket = remove_stored(&mut legacy, token, |t| t.html.len())
                .expect("probed under same lock");
            let expires = ticket.expires;
            let response = ticket_response(ticket);
            if Instant::now() >= expires {
                return TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Expired));
            }
            return TicketLookup::Matched(LaunchOutcome::Delivered(response));
        }
        TicketLookup::Unknown
    }
    fn redeem_sample_in(
        &self,
        store: &mut SampleStore,
        id: &[u8; 32],
        headers: &HeaderMap,
        now: Instant,
    ) -> TicketLookup {
        let e = store.entries.get_mut(id).expect("probed under same lock");
        let refuse = |r| TicketLookup::Matched(LaunchOutcome::Refused(r));
        if !host_matches_origin(headers, &self.config.artifact_origin) {
            return refuse(LaunchRefusal::WrongHost);
        }
        if e.marker.is_invalid() {
            return refuse(LaunchRefusal::Invalid);
        }
        if !e.marker.is_published() {
            return refuse(LaunchRefusal::Unpublished);
        }
        let Some(ticket) = e.ticket.take() else {
            return refuse(LaunchRefusal::Spent);
        };
        store.bytes -= ticket.html.len();
        let response = ticket_response(ticket);
        if now >= e.expires || Instant::now() >= e.expires {
            return refuse(LaunchRefusal::Expired);
        }
        TicketLookup::Matched(LaunchOutcome::Delivered(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str =
        "<!doctype html><html lang=\"en\"><head><title>Owned</title></head><body>Owned</body></html>";
    fn fixture() -> LaunchDelivery {
        LaunchDelivery::isolated_fixture(
            RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap(),
        )
    }
    fn headers(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_str(host).unwrap());
        h
    }
    fn reserve(d: &LaunchDelivery, p: &str) -> SampleTicketReservation {
        d.reserve_sample_launch(SOURCE, &validate(SOURCE).unwrap(), p, None, "artifact")
            .unwrap()
    }
    fn token(p: &SampleTicketReservation) -> String {
        p.descriptor.url.rsplit('/').next().unwrap().into()
    }
    fn publish(p: &SampleTicketReservation) {
        let deadline = Instant::now() + Duration::from_secs(5);
        p.try_lock_for_publication(deadline)
            .unwrap()
            .commit(deadline)
            .unwrap();
    }
    fn body(d: &LaunchDelivery, id: u8) -> (BodyMountMeta, String) {
        let now = Instant::now();
        let meta = BodyMountMeta::checked(
            [id; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            now,
            now + Duration::from_secs(900),
        )
        .unwrap();
        let prepared = d
            .body_context("https://parent.test")
            .unwrap()
            .prepare(
                SOURCE.into(),
                hex::decode(validate(SOURCE).unwrap().body_digest)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        let reservation = d
            .reserve_body_pair(
                prepared,
                BodyMountMeta::checked(
                    [id; 32],
                    [1; 32],
                    [2; 32],
                    [3; 32],
                    now,
                    now + Duration::from_secs(900),
                )
                .unwrap(),
                now + TICKET_TTL,
            )
            .unwrap();
        let ticket = reservation
            .descriptor()
            .url()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        reservation
            .publish(
                &std::sync::atomic::AtomicBool::new(false),
                now + Duration::from_secs(5),
            )
            .unwrap();
        (meta, ticket)
    }
    #[test]
    fn sample_reserved_published_spent_and_original_expiry_are_structural() {
        let d = fixture();
        let p = reserve(&d, "viewer");
        let t = token(&p);
        let h = headers("artifact.test");
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Unpublished))
        ));
        publish(&p);
        assert!(matches!(
            d.lookup_launch(&t, &headers("wrong.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::WrongHost))
        ));
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
        assert_eq!(d.sample_counts(), (1, 0));
        drop(p);
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Spent))
        ));
        let expires = d.tickets.lock().unwrap().entries[&decode_ticket(&t).unwrap()].expires;
        assert!(matches!(
            d.lookup_launch_at(&t, &h, expires),
            TicketLookup::Unknown
        ));
        assert_eq!(d.sample_counts(), (0, 0));
    }
    #[test]
    fn sample_drop_is_nonblocking_invalid_and_charged_until_sweep() {
        let d = fixture();
        let old = reserve(&d, "older");
        publish(&old);
        let p = reserve(&d, "new");
        let t = token(&p);
        let marker = p.publication_marker();
        let held = d.tickets.lock().unwrap();
        let before = held.bytes;
        drop(p);
        assert!(marker.is_invalid());
        assert_eq!(held.bytes, before);
        assert_eq!(held.entries.len(), 2);
        drop(held);
        assert!(matches!(
            d.lookup_launch(&t, &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Invalid))
        ));
        assert!(d.sample_counts().1 < before);
        assert!(matches!(
            d.lookup_launch(&token(&old), &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
        let lock = old.store.lock().unwrap();
        assert_eq!(lock.bytes, 0);
        assert_eq!(lock.entries.len(), 2);
    }
    #[test]
    fn sample_slot_and_principal_caps_count_tombstones_without_eviction() {
        let d = fixture();
        let m = validate(SOURCE).unwrap();
        let mut tokens = Vec::new();
        for group in 0..4 {
            for _ in 0..32 {
                let p = reserve(&d, &format!("principal-{group}"));
                tokens.push(token(&p));
                drop(p);
            }
            assert!(matches!(
                d.reserve_sample_launch(
                    SOURCE,
                    &m,
                    &format!("principal-{group}"),
                    None,
                    "artifact"
                ),
                Err(SampleFailure::Busy)
            ));
        }
        assert_eq!(d.sample_counts(), (128, 0));
        assert!(matches!(
            d.reserve_sample_launch(SOURCE, &m, "other", None, "artifact"),
            Err(SampleFailure::Busy)
        ));
        let st = d.tickets.lock().unwrap();
        assert_eq!(st.entries.len() * RECORD_BYTES, META_BYTES);
        let expiry = st.entries.values().map(|e| e.expires).max().unwrap();
        drop(st);
        for t in tokens {
            assert!(matches!(
                d.lookup_launch_at(&t, &headers("artifact.test"), expiry),
                TicketLookup::Unknown
            ));
        }
        assert_eq!(d.sample_counts(), (0, 0));
        assert!(d
            .reserve_sample_launch(SOURCE, &m, "other", None, "artifact")
            .is_ok());
    }
    #[test]
    fn body_spent_identity_survives_replay_wrong_host_and_exact_retirement() {
        let d = fixture();
        let (meta, t) = body(&d, 9);
        let h = headers("artifact.test");
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Spent))
        ));
        assert!(matches!(
            d.lookup_launch(&t, &headers("wrong.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::WrongHost))
        ));
        assert!(d.body_mount_is_redeemed(&meta).unwrap());
        d.retire_body_mount(&meta).unwrap();
        assert!(matches!(d.lookup_launch(&t, &h), TicketLookup::Unknown));
    }
    #[test]
    fn all_three_occupancy_collision_is_terminal_before_consume_or_host_reclaim() {
        let d = fixture();
        let (meta, b) = body(&d, 8);
        let p = reserve(&d, "sample");
        publish(&p);
        let original = p.id;
        {
            let mut s = d.tickets.lock().unwrap();
            let e = s.entries.remove(&original).unwrap();
            s.entries.insert(decode_ticket(&b).unwrap(), e);
        }
        assert!(matches!(
            d.lookup_launch(&b, &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Collision))
        ));
        assert!(!d.body_mount_is_redeemed(&meta).unwrap());
        let legacy = issue_launch_in_store(
            SOURCE,
            &validate(SOURCE).unwrap(),
            "legacy",
            None,
            "artifact",
            &d.config,
            None,
            None,
            d.legacy_tickets(),
            None,
        )
        .unwrap();
        {
            let mut g = d.legacy_tickets().lock().unwrap();
            let e = remove_stored(&mut g, legacy.url.rsplit('/').next().unwrap(), |t| {
                t.html.len()
            })
            .unwrap();
            g.bytes += e.html.len();
            g.oldest.push_back(b.clone());
            g.entries.insert(b.clone(), e);
        }
        for host in ["artifact.test", "wrong.test"] {
            assert!(matches!(
                d.lookup_launch(&b, &headers(host)),
                TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Collision))
            ));
        }
        assert!(!d.body_mount_is_redeemed(&meta).unwrap());
        assert!(d.sample_counts().1 > 0);
        // Body+legacy and sample+legacy occupancies also refuse before any consume.
        let entry = d
            .tickets
            .lock()
            .unwrap()
            .entries
            .remove(&decode_ticket(&b).unwrap())
            .unwrap();
        assert!(matches!(
            d.lookup_launch(&b, &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Collision))
        ));
        d.tickets
            .lock()
            .unwrap()
            .entries
            .insert(decode_ticket(&b).unwrap(), entry);
        // Retiring the body now leaves the sample+legacy collision.
        d.retire_body_mount(&meta).unwrap();
        assert!(matches!(
            d.lookup_launch(&b, &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::Collision))
        ));
        {
            let mut g = d.legacy_tickets().lock().unwrap();
            assert!(remove_stored(&mut g, &b, |t| t.html.len()).is_some());
        }
        {
            let mut s = d.tickets.lock().unwrap();
            let e = s.entries.remove(&decode_ticket(&b).unwrap()).unwrap();
            s.entries.insert(original, e);
        }
        assert!(matches!(
            d.lookup_launch(&b, &headers("artifact.test")),
            TicketLookup::Unknown
        ));
        assert!(matches!(
            d.lookup_launch(&token(&p), &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
    }
    #[test]
    fn each_busy_store_never_falls_back_and_closed_owner_cannot_publish() {
        let d = fixture();
        {
            let unrelated = fixture();
            let pending = reserve(&unrelated, "unrelated-global-store");
            publish(&pending);
            let normal = LaunchDelivery::new((*d.config).clone());
            let _global = tickets().lock().unwrap();
            let t = token(&pending);
            let h = headers("artifact.test");
            assert!(matches!(
                normal.lookup_launch(&t, &h),
                TicketLookup::Unavailable(StoreUnavailable::Busy)
            ));
            assert!(matches!(
                unrelated.lookup_launch(&t, &h),
                TicketLookup::Matched(LaunchOutcome::Delivered(_))
            ));
        }
        let p = reserve(&d, "viewer");
        publish(&p);
        let t = token(&p);
        let h = headers("artifact.test");
        {
            let sibling = fixture();
            let unrelated = reserve(&sibling, "unrelated");
            publish(&unrelated);
            let _g = d.legacy_tickets().lock().unwrap();
            assert!(matches!(
                d.clone().lookup_launch(&t, &h),
                TicketLookup::Unavailable(StoreUnavailable::Busy)
            ));
            assert!(matches!(
                sibling.lookup_launch(&token(&unrelated), &h),
                TicketLookup::Matched(LaunchOutcome::Delivered(_))
            ));
        }
        {
            let _g = d.tickets.lock().unwrap();
            assert!(matches!(
                d.lookup_launch(&t, &h),
                TicketLookup::Unavailable(StoreUnavailable::Busy)
            ));
        }
        {
            let _g = d.body.0.state.lock().unwrap();
            assert!(matches!(
                d.lookup_launch(&t, &h),
                TicketLookup::Unavailable(StoreUnavailable::Busy)
            ));
        }
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
        let pending = reserve(&d, "pending");
        drop(d);
        assert!(matches!(
            pending.try_lock_for_publication(Instant::now() + Duration::from_secs(5)),
            Err(SampleFailure::Closed)
        ));
    }
    #[test]
    fn local_collision_does_not_overwrite_and_unknown_reaches_legacy_only() {
        let d = fixture();
        let p = reserve(&d, "viewer");
        publish(&p);
        let e = SampleEntry {
            marker: SamplePublicationMarker(Arc::new(AtomicU8::new(RESERVED))),
            expires: Instant::now() + TICKET_TTL,
            principal: "other".into(),
            ticket: None,
        };
        assert!(matches!(
            d.insert_sample(
                p.id,
                e,
                Launch {
                    url: "unused".into(),
                    expires_in_ms: 30000
                },
                Instant::now()
            ),
            Err(SampleFailure::Invalid)
        ));
        let legacy = issue_launch_in_store(
            SOURCE,
            &validate(SOURCE).unwrap(),
            "legacy",
            None,
            "artifact",
            &d.config,
            None,
            None,
            d.legacy_tickets(),
            None,
        )
        .unwrap();
        let t = legacy.url.rsplit('/').next().unwrap();
        assert!(matches!(
            d.lookup_launch(t, &headers("wrong.test")),
            TicketLookup::Matched(LaunchOutcome::Refused(LaunchRefusal::WrongHost))
        ));
        assert!(matches!(
            d.lookup_launch(t, &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
        assert!(matches!(
            d.lookup_launch(t, &headers("artifact.test")),
            TicketLookup::Unknown
        ));
        assert!(matches!(
            d.lookup_launch(&token(&p), &headers("artifact.test")),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
    }
    #[test]
    fn actual_html_charge_refuses_over_cap_without_eviction_and_metadata_is_bounded() {
        let d = fixture();
        let m = validate(SOURCE).unwrap();
        for principal in ["", "  ", &"é".repeat(129)] {
            assert!(matches!(
                d.reserve_sample_launch(SOURCE, &m, principal, None, "a"),
                Err(SampleFailure::Invalid)
            ));
        }
        assert_eq!(d.sample_counts(), (0, 0));
        // Exercise actual retained String bytes/cap, independently of parser projection.
        let mut held = Vec::new();
        for n in 0..8 {
            let id = [n; 32];
            let expires = Instant::now() + TICKET_TTL;
            let entry = SampleEntry {
                marker: SamplePublicationMarker(Arc::new(AtomicU8::new(RESERVED))),
                expires,
                principal: "byte-cap".into(),
                ticket: Some(Ticket {
                    html: "x".repeat(8 * 1024 * 1024),
                    expires,
                    principal: "byte-cap".into(),
                    _issuance_database: None,
                    _artifact_id: "a".into(),
                    _body_digest: m.body_digest.clone(),
                    _adapter_revision: ADAPTER_REVISION,
                    parent_origin: "https://parent.test".into(),
                    attestation: None,
                }),
            };
            held.push(
                d.insert_sample(
                    id,
                    entry,
                    Launch {
                        url: hex::encode(id),
                        expires_in_ms: 30000,
                    },
                    Instant::now(),
                )
                .unwrap(),
            );
        }
        assert_eq!(d.sample_counts(), (8, LAUNCH_TICKET_MAX_BYTES));
        assert!(matches!(
            d.reserve_sample_launch(SOURCE, &m, "new", None, "a"),
            Err(SampleFailure::Busy)
        ));
        assert_eq!(d.sample_counts(), (8, LAUNCH_TICKET_MAX_BYTES));
        drop(held);
        assert_eq!(d.sample_counts(), (8, 0));
        assert!(d
            .reserve_sample_launch(SOURCE, &m, "new", None, "a")
            .is_ok());
    }
    #[test]
    fn each_poisoned_store_is_closed_and_never_consumes_downstream() {
        let d = fixture();
        let p = reserve(&d, "viewer");
        publish(&p);
        let t = token(&p);
        let h = headers("artifact.test");
        // Isolated poison; clear immediately after observation, including the isolated legacy fixture lock.
        for lane in 0..3 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match lane {
                0 => {
                    let _lock = d.legacy_tickets().lock().unwrap();
                    panic!("isolated legacy mutex poison");
                }
                1 => {
                    let _lock = d.tickets.lock().unwrap();
                    panic!("isolated sample mutex poison");
                }
                _ => {
                    let _lock = d.body.0.state.lock().unwrap();
                    panic!("isolated body mutex poison");
                }
            }));
            assert!(result.is_err());
            let lookup = d.lookup_launch(&t, &h);
            match lane {
                0 => d.legacy_tickets().clear_poison(),
                1 => d.tickets.clear_poison(),
                _ => d.body.0.state.clear_poison(),
            }
            assert!(matches!(
                lookup,
                TicketLookup::Unavailable(StoreUnavailable::Closed)
            ));
            assert!(d.tickets.lock().unwrap().entries[&p.id].ticket.is_some());
        }
        assert!(matches!(
            d.lookup_launch(&t, &h),
            TicketLookup::Matched(LaunchOutcome::Delivered(_))
        ));
    }
}
