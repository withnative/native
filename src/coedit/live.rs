//! Live-session service for `session.body.v1` under the single-writer rule.
//!
//! One process-wide service, keyed by the database's storage identity (its
//! canonical file path, see [`session_key`]), so every writer in this process
//! sees the same live doc for a record no matter which [`Db`] handle it holds:
//! hosting's websocket, MCP `update_record`, and app Save all meet here even
//! when the hosting router has re-opened (or LRU-evicted) the handle.
//!
//! While a session is open on a record it is the only writer of that body.
//! Every other body write is routed in as a minimal diff authored by a
//! server-side client id (never a peer's lease), attributed to the caller,
//! broadcast to peers, and followed by a version cut with the caller's reason
//! (see [`route_body_write`]).
//!
//! Versions are ordinary `record.updated` events carrying the live body plus
//! `contributors[]` and `session` (see `version_metadata`). They are cut on
//! idle ([`IDLE_VERSION_AFTER`] with no ops since the last version), when the
//! last editor leaves, on explicit [`SessionPeer::version`], and after every
//! routed-in write. Leaving with unsaved edits cuts a version; it never
//! refuses.
//!
//! Lock order, everywhere: storage-policy lease → database open gate →
//! session ops lock → SQLite write transaction. Peer ops take only the ops
//! lock. Enrolled custody storage is refused for now.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex, Weak};
use std::time::Duration;

use sqlx::Row;
use tokio::sync::{broadcast, Mutex as AsyncMutex, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};
use tokio::time::Instant;
use yrs::updates::encoder::Encode;

use super::refusal::{RefusalCode, Refused};
use super::registry::{
    AcknowledgedContributor, AppAttribution, OpenParams, PeerId, PeerKind, PreparedUpdate,
    SessionId, SessionRegistry,
};

use super::span_map::SpanMap;
use crate::authorization::Capability;
use crate::db::Db;
use crate::mcp::Caller;

/// The contributor's own record of an app, taken from the host-asserted
/// attribution the engine admitted for the call.
impl From<&crate::mcp::app_attribution::AppAttribution> for AppAttribution {
    fn from(app: &crate::mcp::app_attribution::AppAttribution) -> Self {
        Self {
            package: app.package.clone(),
            version: app.version.clone(),
            install_event_id: app.install_event_id.clone(),
        }
    }
}

/// A version is cut once a session has had no accepted ops for this long
/// since its last version.
pub const IDLE_VERSION_AFTER: Duration = Duration::from_secs(30);

/// Write admission for version cuts (see [`set_write_admission`]): `None`
/// refuses the cut; `Some(guard)` admits it, and the guard is held for the
/// whole cut, from before its transaction begins until after it commits (or
/// fails), then dropped.
pub type WriteAdmission = Arc<dyn Fn(&Db) -> Option<Box<dyn Send>> + Send + Sync>;

// Separate from the fleet version-cut hook: acknowledged dirty text retains
// its database lease until a committed cut, so an online scoped drain cannot
// report completion while accepted edits still exist only in memory.
static DIRTY_WRITE_ADMISSION: LazyLock<std::sync::RwLock<Option<WriteAdmission>>> =
    LazyLock::new(|| std::sync::RwLock::new(None));

pub fn set_dirty_write_admission(hook: Option<WriteAdmission>) {
    *DIRTY_WRITE_ADMISSION
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
}

fn admit_dirty_write(db: &Db) -> Result<Option<Box<dyn Send>>, Refused> {
    match DIRTY_WRITE_ADMISSION
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        None => Ok(None),
        Some(hook) => hook(db)
            .map(Some)
            .ok_or_else(|| Refused::new(RefusalCode::Unavailable, WRITES_FROZEN)),
    }
}

static WRITE_ADMISSION: LazyLock<std::sync::RwLock<Option<WriteAdmission>>> =
    LazyLock::new(|| std::sync::RwLock::new(None));

/// Refusal detail for a cut held back by the write admission hook.
const WRITES_FROZEN: &str = "writes are frozen; the version will be retried";

/// Install (or clear, with `None`) the hook every version cut consults
/// before writing: hosting's deployment freeze barrier. The guard it returns
/// spans the cut's transaction through commit, so a freeze that waits for
/// outstanding guards cannot complete underneath a cut. Cuts the hook
/// refuses keep the doc dirty and are retried on the next idle or grace
/// tick; a freeze never counts as a failed cut and never drops unsaved text.
/// On [`shutdown`] a refused cut is skipped and the unsaved text is written
/// to the error log for recovery (peers also resume their pending edits
/// after the restart). Routed writes (`update_record` and the other body
/// writers) are ordinary requests, already inside hosting's barrier, and
/// their own transaction is not consulted here; but each first versions the
/// session's unsaved edits ("saved before a routed write"), and that cut is
/// consulted. A routed write that arrives with a freeze pending and unsaved
/// edits is refused as retryable ("still saving its last edits; retry
/// shortly") and succeeds once the freeze lifts.
pub fn set_write_admission(hook: Option<WriteAdmission>) {
    *WRITE_ADMISSION
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
}

/// Ask the hook to admit a cut. `Err` = refused (frozen); `Ok(guard)` must
/// be held until the cut has committed or failed (`Ok(None)` = no hook).
fn admit_write(db: &Db) -> Result<Option<Box<dyn Send>>, Refused> {
    let hook = WRITE_ADMISSION
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    match hook {
        None => Ok(None),
        Some(admit) => admit(db)
            .map(Some)
            .ok_or_else(|| Refused::new(RefusalCode::Unavailable, WRITES_FROZEN)),
    }
}

/// Set by [`begin_shutdown`]: from then on `open` refuses with
/// `unavailable`.
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Databases shut down in tests (the process-wide flag would leak into
/// other tests).
#[cfg(test)]
static TEST_SHUT_DOWN: LazyLock<StdMutex<std::collections::HashSet<PathBuf>>> =
    LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));

fn shutting_down(db: &Db) -> bool {
    #[cfg(test)]
    if lock(&TEST_SHUT_DOWN).contains(db.live_session_key()) {
        return true;
    }
    let _ = db;
    SHUTTING_DOWN.load(Ordering::SeqCst)
}

/// Stop admitting new sessions: every later [`open`] refuses with
/// `unavailable`. [`shutdown`] calls this first; hosting may call it earlier
/// (e.g. when it stops accepting connections).
pub fn begin_shutdown() {
    SHUTTING_DOWN.store(true, Ordering::SeqCst);
}

fn is_frozen(refused: &Refused) -> bool {
    refused.code == RefusalCode::Unavailable && refused.detail == WRITES_FROZEN
}

/// Requested versions ([`SessionPeer::version`]) are cut at most once per
/// this interval per session; requests inside the window coalesce into one
/// cut at the next allowed slot (contract M5). Idle, leave and routed
/// (agent/app) versions are exempt.
pub const REQUESTED_VERSION_INTERVAL: Duration = Duration::from_secs(10);

/// After the last peer leaves (and its version is cut), the doc stays in
/// memory this long so a resume or new open continues the same doc and the
/// clients' item ids stay valid. With no peers attached the single-writer rule
/// does not apply: an ordinary body write during grace discards the doc.
pub const GRACE_AFTER_LAST_LEAVE: Duration = Duration::from_secs(120);

/// Capacity of each session's event channel. A subscriber that lags past it
/// receives `RecvError::Lagged` and must resync its peer with
/// [`SessionPeer::sync`] (a fresh full state from an empty state vector).
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Which access a peer joins with. Edit requires Edit on the record, View
/// requires View.
pub type SessionMode = PeerKind;

/// What a caller asks for when opening a session.
#[derive(Debug, Clone)]
pub struct OpenRequest {
    pub record_id: String,
    pub mode: SessionMode,
    /// The opaque `peer` from this client's previous `session.opened`. If the
    /// session (or its grace doc) is still in memory and that peer belonged
    /// to the same principal, the same peer token and `doc_client_ids` are
    /// re-issued and the old handle is superseded; otherwise this opens
    /// normally with a fresh peer.
    pub resume_peer: Option<PeerId>,
}

/// The committed version a fresh session was seeded from (or that a joiner's
/// live doc last versioned to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseVersion {
    /// Opaque version token (`rec:<content seq>`, as `get_record` reports).
    pub version: String,
    /// sha256 of the committed body, as `get_record`'s `body_digest`.
    pub body_sha256: String,
    /// Which persisted body revision this is, and which doc items made it up.
    pub proof: CutProof,
}

/// The identity of a persisted body revision and, when it can be shown, of the
/// live-doc items whose text it is.
///
/// - `body_event_id` and `body_event_seq` name the record's latest
///   body-carrying event (`record_body::BODY_CARRYING_EVENT_SQL`), the
///   revision a source pin names, from one row. They are present together or
///   not at all. `rec:<MAX(seq)>` in [`BaseVersion::version`] is not this: a
///   metadata-only event moves it, and an annotation's `source_event_seq`
///   records that `MAX`, so only `body_event_seq` is a body sequence.
/// - `snapshot` is the Yjs `SnapshotV1` (delete set, then state vector) of the
///   doc state whose text hashes to the revision's body. It is present only
///   when that state was read together with the body and the hash matched the
///   stored revision, and it is within `MAX_CUT_SNAPSHOT_BYTES`. Over the cap
///   the event identity stays and the snapshot is absent.
///
/// `None` means unproved, never "unchanged". Bytes alone do not identify
/// items: an identical re-insertion has the same hash and different items.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CutProof {
    pub body_event_id: Option<String>,
    pub body_event_seq: Option<i64>,
    pub snapshot: Option<Arc<[u8]>>,
}

/// A body-carrying event as read from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BodyEvent {
    pub(super) id: String,
    pub(super) seq: i64,
}

impl BodyEvent {
    /// A missing id, a missing sequence or a non-positive sequence is no
    /// identity at all: the proof stays unproved rather than half-named.
    pub(super) fn from_row(id: Option<String>, seq: Option<i64>) -> Option<Self> {
        match (id, seq) {
            (Some(id), Some(seq)) if !id.is_empty() && seq > 0 => Some(Self { id, seq }),
            _ => None,
        }
    }
}

impl CutProof {
    fn named(event: Option<&BodyEvent>) -> Self {
        Self {
            body_event_id: event.map(|event| event.id.clone()),
            body_event_seq: event.map(|event| event.seq),
            snapshot: None,
        }
    }
}

/// Limits a client should respect; the server enforces them regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_update_bytes: usize,
    pub max_edit_peers: usize,
    pub max_view_peers: usize,
}

/// Everything `session.opened` needs.
#[derive(Debug, Clone)]
pub struct Opened {
    pub session: SessionId,
    pub peer: PeerId,
    /// Yjs client ids this peer may author with. Empty for view peers.
    pub doc_client_ids: Vec<u32>,
    /// Full live state (Yjs sync step 2, update encoding v1).
    pub sync: Vec<u8>,
    pub base: BaseVersion,
    pub limits: Limits,
    /// Whether `resume_peer` was honoured (same peer token and client ids).
    pub resumed: bool,
}

/// Successful [`SessionPeer::apply`]: the `session.ack` payload.
#[derive(Debug, Clone)]
pub struct PeerAck {
    pub update_id: String,
    /// Live state vector after the update (encoded v1).
    pub clock: Vec<u8>,
}

/// Who authored a live change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorKind {
    Human,
    Agent,
    App,
}

/// Attribution of a live change, for `session.remote.from`. `principal` is
/// the portable account credential; transports decide what to disclose
/// (`person_ref` follows the canvas presence visibility rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    pub contributor: AcknowledgedContributor,
    pub kind: AuthorKind,
}

/// A committed version, the `session.versioned` payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Versioned {
    pub session: SessionId,
    /// Version token after the cut (`rec:<content seq>`).
    pub version: String,
    pub body_sha256: String,
    pub event_id: String,
    pub contributors: Vec<AcknowledgedContributor>,
    pub reason: String,
    /// Body revision and doc snapshot this version cut (see [`CutProof`]).
    pub proof: CutProof,
    /// The record's `updated_at` as read inside the cut's own write
    /// transaction, before the version was appended and again before commit,
    /// so nothing can commit between the two. `None` for versions not cut
    /// through that transaction (a routed write's own version).
    pub(crate) updated_at_around_cut: Option<(String, String)>,
}

/// Why a peer (or the whole session) closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    Left,
    AccessLost,
    Idle,
    ServerShutdown,
    Superseded,
}

impl CloseReason {
    /// Wire spelling for `session.closed.reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::AccessLost => "access_lost",
            Self::Idle => "idle",
            Self::ServerShutdown => "server_shutdown",
            Self::Superseded => "superseded",
        }
    }
}

/// One event on a session's broadcast channel.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// An accepted update. `origin` is the peer that sent it, or `None` for a
    /// server-side routed write; a transport must not echo a peer's own
    /// update back to it.
    Remote {
        update: Arc<Vec<u8>>,
        origin: Option<PeerId>,
        from: Author,
    },
    Versioned(Versioned),
    /// `peer: Some(p)` closes only that peer (e.g. access lost); `None`
    /// closes the session for everyone.
    Closed {
        peer: Option<PeerId>,
        reason: CloseReason,
    },
}

/// One joined peer. Dropping it without [`SessionPeer::leave`] leaves the
/// session in the background, with the same version cut as an explicit leave,
/// so a crashed connection loses no edits. A handle superseded by a resume
/// refuses every call with `undeclared_session`, and its `leave` is a no-op.
pub struct SessionPeer {
    inner: Arc<PeerInner>,
}

struct PeerInner {
    session: Arc<LiveSession>,
    session_id: SessionId,
    peer: PeerId,
    mode: SessionMode,
    incarnation: u64,
    left: AtomicBool,
}

impl std::fmt::Debug for SessionPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPeer")
            .field("session", &self.inner.session_id)
            .field("peer", &self.inner.peer)
            .field("mode", &self.inner.mode)
            .finish_non_exhaustive()
    }
}

impl Drop for PeerInner {
    fn drop(&mut self) {
        if self.left.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // No runtime (process teardown): detach synchronously rather than
            // leave a phantom peer. No version can be cut from here.
            let mut state = self.session.state();
            if state
                .peers
                .get(&self.peer)
                .is_some_and(|entry| entry.incarnation == self.incarnation)
            {
                state.peers.remove(&self.peer);
                let session_id = state.session.clone();
                state.registry.remove_peer(&session_id, &self.peer);
                if state.peers.is_empty() {
                    state.grace_until = Some(Instant::now() + GRACE_AFTER_LAST_LEAVE);
                }
                tracing::warn!(
                    record = %self.session.record_id,
                    unsaved = state.dirty(),
                    "live session peer dropped outside a tokio runtime; detached without a version"
                );
            }
            return;
        };
        spawn_leave(
            &runtime,
            Arc::clone(&self.session),
            self.peer.clone(),
            self.incarnation,
        );
    }
}

// Spawn helpers. Each builds its (large) future inside its own never-inlined
// frame: in a debug build a function reserves stack for every future it might
// construct, even on branches it never takes, so building these inline in hot
// paths (the append backstop, every commit, every peer op) multiplied stack
// use down deeply nested write chains until server workers overflowed.

#[inline(never)]
fn spawn_leave(
    runtime: &tokio::runtime::Handle,
    session: Arc<LiveSession>,
    peer: PeerId,
    incarnation: u64,
) {
    runtime.spawn(Box::pin(async move {
        leave_peer(&session, &peer, incarnation, CloseReason::Left).await;
    }));
}

#[inline(never)]
fn spawn_idle_loop(session: Arc<LiveSession>) {
    tokio::spawn(Box::pin(idle_loop(session)));
}

#[inline(never)]
fn spawn_requested_version_loop(session: Arc<LiveSession>, slot: Instant) {
    tokio::spawn(Box::pin(requested_version_loop(session, slot)));
}

#[inline(never)]
fn spawn_grace_loop(session: Arc<LiveSession>) {
    tokio::spawn(Box::pin(grace_loop(session)));
}

#[inline(never)]
fn spawn_close_if_unsupported(session: Arc<LiveSession>, db: Db) {
    tokio::spawn(Box::pin(async move {
        let _ops = session.ops.lock().await;
        close_if_unsupported(&session, &db).await;
    }));
}

#[inline(never)]
fn spawn_cut(
    runtime: &tokio::runtime::Handle,
    session: Arc<LiveSession>,
    db: Db,
    reason: &'static str,
) {
    runtime.spawn(Box::pin(async move {
        let _ = run_cut(&session, &db, reason, None).await;
    }));
}

#[inline(never)]
fn spawn_recheck(runtime: &tokio::runtime::Handle, db: Db, flagged: Vec<Arc<LiveSession>>) {
    runtime.spawn(Box::pin(async move {
        for session in flagged {
            match load_supported(&db, &session.record_id).await {
                Err(refused) if refused.code != RefusalCode::Unavailable => {
                    let _ops = session.ops.lock().await;
                    final_cut_and_close(&session, &db).await;
                }
                Err(_) => session.state().pending_recheck = true,
                Ok(_) => {}
            }
        }
    }));
}

// ---------------------------------------------------------------------------
// Process-wide state
// ---------------------------------------------------------------------------

/// Live sessions of one database (one storage identity, see [`session_key`]).
struct DbSessions {
    /// Ordinary body writes hold this shared for their whole transaction; a
    /// fresh session seeds from the committed body holding it exclusively, so
    /// no ordinary write can commit underneath a seed.
    open_gate: Arc<RwLock<()>>,
    records: StdMutex<HashMap<String, Arc<LiveSession>>>,
}

static SERVICE: LazyLock<StdMutex<HashMap<PathBuf, Arc<DbSessions>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Next client id to lease, across every session in this process (each open
/// takes a pool of three). Monotonic per service, not per session, so no id
/// is ever leased twice in the process lifetime, even across a session's
/// teardown and re-seed.
static NEXT_CLIENT_ID: AtomicU32 = AtomicU32::new(2);

/// Reserve a fresh pool start for `registry`'s next open.
fn reserve_client_ids(registry: &mut SessionRegistry) {
    registry.advance_client_ids_to(NEXT_CLIENT_ID.fetch_add(3, Ordering::SeqCst));
}

/// The storage identity live sessions are keyed by. [`Db`] is always a
/// SQLite file (the Postgres and Turso adapters are separate backends with
/// no live-session support), so the canonical file path is stable across
/// handle re-opens and distinct for copies. Falls back to the path as given
/// when it cannot be canonicalised (e.g. already unlinked).
fn session_key(db: &Db) -> PathBuf {
    db.live_session_key().to_path_buf()
}

fn db_sessions(db: &Db) -> Arc<DbSessions> {
    let key = session_key(db);
    let mut service = lock(&SERVICE);
    Arc::clone(service.entry(key).or_insert_with(|| {
        Arc::new(DbSessions {
            open_gate: Arc::new(RwLock::new(())),
            records: StdMutex::new(HashMap::new()),
        })
    }))
}

/// Release empty co-edit bookkeeping after an isolated database has drained.
/// The caller must own the handle lifetime and prevent concurrent new writes
/// or session opens. Active sessions are never removed by this operation.
#[doc(hidden)]
pub fn release_idle_database(db: &Db) -> bool {
    let mut service = lock(&SERVICE);
    let key = session_key(db);
    if service
        .get(&key)
        .is_some_and(|owner| !lock(&owner.records).is_empty())
    {
        return false;
    }
    service.remove(&key);
    true
}

fn existing_db_sessions(db: &Db) -> Option<Arc<DbSessions>> {
    lock(&SERVICE).get(db.live_session_key()).cloned()
}

fn existing_session(db: &Db, record_id: &str) -> Option<Arc<LiveSession>> {
    existing_db_sessions(db).and_then(|owner| lock(&owner.records).get(record_id).cloned())
}

/// Poison is not an expected state here (no code panics while holding these
/// locks); recover the data rather than cascading the panic.
fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One live session (one record). `ops` serialises every state change,
/// including a version or routed write across its SQLite transaction;
/// `state` is held only briefly and never across an await.
struct LiveSession {
    record_id: String,
    owner: Weak<DbSessions>,
    ops: Arc<AsyncMutex<()>>,
    state: StdMutex<State>,
    events: broadcast::Sender<SessionEvent>,
}

struct State {
    /// Most recent handle seen for this database; timers write through it.
    db: Db,
    registry: SessionRegistry,
    session: SessionId,
    /// Torn down (grace expired or discarded). Handles must not use it.
    closed: bool,
    peers: HashMap<PeerId, PeerEntry>,
    /// Peers that left, kept for resume while the doc lives.
    departed: HashMap<PeerId, Departed>,
    /// Callers that have contributed or joined, by principal: candidate
    /// actors for automatic versions.
    callers: HashMap<String, Caller>,
    /// Registry mutation epoch at the last committed version.
    versioned_epoch: u64,
    dirty_admission: Option<Box<dyn Send>>,
    last_op: Instant,
    /// [`IDLE_VERSION_AFTER`], overridable per session in tests only (a
    /// paused tokio clock trips sqlx's pool timeouts).
    idle_after: Duration,
    idle_timer: bool,
    /// [`REQUESTED_VERSION_INTERVAL`], overridable per session in tests.
    version_interval: Duration,
    /// When the last requested cut took its slot.
    last_requested_cut: Option<Instant>,
    /// Latest coalesced request waiting for the next slot: reason and actor.
    pending_request: Option<(String, Caller)>,
    request_timer: bool,
    grace_until: Option<Instant>,
    grace_timer: bool,
    /// Consecutive access/policy failed cuts (see [`MAX_FAILED_CUTS`]).
    failed_cuts: u32,
    /// Consecutive transient failed cuts (drives the retry backoff).
    transient_failures: u32,
    /// When the current run of transient failures began.
    transient_since: Option<Instant>,
    /// [`TRANSIENT_RETRY_WINDOW`], overridable per session in tests.
    transient_window: Duration,
    /// A flush-and-absorb writer ([`BodyWrite::begin_absorb`]) holds `ops`;
    /// body events by exactly this actor may pass the backstop.
    absorbing: Option<String>,
    /// A guarded writer ([`BodyWrite::begin_scope_change`]) holds `ops` and
    /// may take the record out of live scope; it closes the session once its
    /// write has committed.
    scope_change: bool,
    /// An unguarded writer appended a scope-leaving event; re-check the
    /// record after the next commit ([`after_commit`]).
    pending_recheck: bool,
    base: BaseVersion,
    next_incarnation: u64,
}

struct PeerEntry {
    caller: Caller,
    mode: SessionMode,
    author: Author,
    client_ids: Vec<u32>,
    incarnation: u64,
}

struct Departed {
    principal: String,
    app: Option<AppAttribution>,
    mode: SessionMode,
    client_ids: Vec<u32>,
}

/// Bound on remembered departed peers per session.
const MAX_DEPARTED: usize = 64;

/// Consecutive access or policy failures (no contributor can still Edit, or
/// the record is no longer versionable) before the session gives up on its
/// contributors: it saves the unsaved text as a version attributed to the
/// session service, then closes so the record is never locked by a session
/// that cannot save. Transient (storage) failures never count: they retry
/// with backoff indefinitely and never close a session.
const MAX_FAILED_CUTS: u32 = 5;

/// Longest backoff between retries after transient cut failures.
const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(300);

/// How long transient cut failures may persist before they are treated as
/// policy failures (counted towards [`MAX_FAILED_CUTS`], so the usual
/// session-service fallback and logging follow).
const TRANSIENT_RETRY_WINDOW: Duration = Duration::from_secs(3600);

/// Classify an engine error from a version write: deterministic refusals
/// (`Engine`, `Auth`) will fail the same way on retry, so they are policy
/// failures; everything else (storage and the like) is transient.
fn classify_write_error(error: &crate::Error) -> Refused {
    match error {
        crate::Error::Engine(_) | crate::Error::Auth(_) => Refused::new(
            RefusalCode::RecordUnsupported,
            format!("the engine refused the version: {error}"),
        ),
        _ => unavailable(error),
    }
}

/// Whether a failed cut is an access or policy failure (counted towards
/// [`MAX_FAILED_CUTS`]) rather than a transient one.
fn is_access_or_policy(refused: &Refused) -> bool {
    matches!(
        refused.code,
        RefusalCode::AccessLost | RefusalCode::Forbidden | RefusalCode::RecordUnsupported
    )
}

impl State {
    fn epoch(&self) -> u64 {
        self.registry.mutation_epoch(&self.session).unwrap_or(0)
    }

    fn dirty(&self) -> bool {
        self.epoch() != self.versioned_epoch
    }

    fn peer(&self, peer: &PeerId, incarnation: u64) -> Result<&PeerEntry, Refused> {
        if self.closed {
            return Err(Refused::new(
                RefusalCode::UndeclaredSession,
                "session has closed",
            ));
        }
        self.peers
            .get(peer)
            .filter(|entry| entry.incarnation == incarnation)
            .ok_or_else(|| {
                Refused::new(
                    RefusalCode::UndeclaredSession,
                    "peer is not attached (left, closed or superseded by a resume)",
                )
            })
    }

    fn has_edit_peer(&self) -> bool {
        self.peers.values().any(|p| p.mode == PeerKind::Edit)
    }
}

impl LiveSession {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        lock(&self.state)
    }

    fn emit(&self, event: SessionEvent) {
        // No subscribers is fine.
        let _ = self.events.send(event);
    }

    /// Remove this session from its database's map (if it is still the
    /// registered one).
    fn unregister(self: &Arc<Self>) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let empty = {
            let mut records = lock(&owner.records);
            if records
                .get(&self.record_id)
                .is_some_and(|current| Arc::ptr_eq(current, self))
            {
                records.remove(&self.record_id);
            }
            records.is_empty()
        };
        if empty {
            // Drop the database's entry once it holds no sessions and nobody
            // else holds it or its gate (an in-flight writer keeps both).
            let mut service = lock(&SERVICE);
            service.retain(|_, entry| {
                !(Arc::ptr_eq(entry, &owner)
                    && Arc::strong_count(&owner) == 2
                    && Arc::strong_count(&owner.open_gate) == 1
                    && lock(&owner.records).is_empty())
            });
        }
    }
}

fn unavailable(error: impl std::fmt::Display) -> Refused {
    Refused::new(RefusalCode::Unavailable, error.to_string())
}

/// Admit a caller's host-asserted app the way a tool call does: it must name
/// a current adopted v2 install of the caller's own account
/// (`app_attribution::install_is_current`, the predicate behind `admit`).
/// `Forbidden` if not; `Unavailable` if the install table could not be read.
/// A caller with no app is admitted.
async fn admit_app(db: &Db, caller: &Caller) -> Result<(), Refused> {
    let Some(app) = caller.host_asserted_app() else {
        return Ok(());
    };
    match crate::mcp::app_attribution::install_is_current(db, caller.credential(), app).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Refused::new(
            RefusalCode::Forbidden,
            "the app is not an adopted v2 install of this account",
        )),
        Err(error) => Err(unavailable(error)),
    }
}

fn capability(mode: SessionMode) -> Capability {
    match mode {
        PeerKind::Edit => Capability::Edit,
        PeerKind::View => Capability::View,
    }
}

fn sha256_hex(text: &str) -> String {
    crate::mcp::tools::lifecycle::body_digest(Some(text))
}

fn version_token(seq: i64) -> String {
    format!("rec:{seq}")
}

/// Attribution for a caller's ops: the portable credential, the verified
/// executor kind (as ordinary writes attest it), the asserted run key, the
/// host-asserted app on the caller (stream 1's attribution, admitted against
/// the account's installs), and the server-observed channel.
///
/// The wire `kind` says how the change arrived:
/// - a verified `agent` or `delegated_service` executor is an agent;
/// - a call carrying app attribution is an app change;
/// - a call over the MCP transport is an agent (real MCP clients connect as
///   an `authenticated_principal`; contribution metadata renders the same
///   case as `likely_agent`);
/// - anything else (a web or workbench Save, a websocket peer) is a person.
fn author_for(caller: &Caller) -> Author {
    let (executor_kind, _, _) = crate::provenance::verified_executor_attribution(caller);
    let app = caller.host_asserted_app().map(AppAttribution::from);
    let channel = caller.channel();
    let kind = author_kind(&executor_kind, app.is_some(), channel);
    Author {
        contributor: AcknowledgedContributor {
            principal: caller.credential().to_owned(),
            executor_kind,
            // Normalized like the m7 emitter: an empty run key is absent,
            // never `Some("")`. The strict span-map parser rejects
            // present-but-empty optionals, so recording one here would
            // acknowledge an edit its own cut could not persist.
            run_key: caller
                .run_key()
                .filter(|key| !key.is_empty())
                .map(str::to_owned),
            app,
            channel: (channel != crate::provenance::Channel::Unknown)
                .then(|| channel.as_str().to_owned()),
        },
        kind,
    }
}

/// The wire author kind from the verified executor, app attribution and
/// server-observed channel (see [`author_for`]). A verified human over MCP
/// stays a person.
pub(crate) fn author_kind(
    executor_kind: &str,
    has_app: bool,
    channel: crate::provenance::Channel,
) -> AuthorKind {
    if matches!(executor_kind, "agent" | "delegated_service") {
        AuthorKind::Agent
    } else if has_app {
        AuthorKind::App
    } else if channel == crate::provenance::Channel::Mcp && executor_kind != "human" {
        AuthorKind::Agent
    } else {
        AuthorKind::Human
    }
}

/// Check `caller` may open `record_id` in `mode`, and that the body is a
/// live-editable Markdown body. Returns the committed body and its version.
async fn load_committed(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    mode: SessionMode,
) -> Result<(String, BaseVersion), Refused> {
    if !crate::mcp::tools::can_record(db, caller, record_id, capability(mode))
        .await
        .map_err(unavailable)?
    {
        return Err(Refused::new(
            RefusalCode::Forbidden,
            "caller cannot access this record in the requested mode",
        ));
    }
    load_supported(db, record_id).await
}

/// The committed body and version of a live-editable record, without
/// authorization: `forbidden` if it is missing or deleted,
/// `record_unsupported` if its body is not live-editable Markdown,
/// `unavailable` on a storage error.
async fn load_supported(db: &Db, record_id: &str) -> Result<(String, BaseVersion), Refused> {
    let mut tx = db.pool().begin().await.map_err(unavailable)?;
    let row = sqlx::query(
        "SELECT type, kind, body, deleted_at,
                EXISTS(SELECT 1 FROM facet_values
                        WHERE record_id = records.id AND key = 'runtime') AS runtime_present,
                (SELECT MAX(seq) FROM content_events WHERE record_id = records.id) AS seq
           FROM records WHERE id = ?",
    )
    .bind(record_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or_else(|| Refused::new(RefusalCode::Forbidden, "record does not exist"))?;
    let get = |e: sqlx::Error| unavailable(e);
    let stored = stored_body(&mut *tx, record_id).await.ok().flatten();
    let record_type: String = row.try_get("type").map_err(get)?;
    let kind: Option<String> = row.try_get("kind").map_err(get)?;
    let deleted: Option<String> = row.try_get("deleted_at").map_err(get)?;
    let runtime: bool = row.try_get("runtime_present").map_err(get)?;
    let body: Option<String> = row.try_get("body").map_err(get)?;
    let seq: Option<i64> = row.try_get("seq").map_err(get)?;
    let (artifact, instruction) = match kind.as_deref() {
        Some(kind) if record_type == "Document" => {
            let resolved = crate::meta::kind::resolve_on(&mut tx, "Document", kind)
                .await
                .map_err(unavailable)?;
            (
                kind == "artifact"
                    || crate::generated::kinds::CoreKind::DocumentArtifact.matches(&resolved),
                kind == "instruction" || resolved.canonical_kind.as_deref() == Some("instruction"),
            )
        }
        _ => (false, false),
    };
    let _ = tx.rollback().await;
    if deleted.is_some() {
        return Err(Refused::new(RefusalCode::Forbidden, "record is deleted"));
    }
    if record_type != "Document" || runtime || artifact || instruction {
        return Err(Refused::new(
            RefusalCode::RecordUnsupported,
            "live sessions need a Markdown Document body (not an artifact, instruction or runtime body)",
        ));
    }
    let body = body.unwrap_or_default();
    let body_sha256 = sha256_hex(&body);
    let base = BaseVersion {
        version: version_token(seq.unwrap_or(0)),
        // Read in the same transaction as the body, so the identity names the
        // revision these bytes came from; a mismatch drops it.
        proof: CutProof::named(
            stored
                .filter(|stored| stored.sha256 == body_sha256)
                .and_then(|stored| stored.event)
                .as_ref(),
        ),
        body_sha256,
    };
    Ok((body, base))
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

/// Open (or join) the live session on `request.record_id`.
///
/// Checks Edit (edit mode) or View (view mode) with the engine's per-record
/// authorization. Refuses non-Markdown bodies (`record_unsupported`) and
/// committed bodies over 1 MiB (`too_large`). The first opener seeds the doc
/// from the committed body; later openers join the live doc (including a doc
/// still in its grace window). Enrolled custody storage is refused with
/// `record_unsupported` for now.
pub async fn open(
    db: &Db,
    caller: &Caller,
    request: OpenRequest,
) -> Result<(SessionPeer, Opened), Refused> {
    if shutting_down(db) {
        return Err(Refused::new(
            RefusalCode::Unavailable,
            "the server is shutting down; reopen after it restarts",
        ));
    }
    if db.is_enrolled() {
        return Err(Refused::new(
            RefusalCode::RecordUnsupported,
            "live sessions are not available on enrolled custody storage yet",
        ));
    }
    let OpenRequest {
        record_id,
        mode,
        resume_peer,
    } = request;
    // An app claim must name a current adopted v2 install of this account,
    // exactly as a tool call's does (`app_attribution::admit`).
    admit_app(db, caller).await?;
    // Authorise (and check support) up front, whether joining or seeding.
    load_committed(db, caller, &record_id, mode).await?;
    let owner = db_sessions(db);
    let author = author_for(caller);
    loop {
        let existing = lock(&owner.records).get(&record_id).cloned();
        let session = match existing {
            Some(session) => session,
            None => {
                let gate = Arc::clone(&owner.open_gate).write_owned().await;
                if lock(&owner.records).contains_key(&record_id) {
                    drop(gate);
                    continue;
                }
                // Re-read under the gate: no ordinary body write can commit
                // between this read and the seed.
                let (body, base) = load_committed(db, caller, &record_id, mode).await?;
                let mut registry = SessionRegistry::new();
                reserve_client_ids(&mut registry);
                let opened = registry.open(OpenParams {
                    database_id: session_key(db).to_string_lossy().into_owned(),
                    record_id: record_id.clone(),
                    committed_body: body,
                    kind: mode,
                    record_supported: true,
                })?;
                // The seed doc's own snapshot, before any peer can apply: its
                // text must hash to the revision just read, or no proof.
                let base = match registry.version_snapshot(&opened.session_id) {
                    Ok(seed) => BaseVersion {
                        proof: base_proof(
                            &seed,
                            &base.body_sha256,
                            BodyEvent::from_row(
                                base.proof.body_event_id.clone(),
                                base.proof.body_event_seq,
                            )
                            .as_ref(),
                        ),
                        ..base
                    },
                    Err(_) => base,
                };
                let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
                let session = Arc::new(LiveSession {
                    record_id: record_id.clone(),
                    owner: Arc::downgrade(&owner),
                    ops: Arc::new(AsyncMutex::new(())),
                    state: StdMutex::new(State {
                        db: db.clone(),
                        registry,
                        session: opened.session_id.clone(),
                        closed: false,
                        peers: HashMap::new(),
                        departed: HashMap::new(),
                        callers: HashMap::new(),
                        versioned_epoch: 0,
                        dirty_admission: None,
                        last_op: Instant::now(),
                        idle_after: IDLE_VERSION_AFTER,
                        idle_timer: false,
                        version_interval: REQUESTED_VERSION_INTERVAL,
                        last_requested_cut: None,
                        pending_request: None,
                        request_timer: false,
                        grace_until: None,
                        grace_timer: false,
                        failed_cuts: 0,
                        transient_failures: 0,
                        transient_since: None,
                        transient_window: TRANSIENT_RETRY_WINDOW,
                        absorbing: None,
                        scope_change: false,
                        pending_recheck: false,
                        base: base.clone(),
                        next_incarnation: 1,
                    }),
                    events,
                });
                let peer = attach(
                    &session,
                    &mut session.state(),
                    caller,
                    mode,
                    &author,
                    opened.peer_id,
                    &opened.client_ids,
                );
                lock(&owner.records).insert(record_id.clone(), Arc::clone(&session));
                drop(gate);
                let opened = Opened {
                    session: opened.session_id,
                    peer: peer.inner.peer.clone(),
                    doc_client_ids: view_filtered(mode, opened.client_ids),
                    sync: opened.sync_step2,
                    base,
                    limits: LIMITS,
                    resumed: false,
                };
                return Ok((peer, opened));
            }
        };
        let _ops = session.ops.lock().await;
        let mut state = session.state();
        if state.closed {
            continue;
        }
        state.db = db.clone();
        state.grace_until = None;
        let principal = caller.credential();
        let resumable = resume_peer.as_ref().and_then(|peer| {
            let attached = state
                .peers
                .get(peer)
                .filter(|p| {
                    p.caller.credential() == principal
                        && p.mode == mode
                        && p.author.contributor.app == author.contributor.app
                })
                .map(|p| p.client_ids.clone());
            let departed = state
                .departed
                .get(peer)
                .filter(|d| {
                    d.principal == principal && d.mode == mode && d.app == author.contributor.app
                })
                .map(|d| d.client_ids.clone());
            attached.or(departed).map(|ids| (peer.clone(), ids))
        });
        let session_id = state.session.clone();
        let mut superseded = None;
        let (ok, resumed) = match resumable {
            Some((peer, ids)) => {
                let ok = state
                    .registry
                    .restore_peer(&session_id, &peer, mode, &ids)?;
                state.departed.remove(&peer);
                if state.peers.contains_key(&peer) {
                    superseded = Some(peer.clone());
                }
                (ok, true)
            }
            None => {
                reserve_client_ids(&mut state.registry);
                let ok = state.registry.open(OpenParams {
                    database_id: session_key(db).to_string_lossy().into_owned(),
                    record_id: record_id.clone(),
                    committed_body: String::new(),
                    kind: mode,
                    record_supported: true,
                })?;
                (ok, false)
            }
        };
        // The session's own base, read under `ops`: every cut, routed write
        // and absorb advances it before releasing `ops`, so it is current even
        // when a routed write committed after the authorising read above. A
        // clean doc is the state of that base; a dirty one is ahead of it, and
        // either way the base names the last cut, not the live doc.
        let base = state.base.clone();
        // Attach under the same lock: the append backstop must never see
        // this session with no peers (and discard it) mid-join.
        let peer = attach(
            &session,
            &mut state,
            caller,
            mode,
            &author,
            ok.peer_id,
            &ok.client_ids,
        );
        drop(state);
        if let Some(old) = superseded {
            // The handle this resume replaced: emitted before the new handle
            // exists, so only the old connection's subscription sees it.
            session.emit(SessionEvent::Closed {
                peer: Some(old),
                reason: CloseReason::Superseded,
            });
        }
        let opened = Opened {
            session: ok.session_id,
            peer: peer.inner.peer.clone(),
            doc_client_ids: view_filtered(mode, ok.client_ids),
            sync: ok.sync_step2,
            base,
            limits: LIMITS,
            resumed,
        };
        return Ok((peer, opened));
    }
}

const LIMITS: Limits = Limits {
    max_body_bytes: super::registry::MAX_BODY_BYTES,
    max_update_bytes: super::registry::MAX_UPDATE_BYTES,
    max_edit_peers: super::registry::MAX_EDIT_PEERS,
    max_view_peers: super::registry::MAX_VIEW_PEERS,
};

fn view_filtered(mode: SessionMode, ids: Vec<u32>) -> Vec<u32> {
    match mode {
        PeerKind::Edit => ids,
        PeerKind::View => Vec::new(),
    }
}

/// Record a (new or resumed) peer in the session state (whose lock the
/// caller holds) and mint its handle. A resumed peer gets a new incarnation,
/// superseding the old handle.
fn attach(
    session: &Arc<LiveSession>,
    state: &mut State,
    caller: &Caller,
    mode: SessionMode,
    author: &Author,
    peer: PeerId,
    client_ids: &[u32],
) -> SessionPeer {
    let incarnation = state.next_incarnation;
    state.next_incarnation += 1;
    state
        .callers
        .insert(caller.credential().to_owned(), caller.clone());
    state.peers.insert(
        peer.clone(),
        PeerEntry {
            caller: caller.clone(),
            mode,
            author: author.clone(),
            client_ids: client_ids.to_vec(),
            incarnation,
        },
    );
    let session_id = state.session.clone();
    SessionPeer {
        inner: Arc::new(PeerInner {
            session: Arc::clone(session),
            session_id,
            peer,
            mode,
            incarnation,
            left: AtomicBool::new(false),
        }),
    }
}

// ---------------------------------------------------------------------------
// Peer operations
// ---------------------------------------------------------------------------

impl SessionPeer {
    #[must_use]
    pub fn session(&self) -> &SessionId {
        &self.inner.session_id
    }

    #[must_use]
    pub fn peer(&self) -> &PeerId {
        &self.inner.peer
    }

    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.inner.mode
    }

    #[cfg(test)]
    pub(crate) fn set_idle_after_for_test(&self, idle_after: Duration) {
        self.inner.session.state().idle_after = idle_after;
    }

    #[cfg(test)]
    pub(crate) fn set_transient_window_for_test(&self, window: Duration) {
        self.inner.session.state().transient_window = window;
    }

    #[cfg(test)]
    pub(crate) fn set_version_interval_for_test(&self, interval: Duration) {
        self.inner.session.state().version_interval = interval;
    }

    /// Subscribe to this session's events. Subscribe before the first
    /// [`SessionPeer::apply`] to avoid missing remote updates.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.inner.session.events.subscribe()
    }

    /// Apply a Yjs update (v1) from this peer. On success the update is
    /// broadcast to every subscriber as [`SessionEvent::Remote`] with
    /// `origin = Some(self.peer())`.
    pub async fn apply(&self, update_id: &str, update: &[u8]) -> Result<PeerAck, Refused> {
        let session = &self.inner.session;
        let _ops = session.ops.lock().await;
        let mut state = session.state();
        let entry = state.peer(&self.inner.peer, self.inner.incarnation)?;
        if entry.mode != PeerKind::Edit {
            return Err(Refused::new(
                RefusalCode::Forbidden,
                "view-mode peers cannot author updates",
            ));
        }
        let author = entry.author.clone();
        let dirty_admission = admit_dirty_write(&state.db)?;
        let session_id = state.session.clone();
        let ack = state.registry.apply_update_attributed(
            &session_id,
            &self.inner.peer,
            update,
            &author.contributor,
        )?;
        if state.dirty() && state.dirty_admission.is_none() {
            state.dirty_admission = dirty_admission;
        }
        state.last_op = Instant::now();
        let start_timer = state.dirty() && !state.idle_timer;
        if start_timer {
            state.idle_timer = true;
        }
        drop(state);
        session.emit(SessionEvent::Remote {
            update: Arc::new(ack.broadcast),
            origin: Some(self.inner.peer.clone()),
            from: author,
        });
        if start_timer {
            spawn_idle_loop(Arc::clone(session));
        }
        Ok(PeerAck {
            update_id: update_id.to_owned(),
            clock: ack.state_vector,
        })
    }

    /// Everything the live doc has beyond `state_vector` (Yjs sync step 2).
    /// An empty `state_vector` means "everything".
    pub async fn sync(&self, state_vector: &[u8]) -> Result<Vec<u8>, Refused> {
        let state = self.inner.session.state();
        state.peer(&self.inner.peer, self.inner.incarnation)?;
        let since: Vec<u8>;
        let since = if state_vector.is_empty() {
            since = yrs::StateVector::default().encode_v1();
            &since
        } else {
            state_vector
        };
        state.registry.encode_diff(&state.session, since)
    }

    /// Cut a version now, for everyone, with a non-blank `reason`. Requires
    /// an edit peer. A cut with nothing new since the last version returns
    /// `Ok(None)`. Requests are rate-limited to one cut per
    /// [`REQUESTED_VERSION_INTERVAL`] per session: a request inside the
    /// window returns `Ok(None)` at once and is coalesced (latest reason
    /// wins) into one cut at the next allowed slot. Every version, however
    /// triggered (requested, idle, last leave, dropped peer, routed write),
    /// is also broadcast as [`SessionEvent::Versioned`] to every subscriber,
    /// the requester included; the return value is a convenience.
    pub async fn version(&self, reason: &str) -> Result<Option<Versioned>, Refused> {
        if reason.trim().is_empty() {
            return Err(Refused::new(
                RefusalCode::InvalidRequest,
                "a version needs a non-blank reason",
            ));
        }
        let (caller, db) = {
            let state = self.inner.session.state();
            let entry = state.peer(&self.inner.peer, self.inner.incarnation)?;
            if entry.mode != PeerKind::Edit {
                return Err(Refused::new(
                    RefusalCode::Forbidden,
                    "view-mode peers cannot request versions",
                ));
            }
            (entry.caller.clone(), state.db.clone())
        };
        let session = &self.inner.session;
        let deferred_until = {
            let mut state = session.state();
            let now = Instant::now();
            match state.last_requested_cut {
                Some(last) if last + state.version_interval > now => {
                    let slot = last + state.version_interval;
                    state.pending_request = Some((reason.to_owned(), caller.clone()));
                    let start = !state.request_timer;
                    state.request_timer = true;
                    Some((slot, start))
                }
                _ => {
                    // Take the slot before cutting, so concurrent requests
                    // coalesce instead of racing a second cut.
                    state.last_requested_cut = Some(now);
                    None
                }
            }
        };
        match deferred_until {
            None => run_cut(session, &db, reason, Some(caller)).await,
            Some((slot, start)) => {
                if start {
                    spawn_requested_version_loop(Arc::clone(session), slot);
                }
                Ok(None)
            }
        }
    }

    /// Leave the session. If this was the last editor and there are unsaved
    /// edits, a version is cut first; leaving never refuses. Returns that
    /// version, if one was cut.
    pub async fn leave(self) -> Option<Versioned> {
        if self.inner.left.swap(true, Ordering::AcqRel) {
            return None;
        }
        leave_peer(
            &self.inner.session,
            &self.inner.peer,
            self.inner.incarnation,
            CloseReason::Left,
        )
        .await
    }

    /// Re-check this peer's access with the caller's CURRENT authority (call
    /// on the transport heartbeat and on authorization frames). `caller` must
    /// be freshly resolved by the transport for this request (hosted
    /// membership and role facts are folded into the `Caller` at ingress, so
    /// the engine cannot re-resolve them itself), and must be the same
    /// principal that opened the peer. The fresh caller replaces the one
    /// captured at open, so later versions are attributed with it.
    ///
    /// On loss of the mode's capability the peer is removed,
    /// [`SessionEvent::Closed`] with [`CloseReason::AccessLost`] is
    /// broadcast for it, and `Err(access_lost)` is returned. Its acknowledged
    /// ops stay in the doc and in the next version's contributors.
    pub async fn recheck_access(&self, caller: &Caller) -> Result<(), Refused> {
        let (db, mode) = {
            let mut state = self.inner.session.state();
            let entry = state.peer(&self.inner.peer, self.inner.incarnation)?;
            if entry.caller.credential() != caller.credential() {
                return Err(Refused::new(
                    RefusalCode::Forbidden,
                    "recheck caller is not the principal that opened this peer",
                ));
            }
            // The app is part of who this peer is: a re-check cannot move
            // it to another app (or into one, or out of one).
            if entry.author.contributor.app != caller.host_asserted_app().map(AppAttribution::from)
            {
                return Err(Refused::new(
                    RefusalCode::Forbidden,
                    "recheck caller is not the app that opened this peer",
                ));
            }
            let mode = entry.mode;
            if let Some(entry) = state.peers.get_mut(&self.inner.peer) {
                entry.caller = caller.clone();
            }
            state
                .callers
                .insert(caller.credential().to_owned(), caller.clone());
            (state.db.clone(), mode)
        };
        let record = &self.inner.session.record_id;
        // The install behind the app can lapse mid-session; that ends the
        // peer like any other loss of authority.
        let app_admitted = match admit_app(&db, caller).await {
            Ok(()) => true,
            Err(refused) if refused.code == RefusalCode::Forbidden => false,
            Err(refused) => return Err(refused),
        };
        let allowed = app_admitted
            && crate::mcp::tools::can_record(&db, caller, record, capability(mode))
                .await
                .map_err(unavailable)?;
        if allowed {
            return Ok(());
        }
        if !self.inner.left.swap(true, Ordering::AcqRel) {
            leave_peer(
                &self.inner.session,
                &self.inner.peer,
                self.inner.incarnation,
                CloseReason::AccessLost,
            )
            .await;
        }
        Err(Refused::new(
            RefusalCode::AccessLost,
            "access to this record was lost",
        ))
    }
}

/// Detach a peer; cut a version if it was the last editor (or last peer)
/// with unsaved edits; start the grace window when no peers remain. Never
/// refuses: a failed cut is retried by the idle and grace timers.
async fn leave_peer(
    session: &Arc<LiveSession>,
    peer: &PeerId,
    incarnation: u64,
    reason: CloseReason,
) -> Option<Versioned> {
    let (cut_needed, actor, db, empty) = {
        let _ops = session.ops.lock().await;
        let mut state = session.state();
        if state.closed {
            return None;
        }
        let entry = state
            .peers
            .get(peer)
            .filter(|entry| entry.incarnation == incarnation)?;
        let actor = entry.caller.clone();
        let mode = entry.mode;
        state.peers.remove(peer);
        let session_id = state.session.clone();
        if let Some((_, client_ids)) = state.registry.remove_peer(&session_id, peer) {
            if state.departed.len() >= MAX_DEPARTED {
                if let Some(evict) = state.departed.keys().next().cloned() {
                    state.departed.remove(&evict);
                }
            }
            state.departed.insert(
                peer.clone(),
                Departed {
                    principal: actor.credential().to_owned(),
                    app: actor.host_asserted_app().map(AppAttribution::from),
                    mode,
                    client_ids,
                },
            );
        }
        let empty = state.peers.is_empty();
        let last_editor = mode == PeerKind::Edit && !state.has_edit_peer();
        let cut_needed = (last_editor || empty) && state.dirty();
        if empty {
            state.grace_until = Some(Instant::now() + GRACE_AFTER_LAST_LEAVE);
        }
        (cut_needed, actor, state.db.clone(), empty)
    };
    session.emit(SessionEvent::Closed {
        peer: Some(peer.clone()),
        reason,
    });
    let actor = (reason != CloseReason::AccessLost).then_some(actor);
    let versioned = if cut_needed {
        run_cut(session, &db, "session ended", actor)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    if empty {
        start_grace_timer(session);
    }
    versioned
}

// ---------------------------------------------------------------------------
// Versions and timers
// ---------------------------------------------------------------------------

/// Cut a version under the storage-policy lease and the session's ops lock
/// (in that order, matching ordinary tool dispatch).
async fn run_cut(
    session: &Arc<LiveSession>,
    db: &Db,
    reason: &str,
    actor_hint: Option<Caller>,
) -> Result<Option<Versioned>, Refused> {
    let outcome = crate::storage_profile::with_operation(
        db,
        "session.version",
        Some("native.domain-mcp.v1"),
        async {
            let _ops = session.ops.lock().await;
            Ok(boxed_cut_locked(session, db, reason, actor_hint).await)
        },
    )
    .await
    .map_err(unavailable)?;
    outcome
}

/// A cut's future, boxed. The version write inside it (`record_update_in`)
/// is the engine's largest future; built inline it would enlarge every
/// request future that can cut (`update_record` through `begin_body_write`),
/// and in a debug build each poll frame reserves room for it, which
/// overflowed server worker stacks. These never-inlined helpers build it in
/// their own frame and hand back only a pointer.
type BoxedCut<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<Versioned>, Refused>> + Send + 'a>,
>;

#[inline(never)]
fn boxed_cut_locked<'a>(
    session: &'a Arc<LiveSession>,
    db: &'a Db,
    reason: &'a str,
    actor_hint: Option<Caller>,
) -> BoxedCut<'a> {
    Box::pin(cut_locked(session, db, reason, actor_hint))
}

#[inline(never)]
fn boxed_write_cut<'a>(
    session: &'a Arc<LiveSession>,
    db: &'a Db,
    reason: &'a str,
    actor: Caller,
) -> BoxedCut<'a> {
    Box::pin(write_cut(session, db, reason, actor))
}

/// Cut a version; the caller holds `ops`. Nothing new since the last version
/// is `Ok(None)`. Every failure is logged and counted; after
/// [`MAX_FAILED_CUTS`] in a row the session is abandoned (see
/// [`abandon_locked`]) so it can never lock the record.
async fn cut_locked(
    session: &Arc<LiveSession>,
    db: &Db,
    reason: &str,
    actor_hint: Option<Caller>,
) -> Result<Option<Versioned>, Refused> {
    let result = cut_by_contributor(session, db, reason, actor_hint).await;
    match &result {
        Ok(_) => {
            let mut state = session.state();
            state.failed_cuts = 0;
            state.transient_failures = 0;
            state.transient_since = None;
        }
        Err(refused) if is_frozen(refused) => {
            tracing::info!(record = %session.record_id, "live session version deferred: writes are frozen");
        }
        Err(refused) if !is_access_or_policy(refused) && !transient_window_spent(session) => {
            let failures = {
                let mut state = session.state();
                state.transient_failures = state.transient_failures.saturating_add(1);
                state.transient_since.get_or_insert_with(Instant::now);
                state.transient_failures
            };
            tracing::warn!(
                record = %session.record_id,
                failures,
                error = %refused,
                "live session version cut failed (transient); will retry"
            );
        }
        Err(refused) => {
            let failures = {
                let mut state = session.state();
                state.failed_cuts += 1;
                state.failed_cuts
            };
            tracing::warn!(
                record = %session.record_id,
                failures,
                error = %refused,
                "live session version cut failed"
            );
            if failures >= MAX_FAILED_CUTS {
                abandon_locked(session, db).await;
            }
        }
    }
    result
}

#[cfg(test)]
pub(crate) fn classify_write_error_for_test(error: &crate::Error) -> Refused {
    classify_write_error(error)
}

/// Whether transient failures have persisted past the retry window, after
/// which they count as policy failures.
fn transient_window_spent(session: &Arc<LiveSession>) -> bool {
    let state = session.state();
    state
        .transient_since
        .is_some_and(|since| since.elapsed() >= state.transient_window)
}

/// Log unsaved live edits that could not be versioned. Never the document
/// text: only the record, session, contributors, byte length and sha256, so
/// an operator can correlate it with peers' recovery drafts.
fn log_unsaved(session: &Arc<LiveSession>, error: &dyn std::fmt::Display, message: &str) {
    let (session_ref, bytes, sha256, contributors) = {
        let state = session.state();
        let body = state.registry.live_body(&state.session).unwrap_or_default();
        let contributors: Vec<String> = state
            .registry
            .acknowledged_contributors(&state.session)
            .unwrap_or_default()
            .iter()
            .map(|c| format!("{} ({})", c.principal, c.executor_kind))
            .collect();
        (
            state.session.0.clone(),
            body.len(),
            sha256_hex(&body),
            contributors,
        )
    };
    tracing::error!(
        record = %session.record_id,
        session = %session_ref,
        contributors = ?contributors,
        unsaved_bytes = bytes,
        unsaved_sha256 = %sha256,
        error = %error,
        "{message}"
    );
}

/// Give up on a session whose cuts keep failing for access or policy
/// reasons (every contributor lost Edit, or the record is no longer
/// versionable). The caller holds `ops`.
///
/// The unsaved text is saved as a version attributed to the session service
/// (the trusted local caller) with the real contributors listed. This is
/// intended: those ops were acknowledged while their authors held Edit, so
/// they stay in the doc and are credited in the next version (contract
/// M8b). If even that fails it is logged (metadata only, never the text).
/// Then the session closes for everyone with `access_lost`.
async fn abandon_locked(session: &Arc<LiveSession>, db: &Db) {
    if admit_write(db).is_err() {
        // Never give up on unsaved text during a freeze; retry later.
        return;
    }
    let dirty = {
        let state = session.state();
        !state.closed && state.dirty()
    };
    if dirty {
        if let Err(error) = boxed_write_cut(
            session,
            db,
            "session ended (saved by the session service)",
            Caller::local(),
        )
        .await
        {
            log_unsaved(
                session,
                &error,
                "live session closed with unsaved edits that could not be versioned",
            );
        }
    }
    close_session(session, CloseReason::AccessLost);
}

/// Close a session for everyone: tear it down, unregister it, and broadcast
/// `Closed { peer: None, reason }`.
fn close_session(session: &Arc<LiveSession>, reason: CloseReason) {
    {
        let mut state = session.state();
        if state.closed {
            return;
        }
        close_locked(&mut state);
    }
    session.unregister();
    session.emit(SessionEvent::Closed { peer: None, reason });
}

/// Cut through the first contributor (or `actor_hint`) who still has Edit.
async fn cut_by_contributor(
    session: &Arc<LiveSession>,
    db: &Db,
    reason: &str,
    actor_hint: Option<Caller>,
) -> Result<Option<Versioned>, Refused> {
    {
        let state = session.state();
        if state.closed || !state.dirty() {
            return Ok(None);
        }
    }
    // A record that is no longer versionable (deleted, or no longer a
    // Markdown body) is a policy failure, not a transient one.
    if let Err(refused) = load_supported(db, &session.record_id).await {
        return Err(if refused.code == RefusalCode::Unavailable {
            refused
        } else {
            Refused::new(RefusalCode::RecordUnsupported, refused.detail)
        });
    }
    let candidates = {
        let state = session.state();
        if state.closed || !state.dirty() {
            return Ok(None);
        }
        let mut candidates: Vec<Caller> = Vec::new();
        // A version credited to an app must be cut by that app's own account
        // (the install, and so the provenance row, is the account's), so its
        // callers go first. Anyone else's cut carries no app (`write_cut`).
        if let Ok(contributors) = state.registry.acknowledged_contributors(&state.session) {
            if let Some((principal, _)) = uniform_app(&contributors) {
                candidates.extend(
                    state
                        .peers
                        .values()
                        .map(|peer| &peer.caller)
                        .chain(state.callers.values())
                        .filter(|caller| caller.credential() == principal)
                        .cloned(),
                );
            }
        }
        candidates.extend(actor_hint);
        // With no hint (idle, last leave, release flush, shutdown) the actor
        // is the last accepted editor, as the registry contract says: not
        // whichever caller the maps happen to yield first.
        if let Ok(Some(last)) = state.registry.last_accepted_contributor(&state.session) {
            candidates.extend(
                state
                    .peers
                    .values()
                    .map(|peer| &peer.caller)
                    .chain(state.callers.values())
                    .filter(|caller| caller.credential() == last.principal)
                    .cloned(),
            );
        }
        candidates.extend(state.peers.values().map(|p| p.caller.clone()));
        candidates.extend(state.callers.values().cloned());
        candidates
    };
    let record = session.record_id.clone();
    let mut actor = None;
    let mut tried = std::collections::HashSet::new();
    for candidate in candidates {
        if !tried.insert(candidate.credential().to_owned()) {
            continue;
        }
        if crate::mcp::tools::can_record(db, &candidate, &record, Capability::Edit)
            .await
            .map_err(unavailable)?
        {
            actor = Some(candidate);
            break;
        }
    }
    let actor = actor.ok_or_else(|| {
        Refused::new(
            RefusalCode::AccessLost,
            "no contributor can still edit this record to version it",
        )
    })?;
    boxed_write_cut(session, db, reason, actor).await
}

/// The record's `updated_at` as seen inside a write transaction.
#[inline(never)]
async fn record_updated_at_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT updated_at FROM records WHERE id = ?")
        .bind(record)
        .fetch_optional(&mut **tx)
        .await
}

/// The record's stored body and its latest body-carrying event, read in one
/// statement so the pair cannot straddle a commit.
///
/// The event id and sequence come from one row: the join picks the single
/// event whose `seq` is the newest satisfying `BODY_CARRYING_EVENT_SQL`.
///
/// Reads taken after a commit (routed finish, absorb) rely on the single-writer
/// rule, not on a compare-and-swap: while a session has peers, `admit_event`
/// refuses body events that are not that session's own version, and the writer
/// holds `ops`, so no other body writer in this process can commit between its
/// commit and this read. A body writer outside this process (direct SQL) would
/// break that; a different body would then fail the hash filter in
/// [`cut_proof`] and drop the proof, and a same-bytes one would be adopted.
pub(super) struct StoredBody {
    pub(super) sha256: String,
    pub(super) event: Option<BodyEvent>,
}

async fn stored_body_via<'e, E>(
    executor: E,
    record: &str,
) -> Result<Option<StoredBody>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let Some(row) = crate::record_body::stored_body_with_revision_on(executor, record).await?
    else {
        return Ok(None);
    };
    let body: Option<String> = row.try_get("body")?;
    Ok(Some(StoredBody {
        sha256: sha256_hex(&body.unwrap_or_default()),
        event: BodyEvent::from_row(
            row.try_get("body_event_id")?,
            row.try_get("body_event_seq")?,
        ),
    }))
}

/// [`stored_body_via`] on the heap: the sqlx future is large, and the cut path
/// already runs deep inside nested futures on small test stacks.
async fn stored_body<'e, E>(executor: E, record: &str) -> Result<Option<StoredBody>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite> + 'e,
{
    Box::pin(stored_body_via(executor, record)).await
}

/// The proof for a cut whose body hashed to `body_sha256`, given what the
/// database holds after that cut committed. Fail-closed: any disagreement
/// between the snapshot's text, the reported hash and the stored body yields
/// no proof at all, and an old snapshot is never relabelled with a new event
/// unless its own text hashes to the new revision.
pub(super) fn cut_proof(
    snapshot: &super::registry::VersionSnapshot,
    body_sha256: &str,
    stored: Option<&StoredBody>,
) -> CutProof {
    let Some(stored) = stored.filter(|stored| stored.sha256 == body_sha256) else {
        return CutProof::default();
    };
    base_proof(snapshot, body_sha256, stored.event.as_ref())
}

/// Attach the doc snapshot to a revision identity when the snapshot's own text
/// is that revision's body.
pub(super) fn base_proof(
    snapshot: &super::registry::VersionSnapshot,
    body_sha256: &str,
    event: Option<&BodyEvent>,
) -> CutProof {
    let mut proof = CutProof::named(event);
    if event.is_some() && sha256_hex(snapshot.body()) == body_sha256 {
        proof.snapshot = snapshot.ydoc_snapshot().map(Arc::<[u8]>::from);
    }
    proof
}

/// The app a version's provenance row may credit: the one app every
/// contributor in the snapshot acted through, with the account that made it.
/// `None` for no contributors, any contributor without an app, or more than
/// one app or account. The row says "this app made this version", which undo
/// by app relies on, so it is never given to a version that also holds
/// someone else's text.
fn uniform_app(
    contributors: &[AcknowledgedContributor],
) -> Option<(String, crate::mcp::app_attribution::AppAttribution)> {
    let first = contributors.first()?;
    let app = first.app.as_ref()?;
    contributors
        .iter()
        .all(|c| c.app.as_ref() == Some(app) && c.principal == first.principal)
        .then_some(())?;
    let app = crate::mcp::app_attribution::AppAttribution::new(
        app.package.clone(),
        app.version.clone(),
        app.install_event_id.clone(),
    )
    .ok()?;
    Some((first.principal.clone(), app))
}

/// Write the version as `actor`; the caller holds `ops`.
///
/// The cut is one action attestation, and `provenance_action_app_attributions`
/// holds one app per attestation. Whose app it is does not depend on who
/// triggers the cut (a leaving peer, a routed write's flush, a timer): it is
/// decided by the snapshot. Only when every contributor acted through the same
/// app (see [`uniform_app`]) does the cut carry that app, as the app's own
/// account; any other version is cut with no app, and `contributors[]` still
/// lists every app. An app whose install lapsed since it was admitted is cut
/// without the app too: the write transaction re-checks the install and would
/// otherwise fail every cut until the session was abandoned.
async fn write_cut(
    session: &Arc<LiveSession>,
    db: &Db,
    reason: &str,
    actor: Caller,
) -> Result<Option<Versioned>, Refused> {
    let snapshot = {
        let state = session.state();
        if state.closed || !state.dirty() {
            return Ok(None);
        }
        state.registry.version_snapshot(&state.session)?
    };
    let actor = match uniform_app(snapshot.contributors()) {
        Some((principal, app)) if actor.credential() == principal => actor
            .without_host_asserted_app()
            .with_host_asserted_app(app),
        _ => actor.without_host_asserted_app(),
    };
    let actor = match admit_app(db, &actor).await {
        Ok(()) => actor,
        Err(refused) if refused.code == RefusalCode::Forbidden => actor.without_host_asserted_app(),
        Err(refused) => return Err(refused),
    };
    // A cut completes already admitted dirty work even after database freeze
    // intent. Fleet admission is still checked independently by its hook.
    let _dirty_admission = if session.state().dirty_admission.is_none() {
        admit_dirty_write(db)?
    } else {
        None
    };
    // Held until this function returns: through begin, commit and drain.
    let _admission = admit_write(db)?;
    let record = session.record_id.clone();
    let session_ref = snapshot.session_id().0.clone();
    let arguments = serde_json::json!({
        "record_id": record, "session": session_ref, "reason": reason,
    });
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &actor,
        "session.version",
        &arguments,
        None,
    );
    let receipt = dispatch
        .scope(async {
            let mut tx = crate::db::enrolled::begin_document_write(db).await?;
            // Read inside the write transaction, which holds the write lock:
            // nothing can commit between these two reads and the append.
            let before = record_updated_at_in(&mut tx, &record).await?;
            match crate::mcp::tools::lifecycle::write_live_version_in(
                db,
                &mut tx,
                &actor,
                &record,
                snapshot.body(),
                snapshot.contributors(),
                &session_ref,
                reason,
                Some(snapshot.span_map()),
            )
            .await
            {
                Ok(receipt) => {
                    let around = match (before, record_updated_at_in(&mut tx, &record).await?) {
                        (Some(before), Some(after)) => Some((before, after)),
                        _ => None,
                    };
                    // The stored body and its body-carrying event, read in
                    // the cut's own transaction after the append.
                    let stored = stored_body(&mut *tx, &record).await?;
                    db.commit_content(tx).await?;
                    Ok((receipt, around, stored))
                }
                Err(error) => {
                    let _ = tx.rollback().await;
                    Err(error)
                }
            }
        })
        .await
        .map_err(|error| classify_write_error(&error))?;
    let (receipt, updated_at_around_cut, stored) = receipt;
    let body_sha256 = sha256_hex(snapshot.body());
    let proof = cut_proof(&snapshot, &body_sha256, stored.as_ref());
    let versioned = {
        let mut state = session.state();
        // `ops` is held, so nothing moved the epoch since the snapshot.
        let _ = state.registry.drain_version_snapshot(&snapshot);
        state.versioned_epoch = state.epoch();
        state.dirty_admission.take();
        state.base = BaseVersion {
            version: version_token(receipt.version),
            body_sha256: body_sha256.clone(),
            proof: proof.clone(),
        };
        Versioned {
            session: snapshot.session_id().clone(),
            version: version_token(receipt.version),
            body_sha256,
            event_id: receipt.event_id,
            contributors: snapshot.contributors().to_vec(),
            reason: reason.to_owned(),
            proof,
            updated_at_around_cut,
        }
    };
    session.emit(SessionEvent::Versioned(versioned.clone()));
    Ok(Some(versioned))
}

/// Cut a version once the session has been idle for [`IDLE_VERSION_AFTER`]
/// since its last accepted op. Exits when the session is clean or closed.
async fn idle_loop(session: Arc<LiveSession>) {
    loop {
        let (deadline, db) = {
            let mut state = session.state();
            if state.closed || !state.dirty() {
                state.idle_timer = false;
                return;
            }
            (state.last_op + state.idle_after, state.db.clone())
        };
        tokio::time::sleep_until(deadline).await;
        let due = {
            let state = session.state();
            state.last_op + state.idle_after <= Instant::now()
        };
        if !due {
            continue;
        }
        if run_cut(&session, &db, "idle", None).await.is_err() {
            // Logged and counted in `cut_locked`. Back off (exponentially
            // after transient failures); the loop exits if access failures
            // closed the session.
            let backoff = retry_backoff(&session);
            tokio::time::sleep(backoff).await;
        }
    }
}

/// Delay before retrying a failed cut: one idle period, doubled per
/// consecutive transient failure, capped at [`MAX_TRANSIENT_BACKOFF`].
fn retry_backoff(session: &Arc<LiveSession>) -> Duration {
    let state = session.state();
    let doublings = state.transient_failures.saturating_sub(1).min(16);
    state
        .idle_after
        .saturating_mul(1u32 << doublings)
        .min(MAX_TRANSIENT_BACKOFF.max(state.idle_after))
}

/// Cut coalesced requested versions, one per allowed slot.
async fn requested_version_loop(session: Arc<LiveSession>, mut slot: Instant) {
    loop {
        tokio::time::sleep_until(slot).await;
        let (request, db) = {
            let mut state = session.state();
            let request = state.pending_request.take();
            if request.is_none() || state.closed {
                state.request_timer = false;
                return;
            }
            let now = Instant::now();
            state.last_requested_cut = Some(now);
            slot = now + state.version_interval;
            (request, state.db.clone())
        };
        if let Some((reason, caller)) = request {
            // Failure is logged and counted in `cut_locked`; the edits stay
            // dirty for the idle and leave cuts.
            let _ = run_cut(&session, &db, &reason, Some(caller)).await;
        }
    }
}

fn start_grace_timer(session: &Arc<LiveSession>) {
    {
        let mut state = session.state();
        if state.grace_timer || state.closed {
            return;
        }
        state.grace_timer = true;
    }
    spawn_grace_loop(Arc::clone(session));
}

/// Drop the doc once the grace window passes with no peers. Unsaved edits
/// (a failed final cut) are versioned first; the doc is never dropped dirty.
async fn grace_loop(session: Arc<LiveSession>) {
    loop {
        let (until, db) = {
            let mut state = session.state();
            match state.grace_until {
                Some(until) if !state.closed && state.peers.is_empty() => (until, state.db.clone()),
                _ => {
                    state.grace_timer = false;
                    return;
                }
            }
        };
        tokio::time::sleep_until(until).await;
        let (expired, dirty) = {
            let state = session.state();
            (
                state.grace_until.is_some_and(|u| u <= Instant::now())
                    && state.peers.is_empty()
                    && !state.closed,
                state.dirty(),
            )
        };
        if !expired {
            continue;
        }
        if dirty && run_cut(&session, &db, "session ended", None).await.is_err() {
            // Logged and counted in `cut_locked`; retry after another grace
            // window (the loop exits if the failures closed the session).
            let mut state = session.state();
            if state.closed {
                state.grace_timer = false;
                return;
            }
            state.grace_until = Some(Instant::now() + GRACE_AFTER_LAST_LEAVE);
            continue;
        }
        let _ops = session.ops.lock().await;
        let dropped = {
            let mut state = session.state();
            if state.peers.is_empty() && !state.dirty() && !state.closed {
                close_locked(&mut state);
                state.grace_timer = false;
                true
            } else {
                false
            }
        };
        if dropped {
            session.unregister();
            return;
        }
    }
}

fn close_locked(state: &mut State) {
    state.closed = true;
    state.dirty_admission.take();
    let session_id = state.session.clone();
    state.registry.drop_session(&session_id);
    state.departed.clear();
    state.callers.clear();
}

/// Server shutdown: refuse every later open ([`begin_shutdown`], which is
/// never undone), then for every live session in this process cut a version
/// if it has unsaved edits (best effort, logged on failure) and close it for
/// everyone with `server_shutdown`. Call only when the server is really
/// stopping (deploys restart it); peers reconnect and reopen afterwards. A
/// release preparation that may be cancelled should call [`flush_all`].
pub async fn shutdown() {
    begin_shutdown();
    let owners: Vec<Arc<DbSessions>> = lock(&SERVICE).values().cloned().collect();
    for owner in owners {
        shutdown_sessions(&owner).await;
    }
}

/// Outcome of [`flush_all`]: dirty sessions whose edits were versioned, and
/// dirty sessions that could not be (refused by the write admission hook, or
/// failed). Clean sessions count as neither.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub flushed: usize,
    pub not_flushed: usize,
}

/// Version every dirty live session in this process now, without closing
/// any and without refusing later opens (unlike [`shutdown`]). For a release
/// preparation that may be cancelled: the server keeps serving afterwards.
/// Each cut runs under its session's ops lock and the write admission guard,
/// as shutdown's does.
pub async fn flush_all() -> FlushReport {
    let owners: Vec<Arc<DbSessions>> = lock(&SERVICE).values().cloned().collect();
    let mut report = FlushReport::default();
    for owner in owners {
        flush_sessions(&owner, &mut report).await;
    }
    report
}

async fn flush_sessions(owner: &Arc<DbSessions>, report: &mut FlushReport) {
    let sessions: Vec<Arc<LiveSession>> = lock(&owner.records).values().cloned().collect();
    for session in sessions {
        let (dirty, db) = {
            let state = session.state();
            (!state.closed && state.dirty(), state.db.clone())
        };
        if !dirty {
            continue;
        }
        match run_cut(&session, &db, "flushed before a release", None).await {
            Ok(Some(_)) => report.flushed += 1,
            // Became clean meanwhile (another cut won).
            Ok(None) => {}
            Err(error) => {
                report.not_flushed += 1;
                tracing::warn!(record = %session.record_id, error = %error,
                    "live session could not be flushed");
            }
        }
    }
}

#[cfg(test)]
pub(crate) async fn flush_database_for_test(db: &Db) -> FlushReport {
    let mut report = FlushReport::default();
    if let Some(owner) = existing_db_sessions(db) {
        flush_sessions(&owner, &mut report).await;
    }
    report
}

/// [`shutdown`] for one database's sessions.
async fn shutdown_sessions(owner: &Arc<DbSessions>) {
    let sessions: Vec<Arc<LiveSession>> = lock(&owner.records).values().cloned().collect();
    for session in sessions {
        let db = session.state().db.clone();
        // The final cut and the close happen under ONE ops hold, so no op
        // can be acknowledged between them and then dropped with the doc.
        let admitted = crate::storage_profile::with_operation(
            &db,
            "session.version",
            Some("native.domain-mcp.v1"),
            async {
                let _ops = session.ops.lock().await;
                shutdown_locked(&session, &db).await;
                Ok(())
            },
        )
        .await;
        if let Err(error) = admitted {
            // No storage admission: close without a cut (still one hold).
            let _ops = session.ops.lock().await;
            if !session.state().closed && session.state().dirty() {
                log_unsaved(
                    &session,
                    &error,
                    "live session could not save on server shutdown",
                );
            }
            close_session(&session, CloseReason::ServerShutdown);
        }
    }
}

/// The final cut and close of one session; the caller holds `ops`.
async fn shutdown_locked(session: &Arc<LiveSession>, db: &Db) {
    if let Err(error) = boxed_cut_locked(session, db, "server shutdown", None).await {
        // Refused by the freeze barrier or failed. Peers resume their
        // pending edits after the restart.
        log_unsaved(
            session,
            &error,
            "live session could not save on server shutdown",
        );
    }
    close_session(session, CloseReason::ServerShutdown);
}

#[cfg(test)]
pub(crate) async fn shutdown_database_for_test(db: &Db) {
    lock(&TEST_SHUT_DOWN).insert(db.live_session_key().to_path_buf());
    if let Some(owner) = existing_db_sessions(db) {
        shutdown_sessions(&owner).await;
    }
}

// ---------------------------------------------------------------------------
// Single-writer rule: routed body writes, the append backstop, live reads
// ---------------------------------------------------------------------------

/// Held by an ordinary body write (`update_record`) from before its write
/// transaction until it has committed (or failed). Holds the database's open
/// gate shared, so no session can seed underneath the write, and, while a
/// session has peers attached, that session's ops lock, so the write's
/// digest check and diff are exact against the live text.
pub(crate) struct BodyWrite {
    _gate: OwnedRwLockReadGuard<()>,
    live: Option<LiveWrite>,
}

/// The record's `updated_at` just before the flush-first version was
/// appended (`before`) and just after (`after`), both read inside the
/// flush's own write transaction; `None` when nothing was flushed.
#[derive(Default)]
struct FlushTimestamps {
    before: Option<String>,
    after: Option<String>,
}

/// The `updated_at` a timestamp precondition (`if_unmodified_since`) is
/// judged against, inside the write transaction, given the record's
/// `current` value. The flush-first version is the write's own doing and
/// moved `updated_at` from `before` to `after`; while the record is still at
/// `after`, nothing else has committed since and the caller's view is
/// `before`. If the current value is anything else, a write that does not
/// take the ops lock (a metadata-only `update_record`) committed after the
/// flush: the guard must see that, so it uses `current`. With no flush there
/// is nothing to look through.
pub(crate) fn guarded_updated_at<'a>(
    before_flush: Option<&'a str>,
    after_flush: Option<&str>,
    current: &'a str,
) -> &'a str {
    match (before_flush, after_flush) {
        (Some(before), Some(after)) if after == current => before,
        _ => current,
    }
}

struct LiveWrite {
    /// `updated_at` around the flush-first version (see
    /// [`BodyWrite::guard_updated_at`]).
    flush_timestamps: FlushTimestamps,
    session: Arc<LiveSession>,
    _ops: OwnedMutexGuard<()>,
    session_id: SessionId,
    live_body: String,
    prepared: Option<PreparedUpdate>,
    author: Option<Author>,
    reason: String,
    absorbing: bool,
    scope_change: bool,
}

impl Drop for LiveWrite {
    fn drop(&mut self) {
        let absorbing = {
            let mut state = self.session.state();
            if self.scope_change {
                state.scope_change = false;
            }
            if self.absorbing {
                state.absorbing = None;
            }
            self.absorbing
        };
        if absorbing {
            // An absorbing write was neither absorbed nor explicitly
            // cancelled: the future was dropped (cancelled) somewhere between
            // its begin and its absorb, possibly after its commit. The live
            // doc may now be behind the committed body, so close the session
            // rather than let it go stale; peers reopen from committed.
            tracing::warn!(
                record = %self.session.record_id,
                "absorbing write abandoned mid-flight; closing the live session"
            );
            close_session(&self.session, CloseReason::Superseded);
        }
    }
}

/// What a routed write needs to append its version (`record.updated` with
/// the live result plus `contributors[]`, `session` and the span map).
pub(crate) struct RoutedVersion {
    pub(crate) body: String,
    pub(crate) contributors: Vec<AcknowledgedContributor>,
    pub(crate) session_ref: String,
    pub(crate) span_map: SpanMap,
}

/// Enter an ordinary body write on `record_id` by `caller`. With a live
/// session that has peers attached, the returned guard routes the write into
/// it, after versioning any unsaved live edits as their own version (a write
/// that cannot be preceded by that save is refused as retryable). A session in
/// its grace window (no peers) is discarded so the write goes
/// to the committed path; if it still holds unsaved edits they are versioned
/// first, through the writer if no contributor can. A caller without Edit
/// gets a plain guard and never touches session state (the write's own
/// authorization then refuses it).
pub(crate) async fn begin_body_write(
    db: &Db,
    record_id: &str,
    caller: &Caller,
) -> crate::Result<BodyWrite> {
    begin_body_write_inner(db, record_id, caller, None).await
}

/// [`begin_body_write`] for a call that cannot be routed into a live session
/// (a keyed `update_record`, whose merged version cannot be replayed). If a
/// session with peers would take the write, it is refused with `refusal`
/// *before* anything is flushed: the refused call changes nothing, so
/// neither the people's text nor `updated_at` moves, and a resend is judged
/// against the world the caller read. Otherwise identical.
pub(crate) async fn begin_unrouted_body_write(
    db: &Db,
    record_id: &str,
    caller: &Caller,
    refusal: &str,
) -> crate::Result<BodyWrite> {
    begin_body_write_inner(db, record_id, caller, Some(refusal)).await
}

async fn begin_body_write_inner(
    db: &Db,
    record_id: &str,
    caller: &Caller,
    refuse_routed: Option<&str>,
) -> crate::Result<BodyWrite> {
    let authorized = !record_id.is_empty()
        && crate::mcp::tools::can_record(db, caller, record_id, Capability::Edit).await?;
    let owner = db_sessions(db);
    let gate = Arc::clone(&owner.open_gate).read_owned().await;
    let plain = |gate| BodyWrite {
        _gate: gate,
        live: None,
    };
    if !authorized {
        return Ok(plain(gate));
    }
    let session = lock(&owner.records).get(record_id).cloned();
    let Some(session) = session else {
        return Ok(plain(gate));
    };
    let ops = Arc::clone(&session.ops).lock_owned().await;
    let (closed, grace, dirty) = {
        let mut state = session.state();
        state.db = db.clone();
        (state.closed, state.peers.is_empty(), state.dirty())
    };
    if closed {
        return Ok(plain(gate));
    }
    if grace {
        if dirty {
            let saved = boxed_cut_locked(&session, db, "session ended", Some(caller.clone())).await;
            let still_open = !session.state().closed;
            if saved.is_err() && still_open {
                return Err(crate::Error::engine(
                    "a live session on this record is still saving its last edits; retry shortly",
                ));
            }
        }
        // Clean (or abandoned): discard the grace doc, so it cannot go stale.
        let mut state = session.state();
        if !state.closed && state.peers.is_empty() && !state.dirty() {
            close_locked(&mut state);
            drop(state);
            session.unregister();
        }
        return Ok(plain(gate));
    }
    // Decided under `ops`, so a session that gained peers since the caller
    // last looked is still caught, and before the flush below.
    if let Some(refusal) = refuse_routed {
        return Err(crate::Error::engine(refusal));
    }
    // Every routed write starts from a clean session: unsaved live edits are
    // versioned first, as their own version, so the routed write's version
    // holds only its own change and its action row (the app, the agent's run,
    // the person) is only what that caller wrote. The cut runs under `ops`,
    // so no peer op can slip in before the routed diff is applied, and
    // before the write's transaction opens. Who the flush is credited to is
    // decided by the snapshot (`write_cut`), not by this caller.
    // The `updated_at` values around the flush come back with the cut itself,
    // read inside its write transaction, so no write can slip between them.
    let mut flush_timestamps = FlushTimestamps::default();
    if dirty {
        let saved = boxed_cut_locked(
            &session,
            db,
            "saved before a routed write",
            Some(caller.clone()),
        )
        .await;
        if saved.is_err() {
            if session.state().closed {
                // Abandoned and saved by the session service: the session is
                // gone, so the write goes to the committed path.
                return Ok(plain(gate));
            }
            return Err(crate::Error::engine(
                "a live session on this record is still saving its last edits; retry shortly",
            ));
        }
        if let Ok(Some(flushed)) = saved {
            if let Some((before, after)) = flushed.updated_at_around_cut {
                flush_timestamps = FlushTimestamps {
                    before: Some(before),
                    after: Some(after),
                };
            }
        }
    }
    let (session_id, live_body) = {
        let state = session.state();
        let session_id = state.session.clone();
        let live_body = state
            .registry
            .live_body(&session_id)
            .map_err(|refused| crate::Error::engine(refused.to_string()))?;
        (session_id, live_body)
    };
    Ok(BodyWrite {
        _gate: gate,
        live: Some(LiveWrite {
            flush_timestamps,
            session,
            _ops: ops,
            session_id,
            live_body,
            prepared: None,
            author: None,
            reason: String::new(),
            absorbing: false,
            scope_change: false,
        }),
    })
}

impl BodyWrite {
    /// The `updated_at` a timestamp precondition (`if_unmodified_since`) is
    /// judged against, given the record's `current` value read inside the
    /// write transaction (see [`guarded_updated_at`]): the value from before
    /// this write's own flush-first version, so a correct guard survives the
    /// flush, but only while nothing else committed after it. `current` when
    /// not routed or nothing was flushed.
    pub(crate) fn guard_updated_at<'a>(&'a self, current: &'a str) -> &'a str {
        match self.live.as_ref() {
            Some(live) => guarded_updated_at(
                live.flush_timestamps.before.as_deref(),
                live.flush_timestamps.after.as_deref(),
                current,
            ),
            None => current,
        }
    }

    /// Whether this write is routed into a live session.
    pub(crate) fn is_routed(&self) -> bool {
        self.live.is_some()
    }

    /// Build a body-bearing `record.updated` payload from `base` (which must
    /// not already hold `body`). Routed: the body is the live result of the
    /// diff and the payload carries the version metadata. Not routed:
    /// `base` plus `body: new_body`, unchanged from the ordinary path.
    pub(crate) async fn body_payload(
        &mut self,
        caller: &Caller,
        new_body: &str,
        reason: &str,
        mut base: serde_json::Map<String, serde_json::Value>,
    ) -> crate::Result<serde_json::Map<String, serde_json::Value>> {
        match self.prepare(caller, new_body, reason).await? {
            Some(version) => {
                base.insert("body".into(), serde_json::Value::String(version.body));
                super::version_metadata::record_updated_payload(
                    base,
                    Some(&super::version_metadata::VersionMetadata {
                        contributors: &version.contributors,
                        session_ref: &version.session_ref,
                        merged_offline: false,
                        span_map: Some(&version.span_map),
                    }),
                )
            }
            None => {
                base.insert(
                    "body".into(),
                    serde_json::Value::String(new_body.to_owned()),
                );
                Ok(base)
            }
        }
    }

    /// This write may take the record out of live scope (delete, type
    /// correction, kind change, `runtime` facet). Unsaved live edits are
    /// versioned first, through the writer, while `ops` is held, so nothing
    /// typed before the write is lost; the backstop then admits the write,
    /// and [`BodyWrite::finish`] / [`BodyWrite::finish_scope_change`] close
    /// the session once it has committed. A no-op without attached peers.
    pub(crate) async fn begin_scope_change(
        &mut self,
        db: &Db,
        caller: &Caller,
    ) -> crate::Result<()> {
        let Some(live) = self.live.as_mut() else {
            return Ok(());
        };
        if live.session.state().dirty() {
            boxed_cut_locked(
                &live.session,
                db,
                "saved before the record left live editing",
                Some(caller.clone()),
            )
            .await
            .map_err(|refused| {
                crate::Error::engine(format!(
                    "a live session on this record could not save its unsaved edits first; \
                     retry shortly ({refused})"
                ))
            })?;
            // The cut just versioned the live text, which the routed path
            // may still diff against.
            live.live_body = {
                let state = live.session.state();
                state.registry.live_body(&state.session).unwrap_or_default()
            };
        }
        live.session.state().scope_change = true;
        live.scope_change = true;
        Ok(())
    }

    /// After a scope-changing write committed without a routed body: close
    /// the session for everyone with `access_lost` (contract m5) if the
    /// record is no longer live-editable (e.g. note to memo stays live).
    pub(crate) async fn finish_scope_change(self, db: &Db) {
        if let Some(live) = self.live.as_ref() {
            if live.scope_change {
                // `ops` is still held by this write: no edit can land between
                // the commit and this check.
                close_if_unsupported(&live.session, db).await;
            }
        }
    }

    /// Flush-and-absorb, for body writers whose own preconditions are too
    /// intricate to route as a diff (the artifact body save and its Undo):
    /// versions any unsaved live edits first, so the committed body equals
    /// the live text the writer's preconditions then see, and lets the
    /// writer's ordinary body write through the append backstop. Call
    /// [`BodyWrite::absorb_committed`] after the write commits. A no-op when
    /// not routed.
    pub(crate) async fn begin_absorb(&mut self, db: &Db, caller: &Caller) -> crate::Result<()> {
        let Some(live) = self.live.as_mut() else {
            return Ok(());
        };
        if live.session.state().dirty() {
            boxed_cut_locked(
                &live.session,
                db,
                "saved before an app write",
                Some(caller.clone()),
            )
            .await
            .map_err(|refused| {
                crate::Error::engine(format!(
                    "a live session on this record could not save its unsaved edits first; \
                     retry shortly ({refused})"
                ))
            })?;
        }
        live.session.state().absorbing = Some(caller.actor().to_owned());
        live.absorbing = true;
        Ok(())
    }

    /// The absorbed write did not commit (refused or failed): stop admitting
    /// it, leaving the session open and its doc untouched.
    pub(crate) fn cancel_absorb(mut self) {
        self.disarm_absorb();
    }

    fn disarm_absorb(&mut self) {
        if let Some(live) = self.live.as_mut() {
            if live.absorbing {
                live.session.state().absorbing = None;
                live.absorbing = false;
            }
        }
    }

    /// Open an absorbing writer's transaction. A failure here cannot have
    /// committed anything, so the absorb is cancelled (the session stays open)
    /// instead of being left armed to close it on drop.
    pub(crate) async fn open_absorbing<T>(
        &mut self,
        opening: impl std::future::Future<Output = crate::Result<T>>,
    ) -> crate::Result<T> {
        match opening.await {
            Ok(opened) => Ok(opened),
            Err(error) => {
                self.disarm_absorb();
                Err(error)
            }
        }
    }

    /// After an absorbed write committed: bring the live doc to the new
    /// committed body as a server-authored diff attributed to `caller`, and
    /// broadcast it with the writer's event as the version.
    pub(crate) async fn absorb_committed(self, db: &Db, caller: &Caller, reason: &str) {
        let Some(mut live) = self.live else {
            return;
        };
        let record = live.session.record_id.clone();
        let committed = async {
            let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                .bind(&record)
                .fetch_one(db.pool())
                .await?;
            let row = sqlx::query(
                "SELECT id, seq FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
            )
            .bind(&record)
            .fetch_one(db.pool())
            .await?;
            Ok::<_, crate::Error>((
                body.unwrap_or_default(),
                row.try_get::<String, _>("id")?,
                row.try_get::<i64, _>("seq")?,
            ))
        }
        .await;
        let (body, event_id, seq) = match committed {
            Ok(found) => found,
            Err(error) => {
                tracing::error!(record = %record, error = %error,
                    "could not read an absorbed write back; closing the live session");
                close_session(&live.session, CloseReason::Superseded);
                return;
            }
        };
        // What the database now holds as body and body-carrying event, read
        // with `ops` held. A failed read leaves the version unproved.
        let stored = stored_body(db.pool(), &record).await.ok().flatten();
        let author = author_for(caller);
        let (old, new) = (live.live_body.clone(), body.clone());
        let splices = match tokio::task::spawn_blocking(move || {
            super::text_diff::splices(&old, &new)
        })
        .await
        {
            Ok(splices) => splices,
            Err(error) => {
                // Never treat a failed diff as "no change": the live doc
                // would silently fall behind the committed body.
                tracing::error!(record = %record, error = %error,
                        "absorb diff failed; closing the live session");
                live.absorbing = false;
                live.session.state().absorbing = None;
                close_session(&live.session, CloseReason::Superseded);
                return;
            }
        };
        let session = Arc::clone(&live.session);
        let mut events = Vec::new();
        {
            let mut state = session.state();
            state.absorbing = None;
            live.absorbing = false;
            let installed = match state.registry.prepare_server_write(
                &live.session_id,
                &body,
                &splices,
                &author.contributor,
            ) {
                Ok(Some(prepared)) => state
                    .registry
                    .install_prepared_update(&live.session_id, None, prepared)
                    .map(Some)
                    .map_err(|mismatch| format!("{mismatch:?}")),
                // No diff: the live text already is the committed body.
                Ok(None) => Ok(None),
                Err(refused) => Err(refused.to_string()),
            };
            match installed {
                Ok(ack) => {
                    let unchanged = ack.is_none();
                    if let Some(ack) = ack {
                        state.last_op = Instant::now();
                        events.push(SessionEvent::Remote {
                            update: Arc::new(ack.broadcast),
                            origin: None,
                            from: author,
                        });
                    }
                    if let Ok(snapshot) = state.registry.version_snapshot(&live.session_id) {
                        let body_sha256 = sha256_hex(&body);
                        let proof = cut_proof(&snapshot, &body_sha256, stored.as_ref());
                        // An idempotent replay: no new body revision, no
                        // version. A new same-bytes revision still moves the
                        // body event a source pin names, so it refreshes the
                        // base and tells the peers, with the doc's own
                        // (unchanged) snapshot, proved against this body.
                        // Over the snapshot cap the event is still named, so
                        // the base advances without a snapshot. When the
                        // stored read failed or named no body event there is
                        // no fresh identity to announce: the base stays as it
                        // was and may name an older body event. That is
                        // explicit staleness, never a fresh proof; the engine
                        // refuses a pin built from it.
                        if unchanged
                            && (proof.body_event_id.is_none()
                                || proof.body_event_id == state.base.proof.body_event_id)
                        {
                            return;
                        }
                        let contributors = snapshot.contributors().to_vec();
                        let _ = state.registry.drain_version_snapshot(&snapshot);
                        state.versioned_epoch = state.epoch();
                        state.dirty_admission.take();
                        state.base = BaseVersion {
                            version: version_token(seq),
                            body_sha256: body_sha256.clone(),
                            proof: proof.clone(),
                        };
                        events.push(SessionEvent::Versioned(Versioned {
                            session: live.session_id.clone(),
                            version: version_token(seq),
                            body_sha256,
                            event_id,
                            contributors,
                            reason: reason.to_owned(),
                            proof,
                            updated_at_around_cut: None,
                        }));
                    }
                }
                Err(error) => {
                    drop(state);
                    tracing::error!(record = %record, error = %error,
                        "could not absorb a committed write into the live session; closing it");
                    close_session(&session, CloseReason::Superseded);
                    return;
                }
            }
        }
        for event in events {
            session.emit(event);
        }
    }

    /// The live text, when this write is routed into a session.
    pub(crate) fn live_body(&self) -> Option<&str> {
        self.live.as_ref().map(|live| live.live_body.as_str())
    }

    /// Prepare the routed diff turning the live text into `new_body`,
    /// authored by the server and attributed to `caller`. Returns the
    /// version payload pieces; `None` when this write is not routed.
    pub(crate) async fn prepare(
        &mut self,
        caller: &Caller,
        new_body: &str,
        reason: &str,
    ) -> crate::Result<Option<RoutedVersion>> {
        let Some(live) = self.live.as_mut() else {
            return Ok(None);
        };
        let author = author_for(caller);
        // The live text is fixed while `ops` is held. The diff is bounded
        // (see `text_diff`) but still runs off the async thread.
        let (old, new) = (live.live_body.clone(), new_body.to_owned());
        let splices = tokio::task::spawn_blocking(move || super::text_diff::splices(&old, &new))
            .await
            .map_err(|error| crate::Error::engine(format!("routed diff failed: {error}")))?;
        let state = live.session.state();
        let prepared = state
            .registry
            .prepare_server_write(&live.session_id, new_body, &splices, &author.contributor)
            .map_err(|refused| crate::Error::engine(format!("update_record: {refused}")))?;
        let (body, contributors, span_map) = match &prepared {
            Some(prepared) => {
                // Map the candidate's post-state under its successor
                // ownership: the payload commits before install, so the map
                // must already reflect the routed change.
                let span_map = state
                    .registry
                    .span_map_for_prepared(&live.session_id, prepared)
                    .map_err(|refused| crate::Error::engine(refused.to_string()))?;
                (prepared.body(), prepared.contributors(), span_map)
            }
            None => {
                let snapshot = state
                    .registry
                    .version_snapshot(&live.session_id)
                    .map_err(|refused| crate::Error::engine(refused.to_string()))?;
                (
                    snapshot.body().to_owned(),
                    snapshot.contributors().to_vec(),
                    snapshot.span_map().clone(),
                )
            }
        };
        drop(state);
        live.prepared = prepared;
        live.author = Some(author);
        live.reason = reason.to_owned();
        Ok(Some(RoutedVersion {
            body,
            contributors,
            session_ref: live.session_id.0.clone(),
            span_map,
        }))
    }

    /// After the write transaction committed: install the diff in the live
    /// doc, drain the versioned contributors, and broadcast the change and
    /// the version to peers.
    pub(crate) async fn finish(self, event_id: &str, version_seq: i64) {
        let Some(mut live) = self.live else {
            return;
        };
        let session = Arc::clone(&live.session);
        // The committed body and its body-carrying event, read after the
        // commit with `ops` still held: no other body writer can interleave.
        // A failed read leaves the version unproved, as before.
        let stored = {
            let db = session.state().db.clone();
            stored_body(db.pool(), &session.record_id)
                .await
                .ok()
                .flatten()
        };
        let mut events = Vec::new();
        {
            let mut state = session.state();
            if let Some(prepared) = live.prepared.take() {
                match state
                    .registry
                    .install_prepared_update(&live.session_id, None, prepared)
                {
                    Ok(ack) => {
                        state.last_op = Instant::now();
                        events.push(SessionEvent::Remote {
                            update: Arc::new(ack.broadcast),
                            origin: None,
                            from: live.author.clone().expect("prepared routed author"),
                        });
                    }
                    Err(mismatch) => {
                        // Unreachable while `ops` is held. The committed body
                        // is now ahead of the doc: discard it so peers resync
                        // from committed rather than diverge.
                        tracing::error!(
                            ?mismatch,
                            "routed write could not install; closing session"
                        );
                        close_locked(&mut state);
                        drop(state);
                        session.unregister();
                        session.emit(SessionEvent::Closed {
                            peer: None,
                            reason: CloseReason::Superseded,
                        });
                        return;
                    }
                }
            }
            if let Ok(snapshot) = state.registry.version_snapshot(&live.session_id) {
                let body_sha256 = sha256_hex(snapshot.body());
                let proof = cut_proof(&snapshot, &body_sha256, stored.as_ref());
                let contributors = snapshot.contributors().to_vec();
                let _ = state.registry.drain_version_snapshot(&snapshot);
                state.versioned_epoch = state.epoch();
                state.dirty_admission.take();
                state.base = BaseVersion {
                    version: version_token(version_seq),
                    body_sha256: body_sha256.clone(),
                    proof: proof.clone(),
                };
                events.push(SessionEvent::Versioned(Versioned {
                    session: live.session_id.clone(),
                    version: version_token(version_seq),
                    body_sha256,
                    event_id: event_id.to_owned(),
                    contributors,
                    reason: live.reason.clone(),
                    proof,
                    updated_at_around_cut: None,
                }));
            }
        }
        for event in events {
            session.emit(event);
        }
        if live.scope_change {
            // After this write releases `ops` (below, when `live` drops).
            let db = session.state().db.clone();
            spawn_close_if_unsupported(session, db);
        }
    }
}

/// The id and content seq of the newest content event on `record_id`, read
/// inside the writer's transaction right after its append (for
/// [`BodyWrite::finish`]).
pub(crate) async fn latest_event_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> crate::Result<(String, i64)> {
    let row = sqlx::query(
        "SELECT id, seq FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok((row.try_get("id")?, row.try_get("seq")?))
}

/// Backstop for the single-writer rule, run at every content append.
///
/// - An event whose projection writes `records.body` (see
///   `record_body::payload_carries_body`) on a record with an attached live
///   session is refused unless it is that session's own version (its payload
///   names the session). During the grace window (no peers) a clean doc is
///   discarded and the write proceeds.
/// - An event that takes the record out of live-editable scope (deletion, a
///   type correction, a kind change, or a `runtime` facet) closes the session
///   for everyone with `access_lost` (contract m5). If it holds unsaved edits,
///   a kind/type/runtime change is refused (retryable) while a version is cut;
///   a deletion proceeds and the unsaved text is logged for recovery.
pub(crate) fn admit_event(
    db: &Db,
    record_id: &str,
    event_type: &str,
    payload: &serde_json::Value,
    actor: Option<&str>,
    stored_kind: Option<&str>,
) -> crate::Result<()> {
    let Some(session) = existing_session(db, record_id) else {
        return Ok(());
    };
    // Restating the current kind (`stored_kind`, read in the writer's
    // transaction before this event projects) is not a kind change.
    let kind_changes = event_type == "record.updated"
        && payload
            .get("kind")
            .is_some_and(|wanted| wanted.as_str() != stored_kind);
    let state = session.state();
    if state.closed {
        return Ok(());
    }
    let own = payload
        .get(super::version_metadata::SESSION_KEY)
        .and_then(serde_json::Value::as_str)
        == Some(state.session.0.as_str());
    // A pure version cut never carries `kind`, so a session's own payload
    // with `kind` is a routed write that also changes the kind.
    let leaves_scope = match event_type {
        "record.deleted" | "record.type_corrected.v1" => true,
        "record.updated" => kind_changes,
        "facet.set" => payload.get("key").and_then(serde_json::Value::as_str) == Some("runtime"),
        _ => false,
    };
    if leaves_scope && !state.scope_change {
        // An unguarded writer. Nothing is closed here: its transaction can
        // still fail. With unsaved edits it is refused (retryable) while they
        // are versioned; otherwise it proceeds and the record is re-checked
        // after the next commit.
        if state.dirty() {
            let db = state.db.clone();
            drop(state);
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                spawn_cut(
                    &runtime,
                    Arc::clone(&session),
                    db,
                    "saved before the record changed",
                );
            }
            return Err(crate::Error::engine(
                "a live editing session on this record is saving unsaved edits; retry shortly",
            ));
        }
        let mut state = state;
        state.pending_recheck = true;
        return Ok(());
    }
    if leaves_scope {
        // Guarded: the writer closes the session after it commits.
        return Ok(());
    }
    if event_type == "record.created"
        || !crate::record_body::payload_carries_body(event_type, payload)
        || own
        || (state.absorbing.is_some() && state.absorbing.as_deref() == actor)
    {
        return Ok(());
    }
    let mut state = state;
    if state.peers.is_empty() && !state.dirty() {
        close_locked(&mut state);
        drop(state);
        session.unregister();
        return Ok(());
    }
    Err(crate::Error::engine(
        "a live editing session owns this record's body; this kind of body write is \
         refused while it is open (live sessions edit Markdown text only)",
    ))
}

/// Whether any live session is held for `db` in this process (the append
/// path's gate before running the backstop).
pub(crate) fn has_sessions(db: &Db) -> bool {
    existing_db_sessions(db).is_some_and(|owner| !lock(&owner.records).is_empty())
}

/// Why a live session holds a record's body against an ordinary write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyHold {
    /// Peers are attached and editing.
    Editing,
    /// No peers remain, but the grace doc has unsaved edits; it saves within
    /// moments.
    Saving,
}

/// Whether, and why, a live session would refuse an ordinary body write to
/// `record_id` now. Undo of an app's writes (task `650d870`) reports such a
/// body revert as blocked rather than let the append backstop refuse it
/// mid-transaction.
///
/// Mirrors [`admit_event`]'s body arm: an open session with peers attached
/// holds the body, and so does a grace doc (no peers) with unsaved edits. A
/// clean grace doc does not: the write closes it and proceeds.
pub(crate) fn session_holds_body(db: &Db, record_id: &str) -> Option<BodyHold> {
    // Deliberately conservative: `admit_event`'s `own`/`absorbing` exemptions
    // never apply to an undo's plain append, so they are not modelled here.
    let session = existing_session(db, record_id)?;
    let state = session.state();
    if state.closed {
        None
    } else if !state.peers.is_empty() {
        Some(BodyHold::Editing)
    } else if state.dirty() {
        Some(BodyHold::Saving)
    } else {
        None
    }
}

/// Whether `admit_event` needs the record's stored kind for this event (a
/// `record.updated` carrying `kind` on a record with a live session), so the
/// append path reads it only then.
pub(crate) fn needs_stored_kind(
    db: &Db,
    record_id: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> bool {
    event_type == "record.updated"
        && payload.get("kind").is_some()
        && existing_session(db, record_id).is_some()
}

/// Post-commit step for scope changes made by unguarded writers: for every
/// session on `db` flagged by [`admit_event`], re-read the committed record
/// and close the session (`access_lost`) if it is no longer live-editable.
/// Called after every content commit; a no-op without flagged sessions.
pub(crate) fn after_commit(db: &Db) {
    let Some(owner) = existing_db_sessions(db) else {
        return;
    };
    let flagged: Vec<Arc<LiveSession>> = lock(&owner.records)
        .values()
        .filter(|session| {
            let mut state = session.state();
            std::mem::take(&mut state.pending_recheck)
        })
        .cloned()
        .collect();
    if flagged.is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    spawn_recheck(&runtime, db.clone(), flagged);
}

/// The in-memory live text of `record_id`, if a session holds one (with
/// peers attached or in its grace window). Read-only: takes no guard, cuts
/// nothing (for previews such as a dry-run suggestion accept).
pub(crate) fn live_text(db: &Db, record_id: &str) -> Option<String> {
    let session = existing_session(db, record_id)?;
    let state = session.state();
    if state.closed {
        return None;
    }
    state.registry.live_body(&state.session).ok()
}

/// After a committed scope change: if the record is no longer live-editable,
/// version any edits acknowledged since, then close (`access_lost`); on a
/// storage error, re-check after the next commit. The caller holds `ops`.
async fn close_if_unsupported(session: &Arc<LiveSession>, db: &Db) {
    match load_supported(db, &session.record_id).await {
        Ok(_) => {}
        Err(refused) if refused.code == RefusalCode::Unavailable => {
            session.state().pending_recheck = true;
        }
        // Edits acknowledged since the write (e.g. after a routed write
        // released `ops`) are versioned before the close.
        Err(_) => final_cut_and_close(session, db).await,
    }
}

/// The record has left live scope: version any edits acknowledged since the
/// last version (e.g. while an unguarded writer's transaction ran), through a
/// contributor who can still Edit, then close for everyone with
/// `access_lost`. A record that can no longer take the version (deleted, or
/// no longer Markdown) refuses it; that is logged (metadata only) and the
/// peers keep their pending edits as recovery drafts. The caller holds `ops`.
async fn final_cut_and_close(session: &Arc<LiveSession>, db: &Db) {
    let dirty = {
        let state = session.state();
        !state.closed && state.dirty()
    };
    if dirty {
        let candidates: Vec<Caller> = session.state().callers.values().cloned().collect();
        let mut saved = false;
        let mut last_error = None;
        for actor in candidates {
            match crate::mcp::tools::can_record(db, &actor, &session.record_id, Capability::Edit)
                .await
            {
                Ok(true) => {
                    match boxed_write_cut(
                        session,
                        db,
                        "saved as the record left live editing",
                        actor,
                    )
                    .await
                    {
                        Ok(_) => {
                            saved = true;
                            break;
                        }
                        Err(refused) => last_error = Some(refused),
                    }
                }
                Ok(false) => {}
                Err(error) => last_error = Some(unavailable(error)),
            }
        }
        if !saved {
            let error = last_error.unwrap_or_else(|| {
                Refused::new(RefusalCode::AccessLost, "no contributor can still edit")
            });
            log_unsaved(
                session,
                &error,
                "record left live editing with unsaved edits that could not be versioned",
            );
        }
    }
    close_session(session, CloseReason::AccessLost);
}

/// `get_record` during a live session: replace `body` with the live text,
/// with `body_digest` = sha256(live), `body_state: "live"` and
/// `committed_body_digest`. No-op without an attached session.
pub(crate) fn overlay_live_body(db: &Db, record: &mut serde_json::Value) {
    let Some(object) = record.as_object_mut() else {
        return;
    };
    let Some(id) = object.get("id").and_then(serde_json::Value::as_str) else {
        return;
    };
    if !object.contains_key("body") {
        return;
    }
    let Some(session) = existing_session(db, id) else {
        return;
    };
    let live = {
        let state = session.state();
        if state.closed || state.peers.is_empty() {
            return;
        }
        match state.registry.live_body(&state.session) {
            Ok(live) => live,
            Err(_) => return,
        }
    };
    let committed = crate::mcp::tools::lifecycle::body_digest(
        object.get("body").and_then(serde_json::Value::as_str),
    );
    object.insert("body_digest".into(), serde_json::json!(sha256_hex(&live)));
    object.insert("body".into(), serde_json::Value::String(live));
    object.insert("body_state".into(), serde_json::json!("live"));
    object.insert("committed_body_digest".into(), serde_json::json!(committed));
}
