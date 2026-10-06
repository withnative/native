//! In-process live-session core for `session.body.v1`.
//!
//! One [`Session`] owns one Yjs [`Doc`] whose only root is a [`YText`]
//! named `body`. [`SessionRegistry`] multiplexes sessions by
//! `(database id, record id)` and peers within a session.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use yrs::types::text::YChange;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{
    Any, ClientID, Doc, GetString, Map, OffsetKind, Options, Out, ReadTxn, StateVector, Text,
    Transact, Update,
};

use super::refusal::{RefusalCode, Refused};

/// Root name of the single shared text holding the Markdown source.
pub const BODY_ROOT: &str = "body";
/// Largest committed/live body this core will hold (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Largest single update payload this core will integrate (64 KiB).
pub const MAX_UPDATE_BYTES: usize = 64 * 1024;
/// Backstop on the full encoded document state (4 MiB).
///
/// The text-length check below cannot see content that `get_string` skips
/// (embeds, attributes, parked structs), so the encoded state — the bytes
/// later increments will persist — is bounded independently at a small
/// multiple of the body budget.
pub const MAX_ENCODED_STATE_BYTES: usize = 4 * MAX_BODY_BYTES;
/// Max concurrent peers holding edit leases on one record.
pub const MAX_EDIT_PEERS: usize = 16;
/// Max concurrent view-only peers on one record.
pub const MAX_VIEW_PEERS: usize = 32;
/// Max distinct attributed identities retained per live session.
///
/// Pending-attribution memory limit, NOT an authority rule: it bounds how
/// much caller-supplied identity metadata one session can accumulate, so a
/// long-lived session cannot grow its ledger without bound. A perpetual
/// session lifetime is NOT itself a bound; draining the ledger into versions
/// (and any caller lifecycle around it) belongs to the version integration.
pub const MAX_ATTRIBUTED_IDENTITIES: usize = 1024;
/// Max aggregate UTF-8 bytes of `principal` + `executor_kind` across the
/// distinct attributed identities retained per live session.
///
/// Companion to [`MAX_ATTRIBUTED_IDENTITIES`]: the count cap alone does not
/// bound bytes. Same pending-attribution scope — not authority, not a claim
/// that the ledger is production-sized without version drain.
pub const MAX_ATTRIBUTED_IDENTITY_BYTES: usize = 64 * 1024;

/// First client id ever leased to a peer. Leases are `u32`, monotonic from
/// here, never reissued. Seed ids live in the disjoint high half of u32
/// (see [`SessionRegistry::draw_seed_client_id`]).
const FIRST_LEASED_CLIENT_ID: u32 = 2;

/// Provisional minimum for one refusal rotation: initial author, spare
/// rebuild author, reserved confirmed identity. Not a contract/M8a policy.
const OPEN_CLIENT_ID_POOL_SIZE: u32 = 3;

/// Base of the seed-id range: the high half of u32, disjoint from the lease
/// counter growing up from [`FIRST_LEASED_CLIENT_ID`].
const SEED_CLIENT_ID_BASE: u32 = 1 << 31;

/// Opaque id of a live session (one per record while peers are joined).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

/// Opaque id of one joined peer within a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

/// Whether a peer may author updates (`Edit`) or only read (`View`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerKind {
    Edit,
    View,
}

/// Parameters for [`SessionRegistry::open`].
#[derive(Debug, Clone)]
pub struct OpenParams {
    /// Caller-visible database id (part of the session key).
    pub database_id: String,
    /// Record id (part of the session key).
    pub record_id: String,
    /// Committed body to seed the doc when opening a fresh session.
    pub committed_body: String,
    /// Whether the joining peer wants edit or view access.
    pub kind: PeerKind,
    /// The caller decides record-type support for now: `false` refuses
    /// with [`RefusalCode::RecordUnsupported`] without touching the doc.
    pub record_supported: bool,
}

/// Successful [`SessionRegistry::open`]: everything a joiner needs.
#[derive(Debug, Clone)]
pub struct OpenOk {
    /// Session the peer joined (fresh or pre-existing).
    pub session_id: SessionId,
    /// This peer's opaque id for later calls.
    pub peer_id: PeerId,
    /// Yjs client ids leased to this peer (`u32`, unique within this registry,
    /// never reissued to another peer). Author new structs only with these.
    /// Ordered `[initial author, spare rebuild author, reserved confirmed]`:
    /// a provisional engine/SDK convention, not a normative contract count.
    pub client_ids: Vec<u32>,
    /// Full state of the live doc (sync-step-2, update encoding v1).
    pub sync_step2: Vec<u8>,
}

/// Successful [`SessionRegistry::apply_update`].
#[derive(Debug, Clone)]
pub struct Ack {
    /// New state vector of the live doc (encoded v1) — the peer's clock.
    pub state_vector: Vec<u8>,
    /// The accepted update bytes to broadcast to the other peers.
    pub broadcast: Vec<u8>,
}

/// Exact, immutable candidate minted by the registry, never caller-constructed.
///
/// This is correlation, not authorization or a SQL commit witness. The future
/// owned consumer must authenticate and hold the SAME owner lane from prepare
/// through precommit binding check, SQL commit, synchronous install and close.
/// No `Clone`: consuming or dropping the candidate cannot apply it twice.
pub(crate) struct PreparedUpdate {
    session_id: SessionId,
    peer_id: PeerId,
    before_binding: Arc<()>,
    before_epoch: u64,
    before_client_ids: HashSet<u32>,
    before_acknowledged: HashSet<AcknowledgedContributor>,
    before_acknowledged_bytes: usize,
    before_last_accepted: Option<AcknowledgedContributor>,
    doc: Doc,
    acknowledged: HashSet<AcknowledgedContributor>,
    acknowledged_bytes: usize,
    last_accepted: Option<AcknowledgedContributor>,
    mutation_epoch: u64,
    next_binding: Arc<()>,
    encoded_state: Vec<u8>,
    ack: Ack,
}

// Read-only commitments for the allocated future owned persistence consumer.
#[allow(dead_code)]
impl PreparedUpdate {
    /// Exact candidate bytes, already encoded during prepare, for a future
    /// immutable prepared-state commitment. This grants no issuance authority.
    pub(crate) fn encoded_state(&self) -> &[u8] {
        &self.encoded_state
    }

    pub(crate) fn epoch_before(&self) -> u64 {
        self.before_epoch
    }

    pub(crate) fn epoch_after(&self) -> u64 {
        self.mutation_epoch
    }

    /// Preencoded receipt/broadcast; publish only after owned commit/install/close.
    pub(crate) fn ack(&self) -> &Ack {
        &self.ack
    }
}

/// Allocation-free binding refusal, also usable after SQL commit. A postcommit
/// error is an invariant breach: the owner MUST poison/quarantine, withhold ACK
/// and refuse retries. The registry cannot poison a persistence owner itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparedUpdateMismatch {
    Session,
    Peer,
    State,
}

/// Opaque, immutable snapshot of a live session's versionable state.
///
/// Minted only by [`SessionRegistry::version_snapshot`]: fields and the
/// constructor are private, there is no `Clone`, and there is no public
/// editable drain token, so a caller cannot forge or edit one. It binds the
/// session's fresh [`SessionId`] (unique per session incarnation — a torn-down
/// session's id is gone, so a held snapshot then fails drain) and a private
/// mutation epoch.
///
/// It is identity/content **correlation only**: NOT proof that any event
/// committed, and NOT authority.
pub struct VersionSnapshot {
    session_id: SessionId,
    body: String,
    contributors: Vec<AcknowledgedContributor>,
    last_accepted: Option<AcknowledgedContributor>,
    mutation_epoch: u64,
}

impl VersionSnapshot {
    /// Session this snapshot was taken from.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Live body bytes captured at snapshot time.
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Distinct acknowledged contributors captured, sorted by
    /// `(principal, executor_kind)`.
    pub fn contributors(&self) -> &[AcknowledgedContributor] {
        &self.contributors
    }

    /// Last accepted attributed editor at snapshot time, if any.
    pub fn last_accepted(&self) -> Option<&AcknowledgedContributor> {
        self.last_accepted.as_ref()
    }
}

/// Result of [`SessionRegistry::drain_version_snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The epoch matched; the snapshot's contributors were removed.
    Drained,
    /// A later accepted state change moved the session's mutation epoch;
    /// nothing was removed. Exclusive-writer hosts never observe this.
    Stale,
}

/// Caller-supplied identity for one acknowledged update: who the trusted
/// caller says authored it, and in what capacity.
///
/// This is identity/correlation ONLY — never validated proof, never an
/// access grant. The core performs no authorization on these strings: the
/// trusted session host must supply only post-admission facts (e.g. mapped
/// from an admitted executor-identity snapshot), and the receipt-to-action
/// binding for co-edit operations remains a future integration dependency.
/// `None` at the apply seam means legacy-compat/no-attribution, never
/// "unauthenticated author allowed".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AcknowledgedContributor {
    /// Authenticated principal, as supplied by the trusted caller.
    pub principal: String,
    /// Executor kind, as supplied by the trusted caller.
    pub executor_kind: String,
}

impl AcknowledgedContributor {
    /// UTF-8 bytes this pair contributes to the ledger byte budget.
    /// Overflow-checked at the call site via saturating arithmetic.
    fn budgeted_bytes(&self) -> usize {
        self.principal
            .len()
            .saturating_add(self.executor_kind.len())
    }
}

/// One joined peer: its kind and the client ids leased to it.
#[derive(Debug)]
struct Peer {
    kind: PeerKind,
    client_ids: HashSet<u32>,
}

/// Whether a Yjs client id observed in an update counts as authored by
/// `peer`. Only u32 ids can ever be leased (or drawn as seeds), so anything
/// wider is foreign by construction — the conversion, not a truncation,
/// decides.
fn leased_to_peer(peer: &Peer, client: &ClientID) -> bool {
    u32::try_from(client.get())
        .map(|id| peer.client_ids.contains(&id))
        .unwrap_or(false)
}

/// Live state for one record: the doc, its joined peers, and the
/// session-owned acknowledged-contributor ledger.
///
/// The ledger (plus `last_accepted`) survives peer leave and kind changes
/// while the session lives: contributors whose ops landed stay listed for
/// the future version cut. It is dropped whole with the doc on terminal
/// teardown (last-peer leave) — this increment has no persistence, and the
/// future version owner must cut/extract before teardown. There is
/// deliberately no clear/drain API until the version transaction owns it.
struct Session {
    id: SessionId,
    doc: Doc,
    peers: HashMap<String, Peer>,
    acknowledged: HashSet<AcknowledgedContributor>,
    /// Aggregate [`AcknowledgedContributor::budgeted_bytes`] over `acknowledged`.
    acknowledged_bytes: usize,
    /// Contributor of the most recent state-changing acknowledged update
    /// (the last accepted attributed **editor**, which may differ from the
    /// last **peer**; the automatic-cut actor choice stays host-owned).
    last_accepted: Option<AcknowledgedContributor>,
    /// Monotonic count of accepted state-changing applies (attributed or
    /// not). A [`VersionSnapshot`] binds this epoch; drain refuses (`Stale`)
    /// once it moves, so a cut cannot consume a contributor whose ops landed
    /// after the snapshot.
    mutation_epoch: u64,
    /// Private identity of this exact installed doc state, not a numeric grant.
    /// A new candidate allocates its successor before any SQL commit.
    prepared_binding: Arc<()>,
}

impl Session {
    fn edit_peer_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.kind == PeerKind::Edit)
            .count()
    }

    fn view_peer_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.kind == PeerKind::View)
            .count()
    }
}

/// In-memory registry of live co-edit sessions, keyed by
/// `(database id, record id)`.
///
/// Single-writer by construction: every method takes `&mut self`, and the
/// registry performs no internal locking. The caller (eventually the
/// transport's per-database writer loop) must serialise all calls; sharing
/// this across threads without exterior synchronisation is a data race, not
/// just a logic error.
pub struct SessionRegistry {
    sessions: HashMap<(String, String), Session>,
    next_client_id: u32,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    /// Empty registry. The client-id lease counter starts at
    /// [`FIRST_LEASED_CLIENT_ID`]; seed ids are drawn per session from the
    /// disjoint high half of u32.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_client_id: FIRST_LEASED_CLIENT_ID,
        }
    }

    /// Prepare a contiguous low-half pool without consuming any ids.
    /// The caller commits the end-exclusive counter once after admission.
    fn prepare_client_id_pool(&self) -> Result<([u32; 3], u32), Refused> {
        let start = self.next_client_id;
        let end = start
            .checked_add(OPEN_CLIENT_ID_POOL_SIZE)
            .filter(|end| *end <= SEED_CLIENT_ID_BASE)
            .ok_or_else(|| {
                Refused::new(
                    RefusalCode::TooManyPeers,
                    "client-id lease space exhausted for a complete open pool",
                )
            })?;
        // The checked end bounds every member; no partial pool or wrap.
        Ok(([start, start + 1, start + 2], end))
    }

    /// Draw a fresh seed client id from the high half of u32, disjoint from
    /// leased ids. Sound by the lease-side partition above: the counter
    /// never reaches the seed range (exhaustion refuses first), so no
    /// issued or future lease can hold the drawn id; the debug assert pins
    /// that invariant in test builds.
    fn draw_seed_client_id(&self) -> u64 {
        let id = rand::random::<u32>() | SEED_CLIENT_ID_BASE;
        debug_assert!(
            id >= self.next_client_id,
            "lease counter entered the seed-id range"
        );
        u64::from(id)
    }

    /// Open (or join) the live session for a record.
    ///
    /// The first opener seeds the doc from `params.committed_body` (which is
    /// size-checked only on this path); later joiners get the live state and
    /// their `committed_body` is ignored entirely. Returns the session/peer
    /// ids, the client ids leased to this peer, and full-state sync-step-2
    /// bytes. A refused open consumes no client-id lease.
    pub fn open(&mut self, params: OpenParams) -> Result<OpenOk, Refused> {
        if !params.record_supported {
            return Err(Refused::new(
                RefusalCode::RecordUnsupported,
                "record type does not support live co-editing",
            ));
        }
        let key = (params.database_id.clone(), params.record_id.clone());
        let fresh = !self.sessions.contains_key(&key);
        if fresh && params.committed_body.len() > MAX_BODY_BYTES {
            return Err(Refused::new(
                RefusalCode::TooLarge,
                format!(
                    "committed body is {} bytes, limit is {MAX_BODY_BYTES}",
                    params.committed_body.len()
                ),
            ));
        }
        // A fresh candidate stays local until every refusal path has passed.
        let candidate = if fresh {
            Some(Session {
                id: SessionId(format!("sess-{}", uuid::Uuid::new_v4())),
                doc: seed_doc(&params.committed_body, self.draw_seed_client_id()),
                peers: HashMap::new(),
                acknowledged: HashSet::new(),
                acknowledged_bytes: 0,
                last_accepted: None,
                mutation_epoch: 0,
                prepared_binding: Arc::new(()),
            })
        } else {
            None
        };
        if let Some(session) = self.sessions.get(&key) {
            match params.kind {
                PeerKind::Edit if session.edit_peer_count() >= MAX_EDIT_PEERS => {
                    return Err(Refused::new(
                        RefusalCode::TooManyPeers,
                        format!("record already has {MAX_EDIT_PEERS} edit peers"),
                    ));
                }
                PeerKind::View if session.view_peer_count() >= MAX_VIEW_PEERS => {
                    return Err(Refused::new(
                        RefusalCode::TooManyPeers,
                        format!("record already has {MAX_VIEW_PEERS} view peers"),
                    ));
                }
                _ => {}
            }
        }
        let (leased, next_client_id) = self.prepare_client_id_pool()?;
        let peer_id = PeerId(format!("peer-{}", uuid::Uuid::new_v4()));
        let peer = Peer {
            kind: params.kind,
            client_ids: HashSet::from(leased),
        };
        // No Result refusal remains: publish the prepared room, peer and pool.
        let session = self
            .sessions
            .entry(key)
            .or_insert_with(|| candidate.expect("fresh room has a prepared candidate"));
        session.peers.insert(peer_id.0.clone(), peer);
        self.next_client_id = next_client_id;
        let sync_step2 = {
            let txn = session.doc.transact();
            txn.encode_state_as_update_v1(&StateVector::default())
        };
        Ok(OpenOk {
            session_id: session.id.clone(),
            peer_id,
            client_ids: leased.to_vec(),
            sync_step2,
        })
    }

    /// Look up a session by its opaque id (linear scan; session counts are
    /// small and this keeps a single map keyed by `(database, record)`).
    fn find_session(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.values().find(|s| s.id == *session_id)
    }

    fn find_session_mut(&mut self, session_id: &SessionId) -> Option<&mut Session> {
        self.sessions.values_mut().find(|s| s.id == *session_id)
    }
}

/// Seed a fresh doc from the committed body under `seed_client_id`.
///
/// Each seeding draws a random high-half id (see
/// [`SessionRegistry::draw_seed_client_id`]), independently of earlier seeds.
/// This separates seed and lease identities; two seed draws can still collide
/// with probability 1 / 2^31, so it is not a durable uniqueness guarantee.
/// Mechanics note (not a contract claim): a client that retains
/// prior-session structs and applies a new seed's full sync will merge both
/// histories; whether joiners must discard or resync is governed by the
/// session contract owned outside this module. The byte-offset contract is
/// pinned explicitly.
fn seed_doc(committed_body: &str, seed_client_id: u64) -> Doc {
    let mut options = Options::with_client_id(ClientID::new(seed_client_id));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    // The `body` root must ALWAYS exist as Y.Text — even for an empty body.
    // Yjs updates carry root *names*, not root *types*: a receiver that never
    // declared the root integrates it as an untyped branch, so skipping the
    // root for empty bodies would break every later client edit with a shape
    // refusal. Declaring it here keeps the single-root invariant total.
    let text = doc.get_or_insert_text(BODY_ROOT);
    if !committed_body.is_empty() {
        let mut txn = doc.transact_mut();
        text.insert(&mut txn, 0, committed_body);
    }
    doc
}

/// Byte-identical scratch clone of a live doc: full state encoded from
/// `src` is applied to a fresh throwaway doc carrying the live doc's own
/// client id and options, so the "identical clone" claim behind
/// validate-before-integrate is literally true (the id never authors
/// anything: no local edits are made on the clone).
/// The `body` root is declared up front: updates carry root *names*, not
/// root *types*, so without this the clone would integrate `body` as an
/// untyped branch and every validation would misfire.
///
/// Transaction-safety note: yrs transactions block (they do not error) when
/// a second transaction is opened on the same `Doc` while one is live —
/// including a read txn inside a write txn's scope. Every site here scopes
/// each transaction in its own block and never nests them; keep it that way
/// or single-threaded calls will self-deadlock.
fn clone_doc(src: &Doc) -> Doc {
    let full = {
        let txn = src.transact();
        txn.encode_state_as_update_v1(&StateVector::default())
    };
    let mut options = Options::with_client_id(src.client_id());
    options.offset_kind = OffsetKind::Bytes;
    let dst = Doc::with_options(options);
    let _body = dst.get_or_insert_text(BODY_ROOT);
    {
        let mut txn = dst.transact_mut();
        txn.apply_update(Update::decode_v1(&full).expect("own state re-decodes"))
            .expect("full state applies to a fresh doc");
    }
    dst
}

impl SessionRegistry {
    /// Apply a peer's update (v1 bytes) to the live doc, unattributed.
    ///
    /// Legacy entry point: behavior is exactly the unattributed path —
    /// nothing is recorded in the acknowledged-contributor ledger. Trusted
    /// callers that can attribute use [`SessionRegistry::apply_update_attributed`].
    pub fn apply_update(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
        update_v1: &[u8],
    ) -> Result<Ack, Refused> {
        let prepared = self.prepare_update(session_id, peer_id, update_v1, None)?;
        self.install_prepared_update(session_id, peer_id, prepared)
            .map_err(|_| Refused::new(RefusalCode::BadDocShape, "prepared update binding changed"))
    }

    /// Apply a peer's update with trusted-caller attribution.
    ///
    /// `contributor` is caller-supplied identity/correlation ONLY (see
    /// [`AcknowledgedContributor`]): it is recorded in the session ledger
    /// and as last-accepted contributor if and only if the update passes
    /// every admission check, integrates into the live doc, AND adds new
    /// CRDT state (inserts, real deletions, or net-zero insert+delete that
    /// still advances clocks). Replays that add no new state are still
    /// acknowledged but record nothing, so relay identity is never stamped.
    /// Any refusal, view-mode call, or no-op leaves ledger and last
    /// untouched. A prospective NEW ledger entry that would exceed
    /// [`MAX_ATTRIBUTED_IDENTITIES`] or [`MAX_ATTRIBUTED_IDENTITY_BYTES`]
    /// is refused with [`RefusalCode::TooLarge`] before the live doc is
    /// touched; already-ledgered identities and no-ops need no new quota.
    pub fn apply_update_attributed(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
        update_v1: &[u8],
        contributor: &AcknowledgedContributor,
    ) -> Result<Ack, Refused> {
        let prepared = self.prepare_update(session_id, peer_id, update_v1, Some(contributor))?;
        self.install_prepared_update(session_id, peer_id, prepared)
            .map_err(|_| Refused::new(RefusalCode::BadDocShape, "prepared update binding changed"))
    }

    /// Decode, apply and fully allocate on a scratch doc; live state is untouched.
    /// `contributor` remains trusted-caller correlation, never an auth shortcut.
    pub(crate) fn prepare_update(
        &self,
        session_id: &SessionId,
        peer_id: &PeerId,
        update_v1: &[u8],
        contributor: Option<&AcknowledgedContributor>,
    ) -> Result<PreparedUpdate, Refused> {
        // Checks run in this order: edit mode, update size, then — on a
        // scratch clone — pending dependencies, doc shape, resulting size,
        // encoded-state size, authorship. A refused update is dropped whole:
        // the live doc is only touched after every check has passed on the
        // clone, so it is byte-identical to before on every refusal path.
        //
        // Note the deliberate deviation from the slice brief's bullet order
        // (size, authorship, shape): shape is evaluated *before* authorship
        // so that a shape-breaking update is always reported as
        // `bad_doc_shape`, no matter whose client id authored it.
        // Authorship is only meaningful for well-shaped text updates; size
        // and authorship of an update that would corrupt the doc shape are
        // moot.
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let peer = session.peers.get(&peer_id.0).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "peer has not joined this session",
            )
        })?;
        if peer.kind != PeerKind::Edit {
            return Err(Refused::new(
                RefusalCode::Forbidden,
                "view-mode peers cannot author updates",
            ));
        }
        if update_v1.len() > MAX_UPDATE_BYTES {
            return Err(Refused::new(
                RefusalCode::TooLarge,
                format!(
                    "update is {} bytes, limit is {MAX_UPDATE_BYTES}",
                    update_v1.len()
                ),
            ));
        }
        // Decode before integrating: undecodable bytes are a shape refusal,
        // and nothing has touched the live doc yet.
        let decoded = Update::decode_v1(update_v1).map_err(|e| {
            Refused::new(
                RefusalCode::BadDocShape,
                format!("update is not decodable as Yjs update v1: {e}"),
            )
        })?;
        // Authorship bounds from the update's own blocks, captured before
        // `decoded` moves into the scratch apply below: the upper bound for
        // continuous ranges, the lower bound for first-block clocks of
        // gapped ranges (which the upper bound skips). Compared against the
        // live state vector at check time.
        let update_upper = decoded.state_vector();
        let update_lower = decoded.state_vector_lower();
        // Validate on a scratch clone of the live doc. yrs integrates an
        // update as one transaction, but a partially-valid update must not
        // leave partial state behind — so the live doc is only touched
        // after every check below has passed on the clone.
        let scratch = clone_doc(&session.doc);
        // Whether this update newly deletes anything: yrs records a range
        // in the transaction delete set only when it actually marks an
        // item deleted, so replays of already-deleted ranges contribute
        // nothing here. Read before the transaction drops.
        let applied_new_deletes = {
            let mut txn = scratch.transact_mut();
            txn.apply_update(decoded).map_err(|e| {
                Refused::new(
                    RefusalCode::BadDocShape,
                    format!("update does not apply cleanly: {e}"),
                )
            })?;
            !txn.delete_set().is_empty()
        };
        // A struct with missing dependencies parks in yrs' pending set
        // without moving the state vector — the authorship-forgery shape
        // (plant a victim-authored struct now, let it integrate silently
        // under a later legitimate update). Legitimate sync steps and diffs
        // are always self-contained, so anything left pending is hostile.
        if scratch.transact().has_missing_updates() {
            return Err(Refused::new(
                RefusalCode::BadDocShape,
                "update leaves unresolved dependencies",
            ));
        }
        // Whether this update adds new CRDT state (not relayed history) is
        // decided alongside admission on the scratch twin below; replays of
        // known state advance neither signal and record nothing.
        let (new_state, encoded_state) = {
            let txn = scratch.transact();
            let mut roots = txn.root_refs();
            let body_text = match (roots.next(), roots.next()) {
                (Some((BODY_ROOT, Out::YText(body))), None) => {
                    // Same-name cross-type smuggling: a hostile client can
                    // author e.g. a Y.Map on root `body`. yrs resolves roots
                    // by name (first-declared type wins), so the root stays
                    // Y.Text while the map entries merge invisibly into the
                    // branch's map slots. Refuse that too: the body branch
                    // must carry no map entries.
                    let smuggled = txn.get_map(BODY_ROOT).is_some_and(|m| m.len(&txn) > 0);
                    // Non-text content smuggling: embeds, nested shared
                    // types, array-pushed values and format attributes are
                    // all invisible to `get_string` (and uncounted by the
                    // size check below). Every visible chunk must therefore
                    // be a plain string with no attributes, and the text
                    // length must equal the string bytes (`diff` skips
                    // array-pushed `Any` values, but `len` counts them).
                    // Deleted items appear in neither, which is exactly the
                    // "deleted is fine" rule.
                    let plain = body.diff(&txn, YChange::identity).into_iter().all(|chunk| {
                        chunk.attributes.is_none()
                            && matches!(chunk.insert, Out::Any(Any::String(_)))
                    });
                    let body_string = body.get_string(&txn);
                    let len_matches = body.len(&txn) == body_string.len() as u32;
                    if smuggled || !plain || !len_matches {
                        None
                    } else {
                        Some(body_string)
                    }
                }
                _ => None,
            };
            drop(txn);
            if body_text.is_none() {
                return Err(Refused::new(
                    RefusalCode::BadDocShape,
                    "update must touch only root `body` of type text",
                ));
            }
            let body_len = body_text.as_ref().map(|t| t.len());
            if body_len.is_some_and(|len| len > MAX_BODY_BYTES) {
                return Err(Refused::new(
                    RefusalCode::TooLarge,
                    format!(
                        "resulting body is {} bytes, limit is {MAX_BODY_BYTES}",
                        body_len.expect("just checked Some")
                    ),
                ));
            }
            // Backstop for state invisible to the text checks above: the
            // full encoded state is bounded independently so uncounted
            // content cannot grow persistence without bound.
            let encoded_state = scratch
                .transact()
                .encode_state_as_update_v1(&StateVector::default());
            let encoded_len = encoded_state.len();
            if encoded_len > MAX_ENCODED_STATE_BYTES {
                return Err(Refused::new(
                    RefusalCode::TooLarge,
                    format!(
                        "encoded document state is {encoded_len} bytes, \
                         limit is {MAX_ENCODED_STATE_BYTES}"
                    ),
                ));
            }
            let before = session.doc.transact().state_vector();
            // Authorship from the update's own blocks (upper and lower
            // bounds), not just from integrated state-vector deltas: a
            // parked-pending struct moves no clock, so deltas alone miss it.
            let from_blocks = update_upper
                .iter()
                .chain(update_lower.iter())
                .any(|(client, _)| {
                    let known = before.get(client);
                    (update_upper.get(client) > known || update_lower.get(client) > known)
                        && !leased_to_peer(peer, client)
                });
            let after = scratch.transact().state_vector();
            let from_delta = after.iter().any(|(client, _)| {
                after.get(client) > before.get(client) && !leased_to_peer(peer, client)
            });
            if from_blocks || from_delta {
                return Err(Refused::new(
                    RefusalCode::ForeignClientId,
                    "update authors new structs with a client id \
                     not leased to this peer",
                ));
            }
            // Any clock the scratch twin advanced past the live doc covers
            // inserts and net-zero insert+delete (which still lands the
            // insert's clocks); `applied_new_deletes` covers delete-only
            // updates, which move no clocks.
            (
                after
                    .iter()
                    .any(|(client, _)| after.get(client) > before.get(client))
                    || applied_new_deletes,
                encoded_state,
            )
        };
        // The exact validated scratch candidate will be installed by move.
        // There is no second decode/apply into the live doc.
        //
        // Pending-attribution budget for a prospective NEW ledger entry,
        // checked only for state-changing attributed updates after admission
        // and before the live doc is touched. Already-ledgered identities
        // and no-ops need no new quota. Refusal here mutates nothing: not
        // the body, state vector, ledger, or last-accepted contributor. The
        // detail names no identity material.
        // Mutation epoch: ANY accepted state-changing apply advances it,
        // attributed or not, so a snapshot taken before this apply can never
        // be drained afterwards. Checked BEFORE live integration and OUTSIDE
        // the contributor match, so an exhausted epoch refuses atomically
        // (no body, state-vector, ledger, or epoch change) with no wrap and
        // no panic. No-op/duplicate/refused/refused applies never advance it.
        let next_mutation_epoch = if new_state {
            Some(session.mutation_epoch.checked_add(1).ok_or_else(|| {
                Refused::new(RefusalCode::TooLarge, "session mutation epoch exhausted")
            })?)
        } else {
            None
        };
        let stamp = match contributor {
            Some(fact) if new_state && !session.acknowledged.contains(fact) => {
                let entry_bytes = fact.budgeted_bytes();
                let over_count = session.acknowledged.len() >= MAX_ATTRIBUTED_IDENTITIES;
                let over_bytes = session.acknowledged_bytes.saturating_add(entry_bytes)
                    > MAX_ATTRIBUTED_IDENTITY_BYTES;
                if over_count || over_bytes {
                    return Err(Refused::new(
                        RefusalCode::TooLarge,
                        "attributed contributor ledger budget exhausted",
                    ));
                }
                Some((fact.clone(), entry_bytes))
            }
            Some(fact) if new_state => Some((fact.clone(), 0)),
            _ => None,
        };
        // Allocate the complete successor ledger and receipt before returning.
        // Installation performs only binding comparisons and owned field moves.
        let mut acknowledged = session.acknowledged.clone();
        let mut acknowledged_bytes = session.acknowledged_bytes;
        let mut last_accepted = session.last_accepted.clone();
        if let Some((fact, entry_bytes)) = stamp {
            if acknowledged.insert(fact.clone()) {
                acknowledged_bytes = acknowledged_bytes.saturating_add(entry_bytes);
            }
            last_accepted = Some(fact);
        }
        let ack = Ack {
            state_vector: scratch.transact().state_vector().encode_v1(),
            broadcast: update_v1.to_vec(),
        };
        Ok(PreparedUpdate {
            session_id: session_id.clone(),
            peer_id: peer_id.clone(),
            before_binding: Arc::clone(&session.prepared_binding),
            before_epoch: session.mutation_epoch,
            before_client_ids: peer.client_ids.clone(),
            before_acknowledged: session.acknowledged.clone(),
            before_acknowledged_bytes: session.acknowledged_bytes,
            before_last_accepted: session.last_accepted.clone(),
            doc: scratch,
            acknowledged,
            acknowledged_bytes,
            last_accepted,
            mutation_epoch: next_mutation_epoch.unwrap_or(session.mutation_epoch),
            next_binding: Arc::new(()),
            encoded_state,
            ack,
        })
    }

    /// Check this exact candidate against the target before a future SQL write.
    /// The owner must retain its lane and immutable auth/domain binding through
    /// commit/install. IDs and epochs here are correlation, not authorization.
    /// No decoding, encoding, allocation or live mutation occurs in this check.
    pub(crate) fn validate_prepared_update(
        &self,
        session_id: &SessionId,
        peer_id: &PeerId,
        prepared: &PreparedUpdate,
    ) -> Result<(), PreparedUpdateMismatch> {
        let session = self
            .find_session(session_id)
            .ok_or(PreparedUpdateMismatch::Session)?;
        Self::validate_prepared_session(session, session_id, peer_id, prepared)
    }

    fn validate_prepared_session(
        session: &Session,
        session_id: &SessionId,
        peer_id: &PeerId,
        prepared: &PreparedUpdate,
    ) -> Result<(), PreparedUpdateMismatch> {
        if prepared.session_id != *session_id {
            return Err(PreparedUpdateMismatch::Session);
        }
        if prepared.peer_id != *peer_id {
            return Err(PreparedUpdateMismatch::Peer);
        }
        let peer = session
            .peers
            .get(&peer_id.0)
            .ok_or(PreparedUpdateMismatch::Peer)?;
        if peer.kind != PeerKind::Edit || peer.client_ids != prepared.before_client_ids {
            return Err(PreparedUpdateMismatch::Peer);
        }
        // Epoch alone misses a version drain. Compare the preimage ledger too,
        // without recomputation/encoding; otherwise install could resurrect
        // already versioned contributors. Private Arc identity also binds the
        // exact registry/session doc and changes even on duplicate installs.
        if !Arc::ptr_eq(&session.prepared_binding, &prepared.before_binding)
            || session.mutation_epoch != prepared.before_epoch
            || session.acknowledged != prepared.before_acknowledged
            || session.acknowledged_bytes != prepared.before_acknowledged_bytes
            || session.last_accepted != prepared.before_last_accepted
        {
            return Err(PreparedUpdateMismatch::State);
        }
        Ok(())
    }

    /// Synchronously install the exact scratch candidate and return its encoded
    /// ACK. No await, decode, apply, encode, allocation or partial mutation.
    /// A stale/mismatched value refuses BEFORE any field moves. After a future
    /// SQL commit this error requires caller poison, never retry/replay/ACK.
    pub(crate) fn install_prepared_update(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
        prepared: PreparedUpdate,
    ) -> Result<Ack, PreparedUpdateMismatch> {
        self.validate_prepared_update(session_id, peer_id, &prepared)?;
        let session = self
            .find_session_mut(session_id)
            .ok_or(PreparedUpdateMismatch::Session)?;
        session.doc = prepared.doc;
        session.acknowledged = prepared.acknowledged;
        session.acknowledged_bytes = prepared.acknowledged_bytes;
        session.last_accepted = prepared.last_accepted;
        session.mutation_epoch = prepared.mutation_epoch;
        session.prepared_binding = prepared.next_binding;
        Ok(prepared.ack)
    }

    /// Current live body bytes for a session.
    pub fn live_body(&self, session_id: &SessionId) -> Result<String, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let txn = session.doc.transact();
        let mut roots = txn.root_refs();
        match (roots.next(), roots.next()) {
            (Some((BODY_ROOT, Out::YText(body))), None) => Ok(body.get_string(&txn)),
            _ => Err(Refused::new(
                RefusalCode::BadDocShape,
                "live doc does not hold exactly root `body` of type text",
            )),
        }
    }

    /// Current state vector of the live doc (encoded v1).
    pub fn state_vector(&self, session_id: &SessionId) -> Result<Vec<u8>, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        Ok(session.doc.transact().state_vector().encode_v1())
    }

    /// Read-only witness for every accepted CRDT state change, including
    /// deletions that leave the state vector unchanged and net-zero edits.
    /// Scoped to this live session incarnation; it grants no authority.
    pub(crate) fn mutation_epoch(&self, session_id: &SessionId) -> Result<u64, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        Ok(session.mutation_epoch)
    }

    /// Distinct attributed contributors whose updates landed new CRDT state
    /// in this session, in stable `(principal, executor_kind)` order.
    ///
    /// Retention set for the future version cut: it survives peer leave and
    /// kind changes while the session lives and is dropped whole with the
    /// doc on terminal teardown. An unknown session id is refused with
    /// [`RefusalCode::UndeclaredSession`] rather than hidden as empty.
    pub fn acknowledged_contributors(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<AcknowledgedContributor>, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let mut out: Vec<AcknowledgedContributor> = session.acknowledged.iter().cloned().collect();
        out.sort_by(|a, b| (&a.principal, &a.executor_kind).cmp(&(&b.principal, &b.executor_kind)));
        Ok(out)
    }

    /// Contributor of the most recent state-changing acknowledged update, if
    /// any (the eventual automatic-version actor). Same refusal contract as
    /// [`SessionRegistry::acknowledged_contributors`].
    pub fn last_accepted_contributor(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<AcknowledgedContributor>, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        Ok(session.last_accepted.clone())
    }

    /// Snapshot the versionable state of a live session.
    ///
    /// Read-only: it captures the live body, the distinct acknowledged
    /// contributors (sorted), the last accepted attributed editor, and the
    /// session's mutation epoch. Minted only here — [`VersionSnapshot`] has
    /// private fields, a private constructor, and no `Clone`, so a caller
    /// can neither forge nor edit one, and drain consumes only a
    /// registry-minted value.
    ///
    /// The value is identity/content **correlation only**: it is not proof
    /// that any event committed and confers no authority. Drain it only
    /// AFTER the version event has committed, and (host contract) only while
    /// holding exclusive per-DB writer ownership across snapshot → append →
    /// commit → drain. Unknown session id → [`RefusalCode::UndeclaredSession`].
    pub fn version_snapshot(&self, session_id: &SessionId) -> Result<VersionSnapshot, Refused> {
        let body = self.live_body(session_id)?;
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let mut contributors: Vec<AcknowledgedContributor> =
            session.acknowledged.iter().cloned().collect();
        contributors.sort_by(|a, b| {
            (&a.principal, &a.executor_kind).cmp(&(&b.principal, &b.executor_kind))
        });
        Ok(VersionSnapshot {
            session_id: session_id.clone(),
            body,
            contributors,
            last_accepted: session.last_accepted.clone(),
            mutation_epoch: session.mutation_epoch,
        })
    }

    /// Drain a snapshot's contributors after its version event has committed.
    ///
    /// Requires a genuine [`VersionSnapshot`] and the session's current epoch
    /// to match the snapshot's. A session that has been torn down (last-peer
    /// [`SessionRegistry::leave`]) → [`RefusalCode::UndeclaredSession`]; a
    /// session whose epoch has since moved → [`DrainOutcome::Stale`], and
    /// NOTHING is mutated. On match, exactly the snapshot's contributors are
    /// removed and `acknowledged_bytes` is recomputed from the retained set
    /// (so a repeated drain of the same snapshot removes nothing further and
    /// never subtracts bytes twice). `last_accepted` is preserved: contract
    /// §5's automatic-cut actor is the last accepted attributed editor, and
    /// the next accepted attributed mutation replaces it.
    ///
    /// `Stale` detects a host that interleaved an apply during the cut. It is
    /// NOT multiplexed-host support: retaining a contributor whose ops were
    /// already versioned would duplicate attribution in the next version, so
    /// interleaved hosts are unsupported and the exclusive writer is
    /// mandatory.
    pub fn drain_version_snapshot(
        &mut self,
        snapshot: &VersionSnapshot,
    ) -> Result<DrainOutcome, Refused> {
        let session = self.find_session_mut(&snapshot.session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        if session.mutation_epoch != snapshot.mutation_epoch {
            return Ok(DrainOutcome::Stale);
        }
        for contributor in &snapshot.contributors {
            session.acknowledged.remove(contributor);
        }
        // Recompute from the retained set rather than subtracting, so a
        // repeated drain is exactly idempotent in time and byte accounting.
        session.acknowledged_bytes = session
            .acknowledged
            .iter()
            .map(AcknowledgedContributor::budgeted_bytes)
            .sum();
        Ok(DrainOutcome::Drained)
    }

    /// Update bytes (v1) carrying everything since `since_state_vector`.
    ///
    /// An undecodable `since` is a [`RefusalCode::BadDocShape`] refusal:
    /// it describes no position in this doc's history.
    pub fn encode_diff(
        &self,
        session_id: &SessionId,
        since_state_vector: &[u8],
    ) -> Result<Vec<u8>, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let since = StateVector::decode_v1(since_state_vector).map_err(|e| {
            Refused::new(
                RefusalCode::BadDocShape,
                format!("since state vector is not decodable: {e}"),
            )
        })?;
        Ok(session.doc.transact().encode_diff_v1(&since))
    }

    /// Remove a peer; drops the session once the last peer leaves.
    ///
    /// A dropped session loses its live doc (this increment has no
    /// persistence): the next [`SessionRegistry::open`] re-seeds from the
    /// committed body. The acknowledged-contributor ledger and
    /// last-accepted contributor survive non-terminal leaves and are dropped
    /// whole with the doc on terminal teardown; the future version owner
    /// must cut/extract them before the last leave. Returns `true` when the
    /// peer was joined.
    pub fn leave(&mut self, session_id: &SessionId, peer_id: &PeerId) -> bool {
        let mut empty = false;
        let mut removed = false;
        if let Some(session) = self.find_session_mut(session_id) {
            removed = session.peers.remove(&peer_id.0).is_some();
            empty = session.peers.is_empty();
        }
        if empty {
            self.sessions.retain(|_, s| s.id != *session_id);
        }
        removed
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    fn params() -> OpenParams {
        OpenParams {
            database_id: "db".into(),
            record_id: "record".into(),
            committed_body: "body".into(),
            kind: PeerKind::Edit,
            record_supported: true,
        }
    }

    #[test]
    fn default_registry_opens_with_the_same_lease_range_as_new() {
        let mut registry = SessionRegistry::default();
        assert_eq!(
            registry.open(params()).unwrap().client_ids,
            vec![
                FIRST_LEASED_CLIENT_ID,
                FIRST_LEASED_CLIENT_ID + 1,
                FIRST_LEASED_CLIENT_ID + 2
            ]
        );
    }

    /// Compare every registry-owned state affected by admission or apply.
    fn fingerprint(registry: &SessionRegistry) -> (u32, Vec<String>) {
        let mut rooms = Vec::new();
        for (key, session) in &registry.sessions {
            let mut peers: Vec<_> = session
                .peers
                .iter()
                .map(|(id, peer)| {
                    let mut ids: Vec<_> = peer.client_ids.iter().copied().collect();
                    ids.sort_unstable();
                    (id.clone(), format!("{:?}", peer.kind), ids)
                })
                .collect();
            peers.sort();
            let mut contributors: Vec<_> = session
                .acknowledged
                .iter()
                .map(|fact| (fact.principal.clone(), fact.executor_kind.clone()))
                .collect();
            contributors.sort();
            let txn = session.doc.transact();
            rooms.push(format!(
                "{key:?} {:?} {peers:?} {:?} {:?} {:?} {contributors:?} {} {:?} {}",
                session.id,
                txn.encode_state_as_update_v1(&StateVector::default()),
                txn.state_vector().encode_v1(),
                registry.live_body(&session.id).unwrap(),
                session.acknowledged_bytes,
                session.last_accepted,
                session.mutation_epoch
            ));
        }
        rooms.sort();
        (registry.next_client_id, rooms)
    }

    #[test]
    fn final_complete_pool_succeeds_for_both_kinds() {
        for kind in [PeerKind::Edit, PeerKind::View] {
            let mut registry = SessionRegistry::new();
            registry.next_client_id = SEED_CLIENT_ID_BASE - 3;
            let joined = registry.open(OpenParams { kind, ..params() }).unwrap();
            assert_eq!(
                joined.client_ids,
                vec![
                    SEED_CLIENT_ID_BASE - 3,
                    SEED_CLIENT_ID_BASE - 2,
                    SEED_CLIENT_ID_BASE - 1
                ]
            );
            assert_eq!(registry.next_client_id, SEED_CLIENT_ID_BASE);
            let peer = &registry.sessions.values().next().unwrap().peers[&joined.peer_id.0];
            assert_eq!(
                peer.client_ids,
                joined.client_ids.iter().copied().collect::<HashSet<_>>()
            );
            assert!(registry.draw_seed_client_id() >= u64::from(SEED_CLIENT_ID_BASE));
            let before = fingerprint(&registry);
            assert_eq!(
                registry.open(params()).unwrap_err().code,
                RefusalCode::TooManyPeers
            );
            assert_eq!(fingerprint(&registry), before);
        }
    }

    #[test]
    fn final_complete_pool_can_join_an_existing_room() {
        for kind in [PeerKind::Edit, PeerKind::View] {
            let mut registry = SessionRegistry::new();
            let first = registry.open(params()).unwrap();
            let body = registry.live_body(&first.session_id).unwrap();
            let sv = registry.state_vector(&first.session_id).unwrap();
            registry.next_client_id = SEED_CLIENT_ID_BASE - 3;
            let joined = registry.open(OpenParams { kind, ..params() }).unwrap();
            assert_eq!(joined.session_id, first.session_id);
            assert_eq!(
                joined.client_ids,
                vec![
                    SEED_CLIENT_ID_BASE - 3,
                    SEED_CLIENT_ID_BASE - 2,
                    SEED_CLIENT_ID_BASE - 1
                ]
            );
            assert_eq!(registry.next_client_id, SEED_CLIENT_ID_BASE);
            assert_eq!(registry.live_body(&first.session_id).unwrap(), body);
            assert_eq!(registry.state_vector(&first.session_id).unwrap(), sv);
            assert_eq!(registry.sessions.len(), 1);
            assert_eq!(registry.sessions.values().next().unwrap().peers.len(), 2);
        }
    }

    #[test]
    fn incomplete_pool_refuses_repeatedly_without_any_registry_mutation() {
        for next in [
            SEED_CLIENT_ID_BASE - 2,
            SEED_CLIENT_ID_BASE - 1,
            SEED_CLIENT_ID_BASE,
        ] {
            for kind in [PeerKind::Edit, PeerKind::View] {
                let mut registry = SessionRegistry::new();
                registry.open(params()).unwrap();
                registry.next_client_id = next;
                let before = fingerprint(&registry);
                for _ in 0..3 {
                    for record in ["record", "fresh"] {
                        assert_eq!(
                            registry
                                .open(OpenParams {
                                    record_id: record.into(),
                                    kind,
                                    ..params()
                                })
                                .unwrap_err()
                                .code,
                            RefusalCode::TooManyPeers
                        );
                        assert_eq!(fingerprint(&registry), before);
                    }
                }
            }
        }
        // Even a corrupted counter that would overflow is a pure refusal.
        let mut registry = SessionRegistry::new();
        registry.next_client_id = u32::MAX;
        assert!(registry.prepare_client_id_pool().is_err());
        assert_eq!(registry.next_client_id, u32::MAX);
        assert!(registry.sessions.is_empty());
    }

    #[test]
    fn admission_caps_and_unsupported_or_oversize_opens_do_not_burn_pools() {
        let mut registry = SessionRegistry::new();
        for (kind, cap) in [
            (PeerKind::Edit, MAX_EDIT_PEERS),
            (PeerKind::View, MAX_VIEW_PEERS),
        ] {
            for _ in 0..cap {
                registry.open(OpenParams { kind, ..params() }).unwrap();
            }
            let before = fingerprint(&registry);
            for _ in 0..2 {
                assert_eq!(
                    registry
                        .open(OpenParams { kind, ..params() })
                        .unwrap_err()
                        .code,
                    RefusalCode::TooManyPeers
                );
                assert_eq!(fingerprint(&registry), before);
            }
        }
        assert_eq!(registry.next_client_id, FIRST_LEASED_CLIENT_ID + 144);
        for record in ["record", "fresh"] {
            let before = fingerprint(&registry);
            assert_eq!(
                registry
                    .open(OpenParams {
                        record_id: record.into(),
                        record_supported: false,
                        ..params()
                    })
                    .unwrap_err()
                    .code,
                RefusalCode::RecordUnsupported
            );
            assert_eq!(fingerprint(&registry), before);
        }
        let before = fingerprint(&registry);
        assert_eq!(
            registry
                .open(OpenParams {
                    record_id: "fresh".into(),
                    committed_body: "x".repeat(MAX_BODY_BYTES + 1),
                    ..params()
                })
                .unwrap_err()
                .code,
            RefusalCode::TooLarge
        );
        assert_eq!(fingerprint(&registry), before);
    }

    #[test]
    fn refused_updates_do_not_change_registry_state_or_consume_ids() {
        let mut registry = SessionRegistry::new();
        let editor = registry.open(params()).unwrap();
        let viewer = registry
            .open(OpenParams {
                kind: PeerKind::View,
                ..params()
            })
            .unwrap();
        let before = fingerprint(&registry);
        for client in editor
            .client_ids
            .iter()
            .copied()
            .map(u64::from)
            .chain([u64::from(u32::MAX) + 1])
        {
            let doc = Doc::with_options(Options::with_client_id(ClientID::new(client)));
            doc.get_or_insert_text(BODY_ROOT)
                .insert(&mut doc.transact_mut(), 0, "evil");
            let update = doc
                .transact()
                .encode_state_as_update_v1(&StateVector::default());
            let code = registry
                .apply_update(&editor.session_id, &viewer.peer_id, &update)
                .unwrap_err()
                .code;
            assert_eq!(code, RefusalCode::Forbidden);
            assert_eq!(fingerprint(&registry), before);
            // Editor's own IDs are allowed; every other ID below is foreign.
            if client >= u64::from(SEED_CLIENT_ID_BASE) {
                assert_eq!(
                    registry
                        .apply_update(&editor.session_id, &editor.peer_id, &update)
                        .unwrap_err()
                        .code,
                    RefusalCode::ForeignClientId
                );
                assert_eq!(fingerprint(&registry), before);
            }
        }
        for client in &viewer.client_ids {
            let doc = Doc::with_options(Options::with_client_id(ClientID::new(u64::from(*client))));
            doc.get_or_insert_text(BODY_ROOT)
                .insert(&mut doc.transact_mut(), 0, "foreign");
            let update = doc
                .transact()
                .encode_state_as_update_v1(&StateVector::default());
            assert_eq!(
                registry
                    .apply_update(&editor.session_id, &editor.peer_id, &update)
                    .unwrap_err()
                    .code,
                RefusalCode::ForeignClientId
            );
            assert_eq!(fingerprint(&registry), before);
            assert_eq!(
                registry
                    .apply_update(&viewer.session_id, &viewer.peer_id, &update)
                    .unwrap_err()
                    .code,
                RefusalCode::Forbidden
            );
            assert_eq!(fingerprint(&registry), before);
        }
        // A real seeded author must also be refused for NEW structs (known
        // seed structs alone are legitimate resync history).
        let seed_sv = Update::decode_v1(&editor.sync_step2)
            .unwrap()
            .state_vector();
        let seed = seed_sv.iter().next().unwrap().0.get();
        assert!(seed >= u64::from(SEED_CLIENT_ID_BASE));
        let doc = Doc::with_options(Options::with_client_id(ClientID::new(seed)));
        doc.transact_mut()
            .apply_update(Update::decode_v1(&editor.sync_step2).unwrap())
            .unwrap();
        let sv = doc.transact().state_vector();
        doc.get_or_insert_text(BODY_ROOT)
            .insert(&mut doc.transact_mut(), 0, "forged seed");
        let update = doc.transact().encode_diff_v1(&sv);
        assert_eq!(
            registry
                .apply_update(&editor.session_id, &editor.peer_id, &update)
                .unwrap_err()
                .code,
            RefusalCode::ForeignClientId
        );
        assert_eq!(fingerprint(&registry), before);
        for (update, expected) in [
            (vec![255], RefusalCode::BadDocShape),
            (vec![0; MAX_UPDATE_BYTES + 1], RefusalCode::TooLarge),
        ] {
            assert_eq!(
                registry
                    .apply_update(&editor.session_id, &editor.peer_id, &update)
                    .unwrap_err()
                    .code,
                expected
            );
            assert_eq!(fingerprint(&registry), before);
        }
    }

    #[test]
    fn demotion_flip_keeps_ledger_and_refuses_new_attributed_applies() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let fact = AcknowledgedContributor {
            principal: "alice".into(),
            executor_kind: "human".into(),
        };
        // Seed one landed attribution through the admitted test-only path:
        // direct ledger insert mirrors a stamped apply without yrs clients.
        let session = registry
            .sessions
            .values_mut()
            .find(|s| s.id == joined.session_id)
            .expect("session");
        session.acknowledged.insert(fact.clone());
        session.last_accepted = Some(fact.clone());
        // Demote the only peer (simulated kind flip; no public
        // promote/demote authority seam exists in this foundation).
        {
            let session = registry
                .sessions
                .values_mut()
                .find(|s| s.id == joined.session_id)
                .expect("session");
            session.peers.get_mut(&joined.peer_id.0).expect("peer").kind = PeerKind::View;
        }
        // New applies refuse as view-mode; ledger and last are untouched.
        let refused = registry
            .apply_update_attributed(
                &joined.session_id,
                &joined.peer_id,
                &[],
                &AcknowledgedContributor {
                    principal: "mallory".into(),
                    executor_kind: "agent".into(),
                },
            )
            .expect_err("demoted peer cannot author");
        assert_eq!(refused.code, RefusalCode::Forbidden);
        assert_eq!(
            registry
                .acknowledged_contributors(&joined.session_id)
                .expect("readout"),
            vec![fact.clone()]
        );
        assert_eq!(
            registry
                .last_accepted_contributor(&joined.session_id)
                .expect("readout"),
            Some(fact)
        );
    }

    #[test]
    fn epoch_overflow_refuses_atomically_before_live_integration() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let fact = AcknowledgedContributor {
            principal: "alice".into(),
            executor_kind: "human".into(),
        };
        registry
            .sessions
            .values_mut()
            .find(|s| s.id == joined.session_id)
            .expect("session")
            .mutation_epoch = u64::MAX;
        let body_before = registry.live_body(&joined.session_id).unwrap();
        let sv_before = registry.state_vector(&joined.session_id).unwrap();
        // A genuine state-changing update from the peer's leased client id.
        let mut options = Options::with_client_id(ClientID::new(u64::from(joined.client_ids[0])));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        doc.transact_mut()
            .apply_update(Update::decode_v1(&joined.sync_step2).unwrap())
            .unwrap();
        let text = doc.get_or_insert_text(BODY_ROOT);
        let sv = doc.transact().state_vector().encode_v1();
        {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, "x");
        }
        let update = {
            let since = StateVector::decode_v1(&sv).unwrap();
            doc.transact().encode_diff_v1(&since)
        };
        let refused = registry
            .apply_update_attributed(&joined.session_id, &joined.peer_id, &update, &fact)
            .expect_err("exhausted epoch refuses before live integration");
        assert_eq!(refused.code, RefusalCode::TooLarge);
        assert_eq!(registry.live_body(&joined.session_id).unwrap(), body_before);
        assert_eq!(
            registry.state_vector(&joined.session_id).unwrap(),
            sv_before
        );
        assert!(registry
            .acknowledged_contributors(&joined.session_id)
            .unwrap()
            .is_empty());
        let session = registry
            .sessions
            .values()
            .find(|s| s.id == joined.session_id)
            .unwrap();
        assert_eq!(session.mutation_epoch, u64::MAX);
        assert_eq!(session.acknowledged_bytes, 0);
    }

    #[test]
    fn drain_recomputes_bytes_and_repeat_is_idempotent() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let a = AcknowledgedContributor {
            principal: "alice".into(),
            executor_kind: "human".into(),
        };
        let b = AcknowledgedContributor {
            principal: "bob".into(),
            executor_kind: "agent".into(),
        };
        let fact_bytes = |fact: &AcknowledgedContributor| fact.budgeted_bytes();
        {
            let session = registry
                .sessions
                .values_mut()
                .find(|s| s.id == joined.session_id)
                .unwrap();
            session.acknowledged.insert(a.clone());
            session.acknowledged.insert(b.clone());
            session.acknowledged_bytes = fact_bytes(&a) + fact_bytes(&b);
            session.last_accepted = Some(b.clone());
        }
        let snapshot = registry.version_snapshot(&joined.session_id).unwrap();
        assert_eq!(snapshot.contributors().len(), 2);
        assert_eq!(
            registry.drain_version_snapshot(&snapshot).unwrap(),
            DrainOutcome::Drained
        );
        {
            let session = registry
                .sessions
                .values()
                .find(|s| s.id == joined.session_id)
                .unwrap();
            assert!(session.acknowledged.is_empty());
            assert_eq!(session.acknowledged_bytes, 0);
        }
        // Repeating the drain must not subtract bytes a second time.
        assert_eq!(
            registry.drain_version_snapshot(&snapshot).unwrap(),
            DrainOutcome::Drained
        );
        {
            let session = registry
                .sessions
                .values()
                .find(|s| s.id == joined.session_id)
                .unwrap();
            assert_eq!(session.acknowledged_bytes, 0);
        }
        // Bytes are recomputed from the retained set, never blind-subtracted:
        // a deliberately wrong pre-drain value is corrected to the true sum.
        {
            let session = registry
                .sessions
                .values_mut()
                .find(|s| s.id == joined.session_id)
                .unwrap();
            session.acknowledged.insert(a.clone());
            session.acknowledged_bytes = 999;
        }
        let snapshot = registry.version_snapshot(&joined.session_id).unwrap();
        assert_eq!(
            registry.drain_version_snapshot(&snapshot).unwrap(),
            DrainOutcome::Drained
        );
        {
            let session = registry
                .sessions
                .values()
                .find(|s| s.id == joined.session_id)
                .unwrap();
            assert_eq!(session.acknowledged_bytes, 0);
            assert!(session.last_accepted.is_some());
        }
    }

    fn author(joined: &OpenOk) -> Doc {
        let mut options = Options::with_client_id(ClientID::new(u64::from(joined.client_ids[0])));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        doc.get_or_insert_text(BODY_ROOT);
        doc.transact_mut()
            .apply_update(Update::decode_v1(&joined.sync_step2).unwrap())
            .unwrap();
        doc
    }

    fn insert_update(doc: &Doc, value: &str) -> Vec<u8> {
        let before = doc.transact().state_vector();
        doc.get_or_insert_text(BODY_ROOT)
            .insert(&mut doc.transact_mut(), 0, value);
        doc.transact().encode_diff_v1(&before)
    }

    fn contributor() -> AcknowledgedContributor {
        AcknowledgedContributor {
            principal: "alice".into(),
            executor_kind: "human".into(),
        }
    }

    #[test]
    fn prepare_and_drop_leave_live_untouched_and_install_uses_owned_candidate_and_ack() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let doc = author(&joined);
        let mut update = insert_update(&doc, "🦀e\u{301}");
        let original_update = update.clone();
        let mut fact = contributor();
        let original_fact = fact.clone();
        let before = fingerprint(&registry);
        let binding = Arc::clone(
            &registry
                .find_session(&joined.session_id)
                .unwrap()
                .prepared_binding,
        );
        let dropped = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&fact))
            .unwrap();
        assert_eq!(fingerprint(&registry), before);
        drop(dropped);
        assert_eq!(fingerprint(&registry), before);
        assert!(Arc::ptr_eq(
            &binding,
            &registry
                .find_session(&joined.session_id)
                .unwrap()
                .prepared_binding
        ));

        let prepared = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&fact))
            .unwrap();
        let expected_state = prepared.encoded_state().to_vec();
        let expected_ack = prepared.ack().clone();
        assert_eq!((prepared.epoch_before(), prepared.epoch_after()), (0, 1));
        assert_eq!(fingerprint(&registry), before);
        registry
            .validate_prepared_update(&joined.session_id, &joined.peer_id, &prepared)
            .unwrap();
        // Candidate owns both its accepted bytes and identity; changing the
        // source buffers cannot change what a future committed install means.
        update.fill(255);
        fact.principal = "changed-after-prepare".into();
        let ack = registry
            .install_prepared_update(&joined.session_id, &joined.peer_id, prepared)
            .unwrap();
        assert_eq!(ack.broadcast, original_update);
        assert_eq!(ack.broadcast, expected_ack.broadcast);
        assert_eq!(ack.state_vector, expected_ack.state_vector);
        assert_eq!(
            registry
                .encode_diff(&joined.session_id, &StateVector::default().encode_v1())
                .unwrap(),
            expected_state
        );
        assert_eq!(
            registry
                .acknowledged_contributors(&joined.session_id)
                .unwrap(),
            vec![original_fact.clone()]
        );
        assert_eq!(
            registry
                .last_accepted_contributor(&joined.session_id)
                .unwrap(),
            Some(original_fact)
        );
        assert_eq!(registry.mutation_epoch(&joined.session_id).unwrap(), 1);
        assert!(!Arc::ptr_eq(
            &binding,
            &registry
                .find_session(&joined.session_id)
                .unwrap()
                .prepared_binding
        ));
    }

    #[test]
    fn exact_install_preserves_delete_only_and_same_body_attribution_and_clean_replays() {
        for delete_only in [true, false] {
            let mut registry = SessionRegistry::new();
            let joined = registry.open(params()).unwrap();
            let doc = author(&joined);
            let before_sv = doc.transact().state_vector();
            let text = doc.get_or_insert_text(BODY_ROOT);
            {
                let mut txn = doc.transact_mut();
                if delete_only {
                    text.remove_range(&mut txn, 0, 4);
                } else {
                    text.insert(&mut txn, 0, "x");
                    text.remove_range(&mut txn, 0, 1);
                }
            }
            let update = doc.transact().encode_diff_v1(&before_sv);
            let fact = contributor();
            let before = fingerprint(&registry);
            let prepared = registry
                .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&fact))
                .unwrap();
            assert_eq!(fingerprint(&registry), before);
            assert_eq!(prepared.epoch_after(), 1);
            assert_eq!(
                prepared.ack().state_vector == before_sv.encode_v1(),
                delete_only
            );
            let expected_state = prepared.encoded_state().to_vec();
            registry
                .install_prepared_update(&joined.session_id, &joined.peer_id, prepared)
                .unwrap();
            assert_eq!(
                registry.live_body(&joined.session_id).unwrap(),
                if delete_only { "" } else { "body" }
            );
            assert_eq!(
                registry
                    .encode_diff(&joined.session_id, &StateVector::default().encode_v1())
                    .unwrap(),
                expected_state
            );
            assert_eq!(
                registry
                    .acknowledged_contributors(&joined.session_id)
                    .unwrap(),
                vec![fact.clone()]
            );
            let snapshot = registry.version_snapshot(&joined.session_id).unwrap();
            assert_eq!(
                registry.drain_version_snapshot(&snapshot).unwrap(),
                DrainOutcome::Drained
            );
            let before_replay = fingerprint(&registry);
            let relay = AcknowledgedContributor {
                principal: "relay".into(),
                executor_kind: "agent".into(),
            };
            let replay = registry
                .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&relay))
                .unwrap();
            assert_eq!((replay.epoch_before(), replay.epoch_after()), (1, 1));
            registry
                .install_prepared_update(&joined.session_id, &joined.peer_id, replay)
                .unwrap();
            assert_eq!(fingerprint(&registry), before_replay);
            assert_eq!(
                registry
                    .last_accepted_contributor(&joined.session_id)
                    .unwrap(),
                Some(fact)
            );
        }
    }

    #[test]
    fn prepare_refuses_shape_missing_dependencies_foreign_ids_and_sizes_atomically() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let before = fingerprint(&registry);
        let shape = author(&joined);
        shape
            .get_or_insert_map("other")
            .insert(&mut shape.transact_mut(), "key", "value");
        let shape_update = shape
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        let missing = author(&joined);
        let _withheld = insert_update(&missing, "withheld");
        let missing_update = insert_update(&missing, "dependent");
        // A valid Yjs client ID outside the leased u32 domain. Out-of-range
        // 64-bit values panic in Yrs's fixture constructor before admission.
        let foreign = Doc::with_options(Options::with_client_id(ClientID::new(1u64 << 40)));
        foreign
            .get_or_insert_text(BODY_ROOT)
            .insert(&mut foreign.transact_mut(), 0, "foreign");
        let foreign_update = foreign
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        for (update, code) in [
            (shape_update, RefusalCode::BadDocShape),
            (missing_update, RefusalCode::BadDocShape),
            (foreign_update, RefusalCode::ForeignClientId),
            (vec![255], RefusalCode::BadDocShape),
            (vec![0; MAX_UPDATE_BYTES + 1], RefusalCode::TooLarge),
        ] {
            let refused = registry
                .prepare_update(
                    &joined.session_id,
                    &joined.peer_id,
                    &update,
                    Some(&contributor()),
                )
                .err()
                .unwrap();
            assert_eq!(refused.code, code);
            assert_eq!(fingerprint(&registry), before);
        }
        let mut registry = SessionRegistry::new();
        let large = registry
            .open(OpenParams {
                committed_body: "x".repeat(MAX_BODY_BYTES),
                ..params()
            })
            .unwrap();
        let doc = author(&large);
        let update = insert_update(&doc, "x");
        let before = fingerprint(&registry);
        assert_eq!(
            registry
                .prepare_update(&large.session_id, &large.peer_id, &update, None)
                .err()
                .unwrap()
                .code,
            RefusalCode::TooLarge
        );
        assert_eq!(fingerprint(&registry), before);
    }

    #[test]
    fn prepare_epoch_and_ledger_limits_refuse_atomically_but_noops_need_no_new_quota() {
        for limit in [0, 1, 2] {
            let mut registry = SessionRegistry::new();
            let joined = registry.open(params()).unwrap();
            let session = registry.find_session_mut(&joined.session_id).unwrap();
            match limit {
                0 => session.mutation_epoch = u64::MAX,
                1 => {
                    session.acknowledged = (0..MAX_ATTRIBUTED_IDENTITIES)
                        .map(|i| AcknowledgedContributor {
                            principal: format!("old-{i}"),
                            executor_kind: "human".into(),
                        })
                        .collect();
                    session.acknowledged_bytes = session
                        .acknowledged
                        .iter()
                        .map(AcknowledgedContributor::budgeted_bytes)
                        .sum();
                }
                _ => {
                    let full = AcknowledgedContributor {
                        principal: "x".repeat(MAX_ATTRIBUTED_IDENTITY_BYTES - "human".len()),
                        executor_kind: "human".into(),
                    };
                    session.acknowledged_bytes = full.budgeted_bytes();
                    session.acknowledged.insert(full);
                }
            }
            let doc = author(&joined);
            let update = insert_update(&doc, "change");
            let before = fingerprint(&registry);
            assert_eq!(
                registry
                    .prepare_update(
                        &joined.session_id,
                        &joined.peer_id,
                        &update,
                        Some(&contributor())
                    )
                    .err()
                    .unwrap()
                    .code,
                RefusalCode::TooLarge
            );
            assert_eq!(fingerprint(&registry), before);
            let noop = registry
                .prepare_update(
                    &joined.session_id,
                    &joined.peer_id,
                    &joined.sync_step2,
                    Some(&contributor()),
                )
                .unwrap();
            assert_eq!(noop.epoch_before(), noop.epoch_after());
            registry
                .install_prepared_update(&joined.session_id, &joined.peer_id, noop)
                .unwrap();
            assert_eq!(fingerprint(&registry), before);
            if limit != 0 {
                // Existing identities may continue at either ledger ceiling;
                // a real state change refreshes last editor without new quota.
                let session = registry.find_session(&joined.session_id).unwrap();
                let existing = session.acknowledged.iter().next().unwrap().clone();
                let old_ledger = session.acknowledged.clone();
                let old_bytes = session.acknowledged_bytes;
                let candidate = registry
                    .prepare_update(
                        &joined.session_id,
                        &joined.peer_id,
                        &update,
                        Some(&existing),
                    )
                    .unwrap();
                registry
                    .install_prepared_update(&joined.session_id, &joined.peer_id, candidate)
                    .unwrap();
                let session = registry.find_session(&joined.session_id).unwrap();
                assert_eq!(session.acknowledged, old_ledger);
                assert_eq!(session.acknowledged_bytes, old_bytes);
                assert_eq!(session.last_accepted, Some(existing));
                assert_eq!(session.mutation_epoch, 1);
            }
        }
    }

    #[test]
    fn stale_candidate_refuses_before_mutation_after_another_install_or_version_drain() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let doc = author(&joined);
        let update = insert_update(&doc, "one");
        let fact = contributor();
        let first = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&fact))
            .unwrap();
        let stale = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&fact))
            .unwrap();
        registry
            .validate_prepared_update(&joined.session_id, &joined.peer_id, &stale)
            .unwrap();
        registry
            .install_prepared_update(&joined.session_id, &joined.peer_id, first)
            .unwrap();
        let before = fingerprint(&registry);
        assert_eq!(
            registry.validate_prepared_update(&joined.session_id, &joined.peer_id, &stale),
            Err(PreparedUpdateMismatch::State)
        );
        assert_eq!(
            registry
                .install_prepared_update(&joined.session_id, &joined.peer_id, stale)
                .unwrap_err(),
            PreparedUpdateMismatch::State
        );
        assert_eq!(fingerprint(&registry), before);

        // An installed replay moves neither epoch nor ledger. Its private
        // doc-state binding still supersedes another outstanding candidate.
        let pending_before_replay = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&fact))
            .unwrap();
        let before_replay = fingerprint(&registry);
        registry
            .apply_update(&joined.session_id, &joined.peer_id, &update)
            .unwrap();
        assert_eq!(fingerprint(&registry), before_replay);
        assert_eq!(
            registry
                .install_prepared_update(&joined.session_id, &joined.peer_id, pending_before_replay)
                .unwrap_err(),
            PreparedUpdateMismatch::State
        );
        assert_eq!(fingerprint(&registry), before_replay);

        let next = insert_update(&doc, "two");
        let pending = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &next, Some(&fact))
            .unwrap();
        let epoch = registry.mutation_epoch(&joined.session_id).unwrap();
        let snapshot = registry.version_snapshot(&joined.session_id).unwrap();
        registry.drain_version_snapshot(&snapshot).unwrap();
        assert_eq!(registry.mutation_epoch(&joined.session_id).unwrap(), epoch);
        let before = fingerprint(&registry);
        assert_eq!(
            registry.validate_prepared_update(&joined.session_id, &joined.peer_id, &pending),
            Err(PreparedUpdateMismatch::State)
        );
        assert_eq!(
            registry
                .install_prepared_update(&joined.session_id, &joined.peer_id, pending)
                .unwrap_err(),
            PreparedUpdateMismatch::State
        );
        assert_eq!(fingerprint(&registry), before);
    }

    #[test]
    fn candidate_session_peer_and_registry_binding_cannot_be_replaced_by_matching_ids() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let other_peer = registry.open(params()).unwrap();
        let other_room = registry
            .open(OpenParams {
                record_id: "other".into(),
                ..params()
            })
            .unwrap();
        let doc = author(&joined);
        let update = insert_update(&doc, "change");
        for (target_session, target_peer, expected) in [
            (
                &other_room.session_id,
                &other_room.peer_id,
                PreparedUpdateMismatch::Session,
            ),
            (
                &joined.session_id,
                &other_peer.peer_id,
                PreparedUpdateMismatch::Peer,
            ),
        ] {
            let candidate = registry
                .prepare_update(&joined.session_id, &joined.peer_id, &update, None)
                .unwrap();
            let before = fingerprint(&registry);
            assert_eq!(
                registry.validate_prepared_update(target_session, target_peer, &candidate),
                Err(expected)
            );
            assert_eq!(
                registry
                    .install_prepared_update(target_session, target_peer, candidate)
                    .unwrap_err(),
                expected
            );
            assert_eq!(fingerprint(&registry), before);
        }
        let candidate = registry
            .prepare_update(&joined.session_id, &joined.peer_id, &update, None)
            .unwrap();
        let mut independent = SessionRegistry::new();
        let independent_join = independent.open(params()).unwrap();
        // Test-only matching opaque strings, epochs and lease numbers still
        // cannot reproduce the registry-minted private state binding.
        let session = independent
            .find_session_mut(&independent_join.session_id)
            .unwrap();
        session.id = joined.session_id.clone();
        let peer = session.peers.remove(&independent_join.peer_id.0).unwrap();
        session.peers.insert(joined.peer_id.0.clone(), peer);
        let before = fingerprint(&independent);
        assert_eq!(
            independent.validate_prepared_update(&joined.session_id, &joined.peer_id, &candidate),
            Err(PreparedUpdateMismatch::State)
        );
        assert_eq!(
            independent
                .install_prepared_update(&joined.session_id, &joined.peer_id, candidate)
                .unwrap_err(),
            PreparedUpdateMismatch::State
        );
        assert_eq!(fingerprint(&independent), before);
    }

    #[test]
    fn candidate_refuses_departed_demoted_rebound_peers_and_retired_session_before_mutation() {
        for transition in [0, 1, 2, 3] {
            let mut registry = SessionRegistry::new();
            let joined = registry.open(params()).unwrap();
            if transition != 2 {
                registry.open(params()).unwrap();
            }
            let doc = author(&joined);
            let update = insert_update(&doc, "change");
            let candidate = registry
                .prepare_update(&joined.session_id, &joined.peer_id, &update, None)
                .unwrap();
            if transition == 1 {
                registry
                    .find_session_mut(&joined.session_id)
                    .unwrap()
                    .peers
                    .get_mut(&joined.peer_id.0)
                    .unwrap()
                    .kind = PeerKind::View;
            } else if transition == 3 {
                registry
                    .find_session_mut(&joined.session_id)
                    .unwrap()
                    .peers
                    .get_mut(&joined.peer_id.0)
                    .unwrap()
                    .client_ids
                    .insert(999);
            } else {
                registry.leave(&joined.session_id, &joined.peer_id);
            }
            let before = fingerprint(&registry);
            let expected = if transition == 2 {
                PreparedUpdateMismatch::Session
            } else {
                PreparedUpdateMismatch::Peer
            };
            assert_eq!(
                registry.validate_prepared_update(&joined.session_id, &joined.peer_id, &candidate),
                Err(expected)
            );
            assert_eq!(
                registry
                    .install_prepared_update(&joined.session_id, &joined.peer_id, candidate)
                    .unwrap_err(),
                expected
            );
            assert_eq!(fingerprint(&registry), before);
        }
    }
}
