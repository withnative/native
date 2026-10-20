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
    Any, ClientID, Doc, GetString, Map, OffsetKind, Options, Out, ReadTxn, Snapshot, StateVector,
    Text, Transact, Update,
};

use super::refusal::{RefusalCode, Refused};
use super::span_map::{
    build_span_map, parse_span_map, serialize_span_map, validate_span_map, visible_triples,
    DiffChunk, Owner, OwnershipError, OwnershipLedger, SpanBuildError, SpanMap,
    MAX_SERIALIZED_SPAN_MAP_BYTES,
};

/// Root name of the single shared text holding the Markdown source.
pub const BODY_ROOT: &str = "body";
/// Largest committed/live body this core will hold (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Largest single update payload this core will integrate (64 KiB).
pub const MAX_UPDATE_BYTES: usize = 64 * 1024;
/// Largest Yjs `SnapshotV1` (delete set + state vector) a cut proof may carry
/// (64 KiB, before base64). Over it the proof is omitted, never truncated.
pub const MAX_CUT_SNAPSHOT_BYTES: usize = 64 * 1024;
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
    /// `None` for a server-authored (routed) write.
    peer_id: Option<PeerId>,
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
    /// Clock-interval ownership for span authorship (task `632ddcc`):
    /// the successor ledger, allocated whole at prepare and moved into the
    /// session at install alongside the candidate doc. `None` when the
    /// update records no new clock ranges (delete-only, replay, no-op):
    /// install then retains the session ledger with no clone. Retained
    /// across version drains and peer departures; pruned to visible
    /// intervals at version cuts.
    ownership: Option<OwnershipLedger>,
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

    /// Body text of the candidate doc.
    pub(crate) fn body(&self) -> String {
        let txn = self.doc.transact();
        txn.get_text(BODY_ROOT)
            .map(|text| text.get_string(&txn))
            .unwrap_or_default()
    }

    /// Successor contributor ledger, sorted as in [`VersionSnapshot`].
    pub(crate) fn contributors(&self) -> Vec<AcknowledgedContributor> {
        let mut out: Vec<_> = self.acknowledged.iter().cloned().collect();
        out.sort();
        out
    }

    /// Successor ownership ledger, if this candidate records new clock
    /// ranges; `None` retains the session ledger at install.
    pub(crate) fn ownership(&self) -> Option<&OwnershipLedger> {
        self.ownership.as_ref()
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
    /// Yjs `SnapshotV1` of the doc this `body` was read from; `None` when it
    /// exceeds [`MAX_CUT_SNAPSHOT_BYTES`].
    ydoc_snapshot: Option<Vec<u8>>,
    /// Span map of `body`, enumerated on a scratch clone under the live
    /// ownership ledger at snapshot time. Always present: every accepted
    /// edit passed the prospective map caps at prepare, so the cut's map
    /// cannot fail for size.
    span_map: SpanMap,
    /// Visible clock triples at snapshot time: what a drain retains from
    /// the ownership ledger, so deleted text's intervals are pruned at the
    /// cut and the budget recovers.
    visible: Vec<(u32, u32, u32)>,
}

impl VersionSnapshot {
    /// The doc's state vector and delete set at snapshot time, in Yjs
    /// `encodeSnapshotV1` layout (delete set, then state vector), minted in the
    /// same step as [`VersionSnapshot::body`] and the mutation epoch. `None`
    /// when larger than [`MAX_CUT_SNAPSHOT_BYTES`]: an unproved cut, not an
    /// error. It identifies which items made up `body`; it is not proof that
    /// any event committed.
    pub fn ydoc_snapshot(&self) -> Option<&[u8]> {
        self.ydoc_snapshot.as_deref()
    }

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

    /// Span map of the snapshot body, in canonical form.
    pub fn span_map(&self) -> &SpanMap {
        &self.span_map
    }

    /// Visible ownership triples at snapshot time, for ledger pruning.
    pub fn visible(&self) -> &[(u32, u32, u32)] {
        &self.visible
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AcknowledgedContributor {
    /// Authenticated principal, as supplied by the trusted caller.
    pub principal: String,
    /// Executor kind, as supplied by the trusted caller.
    pub executor_kind: String,
    /// Run key the caller asserted, if any (correlation only).
    pub run_key: Option<String>,
    /// App attribution set by the host, if the ops came through an app.
    pub app: Option<AppAttribution>,
    /// Server-observed transport the change arrived over (`"mcp"`, `"web"`,
    /// ...), if declared. A weaker fact than the executor kind (decision
    /// 425a001b): it lets a UI mark an MCP write as a likely agent without
    /// claiming the executor.
    pub channel: Option<String>,
}

/// Which installed app a contributor acted through: the version's own record
/// of the host-asserted app (`Caller::with_host_asserted_app`) the engine
/// admitted for that peer. Correlation only; the provenance row for the cut
/// is `provenance_action_app_attributions`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppAttribution {
    pub package: String,
    pub version: String,
    pub install_event_id: String,
}

impl AppAttribution {
    fn budgeted_bytes(&self) -> usize {
        self.package
            .len()
            .saturating_add(self.version.len())
            .saturating_add(self.install_event_id.len())
    }
}

impl AcknowledgedContributor {
    /// UTF-8 bytes this pair contributes to the ledger byte budget.
    /// Overflow-checked at the call site via saturating arithmetic.
    pub(crate) fn budgeted_bytes(&self) -> usize {
        self.principal
            .len()
            .saturating_add(self.executor_kind.len())
            .saturating_add(self.run_key.as_ref().map_or(0, String::len))
            .saturating_add(self.app.as_ref().map_or(0, AppAttribution::budgeted_bytes))
            .saturating_add(self.channel.as_ref().map_or(0, String::len))
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
    /// Client id the server authors routed-in writes with (high half of u32,
    /// never leased to a peer). Shared by every routed write in this session;
    /// they are serialised, so its clocks stay contiguous.
    server_client_id: u32,
    /// Clock-interval ownership ledger: `(client, start_clock)` mapped to
    /// `(end_clock, owner)`. The seed interval is [`Owner::PriorVersion`];
    /// every accepted state-changing apply adds its new clock ranges under
    /// the update's contributor (or explicit unattributed), which is what
    /// distinguishes routed writers sharing `server_client_id`.
    ownership: OwnershipLedger,
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

    /// Move the lease counter forward to `next` (never back), so a caller
    /// holding many registries can keep client ids monotonic across all of
    /// them. Ids are still only ever leased once.
    pub(crate) fn advance_client_ids_to(&mut self, next: u32) {
        self.next_client_id = self.next_client_id.max(next);
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

    /// Server author id: high half of u32 like seeds, so it can never be
    /// leased. Distinct from any seed only probabilistically (1 / 2^31); a
    /// collision would merely share clocks with the seed author, which never
    /// authors again after seeding.
    fn draw_server_client_id(&self) -> u32 {
        rand::random::<u32>() | SEED_CLIENT_ID_BASE
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
            let seed_client_id = self.draw_seed_client_id();
            let doc = seed_doc(&params.committed_body, seed_client_id);
            // The seed interval is prior-version text by definition: whatever
            // clocks the fresh doc holds for the seed client belong to the
            // committed body the session opened with. An empty body holds no
            // clocks and records no interval. Unreachable-budget: one client,
            // one interval, zero identity bytes on an empty ledger.
            let mut ownership = OwnershipLedger::new();
            let seeded = doc.transact().state_vector();
            ownership
                .record_advance(&StateVector::default(), &seeded, &Owner::PriorVersion)
                .expect("seed intervals fit the empty ownership ledger");
            Some(Session {
                id: SessionId(format!("sess-{}", uuid::Uuid::new_v4())),
                doc,
                peers: HashMap::new(),
                acknowledged: HashSet::new(),
                acknowledged_bytes: 0,
                last_accepted: None,
                ownership,
                mutation_epoch: 0,
                prepared_binding: Arc::new(()),
                server_client_id: self.draw_server_client_id(),
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

/// UTF-8 byte offset a Yjs relative position (`StickyIndex`) resolves to in
/// `doc`'s `body` text, or `None` if it does not resolve.
///
/// yrs 0.28's `StickyIndex::get_offset` on an `OffsetKind::Bytes` doc mixes
/// units: whole preceding items count in bytes, but the offset *within* the
/// item it lands in is in UTF-16 units (Yjs clock units). So resolve on a
/// UTF-16 clone, where both parts agree, and convert that index to bytes over
/// the text. Pinned by the yjs interop vectors; the server-side consumer is
/// anchors (S7), which this milestone defers.
#[allow(dead_code)]
pub(crate) fn sticky_byte_offset(doc: &Doc, sticky: &yrs::StickyIndex) -> Option<usize> {
    let full = doc
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    let mut options = Options::with_client_id(doc.client_id());
    options.offset_kind = OffsetKind::Utf16;
    let utf16 = Doc::with_options(options);
    let text = utf16.get_or_insert_text(BODY_ROOT);
    utf16
        .transact_mut()
        .apply_update(Update::decode_v1(&full).ok()?)
        .ok()?;
    let txn = utf16.transact();
    let index = sticky.get_offset(&txn)?.index as usize;
    let body = text.get_string(&txn);
    let mut units = 0usize;
    for (byte, ch) in body.char_indices() {
        if units >= index {
            return Some(byte);
        }
        units += ch.len_utf16();
    }
    (units >= index).then_some(body.len())
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
    clone_doc_with(src, src.client_id())
}

/// Full-state clone under a chosen client id (the server author for routed
/// writes). Same root-declaration and transaction rules as [`clone_doc`].
fn clone_doc_as(src: &Doc, client_id: u32) -> Doc {
    clone_doc_with(src, ClientID::new(u64::from(client_id)))
}

fn clone_doc_with(src: &Doc, client_id: ClientID) -> Doc {
    let full = {
        let txn = src.transact();
        txn.encode_state_as_update_v1(&StateVector::default())
    };
    let mut options = Options::with_client_id(client_id);
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

/// Visible text of `doc` as diff chunks with their inserting ids.
///
/// Runs `Text::diff_range` with `hi` = the doc's current snapshot and `lo` =
/// the empty snapshot on `doc` itself, so the caller passes a scratch clone
/// and the live doc is never mutated for enumeration. Every visible string
/// item arrives as its own `Added` chunk; deleted items are excluded, so no
/// deleted text can reach a persisted map. Non-string chunks are impossible
/// past the apply-time shape gate and refuse loudly.
fn enumerate_span_chunks(doc: &Doc) -> Result<(String, Vec<DiffChunk>), SpanBuildError> {
    let text = doc.get_or_insert_text(BODY_ROOT);
    let body = text.get_string(&doc.transact());
    let hi = doc.transact().snapshot();
    let lo = Snapshot::default();
    let diffs = {
        let mut txn = doc.transact_mut();
        text.diff_range(&mut txn, Some(&hi), Some(&lo), YChange::identity)
    };
    let mut chunks = Vec::with_capacity(diffs.len());
    for diff in diffs {
        let Some(change) = diff.ychange else {
            return Err(SpanBuildError::Malformed);
        };
        if !matches!(change.kind, yrs::types::text::ChangeKind::Added) {
            return Err(SpanBuildError::Malformed);
        }
        let Out::Any(Any::String(text)) = diff.insert else {
            return Err(SpanBuildError::Malformed);
        };
        chunks.push(DiffChunk {
            text: text.to_string(),
            client: u32::try_from(change.id.client.get()).map_err(|_| SpanBuildError::Malformed)?,
            clock: change.id.clock,
        });
    }
    Ok((body, chunks))
}

/// Build the span map for a scratch doc's current state under `ownership`.
/// The builder's reconstruction check ties the chunks to the body, so a
/// divergence between enumeration and text fails instead of misattributing.
fn build_span_map_for(doc: &Doc, ownership: &OwnershipLedger) -> Result<SpanMap, SpanBuildError> {
    let (body, chunks) = enumerate_span_chunks(doc)?;
    build_span_map(&body, &chunks, ownership)
}

/// Map a span failure to a refusal with a static detail: cut and prepare
/// paths must not leak body text or identity material, and every variant
/// here is unreachable past the apply-time gates except an over-cap map,
/// which refuses `TooLarge` before anything durable happens.
fn span_refusal(error: SpanBuildError) -> Refused {
    match error {
        SpanBuildError::TooManySpans => {
            Refused::new(RefusalCode::TooLarge, "span map exceeds its span budget")
        }
        _ => Refused::new(RefusalCode::BadDocShape, "span map build failed"),
    }
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
        self.install_prepared_update(session_id, Some(peer_id), prepared)
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
        self.install_prepared_update(session_id, Some(peer_id), prepared)
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
        self.prepare_update_as(session_id, Some(peer_id), update_v1, contributor)
    }

    /// Prepare a server-authored write that turns the live body into
    /// `new_body` by applying `splices` (computed by the caller against the
    /// current live text with `text_diff::splices`, off the async thread),
    /// authored by the session's server client id and attributed to
    /// `contributor`. `Ok(None)` when there is nothing to splice. Splices that
    /// do not turn the live text into `new_body` are refused. The update size
    /// limit does not apply (a routed write is one governed call); every other
    /// check does.
    pub(crate) fn prepare_server_write(
        &self,
        session_id: &SessionId,
        new_body: &str,
        splices: &[super::text_diff::Splice],
        contributor: &AcknowledgedContributor,
    ) -> Result<Option<PreparedUpdate>, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        if new_body.len() > MAX_BODY_BYTES {
            return Err(Refused::new(
                RefusalCode::TooLarge,
                format!(
                    "resulting body is {} bytes, limit is {MAX_BODY_BYTES}",
                    new_body.len()
                ),
            ));
        }
        if splices.is_empty() {
            return Ok(None);
        }
        let live = self.live_body(session_id)?;
        if super::text_diff::apply(&live, splices) != new_body {
            return Err(Refused::new(
                RefusalCode::LiveSessionChanged,
                "routed diff was not computed against the current live text",
            ));
        }
        let author = clone_doc_as(&session.doc, session.server_client_id);
        let before = session.doc.transact().state_vector();
        let update = {
            let text = author.get_or_insert_text(BODY_ROOT);
            let mut txn = author.transact_mut();
            // Back to front, so earlier offsets stay valid.
            for splice in splices.iter().rev() {
                if splice.delete > 0 {
                    text.remove_range(&mut txn, splice.at as u32, splice.delete as u32);
                }
                if !splice.insert.is_empty() {
                    text.insert(&mut txn, splice.at as u32, &splice.insert);
                }
            }
            drop(txn);
            author.transact().encode_diff_v1(&before)
        };
        self.prepare_update_as(session_id, None, &update, Some(contributor))
            .map(Some)
    }

    fn prepare_update_as(
        &self,
        session_id: &SessionId,
        peer_id: Option<&PeerId>,
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
        let peer = match peer_id {
            Some(peer_id) => {
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
                Some(peer)
            }
            None => None,
        };
        let authored_by = |client: &ClientID| match peer {
            Some(peer) => leased_to_peer(peer, client),
            None => client.get() == u64::from(session.server_client_id),
        };
        if peer.is_some() && update_v1.len() > MAX_UPDATE_BYTES {
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
        let (new_state, encoded_state, ownership_ranges) = {
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
                        && !authored_by(client)
                });
            let after = scratch.transact().state_vector();
            let from_delta = after
                .iter()
                .any(|(client, _)| after.get(client) > before.get(client) && !authored_by(client));
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
            //
            // The same advance, per client, is the ownership delta the
            // successor ledger will record: `[before, after)` ranges that a
            // later cut resolves per item. Wide clients are unrepresentable
            // in the u32 lease/seed/server space; the authorship gate above
            // already refused new structs from them, so this is unreachable
            // on admitted updates.
            let ownership_ranges: Result<Vec<(u32, u32, u32)>, OwnershipError> = (|| {
                let mut ranges = Vec::new();
                for (client, end) in after.iter() {
                    let start = before.get(client);
                    if *end > start {
                        let client = u32::try_from(client.get())
                            .map_err(|_| OwnershipError::ForeignClient)?;
                        ranges.push((client, start, *end));
                    }
                }
                Ok(ranges)
            })();
            (
                after
                    .iter()
                    .any(|(client, _)| after.get(client) > before.get(client))
                    || applied_new_deletes,
                encoded_state,
                ownership_ranges,
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
        // Successor ownership ledger, allocated whole before install: the
        // update's new clock ranges under its contributor — the full caller-
        // asserted row, so run/app/channel identity distinguishes even one
        // peer's successive updates and routed writers sharing the server
        // client id — or explicit unattributed for legacy unattributed calls.
        // Delete-only updates and replays advance no clocks and record
        // nothing. Refusal here mutates nothing: not the body, state vector,
        // ledgers, last-accepted, or epoch. The detail names no identity
        // material. Draining a version later retains this ledger: surviving
        // text keeps its origin after its contributor drains. `None` retains
        // the session ledger at install with no clone.
        let mut ownership: Option<OwnershipLedger> = None;
        if new_state {
            let owner = match contributor {
                Some(fact) => Owner::Contributor(fact.clone()),
                None => Owner::Unattributed,
            };
            let ranges = ownership_ranges.map_err(|_| {
                Refused::new(
                    RefusalCode::ForeignClientId,
                    "update authors new structs with a client id outside the session space",
                )
            })?;
            // No ranges recorded (delete-only, replay, no-op): retain the
            // session ledger with no clone, but still verify the
            // prospective map below — the author table is
            // encounter-ordered, so every state change re-derives it.
            let current: &OwnershipLedger = if ranges.is_empty() {
                &session.ownership
            } else {
                let mut successor = session.ownership.clone();
                if let Err(error) = successor.record_ranges(&ranges, &owner) {
                    match error {
                        OwnershipError::ForeignClient => {
                            return Err(Refused::new(
                                RefusalCode::ForeignClientId,
                                "update authors new structs with a client id outside the session space",
                            ));
                        }
                        OwnershipError::BudgetExhausted => {
                            // Recovery on the prospective state before the
                            // final budget decision: the scratch twin
                            // already reflects this update's deletions
                            // (cumulative document delete set, not the
                            // fresh transaction's), so prune the successor
                            // ledger first — a deletion/replacement at full
                            // budget frees what it deletes.
                            let deleted = scratch.transact().snapshot().delete_set.clone();
                            successor.retain_not_deleted(&deleted);
                            successor.record_ranges(&ranges, &owner).map_err(
                                |error| match error {
                                    OwnershipError::BudgetExhausted => Refused::new(
                                        RefusalCode::TooLarge,
                                        "ownership ledger budget exhausted",
                                    ),
                                    OwnershipError::ForeignClient => Refused::new(
                                        RefusalCode::ForeignClientId,
                                        "update authors new structs with a client id outside the session space",
                                    ),
                                },
                            )?;
                        }
                    }
                }
                ownership = Some(successor);
                ownership.as_ref().expect("just recorded")
            };
            // Prospective map caps BEFORE install, for every state change:
            // one ledger interval can fragment into several visible spans
            // (interleaved inserts from another owner), so the interval
            // budget alone cannot bound the cut's map. Build the full map
            // on the scratch twin now — linear, like the full-state encode
            // above — and refuse over-cap updates here, so every accepted
            // edit can still be cut later. The serialize/parse/validate
            // round-trip additionally admits the exact emitted owner
            // metadata shape: a caller identity the strict map parser
            // would reject (empty run key, bad app row) refuses here,
            // before anything is acknowledged, rather than wedging its cut.
            let (prospective_body, prospective_chunks) =
                enumerate_span_chunks(&scratch).map_err(span_refusal)?;
            let prospective = build_span_map(&prospective_body, &prospective_chunks, current)
                .map_err(span_refusal)?;
            let serialized =
                serde_json::to_string(&serialize_span_map(&prospective)).map_err(|_| {
                    Refused::new(RefusalCode::BadDocShape, "span map serialization failed")
                })?;
            if serialized.len() > MAX_SERIALIZED_SPAN_MAP_BYTES {
                return Err(Refused::new(
                    RefusalCode::TooLarge,
                    "prospective span map exceeds its serialized budget",
                ));
            }
            let round_tripped =
                parse_span_map(&serialize_span_map(&prospective)).map_err(span_refusal)?;
            validate_span_map(&round_tripped, &prospective_body).map_err(span_refusal)?;
        }
        // No state change: retain the session ledger with no clone.
        let ack = Ack {
            state_vector: scratch.transact().state_vector().encode_v1(),
            broadcast: update_v1.to_vec(),
        };
        Ok(PreparedUpdate {
            session_id: session_id.clone(),
            peer_id: peer_id.cloned(),
            before_binding: Arc::clone(&session.prepared_binding),
            before_epoch: session.mutation_epoch,
            before_client_ids: peer.map(|peer| peer.client_ids.clone()).unwrap_or_default(),
            before_acknowledged: session.acknowledged.clone(),
            before_acknowledged_bytes: session.acknowledged_bytes,
            before_last_accepted: session.last_accepted.clone(),
            doc: scratch,
            acknowledged,
            acknowledged_bytes,
            last_accepted,
            ownership,
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
        peer_id: Option<&PeerId>,
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
        peer_id: Option<&PeerId>,
        prepared: &PreparedUpdate,
    ) -> Result<(), PreparedUpdateMismatch> {
        if prepared.session_id != *session_id {
            return Err(PreparedUpdateMismatch::Session);
        }
        if prepared.peer_id.as_ref() != peer_id {
            return Err(PreparedUpdateMismatch::Peer);
        }
        if let Some(peer_id) = peer_id {
            let peer = session
                .peers
                .get(&peer_id.0)
                .ok_or(PreparedUpdateMismatch::Peer)?;
            if peer.kind != PeerKind::Edit || peer.client_ids != prepared.before_client_ids {
                return Err(PreparedUpdateMismatch::Peer);
            }
        }
        // Epoch alone misses a version drain. Compare the preimage ledger too,
        // without recomputation/encoding; otherwise install could resurrect
        // already versioned contributors. Private Arc identity also binds the
        // exact registry/session doc and changes even on duplicate installs.
        // The ownership ledger needs no preimage compare of its own: it only
        // ever changes on install, and every state-changing install advances
        // the epoch, so the epoch plus binding already serialize it.
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
        peer_id: Option<&PeerId>,
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
        if let Some(ownership) = prepared.ownership {
            session.ownership = ownership;
        }
        session.mutation_epoch = prepared.mutation_epoch;
        session.prepared_binding = prepared.next_binding;
        Ok(prepared.ack)
    }

    /// Span map for a prepared candidate's post-state, for routed versions
    /// whose payload commits before install: decode the candidate's full
    /// state into a scratch doc (never the live doc) and build under the
    /// successor ownership — or the session ledger when the candidate
    /// records no new ranges. The validator ties the map to the body the
    /// version will carry.
    pub(crate) fn span_map_for_prepared(
        &self,
        session_id: &SessionId,
        prepared: &PreparedUpdate,
    ) -> Result<SpanMap, Refused> {
        let session = self.find_session(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let ownership = prepared.ownership.as_ref().unwrap_or(&session.ownership);
        let decoded = Update::decode_v1(prepared.encoded_state()).map_err(|_| {
            Refused::new(RefusalCode::BadDocShape, "prepared state is not decodable")
        })?;
        let mut options = Options::with_client_id(ClientID::new(0));
        options.offset_kind = OffsetKind::Bytes;
        let scratch = Doc::with_options(options);
        let _body = scratch.get_or_insert_text(BODY_ROOT);
        {
            let mut txn = scratch.transact_mut();
            txn.apply_update(decoded).map_err(|_| {
                Refused::new(RefusalCode::BadDocShape, "prepared state does not apply")
            })?;
        }
        let map = build_span_map_for(&scratch, ownership).map_err(span_refusal)?;
        validate_span_map(&map, &prepared.body()).map_err(span_refusal)?;
        Ok(map)
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
        // Read in the same registry borrow as `body` above: no apply can
        // interleave, so the snapshot describes exactly that text.
        let ydoc_snapshot = {
            let encoded = session.doc.transact().snapshot().encode_v1();
            (encoded.len() <= MAX_CUT_SNAPSHOT_BYTES).then_some(encoded)
        };
        // Span map on a scratch clone: enumeration stages block splits, so
        // it must never run on the live doc. The builder's reconstruction
        // check ties the chunks to the enumerated text, and the validator
        // ties the map to the snapshotted body; both read the same
        // unchanging doc state as `body` above. The visible triples ride
        // along so the drain can prune deleted intervals at the cut.
        let (span_map, visible) = {
            let scratch = clone_doc(&session.doc);
            let (enumerated, chunks) = enumerate_span_chunks(&scratch).map_err(span_refusal)?;
            let map =
                build_span_map(&enumerated, &chunks, &session.ownership).map_err(span_refusal)?;
            validate_span_map(&map, &body).map_err(span_refusal)?;
            (map, visible_triples(&chunks))
        };
        Ok(VersionSnapshot {
            session_id: session_id.clone(),
            body,
            contributors,
            last_accepted: session.last_accepted.clone(),
            mutation_epoch: session.mutation_epoch,
            ydoc_snapshot,
            span_map,
            visible,
        })
    }

    /// Drain a snapshot's contributors after its version event has committed.
    ///
    /// The ownership ledger is deliberately NOT drained: surviving text keeps
    /// its origin intervals after the contributor rows drain, which is what
    /// lets later cuts attribute text whose author has since left. Deleted
    /// text's intervals are pruned to the visible set at cut time instead.
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
        // Prune deleted ownership to exactly what the cut saw visible, so
        // the interval and contributor budgets recover across cuts. Stale
        // drains prune nothing: their visible set is outdated.
        session.ownership.retain_visible(&snapshot.visible);
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

    /// Remove a peer WITHOUT tearing the session down when it was the last
    /// one: the doc, ledger and server author stay until
    /// [`SessionRegistry::drop_session`]. Returns the departed peer's kind and
    /// client ids (so a later resume can restore exactly that lease).
    pub(crate) fn remove_peer(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
    ) -> Option<(PeerKind, Vec<u32>)> {
        let session = self.find_session_mut(session_id)?;
        let peer = session.peers.remove(&peer_id.0)?;
        let mut ids: Vec<u32> = peer.client_ids.into_iter().collect();
        ids.sort_unstable();
        Some((peer.kind, ids))
    }

    /// Re-attach a peer under its previous id and client ids (resume). The
    /// caller guarantees those ids were leased to this peer by this registry,
    /// so no other peer can hold them. Peer limits still apply; returns the
    /// usual full-state sync.
    pub(crate) fn restore_peer(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
        kind: PeerKind,
        client_ids: &[u32],
    ) -> Result<OpenOk, Refused> {
        let session = self.find_session_mut(session_id).ok_or_else(|| {
            Refused::new(
                RefusalCode::UndeclaredSession,
                "no live session with that id",
            )
        })?;
        let replacing = session.peers.contains_key(&peer_id.0);
        if !replacing {
            match kind {
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
        session.peers.insert(
            peer_id.0.clone(),
            Peer {
                kind,
                client_ids: client_ids.iter().copied().collect(),
            },
        );
        let sync_step2 = session
            .doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        Ok(OpenOk {
            session_id: session.id.clone(),
            peer_id: peer_id.clone(),
            client_ids: client_ids.to_vec(),
            sync_step2,
        })
    }

    /// Tear a session down whole (end of the grace window, or a discard).
    pub(crate) fn drop_session(&mut self, session_id: &SessionId) {
        self.sessions.retain(|_, s| s.id != *session_id);
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
            run_key: None,
            app: None,
            channel: None,
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
                    run_key: None,
                    app: None,
                    channel: None,
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
            run_key: None,
            app: None,
            channel: None,
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
            run_key: None,
            app: None,
            channel: None,
        };
        let b = AcknowledgedContributor {
            principal: "bob".into(),
            executor_kind: "agent".into(),
            run_key: None,
            app: None,
            channel: None,
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
            run_key: None,
            app: None,
            channel: None,
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
            .validate_prepared_update(&joined.session_id, Some(&joined.peer_id), &prepared)
            .unwrap();
        // Candidate owns both its accepted bytes and identity; changing the
        // source buffers cannot change what a future committed install means.
        update.fill(255);
        fact.principal = "changed-after-prepare".into();
        let ack = registry
            .install_prepared_update(&joined.session_id, Some(&joined.peer_id), prepared)
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
                .install_prepared_update(&joined.session_id, Some(&joined.peer_id), prepared)
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
                run_key: None,
                app: None,
                channel: None,
            };
            let replay = registry
                .prepare_update(&joined.session_id, &joined.peer_id, &update, Some(&relay))
                .unwrap();
            assert_eq!((replay.epoch_before(), replay.epoch_after()), (1, 1));
            registry
                .install_prepared_update(&joined.session_id, Some(&joined.peer_id), replay)
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
                            run_key: None,
                            app: None,
                            channel: None,
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
                        run_key: None,
                        app: None,
                        channel: None,
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
                .install_prepared_update(&joined.session_id, Some(&joined.peer_id), noop)
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
                    .install_prepared_update(&joined.session_id, Some(&joined.peer_id), candidate)
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
            .validate_prepared_update(&joined.session_id, Some(&joined.peer_id), &stale)
            .unwrap();
        registry
            .install_prepared_update(&joined.session_id, Some(&joined.peer_id), first)
            .unwrap();
        let before = fingerprint(&registry);
        assert_eq!(
            registry.validate_prepared_update(&joined.session_id, Some(&joined.peer_id), &stale),
            Err(PreparedUpdateMismatch::State)
        );
        assert_eq!(
            registry
                .install_prepared_update(&joined.session_id, Some(&joined.peer_id), stale)
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
                .install_prepared_update(
                    &joined.session_id,
                    Some(&joined.peer_id),
                    pending_before_replay
                )
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
            registry.validate_prepared_update(&joined.session_id, Some(&joined.peer_id), &pending),
            Err(PreparedUpdateMismatch::State)
        );
        assert_eq!(
            registry
                .install_prepared_update(&joined.session_id, Some(&joined.peer_id), pending)
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
                registry.validate_prepared_update(target_session, Some(target_peer), &candidate),
                Err(expected)
            );
            assert_eq!(
                registry
                    .install_prepared_update(target_session, Some(target_peer), candidate)
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
            independent.validate_prepared_update(
                &joined.session_id,
                Some(&joined.peer_id),
                &candidate
            ),
            Err(PreparedUpdateMismatch::State)
        );
        assert_eq!(
            independent
                .install_prepared_update(&joined.session_id, Some(&joined.peer_id), candidate)
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
                registry.validate_prepared_update(
                    &joined.session_id,
                    Some(&joined.peer_id),
                    &candidate
                ),
                Err(expected)
            );
            assert_eq!(
                registry
                    .install_prepared_update(&joined.session_id, Some(&joined.peer_id), candidate)
                    .unwrap_err(),
                expected
            );
            assert_eq!(fingerprint(&registry), before);
        }
    }

    // ---- cut proof snapshots -------------------------------------------

    fn sha(text: &str) -> String {
        crate::mcp::tools::lifecycle::body_digest(Some(text))
    }

    fn body_event(seq: i64) -> super::super::live::BodyEvent {
        super::super::live::BodyEvent::from_row(Some(format!("evt-{seq}")), Some(seq)).unwrap()
    }

    fn snapshot_v1(snapshot: &VersionSnapshot) -> yrs::Snapshot {
        yrs::Snapshot::decode_v1(snapshot.ydoc_snapshot().expect("within the cap"))
            .expect("the doc's own snapshot decodes")
    }

    #[test]
    fn a_version_snapshot_carries_the_docs_own_snapshot_with_its_text() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let doc = author(&joined);
        let before = registry.version_snapshot(&joined.session_id).unwrap();
        assert_eq!(
            snapshot_v1(&before),
            doc.transact().snapshot(),
            "the seed's snapshot is the joiner's"
        );
        let update = insert_update(&doc, "new ");
        registry
            .apply_update(&joined.session_id, &joined.peer_id, &update)
            .unwrap();
        let after = registry.version_snapshot(&joined.session_id).unwrap();
        assert_eq!(after.body(), "new body");
        assert_eq!(snapshot_v1(&after), doc.transact().snapshot());
        assert_ne!(snapshot_v1(&after), snapshot_v1(&before));

        // The proof attaches the snapshot only to the revision whose body is
        // that snapshot's own text.
        use super::super::live::{base_proof, cut_proof, StoredBody};
        let event = body_event(5);
        let proved = base_proof(&after, &sha(after.body()), Some(&event));
        assert_eq!(proved.snapshot.as_deref(), after.ydoc_snapshot());
        assert_eq!(proved.body_event_id.as_deref(), Some("evt-5"));
        assert_eq!(proved.body_event_seq, Some(5));
        let other = base_proof(&after, &sha("new body!"), Some(&event));
        assert_eq!(other.snapshot, None, "a different body gets no snapshot");
        let unnamed = base_proof(&after, &sha(after.body()), None);
        assert_eq!(
            (unnamed.body_event_id, unnamed.body_event_seq),
            (None, None)
        );
        assert_eq!(unnamed.snapshot, None, "no event, no snapshot");
        // A cut's stored body must be the snapshot's body, or nothing is claimed.
        let stored = |hash: String| StoredBody {
            sha256: hash,
            event: Some(body_event(6)),
        };
        assert_eq!(
            cut_proof(&after, &sha(after.body()), Some(&stored(sha(after.body())))).body_event_seq,
            Some(6)
        );
        for mismatch in [
            cut_proof(&after, &sha(after.body()), Some(&stored(sha("raced")))),
            cut_proof(&after, &sha(after.body()), None),
        ] {
            assert_eq!(mismatch, super::super::live::CutProof::default());
        }
    }

    /// Same bytes, different items: delete-and-reinsert identical text keeps
    /// the body (and so its hash) and moves the snapshot, which is why bytes
    /// alone never identify items.
    #[test]
    fn identical_text_reinserted_has_the_same_body_and_a_different_snapshot() {
        let mut registry = SessionRegistry::new();
        let joined = registry.open(params()).unwrap();
        let doc = author(&joined);
        let first = registry.version_snapshot(&joined.session_id).unwrap();
        let before = doc.transact().state_vector();
        {
            let text = doc.get_or_insert_text(BODY_ROOT);
            let mut txn = doc.transact_mut();
            text.remove_range(&mut txn, 0, 4);
            text.insert(&mut txn, 0, "body");
        }
        let update = doc.transact().encode_diff_v1(&before);
        registry
            .apply_update(&joined.session_id, &joined.peer_id, &update)
            .unwrap();
        let second = registry.version_snapshot(&joined.session_id).unwrap();
        assert_eq!(second.body(), first.body());
        assert_ne!(snapshot_v1(&second), snapshot_v1(&first));
    }

    /// A Yjs v1 update with no structs and one client's delete set. Building it
    /// by hand keeps its size exactly what the test says (about four bytes per
    /// range), whatever a yrs diff would have re-encoded.
    fn delete_only_update(client: u64, ranges: &[(u32, u32)]) -> Vec<u8> {
        fn var(out: &mut Vec<u8>, mut value: u64) {
            while value >= 0x80 {
                out.push((value & 0x7f) as u8 | 0x80);
                value >>= 7;
            }
            out.push(value as u8);
        }
        let mut out = Vec::new();
        var(&mut out, 0); // no clients with structs
        var(&mut out, 1); // one client in the delete set
        var(&mut out, client);
        var(&mut out, ranges.len() as u64);
        for &(clock, len) in ranges {
            var(&mut out, u64::from(clock));
            var(&mut out, u64::from(len));
        }
        out
    }

    #[test]
    fn an_oversize_snapshot_is_omitted_not_truncated() {
        let mut registry = SessionRegistry::new();
        let joined = registry
            .open(OpenParams {
                committed_body: "ab".repeat(50_000),
                ..params()
            })
            .unwrap();
        let doc = author(&joined);
        assert!(registry
            .version_snapshot(&joined.session_id)
            .unwrap()
            .ydoc_snapshot()
            .is_some());
        // The seed client authored all 100,000 bytes. Delete every other one:
        // 40,000 separate delete-set ranges, sent as five updates that each
        // stay under the unchanged per-update limit.
        let seed = *doc
            .transact()
            .state_vector()
            .iter()
            .find(|(_, clock)| **clock == 100_000)
            .expect("the seed client's items")
            .0;
        let ranges: Vec<(u32, u32)> = (0..40_000u32).map(|k| (2 * k + 1, 1)).collect();
        for batch in ranges.chunks(8_000) {
            let update = delete_only_update(seed.get(), batch);
            assert!(update.len() <= MAX_UPDATE_BYTES, "{} bytes", update.len());
            registry
                .apply_update(&joined.session_id, &joined.peer_id, &update)
                .unwrap();
            doc.transact_mut()
                .apply_update(Update::decode_v1(&update).unwrap())
                .unwrap();
        }
        let snapshot = registry.version_snapshot(&joined.session_id).unwrap();
        assert_eq!(snapshot.body().len(), 60_000);
        assert!(
            doc.transact().snapshot().encode_v1().len() > MAX_CUT_SNAPSHOT_BYTES,
            "the fragmented delete set is over the cap"
        );
        assert_eq!(snapshot.ydoc_snapshot(), None);
        // Over the cap the revision is still named; only the snapshot is absent.
        let proof =
            super::super::live::base_proof(&snapshot, &sha(snapshot.body()), Some(&body_event(9)));
        assert_eq!(proof.body_event_id.as_deref(), Some("evt-9"));
        assert_eq!(proof.body_event_seq, Some(9));
        assert_eq!(proof.snapshot, None, "named, not proved");
    }

    /// A checked-in yrs `SnapshotV1` for a later Yjs test to decode. This
    /// test pins what yrs 0.28 emits and the canonical form we expect (state
    /// vector sorted by client, delete set merged and sorted); it does NOT
    /// show that Yjs decodes it. Regenerate with
    /// `COEDIT_WRITE_SNAPSHOT_FIXTURE=1 cargo test --lib snapshot_v1_fixture`.
    #[test]
    fn snapshot_v1_fixture_matches_the_canonical_form_yrs_emits() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        fn client(id: u64) -> Doc {
            let mut options = Options::with_client_id(ClientID::new(id));
            options.offset_kind = OffsetKind::Bytes;
            let doc = Doc::with_options(options);
            doc.get_or_insert_text(BODY_ROOT);
            doc
        }
        fn sync(from: &Doc, to: &Doc) {
            let update = from
                .transact()
                .encode_state_as_update_v1(&StateVector::default());
            to.transact_mut()
                .apply_update(Update::decode_v1(&update).unwrap())
                .unwrap();
        }
        let one = client(1);
        let two = client(2);
        let text_one = one.get_or_insert_text(BODY_ROOT);
        let text_two = two.get_or_insert_text(BODY_ROOT);
        // client 1: "Hello world" = clocks 0..=10.
        text_one.insert(&mut one.transact_mut(), 0, "Hello world");
        sync(&one, &two);
        // client 2: "big " = clocks 0..=3, between "Hello " and "world".
        text_two.insert(&mut two.transact_mut(), 6, "big ");
        sync(&two, &one);
        // Delete "Hello" in two steps (merges to clocks 0..5 of client 1),
        // "wor" (clocks 6..9, a separate range) and all of "big " (client 2).
        text_one.remove_range(&mut one.transact_mut(), 0, 3);
        text_one.remove_range(&mut one.transact_mut(), 0, 2);
        text_one.remove_range(&mut one.transact_mut(), 5, 3);
        sync(&one, &two);
        text_two.remove_range(&mut two.transact_mut(), 1, 4);
        sync(&two, &one);
        assert_eq!(text_one.get_string(&one.transact()), " ld");
        let snapshot = one.transact().snapshot();
        let bytes = snapshot.encode_v1();
        assert_eq!(snapshot, two.transact().snapshot());

        let mut state_vector: Vec<(u64, u32)> = snapshot
            .state_map
            .iter()
            .map(|(client, clock)| (client.get(), *clock))
            .collect();
        state_vector.sort_unstable();
        let delete_set: Vec<(u64, u32, u32)> = snapshot
            .delete_set
            .iter()
            .flat_map(|(client, ranges)| {
                ranges
                    .iter()
                    .map(|range| (client.get(), range.start, range.end - range.start))
                    .collect::<Vec<_>>()
            })
            .collect();
        // Hand-derived: clients 1 and 2 hold 11 and 4 items; client 1 lost
        // clocks 0..5 and 6..9, client 2 lost all of 0..4.
        assert_eq!(state_vector, vec![(1, 11), (2, 4)]);
        assert_eq!(delete_set, vec![(1, 0, 5), (1, 6, 3), (2, 0, 4)]);

        let fixture = serde_json::json!({
            "format": "yjs-snapshot-v1 (delete set, then state vector)",
            "producer": "yrs 0.28.0 Snapshot::encode_v1",
            "yjs_decode_verified": false,
            "text": " ld",
            "snapshot_v1_base64": STANDARD.encode(&bytes),
            "expected_state_vector": [[1, 11], [2, 4]],
            "expected_delete_set": [[1, 0, 5], [1, 6, 3], [2, 0, 4]],
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/coedit/fixtures/snapshot_v1_cut_proof.json"
        );
        if std::env::var_os("COEDIT_WRITE_SNAPSHOT_FIXTURE").is_some() {
            std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
        }
        // Read at run time, so regenerating it needs no recompile.
        let checked_in: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            checked_in, fixture,
            "regenerate the fixture if yrs' encoding changed"
        );
        assert!(bytes.len() < 64, "a small, reviewable fixture");
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::super::text_diff;
    use super::*;
    use crate::coedit::span_map::MAX_OWNERSHIP_INTERVALS;

    fn params(body: &str) -> OpenParams {
        OpenParams {
            database_id: "db".into(),
            record_id: "record".into(),
            committed_body: body.into(),
            kind: PeerKind::Edit,
            record_supported: true,
        }
    }

    fn alice() -> AcknowledgedContributor {
        AcknowledgedContributor {
            principal: "alice".into(),
            executor_kind: "human".into(),
            run_key: None,
            app: None,
            channel: None,
        }
    }

    fn routed_agent(run_key: &str) -> AcknowledgedContributor {
        AcknowledgedContributor {
            principal: "agent".into(),
            executor_kind: "agent".into(),
            run_key: Some(run_key.into()),
            app: None,
            channel: Some("mcp".into()),
        }
    }

    /// A peer-side insert authored by `client_id` on top of `sync` state.
    fn peer_insert(sync: &[u8], client_id: u32, pos: u32, text: &str) -> Vec<u8> {
        let mut options = Options::with_client_id(ClientID::new(u64::from(client_id)));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        let _ = doc.get_or_insert_text(BODY_ROOT);
        {
            let mut txn = doc.transact_mut();
            txn.apply_update(Update::decode_v1(sync).expect("sync decodes"))
                .expect("sync applies");
        }
        {
            let body = doc.get_or_insert_text(BODY_ROOT);
            let mut txn = doc.transact_mut();
            body.insert(&mut txn, pos, text);
        }
        let diff = doc.transact().encode_diff_v1(&StateVector::default());
        diff
    }

    fn session_of(registry: &SessionRegistry) -> (SessionId, u32) {
        let session = registry.sessions.values().next().expect("one session");
        let seed = u32::try_from(session.doc.client_id().get()).expect("seed fits u32");
        (session.id.clone(), seed)
    }

    #[test]
    fn seed_interval_is_prior_version() {
        let mut registry = SessionRegistry::default();
        registry.open(params("hello")).unwrap();
        let (_, seed) = session_of(&registry);
        let session = registry.sessions.values().next().expect("one session");
        assert_eq!(
            session.ownership.owner_at(seed, 0),
            Some(&Owner::PriorVersion)
        );
        assert_eq!(
            session.ownership.owner_at(seed, 4),
            Some(&Owner::PriorVersion)
        );
        assert_eq!(session.ownership.owner_at(seed, 5), None);
    }

    #[test]
    fn empty_seed_records_no_interval() {
        let mut registry = SessionRegistry::default();
        registry.open(params("")).unwrap();
        let session = registry.sessions.values().next().expect("one session");
        assert!(session.ownership.is_empty());
    }

    #[test]
    fn peer_apply_records_contributor_and_drain_retains() {
        let mut registry = SessionRegistry::default();
        let opened = registry.open(params("")).unwrap();
        let client = opened.client_ids[0];
        let update = peer_insert(&opened.sync_step2, client, 0, "hi");
        registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &update, &alice())
            .unwrap();
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "hi");
        let expected = Owner::Contributor(alice());
        {
            let session = registry.sessions.values().next().expect("one session");
            assert_eq!(session.ownership.owner_at(client, 0), Some(&expected));
            assert_eq!(session.ownership.owner_at(client, 1), Some(&expected));
            assert_eq!(session.ownership.owner_at(client, 2), None);
        }
        let snapshot = registry.version_snapshot(&opened.session_id).unwrap();
        assert_eq!(
            registry.drain_version_snapshot(&snapshot).unwrap(),
            DrainOutcome::Drained
        );
        assert!(registry
            .acknowledged_contributors(&opened.session_id)
            .unwrap()
            .is_empty());
        // The contributor row drained, but surviving text keeps its origin.
        let session = registry.sessions.values().next().expect("one session");
        assert_eq!(session.ownership.owner_at(client, 0), Some(&expected));
    }

    #[test]
    fn routed_writers_split_shared_server_id() {
        let mut registry = SessionRegistry::default();
        let opened = registry.open(params("")).unwrap();
        let first = routed_agent("run-one");
        let live = registry.live_body(&opened.session_id).unwrap();
        let prepared = registry
            .prepare_server_write(
                &opened.session_id,
                "ab",
                &text_diff::splices(&live, "ab"),
                &first,
            )
            .unwrap()
            .expect("non-empty write prepares");
        registry
            .install_prepared_update(&opened.session_id, None, prepared)
            .unwrap();
        let second = routed_agent("run-two");
        let live = registry.live_body(&opened.session_id).unwrap();
        let prepared = registry
            .prepare_server_write(
                &opened.session_id,
                "abXY",
                &text_diff::splices(&live, "abXY"),
                &second,
            )
            .unwrap()
            .expect("non-empty write prepares");
        registry
            .install_prepared_update(&opened.session_id, None, prepared)
            .unwrap();
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "abXY");
        let session = registry.sessions.values().next().expect("one session");
        let server = session.server_client_id;
        let expected_first = Owner::Contributor(first);
        let expected_second = Owner::Contributor(second);
        assert_eq!(session.ownership.owner_at(server, 0), Some(&expected_first));
        assert_eq!(session.ownership.owner_at(server, 1), Some(&expected_first));
        assert_eq!(
            session.ownership.owner_at(server, 2),
            Some(&expected_second)
        );
        assert_eq!(
            session.ownership.owner_at(server, 3),
            Some(&expected_second)
        );
        assert_eq!(session.ownership.owner_at(server, 4), None);
    }

    #[test]
    fn over_budget_apply_refuses_before_mutation() {
        let mut registry = SessionRegistry::default();
        let opened = registry.open(params("")).unwrap();
        {
            let session = registry
                .sessions
                .get_mut(&("db".to_string(), "record".to_string()))
                .expect("session");
            for client in 100_000..100_000 + MAX_OWNERSHIP_INTERVALS as u32 {
                session
                    .ownership
                    .record_ranges(&[(client, 0, 1)], &Owner::Unattributed)
                    .unwrap();
            }
        }
        let client = opened.client_ids[0];
        let update = peer_insert(&opened.sync_step2, client, 0, "x");
        let refused = registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &update, &alice())
            .expect_err("over-budget apply refuses");
        assert_eq!(refused.code, RefusalCode::TooLarge);
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "");
        let session = registry.sessions.values().next().expect("one session");
        assert_eq!(session.ownership.len(), MAX_OWNERSHIP_INTERVALS);
    }

    #[test]
    fn non_terminal_leave_retains_ownership() {
        let mut registry = SessionRegistry::default();
        let first = registry.open(params("")).unwrap();
        let _second = registry
            .open(OpenParams {
                kind: PeerKind::Edit,
                ..params("")
            })
            .unwrap();
        let client = first.client_ids[0];
        let update = peer_insert(&first.sync_step2, client, 0, "hi");
        registry
            .apply_update_attributed(&first.session_id, &first.peer_id, &update, &alice())
            .unwrap();
        assert!(registry.leave(&first.session_id, &first.peer_id));
        let expected = Owner::Contributor(alice());
        let session = registry.sessions.values().next().expect("one session");
        assert_eq!(session.ownership.owner_at(client, 0), Some(&expected));
    }

    /// Peer-side replace: delete `delete_len` bytes at `delete_at`, then
    /// insert `text` at `insert_at`, on top of `sync` state.
    fn peer_replace(
        sync: &[u8],
        client_id: u32,
        delete_at: u32,
        delete_len: u32,
        insert_at: u32,
        text: &str,
    ) -> Vec<u8> {
        let mut options = Options::with_client_id(ClientID::new(u64::from(client_id)));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        let _ = doc.get_or_insert_text(BODY_ROOT);
        {
            let mut txn = doc.transact_mut();
            txn.apply_update(Update::decode_v1(sync).expect("sync decodes"))
                .expect("sync applies");
        }
        {
            let body = doc.get_or_insert_text(BODY_ROOT);
            let mut txn = doc.transact_mut();
            if delete_len > 0 {
                body.remove_range(&mut txn, delete_at, delete_len);
            }
            if !text.is_empty() {
                body.insert(&mut txn, insert_at, text);
            }
        }
        let diff = doc.transact().encode_diff_v1(&StateVector::default());
        diff
    }

    fn filler(index: u32) -> AcknowledgedContributor {
        AcknowledgedContributor {
            principal: format!("filler-{index}"),
            executor_kind: "human".into(),
            run_key: None,
            app: None,
            channel: None,
        }
    }

    #[test]
    fn full_budget_delete_replace_succeeds_and_frees_deleted() {
        use super::super::span_map::{MAX_RETAINED_OWNERS, MAX_RETAINED_OWNER_BYTES};
        let mut registry = SessionRegistry::default();
        let opened = registry.open(params("hello")).unwrap();
        let client = opened.client_ids[0];
        // Alice authors "XY" on top of the seed; both intervals exist.
        let update = peer_insert(&opened.sync_step2, client, 5, "XY");
        registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &update, &alice())
            .unwrap();
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "helloXY");
        // Fill both budgets around the two live intervals: every other
        // owner slot and every other interval slot.
        {
            let session = registry
                .sessions
                .get_mut(&("db".to_string(), "record".to_string()))
                .expect("session");
            assert_eq!(session.ownership.contributor_count(), 1);
            for index in 0..MAX_RETAINED_OWNERS as u32 - 1 {
                session
                    .ownership
                    .record_ranges(
                        &[(200_000 + index, 0, 1)],
                        &Owner::Contributor(filler(index)),
                    )
                    .unwrap();
            }
            let used = session.ownership.len();
            for filler_client in 300_000..300_000 + (MAX_OWNERSHIP_INTERVALS - used) as u32 {
                session
                    .ownership
                    .record_ranges(&[(filler_client, 0, 1)], &Owner::Unattributed)
                    .unwrap();
            }
            assert_eq!(session.ownership.len(), MAX_OWNERSHIP_INTERVALS);
            assert_eq!(session.ownership.contributor_count(), MAX_RETAINED_OWNERS);
        }
        // Bob replaces the whole body: deletes the seed and Alice's text,
        // inserts "bye". A new contributor over a full owner budget, with
        // new clocks over a full interval budget — succeeds only because
        // recovery prunes the deleted origins first.
        let bob = routed_agent("run-bob");
        let full = registry
            .encode_diff(&opened.session_id, &StateVector::default().encode_v1())
            .unwrap();
        let replace = peer_replace(&full, client, 0, 7, 0, "bye");
        registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &replace, &bob)
            .unwrap();
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "bye");
        let session = registry.sessions.values().next().expect("one session");
        let expected_bob = Owner::Contributor(bob);
        // Alice's clocks were 0..2; Bob's start at 2.
        assert_eq!(session.ownership.owner_at(client, 0), None);
        assert_eq!(session.ownership.owner_at(client, 2), Some(&expected_bob));
        assert_eq!(session.ownership.owner_at(client, 4), Some(&expected_bob));
        assert_eq!(session.ownership.owner_at(client, 5), None);
        // Seed text deleted: its prior interval is freed, not retained.
        let (_, seed) = session_of(&registry);
        assert_eq!(session.ownership.owner_at(seed, 0), None);
        // Budgets recovered: Bob retained, Alice freed, intervals drained.
        assert_eq!(session.ownership.contributor_count(), MAX_RETAINED_OWNERS);
        assert!(session.ownership.len() < MAX_OWNERSHIP_INTERVALS);
        assert!(session.ownership.contributor_bytes() <= MAX_RETAINED_OWNER_BYTES);
    }

    #[test]
    fn delete_between_cuts_prunes_ledger_and_keeps_map_buildable() {
        let mut registry = SessionRegistry::default();
        let opened = registry.open(params("hello")).unwrap();
        let client = opened.client_ids[0];
        // First cut: Alice appends, then drains; seed and Alice stay visible.
        let update = peer_insert(&opened.sync_step2, client, 5, "XY");
        registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &update, &alice())
            .unwrap();
        let first = registry.version_snapshot(&opened.session_id).unwrap();
        assert_eq!(
            registry.drain_version_snapshot(&first).unwrap(),
            DrainOutcome::Drained
        );
        {
            let session = registry.sessions.values().next().expect("one session");
            assert_eq!(session.ownership.len(), 2);
            assert_eq!(session.ownership.contributor_count(), 1);
        }
        // Between cuts Alice deletes her own text; the second cut versions
        // the seed-only body and prunes her now-invisible interval.
        let full = registry
            .encode_diff(&opened.session_id, &StateVector::default().encode_v1())
            .unwrap();
        let delete = peer_replace(&full, client, 5, 2, 0, "");
        registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &delete, &alice())
            .unwrap();
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "hello");
        let second = registry.version_snapshot(&opened.session_id).unwrap();
        assert_eq!(second.span_map().spans.len(), 1);
        assert_eq!(
            registry.drain_version_snapshot(&second).unwrap(),
            DrainOutcome::Drained
        );
        let session = registry.sessions.values().next().expect("one session");
        assert_eq!(session.ownership.len(), 1);
        assert_eq!(session.ownership.contributor_count(), 0);
        let (_, seed) = session_of(&registry);
        assert_eq!(
            session.ownership.owner_at(seed, 0),
            Some(&Owner::PriorVersion)
        );
        assert_eq!(session.ownership.owner_at(client, 0), None);
    }

    #[test]
    fn empty_run_identity_refuses_before_mutation() {
        // A present-but-empty run key passes the contributor ledger but
        // fails the strict map parser at the cut; prospective admission
        // must refuse it before anything is acknowledged or mutated.
        let mut registry = SessionRegistry::default();
        let opened = registry.open(params("")).unwrap();
        let client = opened.client_ids[0];
        let mut bad = alice();
        bad.run_key = Some(String::new());
        let update = peer_insert(&opened.sync_step2, client, 0, "x");
        let refused = registry
            .apply_update_attributed(&opened.session_id, &opened.peer_id, &update, &bad)
            .expect_err("empty run key refuses");
        assert_eq!(refused.code, RefusalCode::BadDocShape);
        assert_eq!(registry.live_body(&opened.session_id).unwrap(), "");
        let session = registry.sessions.values().next().expect("one session");
        assert!(session.ownership.is_empty());
        assert!(session.acknowledged.is_empty());
    }
}
