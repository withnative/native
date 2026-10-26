//! M3 snapshot read (epic 6b1f3c2): immutable bounded per-principal tokens
//! over the M2 filtered index, with exact catch-up.
//!
//! The M2 seam (`Db::filtered_workspace_index`) answers one principal at one
//! instant but holds its rows in the shared moving index, so multi-call paging
//! cannot read from it directly. `open` copies the filtered **public**
//! projection into a bounded per-handle store and returns an opaque token;
//! `page` reads only that copy, so concurrent commits never move pages
//! mid-read; `catch_up` diffs the old copy against a fresh M2 view and returns
//! exact row upserts/deletes plus a new token.
//!
//! Safety properties (contract acceptance, record 6818e39):
//! - Projection is governed-minus-body: every served column is already visible
//!   to the same principal through governed `query_sql`, so serving it discloses
//!   nothing new. M1/M2 physical rows are never serialized.
//! - A fence change (authorization epoch or relationship seq), a missing or
//!   expired token, or a content gap beyond the window returns
//!   `restart_required` with no rows; the client discards its model and re-opens.
//!   `catch_up` alone distinguishes one safe case — an expired-but-known token
//!   for the same principal with all fences unchanged
//!   (`token_expired_fences_unchanged`) — from the generic
//!   `token_expired_or_unknown` that still covers unknown tokens and principal
//!   mismatches.
//!   Callers that pass `accept_fence_moved: true` to `catch_up` instead receive
//!   the exact old-vs-fresh diff with `fence_moved: true` when the fresh M2 view
//!   is available; the diff's deletes are the revocations, and the fresh view
//!   is filtered for the principal at the new fences, so no hidden row appears
//!   in upserts or content events. `page` still restarts on any fence move.
//!   The `fence_moved` wire key is emitted only when the caller opted in, so
//!   an opt-out delta carries exactly the keys it always has.
//! - M2 `None` (over-cap refusal, absent index, racing fences) surfaces as a
//!   generic `index_unavailable`, never an empty workspace. The fallback reader
//!   is the client's existing governed path.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::query::QueryPrincipal;
use crate::workspace_index::FilteredWorkspaceIndex;

/// V1 tokens held per database handle. Entries are LRU-evicted past this count
/// or [`SNAPSHOT_MAX_BYTES`] total. V2 uses its own bounded handle budget below
/// so member browsers and agents can retain pins together.
pub const SNAPSHOT_MAX_TOKENS: usize = 8;
/// Total estimated bytes across held tokens per handle. Matches
/// [`crate::workspace_index::MAX_INDEX_BYTES`] deliberately: the token budget
/// can never exceed one more refused-sized index.
pub const SNAPSHOT_MAX_BYTES: usize = 32 * 1024 * 1024;
/// V2 shares a handle across members and agents. Retain eight maximum-sized
/// pins (plus smaller pins up to the count bound), rather than making every
/// new member evict the previous member. V1's existing budget is unchanged.
#[cfg(feature = "v2-kernel-probe")]
pub const SNAPSHOT_V2_MAX_BYTES: usize = 256 * 1024 * 1024;
#[cfg(feature = "v2-kernel-probe")]
pub const SNAPSHOT_V2_MAX_TOKENS: usize = 16;
/// Estimated retained v2 pin bytes across every database handle in this
/// process. A single HQ handle keeps its existing 256 MiB/16-pin behavior;
/// additional databases share this budget instead of multiplying it.
#[cfg(feature = "v2-kernel-probe")]
pub const SNAPSHOT_V2_PROCESS_MAX_BYTES: usize = 256 * 1024 * 1024;
/// How long a token stays pageable. Five minutes: long enough to page a large
/// workspace over serial round trips, short enough that a stale pin cannot
/// outlive the operator's patience. Expiry is an explicit restart, not drift.
pub const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
/// Default page occupancy per section; the caller may ask for less, never more
/// than [`SNAPSHOT_PAGE_MAX`]. The cap mirrors `query_sql`'s 1,000-row page so
/// a snapshot page is never harder to serve than the governed read it replaces.
pub const SNAPSHOT_PAGE_DEFAULT: usize = 500;
pub const SNAPSHOT_PAGE_MAX: usize = 1_000;
/// Catch-up bridges at most this many content sequence steps. It matches
/// [`crate::workspace_index::MAX_CONTENT_WINDOW_EVENTS`]: beyond it the index
/// window itself has evicted the evidence, so the honest answer is a restart.
pub const SNAPSHOT_MAX_CATCH_UP_GAP: i64 = 512;

/// One `records` row as the governed view serves it, minus `body`.
/// Bodies travel one at a time through `get_record`; a snapshot carrying them
/// would inherit `query_sql`'s 256 KiB cell refusal for the whole read.
/// The `type` rename keeps the wire key identical to the governed column and
/// the demo-shell index read; `record_type` is the Rust field only because
/// `type` is a reserved word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub home_id: Option<String>,
    pub lifecycle: Option<String>,
    pub persistence: String,
    pub maturity: Option<String>,
    pub summary: Option<String>,
    pub last_activity_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

/// One `facet_values` row, exactly as the governed view serves it: `value_num`
/// is the generated JSON-number projection (`None` when the stored text is
/// not a JSON integer or real). Non-finite `REAL`s are unrepresentable in
/// JSON and are dropped to `None` at projection time rather than failing or
/// nulling a whole page at serialization. `Eq` is absent with `f64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotFacet {
    pub id: String,
    pub record_id: String,
    pub key: String,
    pub value: Option<String>,
    pub value_num: Option<f64>,
    pub vocab_ref: Option<String>,
    pub created_at: String,
}

/// One `links` row, exactly as the governed `links` view serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLink {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    pub note: Option<String>,
    pub created_at: String,
}

/// One content-log ref. `seq` is the content local sequence; `type` already
/// carries the M2 `receipt.committed.v1` → `record.updated` mapping and the
/// three governed exclusions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEvent {
    pub seq: i64,
    pub id: String,
    pub record_id: String,
    pub event_type: String,
    pub created_at: String,
}
impl SnapshotRecord {
    pub(crate) fn from_head(head: &crate::workspace_index::RecordHead) -> Self {
        Self {
            id: head.id.clone(),
            record_type: Some(head.record_type.clone()),
            kind: head.kind.clone(),
            name: head.name.clone(),
            home_id: head.home_id.clone(),
            lifecycle: head.lifecycle.clone(),
            persistence: head.persistence.clone(),
            maturity: head.maturity.clone(),
            summary: head.summary.clone(),
            last_activity_at: head.last_activity_at.clone(),
            created_at: head.created_at.clone(),
            updated_at: head.updated_at.clone(),
            deleted_at: head.deleted_at.clone(),
        }
    }
}

impl SnapshotFacet {
    pub(crate) fn from_row(row: &crate::workspace_index::FacetRow) -> Self {
        Self {
            id: row.id.clone(),
            record_id: row.record_id.clone(),
            key: row.key.clone(),
            value: row.value.clone(),
            value_num: row.value_num.filter(|value| value.is_finite()),
            vocab_ref: row.vocab_ref.clone(),
            created_at: row.created_at.clone(),
        }
    }
}

impl SnapshotLink {
    pub(crate) fn from_row(row: &crate::workspace_index::LinkRow) -> Self {
        Self {
            id: row.id.clone(),
            source_id: row.source_id.clone(),
            target_id: row.target_id.clone(),
            relationship: row.relationship.clone(),
            note: row.note.clone(),
            created_at: row.created_at.clone(),
        }
    }
}

impl SnapshotEvent {
    pub(crate) fn from_ref(event: &crate::workspace_index::ContentEventRef) -> Self {
        Self {
            seq: event.seq,
            id: event.id.clone(),
            record_id: event.record_id.clone(),
            event_type: event.event_type.clone(),
            created_at: event.created_at.clone(),
        }
    }
}

/// One pinned filtered snapshot. BTreeMaps keep page order deterministic by id;
/// the maps ARE the snapshot, so paging and diffing never touch the moving index.
#[derive(Debug, Clone)]
pub(crate) struct SnapshotEntry {
    principal_credential: String,
    principal_is_member: bool,
    principal_trusted_bypass: bool,
    created_at: Instant,
    content_seq: i64,
    authorization_epoch: i64,
    relationship_seq: i64,
    unit_seq_max: i64,
    estimated_bytes: usize,
    #[cfg(feature = "v2-kernel-probe")]
    kernel_v2: bool,
    records: BTreeMap<String, SnapshotRecord>,
    facets: BTreeMap<String, SnapshotFacet>,
    links: BTreeMap<String, SnapshotLink>,
    events: Vec<SnapshotEvent>,
}

/// Upper-bound estimate over held maps: each row counts its struct size (all
/// inline headers), every heap string fully, map keys twice (the key `String`
/// is a second allocation of the id), plus per-row BTreeMap node overhead and
/// per-entry store/token overhead. Anything unmodeled (allocator rounding,
/// HashMap buckets) is covered by the node/entry constants, which exceed
/// typical allocator overhead per row on 64-bit targets. A measured test
/// below pins the bound.
#[doc(hidden)]
pub fn estimate_entry_bytes(
    principal_credential_len: usize,
    records: &BTreeMap<String, SnapshotRecord>,
    facets: &BTreeMap<String, SnapshotFacet>,
    links: &BTreeMap<String, SnapshotLink>,
    events: &[SnapshotEvent],
) -> usize {
    const STORE_ENTRY_OVERHEAD: usize = 512;
    let mut estimated_bytes = 1024 + STORE_ENTRY_OVERHEAD + principal_credential_len + 64;
    estimated_bytes += records
        .values()
        .map(SnapshotRecord::estimated_bytes)
        .sum::<usize>();
    estimated_bytes += facets
        .values()
        .map(SnapshotFacet::estimated_bytes)
        .sum::<usize>();
    estimated_bytes += links
        .values()
        .map(SnapshotLink::estimated_bytes)
        .sum::<usize>();
    estimated_bytes += std::mem::size_of_val(events) + 64;
    for event in events {
        estimated_bytes += event.id.len()
            + event.record_id.len()
            + event.event_type.len()
            + event.created_at.len()
            + 32;
    }
    estimated_bytes
}

impl SnapshotRecord {
    /// Same held representation estimate for both engines: inline struct,
    /// actual strings, map key and node overhead. No JSON escape multiplier.
    pub(crate) fn estimated_bytes(&self) -> usize {
        const MAP_NODE_OVERHEAD: usize = 64;
        std::mem::size_of::<SnapshotRecord>()
            + std::mem::size_of::<String>()
            + self.id.len() * 2
            + self.record_type.as_ref().map_or(0, String::len)
            + self.kind.as_ref().map_or(0, String::len)
            + self.name.len()
            + self.home_id.as_ref().map_or(0, String::len)
            + self.lifecycle.as_ref().map_or(0, String::len)
            + self.persistence.len()
            + self.maturity.as_ref().map_or(0, String::len)
            + self.summary.as_ref().map_or(0, String::len)
            + self.last_activity_at.as_ref().map_or(0, String::len)
            + self.created_at.len()
            + self.updated_at.len()
            + self.deleted_at.as_ref().map_or(0, String::len)
            + MAP_NODE_OVERHEAD
    }
}
impl SnapshotFacet {
    /// Same held representation estimate for both engines: inline struct,
    /// actual strings, map key and node overhead. No JSON escape multiplier.
    pub(crate) fn estimated_bytes(&self) -> usize {
        const MAP_NODE_OVERHEAD: usize = 64;
        std::mem::size_of::<SnapshotFacet>()
            + std::mem::size_of::<String>()
            + self.id.len() * 2
            + self.record_id.len()
            + self.key.len()
            + self.value.as_ref().map_or(0, String::len)
            + self.value_num.map_or(0, |_| 8)
            + self.vocab_ref.as_ref().map_or(0, String::len)
            + self.created_at.len()
            + MAP_NODE_OVERHEAD
    }
}
impl SnapshotLink {
    /// Same held representation estimate for both engines: inline struct,
    /// actual strings, map key and node overhead. No JSON escape multiplier.
    pub(crate) fn estimated_bytes(&self) -> usize {
        const MAP_NODE_OVERHEAD: usize = 64;
        std::mem::size_of::<SnapshotLink>()
            + std::mem::size_of::<String>()
            + self.id.len() * 2
            + self.source_id.len()
            + self.target_id.len()
            + self.relationship.len()
            + self.note.as_ref().map_or(0, String::len)
            + self.created_at.len()
            + MAP_NODE_OVERHEAD
    }
}
impl FilteredWorkspaceIndex {
    fn snapshot_record(&self, head: &crate::workspace_index::RecordHead) -> SnapshotRecord {
        #[allow(unused_mut)]
        let mut row = SnapshotRecord::from_head(head);
        #[cfg(feature = "v2-kernel-probe")]
        if self
            .native_untyped_records
            .as_ref()
            .is_some_and(|ids| ids.contains(&head.id))
        {
            row.record_type = None;
        }
        row
    }
}

impl SnapshotEntry {
    fn project(principal: &QueryPrincipal, filtered: &FilteredWorkspaceIndex) -> Self {
        let records: BTreeMap<String, SnapshotRecord> = filtered
            .records
            .iter()
            .map(|(id, head)| (id.clone(), filtered.snapshot_record(head)))
            .collect();
        let facets: BTreeMap<String, SnapshotFacet> = filtered
            .facets
            .iter()
            .map(|(id, row)| (id.clone(), SnapshotFacet::from_row(row)))
            .collect();
        let links: BTreeMap<String, SnapshotLink> = filtered
            .links
            .iter()
            .map(|(id, row)| (id.clone(), SnapshotLink::from_row(row)))
            .collect();
        let events: Vec<SnapshotEvent> = filtered
            .content_events
            .iter()
            .map(SnapshotEvent::from_ref)
            .collect();
        let estimated_bytes = estimate_entry_bytes(
            principal.credential().len(),
            &records,
            &facets,
            &links,
            &events,
        );
        Self {
            principal_credential: principal.credential().to_string(),
            principal_is_member: principal.is_member(),
            principal_trusted_bypass: principal.trusted_local_bypass(),
            created_at: Instant::now(),
            content_seq: filtered.content_seq,
            authorization_epoch: filtered.authorization_epoch,
            relationship_seq: filtered.relationship_seq,
            unit_seq_max: filtered.unit_seq_max,
            estimated_bytes,
            #[cfg(feature = "v2-kernel-probe")]
            kernel_v2: filtered.native_untyped_records.is_some(),
            records,
            facets,
            links,
            events,
        }
    }

    fn principal_matches(&self, principal: &QueryPrincipal) -> bool {
        self.principal_credential == principal.credential()
            && self.principal_is_member == principal.is_member()
            && self.principal_trusted_bypass == principal.trusted_local_bypass()
    }

    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created_at) >= SNAPSHOT_TTL
    }
}
/// Bounded token store. Count, byte, and TTL caps are enforced on insert;
/// expiry is also checked on read, so a token that ages out between calls
/// restarts rather than serving a stale pin.
///
/// Retired pins leave a bounded, short-lived tombstone (`expired`) carrying
/// only the authority proof — principal fingerprint plus fence stamps, never
/// rows. `catch_up` alone consults it to answer a distinct safe-expiry
/// reason; every other path keeps the generic `token_expired_or_unknown`,
/// so unknown tokens and principal mismatches stay indistinguishable.
#[derive(Debug, Default)]
pub(crate) struct SnapshotStore {
    entries: HashMap<String, SnapshotEntry>,
    bytes: usize,
    expired: HashMap<String, ExpiredPin>,
}

/// Authority proof for one retired pin: who it was pinned for, and the
/// fence stamps it was pinned at. No rows, no bodies, no content — it can
/// vouch that a same-principal re-open loses no authority, never what the
/// rows were.
#[derive(Debug, Clone)]
struct ExpiredPin {
    principal_credential: String,
    principal_is_member: bool,
    principal_trusted_bypass: bool,
    authorization_epoch: i64,
    relationship_seq: i64,
    unit_seq_max: i64,
    retired_at: Instant,
}

impl ExpiredPin {
    fn of(entry: &SnapshotEntry, retired_at: Instant) -> Self {
        Self {
            principal_credential: entry.principal_credential.clone(),
            principal_is_member: entry.principal_is_member,
            principal_trusted_bypass: entry.principal_trusted_bypass,
            authorization_epoch: entry.authorization_epoch,
            relationship_seq: entry.relationship_seq,
            unit_seq_max: entry.unit_seq_max,
            retired_at,
        }
    }

    fn principal_matches(&self, principal: &QueryPrincipal) -> bool {
        self.principal_credential == principal.credential()
            && self.principal_is_member == principal.is_member()
            && self.principal_trusted_bypass == principal.trusted_local_bypass()
    }

    fn fresh(&self, now: Instant) -> bool {
        now.duration_since(self.retired_at) < SNAPSHOT_TTL
    }
}

/// One process-wide admission gate for retained v2 pins. Weak handles never
/// keep a database or its cache alive. All insertion takes this lock before
/// any store lock; paging/expiry/removal only take a store lock, never this
/// lock, so scanning other handles cannot invert the lock order.
#[cfg(feature = "v2-kernel-probe")]
#[derive(Debug)]
struct V2SnapshotBudget {
    max_bytes: usize,
    stores: Vec<std::sync::Weak<std::sync::Mutex<SnapshotStore>>>,
}

#[cfg(feature = "v2-kernel-probe")]
impl V2SnapshotBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            stores: Vec::new(),
        }
    }

    fn insert(
        &mut self,
        store: &std::sync::Arc<std::sync::Mutex<SnapshotStore>>,
        token: String,
        entry: SnapshotEntry,
        retire: Option<&str>,
    ) -> Result<bool> {
        debug_assert!(entry.kernel_v2);
        if entry.estimated_bytes > self.max_bytes || entry.estimated_bytes > SNAPSHOT_MAX_BYTES {
            return Ok(false);
        }
        self.stores.retain(|store| store.strong_count() != 0);
        let weak = std::sync::Arc::downgrade(store);
        if !self.stores.iter().any(|known| known.ptr_eq(&weak)) {
            self.stores.push(weak);
        }
        {
            let mut guard = store
                .lock()
                .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
            if !guard.insert(token.clone(), entry) {
                return Ok(false);
            }
        }
        loop {
            let now = Instant::now();
            let mut total = 0usize;
            let mut oldest = None;
            for handle in self.stores.iter().filter_map(std::sync::Weak::upgrade) {
                // Only cache accounting/eviction may inspect a poisoned handle.
                // Ordinary snapshot reads still refuse that handle as before.
                let mut guard = handle.lock().unwrap_or_else(|error| error.into_inner());
                guard.evict_expired(now);
                for (key, pin) in guard.entries.iter().filter(|(_, pin)| pin.kernel_v2) {
                    total = total.saturating_add(pin.estimated_bytes);
                    if oldest
                        .as_ref()
                        .is_none_or(|(created, _, _)| pin.created_at < *created)
                    {
                        oldest = Some((pin.created_at, handle.clone(), key.clone()));
                    }
                }
            }
            if total <= self.max_bytes {
                break;
            }
            let Some((_, victim, key)) = oldest else {
                break;
            };
            victim
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&key);
        }
        let mut guard = store
            .lock()
            .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
        // A concurrently prepared, older new pin can itself be the global
        // oldest. Never return its already-evicted token or retire its old pin.
        if !guard.entries.contains_key(&token) {
            return Ok(false);
        }
        if let Some(retire) = retire {
            guard.remove(retire);
        }
        Ok(true)
    }
}

impl SnapshotStore {
    /// Insert without holding a store guard. V2 admission always acquires the
    /// process gate first; v1 keeps the existing independent handle budget.
    fn insert_shared(
        store: &std::sync::Arc<std::sync::Mutex<Self>>,
        token: String,
        entry: SnapshotEntry,
        retire: Option<&str>,
    ) -> Result<bool> {
        #[cfg(feature = "v2-kernel-probe")]
        if entry.kernel_v2 {
            static BUDGET: std::sync::OnceLock<std::sync::Mutex<V2SnapshotBudget>> =
                std::sync::OnceLock::new();
            return BUDGET
                .get_or_init(|| {
                    std::sync::Mutex::new(V2SnapshotBudget::new(SNAPSHOT_V2_PROCESS_MAX_BYTES))
                })
                .lock()
                .map_err(|_| Error::engine("workspace snapshot budget is unavailable"))?
                .insert(store, token, entry, retire);
        }
        let mut guard = store
            .lock()
            .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
        if !guard.insert(token, entry) {
            return Ok(false);
        }
        if let Some(retire) = retire {
            guard.remove(retire);
        }
        Ok(true)
    }

    /// Store a pin. Returns `false` (refusal) when the single entry already
    /// exceeds the byte budget: callers must surface unavailable rather than
    /// a token that is already gone. Per-handle eviction excludes the new
    /// token and verifies storage before returning `true`. The process-wide
    /// budget in `insert_shared` can still evict it when it is globally oldest
    /// (including concurrent insertions); that path rechecks storage before
    /// reporting success.
    fn insert(&mut self, token: String, entry: SnapshotEntry) -> bool {
        if entry.estimated_bytes > SNAPSHOT_MAX_BYTES {
            return false;
        }
        let now = Instant::now();
        self.evict_expired(now);
        if let Some(old) = self.entries.remove(&token) {
            self.bytes = self.bytes.saturating_sub(old.estimated_bytes);
        }
        let (max_bytes, max_tokens) = (SNAPSHOT_MAX_BYTES, SNAPSHOT_MAX_TOKENS);
        #[cfg(feature = "v2-kernel-probe")]
        let (max_bytes, max_tokens) = if entry.kernel_v2 {
            (SNAPSHOT_V2_MAX_BYTES, SNAPSHOT_V2_MAX_TOKENS)
        } else {
            (max_bytes, max_tokens)
        };
        let bytes = entry.estimated_bytes;
        self.entries.insert(token.clone(), entry);
        self.bytes += bytes;
        while self.entries.len() > max_tokens || self.bytes > max_bytes {
            let oldest = self
                .entries
                .iter()
                .filter(|(candidate, _)| *candidate != &token)
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(token, _)| token.clone());
            match oldest {
                Some(victim) => {
                    if let Some(removed) = self.entries.remove(&victim) {
                        self.bytes = self.bytes.saturating_sub(removed.estimated_bytes);
                        // Capacity eviction is still a known pin: tombstone it
                        // so a same-principal catch_up can prove safe expiry.
                        self.tombstone(victim, &removed, now);
                    }
                }
                None => break,
            }
        }
        self.entries.contains_key(&token)
    }

    pub(crate) fn remove(&mut self, token: &str) {
        if let Some(removed) = self.entries.remove(token) {
            self.bytes = self.bytes.saturating_sub(removed.estimated_bytes);
            // Rotation after a successful catch_up retires a known-good pin;
            // tombstone it under the same proof rules as expiry.
            self.tombstone(token.to_string(), &removed, Instant::now());
        }
    }

    /// Keep a bounded, short-lived tombstone for a retired pin. Tombstones
    /// never serve rows; they only let `catch_up` prove safe expiry for the
    /// same principal. Count-capped like live pins; the oldest retires first.
    fn tombstone(&mut self, token: String, entry: &SnapshotEntry, now: Instant) {
        self.expired.retain(|_, pin| pin.fresh(now));
        if self.expired.len() >= SNAPSHOT_MAX_TOKENS {
            if let Some(oldest) = self
                .expired
                .iter()
                .min_by_key(|(_, pin)| pin.retired_at)
                .map(|(token, _)| token.clone())
            {
                self.expired.remove(&oldest);
            }
        }
        self.expired.insert(token, ExpiredPin::of(entry, now));
    }

    /// The safe-expiry proof for `catch_up` only: `Some` when the token is a
    /// known retired pin, the caller is the same principal it was pinned for,
    /// and the tombstone itself is fresh. `None` covers unknown tokens,
    /// principal mismatches, and stale tombstones alike — all answer the
    /// generic reason, preserving the oracle boundary.
    fn expired_pin_for(&mut self, principal: &QueryPrincipal, token: &str) -> Option<ExpiredPin> {
        let now = Instant::now();
        self.expired.retain(|_, pin| pin.fresh(now));
        match self.expired.get(token) {
            Some(pin) if pin.principal_matches(principal) => Some(pin.clone()),
            _ => None,
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expired(now))
            .map(|(token, _)| token.clone())
            .collect();
        for token in expired {
            if let Some(removed) = self.entries.remove(&token) {
                self.bytes = self.bytes.saturating_sub(removed.estimated_bytes);
                self.tombstone(token, &removed, now);
            }
        }
    }

    fn get_for(
        &mut self,
        principal: &QueryPrincipal,
        token: &str,
    ) -> std::result::Result<&SnapshotEntry, SnapshotLookup> {
        self.evict_expired(Instant::now());
        match self.entries.get(token) {
            None => Err(SnapshotLookup::Restart {
                reason: "token_expired_or_unknown",
            }),
            Some(entry) if !entry.principal_matches(principal) => Err(SnapshotLookup::Restart {
                reason: "token_expired_or_unknown",
            }),
            Some(entry) => Ok(entry),
        }
    }
}

/// Read outcomes that are not pages. Part of the wire vocabulary: both
/// variants surface as `restart_required` with a reason, never as rows.
/// A principal mismatch reports the same
/// `token_expired_or_unknown` as a missing token: the token is unguessable, but
/// there is no reason to offer a principal oracle either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotLookup {
    Restart { reason: &'static str },
}

/// One facet delete addressed the way page models key facets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FacetKey {
    pub record_id: String,
    pub key: String,
}

/// One link delete addressed the way page models key links. `relationship`
/// is `None` only for a nameless cached row (a `related` pair with no named
/// edge, which the persisted cache keeps but the database never holds: the
/// links table requires a non-null relationship). Catch-up deletes always
/// carry `Some`; resume manifests may name nameless rows to delete them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkKey {
    pub source_id: String,
    pub target_id: String,
    pub relationship: Option<String>,
}

/// Pageable sections of one pinned snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSection {
    Records,
    Facets,
    Links,
    ContentEvents,
}

impl SnapshotSection {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "records" => Some(Self::Records),
            "facets" => Some(Self::Facets),
            "links" => Some(Self::Links),
            "content_events" => Some(Self::ContentEvents),
            _ => None,
        }
    }
}

/// What `open` returns when the index is held: a token plus the triple it is
/// pinned to. `None` from M2 means the index is unavailable (over-cap refusal,
/// absent index, or a racing fence) — never an empty workspace.
pub struct SnapshotOpened {
    pub token: String,
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
}
/// One page of one section. `after_id` is the opaque cursor for the next
/// page (the last row's id), or `None` when the section is exhausted.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotPage {
    pub token: String,
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
    pub section: &'static str,
    pub rows: Vec<serde_json::Value>,
    pub after_id: Option<String>,
    pub has_more: bool,
}

/// Exact delta from an old pin to a fresh view. Apply deletes first, then
/// upserts keyed by id, then swap the event window: the result equals a fresh
/// open at the returned stamp. `fence_moved` is true only when the caller
/// opted into `accept_fence_moved` and the authorization/relationship/unit
/// fences moved under the pin; it is false on the ordinary same-fence path.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotDelta {
    pub token: String,
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
    pub fence_moved: bool,
    pub upsert_records: Vec<SnapshotRecord>,
    pub delete_record_ids: Vec<String>,
    pub upsert_facets: Vec<SnapshotFacet>,
    pub delete_facet_ids: Vec<String>,
    pub delete_facet_keys: Vec<FacetKey>,
    pub upsert_links: Vec<SnapshotLink>,
    pub delete_link_ids: Vec<String>,
    pub delete_link_keys: Vec<LinkKey>,
    pub content_events: Vec<SnapshotEvent>,
}

fn mint_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl crate::db::Db {
    // Select only the physical adapter here; token ownership, budgets, paging,
    // manifest validation and diffs below remain the shared v1 contract.
    async fn snapshot_filtered_index(
        &self,
        principal: QueryPrincipal,
    ) -> Result<Option<FilteredWorkspaceIndex>> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.snapshot_is_v2().await? {
            return crate::mcp::kernel_v2::workspace_snapshot::filtered(self, principal).await;
        }
        self.filtered_workspace_index(principal).await
    }
    async fn snapshot_live_fences(&self) -> Result<(i64, i64, i64)> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.snapshot_is_v2().await? {
            let mut connection = self.governed_pool().acquire().await?;
            return crate::mcp::kernel_v2::workspace_snapshot::fences_on(&mut connection).await;
        }
        self.live_snapshot_fences().await
    }
    #[cfg(feature = "v2-kernel-probe")]
    async fn snapshot_is_v2(&self) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>("PRAGMA application_id")
            .fetch_one(self.pool())
            .await?
            == crate::db::V2_APPLICATION_ID)
    }

    async fn snapshot_gap_exceeded(&self, after: i64, through: i64) -> Result<bool> {
        if through < after {
            return Ok(true);
        }
        #[cfg(feature = "v2-kernel-probe")]
        if self.snapshot_is_v2().await? {
            return crate::mcp::kernel_v2::workspace_snapshot::gap_exceeded(self, after, through)
                .await;
        }
        Ok(through - after > SNAPSHOT_MAX_CATCH_UP_GAP)
    }

    /// Pin the caller's current filtered view under a new token.
    /// Returns `Ok(None)` when M2 holds nothing (generic unavailable) or when
    /// the pin itself is refused by the token budget: a returned token is
    /// always stored and pageable, never already evicted.
    pub async fn open_workspace_snapshot(
        &self,
        principal: QueryPrincipal,
    ) -> Result<Option<SnapshotOpened>> {
        let Some(filtered) = self.snapshot_filtered_index(principal.clone()).await? else {
            return Ok(None);
        };
        let entry = SnapshotEntry::project(&principal, &filtered);
        let opened = SnapshotOpened {
            token: mint_token(),
            content_seq: entry.content_seq,
            authorization_epoch: entry.authorization_epoch,
            relationship_seq: entry.relationship_seq,
        };
        let store = self.workspace_snapshots.clone();
        let token = opened.token.clone();
        if !SnapshotStore::insert_shared(&store, token, entry, None)? {
            return Ok(None);
        }
        Ok(Some(opened))
    }

    /// Read one page of one section from the pinned copy. The copy itself is
    /// immutable under concurrent content commits, but the live
    /// authorization, relationship, and semantic-unit fences are checked before any rows are
    /// returned: a token pinned before a revoke restarts instead of serving
    /// stale rows for the rest of its TTL.
    pub async fn page_workspace_snapshot(
        &self,
        principal: QueryPrincipal,
        token: &str,
        section: SnapshotSection,
        limit: usize,
        after_id: Option<&str>,
    ) -> Result<std::result::Result<SnapshotPage, SnapshotLookup>> {
        let limit = limit.clamp(1, SNAPSHOT_PAGE_MAX);
        // The lock lives only inside this block: the guard (which is not
        // Send) never crosses the fence check's await below.
        let entry = {
            let store = self.workspace_snapshots.clone();
            let mut guard = store
                .lock()
                .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
            match guard.get_for(&principal, token) {
                Ok(entry) => entry.clone(),
                Err(lookup) => return Ok(Err(lookup)),
            }
        };
        let (live_epoch, live_relationship, live_unit_seq_max) =
            self.snapshot_live_fences().await?;
        if live_epoch != entry.authorization_epoch {
            return Ok(Err(SnapshotLookup::Restart {
                reason: "authorization_epoch_moved",
            }));
        }
        if live_relationship != entry.relationship_seq {
            return Ok(Err(SnapshotLookup::Restart {
                reason: "relationship_seq_moved",
            }));
        }
        if live_unit_seq_max != entry.unit_seq_max {
            return Ok(Err(SnapshotLookup::Restart {
                reason: "unit_seq_moved",
            }));
        }
        let section_name = match section {
            SnapshotSection::Records => "records",
            SnapshotSection::Facets => "facets",
            SnapshotSection::Links => "links",
            SnapshotSection::ContentEvents => "content_events",
        };
        let mut rows: Vec<serde_json::Value> = match section {
            SnapshotSection::Records => entry
                .records
                .iter()
                .filter(|(id, _)| after_id.is_none_or(|after| id.as_str() > after))
                .take(limit + 1)
                .map(|(_, row)| serde_json::to_value(row).unwrap_or(serde_json::Value::Null))
                .collect(),
            SnapshotSection::Facets => entry
                .facets
                .iter()
                .filter(|(id, _)| after_id.is_none_or(|after| id.as_str() > after))
                .take(limit + 1)
                .map(|(_, row)| serde_json::to_value(row).unwrap_or(serde_json::Value::Null))
                .collect(),
            SnapshotSection::Links => entry
                .links
                .iter()
                .filter(|(id, _)| after_id.is_none_or(|after| id.as_str() > after))
                .take(limit + 1)
                .map(|(_, row)| serde_json::to_value(row).unwrap_or(serde_json::Value::Null))
                .collect(),
            SnapshotSection::ContentEvents => {
                // Events read in sequence order; the cursor names the last id
                // served and paging resumes just past it. An unknown id means
                // the caller is paging a window that no longer exists.
                let mut selected: &[SnapshotEvent] = entry.events.as_slice();
                if let Some(after) = after_id {
                    match selected.iter().position(|event| event.id == after) {
                        Some(index) => selected = &selected[index + 1..],
                        None => {
                            return Ok(Err(SnapshotLookup::Restart {
                                reason: "unknown_cursor",
                            }));
                        }
                    }
                }
                selected
                    .iter()
                    .take(limit + 1)
                    .map(|event| serde_json::to_value(event).unwrap_or(serde_json::Value::Null))
                    .collect()
            }
        };
        // The id cursor still bounds the page because row ids are unique and
        // BTreeMap iteration is id-ordered. (Events page in sequence order
        // with a positional resume; see above.)
        let has_more = rows.len() > limit;
        if has_more {
            rows.truncate(limit);
        }
        let after_id = if has_more {
            rows.last().and_then(|row| {
                row.get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
        } else {
            None
        };
        Ok(Ok(SnapshotPage {
            token: token.to_string(),
            content_seq: entry.content_seq,
            authorization_epoch: entry.authorization_epoch,
            relationship_seq: entry.relationship_seq,
            section: section_name,
            rows,
            after_id,
            has_more,
        }))
    }
    /// Diff the pinned copy against a fresh M2 view for the same principal.
    /// Same fences: exact upserts/deletes plus a new token, with the old pin
    /// retired only once its replacement is stored. Anything else — missing
    /// token, fence move, content gap beyond the window, M2 `None`, or a
    /// budget-refused replacement (generic unavailable) — carries no old rows.
    /// When `accept_fence_moved` is true and M2 returns a fresh view, a moved
    /// authorization/relationship/unit fence returns the same exact diff with
    /// `fence_moved: true` instead of a restart; the content-gap check still
    /// restarts, and the M2-`None` branch is unchanged.
    pub async fn catch_up_workspace_snapshot(
        &self,
        principal: QueryPrincipal,
        token: &str,
        accept_fence_moved: bool,
    ) -> Result<CatchUpOutcome> {
        // No live pin: either an unknown token, a principal mismatch, or an
        // expired/evicted/rotated one. Only a known tombstone for THIS
        // principal proceeds to the fence proof; everything else stays
        // generic, so unknown tokens and mismatches remain
        // indistinguishable. The lock is released before any await below.
        let old = {
            let store = self.workspace_snapshots.clone();
            let mut guard = store
                .lock()
                .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
            match guard.get_for(&principal, token) {
                Ok(entry) => Ok(entry.clone()),
                Err(_) => match guard.expired_pin_for(&principal, token) {
                    None => {
                        return Ok(CatchUpOutcome::Restart {
                            reason: "token_expired_or_unknown",
                        });
                    }
                    Some(pin) => Err(pin),
                },
            }
        };
        let old = match old {
            Ok(entry) => entry,
            Err(pin) => {
                // Positive authority proof: the pin was issued to this
                // principal (checked above) and no authorization,
                // relationship, or unit fence has moved since it was pinned.
                // Content may be stale — the caller re-opens — but nothing
                // displayed under the old pin was revoked. Any fence move
                // fails closed with its specific reason, never the safe one.
                let (live_epoch, live_relationship, live_unit_seq_max) =
                    self.snapshot_live_fences().await?;
                if live_epoch != pin.authorization_epoch {
                    return Ok(CatchUpOutcome::Restart {
                        reason: "authorization_epoch_moved",
                    });
                }
                if live_relationship != pin.relationship_seq {
                    return Ok(CatchUpOutcome::Restart {
                        reason: "relationship_seq_moved",
                    });
                }
                if live_unit_seq_max != pin.unit_seq_max {
                    return Ok(CatchUpOutcome::Restart {
                        reason: "unit_seq_moved",
                    });
                }
                return Ok(CatchUpOutcome::Restart {
                    reason: "token_expired_fences_unchanged",
                });
            }
        };
        let Some(filtered) = self.snapshot_filtered_index(principal.clone()).await? else {
            // M2 holds nothing: over-cap refusal, absent index, or a fence
            // that raced the visibility read. An unavailable index alone keeps
            // the caller's pin (the governed tail stays safe), but fences that
            // moved under the pin mean revoked rows — that is a restart with
            // no old rows, never an incremental tail.
            let (live_epoch, live_relationship, live_unit_seq_max) =
                self.snapshot_live_fences().await?;
            if live_epoch != old.authorization_epoch {
                return Ok(CatchUpOutcome::Restart {
                    reason: "authorization_epoch_moved",
                });
            }
            if live_relationship != old.relationship_seq {
                return Ok(CatchUpOutcome::Restart {
                    reason: "relationship_seq_moved",
                });
            }
            if live_unit_seq_max != old.unit_seq_max {
                return Ok(CatchUpOutcome::Restart {
                    reason: "unit_seq_moved",
                });
            }
            return Ok(CatchUpOutcome::Unavailable);
        };
        if !accept_fence_moved && filtered.authorization_epoch != old.authorization_epoch {
            return Ok(CatchUpOutcome::Restart {
                reason: "authorization_epoch_moved",
            });
        }
        if !accept_fence_moved && filtered.relationship_seq != old.relationship_seq {
            return Ok(CatchUpOutcome::Restart {
                reason: "relationship_seq_moved",
            });
        }
        if !accept_fence_moved && filtered.unit_seq_max != old.unit_seq_max {
            return Ok(CatchUpOutcome::Restart {
                reason: "unit_seq_moved",
            });
        }
        let fence_moved = filtered.authorization_epoch != old.authorization_epoch
            || filtered.relationship_seq != old.relationship_seq
            || filtered.unit_seq_max != old.unit_seq_max;
        if self
            .snapshot_gap_exceeded(old.content_seq, filtered.content_seq)
            .await?
        {
            return Ok(CatchUpOutcome::Restart {
                reason: "content_gap_outside_window",
            });
        }
        let fresh = SnapshotEntry::project(&principal, &filtered);
        let mut delta = SnapshotDelta {
            token: mint_token(),
            content_seq: fresh.content_seq,
            authorization_epoch: fresh.authorization_epoch,
            relationship_seq: fresh.relationship_seq,
            fence_moved,
            upsert_records: Vec::new(),
            delete_record_ids: Vec::new(),
            upsert_facets: Vec::new(),
            delete_facet_ids: Vec::new(),
            delete_facet_keys: Vec::new(),
            upsert_links: Vec::new(),
            delete_link_ids: Vec::new(),
            delete_link_keys: Vec::new(),
            content_events: fresh.events.clone(),
        };
        for (id, row) in &fresh.records {
            if old.records.get(id) != Some(row) {
                delta.upsert_records.push(row.clone());
            }
        }
        for id in old.records.keys() {
            if !fresh.records.contains_key(id) {
                delta.delete_record_ids.push(id.clone());
            }
        }
        for (id, row) in &fresh.facets {
            if old.facets.get(id) != Some(row) {
                delta.upsert_facets.push(row.clone());
            }
        }
        for (id, row) in &old.facets {
            if !fresh.facets.contains_key(id) {
                delta.delete_facet_ids.push(id.clone());
                delta.delete_facet_keys.push(FacetKey {
                    record_id: row.record_id.clone(),
                    key: row.key.clone(),
                });
            }
        }
        for (id, row) in &fresh.links {
            if old.links.get(id) != Some(row) {
                delta.upsert_links.push(row.clone());
            }
        }
        for (id, row) in &old.links {
            if !fresh.links.contains_key(id) {
                delta.delete_link_ids.push(id.clone());
                delta.delete_link_keys.push(LinkKey {
                    source_id: row.source_id.clone(),
                    target_id: row.target_id.clone(),
                    relationship: Some(row.relationship.clone()),
                });
            }
        }
        // Retire the old pin only after admitting its live replacement.
        if !SnapshotStore::insert_shared(
            &self.workspace_snapshots,
            delta.token.clone(),
            fresh,
            Some(token),
        )? {
            return Ok(CatchUpOutcome::Unavailable);
        }
        Ok(CatchUpOutcome::Delta(Box::new(delta)))
    }
}

/// The three catch-up answers: an exact delta, a whole-model restart with no
/// rows, or a generic unavailable that must never read as empty. The delta is
/// boxed: it is built once per catch-up and its stack footprint would
/// otherwise dwarf the other two answers.
#[derive(Debug)]
pub enum CatchUpOutcome {
    Delta(Box<SnapshotDelta>),
    Restart { reason: &'static str },
    Unavailable,
}

/// Manifest resume (task 679d792): reconcile a bounded client manifest of
/// actual cache row keys + content digests against the fresh
/// current-principal view, returning exact repairs/deletes plus an ordinary
/// new short-lived pin. The manifest is an untrusted comparison hint, never
/// authority: every supplied key is compared against the current authorized
/// projection, claimed old counts/frontiers/fences establish nothing, and
/// all returned row contents come from the fresh filtered view. Key+digest
/// manifests never grant access — a key outside the caller's view resolves
/// to a delete address, never to rows.
pub const RESUME_MANIFEST_VERSION: u32 = 1;
/// Pinned profile string: version and shape travel in the manifest so a
/// future projection change restarts instead of miscomparing.
pub const RESUME_MANIFEST_PROFILE: &str = "workspace-snapshot-resume/v1";
/// Serialized manifest cap: 3.5 MiB, safely under the hosted 4 MiB MCP
/// envelope (`MCP_REQUEST_BODY_LIMIT` in held/hosting/src/http.rs), leaving
/// room for escaping expansion and MCP metadata. Above it the client takes
/// the existing full path; the server refuses before allocating typed maps.
pub const RESUME_MANIFEST_MAX_BYTES: usize = 3_670_016;
/// Total manifest entries across all three sections. Bounds map allocation
/// after the byte cap has passed but before any typed vector is built.
pub const RESUME_MANIFEST_MAX_ENTRIES: usize = 32_768;
/// Restart reasons for the resume path. All carry no rows, like every other
/// restart in this module.
pub const RESUME_RESTART_PROFILE_MISMATCH: &str = "manifest_profile_mismatch";
pub const RESUME_RESTART_MALFORMED: &str = "manifest_malformed";
pub const RESUME_RESTART_OVER_CAP: &str = "manifest_over_cap";

/// Digest domain tags: a section marker pinned into every digest so a record
/// digest can never validate as a facet or link digest (type confusion).
const RESUME_DIGEST_DOMAIN_RECORD: &[u8] = b"native.ws-resume/v1/record\x00";
const RESUME_DIGEST_DOMAIN_FACET: &[u8] = b"native.ws-resume/v1/facet\x00";
const RESUME_DIGEST_DOMAIN_LINK: &[u8] = b"native.ws-resume/v1/link\x00";

/// One string/null field of the fixed digest codec: `0x00` for null or
/// missing (the two encode identically, by construction), else `0x01`
/// followed by the big-endian u32 byte length and the raw UTF-8 bytes. No
/// escaping layer exists, so Rust and JS encoders agree byte for byte as
/// long as the input is valid Unicode; invalid UTF-8 must never reach this
/// function (JSON parsing already rejects it).
fn resume_digest_field(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => out.push(0x00),
        Some(text) => {
            out.push(0x01);
            let bytes = text.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }
}

fn resume_digest_hex(domain: &[u8], fields: &[Option<&str>]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain);
    let mut encoded = Vec::new();
    for field in fields {
        resume_digest_field(&mut encoded, *field);
    }
    hasher.update(&encoded);
    hex::encode(hasher.finalize())
}

/// Digest over exactly the cached record projection: the governed-minus-body
/// public fields the demo-shell cache persists, in this fixed order.
pub(crate) fn record_resume_digest(row: &SnapshotRecord) -> String {
    record_resume_digest_fields(&[
        Some(row.id.as_str()),
        row.record_type.as_deref(),
        row.kind.as_deref(),
        Some(row.name.as_str()),
        row.home_id.as_deref(),
        row.lifecycle.as_deref(),
        Some(row.persistence.as_str()),
        row.maturity.as_deref(),
        row.summary.as_deref(),
        row.last_activity_at.as_deref(),
        Some(row.created_at.as_str()),
        Some(row.updated_at.as_str()),
        row.deleted_at.as_deref(),
    ])
}

/// Field-level record digest: the 13 cached projection fields in pinned
/// order. The struct wrapper above is what the server uses; vectors address
/// this level so permutations (including nulls in required positions) stay
/// expressible.
pub(crate) fn record_resume_digest_fields(fields: &[Option<&str>]) -> String {
    assert_eq!(fields.len(), 13, "record digest pins 13 fields");
    resume_digest_hex(RESUME_DIGEST_DOMAIN_RECORD, fields)
}

/// Digest over the cached facet projection `{record_id, key, value}` only.
/// Raw facet metadata (row id, value_num, vocab_ref, timestamps) is absent
/// from the cache and stays out of the digest: no float canonicalization.
pub(crate) fn facet_resume_digest(record_id: &str, key: &str, value: Option<&str>) -> String {
    resume_digest_hex(
        RESUME_DIGEST_DOMAIN_FACET,
        &[Some(record_id), Some(key), value],
    )
}

/// Digest over the cached link projection `{source, target, relationship,
/// note}`: the tuple plus the note, so a note-only change repairs.
pub(crate) fn link_resume_digest(
    source_id: &str,
    target_id: &str,
    relationship: Option<&str>,
    note: Option<&str>,
) -> String {
    resume_digest_hex(
        RESUME_DIGEST_DOMAIN_LINK,
        &[Some(source_id), Some(target_id), relationship, note],
    )
}

/// A validated resume manifest: logical keys plus claimed digests. Digests
/// are comparison hints only; row contents always come from the fresh view.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResumeManifest {
    records: Vec<(String, String)>,
    facets: Vec<(String, String, String)>,
    links: Vec<(String, String, Option<String>, String)>,
}

fn resume_digest_valid(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validate a resume manifest before any typed map is built. Counts and
/// duplicates are checked during the walk so a lying manifest cannot buy
/// allocation: over-cap restarts before insertion, duplicates and shape
/// violations restart as malformed.
pub(crate) fn parse_resume_manifest(
    manifest: &serde_json::Value,
) -> std::result::Result<ResumeManifest, &'static str> {
    let object = manifest.as_object().ok_or(RESUME_RESTART_MALFORMED)?;
    let version = object
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(RESUME_RESTART_PROFILE_MISMATCH)?;
    if version != u64::from(RESUME_MANIFEST_VERSION) {
        return Err(RESUME_RESTART_PROFILE_MISMATCH);
    }
    let profile = object
        .get("profile")
        .and_then(serde_json::Value::as_str)
        .ok_or(RESUME_RESTART_PROFILE_MISMATCH)?;
    if profile != RESUME_MANIFEST_PROFILE {
        return Err(RESUME_RESTART_PROFILE_MISMATCH);
    }
    let record_tuples = object
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or(RESUME_RESTART_MALFORMED)?;
    let facet_tuples = object
        .get("facets")
        .and_then(serde_json::Value::as_array)
        .ok_or(RESUME_RESTART_MALFORMED)?;
    let link_tuples = object
        .get("links")
        .and_then(serde_json::Value::as_array)
        .ok_or(RESUME_RESTART_MALFORMED)?;
    // Sum section counts with an overflow guard BEFORE any typed clone or
    // map is built: a lying manifest cannot buy allocation through entry
    // count. Duplicate detection below still needs sets, but those are
    // bounded by this gate.
    let total_entries = record_tuples
        .len()
        .checked_add(facet_tuples.len())
        .and_then(|sum| sum.checked_add(link_tuples.len()))
        .ok_or(RESUME_RESTART_MALFORMED)?;
    if total_entries > RESUME_MANIFEST_MAX_ENTRIES {
        return Err(RESUME_RESTART_OVER_CAP);
    }
    // Measure the re-encoded byte length through a bounded counting sink so
    // no second copy of an oversized manifest is ever allocated. A
    // serde_json::Value always serializes, so the only write failure is the
    // cap itself.
    {
        struct ByteCounter {
            count: usize,
            limit: usize,
        }
        impl std::io::Write for ByteCounter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.count = self.count.saturating_add(bytes.len());
                if self.count > self.limit {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::QuotaExceeded,
                        "manifest over cap",
                    ));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut counter = ByteCounter {
            count: 0,
            limit: RESUME_MANIFEST_MAX_BYTES,
        };
        if serde_json::to_writer(&mut counter, manifest).is_err() {
            return Err(RESUME_RESTART_OVER_CAP);
        }
    }
    let mut parsed = ResumeManifest::default();
    let mut record_keys = std::collections::HashSet::new();
    let mut facet_keys = std::collections::HashSet::new();
    let mut link_keys = std::collections::HashSet::new();
    for tuple in record_tuples {
        let pair = tuple.as_array().ok_or(RESUME_RESTART_MALFORMED)?;
        if pair.len() != 2 {
            return Err(RESUME_RESTART_MALFORMED);
        }
        let id = pair[0].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        let digest = pair[1].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        if id.is_empty() || !resume_digest_valid(digest) {
            return Err(RESUME_RESTART_MALFORMED);
        }
        if !record_keys.insert(id.to_string()) {
            return Err(RESUME_RESTART_MALFORMED);
        }
        parsed.records.push((id.to_string(), digest.to_string()));
    }
    for tuple in facet_tuples {
        let triple = tuple.as_array().ok_or(RESUME_RESTART_MALFORMED)?;
        if triple.len() != 3 {
            return Err(RESUME_RESTART_MALFORMED);
        }
        let record_id = triple[0].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        let key = triple[1].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        let digest = triple[2].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        if record_id.is_empty() || key.is_empty() || !resume_digest_valid(digest) {
            return Err(RESUME_RESTART_MALFORMED);
        }
        if !facet_keys.insert((record_id.to_string(), key.to_string())) {
            return Err(RESUME_RESTART_MALFORMED);
        }
        parsed
            .facets
            .push((record_id.to_string(), key.to_string(), digest.to_string()));
    }
    for tuple in link_tuples {
        let quad = tuple.as_array().ok_or(RESUME_RESTART_MALFORMED)?;
        if quad.len() != 4 {
            return Err(RESUME_RESTART_MALFORMED);
        }
        let source_id = quad[0].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        let target_id = quad[1].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        let relationship = match &quad[2] {
            serde_json::Value::Null => None,
            serde_json::Value::String(text) => Some(text.clone()),
            _ => return Err(RESUME_RESTART_MALFORMED),
        };
        let digest = quad[3].as_str().ok_or(RESUME_RESTART_MALFORMED)?;
        if source_id.is_empty() || target_id.is_empty() || !resume_digest_valid(digest) {
            return Err(RESUME_RESTART_MALFORMED);
        }
        if !link_keys.insert((
            source_id.to_string(),
            target_id.to_string(),
            relationship.clone(),
        )) {
            return Err(RESUME_RESTART_MALFORMED);
        }
        parsed.links.push((
            source_id.to_string(),
            target_id.to_string(),
            relationship,
            digest.to_string(),
        ));
    }
    Ok(parsed)
}

/// Which fence moved between the fresh view and the live read, if any.
/// Pure so the race rule is unit-testable without interleaving commits.
fn resume_fence_race_reason(fresh: (i64, i64, i64), live: (i64, i64, i64)) -> Option<&'static str> {
    if live.0 != fresh.0 {
        return Some("authorization_epoch_moved");
    }
    if live.1 != fresh.1 {
        return Some("relationship_seq_moved");
    }
    if live.2 != fresh.2 {
        return Some("unit_seq_moved");
    }
    None
}

impl crate::db::Db {
    /// Reconcile a client manifest against the fresh current-principal view.
    ///
    /// Every supplied key is compared against the current authorized
    /// projection; claimed old counts, frontiers, and fences establish
    /// nothing. Missing keys become upserts (which is also how excluded
    /// Message/Annotation rows and absent lifecycle facets are restored to
    /// the full model), stale or altered keys become repairs, and manifest
    /// keys outside the current view become delete addresses — never rows.
    /// No content-gap limit applies: this is an all-key reconciliation, not
    /// a windowed tail (the `catch_up` gap is unchanged). A fence that races
    /// between the fresh view and the answer restarts with no rows; M2
    /// `None` is the generic unavailable. The new pin is an ordinary
    /// short-lived token serving later `page`/`catch_up` calls; no old
    /// token or durable baseline is involved, so a server restart loses
    /// nothing this call needs.
    pub async fn resume_workspace_snapshot(
        &self,
        principal: QueryPrincipal,
        manifest_value: &serde_json::Value,
    ) -> Result<CatchUpOutcome> {
        let manifest = match parse_resume_manifest(manifest_value) {
            Ok(parsed) => parsed,
            Err(reason) => {
                return Ok(CatchUpOutcome::Restart { reason });
            }
        };
        let Some(filtered) = self.snapshot_filtered_index(principal.clone()).await? else {
            return Ok(CatchUpOutcome::Unavailable);
        };
        let mut delta = SnapshotDelta {
            token: mint_token(),
            content_seq: filtered.content_seq,
            authorization_epoch: filtered.authorization_epoch,
            relationship_seq: filtered.relationship_seq,
            fence_moved: false,
            upsert_records: Vec::new(),
            delete_record_ids: Vec::new(),
            upsert_facets: Vec::new(),
            delete_facet_ids: Vec::new(),
            delete_facet_keys: Vec::new(),
            upsert_links: Vec::new(),
            delete_link_ids: Vec::new(),
            delete_link_keys: Vec::new(),
            content_events: filtered
                .content_events
                .iter()
                .map(SnapshotEvent::from_ref)
                .collect(),
        };
        let mut manifest_record_keys = std::collections::HashSet::new();
        for (id, digest) in &manifest.records {
            manifest_record_keys.insert(id.clone());
            match filtered.records.get(id) {
                None => delta.delete_record_ids.push(id.clone()),
                Some(head) => {
                    let row = filtered.snapshot_record(head);
                    if record_resume_digest(&row) != *digest {
                        delta.upsert_records.push(row);
                    }
                }
            }
        }
        for (id, head) in &filtered.records {
            if !manifest_record_keys.contains(id) {
                delta.upsert_records.push(filtered.snapshot_record(head));
            }
        }
        let mut fresh_facets: std::collections::HashMap<
            (String, String),
            &crate::workspace_index::FacetRow,
        > = std::collections::HashMap::new();
        for row in filtered.facets.values() {
            fresh_facets.insert((row.record_id.clone(), row.key.clone()), row);
        }
        let mut manifest_facet_keys = std::collections::HashSet::new();
        for (record_id, key, digest) in &manifest.facets {
            manifest_facet_keys.insert((record_id.clone(), key.clone()));
            match fresh_facets.get(&(record_id.clone(), key.clone())) {
                None => delta.delete_facet_keys.push(FacetKey {
                    record_id: record_id.clone(),
                    key: key.clone(),
                }),
                Some(row) => {
                    let projected = SnapshotFacet::from_row(row);
                    if facet_resume_digest(
                        &projected.record_id,
                        &projected.key,
                        projected.value.as_deref(),
                    ) != *digest
                    {
                        delta.upsert_facets.push(projected);
                    }
                }
            }
        }
        for ((record_id, key), row) in &fresh_facets {
            if !manifest_facet_keys.contains(&(record_id.clone(), key.clone())) {
                delta.upsert_facets.push(SnapshotFacet::from_row(row));
            }
        }
        let mut fresh_links: std::collections::HashMap<
            (String, String, Option<String>),
            &crate::workspace_index::LinkRow,
        > = std::collections::HashMap::new();
        for row in filtered.links.values() {
            fresh_links.insert(
                (
                    row.source_id.clone(),
                    row.target_id.clone(),
                    Some(row.relationship.clone()),
                ),
                row,
            );
        }
        let mut manifest_link_keys = std::collections::HashSet::new();
        for (source_id, target_id, relationship, digest) in &manifest.links {
            let key = (source_id.clone(), target_id.clone(), relationship.clone());
            manifest_link_keys.insert(key.clone());
            match fresh_links.get(&key) {
                None => delta.delete_link_keys.push(LinkKey {
                    source_id: source_id.clone(),
                    target_id: target_id.clone(),
                    relationship: relationship.clone(),
                }),
                Some(row) => {
                    let projected = SnapshotLink::from_row(row);
                    if link_resume_digest(
                        &projected.source_id,
                        &projected.target_id,
                        Some(projected.relationship.as_str()),
                        projected.note.as_deref(),
                    ) != *digest
                    {
                        // Delete-before-upsert: the client's takeLink keeps
                        // the first note it saw for a duplicate edge, so a
                        // bare upsert cannot repair a changed note.
                        delta.delete_link_keys.push(LinkKey {
                            source_id: source_id.clone(),
                            target_id: target_id.clone(),
                            relationship: relationship.clone(),
                        });
                        delta.upsert_links.push(projected);
                    }
                }
            }
        }
        for ((source_id, target_id, relationship), row) in &fresh_links {
            if !manifest_link_keys.contains(&(
                source_id.clone(),
                target_id.clone(),
                relationship.clone(),
            )) {
                delta.upsert_links.push(SnapshotLink::from_row(row));
            }
        }
        // A fence that moved while the answer was being built voids it: the
        // diff above may already describe a revoked world.
        let (live_epoch, live_relationship, live_unit_seq_max) =
            self.snapshot_live_fences().await?;
        if let Some(reason) = resume_fence_race_reason(
            (
                filtered.authorization_epoch,
                filtered.relationship_seq,
                filtered.unit_seq_max,
            ),
            (live_epoch, live_relationship, live_unit_seq_max),
        ) {
            return Ok(CatchUpOutcome::Restart { reason });
        }
        let fresh = SnapshotEntry::project(&principal, &filtered);
        if !SnapshotStore::insert_shared(
            &self.workspace_snapshots,
            delta.token.clone(),
            fresh,
            None,
        )? {
            return Ok(CatchUpOutcome::Unavailable);
        }
        Ok(CatchUpOutcome::Delta(Box::new(delta)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::events::{FacetSetPayload, LinkAddedPayload};
    use crate::query::QueryPrincipal;
    use crate::store::{add_link, append, create_record, set_facet, update_record, AppendSpec};

    const ALICE_COMMON_ID: &str = "9e795001-0000-4000-8000-000000000001";
    const ALICE_ONLY_ID: &str = "9e795001-0000-4000-8000-000000000002";
    const BEA_ONLY_ID: &str = "9e795001-0000-4000-8000-000000000003";

    fn alice() -> QueryPrincipal {
        QueryPrincipal::authenticated("alice", true)
    }

    fn bea() -> QueryPrincipal {
        QueryPrincipal::authenticated("bea", true)
    }

    async fn three_record_fixture() -> crate::db::Db {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, name) in [
            (ALICE_COMMON_ID, "Common"),
            (ALICE_ONLY_ID, "Alice only"),
            (BEA_ONLY_ID, "Bea only"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id, "type": "Document", "kind": "note", "name": name,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:policy",
            ALICE_COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            ALICE_ONLY_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            BEA_ONLY_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        db
    }

    async fn open_token(db: &crate::db::Db, principal: QueryPrincipal) -> SnapshotOpened {
        db.open_workspace_snapshot(principal)
            .await
            .unwrap()
            .expect("test workspace is held below the cap")
    }

    async fn page_all_records(
        db: &crate::db::Db,
        principal: QueryPrincipal,
        token: &str,
    ) -> BTreeMap<String, SnapshotRecord> {
        let mut rows = BTreeMap::new();
        let mut after_id: Option<String> = None;
        loop {
            let page = db
                .page_workspace_snapshot(
                    principal.clone(),
                    token,
                    SnapshotSection::Records,
                    500,
                    after_id.as_deref(),
                )
                .await
                .unwrap()
                .expect("token stays pinned while paging");
            for row in page.rows {
                let record: SnapshotRecord = serde_json::from_value(row).unwrap();
                rows.insert(record.id.clone(), record);
            }
            if !page.has_more {
                break;
            }
            after_id = page.after_id;
        }
        rows
    }

    async fn page_all_section(
        db: &crate::db::Db,
        principal: QueryPrincipal,
        token: &str,
        section: SnapshotSection,
    ) -> Vec<serde_json::Value> {
        let mut rows = Vec::new();
        let mut after_id: Option<String> = None;
        loop {
            let page = db
                .page_workspace_snapshot(
                    principal.clone(),
                    token,
                    section,
                    500,
                    after_id.as_deref(),
                )
                .await
                .unwrap()
                .expect("token stays pinned while paging");
            rows.extend(page.rows);
            if !page.has_more {
                break;
            }
            after_id = page.after_id;
        }
        rows
    }

    fn facet_map(rows: Vec<serde_json::Value>) -> BTreeMap<String, SnapshotFacet> {
        rows.into_iter()
            .map(|row| {
                let facet: SnapshotFacet = serde_json::from_value(row).unwrap();
                (facet.id.clone(), facet)
            })
            .collect()
    }

    fn link_map(rows: Vec<serde_json::Value>) -> BTreeMap<String, SnapshotLink> {
        rows.into_iter()
            .map(|row| {
                let link: SnapshotLink = serde_json::from_value(row).unwrap();
                (link.id.clone(), link)
            })
            .collect()
    }

    #[tokio::test]
    async fn two_principals_see_only_what_they_may() {
        let db = three_record_fixture().await;
        let alice_open = open_token(&db, alice()).await;
        let bea_open = open_token(&db, bea()).await;
        let alice_rows = page_all_records(&db, alice(), &alice_open.token).await;
        let bea_rows = page_all_records(&db, bea(), &bea_open.token).await;
        assert!(alice_rows.contains_key(ALICE_COMMON_ID));
        assert!(alice_rows.contains_key(ALICE_ONLY_ID));
        assert!(!alice_rows.contains_key(BEA_ONLY_ID));
        assert!(bea_rows.contains_key(ALICE_COMMON_ID));
        assert!(bea_rows.contains_key(BEA_ONLY_ID));
        assert!(!bea_rows.contains_key(ALICE_ONLY_ID));
        // No governed-view column leaks further than the principal's own
        // snapshot: bea's projection never names alice's record at all.
        let governed = crate::query::sql::query_sql(&db, bea(), "SELECT id FROM records")
            .await
            .unwrap();
        let governed_ids: std::collections::HashSet<String> = governed
            .rows
            .iter()
            .filter_map(|row| {
                row.as_object()
                    .and_then(|row| row.values().next())
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(
            bea_rows
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>(),
            governed_ids
        );
    }
    #[tokio::test]
    async fn narrowing_epoch_forces_restart_with_no_old_rows() {
        let db = three_record_fixture().await;
        let bea_open = open_token(&db, bea()).await;
        assert!(page_all_records(&db, bea(), &bea_open.token)
            .await
            .contains_key(ALICE_COMMON_ID));
        replace_explicit_policy(
            &db,
            "test:narrow",
            ALICE_COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        match db
            .catch_up_workspace_snapshot(bea(), &bea_open.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            other => panic!("narrowing must restart, got {other:?}"),
        }
        // Paging the revoked pin serves no rows either: the fence check runs
        // before any row is read, even though the token is fresh.
        match db
            .page_workspace_snapshot(bea(), &bea_open.token, SnapshotSection::Records, 50, None)
            .await
            .unwrap()
        {
            Err(SnapshotLookup::Restart { reason }) => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            Ok(_) => panic!("revoked pin must not page stale rows"),
        }
        // The old token still pages its pin — but a fresh open no longer
        // shows the narrowed record, so nothing formerly visible leaks.
        let fresh = open_token(&db, bea()).await;
        assert!(!page_all_records(&db, bea(), &fresh.token)
            .await
            .contains_key(ALICE_COMMON_ID));
    }

    #[tokio::test]
    async fn unitization_restarts_a_pin_before_it_can_page_a_hidden_artifact() {
        let db = three_record_fixture().await;
        let envelope = "9e795001-0000-4000-8000-000000000004";
        let derived = "9e795001-0000-4000-8000-000000000005";
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Entity",
                    "kind": "semantic-unit",
                    "name": "unit envelope",
                    "home_id": crate::schema::ROOT_RECORD_ID,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": derived,
                "type": "Document",
                "kind": "attachment",
                "name": "derived artifact",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        let derived_anchor: String =
            sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id = ?")
                .bind(derived)
                .fetch_one(db.pool())
                .await
                .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &derived_anchor,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("unit-derived-artifact".into()),
                source_id: derived.into(),
                target_id: envelope.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();

        let opened = open_token(&db, alice()).await;
        assert!(page_all_records(&db, alice(), &opened.token)
            .await
            .contains_key(derived));
        let (epoch_before, relationship_before, unit_before) =
            db.live_snapshot_fences().await.unwrap();
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version": "native.freshness-kernel.v1",
                    "authority_bearer_record_id": ALICE_COMMON_ID,
                    "label": "unit envelope",
                }),
                actor: Some("test:unit".into()),
            },
        )
        .await
        .unwrap();
        let (epoch_after, relationship_after, unit_after) =
            db.live_snapshot_fences().await.unwrap();
        assert_eq!(epoch_after, epoch_before);
        assert_eq!(relationship_after, relationship_before);
        assert!(unit_after > unit_before);
        match db
            .page_workspace_snapshot(alice(), &opened.token, SnapshotSection::Records, 50, None)
            .await
            .unwrap()
        {
            Err(SnapshotLookup::Restart { reason }) => assert_eq!(reason, "unit_seq_moved"),
            Ok(_) => panic!("unitized pin must not page a formerly visible artifact"),
        }
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => assert_eq!(reason, "unit_seq_moved"),
            other => panic!("unitized pin must restart, got {other:?}"),
        }
        let fresh = open_token(&db, alice()).await;
        assert!(!page_all_records(&db, alice(), &fresh.token)
            .await
            .contains_key(derived));
    }

    #[tokio::test]
    async fn relationship_move_forces_restart() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        // The governed relationship writer bumps the relationship fence
        // without touching the authorization epoch or the content cursor.
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "manage_relationships",
                json!({
                    "action": "assert",
                    "relationship_type": "relates_to",
                    "endpoints": [
                        {"role": "participant", "record_id": ALICE_COMMON_ID},
                        {"role": "participant", "record_id": ALICE_ONLY_ID}
                    ],
                    "idempotency_key": "workspace-snapshot-fence"
                }),
            )
            .await
            .unwrap();
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "relationship_seq_moved");
            }
            other => panic!("relationship fence move must restart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn catch_up_applied_equals_fresh_open() {
        let db = three_record_fixture().await;
        set_facet(
            &db,
            ALICE_COMMON_ID,
            FacetSetPayload {
                key: "priority".to_string(),
                value: Some("high".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        // Same-fence changes only: rename, facet set, content link add,
        // delete. (A policy write would bump the epoch and must restart, so
        // the newcomer below is created and shared before the pin.)
        let newcomer = "9e795001-0000-4000-8000-000000000021";
        create_record(
            &db,
            json!({
                "id": newcomer,
                "type": "Document", "kind": "note", "name": "Newcomer",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            newcomer,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let opened = open_token(&db, alice()).await;
        let mut model = page_all_records(&db, alice(), &opened.token).await;
        assert!(model.contains_key(newcomer));
        // The old pin's facet/link sections are read before catch_up retires it.
        let mut facet_model =
            facet_map(page_all_section(&db, alice(), &opened.token, SnapshotSection::Facets).await);
        let mut link_model =
            link_map(page_all_section(&db, alice(), &opened.token, SnapshotSection::Links).await);
        // Record INSERT/DELETE bump the epoch by schema trigger and must
        // restart, so equality here covers the fence-stable writes: renames,
        // facet set/unset, and content link adds. (Record delete_ids machinery
        // stays for symmetry; no fence-stable record delete exists to drive it.)
        update_record(&db, newcomer, json!({ "name": "Newcomer renamed" }))
            .await
            .unwrap();
        update_record(&db, ALICE_ONLY_ID, json!({ "name": "Alice renamed" }))
            .await
            .unwrap();
        set_facet(
            &db,
            ALICE_ONLY_ID,
            FacetSetPayload {
                key: "priority".to_string(),
                value: Some("low".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("9e795001-0000-4000-8000-000000000022".to_string()),
                source_id: ALICE_ONLY_ID.to_string(),
                target_id: newcomer.to_string(),
                // Content-owned and fence-stable: `relates_to` belongs to the
                // relationship tier (projected away), and `part_of` moves the
                // epoch by schema trigger (containment is auth-relevant).
                relationship: "mentions".to_string(),
                note: Some("see also".to_string()),
            },
        )
        .await
        .unwrap();
        crate::store::unset_facet(&db, ALICE_COMMON_ID, "priority")
            .await
            .unwrap();
        let delta = match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("same-fence changes must delta, got {other:?}"),
        };
        assert!(
            !delta.fence_moved,
            "same-fence delta carries fence_moved:false"
        );
        // Exact application rule: deletes first, then whole-row upserts.
        for id in &delta.delete_record_ids {
            model.remove(id);
        }
        assert!(
            delta.delete_record_ids.is_empty(),
            "no fence-stable record delete exists; record removal restarts"
        );
        assert!(delta
            .upsert_records
            .iter()
            .any(|row| row.id == newcomer && row.name == "Newcomer renamed"));
        assert!(delta
            .upsert_facets
            .iter()
            .any(|facet| facet.record_id == ALICE_ONLY_ID && facet.key == "priority"));
        assert!(delta
            .upsert_links
            .iter()
            .any(|link| link.id == "9e795001-0000-4000-8000-000000000022"));
        assert!(
            !delta.delete_facet_ids.is_empty(),
            "the unset priority facet must be reported deleted"
        );
        assert_eq!(
            delta.delete_facet_keys.len(),
            delta.delete_facet_ids.len(),
            "every facet delete carries its page key"
        );
        // A fresh open at the returned stamp must match the caught-up model
        // across records, facets, and links alike.
        let fresh = open_token(&db, alice()).await;
        assert_eq!(delta.content_seq, fresh.content_seq);
        let fresh_model = page_all_records(&db, alice(), &fresh.token).await;
        for row in delta.upsert_records {
            model.insert(row.id.clone(), row);
        }
        assert_eq!(model, fresh_model);
        for id in &delta.delete_facet_ids {
            facet_model.remove(id);
        }
        for facet in delta.upsert_facets {
            facet_model.insert(facet.id.clone(), facet);
        }
        assert_eq!(
            facet_model,
            facet_map(page_all_section(&db, alice(), &fresh.token, SnapshotSection::Facets).await)
        );
        for id in &delta.delete_link_ids {
            link_model.remove(id);
        }
        for link in delta.upsert_links {
            link_model.insert(link.id.clone(), link);
        }
        assert_eq!(
            link_model,
            link_map(page_all_section(&db, alice(), &fresh.token, SnapshotSection::Links).await)
        );
        let fresh_events: Vec<SnapshotEvent> =
            page_all_section(&db, alice(), &fresh.token, SnapshotSection::ContentEvents)
                .await
                .into_iter()
                .map(|row| serde_json::from_value(row).unwrap())
                .collect();
        assert_eq!(delta.content_events, fresh_events);
    }

    #[tokio::test]
    async fn active_content_writes_do_not_move_pinned_pages() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        let before = page_all_records(&db, alice(), &opened.token).await;
        assert!(before.contains_key(ALICE_ONLY_ID));
        // Same-fence writes only: record INSERT/DELETE always bump the epoch
        // by schema trigger, so only renames, facet writes, and content links
        // can land under a pin. The pin must page its pre-write rows.
        update_record(&db, ALICE_ONLY_ID, json!({ "name": "Alice renamed" }))
            .await
            .unwrap();
        set_facet(
            &db,
            ALICE_ONLY_ID,
            FacetSetPayload {
                key: "priority".to_string(),
                value: Some("low".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        crate::store::archive_record(&db, ALICE_ONLY_ID)
            .await
            .unwrap();
        let pinned = page_all_records(&db, alice(), &opened.token).await;
        assert_eq!(pinned, before);
        assert_eq!(pinned[ALICE_ONLY_ID].name, "Alice only");
        // And a fence move restarts the same pin with no rows, even though
        // the token itself is fresh and the principal matches.
        replace_explicit_policy(
            &db,
            "test:narrow",
            ALICE_COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        match db
            .page_workspace_snapshot(alice(), &opened.token, SnapshotSection::Records, 50, None)
            .await
            .unwrap()
        {
            Err(SnapshotLookup::Restart { reason }) => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            Ok(_) => panic!("post-revoke page must not serve stale rows"),
        }
    }

    #[tokio::test]
    async fn catch_up_restarts_beyond_the_content_window() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        // Facet writes advance the content cursor without moving either
        // fence, so a gap past the window must restart for the gap alone.
        for index in 0..SNAPSHOT_MAX_CATCH_UP_GAP + 8 {
            set_facet(
                &db,
                ALICE_ONLY_ID,
                FacetSetPayload {
                    key: "churn".to_string(),
                    value: Some(index.to_string()),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
        }
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "content_gap_outside_window");
            }
            other => panic!("over-window gap must restart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_token_restarts_without_oracle() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        // Another principal's token and a forged token answer identically.
        let foreign = db
            .page_workspace_snapshot(bea(), &opened.token, SnapshotSection::Records, 50, None)
            .await
            .unwrap();
        let forged = db
            .page_workspace_snapshot(
                alice(),
                "not-a-real-token",
                SnapshotSection::Records,
                50,
                None,
            )
            .await
            .unwrap();
        for outcome in [foreign, forged] {
            match outcome {
                Err(SnapshotLookup::Restart { reason }) => {
                    assert_eq!(reason, "token_expired_or_unknown");
                }
                Ok(_) => panic!("foreign token must not page"),
            }
        }
    }

    /// Age one live pin past its TTL, the way the store's own bound test
    /// does. The pin is expired but still known: the tombstone proof below
    /// can vouch for it.
    fn expire_token(db: &crate::db::Db, token: &str) {
        let store = db.workspace_snapshots.clone();
        let mut guard = store.lock().unwrap();
        guard.entries.get_mut(token).unwrap().created_at =
            Instant::now() - SNAPSHOT_TTL - Duration::from_secs(1);
    }

    #[tokio::test]
    async fn expired_known_token_proves_safe_catch_up_for_same_principal() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        expire_token(&db, &opened.token);
        // Paging stays generic even for the same principal: only catch_up
        // carries the safe-expiry proof, never rows.
        match db
            .page_workspace_snapshot(alice(), &opened.token, SnapshotSection::Records, 50, None)
            .await
            .unwrap()
        {
            Err(SnapshotLookup::Restart { reason }) => {
                assert_eq!(reason, "token_expired_or_unknown");
            }
            Ok(_) => panic!("expired token must not serve"),
        }
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "token_expired_fences_unchanged");
            }
            other => panic!("safe expiry must prove, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn expired_token_mismatch_and_unknown_stay_generic_on_catch_up() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        expire_token(&db, &opened.token);
        // Another principal's catch_up and a forged token answer identically:
        // the tombstone never vouches across principals, preserving the
        // oracle boundary the page path already holds.
        for (principal, token) in [
            (bea(), opened.token.clone()),
            (alice(), "not-a-real-token".to_string()),
        ] {
            match db
                .catch_up_workspace_snapshot(principal, &token, false)
                .await
                .unwrap()
            {
                CatchUpOutcome::Restart { reason } => {
                    assert_eq!(reason, "token_expired_or_unknown");
                }
                other => panic!("mismatch/unknown must stay generic, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn expired_token_fence_move_fails_closed_without_safe_reason() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        expire_token(&db, &opened.token);
        // A fence move after expiry must surface its specific reason — never
        // the safe one — so a revoked model cannot retain live content.
        replace_explicit_policy(
            &db,
            "test:narrow",
            ALICE_COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            other => panic!("fence move must fail closed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn expired_pin_with_moved_fence_restarts_even_opt_in() {
        // The tombstone path runs before the opt-in fence-moved path and
        // ignores the flag: an expired pin can never yield a delta, so a
        // revoked model cannot retain live content past expiry.
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        expire_token(&db, &opened.token);
        replace_explicit_policy(
            &db,
            "test:narrow",
            ALICE_COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            other => panic!("expired pin must restart even opt-in, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn over_cap_open_is_unavailable_never_empty() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "9e795001-0000-4000-8000-000000000031";
        create_record(
            &db,
            json!({
                "id": id, "type": "Document", "kind": "note", "name": "large",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let large_summary = "x".repeat(25 * 1024 * 1024);
        sqlx::query("UPDATE records SET summary = ? WHERE id = ?")
            .bind(large_summary)
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(db.open_workspace_snapshot(alice()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn paging_covers_more_than_a_thousand_rows() {
        let db = crate::create_database(":memory:").await.unwrap();
        const COUNT: usize = 1_050;
        for index in 0..COUNT {
            let id = format!("9e795002-0000-4000-8000-{index:012}");
            create_record(
                &db,
                json!({
                    "id": id, "type": "Document", "kind": "note",
                    "name": format!("Bulk {index:04}"),
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                &id,
                vec![AllowEntry::account("alice", Capability::View)],
            )
            .await
            .unwrap();
        }
        let opened = open_token(&db, alice()).await;
        // Small pages force many round trips past the 1,000-row governed cap.
        let mut seen = std::collections::HashSet::new();
        let mut after_id: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = db
                .page_workspace_snapshot(
                    alice(),
                    &opened.token,
                    SnapshotSection::Records,
                    100,
                    after_id.as_deref(),
                )
                .await
                .unwrap()
                .expect("bulk snapshot stays pinned");
            pages += 1;
            assert!(page.rows.len() <= 100);
            for row in page.rows {
                let record: SnapshotRecord = serde_json::from_value(row).unwrap();
                assert!(seen.insert(record.id.clone()), "no row twice");
            }
            if !page.has_more {
                assert!(page.after_id.is_none());
                break;
            }
            after_id = page.after_id;
        }
        // Every created row pages exactly once; seeded workspace rows may
        // ride along, so the assertion is a superset, not an exact count.
        assert!(seen.len() >= COUNT);
        for index in 0..COUNT {
            let id = format!("9e795002-0000-4000-8000-{index:012}");
            assert!(seen.contains(&id), "created row {id} pages");
        }
        assert!(pages >= 11);
        // The same pin pages facets and links sections independently.
        let facet_pages =
            page_all_section(&db, alice(), &opened.token, SnapshotSection::Facets).await;
        assert!(facet_pages.is_empty());
    }

    #[test]
    fn estimate_bounds_measured_footprint() {
        // A representative pin: one record with every optional field set, one
        // numeric and one text facet, one link, one event.
        let mut records = BTreeMap::new();
        records.insert(
            "rec-1".to_string(),
            SnapshotRecord {
                id: "rec-1".to_string(),
                record_type: Some("Document".to_string()),
                kind: Some("note".to_string()),
                name: "A name".to_string(),
                home_id: Some("root".to_string()),
                lifecycle: Some("open".to_string()),
                persistence: "enduring".to_string(),
                maturity: Some("draft".to_string()),
                summary: Some("x".repeat(1000)),
                last_activity_at: Some("2026-09-23T00:00:00Z".to_string()),
                created_at: "2026-09-23T00:00:00Z".to_string(),
                updated_at: "2026-09-23T00:00:00Z".to_string(),
                deleted_at: None,
            },
        );
        let mut facets = BTreeMap::new();
        facets.insert(
            "facet-1".to_string(),
            SnapshotFacet {
                id: "facet-1".to_string(),
                record_id: "rec-1".to_string(),
                key: "estimate".to_string(),
                value: Some("42".to_string()),
                value_num: Some(42.0),
                vocab_ref: None,
                created_at: "2026-09-23T00:00:00Z".to_string(),
            },
        );
        facets.insert(
            "facet-2".to_string(),
            SnapshotFacet {
                id: "facet-2".to_string(),
                record_id: "rec-1".to_string(),
                key: "note".to_string(),
                value: Some("plain text".to_string()),
                value_num: None,
                vocab_ref: None,
                created_at: "2026-09-23T00:00:00Z".to_string(),
            },
        );
        let mut links = BTreeMap::new();
        links.insert(
            "link-1".to_string(),
            SnapshotLink {
                id: "link-1".to_string(),
                source_id: "rec-1".to_string(),
                target_id: "rec-2".to_string(),
                relationship: "mentions".to_string(),
                note: Some("see also".to_string()),
                created_at: "2026-09-23T00:00:00Z".to_string(),
            },
        );
        let events = vec![SnapshotEvent {
            seq: 7,
            id: "evt-1".to_string(),
            record_id: "rec-1".to_string(),
            event_type: "record.updated".to_string(),
            created_at: "2026-09-23T00:00:00Z".to_string(),
        }];
        let measured = serde_json::to_vec(&(&records, &facets, &links, &events))
            .unwrap()
            .len();
        let estimated = estimate_entry_bytes("alice".len(), &records, &facets, &links, &events);
        assert!(
            estimated >= measured,
            "estimate {estimated} must cover measured {measured}"
        );
        assert!(
            estimated <= measured * 8,
            "estimate {estimated} must stay within reason of measured {measured}"
        );
    }

    #[test]
    fn store_bounds_tokens_by_count_bytes_and_ttl() {
        use std::time::Duration;
        let mut store = SnapshotStore::default();
        let entry = |bytes: usize| SnapshotEntry {
            principal_credential: "alice".to_string(),
            principal_is_member: true,
            principal_trusted_bypass: false,
            created_at: Instant::now(),
            content_seq: 1,
            authorization_epoch: 1,
            relationship_seq: 0,
            unit_seq_max: 0,
            estimated_bytes: bytes,
            #[cfg(feature = "v2-kernel-probe")]
            kernel_v2: false,
            records: BTreeMap::new(),
            facets: BTreeMap::new(),
            links: BTreeMap::new(),
            events: Vec::new(),
        };
        let principal = alice();
        for index in 0..SNAPSHOT_MAX_TOKENS + 2 {
            assert!(store.insert(format!("token-{index}"), entry(128)));
        }
        assert_eq!(store.entries.len(), SNAPSHOT_MAX_TOKENS);
        // The survivors are the newest inserts (LRU by creation).
        assert!(store.entries.contains_key("token-9"));
        // A single entry over the byte budget is refused, not stored: the
        // caller must surface unavailable rather than a dead token.
        assert!(!store.insert("huge".to_string(), entry(SNAPSHOT_MAX_BYTES + 1)));
        assert!(!store.entries.contains_key("huge"));
        assert_eq!(store.entries.len(), SNAPSHOT_MAX_TOKENS);
        // An expired token restarts rather than paging a stale pin.
        assert!(store.insert("short-lived".to_string(), entry(128)));
        store.entries.get_mut("short-lived").unwrap().created_at =
            Instant::now() - SNAPSHOT_TTL - Duration::from_secs(1);
        match store.get_for(&principal, "short-lived") {
            Err(SnapshotLookup::Restart { reason }) => {
                assert_eq!(reason, "token_expired_or_unknown");
            }
            Ok(_) => panic!("expired token must not serve"),
        }
        assert!(!store.entries.contains_key("short-lived"));
    }

    #[tokio::test]
    async fn record_wire_key_matches_governed_column() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        let page = db
            .page_workspace_snapshot(alice(), &opened.token, SnapshotSection::Records, 50, None)
            .await
            .unwrap()
            .expect("fixture stays pinned");
        assert!(!page.rows.is_empty());
        // Governed ground truth for the same principal: id → type.
        let governed = crate::query::sql::query_sql(&db, alice(), "SELECT id, type FROM records")
            .await
            .unwrap();
        let mut expected = std::collections::HashMap::new();
        for row in governed.rows {
            let object = row.as_object().unwrap();
            expected.insert(
                object["id"].as_str().unwrap().to_string(),
                object["type"].as_str().unwrap().to_string(),
            );
        }
        for row in &page.rows {
            let object = row.as_object().expect("record row is an object");
            assert!(object.contains_key("type"), "governed/demo key is `type`");
            assert!(!object.contains_key("record_type"));
            let id = object["id"].as_str().unwrap();
            assert_eq!(
                object["type"].as_str().unwrap(),
                expected.get(id).expect("row is governed-visible"),
                "wire `type` carries the governed column value for {id}"
            );
        }
        assert_eq!(
            page.rows.len(),
            expected.len(),
            "pin pages the full governed set"
        );
    }

    #[tokio::test]
    async fn facet_value_num_matches_governed_view() {
        let db = three_record_fixture().await;
        set_facet(
            &db,
            ALICE_ONLY_ID,
            FacetSetPayload {
                key: "estimate".to_string(),
                value: Some("42".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        set_facet(
            &db,
            ALICE_ONLY_ID,
            FacetSetPayload {
                key: "note".to_string(),
                value: Some("plain text".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        // Ground truth straight from the table the governed view reads.
        let raw: Option<f64> = sqlx::query_scalar(
            "SELECT value_num FROM facet_values WHERE record_id = ? AND key = 'estimate'",
        )
        .bind(ALICE_ONLY_ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(raw, Some(42.0));
        // The snapshot carries the same projection through M1 and M2.
        let opened = open_token(&db, alice()).await;
        let facets =
            facet_map(page_all_section(&db, alice(), &opened.token, SnapshotSection::Facets).await);
        let numeric = facets
            .values()
            .find(|facet| facet.record_id == ALICE_ONLY_ID && facet.key == "estimate")
            .expect("numeric facet is held");
        assert_eq!(numeric.value_num, Some(42.0));
        let text = facets
            .values()
            .find(|facet| facet.record_id == ALICE_ONLY_ID && facet.key == "note")
            .expect("text facet is held");
        assert_eq!(text.value_num, None);
        // And the wire form is a JSON number, not a string.
        let wire = serde_json::to_value(numeric).unwrap();
        assert!(wire["value_num"].is_number());
    }

    #[tokio::test]
    async fn opt_in_insert_epoch_move_returns_delta_equal_to_fresh() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        let mut model = page_all_records(&db, alice(), &opened.token).await;
        // A record INSERT moves the authorization epoch by schema trigger.
        let newcomer = "9e795001-0000-4000-8000-000000000041";
        create_record(
            &db,
            json!({
                "id": newcomer,
                "type": "Document", "kind": "note", "name": "Newcomer",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            newcomer,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        // Opt-out still restarts on the moved epoch, without retiring the pin.
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, false)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            other => panic!("opt-out insert must restart, got {other:?}"),
        }
        let delta = match db
            .catch_up_workspace_snapshot(alice(), &opened.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("opt-in insert must delta, got {other:?}"),
        };
        assert!(delta.fence_moved, "epoch moved under the pin");
        assert!(
            delta.upsert_records.iter().any(|row| row.id == newcomer),
            "new record arrives as an upsert"
        );
        assert!(delta.delete_record_ids.is_empty());
        for id in &delta.delete_record_ids {
            model.remove(id);
        }
        for row in delta.upsert_records {
            model.insert(row.id.clone(), row);
        }
        let fresh = open_token(&db, alice()).await;
        assert_eq!(delta.content_seq, fresh.content_seq);
        assert_eq!(delta.authorization_epoch, fresh.authorization_epoch);
        assert_eq!(model, page_all_records(&db, alice(), &fresh.token).await);
    }

    #[tokio::test]
    async fn opt_in_narrowing_returns_revocation_deletes_equal_to_fresh() {
        let db = three_record_fixture().await;
        // Fence-stable setup bea can see: a facet and a both-endpoints-visible
        // link on the record she is about to lose.
        set_facet(
            &db,
            ALICE_COMMON_ID,
            FacetSetPayload {
                key: "priority".to_string(),
                value: Some("high".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("9e795001-0000-4000-8000-000000000042".to_string()),
                source_id: ALICE_COMMON_ID.to_string(),
                target_id: BEA_ONLY_ID.to_string(),
                relationship: "mentions".to_string(),
                note: None,
            },
        )
        .await
        .unwrap();
        let bea_open = open_token(&db, bea()).await;
        // A second pin proves `page` still restarts after the same fence move.
        let bea_page_pin = open_token(&db, bea()).await;
        let mut model = page_all_records(&db, bea(), &bea_open.token).await;
        assert!(model.contains_key(ALICE_COMMON_ID));
        let mut facet_model =
            facet_map(page_all_section(&db, bea(), &bea_open.token, SnapshotSection::Facets).await);
        let mut link_model =
            link_map(page_all_section(&db, bea(), &bea_open.token, SnapshotSection::Links).await);
        let lost_facet = facet_model
            .values()
            .find(|facet| facet.record_id == ALICE_COMMON_ID)
            .expect("common facet is held")
            .id
            .clone();
        assert!(link_model.contains_key("9e795001-0000-4000-8000-000000000042"));
        replace_explicit_policy(
            &db,
            "test:narrow",
            ALICE_COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let delta = match db
            .catch_up_workspace_snapshot(bea(), &bea_open.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("opt-in narrowing must delta, got {other:?}"),
        };
        assert!(delta.fence_moved, "epoch moved under the pin");
        // The revocation is a delete across records, facets, and links.
        assert!(delta
            .delete_record_ids
            .contains(&ALICE_COMMON_ID.to_string()));
        assert!(delta.delete_facet_ids.contains(&lost_facet));
        assert!(
            delta.delete_facet_keys.contains(&FacetKey {
                record_id: ALICE_COMMON_ID.to_string(),
                key: "priority".to_string(),
            }),
            "facet deletes carry their page key"
        );
        assert!(delta
            .delete_link_ids
            .contains(&"9e795001-0000-4000-8000-000000000042".to_string()));
        assert!(
            delta.delete_link_keys.contains(&LinkKey {
                source_id: ALICE_COMMON_ID.to_string(),
                target_id: BEA_ONLY_ID.to_string(),
                relationship: Some("mentions".to_string()),
            }),
            "link deletes carry their page key"
        );
        // No hidden row may appear anywhere else in the response.
        assert!(
            !delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_COMMON_ID),
            "revoked record must not upsert"
        );
        assert!(
            !delta
                .upsert_facets
                .iter()
                .any(|facet| facet.record_id == ALICE_COMMON_ID),
            "revoked facets must not upsert"
        );
        assert!(
            !delta
                .upsert_links
                .iter()
                .any(|link| link.source_id == ALICE_COMMON_ID || link.target_id == ALICE_COMMON_ID),
            "revoked links must not upsert"
        );
        assert!(
            !delta
                .content_events
                .iter()
                .any(|event| event.record_id == ALICE_COMMON_ID),
            "revoked record must not appear in content events"
        );
        // `page` on the sibling pin still restarts with no rows.
        match db
            .page_workspace_snapshot(
                bea(),
                &bea_page_pin.token,
                SnapshotSection::Records,
                50,
                None,
            )
            .await
            .unwrap()
        {
            Err(SnapshotLookup::Restart { reason }) => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            Ok(_) => panic!("revoked pin must not page stale rows"),
        }
        // The caught-up model equals a fresh open for bea across every section.
        for id in &delta.delete_record_ids {
            model.remove(id);
        }
        for row in delta.upsert_records {
            model.insert(row.id.clone(), row);
        }
        for id in &delta.delete_facet_ids {
            facet_model.remove(id);
        }
        for facet in delta.upsert_facets {
            facet_model.insert(facet.id.clone(), facet);
        }
        for id in &delta.delete_link_ids {
            link_model.remove(id);
        }
        for link in delta.upsert_links {
            link_model.insert(link.id.clone(), link);
        }
        let fresh = open_token(&db, bea()).await;
        assert_eq!(delta.content_seq, fresh.content_seq);
        assert_eq!(model, page_all_records(&db, bea(), &fresh.token).await);
        assert_eq!(
            facet_model,
            facet_map(page_all_section(&db, bea(), &fresh.token, SnapshotSection::Facets).await)
        );
        assert_eq!(
            link_model,
            link_map(page_all_section(&db, bea(), &fresh.token, SnapshotSection::Links).await)
        );
        let fresh_events: Vec<SnapshotEvent> =
            page_all_section(&db, bea(), &fresh.token, SnapshotSection::ContentEvents)
                .await
                .into_iter()
                .map(|row| serde_json::from_value(row).unwrap())
                .collect();
        assert_eq!(delta.content_events, fresh_events);
    }

    #[tokio::test]
    async fn opt_in_hidden_parent_masks_child_home_id() {
        // A parent folder becomes hidden while the child stays visible: the
        // child upserts with its home masked to None, and the caught-up
        // model equals a fresh open.
        let db = three_record_fixture().await;
        let parent = "9e795001-0000-4000-8000-000000000061";
        let child = "9e795001-0000-4000-8000-000000000062";
        create_record(
            &db,
            json!({
                "id": parent,
                "type": "Collection", "kind": "folder", "name": "Parent",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": child,
                "type": "Document", "kind": "note", "name": "Child",
                "home_id": parent
            }),
        )
        .await
        .unwrap();
        for id in [parent, child] {
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                vec![
                    AllowEntry::account("alice", Capability::View),
                    AllowEntry::account("bea", Capability::View),
                ],
            )
            .await
            .unwrap();
        }
        let bea_open = open_token(&db, bea()).await;
        let mut model = page_all_records(&db, bea(), &bea_open.token).await;
        assert_eq!(model[child].home_id.as_deref(), Some(parent));
        replace_explicit_policy(
            &db,
            "test:narrow",
            parent,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let delta = match db
            .catch_up_workspace_snapshot(bea(), &bea_open.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("opt-in parent narrowing must delta, got {other:?}"),
        };
        assert!(delta.fence_moved, "epoch moved under the pin");
        assert!(delta.delete_record_ids.contains(&parent.to_string()));
        let masked = delta
            .upsert_records
            .iter()
            .find(|row| row.id == child)
            .expect("visible child arrives as an upsert");
        assert_eq!(masked.home_id, None, "hidden parent is masked, not leaked");
        for id in &delta.delete_record_ids {
            model.remove(id);
        }
        for row in delta.upsert_records {
            model.insert(row.id.clone(), row);
        }
        let fresh = open_token(&db, bea()).await;
        assert_eq!(model, page_all_records(&db, bea(), &fresh.token).await);
    }

    #[tokio::test]
    async fn opt_in_m2_none_with_moved_fence_still_restarts() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "9e795001-0000-4000-8000-000000000051";
        create_record(
            &db,
            json!({
                "id": id, "type": "Document", "kind": "note", "name": "large",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let opened = open_token(&db, alice()).await;
        // Bloat past the index cap so M2 holds nothing, then move the fence
        // with a record INSERT. The opt-in cannot diff without a fresh view.
        let large_summary = "x".repeat(25 * 1024 * 1024);
        sqlx::query("UPDATE records SET summary = ? WHERE id = ?")
            .bind(large_summary)
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        create_record(
            &db,
            json!({
                "id": "9e795001-0000-4000-8000-000000000052",
                "type": "Document", "kind": "note", "name": "Newcomer",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "authorization_epoch_moved");
            }
            other => panic!("M2-None with a moved fence must restart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn opt_in_content_gap_with_moved_fence_still_restarts() {
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        // Facet writes advance the content cursor without moving either
        // fence; the trailing INSERT moves the epoch on top of the gap.
        for index in 0..SNAPSHOT_MAX_CATCH_UP_GAP + 8 {
            set_facet(
                &db,
                ALICE_ONLY_ID,
                FacetSetPayload {
                    key: "churn".to_string(),
                    value: Some(index.to_string()),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({
                "id": "9e795001-0000-4000-8000-000000000053",
                "type": "Document", "kind": "note", "name": "Newcomer",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        match db
            .catch_up_workspace_snapshot(alice(), &opened.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, "content_gap_outside_window");
            }
            other => panic!("over-window gap must restart even opt-in, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn opt_in_relationship_move_returns_delta_equal_to_fresh() {
        // A governed relationship write moves only the relationship fence:
        // the opt-in path diffs with `fence_moved: true` and reaches the
        // same model as a fresh open.
        let db = three_record_fixture().await;
        let opened = open_token(&db, alice()).await;
        let mut model = page_all_records(&db, alice(), &opened.token).await;
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "manage_relationships",
                json!({
                    "action": "assert",
                    "relationship_type": "relates_to",
                    "endpoints": [
                        {"role": "participant", "record_id": ALICE_COMMON_ID},
                        {"role": "participant", "record_id": ALICE_ONLY_ID}
                    ],
                    "idempotency_key": "workspace-snapshot-fence-opt-in"
                }),
            )
            .await
            .unwrap();
        let delta = match db
            .catch_up_workspace_snapshot(alice(), &opened.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("opt-in relationship move must delta, got {other:?}"),
        };
        assert!(delta.fence_moved, "relationship fence moved under the pin");
        for id in &delta.delete_record_ids {
            model.remove(id);
        }
        for row in delta.upsert_records {
            model.insert(row.id.clone(), row);
        }
        let fresh = open_token(&db, alice()).await;
        assert_eq!(delta.content_seq, fresh.content_seq);
        assert_eq!(delta.relationship_seq, fresh.relationship_seq);
        assert_eq!(model, page_all_records(&db, alice(), &fresh.token).await);
    }

    #[tokio::test]
    async fn opt_in_unit_hiding_returns_revocation_deletes() {
        // Unit creation hides the derived artifact behind the unit fence:
        // the opt-in delta lists it in deletes, names it nowhere else, and
        // the caught-up model equals a fresh open.
        let db = three_record_fixture().await;
        let envelope = "9e795001-0000-4000-8000-000000000064";
        let derived = "9e795001-0000-4000-8000-000000000065";
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Entity",
                    "kind": "semantic-unit",
                    "name": "unit envelope",
                    "home_id": crate::schema::ROOT_RECORD_ID,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": derived,
                "type": "Document",
                "kind": "attachment",
                "name": "derived artifact",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        let derived_anchor: String =
            sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id = ?")
                .bind(derived)
                .fetch_one(db.pool())
                .await
                .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &derived_anchor,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("unit-derived-artifact-opt-in".into()),
                source_id: derived.into(),
                target_id: envelope.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        let opened = open_token(&db, alice()).await;
        let mut model = page_all_records(&db, alice(), &opened.token).await;
        assert!(model.contains_key(derived));
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version": "native.freshness-kernel.v1",
                    "authority_bearer_record_id": ALICE_COMMON_ID,
                    "label": "unit envelope",
                }),
                actor: Some("test:unit".into()),
            },
        )
        .await
        .unwrap();
        let delta = match db
            .catch_up_workspace_snapshot(alice(), &opened.token, true)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("opt-in unit hiding must delta, got {other:?}"),
        };
        assert!(delta.fence_moved, "unit fence moved under the pin");
        assert!(delta.delete_record_ids.contains(&derived.to_string()));
        assert!(
            !delta.upsert_records.iter().any(|row| row.id == derived),
            "hidden artifact must not upsert"
        );
        assert!(
            !delta
                .upsert_facets
                .iter()
                .any(|facet| facet.record_id == derived),
            "hidden artifact facets must not upsert"
        );
        assert!(
            !delta
                .upsert_links
                .iter()
                .any(|link| link.source_id == derived || link.target_id == derived),
            "hidden artifact links must not upsert"
        );
        assert!(
            !delta
                .content_events
                .iter()
                .any(|event| event.record_id == derived),
            "hidden artifact must not appear in content events"
        );
        for id in &delta.delete_record_ids {
            model.remove(id);
        }
        for row in delta.upsert_records {
            model.insert(row.id.clone(), row);
        }
        let fresh = open_token(&db, alice()).await;
        assert_eq!(delta.content_seq, fresh.content_seq);
        assert_eq!(model, page_all_records(&db, alice(), &fresh.token).await);
    }

    fn zero_digest() -> String {
        "0".repeat(64)
    }

    fn empty_manifest() -> serde_json::Value {
        json!({
            "version": 1,
            "profile": RESUME_MANIFEST_PROFILE,
            "records": [],
            "facets": [],
            "links": [],
        })
    }

    /// An exact manifest for `principal`: page the fresh open and hash every
    /// row through the resume codec. The correct-digest baseline every
    /// repair test mutates.
    async fn exact_manifest(db: &crate::db::Db, principal: QueryPrincipal) -> serde_json::Value {
        let opened = open_token(db, principal.clone()).await;
        let records = page_all_records(db, principal.clone(), &opened.token).await;
        let facet_rows = page_all_section(
            db,
            principal.clone(),
            &opened.token,
            SnapshotSection::Facets,
        )
        .await;
        let link_rows =
            page_all_section(db, principal.clone(), &opened.token, SnapshotSection::Links).await;
        let record_tuples: Vec<serde_json::Value> = records
            .values()
            .map(|row| json!([row.id, record_resume_digest(row)]))
            .collect();
        let mut facet_tuples = Vec::new();
        for value in facet_rows {
            let facet: SnapshotFacet = serde_json::from_value(value).unwrap();
            facet_tuples.push(json!([
                facet.record_id,
                facet.key,
                facet_resume_digest(&facet.record_id, &facet.key, facet.value.as_deref()),
            ]));
        }
        let mut link_tuples = Vec::new();
        for value in link_rows {
            let link: SnapshotLink = serde_json::from_value(value).unwrap();
            link_tuples.push(json!([
                link.source_id,
                link.target_id,
                link.relationship,
                link_resume_digest(
                    &link.source_id,
                    &link.target_id,
                    Some(link.relationship.as_str()),
                    link.note.as_deref(),
                ),
            ]));
        }
        json!({
            "version": 1,
            "profile": RESUME_MANIFEST_PROFILE,
            "records": record_tuples,
            "facets": facet_tuples,
            "links": link_tuples,
        })
    }

    async fn resume(
        db: &crate::db::Db,
        principal: QueryPrincipal,
        manifest: &serde_json::Value,
    ) -> CatchUpOutcome {
        db.resume_workspace_snapshot(principal, manifest)
            .await
            .unwrap()
    }

    /// Shared digest vectors, computed independently in Python and saved for
    /// both the Rust suite and the forthcoming JS manifest builder: agreement
    /// proves the wire encoding rather than the helper under test.
    const RESUME_VECTOR_FIXTURE: &str =
        include_str!("../tests/fixtures/workspace-snapshot-resume-vectors.json");

    #[tokio::test]
    async fn resume_codec_matches_shared_vectors() {
        let fixture: serde_json::Value = serde_json::from_str(RESUME_VECTOR_FIXTURE).unwrap();
        assert_eq!(
            fixture["profile"].as_str().unwrap(),
            RESUME_MANIFEST_PROFILE,
            "vectors pin the shipped profile"
        );
        let mut seen = std::collections::HashMap::new();
        let vectors = fixture["vectors"].as_array().unwrap();
        for vector in vectors {
            let name = vector["name"].as_str().unwrap();
            let domain = vector["domain"].as_str().unwrap();
            let fields = vector["fields"].as_array().unwrap();
            let present = |index: usize| fields[index].as_str();
            let computed = match domain {
                "record" => {
                    assert_eq!(fields.len(), 13, "{name} pins the 13-field record order");
                    let owned: Vec<Option<String>> = fields
                        .iter()
                        .map(|field| field.as_str().map(str::to_string))
                        .collect();
                    let borrowed: Vec<Option<&str>> =
                        owned.iter().map(|field| field.as_deref()).collect();
                    record_resume_digest_fields(&borrowed)
                }
                "facet" => {
                    assert_eq!(fields.len(), 3, "{name} pins the facet triple");
                    facet_resume_digest(
                        fields[0].as_str().unwrap(),
                        fields[1].as_str().unwrap(),
                        present(2),
                    )
                }
                "link" => {
                    assert_eq!(fields.len(), 4, "{name} pins the link quad");
                    link_resume_digest(
                        fields[0].as_str().unwrap(),
                        fields[1].as_str().unwrap(),
                        present(2),
                        present(3),
                    )
                }
                other => panic!("unknown vector domain {other}"),
            };
            let expected = vector["digest"].as_str().unwrap();
            assert_eq!(computed, expected, "vector {name}");
            assert_eq!(computed.len(), 64, "vector {name} is sha256 hex");
            assert!(
                computed
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "vector {name} is lowercase hex"
            );
            seen.insert(name.to_string(), computed);
        }
        assert_eq!(seen.len(), 14, "fixture pins fourteen vectors");
        // The struct projection the server hashes through agrees with the
        // vector path on the ascii vector, binding struct field order to the
        // documented fixture order.
        let ascii = vectors
            .iter()
            .find(|vector| vector["name"] == "record-ascii")
            .unwrap()["fields"]
            .as_array()
            .unwrap();
        let ascii_opt = |index: usize| ascii[index].as_str().map(str::to_string);
        assert_eq!(
            seen["record-ascii"],
            record_resume_digest(&SnapshotRecord {
                id: ascii[0].as_str().unwrap().into(),
                record_type: Some(ascii[1].as_str().unwrap().into()),
                kind: ascii_opt(2),
                name: ascii[3].as_str().unwrap().into(),
                home_id: ascii_opt(4),
                lifecycle: ascii_opt(5),
                persistence: ascii[6].as_str().unwrap().into(),
                maturity: ascii_opt(7),
                summary: ascii_opt(8),
                last_activity_at: ascii_opt(9),
                created_at: ascii[10].as_str().unwrap().into(),
                updated_at: ascii[11].as_str().unwrap().into(),
                deleted_at: ascii_opt(12),
            })
        );
        // Order, nullness, and domain separation are observable relations
        // between independently computed vectors, not self-comparisons.
        assert_ne!(
            seen["record-ascii"], seen["record-order-permuted"],
            "field order is load-bearing"
        );
        assert_ne!(
            seen["record-null-kind"], seen["record-empty-kind"],
            "null and empty string are distinct claims"
        );
        assert_ne!(seen["facet-null-value"], seen["facet-empty-value"]);
        assert_ne!(seen["link-null-note"], seen["link-empty-note"]);
        assert_ne!(
            seen["record-ascii"], seen["facet-value"],
            "record and facet digests cannot collide"
        );
        assert_ne!(
            seen["facet-value"], seen["link-full"],
            "facet and link digests cannot collide"
        );
    }

    #[tokio::test]
    async fn resume_rejects_malformed_duplicate_and_over_cap_manifests() {
        let db = three_record_fixture().await;
        for (name, manifest) in [
            ("non-object", json!("nope")),
            (
                "missing-version",
                json!({"profile": RESUME_MANIFEST_PROFILE, "records": [], "facets": [], "links": []}),
            ),
            (
                "wrong-version",
                json!({"version": 2, "profile": RESUME_MANIFEST_PROFILE, "records": [], "facets": [], "links": []}),
            ),
            (
                "wrong-profile",
                json!({"version": 1, "profile": "other", "records": [], "facets": [], "links": []}),
            ),
            (
                "missing-sections",
                json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE}),
            ),
            (
                "bad-arity",
                json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE, "records": [["only-id"]], "facets": [], "links": []}),
            ),
            (
                "short-digest",
                json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE, "records": [[ALICE_COMMON_ID, "abc"]], "facets": [], "links": []}),
            ),
            (
                "uppercase-digest",
                json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE, "records": [[ALICE_COMMON_ID, "A".repeat(64)]], "facets": [], "links": []}),
            ),
            (
                "empty-id",
                json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE, "records": [["", zero_digest()]], "facets": [], "links": []}),
            ),
            (
                "duplicate-keys",
                json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE,
                    "records": [[ALICE_COMMON_ID, zero_digest()], [ALICE_COMMON_ID, zero_digest()]],
                    "facets": [], "links": []}),
            ),
        ] {
            match resume(&db, alice(), &manifest).await {
                CatchUpOutcome::Restart { reason } => assert!(
                    reason == RESUME_RESTART_MALFORMED || reason == RESUME_RESTART_PROFILE_MISMATCH,
                    "{name} restarts, got {reason}"
                ),
                other => panic!("{name} must restart with no rows, got {other:?}"),
            }
        }
        // Entry-count cap trips before any typed map is built.
        let mut many_records = Vec::new();
        for index in 0..=RESUME_MANIFEST_MAX_ENTRIES {
            many_records.push(json!([format!("id-{index}"), zero_digest()]));
        }
        match resume(
            &db,
            alice(),
            &json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE,
                "records": many_records, "facets": [], "links": []}),
        )
        .await
        {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, RESUME_RESTART_OVER_CAP)
            }
            other => panic!("over-count manifest must restart, got {other:?}"),
        }
        // Serialized-size cap trips on one huge claim, not many entries.
        let huge = json!({"version": 1, "profile": RESUME_MANIFEST_PROFILE,
            "records": [["x".repeat(RESUME_MANIFEST_MAX_BYTES), zero_digest()]],
            "facets": [], "links": []});
        match resume(&db, alice(), &huge).await {
            CatchUpOutcome::Restart { reason } => {
                assert_eq!(reason, RESUME_RESTART_OVER_CAP)
            }
            other => panic!("over-size manifest must restart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resume_fence_race_helper_names_the_moved_fence() {
        assert_eq!(resume_fence_race_reason((1, 2, 3), (1, 2, 3)), None);
        assert_eq!(
            resume_fence_race_reason((1, 2, 3), (9, 2, 3)),
            Some("authorization_epoch_moved")
        );
        assert_eq!(
            resume_fence_race_reason((1, 2, 3), (1, 9, 3)),
            Some("relationship_seq_moved")
        );
        assert_eq!(
            resume_fence_race_reason((1, 2, 3), (1, 2, 9)),
            Some("unit_seq_moved")
        );
    }

    #[tokio::test]
    async fn resume_empty_manifest_returns_full_model_and_working_pin() {
        let db = three_record_fixture().await;
        let delta = match resume(&db, alice(), &empty_manifest()).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("empty manifest must delta, got {other:?}"),
        };
        let ids: Vec<&str> = delta
            .upsert_records
            .iter()
            .map(|row| row.id.as_str())
            .collect();
        assert!(ids.contains(&ALICE_COMMON_ID) && ids.contains(&ALICE_ONLY_ID));
        assert!(
            !ids.contains(&BEA_ONLY_ID),
            "keys outside the caller view never upsert"
        );
        assert!(delta.delete_record_ids.is_empty());
        assert!(!delta.fence_moved, "resume never sets the fence flag");
        // The new pin is ordinary: it pages like any opened token.
        let rows = page_all_records(&db, alice(), &delta.token).await;
        assert!(rows.contains_key(ALICE_COMMON_ID));
    }

    #[tokio::test]
    async fn resume_exact_manifest_returns_empty_delta() {
        let db = three_record_fixture().await;
        let manifest = exact_manifest(&db, alice()).await;
        let delta = match resume(&db, alice(), &manifest).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("exact manifest must delta, got {other:?}"),
        };
        assert!(
            delta.upsert_records.is_empty(),
            "clean cache repairs nothing"
        );
        assert!(delta.delete_record_ids.is_empty());
        assert!(delta.upsert_facets.is_empty());
        assert!(delta.delete_facet_keys.is_empty());
        assert!(delta.upsert_links.is_empty());
        assert!(delta.delete_link_keys.is_empty());
    }

    #[tokio::test]
    async fn resume_repairs_altered_rows_and_deletes_unknown_keys() {
        let db = three_record_fixture().await;
        set_facet(
            &db,
            ALICE_COMMON_ID,
            FacetSetPayload {
                key: "priority".to_string(),
                value: Some("high".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("9e795001-0000-4000-8000-000000000031".to_string()),
                source_id: ALICE_COMMON_ID.to_string(),
                target_id: ALICE_ONLY_ID.to_string(),
                relationship: "mentions".to_string(),
                note: Some("see also".to_string()),
            },
        )
        .await
        .unwrap();
        let mut manifest = exact_manifest(&db, alice()).await;
        {
            let records = manifest["records"].as_array_mut().unwrap();
            let common = records
                .iter_mut()
                .find(|tuple| tuple[0] == ALICE_COMMON_ID)
                .unwrap();
            common[1] = json!(zero_digest());
        }
        {
            let facets = manifest["facets"].as_array_mut().unwrap();
            facets.retain(|tuple| !(tuple[0] == ALICE_COMMON_ID && tuple[1] == "priority"));
        }
        {
            let links = manifest["links"].as_array_mut().unwrap();
            links.clear();
        }
        manifest["records"].as_array_mut().unwrap().push(json!([
            "9e795001-0000-4000-8000-000000000099",
            zero_digest()
        ]));
        manifest["facets"].as_array_mut().unwrap().push(json!([
            "9e795001-0000-4000-8000-000000000099",
            "ghost",
            zero_digest()
        ]));
        manifest["links"].as_array_mut().unwrap().push(json!([
            ALICE_COMMON_ID,
            "9e795001-0000-4000-8000-000000000099",
            "mentions",
            zero_digest()
        ]));
        let delta = match resume(&db, alice(), &manifest).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("repairable manifest must delta, got {other:?}"),
        };
        assert!(
            delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_COMMON_ID),
            "altered row repairs from the fresh view"
        );
        assert!(
            delta
                .upsert_facets
                .iter()
                .any(|facet| facet.record_id == ALICE_COMMON_ID
                    && facet.key == "priority"
                    && facet.value.as_deref() == Some("high")),
            "dropped facet entry returns with its current value"
        );
        assert!(
            delta
                .upsert_links
                .iter()
                .any(|link| link.source_id == ALICE_COMMON_ID && link.target_id == ALICE_ONLY_ID),
            "dropped link entry returns"
        );
        assert!(
            delta
                .delete_record_ids
                .contains(&"9e795001-0000-4000-8000-000000000099".to_string()),
            "unknown record key becomes a delete address, never rows"
        );
        assert!(
            delta.delete_facet_keys.iter().any(|key| key.record_id
                == "9e795001-0000-4000-8000-000000000099"
                && key.key == "ghost"),
            "unknown facet key becomes a keyed delete"
        );
        assert!(
            delta
                .delete_link_keys
                .iter()
                .any(|key| key.source_id == ALICE_COMMON_ID
                    && key.target_id == "9e795001-0000-4000-8000-000000000099"
                    && key.relationship.as_deref() == Some("mentions")),
            "unknown link key becomes a keyed delete"
        );
    }

    #[tokio::test]
    async fn resume_repairs_changed_link_note_with_delete_before_upsert() {
        let db = three_record_fixture().await;
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("9e795001-0000-4000-8000-000000000032".to_string()),
                source_id: ALICE_COMMON_ID.to_string(),
                target_id: ALICE_ONLY_ID.to_string(),
                relationship: "mentions".to_string(),
                note: Some("second thought".to_string()),
            },
        )
        .await
        .unwrap();
        // The manifest claims the stale note; the fresh view holds the new one.
        let stale_digest = link_resume_digest(
            ALICE_COMMON_ID,
            ALICE_ONLY_ID,
            Some("mentions"),
            Some("first thought"),
        );
        let manifest = json!({
            "version": 1,
            "profile": RESUME_MANIFEST_PROFILE,
            "records": [],
            "facets": [],
            "links": [[ALICE_COMMON_ID, ALICE_ONLY_ID, "mentions", stale_digest]],
        });
        let delta = match resume(&db, alice(), &manifest).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("stale note must delta, got {other:?}"),
        };
        let repaired: Vec<_> = delta
            .upsert_links
            .iter()
            .filter(|link| link.source_id == ALICE_COMMON_ID && link.target_id == ALICE_ONLY_ID)
            .collect();
        assert_eq!(repaired.len(), 1);
        assert_eq!(repaired[0].note.as_deref(), Some("second thought"));
        assert!(
            delta
                .delete_link_keys
                .iter()
                .any(|key| key.source_id == ALICE_COMMON_ID
                    && key.target_id == ALICE_ONLY_ID
                    && key.relationship.as_deref() == Some("mentions")),
            "changed note emits the delete first so takeLink cannot keep the old note"
        );
    }

    #[tokio::test]
    async fn resume_withholds_rows_outside_caller_view_as_deletes() {
        let db = three_record_fixture().await;
        // Bea names an alice-only row her view never held, with a wrong digest
        // for the row she shares: neither may disclose the hidden row.
        let manifest = json!({
            "version": 1,
            "profile": RESUME_MANIFEST_PROFILE,
            "records": [
                [ALICE_ONLY_ID, zero_digest()],
                [ALICE_COMMON_ID, zero_digest()],
            ],
            "facets": [],
            "links": [],
        });
        let delta = match resume(&db, bea(), &manifest).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("bea manifest must delta, got {other:?}"),
        };
        assert!(
            delta.delete_record_ids.contains(&ALICE_ONLY_ID.to_string()),
            "unauthorized manifest key becomes a delete, never rows"
        );
        assert!(
            !delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_ONLY_ID),
            "hidden row must not appear anywhere in the response"
        );
        assert!(
            delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_COMMON_ID),
            "shared row still repairs"
        );
    }

    #[tokio::test]
    async fn resume_purges_revoked_rows_as_deletes_not_restart() {
        let db = three_record_fixture().await;
        let manifest = exact_manifest(&db, alice()).await;
        replace_explicit_policy(
            &db,
            "test:narrow",
            ALICE_ONLY_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        let delta = match resume(&db, alice(), &manifest).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("post-revoke resume must delta, got {other:?}"),
        };
        assert!(
            delta.delete_record_ids.contains(&ALICE_ONLY_ID.to_string()),
            "revoked row purges as a delete"
        );
        assert!(
            !delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_ONLY_ID),
            "revoked row must not upsert"
        );
    }

    #[tokio::test]
    async fn resume_restores_excluded_message_rows_as_missing_key_upserts() {
        let db = three_record_fixture().await;
        const MESSAGE_ID: &str = "9e795001-0000-4000-8000-000000000044";
        create_record(
            &db,
            json!({
                "id": MESSAGE_ID, "type": "Message", "kind": "message",
                "name": "Cached never", "body": "Body",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            MESSAGE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        // The cache projection never persists messages, so the manifest —
        // like dumpIndex — simply omits them.
        let manifest = exact_manifest(&db, alice()).await;
        assert!(
            manifest["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tuple| tuple[0] == MESSAGE_ID),
            "precondition: fresh open holds the message row"
        );
        let pruned = json!({
            "version": 1,
            "profile": RESUME_MANIFEST_PROFILE,
            "records": manifest["records"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|tuple| tuple[0] != MESSAGE_ID)
                .cloned()
                .collect::<Vec<_>>(),
            "facets": manifest["facets"],
            "links": manifest["links"],
        });
        let delta = match resume(&db, alice(), &pruned).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("message omission must delta, got {other:?}"),
        };
        let restored: Vec<_> = delta
            .upsert_records
            .iter()
            .filter(|row| row.id == MESSAGE_ID)
            .collect();
        assert_eq!(restored.len(), 1, "excluded message returns as an upsert");
        assert_eq!(restored[0].record_type.as_deref(), Some("Message"));
        assert!(
            !delta.delete_record_ids.contains(&MESSAGE_ID.to_string()),
            "a visible omitted row is a repair, not a delete"
        );
    }

    #[tokio::test]
    async fn resume_needs_no_surviving_pin_or_token() {
        let db = three_record_fixture().await;
        // Build the manifest first, then churn the token store past its
        // count cap so every pin — including the one the manifest was paged
        // from — is evicted: resume must still reconcile, proving no old
        // snapshot, token, or tombstone is required. A server restart loses
        // nothing this call needs.
        let manifest = exact_manifest(&db, alice()).await;
        for _ in 0..=SNAPSHOT_MAX_TOKENS {
            open_token(&db, alice()).await;
        }
        let delta = match resume(&db, alice(), &manifest).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("post-eviction resume must delta, got {other:?}"),
        };
        assert!(delta.upsert_records.is_empty());
        assert!(delta.delete_record_ids.is_empty());
    }

    #[tokio::test]
    async fn resume_partial_manifest_repairs_everything_unlisted() {
        let db = three_record_fixture().await;
        set_facet(
            &db,
            ALICE_COMMON_ID,
            FacetSetPayload {
                key: "priority".to_string(),
                value: Some("high".to_string()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        let full = exact_manifest(&db, alice()).await;
        // A manifest naming exactly one correct record key and nothing else:
        // every other fresh key must come back as an upsert, so applying the
        // delta to that single row rebuilds the full model.
        let one_record = full["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tuple| tuple[0] == ALICE_COMMON_ID)
            .unwrap()
            .clone();
        let partial = json!({
            "version": 1,
            "profile": RESUME_MANIFEST_PROFILE,
            "records": [one_record],
            "facets": [],
            "links": [],
        });
        let delta = match resume(&db, alice(), &partial).await {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("partial manifest must delta, got {other:?}"),
        };
        assert!(
            !delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_COMMON_ID),
            "the one correct key is already current"
        );
        assert!(
            delta
                .upsert_records
                .iter()
                .any(|row| row.id == ALICE_ONLY_ID),
            "unlisted fresh records upsert"
        );
        assert!(
            delta
                .upsert_facets
                .iter()
                .any(|facet| facet.record_id == ALICE_COMMON_ID && facet.key == "priority"),
            "unlisted fresh facets upsert"
        );
        assert!(delta.delete_record_ids.is_empty());
    }
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod kernel_budget_tests {
    use super::*;
    #[test]
    fn three_members_and_agents_retain_real_large_pins_with_bounded_v2_budget() {
        let store = std::sync::Arc::new(std::sync::Mutex::new(SnapshotStore::default()));
        let summary = "x".repeat(5 * 1024 * 1024);
        let mut held = Vec::new();
        for slot in 0..12 {
            let principal = QueryPrincipal::authenticated(format!("account:{}", slot % 3), true);
            let record = SnapshotRecord {
                id: "shared".into(),
                record_type: Some("Document".into()),
                kind: Some("note".into()),
                name: "Shared fixture".into(),
                home_id: None,
                lifecycle: None,
                persistence: "enduring".into(),
                maturity: None,
                summary: Some(summary.clone()),
                last_activity_at: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                deleted_at: None,
            };
            let records = BTreeMap::from([("shared".into(), record)]);
            let facets = BTreeMap::new();
            let links = BTreeMap::new();
            let events = Vec::new();
            let estimated_bytes = estimate_entry_bytes(
                principal.credential().len(),
                &records,
                &facets,
                &links,
                &events,
            );
            assert!(estimated_bytes < SNAPSHOT_MAX_BYTES);
            let entry = SnapshotEntry {
                principal_credential: principal.credential().into(),
                principal_is_member: principal.is_member(),
                principal_trusted_bypass: principal.trusted_local_bypass(),
                created_at: Instant::now(),
                content_seq: 0,
                authorization_epoch: 0,
                relationship_seq: 0,
                unit_seq_max: 0,
                estimated_bytes,
                kernel_v2: true,
                records,
                facets,
                links,
                events,
            };
            let token = format!("pin-{slot}");
            assert!(SnapshotStore::insert_shared(&store, token.clone(), entry, None).unwrap());
            held.push(token);
        }
        let store = store.lock().unwrap();
        assert!(store.bytes > SNAPSHOT_MAX_BYTES);
        assert!(store.bytes <= SNAPSHOT_V2_MAX_BYTES);
        for token in held {
            assert!(store.entries.contains_key(&token));
        }
    }
    fn budget_entry(bytes: usize, created_at: Instant) -> SnapshotEntry {
        SnapshotEntry {
            principal_credential: "account:owner".into(),
            principal_is_member: true,
            principal_trusted_bypass: false,
            created_at,
            content_seq: 7,
            authorization_epoch: 9,
            relationship_seq: 11,
            unit_seq_max: 13,
            estimated_bytes: bytes,
            kernel_v2: true,
            records: BTreeMap::new(),
            facets: BTreeMap::new(),
            links: BTreeMap::new(),
            events: Vec::new(),
        }
    }
    fn total_v2_bytes(stores: &[std::sync::Arc<std::sync::Mutex<SnapshotStore>>]) -> usize {
        stores
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap()
                    .entries
                    .values()
                    .filter(|e| e.kernel_v2)
                    .map(|e| e.estimated_bytes)
                    .sum::<usize>()
            })
            .sum()
    }
    #[tokio::test]
    async fn process_v2_budget_evicted_db_pin_returns_token_expired_or_unknown() {
        use crate::mcp::{Caller, EngineHandle};
        use serde_json::json;

        let dir = tempfile::tempdir().unwrap();
        let mut registry = crate::mcp::registry::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let mut pins = Vec::new();
        for name in ["first", "second"] {
            let (db, _) = crate::kernel::create_v2_database(
                dir.path().join(format!("{name}.db")).to_str().unwrap(),
                "account",
                "Owner",
                "account:owner",
            )
            .await
            .unwrap();
            let opened = registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    Caller::authenticated("account:owner"),
                    "get_workspace_snapshot",
                    json!({"action":"open"}),
                )
                .await
                .unwrap();
            let token = opened["snapshot_token"].as_str().unwrap().to_owned();
            let entry = db.workspace_snapshots.lock().unwrap().entries[&token].clone();
            pins.push((db, token, entry));
        }
        // Exercise the real Db stores with a local small budget, without
        // changing the process singleton or allocating hundreds of MiB.
        let mut budget = V2SnapshotBudget::new(
            pins.iter()
                .map(|(_, _, e)| e.estimated_bytes)
                .sum::<usize>()
                - 1,
        );
        for (index, (db, token, entry)) in pins.iter().enumerate() {
            let mut entry = entry.clone();
            entry.created_at = Instant::now() - Duration::from_secs(2 - index as u64);
            assert!(budget
                .insert(&db.workspace_snapshots, token.clone(), entry, None)
                .unwrap());
        }
        for (index, (db, token, _)) in pins.iter().enumerate() {
            let page = registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    Caller::authenticated("account:owner"),
                    "get_workspace_snapshot",
                    json!({"action":"page","snapshot_token":token,"section":"records"}),
                )
                .await
                .unwrap();
            if index == 0 {
                assert_eq!(page["restart_required"], true);
                assert_eq!(page["reason"], "token_expired_or_unknown");
                assert!(page.get("rows").is_none());
                assert!(!db
                    .workspace_snapshots
                    .lock()
                    .unwrap()
                    .entries
                    .contains_key(token));
            } else {
                assert_eq!(page["snapshot_token"], *token);
                assert!(page["rows"].is_array());
            }
        }
        for (db, _, _) in pins {
            db.close().await;
        }
    }

    #[test]
    fn process_v2_budget_evicts_global_oldest_across_handles_and_keeps_expiry_private() {
        use std::sync::{Arc, Mutex};
        let stores: Vec<_> = (0..3)
            .map(|_| Arc::new(Mutex::new(SnapshotStore::default())))
            .collect();
        let mut budget = V2SnapshotBudget::new(400);
        let start = Instant::now() - Duration::from_secs(10);
        // The same token string on two handles must remain independent.
        for (slot, token, age) in [
            (0, "same", 0),
            (1, "same", 1),
            (0, "second", 2),
            (2, "new", 3),
        ] {
            assert!(budget
                .insert(
                    &stores[slot],
                    token.into(),
                    budget_entry(100, start + Duration::from_secs(age)),
                    None
                )
                .unwrap());
        }
        // V1 retains its own existing budget and is not a global v2 victim.
        let mut v1 = budget_entry(200, start);
        v1.kernel_v2 = false;
        assert!(SnapshotStore::insert_shared(&stores[0], "v1".into(), v1, None).unwrap());
        // Reading does not turn oldest-pin eviction into LRU eviction.
        let owner = QueryPrincipal::authenticated("account:owner", true);
        assert!(stores[0].lock().unwrap().get_for(&owner, "same").is_ok());
        assert!(budget
            .insert(
                &stores[1],
                "newest".into(),
                budget_entry(100, Instant::now()),
                None
            )
            .unwrap());
        assert_eq!(total_v2_bytes(&stores), 400);
        let mut first = stores[0].lock().unwrap();
        assert!(!first.entries.contains_key("same"));
        assert!(first.entries.contains_key("v1"));
        assert_eq!(first.bytes, 300);
        assert!(first.get_for(&owner, "same").is_err());
        let expired = first.expired_pin_for(&owner, "same").unwrap();
        assert_eq!(expired.authorization_epoch, 9);
        assert!(first
            .expired_pin_for(&QueryPrincipal::authenticated("other", true), "same")
            .is_none());
        assert!(first
            .expired_pin_for(
                &QueryPrincipal::authenticated("account:owner", false),
                "same"
            )
            .is_none());
        drop(first);
        assert!(stores[1].lock().unwrap().get_for(&owner, "same").is_ok());
        assert_eq!(budget.stores.len(), 3);
    }
    #[test]
    fn process_v2_budget_reclaims_dropped_handles_expiry_and_rotation_without_owning_handles() {
        use std::sync::{Arc, Mutex};
        let mut budget = V2SnapshotBudget::new(300);
        let first = Arc::new(Mutex::new(SnapshotStore::default()));
        let second = Arc::new(Mutex::new(SnapshotStore::default()));
        assert!(budget
            .insert(
                &first,
                "dropped".into(),
                budget_entry(200, Instant::now()),
                None
            )
            .unwrap());
        assert_eq!(Arc::strong_count(&first), 1);
        drop(first);
        assert!(budget
            .insert(
                &second,
                "old".into(),
                budget_entry(200, Instant::now()),
                None
            )
            .unwrap());
        assert_eq!(budget.stores.len(), 1);
        // Refusal cannot retire the old pin or admit a dead new token.
        assert!(!budget
            .insert(
                &second,
                "too-large".into(),
                budget_entry(301, Instant::now()),
                Some("old")
            )
            .unwrap());
        assert!(second.lock().unwrap().entries.contains_key("old"));
        second
            .lock()
            .unwrap()
            .entries
            .get_mut("old")
            .unwrap()
            .created_at = Instant::now() - SNAPSHOT_TTL - Duration::from_secs(1);
        let third = Arc::new(Mutex::new(SnapshotStore::default()));
        assert!(budget
            .insert(
                &third,
                "fresh".into(),
                budget_entry(200, Instant::now()),
                None
            )
            .unwrap());
        assert!(second.lock().unwrap().entries.is_empty());
        assert_eq!(second.lock().unwrap().bytes, 0);
        assert!(budget
            .insert(
                &third,
                "rotated".into(),
                budget_entry(100, Instant::now()),
                Some("fresh")
            )
            .unwrap());
        assert_eq!(third.lock().unwrap().bytes, 100);
        assert!(third.lock().unwrap().expired.contains_key("fresh"));
        // Clones of a handle register only once.
        assert!(budget
            .insert(
                &third.clone(),
                "clone".into(),
                budget_entry(100, Instant::now()),
                None
            )
            .unwrap());
        assert_eq!(budget.stores.len(), 2);
    }
    #[test]
    fn process_v2_budget_never_returns_an_already_evicted_new_pin() {
        use std::sync::{Arc, Mutex};
        let mut budget = V2SnapshotBudget::new(100);
        let a = Arc::new(Mutex::new(SnapshotStore::default()));
        let b = Arc::new(Mutex::new(SnapshotStore::default()));
        assert!(budget
            .insert(&a, "held".into(), budget_entry(100, Instant::now()), None)
            .unwrap());
        assert!(!budget
            .insert(
                &b,
                "queued-old".into(),
                budget_entry(100, Instant::now() - Duration::from_secs(1)),
                None
            )
            .unwrap());
        assert!(b.lock().unwrap().entries.is_empty());
        assert!(a.lock().unwrap().entries.contains_key("held"));
    }
    #[test]
    fn process_v2_budget_serializes_concurrent_insertions_and_preserves_handle_count_cap() {
        use std::sync::{Arc, Barrier, Mutex};
        let budget = Arc::new(Mutex::new(V2SnapshotBudget::new(1000)));
        let stores: Vec<_> = (0..8)
            .map(|_| Arc::new(Mutex::new(SnapshotStore::default())))
            .collect();
        let barrier = Arc::new(Barrier::new(stores.len()));
        let threads: Vec<_> = stores
            .iter()
            .map(|store| {
                let (store, budget, barrier) = (store.clone(), budget.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    for slot in 0..5 {
                        budget
                            .lock()
                            .unwrap()
                            .insert(
                                &store,
                                format!("pin-{slot}"),
                                budget_entry(100, Instant::now()),
                                None,
                            )
                            .unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(total_v2_bytes(&stores), 1000);
        let mut budget = V2SnapshotBudget::new(10000);
        let store = Arc::new(Mutex::new(SnapshotStore::default()));
        for slot in 0..=SNAPSHOT_V2_MAX_TOKENS {
            assert!(budget
                .insert(
                    &store,
                    format!("pin-{slot}"),
                    budget_entry(100, Instant::now()),
                    None
                )
                .unwrap());
        }
        assert_eq!(store.lock().unwrap().entries.len(), SNAPSHOT_V2_MAX_TOKENS);
        assert!(!store.lock().unwrap().entries.contains_key("pin-0"));
    }
    #[test]
    fn process_v2_budget_counts_poisoned_handles_without_serving_them() {
        use std::sync::{Arc, Mutex};
        let a = Arc::new(Mutex::new(SnapshotStore::default()));
        let b = Arc::new(Mutex::new(SnapshotStore::default()));
        let mut budget = V2SnapshotBudget::new(300);
        assert!(budget
            .insert(&a, "old".into(), budget_entry(200, Instant::now()), None)
            .unwrap());
        let _ = std::panic::catch_unwind(|| {
            let _guard = a.lock().unwrap();
            panic!("poison snapshot handle");
        });
        assert!(budget
            .insert(&b, "new".into(), budget_entry(200, Instant::now()), None)
            .unwrap());
        assert!(a.lock().unwrap_err().get_ref().entries.is_empty());
        assert_eq!(b.lock().unwrap().bytes, 200);
        assert!(budget
            .insert(
                &a,
                "refused".into(),
                budget_entry(100, Instant::now()),
                None
            )
            .is_err());
    }
}
