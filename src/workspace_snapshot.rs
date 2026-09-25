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
//! - M2 `None` (over-cap refusal, absent index, racing fences) surfaces as a
//!   generic `index_unavailable`, never an empty workspace. The fallback reader
//!   is the client's existing governed path.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::query::QueryPrincipal;
use crate::workspace_index::FilteredWorkspaceIndex;

/// Tokens held per database handle. Eight entries bound memory the way the
/// handle LRU does: entries are LRU-evicted past the count cap or past
/// [`SNAPSHOT_MAX_BYTES`] total, so worst case per handle is one 32 MiB
/// index plus 32 MiB of tokens. Typical test workspaces measure in KiB.
pub const SNAPSHOT_MAX_TOKENS: usize = 8;
/// Total estimated bytes across held tokens per handle. Matches
/// [`crate::workspace_index::MAX_INDEX_BYTES`] deliberately: the token budget
/// can never exceed one more refused-sized index.
pub const SNAPSHOT_MAX_BYTES: usize = 32 * 1024 * 1024;
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
    pub record_type: String,
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
            record_type: head.record_type.clone(),
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
fn estimate_entry_bytes(
    principal_credential_len: usize,
    records: &BTreeMap<String, SnapshotRecord>,
    facets: &BTreeMap<String, SnapshotFacet>,
    links: &BTreeMap<String, SnapshotLink>,
    events: &[SnapshotEvent],
) -> usize {
    const MAP_NODE_OVERHEAD: usize = 64;
    const STORE_ENTRY_OVERHEAD: usize = 512;
    let mut estimated_bytes = 1024 + STORE_ENTRY_OVERHEAD + principal_credential_len + 64;
    for (id, record) in records {
        estimated_bytes += std::mem::size_of::<SnapshotRecord>()
            + std::mem::size_of::<String>()
            + id.len() * 2
            + record.record_type.len()
            + record.kind.as_ref().map_or(0, String::len)
            + record.name.len()
            + record.home_id.as_ref().map_or(0, String::len)
            + record.lifecycle.as_ref().map_or(0, String::len)
            + record.persistence.len()
            + record.maturity.as_ref().map_or(0, String::len)
            + record.summary.as_ref().map_or(0, String::len)
            + record.last_activity_at.as_ref().map_or(0, String::len)
            + record.created_at.len()
            + record.updated_at.len()
            + record.deleted_at.as_ref().map_or(0, String::len)
            + MAP_NODE_OVERHEAD;
    }
    for (id, facet) in facets {
        estimated_bytes += std::mem::size_of::<SnapshotFacet>()
            + std::mem::size_of::<String>()
            + id.len() * 2
            + facet.record_id.len()
            + facet.key.len()
            + facet.value.as_ref().map_or(0, String::len)
            + facet.value_num.map_or(0, |_| 8)
            + facet.vocab_ref.as_ref().map_or(0, String::len)
            + facet.created_at.len()
            + MAP_NODE_OVERHEAD;
    }
    for (id, link) in links {
        estimated_bytes += std::mem::size_of::<SnapshotLink>()
            + std::mem::size_of::<String>()
            + id.len() * 2
            + link.source_id.len()
            + link.target_id.len()
            + link.relationship.len()
            + link.note.as_ref().map_or(0, String::len)
            + link.created_at.len()
            + MAP_NODE_OVERHEAD;
    }
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

impl SnapshotEntry {
    fn project(principal: &QueryPrincipal, filtered: &FilteredWorkspaceIndex) -> Self {
        let records: BTreeMap<String, SnapshotRecord> = filtered
            .records
            .iter()
            .map(|(id, head)| (id.clone(), SnapshotRecord::from_head(head)))
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
#[derive(Debug, Default)]
pub(crate) struct SnapshotStore {
    entries: HashMap<String, SnapshotEntry>,
    bytes: usize,
}

impl SnapshotStore {
    /// Store a pin. Returns `false` (refusal) when the single entry already
    /// exceeds the byte budget: callers must surface unavailable rather than
    /// a token that is already gone. Eviction otherwise protects the new
    /// token — only older pins are candidates — and storage is verified
    /// before returning `true`.
    pub(crate) fn insert(&mut self, token: String, entry: SnapshotEntry) -> bool {
        if entry.estimated_bytes > SNAPSHOT_MAX_BYTES {
            return false;
        }
        let now = Instant::now();
        self.evict_expired(now);
        if let Some(old) = self.entries.remove(&token) {
            self.bytes = self.bytes.saturating_sub(old.estimated_bytes);
        }
        let bytes = entry.estimated_bytes;
        self.entries.insert(token.clone(), entry);
        self.bytes += bytes;
        while self.entries.len() > SNAPSHOT_MAX_TOKENS || self.bytes > SNAPSHOT_MAX_BYTES {
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

/// One link delete addressed the way page models key links.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkKey {
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
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
/// open at the returned stamp.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotDelta {
    pub token: String,
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
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
    /// Pin the caller's current filtered view under a new token.
    /// Returns `Ok(None)` when M2 holds nothing (generic unavailable) or when
    /// the pin itself is refused by the token budget: a returned token is
    /// always stored and pageable, never already evicted.
    pub async fn open_workspace_snapshot(
        &self,
        principal: QueryPrincipal,
    ) -> Result<Option<SnapshotOpened>> {
        let Some(filtered) = self.filtered_workspace_index(principal.clone()).await? else {
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
        {
            let mut guard = store
                .lock()
                .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
            if !guard.insert(token, entry) {
                return Ok(None);
            }
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
            self.live_snapshot_fences().await?;
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
    pub async fn catch_up_workspace_snapshot(
        &self,
        principal: QueryPrincipal,
        token: &str,
    ) -> Result<CatchUpOutcome> {
        let old = {
            let store = self.workspace_snapshots.clone();
            let mut guard = store
                .lock()
                .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
            match guard.get_for(&principal, token) {
                Ok(entry) => entry.clone(),
                Err(SnapshotLookup::Restart { reason }) => {
                    return Ok(CatchUpOutcome::Restart { reason });
                }
            }
        };
        let Some(filtered) = self.filtered_workspace_index(principal.clone()).await? else {
            // M2 holds nothing: over-cap refusal, absent index, or a fence
            // that raced the visibility read. An unavailable index alone keeps
            // the caller's pin (the governed tail stays safe), but fences that
            // moved under the pin mean revoked rows — that is a restart with
            // no old rows, never an incremental tail.
            let (live_epoch, live_relationship, live_unit_seq_max) =
                self.live_snapshot_fences().await?;
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
        if filtered.authorization_epoch != old.authorization_epoch {
            return Ok(CatchUpOutcome::Restart {
                reason: "authorization_epoch_moved",
            });
        }
        if filtered.relationship_seq != old.relationship_seq {
            return Ok(CatchUpOutcome::Restart {
                reason: "relationship_seq_moved",
            });
        }
        if filtered.unit_seq_max != old.unit_seq_max {
            return Ok(CatchUpOutcome::Restart {
                reason: "unit_seq_moved",
            });
        }
        if filtered.content_seq < old.content_seq
            || filtered.content_seq - old.content_seq > SNAPSHOT_MAX_CATCH_UP_GAP
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
                    relationship: row.relationship.clone(),
                });
            }
        }
        {
            let store = self.workspace_snapshots.clone();
            let mut guard = store
                .lock()
                .map_err(|_| Error::engine("workspace snapshot store is unavailable"))?;
            // The old pin retires only after its replacement is stored: a
            // refused replacement leaves the caller able to keep paging the
            // old pin (or retry), never holding a dead new token.
            if !guard.insert(delta.token.clone(), fresh) {
                return Ok(CatchUpOutcome::Unavailable);
            }
            guard.remove(token);
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
            .catch_up_workspace_snapshot(bea(), &bea_open.token)
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
            .catch_up_workspace_snapshot(alice(), &opened.token)
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
            .catch_up_workspace_snapshot(alice(), &opened.token)
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
            .catch_up_workspace_snapshot(alice(), &opened.token)
            .await
            .unwrap()
        {
            CatchUpOutcome::Delta(delta) => delta,
            other => panic!("same-fence changes must delta, got {other:?}"),
        };
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
            .catch_up_workspace_snapshot(alice(), &opened.token)
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
                record_type: "Document".to_string(),
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
}
